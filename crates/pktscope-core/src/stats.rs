use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::packet::{
    Direction, IpScope, ParsedPacket, Protocol, RawPacket, classify_ip, parse_packet,
};

const RATE_WINDOW_SECS: usize = 5;
const THROUGHPUT_RETENTION_SECS: u64 = 300;
const MAX_CONVERSATION_PORTS: usize = 16;

fn epoch_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Fixed-size 1-second bucket ring over a 5-second rolling window.
#[derive(Debug, Clone, Copy, Default)]
struct RateWindow {
    buckets: [(Option<u64>, u64); RATE_WINDOW_SECS],
}

impl RateWindow {
    fn record(&mut self, epoch_sec: u64, bytes: u64) {
        let idx = (epoch_sec as usize) % RATE_WINDOW_SECS;
        match self.buckets[idx].0 {
            Some(sec) if sec == epoch_sec => {
                self.buckets[idx].1 = self.buckets[idx].1.saturating_add(bytes);
            }
            Some(sec) if sec > epoch_sec => {
                // Ignore stale out-of-order samples older than the current slot occupant.
            }
            _ => {
                self.buckets[idx] = (Some(epoch_sec), bytes);
            }
        }
    }

    fn rate_bps(&self, ref_time: SystemTime) -> f64 {
        let ref_sec = epoch_secs(ref_time);
        let min_sec = ref_sec.saturating_sub((RATE_WINDOW_SECS as u64) - 1);
        let total: u64 = self
            .buckets
            .iter()
            .filter_map(|&(sec_opt, bytes)| {
                sec_opt
                    .filter(|&s| s >= min_sec && s <= ref_sec)
                    .map(|_| bytes)
            })
            .sum();
        total as f64 / (RATE_WINDOW_SECS as f64)
    }
}

/// Aggregated traffic statistics for a single IP address.
#[derive(Debug, Clone)]
pub struct IpStats {
    pub ip: IpAddr,
    pub scope: IpScope,
    pub bytes_sent: u64,
    pub packets_sent: u64,
    pub bytes_received: u64,
    pub packets_received: u64,
    pub protocols: BTreeSet<Protocol>,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    sent_window: RateWindow,
    recv_window: RateWindow,
}

impl IpStats {
    fn new(ip: IpAddr, scope: IpScope, timestamp: SystemTime) -> Self {
        Self {
            ip,
            scope,
            bytes_sent: 0,
            packets_sent: 0,
            bytes_received: 0,
            packets_received: 0,
            protocols: BTreeSet::new(),
            first_seen: timestamp,
            last_seen: timestamp,
            sent_window: RateWindow::default(),
            recv_window: RateWindow::default(),
        }
    }

    /// Total bytes sent and received by this IP.
    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent.saturating_add(self.bytes_received)
    }

    /// Total packets sent and received by this IP.
    pub fn total_packets(&self) -> u64 {
        self.packets_sent.saturating_add(self.packets_received)
    }

    /// Rolling outbound byte rate (B/s) over the 5-second window ending at `ref_time`.
    pub fn rate_sent_bps(&self, ref_time: SystemTime) -> f64 {
        self.sent_window.rate_bps(ref_time)
    }

    /// Rolling inbound byte rate (B/s) over the 5-second window ending at `ref_time`.
    pub fn rate_recv_bps(&self, ref_time: SystemTime) -> f64 {
        self.recv_window.rate_bps(ref_time)
    }

    /// Combined rolling byte rate (B/s) over the 5-second window ending at `ref_time`.
    pub fn rate_total_bps(&self, ref_time: SystemTime) -> f64 {
        self.rate_sent_bps(ref_time) + self.rate_recv_bps(ref_time)
    }
}

/// Canonical bidirectional conversation identifier with `addr_a <= addr_b`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConversationKey {
    pub addr_a: IpAddr,
    pub addr_b: IpAddr,
    pub protocol: Protocol,
}

impl ConversationKey {
    /// Creates a canonical [`ConversationKey`] and returns `(key, is_a_to_b)`.
    pub fn new(src: IpAddr, dst: IpAddr, protocol: Protocol) -> (Self, bool) {
        if src <= dst {
            (
                Self {
                    addr_a: src,
                    addr_b: dst,
                    protocol,
                },
                true,
            )
        } else {
            (
                Self {
                    addr_a: dst,
                    addr_b: src,
                    protocol,
                },
                false,
            )
        }
    }
}

/// Bidirectional traffic statistics for an endpoint pair and protocol.
#[derive(Debug, Clone)]
pub struct ConversationStats {
    pub key: ConversationKey,
    pub bytes_a_to_b: u64,
    pub packets_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub packets_b_to_a: u64,
    pub ports: BTreeSet<u16>,
    pub last_seen: SystemTime,
    rate_window: RateWindow,
}

impl ConversationStats {
    fn new(key: ConversationKey, last_seen: SystemTime) -> Self {
        Self {
            key,
            bytes_a_to_b: 0,
            packets_a_to_b: 0,
            bytes_b_to_a: 0,
            packets_b_to_a: 0,
            ports: BTreeSet::new(),
            last_seen,
            rate_window: RateWindow::default(),
        }
    }

    fn record_port(&mut self, port: Option<u16>) {
        if let Some(p) = port
            && self.ports.len() < MAX_CONVERSATION_PORTS
        {
            self.ports.insert(p);
        }
    }

    /// Total bidirectional bytes exchanged in this conversation.
    pub fn total_bytes(&self) -> u64 {
        self.bytes_a_to_b.saturating_add(self.bytes_b_to_a)
    }

    /// Total bidirectional packets exchanged in this conversation.
    pub fn total_packets(&self) -> u64 {
        self.packets_a_to_b.saturating_add(self.packets_b_to_a)
    }

    /// Rolling byte rate (B/s) over the 5-second window ending at `ref_time`.
    pub fn rate_bps(&self, ref_time: SystemTime) -> f64 {
        self.rate_window.rate_bps(ref_time)
    }
}

/// Per-second traffic breakdown bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ThroughputSample {
    pub epoch_sec: u64,
    pub inbound_bytes: u64,
    pub outbound_bytes: u64,
    pub local_bytes: u64,
    pub transit_bytes: u64,
    pub total_bytes: u64,
    pub packets: u64,
}

/// In-memory live packet buffer and traffic aggregator.
#[derive(Debug)]
pub struct TrafficStore {
    max_packets: usize,
    local_ips: HashSet<IpAddr>,
    packets: VecDeque<ParsedPacket>,
    last_overflow_packet: Option<ParsedPacket>,
    ip_stats: HashMap<IpAddr, IpStats>,
    conversations: HashMap<ConversationKey, ConversationStats>,
    protocol_totals: BTreeMap<Protocol, (u64, u64)>,
    port_totals: HashMap<u16, (u64, u64)>,
    throughput: BTreeMap<u64, ThroughputSample>,
    total_packets: u64,
    total_bytes: u64,
    latest_timestamp: Option<SystemTime>,
    next_id: u64,
}

impl TrafficStore {
    /// Creates a new [`TrafficStore`] retaining at most `max_packets` recent packets.
    pub fn new(max_packets: usize) -> Self {
        Self {
            max_packets,
            local_ips: HashSet::new(),
            packets: VecDeque::with_capacity(max_packets.min(1024)),
            last_overflow_packet: None,
            ip_stats: HashMap::new(),
            conversations: HashMap::new(),
            protocol_totals: BTreeMap::new(),
            port_totals: HashMap::new(),
            throughput: BTreeMap::new(),
            total_packets: 0,
            total_bytes: 0,
            latest_timestamp: None,
            next_id: 0,
        }
    }

    /// Updates the local IP set and refreshes `scope` on all existing [`IpStats`].
    pub fn set_local_ips(&mut self, ips: HashSet<IpAddr>) {
        self.local_ips = ips;
        for stat in self.ip_stats.values_mut() {
            stat.scope = classify_ip(stat.ip, &self.local_ips);
        }
    }

    /// Returns the configured local IP address set.
    pub fn local_ips(&self) -> &HashSet<IpAddr> {
        &self.local_ips
    }

    /// Decodes a [`RawPacket`] and ingests it into the store.
    pub fn ingest_raw(&mut self, raw: &RawPacket) -> &ParsedPacket {
        let parsed = parse_packet(raw, &self.local_ips);
        self.ingest_parsed(parsed)
    }

    /// Assigns a monotonic packet ID, updates all aggregations, and stores the packet.
    pub fn ingest_parsed(&mut self, mut pkt: ParsedPacket) -> &ParsedPacket {
        self.next_id = self.next_id.saturating_add(1);
        pkt.id = self.next_id;

        let bytes = u64::from(pkt.original_len);
        let sec = epoch_secs(pkt.timestamp);

        self.total_packets = self.total_packets.saturating_add(1);
        self.total_bytes = self.total_bytes.saturating_add(bytes);
        self.latest_timestamp = Some(match self.latest_timestamp {
            Some(prev) if prev > pkt.timestamp => prev,
            _ => pkt.timestamp,
        });

        if let Some(src) = pkt.src_ip {
            let scope = classify_ip(src, &self.local_ips);
            let stat = self
                .ip_stats
                .entry(src)
                .or_insert_with(|| IpStats::new(src, scope, pkt.timestamp));
            stat.bytes_sent = stat.bytes_sent.saturating_add(bytes);
            stat.packets_sent = stat.packets_sent.saturating_add(1);
            stat.protocols.insert(pkt.protocol);
            if pkt.timestamp < stat.first_seen {
                stat.first_seen = pkt.timestamp;
            }
            if pkt.timestamp > stat.last_seen {
                stat.last_seen = pkt.timestamp;
            }
            stat.sent_window.record(sec, bytes);
        }

        if let Some(dst) = pkt.dst_ip {
            let scope = classify_ip(dst, &self.local_ips);
            let stat = self
                .ip_stats
                .entry(dst)
                .or_insert_with(|| IpStats::new(dst, scope, pkt.timestamp));
            stat.bytes_received = stat.bytes_received.saturating_add(bytes);
            stat.packets_received = stat.packets_received.saturating_add(1);
            stat.protocols.insert(pkt.protocol);
            if pkt.timestamp < stat.first_seen {
                stat.first_seen = pkt.timestamp;
            }
            if pkt.timestamp > stat.last_seen {
                stat.last_seen = pkt.timestamp;
            }
            stat.recv_window.record(sec, bytes);
        }

        if let (Some(src), Some(dst)) = (pkt.src_ip, pkt.dst_ip) {
            let (key, is_a_to_b) = ConversationKey::new(src, dst, pkt.protocol);
            let conv = self
                .conversations
                .entry(key)
                .or_insert_with(|| ConversationStats::new(key, pkt.timestamp));
            if is_a_to_b {
                conv.bytes_a_to_b = conv.bytes_a_to_b.saturating_add(bytes);
                conv.packets_a_to_b = conv.packets_a_to_b.saturating_add(1);
            } else {
                conv.bytes_b_to_a = conv.bytes_b_to_a.saturating_add(bytes);
                conv.packets_b_to_a = conv.packets_b_to_a.saturating_add(1);
            }
            conv.record_port(pkt.src_port);
            conv.record_port(pkt.dst_port);
            if pkt.timestamp > conv.last_seen {
                conv.last_seen = pkt.timestamp;
            }
            conv.rate_window.record(sec, bytes);
        }

        let proto_entry = self.protocol_totals.entry(pkt.protocol).or_insert((0, 0));
        proto_entry.0 = proto_entry.0.saturating_add(1);
        proto_entry.1 = proto_entry.1.saturating_add(bytes);

        if let Some(sp) = pkt.src_port {
            let entry = self.port_totals.entry(sp).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(1);
            entry.1 = entry.1.saturating_add(bytes);
        }
        if let Some(dp) = pkt.dst_port
            && Some(dp) != pkt.src_port
        {
            let entry = self.port_totals.entry(dp).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(1);
            entry.1 = entry.1.saturating_add(bytes);
        }

        let sample = self
            .throughput
            .entry(sec)
            .or_insert_with(|| ThroughputSample {
                epoch_sec: sec,
                ..Default::default()
            });
        match pkt.direction {
            Direction::Inbound => sample.inbound_bytes = sample.inbound_bytes.saturating_add(bytes),
            Direction::Outbound => {
                sample.outbound_bytes = sample.outbound_bytes.saturating_add(bytes);
            }
            Direction::Local => sample.local_bytes = sample.local_bytes.saturating_add(bytes),
            Direction::Transit => sample.transit_bytes = sample.transit_bytes.saturating_add(bytes),
        }
        sample.total_bytes = sample.total_bytes.saturating_add(bytes);
        sample.packets = sample.packets.saturating_add(1);

        let latest_sec = epoch_secs(self.latest_timestamp.unwrap_or(pkt.timestamp));
        let prune_before = latest_sec.saturating_sub(THROUGHPUT_RETENTION_SECS);
        while let Some((&oldest_sec, _)) = self.throughput.first_key_value() {
            if oldest_sec < prune_before {
                self.throughput.pop_first();
            } else {
                break;
            }
        }

        if self.max_packets == 0 {
            self.last_overflow_packet = Some(pkt);
            return self
                .last_overflow_packet
                .as_ref()
                .expect("just stored overflow packet");
        }

        while self.packets.len() >= self.max_packets {
            self.packets.pop_front();
        }
        self.packets.push_back(pkt);
        self.packets.back().expect("just pushed packet")
    }

    /// Resets all collected packets and statistics while keeping `local_ips` and `max_packets`.
    pub fn clear(&mut self) {
        self.packets.clear();
        self.last_overflow_packet = None;
        self.ip_stats.clear();
        self.conversations.clear();
        self.protocol_totals.clear();
        self.port_totals.clear();
        self.throughput.clear();
        self.total_packets = 0;
        self.total_bytes = 0;
        self.latest_timestamp = None;
        self.next_id = 0;
    }

    /// Total number of ingested packets since creation or last [`TrafficStore::clear`].
    pub fn total_packets(&self) -> u64 {
        self.total_packets
    }

    /// Total number of ingested bytes (`original_len`) since creation or last [`TrafficStore::clear`].
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Timestamp of the latest ingested packet, if any.
    pub fn latest_timestamp(&self) -> Option<SystemTime> {
        self.latest_timestamp
    }

    /// Reference time for rate/window queries: `latest_timestamp` if available, else `SystemTime::now()`.
    pub fn reference_time(&self) -> SystemTime {
        self.latest_timestamp.unwrap_or_else(SystemTime::now)
    }

    /// Iterator over per-IP statistics.
    pub fn ip_stats(&self) -> impl Iterator<Item = &IpStats> {
        self.ip_stats.values()
    }

    /// Iterator over bidirectional conversation statistics.
    pub fn conversations(&self) -> impl Iterator<Item = &ConversationStats> {
        self.conversations.values()
    }

    /// Bounded ring buffer of recently ingested packets.
    pub fn recent_packets(&self) -> &VecDeque<ParsedPacket> {
        &self.packets
    }

    /// Total `(packets, bytes)` keyed by protocol.
    pub fn protocol_totals(&self) -> &BTreeMap<Protocol, (u64, u64)> {
        &self.protocol_totals
    }

    /// Top `limit` ports sorted descending by byte count: `(port, packets, bytes)`.
    pub fn top_ports(&self, limit: usize) -> Vec<(u16, u64, u64)> {
        let mut entries: Vec<(u16, u64, u64)> = self
            .port_totals
            .iter()
            .map(|(&port, &(pkts, bytes))| (port, pkts, bytes))
            .collect();
        entries.sort_by(|a, b| {
            b.2.cmp(&a.2)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| a.0.cmp(&b.0))
        });
        entries.truncate(limit);
        entries
    }

    /// Returns `window_secs` contiguous 1-second samples ending at `end_time`.
    pub fn throughput_history(
        &self,
        end_time: SystemTime,
        window_secs: usize,
    ) -> Vec<ThroughputSample> {
        if window_secs == 0 {
            return Vec::new();
        }
        let end_sec = epoch_secs(end_time);
        let start_sec = end_sec.saturating_sub((window_secs as u64).saturating_sub(1));
        (start_sec..=end_sec)
            .map(|sec| {
                self.throughput
                    .get(&sec)
                    .copied()
                    .unwrap_or(ThroughputSample {
                        epoch_sec: sec,
                        ..Default::default()
                    })
            })
            .collect()
    }

    /// Computes `(inbound_bps, outbound_bps, total_bps)` over the 5-second window ending at `ref_time`.
    pub fn current_rates(&self, ref_time: SystemTime) -> (f64, f64, f64) {
        let ref_sec = epoch_secs(ref_time);
        let start_sec = ref_sec.saturating_sub((RATE_WINDOW_SECS as u64) - 1);
        let mut inbound = 0u64;
        let mut outbound = 0u64;
        let mut total = 0u64;

        for (_, sample) in self.throughput.range(start_sec..=ref_sec) {
            inbound = inbound.saturating_add(sample.inbound_bytes);
            outbound = outbound.saturating_add(sample.outbound_bytes);
            total = total.saturating_add(sample.total_bytes);
        }

        let denom = RATE_WINDOW_SECS as f64;
        (
            inbound as f64 / denom,
            outbound as f64 / denom,
            total as f64 / denom,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::LinkType;
    use etherparse::PacketBuilder;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn ts(sec: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(sec)
    }

    fn tcp_raw(
        sec: u64,
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        orig_len: u32,
    ) -> RawPacket {
        let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4(src, dst, 64)
            .tcp(sport, dport, 1, 1024)
            .ack(1);
        let mut data = Vec::with_capacity(builder.size(0));
        builder.write(&mut data, &[]).unwrap();
        RawPacket {
            timestamp: ts(sec),
            captured_len: data.len() as u32,
            original_len: orig_len,
            link_type: LinkType::Ethernet,
            data,
        }
    }

    #[test]
    fn ip_stats_conversations_rates_and_history() {
        let mut store = TrafficStore::new(100);
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let remote_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let other_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let other_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let mut locals = HashSet::new();
        locals.insert(local_ip);
        store.set_local_ips(locals);
        assert!(store.local_ips().contains(&local_ip));

        // Outbound: local -> remote (500B at t=1000)
        let p1 = store.ingest_raw(&tcp_raw(
            1000,
            [192, 168, 1, 10],
            [93, 184, 216, 34],
            50000,
            443,
            500,
        ));
        assert_eq!(p1.id, 1);
        assert_eq!(p1.direction, Direction::Outbound);

        // Inbound: remote -> local (1000B at t=1002)
        let p2 = store.ingest_raw(&tcp_raw(
            1002,
            [93, 184, 216, 34],
            [192, 168, 1, 10],
            443,
            50000,
            1000,
        ));
        assert_eq!(p2.id, 2);
        assert_eq!(p2.direction, Direction::Inbound);

        // Local: local -> local (200B at t=1002)
        let p3 = store.ingest_raw(&tcp_raw(
            1002,
            [192, 168, 1, 10],
            [192, 168, 1, 10],
            1111,
            2222,
            200,
        ));
        assert_eq!(p3.id, 3);
        assert_eq!(p3.direction, Direction::Local);

        // Transit: other_a -> other_b (300B at t=1004)
        let p4 = store.ingest_raw(&tcp_raw(1004, [10, 0, 0, 1], [10, 0, 0, 2], 80, 55555, 300));
        assert_eq!(p4.id, 4);
        assert_eq!(p4.direction, Direction::Transit);

        assert_eq!(store.total_packets(), 4);
        assert_eq!(store.total_bytes(), 2000);
        assert_eq!(store.latest_timestamp(), Some(ts(1004)));
        assert_eq!(store.reference_time(), ts(1004));

        // Verify per-IP sent/received
        let local_stat = store.ip_stats().find(|s| s.ip == local_ip).unwrap();
        assert_eq!(local_stat.scope, IpScope::LocalHost);
        assert_eq!(local_stat.bytes_sent, 700); // 500 + 200
        assert_eq!(local_stat.packets_sent, 2);
        assert_eq!(local_stat.bytes_received, 1200); // 1000 + 200
        assert_eq!(local_stat.packets_received, 2);
        assert_eq!(local_stat.total_bytes(), 1900);
        assert_eq!(local_stat.total_packets(), 4);
        assert!((local_stat.rate_sent_bps(ts(1004)) - 140.0).abs() < 1e-6);
        assert!((local_stat.rate_recv_bps(ts(1004)) - 240.0).abs() < 1e-6);
        assert!((local_stat.rate_total_bps(ts(1004)) - 380.0).abs() < 1e-6);

        let remote_stat = store.ip_stats().find(|s| s.ip == remote_ip).unwrap();
        assert_eq!(remote_stat.scope, IpScope::Public);
        assert_eq!(remote_stat.bytes_sent, 1000);
        assert_eq!(remote_stat.bytes_received, 500);

        // Verify bidirectional conversation aggregation
        let (expected_key, _) = ConversationKey::new(local_ip, remote_ip, Protocol::Tcp);
        assert!(expected_key.addr_a <= expected_key.addr_b);
        let conv = store
            .conversations()
            .find(|c| c.key == expected_key)
            .unwrap();
        assert_eq!(conv.total_bytes(), 1500);
        assert_eq!(conv.total_packets(), 2);
        assert!(conv.ports.contains(&443));
        assert!(conv.ports.contains(&50000));
        assert!((conv.rate_bps(ts(1004)) - 300.0).abs() < 1e-6);

        // Verify transit conversation
        let (transit_key, a_to_b) = ConversationKey::new(other_a, other_b, Protocol::Tcp);
        assert!(a_to_b);
        let transit_conv = store
            .conversations()
            .find(|c| c.key == transit_key)
            .unwrap();
        assert_eq!(transit_conv.bytes_a_to_b, 300);
        assert_eq!(transit_conv.bytes_b_to_a, 0);

        // Protocol totals
        assert_eq!(
            store.protocol_totals().get(&Protocol::Tcp),
            Some(&(4, 2000))
        );

        // Top ports
        let top = store.top_ports(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0], (443, 2, 1500));
        assert_eq!(top[1], (50000, 2, 1500));

        // Contiguous throughput history (t=1000..=1004)
        let history = store.throughput_history(ts(1004), 5);
        assert_eq!(history.len(), 5);
        assert_eq!(history[0].epoch_sec, 1000);
        assert_eq!(history[0].outbound_bytes, 500);
        assert_eq!(history[1].epoch_sec, 1001);
        assert_eq!(history[1].total_bytes, 0);
        assert_eq!(history[2].epoch_sec, 1002);
        assert_eq!(history[2].inbound_bytes, 1000);
        assert_eq!(history[2].local_bytes, 200);
        assert_eq!(history[3].epoch_sec, 1003);
        assert_eq!(history[4].epoch_sec, 1004);
        assert_eq!(history[4].transit_bytes, 300);

        // Rolling rates at t=1004 (5-sec window 1000..=1004)
        let (in_bps, out_bps, tot_bps) = store.current_rates(ts(1004));
        assert!((in_bps - 200.0).abs() < 1e-6); // 1000 / 5
        assert!((out_bps - 100.0).abs() < 1e-6); // 500 / 5
        assert!((tot_bps - 400.0).abs() < 1e-6); // 2000 / 5

        // Update local IPs dynamically -> existing IpStats scope updates
        let mut new_locals = HashSet::new();
        new_locals.insert(other_a);
        store.set_local_ips(new_locals);
        let other_a_stat = store.ip_stats().find(|s| s.ip == other_a).unwrap();
        assert_eq!(other_a_stat.scope, IpScope::LocalHost);
        let old_local_stat = store.ip_stats().find(|s| s.ip == local_ip).unwrap();
        assert_eq!(old_local_stat.scope, IpScope::Private);
    }

    #[test]
    fn bounded_ring_buffer_pruning_and_clear() {
        let mut store = TrafficStore::new(2);
        let mut locals = HashSet::new();
        locals.insert(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        store.set_local_ips(locals);

        store.ingest_raw(&tcp_raw(100, [192, 168, 1, 1], [1, 1, 1, 1], 1000, 80, 100));
        store.ingest_raw(&tcp_raw(200, [192, 168, 1, 1], [1, 1, 1, 1], 1001, 80, 100));
        store.ingest_raw(&tcp_raw(500, [192, 168, 1, 1], [1, 1, 1, 1], 1002, 80, 100));

        // Bounded to 2 most recent packets (IDs 2 and 3)
        assert_eq!(store.recent_packets().len(), 2);
        assert_eq!(store.recent_packets()[0].id, 2);
        assert_eq!(store.recent_packets()[1].id, 3);

        // Throughput history pruned past 300s (t=100 was pruned when t=500 arrived)
        assert!(!store.throughput.contains_key(&100));
        assert!(store.throughput.contains_key(&200));
        assert!(store.throughput.contains_key(&500));

        // Clear resets stats/packets/id while keeping local_ips and max_packets
        store.clear();
        assert_eq!(store.total_packets(), 0);
        assert_eq!(store.total_bytes(), 0);
        assert_eq!(store.latest_timestamp(), None);
        assert!(store.recent_packets().is_empty());
        assert_eq!(store.ip_stats().count(), 0);
        assert_eq!(store.conversations().count(), 0);
        assert!(store.protocol_totals().is_empty());
        assert!(store.top_ports(10).is_empty());
        assert!(
            store
                .local_ips()
                .contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );

        // Next ID starts back at 1
        let next = store.ingest_raw(&tcp_raw(600, [192, 168, 1, 1], [1, 1, 1, 1], 1003, 80, 50));
        assert_eq!(next.id, 1);
    }

    #[test]
    fn conversation_port_cap_and_zero_max_packets() {
        let mut store = TrafficStore::new(0);
        for port in 1..=25u16 {
            let p = store.ingest_raw(&tcp_raw(1000, [10, 0, 0, 1], [10, 0, 0, 2], port, 80, 64));
            assert_eq!(p.id, u64::from(port));
        }
        assert!(store.recent_packets().is_empty());
        let conv = store.conversations().next().unwrap();
        assert_eq!(conv.ports.len(), 16);
    }
}
