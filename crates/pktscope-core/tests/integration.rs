use std::collections::HashSet;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, UNIX_EPOCH};

use etherparse::PacketBuilder;
use pktscope_core::{
    Direction, LinkType, PcapReader, PcapWriter, Protocol, RawPacket, TrafficFilter, TrafficStore,
};

#[test]
fn pcap_round_trip_to_store_and_filter() {
    let local_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 5));
    let mut local_ips = HashSet::new();
    local_ips.insert(local_ip);

    let mut tcp_bytes = Vec::new();
    PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
        .ipv4([192, 168, 10, 5], [1, 1, 1, 1], 64)
        .tcp(49152, 443, 10, 4096)
        .syn()
        .write(&mut tcp_bytes, &[])
        .unwrap();

    let mut udp_bytes = Vec::new();
    PacketBuilder::ethernet2([6, 7, 8, 9, 10, 11], [0, 1, 2, 3, 4, 5])
        .ipv4([8, 8, 8, 8], [192, 168, 10, 5], 56)
        .udp(53, 53000)
        .write(&mut udp_bytes, &[0x12, 0x34])
        .unwrap();

    let raw1 = RawPacket {
        timestamp: UNIX_EPOCH + Duration::from_secs(1_700_000_010),
        captured_len: tcp_bytes.len() as u32,
        original_len: tcp_bytes.len() as u32,
        link_type: LinkType::Ethernet,
        data: tcp_bytes,
    };
    let raw2 = RawPacket {
        timestamp: UNIX_EPOCH + Duration::from_secs(1_700_000_012),
        captured_len: udp_bytes.len() as u32,
        original_len: udp_bytes.len() as u32,
        link_type: LinkType::Ethernet,
        data: udp_bytes,
    };

    let mut pcap_buf = Vec::new();
    {
        let mut writer = PcapWriter::new(&mut pcap_buf, LinkType::Ethernet, 65535).unwrap();
        writer.write_packet(&raw1).unwrap();
        writer.write_packet(&raw2).unwrap();
        writer.flush().unwrap();
    }

    let mut reader = PcapReader::new(Cursor::new(&pcap_buf)).unwrap();
    let mut store = TrafficStore::new(16);
    store.set_local_ips(local_ips);

    while let Some(raw) = reader.next_packet().unwrap() {
        store.ingest_raw(&raw);
    }

    assert_eq!(store.total_packets(), 2);
    assert_eq!(store.recent_packets().len(), 2);

    let outbound_https = TrafficFilter {
        ip_query: "192.168.10.0/24".to_string(),
        port: Some(443),
        protocol: Some(Protocol::Tcp),
        direction: Some(Direction::Outbound),
    };
    let matched: Vec<_> = store
        .recent_packets()
        .iter()
        .filter(|p| outbound_https.matches_packet(p))
        .collect();
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].id, 1);

    let dns_inbound = TrafficFilter {
        port: Some(53),
        direction: Some(Direction::Inbound),
        ..Default::default()
    };
    let matched_dns: Vec<_> = store
        .recent_packets()
        .iter()
        .filter(|p| dns_inbound.matches_packet(p))
        .collect();
    assert_eq!(matched_dns.len(), 1);
    assert_eq!(matched_dns[0].id, 2);
}
