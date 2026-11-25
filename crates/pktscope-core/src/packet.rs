use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

use etherparse::{
    EtherType, Icmpv4Type, Icmpv6Type, LaxNetSlice, LaxSlicedPacket, LinkSlice, TransportSlice,
    VlanSlice,
};

/// Data link type (DLT) representing the link-layer framing of a captured packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkType {
    Ethernet,
    RawIp,
    LinuxSll,
    LinuxSll2,
    Unknown(u32),
}

impl LinkType {
    /// Converts a libpcap/BPF DLT integer into a [`LinkType`].
    pub fn from_dlt(dlt: u32) -> Self {
        match dlt {
            1 => Self::Ethernet,
            12 | 101 => Self::RawIp,
            113 => Self::LinuxSll,
            276 => Self::LinuxSll2,
            other => Self::Unknown(other),
        }
    }

    /// Converts this [`LinkType`] back into its canonical DLT integer.
    pub fn to_dlt(&self) -> u32 {
        match self {
            Self::Ethernet => 1,
            Self::RawIp => 101,
            Self::LinuxSll => 113,
            Self::LinuxSll2 => 276,
            Self::Unknown(dlt) => *dlt,
        }
    }
}

impl fmt::Display for LinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ethernet => write!(f, "Ethernet"),
            Self::RawIp => write!(f, "RawIp"),
            Self::LinuxSll => write!(f, "LinuxSLL"),
            Self::LinuxSll2 => write!(f, "LinuxSLL2"),
            Self::Unknown(dlt) => write!(f, "Unknown({dlt})"),
        }
    }
}

/// Raw captured packet bytes together with capture metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPacket {
    pub timestamp: SystemTime,
    pub captured_len: u32,
    pub original_len: u32,
    pub link_type: LinkType,
    pub data: Vec<u8>,
}

/// Network/transport protocol classification for a decoded packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Arp,
    Other(u8),
}

impl Protocol {
    /// Returns a human-readable protocol name.
    pub fn name(&self) -> String {
        match self {
            Self::Tcp => "TCP".to_string(),
            Self::Udp => "UDP".to_string(),
            Self::Icmp => "ICMP".to_string(),
            Self::Icmpv6 => "ICMPv6".to_string(),
            Self::Arp => "ARP".to_string(),
            Self::Other(num) => format!("Proto({num})"),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name())
    }
}

/// Traffic direction relative to the local host IP set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Inbound,
    Outbound,
    Local,
    Transit,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inbound => f.write_str("Inbound"),
            Self::Outbound => f.write_str("Outbound"),
            Self::Local => f.write_str("Local"),
            Self::Transit => f.write_str("Transit"),
        }
    }
}

/// Scope classification of an IP address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpScope {
    LocalHost,
    Loopback,
    Private,
    LinkLocal,
    Multicast,
    Public,
}

impl fmt::Display for IpScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalHost => f.write_str("LocalHost"),
            Self::Loopback => f.write_str("Loopback"),
            Self::Private => f.write_str("Private"),
            Self::LinkLocal => f.write_str("LinkLocal"),
            Self::Multicast => f.write_str("Multicast"),
            Self::Public => f.write_str("Public"),
        }
    }
}

/// Classifies an IP address into an [`IpScope`] given the set of local interface IPs.
pub fn classify_ip(ip: IpAddr, local_ips: &HashSet<IpAddr>) -> IpScope {
    if local_ips.contains(&ip) {
        return IpScope::LocalHost;
    }

    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                IpScope::Loopback
            } else if v4.is_private() {
                IpScope::Private
            } else if v4.is_link_local() {
                IpScope::LinkLocal
            } else if v4.is_multicast() {
                IpScope::Multicast
            } else {
                IpScope::Public
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                IpScope::Loopback
            } else if (v6.segments()[0] & 0xfe00) == 0xfc00 {
                // RFC 4193 Unique Local IPv6 Unicast Addresses (fc00::/7)
                IpScope::Private
            } else if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                // RFC 4291 Link-Local Unicast Addresses (fe80::/10)
                IpScope::LinkLocal
            } else if v6.is_multicast() {
                IpScope::Multicast
            } else {
                IpScope::Public
            }
        }
    }
}

/// Decoded TCP control flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

impl TcpFlags {
    /// Formats set TCP flags as a compact comma-separated string (e.g. `"SYN,ACK"`).
    pub fn format_short(&self) -> String {
        let mut parts = Vec::with_capacity(6);
        if self.syn {
            parts.push("SYN");
        }
        if self.ack {
            parts.push("ACK");
        }
        if self.fin {
            parts.push("FIN");
        }
        if self.rst {
            parts.push("RST");
        }
        if self.psh {
            parts.push("PSH");
        }
        if self.urg {
            parts.push("URG");
        }
        parts.join(",")
    }
}

/// Decoded IPv4-over-Ethernet ARP payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArpInfo {
    pub opcode: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

/// Decoded representation of a captured network packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPacket {
    pub id: u64,
    pub timestamp: SystemTime,
    pub captured_len: u32,
    pub original_len: u32,
    pub link_type: LinkType,
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
    pub vlan_id: Option<u16>,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Protocol,
    pub ttl: Option<u8>,
    pub tcp_flags: Option<TcpFlags>,
    pub icmp_summary: Option<String>,
    pub arp: Option<ArpInfo>,
    pub direction: Direction,
    pub info: String,
}

const ETHER_TYPE_ARP: u16 = 0x0806;
const ETHER_TYPE_VLAN: u16 = 0x8100;
const ETHER_TYPE_QINQ: u16 = 0x88a8;
const ETHER_TYPE_QINQ_OLD: u16 = 0x9100;

/// Decodes a [`RawPacket`] into a [`ParsedPacket`], never panicking on malformed or truncated data.
pub fn parse_packet(raw: &RawPacket, local_ips: &HashSet<IpAddr>) -> ParsedPacket {
    let mut pkt = ParsedPacket {
        id: 0,
        timestamp: raw.timestamp,
        captured_len: raw.captured_len,
        original_len: raw.original_len,
        link_type: raw.link_type,
        src_mac: None,
        dst_mac: None,
        vlan_id: None,
        src_ip: None,
        dst_ip: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Other(0),
        ttl: None,
        tcp_flags: None,
        icmp_summary: None,
        arp: None,
        direction: Direction::Transit,
        info: String::new(),
    };

    let data = raw.data.as_slice();
    match raw.link_type {
        LinkType::Ethernet => decode_ethernet_or_ether_payload(data, &mut pkt),
        LinkType::RawIp => {
            if let Ok(sliced) = LaxSlicedPacket::from_ip(data) {
                populate_from_lax_slice(&sliced, &mut pkt);
            } else {
                pkt.info = format!("Malformed RawIP ({}B)", data.len());
            }
        }
        LinkType::LinuxSll => decode_linux_sll(data, &mut pkt),
        LinkType::LinuxSll2 => decode_linux_sll2(data, &mut pkt),
        LinkType::Unknown(dlt) => {
            pkt.info = format!("Unknown link type DLT={dlt} ({}B)", data.len());
        }
    }

    pkt.direction = compute_direction(pkt.src_ip, pkt.dst_ip, local_ips);
    if pkt.info.is_empty() {
        pkt.info = format_packet_info(&pkt);
    }
    pkt
}

fn decode_ethernet_or_ether_payload(data: &[u8], pkt: &mut ParsedPacket) {
    if data.len() < 14 {
        pkt.info = format!("Truncated Ethernet ({}B)", data.len());
        return;
    }

    if let Ok(sliced) = LaxSlicedPacket::from_ethernet(data) {
        if let Some(LinkSlice::Ethernet2(eth)) = sliced.link.as_ref() {
            pkt.dst_mac = Some(eth.destination());
            pkt.src_mac = Some(eth.source());
        }
        pkt.vlan_id = extract_vlan_id(sliced.vlan.as_ref());

        if let Some(ether_payload) = sliced.ether_payload()
            && ether_payload.ether_type == EtherType::ARP
        {
            decode_arp(ether_payload.payload, pkt);
            return;
        }

        populate_from_lax_slice(&sliced, pkt);
    } else {
        pkt.info = format!("Malformed Ethernet ({}B)", data.len());
    }
}

fn decode_linux_sll(data: &[u8], pkt: &mut ParsedPacket) {
    if data.len() < 16 {
        pkt.info = format!("Truncated LinuxSLL ({}B)", data.len());
        return;
    }
    let addr_len = u16::from_be_bytes([data[4], data[5]]);
    if addr_len == 6 {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&data[6..12]);
        pkt.src_mac = Some(mac);
    }
    let ether_type = u16::from_be_bytes([data[14], data[15]]);
    decode_ether_type_payload(ether_type, &data[16..], pkt);
}

fn decode_linux_sll2(data: &[u8], pkt: &mut ParsedPacket) {
    if data.len() < 20 {
        pkt.info = format!("Truncated LinuxSLL2 ({}B)", data.len());
        return;
    }
    let ether_type = u16::from_be_bytes([data[0], data[1]]);
    let addr_len = data[11];
    if addr_len == 6 {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&data[12..18]);
        pkt.src_mac = Some(mac);
    }
    decode_ether_type_payload(ether_type, &data[20..], pkt);
}

fn decode_ether_type_payload(mut ether_type: u16, mut payload: &[u8], pkt: &mut ParsedPacket) {
    // Strip up to 2 VLAN tags if present inside SLL/SLL2.
    for _ in 0..2 {
        if matches!(
            ether_type,
            ETHER_TYPE_VLAN | ETHER_TYPE_QINQ | ETHER_TYPE_QINQ_OLD
        ) {
            if payload.len() < 4 {
                pkt.info = format!("Truncated VLAN ({}B)", payload.len());
                return;
            }
            let tci = u16::from_be_bytes([payload[0], payload[1]]);
            pkt.vlan_id = Some(tci & 0x0fff);
            ether_type = u16::from_be_bytes([payload[2], payload[3]]);
            payload = &payload[4..];
        } else {
            break;
        }
    }

    if ether_type == ETHER_TYPE_ARP {
        decode_arp(payload, pkt);
        return;
    }

    let sliced = LaxSlicedPacket::from_ether_type(EtherType(ether_type), payload);
    if pkt.vlan_id.is_none() {
        pkt.vlan_id = extract_vlan_id(sliced.vlan.as_ref());
    }
    populate_from_lax_slice(&sliced, pkt);
    if pkt.src_ip.is_none() && pkt.info.is_empty() {
        pkt.info = format!("EtherType 0x{ether_type:04x} ({}B)", payload.len());
    }
}

fn extract_vlan_id(vlan: Option<&VlanSlice<'_>>) -> Option<u16> {
    vlan.map(|v| match v {
        VlanSlice::SingleVlan(s) => s.vlan_identifier().value(),
        VlanSlice::DoubleVlan(d) => d.inner().vlan_identifier().value(),
    })
}

fn decode_arp(payload: &[u8], pkt: &mut ParsedPacket) {
    pkt.protocol = Protocol::Arp;
    if payload.len() < 28 {
        pkt.info = format!("Truncated ARP ({}B)", payload.len());
        return;
    }

    let hw_type = u16::from_be_bytes([payload[0], payload[1]]);
    let proto_type = u16::from_be_bytes([payload[2], payload[3]]);
    let hw_len = payload[4];
    let proto_len = payload[5];
    let opcode = u16::from_be_bytes([payload[6], payload[7]]);

    if hw_type != 1 || proto_type != 0x0800 || hw_len != 6 || proto_len != 4 {
        pkt.info = format!("ARP (hw={hw_type}, proto=0x{proto_type:04x}, op={opcode})");
        return;
    }

    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&payload[8..14]);
    let sender_ip = Ipv4Addr::new(payload[14], payload[15], payload[16], payload[17]);

    let mut target_mac = [0u8; 6];
    target_mac.copy_from_slice(&payload[18..24]);
    let target_ip = Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]);

    pkt.src_ip = Some(IpAddr::V4(sender_ip));
    pkt.dst_ip = Some(IpAddr::V4(target_ip));
    pkt.arp = Some(ArpInfo {
        opcode,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    });

    pkt.info = match opcode {
        1 => format!("ARP Request: Who has {target_ip}? Tell {sender_ip}"),
        2 => format!("ARP Reply: {sender_ip} is at {}", format_mac(sender_mac)),
        _ => format!("ARP op={opcode} {sender_ip} -> {target_ip}"),
    };
}

fn populate_from_lax_slice(sliced: &LaxSlicedPacket<'_>, pkt: &mut ParsedPacket) {
    let mut ip_proto_num: Option<u8> = None;

    if let Some(net) = sliced.net.as_ref() {
        match net {
            LaxNetSlice::Ipv4(ipv4) => {
                let hdr = ipv4.header();
                pkt.src_ip = Some(IpAddr::V4(hdr.source_addr()));
                pkt.dst_ip = Some(IpAddr::V4(hdr.destination_addr()));
                pkt.ttl = Some(hdr.ttl());
                ip_proto_num = Some(ipv4.payload().ip_number.0);
            }
            LaxNetSlice::Ipv6(ipv6) => {
                let hdr = ipv6.header();
                pkt.src_ip = Some(IpAddr::V6(hdr.source_addr()));
                pkt.dst_ip = Some(IpAddr::V6(hdr.destination_addr()));
                pkt.ttl = Some(hdr.hop_limit());
                ip_proto_num = Some(ipv6.payload().ip_number.0);
            }
            LaxNetSlice::Arp(arp) => {
                decode_arp(arp.slice(), pkt);
                return;
            }
        }
    }

    match sliced.transport.as_ref() {
        Some(TransportSlice::Tcp(tcp)) => {
            pkt.protocol = Protocol::Tcp;
            pkt.src_port = Some(tcp.source_port());
            pkt.dst_port = Some(tcp.destination_port());
            pkt.tcp_flags = Some(TcpFlags {
                syn: tcp.syn(),
                ack: tcp.ack(),
                fin: tcp.fin(),
                rst: tcp.rst(),
                psh: tcp.psh(),
                urg: tcp.urg(),
            });
        }
        Some(TransportSlice::Udp(udp)) => {
            pkt.protocol = Protocol::Udp;
            pkt.src_port = Some(udp.source_port());
            pkt.dst_port = Some(udp.destination_port());
        }
        Some(TransportSlice::Icmpv4(icmp)) => {
            pkt.protocol = Protocol::Icmp;
            pkt.icmp_summary = Some(describe_icmpv4(&icmp.icmp_type()));
        }
        Some(TransportSlice::Icmpv6(icmp6)) => {
            pkt.protocol = Protocol::Icmpv6;
            pkt.icmp_summary = Some(describe_icmpv6(&icmp6.icmp_type()));
        }
        None => {
            if let Some(num) = ip_proto_num {
                pkt.protocol = protocol_from_ip_number(num);
            }
        }
    }
}

fn protocol_from_ip_number(num: u8) -> Protocol {
    match num {
        1 => Protocol::Icmp,
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        58 => Protocol::Icmpv6,
        other => Protocol::Other(other),
    }
}

fn describe_icmpv4(icmp_type: &Icmpv4Type) -> String {
    match icmp_type {
        Icmpv4Type::EchoRequest(h) => format!("Echo Request id={} seq={}", h.id, h.seq),
        Icmpv4Type::EchoReply(h) => format!("Echo Reply id={} seq={}", h.id, h.seq),
        Icmpv4Type::DestinationUnreachable(_) => "Destination Unreachable".to_string(),
        Icmpv4Type::Redirect(_) => "Redirect".to_string(),
        Icmpv4Type::TimeExceeded(_) => "Time Exceeded".to_string(),
        Icmpv4Type::ParameterProblem(_) => "Parameter Problem".to_string(),
        Icmpv4Type::TimestampRequest(_) => "Timestamp Request".to_string(),
        Icmpv4Type::TimestampReply(_) => "Timestamp Reply".to_string(),
        Icmpv4Type::Unknown {
            type_u8, code_u8, ..
        } => format!("ICMP type={type_u8} code={code_u8}"),
    }
}

fn describe_icmpv6(icmp_type: &Icmpv6Type) -> String {
    match icmp_type {
        Icmpv6Type::EchoRequest(h) => format!("Echo Request id={} seq={}", h.id, h.seq),
        Icmpv6Type::EchoReply(h) => format!("Echo Reply id={} seq={}", h.id, h.seq),
        Icmpv6Type::DestinationUnreachable(_) => "Destination Unreachable".to_string(),
        Icmpv6Type::PacketTooBig { mtu } => format!("Packet Too Big mtu={mtu}"),
        Icmpv6Type::TimeExceeded(_) => "Time Exceeded".to_string(),
        Icmpv6Type::ParameterProblem(_) => "Parameter Problem".to_string(),
        Icmpv6Type::Unknown {
            type_u8, code_u8, ..
        } => format!("ICMPv6 type={type_u8} code={code_u8}"),
    }
}

fn compute_direction(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    local_ips: &HashSet<IpAddr>,
) -> Direction {
    let src_local = src_ip.is_some_and(|ip| local_ips.contains(&ip));
    let dst_local = dst_ip.is_some_and(|ip| local_ips.contains(&ip));
    match (src_local, dst_local) {
        (true, true) => Direction::Local,
        (true, false) => Direction::Outbound,
        (false, true) => Direction::Inbound,
        (false, false) => Direction::Transit,
    }
}

fn format_packet_info(pkt: &ParsedPacket) -> String {
    match pkt.protocol {
        Protocol::Tcp => {
            let ports = match (pkt.src_port, pkt.dst_port) {
                (Some(s), Some(d)) => {
                    let svc = well_known_port_name(d).or_else(|| well_known_port_name(s));
                    match svc {
                        Some(name) => format!("{s} -> {d} ({name})"),
                        None => format!("{s} -> {d}"),
                    }
                }
                _ => "TCP".to_string(),
            };
            match pkt.tcp_flags.as_ref().map(TcpFlags::format_short) {
                Some(flags) if !flags.is_empty() => format!("{ports} [{flags}]"),
                _ => ports,
            }
        }
        Protocol::Udp => match (pkt.src_port, pkt.dst_port) {
            (Some(s), Some(d)) => {
                let svc = well_known_port_name(d).or_else(|| well_known_port_name(s));
                match svc {
                    Some(name) => format!("{s} -> {d} ({name})"),
                    None => format!("{s} -> {d}"),
                }
            }
            _ => "UDP".to_string(),
        },
        Protocol::Icmp | Protocol::Icmpv6 => pkt
            .icmp_summary
            .clone()
            .unwrap_or_else(|| pkt.protocol.name()),
        Protocol::Arp => "ARP".to_string(),
        Protocol::Other(num) => match (pkt.src_ip, pkt.dst_ip) {
            (Some(s), Some(d)) => format!("Proto({num}) {s} -> {d}"),
            _ => format!("Proto({num}) ({}B)", pkt.original_len),
        },
    }
}

/// Maps well-known TCP/UDP port numbers to service names.
pub fn well_known_port_name(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("FTP-DATA"),
        21 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("TELNET"),
        25 => Some("SMTP"),
        53 => Some("DNS"),
        67 | 68 => Some("DHCP"),
        69 => Some("TFTP"),
        80 => Some("HTTP"),
        110 => Some("POP3"),
        123 => Some("NTP"),
        143 => Some("IMAP"),
        161 | 162 => Some("SNMP"),
        389 => Some("LDAP"),
        443 => Some("HTTPS"),
        445 => Some("SMB"),
        465 => Some("SMTPS"),
        514 => Some("SYSLOG"),
        587 => Some("SUBMISSION"),
        636 => Some("LDAPS"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        1433 => Some("MSSQL"),
        3306 => Some("MYSQL"),
        3389 => Some("RDP"),
        5353 => Some("MDNS"),
        5432 => Some("POSTGRES"),
        6379 => Some("REDIS"),
        8080 => Some("HTTP-ALT"),
        8443 => Some("HTTPS-ALT"),
        _ => None,
    }
}

/// Formats a 6-byte MAC address in lowercase colon-separated hex.
pub fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Formats a byte count into a human-readable string (`B`, `KB`, `MB`, `GB`, `TB`).
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;

    let b = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if b < MB {
        format!("{:.1} KB", b / KB)
    } else if b < GB {
        format!("{:.1} MB", b / MB)
    } else if b < TB {
        format!("{:.1} GB", b / GB)
    } else {
        format!("{:.1} TB", b / TB)
    }
}

/// Formats a byte-per-second rate into a human-readable string.
pub fn format_rate(bytes_per_sec: f64) -> String {
    let clamped = if bytes_per_sec.is_finite() && bytes_per_sec > 0.0 {
        bytes_per_sec
    } else {
        0.0
    };
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    if clamped < KB {
        format!("{:.0} B/s", clamped)
    } else if clamped < MB {
        format!("{:.1} KB/s", clamped / KB)
    } else if clamped < GB {
        format!("{:.1} MB/s", clamped / MB)
    } else {
        format!("{:.1} GB/s", clamped / GB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use std::net::Ipv6Addr;

    fn make_raw(link_type: LinkType, data: Vec<u8>) -> RawPacket {
        RawPacket {
            timestamp: SystemTime::UNIX_EPOCH,
            captured_len: data.len() as u32,
            original_len: data.len() as u32,
            link_type,
            data,
        }
    }

    #[test]
    fn link_type_dlt_round_trip() {
        assert_eq!(LinkType::from_dlt(1), LinkType::Ethernet);
        assert_eq!(LinkType::Ethernet.to_dlt(), 1);
        assert_eq!(LinkType::from_dlt(12), LinkType::RawIp);
        assert_eq!(LinkType::from_dlt(101), LinkType::RawIp);
        assert_eq!(LinkType::RawIp.to_dlt(), 101);
        assert_eq!(LinkType::from_dlt(113), LinkType::LinuxSll);
        assert_eq!(LinkType::LinuxSll.to_dlt(), 113);
        assert_eq!(LinkType::from_dlt(276), LinkType::LinuxSll2);
        assert_eq!(LinkType::LinuxSll2.to_dlt(), 276);
        assert_eq!(LinkType::from_dlt(999), LinkType::Unknown(999));
        assert_eq!(LinkType::Unknown(999).to_dlt(), 999);
    }

    #[test]
    fn parse_ethernet_ipv4_tcp_syn_ack() {
        let src_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
        let dst_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
            .ipv4([192, 168, 1, 10], [93, 184, 216, 34], 64)
            .tcp(443, 54321, 1000, 65535)
            .syn()
            .ack(2000);
        let mut frame = Vec::with_capacity(builder.size(0));
        builder.write(&mut frame, &[]).unwrap();

        let mut locals = HashSet::new();
        locals.insert(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));

        let pkt = parse_packet(&make_raw(LinkType::Ethernet, frame), &locals);
        assert_eq!(pkt.src_mac, Some(src_mac));
        assert_eq!(pkt.dst_mac, Some(dst_mac));
        assert_eq!(pkt.vlan_id, None);
        assert_eq!(pkt.src_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))));
        assert_eq!(
            pkt.dst_ip,
            Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
        );
        assert_eq!(pkt.src_port, Some(443));
        assert_eq!(pkt.dst_port, Some(54321));
        assert_eq!(pkt.protocol, Protocol::Tcp);
        assert_eq!(pkt.ttl, Some(64));
        assert_eq!(pkt.direction, Direction::Outbound);
        let flags = pkt.tcp_flags.expect("tcp_flags");
        assert!(flags.syn && flags.ack && !flags.fin && !flags.rst);
        assert_eq!(flags.format_short(), "SYN,ACK");
        assert!(pkt.info.contains("HTTPS"));
    }

    #[test]
    fn parse_ethernet_vlan_ipv4_udp_dns() {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1])
            .single_vlan(etherparse::VlanId::try_new(42).unwrap())
            .ipv4([10, 0, 0, 5], [8, 8, 8, 8], 128)
            .udp(55123, 53);
        let mut frame = Vec::with_capacity(builder.size(4));
        builder.write(&mut frame, &[1, 2, 3, 4]).unwrap();

        let pkt = parse_packet(&make_raw(LinkType::Ethernet, frame), &HashSet::new());
        assert_eq!(pkt.vlan_id, Some(42));
        assert_eq!(pkt.protocol, Protocol::Udp);
        assert_eq!(pkt.src_port, Some(55123));
        assert_eq!(pkt.dst_port, Some(53));
        assert_eq!(pkt.ttl, Some(128));
        assert_eq!(pkt.direction, Direction::Transit);
        assert!(pkt.info.contains("DNS"));
    }

    #[test]
    fn parse_ethernet_ipv6_icmpv6() {
        let src_v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let dst_v6 = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let builder = PacketBuilder::ethernet2([0; 6], [1; 6])
            .ipv6(src_v6.octets(), dst_v6.octets(), 64)
            .icmpv6_echo_request(7, 9);
        let mut frame = Vec::with_capacity(builder.size(4));
        builder
            .write(&mut frame, &[0xde, 0xad, 0xbe, 0xef])
            .unwrap();

        let mut locals = HashSet::new();
        locals.insert(IpAddr::V6(dst_v6));

        let pkt = parse_packet(&make_raw(LinkType::Ethernet, frame), &locals);
        assert_eq!(pkt.protocol, Protocol::Icmpv6);
        assert_eq!(pkt.src_ip, Some(IpAddr::V6(src_v6)));
        assert_eq!(pkt.dst_ip, Some(IpAddr::V6(dst_v6)));
        assert_eq!(pkt.ttl, Some(64));
        assert_eq!(pkt.direction, Direction::Inbound);
        assert_eq!(pkt.icmp_summary.as_deref(), Some("Echo Request id=7 seq=9"));
    }

    #[test]
    fn parse_ethernet_arp_request() {
        let sender_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut frame = Vec::with_capacity(42);
        frame.extend_from_slice(&[0xff; 6]); // dst broadcast
        frame.extend_from_slice(&sender_mac);
        frame.extend_from_slice(&0x0806u16.to_be_bytes()); // ARP
        // ARP header + addresses (28 bytes)
        frame.extend_from_slice(&1u16.to_be_bytes()); // Ethernet
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        frame.push(6);
        frame.push(4);
        frame.extend_from_slice(&1u16.to_be_bytes()); // opcode 1 = request
        frame.extend_from_slice(&sender_mac);
        frame.extend_from_slice(&[192, 168, 1, 20]);
        frame.extend_from_slice(&[0x00; 6]);
        frame.extend_from_slice(&[192, 168, 1, 1]);

        let pkt = parse_packet(&make_raw(LinkType::Ethernet, frame), &HashSet::new());
        assert_eq!(pkt.protocol, Protocol::Arp);
        assert_eq!(pkt.src_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))));
        assert_eq!(pkt.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        let arp = pkt.arp.expect("arp info");
        assert_eq!(arp.opcode, 1);
        assert_eq!(arp.sender_mac, sender_mac);
        assert_eq!(arp.target_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert!(pkt.info.contains("ARP Request"));
    }

    #[test]
    fn parse_linux_sll_ipv4_icmp() {
        let mut ip_buf = Vec::new();
        PacketBuilder::ipv4([10, 1, 2, 3], [10, 1, 2, 4], 64)
            .icmpv4_echo_request(11, 22)
            .write(&mut ip_buf, &[1, 2, 3, 4])
            .unwrap();

        let mut frame = vec![0u8; 16];
        frame[4..6].copy_from_slice(&6u16.to_be_bytes()); // addr_len = 6
        frame[6..12].copy_from_slice(&[0xde, 0xad, 0x00, 0x00, 0x00, 0x01]);
        frame[14..16].copy_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&ip_buf);

        let mut locals = HashSet::new();
        locals.insert(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
        locals.insert(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 4)));

        let pkt = parse_packet(&make_raw(LinkType::LinuxSll, frame), &locals);
        assert_eq!(pkt.protocol, Protocol::Icmp);
        assert_eq!(pkt.src_mac, Some([0xde, 0xad, 0x00, 0x00, 0x00, 0x01]));
        assert_eq!(pkt.direction, Direction::Local);
        assert_eq!(
            pkt.icmp_summary.as_deref(),
            Some("Echo Request id=11 seq=22")
        );
    }

    #[test]
    fn parse_linux_sll2_ipv4_tcp() {
        let mut ip_buf = Vec::new();
        PacketBuilder::ipv4([172, 16, 0, 2], [172, 16, 0, 1], 55)
            .tcp(12345, 22, 1, 1024)
            .psh()
            .ack(5)
            .write(&mut ip_buf, b"ssh")
            .unwrap();

        let mut frame = vec![0u8; 20];
        frame[0..2].copy_from_slice(&0x0800u16.to_be_bytes()); // EtherType at 0..2
        frame[11] = 6; // addr_len
        frame[12..18].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        frame.extend_from_slice(&ip_buf);

        let pkt = parse_packet(&make_raw(LinkType::LinuxSll2, frame), &HashSet::new());
        assert_eq!(pkt.protocol, Protocol::Tcp);
        assert_eq!(pkt.src_port, Some(12345));
        assert_eq!(pkt.dst_port, Some(22));
        assert_eq!(pkt.src_mac, Some([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        let flags = pkt.tcp_flags.unwrap();
        assert!(flags.psh && flags.ack && !flags.syn);
    }

    #[test]
    fn parse_raw_ip_udp() {
        let mut frame = Vec::new();
        PacketBuilder::ipv4([1, 1, 1, 1], [2, 2, 2, 2], 32)
            .udp(1000, 2000)
            .write(&mut frame, b"hello")
            .unwrap();

        let pkt = parse_packet(&make_raw(LinkType::RawIp, frame), &HashSet::new());
        assert_eq!(pkt.src_mac, None);
        assert_eq!(pkt.protocol, Protocol::Udp);
        assert_eq!(pkt.src_ip, Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert_eq!(pkt.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))));
        assert_eq!(pkt.src_port, Some(1000));
        assert_eq!(pkt.dst_port, Some(2000));
    }

    #[test]
    fn parse_empty_and_truncated_never_panics() {
        let locals = HashSet::new();
        for lt in [
            LinkType::Ethernet,
            LinkType::RawIp,
            LinkType::LinuxSll,
            LinkType::LinuxSll2,
            LinkType::Unknown(42),
        ] {
            let empty = parse_packet(&make_raw(lt, vec![]), &locals);
            assert!(!empty.info.is_empty());

            let short = parse_packet(&make_raw(lt, vec![0x45, 0x00, 0x00]), &locals);
            assert!(!short.info.is_empty());
        }

        // Truncated ARP
        let mut trunc_arp = vec![0u8; 20];
        trunc_arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        let arp_pkt = parse_packet(&make_raw(LinkType::Ethernet, trunc_arp), &locals);
        assert_eq!(arp_pkt.protocol, Protocol::Arp);
        assert!(arp_pkt.arp.is_none());
    }

    #[test]
    fn classify_ip_scopes_and_formatters() {
        let mut locals = HashSet::new();
        let local_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        locals.insert(local_v4);

        assert_eq!(classify_ip(local_v4, &locals), IpScope::LocalHost);
        assert_eq!(
            classify_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), &locals),
            IpScope::Loopback
        );
        assert_eq!(
            classify_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &locals),
            IpScope::Private
        );
        assert_eq!(
            classify_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)), &locals),
            IpScope::LinkLocal
        );
        assert_eq!(
            classify_ip(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), &locals),
            IpScope::Multicast
        );
        assert_eq!(
            classify_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), &locals),
            IpScope::Public
        );
        assert_eq!(
            classify_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), &locals),
            IpScope::Loopback
        );
        assert_eq!(
            classify_ip(IpAddr::V6("fd00::1".parse().unwrap()), &locals),
            IpScope::Private
        );
        assert_eq!(
            classify_ip(IpAddr::V6("fe80::1".parse().unwrap()), &locals),
            IpScope::LinkLocal
        );
        assert_eq!(
            classify_ip(IpAddr::V6("ff02::1".parse().unwrap()), &locals),
            IpScope::Multicast
        );
        assert_eq!(
            classify_ip(IpAddr::V6("2001:4860:4860::8888".parse().unwrap()), &locals),
            IpScope::Public
        );

        assert_eq!(
            format_mac([0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f]),
            "0a:1b:2c:3d:4e:5f"
        );
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.0 KB");
        assert_eq!(format_rate(1536.0), "1.5 KB/s");
        assert_eq!(well_known_port_name(53), Some("DNS"));
        assert_eq!(well_known_port_name(65432), None);
    }
}
