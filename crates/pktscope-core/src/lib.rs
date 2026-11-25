//! Core packet parsing, PCAP codec, traffic filtering, and live statistics engine.

pub mod filter;
pub mod packet;
pub mod pcap;
pub mod stats;

pub use filter::{TrafficFilter, ip_in_cidr, parse_cidr};
pub use packet::{
    ArpInfo, Direction, IpScope, LinkType, ParsedPacket, Protocol, RawPacket, TcpFlags,
    classify_ip, format_bytes, format_mac, format_rate, parse_packet, well_known_port_name,
};
pub use pcap::{PcapError, PcapHeader, PcapReader, PcapWriter};
pub use stats::{ConversationKey, ConversationStats, IpStats, ThroughputSample, TrafficStore};
