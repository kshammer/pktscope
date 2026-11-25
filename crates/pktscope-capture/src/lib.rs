//! Modular packet capture backends (Linux AF_PACKET, PCAP files, and streaming stdin).

pub mod linux;
pub mod pcap_source;
pub mod source;

pub use linux::{LinuxLiveSource, all_local_ips, list_interfaces};
pub use pcap_source::{PcapFileSource, PcapStreamSource};
pub use source::{
    CaptureConfig, CaptureError, CaptureEvent, CaptureHandle, InterfaceInfo, NextPacket,
    PacketSource,
};
