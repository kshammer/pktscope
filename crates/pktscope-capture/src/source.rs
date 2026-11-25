use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use pktscope_core::{PcapError, RawPacket};
use thiserror::Error;

const CAPTURE_CHANNEL_CAPACITY: usize = 8192;
const BACKPRESSURE_SLEEP: Duration = Duration::from_millis(2);

/// Errors returned by packet capture sources and interface discovery.
#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("permission denied on interface '{interface}': {hint}")]
    PermissionDenied { interface: String, hint: String },

    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PCAP error: {0}")]
    Pcap(#[from] PcapError),

    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),
}

/// Metadata describing a host network interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub name: String,
    pub index: u32,
    pub is_up: bool,
    pub is_loopback: bool,
    pub is_running: bool,
    pub ips: Vec<IpAddr>,
}

/// Configuration for opening a live capture source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfig {
    /// Interface name to capture on; `None` or `Some("any")` captures across all interfaces.
    pub interface: Option<String>,
    pub promiscuous: bool,
    pub snaplen: usize,
    pub read_timeout: Duration,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: None,
            promiscuous: false,
            snaplen: 65535,
            read_timeout: Duration::from_millis(200),
        }
    }
}

/// Result of a single poll on a [`PacketSource`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextPacket {
    Packet(RawPacket),
    Timeout,
    Eof,
}

/// Events emitted by a background [`CaptureHandle`] thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureEvent {
    Packet(RawPacket),
    EndOfStream,
    Error(String),
}

/// Abstraction over live, file-based, or streaming packet capture sources.
pub trait PacketSource: Send {
    /// Reads the next packet, returning [`NextPacket::Timeout`] on read timeout or [`NextPacket::Eof`] at end of stream.
    fn next_packet(&mut self) -> Result<NextPacket, CaptureError>;

    /// Human-readable label identifying this source (e.g. interface name or filename).
    fn source_label(&self) -> String;

    /// Set of local IP addresses associated with this capture source.
    fn local_ips(&self) -> HashSet<IpAddr> {
        HashSet::new()
    }
}

struct RunningGuard(Arc<AtomicBool>);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Background runner driving a [`PacketSource`] and streaming [`CaptureEvent`]s over a bounded channel.
pub struct CaptureHandle {
    source_label: String,
    stop_flag: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl CaptureHandle {
    /// Spawns a background thread reading from `source` and returns the handle alongside the event receiver.
    pub fn start<S: PacketSource + 'static>(mut source: S) -> (Self, mpsc::Receiver<CaptureEvent>) {
        let (tx, rx) = mpsc::sync_channel(CAPTURE_CHANNEL_CAPACITY);
        let source_label = source.source_label();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let running = Arc::new(AtomicBool::new(true));

        let thread_stop = Arc::clone(&stop_flag);
        let thread_running = Arc::clone(&running);

        let thread = thread::spawn(move || {
            let _guard = RunningGuard(thread_running);

            while !thread_stop.load(Ordering::Acquire) {
                match source.next_packet() {
                    Ok(NextPacket::Packet(pkt)) => {
                        if !send_event(&tx, &thread_stop, CaptureEvent::Packet(pkt)) {
                            break;
                        }
                    }
                    Ok(NextPacket::Timeout) => continue,
                    Ok(NextPacket::Eof) => {
                        let _ = send_event(&tx, &thread_stop, CaptureEvent::EndOfStream);
                        break;
                    }
                    Err(err) => {
                        let _ = send_event(&tx, &thread_stop, CaptureEvent::Error(err.to_string()));
                        break;
                    }
                }
            }
        });

        let handle = Self {
            source_label,
            stop_flag,
            running,
            thread: Some(thread),
        };
        (handle, rx)
    }

    /// Returns the label of the underlying packet source.
    pub fn source_label(&self) -> &str {
        &self.source_label
    }

    /// Returns `true` if the background capture thread has not exited yet.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// Signals the background capture thread to stop and waits for it to exit.
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::Release);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        self.running.store(false, Ordering::Release);
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

fn send_event(
    tx: &mpsc::SyncSender<CaptureEvent>,
    stop_flag: &AtomicBool,
    mut event: CaptureEvent,
) -> bool {
    loop {
        if stop_flag.load(Ordering::Acquire) {
            return false;
        }
        match tx.try_send(event) {
            Ok(()) => return true,
            Err(mpsc::TrySendError::Full(returned)) => {
                event = returned;
                if stop_flag.load(Ordering::Acquire) {
                    return false;
                }
                thread::sleep(BACKPRESSURE_SLEEP);
            }
            Err(mpsc::TrySendError::Disconnected(_)) => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pktscope_core::LinkType;
    use std::time::SystemTime;

    struct MockSource {
        packets: Vec<Result<NextPacket, CaptureError>>,
        idx: usize,
        label: String,
    }

    impl PacketSource for MockSource {
        fn next_packet(&mut self) -> Result<NextPacket, CaptureError> {
            if self.idx >= self.packets.len() {
                return Ok(NextPacket::Eof);
            }
            let item = std::mem::replace(&mut self.packets[self.idx], Ok(NextPacket::Eof));
            self.idx += 1;
            item
        }

        fn source_label(&self) -> String {
            self.label.clone()
        }
    }

    struct InfiniteTimeoutSource;

    impl PacketSource for InfiniteTimeoutSource {
        fn next_packet(&mut self) -> Result<NextPacket, CaptureError> {
            thread::sleep(Duration::from_millis(5));
            Ok(NextPacket::Timeout)
        }

        fn source_label(&self) -> String {
            "infinite-timeout".to_string()
        }
    }

    struct FloodSource;

    impl PacketSource for FloodSource {
        fn next_packet(&mut self) -> Result<NextPacket, CaptureError> {
            Ok(NextPacket::Packet(RawPacket {
                timestamp: SystemTime::UNIX_EPOCH,
                captured_len: 1,
                original_len: 1,
                link_type: LinkType::Ethernet,
                data: vec![0xaa],
            }))
        }

        fn source_label(&self) -> String {
            "flood".to_string()
        }
    }

    #[test]
    fn capture_config_defaults() {
        let cfg = CaptureConfig::default();
        assert_eq!(cfg.interface, None);
        assert!(!cfg.promiscuous);
        assert_eq!(cfg.snaplen, 65535);
        assert_eq!(cfg.read_timeout, Duration::from_millis(200));
    }

    #[test]
    fn capture_handle_emits_packets_and_eos_and_stops_on_error() {
        let pkt = RawPacket {
            timestamp: SystemTime::UNIX_EPOCH,
            captured_len: 2,
            original_len: 2,
            link_type: LinkType::Ethernet,
            data: vec![1, 2],
        };
        let src = MockSource {
            packets: vec![
                Ok(NextPacket::Timeout),
                Ok(NextPacket::Packet(pkt.clone())),
                Ok(NextPacket::Eof),
            ],
            idx: 0,
            label: "mock".to_string(),
        };
        let (mut handle, rx) = CaptureHandle::start(src);
        assert_eq!(handle.source_label(), "mock");
        assert_eq!(rx.recv().unwrap(), CaptureEvent::Packet(pkt));
        assert_eq!(rx.recv().unwrap(), CaptureEvent::EndOfStream);
        handle.stop();
        assert!(!handle.is_running());

        let err_src = MockSource {
            packets: vec![Err(CaptureError::InterfaceNotFound("eth99".into()))],
            idx: 0,
            label: "err-mock".to_string(),
        };
        let (mut err_handle, err_rx) = CaptureHandle::start(err_src);
        match err_rx.recv().unwrap() {
            CaptureEvent::Error(msg) => assert!(msg.contains("eth99")),
            other => panic!("expected Error event, got {other:?}"),
        }
        err_handle.stop();
    }

    #[test]
    fn capture_handle_stop_unblocks_full_channel_and_dropped_receiver() {
        // Full channel: never read from `rx`, then stop handle -> must not deadlock.
        let (mut handle, _rx) = CaptureHandle::start(FloodSource);
        thread::sleep(Duration::from_millis(30));
        handle.stop();
        assert!(!handle.is_running());

        // Dropped receiver before handle drop -> thread exits cleanly.
        let (mut handle2, rx2) = CaptureHandle::start(FloodSource);
        drop(rx2);
        thread::sleep(Duration::from_millis(20));
        handle2.stop();
        assert!(!handle2.is_running());

        // Timeout source stops cleanly on drop.
        let (handle3, _rx3) = CaptureHandle::start(InfiniteTimeoutSource);
        assert!(handle3.is_running());
        drop(handle3);
    }
}
