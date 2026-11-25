use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind, Read};
use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime};

use pktscope_core::PcapReader;

use crate::source::{CaptureError, NextPacket, PacketSource};

const MAX_PACE_SLEEP: Duration = Duration::from_millis(250);
const STREAM_POLL_TIMEOUT_MS: i32 = 200;

/// Packet source reading recorded packets from a classic `.pcap` file on disk.
pub struct PcapFileSource {
    reader: PcapReader<BufReader<File>>,
    label: String,
    paced: bool,
    prev_timestamp: Option<SystemTime>,
}

impl PcapFileSource {
    /// Opens a `.pcap` file at `path`. When `paced` is `true`, playback sleeps up to 250ms per inter-packet delta.
    pub fn open<P: AsRef<Path>>(path: P, paced: bool) -> Result<Self, CaptureError> {
        let path_ref = path.as_ref();
        let file = File::open(path_ref)?;
        let reader = PcapReader::new(BufReader::new(file))?;
        let filename = path_ref
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path_ref.display().to_string());
        Ok(Self {
            reader,
            label: format!("pcap: {filename}"),
            paced,
            prev_timestamp: None,
        })
    }
}

impl PacketSource for PcapFileSource {
    fn next_packet(&mut self) -> Result<NextPacket, CaptureError> {
        match self.reader.next_packet()? {
            None => Ok(NextPacket::Eof),
            Some(pkt) => {
                if self.paced {
                    if let Some(prev_ts) = self.prev_timestamp
                        && let Ok(delta) = pkt.timestamp.duration_since(prev_ts)
                    {
                        let sleep_dur = delta.min(MAX_PACE_SLEEP);
                        if !sleep_dur.is_zero() {
                            thread::sleep(sleep_dur);
                        }
                    }
                    self.prev_timestamp = Some(pkt.timestamp);
                }
                Ok(NextPacket::Packet(pkt))
            }
        }
    }

    fn source_label(&self) -> String {
        self.label.clone()
    }
}

enum StreamState<R: Read> {
    Uninitialized(BufReader<R>),
    Initialized(PcapReader<BufReader<R>>),
    Finished,
}

/// Streaming `.pcap` source that lazily parses the global header on the first [`PacketSource::next_packet`] call.
pub struct PcapStreamSource<R: Read + Send> {
    state: StreamState<R>,
    label: String,
    poll_fd: Option<i32>,
    poll_timeout_ms: i32,
}

impl<R: Read + Send> PcapStreamSource<R> {
    /// Wraps `reader` without reading from it until the first packet is requested.
    pub fn new(reader: R, label: impl Into<String>) -> Self {
        Self {
            state: StreamState::Uninitialized(BufReader::new(reader)),
            label: label.into(),
            poll_fd: None,
            poll_timeout_ms: STREAM_POLL_TIMEOUT_MS,
        }
    }

    /// Wraps `reader` with a pollable file descriptor so idle reads time out periodically instead of hanging `stop()`.
    #[cfg(target_os = "linux")]
    pub fn with_poll_fd(reader: R, label: impl Into<String>, fd: std::os::fd::RawFd) -> Self {
        Self {
            state: StreamState::Uninitialized(BufReader::new(reader)),
            label: label.into(),
            poll_fd: Some(fd),
            poll_timeout_ms: STREAM_POLL_TIMEOUT_MS,
        }
    }
}

impl PcapStreamSource<std::io::Stdin> {
    /// Creates a streaming `.pcap` source reading lazily from standard input.
    pub fn from_stdin() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::with_poll_fd(std::io::stdin(), "stdin", libc::STDIN_FILENO)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self::new(std::io::stdin(), "stdin")
        }
    }
}

impl<R: Read + Send> PacketSource for PcapStreamSource<R> {
    fn next_packet(&mut self) -> Result<NextPacket, CaptureError> {
        if let StreamState::Uninitialized(buf_reader) = &self.state {
            if buf_reader.buffer().is_empty()
                && !wait_for_readable(self.poll_fd, self.poll_timeout_ms)?
            {
                return Ok(NextPacket::Timeout);
            }

            let StreamState::Uninitialized(mut buf_reader) =
                std::mem::replace(&mut self.state, StreamState::Finished)
            else {
                unreachable!();
            };

            // Peek at least one byte so an immediate 0-byte EOF returns Eof cleanly rather than Truncated.
            loop {
                match buf_reader.fill_buf() {
                    Ok([]) => return Ok(NextPacket::Eof),
                    Ok(_) => break,
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(e) => return Err(CaptureError::Io(e)),
                }
            }

            let pcap_reader = PcapReader::new(buf_reader)?;
            self.state = StreamState::Initialized(pcap_reader);
        }

        match &mut self.state {
            StreamState::Initialized(reader) => {
                if reader.reader_ref().buffer().is_empty()
                    && !wait_for_readable(self.poll_fd, self.poll_timeout_ms)?
                {
                    return Ok(NextPacket::Timeout);
                }
                match reader.next_packet()? {
                    Some(pkt) => Ok(NextPacket::Packet(pkt)),
                    None => {
                        self.state = StreamState::Finished;
                        Ok(NextPacket::Eof)
                    }
                }
            }
            StreamState::Finished => Ok(NextPacket::Eof),
            StreamState::Uninitialized(_) => unreachable!(),
        }
    }

    fn source_label(&self) -> String {
        self.label.clone()
    }
}

#[cfg(target_os = "linux")]
fn wait_for_readable(poll_fd: Option<i32>, timeout_ms: i32) -> Result<bool, CaptureError> {
    let Some(fd) = poll_fd else {
        return Ok(true);
    };
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if rc == 0 {
        return Ok(false);
    }
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(CaptureError::Io(err));
    }
    Ok(true)
}

#[cfg(not(target_os = "linux"))]
fn wait_for_readable(_poll_fd: Option<i32>, _timeout_ms: i32) -> Result<bool, CaptureError> {
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{CaptureEvent, CaptureHandle};
    use pktscope_core::{LinkType, PcapError, PcapWriter, RawPacket};
    use std::io::Cursor;
    use std::sync::mpsc;
    use std::time::UNIX_EPOCH;

    fn sample_packet(ts_secs: u64, payload: Vec<u8>) -> RawPacket {
        RawPacket {
            timestamp: UNIX_EPOCH + Duration::from_secs(ts_secs),
            captured_len: payload.len() as u32,
            original_len: payload.len() as u32,
            link_type: LinkType::Ethernet,
            data: payload,
        }
    }

    #[test]
    fn pcap_file_source_streams_packets_through_capture_handle() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "pktscope_capture_test_{}_{}.pcap",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));

        let pkt1 = sample_packet(1_700_000_000, vec![0xaa, 0xbb, 0xcc, 0xdd]);
        let pkt2 = sample_packet(1_700_000_001, vec![0x01, 0x02, 0x03]);

        {
            let file = File::create(&path).expect("create temp pcap");
            let mut writer = PcapWriter::new(file, LinkType::Ethernet, 65535).unwrap();
            writer.write_packet(&pkt1).unwrap();
            writer.write_packet(&pkt2).unwrap();
            writer.flush().unwrap();
        }

        let source = PcapFileSource::open(&path, false).expect("open temp pcap");
        assert!(source.source_label().starts_with("pcap: "));
        let (mut handle, rx) = CaptureHandle::start(source);

        assert_eq!(rx.recv().unwrap(), CaptureEvent::Packet(pkt1));
        assert_eq!(rx.recv().unwrap(), CaptureEvent::Packet(pkt2));
        assert_eq!(rx.recv().unwrap(), CaptureEvent::EndOfStream);

        handle.stop();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pcap_stream_source_is_lazy_and_streams_incrementally_from_pipe() {
        let (pipe_reader, mut pipe_writer) = std::io::pipe().expect("create OS pipe");

        // Constructing PcapStreamSource must not block even though no bytes are in the pipe yet.
        let source = PcapStreamSource::new(pipe_reader, "test-pipe");
        assert_eq!(source.source_label(), "test-pipe");
        let (mut handle, rx) = CaptureHandle::start(source);

        // Nothing written yet -> no events arrived.
        assert!(rx.recv_timeout(Duration::from_millis(20)).is_err());

        let pkt1 = sample_packet(1_700_000_010, vec![10, 20, 30, 40]);
        let pkt2 = sample_packet(1_700_000_011, vec![50, 60]);

        // Write header + first packet and flush; packet 1 should arrive before packet 2 or EOF is written.
        {
            let mut pcap_writer =
                PcapWriter::new(&mut pipe_writer, LinkType::Ethernet, 65535).unwrap();
            pcap_writer.write_packet(&pkt1).unwrap();
            pcap_writer.flush().unwrap();

            assert_eq!(
                rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                CaptureEvent::Packet(pkt1)
            );

            // Write second packet and verify incremental arrival.
            pcap_writer.write_packet(&pkt2).unwrap();
            pcap_writer.flush().unwrap();

            assert_eq!(
                rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                CaptureEvent::Packet(pkt2)
            );
        }

        // Close pipe writer -> EndOfStream, and stop() completes cleanly.
        drop(pipe_writer);
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            CaptureEvent::EndOfStream
        );
        handle.stop();
        assert!(!handle.is_running());
    }

    struct ChannelReader {
        rx: mpsc::Receiver<Vec<u8>>,
        buf: Vec<u8>,
        pos: usize,
    }

    impl Read for ChannelReader {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.pos < self.buf.len() {
                let n = (self.buf.len() - self.pos).min(out.len());
                out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            match self.rx.recv() {
                Ok(chunk) => {
                    self.buf = chunk;
                    self.pos = 0;
                    self.read(out)
                }
                Err(_) => Ok(0),
            }
        }
    }

    #[test]
    fn pcap_stream_source_stop_terminates_cleanly_on_channel_close() {
        let (tx, rx) = mpsc::channel();
        let reader = ChannelReader {
            rx,
            buf: Vec::new(),
            pos: 0,
        };
        let source = PcapStreamSource::new(reader, "chan");
        let (mut handle, event_rx) = CaptureHandle::start(source);

        // Build a valid header + 1 packet into an in-memory buffer and send it over the channel.
        let pkt = sample_packet(1_700_000_020, vec![0xde, 0xad, 0xbe, 0xef]);
        let mut bytes = Vec::new();
        {
            let mut w = PcapWriter::new(&mut bytes, LinkType::Ethernet, 65535).unwrap();
            w.write_packet(&pkt).unwrap();
            w.flush().unwrap();
        }
        tx.send(bytes).unwrap();

        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            CaptureEvent::Packet(pkt)
        );

        // Closing the sender ends the stream and allows stop() to join without deadlocking.
        drop(tx);
        handle.stop();
        assert!(!handle.is_running());
    }

    #[test]
    fn pcap_stream_source_empty_eof_and_invalid_magic() {
        let mut empty = PcapStreamSource::new(Cursor::new(Vec::<u8>::new()), "empty");
        assert_eq!(empty.next_packet().unwrap(), NextPacket::Eof);

        let mut bad_magic = PcapStreamSource::new(Cursor::new(vec![0u8; 24]), "bad");
        match bad_magic.next_packet() {
            Err(CaptureError::Pcap(PcapError::InvalidMagic(0))) => {}
            other => panic!("expected InvalidMagic(0), got {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pcap_stream_source_with_poll_fd_stops_promptly_on_idle_open_pipe() {
        use std::os::fd::AsRawFd;
        use std::time::Instant;

        // Case 1: idle before global header with write end still open
        let (pipe_reader, pipe_writer) = std::io::pipe().expect("create OS pipe");
        let fd = pipe_reader.as_raw_fd();
        let source = PcapStreamSource::with_poll_fd(pipe_reader, "idle-pipe", fd);
        let (mut handle, _rx) = CaptureHandle::start(source);

        thread::sleep(Duration::from_millis(30));
        let start = Instant::now();
        handle.stop();
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(1),
            "stop() took too long on idle pre-header pipe: {elapsed:?}"
        );
        assert!(!handle.is_running());
        drop(pipe_writer);

        // Case 2: idle after header + 1 packet with write end still open
        let (pipe_reader2, mut pipe_writer2) = std::io::pipe().expect("create OS pipe");
        let fd2 = pipe_reader2.as_raw_fd();
        let source2 = PcapStreamSource::with_poll_fd(pipe_reader2, "idle-pipe-after-pkt", fd2);
        let (mut handle2, rx2) = CaptureHandle::start(source2);

        let pkt = sample_packet(1_700_000_030, vec![1, 2, 3, 4]);
        let mut pcap_writer =
            PcapWriter::new(&mut pipe_writer2, LinkType::Ethernet, 65535).unwrap();
        pcap_writer.write_packet(&pkt).unwrap();
        pcap_writer.flush().unwrap();

        assert_eq!(
            rx2.recv_timeout(Duration::from_secs(2)).unwrap(),
            CaptureEvent::Packet(pkt)
        );

        thread::sleep(Duration::from_millis(30));
        let start2 = Instant::now();
        handle2.stop();
        let elapsed2 = start2.elapsed();
        assert!(
            elapsed2 < Duration::from_secs(1),
            "stop() took too long on idle post-packet pipe: {elapsed2:?}"
        );
        assert!(!handle2.is_running());
        drop(pipe_writer2);
    }
}
