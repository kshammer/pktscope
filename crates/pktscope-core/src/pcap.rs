use std::io::{self, ErrorKind, Read, Write};
use std::time::{Duration, UNIX_EPOCH};

use thiserror::Error;

use crate::packet::{LinkType, RawPacket};

const MAX_PACKET_LEN: u32 = 16 * 1024 * 1024;
const PCAP_MAGIC_LE_US: u32 = 0xa1b2_c3d4;
const PCAP_MAGIC_BE_US: u32 = 0xd4c3_b2a1;
const PCAP_MAGIC_LE_NS: u32 = 0xa1b2_3c4d;
const PCAP_MAGIC_BE_NS: u32 = 0x4d3c_b2a1;

/// Errors returned while reading or writing classic `.pcap` streams.
#[derive(Debug, Error)]
pub enum PcapError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid PCAP magic number: 0x{0:08x}")]
    InvalidMagic(u32),
    #[error("packet length {0} exceeds maximum supported size")]
    PacketTooLarge(u32),
    #[error("unexpected end of PCAP stream (truncated record)")]
    Truncated,
}

/// Decoded 24-byte classic `.pcap` global file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcapHeader {
    pub link_type: LinkType,
    pub snaplen: u32,
    pub big_endian: bool,
    pub nanosecond: bool,
}

/// Streaming reader for classic `.pcap` files.
pub struct PcapReader<R: Read> {
    reader: R,
    header: PcapHeader,
}

impl<R: Read> PcapReader<R> {
    /// Reads and validates the 24-byte global `.pcap` header from `reader`.
    pub fn new(mut reader: R) -> Result<Self, PcapError> {
        let mut buf = [0u8; 24];
        read_exact_or_truncated(&mut reader, &mut buf)?;

        let magic_le = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let (big_endian, nanosecond) = match magic_le {
            PCAP_MAGIC_LE_US => (false, false),
            PCAP_MAGIC_BE_US => (true, false),
            PCAP_MAGIC_LE_NS => (false, true),
            PCAP_MAGIC_BE_NS => (true, true),
            other => return Err(PcapError::InvalidMagic(other)),
        };

        let snaplen = decode_u32([buf[16], buf[17], buf[18], buf[19]], big_endian);
        let network = decode_u32([buf[20], buf[21], buf[22], buf[23]], big_endian);

        Ok(Self {
            reader,
            header: PcapHeader {
                link_type: LinkType::from_dlt(network),
                snaplen,
                big_endian,
                nanosecond,
            },
        })
    }

    /// Returns the parsed global header.
    pub fn header(&self) -> &PcapHeader {
        &self.header
    }

    /// Returns a shared reference to the underlying reader.
    pub fn reader_ref(&self) -> &R {
        &self.reader
    }

    /// Reads the next packet record, returning `Ok(None)` cleanly at EOF on a record boundary.
    pub fn next_packet(&mut self) -> Result<Option<RawPacket>, PcapError> {
        let mut rec_hdr = [0u8; 16];
        let mut filled = 0;
        while filled < rec_hdr.len() {
            match self.reader.read(&mut rec_hdr[filled..]) {
                Ok(0) => {
                    if filled == 0 {
                        return Ok(None);
                    }
                    return Err(PcapError::Truncated);
                }
                Ok(n) => filled += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(PcapError::Io(e)),
            }
        }

        let ts_sec = decode_u32(
            [rec_hdr[0], rec_hdr[1], rec_hdr[2], rec_hdr[3]],
            self.header.big_endian,
        );
        let ts_subsec = decode_u32(
            [rec_hdr[4], rec_hdr[5], rec_hdr[6], rec_hdr[7]],
            self.header.big_endian,
        );
        let incl_len = decode_u32(
            [rec_hdr[8], rec_hdr[9], rec_hdr[10], rec_hdr[11]],
            self.header.big_endian,
        );
        let orig_len = decode_u32(
            [rec_hdr[12], rec_hdr[13], rec_hdr[14], rec_hdr[15]],
            self.header.big_endian,
        );

        if incl_len > MAX_PACKET_LEN {
            return Err(PcapError::PacketTooLarge(incl_len));
        }

        let mut data = vec![0u8; incl_len as usize];
        read_exact_or_truncated(&mut self.reader, &mut data)?;

        let subsec_dur = if self.header.nanosecond {
            Duration::from_nanos(u64::from(ts_subsec))
        } else {
            Duration::from_micros(u64::from(ts_subsec))
        };
        let timestamp = UNIX_EPOCH + Duration::from_secs(u64::from(ts_sec)) + subsec_dur;

        Ok(Some(RawPacket {
            timestamp,
            captured_len: incl_len,
            original_len: orig_len,
            link_type: self.header.link_type,
            data,
        }))
    }
}

/// Streaming writer for standard little-endian microsecond `.pcap` files.
pub struct PcapWriter<W: Write> {
    writer: W,
}

impl<W: Write> PcapWriter<W> {
    /// Creates a new `.pcap` writer and writes the 24-byte global header.
    pub fn new(mut writer: W, link_type: LinkType, snaplen: u32) -> Result<Self, PcapError> {
        let mut hdr = [0u8; 24];
        hdr[0..4].copy_from_slice(&PCAP_MAGIC_LE_US.to_le_bytes());
        hdr[4..6].copy_from_slice(&2u16.to_le_bytes());
        hdr[6..8].copy_from_slice(&4u16.to_le_bytes());
        hdr[8..12].copy_from_slice(&0i32.to_le_bytes());
        hdr[12..16].copy_from_slice(&0u32.to_le_bytes());
        hdr[16..20].copy_from_slice(&snaplen.to_le_bytes());
        hdr[20..24].copy_from_slice(&link_type.to_dlt().to_le_bytes());
        writer.write_all(&hdr)?;
        Ok(Self { writer })
    }

    /// Writes a single [`RawPacket`] record to the stream.
    pub fn write_packet(&mut self, packet: &RawPacket) -> Result<(), PcapError> {
        let dur = packet
            .timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let ts_sec = dur.as_secs().min(u64::from(u32::MAX)) as u32;
        let ts_usec = dur.subsec_micros();
        let incl_len =
            u32::try_from(packet.data.len()).map_err(|_| PcapError::PacketTooLarge(u32::MAX))?;
        let orig_len = packet.original_len.max(incl_len);

        let mut rec_hdr = [0u8; 16];
        rec_hdr[0..4].copy_from_slice(&ts_sec.to_le_bytes());
        rec_hdr[4..8].copy_from_slice(&ts_usec.to_le_bytes());
        rec_hdr[8..12].copy_from_slice(&incl_len.to_le_bytes());
        rec_hdr[12..16].copy_from_slice(&orig_len.to_le_bytes());

        self.writer.write_all(&rec_hdr)?;
        self.writer.write_all(&packet.data)?;
        Ok(())
    }

    /// Flushes buffered data to the underlying writer.
    pub fn flush(&mut self) -> Result<(), PcapError> {
        self.writer.flush()?;
        Ok(())
    }
}

fn decode_u32(bytes: [u8; 4], big_endian: bool) -> u32 {
    if big_endian {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    }
}

fn read_exact_or_truncated<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), PcapError> {
    match reader.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => Err(PcapError::Truncated),
        Err(e) => Err(PcapError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trip_pcap_writer_reader() {
        let mut buf = Vec::new();
        let pkt1 = RawPacket {
            timestamp: UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_000),
            captured_len: 4,
            original_len: 64,
            link_type: LinkType::Ethernet,
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let pkt2 = RawPacket {
            timestamp: UNIX_EPOCH + Duration::new(1_700_000_001, 500_000_000),
            captured_len: 3,
            original_len: 3,
            link_type: LinkType::Ethernet,
            data: vec![1, 2, 3],
        };

        {
            let mut writer = PcapWriter::new(&mut buf, LinkType::Ethernet, 65535).unwrap();
            writer.write_packet(&pkt1).unwrap();
            writer.write_packet(&pkt2).unwrap();
            writer.flush().unwrap();
        }

        let mut reader = PcapReader::new(Cursor::new(&buf)).unwrap();
        assert_eq!(reader.reader_ref().position(), 24);
        assert_eq!(reader.header().link_type, LinkType::Ethernet);
        assert_eq!(reader.header().snaplen, 65535);
        assert!(!reader.header().big_endian);
        assert!(!reader.header().nanosecond);

        assert_eq!(reader.next_packet().unwrap(), Some(pkt1));
        assert_eq!(reader.next_packet().unwrap(), Some(pkt2));
        assert_eq!(reader.next_packet().unwrap(), None);
    }

    #[test]
    fn read_big_endian_and_nanosecond_headers() {
        // Big-endian microsecond PCAP with 1 RawIP packet
        let mut be_us = Vec::new();
        be_us.extend_from_slice(&0xa1b2_c3d4u32.to_be_bytes());
        be_us.extend_from_slice(&2u16.to_be_bytes());
        be_us.extend_from_slice(&4u16.to_be_bytes());
        be_us.extend_from_slice(&0i32.to_be_bytes());
        be_us.extend_from_slice(&0u32.to_be_bytes());
        be_us.extend_from_slice(&1500u32.to_be_bytes());
        be_us.extend_from_slice(&101u32.to_be_bytes()); // RawIp
        be_us.extend_from_slice(&10u32.to_be_bytes()); // ts_sec
        be_us.extend_from_slice(&250u32.to_be_bytes()); // ts_usec
        be_us.extend_from_slice(&2u32.to_be_bytes()); // incl_len
        be_us.extend_from_slice(&2u32.to_be_bytes()); // orig_len
        be_us.extend_from_slice(&[0x45, 0x00]);

        let mut reader = PcapReader::new(Cursor::new(&be_us)).unwrap();
        assert!(reader.header().big_endian);
        assert!(!reader.header().nanosecond);
        assert_eq!(reader.header().link_type, LinkType::RawIp);
        assert_eq!(reader.header().snaplen, 1500);
        let pkt = reader.next_packet().unwrap().unwrap();
        assert_eq!(pkt.timestamp, UNIX_EPOCH + Duration::new(10, 250_000));
        assert_eq!(pkt.data, vec![0x45, 0x00]);
        assert_eq!(reader.next_packet().unwrap(), None);

        // Little-endian nanosecond PCAP
        let mut le_ns = Vec::new();
        le_ns.extend_from_slice(&PCAP_MAGIC_LE_NS.to_le_bytes());
        le_ns.extend_from_slice(&2u16.to_le_bytes());
        le_ns.extend_from_slice(&4u16.to_le_bytes());
        le_ns.extend_from_slice(&0i32.to_le_bytes());
        le_ns.extend_from_slice(&0u32.to_le_bytes());
        le_ns.extend_from_slice(&65535u32.to_le_bytes());
        le_ns.extend_from_slice(&113u32.to_le_bytes()); // LinuxSll
        le_ns.extend_from_slice(&5u32.to_le_bytes());
        le_ns.extend_from_slice(&789u32.to_le_bytes());
        le_ns.extend_from_slice(&1u32.to_le_bytes());
        le_ns.extend_from_slice(&1u32.to_le_bytes());
        le_ns.push(0xff);

        let mut reader_ns = PcapReader::new(Cursor::new(&le_ns)).unwrap();
        assert!(!reader_ns.header().big_endian);
        assert!(reader_ns.header().nanosecond);
        assert_eq!(reader_ns.header().link_type, LinkType::LinuxSll);
        let pkt_ns = reader_ns.next_packet().unwrap().unwrap();
        assert_eq!(pkt_ns.timestamp, UNIX_EPOCH + Duration::new(5, 789));

        // Big-endian nanosecond header check
        let mut be_ns = Vec::new();
        be_ns.extend_from_slice(&0xa1b2_3c4du32.to_be_bytes());
        be_ns.extend_from_slice(&2u16.to_be_bytes());
        be_ns.extend_from_slice(&4u16.to_be_bytes());
        be_ns.extend_from_slice(&0i32.to_be_bytes());
        be_ns.extend_from_slice(&0u32.to_be_bytes());
        be_ns.extend_from_slice(&2048u32.to_be_bytes());
        be_ns.extend_from_slice(&276u32.to_be_bytes()); // LinuxSll2
        let mut reader_be_ns = PcapReader::new(Cursor::new(&be_ns)).unwrap();
        assert!(reader_be_ns.header().big_endian);
        assert!(reader_be_ns.header().nanosecond);
        assert_eq!(reader_be_ns.header().link_type, LinkType::LinuxSll2);
        assert_eq!(reader_be_ns.next_packet().unwrap(), None);
    }

    #[test]
    fn reject_invalid_magic_truncated_and_oversized() {
        let bad_magic = vec![0u8; 24];
        assert!(matches!(
            PcapReader::new(Cursor::new(&bad_magic)),
            Err(PcapError::InvalidMagic(0))
        ));

        let short_hdr = vec![0u8; 10];
        assert!(matches!(
            PcapReader::new(Cursor::new(&short_hdr)),
            Err(PcapError::Truncated)
        ));

        // Valid header + mid-record header truncation
        let mut buf = Vec::new();
        PcapWriter::new(&mut buf, LinkType::Ethernet, 65535).unwrap();
        buf.extend_from_slice(&[1, 2, 3, 4, 5]);
        let mut reader = PcapReader::new(Cursor::new(&buf)).unwrap();
        assert!(matches!(reader.next_packet(), Err(PcapError::Truncated)));

        // Valid header + truncated packet payload
        let mut buf2 = Vec::new();
        PcapWriter::new(&mut buf2, LinkType::Ethernet, 65535).unwrap();
        buf2.extend_from_slice(&1u32.to_le_bytes());
        buf2.extend_from_slice(&0u32.to_le_bytes());
        buf2.extend_from_slice(&100u32.to_le_bytes());
        buf2.extend_from_slice(&100u32.to_le_bytes());
        buf2.extend_from_slice(&[0u8; 10]);
        let mut reader2 = PcapReader::new(Cursor::new(&buf2)).unwrap();
        assert!(matches!(reader2.next_packet(), Err(PcapError::Truncated)));

        // Oversized packet rejection
        let mut buf3 = Vec::new();
        PcapWriter::new(&mut buf3, LinkType::Ethernet, 65535).unwrap();
        buf3.extend_from_slice(&1u32.to_le_bytes());
        buf3.extend_from_slice(&0u32.to_le_bytes());
        buf3.extend_from_slice(&(MAX_PACKET_LEN + 1).to_le_bytes());
        buf3.extend_from_slice(&(MAX_PACKET_LEN + 1).to_le_bytes());
        let mut reader3 = PcapReader::new(Cursor::new(&buf3)).unwrap();
        assert!(matches!(
            reader3.next_packet(),
            Err(PcapError::PacketTooLarge(len)) if len == MAX_PACKET_LEN + 1
        ));
    }
}
