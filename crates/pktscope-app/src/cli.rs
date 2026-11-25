use std::fmt::Write as _;
use std::path::PathBuf;

use pktscope_capture::{NextPacket, PacketSource, PcapFileSource, PcapStreamSource, all_local_ips};
use pktscope_core::{IpStats, TrafficStore, format_bytes};

const TOP_TALKERS_LIMIT: usize = 50;

/// Parsed command-line arguments for `pktscope`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CliArgs {
    pub interface: Option<String>,
    pub promiscuous: bool,
    pub pcap_path: Option<PathBuf>,
    pub stdin: bool,
    pub summary: bool,
    pub show_help: bool,
}

/// Parses CLI arguments from an iterator of argument strings (excluding `argv[0]`).
pub fn parse_args<I, S>(iter: I) -> Result<CliArgs, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = CliArgs::default();
    let mut it = iter.into_iter();

    while let Some(raw) = it.next() {
        let arg = raw.as_ref();
        match arg {
            "-h" | "--help" => {
                args.show_help = true;
            }
            "--promisc" => {
                args.promiscuous = true;
            }
            "--stdin" => {
                args.stdin = true;
            }
            "--summary" => {
                args.summary = true;
            }
            "-i" | "--interface" => {
                let val = it
                    .next()
                    .ok_or_else(|| format!("missing value for {arg} (expected interface name)"))?;
                let val_str = val.as_ref();
                if val_str.is_empty() {
                    return Err(format!("empty value for {arg} (expected interface name)"));
                }
                args.interface = Some(val_str.to_string());
            }
            "--pcap" => {
                let val = it
                    .next()
                    .ok_or_else(|| "missing value for --pcap (expected file path)".to_string())?;
                let val_str = val.as_ref();
                if val_str.is_empty() {
                    return Err("empty value for --pcap (expected file path)".to_string());
                }
                args.pcap_path = Some(PathBuf::from(val_str));
            }
            _ if arg.starts_with("--interface=") => {
                let val = &arg["--interface=".len()..];
                if val.is_empty() {
                    return Err("empty value for --interface= (expected interface name)".into());
                }
                args.interface = Some(val.to_string());
            }
            _ if arg.starts_with("--pcap=") => {
                let val = &arg["--pcap=".len()..];
                if val.is_empty() {
                    return Err("empty value for --pcap= (expected file path)".into());
                }
                args.pcap_path = Some(PathBuf::from(val));
            }
            _ if arg.starts_with('-') => {
                return Err(format!("unknown option: {arg}"));
            }
            _ => {
                return Err(format!("unexpected positional argument: {arg}"));
            }
        }
    }

    Ok(args)
}

/// Returns CLI usage text.
pub fn usage() -> &'static str {
    "\
pktscope - Live network packet analyzer and IP talker monitor

USAGE:
    pktscope [OPTIONS]

OPTIONS:
    -i, --interface <name>   Start live capture on interface (e.g. eth0, any)
        --promisc            Enable promiscuous mode for live capture
        --pcap <path>        Load and analyze a .pcap capture file
        --stdin              Read a .pcap stream from standard input
        --summary            Print headless IP talkers & protocol summary and exit
    -h, --help               Show this help message

EXAMPLES:
    pktscope
    pktscope -i eth0 --promisc
    pktscope --pcap capture.pcap
    pktscope --pcap capture.pcap --summary
    ssh root@router \"tcpdump -i any -U -w -\" | pktscope --stdin"
}

/// Reads all packets from `--pcap` or `--stdin` into a `TrafficStore` and formats a summary report.
pub fn run_summary(args: &CliArgs) -> Result<String, String> {
    if args.stdin && args.pcap_path.is_some() {
        return Err("cannot specify both --pcap and --stdin".to_string());
    }

    if let Some(path) = &args.pcap_path {
        let source = PcapFileSource::open(path, false).map_err(|e| e.to_string())?;
        run_summary_from_source(source)
    } else if args.stdin {
        let source = PcapStreamSource::from_stdin();
        run_summary_from_source(source)
    } else {
        Err("--summary requires either --pcap <path> or --stdin".to_string())
    }
}

/// Consumes all packets from a `PacketSource` and formats the text summary report.
pub fn run_summary_from_source<S: PacketSource>(mut source: S) -> Result<String, String> {
    let mut store = TrafficStore::new(0);
    store.set_local_ips(all_local_ips());

    loop {
        match source.next_packet() {
            Ok(NextPacket::Packet(raw)) => {
                store.ingest_raw(&raw);
            }
            Ok(NextPacket::Timeout) => continue,
            Ok(NextPacket::Eof) => break,
            Err(err) => return Err(err.to_string()),
        }
    }

    Ok(format_summary(&store, &source.source_label()))
}

/// Formats an aligned text summary of IP talkers, totals, and protocol breakdown.
pub fn format_summary(store: &TrafficStore, source_label: &str) -> String {
    let mut out = String::new();
    let total_packets = store.total_packets();
    let total_bytes = store.total_bytes();

    let _ = writeln!(out, "Source: {source_label}");
    let _ = writeln!(
        out,
        "Total: {total_packets} packets, {} ({total_bytes} bytes)",
        format_bytes(total_bytes)
    );
    let _ = writeln!(out);

    let mut talkers: Vec<&IpStats> = store.ip_stats().collect();
    talkers.sort_by(|a, b| {
        b.total_bytes()
            .cmp(&a.total_bytes())
            .then_with(|| b.total_packets().cmp(&a.total_packets()))
            .then_with(|| a.ip.cmp(&b.ip))
    });

    if talkers.is_empty() {
        let _ = writeln!(out, "IP Talkers: (none)");
    } else {
        let shown = talkers.len().min(TOP_TALKERS_LIMIT);
        let _ = writeln!(
            out,
            "Top IP Talkers (showing {shown} of {}):",
            talkers.len()
        );

        let rows: Vec<[String; 8]> = talkers
            .iter()
            .take(TOP_TALKERS_LIMIT)
            .map(|stat| {
                [
                    stat.ip.to_string(),
                    stat.scope.to_string(),
                    format_bytes(stat.bytes_sent),
                    stat.packets_sent.to_string(),
                    format_bytes(stat.bytes_received),
                    stat.packets_received.to_string(),
                    format_bytes(stat.total_bytes()),
                    stat.total_packets().to_string(),
                ]
            })
            .collect();

        let headers = [
            "IP",
            "Scope",
            "Sent",
            "Sent Pkts",
            "Recv",
            "Recv Pkts",
            "Total",
            "Packets",
        ];
        let mut widths = headers.map(str::len);
        for row in &rows {
            for (idx, col) in row.iter().enumerate() {
                widths[idx] = widths[idx].max(col.len());
            }
        }

        let _ = writeln!(
            out,
            "{:<w0$}  {:<w1$}  {:>w2$}  {:>w3$}  {:>w4$}  {:>w5$}  {:>w6$}  {:>w7$}",
            headers[0],
            headers[1],
            headers[2],
            headers[3],
            headers[4],
            headers[5],
            headers[6],
            headers[7],
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2],
            w3 = widths[3],
            w4 = widths[4],
            w5 = widths[5],
            w6 = widths[6],
            w7 = widths[7],
        );
        let total_width: usize = widths.iter().sum::<usize>() + 14;
        let _ = writeln!(out, "{}", "-".repeat(total_width));

        for row in &rows {
            let _ = writeln!(
                out,
                "{:<w0$}  {:<w1$}  {:>w2$}  {:>w3$}  {:>w4$}  {:>w5$}  {:>w6$}  {:>w7$}",
                row[0],
                row[1],
                row[2],
                row[3],
                row[4],
                row[5],
                row[6],
                row[7],
                w0 = widths[0],
                w1 = widths[1],
                w2 = widths[2],
                w3 = widths[3],
                w4 = widths[4],
                w5 = widths[5],
                w6 = widths[6],
                w7 = widths[7],
            );
        }
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "Protocols:");
    if store.protocol_totals().is_empty() {
        let _ = writeln!(out, "  (none)");
    } else {
        let mut protos: Vec<_> = store.protocol_totals().iter().collect();
        protos.sort_by(|a, b| b.1.1.cmp(&a.1.1).then_with(|| a.0.cmp(b.0)));
        for (proto, &(pkts, bytes)) in protos {
            let pct = if total_bytes > 0 {
                (bytes as f64 / total_bytes as f64) * 100.0
            } else {
                0.0
            };
            let _ = writeln!(
                out,
                "  {:<10} {:>6} pkts  {:>10}  ({pct:5.1}%)",
                proto.name(),
                pkts,
                format_bytes(bytes)
            );
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use pktscope_core::{LinkType, PcapWriter, RawPacket};
    use std::fs::File;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn build_ipv4_frame(proto: u8, src: [u8; 4], dst: [u8; 4], l4_and_payload: &[u8]) -> Vec<u8> {
        let total_ip_len = (20 + l4_and_payload.len()) as u16;
        let mut data = Vec::with_capacity(14 + total_ip_len as usize);
        data.extend_from_slice(&[0x02; 6]);
        data.extend_from_slice(&[0x01; 6]);
        data.extend_from_slice(&0x0800u16.to_be_bytes());
        data.extend_from_slice(&[0x45, 0x00]);
        data.extend_from_slice(&total_ip_len.to_be_bytes());
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 64, proto, 0x00, 0x00]);
        data.extend_from_slice(&src);
        data.extend_from_slice(&dst);
        data.extend_from_slice(l4_and_payload);
        data
    }

    #[test]
    fn parse_args_covers_all_flags_and_errors() {
        let parsed = parse_args([
            "-i",
            "eth0",
            "--promisc",
            "--pcap",
            "/tmp/cap.pcap",
            "--stdin",
            "--summary",
            "--help",
        ])
        .unwrap();
        assert_eq!(parsed.interface.as_deref(), Some("eth0"));
        assert!(parsed.promiscuous);
        assert_eq!(parsed.pcap_path, Some(PathBuf::from("/tmp/cap.pcap")));
        assert!(parsed.stdin);
        assert!(parsed.summary);
        assert!(parsed.show_help);

        let eq_parsed = parse_args(["--interface=wlan0", "--pcap=test.pcap", "-h"]).unwrap();
        assert_eq!(eq_parsed.interface.as_deref(), Some("wlan0"));
        assert_eq!(eq_parsed.pcap_path, Some(PathBuf::from("test.pcap")));
        assert!(eq_parsed.show_help);

        assert!(parse_args(["--unknown"]).is_err());
        assert!(parse_args(["-x"]).is_err());
        assert!(parse_args(["-i"]).is_err());
        assert!(parse_args(["--interface"]).is_err());
        assert!(parse_args(["--pcap"]).is_err());
        assert!(parse_args(["--pcap="]).is_err());
        assert!(parse_args(["positional"]).is_err());
    }

    #[test]
    fn run_summary_reads_pcap_and_prints_ip_talkers_and_protocols() {
        let tmp_dir = std::env::temp_dir();
        let path = tmp_dir.join(format!("pktscope_cli_summary_{}.pcap", std::process::id()));

        let build_tcp = |src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload_len: usize| {
            let mut l4 = Vec::with_capacity(20 + payload_len);
            l4.extend_from_slice(&sport.to_be_bytes());
            l4.extend_from_slice(&dport.to_be_bytes());
            l4.extend_from_slice(&1u32.to_be_bytes());
            l4.extend_from_slice(&1u32.to_be_bytes());
            l4.extend_from_slice(&[0x50, 0x10]);
            l4.extend_from_slice(&1024u16.to_be_bytes());
            l4.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            l4.resize(20 + payload_len, 0x41);
            let data = build_ipv4_frame(6, src, dst, &l4);
            let len = data.len() as u32;
            RawPacket {
                timestamp: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
                captured_len: len,
                original_len: len,
                link_type: LinkType::Ethernet,
                data,
            }
        };

        let build_udp = |src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload_len: usize| {
            let udp_len = (8 + payload_len) as u16;
            let mut l4 = Vec::with_capacity(udp_len as usize);
            l4.extend_from_slice(&sport.to_be_bytes());
            l4.extend_from_slice(&dport.to_be_bytes());
            l4.extend_from_slice(&udp_len.to_be_bytes());
            l4.extend_from_slice(&[0x00, 0x00]);
            l4.resize(udp_len as usize, 0x42);
            let data = build_ipv4_frame(17, src, dst, &l4);
            let len = data.len() as u32;
            RawPacket {
                timestamp: UNIX_EPOCH + Duration::from_secs(1_700_000_001),
                captured_len: len,
                original_len: len,
                link_type: LinkType::Ethernet,
                data,
            }
        };

        let p1 = build_tcp([10, 0, 0, 1], [93, 184, 216, 34], 50000, 443, 100);
        let p2 = build_tcp([93, 184, 216, 34], [10, 0, 0, 1], 443, 50000, 200);
        let p3 = build_udp([10, 0, 0, 2], [8, 8, 8, 8], 51000, 53, 40);

        let expected_total_bytes =
            u64::from(p1.original_len) + u64::from(p2.original_len) + u64::from(p3.original_len);

        {
            let file = File::create(&path).unwrap();
            let mut writer = PcapWriter::new(file, LinkType::Ethernet, 65535).unwrap();
            writer.write_packet(&p1).unwrap();
            writer.write_packet(&p2).unwrap();
            writer.write_packet(&p3).unwrap();
            writer.flush().unwrap();
        }

        let args = CliArgs {
            pcap_path: Some(path.clone()),
            summary: true,
            ..Default::default()
        };
        let report = run_summary(&args).unwrap();
        let _ = std::fs::remove_file(&path);

        assert!(report.contains(&format!(
            "Total: 3 packets, {} ({expected_total_bytes} bytes)",
            format_bytes(expected_total_bytes)
        )));
        assert!(report.contains("10.0.0.1"));
        assert!(report.contains("93.184.216.34"));
        assert!(report.contains("10.0.0.2"));
        assert!(report.contains("8.8.8.8"));
        assert!(report.contains("TCP"));
        assert!(report.contains("UDP"));

        // Ensure Sent/Recv bytes for 10.0.0.1 are accurately represented:
        // p1 sent by 10.0.0.1 (154B), p2 received by 10.0.0.1 (254B)
        let line_10_1 = report
            .lines()
            .find(|l| l.starts_with("10.0.0.1 "))
            .expect("10.0.0.1 row");
        assert!(line_10_1.contains(&format_bytes(u64::from(p1.original_len))));
        assert!(line_10_1.contains(&format_bytes(u64::from(p2.original_len))));
        assert!(line_10_1.contains(&format_bytes(
            u64::from(p1.original_len) + u64::from(p2.original_len)
        )));

        // Missing source error
        let missing_src = CliArgs {
            summary: true,
            ..Default::default()
        };
        assert!(run_summary(&missing_src).is_err());

        // Conflicting sources error
        let conflict = CliArgs {
            pcap_path: Some(PathBuf::from("a.pcap")),
            stdin: true,
            summary: true,
            ..Default::default()
        };
        assert!(run_summary(&conflict).is_err());

        // Check timestamp helper isn't unused
        let _ = SystemTime::UNIX_EPOCH;
    }
}
