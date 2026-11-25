# pktscope

A fast, lightweight Rust desktop network packet analyzer and IP talker monitor built with `egui`/`eframe` and raw Linux `AF_PACKET` sockets.

## Features

- **IP Talkers**: Per-IP Sent and Received byte/packet counters, visual Sent/Recv ratio bars, live 5-second rolling rates, IP scope classification (`LocalHost`, `Private`, `Public`, `Loopback`, `LinkLocal`, `Multicast`), protocols, and one-click row filtering.
- **Conversations**: Bidirectional endpoint-pair aggregation (`A -> B`, `B -> A`, total bytes, active ports with well-known service labels, live rate).
- **Live Packet Feed & Inspector**: Virtualized scrolling packet table (`#`, UTC timestamp, direction, source, destination, protocol, wire length, info) with an L2/L3/L4 Packet Inspector panel (MACs, VLAN ID, IP/TTL/ARP, ports, TCP flags, ICMP summary).
- **Filtering**: Filter by IP address, CIDR subnet (`192.168.1.0/24`, `fd00::/8`), substring search, port, protocol (`TCP`, `UDP`, `ICMP`, `ICMPv6`, `ARP`), and traffic direction (`Inbound`, `Outbound`, `Local`, `Transit`).
- **60-Second Throughput Chart & Protocol Breakdown**: Custom area/line chart tracking Inbound, Outbound, and Transit bytes/sec with hover inspection, alongside a stacked protocol share bar and top 6 active ports.
- **Headless CLI Summary**: Inspect `.pcap` files or streams directly in the terminal with `--summary` (no display server required).

## Build & Run

```bash
cargo build --release
./target/release/pktscope
```

Or run directly during development:

```bash
cargo run --release -p pktscope-app
```

## Non-Root Live Capture on Linux

Live packet capture uses Linux `AF_PACKET` raw sockets, which require `CAP_NET_RAW` (and `CAP_NET_ADMIN` for promiscuous mode). Instead of running the GUI as `root`, grant capabilities to the compiled binary:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/pktscope
```

You can then launch `./target/release/pktscope` as a normal user and start capturing on any interface (or `any`).

## Offline PCAP Analysis

Open a `.pcap` file in the GUI:

```bash
pktscope --pcap capture.pcap
```

Print a headless IP talker and protocol summary to stdout and exit:

```bash
pktscope --pcap capture.pcap --summary
```

## Analyzing Router & Mirror Traffic

Stream live traffic from a remote router or firewall over SSH into `pktscope`:

```bash
ssh root@192.168.1.1 "tcpdump -i any -U -w -" | pktscope --stdin
```

Or generate a quick terminal summary from a remote capture stream:

```bash
ssh root@192.168.1.1 "tcpdump -i any -c 500 -U -w -" | pktscope --stdin --summary
```

When plugged into a switch SPAN/mirror port, enable promiscuous mode so off-host transit traffic is captured and charted in the **Transit** series:

```bash
pktscope -i eth0 --promisc
```

## CLI Options

```text
pktscope [OPTIONS]
    -i, --interface <name>   Start live capture on interface (e.g. eth0, any)
        --promisc            Enable promiscuous mode for live capture
        --pcap <path>        Load and analyze a .pcap capture file
        --stdin              Read a .pcap stream from standard input
        --summary            Print headless IP talkers & protocol summary and exit
    -h, --help               Show help message
```

## Workspace Architecture

- `crates/pktscope-core`: Zero-GUI packet decoding (`etherparse`), classic `.pcap` reader/writer, `TrafficFilter` (IP/CIDR/port/protocol/direction), and `TrafficStore` (bounded packet ring buffer, per-IP stats, conversations, rolling rates, 1-second throughput buckets).
- `crates/pktscope-capture`: Modular `PacketSource` backends (`LinuxLiveSource` via `AF_PACKET` + `getifaddrs`, `PcapFileSource`, `PcapStreamSource`) and bounded background `CaptureHandle` streaming.
- `crates/pktscope-app`: `pktscope` desktop GUI (`eframe`/`egui`) and CLI `--summary` entrypoint.
