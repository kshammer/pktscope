use std::net::IpAddr;

use crate::packet::{Direction, ParsedPacket, Protocol};

/// Filter predicate for matching decoded packets and IP addresses.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct TrafficFilter {
    pub ip_query: String,
    pub port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub direction: Option<Direction>,
}

impl TrafficFilter {
    /// Returns `true` when no filter constraints are configured.
    pub fn is_empty(&self) -> bool {
        self.ip_query.trim().is_empty()
            && self.port.is_none()
            && self.protocol.is_none()
            && self.direction.is_none()
    }

    /// Returns `true` if `pkt` satisfies all configured filter criteria.
    pub fn matches_packet(&self, pkt: &ParsedPacket) -> bool {
        if let Some(proto) = self.protocol
            && pkt.protocol != proto
        {
            return false;
        }
        if let Some(dir) = self.direction
            && pkt.direction != dir
        {
            return false;
        }
        if let Some(port) = self.port
            && pkt.src_port != Some(port)
            && pkt.dst_port != Some(port)
        {
            return false;
        }

        let q = self.ip_query.trim();
        if q.is_empty() {
            return true;
        }

        if let Some((net, prefix)) = parse_cidr(q) {
            return pkt.src_ip.is_some_and(|ip| ip_in_cidr(ip, net, prefix))
                || pkt.dst_ip.is_some_and(|ip| ip_in_cidr(ip, net, prefix));
        }

        if let Ok(target) = q.parse::<IpAddr>() {
            return pkt.src_ip == Some(target) || pkt.dst_ip == Some(target);
        }

        let q_lower = q.to_lowercase();
        pkt.src_ip
            .is_some_and(|ip| ip.to_string().to_lowercase().contains(&q_lower))
            || pkt
                .dst_ip
                .is_some_and(|ip| ip.to_string().to_lowercase().contains(&q_lower))
            || pkt.info.to_lowercase().contains(&q_lower)
    }

    /// Returns `true` if `ip` matches the configured `ip_query` (empty, CIDR, exact, or substring).
    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        let q = self.ip_query.trim();
        if q.is_empty() {
            return true;
        }
        if let Some((net, prefix)) = parse_cidr(q) {
            return ip_in_cidr(ip, net, prefix);
        }
        if let Ok(target) = q.parse::<IpAddr>() {
            return ip == target;
        }
        let q_lower = q.to_lowercase();
        ip.to_string().to_lowercase().contains(&q_lower)
    }

    /// Parses a CIDR string like `"192.168.1.0/24"` or `"fd00::/8"`.
    pub fn parse_cidr(input: &str) -> Option<(IpAddr, u8)> {
        parse_cidr(input)
    }

    /// Checks whether `ip` falls inside the network `net/prefix_len`.
    pub fn ip_in_cidr(ip: IpAddr, net: IpAddr, prefix_len: u8) -> bool {
        ip_in_cidr(ip, net, prefix_len)
    }
}

/// Parses a CIDR string like `"192.168.1.0/24"` or `"fd00::/8"`.
pub fn parse_cidr(input: &str) -> Option<(IpAddr, u8)> {
    let (addr_str, prefix_str) = input.trim().split_once('/')?;
    let addr = addr_str.trim().parse::<IpAddr>().ok()?;
    let prefix = prefix_str.trim().parse::<u8>().ok()?;
    let max_prefix = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix <= max_prefix {
        Some((addr, prefix))
    } else {
        None
    }
}

/// Checks whether `ip` falls inside the network `net/prefix_len`.
pub fn ip_in_cidr(ip: IpAddr, net: IpAddr, prefix_len: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(ip4), IpAddr::V4(net4)) => {
            if prefix_len > 32 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix_len);
            (u32::from(ip4) & mask) == (u32::from(net4) & mask)
        }
        (IpAddr::V6(ip6), IpAddr::V6(net6)) => {
            if prefix_len > 128 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - prefix_len);
            (u128::from(ip6) & mask) == (u128::from(net6) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::LinkType;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::SystemTime;

    fn sample_pkt(
        src_ip: Option<IpAddr>,
        dst_ip: Option<IpAddr>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        protocol: Protocol,
        direction: Direction,
        info: &str,
    ) -> ParsedPacket {
        ParsedPacket {
            id: 1,
            timestamp: SystemTime::UNIX_EPOCH,
            captured_len: 64,
            original_len: 64,
            link_type: LinkType::Ethernet,
            src_mac: None,
            dst_mac: None,
            vlan_id: None,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            ttl: Some(64),
            tcp_flags: None,
            icmp_summary: None,
            arp: None,
            direction,
            info: info.to_string(),
        }
    }

    #[test]
    fn cidr_parsing_and_matching() {
        assert_eq!(
            parse_cidr("192.168.1.0/24"),
            Some((IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24))
        );
        assert_eq!(
            parse_cidr("fd00::/8"),
            Some((IpAddr::V6("fd00::".parse().unwrap()), 8))
        );
        assert_eq!(parse_cidr("192.168.1.0/33"), None);
        assert_eq!(parse_cidr("fd00::/129"), None);
        assert_eq!(parse_cidr("not-a-cidr"), None);

        let v4_net: IpAddr = "192.168.1.0".parse().unwrap();
        assert!(ip_in_cidr("192.168.1.42".parse().unwrap(), v4_net, 24));
        assert!(!ip_in_cidr("192.168.2.42".parse().unwrap(), v4_net, 24));
        assert!(ip_in_cidr("10.0.0.1".parse().unwrap(), v4_net, 0));

        let v6_net: IpAddr = "fd00::".parse().unwrap();
        assert!(ip_in_cidr("fd12:3456::1".parse().unwrap(), v6_net, 8));
        assert!(!ip_in_cidr("fe80::1".parse().unwrap(), v6_net, 8));
        assert!(!ip_in_cidr("192.168.1.1".parse().unwrap(), v6_net, 8));
    }

    #[test]
    fn cidr_boundary_prefixes_v4_and_v6() {
        // IPv4 /0 matches all IPv4 addresses and never matches IPv6
        let (v4_zero_net, v4_zero_prefix) = parse_cidr("0.0.0.0/0").unwrap();
        assert_eq!(v4_zero_prefix, 0);
        assert!(ip_in_cidr("0.0.0.0".parse().unwrap(), v4_zero_net, 0));
        assert!(ip_in_cidr("10.0.0.1".parse().unwrap(), v4_zero_net, 0));
        assert!(ip_in_cidr(
            "255.255.255.255".parse().unwrap(),
            v4_zero_net,
            0
        ));
        assert!(!ip_in_cidr("::1".parse().unwrap(), v4_zero_net, 0));

        // IPv4 /32 matches only the exact host IP
        let (v4_host_net, v4_host_prefix) = parse_cidr("192.168.1.10/32").unwrap();
        assert_eq!(v4_host_prefix, 32);
        assert!(ip_in_cidr("192.168.1.10".parse().unwrap(), v4_host_net, 32));
        assert!(!ip_in_cidr(
            "192.168.1.11".parse().unwrap(),
            v4_host_net,
            32
        ));
        assert!(!ip_in_cidr("192.168.1.0".parse().unwrap(), v4_host_net, 32));

        // IPv6 /0 matches all IPv6 addresses and never matches IPv4
        let (v6_zero_net, v6_zero_prefix) = parse_cidr("::/0").unwrap();
        assert_eq!(v6_zero_prefix, 0);
        assert!(ip_in_cidr("::".parse().unwrap(), v6_zero_net, 0));
        assert!(ip_in_cidr("fe80::1".parse().unwrap(), v6_zero_net, 0));
        assert!(ip_in_cidr(
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap(),
            v6_zero_net,
            0
        ));
        assert!(!ip_in_cidr("10.0.0.1".parse().unwrap(), v6_zero_net, 0));

        // IPv6 /128 matches only the exact host IP
        let (v6_host_net, v6_host_prefix) = parse_cidr("fd00::1/128").unwrap();
        assert_eq!(v6_host_prefix, 128);
        assert!(ip_in_cidr("fd00::1".parse().unwrap(), v6_host_net, 128));
        assert!(!ip_in_cidr("fd00::2".parse().unwrap(), v6_host_net, 128));
        assert!(!ip_in_cidr("fd00::".parse().unwrap(), v6_host_net, 128));
    }

    #[test]
    fn filter_matching_ip_cidr_substring_port_proto_dir_and_combined() {
        let pkt_v4 = sample_pkt(
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            Some(54321),
            Some(53),
            Protocol::Udp,
            Direction::Outbound,
            "54321 -> 53 (DNS)",
        );
        let pkt_v6 = sample_pkt(
            Some(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))),
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 1))),
            Some(12345),
            Some(443),
            Protocol::Tcp,
            Direction::Inbound,
            "12345 -> 443 (HTTPS) [SYN]",
        );

        let empty = TrafficFilter::default();
        assert!(empty.is_empty());
        assert!(empty.matches_packet(&pkt_v4));
        assert!(empty.matches_ip("1.2.3.4".parse().unwrap()));

        // Exact IP match should not match partial prefix like 192.168.1.100
        let exact = TrafficFilter {
            ip_query: "192.168.1.10".to_string(),
            ..Default::default()
        };
        assert!(!exact.is_empty());
        assert!(exact.matches_packet(&pkt_v4));
        assert!(exact.matches_ip("192.168.1.10".parse().unwrap()));
        assert!(!exact.matches_ip("192.168.1.100".parse().unwrap()));

        // IPv4 CIDR
        let cidr_v4 = TrafficFilter {
            ip_query: "192.168.1.0/24".to_string(),
            ..Default::default()
        };
        assert!(cidr_v4.matches_packet(&pkt_v4));
        assert!(!cidr_v4.matches_packet(&pkt_v6));

        // IPv6 CIDR
        let cidr_v6 = TrafficFilter {
            ip_query: "fd00::/8".to_string(),
            ..Default::default()
        };
        assert!(cidr_v6.matches_packet(&pkt_v6));
        assert!(!cidr_v6.matches_packet(&pkt_v4));

        // Case-insensitive substring on info or IP
        let sub_info = TrafficFilter {
            ip_query: "dns".to_string(),
            ..Default::default()
        };
        assert!(sub_info.matches_packet(&pkt_v4));
        assert!(!sub_info.matches_packet(&pkt_v6));

        let sub_ip = TrafficFilter {
            ip_query: "192.168.1".to_string(),
            ..Default::default()
        };
        assert!(sub_ip.matches_ip("192.168.1.99".parse().unwrap()));
        assert!(sub_ip.matches_packet(&pkt_v4));

        // Combined filter (port + protocol + direction + CIDR)
        let combined = TrafficFilter {
            ip_query: "192.168.1.0/24".to_string(),
            port: Some(53),
            protocol: Some(Protocol::Udp),
            direction: Some(Direction::Outbound),
        };
        assert!(combined.matches_packet(&pkt_v4));

        let wrong_dir = TrafficFilter {
            direction: Some(Direction::Inbound),
            ..combined.clone()
        };
        assert!(!wrong_dir.matches_packet(&pkt_v4));

        let wrong_port = TrafficFilter {
            port: Some(80),
            ..combined
        };
        assert!(!wrong_port.matches_packet(&pkt_v4));
    }
}
