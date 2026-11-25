use crate::source::{CaptureConfig, CaptureError, InterfaceInfo, NextPacket, PacketSource};

#[cfg(target_os = "linux")]
mod imp {
    use std::collections::{HashMap, HashSet};
    use std::ffi::{CStr, CString};
    use std::io::{self, ErrorKind};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::fd::RawFd;
    use std::time::{Duration, SystemTime};

    use pktscope_core::{LinkType, RawPacket};

    use super::*;

    const PERMISSION_HINT: &str = "Live capture requires CAP_NET_RAW. Run: sudo setcap cap_net_raw,cap_net_admin=eip $(which pktscope || echo ./target/release/pktscope)  (or launch with sudo)";
    const MIN_CAPTURE_BUF: usize = 2048;

    struct IfAddrsGuard(*mut libc::ifaddrs);

    impl Drop for IfAddrsGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    libc::freeifaddrs(self.0);
                }
            }
        }
    }

    struct OwnedFd(RawFd);

    impl Drop for OwnedFd {
        fn drop(&mut self) {
            if self.0 >= 0 {
                unsafe {
                    libc::close(self.0);
                }
            }
        }
    }

    /// Discovers host network interfaces and their assigned IPv4/IPv6 addresses.
    pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, CaptureError> {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return Err(CaptureError::Io(io::Error::last_os_error()));
        }
        let _guard = IfAddrsGuard(head);

        let mut map: HashMap<String, InterfaceInfo> = HashMap::new();
        let mut cur = head;

        while !cur.is_null() {
            let ifa = unsafe { &*cur };
            cur = ifa.ifa_next;

            if ifa.ifa_name.is_null() {
                continue;
            }

            let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
                .to_string_lossy()
                .into_owned();
            let flags = ifa.ifa_flags;
            let is_up = (flags & libc::IFF_UP as libc::c_uint) != 0;
            let is_loopback = (flags & libc::IFF_LOOPBACK as libc::c_uint) != 0;
            let is_running = (flags & libc::IFF_RUNNING as libc::c_uint) != 0;

            let entry = map.entry(name.clone()).or_insert_with(|| {
                let index = unsafe { libc::if_nametoindex(ifa.ifa_name) };
                InterfaceInfo {
                    name,
                    index,
                    is_up,
                    is_loopback,
                    is_running,
                    ips: Vec::new(),
                }
            });

            entry.is_up |= is_up;
            entry.is_loopback |= is_loopback;
            entry.is_running |= is_running;

            if let Some(ip) = unsafe { sockaddr_to_ip(ifa.ifa_addr) }
                && !entry.ips.contains(&ip)
            {
                entry.ips.push(ip);
            }
        }

        let mut interfaces: Vec<InterfaceInfo> = map.into_values().collect();
        interfaces.sort_by(|a, b| {
            sort_group(a)
                .cmp(&sort_group(b))
                .then_with(|| a.name.cmp(&b.name))
        });

        Ok(interfaces)
    }

    pub(super) unsafe fn sockaddr_to_ip(addr: *const libc::sockaddr) -> Option<IpAddr> {
        if addr.is_null() {
            return None;
        }
        let family = unsafe { std::ptr::read_unaligned(addr).sa_family } as libc::c_int;
        match family {
            libc::AF_INET => {
                let sin = unsafe { std::ptr::read_unaligned(addr as *const libc::sockaddr_in) };
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    sin.sin_addr.s_addr,
                ))))
            }
            libc::AF_INET6 => {
                let sin6 = unsafe { std::ptr::read_unaligned(addr as *const libc::sockaddr_in6) };
                Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }

    fn sort_group(info: &InterfaceInfo) -> u8 {
        if info.is_loopback {
            2
        } else if info.is_up {
            0
        } else {
            1
        }
    }

    /// Collects all local IP addresses across every host interface.
    pub fn all_local_ips() -> HashSet<IpAddr> {
        list_interfaces()
            .unwrap_or_default()
            .into_iter()
            .flat_map(|iface| iface.ips)
            .collect()
    }

    /// Live raw-socket packet capture source backed by Linux `AF_PACKET`.
    pub struct LinuxLiveSource {
        fd: OwnedFd,
        label: String,
        local_ips: HashSet<IpAddr>,
        buf: Vec<u8>,
    }

    impl LinuxLiveSource {
        /// Opens a live `AF_PACKET` capture socket using the given [`CaptureConfig`].
        pub fn open(config: CaptureConfig) -> Result<Self, CaptureError> {
            let (ifindex, label, local_ips) = resolve_interface(config.interface.as_deref())?;

            let protocol = (libc::ETH_P_ALL as u16).to_be();
            let raw_fd = unsafe {
                libc::socket(
                    libc::AF_PACKET,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    protocol as libc::c_int,
                )
            };
            if raw_fd < 0 {
                return Err(map_socket_error(io::Error::last_os_error(), &label));
            }
            let fd = OwnedFd(raw_fd);

            set_receive_timeout(fd.0, config.read_timeout)?;
            bind_af_packet(fd.0, ifindex, protocol, &label)?;

            if config.promiscuous && ifindex != 0 {
                enable_promiscuous(fd.0, ifindex, &label)?;
            }

            let buf_len = config.snaplen.max(MIN_CAPTURE_BUF);
            Ok(Self {
                fd,
                label,
                local_ips,
                buf: vec![0u8; buf_len],
            })
        }
    }

    impl PacketSource for LinuxLiveSource {
        fn next_packet(&mut self) -> Result<NextPacket, CaptureError> {
            let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut addrlen = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

            let n = unsafe {
                libc::recvfrom(
                    self.fd.0,
                    self.buf.as_mut_ptr() as *mut libc::c_void,
                    self.buf.len(),
                    libc::MSG_TRUNC,
                    &mut addr as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                    &mut addrlen,
                )
            };

            if n < 0 {
                let err = io::Error::last_os_error();
                if is_timeout_or_interrupt(&err) {
                    return Ok(NextPacket::Timeout);
                }
                return Err(CaptureError::Io(err));
            }

            let original_len = n as usize;
            let captured_len = original_len.min(self.buf.len());
            let link_type = hatype_to_link_type(addr.sll_hatype);

            Ok(NextPacket::Packet(RawPacket {
                timestamp: SystemTime::now(),
                captured_len: u32::try_from(captured_len).unwrap_or(u32::MAX),
                original_len: u32::try_from(original_len).unwrap_or(u32::MAX),
                link_type,
                data: self.buf[..captured_len].to_vec(),
            }))
        }

        fn source_label(&self) -> String {
            self.label.clone()
        }

        fn local_ips(&self) -> HashSet<IpAddr> {
            self.local_ips.clone()
        }
    }

    fn resolve_interface(
        interface: Option<&str>,
    ) -> Result<(u32, String, HashSet<IpAddr>), CaptureError> {
        match interface {
            None | Some("any") => Ok((0, "any".to_string(), all_local_ips())),
            Some(name) => {
                let interfaces = list_interfaces()?;
                if let Some(info) = interfaces.into_iter().find(|i| i.name == name) {
                    let index = if info.index != 0 {
                        info.index
                    } else {
                        if_name_to_index(name)?
                    };
                    if index == 0 {
                        return Err(CaptureError::InterfaceNotFound(name.to_string()));
                    }
                    let ips = info.ips.into_iter().collect();
                    return Ok((index, name.to_string(), ips));
                }

                let index = if_name_to_index(name)?;
                if index == 0 {
                    return Err(CaptureError::InterfaceNotFound(name.to_string()));
                }
                Ok((index, name.to_string(), HashSet::new()))
            }
        }
    }

    fn if_name_to_index(name: &str) -> Result<u32, CaptureError> {
        let c_name =
            CString::new(name).map_err(|_| CaptureError::InterfaceNotFound(name.to_string()))?;
        Ok(unsafe { libc::if_nametoindex(c_name.as_ptr()) })
    }

    pub(super) fn map_socket_error(err: io::Error, interface: &str) -> CaptureError {
        match err.raw_os_error() {
            Some(code) if code == libc::EPERM || code == libc::EACCES => {
                CaptureError::PermissionDenied {
                    interface: interface.to_string(),
                    hint: PERMISSION_HINT.to_string(),
                }
            }
            _ => CaptureError::Io(err),
        }
    }

    fn set_receive_timeout(fd: RawFd, timeout: Duration) -> Result<(), CaptureError> {
        let mut secs = timeout.as_secs();
        let mut usecs = timeout.subsec_micros();
        if !timeout.is_zero() && secs == 0 && usecs == 0 {
            usecs = 1;
        } else if secs == 0 && usecs == 0 {
            secs = 0;
            usecs = 0;
        }
        let tv = libc::timeval {
            tv_sec: secs as libc::time_t,
            tv_usec: usecs as libc::suseconds_t,
        };
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(CaptureError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }

    fn bind_af_packet(
        fd: RawFd,
        ifindex: u32,
        protocol: u16,
        interface: &str,
    ) -> Result<(), CaptureError> {
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = protocol;
        sll.sll_ifindex = ifindex as libc::c_int;

        let rc = unsafe {
            libc::bind(
                fd,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(map_socket_error(io::Error::last_os_error(), interface));
        }
        Ok(())
    }

    fn enable_promiscuous(fd: RawFd, ifindex: u32, interface: &str) -> Result<(), CaptureError> {
        let mut mreq: libc::packet_mreq = unsafe { std::mem::zeroed() };
        mreq.mr_ifindex = ifindex as libc::c_int;
        mreq.mr_type = libc::PACKET_MR_PROMISC as u16;

        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                &mreq as *const libc::packet_mreq as *const libc::c_void,
                std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(map_socket_error(io::Error::last_os_error(), interface));
        }
        Ok(())
    }

    fn is_timeout_or_interrupt(err: &io::Error) -> bool {
        if matches!(
            err.kind(),
            ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
        ) {
            return true;
        }
        matches!(
            err.raw_os_error(),
            Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK || code == libc::EINTR
        )
    }

    fn hatype_to_link_type(hatype: u16) -> LinkType {
        const ARPHRD_ETHER: u16 = 1;
        const ARPHRD_LOOPBACK: u16 = 772;
        const ARPHRD_NONE: u16 = 65534;
        const ARPHRD_VOID: u16 = 65535;

        match hatype {
            ARPHRD_ETHER | ARPHRD_LOOPBACK => LinkType::Ethernet,
            ARPHRD_NONE | ARPHRD_VOID => LinkType::RawIp,
            _ => LinkType::Ethernet,
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::collections::HashSet;
    use std::net::IpAddr;

    use super::*;

    /// Discovers host network interfaces (unsupported on non-Linux platforms).
    pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, CaptureError> {
        Err(CaptureError::UnsupportedPlatform(
            "live interface discovery is only supported on Linux".to_string(),
        ))
    }

    /// Collects all local IP addresses across every host interface.
    pub fn all_local_ips() -> HashSet<IpAddr> {
        HashSet::new()
    }

    /// Placeholder live capture source for non-Linux targets.
    pub struct LinuxLiveSource;

    impl LinuxLiveSource {
        /// Returns [`CaptureError::UnsupportedPlatform`] on non-Linux targets.
        pub fn open(_config: CaptureConfig) -> Result<Self, CaptureError> {
            Err(CaptureError::UnsupportedPlatform(
                "AF_PACKET live capture is only supported on Linux".to_string(),
            ))
        }
    }

    impl PacketSource for LinuxLiveSource {
        fn next_packet(&mut self) -> Result<NextPacket, CaptureError> {
            Err(CaptureError::UnsupportedPlatform(
                "AF_PACKET live capture is only supported on Linux".to_string(),
            ))
        }

        fn source_label(&self) -> String {
            "unsupported".to_string()
        }
    }
}

pub use imp::{LinuxLiveSource, all_local_ips, list_interfaces};

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn list_interfaces_finds_loopback_and_sorts_correctly() {
        let interfaces = list_interfaces().expect("list_interfaces should succeed on Linux");
        let lo = interfaces
            .iter()
            .find(|iface| iface.name == "lo")
            .expect("loopback interface 'lo' should exist");
        assert!(lo.is_loopback);
        assert!(lo.index > 0);
        assert!(
            lo.ips.iter().any(|ip| ip.is_loopback()),
            "expected loopback IP (127.0.0.1 or ::1), got {:?}",
            lo.ips
        );

        // Verify sort invariant: non-loopback UP (0), non-loopback other (1), loopback (2), alphabetical within group.
        for pair in interfaces.windows(2) {
            let group = |info: &InterfaceInfo| -> u8 {
                if info.is_loopback {
                    2
                } else if info.is_up {
                    0
                } else {
                    1
                }
            };
            let g0 = group(&pair[0]);
            let g1 = group(&pair[1]);
            assert!(
                g0 < g1 || (g0 == g1 && pair[0].name <= pair[1].name),
                "interfaces out of order: {:?} before {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn open_nonexistent_interface_returns_interface_not_found() {
        let cfg = CaptureConfig {
            interface: Some("nonexistent_iface_xyz99".to_string()),
            ..Default::default()
        };
        let err = match LinuxLiveSource::open(cfg) {
            Ok(_) => panic!("expected InterfaceNotFound error"),
            Err(e) => e,
        };
        assert!(
            matches!(err, CaptureError::InterfaceNotFound(ref name) if name == "nonexistent_iface_xyz99"),
            "expected InterfaceNotFound, got {err:?}"
        );
    }

    #[test]
    fn open_default_either_succeeds_or_returns_permission_denied_with_setcap_hint() {
        match LinuxLiveSource::open(CaptureConfig::default()) {
            Ok(src) => {
                assert_eq!(src.source_label(), "any");
            }
            Err(CaptureError::PermissionDenied { hint, .. }) => {
                assert!(
                    hint.contains("setcap"),
                    "expected setcap in PermissionDenied hint, got: {hint}"
                );
            }
            Err(other) => panic!("unexpected error from LinuxLiveSource::open: {other:?}"),
        }
    }

    #[test]
    fn sockaddr_to_ip_handles_unaligned_v4_and_v6_pointers() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        // Construct unaligned (offset + 1) sockaddr_in and sockaddr_in6 buffers.
        let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_addr.s_addr = u32::from(Ipv4Addr::new(10, 20, 30, 40)).to_be();

        let mut buf4 = vec![0u8; std::mem::size_of::<libc::sockaddr_in>() + 1];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &sin as *const libc::sockaddr_in as *const u8,
                buf4.as_mut_ptr().add(1),
                std::mem::size_of::<libc::sockaddr_in>(),
            );
            let ptr4 = buf4.as_ptr().add(1) as *const libc::sockaddr;
            assert_eq!(
                imp::sockaddr_to_ip(ptr4),
                Some(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)))
            );
        }

        let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        let expected_v6 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x42);
        sin6.sin6_addr.s6_addr = expected_v6.octets();

        let mut buf6 = vec![0u8; std::mem::size_of::<libc::sockaddr_in6>() + 1];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &sin6 as *const libc::sockaddr_in6 as *const u8,
                buf6.as_mut_ptr().add(1),
                std::mem::size_of::<libc::sockaddr_in6>(),
            );
            let ptr6 = buf6.as_ptr().add(1) as *const libc::sockaddr;
            assert_eq!(imp::sockaddr_to_ip(ptr6), Some(IpAddr::V6(expected_v6)));
        }
    }

    #[test]
    fn map_socket_error_maps_eperm_and_eacces_to_permission_denied() {
        for code in [libc::EPERM, libc::EACCES] {
            let err = std::io::Error::from_raw_os_error(code);
            match imp::map_socket_error(err, "eth0") {
                CaptureError::PermissionDenied { interface, hint } => {
                    assert_eq!(interface, "eth0");
                    assert!(hint.contains("setcap"), "unexpected hint: {hint}");
                }
                other => panic!("expected PermissionDenied, got {other:?}"),
            }
        }
    }
}
