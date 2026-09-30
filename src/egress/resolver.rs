use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

/// Checks if an IP address belongs to private/internal/reserved ranges.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => is_blocked_ipv6(v6),
    }
}

fn is_blocked_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    // 0.0.0.0/8 (Broadcast/Current network)
    if octets[0] == 0 {
        return true;
    }
    // 10.0.0.0/8 (Private)
    if octets[0] == 10 {
        return true;
    }
    // 100.64.0.0/10 (CGNAT)
    if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
        return true;
    }
    // 127.0.0.0/8 (Loopback)
    if octets[0] == 127 {
        return true;
    }
    // 169.254.0.0/16 (Link-local / Cloud Metadata)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // 172.16.0.0/12 (Private)
    if octets[0] == 172 && (octets[1] & 0xF0) == 16 {
        return true;
    }
    // 192.0.0.0/24 (IETF assignments)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return true;
    }
    // 192.0.2.0/24 (TEST-NET-1)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return true;
    }
    // 192.88.99.0/24 (6to4 Relay)
    if octets[0] == 192 && octets[1] == 88 && octets[2] == 99 {
        return true;
    }
    // 192.168.0.0/16 (Private)
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // 198.18.0.0/15 (Benchmarking)
    if octets[0] == 198 && (octets[1] & 0xFE) == 18 {
        return true;
    }
    // 198.51.100.0/24 (TEST-NET-2)
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }
    // 203.0.113.0/24 (TEST-NET-3)
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }
    // 224.0.0.0/4 (Multicast)
    if (octets[0] & 0xF0) == 224 {
        return true;
    }
    // 240.0.0.0/4 (Reserved) & 255.255.255.255
    if (octets[0] & 0xF0) == 240 {
        return true;
    }

    false
}

fn is_blocked_ipv6(ip: Ipv6Addr) -> bool {
    // Check IPv4-mapped IPv6 (::ffff:x.x.x.x)
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_blocked_ipv4(v4);
    }

    // Unspecified ::/128
    if ip.is_unspecified() {
        return true;
    }
    // Loopback ::1/128
    if ip.is_loopback() {
        return true;
    }

    // Unique local fc00::/7
    let segments = ip.segments();
    if (segments[0] & 0xFE00) == 0xFC00 {
        return true;
    }
    // Link-local fe80::/10
    if (segments[0] & 0xFFC0) == 0xFE80 {
        return true;
    }
    // Multicast ff00::/8
    if (segments[0] & 0xFF00) == 0xFF00 {
        return true;
    }
    // Discard-only 100::/64
    if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 {
        return true;
    }
    // Documentation 2001:db8::/32
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return true;
    }

    // Check NAT64 well-known prefix (64:ff9b::/96)
    if segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
    {
        let v4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        );
        return is_blocked_ipv4(v4);
    }

    false
}

/// SSRF-safe DNS resolver implementation for reqwest.
#[derive(Clone, Debug)]
pub struct SsrfSafeResolver {
    allow_private_ips: bool,
}

impl SsrfSafeResolver {
    pub fn new(allow_private_ips: bool) -> Self {
        Self { allow_private_ips }
    }
}

impl Resolve for SsrfSafeResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let allow_private = self.allow_private_ips;
        let host = name.as_str().to_string();

        Box::pin(async move {
            // If already IP literal
            if let Ok(ip) = IpAddr::from_str(&host) {
                if !allow_private && is_blocked_ip(ip) {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "SSRF guard blocked destination IP",
                    ))
                        as Box<dyn std::error::Error + Send + Sync>);
                }
                let socket_addr = SocketAddr::new(ip, 0);
                let addrs: Addrs = Box::new(std::iter::once(socket_addr));
                return Ok(addrs);
            }

            // Resolve host via standard tokio lookup
            let addr_port = format!("{host}:0");
            let mut resolved = Vec::new();

            match tokio::net::lookup_host(&addr_port).await {
                Ok(iter) => {
                    for socket_addr in iter {
                        let ip = socket_addr.ip();
                        if allow_private || !is_blocked_ip(ip) {
                            resolved.push(socket_addr);
                        } else {
                            tracing::warn!(
                                host = %host,
                                ip = %ip,
                                "SSRF guard filtered resolved private/reserved IP"
                            );
                        }
                    }
                }
                Err(e) => {
                    return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
                }
            }

            if resolved.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "SSRF guard blocked all resolved IP addresses for host",
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            let addrs: Addrs = Box::new(resolved.into_iter());
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_blocked_ipv4() {
        assert!(is_blocked_ip("127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("10.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("172.16.0.1".parse().unwrap()));
        assert!(is_blocked_ip("172.31.255.255".parse().unwrap()));
        assert!(is_blocked_ip("192.168.1.1".parse().unwrap()));
        assert!(is_blocked_ip("169.254.169.254".parse().unwrap())); // AWS metadata
        assert!(is_blocked_ip("100.64.0.1".parse().unwrap())); // CGNAT
        assert!(is_blocked_ip("0.0.0.0".parse().unwrap()));
        assert!(is_blocked_ip("224.0.0.1".parse().unwrap())); // Multicast
        assert!(is_blocked_ip("240.0.0.1".parse().unwrap())); // Reserved

        // Public IPs
        assert!(!is_blocked_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_blocked_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_blocked_ip("142.250.190.46".parse().unwrap()));
        assert!(!is_blocked_ip("172.15.0.1".parse().unwrap()));
        assert!(!is_blocked_ip("172.32.0.1".parse().unwrap()));
    }

    #[test]
    fn test_is_blocked_ipv6() {
        assert!(is_blocked_ip("::1".parse().unwrap()));
        assert!(is_blocked_ip("::".parse().unwrap()));
        assert!(is_blocked_ip("fc00::1".parse().unwrap()));
        assert!(is_blocked_ip("fd12:3456:789a::1".parse().unwrap()));
        assert!(is_blocked_ip("fe80::1".parse().unwrap()));
        assert!(is_blocked_ip("ff02::1".parse().unwrap()));
        assert!(is_blocked_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("::ffff:192.168.0.1".parse().unwrap()));

        // Public IPv6
        assert!(!is_blocked_ip("2606:4700:4700::1111".parse().unwrap()));
        assert!(!is_blocked_ip("2001:4860:4860::8888".parse().unwrap()));
    }
}
