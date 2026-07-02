//! Bridge network identity probe. It checks only Docker-stable shape: a
//! non-loopback eth0 IPv4 address, rtnetlink visibility for link/address/route,
//! bridge-shaped /proc/net and /sys/class/net files, and runtime-managed
//! hosts/resolv.conf.

use std::ffi::CStr;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::time::{Duration, Instant};

const NETLINK_ROUTE: i32 = 0;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;
const IFLA_IFNAME: u16 = 3;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTA_GATEWAY: u16 = 5;

fn main() {
    let eth0_ip = eth0_ipv4();
    println!("bridge_getifaddrs_eth0=true");
    println!("bridge_getifaddrs_nonloopback={}", !eth0_ip.is_loopback());
    println!("bridge_hosts_has_eth0_ip={}", file_contains_ip("/etc/hosts", eth0_ip));
    println!(
        "bridge_host_docker_internal={}",
        host_gateway_match(
            "host.docker.internal",
            "CARRICK_PROBE_EXPECT_HOST_DOCKER_INTERNAL"
        )
    );
    println!(
        "bridge_gateway_docker_internal={}",
        host_gateway_match(
            "gateway.docker.internal",
            "CARRICK_PROBE_EXPECT_GATEWAY_DOCKER_INTERNAL"
        )
    );
    println!("bridge_resolv_has_nameserver={}", resolv_has_nameserver());
    println!(
        "bridge_resolv_nameservers_match={}",
        resolv_nameservers_match()
    );
    println!("bridge_resolv_search_match={}", resolv_search_match());
    println!("bridge_resolv_options_match={}", resolv_options_match());
    println!("bridge_gethostname_match={}", gethostname_match());
    println!("bridge_uname_nodename_match={}", uname_nodename_match());
    println!(
        "bridge_proc_hostname_match={}",
        file_trimmed_match("/proc/sys/kernel/hostname", "CARRICK_PROBE_EXPECT_HOSTNAME")
    );
    println!(
        "bridge_etc_hostname_match={}",
        file_trimmed_match("/etc/hostname", "CARRICK_PROBE_EXPECT_HOSTNAME")
    );
    println!("bridge_hosts_has_hostname={}", hosts_has_expected_hostname());
    println!("bridge_proc_dev_has_eth0={}", proc_dev_has_eth0());
    println!(
        "bridge_proc_route_default_gateway={}",
        proc_route_has_default_gateway()
    );
    println!("bridge_sysfs_has_eth0={}", sysfs_has_eth0());
    println!("bridge_sysfs_hides_host_en0={}", !fs::metadata("/sys/class/net/en0").is_ok());

    let link_messages = unsafe { netlink_dump(RTM_GETLINK) };
    let addr_messages = unsafe { netlink_dump(RTM_GETADDR) };
    let route_messages = unsafe { netlink_dump(RTM_GETROUTE) };
    println!("bridge_netlink_link_eth0={}", netlink_link_has_eth0(&link_messages));
    println!(
        "bridge_netlink_addr_eth0_ip={}",
        netlink_addr_has_ip(&addr_messages, eth0_ip)
    );
    println!(
        "bridge_netlink_default_gateway={}",
        netlink_route_has_default_gateway(&route_messages)
    );
}

fn eth0_ipv4() -> Ipv4Addr {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 || head.is_null() {
        panic!("getifaddrs failed");
    }
    let mut fallback = None;
    let mut cur = head;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_name.is_null() || ifa.ifa_addr.is_null() {
            continue;
        }
        let family = unsafe { (*ifa.ifa_addr).sa_family } as i32;
        if family != libc::AF_INET {
            continue;
        }
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }.to_string_lossy();
        let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
        let octets = sin.sin_addr.s_addr.to_ne_bytes();
        let ip = Ipv4Addr::from(octets);
        if ip.is_loopback() {
            continue;
        }
        if name == "eth0" {
            unsafe { libc::freeifaddrs(head) };
            return ip;
        }
        fallback = Some(ip);
    }
    unsafe { libc::freeifaddrs(head) };
    fallback.expect("non-loopback IPv4 address")
}

fn file_contains_ip(path: &str, ip: Ipv4Addr) -> bool {
    fs::read_to_string(path).is_ok_and(|contents| contents.contains(&ip.to_string()))
}

fn resolve_host_v4(host: &str) -> Option<Ipv4Addr> {
    (host, 80)
        .to_socket_addrs()
        .ok()?
        .find_map(|addr| match addr.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
}

fn host_gateway_match(host: &str, env_name: &str) -> bool {
    let Some(expected) = std::env::var(env_name)
        .ok()
        .and_then(|value| value.parse::<Ipv4Addr>().ok())
    else {
        return true;
    };
    resolve_host_v4(host) == Some(expected)
}

fn resolv_has_nameserver() -> bool {
    fs::read_to_string("/etc/resolv.conf").is_ok_and(|contents| {
        contents
            .lines()
            .any(|line| line.split_whitespace().next() == Some("nameserver"))
    })
}

fn resolv_nameservers_match() -> bool {
    let Some(expected) = env_list("CARRICK_PROBE_EXPECT_DNS") else {
        return true;
    };
    resolv_directive_values("nameserver").is_some_and(|actual| actual == expected)
}

fn resolv_search_match() -> bool {
    let Some(expected) = env_list("CARRICK_PROBE_EXPECT_DNS_SEARCH") else {
        return true;
    };
    resolv_directive_values("search").is_some_and(|actual| actual == expected)
}

fn resolv_options_match() -> bool {
    let Some(expected) = env_list("CARRICK_PROBE_EXPECT_DNS_OPTIONS") else {
        return true;
    };
    resolv_directive_values("options").is_some_and(|actual| actual == expected)
}

fn env_list(name: &str) -> Option<Vec<String>> {
    std::env::var(name).ok().map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::to_string)
            .collect()
    })
}

fn expected_hostname() -> Option<String> {
    std::env::var("CARRICK_PROBE_EXPECT_HOSTNAME")
        .ok()
        .filter(|value| !value.is_empty())
}

fn gethostname_match() -> bool {
    let Some(expected) = expected_hostname() else {
        return true;
    };
    let mut buf = [0 as libc::c_char; 256];
    if unsafe { libc::gethostname(buf.as_mut_ptr(), buf.len()) } != 0 {
        return false;
    }
    unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy() == expected
}

fn uname_nodename_match() -> bool {
    let Some(expected) = expected_hostname() else {
        return true;
    };
    let mut uts = unsafe { std::mem::zeroed::<libc::utsname>() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return false;
    }
    unsafe { CStr::from_ptr(uts.nodename.as_ptr()) }.to_string_lossy() == expected
}

fn file_trimmed_match(path: &str, env_name: &str) -> bool {
    let Some(expected) = std::env::var(env_name).ok() else {
        return true;
    };
    fs::read_to_string(path).is_ok_and(|contents| contents.trim() == expected)
}

fn hosts_has_expected_hostname() -> bool {
    let Some(expected) = expected_hostname() else {
        return true;
    };
    fs::read_to_string("/etc/hosts").is_ok_and(|contents| {
        contents
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .any(|line| line.split_whitespace().skip(1).any(|name| name == expected))
    })
}

fn resolv_directive_values(directive: &str) -> Option<Vec<String>> {
    let contents = fs::read_to_string("/etc/resolv.conf").ok()?;
    Some(
        contents
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                if fields.next() != Some(directive) {
                    return None;
                }
                Some(fields.map(str::to_string).collect::<Vec<_>>())
            })
            .flatten()
            .collect(),
    )
}

fn proc_dev_has_eth0() -> bool {
    fs::read_to_string("/proc/net/dev").is_ok_and(|contents| {
        contents.lines().any(|line| line.trim_start().starts_with("eth0:"))
    })
}

fn proc_route_has_default_gateway() -> bool {
    fs::read_to_string("/proc/net/route").is_ok_and(|contents| {
        contents.lines().skip(1).any(|line| {
            let cols = line.split_whitespace().collect::<Vec<_>>();
            cols.len() > 2 && cols[0] == "eth0" && cols[1] == "00000000" && cols[2] != "00000000"
        })
    })
}

fn sysfs_has_eth0() -> bool {
    fs::read_to_string("/sys/class/net/eth0/ifindex").is_ok_and(|contents| {
        contents
            .trim()
            .parse::<u32>()
            .is_ok_and(|index| index > 1)
    })
}

unsafe fn netlink_dump(request_type: u16) -> Vec<(u16, Vec<u8>)> {
    let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE);
    if fd < 0 {
        return Vec::new();
    }
    let mut req = [0u8; 20];
    req[0..4].copy_from_slice(&(20u32).to_ne_bytes());
    req[4..6].copy_from_slice(&request_type.to_ne_bytes());
    req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    req[8..12].copy_from_slice(&(1u32).to_ne_bytes());
    req[16] = libc::AF_UNSPEC as u8;
    if libc::send(fd, req.as_ptr() as *const _, req.len(), 0) < 0 {
        libc::close(fd);
        return Vec::new();
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    'outer: while Instant::now() < deadline {
        let n = libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0);
        if n <= 0 {
            break;
        }
        let total = n as usize;
        let mut off = 0usize;
        while off + 16 <= total {
            let msg_len =
                u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
            let msg_type = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
            if msg_len < 16 || off + msg_len > total {
                break;
            }
            if msg_type == NLMSG_DONE {
                break 'outer;
            }
            out.push((msg_type, buf[off + 16..off + msg_len].to_vec()));
            off += (msg_len + 3) & !3;
        }
    }
    libc::close(fd);
    out
}

fn netlink_link_has_eth0(messages: &[(u16, Vec<u8>)]) -> bool {
    messages.iter().any(|(kind, payload)| {
        *kind == RTM_NEWLINK
            && payload.len() >= 16
            && attrs(&payload[16..]).any(|(kind, value)| kind == IFLA_IFNAME && nul_str(value) == "eth0")
    })
}

fn netlink_addr_has_ip(messages: &[(u16, Vec<u8>)], ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    messages.iter().any(|(kind, payload)| {
        *kind == RTM_NEWADDR
            && payload.len() >= 8
            && attrs(&payload[8..]).any(|(kind, value)| {
                matches!(kind, IFA_ADDRESS | IFA_LOCAL) && value == octets
            })
    })
}

fn netlink_route_has_default_gateway(messages: &[(u16, Vec<u8>)]) -> bool {
    messages.iter().any(|(kind, payload)| {
        *kind == RTM_NEWROUTE
            && payload.len() >= 12
            && payload[1] == 0
            && attrs(&payload[12..]).any(|(kind, value)| {
                kind == RTA_GATEWAY && value.len() == 4 && value != [0, 0, 0, 0]
            })
    })
}

fn attrs(mut bytes: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        while bytes.len() >= 4 {
            let len = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
            let kind = u16::from_ne_bytes([bytes[2], bytes[3]]);
            if len < 4 || len > bytes.len() {
                bytes = &[];
                return None;
            }
            let value = &bytes[4..len];
            let aligned = (len + 3) & !3;
            bytes = if aligned <= bytes.len() {
                &bytes[aligned..]
            } else {
                &[]
            };
            return Some((kind, value));
        }
        None
    })
}

fn nul_str(bytes: &[u8]) -> &str {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).unwrap_or("")
}
