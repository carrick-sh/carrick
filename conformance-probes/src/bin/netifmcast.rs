//! Guest interface enumeration and `/proc/net/igmp6` must agree on interface
//! names. Go's `net.Interface.MulticastAddrs` enumerates interfaces through
//! rtnetlink, then filters `/proc/net/igmp6` rows by that same name. Carrick
//! once exposed Darwin names in netlink (`lo0`, `en0`) while procfs used Linux
//! names (`lo`, `eth0`), so every IPv6 multicast row was dropped.

use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::fs;

fn main() {
    let ipv6_ifaces = active_ipv6_interfaces();
    let igmp6_ifaces = igmp6_interfaces();
    let has_membership = ipv6_ifaces.iter().any(|name| igmp6_ifaces.contains(name));
    let name_index_roundtrip = ipv6_ifaces
        .iter()
        .all(|name| if_name_index_roundtrips(name));

    println!("active_ipv6_iface_present={}", !ipv6_ifaces.is_empty());
    println!("igmp6_membership_present={}", !igmp6_ifaces.is_empty());
    println!("ipv6_iface_has_igmp6_membership={has_membership}");
    println!("iface_name_index_roundtrip={name_index_roundtrip}");
}

fn active_ipv6_interfaces() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 || head.is_null() {
        return out;
    }

    let mut cur = head;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_name.is_null() || ifa.ifa_addr.is_null() {
            continue;
        }
        let family = unsafe { (*ifa.ifa_addr).sa_family } as i32;
        let is_up = (ifa.ifa_flags as i32 & libc::IFF_UP) != 0;
        if family != libc::AF_INET6 || !is_up {
            continue;
        }
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        out.insert(name);
    }

    unsafe { libc::freeifaddrs(head) };
    out
}

fn igmp6_interfaces() -> BTreeSet<String> {
    let Ok(contents) = fs::read_to_string("/proc/net/igmp6") else {
        return BTreeSet::new();
    };
    contents
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _idx = fields.next()?;
            let name = fields.next()?;
            let addr = fields.next()?;
            (addr.len() == 32).then(|| name.to_owned())
        })
        .collect()
}

fn if_name_index_roundtrips(name: &str) -> bool {
    let Ok(c_name) = CString::new(name) else {
        return false;
    };
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        return false;
    }

    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    let ptr = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if ptr.is_null() {
        return false;
    }
    let roundtrip = unsafe { CStr::from_ptr(ptr) }.to_string_lossy();
    roundtrip == name
}
