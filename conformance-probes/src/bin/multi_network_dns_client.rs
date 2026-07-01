//! Raw UDP DNS probe for Carrick's embedded bridge DNS responder.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

fn main() {
    let label = std::env::var("CARRICK_PROBE_LABEL").unwrap_or_else(|_| "dns".to_string());
    let target = std::env::var("CARRICK_PROBE_TARGET").expect("CARRICK_PROBE_TARGET");
    let expect = std::env::var("CARRICK_PROBE_EXPECT").unwrap_or_else(|_| "success".to_string());
    let server = nameserver().unwrap_or_else(|| Ipv4Addr::new(172, 31, 0, 1));
    let addrs = query_a(server, &target);

    match expect.as_str() {
        "success" => {
            assert!(!addrs.is_empty(), "{label}: {target} did not resolve");
            println!("{label}_dns_addrs={}", format_addrs(&addrs));
            println!("{label}_dns_ok=true");
        }
        "failure" => {
            assert!(addrs.is_empty(), "{label}: unexpectedly resolved {target}");
            println!("{label}_dns_isolated=true");
        }
        other => panic!("unsupported CARRICK_PROBE_EXPECT={other:?}"),
    }
}

fn nameserver() -> Option<Ipv4Addr> {
    let resolv = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    resolv.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next() == Some("nameserver"))
            .then(|| fields.next())
            .flatten()
            .and_then(|addr| addr.parse().ok())
    })
}

fn query_a(server: Ipv4Addr, target: &str) -> Vec<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("bind udp");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set timeout");
    let request = dns_query(target);
    socket
        .send_to(&request, SocketAddr::new(server.into(), 53))
        .expect("send query");
    let mut response = [0_u8; 512];
    let (len, _) = socket.recv_from(&mut response).expect("recv response");
    parse_a_response(&response[..len])
}

fn dns_query(target: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x4242_u16.to_be_bytes());
    out.extend_from_slice(&0x0100_u16.to_be_bytes());
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    for label in target.trim_end_matches('.').split('.') {
        out.push(u8::try_from(label.len()).expect("label length"));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&1_u16.to_be_bytes());
    out
}

fn parse_a_response(packet: &[u8]) -> Vec<Ipv4Addr> {
    if packet.len() < 12 || packet[3] & 0x0f == 3 {
        return Vec::new();
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_name(packet, offset);
        offset = offset.saturating_add(4);
    }
    let mut addrs = Vec::new();
    for _ in 0..ancount {
        offset = skip_name(packet, offset);
        if offset + 10 > packet.len() {
            return addrs;
        }
        let rr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let rr_class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let rdlen = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > packet.len() {
            return addrs;
        }
        if rr_type == 1 && rr_class == 1 && rdlen == 4 {
            addrs.push(Ipv4Addr::new(
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            ));
        }
        offset += rdlen;
    }
    addrs
}

fn skip_name(packet: &[u8], mut offset: usize) -> usize {
    while offset < packet.len() {
        let len = packet[offset];
        offset += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 == 0xc0 {
            offset += 1;
            break;
        }
        offset += usize::from(len);
    }
    offset
}

fn format_addrs(addrs: &[Ipv4Addr]) -> String {
    addrs
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}
