use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use std::net::Ipv4Addr;

const DNS_TTL_SECS: u32 = 0;

/// Resolve `name` to its IPv4 addresses for the guest's synthetic DNS server.
///
/// Deliberately does NOT use `getaddrinfo` (`ToSocketAddrs`). On macOS that goes
/// through mDNSResponder, which initializes ObjC classes on a host thread — and
/// carrick forks the host process to service a guest `execve`. A fork landing
/// while `+[NSNumber initialize]` is in progress aborts the child outright:
///
///     objc[...]: +[NSNumber initialize] may have been in progress in another
///     thread when fork() was called. ... Crashing instead.
///
/// That killed `node-libuv` in `--network bridge` mode before it emitted a
/// single TAP line (exit 134). Proven by single-variable experiment: stubbing
/// this function out took the same run from 0 TAP lines and 4 ObjC aborts to 507
/// TAP lines and zero. `carrick trace` could not have shown it any more clearly,
/// and the fork-unsafety is structural, not a race worth retrying.
///
/// So the lookup is done here instead, over plain UDP with `hickory-proto` (which
/// this module already uses to BUILD the guest's responses). Every step is
/// fork-safe: a file read and a datagram socket, no libc resolver, no framework.
pub fn resolve_host_a(name: &str) -> Vec<Ipv4Addr> {
    // A literal address is its own answer — no resolver, and the guest may hand
    // us one directly.
    if let Ok(addr) = name.trim_end_matches('.').parse::<Ipv4Addr>() {
        return vec![addr];
    }
    let mut addrs = hosts_file_lookup(name);
    if addrs.is_empty() {
        addrs = udp_query_a(name);
    }
    addrs.sort_unstable();
    addrs.dedup();
    addrs
}

/// `/etc/hosts` first, exactly as a resolver would: `localhost` and any operator
/// override must not depend on a nameserver being reachable.
fn hosts_file_lookup(name: &str) -> Vec<Ipv4Addr> {
    let want = name.trim_end_matches('.').to_ascii_lowercase();
    let Ok(text) = std::fs::read_to_string("/etc/hosts") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut fields = line.split_whitespace();
        let Some(addr) = fields.next().and_then(|a| a.parse::<Ipv4Addr>().ok()) else {
            continue;
        };
        if fields.any(|host| host.to_ascii_lowercase() == want) {
            out.push(addr);
        }
    }
    out
}

/// Nameservers from `/etc/resolv.conf`. A plain file read, so it stays fork-safe;
/// macOS keeps this file generated and current.
fn resolv_conf_nameservers() -> Vec<std::net::Ipv4Addr> {
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("");
            let mut fields = line.split_whitespace();
            match fields.next() {
                Some("nameserver") => fields.next()?.parse::<Ipv4Addr>().ok(),
                _ => None,
            }
        })
        .collect()
}

/// One A query per nameserver until one answers. Bounded by an explicit timeout:
/// this runs on the guest's DNS path, so an unreachable resolver must fail fast
/// rather than stall the guest.
fn udp_query_a(name: &str) -> Vec<Ipv4Addr> {
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;
    use std::net::UdpSocket;

    let Ok(parsed) = Name::from_utf8(name) else {
        return Vec::new();
    };
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(parsed, RecordType::A));
    let Some(request) = encode_message(&query) else {
        return Vec::new();
    };

    for server in resolv_conf_nameservers() {
        let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
            continue;
        };
        if socket
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .is_err()
            || socket.send_to(&request, (server, 53)).is_err()
        {
            continue;
        }
        let mut buf = [0u8; 1500];
        let Ok((len, _)) = socket.recv_from(&mut buf) else {
            continue;
        };
        let Ok(response) = Message::from_vec(&buf[..len]) else {
            continue;
        };
        if response.metadata.id != query.metadata.id {
            continue;
        }
        let addrs: Vec<Ipv4Addr> = response
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(A(addr)) => Some(*addr),
                _ => None,
            })
            .collect();
        if !addrs.is_empty() {
            return addrs;
        }
    }
    Vec::new()
}

pub fn build_a_response<F>(request: &[u8], mut lookup: F) -> Option<Vec<u8>>
where
    F: FnMut(&str) -> Vec<Ipv4Addr>,
{
    let query = Message::from_vec(request).ok()?;
    let question = query.queries.first()?.clone();
    let mut response = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    response.add_query(question.clone());
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = false;
    response.metadata.authoritative = true;

    if query.metadata.message_type != MessageType::Query || query.metadata.op_code != OpCode::Query
    {
        response.metadata.response_code = ResponseCode::NotImp;
        return encode_message(&response);
    }
    if question.query_type() != RecordType::A {
        response.metadata.response_code = ResponseCode::NoError;
        return encode_message(&response);
    }

    let name = question.name().to_ascii();
    let addrs = lookup(&name);
    if addrs.is_empty() {
        response.metadata.response_code = ResponseCode::NXDomain;
    } else {
        response.metadata.response_code = ResponseCode::NoError;
        for addr in addrs {
            response.add_answer(Record::from_rdata(
                question.name().clone(),
                DNS_TTL_SECS,
                RData::A(A(addr)),
            ));
        }
    }
    encode_message(&response)
}

fn encode_message(message: &Message) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut bytes);
    message.emit(&mut encoder).ok()?;
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::Name;

    #[test]
    fn host_lookup_filters_to_ipv4() {
        assert_eq!(resolve_host_a("127.0.0.1"), vec![Ipv4Addr::LOCALHOST]);
    }

    #[test]
    fn builds_a_record_response() {
        let mut query = Message::query();
        query.add_query(Query::query(
            Name::from_ascii("web.").expect("name"),
            RecordType::A,
        ));
        let request = encode_message(&query).expect("encode query");

        let response =
            build_a_response(&request, |_| vec![Ipv4Addr::new(172, 31, 20, 9)]).expect("response");
        let parsed = Message::from_vec(&response).expect("parse response");

        assert_eq!(parsed.metadata.response_code, ResponseCode::NoError);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(
            &parsed.answers[0].data,
            &RData::A(A(Ipv4Addr::new(172, 31, 20, 9)))
        );
    }

    #[test]
    fn unknown_a_query_returns_nxdomain() {
        let mut query = Message::query();
        query.add_query(Query::query(
            Name::from_ascii("missing.").expect("name"),
            RecordType::A,
        ));
        let request = encode_message(&query).expect("encode query");

        let response = build_a_response(&request, |_| Vec::new()).expect("response");
        let parsed = Message::from_vec(&response).expect("parse response");

        assert_eq!(parsed.metadata.response_code, ResponseCode::NXDomain);
        assert!(parsed.answers.is_empty());
    }
}
