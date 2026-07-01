use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use std::net::Ipv4Addr;

const DNS_TTL_SECS: u32 = 0;

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
