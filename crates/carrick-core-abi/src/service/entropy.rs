//! Bounded entropy exchange owned by one authenticated native continuation.
//!
//! The address names ring staging, never a user buffer. The service ticket
//! authenticates its member and MM; this descriptor alone grants no access.
use carrick_guest_arch::{GuestLen, GuestVa};

pub const MAX_ENTROPY_BYTES: usize = crate::mm::MM_PORTAL_MAX_BYTES as usize;
pub const ENTROPY_HEADER_BYTES: usize = 32;
const _: () = assert!(MAX_ENTROPY_BYTES <= u32::MAX as usize - ENTROPY_HEADER_BYTES);
const MAGIC: u32 = u32::from_le_bytes(*b"CENT");
const VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntropyPayloadDescriptor {
    address: GuestVa,
    length: GuestLen,
}
impl EntropyPayloadDescriptor {
    pub const fn checked(address: GuestVa, length: GuestLen) -> Option<Self> {
        if address.raw() == 0
            || length.raw() < ENTROPY_HEADER_BYTES as u64
            || length.raw() > (ENTROPY_HEADER_BYTES + MAX_ENTROPY_BYTES) as u64
            || address.raw().checked_add(length.raw()).is_none()
        {
            return None;
        }
        Some(Self { address, length })
    }
    pub const fn address(self) -> GuestVa {
        self.address
    }
    pub const fn length(self) -> GuestLen {
        self.length
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidEntropyRecord;

/// Validated request fields. Flags are opaque to this neutral protocol;
/// their Linux interpretation belongs to the existing getrandom handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntropyRequest {
    pub flags: u32,
    pub capacity: usize,
}

fn word(record: &[u8], offset: usize) -> Result<u32, InvalidEntropyRecord> {
    Ok(u32::from_le_bytes(
        record
            .get(offset..offset + 4)
            .ok_or(InvalidEntropyRecord)?
            .try_into()
            .map_err(|_| InvalidEntropyRecord)?,
    ))
}
fn header(record: &[u8]) -> Result<EntropyRequest, InvalidEntropyRecord> {
    if word(record, 0)? != MAGIC || word(record, 4)? != VERSION || word(record, 28)? != 0 {
        return Err(InvalidEntropyRecord);
    }
    let capacity = word(record, 12)? as usize;
    if capacity > MAX_ENTROPY_BYTES || record.len() != ENTROPY_HEADER_BYTES + capacity {
        return Err(InvalidEntropyRecord);
    }
    Ok(EntropyRequest {
        flags: word(record, 8)?,
        capacity,
    })
}

pub fn encode_request(record: &mut [u8], flags: u32) -> Result<(), InvalidEntropyRecord> {
    let capacity = record
        .len()
        .checked_sub(ENTROPY_HEADER_BYTES)
        .filter(|capacity| *capacity <= MAX_ENTROPY_BYTES)
        .ok_or(InvalidEntropyRecord)?;
    record.fill(0);
    for (offset, value) in [(0, MAGIC), (4, VERSION), (8, flags), (12, capacity as u32)] {
        record[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

pub fn request(record: &[u8]) -> Result<EntropyRequest, InvalidEntropyRecord> {
    let request = header(record)?;
    if word(record, 16)? != 0 || word(record, 20)? != 0 || word(record, 24)? != 0 {
        return Err(InvalidEntropyRecord);
    }
    Ok(request)
}

/// Publish only after the handler has filled staging. No invalid reply can
/// partially change the request. The ticket's release ACK publishes the bytes.
pub fn publish_reply(record: &mut [u8], result: i64) -> Result<(), InvalidEntropyRecord> {
    let request = request(record)?;
    if !valid_result(result, request.capacity) {
        return Err(InvalidEntropyRecord);
    }
    record[16..24].copy_from_slice(&result.to_le_bytes());
    record[24..28].copy_from_slice(&1u32.to_le_bytes());
    Ok(())
}

pub fn reply(record: &[u8]) -> Result<(i64, &[u8]), InvalidEntropyRecord> {
    let request = header(record)?;
    if word(record, 24)? != 1 {
        return Err(InvalidEntropyRecord);
    }
    let result = i64::from_le_bytes(
        record[16..24]
            .try_into()
            .map_err(|_| InvalidEntropyRecord)?,
    );
    if !valid_result(result, request.capacity) {
        return Err(InvalidEntropyRecord);
    }
    let count = usize::try_from(result).unwrap_or(0);
    Ok((
        result,
        &record[ENTROPY_HEADER_BYTES..ENTROPY_HEADER_BYTES + count],
    ))
}

fn valid_result(result: i64, capacity: usize) -> bool {
    (-4095..=capacity as i64).contains(&result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_record_roundtrips_bounded_requests_and_replies() {
        for capacity in [0, 1, 8, MAX_ENTROPY_BYTES] {
            for flags in [0, 1, 7, u32::MAX] {
                let mut record = alloc::vec![0xa5; ENTROPY_HEADER_BYTES + capacity];
                encode_request(&mut record, flags).unwrap();
                assert_eq!(request(&record), Ok(EntropyRequest { flags, capacity }));
                assert!(reply(&record).is_err());
                record[ENTROPY_HEADER_BYTES..].fill(0x73);
                publish_reply(&mut record, capacity as i64).unwrap();
                let (result, bytes) = reply(&record).unwrap();
                assert_eq!(result, capacity as i64);
                assert_eq!(bytes, alloc::vec![0x73; capacity]);
                assert!(request(&record).is_err());
                assert!(publish_reply(&mut record, 0).is_err());
            }
        }
    }

    #[test]
    fn entropy_record_rejects_malformed_lengths_states_reserved_and_counts() {
        for length in [
            0,
            ENTROPY_HEADER_BYTES - 1,
            ENTROPY_HEADER_BYTES + MAX_ENTROPY_BYTES + 1,
        ] {
            assert!(encode_request(&mut alloc::vec![0; length], 0).is_err());
        }
        let mut record = alloc::vec![0; ENTROPY_HEADER_BYTES + 8];
        encode_request(&mut record, 1).unwrap();
        for offset in [0, 4, 12, 16, 20, 24, 28] {
            let mut invalid = record.clone();
            invalid[offset] ^= 0x80;
            assert!(request(&invalid).is_err(), "offset {offset}");
        }
        for result in [9, i64::MAX, -4096, i64::MIN] {
            let before = record.clone();
            assert!(publish_reply(&mut record, result).is_err());
            assert_eq!(record, before);
            let mut invalid = record.clone();
            invalid[16..24].copy_from_slice(&result.to_le_bytes());
            invalid[24..28].copy_from_slice(&1u32.to_le_bytes());
            assert!(reply(&invalid).is_err());
        }
        for result in [-4095, -14, 0, 3, 8] {
            let mut valid = record.clone();
            publish_reply(&mut valid, result).unwrap();
            assert_eq!(reply(&valid).unwrap().0, result);
        }
    }

    #[test]
    fn entropy_descriptor_rejects_wrapped_null_and_unbounded_staging() {
        for (address, length) in [
            (0, 32),
            (u64::MAX - 16, 32),
            (1, 31),
            (1, 4129),
            (1, u64::MAX),
        ] {
            assert!(
                EntropyPayloadDescriptor::checked(GuestVa::new(address), GuestLen::new(length))
                    .is_none()
            );
        }
        for length in [32, 40, 4128] {
            let descriptor =
                EntropyPayloadDescriptor::checked(GuestVa::new(4096), GuestLen::new(length))
                    .unwrap();
            assert_eq!(descriptor.address().raw(), 4096);
            assert_eq!(descriptor.length().raw(), length);
        }
    }
}
