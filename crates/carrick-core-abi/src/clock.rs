//! Typed clock-resource crossing record for ring-owned (native) processes.
//!
//! Both ISA entries share one fixed-size wire protocol (`CLOCK_RECORD_BYTES`)
//! staged in ring-owned supervisor storage:
//! - ARM EL1 submits the record via [`crate::service::ServiceOperation::Clock`].
//! - x86 CPL0 submits the record via `ClockResourceCrossing` on the synchronous
//!   physical port.
//!
//! Neither transport blocks a host executor thread or forwards a Linux syscall
//! to the legacy root dispatcher. Linux argument order, caller credentials,
//! guest CPU-clock accounting, user-memory fault policy, and retained copyout
//! remain in the ring; the host adapter serves bounded `ClockDomain` queries,
//! atomic `timex` updates, and non-blocking sleep deadline subscriptions.

use core::num::NonZeroU64;

/// Run-scoped capability naming the container's shared `ClockDomain` resource.
///
/// Minted before native root admission from the root process's birth serial,
/// inherited across `fork`/`clone`, and preserved across both host and native
/// `exec` until every process in the run has joined.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[repr(transparent)]
pub struct ClockCapabilityId(NonZeroU64);

impl ClockCapabilityId {
    pub const fn new(raw: NonZeroU64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> NonZeroU64 {
        self.0
    }
}

/// Fixed wire size of a staged clock-resource record (48-byte header + 208-byte `timex` area).
pub const CLOCK_RECORD_BYTES: usize = 256;

/// Fixed header size preceding the 208-byte payload area.
pub const CLOCK_HEADER_BYTES: usize = 48;

/// Linux `struct __kernel_timex` ABI byte size on 64-bit targets.
pub const CLOCK_TIMEX_BYTES: usize = 208;

const _: () = assert!(CLOCK_HEADER_BYTES + CLOCK_TIMEX_BYTES == CLOCK_RECORD_BYTES);

const CLOCK_RECORD_MAGIC: u32 = u32::from_le_bytes(*b"CCLK");
const CLOCK_RECORD_VERSION: u16 = 1;

/// Refusal diagnostic base above all syscall and host-file refusal ordinals.
pub const CLOCK_REFUSAL_ORDINAL_BASE: u64 = 0x2_0000;

/// Bounded operations served by the host `ClockDomain` resource owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ClockResourceOp {
    /// Sample a physical or virtual container clock (`arg0 = clock_id`).
    Sample = 1,
    /// Preflight state-dependent `timex` step validation before output preparation.
    TimexPreflight = 2,
    /// Atomically apply a validated `timex` request and format its 208-byte reply.
    TimexApply = 3,
    /// Sample/check a sleep deadline and arm or refresh non-blocking wake subscriptions.
    SleepArm = 4,
    /// Cancel an armed sleep subscription and optionally sample remaining duration.
    SleepCancel = 5,
}

impl ClockResourceOp {
    pub const fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::Sample),
            2 => Some(Self::TimexPreflight),
            3 => Some(Self::TimexApply),
            4 => Some(Self::SleepArm),
            5 => Some(Self::SleepCancel),
            _ => None,
        }
    }
}

/// Flags carried by [`ClockResourceOp::SleepArm`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockSleepFlags(u64);

impl ClockSleepFlags {
    pub const NONE: Self = Self(0);
    pub const ABSOLUTE: u64 = 1 << 0;
    pub const PINNED_DEADLINE: u64 = 1 << 1;

    pub const fn new(absolute: bool, pinned_deadline: bool) -> Self {
        let mut bits = 0;
        if absolute {
            bits |= Self::ABSOLUTE;
        }
        if pinned_deadline {
            bits |= Self::PINNED_DEADLINE;
        }
        Self(bits)
    }

    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw & !(Self::ABSOLUTE | Self::PINNED_DEADLINE) != 0 {
            return None;
        }
        Some(Self(raw))
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn is_absolute(self) -> bool {
        self.0 & Self::ABSOLUTE != 0
    }

    pub const fn has_pinned_deadline(self) -> bool {
        self.0 & Self::PINNED_DEADLINE != 0
    }
}

/// Ring wait-channel identity woken when an armed sleep expires or its clock changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockSleepChannel {
    pub record_id: u32,
    pub record_generation: u64,
    pub mm: u64,
    pub address: NonZeroU64,
}

/// Decoded request view over a validated 256-byte clock record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockRequest<'a> {
    Sample {
        clock_id: u64,
    },
    TimexPreflight {
        can_adjust: bool,
        timex: &'a [u8; CLOCK_TIMEX_BYTES],
    },
    TimexApply {
        can_adjust: bool,
        timex: &'a [u8; CLOCK_TIMEX_BYTES],
    },
    SleepArm {
        clock_id: u64,
        flags: ClockSleepFlags,
        sleep_id: Option<NonZeroU64>,
        secs: u64,
        nanos: u32,
        channel: ClockSleepChannel,
    },
    SleepCancel {
        sleep_id: NonZeroU64,
        clock_id: u64,
        compute_remaining: bool,
        deadline_secs: u64,
        deadline_nanos: u32,
    },
}

/// Decoded reply from a completed clock-resource record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockReply<'a> {
    Sample(Result<(u64, u32), i32>),
    TimexPreflight(Result<(), i32>),
    TimexApply(Result<(i64, &'a [u8; CLOCK_TIMEX_BYTES]), i32>),
    SleepArm(Result<ClockSleepArmOutcome, i32>),
    SleepCancel {
        remaining_secs: u64,
        remaining_nanos: u32,
    },
}

/// Non-blocking result of [`ClockResourceOp::SleepArm`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockSleepArmOutcome {
    Elapsed,
    Armed {
        sleep_id: NonZeroU64,
        deadline_secs: u64,
        deadline_nanos: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockRecordError {
    Invalid,
}

const REPLY_NONE: u32 = 0;
const REPLY_OK: u32 = 1;
const REPLY_ERRNO: u32 = 2;
const REPLY_ARMED: u32 = 3;

fn write_u16(buf: &mut [u8], offset: usize, val: u16) {
    buf[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
}

fn write_u32(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_u64(buf: &mut [u8], offset: usize, val: u64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        buf.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        buf.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(buf: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        buf.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn init_header(buf: &mut [u8; CLOCK_RECORD_BYTES], op: ClockResourceOp) {
    buf.fill(0);
    write_u32(buf, 0, CLOCK_RECORD_MAGIC);
    write_u16(buf, 4, CLOCK_RECORD_VERSION);
    write_u16(buf, 6, op as u16);
    write_u32(buf, 8, REPLY_NONE);
}

/// Encode a clock-sample request into `buf`.
pub fn encode_sample_request(buf: &mut [u8; CLOCK_RECORD_BYTES], clock_id: u64) {
    init_header(buf, ClockResourceOp::Sample);
    write_u64(buf, 16, clock_id);
}

/// Encode a `timex` preflight or apply request into `buf`.
pub fn encode_timex_request(
    buf: &mut [u8; CLOCK_RECORD_BYTES],
    preflight_only: bool,
    can_adjust: bool,
    timex: &[u8; CLOCK_TIMEX_BYTES],
) {
    init_header(
        buf,
        if preflight_only {
            ClockResourceOp::TimexPreflight
        } else {
            ClockResourceOp::TimexApply
        },
    );
    write_u64(buf, 16, u64::from(can_adjust));
    buf[CLOCK_HEADER_BYTES..].copy_from_slice(timex);
}

/// Encode a non-blocking sleep deadline poll/arm request into `buf`.
pub fn encode_sleep_arm_request(
    buf: &mut [u8; CLOCK_RECORD_BYTES],
    clock_id: u64,
    flags: ClockSleepFlags,
    sleep_id: Option<NonZeroU64>,
    secs: u64,
    nanos: u32,
    channel: ClockSleepChannel,
) {
    init_header(buf, ClockResourceOp::SleepArm);
    write_u32(buf, 12, nanos);
    write_u64(buf, 16, clock_id);
    write_u64(buf, 24, flags.raw());
    write_u64(buf, 32, sleep_id.map_or(0, NonZeroU64::get));
    write_u64(buf, 40, secs);
    write_u32(buf, CLOCK_HEADER_BYTES, channel.record_id);
    write_u64(buf, CLOCK_HEADER_BYTES + 8, channel.record_generation);
    write_u64(buf, CLOCK_HEADER_BYTES + 16, channel.mm);
    write_u64(buf, CLOCK_HEADER_BYTES + 24, channel.address.get());
}

/// Encode a sleep cancellation request into `buf`.
pub fn encode_sleep_cancel_request(
    buf: &mut [u8; CLOCK_RECORD_BYTES],
    sleep_id: NonZeroU64,
    clock_id: u64,
    compute_remaining: bool,
    deadline_secs: u64,
    deadline_nanos: u32,
) {
    init_header(buf, ClockResourceOp::SleepCancel);
    write_u32(buf, 12, deadline_nanos);
    write_u64(buf, 16, sleep_id.get());
    write_u64(buf, 24, clock_id);
    write_u64(buf, 32, u64::from(compute_remaining));
    write_u64(buf, 40, deadline_secs);
}

fn validate_envelope(bytes: &[u8]) -> Result<ClockResourceOp, ClockRecordError> {
    if bytes.len() != CLOCK_RECORD_BYTES
        || read_u32(bytes, 0) != Some(CLOCK_RECORD_MAGIC)
        || read_u16(bytes, 4) != Some(CLOCK_RECORD_VERSION)
    {
        return Err(ClockRecordError::Invalid);
    }
    let raw_op = read_u16(bytes, 6).ok_or(ClockRecordError::Invalid)?;
    ClockResourceOp::from_raw(raw_op).ok_or(ClockRecordError::Invalid)
}

/// Diagnostic refusal ordinal reported on `hvpatch-native-crossing-refused`.
pub fn refusal_ordinal(bytes: &[u8]) -> u64 {
    CLOCK_REFUSAL_ORDINAL_BASE + validate_envelope(bytes).map_or(0, |op| u64::from(op as u16))
}

/// Parse an unanswered clock-resource request on the host side.
pub fn parse_request(bytes: &[u8]) -> Result<ClockRequest<'_>, ClockRecordError> {
    let op = validate_envelope(bytes)?;
    if read_u32(bytes, 8) != Some(REPLY_NONE) {
        return Err(ClockRecordError::Invalid);
    }
    let aux = read_u32(bytes, 12).ok_or(ClockRecordError::Invalid)?;
    let w0 = read_u64(bytes, 16).ok_or(ClockRecordError::Invalid)?;
    let w1 = read_u64(bytes, 24).ok_or(ClockRecordError::Invalid)?;
    let w2 = read_u64(bytes, 32).ok_or(ClockRecordError::Invalid)?;
    let w3 = read_u64(bytes, 40).ok_or(ClockRecordError::Invalid)?;
    let payload: &[u8; CLOCK_TIMEX_BYTES] = bytes[CLOCK_HEADER_BYTES..]
        .try_into()
        .map_err(|_| ClockRecordError::Invalid)?;

    match op {
        ClockResourceOp::Sample => {
            if aux != 0 || w1 != 0 || w2 != 0 || w3 != 0 {
                return Err(ClockRecordError::Invalid);
            }
            Ok(ClockRequest::Sample { clock_id: w0 })
        }
        ClockResourceOp::TimexPreflight => {
            if aux != 0 || w0 > 1 || w1 != 0 || w2 != 0 || w3 != 0 {
                return Err(ClockRecordError::Invalid);
            }
            Ok(ClockRequest::TimexPreflight {
                can_adjust: w0 != 0,
                timex: payload,
            })
        }
        ClockResourceOp::TimexApply => {
            if aux != 0 || w0 > 1 || w1 != 0 || w2 != 0 || w3 != 0 {
                return Err(ClockRecordError::Invalid);
            }
            Ok(ClockRequest::TimexApply {
                can_adjust: w0 != 0,
                timex: payload,
            })
        }
        ClockResourceOp::SleepArm => {
            if aux >= 1_000_000_000 {
                return Err(ClockRecordError::Invalid);
            }
            let flags = ClockSleepFlags::from_raw(w1).ok_or(ClockRecordError::Invalid)?;
            let record_id = read_u32(bytes, CLOCK_HEADER_BYTES).ok_or(ClockRecordError::Invalid)?;
            let record_generation =
                read_u64(bytes, CLOCK_HEADER_BYTES + 8).ok_or(ClockRecordError::Invalid)?;
            let mm = read_u64(bytes, CLOCK_HEADER_BYTES + 16).ok_or(ClockRecordError::Invalid)?;
            let address_raw =
                read_u64(bytes, CLOCK_HEADER_BYTES + 24).ok_or(ClockRecordError::Invalid)?;
            let address = NonZeroU64::new(address_raw).ok_or(ClockRecordError::Invalid)?;
            if mm == 0 {
                return Err(ClockRecordError::Invalid);
            }
            Ok(ClockRequest::SleepArm {
                clock_id: w0,
                flags,
                sleep_id: NonZeroU64::new(w2),
                secs: w3,
                nanos: aux,
                channel: ClockSleepChannel {
                    record_id,
                    record_generation,
                    mm,
                    address,
                },
            })
        }
        ClockResourceOp::SleepCancel => {
            if aux >= 1_000_000_000 || w2 > 1 {
                return Err(ClockRecordError::Invalid);
            }
            let sleep_id = NonZeroU64::new(w0).ok_or(ClockRecordError::Invalid)?;
            Ok(ClockRequest::SleepCancel {
                sleep_id,
                clock_id: w1,
                compute_remaining: w2 != 0,
                deadline_secs: w3,
                deadline_nanos: aux,
            })
        }
    }
}

/// Write an errno failure reply in place.
pub fn write_errno_reply(bytes: &mut [u8], errno: i32) -> Result<(), ClockRecordError> {
    let _ = validate_envelope(bytes)?;
    if errno <= 0 {
        return Err(ClockRecordError::Invalid);
    }
    write_u32(bytes, 8, REPLY_ERRNO);
    write_u32(bytes, 12, errno as u32);
    Ok(())
}

/// Write a successful [`ClockResourceOp::Sample`] reply in place.
pub fn write_sample_reply(bytes: &mut [u8], secs: u64, nanos: u32) -> Result<(), ClockRecordError> {
    if validate_envelope(bytes)? != ClockResourceOp::Sample || nanos >= 1_000_000_000 {
        return Err(ClockRecordError::Invalid);
    }
    write_u32(bytes, 8, REPLY_OK);
    write_u32(bytes, 12, nanos);
    write_u64(bytes, 16, secs);
    Ok(())
}

/// Write a successful [`ClockResourceOp::TimexPreflight`] reply in place.
pub fn write_timex_preflight_ok(bytes: &mut [u8]) -> Result<(), ClockRecordError> {
    if validate_envelope(bytes)? != ClockResourceOp::TimexPreflight {
        return Err(ClockRecordError::Invalid);
    }
    write_u32(bytes, 8, REPLY_OK);
    write_u32(bytes, 12, 0);
    Ok(())
}

/// Write a successful [`ClockResourceOp::TimexApply`] reply in place.
pub fn write_timex_apply_reply(
    bytes: &mut [u8],
    return_value: i64,
    output: &[u8; CLOCK_TIMEX_BYTES],
) -> Result<(), ClockRecordError> {
    if validate_envelope(bytes)? != ClockResourceOp::TimexApply || return_value < 0 {
        return Err(ClockRecordError::Invalid);
    }
    write_u32(bytes, 8, REPLY_OK);
    write_u32(bytes, 12, 0);
    write_u64(bytes, 16, return_value as u64);
    bytes[CLOCK_HEADER_BYTES..].copy_from_slice(output);
    Ok(())
}

/// Write a [`ClockResourceOp::SleepArm`] reply in place.
pub fn write_sleep_arm_reply(
    bytes: &mut [u8],
    outcome: ClockSleepArmOutcome,
) -> Result<(), ClockRecordError> {
    if validate_envelope(bytes)? != ClockResourceOp::SleepArm {
        return Err(ClockRecordError::Invalid);
    }
    match outcome {
        ClockSleepArmOutcome::Elapsed => {
            write_u32(bytes, 8, REPLY_OK);
            write_u32(bytes, 12, 0);
        }
        ClockSleepArmOutcome::Armed {
            sleep_id,
            deadline_secs,
            deadline_nanos,
        } => {
            if deadline_nanos >= 1_000_000_000 {
                return Err(ClockRecordError::Invalid);
            }
            write_u32(bytes, 8, REPLY_ARMED);
            write_u32(bytes, 12, deadline_nanos);
            write_u64(bytes, 16, sleep_id.get());
            write_u64(bytes, 24, deadline_secs);
        }
    }
    Ok(())
}

/// Write a [`ClockResourceOp::SleepCancel`] reply in place.
pub fn write_sleep_cancel_reply(
    bytes: &mut [u8],
    remaining_secs: u64,
    remaining_nanos: u32,
) -> Result<(), ClockRecordError> {
    if validate_envelope(bytes)? != ClockResourceOp::SleepCancel || remaining_nanos >= 1_000_000_000
    {
        return Err(ClockRecordError::Invalid);
    }
    write_u32(bytes, 8, REPLY_OK);
    write_u32(bytes, 12, remaining_nanos);
    write_u64(bytes, 16, remaining_secs);
    Ok(())
}

/// Whether the carrier has written a valid reply into `bytes`.
pub fn has_reply(bytes: &[u8]) -> bool {
    parse_reply(bytes).is_ok()
}

/// Parse a completed clock-resource reply in the ring.
pub fn parse_reply(bytes: &[u8]) -> Result<ClockReply<'_>, ClockRecordError> {
    let op = validate_envelope(bytes)?;
    let tag = read_u32(bytes, 8).ok_or(ClockRecordError::Invalid)?;
    let aux = read_u32(bytes, 12).ok_or(ClockRecordError::Invalid)?;
    let w0 = read_u64(bytes, 16).ok_or(ClockRecordError::Invalid)?;
    let w1 = read_u64(bytes, 24).ok_or(ClockRecordError::Invalid)?;

    if tag == REPLY_NONE {
        return Err(ClockRecordError::Invalid);
    }
    if tag == REPLY_ERRNO {
        let errno = i32::try_from(aux).map_err(|_| ClockRecordError::Invalid)?;
        if errno <= 0 {
            return Err(ClockRecordError::Invalid);
        }
        return match op {
            ClockResourceOp::Sample => Ok(ClockReply::Sample(Err(errno))),
            ClockResourceOp::TimexPreflight => Ok(ClockReply::TimexPreflight(Err(errno))),
            ClockResourceOp::TimexApply => Ok(ClockReply::TimexApply(Err(errno))),
            ClockResourceOp::SleepArm => Ok(ClockReply::SleepArm(Err(errno))),
            ClockResourceOp::SleepCancel => Err(ClockRecordError::Invalid),
        };
    }

    match (op, tag) {
        (ClockResourceOp::Sample, REPLY_OK) => {
            if aux >= 1_000_000_000 {
                return Err(ClockRecordError::Invalid);
            }
            Ok(ClockReply::Sample(Ok((w0, aux))))
        }
        (ClockResourceOp::TimexPreflight, REPLY_OK) => Ok(ClockReply::TimexPreflight(Ok(()))),
        (ClockResourceOp::TimexApply, REPLY_OK) => {
            let value = i64::try_from(w0).map_err(|_| ClockRecordError::Invalid)?;
            let output: &[u8; CLOCK_TIMEX_BYTES] = bytes[CLOCK_HEADER_BYTES..]
                .try_into()
                .map_err(|_| ClockRecordError::Invalid)?;
            Ok(ClockReply::TimexApply(Ok((value, output))))
        }
        (ClockResourceOp::SleepArm, REPLY_OK) => {
            Ok(ClockReply::SleepArm(Ok(ClockSleepArmOutcome::Elapsed)))
        }
        (ClockResourceOp::SleepArm, REPLY_ARMED) => {
            if aux >= 1_000_000_000 {
                return Err(ClockRecordError::Invalid);
            }
            let sleep_id = NonZeroU64::new(w0).ok_or(ClockRecordError::Invalid)?;
            Ok(ClockReply::SleepArm(Ok(ClockSleepArmOutcome::Armed {
                sleep_id,
                deadline_secs: w1,
                deadline_nanos: aux,
            })))
        }
        (ClockResourceOp::SleepCancel, REPLY_OK) => {
            if aux >= 1_000_000_000 {
                return Err(ClockRecordError::Invalid);
            }
            Ok(ClockReply::SleepCancel {
                remaining_secs: w0,
                remaining_nanos: aux,
            })
        }
        _ => Err(ClockRecordError::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_roundtrip_and_unanswered_rejection() {
        let mut buf = [0u8; CLOCK_RECORD_BYTES];
        encode_sample_request(&mut buf, 7);
        assert!(!has_reply(&buf));
        assert_eq!(
            parse_request(&buf),
            Ok(ClockRequest::Sample { clock_id: 7 })
        );
        write_sample_reply(&mut buf, 1_700_000_123, 456_789_012).unwrap();
        assert_eq!(parse_request(&buf), Err(ClockRecordError::Invalid));
        assert_eq!(
            parse_reply(&buf),
            Ok(ClockReply::Sample(Ok((1_700_000_123, 456_789_012))))
        );
    }

    #[test]
    fn timex_apply_and_errno_roundtrip() {
        let mut buf = [0u8; CLOCK_RECORD_BYTES];
        let mut input = [0u8; CLOCK_TIMEX_BYTES];
        input[0] = 0x5a;
        input[207] = 0xa5;
        encode_timex_request(&mut buf, false, true, &input);
        assert_eq!(
            parse_request(&buf),
            Ok(ClockRequest::TimexApply {
                can_adjust: true,
                timex: &input,
            })
        );
        let mut out = [0u8; CLOCK_TIMEX_BYTES];
        out[8] = 42;
        write_timex_apply_reply(&mut buf, 5, &out).unwrap();
        assert_eq!(parse_reply(&buf), Ok(ClockReply::TimexApply(Ok((5, &out)))));

        encode_timex_request(&mut buf, true, false, &input);
        write_errno_reply(&mut buf, 22).unwrap();
        assert_eq!(parse_reply(&buf), Ok(ClockReply::TimexPreflight(Err(22))));
    }

    #[test]
    fn sleep_arm_and_cancel_roundtrip() {
        let mut buf = [0u8; CLOCK_RECORD_BYTES];
        let channel = ClockSleepChannel {
            record_id: 3,
            record_generation: 9,
            mm: 11,
            address: NonZeroU64::new(0x1000).unwrap(),
        };
        let flags = ClockSleepFlags::new(true, false);
        encode_sleep_arm_request(&mut buf, 0, flags, None, 100, 250, channel);
        assert_eq!(
            parse_request(&buf),
            Ok(ClockRequest::SleepArm {
                clock_id: 0,
                flags,
                sleep_id: None,
                secs: 100,
                nanos: 250,
                channel,
            })
        );
        let id = NonZeroU64::new(77).unwrap();
        write_sleep_arm_reply(
            &mut buf,
            ClockSleepArmOutcome::Armed {
                sleep_id: id,
                deadline_secs: 100,
                deadline_nanos: 250,
            },
        )
        .unwrap();
        assert_eq!(
            parse_reply(&buf),
            Ok(ClockReply::SleepArm(Ok(ClockSleepArmOutcome::Armed {
                sleep_id: id,
                deadline_secs: 100,
                deadline_nanos: 250,
            })))
        );

        encode_sleep_cancel_request(&mut buf, id, 1, true, 100, 250);
        assert_eq!(
            parse_request(&buf),
            Ok(ClockRequest::SleepCancel {
                sleep_id: id,
                clock_id: 1,
                compute_remaining: true,
                deadline_secs: 100,
                deadline_nanos: 250,
            })
        );
        write_sleep_cancel_reply(&mut buf, 0, 500_000).unwrap();
        assert_eq!(
            parse_reply(&buf),
            Ok(ClockReply::SleepCancel {
                remaining_secs: 0,
                remaining_nanos: 500_000,
            })
        );
    }
}
