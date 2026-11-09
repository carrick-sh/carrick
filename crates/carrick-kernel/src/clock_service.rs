//! Bounded host `ClockDomain` resource adapter for ring-owned processes.
//!
//! Serves the fixed-size `carrick_core_abi::clock` wire protocol without
//! blocking any vCPU executor thread or routing Linux syscalls through the
//! legacy root dispatcher.

use std::sync::Arc;
use std::time::Duration;

use carrick_abi::{
    LINUX_CLOCK_BOOTTIME, LINUX_CLOCK_BOOTTIME_ALARM, LINUX_CLOCK_MONOTONIC,
    LINUX_CLOCK_MONOTONIC_COARSE, LINUX_CLOCK_MONOTONIC_RAW, LINUX_CLOCK_REALTIME,
    LINUX_CLOCK_REALTIME_ALARM, LINUX_CLOCK_REALTIME_COARSE, LINUX_CLOCK_TAI, LINUX_EINVAL,
    LINUX_EPERM, LinuxTimeval, LinuxTimex,
};
use carrick_core_abi::clock::{
    CLOCK_RECORD_BYTES, CLOCK_TIMEX_BYTES, ClockRecordError, ClockRequest, parse_request,
    write_errno_reply, write_sample_reply, write_timex_apply_reply, write_timex_preflight_ok,
};
use carrick_time_core::{TimexAccess, TimexRequest, TimexValidationError};
use zerocopy::{FromBytes, IntoBytes};

use crate::dispatch::format_time::linux_coarse_duration;
use crate::kernel::container::ClockDomain;

/// Run-scoped host adapter serving `carrick_core_abi::clock` records against
/// one container's [`ClockDomain`]. Sleeps never reach it: the ring's signal
/// wait owner serves them on the scheduler timer (#1808).
pub struct ClockResourceService {
    clock: Arc<ClockDomain>,
}

impl std::fmt::Debug for ClockResourceService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClockResourceService")
            .field("clock", &self.clock)
            .finish_non_exhaustive()
    }
}

impl ClockResourceService {
    pub fn new(clock: Arc<ClockDomain>) -> Self {
        Self { clock }
    }

    pub fn clock(&self) -> &Arc<ClockDomain> {
        &self.clock
    }

    /// Validate and answer one 256-byte staged clock-resource record in place.
    pub fn serve_record(
        &self,
        bytes: &mut [u8; CLOCK_RECORD_BYTES],
    ) -> Result<(), ClockRecordError> {
        let request = parse_request(bytes)?;
        match request {
            ClockRequest::Sample { clock_id } => {
                match sample_container_clock(&self.clock, clock_id) {
                    Ok(now) => write_sample_reply(bytes, now.as_secs(), now.subsec_nanos()),
                    Err(errno) => write_errno_reply(bytes, errno),
                }
            }
            ClockRequest::TimexPreflight { can_adjust, timex } => {
                let timex = *timex;
                self.serve_timex_preflight(bytes, can_adjust, &timex)
            }
            ClockRequest::TimexApply { can_adjust, timex } => {
                let timex = *timex;
                self.serve_timex_apply(bytes, can_adjust, &timex)
            }
        }
    }

    fn serve_timex_preflight(
        &self,
        bytes: &mut [u8; CLOCK_RECORD_BYTES],
        can_adjust: bool,
        raw_timex: &[u8; CLOCK_TIMEX_BYTES],
    ) -> Result<(), ClockRecordError> {
        let Ok(parsed) = LinuxTimex::read_from_bytes(raw_timex) else {
            return Err(ClockRecordError::Invalid);
        };
        let access = if can_adjust {
            TimexAccess::Adjust
        } else {
            TimexAccess::ReadOnly
        };
        let request = match TimexRequest::validate(&parsed, access) {
            Ok(req) => req,
            Err(TimexValidationError::Errno(errno)) => {
                return write_errno_reply(bytes, errno);
            }
            Err(TimexValidationError::InvalidModeOutput) => {
                return write_errno_reply(bytes, LINUX_EINVAL);
            }
        };
        let step = match request.realtime_step(|| {
            carrick_abi::LinuxTimexStatus::from_bits_retain(self.clock.adjtimex_state().status)
        }) {
            Ok(step) => step,
            Err(errno) => return write_errno_reply(bytes, errno),
        };
        if step.is_some() && self.clock.is_controlled() {
            return write_errno_reply(bytes, LINUX_EPERM);
        }
        write_timex_preflight_ok(bytes)
    }

    fn serve_timex_apply(
        &self,
        bytes: &mut [u8; CLOCK_RECORD_BYTES],
        can_adjust: bool,
        raw_timex: &[u8; CLOCK_TIMEX_BYTES],
    ) -> Result<(), ClockRecordError> {
        let Ok(parsed) = LinuxTimex::read_from_bytes(raw_timex) else {
            return Err(ClockRecordError::Invalid);
        };
        let access = if can_adjust {
            TimexAccess::Adjust
        } else {
            TimexAccess::ReadOnly
        };
        let request = match TimexRequest::validate(&parsed, access) {
            Ok(req) => req,
            Err(TimexValidationError::Errno(errno)) => {
                return write_errno_reply(bytes, errno);
            }
            Err(TimexValidationError::InvalidModeOutput) => {
                return write_errno_reply(bytes, LINUX_EINVAL);
            }
        };
        let mut output = LinuxTimex::new_read_state(LinuxTimeval::new(0, 0));
        match self.clock.apply_timex(&request, &mut output) {
            Ok(value) => {
                let out_bytes: &[u8; CLOCK_TIMEX_BYTES] = output
                    .as_bytes()
                    .try_into()
                    .map_err(|_| ClockRecordError::Invalid)?;
                write_timex_apply_reply(bytes, value, out_bytes)
            }
            Err(errno) => write_errno_reply(bytes, errno),
        }
    }
}

fn sample_container_clock(
    clock: &ClockDomain,
    clock_id: u64,
) -> Result<Duration, carrick_abi::LinuxErrno> {
    match clock_id {
        LINUX_CLOCK_REALTIME | LINUX_CLOCK_REALTIME_ALARM | LINUX_CLOCK_TAI => {
            Ok(clock.realtime_now())
        }
        LINUX_CLOCK_REALTIME_COARSE => Ok(linux_coarse_duration(clock.realtime_now())),
        LINUX_CLOCK_MONOTONIC | LINUX_CLOCK_MONOTONIC_RAW => Ok(clock.monotonic_now()),
        LINUX_CLOCK_MONOTONIC_COARSE => Ok(linux_coarse_duration(clock.monotonic_now())),
        LINUX_CLOCK_BOOTTIME | LINUX_CLOCK_BOOTTIME_ALARM => Ok(clock.boottime_now()),
        _ => Err(LINUX_EINVAL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_core_abi::clock::{ClockReply, encode_sample_request, parse_reply};
    use std::time::UNIX_EPOCH;

    #[test]
    fn sample_reads_the_container_clock() {
        let clock = Arc::new(ClockDomain::deterministic(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        ));
        let service = ClockResourceService::new(Arc::clone(&clock));
        let mut buf = [0u8; CLOCK_RECORD_BYTES];
        encode_sample_request(&mut buf, LINUX_CLOCK_MONOTONIC);
        service.serve_record(&mut buf).unwrap();
        assert_eq!(parse_reply(&buf), Ok(ClockReply::Sample(Ok((0, 0)))));
        encode_sample_request(&mut buf, carrick_abi::LINUX_CLOCK_PROCESS_CPUTIME_ID);
        service.serve_record(&mut buf).unwrap();
        assert_eq!(parse_reply(&buf), Ok(ClockReply::Sample(Err(LINUX_EINVAL))));
    }
}
