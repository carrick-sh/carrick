//! Clock reads whose Linux semantics are shared by both ring entries.

use crate::abi::entry::SyscallResult;
use crate::lifecycle::{LifecycleNative, LifecycleOutcome};
use carrick_guest_arch::{CounterFrequency, CounterTick, UserVa};
use carrick_syscall_abi::{
    LINUX_CLOCK_MONOTONIC, LINUX_CLOCK_MONOTONIC_RAW, LINUX_CLOCK_REALTIME,
    LINUX_CLOCK_REALTIME_COARSE, LINUX_CLOCK_RESOLUTION_NSEC, LINUX_EFAULT, LINUX_EINVAL,
    linux_clock_resolution_ns,
};

pub(crate) fn clock_getres(native: &mut dyn LifecycleNative<'_>) -> LifecycleOutcome {
    let [clock, output, ..] = native.arguments();
    let result = match linux_clock_resolution_ns(clock as i32) {
        None => SyscallResult::from_errno(LINUX_EINVAL),
        Some(_) if output == 0 => SyscallResult::new(0),
        Some(nanos) => {
            return native.finish_signal_output(
                UserVa::new(output),
                crate::sleep::timespec_bytes(nanos as u64).to_vec(),
                false,
            );
        }
    };
    LifecycleOutcome::Returned {
        result,
        work: false,
    }
}

pub(crate) const fn uses_monotonic_counter(clock: u64) -> bool {
    matches!(
        clock as i32 as u64,
        LINUX_CLOCK_MONOTONIC | LINUX_CLOCK_MONOTONIC_RAW
    )
}

pub(crate) const fn uses_realtime_counter(clock: u64) -> bool {
    matches!(
        clock as i32 as u64,
        LINUX_CLOCK_REALTIME | LINUX_CLOCK_REALTIME_COARSE
    )
}

fn counter_nanos(sample: CounterTick, frequency: CounterFrequency) -> u64 {
    (u128::from(sample.raw()) * 1_000_000_000 / u128::from(frequency.raw().get())) as u64
}

fn realtime_nanos(native: &mut dyn LifecycleNative<'_>) -> Option<u64> {
    let (sample, frequency, offset) = native.realtime_counter()?;
    Some(counter_nanos(sample, frequency).wrapping_add(offset))
}

fn bad_output() -> LifecycleOutcome {
    LifecycleOutcome::Returned {
        result: SyscallResult::from_errno(LINUX_EFAULT),
        work: false,
    }
}

/// Use the same epoch and conversion as the vDSO. A venue without an
/// admitted sample retains its existing dispatch policy.
pub(crate) fn clock_gettime(native: &mut dyn LifecycleNative<'_>) -> Option<LifecycleOutcome> {
    let [clock, output, ..] = native.arguments();
    let nanos = if uses_monotonic_counter(clock) {
        if output == 0 {
            return Some(bad_output());
        }
        let (sample, frequency) = native.monotonic_counter()?;
        counter_nanos(sample, frequency)
    } else if uses_realtime_counter(clock) {
        let nanos = realtime_nanos(native)?;
        if output == 0 {
            return Some(bad_output());
        }
        if clock as i32 as u64 == LINUX_CLOCK_REALTIME_COARSE {
            nanos - nanos % LINUX_CLOCK_RESOLUTION_NSEC.unsigned_abs()
        } else {
            nanos
        }
    } else {
        return None;
    };
    Some(native.finish_signal_output(
        UserVa::new(output),
        crate::sleep::timespec_bytes(nanos).to_vec(),
        false,
    ))
}
