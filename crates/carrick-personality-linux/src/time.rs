//! Clock reads whose Linux semantics are shared by both ring entries.

use crate::abi::entry::SyscallResult;
use crate::lifecycle::{LifecycleNative, LifecycleOutcome};
use carrick_guest_arch::UserVa;
use carrick_syscall_abi::{
    LINUX_CLOCK_MONOTONIC, LINUX_CLOCK_MONOTONIC_RAW, LINUX_EINVAL, linux_clock_resolution_ns,
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

/// Both vDSOs derive MONOTONIC and MONOTONIC_RAW from the same guest
/// counter. Other clocks and venues without a qualified counter keep
/// their existing venue decision.
pub(crate) fn clock_gettime(native: &mut dyn LifecycleNative<'_>) -> Option<LifecycleOutcome> {
    use carrick_syscall_abi::LINUX_EFAULT;

    let [clock, output, ..] = native.arguments();
    if !uses_monotonic_counter(clock) {
        return None;
    }
    if output == 0 {
        return Some(LifecycleOutcome::Returned {
            result: SyscallResult::from_errno(LINUX_EFAULT),
            work: false,
        });
    }
    let (sample, frequency) = native.monotonic_counter()?;
    let nanos =
        (u128::from(sample.raw()) * 1_000_000_000 / u128::from(frequency.raw().get())) as u64;
    Some(native.finish_signal_output(
        UserVa::new(output),
        crate::sleep::timespec_bytes(nanos).to_vec(),
        false,
    ))
}
