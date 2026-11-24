//! Clock reads whose Linux semantics are shared by both ring entries.

use crate::abi::entry::SyscallResult;
use crate::lifecycle::{LifecycleNative, LifecycleOutcome};
use carrick_guest_arch::{CounterFrequency, CounterTick, UserVa};
use carrick_syscall_abi::{
    LINUX_CLOCK_RESOLUTION_NSEC, LINUX_EINVAL, LinuxClockRead, linux_clock_read,
    linux_clock_resolution_ns,
};

#[inline(never)]
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

#[inline(never)]
fn counter_nanos(sample: CounterTick, frequency: CounterFrequency) -> u64 {
    (u128::from(sample.raw()) * 1_000_000_000 / u128::from(frequency.raw().get())) as u64
}

/// `clock_gettime(2)` for every clock id, in ring. Linux rejects an unknown
/// id, and a CPU clock naming no task it can read, with EINVAL before it
/// touches the output, then faults a bad output with EFAULT. The counter
/// clocks read the guest counter (the epoch the vDSO uses); BOOTTIME reads it
/// too, since a guest never suspends apart from its counter. The wall clocks
/// add the carrier's ring-published realtime calibration, the same word the
/// vDSO adds. A CPU clock is resolved by the venue's task owner
/// ([`LifecycleNative::cpu_clock_nanos`]).
#[inline(never)]
pub(crate) fn clock_gettime(native: &mut dyn LifecycleNative<'_>) -> Option<LifecycleOutcome> {
    use carrick_syscall_abi::LINUX_EFAULT;

    let [clock, output, ..] = native.arguments();
    let refuse = |errno| {
        Some(LifecycleOutcome::Returned {
            result: SyscallResult::from_errno(errno),
            work: false,
        })
    };
    let Some(read) = linux_clock_read(clock) else {
        return refuse(LINUX_EINVAL);
    };
    // A CPU clock's target is checked before the output (EINVAL, then
    // EFAULT); every other valid clock faults a null output unread.
    let cpu = match read {
        LinuxClockRead::Cpu(cpu) => match native.cpu_clock_nanos(cpu)? {
            Ok(nanos) => Some(nanos),
            Err(errno) => return refuse(errno),
        },
        _ => None,
    };
    if output == 0 {
        return refuse(LINUX_EFAULT);
    }
    let coarse = |nanos: u64| nanos - nanos % LINUX_CLOCK_RESOLUTION_NSEC as u64;
    let nanos = match (read, cpu) {
        (_, Some(nanos)) => nanos,
        (LinuxClockRead::Realtime, _) => realtime_nanos(native)?,
        (LinuxClockRead::RealtimeCoarse, _) => coarse(realtime_nanos(native)?),
        (LinuxClockRead::Monotonic | LinuxClockRead::Boottime, _) => monotonic_nanos(native)?,
        (LinuxClockRead::MonotonicCoarse, _) => coarse(monotonic_nanos(native)?),
        (LinuxClockRead::Cpu(_), None) => return None,
    };
    Some(native.finish_signal_output(
        UserVa::new(output),
        crate::sleep::timespec_bytes(nanos).to_vec(),
        false,
    ))
}

fn monotonic_nanos(native: &mut dyn LifecycleNative<'_>) -> Option<u64> {
    let (sample, frequency) = native.monotonic_counter()?;
    Some(counter_nanos(sample, frequency))
}

fn realtime_nanos(native: &mut dyn LifecycleNative<'_>) -> Option<u64> {
    let sample = native.realtime_counter()?;
    Some(counter_nanos(sample.tick, sample.frequency).wrapping_add(sample.offset_ns))
}

#[inline(never)]
pub(crate) fn realtime_alias(
    ordinal: u64,
    native: &mut dyn LifecycleNative<'_>,
) -> Option<LifecycleOutcome> {
    use carrick_syscall_abi::{CARRICK_PRIVATE_X86_TIME, LinuxTimeval, LinuxTimezone};
    use zerocopy::IntoBytes;

    let [first, second, ..] = native.arguments();
    let (records, result) = if ordinal == CARRICK_PRIVATE_X86_TIME {
        let seconds = (realtime_nanos(native)? / 1_000_000_000) as i64;
        let output = (first != 0).then(|| (UserVa::new(first), seconds.to_le_bytes().to_vec()));
        ([output, None], SyscallResult::new(seconds))
    } else {
        let timeval = if first != 0 {
            let nanos = realtime_nanos(native)?;
            let value = LinuxTimeval::new(
                (nanos / 1_000_000_000) as i64,
                (nanos % 1_000_000_000 / 1_000) as i64,
            );
            Some((UserVa::new(first), value.as_bytes().to_vec()))
        } else {
            None
        };
        let timezone = (second != 0).then(|| {
            (
                UserVa::new(second),
                LinuxTimezone::utc().as_bytes().to_vec(),
            )
        });
        ([timeval, timezone], SyscallResult::new(0))
    };
    Some(native.finish_time_output(records, result))
}

#[inline(never)]
pub(crate) fn times(native: &mut dyn LifecycleNative<'_>) -> Option<LifecycleOutcome> {
    use carrick_syscall_abi::LINUX_CLK_TCK;
    use zerocopy::IntoBytes;

    let [output, ..] = native.arguments();
    let (sample, frequency) = native.monotonic_counter()?;
    let mono_ns = counter_nanos(sample, frequency);
    let clock_ticks = LINUX_CLK_TCK.saturating_add((mono_ns / 10_000_000) as i64);
    if output == 0 {
        return Some(LifecycleOutcome::Returned {
            result: SyscallResult::new(clock_ticks),
            work: false,
        });
    }
    let tms = native.process_tms()?;
    Some(native.finish_time_output(
        [Some((UserVa::new(output), tms.as_bytes().to_vec())), None],
        SyscallResult::new(clock_ticks),
    ))
}
