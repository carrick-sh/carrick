//! Clock reads whose Linux semantics are shared by both ring entries.

use crate::abi::entry::SyscallResult;
use crate::lifecycle::{LifecycleNative, LifecycleOutcome};
use carrick_guest_arch::{CounterFrequency, CounterTick, UserVa};
use carrick_syscall_abi::{
    LINUX_CLOCK_RESOLUTION_NSEC, LINUX_EINVAL, LinuxClockRead, LinuxCpuClock, LinuxCpuSample,
    linux_clock_read, linux_clock_resolution_ns,
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

/// Whether the ring serves `clock_gettime` for this clock id, classified by
/// the shared [`linux_clock_read`]. An unknown id is served (EINVAL). Only a
/// user-time-only CPU clock is unserved: the ring accounts total CPU time.
/// A CPU clock naming another task is decided against the caller in
/// [`clock_gettime`].
pub(crate) const fn serves_clock_gettime(clock: u64) -> bool {
    !matches!(
        linux_clock_read(clock),
        Some(LinuxClockRead::Cpu(LinuxCpuClock {
            sample: LinuxCpuSample::Virt,
            ..
        }))
    )
}

#[inline(never)]
fn counter_nanos(sample: CounterTick, frequency: CounterFrequency) -> u64 {
    (u128::from(sample.raw()) * 1_000_000_000 / u128::from(frequency.raw().get())) as u64
}

/// Whether a CPU clock names the caller. A dynamic id may name the calling
/// thread by tid, or its process by pid; any other task's clock (or a task
/// that does not exist, EINVAL natively) is not the ring's to read yet.
fn names_caller(native: &dyn LifecycleNative<'_>, cpu: LinuxCpuClock) -> bool {
    let Some(target) = cpu.target else {
        return true;
    };
    let own = if cpu.per_thread {
        native.visible_tid()
    } else {
        native.process_pid()
    };
    own == Some(target.get())
}

/// `clock_gettime(2)` for every clock id, in ring. Linux rejects an unknown
/// id with EINVAL before it touches the output, then faults a bad output
/// with EFAULT. The counter clocks read the guest counter (the epoch the
/// vDSO uses); BOOTTIME reads it too, since a guest never suspends apart from
/// its counter. The wall clocks add the carrier's ring-published realtime
/// calibration, the same word the vDSO adds.
#[inline(never)]
pub(crate) fn clock_gettime(native: &mut dyn LifecycleNative<'_>) -> Option<LifecycleOutcome> {
    use carrick_syscall_abi::LINUX_EFAULT;

    let [clock, output, ..] = native.arguments();
    if !serves_clock_gettime(clock) {
        return None;
    }
    let Some(read) = linux_clock_read(clock) else {
        return Some(LifecycleOutcome::Returned {
            result: SyscallResult::from_errno(LINUX_EINVAL),
            work: false,
        });
    };
    if let LinuxClockRead::Cpu(cpu) = read
        && !names_caller(native, cpu)
    {
        return None;
    }
    if output == 0 {
        return Some(LifecycleOutcome::Returned {
            result: SyscallResult::from_errno(LINUX_EFAULT),
            work: false,
        });
    }
    let coarse = |nanos: u64| nanos - nanos % LINUX_CLOCK_RESOLUTION_NSEC as u64;
    let nanos = match read {
        LinuxClockRead::Realtime => realtime_nanos(native)?,
        LinuxClockRead::RealtimeCoarse => coarse(realtime_nanos(native)?),
        LinuxClockRead::Monotonic | LinuxClockRead::Boottime => monotonic_nanos(native)?,
        LinuxClockRead::MonotonicCoarse => coarse(monotonic_nanos(native)?),
        LinuxClockRead::Cpu(cpu) => native.cputime_nanos(cpu.per_thread)?,
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
