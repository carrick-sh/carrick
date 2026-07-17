#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::sync::OnceLock;

pub(super) const COMMPAGE_TIMEBASE_ADDRESS: u64 = 0x0000_000f_ffff_c088;
const COMMPAGE_MODE_ADDRESS: u64 = COMMPAGE_TIMEBASE_ADDRESS + 8;
const MRS_CNTVCT_X0: u32 = 0xd53b_e040;
const MRS_APPLE_TIMEBASE_X0: u32 = 0xd53c_fac0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HostCounterSource {
    Cntvct,
    AppleTimebase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CounterScale {
    numerator: u32,
    denominator: u32,
}

impl CounterScale {
    pub(super) fn new(numerator: u32, denominator: u32) -> Option<Self> {
        if numerator == 0 || denominator == 0 {
            return None;
        }
        let divisor = gcd(u128::from(numerator), u128::from(denominator));
        Some(Self {
            numerator: u32::try_from(u128::from(numerator) / divisor).ok()?,
            denominator: u32::try_from(u128::from(denominator) / divisor).ok()?,
        })
    }

    pub(super) const fn numerator(self) -> u32 {
        self.numerator
    }

    pub(super) const fn denominator(self) -> u32 {
        self.denominator
    }

    pub(super) fn apply(self, ticks: u64) -> u64 {
        let denominator = u64::from(self.denominator);
        let quotient = ticks / denominator;
        let remainder = ticks % denominator;
        quotient
            .wrapping_mul(u64::from(self.numerator))
            .wrapping_add(remainder * u64::from(self.numerator) / u64::from(self.denominator))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HostCounterPlan {
    Inline {
        source: HostCounterSource,
        scale: CounterScale,
    },
    Fallback {
        scale: CounterScale,
    },
    Unsupported,
}

fn gcd(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn scale_from_timebase(numerator: u32, denominator: u32, frequency: u64) -> Option<CounterScale> {
    if numerator == 0 || denominator == 0 || frequency == 0 {
        return None;
    }
    let numerator = u128::from(numerator).checked_mul(u128::from(frequency))?;
    let denominator = u128::from(denominator).checked_mul(1_000_000_000)?;
    let divisor = gcd(numerator, denominator);
    let numerator = u32::try_from(numerator / divisor).ok()?;
    let denominator = u32::try_from(denominator / divisor).ok()?;
    CounterScale::new(numerator, denominator)
}

pub(super) fn plan_for_mode(mode: Option<u8>, host_scale: Option<CounterScale>) -> HostCounterPlan {
    match mode {
        Some(1) => HostCounterPlan::Inline {
            source: HostCounterSource::Cntvct,
            scale: CounterScale {
                numerator: 1,
                denominator: 1,
            },
        },
        Some(3) => host_scale.map_or(HostCounterPlan::Unsupported, |scale| {
            HostCounterPlan::Inline {
                source: HostCounterSource::AppleTimebase,
                scale,
            }
        }),
        _ => host_scale.map_or(HostCounterPlan::Unsupported, |scale| {
            HostCounterPlan::Fallback { scale }
        }),
    }
}

pub(super) const fn counter_word(source: HostCounterSource, destination: u32) -> Option<u32> {
    let base = match source {
        HostCounterSource::Cntvct => MRS_CNTVCT_X0,
        HostCounterSource::AppleTimebase => MRS_APPLE_TIMEBASE_X0,
    };
    if destination <= 31 {
        Some(base | destination)
    } else {
        None
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn host_commpage_mode() -> Option<u8> {
    let mut mode = 0_u8;
    let mut bytes_read = 0_u64;
    let destination = u64::try_from(std::ptr::addr_of_mut!(mode) as usize).ok()?;
    // SAFETY: the destination is a writable one-byte local, the source is read
    // through the current task's VM API, and success is accepted only when the
    // kernel reports that the complete mode byte was copied.
    let status = unsafe {
        mach2::vm::mach_vm_read_overwrite(
            mach2::traps::mach_task_self(),
            COMMPAGE_MODE_ADDRESS,
            1,
            destination,
            &mut bytes_read,
        )
    };
    if status == mach2::kern_return::KERN_SUCCESS && bytes_read == 1 {
        Some(mode)
    } else {
        None
    }
}

#[allow(deprecated)]
pub(super) fn host_counter_scale() -> Option<CounterScale> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        static SCALE: OnceLock<Option<CounterScale>> = OnceLock::new();
        *SCALE.get_or_init(|| {
            let mut info = libc::mach_timebase_info { numer: 0, denom: 0 };
            // SAFETY: the call initializes the fixed-size out parameter.
            if unsafe { libc::mach_timebase_info(&mut info) } != libc::KERN_SUCCESS {
                return None;
            }
            let frequency = crate::trap::host_counter_frequency();
            scale_from_timebase(info.numer, info.denom, frequency)
        })
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        None
    }
}

pub(super) fn host_counter_plan() -> HostCounterPlan {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        static PLAN: OnceLock<HostCounterPlan> = OnceLock::new();
        *PLAN.get_or_init(|| {
            let mode = host_commpage_mode();
            plan_for_mode(mode, host_counter_scale())
        })
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        HostCounterPlan::Unsupported
    }
}

#[inline]
#[allow(deprecated)]
#[cfg(target_os = "macos")]
pub(super) fn mach_absolute_time_ticks() -> u64 {
    // SAFETY: `mach_absolute_time` has no arguments and returns the monotonic
    // host uptime counter.
    unsafe { libc::mach_absolute_time() }
}

#[cfg(target_os = "macos")]
pub(super) fn fallback_counter_ticks() -> Option<u64> {
    let scale = match host_counter_plan() {
        HostCounterPlan::Inline { scale, .. } | HostCounterPlan::Fallback { scale } => scale,
        HostCounterPlan::Unsupported => return None,
    };
    Some(scale.apply(mach_absolute_time_ticks()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_modes_select_inline_sources() {
        let host_scale = CounterScale::new(125, 3).expect("host scale");
        assert_eq!(
            plan_for_mode(Some(1), None),
            HostCounterPlan::Inline {
                source: HostCounterSource::Cntvct,
                scale: CounterScale::new(1, 1).expect("identity scale"),
            }
        );
        assert_eq!(
            plan_for_mode(Some(3), Some(host_scale)),
            HostCounterPlan::Inline {
                source: HostCounterSource::AppleTimebase,
                scale: host_scale,
            }
        );
        assert_eq!(plan_for_mode(Some(3), None), HostCounterPlan::Unsupported);
    }

    #[test]
    fn unproved_modes_select_fallback() {
        let scale = CounterScale::new(125, 3).expect("host scale");
        for mode in [0, 2, 4, u8::MAX] {
            assert_eq!(
                plan_for_mode(Some(mode), Some(scale)),
                HostCounterPlan::Fallback { scale }
            );
            assert_eq!(
                plan_for_mode(Some(mode), None),
                HostCounterPlan::Unsupported
            );
        }
    }

    #[test]
    fn injected_timebase_scale_is_exact_or_unsupported() {
        assert_eq!(
            scale_from_timebase(125, 3, 1_000_000_000),
            CounterScale::new(125, 3)
        );
        assert_eq!(scale_from_timebase(u32::MAX, 1, u64::MAX), None);
    }

    #[test]
    fn unreadable_mode_selects_scaled_fallback_without_a_raw_counter_provider() {
        let scale = CounterScale::new(125, 3).expect("host scale");
        assert_eq!(
            plan_for_mode(None, Some(scale)),
            HostCounterPlan::Fallback { scale }
        );
        assert_eq!(plan_for_mode(None, None), HostCounterPlan::Unsupported);
    }

    #[test]
    fn source_words_preserve_destination() {
        assert_eq!(
            counter_word(HostCounterSource::Cntvct, 2),
            Some(0xd53b_e042)
        );
        assert_eq!(
            counter_word(HostCounterSource::AppleTimebase, 2),
            Some(0xd53c_fac2)
        );
        assert_eq!(counter_word(HostCounterSource::Cntvct, 32), None);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn host_counter_plan_is_stable() {
        let first = host_counter_plan();
        let second = host_counter_plan();
        eprintln!("host counter plan: {first:?}");
        assert_eq!(first, second);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fallback_ticks_are_nondecreasing() {
        let before = mach_absolute_time_ticks();
        let after = mach_absolute_time_ticks();
        assert!(after >= before);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn host_scale_converts_mach_ticks_into_cntfrq_domain() {
        let scale = host_counter_scale().expect("representable host counter scale");
        let frequency = crate::trap::host_counter_frequency();
        if frequency == 1_000_000_000 {
            assert_eq!(
                scale,
                CounterScale::new(125, 3).expect("known reduced scale")
            );
        }
        let before = crate::trap::host_clock_uptime_ns();
        let ticks = scale.apply(mach_absolute_time_ticks());
        let after = crate::trap::host_clock_uptime_ns();
        let observed = u64::try_from(u128::from(ticks) * 1_000_000_000 / u128::from(frequency))
            .expect("scaled counter nanoseconds fit u64");
        assert!(before.saturating_sub(1_000) <= observed);
        assert!(observed <= after.saturating_add(1_000));
    }

    #[test]
    fn scale_uses_exact_quotient_remainder_arithmetic() {
        let scale = CounterScale::new(125, 3).expect("reduced scale");
        let ticks = u64::MAX - 1;
        let modulus = u128::from(u64::MAX) + 1;
        let exact = u64::try_from((u128::from(ticks) * 125 / 3) % modulus)
            .expect("reduced exact result fits u64");
        assert_eq!(scale.apply(ticks), exact);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn unknown_mode_fallback_uses_host_scale() {
        let scale = host_counter_scale().expect("representable host counter scale");
        assert_eq!(
            plan_for_mode(Some(0), Some(scale)),
            HostCounterPlan::Fallback { scale }
        );
        let before = scale.apply(mach_absolute_time_ticks());
        let observed = fallback_counter_ticks().expect("scaled fallback counter");
        let after = scale.apply(mach_absolute_time_ticks());
        assert!(before <= observed && observed <= after);
    }
}
