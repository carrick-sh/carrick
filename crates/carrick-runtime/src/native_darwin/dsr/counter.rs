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
    MachAbsoluteTime,
}

pub(super) const fn source_for_mode(mode: u8) -> HostCounterSource {
    match mode {
        1 => HostCounterSource::Cntvct,
        3 => HostCounterSource::AppleTimebase,
        _ => HostCounterSource::MachAbsoluteTime,
    }
}

pub(super) const fn counter_word(source: HostCounterSource, destination: u32) -> Option<u32> {
    let base = match source {
        HostCounterSource::Cntvct => MRS_CNTVCT_X0,
        HostCounterSource::AppleTimebase => MRS_APPLE_TIMEBASE_X0,
        HostCounterSource::MachAbsoluteTime => return None,
    };
    if destination <= 31 {
        Some(base | destination)
    } else {
        None
    }
}

pub(super) fn host_counter_source() -> HostCounterSource {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        static MODE: OnceLock<u8> = OnceLock::new();
        let mode = *MODE.get_or_init(|| {
            // SAFETY: Darwin maps the commpage read-only at a fixed userspace
            // address, and the mode field is one byte at the documented offset.
            unsafe { (COMMPAGE_MODE_ADDRESS as *const u8).read_volatile() }
        });
        source_for_mode(mode)
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        HostCounterSource::MachAbsoluteTime
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_modes_select_inline_sources() {
        assert_eq!(source_for_mode(1), HostCounterSource::Cntvct);
        assert_eq!(source_for_mode(3), HostCounterSource::AppleTimebase);
    }

    #[test]
    fn unproved_modes_select_fallback() {
        for mode in [0, 2, 4, u8::MAX] {
            assert_eq!(source_for_mode(mode), HostCounterSource::MachAbsoluteTime);
        }
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
        assert_eq!(counter_word(HostCounterSource::MachAbsoluteTime, 2), None);
        assert_eq!(counter_word(HostCounterSource::Cntvct, 32), None);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn host_mode_selects_a_proven_inline_source() {
        let source = host_counter_source();
        eprintln!("host counter source: {source:?}");
        assert!(matches!(
            source,
            HostCounterSource::Cntvct | HostCounterSource::AppleTimebase
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fallback_ticks_are_nondecreasing() {
        let before = mach_absolute_time_ticks();
        let after = mach_absolute_time_ticks();
        assert!(after >= before);
    }
}
