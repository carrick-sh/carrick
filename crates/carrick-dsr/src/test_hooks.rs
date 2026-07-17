//! Test-only failpoints and captures for the native mapping machinery.
//!
//! Moved here from `carrick-runtime/src/native_darwin.rs` because cross-crate
//! `cfg(test)` does not compose: once `mapped_memory.rs` moves into this
//! crate, its hook CHECK sites compile inside carrick-dsr while the hook
//! DRIVERS (the runtime's native test module) live in another crate. The
//! state therefore sits behind `cfg(any(test, feature = "test-hooks"))`:
//!
//!  * `cargo test -p carrick-dsr` sees it via `cfg(test)`;
//!  * carrick-runtime's `[dev-dependencies]` re-declare carrick-dsr (and
//!    carrick-dsr-aarch64, which forwards) with `features = ["test-hooks"]`,
//!    so cargo's feature unification compiles the hooks into every runtime
//!    TEST build while production builds (e.g. carrick-cli) never enable the
//!    feature and never carry the statics.
//!
//! Everything here is thread-local plumbing only — no policy: setters/takers
//! are one-line accessors the drivers call, and the check sites in the
//! mapping code consume the armed state at the matching failpoint.

use crate::probes::DsrCacheLifecyclePhase;

thread_local! {
    pub static NATIVE_TEST_FAIL_EXEC_AFTER_SETUP: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    pub static NATIVE_TEST_PREPARED_MAPPING_FAILPOINT:
        std::cell::Cell<Option<NativePreparedMappingFailpoint>> = const {
            std::cell::Cell::new(None)
        };
    pub static NATIVE_TEST_VVAR_WORDS:
        std::cell::RefCell<Option<Vec<(usize, u64)>>> = const {
            std::cell::RefCell::new(None)
        };
    pub static NATIVE_TEST_SUPPLEMENTAL_ROLLBACKS:
        std::cell::RefCell<Vec<std::ops::Range<carrick_guest_mem::HostVa>>> = const {
            std::cell::RefCell::new(Vec::new())
        };
    pub static NATIVE_TEST_REEXEC_LIFECYCLE:
        std::cell::RefCell<Option<Vec<DsrCacheLifecyclePhase>>> = const {
            std::cell::RefCell::new(None)
        };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativePreparedMappingFailpoint {
    SecondRegionMap,
    Relocation,
    VvarStamp,
    FinalProtection,
}

pub fn set_native_prepared_mapping_failpoint(failpoint: Option<NativePreparedMappingFailpoint>) {
    NATIVE_TEST_PREPARED_MAPPING_FAILPOINT.with(|slot| slot.set(failpoint));
}

pub fn take_native_prepared_mapping_failpoint(failpoint: NativePreparedMappingFailpoint) -> bool {
    NATIVE_TEST_PREPARED_MAPPING_FAILPOINT.with(|slot| {
        if slot.get() == Some(failpoint) {
            slot.set(None);
            true
        } else {
            false
        }
    })
}

pub fn set_native_test_vvar_words(words: Option<Vec<(usize, u64)>>) {
    NATIVE_TEST_VVAR_WORDS.with(|slot| *slot.borrow_mut() = words);
}

pub fn take_native_test_supplemental_rollbacks() -> Vec<std::ops::Range<carrick_guest_mem::HostVa>>
{
    NATIVE_TEST_SUPPLEMENTAL_ROLLBACKS.with(|slot| std::mem::take(&mut *slot.borrow_mut()))
}

pub fn set_native_reexec_lifecycle_capture(enabled: bool) {
    NATIVE_TEST_REEXEC_LIFECYCLE.with(|slot| {
        *slot.borrow_mut() = enabled.then(Vec::new);
    });
}

pub fn take_native_reexec_lifecycle_capture() -> Vec<DsrCacheLifecyclePhase> {
    NATIVE_TEST_REEXEC_LIFECYCLE.with(|slot| slot.borrow_mut().take().unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_mapping_failpoint_fires_once_at_matching_site_only() {
        set_native_prepared_mapping_failpoint(Some(NativePreparedMappingFailpoint::VvarStamp));
        assert!(!take_native_prepared_mapping_failpoint(
            NativePreparedMappingFailpoint::Relocation
        ));
        assert!(take_native_prepared_mapping_failpoint(
            NativePreparedMappingFailpoint::VvarStamp
        ));
        assert!(!take_native_prepared_mapping_failpoint(
            NativePreparedMappingFailpoint::VvarStamp
        ));
    }

    #[test]
    fn reexec_lifecycle_capture_records_and_drains() {
        set_native_reexec_lifecycle_capture(true);
        NATIVE_TEST_REEXEC_LIFECYCLE.with(|slot| {
            if let Some(phases) = slot.borrow_mut().as_mut() {
                phases.push(DsrCacheLifecyclePhase::HostSelfReexecPreparedMapBegin);
            }
        });
        assert_eq!(
            take_native_reexec_lifecycle_capture(),
            vec![DsrCacheLifecyclePhase::HostSelfReexecPreparedMapBegin]
        );
        // Drained and disarmed: further takes yield nothing.
        assert_eq!(take_native_reexec_lifecycle_capture(), Vec::new());
    }

    #[test]
    fn vvar_words_and_supplemental_rollbacks_round_trip() {
        set_native_test_vvar_words(Some(vec![(8, 42)]));
        assert_eq!(
            NATIVE_TEST_VVAR_WORDS.with(|slot| slot.borrow().clone()),
            Some(vec![(8, 42)])
        );
        set_native_test_vvar_words(None);

        NATIVE_TEST_SUPPLEMENTAL_ROLLBACKS.with(|slot| {
            slot.borrow_mut()
                .push(carrick_guest_mem::HostVa(0x1000)..carrick_guest_mem::HostVa(0x2000));
        });
        assert_eq!(
            take_native_test_supplemental_rollbacks(),
            vec![carrick_guest_mem::HostVa(0x1000)..carrick_guest_mem::HostVa(0x2000)]
        );
        assert!(take_native_test_supplemental_rollbacks().is_empty());
    }
}
