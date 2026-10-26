//! Proof that the host holds an MM's guest EL1 editor exclusion.
//!
//! The kernel owns the exclusion guard, but the engine operation it protects
//! may execute on another host thread. Consequently the proof is an owned,
//! process-visible capability rather than thread-local state. The capability
//! stays live only while the kernel guard which registered it is alive.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

#[derive(Debug)]
struct ExclusionCapability {
    mm: u64,
    active: std::sync::atomic::AtomicBool,
}

fn held() -> &'static Mutex<BTreeMap<u64, Vec<Weak<ExclusionCapability>>>> {
    static HELD: OnceLock<Mutex<BTreeMap<u64, Vec<Weak<ExclusionCapability>>>>> = OnceLock::new();
    HELD.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// One held exclusion of an MM's EL1 editor. Owned by the guard that raised
/// the MM's gate (or proved the MM unpublished) and dropped before that gate
/// is lowered.
#[derive(Debug)]
pub struct HeldEl1EditorExclusion {
    capability: Arc<ExclusionCapability>,
}

impl HeldEl1EditorExclusion {
    /// Register the exclusion `excluded` proves for its exact MM.
    #[must_use]
    pub fn register(excluded: &carrick_sched_core::ExcludedEditor<'_>) -> Self {
        let capability = Arc::new(ExclusionCapability {
            mm: excluded.key(),
            active: std::sync::atomic::AtomicBool::new(true),
        });
        held()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(capability.mm)
            .or_default()
            .push(Arc::downgrade(&capability));
        Self { capability }
    }

    /// The MM whose editor is excluded.
    #[must_use]
    pub fn mm(&self) -> u64 {
        self.capability.mm
    }

    /// Borrow-independent proof which may be handed to the host thread that
    /// performs the edit. It remains valid only while this held exclusion is
    /// alive.
    #[must_use]
    pub fn license(&self) -> El1EditorExcluded {
        El1EditorExcluded {
            capability: Arc::clone(&self.capability),
        }
    }
}

impl Drop for HeldEl1EditorExclusion {
    fn drop(&mut self) {
        self.capability
            .active
            .store(false, std::sync::atomic::Ordering::Release);
        let mut held = held()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(capabilities) = held.get_mut(&self.capability.mm) else {
            carrick_fatal::carrick_fatal!(
                "hal::el1_editor_exclusion",
                "EL1 editor exclusion of MM {} was not registered",
                self.capability.mm
            );
        };
        capabilities.retain(|candidate| {
            candidate
                .upgrade()
                .is_some_and(|candidate| !Arc::ptr_eq(&candidate, &self.capability))
        });
        if capabilities.is_empty() {
            held.remove(&self.capability.mm);
        }
    }
}

/// Owned witness that MM [`Self::mm`]'s EL1 editor is excluded. The private
/// capability can only be minted by [`HeldEl1EditorExclusion::register`].
#[derive(Clone, Debug)]
pub struct El1EditorExcluded {
    capability: Arc<ExclusionCapability>,
}

impl El1EditorExcluded {
    /// The MM whose live descriptors the holder may store to.
    #[must_use]
    pub fn mm(&self) -> u64 {
        self.capability.mm
    }

    /// Whether the kernel guard which owns this capability is still live.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.capability
            .active
            .load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Run `f` with an owned proof for `mm` when its kernel exclusion is held.
/// The lookup is process-wide because the admitted engine operation may run
/// on a different host thread from the kernel guard that owns the exclusion.
pub fn with_held_exclusion<R>(mm: u64, f: impl FnOnce(Option<&El1EditorExcluded>) -> R) -> R {
    let license = if mm == 0 {
        None
    } else {
        let mut held = held()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let capabilities = held.get_mut(&mm);
        let capability = capabilities.and_then(|capabilities| {
            capabilities.retain(|candidate| candidate.strong_count() != 0);
            capabilities
                .iter()
                .filter_map(Weak::upgrade)
                .find(|capability| capability.active.load(std::sync::atomic::Ordering::Acquire))
        });
        if held.get(&mm).is_some_and(Vec::is_empty) {
            held.remove(&mm);
        }
        capability.map(|capability| El1EditorExcluded { capability })
    };
    f(license.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_exclusion_mints_an_owned_cross_thread_witness() {
        let spaces = Box::new(carrick_sched_core::AddressSpaces::new());
        let index = spaces.publish_closed(41, 0x1000, 0).expect("publish");
        assert!(with_held_exclusion(41, |witness| witness.is_none()));
        {
            let excluded = spaces.raise_and_wait_for_editor(index, || {});
            let held = HeldEl1EditorExclusion::register(&excluded);
            assert_eq!(held.mm(), 41);
            assert_eq!(held.license().mm(), 41);
            assert_eq!(
                with_held_exclusion(41, |witness| witness.map(El1EditorExcluded::mm)),
                Some(41)
            );
            assert!(with_held_exclusion(42, |witness| witness.is_none()));
            std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        assert_eq!(
                            with_held_exclusion(41, |witness| {
                                witness.map(El1EditorExcluded::mm)
                            }),
                            Some(41)
                        );
                    })
                    .join()
                    .unwrap();
            });
            drop(held);
            spaces.lower(index);
        }
        assert!(with_held_exclusion(41, |witness| witness.is_none()));
    }
}
