//! Proof, for host code on THIS thread, that it holds an MM's guest EL1
//! editor exclusion.
//!
//! On the guest descriptor lane EL1 owns the live stage-1 descriptors: it
//! publishes, protects and retires leaves under an MM's editor token. The
//! host may store to those descriptors itself only while that editor is
//! excluded (the MM's gate raised and no admitted EL1 editor left), which
//! makes the host the MM's one editor. The exclusion is acquired in the
//! kernel (`mm_occupancy::exclude_el1_editor`, held by the syscall and
//! first-touch mutation guards) while the stores happen in the engine below
//! it, so the proof travels through this crate, which both depend on.
//!
//! The proof is a type, not a convention:
//! - [`HeldEl1EditorExclusion`] is registered only from a
//!   [`carrick_sched_core::ExcludedEditor`], which only
//!   `AddressSpaces::raise_and_wait_for_editor` (or `unpublished`) mints,
//!   and it unregisters when dropped, on the thread that registered it.
//! - [`El1EditorExcluded`] is the witness host-side descriptor stores
//!   demand. It is minted only by [`with_held_exclusion`], inside a closure
//!   on the registering thread, while a registration for the exact MM is
//!   held; it is neither `Clone`, `Send` nor constructible elsewhere.

use std::cell::RefCell;
use std::marker::PhantomData;

thread_local! {
    static HELD: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

/// One held exclusion of an MM's EL1 editor, registered on this thread for
/// as long as it lives. Owned by the guard that raised the MM's gate and
/// dropped before that gate is lowered.
#[derive(Debug)]
pub struct HeldEl1EditorExclusion {
    mm: u64,
    _thread_bound: PhantomData<*const ()>,
}

impl HeldEl1EditorExclusion {
    /// Register the exclusion `excluded` proves for its MM on this thread.
    #[must_use]
    pub fn register(excluded: &carrick_sched_core::ExcludedEditor<'_>) -> Self {
        let mm = excluded.key();
        HELD.with(|held| held.borrow_mut().push(mm));
        Self {
            mm,
            _thread_bound: PhantomData,
        }
    }

    /// The MM whose editor is excluded.
    #[must_use]
    pub fn mm(&self) -> u64 {
        self.mm
    }
}

impl Drop for HeldEl1EditorExclusion {
    fn drop(&mut self) {
        HELD.with(|held| {
            let mut held = held.borrow_mut();
            match held.iter().rposition(|&mm| mm == self.mm) {
                Some(at) => {
                    held.remove(at);
                }
                None => carrick_fatal::carrick_fatal!(
                    "hal::el1_editor_exclusion",
                    "EL1 editor exclusion of MM {} released on a thread that never held it",
                    self.mm
                ),
            }
        });
    }
}

/// Witness that the calling thread holds MM [`Self::mm`]'s EL1 editor
/// exclusion. Only [`with_held_exclusion`] mints one, for the duration of
/// its closure.
#[derive(Debug)]
pub struct El1EditorExcluded {
    mm: u64,
    _thread_bound: PhantomData<*const ()>,
}

impl El1EditorExcluded {
    /// The MM whose live descriptors the holder may store to.
    #[must_use]
    pub fn mm(&self) -> u64 {
        self.mm
    }
}

/// Run `f` with the witness for `mm` when this thread holds its EL1 editor
/// exclusion, else with `None`.
pub fn with_held_exclusion<R>(mm: u64, f: impl FnOnce(Option<&El1EditorExcluded>) -> R) -> R {
    let held = mm != 0 && HELD.with(|held| held.borrow().contains(&mm));
    if held {
        let witness = El1EditorExcluded {
            mm,
            _thread_bound: PhantomData,
        };
        f(Some(&witness))
    } else {
        f(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_registered_exclusion_on_this_thread_mints_a_witness() {
        let spaces = Box::new(carrick_sched_core::AddressSpaces::new());
        let index = spaces.publish_closed(41, 0x1000, 0).expect("publish");
        assert!(with_held_exclusion(41, |witness| witness.is_none()));
        {
            let excluded = spaces.raise_and_wait_for_editor(index, || {});
            let held = HeldEl1EditorExclusion::register(&excluded);
            assert_eq!(held.mm(), 41);
            assert_eq!(
                with_held_exclusion(41, |witness| witness.map(El1EditorExcluded::mm)),
                Some(41)
            );
            assert!(
                with_held_exclusion(42, |witness| witness.is_none()),
                "exact MM only"
            );
            std::thread::scope(|scope| {
                scope
                    .spawn(|| assert!(with_held_exclusion(41, |witness| witness.is_none())))
                    .join()
                    .unwrap();
            });
            drop(held);
            spaces.lower(index);
        }
        assert!(with_held_exclusion(41, |witness| witness.is_none()));
    }
}
