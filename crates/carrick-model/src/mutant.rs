//! Seeded mutants: a test-only branch at a fix site that restores the
//! pre-fix behaviour, so a model proves it would have found the bug.
//!
//! A crate declares its mutants as one enum, implements the always-compiled
//! [`Mutant`] trait for it with [`mutants!`](crate::mutants), and
//! gates the branch on its own test builds, so production code can't take
//! it:
//!
//! ```ignore
//! #[derive(Clone, Copy, Debug, Eq, PartialEq)]
//! pub(crate) enum Mutant { NoWakeOnPut, FalseEmpty }
//! carrick_model::mutants!(Mutant { NoWakeOnPut, FalseEmpty });
//! #[cfg(test)]
//! fn mutant(which: Mutant) -> bool { carrick_model::mutant::is(which) }
//! #[cfg(not(test))]
//! const fn mutant(_: Mutant) -> bool { false }
//! ```
//!
//! [`with`] activates one mutant on this thread for one closure, and
//! [`mutants_killed`](crate::explore::mutants_killed) requires each
//! mutant's named invariant, not just any failure, to kill it.

use core::any::TypeId;
use core::cell::Cell;

use crate::Mutant;

/// The active mutant: its enum's type, its index in `ALL`, and its name
/// (which a counterexample's replay line carries).
#[derive(Clone, Copy, Debug)]
struct Active {
    ty: TypeId,
    index: usize,
    name: &'static str,
}

std::thread_local! {
    static ACTIVE: Cell<Option<Active>> = const { Cell::new(None) };
}

fn slot<M: Mutant>(which: M) -> Active {
    let index = M::ALL
        .iter()
        .position(|&m| m == which)
        .unwrap_or(usize::MAX);
    Active {
        ty: TypeId::of::<M>(),
        index,
        name: which.name(),
    }
}

/// Whether `which` is the active mutant on this thread.
pub fn is<M: Mutant>(which: M) -> bool {
    let want = slot(which);
    ACTIVE.with(|active| {
        active
            .get()
            .is_some_and(|now| now.ty == want.ty && now.index == want.index)
    })
}

/// The name of the active mutant on this thread, if any.
pub fn active() -> Option<&'static str> {
    ACTIVE.with(|active| active.get().map(|now| now.name))
}

/// Run `f` with `which` active on this thread. The mutant that was active
/// before (an enclosing `with`, or none) is restored afterwards, on unwind
/// too, so a nested scope never disables its outer scope's mutant.
pub fn with<M: Mutant, R>(which: M, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<Active>);
    impl Drop for Restore {
        fn drop(&mut self) {
            ACTIVE.with(|active| active.set(self.0));
        }
    }
    let _restore = Restore(ACTIVE.with(|active| active.replace(Some(slot(which)))));
    f()
}

/// Run `f` with no mutant active on this thread, restoring the enclosing
/// one afterwards (on unwind too).
pub fn none<R>(f: impl FnOnce() -> R) -> R {
    struct Restore(Option<Active>);
    impl Drop for Restore {
        fn drop(&mut self) {
            ACTIVE.with(|active| active.set(self.0));
        }
    }
    let _restore = Restore(ACTIVE.with(|active| active.replace(None)));
    f()
}

/// The mutant set of a protocol that has none, for
/// [`replay_line`](crate::explore::replay_line).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoMutants {}

impl Mutant for NoMutants {
    const ALL: &'static [Self] = &[];
    fn name(self) -> &'static str {
        match self {}
    }
}

/// Implement [`Mutant`](crate::Mutant) for a crate's mutant enum, listing
/// every variant once:
///
/// ```ignore
/// #[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// enum Mutant { NoWakeOnPut, FalseEmpty }
/// carrick_model::mutants!(Mutant { NoWakeOnPut, FalseEmpty });
/// ```
#[macro_export]
macro_rules! mutants {
    ($ty:ident { $($name:ident),+ $(,)? }) => {
        impl $crate::Mutant for $ty {
            const ALL: &'static [Self] = &[$($ty::$name),+];

            fn name(self) -> &'static str {
                match self {
                    $($ty::$name => stringify!($name)),+
                }
            }
        }
    };
}
