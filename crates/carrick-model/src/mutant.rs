//! Seeded mutants: a test-only branch at a fix site that restores the
//! pre-fix behaviour, so a model proves it would have found the bug.
//!
//! A crate declares its mutants as one enum, implements the always-compiled
//! [`Mutant`](crate::Mutant) trait for it with [`mutants!`](crate::mutants), and
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

std::thread_local! {
    /// The active mutant: its enum's type and its index in `ALL`.
    static ACTIVE: Cell<Option<(TypeId, usize)>> = const { Cell::new(None) };
}

fn slot<M: Mutant>(which: M) -> (TypeId, usize) {
    let index = M::ALL
        .iter()
        .position(|&m| m == which)
        .unwrap_or(usize::MAX);
    (TypeId::of::<M>(), index)
}

/// Whether `which` is the active mutant on this thread.
pub fn is<M: Mutant>(which: M) -> bool {
    ACTIVE.with(|active| active.get() == Some(slot(which)))
}

/// Run `f` with `which` active on this thread.
pub fn with<M: Mutant, R>(which: M, f: impl FnOnce() -> R) -> R {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ACTIVE.with(|active| active.set(None));
        }
    }
    ACTIVE.with(|active| active.set(Some(slot(which))));
    let _reset = Reset;
    f()
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
