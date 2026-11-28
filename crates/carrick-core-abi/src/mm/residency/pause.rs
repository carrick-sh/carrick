//! Named pause points inside the residency table's multi-step edits, for
//! the interleaving witnesses in `interleaving_tests.rs`.
//!
//! Each point sits between two stores of one edit. A witness installs a
//! hook that runs a peer's whole operation (another MM's publication, a
//! lock-free reader) when the edit reaches the point, so every schedule is
//! an exact, deterministic interleaving on the real table, with no threads
//! and no timing. Outside tests [`at`] is an empty `const fn`, so every
//! point folds away.

/// Where an edit is paused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Point {
    /// A row's state has just become `GRANT_RETIRED`: its slot is
    /// reusable by any MM.
    Retired { slot: usize },
    /// A row has just become `GRANT_LIVE` in its slot.
    Published { slot: usize },
    /// A transfer has just tagged a slot as one of its reservations.
    Tagged { slot: usize },
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
type Hook = std::boxed::Box<dyn FnMut(Point)>;

#[cfg(test)]
std::thread_local! {
    static HOOK: core::cell::RefCell<Option<Hook>> = const { core::cell::RefCell::new(None) };
}

/// Run this thread's hook at `point`. The hook is taken out while it runs,
/// so the peer operations it runs pass their own points without pausing.
#[cfg(test)]
pub(super) fn at(point: Point) {
    let Some(mut hook) = HOOK.with(|slot| slot.borrow_mut().take()) else {
        return;
    };
    hook(point);
    HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(hook);
        }
    });
}

#[cfg(not(test))]
#[inline(always)]
pub(super) const fn at(_point: Point) {}

/// Run `body` with `hook` installed on this thread.
#[cfg(test)]
pub(super) fn with<T>(hook: impl FnMut(Point) + 'static, body: impl FnOnce() -> T) -> T {
    HOOK.with(|slot| *slot.borrow_mut() = Some(std::boxed::Box::new(hook)));
    let result = body();
    HOOK.with(|slot| *slot.borrow_mut() = None);
    result
}
