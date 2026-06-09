//! Platform-NEUTRAL child-exit watch registry, shared by every backend.
//!
//! carrick's guest children are REAL host processes (a guest `fork` runs
//! `libc::fork`). When a guest installs a SIGCHLD handler (or blocks SIGCHLD for
//! `sigwait`, or sets a non-default-ignore disposition) and reaps the child FROM
//! the handler / an event loop WITHOUT first blocking in `wait4`, it must receive
//! its child-exit signal asynchronously the instant the child exits. This module
//! owns the bookkeeping that stands in for the kernel's parent/child link: a
//! `child_pid -> (parent_tid, exit_signal)` map recording, for each watched guest
//! child, the guest tid to wake on the child's exit and the signal the guest
//! asked for (clone `exit_signal` / clone3 `exit_signal`).
//!
//! The map + its sanitization + `register`/`take`/`is_tracked`/`tracked_pids`/
//! `clear` are platform-NEUTRAL and live here. Each backend layers its own GLUE
//! on top:
//!   * HVF arms an `EVFILT_PROC`/`NOTE_EXIT` kqueue watch per registered child;
//!     on the watch firing it `take`s the entry and publishes the recorded
//!     exit-signal to the recorded parent tid (a kqueue + self-pipe wake).
//!   * KVM installs a host SIGCHLD handler that pokes its self-pipe; the pump
//!     thread peeks each `tracked_pids()` entry with `waitid(WNOWAIT|WNOHANG)`
//!     and, on a terminal exit, `take`s the entry and publishes the recorded
//!     exit-signal to the recorded parent tid (then kicks the vCPUs).
//!
//! `0` as an exit signal is the "no exit signal" sentinel (`clone(0)`): preserved
//! as-is so the backend's glue publishes nothing. The synchronous terminal-reap
//! path (a guest `wait4` that reaps the child itself) calls [`take`] to CANCEL the
//! watch, which — together with [`take`]'s remove — is the double-delivery guard:
//! a child reaped synchronously is removed before any async reaper could publish,
//! and a `take` removes the entry so a later async wake can't re-deliver it.

use std::collections::HashMap;
use std::sync::Mutex;

/// Linux SIGCHLD. The canonical definition is `carrick_abi::LINUX_SIGCHLD` (this
/// neutral leaf crate does not depend on carrick-abi); the value MUST stay in
/// sync (a unit test below asserts the fallback uses this number). macOS's SIGCHLD
/// is 20, but the map stores the LINUX numbering on every backend.
const LINUX_SIGCHLD: i32 = 17;

/// Children the guest forked, mapped from their (host == guest, mirrored) pid to
/// `(parent_tid, exit_signal)`: the guest tid to wake on the child's exit and the
/// signal the guest requested at clone time. `0` means "no exit signal" (the
/// backend glue publishes nothing in that case). A `Mutex<Option<HashMap>>` so
/// the static is const-initialisable in this edition (matching the crate idiom in
/// `lib.rs`'s `THREAD_PENDING`); lazily filled on first `register`.
static CHILD_WATCHES: Mutex<Option<HashMap<i32, (i32, i32)>>> = Mutex::new(None);

/// Lock the watch table, lazily initialising it, recovering the guard if a
/// panicking thread poisoned the mutex (the contents are a plain map of small
/// integers, never left half-updated — and a poisoned watch table must not crash
/// child-exit delivery).
fn lock() -> std::sync::MutexGuard<'static, Option<HashMap<i32, (i32, i32)>>> {
    let mut guard = CHILD_WATCHES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

/// Record that guest tid `parent_tid` forked child `child_pid`, which should
/// receive `exit_signal` when it exits. `child_pid <= 0` is ignored. The exit
/// signal is sanitized: `0` (the "no exit signal" clone sentinel) is preserved;
/// a value in `1..=64` is kept; anything else falls back to SIGCHLD so a malformed
/// signum still produces SIGCHLD-class behavior. Backends arm their own per-child
/// watch glue AFTER calling this.
pub fn register(child_pid: i32, parent_tid: i32, exit_signal: i32) {
    if child_pid <= 0 {
        return;
    }
    let exit_signal = if exit_signal == 0 {
        0
    } else if (1..=64).contains(&exit_signal) {
        exit_signal
    } else {
        LINUX_SIGCHLD
    };
    lock()
        .get_or_insert_with(HashMap::new)
        .insert(child_pid, (parent_tid, exit_signal));
}

/// Remove and return the `(parent_tid, exit_signal)` for `child_pid`, or `None`
/// if it was not a tracked guest child. Called when a child's exit is observed
/// (the async reaper / kqueue watch) AND to CANCEL a watch when the guest reaps
/// the child synchronously — both rely on the atomic remove for publish-once.
pub fn take(child_pid: i32) -> Option<(i32, i32)> {
    lock().as_mut().and_then(|map| map.remove(&child_pid))
}

/// True iff `child_pid` is a tracked guest child (without consuming the mapping).
/// Lets a backend distinguish a child-exit event from its other wake sources.
pub fn is_tracked(child_pid: i32) -> bool {
    lock()
        .as_ref()
        .is_some_and(|map| map.contains_key(&child_pid))
}

/// Snapshot of every currently-tracked child pid. HVF's re-arm and the KVM
/// reaper both iterate this set (HVF to re-add EVFILT_PROC watches; KVM to
/// `waitid`-peek each tracked child on a pump wake).
pub fn tracked_pids() -> Vec<i32> {
    lock()
        .as_ref()
        .map(|map| map.keys().copied().collect())
        .unwrap_or_default()
}

/// Clear the entire watch table. Used by a freshly-forked CHILD so it does not
/// inherit (and deliver child-exit signals for) the PARENT's children — its own
/// children are registered on its own re-armed watch glue.
pub fn clear() {
    if let Some(map) = lock().as_mut() {
        map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialise the tests: `CHILD_WATCHES` is a process-global static, so
    /// distinct test cases must not race each other's inserts/removes.
    fn guard() -> std::sync::MutexGuard<'static, ()> {
        static TEST_LOCK: Mutex<()> = Mutex::new(());
        TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn register_sanitizes_exit_signal() {
        let _g = guard();
        clear();
        // 0 -> 0 (the "no exit signal" sentinel is preserved).
        register(101, 1, 0);
        assert_eq!(take(101), Some((1, 0)));
        // in-range kept verbatim.
        register(102, 2, 5);
        assert_eq!(take(102), Some((2, 5)));
        // out of range -> SIGCHLD (17).
        register(103, 3, 99);
        assert_eq!(take(103), Some((3, LINUX_SIGCHLD)));
        assert_eq!(LINUX_SIGCHLD, 17);
        clear();
    }

    #[test]
    fn take_removes_and_returns_once() {
        let _g = guard();
        clear();
        register(201, 7, 17);
        assert_eq!(take(201), Some((7, 17)));
        // A second take finds nothing (publish-once: the entry is gone).
        assert_eq!(take(201), None);
        clear();
    }

    #[test]
    fn register_ignores_nonpositive_pid() {
        let _g = guard();
        clear();
        register(0, 1, 17);
        register(-5, 1, 17);
        assert!(!is_tracked(0));
        assert!(!is_tracked(-5));
        assert!(tracked_pids().is_empty());
        clear();
    }

    #[test]
    fn is_tracked_reflects_membership() {
        let _g = guard();
        clear();
        assert!(!is_tracked(301));
        register(301, 9, 17);
        assert!(is_tracked(301));
        let _ = take(301);
        assert!(!is_tracked(301));
        clear();
    }

    #[test]
    fn tracked_pids_snapshot() {
        let _g = guard();
        clear();
        register(401, 1, 17);
        register(402, 2, 17);
        register(403, 3, 0);
        let mut pids = tracked_pids();
        pids.sort_unstable();
        assert_eq!(pids, vec![401, 402, 403]);
        clear();
    }

    #[test]
    fn clear_empties_the_table() {
        let _g = guard();
        clear();
        register(501, 1, 17);
        register(502, 2, 17);
        assert!(!tracked_pids().is_empty());
        clear();
        assert!(tracked_pids().is_empty());
        assert!(!is_tracked(501));
    }
}
