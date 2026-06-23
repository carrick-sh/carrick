//! Process-tree-wide published GUEST run-state, so `/proc/<pid>/stat` reports a
//! guest process's TRUE Linux run-state instead of the host vCPU-thread's
//! scheduler state.
//!
//! # Why the host scheduler state is not enough
//!
//! carrick runs each guest process on a host vCPU thread that drives the guest
//! and parks in a host `ppoll`/`futex`/`wait4` whenever it has no guest work.
//! That host park is INDISTINGUISHABLE between two very different guest states:
//!
//!   * a guest genuinely blocked in `pause()`/`read()`/`futex()` (Linux `S`), and
//!   * a freshly-forked child still doing its post-fork RUNTIME BOOT before it has
//!     executed a single guest instruction (Linux `R` — on real Linux the child
//!     is runnable during setup).
//!
//! Both park the vCPU thread in `do_sys_poll` (`syscall=271`, `state=S`), so a
//! sibling reading `/proc/<child>/stat` via the host kernel (`host_proc`) sees
//! `S` for a child that Linux would report `R`. The `pauseinterrupt2` probe fires
//! `kill(child, SIGINT)` as soon as the child shows `S`; carrick reported `S`
//! ~45 ms too early (during boot), the child's empty handler consumed the SIGINT
//! before its real `pause()`, and the test diverged from Linux.
//!
//! # The fix: publish the guest's true run-state
//!
//! Each vCPU publishes its guest's run-state into a `MAP_SHARED` table mmap'd
//! before the first guest fork and inherited by every host descendant — the same
//! durable, fork-coherent pattern as [`crate::deadlock_watchdog`] and
//! [`crate::guest_cpu`]'s reaped-child table (an in-process `HashMap` would NOT
//! survive `fork(2)` and would silently diverge). The table is keyed by host pid,
//! so ANY guest process can read ANY other guest's published state.
//!
//!   * [`RunState::Booting`] — process start until the vCPU first resumes guest
//!     code (post-fork runtime boot). Renders `R`.
//!   * [`RunState::Running`] — the vCPU is executing guest code (or in the host
//!     servicing a non-blocking syscall). Renders `R`.
//!   * [`RunState::Blocked`] — the vCPU is parked in a GENUINE guest-blocking wait
//!     (`pause`/`poll`/`select`/`epoll`/`futex`/`nanosleep`/`wait4`). Renders `S`.
//!
//! `/proc/<pid>/stat` (and `/task/<tid>/stat`) prefers the published state for a
//! guest process and falls back to the host scheduler state when none is
//! published (a process that never ran the vCPU loop, or a stale/evicted slot).
//! Zombie/stopped/uninterruptible classification stays with the host kernel —
//! this only disambiguates `R` vs `S` for a live guest.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Published guest run-state of a process. The encoded value lives in the high
/// 8 bits of a shared `u64` slot whose low bits hold the owning host pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    /// Post-fork runtime boot, before guest code first resumes. Linux `R`.
    Booting,
    /// Executing guest code, or in the host on a non-blocking syscall. Linux `R`.
    Running,
    /// Parked in a genuine guest-blocking wait (pause/poll/futex/sleep/wait4).
    /// Linux `S`.
    Blocked,
}

impl RunState {
    fn encode(self) -> u64 {
        match self {
            RunState::Booting => 1,
            RunState::Running => 2,
            RunState::Blocked => 3,
        }
    }

    fn decode(v: u64) -> Option<RunState> {
        match v {
            1 => Some(RunState::Booting),
            2 => Some(RunState::Running),
            3 => Some(RunState::Blocked),
            _ => None,
        }
    }

    /// The Linux `/proc/<pid>/stat` state char for this published run-state.
    /// Only ever `R` or `S`; zombie/stopped/uninterruptible stay with the host
    /// kernel (this disambiguates a LIVE guest's R-vs-S only).
    pub fn stat_char(self) -> char {
        match self {
            RunState::Booting | RunState::Running => 'R',
            RunState::Blocked => 'S',
        }
    }
}

// Linear-scan slot table in a shared mapping. Each slot is a single u64:
//   bits  0..32  host pid (0 = empty slot)
//   bits 32..40  encoded RunState (0 = unset)
// A single atomic u64 store publishes pid+state together, so a reader never sees
// a pid paired with another process's state (no torn cross-field read). A process
// claims ANY free slot (and caches its index for O(1) republish), and a reader
// scans for its pid — so a slot may sit anywhere (no home-index invariant), which
// keeps full-table dead-slot reclamation correct (an evicted slot is readable
// wherever it lands). 510 slots comfortably exceeds the live guest-process count
// of any conformance workload; once full, a process whose slot can't be claimed
// degrades to the host-state fallback (never a wrong state).
const SLOTS: usize = 510;

const PID_MASK: u64 = 0xffff_ffff;
const STATE_SHIFT: u64 = 32;
const STATE_MASK: u64 = 0xff;

fn pack(pid: u32, state: RunState) -> u64 {
    (pid as u64) | (state.encode() << STATE_SHIFT)
}

fn unpack(raw: u64) -> Option<(u32, RunState)> {
    let pid = (raw & PID_MASK) as u32;
    if pid == 0 {
        return None;
    }
    let st = RunState::decode((raw >> STATE_SHIFT) & STATE_MASK)?;
    Some((pid, st))
}

/// The shared slot table, in a `MAP_SHARED` anonymous mapping established before
/// the first guest fork and inherited (the SAME physical pages) by every host
/// descendant. Falls back to a process-private box if `mmap` fails — the guest
/// then publishes/reads only its own state, which is harmless (the reader's
/// host-state fallback covers a sibling that isn't visible).
fn table() -> &'static [AtomicU64] {
    static CELL: OnceLock<usize> = OnceLock::new();
    let base = *CELL.get_or_init(|| {
        let bytes = SLOTS * std::mem::size_of::<AtomicU64>();
        // SAFETY: a fresh anonymous shared mapping owned for the process lifetime.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_SHARED,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            // Process-private fallback: a leaked zeroed Box of the same shape.
            let v: Vec<AtomicU64> = (0..SLOTS).map(|_| AtomicU64::new(0)).collect();
            return Box::into_raw(v.into_boxed_slice()) as *mut AtomicU64 as usize;
        }
        // mmap(MAP_ANON) zero-fills, so every slot starts empty (pid 0).
        p as usize
    });
    // SAFETY: `base` points at SLOTS contiguous AtomicU64 valid for the whole
    // process; MAP_SHARED makes them the SAME words in every host descendant.
    unsafe { std::slice::from_raw_parts(base as *const AtomicU64, SLOTS) }
}

/// Ensure the shared table exists before the first guest fork (so every
/// descendant inherits the SAME mapping). Idempotent. Called once at loop start.
pub fn init_table() {
    let _ = table();
}

/// THIS process's own slot index, cached after the first claim so the hot-path
/// republish (every loop iteration) is one bounds check + one atomic store, not
/// a full-table scan. Process-local (NOT shared): each host process owns a
/// distinct slot, and a forked child re-claims a fresh one. `usize::MAX` = not
/// yet claimed. Reset to unclaimed on fork (`reinit_booting_after_fork`).
static MY_SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Publish `state` for THIS process. Claims a slot on first publish, caches its
/// index in `MY_SLOT`, then updates it in place — so the hot-path republish (every
/// loop iteration) is one bounds check + one atomic store, not a full-table scan.
/// A single atomic store publishes pid+state atomically.
pub fn publish(state: RunState) {
    let pid = std::process::id();
    if pid == 0 {
        return;
    }
    let tbl = table();
    let want = pack(pid, state);
    // Fast path: our slot is cached and still ours (a forked child clears the
    // cache, so a stale parent index can't be reused by the child).
    let cached = MY_SLOT.load(Ordering::Relaxed);
    if cached != usize::MAX
        && cached < SLOTS
        && (tbl[cached].load(Ordering::Relaxed) & PID_MASK) as u32 == pid
    {
        tbl[cached].store(want, Ordering::Release);
        return;
    }
    if let Some(slot) = claim_slot(tbl, pid, want) {
        MY_SLOT.store(slot, Ordering::Relaxed);
    }
}

/// Publish `state` for an ARBITRARY pid (used to seed a child's `Booting` from
/// the parent, and by tests). Cache-free: never reads or writes `MY_SLOT` (that
/// cache belongs to THIS process's own slot), so it can't perturb the caller's
/// fast path.
fn publish_for(pid: u32, state: RunState) {
    if pid == 0 {
        return;
    }
    let tbl = table();
    let want = pack(pid, state);
    let _ = claim_slot(tbl, pid, want);
}

/// Find or claim this pid's slot, writing `want`. Returns the slot index, or
/// `None` if the table is full of LIVE processes (the process then degrades to
/// the host-state fallback — never a wrong state). Once per process (cached
/// after), so the dead-slot eviction scan here is off the hot path. Linear scan:
/// the slot may land anywhere, so the reader scans too — which is what makes
/// full-table dead-slot reclamation correct (an evicted slot is readable wherever
/// it lands, with no home-index invariant to violate).
fn claim_slot(tbl: &[AtomicU64], pid: u32, want: u64) -> Option<usize> {
    // First pass: reuse our own slot if present, else claim a free one.
    for (idx, slot) in tbl.iter().enumerate() {
        let cur = slot.load(Ordering::Relaxed);
        let cur_pid = (cur & PID_MASK) as u32;
        if cur_pid == pid {
            slot.store(want, Ordering::Release); // already ours — update
            return Some(idx);
        }
        if cur_pid == 0
            && slot
                .compare_exchange(cur, want, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            return Some(idx);
        }
    }
    // Full: reclaim a slot whose owner is no longer a live process. Only in the
    // rare full-table case (a guest that has forked >510 processes), at most once
    // per process, so the per-slot `kill(pid, 0)` liveness probe is off the hot
    // path.
    for (idx, slot) in tbl.iter().enumerate() {
        let cur = slot.load(Ordering::Relaxed);
        let cur_pid = (cur & PID_MASK) as u32;
        if cur_pid != 0
            && cur_pid != pid
            && !pid_is_live(cur_pid)
            && slot
                .compare_exchange(cur, want, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            return Some(idx);
        }
    }
    None
}

/// Whether `pid` is still a live process (any state, including zombie). Used
/// only to reclaim a dead process's slot when the table is full.
fn pid_is_live(pid: u32) -> bool {
    // SAFETY: kill(pid, 0) sends no signal; it only checks existence/permission.
    // EPERM (process exists, owned by another user) still means "live"; only
    // ESRCH means gone. All carrick guests are same-user, so EPERM is unexpected
    // but treated conservatively as live (never wrongly evict a live process).
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Reset THIS (freshly-forked child) process's published state to `Booting`.
/// The child inherited the parent's (shared) table AND the parent's cached slot
/// index, but is a NEW host pid — so clear the cache (forcing a fresh claim) and
/// publish a `Booting` entry for the child pid. The parent's entry is untouched
/// and the table is shared, so the parent still reads its own state. Call in the
/// fork-CHILD setup, before any boot work that could park the vCPU.
pub fn reinit_booting_after_fork() {
    MY_SLOT.store(usize::MAX, Ordering::Relaxed);
    publish_for(std::process::id(), RunState::Booting);
}

/// Publish `Booting` for a just-forked CHILD pid, from the PARENT, before the
/// parent's fork returns. This closes the race where the parent polls
/// `/proc/<child>/stat` faster than the child can run its own
/// `reinit_booting_after_fork`: without it, those first parent reads see the
/// child's host boot-`ppoll` as `S` (the pauseinterrupt2 bug). The table is
/// shared, so this parent-side write IS the entry the child later updates to
/// Running/Blocked from its own vCPU. Does NOT touch the parent's cached slot.
pub fn publish_child_booting(child_pid: u32) {
    publish_for(child_pid, RunState::Booting);
}

/// Read the published run-state of `pid` (any guest process). `None` if `pid`
/// has no published slot — the caller then falls back to the host kernel state.
/// Full linear scan (no home-index invariant): rare, /proc-read-only, and ~510
/// relaxed loads is trivial.
pub fn published(pid: u32) -> Option<RunState> {
    if pid == 0 {
        return None;
    }
    let tbl = table();
    for slot in tbl.iter() {
        let raw = slot.load(Ordering::Acquire);
        if let Some((p, st)) = unpack(raw)
            && p == pid
        {
            return Some(st);
        }
    }
    None
}

/// The Linux `/proc/<pid>/stat` state char for `pid`, preferring the published
/// guest run-state and returning `None` when nothing is published (caller uses
/// the host kernel state). Maps `Booting`/`Running` → `R`, `Blocked` → `S`.
pub fn published_stat_char(pid: u32) -> Option<char> {
    published(pid).map(RunState::stat_char)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrips() {
        for st in [RunState::Booting, RunState::Running, RunState::Blocked] {
            assert_eq!(RunState::decode(st.encode()), Some(st));
        }
        assert_eq!(RunState::decode(0), None);
        assert_eq!(RunState::decode(99), None);
    }

    #[test]
    fn stat_char_maps_running_and_booting_to_r_blocked_to_s() {
        assert_eq!(RunState::Booting.stat_char(), 'R');
        assert_eq!(RunState::Running.stat_char(), 'R');
        assert_eq!(RunState::Blocked.stat_char(), 'S');
    }

    #[test]
    fn pack_unpack_pairs_pid_with_state() {
        let raw = pack(4242, RunState::Blocked);
        assert_eq!(unpack(raw), Some((4242, RunState::Blocked)));
        // pid 0 is the empty sentinel.
        assert_eq!(unpack(0), None);
    }

    #[test]
    fn publish_then_read_back_for_several_pids() {
        // Distinct synthetic pids exercise the open-addressing claim+lookup.
        let pids = [101u32, 202, 303, 404, 505];
        for (i, &p) in pids.iter().enumerate() {
            let st = match i % 3 {
                0 => RunState::Booting,
                1 => RunState::Running,
                _ => RunState::Blocked,
            };
            publish_for(p, st);
        }
        for (i, &p) in pids.iter().enumerate() {
            let want = match i % 3 {
                0 => RunState::Booting,
                1 => RunState::Running,
                _ => RunState::Blocked,
            };
            assert_eq!(published(p), Some(want), "pid {p}");
        }
        // An unpublished pid reads None (host-state fallback).
        assert_eq!(published(999_001), None);
    }

    #[test]
    fn republish_updates_in_place() {
        publish_for(770_077, RunState::Running);
        assert_eq!(published(770_077), Some(RunState::Running));
        publish_for(770_077, RunState::Blocked);
        assert_eq!(published(770_077), Some(RunState::Blocked));
        publish_for(770_077, RunState::Running);
        assert_eq!(published(770_077), Some(RunState::Running));
    }
}
