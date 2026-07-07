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
//! Each vCPU publishes its guest's run-state into the carrick-kernel arena's
//! process section, which is mmap'd before the first guest fork and inherited by
//! every host descendant. The process section is keyed by host pid, so ANY guest
//! process can read ANY other guest's published state.
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

use std::sync::atomic::{AtomicU64, Ordering};

use carrick_kernel::arena::{ArenaError, KernelArena};
use carrick_kernel::domains::{HostPid, ProcessGeneration};
use carrick_kernel::process::{ProcessRecord, ProcessRecordRef, ProcessSection};

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

// Linear-scan arena records. Each record's `run_state` is a single u64:
//   bits  0..32  id — host pid (process entry) or guest tid (worker entry)
//   bits 32..40  encoded RunState (0 = unset)
//   bit  40      KIND_TID — set for a worker-thread entry, clear for a process
// A single atomic u64 store publishes id+state together, so a reader never sees
// an id paired with another owner's state (no torn cross-field read). A process
// claims ANY free record (and caches its ref for O(1) republish), and a reader
// scans for its id. The arena's fixed capacity is deliberately fail-closed:
// exhausting process records aborts instead of silently falling back to
// process-local state.
//
// Worker guest tids are `host_pid + k` (registry-allocated), so they share the
// low-32 numbering space with host pids: a worker tid can numerically equal a
// DIFFERENT process's host pid. The KIND_TID bit keeps those two disjoint — a
// worker entry and a process entry with the same low-32 value occupy separate
// slots (never clobber), and `published` prefers the process entry so a live
// process's /proc state is never shadowed by an aliasing worker tid.
const PID_MASK: u64 = 0xffff_ffff;
const STATE_SHIFT: u64 = 32;
const STATE_MASK: u64 = 0xff;
/// Distinguishes a worker-thread (guest tid) entry from a process (host pid)
/// entry so the two never collide in the low-32 id space. Part of the slot KEY.
const KIND_TID: u64 = 1 << 40;
fn pack(pid: u32, state: RunState) -> u64 {
    (pid as u64) | (state.encode() << STATE_SHIFT)
}

/// Pack a worker-thread (guest tid) entry — a process `pack` with the KIND_TID
/// tag set, so it never shares a slot with the host-pid entry of the same value.
fn pack_tid(tid: u32, state: RunState) -> u64 {
    pack(tid, state) | KIND_TID
}

fn unpack(raw: u64) -> Option<(u32, RunState)> {
    let pid = (raw & PID_MASK) as u32;
    if pid == 0 {
        return None;
    }
    let st = RunState::decode((raw >> STATE_SHIFT) & STATE_MASK)?;
    Some((pid, st))
}

fn processes() -> &'static ProcessSection {
    &KernelArena::init_global().layout().processes
}

/// Ensure the arena exists before the first guest fork (so every descendant
/// inherits the SAME mapping). Idempotent. Called once at loop start.
pub fn init_table() {
    let _ = KernelArena::init_global();
}

const REF_NONE: u64 = u64::MAX;
const REF_INDEX_MASK: u64 = 0xffff_ffff;

fn pack_ref(r: ProcessRecordRef) -> u64 {
    (u64::from(r.generation.raw()) << 32) | (r.index as u64)
}

fn unpack_ref(raw: u64) -> Option<ProcessRecordRef> {
    if raw == REF_NONE {
        return None;
    }
    let index = (raw & REF_INDEX_MASK) as usize;
    let generation = (raw >> 32) as u32;
    if generation == 0 {
        return None;
    }
    Some(ProcessRecordRef {
        index,
        generation: ProcessGeneration::new(generation),
    })
}

/// THIS process's own record ref, cached after the first claim so the hot-path
/// republish (every loop iteration) is one bounds check + one atomic store, not
/// a full-table scan. Process-local (NOT shared): each host process owns a
/// distinct record, and a forked child re-claims a fresh one. `REF_NONE` = not
/// yet claimed. Reset to unclaimed on fork (`reinit_booting_after_fork`).
static MY_SLOT: AtomicU64 = AtomicU64::new(REF_NONE);

/// Publish `state` for THIS process. Claims a slot on first publish, caches its
/// index in `MY_SLOT`, then updates it in place — so the hot-path republish (every
/// loop iteration) is one bounds check + one atomic store, not a full-table scan.
/// A single atomic store publishes pid+state atomically.
pub fn publish(state: RunState) {
    let pid = std::process::id();
    if pid == 0 {
        return;
    }
    let section = processes();
    let want = pack(pid, state);
    // Fast path: our slot is cached and still ours (a forked child clears the
    // cache, so a stale parent index can't be reused by the child).
    let cached = MY_SLOT.load(Ordering::Relaxed);
    if let Some(record) = cached_record(section, cached, pid, false) {
        record.run_state.store(want, Ordering::Release);
        return;
    }
    let r = claim_record(section, pid, want, false);
    MY_SLOT.store(pack_ref(r), Ordering::Relaxed);
}

/// Publish `state` for an ARBITRARY pid (used to seed a child's `Booting` from
/// the parent, and by tests). Cache-free: never reads or writes `MY_SLOT` (that
/// cache belongs to THIS process's own slot), so it can't perturb the caller's
/// fast path.
fn publish_for(pid: u32, state: RunState) {
    if pid == 0 {
        return;
    }
    let section = processes();
    let want = pack(pid, state);
    let _ = claim_record(section, pid, want, false);
}

/// Publish a guest-visible WORKER thread id into the shared state table. Worker
/// ids are not host pids (they can numerically equal another process's pid), so
/// they go into a KIND_TID-tagged slot disjoint from any process entry — other
/// guest processes can still poll `/proc/<tid>/stat` for them, fork-coherently,
/// without clobbering a process's slot. A tid equal to this process's own pid is
/// the thread-group LEADER, already covered by [`publish`], so it is skipped.
pub fn publish_guest_tid(tid: i32, state: RunState) {
    if let Ok(tid) = u32::try_from(tid) {
        if tid == 0 || tid == std::process::id() {
            return;
        }
        let section = processes();
        let _ = claim_record(section, tid, pack_tid(tid, state), true);
    }
}

/// Remove a guest-visible worker thread id from the shared state table when that
/// thread exits, so `/proc/<tid>` stops resolving through stale state. Clears
/// ONLY the KIND_TID-tagged slot, never a process entry that shares the low-32
/// value.
pub fn clear_guest_tid(tid: i32) {
    let Ok(tid) = u32::try_from(tid) else {
        return;
    };
    if tid == 0 {
        return;
    }
    let section = processes();
    if let Some(r) = find_record(section, tid, true) {
        section.release(r);
    }
}

fn cached_record(
    section: &ProcessSection,
    packed_ref: u64,
    id: u32,
    want_tid: bool,
) -> Option<&ProcessRecord> {
    let r = unpack_ref(packed_ref)?;
    let record = section.records.get(r.index)?;
    if record.generation.load(Ordering::Acquire) != r.generation.raw() {
        return None;
    }
    if record.host_pid.load(Ordering::Acquire) != id {
        return None;
    }
    let raw = record.run_state.load(Ordering::Acquire);
    if (raw & PID_MASK) as u32 == id && ((raw & KIND_TID) != 0) == want_tid {
        Some(record)
    } else {
        None
    }
}

fn find_record(section: &ProcessSection, id: u32, want_tid: bool) -> Option<ProcessRecordRef> {
    for (index, record) in section.records.iter().enumerate() {
        if record.host_pid.load(Ordering::Acquire) != id {
            continue;
        }
        let generation = record.generation.load(Ordering::Acquire);
        if generation == 0 {
            continue;
        }
        let raw = record.run_state.load(Ordering::Acquire);
        if (raw & PID_MASK) as u32 == id && ((raw & KIND_TID) != 0) == want_tid {
            return Some(ProcessRecordRef {
                index,
                generation: ProcessGeneration::new(generation),
            });
        }
    }
    None
}

fn claim_record(section: &ProcessSection, id: u32, want: u64, want_tid: bool) -> ProcessRecordRef {
    if let Some(r) = find_record(section, id, want_tid) {
        section.records[r.index]
            .run_state
            .store(want, Ordering::Release);
        return r;
    }

    let generation = KernelArena::global().allocate_generation();
    match section.claim(Some(HostPid::new(id)), generation, |record| {
        record.run_state.store(want, Ordering::Relaxed);
    }) {
        Ok(r) => r,
        Err(err) => abort_on_arena_error(err),
    }
}

fn abort_on_arena_error(err: ArenaError) -> ! {
    eprintln!("carrick: run-state arena publication failed: {err:?}");
    std::process::abort();
}

/// Reset THIS (freshly-forked child) process's published state to `Booting`.
/// The child inherited the parent's (shared) table AND the parent's cached slot
/// index, but is a NEW host pid — so clear the cache (forcing a fresh claim) and
/// publish a `Booting` entry for the child pid. The parent's entry is untouched
/// and the table is shared, so the parent still reads its own state. Call in the
/// fork-CHILD setup, before any boot work that could park the vCPU.
pub fn reinit_booting_after_fork() {
    MY_SLOT.store(REF_NONE, Ordering::Relaxed);
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

/// Read the published run-state of `pid` (any guest process, or a worker thread
/// by its guest tid). `None` if nothing is published — the caller then falls back
/// to the host kernel state. Full linear scan (no home-index invariant): rare,
/// /proc-read-only, and ~510 relaxed loads is trivial.
///
/// A PROCESS entry for `pid` wins outright: if a live process holds this id, its
/// state is authoritative and is never shadowed by a worker-tid entry that
/// happens to alias the value. A worker-tid entry is returned only when no
/// process entry claims the id (the genuine cross-process `/proc/<tid>` case).
pub fn published(pid: u32) -> Option<RunState> {
    if pid == 0 {
        return None;
    }
    let section = processes();
    let mut tid_hit = None;
    for record in section.records.iter() {
        if record.host_pid.load(Ordering::Acquire) != pid {
            continue;
        }
        let generation = record.generation.load(Ordering::Acquire);
        if generation == 0 {
            continue;
        }
        let raw = record.run_state.load(Ordering::Acquire);
        if let Some((p, st)) = unpack(raw)
            && p == pid
        {
            if raw & KIND_TID == 0 {
                return Some(st); // a process entry for this id is authoritative
            }
            tid_hit = Some(st); // remember; used only if no process entry exists
        }
    }
    tid_hit
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
    fn table_covers_ltp_futex_cmp_requeue_fanout() {
        // `futex_cmp_requeue01` waits for 1000 children to show `S` before it
        // changes the futex word. If the run-state table fills first, later
        // children fall back to host scheduler state and can appear asleep before
        // their shared futex waiter is actually enrolled.
        let first = 0x2000_0000_u32;
        let count = 1200_u32;
        for id in first..first + count {
            wipe_id(id);
            publish_for(id, RunState::Blocked);
        }
        for id in first..first + count {
            assert_eq!(
                published(id),
                Some(RunState::Blocked),
                "missing high-fanout run-state slot for pid {id}"
            );
        }
        for id in first..first + count {
            wipe_id(id);
        }
    }

    /// Zero every slot (either kind) holding this low-32 id, so a test leaves the
    /// process-shared table clean for the others.
    fn wipe_id(id: u32) {
        let section = processes();
        for (index, record) in section.records.iter().enumerate() {
            if record.host_pid.load(Ordering::Relaxed) == id {
                let generation = record.generation.load(Ordering::Relaxed);
                if generation != 0 {
                    section.release(ProcessRecordRef {
                        index,
                        generation: ProcessGeneration::new(generation),
                    });
                }
            }
        }
    }

    #[test]
    fn worker_tid_entry_does_not_collide_with_process_pid_entry() {
        // A worker guest tid can numerically equal a DIFFERENT process's host pid.
        // The two must occupy disjoint slots; the process entry is authoritative,
        // and clearing the worker tid must not erase the process entry.
        let id = 0x0BAD_F00D;
        wipe_id(id);
        publish_for(id, RunState::Running); // as if process host-pid==id booted
        publish_guest_tid(id as i32, RunState::Blocked); // worker of another proc

        // The process entry wins — never shadowed by the aliasing worker tid.
        assert_eq!(published(id), Some(RunState::Running));
        // Clearing the worker tid must NOT erase the process entry.
        clear_guest_tid(id as i32);
        assert_eq!(published(id), Some(RunState::Running));
        wipe_id(id);
    }

    #[test]
    fn worker_tid_visible_only_until_it_exits() {
        // With no process claiming the id, a worker-tid entry resolves the genuine
        // cross-process `/proc/<tid>` read, and disappears when the thread exits.
        let tid = 0x0BAD_BEEF;
        wipe_id(tid);
        publish_guest_tid(tid as i32, RunState::Blocked);
        assert_eq!(published(tid), Some(RunState::Blocked));
        clear_guest_tid(tid as i32);
        assert_eq!(published(tid), None);
        wipe_id(tid);
    }

    #[test]
    fn publish_guest_tid_skips_the_thread_group_leader() {
        // The leader's tid equals the process pid; publish() already covers that
        // slot, so publish_guest_tid must not add a separate worker entry for it.
        let me = std::process::id();
        wipe_id(me);
        publish_guest_tid(me as i32, RunState::Blocked);
        assert_eq!(
            published(me),
            None,
            "no worker entry created for the leader"
        );
        wipe_id(me);
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
