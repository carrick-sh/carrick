//! Platform-NEUTRAL fork-coherent FASYNC (signal-driven I/O) registry.
//!
//! Linux's `O_ASYNC`/`FASYNC` on a pipe/socket/fifo makes the kernel send a
//! signal (default `SIGIO`, or the `F_SETSIG` signal) to the fd's `F_SETOWN`
//! owner whenever the fd becomes ready. The signal fires on the readiness EDGE
//! regardless of which process triggered it — for a pipe, a WRITER in one
//! process makes the READER's fd ready and the READER's owner gets the signal.
//!
//! carrick forks real host processes for `clone(2)`, so the arming state (the
//! owner, signal, and FASYNC flag) recorded on the reader's `OpenDescription`
//! lives in the ARMING process's address space and is invisible to the writer
//! process. An in-memory map would silently diverge across fork (see
//! AGENTS.md). The durable, fork-coherent mechanism is a `MAP_SHARED|MAP_ANON`
//! table — allocated once pre-fork and inherited by every guest process,
//! exactly like the xsignal ring ([`crate::xsig`]). It is keyed by a single
//! carrick "pipe id" (`u64`) — a value assigned at pipe creation and stored on
//! BOTH ends' `OpenDescription`s, so it is identical for the reader and the
//! writer and is inherited unchanged across fork. (On Linux both pipe ends
//! share one host inode, but on macOS the two ends have DIFFERENT `st_ino`, so
//! a per-fd host-inode key armed on the read end would never match the
//! write-end write that triggers the signal — the pipe id collapses both ends
//! onto one stable key.) A writer can therefore look up the reader's arming and
//! deliver the signal.
//!
//! This module is the platform-NEUTRAL core (the slot layout, the
//! `MAP_SHARED|MAP_ANON` allocation, arm/disarm/lookup). The actual signal
//! delivery — translating the owner ns-pid to a host pid and routing the signal
//! through the kill path — stays in the dispatcher, which calls [`lookup`] on
//! the readiness edge.

use std::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

const FASYNC_SLOTS: usize = 256;

#[repr(C)]
struct FasyncSlot {
    /// 0 = free, 1 = claiming (payload not yet valid), 2 = armed.
    used: AtomicU32,
    /// carrick pipe id of the pipe/socket object: the join key shared by both
    /// ends and stable across fork (see the module docs). `0` is never a valid
    /// armed key.
    pipe_id: AtomicU64,
    /// `F_SETOWN`/`F_SETOWN_EX` target (guest ns-pid == host pid in carrick).
    owner_pid: AtomicU32,
    /// `F_OWNER_TID` (0) / `F_OWNER_PID` (1) / `F_OWNER_PGRP` (2).
    owner_type: AtomicU32,
    /// `F_SETSIG` signal (Linux signum); 0 means the default `SIGIO`.
    sig: AtomicU32,
}

#[repr(C)]
struct FasyncTable {
    slots: [FasyncSlot; FASYNC_SLOTS],
}

static FASYNC_TABLE: AtomicPtr<FasyncTable> = AtomicPtr::new(std::ptr::null_mut());

/// An armed FASYNC registration, returned by [`lookup`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FasyncOwner {
    /// `F_SETOWN` target pid (or pgrp id for `F_OWNER_PGRP`).
    pub owner_pid: i32,
    /// `F_OWNER_TID` / `F_OWNER_PID` / `F_OWNER_PGRP`.
    pub owner_type: i32,
    /// The signal to deliver (Linux signum); 0 == default `SIGIO`.
    pub sig: i32,
}

/// Allocate the shared FASYNC table once (`MAP_SHARED|MAP_ANON`, inherited
/// across fork). Idempotent — a non-null pointer (the child inherited the
/// mapping) is a no-op, so every process shares ONE table. Best-effort: a failed
/// mmap leaves the table absent and arm/lookup become no-ops (FASYNC delivery
/// silently degrades, never crashes).
pub fn fasync_init() {
    if !FASYNC_TABLE.load(Ordering::Acquire).is_null() {
        return;
    }
    let size = std::mem::size_of::<FasyncTable>();
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return;
    }
    // mmap zero-fills, so every slot's `used` is 0 (free) already.
    FASYNC_TABLE.store(p.cast::<FasyncTable>(), Ordering::Release);
}

fn table() -> Option<&'static FasyncTable> {
    let p = FASYNC_TABLE.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: a non-null FASYNC_TABLE points at a live MAP_SHARED mapping of
        // exactly one FasyncTable, allocated by fasync_init and never unmapped.
        Some(unsafe { &*p })
    }
}

/// Find the slot armed for `pipe_id`, if any. Returns the slot index.
fn find_armed(t: &FasyncTable, pipe_id: u64) -> Option<usize> {
    t.slots.iter().position(|s| {
        s.used.load(Ordering::Acquire) == 2 && s.pipe_id.load(Ordering::Acquire) == pipe_id
    })
}

/// Cheap pre-check for the write-path hook: is ANY fd armed for signal-driven
/// I/O anywhere? Lets the hot pipe/socket write path skip its per-write inode
/// `fstat` when no fasync registration exists (the overwhelmingly common case).
/// A scan of the fixed slot array is atomic loads only — no syscall.
pub fn any_armed() -> bool {
    match table() {
        Some(t) => t.slots.iter().any(|s| s.used.load(Ordering::Acquire) == 2),
        None => false,
    }
}

/// Arm (or re-arm) signal-driven I/O for the pipe/socket `pipe_id`. A later
/// `lookup` on the same key returns `owner`/`sig`. Re-arming the same key
/// overwrites the previous owner/signal (Linux's per-fd FASYNC + F_SETOWN +
/// F_SETSIG can each be re-set). Best-effort: a full or absent table drops the
/// arm silently.
pub fn arm(pipe_id: u64, owner: FasyncOwner) {
    let Some(t) = table() else {
        return;
    };
    // Re-arm an existing entry in place (Relaxed stores are fine: the slot is
    // already published at `used == 2` and `lookup` re-reads each field).
    if let Some(idx) = find_armed(t, pipe_id)
        && let Some(slot) = t.slots.get(idx)
    {
        slot.owner_pid
            .store(owner.owner_pid as u32, Ordering::Relaxed);
        slot.owner_type
            .store(owner.owner_type as u32, Ordering::Relaxed);
        slot.sig.store(owner.sig as u32, Ordering::Relaxed);
        return;
    }
    // Claim a free slot (0 -> 1), fill it, then publish (1 -> 2).
    for slot in t.slots.iter() {
        if slot
            .used
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            slot.pipe_id.store(pipe_id, Ordering::Relaxed);
            slot.owner_pid
                .store(owner.owner_pid as u32, Ordering::Relaxed);
            slot.owner_type
                .store(owner.owner_type as u32, Ordering::Relaxed);
            slot.sig.store(owner.sig as u32, Ordering::Relaxed);
            slot.used.store(2, Ordering::Release);
            return;
        }
    }
}

/// Disarm signal-driven I/O for `pipe_id` (clearing `O_ASYNC`, or the last
/// close of the pipe). A no-op if no entry is armed for the key.
pub fn disarm(pipe_id: u64) {
    let Some(t) = table() else {
        return;
    };
    if let Some(idx) = find_armed(t, pipe_id)
        && let Some(slot) = t.slots.get(idx)
    {
        slot.pipe_id.store(0, Ordering::Relaxed);
        slot.used.store(0, Ordering::Release);
    }
}

/// Look up the FASYNC owner armed for `pipe_id`, if any. Called on the fd's
/// readiness edge (e.g. a guest write to a pipe whose read end is armed) to
/// decide whether — and to whom — to deliver the I/O signal.
pub fn lookup(pipe_id: u64) -> Option<FasyncOwner> {
    let t = table()?;
    let idx = find_armed(t, pipe_id)?;
    let slot = t.slots.get(idx)?;
    Some(FasyncOwner {
        owner_pid: slot.owner_pid.load(Ordering::Acquire) as i32,
        owner_type: slot.owner_type.load(Ordering::Acquire) as i32,
        sig: slot.sig.load(Ordering::Acquire) as i32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn reset() {
        fasync_init();
        if let Some(t) = table() {
            for slot in t.slots.iter() {
                slot.used.store(0, Ordering::Release);
                slot.pipe_id.store(0, Ordering::Relaxed);
            }
        }
    }

    #[test]
    fn init_is_idempotent() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        fasync_init();
        let first = FASYNC_TABLE.load(Ordering::Acquire);
        assert!(!first.is_null());
        fasync_init();
        assert_eq!(first, FASYNC_TABLE.load(Ordering::Acquire));
    }

    #[test]
    fn arm_then_lookup_round_trips() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        assert_eq!(lookup(42), None);
        arm(
            42,
            FasyncOwner {
                owner_pid: 1234,
                owner_type: 1,
                sig: 10,
            },
        );
        assert_eq!(
            lookup(42),
            Some(FasyncOwner {
                owner_pid: 1234,
                owner_type: 1,
                sig: 10,
            })
        );
        // A different pipe id is not armed.
        assert_eq!(lookup(43), None);
        reset();
    }

    #[test]
    fn rearm_overwrites_owner_and_sig() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        arm(
            1,
            FasyncOwner {
                owner_pid: 100,
                owner_type: 1,
                sig: 0,
            },
        );
        // F_SETOWN then F_SETSIG re-arm the SAME pipe id with new owner/sig.
        arm(
            1,
            FasyncOwner {
                owner_pid: 200,
                owner_type: 2,
                sig: 12,
            },
        );
        assert_eq!(
            lookup(1),
            Some(FasyncOwner {
                owner_pid: 200,
                owner_type: 2,
                sig: 12,
            })
        );
        // Only one slot is consumed (re-arm is in place, not a new slot).
        let armed = table()
            .map(|t| {
                t.slots
                    .iter()
                    .filter(|s| s.used.load(Ordering::Acquire) == 2)
                    .count()
            })
            .unwrap_or(0);
        assert_eq!(armed, 1);
        reset();
    }

    #[test]
    fn disarm_clears_the_entry() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        arm(
            6,
            FasyncOwner {
                owner_pid: 9,
                owner_type: 1,
                sig: 29,
            },
        );
        assert!(lookup(6).is_some());
        disarm(6);
        assert_eq!(lookup(6), None);
        // Disarming an unarmed key is a harmless no-op.
        disarm(6);
        assert_eq!(lookup(6), None);
        reset();
    }
}
