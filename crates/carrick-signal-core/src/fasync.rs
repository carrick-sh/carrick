//! Platform-NEUTRAL fork-coherent FASYNC (signal-driven I/O) registry.
//!
//! Linux's `O_ASYNC`/`FASYNC` on a pipe/socket/fifo makes the kernel send a
//! signal (default `SIGIO`, or the `F_SETSIG` signal) to the fd's `F_SETOWN`
//! owner whenever the fd becomes ready. The signal fires on the readiness EDGE
//! regardless of which process triggered it — for a pipe, a WRITER in one
//! process makes the READER's fd ready and the READER's owner gets the signal.
//!
//! HVPatch keeps every logical Linux task in one carrier and one Carrick kernel
//! graph. The readiness edge may nevertheless be observed by a different task
//! (or container) than the one that armed the read end, so the registry retains
//! the arming container plus exact task/thread/group generation. It is keyed by
//! one Carrick pipe id (`u64`) assigned at pipe creation and stored on BOTH
//! ends' open descriptions. (On macOS the host pipe ends have different inode
//! numbers, so a host-inode key cannot join the writer's edge to the reader's
//! owner.)
//!
//! This module is the platform-neutral slot store. The runtime resolves the
//! guest-visible F_SETOWN id once, stores an exact kernel generation here, and
//! posts through Carrick's signal authority on lookup. No host PID or host
//! signal transport participates in HVPatch delivery.

use std::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

use carrick_fatal::carrick_fatal;

#[cfg(test)]
static USED_SLOT_LOADS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static ARMED_COUNT_LOADS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static TABLE_POINTER_LOADS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

const FASYNC_SLOTS: usize = 256;

#[repr(C)]
struct FasyncSlot {
    /// 0 = free, 1 = claiming (payload not yet valid), 2 = armed.
    used: AtomicU32,
    /// Even = stable payload, odd = a writer is replacing it. This seqlock is
    /// never reset when a slot is reused, so a reader spanning disarm/re-arm
    /// cannot mistake two different publications for one stable tuple.
    sequence: AtomicU64,
    /// carrick pipe id of the pipe/socket object: the join key shared by both
    /// ends and stable across fork (see the module docs). `0` is never a valid
    /// armed key.
    pipe_id: AtomicU64,
    /// Exact Carrick open-file-description generation that owns this arm.
    /// Closing a different description for the same pipe must not disarm it.
    registration_id: AtomicU64,
    /// Guest-visible `F_SETOWN`/`F_SETOWN_EX` value, retained for GETOWN.
    owner_pid: AtomicU32,
    /// `F_OWNER_TID` (0) / `F_OWNER_PID` (1) / `F_OWNER_PGRP` (2).
    owner_type: AtomicU32,
    /// `F_SETSIG` signal (Linux signum); 0 means the default `SIGIO`.
    sig: AtomicU32,
    /// Carrick kernel container that owned the namespace lookup at F_SETOWN.
    container_id: AtomicU64,
    /// Exact kernel task or process-group id selected at F_SETOWN.
    target_id: AtomicU32,
    /// Task serial or process-group object generation. Zero means unresolved.
    target_generation: AtomicU64,
    /// Exact kernel TID for F_OWNER_TID; zero for process/group owners.
    thread_id: AtomicU32,
    /// Exact thread serial for F_OWNER_TID; zero for process/group owners.
    thread_generation: AtomicU64,
}

#[repr(C)]
struct FasyncTable {
    /// Number of published or currently re-arming slots. The successful-write
    /// hot path reads this one word instead of scanning all 256 slots.
    armed_count: AtomicU32,
    slots: [FasyncSlot; FASYNC_SLOTS],
}

static FASYNC_TABLE: AtomicPtr<FasyncTable> = AtomicPtr::new(std::ptr::null_mut());

/// An armed FASYNC registration, returned by [`lookup`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FasyncOwner {
    /// Exact Carrick open-file-description id that owns the registration.
    pub registration_id: u64,
    /// `F_SETOWN` target pid (or pgrp id for `F_OWNER_PGRP`).
    pub owner_pid: i32,
    /// `F_OWNER_TID` / `F_OWNER_PID` / `F_OWNER_PGRP`.
    pub owner_type: i32,
    /// The signal to deliver (Linux signum); 0 == default `SIGIO`.
    pub sig: i32,
    /// Monotonic Carrick container identity captured at F_SETOWN.
    pub container_id: u64,
    /// Exact internal task/process-group id; zero means the target did not resolve.
    pub target_id: i32,
    /// Exact task serial or process-group generation; zero means unresolved.
    pub target_generation: u64,
    /// Exact internal TID for F_OWNER_TID; zero otherwise.
    pub thread_id: i32,
    /// Exact thread serial for F_OWNER_TID; zero otherwise.
    pub thread_generation: u64,
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
    #[cfg(test)]
    TABLE_POINTER_LOADS.fetch_add(1, Ordering::Relaxed);
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
enum SlotSearch {
    Armed(usize),
    Busy,
    Missing,
}

fn find_armed(t: &FasyncTable, pipe_id: u64) -> SlotSearch {
    let mut busy = false;
    for (index, slot) in t.slots.iter().enumerate() {
        let used = load_used(slot, Ordering::Acquire);
        if used == 1 {
            busy = true;
            continue;
        }
        if used == 2 && slot.pipe_id.load(Ordering::Acquire) == pipe_id {
            return SlotSearch::Armed(index);
        }
    }
    if busy {
        SlotSearch::Busy
    } else {
        SlotSearch::Missing
    }
}

fn load_used(slot: &FasyncSlot, ordering: Ordering) -> u32 {
    #[cfg(test)]
    USED_SLOT_LOADS.fetch_add(1, Ordering::Relaxed);
    slot.used.load(ordering)
}

/// Cheap pre-check for the write-path hook: is ANY fd armed for signal-driven
/// I/O anywhere? Lets the hot pipe/socket write path skip its per-write inode
/// `fstat` when no fasync registration exists (the overwhelmingly common case).
/// This is exactly one shared counter load after the table-pointer load; it
/// does not touch any of the 256 slots.
#[inline]
pub fn any_armed() -> bool {
    table().is_some_and(|t| {
        #[cfg(test)]
        ARMED_COUNT_LOADS.fetch_add(1, Ordering::Relaxed);
        t.armed_count.load(Ordering::Acquire) != 0
    })
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
    loop {
        match find_armed(t, pipe_id) {
            SlotSearch::Armed(index) => {
                let slot = &t.slots[index];
                if slot
                    .used
                    .compare_exchange(2, 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    std::hint::spin_loop();
                    continue;
                }
                publish_slot(slot, pipe_id, owner);
                slot.used.store(2, Ordering::Release);
                return;
            }
            SlotSearch::Busy => {
                // Mutations are rare. Waiting for an in-flight claim/re-arm to
                // settle prevents two concurrent arms for one key from
                // consuming separate slots.
                std::hint::spin_loop();
                continue;
            }
            SlotSearch::Missing => {}
        }

        let Some(slot) = t
            .slots
            .iter()
            .find(|slot| load_used(slot, Ordering::Acquire) == 0)
        else {
            return;
        };
        if slot
            .used
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            std::hint::spin_loop();
            continue;
        }
        publish_slot(slot, pipe_id, owner);
        t.armed_count.fetch_add(1, Ordering::Release);
        slot.used.store(2, Ordering::Release);
        return;
    }
}

fn publish_slot(slot: &FasyncSlot, pipe_id: u64, owner: FasyncOwner) {
    let sequence = slot.sequence.fetch_add(1, Ordering::AcqRel);
    if sequence & 1 != 0 {
        carrick_fatal!(
            "signal::fasync",
            "fasync seqlock sequence {sequence} was odd during slot publication start for pipe_id={pipe_id} registration_id={}",
            owner.registration_id
        );
    }
    slot.pipe_id.store(pipe_id, Ordering::Relaxed);
    slot.registration_id
        .store(owner.registration_id, Ordering::Relaxed);
    slot.owner_pid
        .store(owner.owner_pid as u32, Ordering::Relaxed);
    slot.owner_type
        .store(owner.owner_type as u32, Ordering::Relaxed);
    slot.sig.store(owner.sig as u32, Ordering::Relaxed);
    slot.container_id
        .store(owner.container_id, Ordering::Relaxed);
    slot.target_id
        .store(owner.target_id as u32, Ordering::Relaxed);
    slot.target_generation
        .store(owner.target_generation, Ordering::Relaxed);
    slot.thread_id
        .store(owner.thread_id as u32, Ordering::Relaxed);
    slot.thread_generation
        .store(owner.thread_generation, Ordering::Relaxed);
    slot.sequence
        .store(sequence.wrapping_add(2), Ordering::Release);
}

/// Disarm signal-driven I/O for the exact open-file-description registration
/// on `pipe_id` (clearing `O_ASYNC`, or its final close). A no-op if another
/// description has since replaced the registration for the same pipe key.
pub fn disarm(pipe_id: u64, registration_id: u64) {
    let Some(t) = table() else {
        return;
    };
    loop {
        match find_armed(t, pipe_id) {
            SlotSearch::Armed(index) => {
                let slot = &t.slots[index];
                if slot
                    .used
                    .compare_exchange(2, 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    std::hint::spin_loop();
                    continue;
                }
                if slot.registration_id.load(Ordering::Acquire) != registration_id {
                    slot.used.store(2, Ordering::Release);
                    return;
                }
                let sequence = slot.sequence.fetch_add(1, Ordering::AcqRel);
                if sequence & 1 != 0 {
                    carrick_fatal!(
                        "signal::fasync",
                        "fasync seqlock sequence {sequence} was odd during slot disarm for pipe_id={pipe_id} registration_id={registration_id}"
                    );
                }
                slot.pipe_id.store(0, Ordering::Relaxed);
                slot.registration_id.store(0, Ordering::Relaxed);
                slot.sequence
                    .store(sequence.wrapping_add(2), Ordering::Release);
                slot.used.store(0, Ordering::Release);
                if t.armed_count.fetch_sub(1, Ordering::AcqRel) == 0 {
                    carrick_fatal!(
                        "signal::fasync",
                        "armed fasync registration count underflowed zero during disarm for pipe_id={pipe_id} registration_id={registration_id}"
                    );
                }
                return;
            }
            SlotSearch::Busy => std::hint::spin_loop(),
            SlotSearch::Missing => return,
        }
    }
}

/// Look up the FASYNC owner armed for `pipe_id`, if any. Called on the fd's
/// readiness edge (e.g. a guest write to a pipe whose read end is armed) to
/// decide whether — and to whom — to deliver the I/O signal.
pub fn lookup(pipe_id: u64) -> Option<FasyncOwner> {
    let t = table()?;
    loop {
        let slot = match find_armed(t, pipe_id) {
            SlotSearch::Armed(index) => &t.slots[index],
            SlotSearch::Busy => {
                std::hint::spin_loop();
                continue;
            }
            SlotSearch::Missing => return None,
        };
        let before = slot.sequence.load(Ordering::Acquire);
        if before & 1 != 0 {
            std::hint::spin_loop();
            continue;
        }
        let owner = FasyncOwner {
            registration_id: slot.registration_id.load(Ordering::Relaxed),
            owner_pid: slot.owner_pid.load(Ordering::Relaxed) as i32,
            owner_type: slot.owner_type.load(Ordering::Relaxed) as i32,
            sig: slot.sig.load(Ordering::Relaxed) as i32,
            container_id: slot.container_id.load(Ordering::Relaxed),
            target_id: slot.target_id.load(Ordering::Relaxed) as i32,
            target_generation: slot.target_generation.load(Ordering::Relaxed),
            thread_id: slot.thread_id.load(Ordering::Relaxed) as i32,
            thread_generation: slot.thread_generation.load(Ordering::Relaxed),
        };
        std::sync::atomic::fence(Ordering::Acquire);
        let after = slot.sequence.load(Ordering::Relaxed);
        if before == after
            && after & 1 == 0
            && load_used(slot, Ordering::Acquire) == 2
            && slot.pipe_id.load(Ordering::Acquire) == pipe_id
        {
            return Some(owner);
        }
        std::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn reset() {
        fasync_init();
        if let Some(t) = table() {
            t.armed_count.store(0, Ordering::Release);
            for slot in t.slots.iter() {
                slot.used.store(0, Ordering::Release);
                slot.pipe_id.store(0, Ordering::Relaxed);
                slot.registration_id.store(0, Ordering::Relaxed);
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
    fn unarmed_fast_path_reads_no_slots() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        USED_SLOT_LOADS.store(0, Ordering::Relaxed);
        ARMED_COUNT_LOADS.store(0, Ordering::Relaxed);
        TABLE_POINTER_LOADS.store(0, Ordering::Relaxed);

        assert!(!any_armed());
        assert_eq!(
            USED_SLOT_LOADS.load(Ordering::Relaxed),
            0,
            "the successful-write fast path must not scan all FASYNC slots",
        );
        assert_eq!(ARMED_COUNT_LOADS.load(Ordering::Relaxed), 1);
        assert_eq!(TABLE_POINTER_LOADS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn arm_then_lookup_round_trips() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        assert_eq!(lookup(42), None);
        arm(
            42,
            FasyncOwner {
                registration_id: 41,
                owner_pid: 1234,
                owner_type: 1,
                sig: 10,
                container_id: 91,
                target_id: 4_001,
                target_generation: 51,
                thread_id: 4_002,
                thread_generation: 52,
            },
        );
        assert_eq!(
            lookup(42),
            Some(FasyncOwner {
                registration_id: 41,
                owner_pid: 1234,
                owner_type: 1,
                sig: 10,
                container_id: 91,
                target_id: 4_001,
                target_generation: 51,
                thread_id: 4_002,
                thread_generation: 52,
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
                registration_id: 51,
                owner_pid: 100,
                owner_type: 1,
                sig: 0,
                container_id: 11,
                target_id: 100,
                target_generation: 1,
                thread_id: 0,
                thread_generation: 0,
            },
        );
        // F_SETOWN then F_SETSIG re-arm the SAME pipe id with new owner/sig.
        arm(
            1,
            FasyncOwner {
                registration_id: 52,
                owner_pid: 200,
                owner_type: 2,
                sig: 12,
                container_id: 12,
                target_id: 200,
                target_generation: 2,
                thread_id: 0,
                thread_generation: 0,
            },
        );
        assert_eq!(
            lookup(1),
            Some(FasyncOwner {
                registration_id: 52,
                owner_pid: 200,
                owner_type: 2,
                sig: 12,
                container_id: 12,
                target_id: 200,
                target_generation: 2,
                thread_id: 0,
                thread_generation: 0,
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
    fn concurrent_rearm_never_publishes_a_torn_owner() {
        use std::sync::atomic::AtomicBool;
        use std::sync::{Arc, Barrier};

        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let first = FasyncOwner {
            registration_id: 61,
            owner_pid: 101,
            owner_type: 1,
            sig: 10,
            container_id: 1_001,
            target_id: 2_001,
            target_generation: 3_001,
            thread_id: 4_001,
            thread_generation: 5_001,
        };
        let second = FasyncOwner {
            registration_id: 62,
            owner_pid: 102,
            owner_type: 2,
            sig: 12,
            container_id: 1_002,
            target_id: 2_002,
            target_generation: 3_002,
            thread_id: 4_002,
            thread_generation: 5_002,
        };
        arm(71, first);

        let start = Arc::new(Barrier::new(3));
        let done = Arc::new(AtomicBool::new(false));
        let torn = Arc::new(std::sync::Mutex::new(None));
        std::thread::scope(|scope| {
            let writer_start = Arc::clone(&start);
            let writer_done = Arc::clone(&done);
            scope.spawn(move || {
                writer_start.wait();
                for _ in 0..250_000 {
                    arm(71, second);
                    arm(71, first);
                }
                writer_done.store(true, Ordering::Release);
            });
            for _ in 0..2 {
                let start = Arc::clone(&start);
                let done = Arc::clone(&done);
                let torn = Arc::clone(&torn);
                scope.spawn(move || {
                    start.wait();
                    while !done.load(Ordering::Acquire) {
                        if let Some(observed) = lookup(71)
                            && observed != first
                            && observed != second
                        {
                            *torn.lock().unwrap_or_else(|e| e.into_inner()) = Some(observed);
                            done.store(true, Ordering::Release);
                            break;
                        }
                    }
                });
            }
        });
        assert_eq!(
            *torn.lock().unwrap_or_else(|e| e.into_inner()),
            None,
            "lookup must observe one complete owner publication",
        );
        reset();
    }

    #[test]
    fn disarm_clears_the_entry() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        arm(
            6,
            FasyncOwner {
                registration_id: 66,
                owner_pid: 9,
                owner_type: 1,
                sig: 29,
                container_id: 19,
                target_id: 9,
                target_generation: 3,
                thread_id: 0,
                thread_generation: 0,
            },
        );
        assert!(lookup(6).is_some());
        disarm(6, 67);
        assert!(lookup(6).is_some(), "another description cannot disarm it");
        disarm(6, 66);
        assert_eq!(lookup(6), None);
        // Disarming an unarmed key is a harmless no-op.
        disarm(6, 66);
        assert_eq!(lookup(6), None);
        reset();
    }
}
