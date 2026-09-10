//! Platform-NEUTRAL cross-process explicit-signal ring ("xsignal ring").
//!
//! Some guest cross-process signals cannot be delivered by a plain host `kill`
//! of a translated signum: a guest signal whose host number collides with one a
//! sibling carrick process treats specially (a host `kill` would take the host
//! default action), or a real-time signal (32..=64) for which macOS has no host
//! signal number. For these the sender writes an entry into a `MAP_SHARED` ring
//! (inherited across fork, so every carrick process shares ONE ring) and nudges
//! the target with a host signal NO guest signal maps to. The target's nudge
//! handler sets a dirty flag + wakes parked waiters; the runtime drains the ring
//! in DISPATCH context (where it can take locks) and publishes each signal to the
//! guest with the sender's ns-pid + sigval.
//!
//! This module owns the platform-NEUTRAL ring core: the slot/ring layout, the
//! `MAP_SHARED|MAP_ANON` allocation (identical on Linux and macOS), the dirty
//! flag, enqueue, drain, and the deliverable-for-self peek. The platform GLUE —
//! the nudge SIGNAL NUMBER, the `kill`-the-target nudge, and the per-backend
//! nudge handler wake — stays in each backend's `host_signal` module. The
//! backend nudge handler calls [`mark_xsig_dirty`] instead of touching the dirty
//! flag (now private to this module) directly.

use crate::signal_unblocked_by_mask;
use std::os::fd::IntoRawFd;
use std::sync::atomic::{
    AtomicBool, AtomicI32, AtomicI64, AtomicPtr, AtomicU32, AtomicU64, Ordering,
};

const XSIG_SLOTS: usize = 256;
const XSIG_OCCUPANCY_WORDS: usize = XSIG_SLOTS / 64;

#[cfg(test)]
static SLOT_LOAD_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[inline]
fn slot_used_load(slot: &XSigSlot, ordering: Ordering) -> u32 {
    #[cfg(test)]
    SLOT_LOAD_COUNT.fetch_add(1, Ordering::Relaxed);
    slot.used.load(ordering)
}

#[repr(C)]
struct XSigSlot {
    used: AtomicU32, // 0 = free, 1 = claiming (payload not yet valid), 2 = ready, 3 = draining (one consumer claimed it)
    target_host_pid: AtomicI32,
    /// Guest ns tid of a THREAD-DIRECTED cross-process send (tkill/tgkill/
    /// rt_tgsigqueueinfo); 0 = process-directed (kill/rt_sigqueueinfo/pidfd).
    /// Same-binary fork-shared ring: layout changes are compat-safe.
    target_ns_tid: AtomicI32,
    signum: AtomicI32, // Linux signum
    /// Linux `si_code` of the SEND (SI_USER for kill(2), SI_TKILL for
    /// tkill/tgkill, SI_QUEUE for rt_sigqueueinfo). Carried explicitly:
    /// guessing it from the signum at drain time stamped a plain `kill` of an
    /// RT signal as SI_QUEUE (LTP sigwaitinfo "struct siginfo mismatch").
    code: AtomicI32,
    sender_ns_pid: AtomicI32,
    sender_uid: AtomicU32,
    value: AtomicI64, // sigval (rt_sigqueueinfo); 0 otherwise
}

#[repr(C)]
struct XSigRing {
    /// Authoritative publication index: bit `i` is set (1) if and only if slot `i`
    /// is published and ready for delivery/checking. 256 slots = 4 AtomicU64 words.
    ///
    /// Checkers and drainers inspect these 4 words (which fit in a single 32-byte
    /// slice within the ring's first cache line) to determine occupancy in O(1)
    /// constant time without scanning all 256 payload slots.
    published: [AtomicU64; XSIG_OCCUPANCY_WORDS],
    slots: [XSigSlot; XSIG_SLOTS],
}

static XSIG_RING: AtomicPtr<XSigRing> = AtomicPtr::new(std::ptr::null_mut());
static XSIG_RING_FD: AtomicI32 = AtomicI32::new(-1);
static XSIG_DIRTY: AtomicBool = AtomicBool::new(false);
// `getpid(2)` is not a vDSO read on FreeBSD. Wait predicates inspect the ring
// before and after every guest futex park, so resolving the unchanged process
// identity there amplified a short Go scheduler sleep into two extra host
// syscalls. Refreshed explicitly at every fork-child/reexec boundary below.
static XSIG_SELF_HOST_PID: AtomicI32 = AtomicI32::new(0);

fn xsig_self_host_pid() -> i32 {
    let cached = XSIG_SELF_HOST_PID.load(Ordering::Acquire);
    if cached > 0 {
        cached
    } else {
        let pid = std::process::id() as i32;
        XSIG_SELF_HOST_PID.store(pid, Ordering::Release);
        pid
    }
}

/// Refresh the cached host-process identity after `fork(2)` or host reexec.
///
/// The xsignal mapping is inherited across fork, but its target identity is not.
/// Every backend fork-child reset must call this before inspecting or draining
/// the inherited shared ring.
pub fn xsig_refresh_self_host_pid() {
    XSIG_SELF_HOST_PID.store(std::process::id() as i32, Ordering::Release);
}

/// Allocate the shared xsignal ring once. A deleted temporary file backs the
/// mapping so native fork-children can carry its fd through a host self-reexec
/// and remap the same ring; ordinary fork descendants inherit both mapping and
/// fd. Best-effort — a failed allocation leaves the ring absent and senders
/// fall back to a plain host `kill`.
pub fn xsig_init() {
    xsig_refresh_self_host_pid();
    if !XSIG_RING.load(Ordering::Acquire).is_null() {
        return;
    }
    let size = std::mem::size_of::<XSigRing>();
    let Ok(file) = tempfile::tempfile() else {
        return;
    };
    if file.set_len(size as u64).is_err() {
        return;
    }
    let fd = file.into_raw_fd();
    if !xsig_adopt_reexec_fd(fd) {
        unsafe {
            libc::close(fd);
        }
    }
}

/// The private backing fd a native host self-reexec must preserve. The fd is
/// never a guest descriptor and remains owned by this module.
pub fn xsig_reexec_fd() -> Option<i32> {
    let fd = XSIG_RING_FD.load(Ordering::Acquire);
    (fd >= 0).then_some(fd)
}

/// Adopt a ring backing fd inherited through native host self-reexec.
///
/// The caller transfers process-lifetime ownership of `fd`. The fresh process
/// has no old ring mapping, while ordinary fork descendants hit the idempotent
/// already-mapped path and keep their inherited fd.
pub fn xsig_adopt_reexec_fd(fd: i32) -> bool {
    xsig_refresh_self_host_pid();
    if fd < 0 {
        return false;
    }
    if !XSIG_RING.load(Ordering::Acquire).is_null() {
        return XSIG_RING_FD.load(Ordering::Acquire) == fd;
    }
    let size = std::mem::size_of::<XSigRing>();
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } < 0 {
        return false;
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_size != size as libc::off_t {
        return false;
    }
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if mapping == libc::MAP_FAILED {
        return false;
    }
    match XSIG_RING.compare_exchange(
        std::ptr::null_mut(),
        mapping.cast::<XSigRing>(),
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {
            XSIG_RING_FD.store(fd, Ordering::Release);
            true
        }
        Err(_) => {
            unsafe {
                libc::munmap(mapping, size);
            }
            false
        }
    }
}

fn xsig_ring() -> Option<&'static XSigRing> {
    let p = XSIG_RING.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: a non-null XSIG_RING points at a live MAP_SHARED mapping of
        // exactly one XSigRing, allocated by xsig_init and never unmapped.
        Some(unsafe { &*p })
    }
}

/// Mark the ring dirty (a nudge arrived). Called by each backend's nudge handler
/// — which can no longer see the private dirty flag — in place of touching it
/// directly. Async-signal-safe (a single atomic store).
pub fn mark_xsig_dirty() {
    XSIG_DIRTY.store(true, Ordering::SeqCst);
}

/// Enqueue a cross-process signal for `target_host_pid` and return whether it
/// was queued (false = no ring or ring full → caller falls back / drops).
pub fn xsig_enqueue(
    target_host_pid: i32,
    signum: i32,
    code: i32,
    sender_ns_pid: i32,
    sender_uid: u32,
    value: i64,
    target_ns_tid: i32,
) -> bool {
    let Some(ring) = xsig_ring() else {
        return false;
    };
    for (slot_idx, slot) in ring.slots.iter().enumerate() {
        // Phase 1 — CLAIM the slot (0 -> 1). `used == 1` means "claimed but the
        // payload is NOT yet valid", so a concurrent cross-process consumer
        // gating on `== 2` will skip it until we publish below.
        if slot
            .used
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            slot.target_host_pid
                .store(target_host_pid, Ordering::Relaxed);
            slot.target_ns_tid.store(target_ns_tid, Ordering::Relaxed);
            slot.signum.store(signum, Ordering::Relaxed);
            slot.code.store(code, Ordering::Relaxed);
            slot.sender_ns_pid.store(sender_ns_pid, Ordering::Relaxed);
            slot.sender_uid.store(sender_uid, Ordering::Relaxed);
            slot.value.store(value, Ordering::Relaxed);

            // Phase 2 — PUBLISH (1 -> 2). This single Release store is the
            // payload publish point: it carries all the Relaxed payload stores above.
            slot.used.store(2, Ordering::Release);

            // Phase 3 — AUTHORITATIVE PUBLICATION INDEX UPDATE.
            // Mark the slot as published in the shared publication bitmap.
            // The Release ordering ensures that any reader observing this bit with
            // Acquire ordering is guaranteed to observe `used == 2` and the full
            // payload. Because this store completes before `xsig_enqueue` returns,
            // no published signal can be hidden from any subsequent recheck.
            let word_idx = slot_idx / 64;
            let bit_idx = slot_idx % 64;
            let bit_mask = 1u64 << bit_idx;
            ring.published[word_idx].fetch_or(bit_mask, Ordering::Release);

            return true;
        }
    }
    false
}

/// Did a nudge arrive since the last drain? Folded into `has_pending_for` so the
/// runtime delivers, and into the waiter so a parked thread wakes.
pub fn xsig_has_pending() -> bool {
    XSIG_DIRTY.load(Ordering::SeqCst)
}

/// Whether the SHARED ring holds at least one entry targeting THIS process whose
/// signum is deliverable given `block_mask`. Used by the backend waiter so a
/// parked thread only wakes for a signal it can actually deliver.
///
/// RING-AUTHORITATIVE: this inspects the `MAP_SHARED` publication index directly
/// and does NOT consult the process-local `XSIG_DIRTY` hint. `XSIG_DIRTY` is set
/// only by the backend nudge handler ([`mark_xsig_dirty`]), and that host nudge
/// is LOSABLE — it can race the target's ppoll/wait entry (the classic
/// kick-vs-enter window) or land mid fork-reinit. Gating this recheck on
/// `XSIG_DIRTY` therefore let an already-enqueued cross-process signal stay
/// permanently invisible to a parked waiter (the Linux/KVM `do_sys_poll` wedge).
///
/// Thanks to the authoritative publication bitmap in the ring header, empty occupancy
/// is verified in O(1) bounded metadata inspection without scanning all 256 payload
/// slots; when nonempty, only occupied slots are visited.
pub fn xsig_has_unblocked_for_self(block_mask: carrick_abi::SigBlockMask) -> bool {
    let Some(ring) = xsig_ring() else {
        return false;
    };
    let me = xsig_self_host_pid();
    for (word_idx, word_atomic) in ring.published.iter().enumerate() {
        let mut mask = word_atomic.load(Ordering::Acquire);
        while mask != 0 {
            let bit_idx = mask.trailing_zeros() as usize;
            let slot_idx = word_idx * 64 + bit_idx;
            mask &= mask - 1; // clear lowest set bit

            let slot = &ring.slots[slot_idx];
            if slot_used_load(slot, Ordering::Acquire) == 2
                && slot.target_host_pid.load(Ordering::Acquire) == me
                && signal_unblocked_by_mask(slot.signum.load(Ordering::Acquire), block_mask)
            {
                return true;
            }
        }
    }
    false
}

/// Drain every entry targeting THIS process, clearing the dirty flag. Called in
/// DISPATCH context (may allocate / take locks). Returns
/// `(signum, code, sender_ns_pid, sender_uid, value, target_ns_tid)` per entry.
pub fn xsig_drain_for_self() -> Vec<(i32, i32, i32, u32, i64, i32)> {
    XSIG_DIRTY.store(false, Ordering::SeqCst);
    let mut out = Vec::new();
    let Some(ring) = xsig_ring() else {
        return out;
    };
    let me = xsig_self_host_pid();
    for (word_idx, word_atomic) in ring.published.iter().enumerate() {
        let mut mask = word_atomic.load(Ordering::Acquire);
        while mask != 0 {
            let bit_idx = mask.trailing_zeros() as usize;
            let bit_mask = 1u64 << bit_idx;
            let slot_idx = word_idx * 64 + bit_idx;
            mask &= mask - 1; // advance to next occupied slot

            let slot = &ring.slots[slot_idx];
            // Only consider published entries (`== 2`) targeting THIS process. The
            // target check happens BEFORE the claim so a thread never claims a slot
            // destined for another process; a `== 2` slot's target is immutable until
            // it is freed (a producer can only re-claim from state 0), so this read is
            // stable across the compare_exchange below.
            if slot_used_load(slot, Ordering::Acquire) != 2 {
                continue;
            }
            if slot.target_host_pid.load(Ordering::Acquire) != me {
                continue;
            }
            // CLAIM the slot for draining (2 -> 3), mirroring the producer's
            // 0 -> 1 claim. Exactly one of several concurrent sibling-thread drainers
            // wins the compare_exchange; the losers see it fail and skip the slot, so
            // a process-directed signal is delivered EXACTLY ONCE rather than once per
            // racing drainer. State 3 is disjoint from the producer (which only ever
            // touches 0/1/2), so claim and publish never collide.
            if slot
                .used
                .compare_exchange(2, 3, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            let signum = slot.signum.load(Ordering::Relaxed);
            let code = slot.code.load(Ordering::Relaxed);
            let sp = slot.sender_ns_pid.load(Ordering::Relaxed);
            let su = slot.sender_uid.load(Ordering::Relaxed);
            let v = slot.value.load(Ordering::Acquire);
            let tt = slot.target_ns_tid.load(Ordering::Relaxed);

            // RETIREMENT PROTOCOL:
            // 1. Clear the publication index bit while slot is STILL in state 3 (DRAINING).
            //    Because the slot is in state 3, no producer can claim it (producers require state 0).
            //    This guarantees that clearing the bit strictly precedes any future occupant's
            //    bit setting on slot reuse, preventing the clear from ever erasing a later occupant.
            word_atomic.fetch_and(!bit_mask, Ordering::AcqRel);

            // 2. Free the slot back to state 0 for reuse.
            slot.used.store(0, Ordering::Release);

            out.push((signum, code, sp, su, v, tt));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ring is process-global, so these tests would race if run in parallel.
    /// Serialise them and reset the ring at the top of each so they are
    /// order-independent.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Drain everything targeting THIS pid AND every other slot, then clear the
    /// dirty flag, so each test starts from an empty, clean ring.
    fn reset_ring() {
        xsig_init();
        // Drain entries for self.
        let _ = xsig_drain_for_self();
        // Free any slots left targeting OTHER pids by earlier tests and clear
        // the publication bitmap words.
        if let Some(ring) = xsig_ring() {
            for slot in ring.slots.iter() {
                slot.used.store(0, Ordering::Release);
            }
            for word in ring.published.iter() {
                word.store(0, Ordering::Release);
            }
        }
        XSIG_DIRTY.store(false, Ordering::SeqCst);
    }

    #[test]
    fn self_pid_cache_refreshes_at_process_boundaries() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        XSIG_SELF_HOST_PID.store(1, Ordering::Release);
        assert_eq!(xsig_self_host_pid(), 1);
        xsig_refresh_self_host_pid();
        assert_eq!(xsig_self_host_pid(), std::process::id() as i32);
    }

    #[test]
    fn xsig_init_is_idempotent() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        xsig_init();
        let first = XSIG_RING.load(Ordering::Acquire);
        assert!(!first.is_null());
        xsig_init();
        let second = XSIG_RING.load(Ordering::Acquire);
        assert_eq!(first, second, "a second xsig_init must not re-map the ring");
    }

    #[test]
    fn reexec_backing_fd_maps_the_same_shared_ring() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        let fd = xsig_reexec_fd().expect("xsignal ring backing fd");
        let size = std::mem::size_of::<XSigRing>();
        let remapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert_ne!(remapped, libc::MAP_FAILED);

        let me = std::process::id() as i32;
        assert!(xsig_enqueue(me, 15, 0, 42, 0, 0, 0));
        let remapped_ring = unsafe { &*remapped.cast::<XSigRing>() };
        assert_ne!(remapped_ring.published[0].load(Ordering::Acquire), 0);
        assert!(remapped_ring.slots.iter().any(|slot| {
            slot.used.load(Ordering::Acquire) == 2
                && slot.target_host_pid.load(Ordering::Acquire) == me
                && slot.signum.load(Ordering::Acquire) == 15
        }));

        unsafe {
            libc::munmap(remapped, size);
        }
        let _ = xsig_drain_for_self();
    }

    #[test]
    fn mark_dirty_makes_has_pending_true() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        // Enqueue alone does NOT set DIRTY — the nudge handler does. Simulate the
        // nudge with mark_xsig_dirty.
        assert!(!xsig_has_pending());
        assert!(xsig_enqueue(std::process::id() as i32, 10, 0, 42, 0, 0, 0));
        assert!(!xsig_has_pending(), "enqueue alone must not set DIRTY");
        mark_xsig_dirty();
        assert!(xsig_has_pending());
        reset_ring();
    }

    #[test]
    fn empty_ring_rechecks_reuse_cached_self_pid() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        for _ in 0..10_000 {
            assert!(!xsig_has_unblocked_for_self(
                carrick_abi::SigBlockMask::NONE
            ));
        }
    }

    #[test]
    fn empty_check_reads_no_payload_slots() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        SLOT_LOAD_COUNT.store(0, Ordering::Relaxed);

        assert!(!xsig_has_unblocked_for_self(
            carrick_abi::SigBlockMask::NONE
        ));
        assert_eq!(
            SLOT_LOAD_COUNT.load(Ordering::Relaxed),
            0,
            "empty ring check must examine constant metadata and read 0 payload slots"
        );
    }

    #[test]
    fn single_occupied_check_reads_only_occupied_slot() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        let me = std::process::id() as i32;
        // Enqueue 1 signal into the ring.
        assert!(xsig_enqueue(me, 10, 0, 1, 0, 0, 0));

        SLOT_LOAD_COUNT.store(0, Ordering::Relaxed);
        assert!(xsig_has_unblocked_for_self(carrick_abi::SigBlockMask::NONE));
        let loads = SLOT_LOAD_COUNT.load(Ordering::Relaxed);
        assert_eq!(
            loads, 1,
            "nonempty check must visit only occupied slots (expected 1, got {})",
            loads
        );
        reset_ring();
    }

    #[test]
    fn has_unblocked_for_self_is_ring_authoritative_without_nudge() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        let me = std::process::id() as i32;
        // Lost-nudge case: the sender wrote the SHARED ring but the host nudge
        // that would set the process-local XSIG_DIRTY was dropped.
        assert!(xsig_enqueue(me, 10, 0, 42, 0, 0, 0));
        assert!(!xsig_has_pending(), "no nudge => local DIRTY stays clear");
        // A parked waiter's recheck must STILL see the entry (ring-authoritative),
        // so it wakes despite the lost nudge — this is the anti-wedge invariant.
        assert!(
            xsig_has_unblocked_for_self(carrick_abi::SigBlockMask::NONE),
            "recheck must scan the shared ring, not the losable DIRTY flag"
        );
        // A fully-blocking mask correctly hides it (not deliverable yet).
        assert!(!xsig_has_unblocked_for_self(
            carrick_abi::SigBlockMask::blocking_all_of(carrick_abi::SigSet::EMPTY.complement())
        ));
        reset_ring();
    }

    #[test]
    fn masked_to_unmasked_visibility_without_new_nudge() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        let me = std::process::id() as i32;
        // Enqueue standard catchable signal SIGUSR1 (10).
        assert!(xsig_enqueue(me, 10, 0, 42, 0, 0, 0));

        // When masked, has_unblocked_for_self returns false.
        let blocking_usr1 =
            carrick_abi::SigBlockMask::blocking_all_of(carrick_abi::SigSet::EMPTY.with(10));
        assert!(!xsig_has_unblocked_for_self(blocking_usr1));

        // When mask unblocks it, it is immediately visible without any new enqueue or nudge.
        assert!(xsig_has_unblocked_for_self(carrick_abi::SigBlockMask::NONE));

        // Uncatchable signals (SIGKILL=9, SIGSTOP=19) are ALWAYS visible even under complete block mask.
        let all_blocked =
            carrick_abi::SigBlockMask::blocking_all_of(carrick_abi::SigSet::EMPTY.complement());
        assert!(xsig_enqueue(me, 9, 0, 42, 0, 0, 0));
        assert!(xsig_has_unblocked_for_self(all_blocked));

        reset_ring();
    }

    #[test]
    fn mixed_destinations_isolation_and_drain() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        let me = std::process::id() as i32;
        let other_a = me + 100;
        let other_b = me + 200;

        assert!(xsig_enqueue(other_a, 10, 0, 101, 0, 0, 0));
        assert!(xsig_enqueue(other_b, 12, 0, 102, 0, 0, 0));

        // Ring is nonempty, but nothing targets `me`.
        assert!(!xsig_has_unblocked_for_self(
            carrick_abi::SigBlockMask::NONE
        ));
        assert!(xsig_drain_for_self().is_empty());

        // Enqueue for `me`.
        assert!(xsig_enqueue(me, 15, 0, 103, 0, 0, 0));
        assert!(xsig_has_unblocked_for_self(carrick_abi::SigBlockMask::NONE));

        // Drain for `me` drains ONLY the signal for `me`.
        let drained = xsig_drain_for_self();
        assert_eq!(drained, vec![(15, 0, 103, 0, 0, 0)]);

        // Other PIDs' signals remain published and undamaged.
        assert!(!xsig_has_unblocked_for_self(
            carrick_abi::SigBlockMask::NONE
        ));
        let ring = xsig_ring().expect("ring");
        let published_count: u32 = ring
            .published
            .iter()
            .map(|w| w.load(Ordering::Acquire).count_ones())
            .sum();
        assert_eq!(
            published_count, 2,
            "other PIDs' signals must remain in publication index"
        );

        reset_ring();
    }

    #[test]
    fn slot_retirement_reuse_preserves_publication_index() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        let me = std::process::id() as i32;

        for round in 0..500 {
            // Fill 4 slots
            for i in 0..4 {
                assert!(xsig_enqueue(
                    me,
                    10 + i,
                    0,
                    round,
                    0,
                    round as i64 * 10 + i as i64,
                    0,
                ));
            }
            assert!(xsig_has_unblocked_for_self(carrick_abi::SigBlockMask::NONE));

            let drained = xsig_drain_for_self();
            assert_eq!(drained.len(), 4);
            for (i, item) in drained.iter().enumerate() {
                assert_eq!(item.0, 10 + i as i32);
                assert_eq!(item.2, round);
                assert_eq!(item.4, round as i64 * 10 + i as i64);
            }

            // Ring must be completely retired and empty.
            assert!(!xsig_has_unblocked_for_self(
                carrick_abi::SigBlockMask::NONE
            ));
            SLOT_LOAD_COUNT.store(0, Ordering::Relaxed);
            assert!(!xsig_has_unblocked_for_self(
                carrick_abi::SigBlockMask::NONE
            ));
            assert_eq!(SLOT_LOAD_COUNT.load(Ordering::Relaxed), 0);
        }
        reset_ring();
    }

    #[test]
    fn drain_for_self_returns_entry_and_clears() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        let me = std::process::id() as i32;
        assert!(xsig_enqueue(me, 12, -1, 4242, 1000, 0x5eed, 0));
        mark_xsig_dirty();
        assert!(xsig_has_pending());

        let drained = xsig_drain_for_self();
        assert_eq!(drained, vec![(12, -1, 4242, 1000, 0x5eed, 0)]);
        // Drain clears DIRTY.
        assert!(!xsig_has_pending());
        // The slot is freed: a second drain returns empty.
        assert!(xsig_drain_for_self().is_empty());
        reset_ring();
    }

    #[test]
    fn drain_for_self_skips_other_pid() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        let other = std::process::id() as i32 + 1;
        assert!(xsig_enqueue(other, 17, 0, 99, 0, 0, 0));
        mark_xsig_dirty();

        // The entry targets a DIFFERENT pid → not drained for self.
        assert!(xsig_drain_for_self().is_empty());
        // It is still present for the real target.
        let mut found = false;
        if let Some(ring) = xsig_ring() {
            for slot in ring.slots.iter() {
                if slot.used.load(Ordering::Acquire) == 2
                    && slot.target_host_pid.load(Ordering::Acquire) == other
                {
                    found = true;
                }
            }
        }
        assert!(found, "an other-pid entry must stay for its real target");
        reset_ring();
    }

    #[test]
    fn two_phase_publish_slot_reaches_ready() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        let me = std::process::id() as i32;

        // A successful enqueue must drive the slot all the way to the `used == 2`
        // (ready) state — the drain gate is `== 2`, so a slot stuck at `1`
        // (claimed-but-unpublished) would NOT be returned. Getting the entry back
        // proves the publish store landed and the consumer gate matches.
        assert!(xsig_enqueue(
            me,
            13,
            -1,
            7777,
            1234,
            0x1234_5678_9abc_def0_u64 as i64,
            0
        ));

        // The entire payload tuple survives the MAP_SHARED round-trip intact,
        // reinforcing that the single `used = 2` Release publishes ALL the
        // preceding payload fields (target/signum/sender_ns/sender_uid/value),
        // not just `value` — a torn read would corrupt one of these.
        let drained = xsig_drain_for_self();
        assert_eq!(
            drained,
            vec![(13, -1, 7777, 1234, 0x1234_5678_9abc_def0_u64 as i64, 0)],
            "published payload must round-trip byte-for-byte"
        );

        // The slot was freed back to 0 by the drain, so a second drain is empty
        // (no stale ready slot lingers at `used == 2`).
        assert!(xsig_drain_for_self().is_empty());
        reset_ring();
    }

    #[test]
    fn concurrent_drain_delivers_each_entry_exactly_once() {
        use std::sync::{Arc, Barrier};

        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        let me = std::process::id() as i32;

        // Sibling vCPU threads of one guest process all reach their signal
        // safe-point and call xsig_drain_for_self concurrently (the nudge handler
        // broadcasts a wake to every parked thread). A process-directed entry must
        // be delivered to EXACTLY ONE of them. With an unguarded load(==2)+store(0)
        // drain, two threads can both observe the single ready slot, both read the
        // payload, and both return it — a duplicate (extra) delivery.
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .clamp(4, 16);
        const ROUNDS: usize = 1000;

        let mut total_deliveries = 0usize;
        for round in 0..ROUNDS {
            // Publish exactly ONE entry targeting this process.
            assert!(xsig_enqueue(me, 20, 0, round as i32, 0, round as i64, 0));

            // Release all drainers together so they contend on the single slot.
            let barrier = Arc::new(Barrier::new(threads));
            let handles: Vec<_> = (0..threads)
                .map(|_| {
                    let b = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        b.wait();
                        xsig_drain_for_self().len()
                    })
                })
                .collect();
            let delivered: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
            total_deliveries += delivered;

            reset_ring();
        }

        assert_eq!(
            total_deliveries,
            ROUNDS,
            "each published entry must be drained exactly once across all sibling \
             threads; {} extra deliveries reveal the load-then-free drain race",
            total_deliveries.saturating_sub(ROUNDS),
        );
        reset_ring();
    }

    #[test]
    fn adversarial_multithreaded_enqueue_drain_stress() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize};

        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();

        const PRODUCERS: usize = 4;
        const CONSUMERS: usize = 4;
        const MESSAGES_PER_PRODUCER: usize = 2000;
        const TOTAL_MESSAGES: usize = PRODUCERS * MESSAGES_PER_PRODUCER;

        let me = std::process::id() as i32;
        let done = Arc::new(AtomicBool::new(false));
        let total_received = Arc::new(AtomicUsize::new(0));

        std::thread::scope(|s| {
            // Producer threads
            for p in 0..PRODUCERS {
                s.spawn(move || {
                    for seq in 0..MESSAGES_PER_PRODUCER {
                        while !xsig_enqueue(
                            me,
                            10,
                            0,
                            p as i32,
                            0,
                            (p * MESSAGES_PER_PRODUCER + seq) as i64,
                            0,
                        ) {
                            std::thread::yield_now();
                        }
                    }
                });
            }

            // Consumer threads
            for _ in 0..CONSUMERS {
                let done = Arc::clone(&done);
                let total_received = Arc::clone(&total_received);
                s.spawn(move || {
                    while !done.load(Ordering::Acquire) {
                        let batch = xsig_drain_for_self();
                        if !batch.is_empty() {
                            total_received.fetch_add(batch.len(), Ordering::Relaxed);
                        } else {
                            std::thread::yield_now();
                        }
                    }
                    // Final drain to ensure no messages left behind
                    let batch = xsig_drain_for_self();
                    if !batch.is_empty() {
                        total_received.fetch_add(batch.len(), Ordering::Relaxed);
                    }
                });
            }

            while total_received.load(Ordering::Relaxed) < TOTAL_MESSAGES {
                std::thread::yield_now();
            }
            done.store(true, Ordering::Release);
        });

        assert_eq!(
            total_received.load(Ordering::Relaxed),
            TOTAL_MESSAGES,
            "all published messages across concurrent producers must be delivered exactly once"
        );
        assert!(!xsig_has_unblocked_for_self(
            carrick_abi::SigBlockMask::NONE
        ));
        reset_ring();
    }

    #[test]
    fn ring_full_rejects_257th_enqueue() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        let me = std::process::id() as i32;
        // Fill all 256 slots.
        for _ in 0..XSIG_SLOTS {
            assert!(xsig_enqueue(me, 10, 0, 1, 0, 0, 0));
        }
        // The 257th must fail (ring full).
        assert!(!xsig_enqueue(me, 10, 0, 1, 0, 0, 0));
        reset_ring();
    }

    #[test]
    fn enqueue_carries_target_tid_through_drain() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        assert!(xsig_enqueue(
            std::process::id() as i32,
            10,
            0,
            7,
            1000,
            0,
            4321
        ));
        let drained = xsig_drain_for_self();
        assert_eq!(drained.len(), 1);
        let (_sig, _code, _ns, _uid, _val, target_ns_tid) = drained[0];
        assert_eq!(target_ns_tid, 4321);
        reset_ring();
    }

    #[test]
    fn cross_process_fork_shared_ring_delivery() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            // Child process
            xsig_refresh_self_host_pid();
            let mut drained = Vec::new();
            for _ in 0..10_000 {
                if xsig_has_unblocked_for_self(carrick_abi::SigBlockMask::NONE) {
                    drained = xsig_drain_for_self();
                    if !drained.is_empty() {
                        break;
                    }
                }
                std::thread::yield_now();
            }
            let success = drained.len() == 1 && drained[0].0 == 12 && drained[0].2 == 9999;
            unsafe {
                libc::_exit(if success { 0 } else { 1 });
            }
        } else {
            // Parent process
            // Enqueue signal targeting child
            assert!(xsig_enqueue(child, 12, 0, 9999, 1000, 0xcafe, 0));
            let mut status: libc::c_int = 0;
            let ret = unsafe { libc::waitpid(child, &mut status, 0) };
            assert_eq!(ret, child);
            assert!(libc::WIFEXITED(status), "child did not exit normally");
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "child failed xsignal verification"
            );
            reset_ring();
        }
    }
}
