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
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicPtr, AtomicU32, Ordering};

const XSIG_SLOTS: usize = 256;

#[repr(C)]
struct XSigSlot {
    used: AtomicU32, // 0 = free, 1 = claiming (payload not yet valid), 2 = ready, 3 = draining (one consumer claimed it)
    target_host_pid: AtomicI32,
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
    slots: [XSigSlot; XSIG_SLOTS],
}

static XSIG_RING: AtomicPtr<XSigRing> = AtomicPtr::new(std::ptr::null_mut());
static XSIG_DIRTY: AtomicBool = AtomicBool::new(false);

/// Allocate the shared xsignal ring once (`MAP_SHARED|MAP_ANON`, inherited
/// across fork). Idempotent: the post-fork `install_default_handlers` call sees
/// a non-null pointer (the child inherited the mapping) and is a no-op, so all
/// processes share ONE ring. Best-effort — a failed mmap leaves the ring absent
/// and senders fall back to a plain host `kill`.
pub fn xsig_init() {
    if !XSIG_RING.load(Ordering::Acquire).is_null() {
        return;
    }
    let size = std::mem::size_of::<XSigRing>();
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
    XSIG_RING.store(p.cast::<XSigRing>(), Ordering::Release);
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
) -> bool {
    let Some(ring) = xsig_ring() else {
        return false;
    };
    for slot in ring.slots.iter() {
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
            slot.signum.store(signum, Ordering::Relaxed);
            slot.code.store(code, Ordering::Relaxed);
            slot.sender_ns_pid.store(sender_ns_pid, Ordering::Relaxed);
            slot.sender_uid.store(sender_uid, Ordering::Relaxed);
            slot.value.store(value, Ordering::Relaxed);
            // Phase 2 — PUBLISH (1 -> 2). This single Release store is the sole
            // publish point: it carries all the Relaxed payload stores above, so
            // a consumer that observes `used == 2` with an Acquire load is
            // guaranteed to see the fully-written slot.
            slot.used.store(2, Ordering::Release); // publish: payload is now fully written
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
/// signum is deliverable given `block_mask` (bit `signum-1`). Used by the backend
/// waiter so a parked thread only wakes for a signal it can actually deliver.
///
/// RING-AUTHORITATIVE: this scans the `MAP_SHARED` ring directly and does NOT
/// consult the process-local `XSIG_DIRTY` hint. `XSIG_DIRTY` is set only by the
/// backend nudge handler ([`mark_xsig_dirty`]), and that host nudge is LOSABLE —
/// it can race the target's ppoll/wait entry (the classic kick-vs-enter window)
/// or land mid fork-reinit. Gating this recheck on `XSIG_DIRTY` therefore let an
/// already-enqueued cross-process signal stay permanently invisible to a parked
/// waiter (the Linux/KVM `do_sys_poll` wedge). Since the sender reliably writes
/// the shared ring before nudging, scanning the ring is the authoritative test;
/// `XSIG_DIRTY` survives only as a fast-path hint for [`xsig_has_pending`].
pub fn xsig_has_unblocked_for_self(block_mask: u64) -> bool {
    let Some(ring) = xsig_ring() else {
        return false;
    };
    let me = std::process::id() as i32;
    for slot in ring.slots.iter() {
        if slot.used.load(Ordering::Acquire) == 2
            && slot.target_host_pid.load(Ordering::Acquire) == me
            && signal_unblocked_by_mask(slot.signum.load(Ordering::Acquire), block_mask)
        {
            return true;
        }
    }
    false
}

/// Drain every entry targeting THIS process, clearing the dirty flag. Called in
/// DISPATCH context (may allocate / take locks). Returns
/// `(signum, code, sender_ns_pid, sender_uid, value)` per entry.
pub fn xsig_drain_for_self() -> Vec<(i32, i32, i32, u32, i64)> {
    XSIG_DIRTY.store(false, Ordering::SeqCst);
    let mut out = Vec::new();
    let Some(ring) = xsig_ring() else {
        return out;
    };
    let me = std::process::id() as i32;
    for slot in ring.slots.iter() {
        // Only consider published entries (`== 2`) targeting THIS process. The
        // target check happens BEFORE the claim so a thread never claims a slot
        // destined for another process; a `== 2` slot's target is immutable until
        // it is freed (a producer can only re-claim from state 0), so this read is
        // stable across the compare_exchange below.
        if slot.used.load(Ordering::Acquire) != 2 {
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
        slot.used.store(0, Ordering::Release); // free the slot for reuse
        out.push((signum, code, sp, su, v));
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
        // Free any slots left targeting OTHER pids by earlier tests.
        if let Some(ring) = xsig_ring() {
            for slot in ring.slots.iter() {
                slot.used.store(0, Ordering::Release);
            }
        }
        XSIG_DIRTY.store(false, Ordering::SeqCst);
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
    fn mark_dirty_makes_has_pending_true() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        // Enqueue alone does NOT set DIRTY — the nudge handler does. Simulate the
        // nudge with mark_xsig_dirty.
        assert!(!xsig_has_pending());
        assert!(xsig_enqueue(std::process::id() as i32, 10, 0, 42, 0, 0));
        assert!(!xsig_has_pending(), "enqueue alone must not set DIRTY");
        mark_xsig_dirty();
        assert!(xsig_has_pending());
        reset_ring();
    }

    #[test]
    fn has_unblocked_for_self_is_ring_authoritative_without_nudge() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        let me = std::process::id() as i32;
        // Lost-nudge case: the sender wrote the SHARED ring but the host nudge
        // that would set the process-local XSIG_DIRTY was dropped.
        assert!(xsig_enqueue(me, 10, 0, 42, 0, 0));
        assert!(!xsig_has_pending(), "no nudge => local DIRTY stays clear");
        // A parked waiter's recheck must STILL see the entry (ring-authoritative),
        // so it wakes despite the lost nudge — this is the anti-wedge invariant.
        assert!(
            xsig_has_unblocked_for_self(0),
            "recheck must scan the shared ring, not the losable DIRTY flag"
        );
        // A fully-blocking mask correctly hides it (not deliverable yet).
        assert!(!xsig_has_unblocked_for_self(u64::MAX));
        reset_ring();
    }

    #[test]
    fn drain_for_self_returns_entry_and_clears() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        let me = std::process::id() as i32;
        assert!(xsig_enqueue(me, 12, -1, 4242, 1000, 0x5eed));
        mark_xsig_dirty();
        assert!(xsig_has_pending());

        let drained = xsig_drain_for_self();
        assert_eq!(drained, vec![(12, -1, 4242, 1000, 0x5eed)]);
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
        assert!(xsig_enqueue(other, 17, 0, 99, 0, 0));
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
            0x1234_5678_9abc_def0_u64 as i64
        ));

        // The entire payload tuple survives the MAP_SHARED round-trip intact,
        // reinforcing that the single `used = 2` Release publishes ALL the
        // preceding payload fields (target/signum/sender_ns/sender_uid/value),
        // not just `value` — a torn read would corrupt one of these.
        let drained = xsig_drain_for_self();
        assert_eq!(
            drained,
            vec![(13, -1, 7777, 1234, 0x1234_5678_9abc_def0_u64 as i64)],
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
            assert!(xsig_enqueue(me, 20, 0, round as i32, 0, round as i64));

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
    fn ring_full_rejects_257th_enqueue() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_ring();
        let me = std::process::id() as i32;
        // Fill all 256 slots.
        for _ in 0..XSIG_SLOTS {
            assert!(xsig_enqueue(me, 10, 0, 1, 0, 0));
        }
        // The 257th must fail (ring full).
        assert!(!xsig_enqueue(me, 10, 0, 1, 0, 0));
        reset_ring();
    }
}
