//! Cross-process eventfd counter slab.
//!
//! An eventfd's counter must be FORK-COHERENT: LTP eventfd2_03 forks two
//! children that ping-pong EFD_SEMAPHORE posts/waits across process
//! boundaries, and carrick forks real host processes for `clone(2)` — an
//! in-process `Mutex<u64>` silently diverges after the first fork (the
//! AGENTS.md fork-coherence rule). The counter therefore lives in a
//! `MAP_SHARED | MAP_ANON` slab of `AtomicU64` slots mapped once per process
//! TREE (lazily, on first eventfd creation) and inherited across `fork(2)` —
//! HOST memory, so it is coherent on every backend, including bhyve, whose
//! GUEST RAM is per-VM vmm(4) segments that a fork must copy.
//!
//! Slots are BUMP-ALLOCATED and never reused: a cross-process free would need
//! a distributed refcount whose miscount (a SIGKILLed holder, a `_exit` path
//! that skips Drop) silently hands one live eventfd's slot to another — a
//! corruption class strictly worse than the leak class. The slab holds 64Ki
//! slots (512 KiB, zero-filled lazily); a guest tree that outlives 64Ki
//! eventfd CREATIONS gets a clean ENOMEM from eventfd2(2). Slot reclamation
//! belongs to the durable-memory backing-object work.
//!
//! Lazy init is fork-topology-correct: whichever process first creates an
//! eventfd maps the slab, and every DESCENDANT inherits that mapping, so any
//! process that can inherit an eventfd fd necessarily shares the slab that
//! backs it. Two disjoint branches may map two slabs, but no eventfd can span
//! them.

use std::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

const SLOTS: usize = 65536;

#[repr(C)]
struct Slab {
    /// Bump cursor (slot 0 is a valid allocation; the cursor counts CLAIMED
    /// slots).
    next: AtomicUsize,
    counters: [AtomicU64; SLOTS],
}

static SLAB: AtomicPtr<Slab> = AtomicPtr::new(std::ptr::null_mut());

fn slab() -> Option<&'static Slab> {
    let p = SLAB.load(Ordering::Acquire);
    if !p.is_null() {
        // SAFETY: a non-null SLAB points at a live MAP_SHARED mapping of
        // exactly one Slab, mapped below and never unmapped.
        return Some(unsafe { &*p });
    }
    let size = std::mem::size_of::<Slab>();
    // SAFETY: fresh anonymous shared mapping of `size` bytes; zero-filled by
    // the kernel, so `next` is 0 and every counter is 0 (both valid).
    let mapped = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return None;
    }
    let fresh = mapped.cast::<Slab>();
    match SLAB.compare_exchange(
        std::ptr::null_mut(),
        fresh,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        // SAFETY: we just published `fresh`; same invariant as above.
        Ok(_) => Some(unsafe { &*fresh }),
        Err(winner) => {
            // A sibling thread won the race; discard ours.
            // SAFETY: `mapped` is the still-private mapping created above.
            unsafe { libc::munmap(mapped, size) };
            // SAFETY: `winner` was published by the winning thread.
            Some(unsafe { &*winner })
        }
    }
}

/// Claim a fresh slot initialized to `initval`. `None` = the slab could not be
/// mapped or is exhausted (caller surfaces ENOMEM).
pub(crate) fn alloc(initval: u64) -> Option<usize> {
    let slab = slab()?;
    let idx = slab.next.fetch_add(1, Ordering::AcqRel);
    if idx >= SLOTS {
        // Saturate so the cursor cannot wrap after ~usize::MAX failures.
        slab.next.store(SLOTS, Ordering::Release);
        return None;
    }
    slab.counters[idx].store(initval, Ordering::Release);
    Some(idx)
}

/// The shared counter behind slot `idx`. Panics never: `idx` comes only from
/// [`alloc`] in this process tree, whose slab mapping is inherited.
pub(crate) fn counter(idx: usize) -> Option<&'static AtomicU64> {
    slab().and_then(|s| s.counters.get(idx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn alloc_initializes_and_counters_are_shared_by_index() {
        let a = alloc(7).expect("slab alloc");
        let b = alloc(0).expect("slab alloc");
        assert_ne!(a, b);
        assert_eq!(counter(a).expect("live slot").load(Ordering::SeqCst), 7);
        assert_eq!(counter(b).expect("live slot").load(Ordering::SeqCst), 0);
        counter(b).expect("live slot").store(41, Ordering::SeqCst);
        assert_eq!(counter(b).expect("live slot").load(Ordering::SeqCst), 41);
    }
}
