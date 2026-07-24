//! FreeBSD-only cross-process shared-futex primitive for the native (DSR)
//! backend.
//!
//! Moved verbatim from `carrick-runtime/src/native_freebsd.rs` as the Phase-3
//! futex seam: the FreeBSD half of the "shared code names the operation, not
//! the syscall" contract. The Darwin lane already names its shared futex
//! behind `carrick_hal::PlatformFutex` (backed by `carrick-host::ulock`, which
//! carries its OWN `__ulock` waiter table); this module is the FreeBSD peer,
//! naming the operation behind `_umtx_op(2)` + the fork-shared waiter-count
//! table. The two lanes' waiter-table workarounds stay lane-side by design:
//! each reconstructs a woken-count / atomic-requeue its host primitive does not
//! natively report, and the accounting is specific to that primitive's quirk.
//!
//! `native_freebsd.rs`'s x86 run loop calls [`shared_wait`], [`shared_wake`],
//! and [`shared_requeue`] for the `SharedFutexWait{,v}` / `SharedFutexWake` /
//! `SharedFutexRequeue` dispatch outcomes; [`init_shared_waiter_table`] runs
//! pre-fork so every descendant maps the same shared table.

use std::sync::atomic::Ordering;

// Cross-process shared-futex WAITER COUNT table. FreeBSD's native
// `_umtx_op(UMTX_OP_WAKE)` returns 0, not the number of threads it woke; Linux
// `FUTEX_WAKE` returns that count (FreeBSD's OWN linuxulator does too, via
// `umtxq_signal_mask` returning the woken count into `td_retval[0]` — but that
// path is only reachable through the Linux-ABI sysent, and it keys futexes as
// `TYPE_FUTEX` where native `_umtx_op(UMTX_OP_WAIT_UINT)` uses `TYPE_SIMPLE_WAIT`,
// so a native binary cannot borrow it). We reconstruct the count the same way
// the kernel does — by tracking how many waiters are parked on each key — in a
// small MAP_SHARED table inherited across `fork` (identity: the guest futex word
// is a host VA identical in every process). Each shared waiter increments its
// word's slot before parking and decrements after; a WAKE returns
// `min(requested, parked)`. This unblocks `futexwakecount` (asserts the woken
// count is >= N) and `futexsharedalias` (asserts a single wake returns exactly 1).
#[repr(C)]
struct WaiterSlot {
    /// Stable shared-backing waiter key for this slot, or 0 when free. Unlike
    /// the host VA, this remains identical when the same file offset is mapped
    /// at a different address after exec.
    key: std::sync::atomic::AtomicU64,
    /// Live parked-waiter count on `key`.
    count: std::sync::atomic::AtomicU32,
    /// Requeue assignments consumed by waiters physically released from this
    /// source bucket. Direct-wake assignments are consumed before moves.
    requeue_direct: std::sync::atomic::AtomicU32,
    requeue_moved: std::sync::atomic::AtomicU32,
    requeue_to_key: std::sync::atomic::AtomicU64,
    requeue_to_generation: std::sync::atomic::AtomicU32,
    /// Requeued waiters park on this internal generation rather than re-checking
    /// the destination guest word. Credits make wake-before-park lossless.
    logical_generation: std::sync::atomic::AtomicU32,
    logical_requeued: std::sync::atomic::AtomicU32,
    logical_wake: std::sync::atomic::AtomicU32,
}
const WAITER_SLOTS: usize = 1024;
static SHARED_WAITER_TABLE: std::sync::atomic::AtomicPtr<WaiterSlot> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

/// Allocate the fork-shared waiter-count table (idempotent). MUST run pre-fork so
/// every descendant maps the SAME physical pages (MAP_SHARED|MAP_ANON survives
/// `fork` as genuinely shared).
pub fn init_shared_waiter_table() {
    if !SHARED_WAITER_TABLE.load(Ordering::Acquire).is_null() {
        return;
    }
    let bytes = WAITER_SLOTS * std::mem::size_of::<WaiterSlot>();
    // SAFETY: a fresh anonymous shared mapping; zero-filled (key 0 = free).
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return;
    }
    // First writer wins; a loser unmaps its spare (another thread already
    // published, exceedingly unlikely under RUN_LOCK but kept correct).
    if SHARED_WAITER_TABLE
        .compare_exchange(
            std::ptr::null_mut(),
            p as *mut WaiterSlot,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        // SAFETY: `p` is our own fresh mapping; nobody else references it.
        unsafe { libc::munmap(p, bytes) };
    }
}

/// The `WaiterSlot` for a stable shared-backing `waiter_key`, claiming a free
/// slot on first use (open-addressed, linear probe). `None` if the table is
/// unmapped or full.
fn shared_waiter_slot(waiter_key: usize) -> Option<&'static WaiterSlot> {
    let base = SHARED_WAITER_TABLE.load(Ordering::Acquire);
    if base.is_null() {
        return None;
    }
    // SAFETY: `base` is a live mapping of exactly WAITER_SLOTS entries.
    let table = unsafe { std::slice::from_raw_parts(base, WAITER_SLOTS) };
    let key = waiter_key as u64;
    let mut idx = (waiter_key >> 2) % WAITER_SLOTS;
    for _ in 0..WAITER_SLOTS {
        let slot = &table[idx];
        let cur = slot.key.load(Ordering::Acquire);
        if cur == key {
            return Some(slot);
        }
        if cur == 0 {
            match slot
                .key
                .compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Some(slot),
                Err(existing) if existing == key => return Some(slot),
                Err(_) => {} // lost the slot to a different key; probe on
            }
        }
        idx = (idx + 1) % WAITER_SLOTS;
    }
    None
}

/// Live parked-waiter count on `waiter_key`, or `None` when the table is
/// unmapped/full. A diagnostic accessor (mirrors `carrick-host::ulock`'s public
/// `waiter_debug_counts`) so callers can observe a peer parking without reaching
/// into the private slot representation.
pub fn waiter_parked_count(waiter_key: usize) -> Option<u32> {
    shared_waiter_slot(waiter_key).map(|slot| slot.count.load(Ordering::SeqCst))
}

// FreeBSD `_umtx_op(2)` — the host primitive for a cross-PROCESS futex. The
// NON-private op keys on the shared VM object + offset, so a wait/wake on a
// guest `MAP_SHARED` word (identity: guest VA == host VA) reaches a peer parked
// in another forked process — exactly what the in-process parking-lot
// `FutexTable` cannot do across a `fork`.
pub const SYS_UMTX_OP: libc::c_int = 454;
const UMTX_OP_WAIT_UINT: libc::c_int = 11;
pub const UMTX_OP_WAKE: libc::c_int = 3;
// `_umtx_op` reads a relative timeout as a bare `struct timespec` when its
// `uaddr` (4th) arg equals `sizeof(struct timespec)`; `uaddr2` (5th) points at it.
const UMTX_TIMESPEC_SIZE: usize = std::mem::size_of::<libc::timespec>();

enum SharedWaitAssignment {
    Direct,
    Requeue { waiter_key: usize, generation: u32 },
}

fn consume_waiter_assignment(counter: &std::sync::atomic::AtomicU32) -> bool {
    let mut current = counter.load(Ordering::Acquire);
    while current != 0 {
        match counter.compare_exchange_weak(
            current,
            current - 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(next) => current = next,
        }
    }
    false
}

fn take_shared_wait_assignment(slot: Option<&WaiterSlot>) -> SharedWaitAssignment {
    let Some(slot) = slot else {
        return SharedWaitAssignment::Direct;
    };
    if consume_waiter_assignment(&slot.requeue_direct) {
        return SharedWaitAssignment::Direct;
    }
    if consume_waiter_assignment(&slot.requeue_moved) {
        return SharedWaitAssignment::Requeue {
            waiter_key: slot.requeue_to_key.load(Ordering::Acquire) as usize,
            generation: slot.requeue_to_generation.load(Ordering::Acquire),
        };
    }
    SharedWaitAssignment::Direct
}

fn decrement_logical_requeued(slot: &WaiterSlot) {
    let _ = slot
        .logical_requeued
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            Some(count.saturating_sub(1))
        });
}

fn reserve_logical_wakes(slot: &WaiterSlot, requested: u32) -> u32 {
    let mut credits = slot.logical_wake.load(Ordering::Acquire);
    loop {
        let pending = slot.logical_requeued.load(Ordering::Acquire);
        let reserved = requested.min(pending.saturating_sub(credits));
        if reserved == 0 {
            return 0;
        }
        match slot.logical_wake.compare_exchange_weak(
            credits,
            credits.saturating_add(reserved),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return reserved,
            Err(next) => credits = next,
        }
    }
}

/// Complete a logically requeued wait. The destination slot's internal
/// generation + wake credits close the wake-before-park race without depending
/// on the destination guest VA being identical in every process.
fn wait_requeued(
    waiter_key: usize,
    mut generation: u32,
    deadline: Option<std::time::Instant>,
    interrupted: &dyn Fn() -> bool,
) -> i64 {
    let Some(slot) = shared_waiter_slot(waiter_key) else {
        return carrick_abi::LINUX_EAGAIN.guest_retval();
    };
    loop {
        if interrupted() {
            decrement_logical_requeued(slot);
            return carrick_abi::LINUX_EINTR.guest_retval();
        }
        if consume_waiter_assignment(&slot.logical_wake) {
            decrement_logical_requeued(slot);
            return 0;
        }
        let remaining = match deadline {
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    decrement_logical_requeued(slot);
                    return carrick_abi::LINUX_ETIMEDOUT.guest_retval();
                }
                Some(remaining)
            }
            None => None,
        };
        let current = slot.logical_generation.load(Ordering::Acquire);
        if current != generation {
            generation = current;
            continue;
        }
        // Bound each host park so a wake racing before umtx enrollment is
        // observed from its already-published logical credit within 20 ms.
        let slice = remaining
            .unwrap_or(std::time::Duration::from_millis(20))
            .min(std::time::Duration::from_millis(20));
        let ts = libc::timespec {
            tv_sec: slice.as_secs() as libc::time_t,
            tv_nsec: slice.subsec_nanos() as libc::c_long,
        };
        let uaddr = UMTX_TIMESPEC_SIZE as *mut libc::c_void;
        let uaddr2 = (&ts as *const libc::timespec)
            .cast_mut()
            .cast::<libc::c_void>();
        let generation_word = (&slot.logical_generation as *const std::sync::atomic::AtomicU32)
            .cast_mut()
            .cast::<libc::c_void>();
        // SAFETY: the generation word lives in the pre-fork MAP_SHARED waiter
        // table and remains mapped for the run's lifetime.
        let rc = unsafe {
            libc::syscall(
                SYS_UMTX_OP,
                generation_word,
                UMTX_OP_WAIT_UINT,
                generation as libc::c_ulong,
                uaddr,
                uaddr2,
            )
        } as libc::c_long;
        if rc == 0 {
            generation = slot.logical_generation.load(Ordering::Acquire);
            continue;
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        match errno {
            libc::EAGAIN => {
                generation = slot.logical_generation.load(Ordering::Acquire);
            }
            libc::EINTR => {
                if consume_waiter_assignment(&slot.logical_wake) {
                    decrement_logical_requeued(slot);
                    return 0;
                }
                decrement_logical_requeued(slot);
                return carrick_abi::LINUX_EINTR.guest_retval();
            }
            libc::ETIMEDOUT => {
                // Slice timeout, not necessarily the guest deadline. Loop to
                // re-check logical credit and the absolute deadline.
            }
            _ => {
                decrement_logical_requeued(slot);
                return carrick_abi::LINUX_EAGAIN.guest_retval();
            }
        }
    }
}

/// Cross-process shared-futex WAIT via `_umtx_op(UMTX_OP_WAIT_UINT)`. `word` is a
/// live host address of the 4-byte futex word; the kernel re-checks `*word ==
/// value` atomically before parking (closing the classic set-then-wake race with
/// a peer process), then blocks until a [`shared_wake`] on the same page wakes
/// it, the relative `timeout` elapses, or a signal interrupts. A waiter selected
/// by `FUTEX_REQUEUE` transparently continues on the destination while retaining
/// the original absolute deadline. Returns the Linux `FUTEX_WAIT` retval: 0
/// (woken), `-EAGAIN` (value mismatch), `-ETIMEDOUT`, or `-EINTR`.
pub fn shared_wait(
    word: usize,
    waiter_key: usize,
    value: u32,
    timeout: Option<std::time::Duration>,
    interrupted: &dyn Fn() -> bool,
) -> i64 {
    if interrupted() {
        return carrick_abi::LINUX_EINTR.guest_retval();
    }
    let deadline = timeout.and_then(|duration| std::time::Instant::now().checked_add(duration));
    let remaining = match deadline {
        Some(deadline) => {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return carrick_abi::LINUX_ETIMEDOUT.guest_retval();
            }
            Some(remaining)
        }
        None => None,
    };
    let ts = remaining.map(|duration| libc::timespec {
        tv_sec: duration.as_secs() as libc::time_t,
        tv_nsec: duration.subsec_nanos() as libc::c_long,
    });
    let (uaddr, uaddr2) = match &ts {
        Some(ts) => (
            UMTX_TIMESPEC_SIZE as *mut libc::c_void,
            ts as *const libc::timespec as *mut libc::c_void,
        ),
        None => (std::ptr::null_mut(), std::ptr::null_mut()),
    };
    // Announce this parked waiter under its stable backing key so a peer's
    // WAKE can report how many it woke even when it mapped the same file at
    // another VA after exec. Increment before the park and decrement after
    // every return path.
    let slot = shared_waiter_slot(waiter_key);
    if let Some(slot) = slot {
        slot.count.fetch_add(1, Ordering::SeqCst);
    }
    // SAFETY: `word` is an identity host VA of a guest-mapped,
    // 4-byte-aligned shared futex word; `_umtx_op` only reads it.
    let rc = unsafe {
        libc::syscall(
            SYS_UMTX_OP,
            word as *mut u32 as *mut libc::c_void,
            UMTX_OP_WAIT_UINT,
            value as libc::c_ulong,
            uaddr,
            uaddr2,
        )
    } as libc::c_long;
    if let Some(slot) = slot {
        slot.count.fetch_sub(1, Ordering::SeqCst);
    }
    if rc == 0 {
        return match take_shared_wait_assignment(slot) {
            SharedWaitAssignment::Direct => 0,
            SharedWaitAssignment::Requeue {
                waiter_key: next_key,
                generation,
            } => wait_requeued(next_key, generation, deadline, interrupted),
        };
    }
    match std::io::Error::last_os_error().raw_os_error().unwrap_or(0) {
        libc::ETIMEDOUT => carrick_abi::LINUX_ETIMEDOUT.guest_retval(),
        libc::EINTR => carrick_abi::LINUX_EINTR.guest_retval(),
        // `*word != value` at entry (a peer already advanced it): Linux returns
        // EAGAIN and the guest retry loop re-reads the word.
        libc::EAGAIN => carrick_abi::LINUX_EAGAIN.guest_retval(),
        _ => carrick_abi::LINUX_EAGAIN.guest_retval(),
    }
}

/// Implement Linux `FUTEX_REQUEUE` over FreeBSD's non-requeueing umtx ABI.
/// The source waiters are physically released, but each consumes an assignment
/// from the fork-shared slot: the first `wake_count` return to the guest and the
/// next `requeue_count` transparently park on the destination. Publishing the
/// assignments before `_umtx_op(WAKE)` closes the assignment race.
pub fn shared_requeue(
    from_word: usize,
    from_key: usize,
    to_key: usize,
    wake_count: u32,
    requeue_count: u32,
) -> (u32, u32) {
    let Some(slot) = shared_waiter_slot(from_key) else {
        return (0, 0);
    };
    let parked = slot.count.load(Ordering::SeqCst);
    let direct = parked.min(wake_count);
    let destination = shared_waiter_slot(to_key);
    let moved = if destination.is_some() {
        parked.saturating_sub(direct).min(requeue_count)
    } else {
        0
    };
    let total = direct.saturating_add(moved);
    if total == 0 {
        return (0, 0);
    }
    let generation = destination
        .map(|slot| {
            slot.logical_requeued.fetch_add(moved, Ordering::AcqRel);
            slot.logical_generation.load(Ordering::Acquire)
        })
        .unwrap_or(0);
    slot.requeue_to_key.store(to_key as u64, Ordering::Relaxed);
    slot.requeue_to_generation
        .store(generation, Ordering::Relaxed);
    slot.requeue_moved.store(moved, Ordering::Release);
    slot.requeue_direct.store(direct, Ordering::Release);

    // SAFETY: source is the live shared futex word. The side-table assignments
    // are visible before the physical wake, so every released waiter either
    // returns directly or continues at the destination.
    let rc = unsafe {
        libc::syscall(
            SYS_UMTX_OP,
            from_word as *mut u32 as *mut libc::c_void,
            UMTX_OP_WAKE,
            total as libc::c_ulong,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if rc < 0 {
        slot.requeue_direct.store(0, Ordering::Release);
        slot.requeue_moved.store(0, Ordering::Release);
        return (0, 0);
    }
    (direct, moved)
}

/// Cross-process shared-futex WAKE via `_umtx_op(UMTX_OP_WAKE)`: wake up to
/// `count` waiters parked (possibly in another forked process) on `word`, and
/// return how many were woken — the Linux `FUTEX_WAKE` retval. FreeBSD's native
/// `_umtx_op(UMTX_OP_WAKE)` returns 0 rather than the count (unlike its own
/// linuxulator futex), so we read the fork-shared waiter-count table
/// [`shared_waiter_slot`] under the stable shared-backing key BEFORE the wake
/// and return `min(count, parked)` — the
/// same number `umtxq_signal_mask` would have reported. Zero parked yields 0,
/// matching Linux on a page nothing is parked on (`futexghost`).
pub fn shared_wake(word: usize, waiter_key: usize, count: u32) -> i64 {
    let Some(slot) = shared_waiter_slot(waiter_key) else {
        return 0;
    };
    // Logically requeued waiters are counted even before they park on the
    // destination's internal generation. Reserve their credits first; this
    // makes a destination wake lossless across the requeue-to-park window.
    let logical_woke = reserve_logical_wakes(slot, count);
    if logical_woke != 0 {
        slot.logical_generation.fetch_add(1, Ordering::AcqRel);
        let generation_word = (&slot.logical_generation as *const std::sync::atomic::AtomicU32)
            .cast_mut()
            .cast::<libc::c_void>();
        // SAFETY: the generation word is in the run-lifetime MAP_SHARED table.
        // Credits, not the physical wake count, select exactly which waiters
        // complete, so waking all sleepers is safe.
        unsafe {
            libc::syscall(
                SYS_UMTX_OP,
                generation_word,
                UMTX_OP_WAKE,
                u32::MAX as libc::c_ulong,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
    }
    let remaining = count.saturating_sub(logical_woke);
    // Snapshot ordinary parked waiters before waking; released waiters race to
    // decrement as they return from the kernel.
    let normal_woke = remaining.min(slot.count.load(Ordering::SeqCst));
    if normal_woke != 0 {
        // SAFETY: as in `shared_wait`; WAKE neither reads nor writes the guest
        // word.
        unsafe {
            libc::syscall(
                SYS_UMTX_OP,
                word as *mut u32 as *mut libc::c_void,
                UMTX_OP_WAKE,
                normal_woke as libc::c_ulong,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
    }
    i64::from(logical_woke.saturating_add(normal_woke))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_requeue_credit_survives_wake_before_destination_park() {
        init_shared_waiter_table();
        let words = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(words, libc::MAP_FAILED);
        let from_word = words as usize;
        let to_word = from_word + 4;
        let from_key = from_word;
        let to_key = to_word;
        let source = shared_waiter_slot(from_key).expect("source waiter slot");
        source.count.store(1, Ordering::SeqCst);

        assert_eq!(shared_requeue(from_word, from_key, to_key, 0, 1), (0, 1));
        let assignment = take_shared_wait_assignment(Some(source));
        source.count.store(0, Ordering::SeqCst);
        let SharedWaitAssignment::Requeue {
            waiter_key,
            generation,
        } = assignment
        else {
            panic!("waiter was not assigned to the destination");
        };

        // Wake BEFORE the moved waiter begins its destination park. The logical
        // credit must make the subsequent wait complete without blocking.
        assert_eq!(shared_wake(to_word, to_key, 1), 1);
        assert_eq!(
            wait_requeued(
                waiter_key,
                generation,
                Some(std::time::Instant::now() + std::time::Duration::from_secs(1)),
                &|| false,
            ),
            0
        );
        assert_eq!(
            shared_waiter_slot(to_key)
                .expect("destination waiter slot")
                .logical_requeued
                .load(Ordering::SeqCst),
            0
        );

        unsafe { libc::munmap(words, 4096) };
    }
}
