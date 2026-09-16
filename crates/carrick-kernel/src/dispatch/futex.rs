//! Futex syscall handling and wait/wake coordination.
//!
//! Owns the normalized handling for `SYS_futex` and `SYS_futex_waitv`,
//! including private in-process futex queues, cross-process MAP_SHARED
//! futex mirrors, priority-inheritance operations, and timeout conversions.

use std::time::Duration;

use carrick_abi::{
    LINUX_CLOCK_MONOTONIC, LINUX_CLOCK_REALTIME, LINUX_EAGAIN, LINUX_EDEADLK, LINUX_EFAULT,
    LINUX_EINVAL, LINUX_ENOSYS, LINUX_EPERM, LINUX_ETIMEDOUT, LINUX_FUTEX_32, LINUX_FUTEX_CMD_MASK,
    LINUX_FUTEX_CMP_REQUEUE, LINUX_FUTEX_LOCK_PI, LINUX_FUTEX_PRIVATE_FLAG, LINUX_FUTEX_REQUEUE,
    LINUX_FUTEX_TID_MASK, LINUX_FUTEX_TRYLOCK_PI, LINUX_FUTEX_UNLOCK_PI, LINUX_FUTEX_WAIT,
    LINUX_FUTEX_WAIT_BITSET, LINUX_FUTEX_WAITV_MAX, LINUX_FUTEX_WAKE, LINUX_FUTEX_WAKE_BITSET,
    LinuxErrno, LinuxFutexFlags,
};
use carrick_guest_mem::CurrentMmMemory;

use super::outcome::{DispatchOutcome, SharedFutexTarget};
use super::request::SyscallRequest;
use super::{
    duration_from_linux_timespec, linux_timeout_timespec_is_valid, read_timespec, read_u32,
    write_u32,
};
use crate::compat::CompatReporter;

/// Convert an ABSOLUTE futex deadline (FUTEX_WAIT_BITSET) to the remaining
/// duration from now, on the host monotonic clock (or realtime when
/// FUTEX_CLOCK_REALTIME is set). Clamps to zero if already past — Linux then
/// returns ETIMEDOUT immediately.
pub(crate) fn relative_from_absolute_timespec(
    clock: &crate::kernel::container::ClockDomain,
    tv_sec: i64,
    tv_nsec: i64,
    realtime: bool,
) -> Duration {
    let abs_ns = (tv_sec as i128) * 1_000_000_000 + tv_nsec as i128;
    if realtime && clock.is_frozen() {
        let frozen_ns = clock.realtime_now().as_nanos() as i128;
        if abs_ns <= frozen_ns {
            return Duration::ZERO;
        }
        return Duration::MAX;
    }
    let now_ns: i128 = if realtime {
        clock.realtime_now().as_nanos() as i128
    } else {
        clock.monotonic_now().as_nanos() as i128
    };
    let rel_ns = (abs_ns - now_ns).max(0);
    let dur = Duration::from_nanos(rel_ns.min(u64::MAX as i128) as u64);
    clock.scale_timeout(dur)
}

pub(crate) fn dispatch_futex_pi(
    memory: &mut impl CurrentMmMemory,
    address: u64,
    command: u64,
    word: u32,
    tid: u32,
    futex: Option<&crate::thread::FutexTable>,
) -> DispatchOutcome {
    // The low 30 bits of a PI-futex word hold the owner TID (FUTEX_TID_MASK,
    // imported from carrick-abi); the upper two are FUTEX_WAITERS/OWNER_DIED.
    if tid == 0 || tid > LINUX_FUTEX_TID_MASK {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }

    let owner = word & LINUX_FUTEX_TID_MASK;
    match command {
        LINUX_FUTEX_LOCK_PI | LINUX_FUTEX_TRYLOCK_PI => {
            if owner == 0 {
                if let Err(errno) = write_u32(memory, address, tid) {
                    return DispatchOutcome::Errno { errno };
                }
                return DispatchOutcome::Returned { value: 0 };
            }
            if owner == tid {
                return DispatchOutcome::Errno {
                    errno: LINUX_EDEADLK,
                };
            }
            DispatchOutcome::Errno {
                errno: LINUX_EAGAIN,
            }
        }
        LINUX_FUTEX_UNLOCK_PI => {
            if owner != tid {
                return DispatchOutcome::Errno { errno: LINUX_EPERM };
            }
            if let Err(errno) = write_u32(memory, address, 0) {
                return DispatchOutcome::Errno { errno };
            }
            if let Some(futex) = futex {
                let woken = futex.wake(address, 1);
                crate::event_ring::rec_futex_wake(address, woken);
            }
            DispatchOutcome::Returned { value: 0 }
        }
        _ => DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        },
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_threaded_futex(
    clock: &crate::kernel::container::ClockDomain,
    request: SyscallRequest,
    memory: &mut impl CurrentMmMemory,
    reporter: &CompatReporter,
    futex: &crate::thread::FutexTable,
    _tid: crate::thread::ThreadId,
    registry: &crate::thread::ThreadRegistry,
    hvpatch_linux_tid: Option<u32>,
) -> DispatchOutcome {
    let address = request.arg(0);
    let operation = request.arg(1);
    let value = request.arg(2) as u32;
    let timeout_address = request.arg(3);

    let raw_command = operation & LINUX_FUTEX_CMD_MASK;
    let command = match raw_command {
        LINUX_FUTEX_WAIT_BITSET => LINUX_FUTEX_WAIT,
        LINUX_FUTEX_WAKE_BITSET => LINUX_FUTEX_WAKE,
        other => other,
    };
    let flags = operation & !LINUX_FUTEX_CMD_MASK;
    let futex_flags = LinuxFutexFlags::from_bits_retain(flags);
    // Unknown OPERATION outranks bad flags; see the `futex` handler.
    if !linux_futex_command_is_known(raw_command) {
        return DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        };
    }
    if flags & !LinuxFutexFlags::SUPPORTED_MASK != 0 {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }
    // Identical well-formedness gate to the `futex` handler in `proc.rs`; a
    // guest thread reaches THIS path, so validating only there left every
    // check unreachable in practice (`eventwaitmatrix`).
    if !address.is_multiple_of(4) {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }
    if matches!(
        raw_command,
        LINUX_FUTEX_WAIT_BITSET | LINUX_FUTEX_WAKE_BITSET
    ) && request.arg(5) as u32 == 0
    {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }
    if timeout_address != 0
        && matches!(raw_command, LINUX_FUTEX_WAIT | LINUX_FUTEX_WAIT_BITSET)
        && let Ok(timespec) = read_timespec(memory, timeout_address)
        && !linux_timeout_timespec_is_valid(timespec)
    {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }

    // Only WAIT / CMP_REQUEUE / PI ops consult the futex VALUE; WAKE and plain
    // REQUEUE are keyed purely on the guest address (the parking-lot table keys
    // on the VA, which is identical across the shared guest address space). Real
    // Linux FUTEX_WAKE likewise computes only the hash key — it never reads the
    // word. So reading the word for a WAKE is unnecessary, and surfacing its
    // EFAULT is actively harmful: a cross-thread waker whose per-thread
    // `GuestMemory` view can't translate the *waiter's* futex page (the syscall
    // path uses a per-sibling window snapshot, unlike the coherent whole-RAM
    // view HVF exposes) would spuriously fail the wake. Go's
    // `runtime.futexwakeup` treats any unexpected errno (incl. EFAULT) as fatal
    // and self-crashes (SIGSEGV at 0x1006), which is exactly the intermittent
    // Go-on-KVM failure. Make the read non-fatal for value-independent ops.
    let needs_word = matches!(
        command,
        LINUX_FUTEX_WAIT
            | LINUX_FUTEX_LOCK_PI
            | LINUX_FUTEX_TRYLOCK_PI
            | LINUX_FUTEX_UNLOCK_PI
            | LINUX_FUTEX_CMP_REQUEUE
    );
    let word = match read_futex_word(memory, address) {
        Ok(word) => word,
        Err(errno) if needs_word => return DispatchOutcome::Errno { errno },
        // WAKE / plain REQUEUE: the value is unused; proceed address-keyed.
        Err(_) => 0,
    };

    if matches!(
        command,
        LINUX_FUTEX_LOCK_PI | LINUX_FUTEX_TRYLOCK_PI | LINUX_FUTEX_UNLOCK_PI
    ) {
        let Some(guest_tid) = hvpatch_linux_tid else {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        };
        return dispatch_futex_pi(memory, address, command, word, guest_tid, Some(futex));
    }

    if !futex_flags.contains(LinuxFutexFlags::PRIVATE) {
        reporter.record(crate::compat::CompatEvent::partial_syscall(
            98,
            "futex",
            request.args,
            "non-private futex treated as private (shared address space)",
        ));
    }

    // A futex word that lives in a genuine MAP_SHARED file mapping is an
    // inter-process rendezvous: route it through the host __ulock keyed on the
    // shared physical page so a waker in another carrick process is reached.
    // Private/anon futexes stay in the in-process parking-lot table.
    //
    // EXCEPT a non-PRIVATE futex on a live thread's CLONE_CHILD_CLEARTID address:
    // glibc's `pthread_join` waits on `pd->tid` non-PRIVATE, but its waker is
    // carrick's IN-PROCESS `handle_thread_exit` (`futex.wake`), not a guest
    // `FUTEX_WAKE`. It must stay in the in-process table — on bhyve the cross-process
    // mirror is a SEPARATE word and a mirror `__ulock` WAIT would never be woken by
    // the in-process exit-wake, so the join HANGS (the immediate-`pthread_join`
    // failure; KVM is immune — its mirror IS the guest word). No-op on HVF/KVM, where
    // this private descriptor word never resolved to a mirror anyway.
    let shared_location = if futex_flags.contains(LinuxFutexFlags::PRIVATE)
        || registry.is_clear_child_tid_addr(address)
    {
        None
    } else {
        memory.shared_futex_location(address)
    };
    crate::probes::futex_route(
        address,
        command as i32,
        if shared_location.is_some() { 1 } else { 0 },
        shared_location
            .map(|location| location.wait_addr().raw() as u64)
            .unwrap_or(0),
    );

    match command {
        LINUX_FUTEX_WAKE => {
            if let Some(location) = shared_location {
                // Publish the waker's word to the SHARED MIRROR before the wake so
                // a cross-process WAITer observes it — but ONLY on a backend that
                // actually uses a separate mirror (bhyve, whose per-VM guest word
                // is not shared across fork). On HVF/KVM the wait address IS the guest
                // word, which the waker already wrote before this FUTEX_WAKE
                // syscall: republishing here is redundant AND races — the value we
                // could write is necessarily a slightly stale snapshot, so it
                // would OVERWRITE a concurrent peer update and REVERT it (measured
                // ~3% of wakes), which desynced cross-process semaphores/barriers
                // and hung cpython multiprocessing. So gate the publish on
                // `SharedFutexLocation::Mirror` and, when it IS needed, read the
                // word FRESH (not the stale top-of-handler `word`).
                if location.is_mirror() {
                    let fresh = read_futex_word(memory, address).unwrap_or(word);
                    // SAFETY: the wait address is a live 4-byte-aligned host mirror word.
                    unsafe {
                        (*(location.wait_addr().raw() as *const std::sync::atomic::AtomicU32))
                            .store(fresh, std::sync::atomic::Ordering::SeqCst);
                    }
                }
                // Cross-PROCESS (MAP_SHARED) wake: route through the
                // `PlatformFutex::shared_wake` seam (the wake counterpart of the
                // `SharedFutexWait` outcome) so the wake reaches a waiter parked
                // in another carrick process via the SAME backend the wait uses —
                // HVF's __ulock (one-at-a-time + sched_yield, the macOS spurious-
                // success cure) or KVM's host `SYS_futex(FUTEX_WAKE)`. The loop
                // completes the syscall with the count woken.
                return DispatchOutcome::SharedFutexWake {
                    target: SharedFutexTarget::new(location, location.waiter_key()),
                    count: value,
                };
            }
            let n = futex.wake(address, value);
            crate::event_ring::rec_futex_wake(address, n);
            DispatchOutcome::Returned {
                value: i64::from(n),
            }
        }
        LINUX_FUTEX_WAIT => {
            // For a SHARED (cross-process) futex the authoritative current value is at
            // the fork-coherent host word (the mirror on bhyve; == the guest word on
            // HVF/KVM). Compare THAT, not the possibly stale per-VM sysmem copy, and
            // publish it back to the guest word so the caller's retry loop re-reads what
            // another process wrote instead of spinning on the stale value (see proc.rs).
            let current = if let Some(location) = shared_location {
                // SAFETY: the wait address is a live 4-byte-aligned host word.
                let mirror = unsafe {
                    (*(location.wait_addr().raw() as *const std::sync::atomic::AtomicU32))
                        .load(std::sync::atomic::Ordering::SeqCst)
                };
                // On bhyve (separate mirror) sync the mirror -> the waiter's
                // per-VM guest word so its retry loop re-reads what a peer wrote.
                // On HVF/KVM the wait address IS the guest word, so this write-back is
                // redundant AND races exactly like the FUTEX_WAKE store-back: a
                // concurrent peer write landing between the load above and this
                // store reverts the peer's update, desyncing the protocol (the
                // residual that hung multiprocessing test_thousand). Gate it on
                // the mirror flag — `mirror` is already the authoritative current
                // value used for the compare below regardless.
                if mirror != word && location.is_mirror() {
                    let _ = memory.write_bytes(address, &mirror.to_ne_bytes());
                }
                mirror
            } else {
                word
            };
            if current != value {
                return DispatchOutcome::Errno {
                    errno: LINUX_EAGAIN,
                };
            }
            let timeout = if timeout_address == 0 {
                None
            } else {
                let timespec = match read_timespec(memory, timeout_address) {
                    Ok(t) => t,
                    Err(errno) => return DispatchOutcome::Errno { errno },
                };
                // FUTEX_WAIT uses a RELATIVE timeout; FUTEX_WAIT_BITSET uses an
                // ABSOLUTE deadline (CLOCK_MONOTONIC, or CLOCK_REALTIME if
                // FUTEX_CLOCK_REALTIME) — convert it to the remaining duration,
                // else the wait would block until now+deadline ≈ forever.
                if raw_command == LINUX_FUTEX_WAIT_BITSET {
                    Some(relative_from_absolute_timespec(
                        clock,
                        timespec.tv_sec,
                        timespec.tv_nsec,
                        futex_flags.contains(LinuxFutexFlags::CLOCK_REALTIME),
                    ))
                } else {
                    // A present (non-NULL) relative timespec ALWAYS specifies a
                    // deadline — even {0,0}, which means "expire IMMEDIATELY"
                    // (ETIMEDOUT now), NOT "infinite". duration_from_linux_timespec
                    // maps {0,0} to None ("no duration"); collapsing that to the
                    // `timeout_address == 0` None (block forever) made the threaded
                    // park (FutexWait) compute no deadline and spin forever on a
                    // zero-timeout WAIT that Linux returns ETIMEDOUT from at once.
                    // Force the zero case to a ZERO duration so the park deadline is
                    // `now` and fires immediately (mirrors the proc.rs fix 519dd40f).
                    match duration_from_linux_timespec(timespec) {
                        Ok(t) => Some(clock.scale_timeout(t.unwrap_or(std::time::Duration::ZERO))),
                        Err(errno) => return DispatchOutcome::Errno { errno },
                    }
                }
            };
            if let Some(location) = shared_location {
                // The shared path's compare-and-wait is atomic in the kernel
                // (__ulock UL_COMPARE_AND_WAIT re-checks the word), so no
                // generation snapshot is needed here.
                return DispatchOutcome::SharedFutexWait {
                    target: SharedFutexTarget::new(location, location.waiter_key()),
                    generation: carrick_thread::platform_futex::carrier_shared_futex_table()
                        .prepare_wait(location.waiter_key() as u64),
                    value,
                    timeout,
                };
            }
            // Private/anon futex: snapshot the wait generation BEFORE
            // re-validating the word, then re-read the word. This closes a
            // lost-wakeup race — capturing the generation only at park time
            // (i.e. after the value was read at the top of the handler) loses a
            // FUTEX_WAKE delivered in the window between that read and the
            // enqueue: the waker bumps the generation, the waiter then captures
            // the ALREADY-bumped value and sleeps forever. With the snapshot
            // first, a racing wake either advances the captured generation (the
            // wait returns Woken) or has already stored the new word value (the
            // re-read mismatches → EAGAIN, no stale park). High-frequency Go
            // scheduler M park/unpark hit this window and intermittently hung.
            let wait = futex.prepare_wait(address);
            match read_u32(memory, address) {
                Ok(reread) if reread != value => {
                    return DispatchOutcome::Errno {
                        errno: LINUX_EAGAIN,
                    };
                }
                Ok(_) => {}
                Err(errno) => return DispatchOutcome::Errno { errno },
            }
            DispatchOutcome::FutexWait { wait, timeout }
        }
        LINUX_FUTEX_REQUEUE | LINUX_FUTEX_CMP_REQUEUE => {
            // FUTEX_(CMP_)REQUEUE: wake `nr_wake` waiters on uaddr1, then move
            // up to `nr_requeue` of the rest to uaddr2's queue. For this op the
            // futex(2) ABI REINTERPRETS the arg slots: arg3 (normally the
            // timeout pointer) is `nr_requeue`, arg4 is uaddr2, arg5 is val3
            // (the CMP_REQUEUE expected value).
            let nr_wake = value;
            // nr_wake and nr_requeue are signed ints in the kernel ABI; a
            // negative value (e.g. a guest passing ~0 as a "max" by mistake)
            // is EINVAL, checked BEFORE the val3 comparison.
            if (request.arg(2) as i32) < 0 || (request.arg(3) as i32) < 0 {
                return DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                };
            }
            let nr_requeue = request.arg(3) as u32;
            let uaddr2 = request.arg(4);
            let val3 = request.arg(5) as u32;

            // CMP_REQUEUE atomically validates *uaddr1 == val3 before doing any
            // work (the race-free condvar handoff); plain REQUEUE skips it.
            if raw_command == LINUX_FUTEX_CMP_REQUEUE && word != val3 {
                return DispatchOutcome::Errno {
                    errno: LINUX_EAGAIN,
                };
            }

            if let Some(location) = shared_location {
                let Some(to_location) = memory.shared_futex_location(uaddr2) else {
                    return DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    };
                };
                return DispatchOutcome::SharedFutexRequeue {
                    from: SharedFutexTarget::new(location, location.waiter_key()),
                    to: SharedFutexTarget::new(to_location, to_location.waiter_key()),
                    wake: nr_wake,
                    requeue: nr_requeue,
                };
            }

            // Private/anon: real requeue via parking_lot_core::unpark_requeue.
            let (woken, requeued) = futex.requeue(address, uaddr2, nr_wake, nr_requeue);
            // Linux returns the total number of waiters woken PLUS requeued.
            DispatchOutcome::Returned {
                value: i64::from(woken + requeued),
            }
        }
        _ => DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        },
    }
}

#[derive(Debug, Clone, Copy)]
struct FutexWaitvEntry {
    address: u64,
    value: u32,
    private: bool,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_futex_waitv_args(
    clock: &crate::kernel::container::ClockDomain,
    memory: &mut impl CurrentMmMemory,
    futex: Option<&crate::thread::FutexTable>,
    waiters: u64,
    nr_futexes: u64,
    flags: u64,
    timeout_address: u64,
    clockid: u64,
) -> DispatchOutcome {
    if flags != 0
        || nr_futexes == 0
        || nr_futexes > LINUX_FUTEX_WAITV_MAX
        || waiters == 0
        || !matches!(clockid, LINUX_CLOCK_MONOTONIC | LINUX_CLOCK_REALTIME)
    {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }

    let timeout = if timeout_address == 0 {
        None
    } else {
        let timespec = match read_timespec(memory, timeout_address) {
            Ok(timespec) => timespec,
            Err(errno) => return DispatchOutcome::Errno { errno },
        };
        Some(relative_from_absolute_timespec(
            clock,
            timespec.tv_sec,
            timespec.tv_nsec,
            clockid == LINUX_CLOCK_REALTIME,
        ))
    };

    let mut entries = Vec::with_capacity(nr_futexes as usize);
    for index in 0..nr_futexes {
        let Some(entry_address) = waiters.checked_add(index.saturating_mul(24)) else {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        };
        let bytes = match memory.read_bytes(entry_address, 24) {
            Ok(bytes) => bytes,
            Err(_) => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                };
            }
        };
        let mut value_bytes = [0u8; 8];
        value_bytes.copy_from_slice(&bytes[0..8]);
        let mut address_bytes = [0u8; 8];
        address_bytes.copy_from_slice(&bytes[8..16]);
        let mut flags_bytes = [0u8; 4];
        flags_bytes.copy_from_slice(&bytes[16..20]);
        let mut reserved_bytes = [0u8; 4];
        reserved_bytes.copy_from_slice(&bytes[20..24]);

        let value = u64::from_ne_bytes(value_bytes);
        let address = u64::from_ne_bytes(address_bytes);
        let waiter_flags = u32::from_ne_bytes(flags_bytes) as u64;
        let reserved = u32::from_ne_bytes(reserved_bytes);

        let size = waiter_flags & LINUX_FUTEX_32;
        let unknown = waiter_flags & !(LINUX_FUTEX_32 | LINUX_FUTEX_PRIVATE_FLAG);
        if reserved != 0 || size != LINUX_FUTEX_32 || unknown != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if address == 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }
        if address & 0x3 != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if value > u64::from(u32::MAX) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        let expected = value as u32;
        let private = carrick_abi::LinuxFutexFlags::from_bits_truncate(waiter_flags)
            .contains(carrick_abi::LinuxFutexFlags::PRIVATE);
        match read_futex_word(memory, address) {
            Ok(word) if word == expected => {}
            Ok(_) => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EAGAIN,
                };
            }
            Err(errno) => return DispatchOutcome::Errno { errno },
        }
        entries.push(FutexWaitvEntry {
            address,
            value: expected,
            private,
        });
    }

    if let Some((index, entry)) = entries
        .len()
        .checked_sub(1)
        .and_then(|index| entries.get(index).map(|entry| (index, *entry)))
    {
        if !entry.private
            && let Some(location) = memory.shared_futex_location(entry.address)
        {
            return DispatchOutcome::SharedFutexWaitv {
                target: SharedFutexTarget::new(location, location.waiter_key()),
                generation: carrick_thread::platform_futex::carrier_shared_futex_table()
                    .prepare_wait(location.waiter_key() as u64),
                value: entry.value,
                timeout,
                index: index as i64,
            };
        }
        if let Some(futex) = futex {
            let wait = futex.prepare_wait(entry.address);
            match read_futex_word(memory, entry.address) {
                Ok(word) if word != entry.value => {
                    return DispatchOutcome::returned_len_or_errno(index);
                }
                Ok(_) => {}
                Err(errno) => return DispatchOutcome::Errno { errno },
            }
            return DispatchOutcome::FutexWaitv {
                wait,
                timeout,
                index: index as i64,
            };
        }
    }

    for (index, entry) in entries.iter().enumerate() {
        match read_futex_word(memory, entry.address) {
            Ok(word) if word != entry.value => {
                return DispatchOutcome::returned_len_or_errno(index);
            }
            Ok(_) => {}
            Err(errno) => return DispatchOutcome::Errno { errno },
        }
    }
    if let Some(timeout) = timeout {
        DispatchOutcome::WaitOnSleep {
            duration: timeout,
            remaining: None,
        }
    } else {
        DispatchOutcome::Errno {
            errno: LINUX_ETIMEDOUT,
        }
    }
}

/// Read a futex word, falling back to the fork-coherent shared mapping when the
/// dispatcher's software guest-memory view can't translate the address. A
/// MAP_SHARED semaphore's futex word is reachable in a forked child via the
/// host `__ulock`-keyed shared pointer (the same one the wait/wake paths read)
/// even when the child's software memory view misses the high shared aperture
/// (the guest CPU reaches it through HVF stage-2, but the dispatcher's read
/// does not). Surfacing the read EFAULT instead trips glibc's
/// `futex_fatal_error()` (SIGABRT) on a VALID cross-process futex — observed in
/// CPython multiprocessing SyncManager teardown, where a forked server child's
/// `FUTEX_WAIT_BITSET|CLOCK_REALTIME` on a shared semaphore aborted the process.
pub(crate) fn read_futex_word(
    memory: &impl CurrentMmMemory,
    address: u64,
) -> Result<u32, LinuxErrno> {
    match read_u32(memory, address) {
        Ok(word) => Ok(word),
        Err(errno) => match memory.shared_futex_location(address) {
            // SAFETY: a resolved shared host addr points into a live MAP_SHARED
            // region in THIS process — the identical pointer `shared_futex_wait`
            // reads at the wait site. `read_unaligned` avoids assuming stricter
            // alignment than the guest futex ABI's 4-byte guarantee.
            Some(location) => {
                Ok(unsafe { (location.wait_addr().raw() as *const u32).read_unaligned() })
            }
            None => Err(errno),
        },
    }
}

/// Futex operations carrick implements. An operation outside this set is
/// ENOSYS -- "this op does not exist" -- which Linux distinguishes from the
/// EINVAL it gives a malformed call (`eventwaitmatrix`
/// `futex_invalid_op_enosys`).
pub(crate) fn linux_futex_command_is_known(command: u64) -> bool {
    matches!(
        command,
        LINUX_FUTEX_WAIT
            | LINUX_FUTEX_WAKE
            | LINUX_FUTEX_REQUEUE
            | LINUX_FUTEX_CMP_REQUEUE
            | LINUX_FUTEX_LOCK_PI
            | LINUX_FUTEX_UNLOCK_PI
            | LINUX_FUTEX_TRYLOCK_PI
            | LINUX_FUTEX_WAIT_BITSET
            | LINUX_FUTEX_WAKE_BITSET
    )
}
