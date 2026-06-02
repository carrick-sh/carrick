//! Private priority-inheritance futex fast path. Apple Rosetta uses
//! `FUTEX_LOCK_PI_PRIVATE`; carrick must not report ENOSYS for the uncontended
//! userspace-lock shape even though it does not emulate scheduler priority
//! inheritance.

use conformance_probes::{errno, report};
use std::sync::atomic::{AtomicU32, Ordering};

const FUTEX_LOCK_PI: libc::c_int = 6;
const FUTEX_UNLOCK_PI: libc::c_int = 7;
const FUTEX_TRYLOCK_PI: libc::c_int = 8;
const FUTEX_PRIVATE: libc::c_int = 128;
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;

static WORD: AtomicU32 = AtomicU32::new(0);

unsafe fn futex_pi(op: libc::c_int) -> libc::c_long {
    libc::syscall(
        libc::SYS_futex,
        WORD.as_ptr(),
        op | FUTEX_PRIVATE,
        0,
        std::ptr::null::<libc::timespec>(),
    )
}

fn main() {
    unsafe {
        WORD.store(0, Ordering::SeqCst);
        let tid = libc::syscall(libc::SYS_gettid) as u32;

        let lock = futex_pi(FUTEX_LOCK_PI);
        let locked_word = WORD.load(Ordering::SeqCst);
        report!(
            lock_pi_uncontended_rc_zero = lock == 0,
            lock_pi_records_owner_tid = (locked_word & FUTEX_TID_MASK) == tid,
        );

        let try_self = futex_pi(FUTEX_TRYLOCK_PI);
        let try_self_errno = errno();
        report!(
            trylock_pi_self_rc_neg_one = try_self == -1,
            trylock_pi_self_errno_edeadlk = try_self_errno == libc::EDEADLK,
        );

        let unlock = futex_pi(FUTEX_UNLOCK_PI);
        report!(
            unlock_pi_owner_rc_zero = unlock == 0,
            unlock_pi_clears_word = WORD.load(Ordering::SeqCst) == 0,
        );

        let unlock_unowned = futex_pi(FUTEX_UNLOCK_PI);
        let unlock_unowned_errno = errno();
        report!(
            unlock_pi_unowned_rc_neg_one = unlock_unowned == -1,
            unlock_pi_unowned_errno_eperm = unlock_unowned_errno == libc::EPERM,
        );
    }
}
