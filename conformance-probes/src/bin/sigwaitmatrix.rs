//! Signal wait, timed wait, queue info, and mask restoration conformance matrix probe.
//!
//! Exercises Linux flag validation, siginfo payload propagation, queue priority ordering,
//! permission constraints, and synchronous dequeue semantics across:
//! 1. `rt_sigtimedwait` Argument & Timespec Validation: invalid `tv_nsec`, bad `sigsetsize`,
//!    null pointers, and zero-timeout non-blocking `EAGAIN` returns.
//! 2. Synchronous Signal Dequeue & Delivery: pending signal consumption without handler
//!    execution, numerical priority ordering (lowest standard signal first), and mask preservation.
//! 3. `rt_sigqueueinfo` and `rt_tgsigqueueinfo` Error & Security Validation: invalid signal
//!    numbers, non-existent PID/TID (`ESRCH`), `si_code >= 0` unprivileged spoofing rejection (`EPERM`),
//!    `si_signo` matching constraint, and valid `SI_QUEUE` payload delivery.
//! 4. Signal Mask Constraints: `SIGKILL`/`SIGSTOP` unblockability, invalid `how` argument in
//!    `sigprocmask`, and fault handling on invalid sigset pointers.
//!
//! Output format: deterministic `key=value` lines diffed against the Linux oracle.
//! Uses non-blocking zero-timeout calls and pre-raised signals to avoid timing races or lane hangs.

use conformance_probes::{
    block_signal, errno, install_handler, is_blocked, is_pending, report, unblock_signal,
};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU32, Ordering};

const SYS_RT_SIGTIMEDWAIT: libc::c_long = libc::SYS_rt_sigtimedwait;
const SYS_RT_SIGQUEUEINFO: libc::c_long = libc::SYS_rt_sigqueueinfo;
const SYS_RT_TGSIGQUEUEINFO: libc::c_long = libc::SYS_rt_tgsigqueueinfo;
const SYS_RT_SIGSUSPEND: libc::c_long = libc::SYS_rt_sigsuspend;
const SYS_GETTID: libc::c_long = libc::SYS_gettid;

static HANDLER_COUNT: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_signal(_: i32) {
    HANDLER_COUNT.fetch_add(1, Ordering::SeqCst);
}

// -----------------------------------------------------------------------------
// 1. rt_sigtimedwait Argument & Timespec Validation Matrix
// -----------------------------------------------------------------------------

unsafe fn test_sigtimedwait_validation_matrix() {
    let mut set: libc::sigset_t = MaybeUninit::zeroed().assume_init();
    libc::sigemptyset(&mut set);
    libc::sigaddset(&mut set, libc::SIGUSR1);

    let mut info: libc::siginfo_t = MaybeUninit::zeroed().assume_init();

    let bad_ts_neg = libc::timespec {
        tv_sec: 0,
        tv_nsec: -1,
    };
    let bad_ts_over = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000_000,
    };
    let zero_ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    // 1.1 Timespec validation -> EINVAL
    let rc_neg = libc::syscall(
        SYS_RT_SIGTIMEDWAIT,
        &set as *const _,
        &mut info as *mut _,
        &bad_ts_neg as *const _,
        8usize,
    );
    let ts_neg_einval = rc_neg == -1 && errno() == libc::EINVAL;

    let rc_over = libc::syscall(
        SYS_RT_SIGTIMEDWAIT,
        &set as *const _,
        &mut info as *mut _,
        &bad_ts_over as *const _,
        8usize,
    );
    let ts_over_einval = rc_over == -1 && errno() == libc::EINVAL;

    // 1.2 Invalid sigsetsize (must be 8 on aarch64 Linux) -> EINVAL
    let rc_sz_small = libc::syscall(
        SYS_RT_SIGTIMEDWAIT,
        &set as *const _,
        &mut info as *mut _,
        &zero_ts as *const _,
        4usize,
    );
    let sz_small_einval = rc_sz_small == -1 && errno() == libc::EINVAL;

    let rc_sz_large = libc::syscall(
        SYS_RT_SIGTIMEDWAIT,
        &set as *const _,
        &mut info as *mut _,
        &zero_ts as *const _,
        16usize,
    );
    let sz_large_einval = rc_sz_large == -1 && errno() == libc::EINVAL;

    let rc_sz_zero = libc::syscall(
        SYS_RT_SIGTIMEDWAIT,
        &set as *const _,
        &mut info as *mut _,
        &zero_ts as *const _,
        0usize,
    );
    let sz_zero_einval = rc_sz_zero == -1 && errno() == libc::EINVAL;

    // 1.3 Zero-timeout with nothing pending -> EAGAIN immediately
    let rc_empty = libc::syscall(
        SYS_RT_SIGTIMEDWAIT,
        &set as *const _,
        &mut info as *mut _,
        &zero_ts as *const _,
        8usize,
    );
    let empty_eagain = rc_empty == -1 && errno() == libc::EAGAIN;

    // 1.4 Bad set pointer -> EFAULT
    let rc_null_set = libc::syscall(
        SYS_RT_SIGTIMEDWAIT,
        std::ptr::null::<libc::sigset_t>(),
        &mut info as *mut _,
        &zero_ts as *const _,
        8usize,
    );
    let null_set_efault = rc_null_set == -1 && errno() == libc::EFAULT;

    report!(
        sigtimedwait_timespec_validation = ts_neg_einval && ts_over_einval,
        sigtimedwait_sigsetsize_validation = sz_small_einval && sz_large_einval && sz_zero_einval,
        sigtimedwait_zero_timeout_eagain = empty_eagain,
        sigtimedwait_null_set_efault = null_set_efault,
    );
}

// -----------------------------------------------------------------------------
// 2. Synchronous Signal Dequeue & Delivery Matrix
// -----------------------------------------------------------------------------

unsafe fn test_synchronous_dequeue_matrix() {
    let pid = libc::getpid();
    let zero_ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    // 2.1 Single signal dequeue: pending bit consumed, mask intact, siginfo populated
    block_signal(libc::SIGUSR1);
    libc::raise(libc::SIGUSR1);
    let pending_before = is_pending(libc::SIGUSR1);

    let mut set1: libc::sigset_t = MaybeUninit::zeroed().assume_init();
    libc::sigemptyset(&mut set1);
    libc::sigaddset(&mut set1, libc::SIGUSR1);

    let mut info1: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
    let rc1 = libc::syscall(
        SYS_RT_SIGTIMEDWAIT,
        &set1 as *const _,
        &mut info1 as *mut _,
        &zero_ts as *const _,
        8usize,
    ) as i32;

    let dequeue_ok = rc1 == libc::SIGUSR1
        && info1.si_signo == libc::SIGUSR1
        && info1.si_code == 0 // SI_USER
        && info1.si_pid() == pid;
    let pending_after = is_pending(libc::SIGUSR1);
    let mask_intact = is_blocked(libc::SIGUSR1);
    unblock_signal(libc::SIGUSR1);

    // 2.2 Multiple signals: lowest standard signal dequeued first
    block_signal(libc::SIGUSR1);
    block_signal(libc::SIGUSR2);
    // Raise in reverse order: SIGUSR2 first, then SIGUSR1
    libc::raise(libc::SIGUSR2);
    libc::raise(libc::SIGUSR1);

    let mut set_both: libc::sigset_t = MaybeUninit::zeroed().assume_init();
    libc::sigemptyset(&mut set_both);
    libc::sigaddset(&mut set_both, libc::SIGUSR1);
    libc::sigaddset(&mut set_both, libc::SIGUSR2);

    let mut info_a: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
    let first_rc = libc::syscall(
        SYS_RT_SIGTIMEDWAIT,
        &set_both as *const _,
        &mut info_a as *mut _,
        &zero_ts as *const _,
        8usize,
    ) as i32;

    let mut info_b: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
    let second_rc = libc::syscall(
        SYS_RT_SIGTIMEDWAIT,
        &set_both as *const _,
        &mut info_b as *mut _,
        &zero_ts as *const _,
        8usize,
    ) as i32;

    let priority_ok = first_rc == libc::SIGUSR1 && second_rc == libc::SIGUSR2;
    let both_cleared = !is_pending(libc::SIGUSR1) && !is_pending(libc::SIGUSR2);
    unblock_signal(libc::SIGUSR1);
    unblock_signal(libc::SIGUSR2);

    // 2.3 Handler suppression: dequeuing consumes signal without executing handler
    HANDLER_COUNT.store(0, Ordering::SeqCst);
    install_handler(libc::SIGUSR1, on_signal, 0);
    block_signal(libc::SIGUSR1);
    libc::raise(libc::SIGUSR1);

    let mut info_h: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
    let rc_h = libc::syscall(
        SYS_RT_SIGTIMEDWAIT,
        &set1 as *const _,
        &mut info_h as *mut _,
        &zero_ts as *const _,
        8usize,
    ) as i32;
    let dequeued_h = rc_h == libc::SIGUSR1;

    // Unblock: since it was dequeued, no handler should run
    unblock_signal(libc::SIGUSR1);
    let handler_stayed_zero = HANDLER_COUNT.load(Ordering::SeqCst) == 0;

    report!(
        sigtimedwait_single_dequeue_semantics =
            pending_before && dequeue_ok && !pending_after && mask_intact,
        sigtimedwait_numerical_priority_order = priority_ok && both_cleared,
        sigtimedwait_suppresses_handler_execution = dequeued_h && handler_stayed_zero,
    );
}

// -----------------------------------------------------------------------------
// 3. rt_sigqueueinfo & rt_tgsigqueueinfo Error and Security Matrix
// -----------------------------------------------------------------------------

unsafe fn test_sigqueueinfo_matrix() {
    let pid = libc::getpid();
    let tid = libc::syscall(SYS_GETTID) as i32;

    let mut info: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
    info.si_signo = libc::SIGUSR1;
    info.si_code = -1; // SI_QUEUE

    // 3.1 Invalid signal numbers -> EINVAL
    let q_neg = libc::syscall(SYS_RT_SIGQUEUEINFO, pid as i64, -1i64, &info as *const _);
    let q_neg_einval = q_neg == -1 && errno() == libc::EINVAL;

    let q_zero = libc::syscall(SYS_RT_SIGQUEUEINFO, pid as i64, 0i64, &info as *const _);
    let q_zero_einval = q_zero == -1 && errno() == libc::EINVAL;

    let q_large = libc::syscall(SYS_RT_SIGQUEUEINFO, pid as i64, 65i64, &info as *const _);
    let q_large_einval = q_large == -1 && errno() == libc::EINVAL;

    let tg_neg = libc::syscall(
        SYS_RT_TGSIGQUEUEINFO,
        pid as i64,
        tid as i64,
        -1i64,
        &info as *const _,
    );
    let tg_neg_einval = tg_neg == -1 && errno() == libc::EINVAL;

    let tg_large = libc::syscall(
        SYS_RT_TGSIGQUEUEINFO,
        pid as i64,
        tid as i64,
        65i64,
        &info as *const _,
    );
    let tg_large_einval = tg_large == -1 && errno() == libc::EINVAL;

    // 3.2 Non-existent PID/TID -> ESRCH
    let q_bad_pid = libc::syscall(
        SYS_RT_SIGQUEUEINFO,
        999999i64,
        libc::SIGUSR1 as i64,
        &info as *const _,
    );
    let q_bad_pid_esrch = q_bad_pid == -1 && errno() == libc::ESRCH;

    let tg_bad_tid = libc::syscall(
        SYS_RT_TGSIGQUEUEINFO,
        pid as i64,
        999999i64,
        libc::SIGUSR1 as i64,
        &info as *const _,
    );
    let tg_bad_tid_esrch = tg_bad_tid == -1 && errno() == libc::ESRCH;

    let tg_bad_tgid = libc::syscall(
        SYS_RT_TGSIGQUEUEINFO,
        999999i64,
        tid as i64,
        libc::SIGUSR1 as i64,
        &info as *const _,
    );
    let tg_bad_tgid_esrch = tg_bad_tgid == -1 && errno() == libc::ESRCH;

    // 3.3 Security check: si_code >= 0 (e.g. SI_USER = 0) without privileges -> EPERM
    let mut info_user: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
    info_user.si_signo = libc::SIGUSR1;
    info_user.si_code = 0; // SI_USER

    let q_user = libc::syscall(
        SYS_RT_SIGQUEUEINFO,
        pid as i64,
        libc::SIGUSR1 as i64,
        &info_user as *const _,
    );
    let q_user_eperm = q_user == -1 && errno() == libc::EPERM;

    let tg_user = libc::syscall(
        SYS_RT_TGSIGQUEUEINFO,
        pid as i64,
        tid as i64,
        libc::SIGUSR1 as i64,
        &info_user as *const _,
    );
    let tg_user_eperm = tg_user == -1 && errno() == libc::EPERM;

    // 3.4 si_signo mismatch between argument and siginfo_t -> EINVAL
    let mut info_mismatch: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
    info_mismatch.si_signo = libc::SIGUSR2; // Mismatch with SIGUSR1
    info_mismatch.si_code = -1; // SI_QUEUE

    let q_mismatch = libc::syscall(
        SYS_RT_SIGQUEUEINFO,
        pid as i64,
        libc::SIGUSR1 as i64,
        &info_mismatch as *const _,
    );
    let q_mismatch_einval = q_mismatch == -1 && errno() == libc::EINVAL;

    let tg_mismatch = libc::syscall(
        SYS_RT_TGSIGQUEUEINFO,
        pid as i64,
        tid as i64,
        libc::SIGUSR1 as i64,
        &info_mismatch as *const _,
    );
    let tg_mismatch_einval = tg_mismatch == -1 && errno() == libc::EINVAL;

    // 3.5 Valid queueing with SI_QUEUE payload round-trip
    let rt_sig = libc::SIGRTMIN();
    block_signal(rt_sig);

    let mut info_valid: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
    let info_bytes = &mut info_valid as *mut libc::siginfo_t as *mut u8;
    core::ptr::write(info_bytes.add(0) as *mut i32, rt_sig);
    core::ptr::write(info_bytes.add(8) as *mut i32, -1); // SI_QUEUE
    core::ptr::write(info_bytes.add(0x18) as *mut i32, 0x1234_5678); // sival_int payload

    let q_valid = libc::syscall(
        SYS_RT_SIGQUEUEINFO,
        pid as i64,
        rt_sig as i64,
        &info_valid as *const _,
    );
    let q_valid_ok = q_valid == 0;

    let mut set_rt: libc::sigset_t = MaybeUninit::zeroed().assume_init();
    libc::sigemptyset(&mut set_rt);
    libc::sigaddset(&mut set_rt, rt_sig);

    let zero_ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut info_out: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
    let rc_recv = libc::syscall(
        SYS_RT_SIGTIMEDWAIT,
        &set_rt as *const _,
        &mut info_out as *mut _,
        &zero_ts as *const _,
        8usize,
    ) as i32;

    let out_bytes = &info_out as *const libc::siginfo_t as *const u8;
    let sival_received = core::ptr::read(out_bytes.add(0x18) as *const i32);

    let payload_ok = rc_recv == rt_sig
        && info_out.si_signo == rt_sig
        && info_out.si_code == -1
        && sival_received == 0x1234_5678;

    unblock_signal(rt_sig);

    report!(
        sigqueue_invalid_signum_einval =
            q_neg_einval && q_zero_einval && q_large_einval && tg_neg_einval && tg_large_einval,
        sigqueue_nonexistent_target_esrch =
            q_bad_pid_esrch && tg_bad_tid_esrch && tg_bad_tgid_esrch,
        sigqueue_user_code_security_eperm = q_user_eperm && tg_user_eperm,
        sigqueue_signo_mismatch_einval = q_mismatch_einval && tg_mismatch_einval,
        sigqueue_si_queue_payload_roundtrip = q_valid_ok && payload_ok,
    );
}

// -----------------------------------------------------------------------------
// 4. Signal Mask and Disposition Constraints Matrix
// -----------------------------------------------------------------------------

unsafe fn test_signal_mask_matrix() {
    // 4.1 SIGKILL and SIGSTOP cannot be blocked
    let mut unblockable: libc::sigset_t = MaybeUninit::zeroed().assume_init();
    libc::sigemptyset(&mut unblockable);
    libc::sigaddset(&mut unblockable, libc::SIGKILL);
    libc::sigaddset(&mut unblockable, libc::SIGSTOP);

    let setmask_rc = libc::sigprocmask(libc::SIG_BLOCK, &unblockable, std::ptr::null_mut());
    let kill_not_blocked = !is_blocked(libc::SIGKILL);
    let stop_not_blocked = !is_blocked(libc::SIGSTOP);

    // 4.2 Invalid `how` in sigprocmask -> EINVAL
    let bad_how_rc = libc::sigprocmask(99999, &unblockable, std::ptr::null_mut());
    let bad_how_einval = bad_how_rc == -1 && errno() == libc::EINVAL;

    // 4.3 sigpending with NULL pointer -> EFAULT
    let pend_null_rc = libc::sigpending(std::ptr::null_mut());
    let pend_null_efault = pend_null_rc == -1 && errno() == libc::EFAULT;

    // 4.4 sigsuspend with invalid pointer -> EFAULT
    let ss_null_rc = libc::syscall(
        SYS_RT_SIGSUSPEND,
        std::ptr::null::<libc::sigset_t>(),
        8usize,
    );
    let ss_null_efault = ss_null_rc == -1 && errno() == libc::EFAULT;

    report!(
        sigmask_unblockable_signals = setmask_rc == 0 && kill_not_blocked && stop_not_blocked,
        sigprocmask_invalid_how_einval = bad_how_einval,
        sigpending_null_pointer_efault = pend_null_efault,
        sigsuspend_null_pointer_efault = ss_null_efault,
    );
}

fn main() {
    unsafe {
        test_sigtimedwait_validation_matrix();
        test_synchronous_dequeue_matrix();
        test_sigqueueinfo_matrix();
        test_signal_mask_matrix();
    }
}
