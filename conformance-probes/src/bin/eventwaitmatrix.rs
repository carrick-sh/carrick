//! Event and wait flag, error, and deadline conformance matrix probe.
//!
//! Exercises Linux flag validation, invalid timespec errors, readiness transitions,
//! and non-blocking deadline semantics across:
//! 1. Clock & Timerfd Matrix: `clock_adjtime`, `clock_settime`, `timerfd_create`,
//!    `timerfd_settime`, `timerfd_gettime`, `timer_settime`, and `timer_gettime`.
//! 2. Futex Validation & Zero-Timeout Matrix: `FUTEX_WAIT`, `FUTEX_WAIT_BITSET`,
//!    `FUTEX_CLOCK_REALTIME`, timespec validation, alignment checks, and immediate timeouts.
//! 3. POSIX Message Queue Timed Matrix: `mq_timedsend`, `mq_timedreceive`, access modes,
//!    buffer size constraints, priority limits, timespec validation, and empty/full timeouts.
//! 4. Poll, Ppoll, Select, Pselect Readiness Matrix: timespec validation, negative fds,
//!    negative nfds, and zero-timeout non-blocking probes across poll/ppoll/select/pselect6/epoll.
//!
//! Deterministic key=value output only. Short monotonic deadlines and non-blocking descriptors
//! ensure broken implementations fail fast without hanging the test harness.

use conformance_probes::{errno, report};
use std::ffi::CString;
use std::mem::MaybeUninit;

const SYS_CLOCK_ADJTIME: libc::c_long = libc::SYS_clock_adjtime;
const SYS_TIMERFD_CREATE: libc::c_long = libc::SYS_timerfd_create;
const SYS_TIMERFD_SETTIME: libc::c_long = libc::SYS_timerfd_settime;
const SYS_TIMERFD_GETTIME: libc::c_long = libc::SYS_timerfd_gettime;
const SYS_FUTEX: libc::c_long = libc::SYS_futex;
const SYS_MQ_OPEN: libc::c_long = libc::SYS_mq_open;
const SYS_MQ_UNLINK: libc::c_long = libc::SYS_mq_unlink;
const SYS_MQ_TIMEDSEND: libc::c_long = libc::SYS_mq_timedsend;
const SYS_MQ_TIMEDRECEIVE: libc::c_long = libc::SYS_mq_timedreceive;
const SYS_PPOLL: libc::c_long = libc::SYS_ppoll;
const SYS_PSELECT6: libc::c_long = libc::SYS_pselect6;

const TFD_TIMER_ABSTIME: libc::c_int = 1;
const TFD_TIMER_CANCEL_ON_SET: libc::c_int = 2;
const TFD_CLOEXEC: libc::c_int = libc::O_CLOEXEC;
const TFD_NONBLOCK: libc::c_int = libc::O_NONBLOCK;

const FUTEX_WAIT: libc::c_long = 0;
const FUTEX_WAIT_BITSET: libc::c_long = 9;
const FUTEX_PRIVATE_FLAG: libc::c_long = 128;
const FUTEX_CLOCK_REALTIME: libc::c_long = 256;
const FUTEX_BITSET_MATCH_ANY: u32 = 0xffff_ffff;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct MqAttr {
    mq_flags: i64,
    mq_maxmsg: i64,
    mq_msgsize: i64,
    mq_curmsgs: i64,
    __reserved: [i64; 4],
}

// -----------------------------------------------------------------------------
// 1. Clock & Timerfd Matrix
// -----------------------------------------------------------------------------

unsafe fn test_clock_and_timerfd_matrix() {
    let mut tx: libc::timex = MaybeUninit::zeroed().assume_init();

    // 1.1 clock_adjtime on non-adjustable clockids -> EINVAL
    let adj_mono = libc::syscall(SYS_CLOCK_ADJTIME, libc::CLOCK_MONOTONIC, &mut tx as *mut _);
    let adj_mono_err = if adj_mono == -1 { errno() } else { 0 };

    let adj_boot = libc::syscall(SYS_CLOCK_ADJTIME, libc::CLOCK_BOOTTIME, &mut tx as *mut _);
    let adj_boot_err = if adj_boot == -1 { errno() } else { 0 };

    let adj_cpu = libc::syscall(
        SYS_CLOCK_ADJTIME,
        libc::CLOCK_PROCESS_CPUTIME_ID,
        &mut tx as *mut _,
    );
    let adj_cpu_err = if adj_cpu == -1 { errno() } else { 0 };

    let adj_bad = libc::syscall(SYS_CLOCK_ADJTIME, 99999i32, &mut tx as *mut _);
    let adj_bad_err = if adj_bad == -1 { errno() } else { 0 };

    let adj_null = libc::syscall(
        SYS_CLOCK_ADJTIME,
        libc::CLOCK_REALTIME,
        std::ptr::null_mut::<libc::timex>(),
    );
    let adj_null_err = if adj_null == -1 { errno() } else { 0 };

    report!(
        clock_adjtime_monotonic_einval = adj_mono == -1 && adj_mono_err == libc::EINVAL,
        clock_adjtime_boottime_einval = adj_boot == -1 && adj_boot_err == libc::EINVAL,
        clock_adjtime_process_cputime_einval = adj_cpu == -1 && adj_cpu_err == libc::EINVAL,
        clock_adjtime_invalid_clockid_einval = adj_bad == -1 && adj_bad_err == libc::EINVAL,
        clock_adjtime_null_timex_efault = adj_null == -1 && adj_null_err == libc::EFAULT,
    );

    // 1.2 clock_settime on non-settable clockids and invalid timespec -> EINVAL / EFAULT
    let valid_ts = libc::timespec {
        tv_sec: 1000,
        tv_nsec: 0,
    };
    let set_mono = libc::syscall(
        libc::SYS_clock_settime,
        libc::CLOCK_MONOTONIC,
        &valid_ts as *const _,
    );
    let set_mono_err = if set_mono == -1 { errno() } else { 0 };

    let set_bad = libc::syscall(libc::SYS_clock_settime, 99999i32, &valid_ts as *const _);
    let set_bad_err = if set_bad == -1 { errno() } else { 0 };

    let bad_ts_neg = libc::timespec {
        tv_sec: 1000,
        tv_nsec: -1,
    };
    let set_nsec_neg = libc::syscall(
        libc::SYS_clock_settime,
        libc::CLOCK_REALTIME,
        &bad_ts_neg as *const _,
    );
    let set_nsec_neg_err = if set_nsec_neg == -1 { errno() } else { 0 };

    let bad_ts_over = libc::timespec {
        tv_sec: 1000,
        tv_nsec: 1_000_000_000,
    };
    let set_nsec_over = libc::syscall(
        libc::SYS_clock_settime,
        libc::CLOCK_REALTIME,
        &bad_ts_over as *const _,
    );
    let set_nsec_over_err = if set_nsec_over == -1 { errno() } else { 0 };

    let set_null = libc::syscall(
        libc::SYS_clock_settime,
        libc::CLOCK_REALTIME,
        std::ptr::null::<libc::timespec>(),
    );
    let set_null_err = if set_null == -1 { errno() } else { 0 };

    report!(
        clock_settime_monotonic_einval = set_mono == -1 && set_mono_err == libc::EINVAL,
        clock_settime_invalid_clockid_einval = set_bad == -1 && set_bad_err == libc::EINVAL,
        clock_settime_negative_nsec_einval = set_nsec_neg == -1 && set_nsec_neg_err == libc::EINVAL,
        clock_settime_overflow_nsec_einval = set_nsec_over == -1 && set_nsec_over_err == libc::EINVAL,
        clock_settime_null_timespec_efault = set_null == -1 && set_null_err == libc::EFAULT,
    );

    // 1.3 timerfd_create flags and clockids
    let tfd_nb_clo = libc::syscall(
        SYS_TIMERFD_CREATE,
        libc::CLOCK_MONOTONIC,
        TFD_NONBLOCK | TFD_CLOEXEC,
    ) as i32;
    let tfd_nb_clo_ok = tfd_nb_clo >= 0;
    let (tfd_is_nb, tfd_is_clo) = if tfd_nb_clo_ok {
        let fl = libc::fcntl(tfd_nb_clo, libc::F_GETFL);
        let fd_fl = libc::fcntl(tfd_nb_clo, libc::F_GETFD);
        (
            (fl & libc::O_NONBLOCK) != 0,
            (fd_fl & libc::FD_CLOEXEC) != 0,
        )
    } else {
        (false, false)
    };
    if tfd_nb_clo >= 0 {
        libc::close(tfd_nb_clo);
    }

    let tfd_real = libc::syscall(SYS_TIMERFD_CREATE, libc::CLOCK_REALTIME, 0) as i32;
    let tfd_real_ok = tfd_real >= 0;
    if tfd_real >= 0 {
        libc::close(tfd_real);
    }

    let tfd_boot = libc::syscall(SYS_TIMERFD_CREATE, libc::CLOCK_BOOTTIME, 0) as i32;
    let tfd_boot_ok = tfd_boot >= 0;
    if tfd_boot >= 0 {
        libc::close(tfd_boot);
    }

    let tfd_cpu = libc::syscall(SYS_TIMERFD_CREATE, libc::CLOCK_PROCESS_CPUTIME_ID, 0) as i32;
    let tfd_cpu_err = if tfd_cpu == -1 { errno() } else { 0 };
    if tfd_cpu >= 0 {
        libc::close(tfd_cpu);
    }

    let tfd_bad_clk = libc::syscall(SYS_TIMERFD_CREATE, 99999i32, 0) as i32;
    let tfd_bad_clk_err = if tfd_bad_clk == -1 { errno() } else { 0 };
    if tfd_bad_clk >= 0 {
        libc::close(tfd_bad_clk);
    }

    let tfd_bad_fl =
        libc::syscall(SYS_TIMERFD_CREATE, libc::CLOCK_MONOTONIC, 0x1000_0000i32) as i32;
    let tfd_bad_fl_err = if tfd_bad_fl == -1 { errno() } else { 0 };
    if tfd_bad_fl >= 0 {
        libc::close(tfd_bad_fl);
    }

    report!(
        timerfd_create_nonblock_cloexec_ok = tfd_nb_clo_ok,
        timerfd_create_is_nonblock = tfd_is_nb,
        timerfd_create_is_cloexec = tfd_is_clo,
        timerfd_create_realtime_ok = tfd_real_ok,
        timerfd_create_boottime_ok = tfd_boot_ok,
        timerfd_create_cputime_einval = tfd_cpu == -1 && tfd_cpu_err == libc::EINVAL,
        timerfd_create_invalid_clockid_einval = tfd_bad_clk == -1 && tfd_bad_clk_err == libc::EINVAL,
        timerfd_create_invalid_flags_einval = tfd_bad_fl == -1 && tfd_bad_fl_err == libc::EINVAL,
    );

    // 1.4 timerfd_settime & timerfd_gettime error matrix and disarm lifecycle
    let tfd = libc::syscall(SYS_TIMERFD_CREATE, libc::CLOCK_MONOTONIC, TFD_NONBLOCK) as i32;
    let mut pipe_fds = [-1i32; 2];
    libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_NONBLOCK);

    let valid_spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 100,
            tv_nsec: 0,
        },
    };

    let s_bad_fl = libc::syscall(
        SYS_TIMERFD_SETTIME,
        tfd,
        0x1000i32,
        &valid_spec as *const _,
        std::ptr::null_mut::<libc::itimerspec>(),
    );
    let s_bad_fl_err = if s_bad_fl == -1 { errno() } else { 0 };

    let s_cancel_no_abs = libc::syscall(
        SYS_TIMERFD_SETTIME,
        tfd,
        TFD_TIMER_CANCEL_ON_SET,
        &valid_spec as *const _,
        std::ptr::null_mut::<libc::itimerspec>(),
    );
    let s_cancel_no_abs_err = if s_cancel_no_abs == -1 { errno() } else { 0 };

    let s_cancel_mono = libc::syscall(
        SYS_TIMERFD_SETTIME,
        tfd,
        TFD_TIMER_CANCEL_ON_SET | TFD_TIMER_ABSTIME,
        &valid_spec as *const _,
        std::ptr::null_mut::<libc::itimerspec>(),
    );
    let s_cancel_mono_err = if s_cancel_mono == -1 { errno() } else { 0 };

    let bad_val_spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 1,
            tv_nsec: 1_000_000_000,
        },
    };
    let s_bad_val = libc::syscall(
        SYS_TIMERFD_SETTIME,
        tfd,
        0,
        &bad_val_spec as *const _,
        std::ptr::null_mut::<libc::itimerspec>(),
    );
    let s_bad_val_err = if s_bad_val == -1 { errno() } else { 0 };

    let bad_int_spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: -1,
        },
        it_value: libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        },
    };
    let s_bad_int = libc::syscall(
        SYS_TIMERFD_SETTIME,
        tfd,
        0,
        &bad_int_spec as *const _,
        std::ptr::null_mut::<libc::itimerspec>(),
    );
    let s_bad_int_err = if s_bad_int == -1 { errno() } else { 0 };

    let s_pipe = libc::syscall(
        SYS_TIMERFD_SETTIME,
        pipe_fds[0],
        0,
        &valid_spec as *const _,
        std::ptr::null_mut::<libc::itimerspec>(),
    );
    let s_pipe_err = if s_pipe == -1 { errno() } else { 0 };

    let s_badf = libc::syscall(
        SYS_TIMERFD_SETTIME,
        -1,
        0,
        &valid_spec as *const _,
        std::ptr::null_mut::<libc::itimerspec>(),
    );
    let s_badf_err = if s_badf == -1 { errno() } else { 0 };

    let mut cur_spec: libc::itimerspec = MaybeUninit::zeroed().assume_init();
    let g_pipe = libc::syscall(
        SYS_TIMERFD_GETTIME,
        pipe_fds[0],
        &mut cur_spec as *mut libc::itimerspec,
    );
    let g_pipe_err = if g_pipe == -1 { errno() } else { 0 };

    let g_badf = libc::syscall(
        SYS_TIMERFD_GETTIME,
        -1,
        &mut cur_spec as *mut libc::itimerspec,
    );
    let g_badf_err = if g_badf == -1 { errno() } else { 0 };

    // Arm, then disarm and verify old_value and gettime
    libc::syscall(
        SYS_TIMERFD_SETTIME,
        tfd,
        0,
        &valid_spec as *const _,
        std::ptr::null_mut::<libc::itimerspec>(),
    );
    let disarm_spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    let mut old_spec: libc::itimerspec = MaybeUninit::zeroed().assume_init();
    let s_disarm = libc::syscall(
        SYS_TIMERFD_SETTIME,
        tfd,
        0,
        &disarm_spec as *const _,
        &mut old_spec as *mut _,
    );
    let disarm_had_old =
        s_disarm == 0 && (old_spec.it_value.tv_sec > 0 || old_spec.it_value.tv_nsec > 0);

    let g_disarmed = libc::syscall(SYS_TIMERFD_GETTIME, tfd, &mut cur_spec as *mut _);
    let gettime_zero = g_disarmed == 0
        && cur_spec.it_value.tv_sec == 0
        && cur_spec.it_value.tv_nsec == 0
        && cur_spec.it_interval.tv_sec == 0
        && cur_spec.it_interval.tv_nsec == 0;

    let mut exp_cnt = 0u64;
    let r_unfired = libc::read(tfd, &mut exp_cnt as *mut _ as *mut libc::c_void, 8);
    let r_unfired_err = if r_unfired == -1 { errno() } else { 0 };

    libc::close(tfd);
    libc::close(pipe_fds[0]);
    libc::close(pipe_fds[1]);

    report!(
        timerfd_settime_invalid_flags_einval = s_bad_fl == -1 && s_bad_fl_err == libc::EINVAL,
        timerfd_settime_cancel_without_abstime_einval =
            s_cancel_no_abs == -1 && s_cancel_no_abs_err == libc::EINVAL,
        timerfd_settime_cancel_on_monotonic_einval =
            s_cancel_mono == -1 && s_cancel_mono_err == libc::EINVAL,
        timerfd_settime_bad_value_nsec_einval = s_bad_val == -1 && s_bad_val_err == libc::EINVAL,
        timerfd_settime_bad_interval_nsec_einval =
            s_bad_int == -1 && s_bad_int_err == libc::EINVAL,
        timerfd_settime_pipe_fd_einval = s_pipe == -1 && s_pipe_err == libc::EINVAL,
        timerfd_settime_bad_fd_ebadf = s_badf == -1 && s_badf_err == libc::EBADF,
        timerfd_gettime_pipe_fd_einval = g_pipe == -1 && g_pipe_err == libc::EINVAL,
        timerfd_gettime_bad_fd_ebadf = g_badf == -1 && g_badf_err == libc::EBADF,
        timerfd_disarm_returned_old_value = disarm_had_old,
        timerfd_disarm_gettime_zero = gettime_zero,
        timerfd_unfired_nonblock_read_eagain = r_unfired == -1 && r_unfired_err == libc::EAGAIN,
    );

    // 1.5 Raw timer syscalls with an invalid kernel timer ID. glibc's public
    // timer_t is an implementation pointer, so passing a fabricated timer_t to
    // its wrapper dereferences userspace garbage instead of testing Linux.
    let bad_timer_id = -1i32;
    let t_set_bad = libc::syscall(
        libc::SYS_timer_settime,
        bad_timer_id,
        0,
        &valid_spec as *const _,
        std::ptr::null_mut::<libc::itimerspec>(),
    );
    let t_set_bad_err = if t_set_bad == -1 { errno() } else { 0 };

    let t_get_bad = libc::syscall(
        libc::SYS_timer_gettime,
        bad_timer_id,
        &mut cur_spec as *mut _,
    );
    let t_get_bad_err = if t_get_bad == -1 { errno() } else { 0 };

    let t_del_bad = libc::syscall(libc::SYS_timer_delete, bad_timer_id);
    let t_del_bad_err = if t_del_bad == -1 { errno() } else { 0 };

    let t_ovr_bad = libc::syscall(libc::SYS_timer_getoverrun, bad_timer_id);
    let t_ovr_bad_err = if t_ovr_bad == -1 { errno() } else { 0 };

    report!(
        timer_settime_invalid_id_einval = t_set_bad == -1 && t_set_bad_err == libc::EINVAL,
        timer_gettime_invalid_id_einval = t_get_bad == -1 && t_get_bad_err == libc::EINVAL,
        timer_delete_invalid_id_einval = t_del_bad == -1 && t_del_bad_err == libc::EINVAL,
        timer_getoverrun_invalid_id_einval = t_ovr_bad == -1 && t_ovr_bad_err == libc::EINVAL,
    );
}

// -----------------------------------------------------------------------------
// 2. Futex Validation & Zero-Timeout Matrix
// -----------------------------------------------------------------------------

unsafe fn test_futex_wait_matrix() {
    let mut word: u32 = 42;

    // 2.1 FUTEX_WAIT timespec validation
    let bad_ts_neg = libc::timespec {
        tv_sec: 0,
        tv_nsec: -1,
    };
    let rc_neg = libc::syscall(
        SYS_FUTEX,
        &mut word as *mut u32,
        FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
        42i64,
        &bad_ts_neg as *const _,
        std::ptr::null::<u32>(),
        0i64,
    );
    let rc_neg_err = if rc_neg == -1 { errno() } else { 0 };

    let bad_ts_over = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000_000,
    };
    let rc_over = libc::syscall(
        SYS_FUTEX,
        &mut word as *mut u32,
        FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
        42i64,
        &bad_ts_over as *const _,
        std::ptr::null::<u32>(),
        0i64,
    );
    let rc_over_err = if rc_over == -1 { errno() } else { 0 };

    // Every case below that should reject before waiting still carries a zero
    // deadline. If Carrick fails to validate the earlier argument, the probe
    // must report a fast mismatch instead of hanging the conformance process.
    let zero_ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    // 2.2 Unaligned futex address -> EINVAL
    let raw_buf = [0u8; 8];
    let unaligned_ptr = raw_buf.as_ptr().add(1) as *mut u32;
    let rc_unaligned = libc::syscall(
        SYS_FUTEX,
        unaligned_ptr,
        FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
        0i64,
        &zero_ts as *const _,
        std::ptr::null::<u32>(),
        0i64,
    );
    let rc_unaligned_err = if rc_unaligned == -1 { errno() } else { 0 };

    // 2.3 Zero-timeout FUTEX_WAIT with matching value -> immediate ETIMEDOUT
    let rc_zero = libc::syscall(
        SYS_FUTEX,
        &mut word as *mut u32,
        FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
        42i64,
        &zero_ts as *const _,
        std::ptr::null::<u32>(),
        0i64,
    );
    let rc_zero_err = if rc_zero == -1 { errno() } else { 0 };

    // 2.4 FUTEX_WAIT_BITSET validation: bitset=0 -> EINVAL, bad timespec -> EINVAL, past CLOCK_REALTIME -> ETIMEDOUT
    let rc_bitset_zero = libc::syscall(
        SYS_FUTEX,
        &mut word as *mut u32,
        FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG,
        42i64,
        &zero_ts as *const _,
        std::ptr::null::<u32>(),
        0u32 as i64, // bitset 0 is invalid
    );
    let rc_bitset_zero_err = if rc_bitset_zero == -1 { errno() } else { 0 };

    let rc_bitset_bad_ts = libc::syscall(
        SYS_FUTEX,
        &mut word as *mut u32,
        FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG,
        42i64,
        &bad_ts_over as *const _,
        std::ptr::null::<u32>(),
        FUTEX_BITSET_MATCH_ANY as i64,
    );
    let rc_bitset_bad_ts_err = if rc_bitset_bad_ts == -1 { errno() } else { 0 };

    let past_realtime = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    let rc_bitset_past_realtime = libc::syscall(
        SYS_FUTEX,
        &mut word as *mut u32,
        FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME | FUTEX_PRIVATE_FLAG,
        42i64,
        &past_realtime as *const _,
        std::ptr::null::<u32>(),
        FUTEX_BITSET_MATCH_ANY as i64,
    );
    let rc_bitset_past_realtime_err = if rc_bitset_past_realtime == -1 {
        errno()
    } else {
        0
    };

    // 2.5 Invalid futex op -> ENOSYS
    let rc_inv_op = libc::syscall(
        SYS_FUTEX,
        &mut word as *mut u32,
        99999i64,
        0i64,
        std::ptr::null::<libc::timespec>(),
        std::ptr::null::<u32>(),
        0i64,
    );
    let rc_inv_op_err = if rc_inv_op == -1 { errno() } else { 0 };

    report!(
        futex_wait_negative_nsec_einval = rc_neg == -1 && rc_neg_err == libc::EINVAL,
        futex_wait_overflow_nsec_einval = rc_over == -1 && rc_over_err == libc::EINVAL,
        futex_wait_unaligned_address_einval =
            rc_unaligned == -1 && rc_unaligned_err == libc::EINVAL,
        futex_wait_zero_timeout_etimedout = rc_zero == -1 && rc_zero_err == libc::ETIMEDOUT,
        futex_wait_bitset_zero_mask_einval =
            rc_bitset_zero == -1 && rc_bitset_zero_err == libc::EINVAL,
        futex_wait_bitset_bad_timespec_einval =
            rc_bitset_bad_ts == -1 && rc_bitset_bad_ts_err == libc::EINVAL,
        futex_wait_bitset_past_realtime_etimedout =
            rc_bitset_past_realtime == -1 && rc_bitset_past_realtime_err == libc::ETIMEDOUT,
        futex_invalid_op_enosys = rc_inv_op == -1 && rc_inv_op_err == libc::ENOSYS,
    );
}

// -----------------------------------------------------------------------------
// 3. POSIX Message Queue Timed Matrix
// -----------------------------------------------------------------------------

unsafe fn test_mq_timed_matrix() {
    let pid = libc::getpid();
    let qname = format!("carrick_ev_mq_{pid}");
    let cqname = CString::new(qname.as_str()).unwrap();

    // Clean up if already exists
    libc::syscall(SYS_MQ_UNLINK, cqname.as_ptr());

    let attr = MqAttr {
        mq_maxmsg: 2,
        mq_msgsize: 32,
        ..Default::default()
    };

    let mqd = libc::syscall(
        SYS_MQ_OPEN,
        cqname.as_ptr(),
        libc::O_CREAT | libc::O_RDWR | libc::O_NONBLOCK,
        0o600,
        &attr as *const MqAttr as usize,
    ) as i32;
    let mq_open_ok = mqd >= 0;

    let mut pipe_fds = [-1i32; 2];
    libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_NONBLOCK);

    let buf = [0x41u8; 64];
    let mut recv_buf = [0u8; 64];
    let mut prio = 0u32;
    let past_ts = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    let bad_ts_neg = libc::timespec {
        tv_sec: 100,
        tv_nsec: -1,
    };
    let bad_ts_over = libc::timespec {
        tv_sec: 100,
        tv_nsec: 1_000_000_000,
    };

    // 3.1 Invalid descriptor & non-mq descriptors -> EBADF
    let s_badf = libc::syscall(
        SYS_MQ_TIMEDSEND,
        -1,
        buf.as_ptr(),
        4usize,
        0u32,
        &past_ts as *const _,
    );
    let s_badf_err = if s_badf == -1 { errno() } else { 0 };

    let r_badf = libc::syscall(
        SYS_MQ_TIMEDRECEIVE,
        -1,
        recv_buf.as_mut_ptr(),
        32usize,
        &mut prio as *mut _,
        &past_ts as *const _,
    );
    let r_badf_err = if r_badf == -1 { errno() } else { 0 };

    let s_pipe = libc::syscall(
        SYS_MQ_TIMEDSEND,
        pipe_fds[1],
        buf.as_ptr(),
        4usize,
        0u32,
        &past_ts as *const _,
    );
    let s_pipe_err = if s_pipe == -1 { errno() } else { 0 };

    let r_pipe = libc::syscall(
        SYS_MQ_TIMEDRECEIVE,
        pipe_fds[0],
        recv_buf.as_mut_ptr(),
        32usize,
        &mut prio as *mut _,
        &past_ts as *const _,
    );
    let r_pipe_err = if r_pipe == -1 { errno() } else { 0 };

    report!(
        mq_open_ok = mq_open_ok,
        mq_timedsend_bad_fd_ebadf = s_badf == -1 && s_badf_err == libc::EBADF,
        mq_timedreceive_bad_fd_ebadf = r_badf == -1 && r_badf_err == libc::EBADF,
        mq_timedsend_pipe_fd_ebadf = s_pipe == -1 && s_pipe_err == libc::EBADF,
        mq_timedreceive_pipe_fd_ebadf = r_pipe == -1 && r_pipe_err == libc::EBADF,
    );

    // 3.2 Access mode mismatch
    let rd_mqd = libc::syscall(
        SYS_MQ_OPEN,
        cqname.as_ptr(),
        libc::O_RDONLY | libc::O_NONBLOCK,
        0,
        0usize,
    ) as i32;
    let s_rdonly = libc::syscall(
        SYS_MQ_TIMEDSEND,
        rd_mqd,
        buf.as_ptr(),
        4usize,
        0u32,
        &past_ts as *const _,
    );
    let s_rdonly_err = if s_rdonly == -1 { errno() } else { 0 };
    if rd_mqd >= 0 {
        libc::close(rd_mqd);
    }

    let wr_mqd = libc::syscall(
        SYS_MQ_OPEN,
        cqname.as_ptr(),
        libc::O_WRONLY | libc::O_NONBLOCK,
        0,
        0usize,
    ) as i32;
    let r_wronly = libc::syscall(
        SYS_MQ_TIMEDRECEIVE,
        wr_mqd,
        recv_buf.as_mut_ptr(),
        32usize,
        &mut prio as *mut _,
        &past_ts as *const _,
    );
    let r_wronly_err = if r_wronly == -1 { errno() } else { 0 };
    if wr_mqd >= 0 {
        libc::close(wr_mqd);
    }

    report!(
        mq_timedsend_rdonly_ebadf = s_rdonly == -1 && s_rdonly_err == libc::EBADF,
        mq_timedreceive_wronly_ebadf = r_wronly == -1 && r_wronly_err == libc::EBADF,
    );

    // 3.3 Message size constraints: send > mq_msgsize -> EMSGSIZE, recv < mq_msgsize -> EMSGSIZE
    let s_toolarge = libc::syscall(
        SYS_MQ_TIMEDSEND,
        mqd,
        buf.as_ptr(),
        33usize, // > 32
        0u32,
        &past_ts as *const _,
    );
    let s_toolarge_err = if s_toolarge == -1 { errno() } else { 0 };

    let r_toosmall = libc::syscall(
        SYS_MQ_TIMEDRECEIVE,
        mqd,
        recv_buf.as_mut_ptr(),
        16usize, // < 32
        &mut prio as *mut _,
        &past_ts as *const _,
    );
    let r_toosmall_err = if r_toosmall == -1 { errno() } else { 0 };

    // 3.4 Priority validation: prio >= 32768 -> EINVAL
    let s_bad_prio = libc::syscall(
        SYS_MQ_TIMEDSEND,
        mqd,
        buf.as_ptr(),
        4usize,
        32768u32,
        &past_ts as *const _,
    );
    let s_bad_prio_err = if s_bad_prio == -1 { errno() } else { 0 };

    report!(
        mq_timedsend_msg_too_large_emsgsize =
            s_toolarge == -1 && s_toolarge_err == libc::EMSGSIZE,
        mq_timedreceive_buffer_too_small_emsgsize =
            r_toosmall == -1 && r_toosmall_err == libc::EMSGSIZE,
        mq_timedsend_invalid_prio_einval = s_bad_prio == -1 && s_bad_prio_err == libc::EINVAL,
    );

    // 3.5 Timespec validation -> EINVAL
    let s_ts_neg = libc::syscall(
        SYS_MQ_TIMEDSEND,
        mqd,
        buf.as_ptr(),
        4usize,
        0u32,
        &bad_ts_neg as *const _,
    );
    let s_ts_neg_err = if s_ts_neg == -1 { errno() } else { 0 };

    let s_ts_over = libc::syscall(
        SYS_MQ_TIMEDSEND,
        mqd,
        buf.as_ptr(),
        4usize,
        0u32,
        &bad_ts_over as *const _,
    );
    let s_ts_over_err = if s_ts_over == -1 { errno() } else { 0 };

    let r_ts_neg = libc::syscall(
        SYS_MQ_TIMEDRECEIVE,
        mqd,
        recv_buf.as_mut_ptr(),
        32usize,
        &mut prio as *mut _,
        &bad_ts_neg as *const _,
    );
    let r_ts_neg_err = if r_ts_neg == -1 { errno() } else { 0 };

    let r_ts_over = libc::syscall(
        SYS_MQ_TIMEDRECEIVE,
        mqd,
        recv_buf.as_mut_ptr(),
        32usize,
        &mut prio as *mut _,
        &bad_ts_over as *const _,
    );
    let r_ts_over_err = if r_ts_over == -1 { errno() } else { 0 };

    report!(
        mq_timedsend_negative_nsec_einval = s_ts_neg == -1 && s_ts_neg_err == libc::EINVAL,
        mq_timedsend_overflow_nsec_einval = s_ts_over == -1 && s_ts_over_err == libc::EINVAL,
        mq_timedreceive_negative_nsec_einval = r_ts_neg == -1 && r_ts_neg_err == libc::EINVAL,
        mq_timedreceive_overflow_nsec_einval = r_ts_over == -1 && r_ts_over_err == libc::EINVAL,
    );

    // 3.6 Immediate timeouts on empty / full queues
    let r_empty_past = libc::syscall(
        SYS_MQ_TIMEDRECEIVE,
        mqd,
        recv_buf.as_mut_ptr(),
        32usize,
        &mut prio as *mut _,
        &past_ts as *const _,
    );
    let r_empty_past_err = if r_empty_past == -1 { errno() } else { 0 };

    // Fill queue to maxmsg=2
    let s_msg1 = libc::syscall(
        SYS_MQ_TIMEDSEND,
        mqd,
        b"msg1".as_ptr(),
        4usize,
        1u32,
        0usize,
    );
    let s_msg2 = libc::syscall(
        SYS_MQ_TIMEDSEND,
        mqd,
        b"msg2".as_ptr(),
        4usize,
        2u32,
        0usize,
    );

    let s_full_past = libc::syscall(
        SYS_MQ_TIMEDSEND,
        mqd,
        b"msg3".as_ptr(),
        4usize,
        3u32,
        &past_ts as *const _,
    );
    let s_full_past_err = if s_full_past == -1 { errno() } else { 0 };

    // Drain queue
    let r1 = libc::syscall(
        SYS_MQ_TIMEDRECEIVE,
        mqd,
        recv_buf.as_mut_ptr(),
        32usize,
        &mut prio as *mut _,
        0usize,
    );
    let r2 = libc::syscall(
        SYS_MQ_TIMEDRECEIVE,
        mqd,
        recv_buf.as_mut_ptr(),
        32usize,
        &mut prio as *mut _,
        0usize,
    );

    if mqd >= 0 {
        libc::close(mqd);
    }
    libc::syscall(SYS_MQ_UNLINK, cqname.as_ptr());
    libc::close(pipe_fds[0]);
    libc::close(pipe_fds[1]);

    report!(
        mq_timedreceive_empty_past_etimedout =
            r_empty_past == -1 && r_empty_past_err == libc::ETIMEDOUT,
        mq_timedsend_fill_ok = s_msg1 == 0 && s_msg2 == 0,
        mq_timedsend_full_past_etimedout =
            s_full_past == -1 && s_full_past_err == libc::ETIMEDOUT,
        mq_timedreceive_drain_ok = r1 == 4 && r2 == 4,
    );
}

// -----------------------------------------------------------------------------
// 4. Poll, Ppoll, Select, Pselect Readiness Matrix
// -----------------------------------------------------------------------------

unsafe fn test_poll_select_ppoll_matrix() {
    let mut pipe_fds = [-1i32; 2];
    libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_NONBLOCK);
    let (rd, wr) = (pipe_fds[0], pipe_fds[1]);

    let mut pfd = libc::pollfd {
        fd: rd,
        events: libc::POLLIN,
        revents: 0,
    };

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
    let mut zero_tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };

    // 4.1 ppoll timespec validation
    let pp_neg = libc::syscall(
        SYS_PPOLL,
        &mut pfd as *mut _,
        1usize,
        &bad_ts_neg as *const _,
        std::ptr::null::<libc::sigset_t>(),
        8usize,
    );
    let pp_neg_err = if pp_neg == -1 { errno() } else { 0 };

    let pp_over = libc::syscall(
        SYS_PPOLL,
        &mut pfd as *mut _,
        1usize,
        &bad_ts_over as *const _,
        std::ptr::null::<libc::sigset_t>(),
        8usize,
    );
    let pp_over_err = if pp_over == -1 { errno() } else { 0 };

    report!(
        ppoll_negative_nsec_einval = pp_neg == -1 && pp_neg_err == libc::EINVAL,
        ppoll_overflow_nsec_einval = pp_over == -1 && pp_over_err == libc::EINVAL,
    );

    // 4.2 Negative fd handling in poll and ppoll (ignored, revents zeroed)
    let mut pfd_neg = libc::pollfd {
        fd: -1,
        events: libc::POLLIN | libc::POLLOUT,
        revents: 0x7fff,
    };
    let pp_neg_fd = libc::syscall(
        SYS_PPOLL,
        &mut pfd_neg as *mut _,
        1usize,
        &zero_ts as *const _,
        std::ptr::null::<libc::sigset_t>(),
        8usize,
    );
    let pp_neg_revents = pfd_neg.revents;

    pfd_neg.revents = 0x7fff;
    let poll_neg_fd = libc::poll(&mut pfd_neg as *mut _, 1, 0);
    let poll_neg_revents = pfd_neg.revents;

    report!(
        ppoll_negative_fd_ignored = pp_neg_fd == 0 && pp_neg_revents == 0,
        poll_negative_fd_ignored = poll_neg_fd == 0 && poll_neg_revents == 0,
    );

    // 4.3 pselect6 timespec validation
    let ps_neg = libc::syscall(
        SYS_PSELECT6,
        0i64,
        0i64,
        0i64,
        0i64,
        &bad_ts_neg as *const _,
        0i64,
    );
    let ps_neg_err = if ps_neg == -1 { errno() } else { 0 };

    let ps_over = libc::syscall(
        SYS_PSELECT6,
        0i64,
        0i64,
        0i64,
        0i64,
        &bad_ts_over as *const _,
        0i64,
    );
    let ps_over_err = if ps_over == -1 { errno() } else { 0 };

    report!(
        pselect6_negative_nsec_einval = ps_neg == -1 && ps_neg_err == libc::EINVAL,
        pselect6_overflow_nsec_einval = ps_over == -1 && ps_over_err == libc::EINVAL,
    );

    // 4.4 Negative nfds rejection
    let sel_neg = libc::select(
        -1,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut zero_tv,
    );
    let sel_neg_err = if sel_neg == -1 { errno() } else { 0 };

    let ps_neg_nfds = libc::syscall(
        SYS_PSELECT6,
        -1i64,
        0i64,
        0i64,
        0i64,
        &zero_ts as *const _,
        0i64,
    );
    let ps_neg_nfds_err = if ps_neg_nfds == -1 { errno() } else { 0 };

    report!(
        select_negative_nfds_einval = sel_neg == -1 && sel_neg_err == libc::EINVAL,
        pselect6_negative_nfds_einval = ps_neg_nfds == -1 && ps_neg_nfds_err == libc::EINVAL,
    );

    // 4.5 Zero-timeout non-blocking probe across event interfaces
    let mut rset: libc::fd_set = MaybeUninit::zeroed().assume_init();
    libc::FD_ZERO(&mut rset);
    libc::FD_SET(rd, &mut rset);

    let sel_zero = libc::select(
        rd + 1,
        &mut rset as *mut _,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut zero_tv,
    );

    libc::FD_ZERO(&mut rset);
    libc::FD_SET(rd, &mut rset);
    let ps_zero = libc::syscall(
        SYS_PSELECT6,
        (rd + 1) as i64,
        &mut rset as *mut _ as i64,
        0i64,
        0i64,
        &zero_ts as *const _ as i64,
        0i64,
    );

    pfd.revents = 0;
    let poll_zero = libc::poll(&mut pfd as *mut _, 1, 0);
    let poll_zero_revents = pfd.revents;

    pfd.revents = 0;
    let ppoll_zero = libc::syscall(
        SYS_PPOLL,
        &mut pfd as *mut _,
        1usize,
        &zero_ts as *const _,
        std::ptr::null::<libc::sigset_t>(),
        8usize,
    );
    let ppoll_zero_revents = pfd.revents;

    let ep = libc::epoll_create1(0);
    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: rd as u64,
    };
    libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, rd, &mut ev);

    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
    let ep_wait_zero = libc::epoll_wait(ep, events.as_mut_ptr(), 1, 0);

    let ep_pwait_zero = libc::epoll_pwait(ep, events.as_mut_ptr(), 1, 0, std::ptr::null());

    libc::close(ep);
    libc::close(rd);
    libc::close(wr);

    report!(
        select_zero_timeout_ready_zero = sel_zero == 0,
        pselect6_zero_timeout_ready_zero = ps_zero == 0,
        poll_zero_timeout_revents_zero = poll_zero == 0 && poll_zero_revents == 0,
        ppoll_zero_timeout_revents_zero = ppoll_zero == 0 && ppoll_zero_revents == 0,
        epoll_wait_zero_timeout_events_zero = ep_wait_zero == 0,
        epoll_pwait_zero_timeout_events_zero = ep_pwait_zero == 0,
    );
}

fn main() {
    unsafe {
        test_clock_and_timerfd_matrix();
        test_futex_wait_matrix();
        test_mq_timed_matrix();
        test_poll_select_ppoll_matrix();
    }
}
