//! Conformance probe for eventfd(2) and signalfd(2) state and lifecycle semantics.
//!
//! Covers:
//! 1. eventfd flags: `EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC` flag reflection
//!    via `fcntl` (`FD_CLOEXEC` and `O_NONBLOCK`).
//! 2. eventfd semaphore mode: decrement-one reads until `EAGAIN`.
//! 3. eventfd ordinary mode: aggregate-and-reset behavior.
//! 4. eventfd buffer size validation: short 4-byte read and write return `EINVAL`.
//! 5. eventfd value validation: writing `UINT64_MAX` returns `EINVAL`.
//! 6. eventfd overflow: nonblocking write exceeding max counter returns `EAGAIN`
//!    while preserving counter state.
//! 7. signalfd flags: `SFD_NONBLOCK | SFD_CLOEXEC` flag reflection with blocked signals.
//! 8. signalfd mask update: updating mask on an existing fd returns the same fd.
//! 9. signalfd batch drain: queued signals drained as exact `signalfd_siginfo` records.
//! 10. signalfd nonblocking drain: empty read returns `EAGAIN`.
//! 11. signalfd buffer size validation: short buffer read returns `EINVAL`.
//! 12. Safe lifecycle: original thread signal mask restored and all fds closed.

use conformance_probes::{arm_alarm_ms, disarm_alarm, errno, report};
use std::mem::MaybeUninit;

fn main() {
    unsafe {
        // Probe-local 1000 ms upper-bound alarm.
        arm_alarm_ms(1000);

        // =====================================================================
        // Part 1: eventfd semantics
        // =====================================================================

        // 1. EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC flag reflection
        let efd_flags = libc::eventfd(
            0,
            libc::EFD_SEMAPHORE | libc::EFD_NONBLOCK | libc::EFD_CLOEXEC,
        );
        let efd_flags_created = efd_flags >= 0;
        let mut efd_flags_cloexec = false;
        let mut efd_flags_nonblock = false;
        if efd_flags_created {
            let f_fd = libc::fcntl(efd_flags, libc::F_GETFD);
            let f_fl = libc::fcntl(efd_flags, libc::F_GETFL);
            efd_flags_cloexec = f_fd >= 0 && (f_fd & libc::FD_CLOEXEC) != 0;
            efd_flags_nonblock = f_fl >= 0 && (f_fl & libc::O_NONBLOCK) != 0;
            libc::close(efd_flags);
        }

        // 2. Decrement-one reads until EAGAIN (semaphore mode)
        let sem_efd = libc::eventfd(
            3,
            libc::EFD_SEMAPHORE | libc::EFD_NONBLOCK | libc::EFD_CLOEXEC,
        );
        let sem_created = sem_efd >= 0;
        let mut sem_val1: u64 = 0;
        let mut sem_val2: u64 = 0;
        let mut sem_val3: u64 = 0;
        let mut sem_r1 = -1;
        let mut sem_r2 = -1;
        let mut sem_r3 = -1;
        let mut sem_r4 = 0;
        let mut sem_err4 = 0;

        if sem_efd >= 0 {
            sem_r1 = libc::read(
                sem_efd,
                &mut sem_val1 as *mut _ as *mut libc::c_void,
                std::mem::size_of::<u64>(),
            );
            sem_r2 = libc::read(
                sem_efd,
                &mut sem_val2 as *mut _ as *mut libc::c_void,
                std::mem::size_of::<u64>(),
            );
            sem_r3 = libc::read(
                sem_efd,
                &mut sem_val3 as *mut _ as *mut libc::c_void,
                std::mem::size_of::<u64>(),
            );
            let mut sem_val4: u64 = 0;
            sem_r4 = libc::read(
                sem_efd,
                &mut sem_val4 as *mut _ as *mut libc::c_void,
                std::mem::size_of::<u64>(),
            );
            sem_err4 = if sem_r4 == -1 { errno() } else { 0 };
            libc::close(sem_efd);
        }

        let sem_decrement_ok = sem_created
            && sem_r1 == 8
            && sem_val1 == 1
            && sem_r2 == 8
            && sem_val2 == 1
            && sem_r3 == 8
            && sem_val3 == 1
            && sem_r4 == -1
            && sem_err4 == libc::EAGAIN;

        // 3. Ordinary eventfd aggregate-and-reset behavior
        let ord_efd = libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC);
        let ord_created = ord_efd >= 0;
        let mut ord_w1 = -1;
        let mut ord_w2 = -1;
        let mut ord_r1 = -1;
        let mut ord_val: u64 = 0;
        let mut ord_r2 = 0;
        let mut ord_err2 = 0;

        if ord_efd >= 0 {
            let v1: u64 = 5;
            let v2: u64 = 7;
            ord_w1 = libc::write(
                ord_efd,
                &v1 as *const _ as *const libc::c_void,
                std::mem::size_of::<u64>(),
            );
            ord_w2 = libc::write(
                ord_efd,
                &v2 as *const _ as *const libc::c_void,
                std::mem::size_of::<u64>(),
            );
            ord_r1 = libc::read(
                ord_efd,
                &mut ord_val as *mut _ as *mut libc::c_void,
                std::mem::size_of::<u64>(),
            );
            let mut ord_val2: u64 = 0;
            ord_r2 = libc::read(
                ord_efd,
                &mut ord_val2 as *mut _ as *mut libc::c_void,
                std::mem::size_of::<u64>(),
            );
            ord_err2 = if ord_r2 == -1 { errno() } else { 0 };
            libc::close(ord_efd);
        }

        let ord_aggregate_reset_ok = ord_created
            && ord_w1 == 8
            && ord_w2 == 8
            && ord_r1 == 8
            && ord_val == 12
            && ord_r2 == -1
            && ord_err2 == libc::EAGAIN;

        // 4. Short 4-byte read/write EINVAL
        let short_efd = libc::eventfd(1, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC);
        let short_created = short_efd >= 0;
        let mut short_read_rc = 0;
        let mut short_read_err = 0;
        let mut short_write_rc = 0;
        let mut short_write_err = 0;

        if short_efd >= 0 {
            let mut buf4 = [0u8; 4];
            short_read_rc = libc::read(short_efd, buf4.as_mut_ptr() as *mut libc::c_void, 4);
            short_read_err = if short_read_rc == -1 { errno() } else { 0 };

            short_write_rc = libc::write(short_efd, buf4.as_ptr() as *const libc::c_void, 4);
            short_write_err = if short_write_rc == -1 { errno() } else { 0 };

            libc::close(short_efd);
        }

        let short_read_einval =
            short_created && short_read_rc == -1 && short_read_err == libc::EINVAL;
        let short_write_einval =
            short_created && short_write_rc == -1 && short_write_err == libc::EINVAL;

        // 5. Write UINT64_MAX EINVAL
        let max_efd = libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC);
        let max_created = max_efd >= 0;
        let mut max_write_rc = 0;
        let mut max_write_err = 0;

        if max_efd >= 0 {
            let u64_max: u64 = u64::MAX; // 0xffffffffffffffff
            max_write_rc = libc::write(
                max_efd,
                &u64_max as *const _ as *const libc::c_void,
                std::mem::size_of::<u64>(),
            );
            max_write_err = if max_write_rc == -1 { errno() } else { 0 };
            libc::close(max_efd);
        }

        let write_u64_max_einval =
            max_created && max_write_rc == -1 && max_write_err == libc::EINVAL;

        // 6. Overflow / nonblocking EAGAIN
        let ovf_efd = libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC);
        let ovf_created = ovf_efd >= 0;
        let mut ovf_w1 = -1;
        let mut ovf_w2 = 0;
        let mut ovf_err2 = 0;
        let mut ovf_read_val: u64 = 0;
        let mut ovf_r1 = -1;

        if ovf_efd >= 0 {
            let max_allowed: u64 = u64::MAX - 1; // 0xfffffffffffffffe
            ovf_w1 = libc::write(
                ovf_efd,
                &max_allowed as *const _ as *const libc::c_void,
                std::mem::size_of::<u64>(),
            );

            let one: u64 = 1;
            ovf_w2 = libc::write(
                ovf_efd,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<u64>(),
            );
            ovf_err2 = if ovf_w2 == -1 { errno() } else { 0 };

            ovf_r1 = libc::read(
                ovf_efd,
                &mut ovf_read_val as *mut _ as *mut libc::c_void,
                std::mem::size_of::<u64>(),
            );
            libc::close(ovf_efd);
        }

        let write_overflow_eagain = ovf_created
            && ovf_w1 == 8
            && ovf_w2 == -1
            && ovf_err2 == libc::EAGAIN
            && ovf_r1 == 8
            && ovf_read_val == (u64::MAX - 1);

        report!(
            eventfd_flags_cloexec = efd_flags_cloexec,
            eventfd_flags_nonblock = efd_flags_nonblock,
            eventfd_sem_decrement_to_eagain = sem_decrement_ok,
            eventfd_ord_aggregate_and_reset = ord_aggregate_reset_ok,
            eventfd_short_read_einval = short_read_einval,
            eventfd_short_write_einval = short_write_einval,
            eventfd_write_u64_max_einval = write_u64_max_einval,
            eventfd_write_overflow_eagain = write_overflow_eagain,
        );

        // =====================================================================
        // Part 2: signalfd semantics
        // =====================================================================

        // 7. Block SIGUSR1 and SIGUSR2 in thread signal mask using pthread_sigmask
        let mut orig_mask: libc::sigset_t = MaybeUninit::zeroed().assume_init();
        let mut block_mask: libc::sigset_t = MaybeUninit::zeroed().assume_init();
        libc::sigemptyset(&mut block_mask);
        libc::sigaddset(&mut block_mask, libc::SIGUSR1);
        libc::sigaddset(&mut block_mask, libc::SIGUSR2);

        let sigprocmask_ok =
            libc::pthread_sigmask(libc::SIG_BLOCK, &block_mask, &mut orig_mask) == 0;

        let mut sfd_cloexec = false;
        let mut sfd_nonblock = false;
        let mut update_returns_same_fd = false;
        let mut batch_drain_ok = false;
        let mut empty_signalfd_eagain = false;
        let mut short_signalfd_read_einval = false;
        let mut signals_drained = false;
        let mut mask_restored = false;

        if sigprocmask_ok {
            // 8. Create SFD_NONBLOCK | SFD_CLOEXEC signalfd initially with SIGUSR1
            let mut mask_usr1: libc::sigset_t = MaybeUninit::zeroed().assume_init();
            libc::sigemptyset(&mut mask_usr1);
            libc::sigaddset(&mut mask_usr1, libc::SIGUSR1);

            let sfd = libc::signalfd(-1, &mask_usr1, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC);
            let sfd_created = sfd >= 0;
            if sfd_created {
                let f_fd = libc::fcntl(sfd, libc::F_GETFD);
                let f_fl = libc::fcntl(sfd, libc::F_GETFL);
                sfd_cloexec = f_fd >= 0 && (f_fd & libc::FD_CLOEXEC) != 0;
                sfd_nonblock = f_fl >= 0 && (f_fl & libc::O_NONBLOCK) != 0;
            }

            // 9. Update existing signalfd mask to include both SIGUSR1 and SIGUSR2
            let mut mask_both: libc::sigset_t = MaybeUninit::zeroed().assume_init();
            libc::sigemptyset(&mut mask_both);
            libc::sigaddset(&mut mask_both, libc::SIGUSR1);
            libc::sigaddset(&mut mask_both, libc::SIGUSR2);

            let sfd_updated = if sfd >= 0 {
                libc::signalfd(sfd, &mask_both, 0)
            } else {
                -1
            };
            update_returns_same_fd = sfd_created && (sfd_updated == sfd);

            // 10. Queue both signals and batch-drain exact signalfd_siginfo records
            let mut raised_usr1 = false;
            let mut raised_usr2 = false;
            let mut batch_read_n = -1;
            let mut siginfos: [libc::signalfd_siginfo; 2] = MaybeUninit::zeroed().assume_init();
            let siginfo_sz = std::mem::size_of::<libc::signalfd_siginfo>();
            let batch_sz = 2 * siginfo_sz; // 256 bytes

            if sfd >= 0 && update_returns_same_fd {
                raised_usr1 = libc::raise(libc::SIGUSR1) == 0;
                raised_usr2 = libc::raise(libc::SIGUSR2) == 0;

                batch_read_n =
                    libc::read(sfd, siginfos.as_mut_ptr() as *mut libc::c_void, batch_sz);
            }

            batch_drain_ok = raised_usr1
                && raised_usr2
                && batch_read_n == batch_sz as isize
                && siginfos[0].ssi_signo as i32 == libc::SIGUSR1
                && siginfos[1].ssi_signo as i32 == libc::SIGUSR2;

            // 11. Empty signalfd read returns EAGAIN
            let mut empty_si: libc::signalfd_siginfo = MaybeUninit::zeroed().assume_init();
            let empty_read_n = if sfd >= 0 {
                libc::read(
                    sfd,
                    &mut empty_si as *mut _ as *mut libc::c_void,
                    siginfo_sz,
                )
            } else {
                0
            };
            let empty_read_err = if empty_read_n == -1 { errno() } else { 0 };
            empty_signalfd_eagain = empty_read_n == -1 && empty_read_err == libc::EAGAIN;

            // 12. Short buffer read returns EINVAL
            let mut tiny_buf = [0u8; 64];
            let tiny_read_n = if sfd >= 0 {
                libc::read(
                    sfd,
                    tiny_buf.as_mut_ptr() as *mut libc::c_void,
                    tiny_buf.len(),
                )
            } else {
                0
            };
            let tiny_read_err = if tiny_read_n == -1 { errno() } else { 0 };
            short_signalfd_read_einval = tiny_read_n == -1 && tiny_read_err == libc::EINVAL;

            // (5) Close the signalfd before mask restoration
            if sfd >= 0 {
                libc::close(sfd);
            }

            // (4) Reliably drain any remaining pending SIGUSR1/SIGUSR2 while they remain blocked,
            // using bounded nonblocking signal consumption (sigtimedwait with zero timeout until EAGAIN).
            let zero_ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let mut drain_mask: libc::sigset_t = MaybeUninit::zeroed().assume_init();
            libc::sigemptyset(&mut drain_mask);
            libc::sigaddset(&mut drain_mask, libc::SIGUSR1);
            libc::sigaddset(&mut drain_mask, libc::SIGUSR2);

            let mut drain_si: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
            loop {
                let r = libc::sigtimedwait(&drain_mask, &mut drain_si, &zero_ts);
                if r == -1 {
                    break;
                }
            }

            // Confirm neither signal is pending
            let mut pending_set: libc::sigset_t = MaybeUninit::zeroed().assume_init();
            libc::sigpending(&mut pending_set);
            let usr1_pending = libc::sigismember(&pending_set, libc::SIGUSR1) == 1;
            let usr2_pending = libc::sigismember(&pending_set, libc::SIGUSR2) == 1;
            signals_drained = !usr1_pending && !usr2_pending;

            // (2) Restore original mask only because it was successfully captured and signals are drained
            if signals_drained {
                mask_restored =
                    libc::pthread_sigmask(libc::SIG_SETMASK, &orig_mask, core::ptr::null_mut())
                        == 0;
            }
        }

        report!(
            signalfd_sigprocmask_ok = sigprocmask_ok,
            signalfd_flags_cloexec = sfd_cloexec,
            signalfd_flags_nonblock = sfd_nonblock,
            signalfd_update_same_fd = update_returns_same_fd,
            signalfd_batch_drain_records = batch_drain_ok,
            signalfd_empty_eagain = empty_signalfd_eagain,
            signalfd_short_read_einval = short_signalfd_read_einval,
            signalfd_signals_drained = signals_drained,
            signalfd_mask_restored = mask_restored,
        );

        disarm_alarm();
    }
}
