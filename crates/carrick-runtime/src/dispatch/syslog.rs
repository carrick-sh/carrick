//! `syslog(2)` / `klogctl(3)` dispatch handler.
//!
//! # Specification and Permission Ordering
//!
//! Linux printk `do_syslog` validates credentials BEFORE checking actions or
//! arguments (`check_syslog_permissions` in `kernel/printk/printk.c`). When a
//! calling process lacks `CAP_SYSLOG`, every syslog action returns `EPERM`
//! immediately — including unknown action codes and NULL/invalid pointers.
//!
//! When authorized:
//! - Actions 0 (`CLOSE`) / 1 (`OPEN`): NOP returning 0.
//! - Action 2 (`READ`): Consuming read from the unread cursor. Rejection of NULL
//!   or negative length yields `EINVAL`; zero length yields 0; if no unread
//!   messages are available, parks interruptibly via [`DispatchOutcome::WaitOnFds`].
//! - Action 3 (`READ_ALL`): Non-destructive read from oldest available records.
//! - Action 4 (`READ_CLEAR`): Reads available records and clears the buffer.
//! - Action 5 (`CLEAR`): Clears the log buffer (advances clear marker).
//! - Action 6 (`CONSOLE_OFF`): Disables console logging (lowers loglevel).
//! - Action 7 (`CONSOLE_ON`): Enables console logging (restores saved level).
//! - Action 8 (`CONSOLE_LEVEL`): Sets console loglevel (valid 1..=8, else `EINVAL`).
//! - Action 9 (`SIZE_UNREAD`): Returns unread byte count for consuming reader.
//! - Action 10 (`SIZE_BUFFER`): Returns buffer capacity in bytes.

use super::*;
use carrick_abi::{LINUX_EINVAL, LINUX_EPERM};

pub const SYSLOG_ACTION_CLOSE: i32 = 0;
pub const SYSLOG_ACTION_OPEN: i32 = 1;
pub const SYSLOG_ACTION_READ: i32 = 2;
pub const SYSLOG_ACTION_READ_ALL: i32 = 3;
pub const SYSLOG_ACTION_READ_CLEAR: i32 = 4;
pub const SYSLOG_ACTION_CLEAR: i32 = 5;
pub const SYSLOG_ACTION_CONSOLE_OFF: i32 = 6;
pub const SYSLOG_ACTION_CONSOLE_ON: i32 = 7;
pub const SYSLOG_ACTION_CONSOLE_LEVEL: i32 = 8;
pub const SYSLOG_ACTION_SIZE_UNREAD: i32 = 9;
pub const SYSLOG_ACTION_SIZE_BUFFER: i32 = 10;

syscall_table! {
    /// Routing for the syslog syscall family.
    pub(crate) fn dispatch_syslog;
    116 => syslog,
}

impl SyscallDispatcher {
    define_syscall! {
        /// `syslog(2)` / `klogctl(3)`.
        fn syslog(
            this,
            cx,
            action: u64,
            buf: GuestPtr,
            len: u64,
        ) {
            let _ = this;
            let action = action as i32;
            let len = len as i32;
            let owner_id = cx.kernel.syslog().id();
            // 1. Permission check runs FIRST, before action and argument validation.
            // On Linux 5.10+, CAP_SYSLOG is strictly required; CAP_SYS_ADMIN alone is denied.
            if !super::creds::has_effective_capability(
                cx.kernel,
                crate::namespace::process::CAP_SYSLOG,
            ) {
                crate::event_ring::rec_syslog(owner_id, action, len, -LINUX_EPERM.get());
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }

            // 2. Validate action bounds.
            if !(SYSLOG_ACTION_CLOSE..=SYSLOG_ACTION_SIZE_BUFFER).contains(&action) {
                crate::event_ring::rec_syslog(owner_id, action, len, -LINUX_EINVAL.get());
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            let syslog = cx.kernel.syslog();

            match action {
                SYSLOG_ACTION_CLOSE | SYSLOG_ACTION_OPEN => {
                    crate::event_ring::rec_syslog(owner_id, action, len, 0);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                SYSLOG_ACTION_READ => {
                    if buf.0 == 0 || len < 0 {
                        crate::event_ring::rec_syslog(owner_id, action, len, -LINUX_EINVAL.get());
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    if len == 0 {
                        crate::event_ring::rec_syslog(owner_id, action, len, 0);
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    if let Some(data) = syslog.read_consuming(len as usize) {
                        if !data.is_empty() {
                            cx.memory.write_bytes(buf.0, &data)?;
                        }
                        crate::event_ring::rec_syslog(owner_id, action, len, data.len() as i32);
                        return Ok(DispatchOutcome::returned_len(data.len())?);
                    }

                    // Buffer is empty relative to this reader: park interruptibly using WaitOnFds.
                    let poll_fd = match syslog.read_poll_fd() {
                        Some(fd) => fd,
                        None => return Ok(DispatchOutcome::errno(carrick_abi::LINUX_EMFILE)),
                    };
                    crate::event_ring::rec_syslog(owner_id, action, len, 0);
                    crate::event_ring::rec_syslog_wake(owner_id, 3, 0, poll_fd.raw());
                    Ok(DispatchOutcome::WaitOnFds {
                        fds: WaitFds::anchored_one(poll_fd.raw(), libc::POLLIN, Some(poll_fd))
                            .with_authority(WaitFdAuthority::internal(
                                InternalWaitKind::CarrierControl,
                            )),
                        timeout: None,
                        sig_mask: carrick_abi::WaitSigMask::Additive(carrick_abi::SigSet::EMPTY),
                        completion: FdWaitCompletion::Fd { on_timeout: 0 },
                    })
                }
                SYSLOG_ACTION_READ_ALL => {
                    if buf.0 == 0 || len < 0 {
                        crate::event_ring::rec_syslog(owner_id, action, len, -LINUX_EINVAL.get());
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    if len == 0 {
                        crate::event_ring::rec_syslog(owner_id, action, len, 0);
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    let data = syslog.read_all(len as usize);
                    if !data.is_empty() {
                        cx.memory.write_bytes(buf.0, &data)?;
                    }
                    crate::event_ring::rec_syslog(owner_id, action, len, data.len() as i32);
                    Ok(DispatchOutcome::returned_len(data.len())?)
                }
                SYSLOG_ACTION_READ_CLEAR => {
                    if buf.0 == 0 || len < 0 {
                        crate::event_ring::rec_syslog(owner_id, action, len, -LINUX_EINVAL.get());
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    if len == 0 {
                        crate::event_ring::rec_syslog(owner_id, action, len, 0);
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    let data = syslog.read_clear(len as usize);
                    if !data.is_empty() {
                        cx.memory.write_bytes(buf.0, &data)?;
                    }
                    crate::event_ring::rec_syslog(owner_id, action, len, data.len() as i32);
                    Ok(DispatchOutcome::returned_len(data.len())?)
                }
                SYSLOG_ACTION_CLEAR => {
                    syslog.clear();
                    crate::event_ring::rec_syslog(owner_id, action, len, 0);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                SYSLOG_ACTION_CONSOLE_OFF => {
                    syslog.console_off();
                    crate::event_ring::rec_syslog(owner_id, action, len, 0);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                SYSLOG_ACTION_CONSOLE_ON => {
                    syslog.console_on();
                    crate::event_ring::rec_syslog(owner_id, action, len, 0);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                SYSLOG_ACTION_CONSOLE_LEVEL => {
                    if !(1..=8).contains(&len) {
                        crate::event_ring::rec_syslog(owner_id, action, len, -LINUX_EINVAL.get());
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    let _ = syslog.set_console_level(len as u32);
                    crate::event_ring::rec_syslog(owner_id, action, len, 0);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                SYSLOG_ACTION_SIZE_UNREAD => {
                    let unread = syslog.size_unread();
                    crate::event_ring::rec_syslog(owner_id, action, len, unread as i32);
                    Ok(DispatchOutcome::returned_len(unread)?)
                }
                SYSLOG_ACTION_SIZE_BUFFER => {
                    let size = syslog.size_buffer();
                    crate::event_ring::rec_syslog(owner_id, action, len, size as i32);
                    Ok(DispatchOutcome::returned_len(size)?)
                }
                _ => {
                    crate::event_ring::rec_syslog(owner_id, action, len, -LINUX_EINVAL.get());
                    Ok(DispatchOutcome::errno(LINUX_EINVAL))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;
    use crate::compat::CompatReporter;
    use crate::kernel::KernelContext;

    fn test_dispatcher() -> (SyscallDispatcher, KernelContext) {
        let dispatcher = SyscallDispatcher::new();
        let kernel_ctx = dispatcher.capture_one_task_context().unwrap();
        (dispatcher, kernel_ctx)
    }

    #[test]
    fn syslog_unprivileged_returns_eperm_for_all_actions() {
        let (mut dispatcher, kernel_ctx) = test_dispatcher();
        // Default container context has no CAP_SYSLOG
        let mut memory = crate::dispatch::LinearMemory::new(0x1000, vec![0u8; 1024]);
        let reporter = CompatReporter::default();

        // 1. Invalid action 100
        let req = SyscallRequest::new(116, SyscallArgs([100, 0x1000, 0, 0, 0, 0]));
        let res = dispatcher
            .dispatch(&kernel_ctx, req, &mut memory, &reporter)
            .unwrap();
        assert_eq!(res, DispatchOutcome::errno(LINUX_EPERM));

        // 2. Action 2 NULL read len 0
        let req = SyscallRequest::new(116, SyscallArgs([2, 0, 0, 0, 0, 0]));
        let res = dispatcher
            .dispatch(&kernel_ctx, req, &mut memory, &reporter)
            .unwrap();
        assert_eq!(res, DispatchOutcome::errno(LINUX_EPERM));

        // 3. Action 3 negative len
        let req = SyscallRequest::new(
            116,
            SyscallArgs([3, 0x1000, (-1i32) as u32 as u64, 0, 0, 0]),
        );
        let res = dispatcher
            .dispatch(&kernel_ctx, req, &mut memory, &reporter)
            .unwrap();
        assert_eq!(res, DispatchOutcome::errno(LINUX_EPERM));

        // 4. Action 8 out of bounds level
        let req = SyscallRequest::new(116, SyscallArgs([8, 0x1000, 9, 0, 0, 0]));
        let res = dispatcher
            .dispatch(&kernel_ctx, req, &mut memory, &reporter)
            .unwrap();
        assert_eq!(res, DispatchOutcome::errno(LINUX_EPERM));

        // 5. Action 10 buffer size
        let req = SyscallRequest::new(116, SyscallArgs([10, 0, 0, 0, 0, 0]));
        let res = dispatcher
            .dispatch(&kernel_ctx, req, &mut memory, &reporter)
            .unwrap();
        assert_eq!(res, DispatchOutcome::errno(LINUX_EPERM));
    }

    #[test]
    fn syslog_with_cap_syslog_validation_and_actions() {
        let (mut dispatcher, kernel_ctx) = test_dispatcher();
        // Grant CAP_SYSLOG to the calling task
        kernel_ctx.task().with_caps(|caps| {
            caps.effective |= 1u64 << crate::namespace::process::CAP_SYSLOG;
            caps.permitted |= 1u64 << crate::namespace::process::CAP_SYSLOG;
        });

        let mut memory = crate::dispatch::LinearMemory::new(0x1000, vec![0u8; 1024]);
        let reporter = CompatReporter::default();

        // 1. Invalid action 100 -> EINVAL
        let req = SyscallRequest::new(116, SyscallArgs([100, 0x1000, 0, 0, 0, 0]));
        let res = dispatcher
            .dispatch(&kernel_ctx, req, &mut memory, &reporter)
            .unwrap();
        assert_eq!(res, DispatchOutcome::errno(LINUX_EINVAL));

        // 2. Action 2 NULL read -> EINVAL
        let req = SyscallRequest::new(116, SyscallArgs([2, 0, 0, 0, 0, 0]));
        let res = dispatcher
            .dispatch(&kernel_ctx, req, &mut memory, &reporter)
            .unwrap();
        assert_eq!(res, DispatchOutcome::errno(LINUX_EINVAL));

        // 3. Action 3 negative len -> EINVAL
        let req = SyscallRequest::new(
            116,
            SyscallArgs([3, 0x1000, (-1i32) as u32 as u64, 0, 0, 0]),
        );
        let res = dispatcher
            .dispatch(&kernel_ctx, req, &mut memory, &reporter)
            .unwrap();
        assert_eq!(res, DispatchOutcome::errno(LINUX_EINVAL));

        // 4. Action 8 negative level -> EINVAL
        let req = SyscallRequest::new(
            116,
            SyscallArgs([8, 0x1000, (-1i32) as u32 as u64, 0, 0, 0]),
        );
        let res = dispatcher
            .dispatch(&kernel_ctx, req, &mut memory, &reporter)
            .unwrap();
        assert_eq!(res, DispatchOutcome::errno(LINUX_EINVAL));

        // 5. Action 8 level 9 -> EINVAL
        let req = SyscallRequest::new(116, SyscallArgs([8, 0x1000, 9, 0, 0, 0]));
        let res = dispatcher
            .dispatch(&kernel_ctx, req, &mut memory, &reporter)
            .unwrap();
        assert_eq!(res, DispatchOutcome::errno(LINUX_EINVAL));

        // 6. Action 2 valid ptr len 0 -> 0
        let req = SyscallRequest::new(116, SyscallArgs([2, 0x1000, 0, 0, 0, 0]));
        let res = dispatcher
            .dispatch(&kernel_ctx, req, &mut memory, &reporter)
            .unwrap();
        assert_eq!(res, DispatchOutcome::Returned { value: 0 });

        // 7. Action 10 buffer size -> size > 0
        let req = SyscallRequest::new(116, SyscallArgs([10, 0, 0, 0, 0, 0]));
        let res = dispatcher
            .dispatch(&kernel_ctx, req, &mut memory, &reporter)
            .unwrap();
        match res {
            DispatchOutcome::Returned { value } => assert!(value > 0),
            _ => panic!("expected Returned buffer size"),
        }

        // 8. Action 2 on empty ring -> WaitOnFds
        let _ = kernel_ctx.syslog().read_consuming(4096);
        let req = SyscallRequest::new(116, SyscallArgs([2, 0x1000, 512, 0, 0, 0]));
        let res = dispatcher
            .dispatch(&kernel_ctx, req, &mut memory, &reporter)
            .unwrap();
        match res {
            DispatchOutcome::WaitOnFds { .. } => {}
            other => panic!("expected WaitOnFds for empty ring read, got {other:?}"),
        }

        // 9. Append data and verify Action 2 reads it
        kernel_ctx
            .syslog()
            .append(6, 0, 100, b"kernel log message\n".to_vec());
        let req = SyscallRequest::new(116, SyscallArgs([2, 0x1000, 512, 0, 0, 0]));
        let res = dispatcher
            .dispatch(&kernel_ctx, req, &mut memory, &reporter)
            .unwrap();
        match res {
            DispatchOutcome::Returned { value } => {
                assert!(value > 0);
                let bytes = memory.read_bytes(0x1000, value as usize).unwrap();
                assert_eq!(bytes, b"<6>kernel log message\n");
            }
            other => panic!("expected Returned from syslog read, got {other:?}"),
        }
    }

    #[test]
    fn syslog_admin_without_syslog_is_denied_controller() {
        let (mut dispatcher, kernel_ctx) = test_dispatcher();
        kernel_ctx.task().with_caps(|caps| {
            caps.effective = 1u64 << crate::namespace::process::CAP_SYS_ADMIN;
            caps.permitted = caps.effective;
        });
        let mut memory = crate::dispatch::LinearMemory::new(0x1000, vec![0u8; 1024]);
        let reporter = CompatReporter::default();
        let req = SyscallRequest::new(116, SyscallArgs([10, 0, 0, 0, 0, 0]));
        let result = dispatcher
            .dispatch(&kernel_ctx, req, &mut memory, &reporter)
            .unwrap();
        assert_eq!(result, DispatchOutcome::errno(LINUX_EPERM));
    }

    #[test]
    fn syslog_native_capability_controls_parity() {
        let (mut dispatcher, kernel_ctx) = test_dispatcher();
        let mut memory = crate::dispatch::LinearMemory::new(0x1000, vec![0u8; 1024]);
        let reporter = CompatReporter::default();

        // Control 1: Default container context (no CAP_SYSLOG) -> EPERM for action 100 and action 10
        let req100 = SyscallRequest::new(116, SyscallArgs([100, 0x1000, 0, 0, 0, 0]));
        assert_eq!(
            dispatcher
                .dispatch(&kernel_ctx, req100, &mut memory, &reporter)
                .unwrap(),
            DispatchOutcome::errno(LINUX_EPERM)
        );
        let req10 = SyscallRequest::new(116, SyscallArgs([10, 0, 0, 0, 0, 0]));
        assert_eq!(
            dispatcher
                .dispatch(&kernel_ctx, req10, &mut memory, &reporter)
                .unwrap(),
            DispatchOutcome::errno(LINUX_EPERM)
        );

        // Control 2: Add CAP_SYS_ADMIN / drop CAP_SYSLOG -> still EPERM for action 100 and action 10
        kernel_ctx.task().with_caps(|caps| {
            caps.effective = 1u64 << crate::namespace::process::CAP_SYS_ADMIN;
            caps.permitted = 1u64 << crate::namespace::process::CAP_SYS_ADMIN;
        });
        assert_eq!(
            dispatcher
                .dispatch(&kernel_ctx, req100, &mut memory, &reporter)
                .unwrap(),
            DispatchOutcome::errno(LINUX_EPERM)
        );
        assert_eq!(
            dispatcher
                .dispatch(&kernel_ctx, req10, &mut memory, &reporter)
                .unwrap(),
            DispatchOutcome::errno(LINUX_EPERM)
        );

        // Control 3: Add CAP_SYSLOG -> yields EINVAL for action 100 and buffer capacity for action 10
        kernel_ctx.task().with_caps(|caps| {
            caps.effective |= 1u64 << crate::namespace::process::CAP_SYSLOG;
            caps.permitted |= 1u64 << crate::namespace::process::CAP_SYSLOG;
        });
        assert_eq!(
            dispatcher
                .dispatch(&kernel_ctx, req100, &mut memory, &reporter)
                .unwrap(),
            DispatchOutcome::errno(LINUX_EINVAL)
        );
        let res10 = dispatcher
            .dispatch(&kernel_ctx, req10, &mut memory, &reporter)
            .unwrap();
        match res10 {
            DispatchOutcome::Returned { value } => {
                assert_eq!(value, crate::syslog::DEFAULT_LOG_BUF_LEN as i64)
            }
            other => panic!("expected buffer capacity, got {other:?}"),
        }
    }

    #[test]
    fn syslog_wait_on_fds_readiness_poll_and_continuation() {
        let (mut dispatcher, kernel_ctx) = test_dispatcher();
        kernel_ctx.task().with_caps(|caps| {
            caps.effective |= 1u64 << crate::namespace::process::CAP_SYSLOG;
            caps.permitted |= 1u64 << crate::namespace::process::CAP_SYSLOG;
        });
        let mut memory = crate::dispatch::LinearMemory::new(0x1000, vec![0u8; 1024]);
        let reporter = CompatReporter::default();

        // 1. Drain existing logs
        let _ = kernel_ctx.syslog().read_consuming(4096);

        // 2. Dispatch action 2 on empty ring -> WaitOnFds
        let req = SyscallRequest::new(116, SyscallArgs([2, 0x1000, 512, 0, 0, 0]));
        let res = dispatcher
            .dispatch(&kernel_ctx, req, &mut memory, &reporter)
            .unwrap();
        let raw_poll_fd = match res {
            DispatchOutcome::WaitOnFds { fds, .. } => {
                let poll_fd = kernel_ctx.syslog().read_poll_fd().unwrap();
                assert_eq!(fds.fds[0].fd(), poll_fd.raw());
                poll_fd.raw()
            }
            other => panic!("expected WaitOnFds, got {other:?}"),
        };

        // 3. Negative check: poll_fd must NOT be readable before append
        let mut pfd = libc::pollfd {
            fd: raw_poll_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_before = unsafe { libc::poll(&mut pfd, 1, 0) };
        assert_eq!(
            poll_before, 0,
            "empty syslog poll fd must not report readiness before append"
        );

        // 4. Waiter thread polls with bounded timeout behind deterministic barrier
        let barrier = Arc::new(Barrier::new(2));
        let barrier_clone = Arc::clone(&barrier);
        let waiter = std::thread::spawn(move || {
            let mut pfd = libc::pollfd {
                fd: raw_poll_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            barrier_clone.wait();
            let rc = unsafe { libc::poll(&mut pfd, 1, 5000) };
            assert_eq!(
                rc, 1,
                "poll on syslog read fd must wake with readiness on append"
            );
            assert_ne!(
                pfd.revents & libc::POLLIN,
                0,
                "revents must include POLLIN readiness"
            );
        });

        barrier.wait();
        std::thread::yield_now();

        // 5. Producer writes a kernel log record, waking waiter via readiness pipe
        kernel_ctx
            .syslog()
            .append(5, 0, 12345, b"continuation test message\n".to_vec());
        waiter.join().expect("waiter thread completed successfully");

        // 6. Continuation re-dispatches action 2 -> data returned
        let res = dispatcher
            .dispatch(&kernel_ctx, req, &mut memory, &reporter)
            .unwrap();
        match res {
            DispatchOutcome::Returned { value } => {
                assert!(value > 0);
                let bytes = memory.read_bytes(0x1000, value as usize).unwrap();
                assert_eq!(bytes, b"<5>continuation test message\n");
            }
            other => panic!("expected Returned, got {other:?}"),
        }

        // 7. After full consumption, poll fd must be drained and not report readiness
        let poll_after = unsafe { libc::poll(&mut pfd, 1, 0) };
        assert_eq!(
            poll_after, 0,
            "syslog poll fd must be drained after consuming all records"
        );
    }

    #[test]
    fn syslog_wait_queue_and_partial_read_drain_interleaving() {
        let (_dispatcher, kernel_ctx) = test_dispatcher();
        let _ = kernel_ctx.syslog().read_consuming(4096);

        // 1. Test WaitQueue enrollment lifecycle (register & unregister)
        let wait_set = crate::kernel::wait_set::WaitSet::new();
        let enrollment = kernel_ctx.syslog().wait_queue().enroll(&wait_set);
        assert_eq!(kernel_ctx.syslog().wait_queue().waiter_count(), 1);

        // Cancel / unenroll before append (signal simulation)
        enrollment.unregister();
        assert_eq!(kernel_ctx.syslog().wait_queue().waiter_count(), 0);

        // 2. Test active WaitSet thread wake on producer append
        let wait_set2 = crate::kernel::wait_set::WaitSet::new();
        let _enrollment2 = kernel_ctx.syslog().wait_queue().enroll(&wait_set2);
        assert_eq!(kernel_ctx.syslog().wait_queue().waiter_count(), 1);

        let wait_set_clone = wait_set2.clone();
        let barrier = Arc::new(Barrier::new(2));
        let barrier_clone = Arc::clone(&barrier);
        let waiter_thread = std::thread::spawn(move || {
            barrier_clone.wait();
            let outcome =
                wait_set_clone.wait(&[], Some(std::time::Duration::from_millis(5000)), || false);
            assert_eq!(outcome, crate::kernel::wait_set::WaitSetOutcome::Woken);
        });

        barrier.wait();
        std::thread::yield_now();

        // Append two records
        kernel_ctx
            .syslog()
            .append(6, 0, 100, b"alpha line\n".to_vec());
        kernel_ctx
            .syslog()
            .append(6, 0, 200, b"beta line\n".to_vec());

        waiter_thread
            .join()
            .expect("waiter thread joined successfully");

        let poll_fd = kernel_ctx.syslog().read_poll_fd().unwrap().raw();
        let mut pfd = libc::pollfd {
            fd: poll_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut pfd, 1, 0) }, 1);

        // Partial read: only read 5 bytes
        let partial = kernel_ctx.syslog().read_consuming(5).unwrap();
        assert_eq!(partial, b"<6>al");
        // Readiness pipe must STILL be ready because unread data remains
        assert_eq!(
            unsafe { libc::poll(&mut pfd, 1, 0) },
            1,
            "partial read must not drain readiness pipe while unread data remains"
        );

        // Drain remaining data
        let rest = kernel_ctx.syslog().read_consuming(1024).unwrap();
        assert_eq!(rest, b"pha line\n<6>beta line\n");

        // Now that all data is consumed, readiness pipe must be drained
        assert_eq!(
            unsafe { libc::poll(&mut pfd, 1, 0) },
            0,
            "readiness pipe must be drained after all unread data is consumed"
        );
    }
}
