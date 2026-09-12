//! Syscall execution and dispatch methods on [`SyscallDispatcher`].
//!
//! Provides single-threaded, multi-threaded, and threaded-independent entry
//! points for syscall dispatch, lease management, and exact-MM executor
//! admission.

use std::sync::Arc;

use carrick_guest_mem::CurrentMmMemory;

use crate::compat::{CompatEvent, CompatReporter};
use crate::dispatch::SyscallDispatcher;
use crate::dispatch::futex::{dispatch_futex_waitv_args, dispatch_threaded_futex};
use crate::dispatch::mm_authority::MmExecutorParticipation;
use crate::dispatch::mm_mutation;
use crate::dispatch::outcome::{DispatchError, DispatchOutcome, lower_handler_result};
use crate::dispatch::request::{
    PreparedDispatch, PreparedSyscall, SyscallRequest, ThreadCtx,
    threaded_independent_dispatch_supports,
};
use crate::dispatch::resources;
use crate::dispatch::routing::{
    MutationDispatchRoute, NormalizedDispatchRoute, OrdinaryDispatchRoute,
    syscall_requires_mm_mutation,
};
use crate::linux_abi::{LINUX_EINVAL, LINUX_ENOSYS, LINUX_ESRCH, LINUX_MAX_SIGNUM};
use crate::syscall::lookup_aarch64;

#[cfg(feature = "watchpoint")]
use super::watch_addr;

impl SyscallDispatcher {
    /// Single-threaded dispatch (legacy + unit tests + the fork-based runtime
    /// path). Tid-aware handlers see `thread: None`. The exact current MM's
    /// executor census, not `&mut self`, proves mutation exclusivity.
    pub fn dispatch(
        &mut self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.dispatch_with_lease(kernel, request, memory, reporter, None)
    }

    /// Single-threaded dispatch accepting an explicitly borrowed `ThreadExecutionLease`.
    pub(crate) fn dispatch_with_lease(
        &mut self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        lease: Option<&crate::kernel::objects::ThreadExecutionLease>,
    ) -> Result<DispatchOutcome, DispatchError> {
        match self.prepare_syscall(kernel, request, reporter)? {
            PreparedDispatch::Invoke(syscall) => {
                self.dispatch_prepared_with_lease(kernel, syscall, memory, reporter, lease)
            }
            PreparedDispatch::Complete { outcome, .. } => Ok(outcome),
        }
    }

    pub(crate) fn dispatch_prepared(
        &mut self,
        kernel: &crate::kernel::KernelContext,
        syscall: PreparedSyscall,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.dispatch_prepared_with_lease(kernel, syscall, memory, reporter, None)
    }

    /// Handler-only single-threaded dispatch. Repeated readiness attempts reuse
    /// the same prepared envelope and enter here without running preflight.
    pub(crate) fn dispatch_prepared_with_lease(
        &mut self,
        kernel: &crate::kernel::KernelContext,
        syscall: PreparedSyscall,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        lease: Option<&crate::kernel::objects::ThreadExecutionLease>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // Tree-wide forward-progress beat for the deadlock watchdog.
        crate::deadlock_watchdog::tick();
        let request = syscall.request;
        let mut executor = self
            .enter_mm_executor()
            .map_err(DispatchError::MmExecutorAdmission)?;
        if syscall_requires_mm_mutation(request.number.raw(), request.args) {
            let coordinator = executor.mutation_coordinator();
            let mm = executor.mm_id();
            crate::vcpu_loop::with_sole_mm_stage1(&mut executor, |authority| {
                let mut guard = mm_mutation::from_sole_executor(authority, coordinator, mm);
                self.dispatch_inner(
                    kernel,
                    request,
                    memory,
                    reporter,
                    None,
                    MutationDispatchRoute {
                        guard: &mut guard,
                        lease,
                    },
                )
            })
            .ok_or(DispatchError::MmMutationPeerExecutor)?
        } else {
            self.dispatch_inner(
                kernel,
                request,
                memory,
                reporter,
                None,
                OrdinaryDispatchRoute {
                    lease,
                    mm_executor: Some(&mut executor),
                },
            )
        }
    }

    /// Run a non-threaded completion under a fresh exact-MM census admission.
    pub(crate) fn with_mm_executor_mutation<T>(
        &mut self,
        run: impl FnOnce(&mut Self, &mut mm_mutation::MmMutationGuard<'_>) -> T,
    ) -> Result<T, DispatchError> {
        let mut executor = self
            .enter_mm_executor()
            .map_err(DispatchError::MmExecutorAdmission)?;
        let coordinator = executor.mutation_coordinator();
        let mm = executor.mm_id();
        crate::vcpu_loop::with_sole_mm_stage1(&mut executor, |authority| {
            let mut guard = mm_mutation::from_sole_executor(authority, coordinator, mm);
            run(self, &mut guard)
        })
        .ok_or(DispatchError::MmMutationPeerExecutor)
    }

    /// Multi-threaded dispatch through a shared dispatcher reference. Handlers
    /// Multi-threaded dispatch through a shared dispatcher reference. Handlers
    /// that touch process-wide state must protect that state with subsystem
    /// locks; there is no dispatcher-wide fallback on this path.
    pub fn dispatch_threaded(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: ThreadCtx<'_>,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.dispatch_threaded_with_lease(kernel, request, memory, reporter, thread, None)
    }

    pub(crate) fn dispatch_threaded_with_lease(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: ThreadCtx<'_>,
        lease: Option<&crate::kernel::objects::ThreadExecutionLease>,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.dispatch_threaded_with_executor_and_lease(
            kernel,
            request,
            memory,
            reporter,
            thread,
            OrdinaryDispatchRoute {
                lease,
                mm_executor: None,
            },
        )
    }

    fn dispatch_threaded_with_executor_and_lease(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: ThreadCtx<'_>,
        route: OrdinaryDispatchRoute<'_, '_>,
    ) -> Result<DispatchOutcome, DispatchError> {
        match self.prepare_syscall(kernel, request, reporter)? {
            PreparedDispatch::Invoke(syscall) => self
                .dispatch_threaded_prepared_with_executor_and_lease(
                    kernel, syscall, memory, reporter, thread, route,
                ),
            PreparedDispatch::Complete { outcome, .. } => Ok(outcome),
        }
    }

    pub(crate) fn dispatch_threaded_prepared_with_mm_executor_and_lease(
        &self,
        kernel: &crate::kernel::KernelContext,
        syscall: PreparedSyscall,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: ThreadCtx<'_>,
        route: OrdinaryDispatchRoute<'_, '_>,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.dispatch_threaded_prepared_with_executor_and_lease(
            kernel, syscall, memory, reporter, thread, route,
        )
    }

    fn dispatch_threaded_prepared_with_executor_and_lease(
        &self,
        kernel: &crate::kernel::KernelContext,
        syscall: PreparedSyscall,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: ThreadCtx<'_>,
        route: OrdinaryDispatchRoute<'_, '_>,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.dispatch_threaded_prepared_with_route(kernel, syscall, memory, reporter, thread, route)
    }

    /// Shared-dispatch semantics under an exact-MM executor participation.
    /// Mutation is admitted only while that participation can lock a real
    /// sole-executor census election. Production multi-vCPU dispatch uses the
    /// same participation and takes a real page-table pause when a peer exists.
    pub fn dispatch_threaded_with_mm_executor(
        &self,
        executor: &mut MmExecutorParticipation,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: ThreadCtx<'_>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let authority = self.mm_binding.current.load_full();
        if !executor.authorizes(&authority) || executor.mm_id() != kernel.shared().mm().id() {
            return Err(DispatchError::MmMutationPeerExecutor);
        }
        match self.prepare_syscall(kernel, request, reporter)? {
            PreparedDispatch::Complete { outcome, .. } => Ok(outcome),
            PreparedDispatch::Invoke(syscall) => {
                if syscall_requires_mm_mutation(syscall.request.number.raw(), syscall.request.args)
                {
                    let coordinator = executor.mutation_coordinator();
                    crate::vcpu_loop::with_sole_mm_stage1(executor, |outer| {
                        let mut guard = mm_mutation::from_sole_executor(
                            outer,
                            coordinator,
                            kernel.shared().mm().id(),
                        );
                        self.dispatch_threaded_prepared_mutation_with_lease(
                            kernel,
                            syscall,
                            memory,
                            reporter,
                            thread,
                            MutationDispatchRoute {
                                guard: &mut guard,
                                lease: None,
                            },
                        )
                    })
                    .ok_or(DispatchError::MmMutationPeerExecutor)?
                } else {
                    self.dispatch_threaded_prepared_with_mm_executor_and_lease(
                        kernel,
                        syscall,
                        memory,
                        reporter,
                        thread,
                        OrdinaryDispatchRoute {
                            lease: None,
                            mm_executor: Some(executor),
                        },
                    )
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn dispatch_threaded_for_test(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: ThreadCtx<'_>,
    ) -> Result<DispatchOutcome, DispatchError> {
        match self.prepare_syscall(kernel, request, reporter)? {
            PreparedDispatch::Complete { outcome, .. } => Ok(outcome),
            PreparedDispatch::Invoke(syscall) => {
                if syscall_requires_mm_mutation(syscall.request.number.raw(), syscall.request.args)
                {
                    mm_mutation::test_support::with_guard(self.mm_mutation_coordinator(), |guard| {
                        self.dispatch_threaded_prepared_mutation_with_lease(
                            kernel,
                            syscall,
                            memory,
                            reporter,
                            thread,
                            MutationDispatchRoute { guard, lease: None },
                        )
                    })
                } else {
                    self.dispatch_threaded_prepared_with_executor_and_lease(
                        kernel,
                        syscall,
                        memory,
                        reporter,
                        thread,
                        OrdinaryDispatchRoute {
                            lease: None,
                            mm_executor: None,
                        },
                    )
                }
            }
        }
    }

    pub(crate) fn dispatch_threaded_prepared_mutation_with_lease(
        &self,
        kernel: &crate::kernel::KernelContext,
        syscall: PreparedSyscall,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: ThreadCtx<'_>,
        route: MutationDispatchRoute<'_, '_, '_>,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.dispatch_threaded_prepared_with_route(kernel, syscall, memory, reporter, thread, route)
    }

    fn dispatch_threaded_prepared_with_route<R: NormalizedDispatchRoute>(
        &self,
        kernel: &crate::kernel::KernelContext,
        syscall: PreparedSyscall,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: ThreadCtx<'_>,
        mut route: R,
    ) -> Result<DispatchOutcome, DispatchError> {
        let request = syscall.request;

        // The calling MM's vDSO realtime word follows a guest `clock_settime`
        // made by any process (one atomic compare when nothing changed).
        if let Err(error) =
            self.sync_vvar_realtime_offset(kernel.task().container().clock(), memory)
        {
            tracing::error!("vvar realtime re-stamp failed: {error}");
            return Err(DispatchError::from(error));
        }
        if let Some(result) =
            self.dispatch_threaded_independent(kernel, request, memory, reporter, thread)
        {
            return result;
        }
        resources::with_captured_resources(kernel, || {
            self.dispatch_threaded_captured(kernel, request, memory, reporter, thread, &mut route)
        })
    }

    fn dispatch_threaded_captured<R: NormalizedDispatchRoute>(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: ThreadCtx<'_>,
        route: &mut R,
    ) -> Result<DispatchOutcome, DispatchError> {
        if let Some(result) =
            self.dispatch_threaded_shared(kernel, request, memory, reporter, thread, route)
        {
            return result;
        }

        let syscall = lookup_aarch64(request.number.raw());
        let name = syscall.map_or("unknown", |syscall| syscall.name);
        reporter.record(CompatEvent::unhandled_syscall(
            request.number.raw(),
            name,
            request.args,
        ));
        Ok(DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        })
    }

    /// Shared threaded dispatch path for subsystems already moved behind
    /// interior locks.
    fn dispatch_threaded_shared<R: NormalizedDispatchRoute>(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: ThreadCtx<'_>,
        route: &mut R,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        if request.number.raw() == 64
            && !resources::with_captured_resources(kernel, || {
                self.write_shared_supported(request.args.0[0] as i32)
            })
        {
            return None;
        }

        if !Self::dispatch_normalized_known(request.number.raw()) {
            return None;
        }

        #[cfg(feature = "watchpoint")]
        if let Some(addr) = watch_addr()
            && let Ok(bytes) = memory.read_bytes(addr, 8)
        {
            let mut le = [0u8; 8];
            le.copy_from_slice(&bytes[..8]);
            crate::probes::mem_watch(request.number.raw(), addr, u64::from_le_bytes(le));
        }

        let result = route.dispatch(self, kernel, request, memory, reporter, Some(thread));
        let outcome = match result {
            Some(r) => match lower_handler_result(r) {
                Ok(outcome) => outcome,
                Err(fatal) => return Some(Err(fatal)),
            },
            None => DispatchOutcome::Errno {
                errno: LINUX_ENOSYS,
            },
        };
        // Consumption-based EPOLLET re-arm: a read/write-family syscall on a
        // watched fd services the latched edge; clear it so the next sampled
        // assertion is delivered (the Linux-lane lost-edge wedge — see
        // `epoll_rearm_after_io`). Outcome matters: an EAGAIN write did not
        // consume writable capacity and must not synthesize another OUT edge.
        resources::with_captured_resources(kernel, || {
            self.epoll_rearm_after_io(&request, &outcome);
        });
        Some(Ok(outcome))
    }

    /// Thread-local syscall subset that does not touch mutable dispatcher
    /// subsystem state. The runtime checks this before taking the serialized
    /// legacy dispatcher path so futex and tid coordination can proceed without
    /// the dispatcher-wide lock.
    pub(crate) fn dispatch_threaded_independent(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: ThreadCtx<'_>,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        if !threaded_independent_dispatch_supports(request.number.raw()) {
            return None;
        }
        match request.number.raw() {
            130 => {
                let target =
                    crate::namespace::pid::guest_tid_to_kernel_for(kernel, request.arg(0) as i32)
                        .map(crate::thread::ThreadId::from_guest_supplied_tid);
                let signum = request.arg(1);
                if signum <= LINUX_MAX_SIGNUM
                    && target.is_none_or(|target| {
                        target == thread.tid || !thread.registry.is_live(target)
                    })
                {
                    return None;
                }
            }
            131 => {
                let target =
                    crate::namespace::pid::guest_tid_to_kernel_for(kernel, request.arg(1) as i32)
                        .map(crate::thread::ThreadId::from_guest_supplied_tid);
                let signum = request.arg(2);
                if signum <= LINUX_MAX_SIGNUM
                    && target.is_none_or(|target| {
                        target == thread.tid || !thread.registry.is_live(target)
                    })
                {
                    return None;
                }
            }
            _ => {}
        }

        let outcome = match request.number.raw() {
            96 => {
                let addr = request.arg(0);
                thread.registry.set_clear_child_tid(thread.tid, addr);
                let Some(visible) = u32::try_from(kernel.thread().key().tid.raw())
                    .ok()
                    .and_then(|tid| crate::namespace::pid::kernel_to_ns_for(kernel, tid))
                else {
                    return Some(Ok(DispatchOutcome::errno(LINUX_ESRCH)));
                };
                DispatchOutcome::Returned {
                    value: i64::from(visible),
                }
            }
            98 => {
                let hvpatch_linux_tid = u32::try_from(kernel.thread().key().tid.raw())
                    .ok()
                    .and_then(|tid| crate::namespace::pid::kernel_to_ns_for(kernel, tid));
                let clock = Arc::clone(kernel.task().container().clock());
                dispatch_threaded_futex(
                    &clock,
                    request,
                    memory,
                    reporter,
                    thread.futex,
                    thread.tid,
                    thread.registry,
                    hvpatch_linux_tid,
                )
            }
            99 => {
                // set_robust_list: len must equal sizeof(struct
                // robust_list_head) (24); anything else → EINVAL (matches the
                // serialized macro handler — LTP set_robust_list01).
                let len = request.arg(1);
                if len != 24 {
                    DispatchOutcome::Errno {
                        errno: LINUX_EINVAL,
                    }
                } else {
                    DispatchOutcome::Returned { value: 0 }
                }
            }
            124 => DispatchOutcome::SchedulerYield,
            172 => DispatchOutcome::Returned {
                value: i64::from(self.identity_snapshot(kernel).pid),
            },
            130 => {
                let target =
                    crate::thread::ThreadId::from_guest_supplied_tid(request.arg(0) as i32);
                let signum = request.arg(1);
                {
                    let info = (signum != 0).then(|| {
                        crate::linux_abi::LinuxSiginfo::kill(
                            signum as i32,
                            crate::linux_abi::LINUX_SI_TKILL,
                            crate::dispatch::signal::ns_visible_sender_pid(kernel),
                            kernel.resources().credentials().ruid().raw(),
                        )
                    });
                    self.hvpatch_specific_thread_signal(kernel, None, target.raw(), signum, info)
                        .unwrap_or_else(|| DispatchOutcome::errno(LINUX_ESRCH))
                }
            }
            131 => {
                let target =
                    crate::thread::ThreadId::from_guest_supplied_tid(request.arg(1) as i32);
                let signum = request.arg(2);
                {
                    let info = (signum != 0).then(|| {
                        crate::linux_abi::LinuxSiginfo::kill(
                            signum as i32,
                            crate::linux_abi::LINUX_SI_TKILL,
                            crate::dispatch::signal::ns_visible_sender_pid(kernel),
                            kernel.resources().credentials().ruid().raw(),
                        )
                    });
                    self.hvpatch_specific_thread_signal(
                        kernel,
                        Some(request.arg(0) as i32),
                        target.raw(),
                        signum,
                        info,
                    )
                    .unwrap_or_else(|| DispatchOutcome::errno(LINUX_ESRCH))
                }
            }
            178 => match crate::vcpu_loop::ns_visible_guest_tid(self, kernel) {
                Some(tid) => DispatchOutcome::Returned {
                    value: i64::from(tid),
                },
                None => DispatchOutcome::errno(LINUX_ESRCH),
            },
            449 => {
                let clock = Arc::clone(kernel.task().container().clock());
                dispatch_futex_waitv_args(
                    &clock,
                    memory,
                    Some(thread.futex),
                    request.arg(0),
                    request.arg(1),
                    request.arg(2),
                    request.arg(3),
                    request.arg(4),
                )
            }
            _ => DispatchOutcome::Errno {
                errno: LINUX_ENOSYS,
            },
        };

        Some(Ok(outcome))
    }

    fn dispatch_inner<R: NormalizedDispatchRoute>(
        &mut self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: Option<ThreadCtx>,
        mut route: R,
    ) -> Result<DispatchOutcome, DispatchError> {
        let syscall = lookup_aarch64(request.number.raw());
        let name = syscall.map_or("unknown", |syscall| syscall.name);

        // The calling MM's vDSO realtime word follows a guest `clock_settime`
        // made by any process (see `dispatch_threaded`).
        if let Err(error) =
            self.sync_vvar_realtime_offset(kernel.task().container().clock(), memory)
        {
            tracing::error!("vvar realtime re-stamp failed: {error}");
            return Err(DispatchError::from(error));
        }

        // Reusable guest-memory watchpoint (`watchpoint` feature +
        // CARRICK_WATCH_ADDR=<hex>): fire a probe with the current u64 at the
        // watched address before each syscall, so a trace can bracket which
        // syscall changes it.
        #[cfg(feature = "watchpoint")]
        if let Some(addr) = watch_addr()
            && let Ok(bytes) = memory.read_bytes(addr, 8)
        {
            let mut le = [0u8; 8];
            le.copy_from_slice(&bytes[..8]);
            crate::probes::mem_watch(request.number.raw(), addr, u64::from_le_bytes(le));
        }

        // Syscalls migrated to the normalized SyscallCtx handler contract are
        // dispatched here first; the borrow of memory/reporter is scoped to
        // the call, so the legacy match below can still use them for the rest.
        if let Some(result) = route.dispatch(self, kernel, request, memory, reporter, thread) {
            let outcome = lower_handler_result(result)?;
            // Consumption-based EPOLLET re-arm (see `epoll_rearm_after_io`).
            resources::with_captured_resources(kernel, || {
                self.epoll_rearm_after_io(&request, &outcome);
            });
            return Ok(outcome);
        }

        // The normalized macro table is the single authoritative syscall
        // registry. Any number it does not claim is genuinely unimplemented:
        // record a structured compat event and return ENOSYS. The supervisor
        // must never panic on guest input — an unknown syscall is the guest's
        // problem to handle (it gets -ENOSYS), not ours to crash on.
        reporter.record(CompatEvent::unhandled_syscall(
            request.number.raw(),
            name,
            request.args,
        ));
        Ok(DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        })
    }
}
