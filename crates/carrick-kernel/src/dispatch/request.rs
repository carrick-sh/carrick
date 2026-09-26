use std::sync::Arc;

use carrick_abi::LinuxErrno;
use carrick_guest_mem::CurrentMmMemory;
use serde::Serialize;

use super::mm_mutation::MmMutationGuard;
use super::{DispatchOutcome, MmExecutorParticipation};
use crate::compat::{CompatEvent, CompatReporter, SyscallArgs};
use crate::linux_abi::{CanonicalNr, LinuxGuestAbi, NativeNr};

pub(crate) fn threaded_independent_dispatch_supports(number: u64) -> bool {
    matches!(number, 96 | 98 | 99 | 124 | 130 | 131 | 172 | 178 | 449)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SyscallRequest {
    /// The CANONICAL (asm-generic/aarch64) syscall number the dispatch tables
    /// switch on. Typed [`CanonicalNr`] so it cannot be swapped with
    /// [`native_number`](Self::native_number) at a constructor.
    pub number: CanonicalNr,
    pub args: SyscallArgs,
    pub guest_abi: LinuxGuestAbi,
    /// The guest's architecture-native syscall number (see
    /// [`carrick_hal::RawSyscall::native_number`]): equals `number` for aarch64
    /// guests, the raw x86_64 UAPI number for x86_64 guests. seccomp filters are
    /// evaluated against this, not the normalized `number`.
    pub native_number: NativeNr,
    /// Current guest stack pointer at the syscall trap, when the run loop can
    /// cheaply read it from the vCPU. Legacy/synthetic dispatch paths leave
    /// this absent.
    pub current_guest_sp: Option<u64>,
}

impl SyscallRequest {
    /// Build an aarch64-ABI request from a bare canonical number (aarch64
    /// guests issue canonical numbers, so native == canonical). Takes `u64`
    /// deliberately — the hundreds of literal-number test call sites stay
    /// unchanged; the typed wrap happens here, in ONE place.
    pub fn new(number: u64, args: SyscallArgs) -> Self {
        Self {
            number: CanonicalNr(number),
            args,
            guest_abi: LinuxGuestAbi::Aarch64,
            native_number: NativeNr(number),
            current_guest_sp: None,
        }
    }

    pub fn with_guest_abi(mut self, guest_abi: LinuxGuestAbi) -> Self {
        self.guest_abi = guest_abi;
        self
    }

    pub fn with_current_guest_sp(mut self, current_guest_sp: Option<u64>) -> Self {
        self.current_guest_sp = current_guest_sp;
        self
    }

    /// Populate trap stack metadata from the backend when the transport did not
    /// supply it. The fallback must not be evaluated for captured metadata.
    pub fn with_guest_sp_fallback(self, read_sp: impl FnOnce() -> Option<u64>) -> Self {
        self.with_current_guest_sp(self.current_guest_sp.or_else(read_sp))
    }

    pub fn arg(&self, index: usize) -> u64 {
        self.args.0[index]
    }

    /// Build a request from the ISA-neutral [`carrick_hal::RawSyscall`] the
    /// backend now hands back from `next_syscall` (the per-ISA register decode
    /// moved into the backend's `GuestArch`; the runtime loop only sees
    /// number + args).
    pub fn from_raw(raw: carrick_hal::RawSyscall) -> Self {
        Self {
            number: raw.number,
            args: SyscallArgs::from(raw.args),
            // The backend's `GuestArch` stamped the guest ABI onto the decoded
            // syscall (it cannot be inferred here — the no-threads / combined
            // Linux loops are type-erased over the ISA). Reading it off `raw`
            // means no call site can forget it and mis-marshal the x86 path.
            guest_abi: raw.guest_abi,
            native_number: raw.native_number,
            current_guest_sp: raw.current_guest_sp,
        }
    }
}

/// One immutable syscall identity plus the effective scalar arguments selected
/// by the one-time preflight pipeline.
#[derive(Debug, Clone, Copy)]
pub struct PreparedSyscall {
    pub original_args: SyscallArgs,
    pub request: SyscallRequest,
}

#[cfg(test)]
mod captured_metadata_tests {
    use super::*;

    #[test]
    fn captured_stack_pointer_needs_no_backend_read() {
        for scale in [1, 8, 32, 128] {
            let mut reads = 0;
            for index in 0..scale {
                let sp = index * 16;
                let raw = carrick_hal::RawSyscall {
                    number: CanonicalNr(132), // sigaltstack consumes this metadata
                    native_number: NativeNr(132),
                    guest_abi: LinuxGuestAbi::Aarch64,
                    args: [0; 6],
                    current_guest_sp: Some(sp),
                };
                let request = SyscallRequest::from_raw(raw).with_guest_sp_fallback(|| {
                    reads += 1;
                    Some(sp)
                });
                assert_eq!(request.current_guest_sp, Some(sp));
                assert_eq!(
                    crate::observe::SyscallInfo::new(&request).current_guest_sp(),
                    Some(sp)
                );
            }
            assert_eq!(reads, 0, "captured metadata must not trigger backend reads");
        }
    }

    #[test]
    fn missing_stack_pointer_reads_backend_once_and_preserves_failure() {
        for result in [Some(0), Some(0x9000), None] {
            let mut reads = 0;
            let request = SyscallRequest::new(132, SyscallArgs::new([0; 6]))
                .with_guest_sp_fallback(|| {
                    reads += 1;
                    result
                });
            assert_eq!(request.current_guest_sp, result);
            assert_eq!(reads, 1);
        }
    }
}

impl PreparedSyscall {
    pub(crate) fn effective_info(&self) -> crate::observe::SyscallInfo<'_> {
        crate::observe::SyscallInfo::new_effective(&self.request, self.original_args)
    }
}

/// Result of the one-time interceptor and policy preflight.
///
/// Deliberately not `Clone`/`Copy`: terminal dispatch outcomes own continuation
/// and descriptor state that must retain a single run-loop owner.
pub enum PreparedDispatch {
    Invoke(PreparedSyscall),
    Complete {
        syscall: PreparedSyscall,
        outcome: DispatchOutcome,
    },
}

/// Merge one policy-layer terminal result without letting a later layer weaken
/// an earlier one. A signal death is stricter than an errno, which is stricter
/// than seccomp's ABI-defined `ERRNO|0` successful return. Equal-strength
/// outcomes preserve the earlier policy layer's deterministic decision.
pub(crate) fn merge_policy_terminal(
    terminal: &mut Option<DispatchOutcome>,
    candidate: DispatchOutcome,
) {
    fn restriction_rank(outcome: &DispatchOutcome) -> u8 {
        match outcome {
            DispatchOutcome::SignalDeath { .. } => 2,
            DispatchOutcome::Errno { .. } => 1,
            _ => 0,
        }
    }

    let should_replace = match terminal.as_ref() {
        Some(current) => restriction_rank(&candidate) > restriction_rank(current),
        None => true,
    };
    if should_replace {
        *terminal = Some(candidate);
    }
}

/// Single owner for terminal syscall publication across deferred run-loop work.
pub struct SyscallCompletionToken {
    syscall: PreparedSyscall,
    context: crate::kernel::KernelContext,
    container_id: crate::kernel::container::ContainerId,
    observers: Option<Arc<crate::observe::ObserverChain>>,
}

impl SyscallCompletionToken {
    pub fn new(
        syscall: PreparedSyscall,
        context: crate::kernel::KernelContext,
        observers: Option<Arc<crate::observe::ObserverChain>>,
    ) -> Self {
        let container_id = context.task().container().id();
        Self {
            syscall,
            context,
            container_id,
            observers,
        }
    }

    pub const fn syscall(&self) -> PreparedSyscall {
        self.syscall
    }

    /// Publish a return only after the engine has accepted the actual guest
    /// completion. Ownership of `self` makes duplicate publication impossible.
    pub fn publish_return(self, reporter: &CompatReporter, value: i64) {
        debug_assert_eq!(self.context.task().container().id(), self.container_id);
        let info = self.syscall.effective_info();
        let outcome = crate::observe::SyscallOutcome::from_retval(value);
        reporter.record(CompatEvent::SyscallReturn {
            number: info.number(),
            name: ::std::borrow::Cow::Borrowed(info.name()),
            retval: outcome.value,
            errno: outcome.errno.map(LinuxErrno::get),
        });
        if let Some(observers) = self.observers {
            let process = crate::observe::ProcessInfo::new(&self.context);
            observers.on_syscall_return(&process, &info, &outcome);
        }
    }
}

/// Explicit executor authority for external host operations. The running
/// lease is supplied separately by the dispatch route and authenticated at use.
#[derive(Clone, Copy)]
pub struct HostWaitContext<'a> {
    pub scheduler: &'a crate::kernel::Scheduler,
    pub registration: &'a crate::kernel::ExecutorRegistration,
}

/// Uniform context handed to every normalized syscall handler. The optional
/// host-wait capability is explicit; off-executor callers do not fabricate CPU
/// ownership from a numeric thread ID.
pub struct SyscallCtx<'a, M: CurrentMmMemory> {
    pub host_wait: Option<HostWaitContext<'a>>,
    /// Coherent kernel object generation captured once at syscall entry.
    pub kernel: &'a crate::kernel::KernelContext,
    pub request: SyscallRequest,
    pub memory: &'a mut M,
    pub reporter: &'a CompatReporter,
    /// Present only when the syscall is dispatched on behalf of a specific
    /// guest thread (the multi-threaded runtime path). Carries this thread's
    /// tid and the shared thread/futex coordination tables. `None` for the
    /// single-threaded `dispatch` path (legacy callers + unit tests), where
    /// tid-aware handlers fall back to pid-based answers.
    pub thread: Option<ThreadCtx<'a>>,
    pub execution_lease: Option<&'a crate::kernel::objects::ThreadExecutionLease>,
    /// The caller's exact-MM executor admission. Present on the ordinary
    /// single-threaded and production HVPatch routes so a handler can cross a
    /// typed boundary that temporarily removes only this caller from its MM's
    /// executor population. Mutation handlers deliberately do not receive it:
    /// they already execute under a stronger stage-1 authority.
    pub(crate) mm_executor: Option<&'a mut MmExecutorParticipation>,
}

impl<M: CurrentMmMemory> SyscallCtx<'_, M> {
    #[inline]
    pub fn can_host_wait(&self) -> bool {
        self.host_wait.is_some() && self.execution_lease.is_some() && self.mm_executor.is_some()
    }
}

/// Context available only after the outer run loop has established structural
/// page-table mutation authority for this exact syscall and MM.
pub struct MutationSyscallCtx<'a, 'mutation, 'authority, M: CurrentMmMemory> {
    pub kernel: &'a crate::kernel::KernelContext,
    pub request: SyscallRequest,
    pub memory: &'a mut M,
    pub reporter: &'a CompatReporter,
    pub thread: Option<ThreadCtx<'a>>,
    pub(crate) mm_mutation: &'mutation mut MmMutationGuard<'authority>,
    pub execution_lease: Option<&'a crate::kernel::objects::ThreadExecutionLease>,
}

impl<M: CurrentMmMemory> MutationSyscallCtx<'_, '_, '_, M> {
    #[inline]
    pub fn number(&self) -> u64 {
        self.request.number.raw()
    }

    #[inline]
    pub fn raw_args(&self) -> SyscallArgs {
        self.request.args
    }

    #[inline]
    pub fn guest_abi(&self) -> LinuxGuestAbi {
        self.request.guest_abi
    }

    pub fn tid(&self) -> crate::thread::ThreadId {
        self.thread
            .map(|thread| thread.tid)
            .unwrap_or_else(crate::thread::ThreadId::main_from_host_pid)
    }
}

impl<M: CurrentMmMemory> SyscallCtx<'_, M> {
    #[inline]
    pub fn number(&self) -> u64 {
        self.request.number.raw()
    }

    #[inline]
    pub fn raw_args(&self) -> SyscallArgs {
        self.request.args
    }

    #[inline]
    pub fn guest_abi(&self) -> LinuxGuestAbi {
        self.request.guest_abi
    }

    /// The current guest thread's Linux tid, as keyed by the signal/IO-wait
    /// machinery (`host_signal`, `io_wait`). Falls back to the process pid (the
    /// main thread's tid) on the single-threaded path where no thread ctx is
    /// present — matching how the run loop derives `this_tid`.
    #[inline]
    pub fn tid(&self) -> crate::thread::ThreadId {
        self.thread
            .map(|t| t.tid)
            .unwrap_or_else(crate::thread::ThreadId::main_from_host_pid)
    }

    #[inline]
    pub(crate) fn with_execution_lease<R>(
        &self,
        operation: impl FnOnce(&crate::kernel::objects::ThreadExecutionLease) -> R,
    ) -> Option<R> {
        self.execution_lease.map(operation)
    }
}

/// Exact classifier for syscalls that consume a live `ThreadExecutionLease`.
///
/// `process_vm_readv` (270), `process_vm_writev` (271), and `ptrace` (117)
/// memory access requests (`PTRACE_PEEKTEXT`, `PTRACE_PEEKDATA`, `PTRACE_POKETEXT`,
/// `PTRACE_POKEDATA`) consume the execution lease. The selected
/// filesystem durability operations (`sync`, `fsync`, `fdatasync`,
/// `sync_file_range`, `syncfs`) and scalar `write` also borrow it for host-wait handoff. Other
/// ordinary syscalls and non-memory ptrace requests execute without acquiring or
/// consulting the execution lease lock.
#[inline]
pub const fn syscall_requires_execution_lease(nr: u64, args: SyscallArgs) -> bool {
    match nr {
        64 | 81..=84 | 267 | 270 | 271 => true,
        117 => matches!(
            args.0[0],
            carrick_abi::LINUX_PTRACE_PEEKTEXT
                | carrick_abi::LINUX_PTRACE_PEEKDATA
                | carrick_abi::LINUX_PTRACE_POKETEXT
                | carrick_abi::LINUX_PTRACE_POKEDATA
        ),
        _ => false,
    }
}

/// Per-thread coordination handles handed to tid-aware syscall handlers
/// (`gettid`, `set_tid_address`, `futex`).
#[derive(Clone, Copy)]
pub struct ThreadCtx<'a> {
    pub tid: crate::thread::ThreadId,
    pub registry: &'a crate::thread::ThreadRegistry,
    pub futex: &'a crate::thread::FutexTable,
    pub work_scope: Option<&'a carrick_observability::work_meter::WorkScope>,
    /// The in-guest scheduler zone serving this thread's process's private
    /// futexes, with the process's zone key, when the carrier runs one
    /// ([`crate::el1_zone`]). `None`: the private futex table serves them.
    pub zone: Option<(&'static carrick_el1_abi::ZoneTables, u64)>,
}

impl<'a> ThreadCtx<'a> {
    #[inline]
    pub const fn new(
        tid: crate::thread::ThreadId,
        registry: &'a crate::thread::ThreadRegistry,
        futex: &'a crate::thread::FutexTable,
    ) -> Self {
        Self {
            tid,
            registry,
            futex,
            work_scope: None,
            zone: None,
        }
    }

    /// Serve this thread's private futexes from the in-guest zone under
    /// `zone_mm` (its process's zone key).
    #[inline]
    pub fn with_zone(mut self, zone: Option<(&'static carrick_el1_abi::ZoneTables, u64)>) -> Self {
        self.zone = zone;
        self
    }

    #[inline]
    pub fn with_work_scope(
        mut self,
        scope: &'a carrick_observability::work_meter::WorkScope,
    ) -> Self {
        self.work_scope = Some(scope);
        self
    }
}
