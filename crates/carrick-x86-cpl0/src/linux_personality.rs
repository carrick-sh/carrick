//! Linux OS personality implementation for the x86 CPL0 carrier.

#![cfg(all(target_os = "none", target_arch = "x86_64"))]

use carrick_abi::{LINUX_SEGV_ACCERR, LINUX_SEGV_MAPERR, LINUX_SIGSEGV, LinuxErrno, LinuxSiginfo};
use carrick_el1::isa::x86::context::native::{CpuBinding, NativeFrame, checked_scheduler_slot};
use carrick_el1::isa::x86::context::scheduler::XsaveArea;
use carrick_el1_abi::{
    Action, Counters, CurrentTask, DelegatedOpenFile, FileTables, HostObjectBinding,
    HostObjectReleaseCrossing, HostObjectWriteCrossing, HostReadinessCrossing, fd_map_lookup,
};
use carrick_el1_linux::crossing_operand::{
    CrossingOperand, classify_fd_operand, resolve_crossing_operand,
};
use carrick_el1_linux::dispatch::GuestDispatchFrame;
use carrick_el1_linux::dispatch::{PollSignalMask, PollTimeoutKind, dispatch_syscall_with_native};
use carrick_el1_linux::lifecycle::LifecycleVenue;
use carrick_el1_linux::thread_setup::GuestLifecycleVenue;
use carrick_guest_arch::{LayoutBackend, NativeReturnWord, SlotId, UserVa};
use carrick_personality_linux::crossing::{HostCrossingSet, evaluate_host_crossing};
use carrick_personality_linux::dispatch::{CompletionRoute, SyscallFrame};
use carrick_personality_linux::entry::{CanonicalCall, decode_x86_snapshot};
use carrick_personality_linux::lifecycle::LinuxWaitStatus;
use carrick_syscall_abi::CanonicalNr;
use carrick_x86_carrier::entry::{
    PageFaultStack, cross_owner_grant, fatal_boot, fatal_error, forward_to_host, halt, notify_work,
    prepare_user_page_fault, user_fault_gate,
};
use carrick_x86_carrier::native_execution::{capture, migrate};
use carrick_x86_carrier::personality::{
    CallContext, ControlFlow, EntryDecodeError, ExecutionContext, OwnedContinuation, Personality,
    PersonalityAbi, TerminationRequest,
};
use core::sync::atomic::Ordering;

use crate::{anonymous, native_execution, native_process};

pub fn file_tables(binding: &CpuBinding) -> FileTables<'static> {
    // SAFETY: current carrier CPU binding was installed by stopped bootstrap;
    // its supervisor mapping remains live until every guest CPU stops.
    unsafe { FileTables::in_guest(binding.file_region) }.unwrap_or_else(|error| {
        // SAFETY: this carrier owns the fatal doorbell; publish the complete
        // venue-refusal domain before halting, rather than incidental RAX bits.
        unsafe {
            core::arch::asm!("out dx, al", in("dx") carrick_x86_carrier::entry::FATAL_PORT,
                in("rax") error.fatal_payload(), options(nostack, preserves_flags));
        }
        halt()
    })
}

// SAFETY: live diagnostic counter exported for test/telemetry inspection.
#[unsafe(no_mangle)]
pub static CARRICK_CPL0_ISA_UNSUPPORTED_FORWARDS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Forward a crossing the ring did not serve, applying the shared fd-operand
/// resolver's verdict ([`CrossingOperand`]) to this ISA's frame registers.
pub fn forward_crossing(frame: &mut NativeFrame, operand: Option<CrossingOperand>) {
    match operand {
        Some(CrossingOperand::ObjectWrite(binding)) => {
            let saved = (frame.rdi, frame.rcx);
            frame.rax = HostObjectWriteCrossing::NUMBER;
            frame.rdi = binding.encoded() as u64;
            frame.rcx = HostObjectWriteCrossing::FRAME_TAG;
            forward_to_host(frame);
            (frame.rdi, frame.rcx) = saved;
        }
        Some(CrossingOperand::Rewrite { index, host_fd }) => {
            let saved = core::mem::replace(frame.syscall_argument_mut(index), host_fd as u64);
            forward_to_host(frame);
            *frame.syscall_argument_mut(index) = saved;
        }
        // The shared dispatch owner answered these in ring before any Forward.
        Some(CrossingOperand::InRing | CrossingOperand::BadFd) => fatal_error(frame),
        Some(CrossingOperand::Pass) | None => forward_to_host(frame),
    }
}

pub struct NativeDispatch<'a> {
    pub frame: &'a mut NativeFrame,
    pub fpstate: &'a mut XsaveArea,
    pub call: CanonicalCall,
    pub publications: &'a core::sync::atomic::AtomicU64,
    pub slot: Option<carrick_guest_arch::SlotId>,
    pub file_table: u64,
    pub files: &'a FileTables<'a>,
    /// The caller's retained host-file venue; `None` keeps every call on
    /// its existing route.
    pub host_file: Option<HostFileVenue<'a>>,
    /// The answer staged ahead of the crossing table, completed by the caller.
    pub staged: Option<carrick_personality_linux::native_host_file::HostFileStage>,
    /// The shared resolver's verdict on the crossing's descriptor operand,
    /// applied to the frame on the `Forward` route.
    pub crossing_operand: Option<CrossingOperand>,
}

#[derive(Clone, Copy)]
pub struct HostFileVenue<'a> {
    pub task: &'a CurrentTask,
    pub cpu_slot: u32,
    pub origin: carrick_core_abi::service::ServiceOrigin,
}

impl SyscallFrame for NativeDispatch<'_> {
    fn canonical_ordinal(&self) -> CanonicalNr {
        self.call.canonical
    }
    fn argument(&self, index: usize) -> Option<u64> {
        self.call.args.get(index).copied()
    }
    fn result(&self) -> NativeReturnWord {
        NativeReturnWord(self.frame.rax)
    }
    fn set_result(&mut self, result: NativeReturnWord) {
        self.frame.rax = result.0;
    }
    fn slot(&self) -> Option<carrick_guest_arch::SlotId> {
        self.slot
    }
    fn task_index(&self) -> usize {
        if self.slot.is_some() { 0 } else { usize::MAX }
    }
    fn user_sp(&self) -> Option<UserVa> {
        Some(self.call.stack)
    }
}

impl GuestDispatchFrame for NativeDispatch<'_> {
    fn can_capture_thread_child(&self, stack: UserVa, tls: Option<UserVa>) -> bool {
        stack.raw() != 0 && stack.raw() < (1 << 47) && tls.is_none_or(|tls| tls.raw() < (1 << 47))
    }
    fn capture_x86_thread_child(
        &self,
        child: &mut carrick_sched_core::ParkedContextWords,
        context: &carrick_personality_linux::lifecycle::ChildContext,
    ) -> bool {
        if !self.can_capture_thread_child(context.stack, context.tls) {
            return false;
        }
        *child = capture(self.frame, self.fpstate);
        use carrick_guest_arch::ProcessContext;
        child.set_user_stack(context.stack.raw());
        child.set_syscall_return(context.result.raw() as u64);
        if let Some(tls) = context.tls {
            child.set_thread_pointer(carrick_guest_arch::ThreadPointerRegister::FS, tls.raw());
        }
        true
    }
    fn restart_syscall(&mut self) {
        if carrick_guest_arch::SyscallReturnFrame::rewind_to_syscall(self.frame).is_none() {
            fatal_boot!();
        }
    }
    fn operation_resume_pc(
        &self,
    ) -> Option<carrick_el1::substrate::sched::object_wait::OperationResumePc> {
        // x86 instructions are byte-aligned: only a null PC is refused.
        carrick_guest_arch::SyscallReturnFrame::syscall_pc(self.frame)
            .and_then(carrick_el1::substrate::sched::object_wait::OperationResumePc::from_raw)
    }
    fn native_number(&self) -> carrick_guest_arch::NativeOrdinal {
        self.call.native
    }
    fn crossing_set(&self) -> carrick_personality_linux::crossing::HostCrossingSet {
        carrick_personality_linux::crossing::HostCrossingSet::X86
    }
    fn settles_owed_work_at_continuation_boundary(&self) -> bool {
        true
    }
    fn rerun_after_owed_work(&mut self) -> bool {
        // The crossing table may already have written its refusal into RAX.
        restart_native_syscall(
            self.frame,
            carrick_guest_arch::NativeOrdinal::new(self.call.native.raw()),
        );
        true
    }

    fn may_serve_descriptor(&self) -> bool {
        [
            carrick_personality_linux::crossing::nr::CLOSE,
            carrick_personality_linux::crossing::nr::DUP,
            carrick_personality_linux::crossing::nr::DUP3,
        ]
        .contains(&carrick_syscall_abi::CanonicalNr(self.call.canonical.raw()))
            || self.call.canonical.raw() == carrick_syscall_abi::CARRICK_PRIVATE_X86_DUP2
    }

    fn preflight_host_crossing(
        &mut self,
        ordinal: u64,
    ) -> carrick_personality_linux::dispatch::HostCrossingPreflight {
        let venue = self.host_file;
        let operand = resolve_crossing_operand(
            HostCrossingSet::X86,
            CanonicalNr::new(ordinal),
            &self.call.args,
            |fd| {
                classify_fd_operand(
                    self.files.fd_map(),
                    self.files.opens(),
                    self.file_table,
                    fd,
                    |fd| {
                        let venue = venue?;
                        let ipc = carrick_el1_linux::ipc::guest_venue(venue.cpu_slot)?;
                        let table = carrick_el1_linux::ipc::native_table(&ipc, venue.task)?;
                        carrick_el1_linux::ipc::native_descriptor(&ipc, table, fd)
                    },
                )
            },
            |address| {
                let task = venue?.task;
                let mut copy = carrick_el1_linux::file::ValidatedCopy {
                    task,
                    validator: &carrick_el1_linux::file::HardwareValidator,
                };
                let mut byte = [0u8];
                carrick_el1_linux::file::UserCopy::copy_in(&mut copy, &mut byte, address)
                    .then_some(byte[0])
            },
        );
        self.crossing_operand = Some(operand);
        operand.preflight()
    }

    fn stage_native_host_file(&mut self) -> bool {
        let Some(venue) = self.host_file else {
            return false;
        };
        let (files, file_table) = (self.files, self.file_table);
        // The carrier's file table delegates the run's stdio streams to host
        // objects; their transfers keep that route.
        let delegated = |fd: i32| {
            fd_map_lookup(files.fd_map(), file_table, fd)
                .and_then(|(handle, _)| handle.checked_sub(1))
                .and_then(|index| files.opens().get(index as usize))
                .and_then(DelegatedOpenFile::host_object)
                .is_some()
        };
        self.staged = crate::native_host_file::stage(
            &self.call,
            venue.task,
            venue.cpu_slot,
            venue.origin,
            delegated,
        );
        self.staged.is_some()
    }

    fn staged_for_ring_owner(&self) -> bool {
        matches!(
            self.staged,
            Some(carrick_personality_linux::native_host_file::HostFileStage::InRing)
        )
    }

    fn release_host_object(
        &mut self,
        binding: HostObjectBinding,
        handle: u32,
        incarnation: u64,
    ) -> bool {
        let saved = (
            self.frame.rax,
            self.frame.rdi,
            self.frame.rsi,
            self.frame.rdx,
            self.frame.rcx,
        );
        self.frame.rax = HostObjectReleaseCrossing::NUMBER;
        self.frame.rdi = binding.encoded() as u64;
        self.frame.rsi = handle as u64;
        self.frame.rdx = incarnation;
        self.frame.rcx = HostObjectReleaseCrossing::FRAME_TAG;
        forward_to_host(self.frame);
        let acknowledged = self.frame.rax == 0;
        (
            self.frame.rax,
            self.frame.rdi,
            self.frame.rsi,
            self.frame.rdx,
            self.frame.rcx,
        ) = saved;
        acknowledged
    }

    fn may_serve_poll(&self) -> bool {
        self.call.native
            == carrick_guest_arch::NativeOrdinal::new(
                carrick_syscall_abi::syscall_x86_64::X86_POLL.raw(),
            )
            || self.call.native
                == carrick_guest_arch::NativeOrdinal::new(
                    carrick_syscall_abi::syscall_x86_64::X86_PPOLL.raw(),
                )
    }

    fn poll_timeout_kind(&self) -> PollTimeoutKind {
        if self.call.native
            == carrick_guest_arch::NativeOrdinal::new(
                carrick_syscall_abi::syscall_x86_64::X86_POLL.raw(),
            )
        {
            PollTimeoutKind::Milliseconds
        } else {
            PollTimeoutKind::Timespec
        }
    }

    fn query_host_readiness(
        &mut self,
        entries: &mut [carrick_el1_abi::HostReadinessEntry],
        timeout_ms: i32,
        sig_mask: PollSignalMask,
    ) -> Option<i64> {
        if !self.may_serve_poll() {
            return None;
        }
        let saved = (
            self.frame.rdi,
            self.frame.rsi,
            self.frame.rdx,
            self.frame.r10,
            self.frame.r8,
            self.frame.rcx,
        );
        self.frame.rax = HostReadinessCrossing::NUMBER;
        self.frame.rdi = entries.as_mut_ptr() as u64;
        self.frame.rsi = entries.len() as u64;
        self.frame.rdx = timeout_ms as u64;
        self.frame.r10 = match sig_mask {
            PollSignalMask::Inherit => 0,
            PollSignalMask::Replace(bits) => bits.bits(),
        };
        self.frame.r8 = match sig_mask {
            PollSignalMask::Replace(_) => HostReadinessCrossing::MASK_REPLACE,
            PollSignalMask::Inherit => HostReadinessCrossing::MASK_NONE,
        };
        self.frame.rcx = HostReadinessCrossing::FRAME_TAG;
        forward_to_host(self.frame);
        let result = self.frame.rax as i64;
        (
            self.frame.rdi,
            self.frame.rsi,
            self.frame.rdx,
            self.frame.r10,
            self.frame.r8,
            self.frame.rcx,
        ) = saved;
        Some(result)
    }

    fn arm_frame(&mut self) -> Option<&mut carrick_el1_abi::TrapFrame> {
        None
    }
    fn arm_frame_ref(&self) -> Option<&carrick_el1_abi::TrapFrame> {
        None
    }
    fn arm_scheduler(&self) -> bool {
        false
    }
    fn robust_publications(&self) -> Option<&core::sync::atomic::AtomicU64> {
        Some(self.publications)
    }
    fn record_isa_unsupported_forward(&self) {
        CARRICK_CPL0_ISA_UNSUPPORTED_FORWARDS.fetch_add(1, Ordering::Relaxed);
    }

    fn restore_signal_frame(
        &mut self,
        copy_in: &mut dyn carrick_personality_linux::lifecycle::UserCopy,
    ) -> Result<carrick_personality_linux::signal::RestoredSignalFrame, LinuxErrno> {
        let mut backend = carrick_el1_linux::x86_signal::LinuxX86Backend;
        carrick_personality_linux::signal::SignalBackend::restore_signal_frame(
            &mut backend,
            self.frame,
            &mut self.fpstate.0,
            &mut |dst, va| copy_in.copy_in(dst, va).is_done(),
        )
        .map_err(|_| carrick_personality_linux::abi::signal::LINUX_EFAULT)
    }

    fn setup_signal_frame(
        &mut self,
        params: carrick_personality_linux::signal::SignalFrameParams,
        siginfo: Option<&[u8]>,
        copy_out: &mut dyn carrick_personality_linux::lifecycle::UserCopy,
    ) -> Result<UserVa, LinuxErrno> {
        let mut backend = carrick_el1_linux::x86_signal::LinuxX86Backend;
        match carrick_personality_linux::signal::SignalBackend::setup_signal_frame(
            &mut backend,
            self.frame,
            params,
            siginfo,
            &self.fpstate.0,
            &mut |va, src| copy_out.copy_out(va, src),
        ) {
            Ok(carrick_personality_linux::signal::SignalFrameSetup::Installed(sp)) => Ok(sp),
            Ok(carrick_personality_linux::signal::SignalFrameSetup::NotYet(_)) | Err(_) => {
                Err(carrick_personality_linux::abi::signal::LINUX_EFAULT)
            }
        }
    }
}

pub fn complete_run_failure(
    task: &CurrentTask,
    cause: carrick_core_abi::NativeRunFailureCause,
) -> ! {
    carrick_el1::isa::x86::complete_native_run_failure(
        carrick_el1_linux::common_entry::execution_binding(task),
        cause,
    )
}

pub fn complete_root_exit(task: &CurrentTask, status: LinuxWaitStatus) -> ! {
    let exit = carrick_core_abi::NativeRootExit::new(
        carrick_el1_linux::common_entry::execution_binding(task),
        status.terminal_status().unwrap_or_else(|_| fatal_boot!()),
    )
    .unwrap_or_else(|| fatal_boot!());
    // SAFETY: shared retirement authenticated this exact root completion.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") carrick_core_abi::NATIVE_ROOT_EXIT_PORT,
            in("rax") &exit as *const _ as u64,
            options(nostack, preserves_flags)
        );
    }
    halt();
}

/// The x86 frame carries its own syscall position (`NativeFrame`'s
/// `syscall_position`, #2900): a rerun, a handler entry and a parked copy
/// all read and write it there.
pub(crate) struct X86SignalMachine {
    backend: carrick_el1_linux::x86_signal::LinuxX86Backend,
    address: carrick_guest_arch::AddressContext<carrick_guest_arch::RootGpa>,
}

impl X86SignalMachine {
    pub(crate) fn new(
        address: carrick_guest_arch::AddressContext<carrick_guest_arch::RootGpa>,
    ) -> Self {
        Self {
            backend: carrick_el1_linux::x86_signal::LinuxX86Backend,
            address,
        }
    }
}

impl carrick_el1_linux::signal_delivery::SignalMachine<carrick_sched_core::ParkedContextWords>
    for X86SignalMachine
{
    type Backend = carrick_el1_linux::x86_signal::LinuxX86Backend;

    fn backend(&mut self) -> &mut Self::Backend {
        &mut self.backend
    }

    fn user_sp(&self, frame: &NativeFrame) -> UserVa {
        UserVa::new(frame.rsp)
    }

    fn restart(
        &mut self,
        frame: &mut NativeFrame,
        original: &carrick_sched_core::ParkedContextWords,
    ) -> bool {
        carrick_guest_arch::rerun_interrupted_syscall(frame, original)
    }

    fn group_exit_custody(
        &self,
        task: &CurrentTask,
    ) -> carrick_el1_linux::signal_delivery::SignalReturnRoute {
        complete_run_failure(
            task,
            carrick_core_abi::NativeRunFailureReason::X86GroupExitCustody.at_caller(),
        )
    }

    fn sync_parked_context(
        &self,
        frame: &NativeFrame,
        ctx: &mut carrick_sched_core::ParkedContextWords,
    ) {
        use carrick_el1::isa::x86::context;
        let native = context::context_words::into_native(*ctx, self.address)
            .unwrap_or_else(|_| fatal_boot!());
        let updated = context::context_words::from_syscall(
            frame,
            self.address,
            native.fs_base,
            native.gs_base,
            &native.xsave,
        )
        .unwrap_or_else(|_| fatal_boot!());
        let position = carrick_guest_arch::SyscallReturnFrame::syscall_position(frame)
            .unwrap_or_else(|| fatal_boot!());
        *ctx = context::context_words::from_native(&updated, position);
    }
}

pub(crate) fn deliver_signal_on_syscall_return(
    task: &CurrentTask,
    process: &mut carrick_el1_linux::native_process_runtime::NativeProcessEntry<
        '_,
        'static,
        native_process::Mm,
        carrick_sched_core::ParkedContextWords,
        native_process::Service,
    >,
    frame: &mut NativeFrame,
    fpstate: &XsaveArea,
    machine: &mut X86SignalMachine,
) -> Option<carrick_el1_linux::signal_delivery::SignalReturnRoute> {
    let (_, control) = task.lifecycle_refs()?;
    #[cfg(feature = "test-support")]
    crate::test_support::block_sigusr1_at_checkpoint(control);
    carrick_el1_linux::signal_delivery::deliver_signal_on_syscall_return(
        task, control, process, frame, &fpstate.0, machine,
    )
}

pub fn signal_user_return(
    frame: &mut NativeFrame,
    xsave: &XsaveArea,
    forced: Option<LinuxSiginfo>,
) -> bool {
    use carrick_el1::isa::x86::context;
    if !native_process::is_admitted() {
        return false;
    }
    let binding = context::current_cpu_binding().unwrap_or_else(|| fatal_boot!());
    let slot = SlotId::from_index(binding.cpu_slot as usize).unwrap_or_else(|| fatal_boot!());
    let source = carrick_x86_carrier::native_execution::source(slot);
    // SAFETY: return validation runs on the CPU that owns this task binding.
    let task = unsafe { &*(binding.task_address as *const CurrentTask) };
    let mut suspended = false;
    let root_exit;
    {
        let _copy_gate = user_fault_gate::install();
        let words = capture(frame, xsave);
        let mut service = native_process::Service::new(task, slot);
        native_process::drain_external_ingress(source, &mut service)
            .unwrap_or_else(|_| fatal_boot!());
        let (process_runtime, address) =
            native_process::runtime(source, task).unwrap_or_else(|_| fatal_boot!());
        let mut process = process_runtime
            .enter_registered(
                native_process::registry(),
                source,
                task,
                address,
                &words,
                &mut service,
            )
            .unwrap_or_else(|_| fatal_boot!());
        if let Some(info) = forced {
            use carrick_personality_linux::signal::policy::{SigBlockMask, Signal};
            let Some(thread) = GuestLifecycleVenue.thread(task) else {
                return false;
            };
            let blocked = SigBlockMask::blocking_all_of(
                carrick_personality_linux::signal::SignalSet::from_bits(thread.slot.blocked().0),
            );
            let Some(signal) = Signal::from_number(info.si_signo) else {
                return false;
            };
            if process.force_fault_info(signal, blocked, info).is_err() {
                return false;
            }
            let mask = blocked.signals().without(signal);
            let _ = thread.slot.store_blocked_then_read_pending(
                carrick_el1_abi::BlockedMask(mask.bits()),
                thread.slot.pending(),
            );
        }
        if let Some(route) = deliver_signal_on_syscall_return(
            task,
            &mut process,
            frame,
            xsave,
            &mut X86SignalMachine::new(address),
        ) {
            if route != carrick_el1_linux::signal_delivery::SignalReturnRoute::Suspended {
                fatal_boot!(route);
            }
            suspended = true;
        }
        root_exit = process.take_root_exit();
    }
    if let Some(status) = root_exit {
        complete_root_exit(task, status);
    }
    if suspended {
        native_execution::schedule(slot);
    }
    true
}

pub fn signal_syscall_return(frame: &mut NativeFrame, xsave: &mut XsaveArea) {
    signal_user_return(frame, xsave, None);
}

pub fn signal_irq_return(
    frame: &mut carrick_el1::isa::x86::context::scheduler::InterruptFrame,
    xsave: &mut XsaveArea,
) {
    use carrick_el1::isa::x86::context;
    let binding = context::current_cpu_binding().unwrap_or_else(|| fatal_boot!());
    let slot = SlotId::from_index(binding.cpu_slot as usize).unwrap_or_else(|| fatal_boot!());
    let source = carrick_x86_carrier::native_execution::source(slot);
    if !native_process::is_admitted() {
        return;
    }
    // SAFETY: this CPU owns its retained current-task binding during IRQ entry.
    let task = unsafe { &*(binding.task_address as *const CurrentTask) };
    let mm = carrick_el1_abi::ReservationMm::new(task.mm.key.load(Ordering::Acquire))
        .unwrap_or_else(|| fatal_boot!());
    let address = anonymous::live_words(mm)
        .and_then(|words| words.context)
        .unwrap_or_else(|| fatal_boot!());
    let mut native = context::scheduler::NativeContext {
        frame: *frame,
        address,
        fs_base: carrick_x86_carrier::native_execution::read_msr(0xc000_0100),
        gs_base: carrick_x86_carrier::native_execution::read_msr(0xc000_0102),
        xsave: xsave.clone(),
    };
    // An interrupt saves the instruction it interrupted: the frame stands
    // at its resume point, which no rerun may rewind (#2851).
    let mut returned = context::context_words::syscall_frame_from_native(
        &native,
        address,
        carrick_sched_core::SavedSyscallPc::AtSyscall,
    )
    .unwrap_or_else(|_| fatal_boot!());
    let record = source
        .zone
        .slot(slot)
        .current()
        .or_else(|| source.zone.slot(slot).host_record())
        .unwrap_or_else(|| fatal_boot!());
    let mut suspended = false;
    let root_exit;
    {
        let _copy_gate = user_fault_gate::install();
        let mut service = native_process::Service::new(task, slot);
        native_process::drain_external_ingress(source, &mut service)
            .unwrap_or_else(|_| fatal_boot!());
        let (process_runtime, runtime_address) =
            native_process::runtime(source, task).unwrap_or_else(|_| fatal_boot!());
        let mut process = process_runtime
            .enter_registered(
                native_process::registry(),
                source,
                task,
                runtime_address,
                &context::context_words::from_native(
                    &native,
                    carrick_sched_core::SavedSyscallPc::AtSyscall,
                ),
                &mut service,
            )
            .unwrap_or_else(|_| fatal_boot!());
        if let Some(route) = deliver_signal_on_syscall_return(
            task,
            &mut process,
            &mut returned,
            xsave,
            &mut X86SignalMachine::new(runtime_address),
        ) {
            if route != carrick_el1_linux::signal_delivery::SignalReturnRoute::Suspended {
                fatal_boot!(route);
            }
            suspended = true;
        }
        root_exit = process.take_root_exit();
    }
    if let Some(status) = root_exit {
        complete_root_exit(task, status);
    }
    if !suspended {
        native = context::context_words::from_syscall(
            &returned,
            address,
            native.fs_base,
            native.gs_base,
            xsave,
        )
        .unwrap_or_else(|_| fatal_boot!());
        *frame = native.frame;
        if source.zone.runnable_head(slot).is_some() {
            // SAFETY: IRQ entry owns this exact running/home record's context.
            // The frame says where its PC sits: the interrupted instruction
            // or a handler entry, which a retained rerun must never rewind
            // again (#2851, #2900).
            let position = carrick_guest_arch::SyscallReturnFrame::syscall_position(&returned)
                .unwrap_or_else(|| fatal_boot!());
            unsafe {
                *source.zone.record(record).ctx_mut() =
                    context::context_words::from_native(&native, position);
            }
            // IRQ entry owns this running/home record: a refusal is a broken
            // invariant, never contention (#1100).
            if !source.zone.requeue_preempted(slot, record).is_queued() {
                fatal_boot!();
            }
            suspended = true;
        } else if source.zone.slot(slot).queued() != 0 {
            native_execution::rearm_slice(source.zone, slot);
        }
    }
    if suspended {
        native_execution::schedule(slot);
    }
}

pub fn handle_user_page_fault(frame: &mut PageFaultStack, fpstate: &XsaveArea) -> u64 {
    let prep = match prepare_user_page_fault(frame) {
        Ok(p) => p,
        Err(code) => return code,
    };
    handle_user_page_fault_prepared(&prep, frame, fpstate)
}

pub fn handle_user_page_fault_prepared(
    prep: &carrick_x86_carrier::entry::PreparedUserPageFault<'_>,
    frame: &mut PageFaultStack,
    fpstate: &XsaveArea,
) -> u64 {
    if let Some((slot, zone, now)) = carrick_x86_carrier::entry::current_slot_and_zone() {
        zone.cpu_enter_ring(slot, zone.current_record_ref(slot), now);
    }
    let code = match supply_user_fault(prep) {
        UserFaultSupply::Served => 0,
        UserFaultSupply::Signal {
            signum,
            code,
            address,
        } => deliver_page_fault_signal(frame, fpstate, signum, code, address),
        UserFaultSupply::MmRelease(cause) => park_contended_user_fault(prep, frame, fpstate, cause),
        UserFaultSupply::TypedRelease(wait) => {
            park_owner_waiting_user_fault(prep, frame, fpstate, wait)
        }
        UserFaultSupply::Unresolved(reason) => reason,
    };
    if code == 0
        && let Some((slot, zone, now)) = carrick_x86_carrier::entry::current_slot_and_zone()
    {
        zone.cpu_enter_user(slot, zone.current_record_ref(slot), now);
    }
    code
}

fn park_owner_waiting_user_fault(
    prep: &carrick_x86_carrier::entry::PreparedUserPageFault<'_>,
    frame: &PageFaultStack,
    fpstate: &XsaveArea,
    wait: carrick_el1_abi::PortalOwnerWait,
) -> u64 {
    use carrick_el1::isa::x86::context;
    let Some(address) =
        carrick_el1_abi::ReservationMm::new(prep.task.mm.key.load(Ordering::Acquire))
            .and_then(anonymous::live_words)
            .and_then(|words| words.context)
    else {
        return 9;
    };
    let native = rust_alloc::boxed::Box::new(context::scheduler::NativeContext {
        frame: context::scheduler::InterruptFrame {
            gpr: frame.saved_gprs,
            rip: frame.rip,
            cs: frame.cs,
            flags: frame.rflags,
            rsp: frame.rsp,
            ss: frame.ss,
        },
        address,
        fs_base: carrick_x86_carrier::native_execution::read_msr(0xc000_0100),
        gs_base: carrick_x86_carrier::native_execution::read_msr(0xc000_0102),
        xsave: fpstate.clone(),
    });
    // A fault saves the faulting instruction; nothing rewinds it.
    let saved = rust_alloc::boxed::Box::new(context::context_words::from_native(
        &native,
        carrick_sched_core::SavedSyscallPc::AtSyscall,
    ));
    drop(native);
    if !native_process::is_admitted()
        && native_process::admit_root(
            *saved,
            carrick_x86_carrier::native_execution::source(prep.slot),
            carrick_x86_carrier::native_execution::task(),
        )
        .is_err()
    {
        return 9;
    }
    match anonymous::park_owner_fault_wait(prep.task, prep.slot, wait, &saved) {
        anonymous::ContendedFault::Parked => {
            drop(saved);
            native_execution::schedule(prep.slot)
        }
        anonymous::ContendedFault::Rerun => 0,
        anonymous::ContendedFault::Refused => 9,
    }
}

fn park_contended_user_fault(
    prep: &carrick_x86_carrier::entry::PreparedUserPageFault<'_>,
    frame: &PageFaultStack,
    fpstate: &XsaveArea,
    cause: carrick_sched_core::spaces::notification::SpaceWaitCause,
) -> u64 {
    use carrick_el1::isa::x86::context;
    let Some(address) =
        carrick_el1_abi::ReservationMm::new(prep.task.mm.key.load(Ordering::Acquire))
            .and_then(anonymous::live_words)
            .and_then(|words| words.context)
    else {
        return 9;
    };
    let native = rust_alloc::boxed::Box::new(context::scheduler::NativeContext {
        frame: context::scheduler::InterruptFrame {
            gpr: frame.saved_gprs,
            rip: frame.rip,
            cs: frame.cs,
            flags: frame.rflags,
            rsp: frame.rsp,
            ss: frame.ss,
        },
        address,
        fs_base: carrick_x86_carrier::native_execution::read_msr(0xc000_0100),
        gs_base: carrick_x86_carrier::native_execution::read_msr(0xc000_0102),
        xsave: fpstate.clone(),
    });
    // A fault saves the faulting instruction; nothing rewinds it.
    let saved = rust_alloc::boxed::Box::new(context::context_words::from_native(
        &native,
        carrick_sched_core::SavedSyscallPc::AtSyscall,
    ));
    drop(native);
    if !native_process::is_admitted()
        && native_process::admit_root(
            *saved,
            carrick_x86_carrier::native_execution::source(prep.slot),
            carrick_x86_carrier::native_execution::task(),
        )
        .is_err()
    {
        return 9;
    }
    match anonymous::park_contended_fault(prep.task, prep.slot, cause, &saved) {
        anonymous::ContendedFault::Parked => {
            drop(saved);
            native_execution::schedule(prep.slot)
        }
        anonymous::ContendedFault::Rerun => 0,
        anonymous::ContendedFault::Refused => 9,
    }
}

/// What the owner fault path made of one user access.
pub enum UserFaultSupply {
    /// The access is now resident; the faulting access may retry.
    Served,
    /// Linux refuses the access with this signal (an in-kernel user copy
    /// answers EFAULT instead).
    Signal {
        signum: i32,
        code: i32,
        address: UserVa,
    },
    /// Another owner holds the MM root, editor or gate. This is "not now":
    /// park on its release and retry the unchanged access.
    MmRelease(carrick_sched_core::spaces::notification::SpaceWaitCause),
    /// A typed owner receipt names either an MM release, the carrier
    /// reservation pool, or this member's host-readiness queue.
    TypedRelease(carrick_el1_abi::PortalOwnerWait),
    /// No owner could supply the access: the #PF entry reports this reason.
    Unresolved(u64),
}

/// Supply a syscall's staged user access through the same owner fault path
/// as the #PF entry, so a non-resident buffer is faulted in, never EFAULT.
/// Stage and begin a claimed native exec. A staging fault is supplied through
/// the owner fault path and the exact syscall is re-entered; a refused supply
/// is EFAULT, and a staging errno is returned as is.
fn native_exec_call(
    process: &mut carrick_el1_linux::native_process_runtime::NativeProcessEntry<
        '_,
        'static,
        native_process::Mm,
        carrick_sched_core::ParkedContextWords,
        native_process::Service,
    >,
    frame: &mut NativeFrame,
    binding: &CpuBinding,
    task: &CurrentTask,
    slot: carrick_sched_core::SlotId,
    request: carrick_el1_linux::exec_stage::ExecStageRequest,
    resume: NativeExecResume<'_>,
) -> CompletionRoute {
    let NativeExecResume { ordinal, saved } = resume;
    use carrick_el1_linux::dispatch::NativeExecStage;
    use carrick_el1_linux::native_process_runtime::NativeServiceCall;
    // SAFETY: the admitted CPU binding retains the initialized counter
    // region for the entire native service continuation.
    let counters: &'static Counters = unsafe { &*(binding.counters_address as *const Counters) };
    let staged = carrick_el1_linux::dispatch::native_exec_stage_request(
        task,
        &carrick_el1_linux::file::HardwareValidator,
        request,
    );
    let payload = match staged {
        Some(NativeExecStage::Payload(payload)) => payload,
        Some(NativeExecStage::Failed(errno)) => {
            frame.rax = errno.guest_retval() as u64;
            return CompletionRoute::Served;
        }
        Some(NativeExecStage::Fault(fault)) => {
            return match supply_syscall_fault(
                binding,
                task,
                counters,
                slot,
                fault.address.raw(),
                fault.access,
            ) {
                UserFaultSupply::Served => {
                    restart_native_syscall(frame, ordinal);
                    CompletionRoute::Served
                }
                UserFaultSupply::MmRelease(cause) => {
                    let restart = boxed_restarted_syscall_context(saved, ordinal);
                    match anonymous::park_contended_fault(task, slot, cause, &restart) {
                        anonymous::ContendedFault::Parked => CompletionRoute::Suspended,
                        anonymous::ContendedFault::Rerun => {
                            restart_native_syscall(frame, ordinal);
                            CompletionRoute::Served
                        }
                        anonymous::ContendedFault::Refused => fatal_boot!(),
                    }
                }
                UserFaultSupply::TypedRelease(wait) => {
                    let restart = boxed_restarted_syscall_context(saved, ordinal);
                    match anonymous::park_owner_fault_wait(task, slot, wait, &restart) {
                        anonymous::ContendedFault::Parked => CompletionRoute::Suspended,
                        anonymous::ContendedFault::Rerun => {
                            restart_native_syscall(frame, ordinal);
                            CompletionRoute::Served
                        }
                        anonymous::ContendedFault::Refused => fatal_boot!(),
                    }
                }
                UserFaultSupply::Signal { .. } | UserFaultSupply::Unresolved(_) => {
                    frame.rax = carrick_syscall_abi::LINUX_EFAULT.guest_retval() as u64;
                    CompletionRoute::Served
                }
            };
        }
        None => fatal_boot!(),
    };
    let table = carrick_el1_linux::ipc::guest_venue(u32::from(slot.raw()))
        .and_then(|venue| carrick_el1_linux::ipc::native_exec_table(venue.tables, task));
    match inline_service(process.begin_exec_call(
        payload,
        table,
        NativeServiceCall::new(ordinal, counters),
    )) {
        InlineService::Suspended => {
            // The ring owner took the call: its replacement or errno is now
            // the owner's, and the census records the call as ring-served.
            if let Some(served) = counters.served.get(ordinal.raw() as usize) {
                served.fetch_add(1, Ordering::Relaxed);
            }
            CompletionRoute::Suspended
        }
        InlineService::Returned(result) => {
            frame.rax = result as u64;
            CompletionRoute::Served
        }
        InlineService::Restart => {
            restart_native_syscall(frame, ordinal);
            CompletionRoute::Served
        }
    }
}

struct NativeExecResume<'a> {
    ordinal: carrick_guest_arch::NativeOrdinal,
    saved: &'a carrick_sched_core::ParkedContextWords,
}

/// Box a copy of a syscall's saved context rewound to re-execute `SYSCALL`
/// with `ordinal` in RAX, keeping `ParkedContextWords` off the CPL0 stack.
#[inline(never)]
fn boxed_restarted_syscall_context(
    saved: &carrick_sched_core::ParkedContextWords,
    ordinal: carrick_guest_arch::NativeOrdinal,
) -> rust_alloc::boxed::Box<carrick_sched_core::ParkedContextWords> {
    use carrick_guest_arch::ProcessContext;
    let mut restart = rust_alloc::boxed::Box::new(*saved);
    restart.restart_syscall();
    restart.set_syscall_return(ordinal.raw());
    restart
}

/// How this entry completes a call whose shared service began inline.
enum InlineService {
    /// The service parked: the member left this CPU.
    Suspended,
    /// The service settled with this syscall result.
    Returned(i64),
    /// The service settled before it parked with no effect (an owner wait
    /// released ahead of its park, a cancelled host-file call, a retained
    /// map source): re-enter the call with its original arguments.
    Restart,
}

/// The inline result of a shared `begin_*_call` owner (#2416). The owner is
/// ISA-neutral; ARM's SVC user return accepts the same `RetrySyscall`
/// (#2342), and the resumed checkpoint replays it in `native_execution`.
fn inline_service(
    result: Result<
        carrick_el1_linux::native_process_runtime::NativeResume,
        carrick_el1_linux::native_process_runtime::NativeProcessError,
    >,
) -> InlineService {
    use carrick_el1_linux::native_process_runtime::NativeResume;
    match result {
        Ok(NativeResume::Left(None)) => InlineService::Suspended,
        Ok(NativeResume::Returned(result)) => InlineService::Returned(result.raw()),
        Ok(NativeResume::RetrySyscall) => InlineService::Restart,
        // Only a resumed checkpoint names a saved syscall or a pending
        // completion, and a root exit leaves through its own owner.
        Ok(
            NativeResume::NoPending
            | NativeResume::RetrySavedSyscall
            | NativeResume::Left(Some(_))
            | NativeResume::Invalid,
        )
        | Err(_) => fatal_boot!(),
    }
}

/// The x86 mechanic of a restart: put RCX on this call's `SYSCALL`, from
/// where the frame says it sits, and restore its number in RAX; every
/// argument register is still the call's. A frame already on its `SYSCALL`
/// stays there (#2900).
fn restart_native_syscall(frame: &mut NativeFrame, native: carrick_guest_arch::NativeOrdinal) {
    use carrick_guest_arch::{SyscallReturnFrame, SyscallReturnRegisters};
    if frame.rewind_to_syscall().is_none() {
        fatal_boot!();
    }
    frame.set_entry_word(native.raw());
}

fn supply_syscall_fault(
    binding: &CpuBinding,
    task: &CurrentTask,
    counters: &Counters,
    slot: carrick_sched_core::SlotId,
    address: u64,
    access: carrick_guest_arch::Access,
) -> UserFaultSupply {
    let fault = carrick_guest_arch::FaultInfo {
        address: UserVa::new(address),
        access,
        // A write to a readable page is a permission (COW) fault.
        present: access == carrick_guest_arch::Access::Write
            && carrick_el1_linux::file::MemoryValidator::readable_bytes(
                &carrick_el1_linux::file::HardwareValidator,
                address,
                1,
            ) == 1,
    };
    supply_user_fault(&carrick_x86_carrier::entry::PreparedUserPageFault {
        fault,
        binding,
        task,
        counters,
        slot,
    })
}

fn supply_user_fault(
    prep: &carrick_x86_carrier::entry::PreparedUserPageFault<'_>,
) -> UserFaultSupply {
    use carrick_el1::fault::dispatch_x86_fault_with_prepared;
    let fault = prep.fault;
    let binding = prep.binding;
    let task = prep.task;
    let counters = prep.counters;
    let slot = prep.slot;
    let mm_key = task.mm.key.load(Ordering::Acquire);
    let Some(reservation_mm) = carrick_el1_abi::ReservationMm::new(mm_key) else {
        return UserFaultSupply::Unresolved(9);
    };
    let Some(words) = anonymous::live_words(reservation_mm) else {
        return UserFaultSupply::Unresolved(9);
    };
    let layout = <carrick_el1::isa::x86::X86Backend as LayoutBackend>::KERNEL_LAYOUT;
    let Some(venues) = carrick_el1_abi::KernelFaultVenues::derive(layout)
        .and_then(carrick_el1_abi::KernelFaultVenues::require_upper_half)
    else {
        return UserFaultSupply::Unresolved(7);
    };
    // SAFETY: production KVM bootstrap maps and zero-initializes the
    // retained x86 kernel region at this typed upper-half layout.
    let (residency, portal, cow_pool) = unsafe {
        (
            &*(venues.residency.raw() as *const carrick_el1_abi::FrameGrantResidencyTable),
            &*(layout.portal.raw() as *const carrick_el1_abi::MmPortalSlots),
            &*(venues.cow_pool.raw() as *const carrick_el1_abi::CowGrantPool),
        )
    };
    // SAFETY: the boot owner retains the compact zone and its parked ABI.
    let zone =
        unsafe { &*(venues.zone.raw() as *const carrick_el1::memory::reservations::X86Cpl0Zone) };
    let roots = carrick_el1::memory::reservations::shared_x86_cpl0_guest();
    let spaces = carrick_core::wait::space_access(zone, slot, native_process::release);
    let handle = native_process::admitted_fault_mm_handle(zone, slot, task, reservation_mm);
    let supply = match handle {
        Some(handle) => carrick_el1::fault::OwnerFaultSupply::new(portal).with_handle(handle),
        None => carrick_el1::fault::OwnerFaultSupply::new(portal),
    };
    let Some(prepared_mm) = core::num::NonZeroU64::new(mm_key) else {
        return UserFaultSupply::Unresolved(9);
    };
    // SAFETY: the shared fault owner acquires the exact-MM editor before
    // every prepared commit; InitialWords retains its mapped window.
    let mut prepared =
        unsafe { carrick_el1::fault::X86PreparedResolver::under_editor(prepared_mm, &words) };
    let mut cow = carrick_el1_linux::cow_resolver::X86CowResolver {
        words: &words,
        pool: cow_pool,
        residency,
        completion: None,
    };
    let result = dispatch_x86_fault_with_prepared(
        carrick_guest_arch::CpuId::new(binding.cpu_slot),
        fault,
        counters,
        task,
        spaces,
        carrick_el1::fault::FaultSupply::Owner(&supply),
        Some(carrick_el1::fault::PreparedFaultPath {
            residency,
            resolver: &mut prepared,
            roots: Some(roots),
            file_slots: Some(portal),
        }),
        &mut cow,
    );
    if result == Action::Served {
        return settle_served_cow(binding, fault, cow_pool, mm_key, cow.completion.is_some());
    }
    use carrick_el1::fault::OwnerFaultSupplyOutcome;
    match supply.outcome() {
        OwnerFaultSupplyOutcome::PolicyDeclined => UserFaultSupply::Signal {
            signum: LINUX_SIGSEGV,
            code: if fault.present {
                LINUX_SEGV_ACCERR
            } else {
                LINUX_SEGV_MAPERR
            },
            address: fault.address,
        },
        OwnerFaultSupplyOutcome::Wait(wait) => UserFaultSupply::TypedRelease(wait),
        // Reason 9 in the low byte; the shared policy's deciding branch
        // above it, so the host's refusal line names it (#2668).
        OwnerFaultSupplyOutcome::Unavailable => {
            UserFaultSupply::Unresolved(9 | (supply.verdict().code() << 8))
        }
        // The replacement grant this member asks for is supplied to the MM's
        // pool, where any member holding the editor may claim it. So each
        // pass asks once and resolves again; a pass that selects again lost
        // its grant to a sibling's copy-on-write, which made progress with
        // it, and asks again (#2749).
        OwnerFaultSupplyOutcome::CowSelected => loop {
            let Some(grant_slot) = portal.grant(binding.cpu_slot as usize) else {
                return UserFaultSupply::Unresolved(9);
            };
            // The lane leases the selection it published across the
            // crossing; settling reports whether the carrier took it or the
            // lane withdrew it.
            let Some(lease) = grant_slot.adopt_cow_selection(mm_key, fault.address.raw()) else {
                return UserFaultSupply::Unresolved(9);
            };
            cross_owner_grant(
                carrick_guest_arch::CpuId::new(binding.cpu_slot),
                fault.address,
            );
            match lease.settle() {
                carrick_el1_abi::CowSettlement::Taken => {}
                // The carrier met this MM's editor held on the other CPU and
                // supplied nothing. Settling withdrew the selection; park on
                // that editor's release.
                carrick_el1_abi::CowSettlement::Withdrawn => {
                    return UserFaultSupply::MmRelease(
                        carrick_sched_core::spaces::notification::SpaceWaitCause::Editor,
                    );
                }
                carrick_el1_abi::CowSettlement::Lost => return UserFaultSupply::Unresolved(9),
            }
            #[cfg(feature = "test-support")]
            crate::test_support::hold_armed_cow_supply();
            let supply = match handle {
                Some(handle) => {
                    carrick_el1::fault::OwnerFaultSupply::new(portal).with_handle(handle)
                }
                None => carrick_el1::fault::OwnerFaultSupply::new(portal),
            };
            let mut cow = carrick_el1_linux::cow_resolver::X86CowResolver {
                words: &words,
                pool: cow_pool,
                residency,
                completion: None,
            };
            let result = dispatch_x86_fault_with_prepared(
                carrick_guest_arch::CpuId::new(binding.cpu_slot),
                fault,
                counters,
                task,
                spaces,
                carrick_el1::fault::FaultSupply::Owner(&supply),
                Some(carrick_el1::fault::PreparedFaultPath {
                    residency,
                    resolver: &mut prepared,
                    roots: Some(roots),
                    file_slots: Some(portal),
                }),
                &mut cow,
            );
            if result == Action::Served {
                // Resolved with a grant, or already resolved by a sibling's
                // write to the same page: an unclaimed grant stays ready
                // for the MM's next copy-on-write.
                return settle_served_cow(
                    binding,
                    fault,
                    cow_pool,
                    mm_key,
                    cow.completion.is_some(),
                );
            }
            match supply.outcome() {
                OwnerFaultSupplyOutcome::PolicyDeclined => {
                    return UserFaultSupply::Signal {
                        signum: LINUX_SIGSEGV,
                        code: if fault.present {
                            LINUX_SEGV_ACCERR
                        } else {
                            LINUX_SEGV_MAPERR
                        },
                        address: fault.address,
                    };
                }
                OwnerFaultSupplyOutcome::Wait(wait) => return UserFaultSupply::TypedRelease(wait),
                OwnerFaultSupplyOutcome::CowSelected => {}
                // The rerun after the COW supply: bit 24 marks it (#2668).
                _ => {
                    return UserFaultSupply::Unresolved(
                        9 | (supply.verdict().code() << 8) | (1 << 24),
                    );
                }
            }
        },
        OwnerFaultSupplyOutcome::Selected => {
            let Some(grant_slot) = portal.grant(binding.cpu_slot as usize) else {
                return UserFaultSupply::Unresolved(9);
            };
            serve_selected_window(binding, task, fault, grant_slot, residency, &words)
        }
    }
}

/// A served fault's settlement of its MM's copy-on-write completions.
///
/// A completion is the MM's, in its pool, and the carrier settles every one
/// of the MM under one exclusion. So the crossing is not this CPU's debt for
/// its own grant: whichever member sees a completion of its MM rings it, and
/// the carrier settles them all, a sibling's included (#2749). A completion
/// still in the pool after the crossing means the carrier met the MM's
/// editor held on the other CPU: the member parks on that editor's release,
/// its rerun finds the page resolved, and it rings again here.
fn settle_served_cow(
    binding: &CpuBinding,
    fault: carrick_guest_arch::FaultInfo,
    pool: &carrick_el1_abi::CowGrantPool,
    mm_key: u64,
    completed: bool,
) -> UserFaultSupply {
    if !completed && !pool.has_completions_for(mm_key) {
        return UserFaultSupply::Served;
    }
    #[cfg(feature = "test-support")]
    if completed {
        crate::test_support::hold_armed_cow_settle();
    }
    cross_owner_grant(
        carrick_guest_arch::CpuId::new(binding.cpu_slot),
        fault.address,
    );
    if pool.has_completions_for(mm_key) {
        return UserFaultSupply::MmRelease(
            carrick_sched_core::spaces::notification::SpaceWaitCause::Editor,
        );
    }
    UserFaultSupply::Served
}

/// Serve this CPU's owner-selected window, then settle it through the
/// carrier before answering. The grant slot is this CPU's custody: a member
/// that parks may resume on the other CPU, and any later crossing on this one
/// would find a still-submitted window. So every serve, published or not,
/// crosses once to settle its receipt or withdraw its window, and a refused
/// receipt takes the shared publication policy's next action.
fn serve_selected_window(
    binding: &CpuBinding,
    task: &CurrentTask,
    fault: carrick_guest_arch::FaultInfo,
    grant_slot: &carrick_el1_abi::PortalGrantSlot,
    residency: &carrick_el1_abi::FrameGrantResidencyTable,
    words: &carrick_x86_carrier::entry::InitialWords,
) -> UserFaultSupply {
    use carrick_core::mm::frames::{
        GrantServeOutcome, PublicationCompletion, PublicationDecline, PublicationNextAction,
        SelectedBackingPlan, publication_next_action,
    };
    use carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome;
    let cpu = carrick_guest_arch::CpuId::new(binding.cpu_slot);
    let mm_key = task.mm.key.load(Ordering::Acquire);
    loop {
        // The carrier prepares and submits the selected window.
        cross_owner_grant(cpu, fault.address);
        let Some(window) = grant_slot.window() else {
            if let Some(wait) = grant_slot.take_pool_wait(mm_key, fault.address.raw()) {
                return UserFaultSupply::TypedRelease(wait);
            }
            if grant_slot.take_refused_fault_selection(mm_key, fault.address.raw()) {
                return UserFaultSupply::Signal {
                    signum: LINUX_SIGSEGV,
                    code: if fault.present {
                        LINUX_SEGV_ACCERR
                    } else {
                        LINUX_SEGV_MAPERR
                    },
                    address: fault.address,
                };
            }
            // No physical backing for a still-authenticated file selection:
            // EOF/truncation follows Linux backing-fault signal policy.
            let Some((generation, selected)) =
                grant_slot.pending_fault_selection(mm_key, fault.address.raw())
            else {
                // The carrier met this MM's editor held on the other CPU and
                // returned the selection unserved: park on its release.
                return UserFaultSupply::MmRelease(
                    carrick_sched_core::spaces::notification::SpaceWaitCause::Editor,
                );
            };
            if selected.host_backing.is_some()
                && grant_slot.cancel_fault_selection(selected, generation)
            {
                return UserFaultSupply::Signal {
                    signum: carrick_syscall_abi::LINUX_SIGBUS,
                    code: carrick_syscall_abi::LINUX_BUS_ADRERR,
                    address: fault.address,
                };
            }
            return UserFaultSupply::Unresolved(9);
        };
        let Ok(owner) = native_process::portal() else {
            cross_owner_grant(cpu, fault.address);
            return UserFaultSupply::Unresolved(9);
        };
        #[cfg(feature = "test-support")]
        crate::test_support::hold_editor_for_selected_serve(task);
        // SAFETY: the retained residency table and metadata allocator are
        // the CPL0 guest venue. The shared helper releases its editor and
        // descriptor claim before growing or returning NotNow.
        let outcome = unsafe {
            carrick_core::mm::frames::serve_grant_with_venue(
                &owner,
                grant_slot,
                residency,
                &carrick_el1::alloc::GLOBAL_ALLOCATOR,
                binding.cpu_slot,
                |target, view| {
                    Ok(carrick_core::mm::frames::try_apply_grant::<
                        carrick_mmu_core::x86::owner_mmu::X86Mmu,
                        _,
                    >(grant_slot, words, view, target, || {}))
                },
            )
        };
        // Publish an applied receipt; settle a refused one or withdraw an
        // unserved window. Either way this CPU's slot is idle again.
        cross_owner_grant(cpu, fault.address);
        let reason = match outcome {
            Ok(GrantServeOutcome::Completed(receipt)) => match receipt.outcome {
                DescriptorOutcome::Applied(_) => return UserFaultSupply::Served,
                DescriptorOutcome::Refused(reason) | DescriptorOutcome::RolledBack(reason) => {
                    reason
                }
                DescriptorOutcome::Indeterminate(_) => return UserFaultSupply::Unresolved(9),
            },
            Ok(GrantServeOutcome::NotNow(continuation)) => {
                return match continuation.owner_wait {
                    Some(wait) => UserFaultSupply::TypedRelease(wait),
                    None => UserFaultSupply::MmRelease(
                        carrick_sched_core::spaces::notification::SpaceWaitCause::Editor,
                    ),
                };
            }
            Err(carrick_core::mm::transaction::MmError::Wait(wait)) => {
                return UserFaultSupply::TypedRelease(wait);
            }
            Ok(GrantServeOutcome::Empty) | Err(_) => {
                return UserFaultSupply::MmRelease(
                    carrick_sched_core::spaces::notification::SpaceWaitCause::Editor,
                );
            }
        };
        let Ok(selected) = SelectedBackingPlan::new(window.range, window.range, window.fault_page)
        else {
            return UserFaultSupply::Unresolved(9);
        };
        match publication_next_action(
            PublicationCompletion::Declined(Some(PublicationDecline::from_descriptor(reason))),
            selected,
            mm_key,
        ) {
            PublicationNextAction::ParkOnMmRelease { .. } => {
                return UserFaultSupply::MmRelease(
                    carrick_sched_core::spaces::notification::SpaceWaitCause::Editor,
                );
            }
            PublicationNextAction::RerunWith(fallback) => {
                // One strictly smaller selection: the fault page alone.
                let mut page = window;
                page.range = fallback.range();
                page.host_backing = match window.host_backing {
                    Some(source) => {
                        match source.advance(fallback.range().start() - window.range.start()) {
                            Some(source) => Some(source),
                            None => return UserFaultSupply::Unresolved(9),
                        }
                    }
                    None => None,
                };
                if !grant_slot.publish_fault_selection(window.operation.sequence.get(), page) {
                    return UserFaultSupply::Unresolved(9);
                }
            }
            // The fault page holds an output already: rerun the access, whose
            // reselection takes the inherited-Prepared supply or finds it valid.
            PublicationNextAction::ReplanInheritedPrepared => return UserFaultSupply::Served,
            PublicationNextAction::TerminalRefusal(_)
            | PublicationNextAction::Fatal(_)
            | PublicationNextAction::Published => return UserFaultSupply::Unresolved(9),
        }
    }
}

fn deliver_page_fault_signal(
    frame: &mut PageFaultStack,
    fpstate: &XsaveArea,
    signum: i32,
    code: i32,
    address: UserVa,
) -> u64 {
    let mut native_frame = NativeFrame {
        r15: frame.saved_gprs[0],
        r14: frame.saved_gprs[1],
        r13: frame.saved_gprs[2],
        r12: frame.saved_gprs[3],
        rbp: frame.saved_gprs[4],
        rbx: frame.saved_gprs[5],
        r11: frame.rflags,
        r10: frame.saved_gprs[7],
        r9: frame.saved_gprs[8],
        r8: frame.saved_gprs[9],
        rax: frame.saved_gprs[10],
        rcx: frame.rip,
        rdx: frame.saved_gprs[12],
        rsi: frame.saved_gprs[13],
        rdi: frame.saved_gprs[14],
        rsp: frame.rsp,
        user_rcx: frame.saved_gprs[11],
        user_r11: frame.saved_gprs[6],
        // A fault saves the faulting instruction; nothing rewinds it.
        syscall_position: carrick_guest_arch::SavedSyscallPcWord::new(
            carrick_sched_core::SavedSyscallPc::AtSyscall,
        ),
    };
    let info = LinuxSiginfo {
        si_signo: signum,
        si_code: code,
        si_addr: address.raw(),
        ..LinuxSiginfo::empty()
    };
    if !signal_user_return(&mut native_frame, fpstate, Some(info)) {
        return 6;
    }
    frame.rip = native_frame.rcx;
    frame.rflags = native_frame.r11;
    frame.rsp = native_frame.rsp;
    frame.saved_gprs = [
        native_frame.r15,
        native_frame.r14,
        native_frame.r13,
        native_frame.r12,
        native_frame.rbp,
        native_frame.rbx,
        native_frame.user_r11,
        native_frame.r10,
        native_frame.r9,
        native_frame.r8,
        native_frame.rax,
        native_frame.user_rcx,
        native_frame.rdx,
        native_frame.rsi,
        native_frame.rdi,
    ];
    0
}

#[derive(Default)]
pub struct LinuxPersonality;

impl PersonalityAbi<carrick_el1::isa::x86::Kernel> for LinuxPersonality {
    type Call = CanonicalCall;

    fn decode(
        &self,
        cx: &mut CallContext<'_, carrick_el1::isa::x86::Kernel>,
    ) -> Result<Self::Call, EntryDecodeError> {
        let snapshot = cx.snapshot()?;
        decode_x86_snapshot(snapshot).ok_or(EntryDecodeError::UnsupportedAbi)
    }

    fn encode_return(
        &self,
        result: NativeReturnWord,
        frame: &mut NativeFrame,
    ) -> Result<(), EntryDecodeError> {
        frame.rax = result.0;
        Ok(())
    }
}

impl Personality for LinuxPersonality {
    type Return = ();
    type Continuation = OwnedContinuation;

    fn call_stack(&self, call: &Self::Call) -> UserVa {
        call.stack
    }

    fn settle_work_before_dispatch(&self, call: &Self::Call) -> bool {
        carrick_syscall_abi::syscall_x86_64::canonical_x86_64(carrick_syscall_abi::NativeNr(
            call.native.raw(),
        )) == Some(carrick_syscall_abi::nr::WAIT4)
    }

    fn handle_unrecognized_call(
        &mut self,
        frame: &mut NativeFrame,
        _task: &CurrentTask,
        binding: &CpuBinding,
        counters: &Counters,
    ) {
        evaluate_host_crossing(HostCrossingSet::X86, true, None, None, None, |ret| {
            frame.rax = ret.raw() as u64
        });
        let slot = checked_scheduler_slot(carrick_guest_arch::CpuId::new(binding.cpu_slot))
            .unwrap_or_else(|| fatal_boot!());
        let source = carrick_x86_carrier::native_execution::source(slot);
        let child = source.zone.slot(slot).current().is_some_and(|record| {
            native_process::registry()
                .record_is_fork_child(source.zone, source.zone.record_ref(record))
        });
        counters.record_refusal(
            carrick_guest_arch::NativeOrdinal::new(512),
            if child {
                carrick_core_abi::service::ServiceOrigin::Descendant
            } else {
                carrick_core_abi::service::ServiceOrigin::Initial
            },
            carrick_el1_abi::RefusalVenue::Ring,
        );
    }

    fn dispatch(
        &mut self,
        call: Self::Call,
        cx: &mut ExecutionContext<'_>,
    ) -> ControlFlow<Self::Return, Self::Continuation> {
        let task = cx.task;
        let binding = cx.binding;
        let counters = cx.counters;
        let frame = &mut *cx.frame;
        let early_xstate = &mut *cx.xsave;

        #[cfg(feature = "test-support")]
        if let Some(result) = crate::test_support::dispatch(call.native.raw(), binding) {
            frame.rax = result;
            return ControlFlow::Return(());
        }

        if call.native.raw() == carrick_syscall_abi::syscall_x86_64::ARCH_PRCTL_NR {
            struct Cpl0ArchPrctl<'a> {
                task: &'a CurrentTask,
            }

            impl carrick_guest_arch::SegmentBaseRegs for Cpl0ArchPrctl<'_> {
                type Error = core::convert::Infallible;

                fn seg_set_fs_base(&mut self, addr: u64) -> Result<(), Self::Error> {
                    use carrick_el1::isa::x86::context::scheduler::{NativeTlsRegister, write_tls};
                    write_tls(NativeTlsRegister::Fs, addr);
                    Ok(())
                }

                fn seg_get_fs_base(&self) -> Result<u64, Self::Error> {
                    use carrick_el1::isa::x86::context::scheduler::{NativeTlsRegister, read_tls};
                    Ok(read_tls(NativeTlsRegister::Fs))
                }

                fn seg_set_gs_base(&mut self, addr: u64) -> Result<(), Self::Error> {
                    use carrick_el1::isa::x86::context::scheduler::{NativeTlsRegister, write_tls};
                    write_tls(NativeTlsRegister::UserGs, addr);
                    Ok(())
                }

                fn seg_get_gs_base(&self) -> Result<u64, Self::Error> {
                    use carrick_el1::isa::x86::context::scheduler::{NativeTlsRegister, read_tls};
                    Ok(read_tls(NativeTlsRegister::UserGs))
                }
            }

            impl carrick_guest_arch::CurrentMmMemory for Cpl0ArchPrctl<'_> {
                fn write_bytes(
                    &mut self,
                    address: u64,
                    bytes: &[u8],
                ) -> Result<(), carrick_guest_arch::UserMemoryFault> {
                    // SAFETY: `task` is the currently executing task whose #PF recovery gate
                    // is installed on this CPU. Source buffer `bytes` is in kernel memory and
                    // disjoint from the user target `address`.
                    let copied = unsafe {
                        carrick_el1::isa::x86::user_access::copy(
                            self.task,
                            address as *mut u8,
                            bytes.as_ptr(),
                            bytes.len(),
                            address,
                            true,
                        )
                    };
                    if copied {
                        Ok(())
                    } else {
                        Err(carrick_guest_arch::UserMemoryFault)
                    }
                }
            }

            let mut ctx = Cpl0ArchPrctl { task };
            let ret = carrick_personality_linux::arch_prctl::service_arch_prctl(
                &mut ctx,
                call.args[0],
                call.args[1],
            )
            .unwrap_or_else(|inf| match inf {});
            frame.rax = ret as u64;
            return ControlFlow::Return(());
        }

        let files = file_tables(binding);
        let ipc = carrick_el1_linux::ipc::guest_venue(binding.cpu_slot);
        let cache_lookup = |handle: u32| {
            files
                .cache(handle)
                .map_or(core::ptr::null_mut(), |ptr| ptr.as_ptr())
        };

        let slot = checked_scheduler_slot(carrick_guest_arch::CpuId::new(binding.cpu_slot))
            .unwrap_or_else(|| fatal_boot!());
        let source = carrick_x86_carrier::native_execution::source(slot);
        let words = capture(frame, early_xstate);
        native_process::admit_root(words, source, task).unwrap_or_else(|_| fatal_boot!());
        let file_table = task.linux.file_table.load(Ordering::Acquire).max(1);
        let mut service = native_process::Service::new(task, slot);
        native_process::drain_external_ingress(source, &mut service)
            .unwrap_or_else(|_| fatal_boot!());
        let crossing_operand;
        let (route, root_exit) = {
            let (runtime, address) =
                native_process::runtime(source, task).unwrap_or_else(|_| fatal_boot!());
            let mut process = runtime
                .enter_registered(
                    native_process::registry(),
                    source,
                    task,
                    address,
                    &words,
                    &mut service,
                )
                .unwrap_or_else(|_| fatal_boot!());
            let origin = if process.is_root_process() {
                carrick_core_abi::service::ServiceOrigin::Initial
            } else {
                carrick_core_abi::service::ServiceOrigin::Descendant
            };
            let mut anonymous = anonymous::X86AnonymousVenue::new(
                &call,
                task,
                binding.cpu_slot,
                frame.rcx,
                source,
                words,
                origin,
            );
            let mut native = NativeDispatch {
                frame,
                fpstate: early_xstate,
                call,
                publications: &binding.publications,
                slot: carrick_guest_arch::SlotId::from_index(binding.cpu_slot as usize),
                file_table,
                files: &files,
                host_file: Some(HostFileVenue {
                    task,
                    cpu_slot: binding.cpu_slot,
                    origin,
                }),
                staged: None,
                crossing_operand: None,
            };
            let mut route = dispatch_syscall_with_native(
                &mut native,
                counters,
                core::slice::from_ref(task),
                files.fd_map(),
                files.objects(),
                files.opens(),
                &[],
                files.names(),
                None::<
                    carrick_el1_linux::dispatch::Zone<
                        '_,
                        carrick_el1::substrate::sched::HardwareCpu,
                        carrick_el1::substrate::sched::HardwareUserWord,
                    >,
                >,
                ipc.as_ref(),
                Some(&GuestLifecycleVenue),
                Some(&mut *process),
                Some(source),
                anonymous.as_mut().map(|venue| venue as &mut dyn carrick_personality_linux::pending_anonymous::PendingAnonymousVenue),
                cache_lookup,
            );
            let socket_epoll = route == CompletionRoute::NativeService
                && call.canonical.raw() == carrick_personality_linux::crossing::nr::EPOLL_CTL.raw();
            let staged = if socket_epoll {
                ipc.as_ref()
                    .and_then(|venue| carrick_el1_linux::ipc::native_table(venue, task))
                    .map(|table| {
                        carrick_el1_linux::dispatch::stage_native_socket_epoll(
                            task,
                            &carrick_el1_linux::file::HardwareValidator,
                            table,
                            call.args,
                            carrick_abi::LinuxGuestAbi::X86_64,
                        )
                    })
            } else {
                native.staged.take()
            };
            crossing_operand = native.crossing_operand.take();
            if route == CompletionRoute::NativeService
                && call.canonical.raw() == carrick_personality_linux::crossing::nr::GETRANDOM.raw()
            {
                use carrick_el1_linux::native_process_runtime::{
                    NativeEntropyArgs, NativeEntropyFlags,
                };
                route = match inline_service(process.begin_entropy_call(NativeEntropyArgs {
                    address: carrick_guest_arch::UserVa::new(call.args[0]),
                    length: carrick_guest_arch::GuestLen::new(call.args[1]),
                    flags: NativeEntropyFlags::from_bits_retain(call.args[2] as u32),
                })) {
                    InlineService::Suspended => CompletionRoute::Suspended,
                    InlineService::Returned(result) => {
                        frame.rax = result as u64;
                        CompletionRoute::Served
                    }
                    InlineService::Restart => {
                        restart_native_syscall(
                            frame,
                            carrick_guest_arch::NativeOrdinal::new(call.native.raw()),
                        );
                        CompletionRoute::Served
                    }
                };
            }
            // A fork child's execve/execveat (#2235), and the run root's
            // (#2142), is the native exec service's: stage its arguments
            // exactly as ARM's owned entry does, then hand the payload to
            // the shared owner, which parks until the carrier has prepared
            // and sealed the successor. The carrier consumes the root's
            // settlement on the loaded lane, so only the root thread holding
            // that lane's custody hands it over; ARM's root forwards to its
            // host instead.
            if route == CompletionRoute::NativeService
                && carrick_el1_linux::dispatch::native_exec_claimed(
                    carrick_el1_linux::dispatch::RootExecServer::native_service_for(
                        source.zone.slot(slot).host_record(),
                        source.zone.slot(slot).current(),
                    ),
                    || process.thread_group_owner(),
                )
                && let Some(request) =
                    carrick_el1_linux::exec_stage::ExecStageRequest::from_canonical(
                        call.canonical.raw(),
                        call.args,
                    )
            {
                route = native_exec_call(
                    &mut process,
                    frame,
                    binding,
                    task,
                    slot,
                    request,
                    NativeExecResume {
                        ordinal: carrick_guest_arch::NativeOrdinal::new(call.native.raw()),
                        saved: &words,
                    },
                );
            }
            if let Some(venue) = anonymous.as_mut()
                && venue.take_retry()
            {
                restart_native_syscall(
                    frame,
                    carrick_guest_arch::NativeOrdinal::new(venue.original_syscall_number()),
                );
            }
            // Staged ahead of the crossing table by the dispatch owner, so a
            // call the strict x86 set refuses (writev) still reaches the
            // retained host-file venue, as ARM stages ahead of its route.
            if (matches!(
                route,
                CompletionRoute::Forward | CompletionRoute::NativeService
            ) || socket_epoll)
                && let Some(stage) = staged
            {
                use carrick_el1_linux::native_process_runtime::NativeServiceCall;
                // SAFETY: the admitted CPU binding retains the initialized counter
                // region for the entire native service continuation.
                let counters: &'static Counters =
                    unsafe { &*(binding.counters_address as *const Counters) };
                use carrick_personality_linux::native_host_file::HostFileStage;
                // Staging made no descriptor/IPC effect. Feed the exact
                // access through the owner fault path #PF entry uses, then
                // retry the same syscall, as ARM re-enters its SVC. Only a
                // refused access (no mapping, wrong protection, backing past
                // EOF) completes without it: EFAULT, or the short write of
                // the bytes gathered before it, as Linux's user copy does.
                let mut retry = false;
                let mut parked = false;
                let mut crosses = false;
                let stage = match stage.fault() {
                    Some((address, access)) => {
                        match supply_syscall_fault(binding, task, counters, slot, address, access) {
                            UserFaultSupply::Served => {
                                retry = true;
                                None
                            }
                            // The owner refused or could not supply the
                            // access (no reservation names it): never a
                            // carrier abort.
                            UserFaultSupply::MmRelease(cause) => {
                                let restart = boxed_restarted_syscall_context(
                                    &words,
                                    carrick_guest_arch::NativeOrdinal::new(call.native.raw()),
                                );
                                match anonymous::park_contended_fault(task, slot, cause, &restart) {
                                    anonymous::ContendedFault::Parked => parked = true,
                                    anonymous::ContendedFault::Rerun => retry = true,
                                    anonymous::ContendedFault::Refused => fatal_boot!(),
                                }
                                None
                            }
                            UserFaultSupply::TypedRelease(wait) => {
                                let restart = boxed_restarted_syscall_context(
                                    &words,
                                    carrick_guest_arch::NativeOrdinal::new(call.native.raw()),
                                );
                                match anonymous::park_owner_fault_wait(task, slot, wait, &restart) {
                                    anonymous::ContendedFault::Parked => parked = true,
                                    anonymous::ContendedFault::Rerun => retry = true,
                                    anonymous::ContendedFault::Refused => fatal_boot!(),
                                }
                                None
                            }
                            UserFaultSupply::Signal { .. } | UserFaultSupply::Unresolved(_) => {
                                Some(stage.refused())
                            }
                        }
                    }
                    None => Some(stage),
                };
                let result = match stage {
                    None => None,
                    Some(HostFileStage::Request {
                        record,
                        output,
                        resolves_path,
                        map,
                        chdir,
                    }) => {
                        match inline_service(process.begin_host_file_call(
                            record,
                            output,
                            resolves_path,
                            map,
                            chdir,
                            NativeServiceCall::new(
                                carrick_guest_arch::NativeOrdinal::new(call.native.raw()),
                                counters,
                            ),
                        )) {
                            InlineService::Suspended => None,
                            InlineService::Returned(result) => Some(result),
                            InlineService::Restart => {
                                retry = true;
                                None
                            }
                        }
                    }
                    Some(HostFileStage::Returned(result)) => Some(result.raw()),
                    Some(HostFileStage::InRingReply { output, bytes }) => {
                        let mut copy = carrick_el1_linux::file::ValidatedCopy {
                            task,
                            validator: &carrick_el1_linux::file::HardwareValidator,
                        };
                        Some(
                            if carrick_el1_linux::file::UserCopy::copy_out(
                                &mut copy,
                                output.address,
                                &bytes,
                            ) {
                                0
                            } else {
                                carrick_syscall_abi::LINUX_EFAULT.guest_retval()
                            },
                        )
                    }
                    // A refused output supply: the crossing runs as it is.
                    Some(HostFileStage::Crossing) => {
                        crosses = true;
                        None
                    }
                    // `refused` answers every fault it is given.
                    Some(
                        HostFileStage::Fault { .. }
                        | HostFileStage::FaultAfterPrefix { .. }
                        | HostFileStage::PrepareOutput { .. },
                    ) => fatal_boot!(),
                    Some(HostFileStage::InRing) => {
                        counters.record_refusal(
                            carrick_guest_arch::NativeOrdinal::new(call.native.raw()),
                            origin,
                            carrick_el1_abi::RefusalVenue::Ring,
                        );
                        Some(carrick_syscall_abi::LINUX_ENOSYS.guest_retval())
                    }
                };
                route = if parked {
                    CompletionRoute::Suspended
                } else if retry {
                    restart_native_syscall(
                        frame,
                        carrick_guest_arch::NativeOrdinal::new(call.native.raw()),
                    );
                    CompletionRoute::Served
                } else if crosses {
                    // A staged readlink reaches host dispatch only for the
                    // root when output preparation was refused. The generic
                    // stage did not account for this replay.
                    if route == CompletionRoute::NativeService
                        && origin == carrick_core_abi::service::ServiceOrigin::Initial
                    {
                        carrick_personality_linux::dispatch::EntryCounters {
                            served: &counters.served,
                            forwarded: &counters.forwarded,
                        }
                        .forwarded(call.canonical.raw());
                    }
                    CompletionRoute::Forward
                } else if let Some(result) = result {
                    frame.rax = result as u64;
                    CompletionRoute::Served
                } else {
                    CompletionRoute::Suspended
                };
            }
            // A fork child has no host task context, so an allowed crossing no
            // ring stage served is answered in ring with a counted ENOSYS, by
            // the one Linux policy ARM's owned native entry asks too.
            if route == CompletionRoute::Forward
                && carrick_el1_linux::dispatch::unclaimed_native_syscall(
                    process.thread_group_owner(),
                ) == carrick_el1_linux::dispatch::UnclaimedNativeSyscall::CountedEnosys
            {
                if task.linux.has_pending_host_work() {
                    // The same rule as the shared crossing refusal: an
                    // effect-free decline under owed work reruns after the
                    // work boundary, and only the rerun may be refused.
                    restart_native_syscall(
                        frame,
                        carrick_guest_arch::NativeOrdinal::new(call.native.raw()),
                    );
                    task.linux.record_completed_with_work();
                    route = CompletionRoute::WithWork;
                } else {
                    frame.rax = carrick_el1_linux::dispatch::count_unclaimed_native_refusal(
                        carrick_guest_arch::NativeOrdinal::new(call.native.raw()),
                        counters,
                    )
                    .0;
                    route = CompletionRoute::Served;
                }
            }
            if let Some(reason) = process.take_run_failure() {
                complete_run_failure(task, reason);
            }
            if carrick_personality_linux::signal::signal_delivery_before_work(route, &task.linux)
                && let Some(r) = deliver_signal_on_syscall_return(
                    task,
                    &mut process,
                    frame,
                    early_xstate,
                    &mut X86SignalMachine::new(address),
                )
            {
                route = r.completion_route();
            }
            let root_exit = process.take_root_exit();
            (route, root_exit)
        };
        if !matches!(route, CompletionRoute::Suspended) {
            migrate(slot);
        }

        match route {
            CompletionRoute::Served => ControlFlow::Return(()),
            CompletionRoute::WithWork => {
                notify_work(frame);
                ControlFlow::Return(())
            }
            CompletionRoute::Suspended => {
                if let Some(status) = root_exit {
                    ControlFlow::Terminate(TerminationRequest::new(
                        status.terminal_status().unwrap_or_else(|_| fatal_boot!()),
                    ))
                } else {
                    ControlFlow::Suspend(OwnedContinuation::new(0))
                }
            }
            CompletionRoute::InvalidCompletion => {
                fatal_error(frame);
            }
            // Entropy has been staged above. Any other unwired native service
            // fails closed with a counted refusal.
            CompletionRoute::NativeService => {
                // A fork child's or the root's exec was handed to the native
                // exec service above; everything else is the counted refusal.
                frame.rax = carrick_el1_linux::dispatch::settle_unwired_native_service(
                    native_process::registry(),
                    source.zone,
                    source
                        .zone
                        .slot(slot)
                        .current()
                        .map(|r| source.zone.record_ref(r)),
                    carrick_guest_arch::NativeOrdinal::new(call.native.raw()),
                    counters,
                ) as u64;
                ControlFlow::Return(())
            }
            CompletionRoute::Forward | CompletionRoute::HostCustody => {
                forward_crossing(frame, crossing_operand);
                ControlFlow::Return(())
            }
        }
    }

    fn schedule(slot: SlotId) -> ! {
        crate::native_execution::schedule(slot);
    }

    fn on_irq_return(
        &mut self,
        frame: &mut carrick_el1::isa::x86::context::scheduler::InterruptFrame,
        xsave: &mut XsaveArea,
    ) {
        signal_irq_return(frame, xsave);
    }

    fn on_user_return(&mut self, frame: &mut NativeFrame, xsave: &mut XsaveArea) {
        signal_syscall_return(frame, xsave);
    }

    fn on_timer(&mut self, slot: SlotId) {
        native_execution::expire_signal_timer(slot);
    }

    fn has_pending_host_work(&mut self, task: &CurrentTask) -> bool {
        if task.linux.has_pending_host_work() {
            task.linux.record_completed_with_work();
            true
        } else {
            false
        }
    }

    fn handle_page_fault(frame: &mut PageFaultStack, fpstate: &XsaveArea) -> u64 {
        handle_user_page_fault(frame, fpstate)
    }
}
