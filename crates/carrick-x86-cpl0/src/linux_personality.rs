//! Linux OS personality implementation for the x86 CPL0 carrier.

#![cfg(all(target_os = "none", target_arch = "x86_64"))]

use carrick_abi::{LINUX_SEGV_ACCERR, LINUX_SEGV_MAPERR, LINUX_SIGSEGV, LinuxErrno, LinuxSiginfo};
use carrick_el1::isa::x86::context::native::{CpuBinding, NativeFrame, checked_scheduler_slot};
use carrick_el1::isa::x86::context::scheduler::XsaveArea;
use carrick_el1_abi::{
    Action, Counters, CurrentTask, DelegatedOpenFile, FileTables, HostObjectBinding,
    HostObjectReleaseCrossing, HostObjectWriteCrossing, HostReadinessCrossing, fd_map_lookup,
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
use carrick_syscall_abi::{CanonicalNr, LINUX_EBADF};
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

/// One stdio admission policy for production and the hardware fixture lane.
pub fn admit_stdio_cached(binding: &CpuBinding, task: &CurrentTask, files: &FileTables<'_>) {
    let file_table = task.linux.file_table.load(Ordering::Acquire).max(1);
    if binding.stdio_table_admitted.load(Ordering::Acquire) != file_table {
        carrick_el1_linux::file_table::admit_stdio(
            files.fd_map(),
            files.opens(),
            files.objects(),
            file_table,
            [true; 3],
        );
        binding
            .stdio_table_admitted
            .store(file_table, Ordering::Release);
    }
}

// SAFETY: live diagnostic counter exported for test/telemetry inspection.
#[unsafe(no_mangle)]
pub static CARRICK_CPL0_ISA_UNSUPPORTED_FORWARDS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

pub struct NativeDispatch<'a> {
    pub frame: &'a mut NativeFrame,
    pub fpstate: &'a mut XsaveArea,
    pub call: CanonicalCall,
    pub publications: &'a core::sync::atomic::AtomicU64,
    pub slot: Option<carrick_guest_arch::SlotId>,
    pub file_table: u64,
    pub files: &'a FileTables<'a>,
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
    fn native_number(&self) -> carrick_guest_arch::NativeOrdinal {
        self.call.native
    }
    fn crossing_set(&self) -> carrick_personality_linux::crossing::HostCrossingSet {
        carrick_personality_linux::crossing::HostCrossingSet::X86
    }
    fn settles_owed_work_at_continuation_boundary(&self) -> bool {
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

    fn preflight_host_crossing(&mut self, ordinal: u64) -> bool {
        let read = ordinal == carrick_personality_linux::crossing::nr::READ.raw();
        let stdio_call = read
            || [
                carrick_personality_linux::crossing::nr::WRITE,
                carrick_personality_linux::crossing::nr::LSEEK,
                carrick_personality_linux::crossing::nr::PREAD64,
                carrick_personality_linux::crossing::nr::PWRITE64,
            ]
            .iter()
            .any(|nr| nr.raw() == ordinal);
        let guest_fd = self.call.args[0] as i32;
        if !stdio_call || !(0..=2).contains(&guest_fd) {
            return true;
        }
        let binding = fd_map_lookup(self.files.fd_map(), self.file_table, guest_fd)
            .and_then(|(handle, _)| handle.checked_sub(1))
            .and_then(|index| self.files.opens().get(index as usize))
            .and_then(DelegatedOpenFile::host_object);
        if binding.is_none()
            || (read && binding.is_some_and(|binding| binding.stdio_fd() != Some(guest_fd)))
        {
            self.frame.rax = carrick_syscall_abi::LINUX_EBADF.guest_retval() as u64;
            return false;
        }
        true
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
            &mut |dst, va| copy_in.copy_in(dst, va),
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
        carrick_personality_linux::signal::SignalBackend::setup_signal_frame(
            &mut backend,
            self.frame,
            params,
            siginfo,
            &self.fpstate.0,
            &mut |va, src| copy_out.copy_out(va, src),
        )
        .map_err(|_| carrick_personality_linux::abi::signal::LINUX_EFAULT)
    }
}

pub fn complete_run_failure(
    task: &CurrentTask,
    reason: carrick_core_abi::NativeRunFailureReason,
) -> ! {
    carrick_el1::isa::x86::complete_native_run_failure(
        carrick_el1_linux::common_entry::execution_binding(task),
        reason,
    )
}

pub fn complete_root_exit(task: &CurrentTask, status: LinuxWaitStatus) -> ! {
    let exit = carrick_core_abi::NativeRootExit::new(
        carrick_el1_linux::common_entry::execution_binding(task),
        status.terminal_status().unwrap_or_else(|_| fatal_boot()),
    )
    .unwrap_or_else(|| fatal_boot());
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

struct X86SignalMachine {
    backend: carrick_el1_linux::x86_signal::LinuxX86Backend,
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
        &self,
        frame: &mut NativeFrame,
        original: &carrick_sched_core::ParkedContextWords,
    ) -> bool {
        frame.rax = original.syscall_return();
        if let Some(pc) = frame.rcx.checked_sub(2) {
            frame.rcx = pc;
            true
        } else {
            false
        }
    }

    fn group_exit_custody(&self, task: &CurrentTask) -> CompletionRoute {
        complete_run_failure(
            task,
            carrick_core_abi::NativeRunFailureReason::X86GroupExitCustody,
        )
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
) -> Option<CompletionRoute> {
    carrick_el1_linux::signal_delivery::deliver_signal_on_syscall_return(
        task,
        process,
        frame,
        &fpstate.0,
        &mut X86SignalMachine {
            backend: carrick_el1_linux::x86_signal::LinuxX86Backend,
        },
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
    let binding = context::current_cpu_binding().unwrap_or_else(|| fatal_boot());
    let slot = SlotId::from_index(binding.cpu_slot as usize).unwrap_or_else(|| fatal_boot());
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
            .unwrap_or_else(|_| fatal_boot());
        let (process_runtime, address) =
            native_process::runtime(source, task).unwrap_or_else(|_| fatal_boot());
        let mut process = process_runtime
            .enter_registered(
                native_process::registry(),
                source,
                task,
                address,
                &words,
                &mut service,
            )
            .unwrap_or_else(|_| fatal_boot());
        if let Some(info) = forced {
            use carrick_personality_linux::signal::policy::{SigBlockMask, Signal};
            let Some(thread) = GuestLifecycleVenue.thread(task) else {
                return false;
            };
            let blocked = SigBlockMask::blocking_all_of(
                carrick_personality_linux::signal::SignalSet::from_bits(thread.slot.blocked().0),
            );
            if process.force_sigsegv_info(blocked, info).is_err() {
                return false;
            }
            let mask = blocked.signals().without(Signal::SEGV);
            let _ = thread.slot.store_blocked_then_read_pending(
                carrick_el1_abi::BlockedMask(mask.bits()),
                thread.slot.pending(),
            );
        }
        if let Some(route) = deliver_signal_on_syscall_return(task, &mut process, frame, xsave) {
            if route != CompletionRoute::Suspended {
                fatal_boot();
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
    let binding = context::current_cpu_binding().unwrap_or_else(|| fatal_boot());
    let slot = SlotId::from_index(binding.cpu_slot as usize).unwrap_or_else(|| fatal_boot());
    let source = carrick_x86_carrier::native_execution::source(slot);
    if !native_process::is_admitted() {
        return;
    }
    // SAFETY: this CPU owns its retained current-task binding during IRQ entry.
    let task = unsafe { &*(binding.task_address as *const CurrentTask) };
    let mm = carrick_el1_abi::ReservationMm::new(task.mm.key.load(Ordering::Acquire))
        .unwrap_or_else(|| fatal_boot());
    let address = anonymous::live_words(mm)
        .and_then(|words| words.context)
        .unwrap_or_else(|| fatal_boot());
    let mut native = context::scheduler::NativeContext {
        frame: *frame,
        address,
        fs_base: carrick_x86_carrier::native_execution::read_msr(0xc000_0100),
        gs_base: carrick_x86_carrier::native_execution::read_msr(0xc000_0102),
        xsave: xsave.clone(),
    };
    let mut returned = context::context_words::syscall_frame_from_native(&native, address)
        .unwrap_or_else(|_| fatal_boot());
    let record = source
        .zone
        .slot(slot)
        .current()
        .or_else(|| source.zone.slot(slot).host_record())
        .unwrap_or_else(|| fatal_boot());
    let mut suspended = false;
    let root_exit;
    {
        let _copy_gate = user_fault_gate::install();
        let mut service = native_process::Service::new(task, slot);
        native_process::drain_external_ingress(source, &mut service)
            .unwrap_or_else(|_| fatal_boot());
        let (process_runtime, runtime_address) =
            native_process::runtime(source, task).unwrap_or_else(|_| fatal_boot());
        let mut process = process_runtime
            .enter_registered(
                native_process::registry(),
                source,
                task,
                runtime_address,
                &context::context_words::from_native(&native),
                &mut service,
            )
            .unwrap_or_else(|_| fatal_boot());
        if let Some(route) =
            deliver_signal_on_syscall_return(task, &mut process, &mut returned, xsave)
        {
            if route != CompletionRoute::Suspended {
                fatal_boot();
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
        .unwrap_or_else(|_| fatal_boot());
        *frame = native.frame;
        if source.zone.runnable_head(slot).is_some() {
            // SAFETY: IRQ entry owns this exact running/home record's context.
            unsafe {
                *source.zone.record(record).ctx_mut() =
                    context::context_words::from_native(&native);
            }
            source.zone.requeue_preempted(slot, record);
            suspended = true;
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
    use carrick_el1::fault::dispatch_x86_fault_with_prepared;
    let fault = prep.fault;
    let binding = prep.binding;
    let task = prep.task;
    let counters = prep.counters;
    let slot = prep.slot;
    let mm_key = task.mm.key.load(Ordering::Acquire);
    let Some(words) = anonymous::live_words(match carrick_el1_abi::ReservationMm::new(mm_key) {
        Some(mm) => mm,
        None => return 9,
    }) else {
        return 9;
    };
    let layout = <carrick_el1::isa::x86::X86Backend as LayoutBackend>::KERNEL_LAYOUT;
    let Some(venues) = carrick_el1_abi::KernelFaultVenues::derive(layout)
        .and_then(carrick_el1_abi::KernelFaultVenues::require_upper_half)
    else {
        return 7;
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
    let spaces = carrick_core::wait::space_access(zone, slot, anonymous::initial_release);
    let supply = carrick_el1::fault::OwnerFaultSupply::new(portal);
    let Some(prepared_mm) = core::num::NonZeroU64::new(mm_key) else {
        return 9;
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
            file_slots: None,
        }),
        &mut cow,
    );
    if result == Action::Served {
        if cow.completion.is_some() {
            cross_owner_grant(
                carrick_guest_arch::CpuId::new(binding.cpu_slot),
                fault.address,
            );
        }
        return 0;
    }
    use carrick_el1::fault::OwnerFaultSupplyOutcome;
    match supply.outcome() {
        OwnerFaultSupplyOutcome::PolicyDeclined => {
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
            };
            let info = LinuxSiginfo {
                si_signo: LINUX_SIGSEGV,
                si_code: if fault.present {
                    LINUX_SEGV_ACCERR
                } else {
                    LINUX_SEGV_MAPERR
                },
                si_addr: fault.address.raw(),
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
        OwnerFaultSupplyOutcome::Unavailable => 9,
        OwnerFaultSupplyOutcome::CowSelected => {
            cross_owner_grant(
                carrick_guest_arch::CpuId::new(binding.cpu_slot),
                fault.address,
            );
            let supply = carrick_el1::fault::OwnerFaultSupply::new(portal);
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
                    file_slots: None,
                }),
                &mut cow,
            );
            if result != Action::Served || cow.completion.is_none() {
                return 9;
            }
            cross_owner_grant(
                carrick_guest_arch::CpuId::new(binding.cpu_slot),
                fault.address,
            );
            0
        }
        OwnerFaultSupplyOutcome::Selected => {
            cross_owner_grant(
                carrick_guest_arch::CpuId::new(binding.cpu_slot),
                fault.address,
            );
            let Some(grant_slot) = portal.grant(binding.cpu_slot as usize) else {
                return 9;
            };
            let Some(window) = grant_slot.window() else {
                return 9;
            };
            let Some(index) = spaces.find(mm_key) else {
                return 9;
            };
            let Ok(mut root) =
                roots.lock_in(spaces, index.index(), window.operation.mm, binding.cpu_slot)
            else {
                return 9;
            };
            let Ok(target) = carrick_core::mm::frames::grant_target_in(
                match portal.carrier() {
                    Some(carrier) => carrier,
                    None => return 9,
                },
                window,
                spaces,
                binding.cpu_slot,
                &mut root,
            ) else {
                return 9;
            };
            let receipt = carrick_core::mm::frames::apply_grant::<
                carrick_mmu_core::x86::owner_mmu::X86Mmu,
                _,
            >(grant_slot, &words, residency, target, || {});
            drop(root);
            let applied = receipt.is_some_and(|receipt| {
                matches!(
                    receipt.outcome,
                    carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome::Applied(_)
                )
            });
            cross_owner_grant(
                carrick_guest_arch::CpuId::new(binding.cpu_slot),
                fault.address,
            );
            if applied { 0 } else { 9 }
        }
    }
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
        _binding: &CpuBinding,
        counters: &Counters,
    ) {
        evaluate_host_crossing(
            HostCrossingSet::X86,
            true,
            None,
            None,
            Some(&counters.refused),
            |ret| frame.rax = ret.raw() as u64,
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
        let cache_lookup = |handle: u32| {
            files
                .cache(handle)
                .map_or(core::ptr::null_mut(), |ptr| ptr.as_ptr())
        };

        let mut anonymous =
            anonymous::X86AnonymousVenue::new(&call, task, binding.cpu_slot, frame.rcx);
        let slot = checked_scheduler_slot(carrick_guest_arch::CpuId::new(binding.cpu_slot))
            .unwrap_or_else(|| fatal_boot());
        let source = carrick_x86_carrier::native_execution::source(slot);
        let words = capture(frame, early_xstate);
        native_process::admit_root(words, source, task).unwrap_or_else(|_| fatal_boot());
        admit_stdio_cached(binding, task, &files);
        let file_table = task.linux.file_table.load(Ordering::Acquire).max(1);
        let mut service = native_process::Service::new(task, slot);
        native_process::drain_external_ingress(source, &mut service)
            .unwrap_or_else(|_| fatal_boot());
        let (route, root_exit) = {
            let (runtime, address) =
                native_process::runtime(source, task).unwrap_or_else(|_| fatal_boot());
            let mut process = runtime
                .enter_registered(
                    native_process::registry(),
                    source,
                    task,
                    address,
                    &words,
                    &mut service,
                )
                .unwrap_or_else(|_| fatal_boot());
            let mut native = NativeDispatch {
                frame,
                fpstate: early_xstate,
                call,
                publications: &binding.publications,
                slot: carrick_guest_arch::SlotId::from_index(binding.cpu_slot as usize),
                file_table,
                files: &files,
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
                None,
                Some(&GuestLifecycleVenue),
                Some(&mut *process),
                Some(source),
                Some(&mut anonymous),
                cache_lookup,
            );
            if let Some(reason) = process.take_run_failure() {
                complete_run_failure(task, reason);
            }
            if carrick_personality_linux::signal::signal_delivery_before_work(route, &task.linux)
                && let Some(r) =
                    deliver_signal_on_syscall_return(task, &mut process, frame, early_xstate)
            {
                route = r;
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
                        status.terminal_status().unwrap_or_else(|_| fatal_boot()),
                    ))
                } else {
                    ControlFlow::Suspend(OwnedContinuation::new(0))
                }
            }
            CompletionRoute::InvalidCompletion => {
                fatal_error(frame);
            }
            CompletionRoute::Forward | CompletionRoute::HostCustody => {
                let mut handled_in_ring = false;
                if [
                    carrick_personality_linux::crossing::nr::READ,
                    carrick_personality_linux::crossing::nr::WRITE,
                    carrick_personality_linux::crossing::nr::LSEEK,
                    carrick_personality_linux::crossing::nr::PREAD64,
                    carrick_personality_linux::crossing::nr::PWRITE64,
                ]
                .contains(&carrick_syscall_abi::CanonicalNr(call.canonical.raw()))
                {
                    let table = task.linux.file_table.load(Ordering::Acquire).max(1);
                    let guest_fd = call.args[0] as i32;
                    let binding = fd_map_lookup(files.fd_map(), table, guest_fd)
                        .and_then(|(handle, _)| handle.checked_sub(1))
                        .and_then(|index| files.opens().get(index as usize))
                        .and_then(DelegatedOpenFile::host_object);
                    if call.canonical.raw() == carrick_personality_linux::crossing::nr::WRITE.raw()
                        && let Some(binding) = binding
                        && binding.stdio_fd() != Some(guest_fd)
                    {
                        let saved = (frame.rax, frame.rdi, frame.rcx);
                        frame.rax = HostObjectWriteCrossing::NUMBER;
                        frame.rdi = binding.encoded() as u64;
                        frame.rcx = HostObjectWriteCrossing::FRAME_TAG;
                        forward_to_host(frame);
                        let result = frame.rax;
                        (frame.rdi, frame.rcx) = (saved.1, saved.2);
                        frame.rax = result;
                        handled_in_ring = true;
                    }
                    let positional = [
                        carrick_personality_linux::crossing::nr::LSEEK,
                        carrick_personality_linux::crossing::nr::PREAD64,
                        carrick_personality_linux::crossing::nr::PWRITE64,
                    ]
                    .contains(&carrick_syscall_abi::CanonicalNr(call.canonical.raw()));
                    if !handled_in_ring
                        && positional
                        && (0..=2).contains(&guest_fd)
                        && let Some(host_fd) = binding.and_then(|binding| {
                            binding
                                .stdio_fd()
                                .or_else(|| binding.host_fd().map(|fd| fd.raw()))
                        })
                        && host_fd != guest_fd
                    {
                        let saved_fd = frame.rdi;
                        frame.rdi = host_fd as u64;
                        forward_to_host(frame);
                        frame.rdi = saved_fd;
                        handled_in_ring = true;
                    }
                    if !handled_in_ring
                        && (0..=2).contains(&guest_fd)
                        && (binding.is_none()
                            || binding.is_some_and(|binding| binding.stdio_fd() != Some(guest_fd)))
                    {
                        frame.rax = LINUX_EBADF.guest_retval() as u64;
                        handled_in_ring = true;
                    }
                }
                if !handled_in_ring {
                    forward_to_host(frame);
                }
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
