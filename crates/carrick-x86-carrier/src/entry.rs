//! Native x86 CPL0 entry, page fault fixup, and syscall dispatch loop.

pub use carrick_el1::isa::x86::context::native::{
    CONTROL_PORT, CpuBinding, DIRECT_VA, ENTRY_KICK_PORT, FATAL_PORT, FAULT_DOORBELL_PORT,
    FORWARD_PORT, NativeFrame, OWNER_GRANT_PORT, RETURN_KICK_PORT, ShootdownTable, WORK_PORT,
    checked_scheduler_slot, decode_user_page_fault,
};
pub use carrick_el1::isa::x86::context::scheduler::{InterruptFrame, XsaveArea};

use crate::personality::{CallContext, ControlFlow, ExecutionContext, Personality};
use crate::table_span;
use carrick_el1_abi::{Counters, CurrentTask};
use carrick_guest_arch::{InterruptArch, UserVa};
use core::sync::atomic::Ordering;

pub use crate::initial_boot::fatal_boot;
pub use crate::native_execution::read_msr;

#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".global CARRICK_X86_CPL0_IMAGE_END",
    ".set CARRICK_X86_CPL0_IMAGE_END, {end}",
    end = const carrick_el1_abi::X86_CPL0_SUPERVISOR_IMAGE_BASE
        + carrick_el1_abi::X86_CPL0_SUPERVISOR_IMAGE_SIZE,
);

const _: () = assert!(core::mem::offset_of!(CpuBinding, task_address) == 24);

#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".section .initial_boot_header, \"a\"",
    ".quad 0x3130304e55525843",
    ".long {version}",
    ".long 0",
    ".quad carrick_x86_initial_boot",
    ".quad carrick_x86_peer_boot",
    version = const carrick_el1_abi::X86_INITIAL_BOOT_VERSION,
);

#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".section .text.entry, \"ax\"",
    ".global carrick_x86_syscall",
    "carrick_x86_syscall:",
    "swapgs",
    "mov gs:[8], rsp",
    "mov rsp, gs:[0]",
    "push r11",
    "push rcx",
    "push qword ptr gs:[8]",
    "push r11",
    "push rcx",
    "push rax",
    "push rdi",
    "push rsi",
    "push rdx",
    "push r10",
    "push r8",
    "push r9",
    "push rbx",
    "push rbp",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov r12, rsp",
    "sub rsp, 896",
    "and rsp, -64",
    "mov r13, rsp",
    "cld",
    "xor eax, eax",
    "mov rdi, rsp",
    "mov ecx, 104",
    "rep stosq",
    "mov eax, 7",
    "xor edx, edx",
    "xsave64 [rsp]",
    "mov rdi, r12",
    "mov rsi, gs:[16]",
    "mov rdx, r13",
    "call carrick_x86_enter",
    "mov rdi, r12",
    "mov rsi, r13",
    "call carrick_x86_validate_return",
    "mov eax, 7",
    "xor edx, edx",
    "xrstor64 [r13]",
    "mov rsp, r12",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbp",
    "pop rbx",
    "pop r9",
    "pop r8",
    "pop r10",
    "pop rdx",
    "pop rsi",
    "pop rdi",
    "pop rax",
    "pop rcx",
    "pop r11",
    "push r11",
    "push 0x23",
    "push rcx",
    "mov rcx, qword ptr [rsp + 32]",
    "mov r11, qword ptr [rsp + 40]",
    "mov qword ptr [rsp + 32], 0x1b",
    "swapgs",
    "iretq",
);

#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".global carrick_x86_page_fault_fixup",
    "carrick_x86_page_fault_fixup:",
    "push rax",
    "push rdx",
    "cmp qword ptr [rsp + 32], 8",
    "jne 9f",
    "mov rax, qword ptr gs:[24]", // CpuBinding.task_address
    "test rax, rax",
    "jz 9f",
    "mov rdx, qword ptr [rax + 24]", // CurrentTask.linux.fixup_pc
    "test rdx, rdx",
    "jz 9f",
    "mov qword ptr [rsp + 24], rdx",
    "pop rdx",
    "pop rax",
    "add rsp, 8", // discard #PF error code
    "iretq",
    "9:",
    "ud2",
);

#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".global carrick_x86_user_page_fault",
    "carrick_x86_user_page_fault:",
    "push rdi",
    "push rsi",
    "push rdx",
    "push rcx",
    "push rax",
    "push r8",
    "push r9",
    "push r10",
    "push r11",
    "push rbx",
    "push rbp",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov r12, rsp",
    "test byte ptr [r12 + 136], 3",
    "jz 7f",
    "swapgs",
    "2:",
    "mov eax, 1",
    "xchg qword ptr gs:[136], rax",
    "test rax, rax",
    "jnz 5f",
    "mov qword ptr gs:[144], r12",
    "mov rax, cr2",
    "mov qword ptr gs:[152], rax",
    "mov qword ptr gs:[160], 0",
    "mov rsp, gs:[0]",
    "sub rsp, 896",
    "and rsp, -64",
    "mov rdi, rsp",
    "call carrick_x86_save_extended_state",
    "mov rdi, r12",
    "mov rsi, rsp",
    "call carrick_x86_handle_user_page_fault",
    "test rax, rax",
    "jnz 3f",
    "mov rdi, rsp",
    "call carrick_x86_restore_extended_state",
    "xor eax, eax",
    "mov qword ptr gs:[136], rax",
    "mov rsp, r12",
    "swapgs",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbp",
    "pop rbx",
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rax",
    "pop rcx",
    "pop rdx",
    "pop rsi",
    "pop rdi",
    "add rsp, 8",
    "iretq",
    "3:",
    "mov rdx, rax",
    "mov rsi, qword ptr gs:[152]",
    "mov rdi, r12",
    "call carrick_x86_unresolved_user_page_fault",
    "5:",
    "ud2",
    "7:",
    "ud2",
);

pub mod user_fault_gate {
    use carrick_el1::isa::x86::interrupts;

    #[repr(C, packed)]
    struct Idtr {
        limit: u16,
        base: u64,
    }

    // SAFETY: assembly stubs declared in CPL0 entry assembly.
    unsafe extern "C" {
        fn carrick_x86_page_fault_fixup();
        fn carrick_x86_user_page_fault();
    }

    pub struct GateGuard {
        slot: *mut u8,
        previous: [u8; 16],
    }

    impl Drop for GateGuard {
        fn drop(&mut self) {
            // SAFETY: the same CPL0 CPU owns this private IDT. Mask IF while
            // restoring a multi-byte gate, then restore this lane's original IF state.
            unsafe {
                let mask = interrupts::hardware::mask_interrupts();
                for (i, byte) in self.previous.into_iter().enumerate() {
                    core::ptr::write_volatile(self.slot.add(i), byte);
                }
                interrupts::hardware::restore_interrupts(mask);
            }
        }
    }

    pub fn install() -> GateGuard {
        replace(carrick_x86_page_fault_fixup as *const () as u64)
    }

    pub fn install_persistent() {
        core::mem::forget(replace(carrick_x86_user_page_fault as *const () as u64));
    }

    fn replace(entry: u64) -> GateGuard {
        // SAFETY: CPL0 owns this CPU's IF; a gate update is not atomic.
        let mask = unsafe { interrupts::hardware::mask_interrupts() };
        let mut idtr = Idtr { limit: 0, base: 0 };
        // SAFETY: SIDT is legal at CPL0 and writes exactly the packed record.
        unsafe { core::arch::asm!("sidt [{}]", in(reg) &raw mut idtr, options(nostack)) };
        let base = idtr.base;
        if u64::from(idtr.limit) < 15 * 16 - 1 {
            // SAFETY: an undersized IDT cannot support recoverable #PF.
            unsafe { core::arch::asm!("ud2", options(noreturn)) }
        }
        let mut bytes = [0_u8; 16];
        bytes[0..2].copy_from_slice(&(entry as u16).to_le_bytes());
        bytes[2..4].copy_from_slice(&8_u16.to_le_bytes());
        bytes[5] = 0x8e;
        bytes[6..8].copy_from_slice(&((entry >> 16) as u16).to_le_bytes());
        bytes[8..12].copy_from_slice(&((entry >> 32) as u32).to_le_bytes());
        let slot = (base + 14 * 16) as *mut u8;
        let mut previous = [0_u8; 16];
        // SAFETY: each CPU owns its private, supervisor-mapped IDT page. IF
        // is masked through SYSCALL and no other CPU can reach this gate.
        unsafe {
            for (i, byte) in previous.iter_mut().enumerate() {
                *byte = core::ptr::read_volatile(slot.add(i));
            }
            for (i, byte) in bytes.into_iter().enumerate() {
                core::ptr::write_volatile(slot.add(i), byte);
            }
            interrupts::hardware::restore_interrupts(mask);
        }
        GateGuard { slot, previous }
    }
}

pub fn cross_owner_grant(cpu: carrick_guest_arch::CpuId, address: UserVa) {
    // SAFETY: this CPU owns the retained selection/completion slot. The
    // host authenticates CPU, MM, root and selected address before grant.
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") OWNER_GRANT_PORT,
            in("eax") cpu.raw(), in("rdi") address.raw(), options(nostack));
    }
}

#[repr(C)]
pub struct PageFaultStack {
    pub saved_gprs: [u64; 15],
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const _: () = {
    assert!(core::mem::offset_of!(PageFaultStack, error) == 120);
    assert!(core::mem::offset_of!(PageFaultStack, cs) == 136);
};

#[cold]
// SAFETY: no_mangle fault entry called by assembly on unrecoverable user page fault.
#[unsafe(no_mangle)]
pub extern "C" fn carrick_x86_unresolved_user_page_fault(
    frame: &PageFaultStack,
    far: u64,
    reason: u64,
) -> ! {
    if let Some(binding) = carrick_el1::isa::x86::context::current_cpu_binding() {
        binding.fault_reason.store(reason, Ordering::Release);
    }
    fn word(value: u32) {
        // SAFETY: this CPL0 CPU owns the existing 32-bit fault transport.
        unsafe {
            core::arch::asm!("out dx, eax", in("dx") FAULT_DOORBELL_PORT,
            in("eax") value, options(nostack, preserves_flags));
        }
    }
    word(14);
    for value in [
        frame.error,
        frame.rip,
        frame.cs,
        frame.rsp,
        frame.rflags,
        frame.saved_gprs[10],
        far,
    ] {
        word(value as u32);
        word((value >> 32) as u32);
    }
    // SAFETY: terminal kernel custody error; report the named stage
    // without replaying a partially committed syscall on this vCPU.
    unsafe {
        core::arch::asm!("sti", "nop", "out dx, al",
            in("dx") CONTROL_PORT, in("al") 0u8, options(nostack));
    }
    halt();
}

pub struct ExitAdmission;

fn admit_exit() -> ExitAdmission {
    ExitAdmission
}

fn write_port(port: u16, frame: &NativeFrame, _admission: ExitAdmission) {
    // SAFETY: CPL0 owns the declared control/forwarding transport.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("rax") frame as *const _ as u64,
            options(nostack, preserves_flags));
    }
}

pub(crate) fn doorbell(port: u16, frame: &NativeFrame) {
    write_port(port, frame, admit_exit());
}

/// Forward an unhandled Linux syscall to the host through the declared forward port.
pub fn forward_to_host(frame: &NativeFrame) {
    doorbell(FORWARD_PORT, frame);
}

/// Notify the host of completed work through the declared work port.
pub fn notify_work(frame: &NativeFrame) {
    doorbell(WORK_PORT, frame);
}

/// Signal fatal execution error through the declared fatal port and halt.
pub fn fatal_error(frame: &NativeFrame) -> ! {
    doorbell(FATAL_PORT, frame);
    halt();
}

/// Notify the fixture control listener through the declared control port.
pub fn control_doorbell(frame: &NativeFrame) {
    doorbell(CONTROL_PORT, frame);
}

pub fn halt() -> ! {
    loop {
        // SAFETY: terminal CPL0 fatal path, never returns to user.
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

pub struct PreparedUserPageFault<'a> {
    pub fault: carrick_guest_arch::FaultInfo,
    pub binding: &'a CpuBinding,
    pub task: &'a CurrentTask,
    pub counters: &'a Counters,
    pub slot: carrick_sched_core::SlotId,
}

pub fn prepare_user_page_fault<'a>(
    frame: &PageFaultStack,
) -> Result<PreparedUserPageFault<'a>, u64> {
    // This is the single production user #PF entry. Settle published
    // translation debt before handling or reporting this fault.
    if carrick_el1::isa::x86::interrupt::service_shootdowns().is_err() {
        carrick_el1::isa::x86::fatal_entry_binding();
    }
    let far: u64;
    // SAFETY: CR2 is the architectural fault address for this #PF entry.
    unsafe { core::arch::asm!("mov {}, cr2", out(reg) far, options(nomem, nostack)) };
    let Some(fault) = decode_user_page_fault(frame.error, far, frame.cs) else {
        return Err(1);
    };
    let Some(binding) = carrick_el1::isa::x86::context::current_cpu_binding() else {
        return Err(2);
    };
    if binding.task_address == 0 || binding.counters_address == 0 {
        return Err(3);
    }
    // SAFETY: the active CPU binding is retained from CPL0 bootstrap and
    // names this CPU's task and counters until its final user return.
    let (task, counters) = unsafe {
        (
            &*(binding.task_address as *const CurrentTask),
            &*(binding.counters_address as *const Counters),
        )
    };
    let Some(slot) = checked_scheduler_slot(carrick_guest_arch::CpuId::new(binding.cpu_slot))
    else {
        return Err(5);
    };
    Ok(PreparedUserPageFault {
        fault,
        binding,
        task,
        counters,
        slot,
    })
}

pub fn cache_lookup(handle: u32) -> *mut u8 {
    use carrick_guest_arch::LayoutBackend;
    let layout = <carrick_el1::isa::x86::X86Backend as LayoutBackend>::KERNEL_LAYOUT;
    handle
        .checked_sub(1)
        .and_then(|index| u64::from(index).checked_mul(carrick_el1_abi::DELEGATED_FILE_MAX_SIZE))
        .and_then(|offset| {
            layout
                .region
                .raw()
                .checked_add(carrick_el1_abi::EL1_CACHE_OFFSET)?
                .checked_add(offset)
        })
        .map_or(core::ptr::null_mut(), |address| address as *mut u8)
}

pub struct InitialWords {
    start: u64,
    end: u64,
    edit_root: Option<carrick_guest_arch::RootGpa>,
    working: Option<carrick_el1_abi::X86PrepareTableSpan>,
    pub context: Option<carrick_guest_arch::AddressContext<carrick_guest_arch::RootGpa>>,
}

impl InitialWords {
    pub fn new(
        start: u64,
        end: u64,
        edit_root: Option<carrick_guest_arch::RootGpa>,
        working: Option<carrick_el1_abi::X86PrepareTableSpan>,
        context: Option<carrick_guest_arch::AddressContext<carrick_guest_arch::RootGpa>>,
    ) -> Self {
        Self {
            start,
            end,
            edit_root,
            working,
            context,
        }
    }

    pub fn production(table_start: u64, table_end: u64) -> Self {
        Self {
            start: table_start,
            end: table_end,
            edit_root: None,
            working: table_span::working_tables(),
            context: None,
        }
    }

    pub fn live(
        table_start: u64,
        table_end: u64,
        context: carrick_guest_arch::AddressContext<carrick_guest_arch::RootGpa>,
        working: carrick_el1_abi::X86PrepareTableSpan,
    ) -> Self {
        Self {
            start: table_start,
            end: table_end,
            edit_root: None,
            working: Some(working),
            context: Some(context),
        }
    }

    fn word(
        &self,
        pa: u64,
    ) -> Result<
        &core::sync::atomic::AtomicU64,
        carrick_mmu_core::descriptor_refusal::DescriptorRefusal,
    > {
        use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
        let in_grants = pa >= self.start && pa.checked_add(8).is_some_and(|end| end <= self.end);
        let source_root = if self.start == 0xd0_0000 {
            (0x60_0000..0x7c_0000).contains(&pa)
        } else {
            self.start >= 0x40_00000 && (0x60_0000..0x60_1000).contains(&pa)
        };
        let in_working = self
            .working
            .is_some_and(|span| span.contains_word(carrick_guest_arch::FrameGpa::new(pa)));
        if pa & 7 != 0 || !(in_grants || in_working || source_root) {
            return Err(DescriptorRefusal::TableOutsidePrimary);
        }
        let mapped = carrick_el1::isa::x86::user_tables::table_alias(
            carrick_guest_arch::FrameGpa::new(pa & !4095),
        )
        .ok_or(DescriptorRefusal::TableOutsidePrimary)?
        .raw()
            + (pa & 4095);
        // SAFETY: the exact editor and mapped table window remain held until
        // the native transaction and its drain receipt have retired.
        Ok(unsafe { &*(mapped as *const core::sync::atomic::AtomicU64) })
    }
}

impl carrick_mmu_core::x86::descriptor_txn::LiveDescriptorWords for InitialWords {
    fn load(
        &self,
        pa: u64,
    ) -> Result<u64, carrick_mmu_core::descriptor_refusal::DescriptorRefusal> {
        Ok(self.word(pa)?.load(Ordering::Acquire))
    }
    fn compare_exchange(
        &self,
        pa: u64,
        before: u64,
        after: u64,
    ) -> Result<bool, carrick_mmu_core::descriptor_refusal::DescriptorRefusal> {
        Ok(self
            .word(pa)?
            .compare_exchange(before, after, Ordering::AcqRel, Ordering::Acquire)
            .is_ok())
    }
    fn store_unlinked(
        &self,
        pa: u64,
        value: u64,
    ) -> Result<(), carrick_mmu_core::descriptor_refusal::DescriptorRefusal> {
        use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
        self.word(pa)?
            .compare_exchange(0, value, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| DescriptorRefusal::Contended)
    }
    fn publish_barrier(&self) {
        core::sync::atomic::fence(Ordering::SeqCst);
    }
    fn invalidate_range(&self, _va: u64, _len: u64) {
        if let Some(context) = self.context {
            use carrick_guest_arch::{GuestLen, MmuBackend, UserRange};
            let binding = carrick_el1::isa::x86::context::current_cpu_binding()
                .unwrap_or_else(|| carrick_el1::isa::x86::fatal_entry_binding());
            let zone_address = carrick_el1::isa::x86_kernel_layout().zone.raw();
            // SAFETY: the carrier retains this compact supervisor zone;
            // its occupancy authority selects every executing MM.
            let zone = unsafe {
                &*(zone_address as *const carrick_el1::memory::reservations::X86Cpl0Zone)
            };
            let peer_live =
                (0..carrick_el1::isa::x86::context::native::CPL0_CPU_COUNT).any(|cpu| {
                    cpu != binding.cpu_slot as usize
                        && carrick_sched_core::SlotId::from_index(cpu).is_some_and(|slot| {
                            zone.installed_space(slot) == context.mm.raw().get()
                        })
                });
            if peer_live {
                if carrick_el1::isa::x86::interrupt::rendezvous_root(context.root.address().raw())
                    .is_err()
                {
                    carrick_el1::isa::x86::fatal_entry_binding();
                }
            } else {
                let range = UserRange::checked(UserVa::new(_va), GuestLen::new(_len))
                    .unwrap_or_else(|| carrick_el1::isa::x86::fatal_entry_binding());
                let mut backend = carrick_el1::isa::x86::X86Backend;
                let ticket = backend
                    .request_invalidation(context, range)
                    .unwrap_or_else(|_| carrick_el1::isa::x86::fatal_entry_binding());
                let receipt = backend
                    .ack_drain(ticket)
                    .unwrap_or_else(|_| carrick_el1::isa::x86::fatal_entry_binding());
                if receipt.context() != context {
                    carrick_el1::isa::x86::fatal_entry_binding();
                }
            }
            return;
        }
        if let Some(root) = self.edit_root.filter(|root| {
            carrick_el1::isa::x86::hardware_live_root().is_ok_and(|live| live == *root)
        }) {
            // SAFETY: this CPU owns the exact live root. With no PCID or
            // global translations, MOV CR3 drains its old user leaves.
            unsafe {
                core::arch::asm!("mov cr3, {}", in(reg) root.address().raw(), options(nostack, preserves_flags))
            }
        }
    }
}

pub fn carrier_enter<P: Personality>(
    frame: &mut NativeFrame,
    binding: &CpuBinding,
    early_xstate: &mut XsaveArea,
) {
    if !frame.valid_user_return() {
        doorbell(FATAL_PORT, frame);
        halt();
    }
    let mut arch = carrick_el1::isa::x86::kernel_arch();
    if arch.current_cpu().raw() != binding.cpu_slot {
        doorbell(FATAL_PORT, frame);
        halt();
    }
    if binding.entries.load(Ordering::Acquire) == 0 {
        user_fault_gate::install_persistent();
    }

    // SAFETY: bootstrap retains these supervisor-only records until the
    // VM/vCPUs retire; each binding names its issued current task.
    let (task, counters): (&'static CurrentTask, &'static Counters) = unsafe {
        (
            &*(binding.task_address as *const CurrentTask),
            &*(binding.counters_address as *const Counters),
        )
    };
    let _user_fault_gate = user_fault_gate::install();

    let mut arch = carrick_el1::isa::x86::kernel_arch();
    let mut decode_cx = CallContext::new(&mut arch, frame);
    let mut personality = P::default();
    let call = match personality.decode(&mut decode_cx) {
        Ok(call) => call,
        Err(_) => {
            binding.entries.fetch_add(1, Ordering::Relaxed);
            if binding.entry_kick.swap(0, Ordering::AcqRel) != 0 {
                doorbell(ENTRY_KICK_PORT, frame);
            }
            personality.handle_unrecognized_call(frame, task, binding, counters);
            binding.completions.fetch_add(1, Ordering::Relaxed);
            personality.on_counted_completion(binding);
            if binding.return_kick.swap(0, Ordering::AcqRel) != 0 {
                doorbell(RETURN_KICK_PORT, frame);
            }
            if personality.has_pending_host_work(task) {
                doorbell(WORK_PORT, frame);
            }
            return;
        }
    };

    let counted = personality.is_counted_call(&call);
    if counted {
        binding.entries.fetch_add(1, Ordering::Relaxed);
        if binding.entry_kick.swap(0, Ordering::AcqRel) != 0 {
            doorbell(ENTRY_KICK_PORT, frame);
        }
        binding
            .captured_stack
            .store(personality.call_stack(&call).raw(), Ordering::Release);
    }

    let mut cx = ExecutionContext {
        task,
        binding,
        counters,
        frame,
        xsave: early_xstate,
    };

    let flow = personality.dispatch(call, &mut cx);

    match flow {
        ControlFlow::Return(_) => {
            let _ =
                personality.encode_return(carrick_guest_arch::NativeReturnWord(frame.rax), frame);
        }
        ControlFlow::Suspend(_continuation) => {
            drop(_user_fault_gate);
            let slot = checked_scheduler_slot(carrick_guest_arch::CpuId::new(binding.cpu_slot))
                .unwrap_or_else(|| fatal_boot());
            P::schedule(slot);
        }
        ControlFlow::Terminate(termination) => {
            drop(_user_fault_gate);
            crate::native_execution::publish_root_exit(task, termination.status());
        }
    }

    if counted {
        binding.completions.fetch_add(1, Ordering::Relaxed);
        personality.on_counted_completion(binding);
        if binding.return_kick.swap(0, Ordering::AcqRel) != 0 {
            doorbell(RETURN_KICK_PORT, frame);
        }
        if personality.has_pending_host_work(task) {
            doorbell(WORK_PORT, frame);
        }
    }
}

pub fn carrier_validate_return<P: Personality>(frame: &mut NativeFrame, xsave: &mut XsaveArea) {
    let mut personality = P::default();
    personality.on_user_return(frame, xsave);
    if !frame.valid_user_return() {
        doorbell(FATAL_PORT, frame);
        halt();
    }
    if carrick_el1::isa::x86::interrupt::check_user_return_generation().is_err() {
        doorbell(FATAL_PORT, frame);
        halt();
    }
}
