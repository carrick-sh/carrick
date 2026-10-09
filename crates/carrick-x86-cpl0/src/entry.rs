// Thin native entry into Carrick's common in-guest Linux personality.
// Included by both the production and fixture binaries.
// Architecture-specific crate attributes belong to their wrappers.

#[cfg(not(target_os = "none"))]
fn main() {}

// Cargo compiles this source as two distinct targets. The fixture target is
// the only image that can dispatch synthetic observation syscalls. The const
// predicate is folded before production linking, so those leaves are absent
// from the ordinary carrick-x86-cpl0 image. Every fixture dispatch branch
// passes through the same retained, high-entropy witness.
#[cfg(target_os = "none")]
macro_rules! fixture_dispatch_enabled {
    () => {
        fixture_expr!(crate::carrick_x86_fixture_dispatch_witness())
    };
}

#[cfg(target_os = "none")]
extern crate alloc as rust_alloc;

#[cfg(target_os = "none")]
use carrick_el1::isa::x86::context::native as adapter;

#[cfg(target_os = "none")]
use carrick_el1::isa::x86::interrupts;
#[cfg(target_os = "none")]
mod native_irq;
#[cfg(target_os = "none")]
const _: () = assert!(core::mem::offset_of!(adapter::CpuBinding, task_address) == 24);
fixture_items! {
    #[cfg(target_os = "none")]
    use carrick_el1::isa::x86::context::scheduler;
}

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
    // The complete frame already owns R12/R13. Keep its address and the
    // aligned native xstate area in callee-preserved registers across Rust
    // and stopped-host forwarding; no Rust may run after the final XRSTOR.
    "mov r12, rsp",
    "sub rsp, 896",
    "and rsp, -64",
    "mov r13, rsp",
    // XSAVE does not initialize reserved header words. Reused stack bytes
    // must not become an unsupported component or XRSTOR reserved-bit fault.
    "xor eax, eax",
    "mov qword ptr [rsp + 512], rax",
    "mov qword ptr [rsp + 520], rax",
    "mov qword ptr [rsp + 528], rax",
    "mov qword ptr [rsp + 536], rax",
    "mov qword ptr [rsp + 544], rax",
    "mov qword ptr [rsp + 552], rax",
    "mov qword ptr [rsp + 560], rax",
    "mov qword ptr [rsp + 568], rax",
    "mov eax, 7",
    "xor edx, edx",
    "xsave64 [rsp]",
    "mov rdi, r12",
    "mov rsi, gs:[16]",
    "mov rdx, r13",
    "call carrick_x86_enter",
    // A host forward may alter the retained frame after the entry check.
    // Validate once more after every early return and before SWAPGS/IRETQ.
    "mov rdi, r12",
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
    // The saved user SP is already at the correct place in the IRET frame.
    "push r11",
    "push 0x23",
    "push rcx",
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
    // Error code, RIP and CS follow the two saved scratch registers.
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
    "ud2", // an unguarded kernel/user fault is fatal
);

// Vector 14's long-lived CPL3 path saves the full GPR and enabled xstate
// before calling shared fault policy. The syscall-scoped kernel-copy gate
// temporarily replaces it and restores it before returning to user mode.
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
    // Fifteen saved registers, then error, RIP, CS, RFLAGS, RSP and SS.
    "test byte ptr [r12 + 136], 3",
    "jz 7f",
    "swapgs",
    "2:",
    // Claim before resetting RSP: a nested CPL0 #PF must not overwrite the
    // outer xstate or Rust frame. XCHG supplies per-CPU atomic ownership.
    "mov eax, 1",
    "xchg qword ptr gs:[136], rax",
    "test rax, rax",
    "jnz 5f",
    "mov qword ptr gs:[144], r12",
    "mov rax, cr2",
    "mov qword ptr gs:[152], rax",
    "mov qword ptr gs:[160], 0",
    // TSS.RSP0 is a 4 KiB fault-entry stack. Keep its hardware/GPR frame
    // there, then run xsave and Rust on this CPU's 64 KiB syscall stack.
    "mov rsp, gs:[0]",
    "sub rsp, 4160",
    "and rsp, -64",
    "mov rdi, rsp",
    "call carrick_x86_save_extended_state",
    "mov r14, cr2",
    "mov rdi, r12",
    "call carrick_x86_handle_user_page_fault",
    "mov r13, rax",
    "test r13, r13",
    "jnz 3f",
    "mov rdi, rsp",
    "call carrick_x86_restore_extended_state",
    "mov rsp, r12",
    "mov qword ptr gs:[136], 0",
    "test byte ptr [rsp + 136], 3",
    "jz 4f",
    "swapgs",
    "4:",
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
    "add rsp, 8", // discard the x86 page-fault error word
    "iretq",
    "3:",
    "mov rdi, r12",
    "mov rsi, r14",
    "mov rdx, r13",
    "call carrick_x86_unresolved_user_page_fault",
    "7:",
    // Nested CPL0 entry retains the claimed outer fault before terminating.
    "cmp qword ptr gs:[136], 0",
    "jne 5f",
    // A non-nested CPL0 fault bypasses Linux policy and stack reuse.
    "mov qword ptr gs:[160], 1",
    "mov dx, 0xcc",
    "mov eax, 1",
    "out dx, al",
    "jmp 6f",
    "5:",
    // Retain the outer frame and original CR2 in this CPU binding. Report a
    // kernel invariant error, without calling Rust or reusing its outer stack.
    "mov qword ptr gs:[160], 8",
    "mov dx, 0xcc", // existing fatal transport
    "mov eax, 8",
    "out dx, al",
    "6:",
    "cli",
    "hlt",
    "jmp 6b",
    "ud2",
);

#[cfg(target_os = "none")]
mod user_fault_gate {
    use crate::interrupts;

    #[repr(C, packed)]
    struct Idtr {
        limit: u16,
        base: u64,
    }

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
            // restoring a multi-byte gate, then restore this lane's prior IF.
            unsafe {
                let mask = interrupts::hardware::mask_interrupts();
                for (i, byte) in self.previous.into_iter().enumerate() {
                    core::ptr::write_volatile(self.slot.add(i), byte);
                }
                interrupts::hardware::restore_interrupts(mask);
            }
        }
    }

    /// Install the CPL0 #PF fixup on this CPU's private IDT before any
    /// guarded user access. SYSCALL has masked IF and the IDT is retained by
    /// the image owner until this CPU retires.
    pub fn install() -> GateGuard {
        replace(carrick_x86_page_fault_fixup as *const () as u64)
    }

    /// Retain the CPL3 #PF gate after the initial image enters userspace.
    /// The kernel-copy guard replaces it only for one syscall and restores it.
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
        // is masked through SYSCALL and no other CPU can read this gate.
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

#[cfg(target_os = "none")]
mod kernel {
    mod initial_boot {
        include!("initial_boot.rs");
    }
    mod anonymous {
        include!("anonymous.rs");
    }
    mod native_process {
        include!("native_process.rs");
    }
    mod native_execution {
        include!("native_execution.rs");
    }
    use super::adapter::*;
    use carrick_el1::lock::SpinLock;
    use carrick_el1::personality::thread_setup::GuestLifecycleVenue;
    use carrick_el1::personality::{dispatch, sched};
    use carrick_el1_abi::{Counters, CurrentTask, InotifyNameCache};
    use carrick_guest_arch::{CanonicalNr, InterruptArch, LayoutBackend, NativeReturnWord, SyscallFrame, UserVa};
    use carrick_x86_cpl0::ProductionBoundary;
    fixture_items! { use carrick_guest_arch::EntryArch; }
    fixture_items! { use core::sync::atomic::AtomicU64; }
    use core::sync::atomic::Ordering;

    /// One physical grant crossing for hardware faults and kernel user copies.
    /// RDI names the selected user page independently of the last hardware CR2.
    fn cross_owner_grant(cpu: carrick_guest_arch::CpuId, address: UserVa) {
        // SAFETY: this CPU owns the retained selection/completion slot. The
        // host authenticates CPU, MM, root and selected address before lending.
        unsafe {
            core::arch::asm!("out dx, eax", in("dx") OWNER_GRANT_PORT,
                in("eax") cpu.raw(), in("rdi") address.raw(), options(nostack));
        }
    }

    struct NativeDispatch<'a> {
        frame: &'a mut NativeFrame,
        call: carrick_personality_linux::entry::CanonicalCall,
        publications: &'a core::sync::atomic::AtomicU64,
        slot: Option<carrick_guest_arch::SlotId>,
    }

    impl SyscallFrame for NativeDispatch<'_> {
        fn canonical_ordinal(&self) -> CanonicalNr { self.call.canonical }
        fn argument(&self, index: usize) -> Option<u64> { self.call.args.get(index).copied() }
        fn result(&self) -> NativeReturnWord { NativeReturnWord(self.frame.rax) }
        fn set_result(&mut self, result: NativeReturnWord) { self.frame.rax = result.0; }
        fn slot(&self) -> Option<carrick_guest_arch::SlotId> { self.slot }
        // The retained metadata stores task records at an ISA-specific stride;
        // this call projects only the authenticated current task as a slice.
        fn task_index(&self) -> usize { if self.slot.is_some() { 0 } else { usize::MAX } }
        fn user_sp(&self) -> Option<UserVa> { Some(self.call.stack) }
    }
    impl dispatch::GuestDispatchFrame for NativeDispatch<'_> {
        fn native_number(&self) -> carrick_guest_arch::NativeOrdinal { self.call.native }
        fn crossing_set(&self) -> carrick_personality_linux::crossing::HostCrossingSet {
            carrick_personality_linux::crossing::HostCrossingSet::X86
        }

        fn arm_frame(&mut self) -> Option<&mut carrick_el1_abi::TrapFrame> { None }
        fn arm_frame_ref(&self) -> Option<&carrick_el1_abi::TrapFrame> { None }
        fn arm_scheduler(&self) -> bool { false }
        fn robust_publications(&self) -> Option<&core::sync::atomic::AtomicU64> {
            Some(self.publications)
        }
        fn record_isa_unsupported_forward(&self) {
            CARRICK_CPL0_ISA_UNSUPPORTED_FORWARDS.fetch_add(1, Ordering::Relaxed);
        }
    }

    static EMPTY_NAME_CACHE: InotifyNameCache = InotifyNameCache::new();

    // Count native exits across CPL0 CPUs for image/link and live diagnostics.
    // A port write exits the VM, so no lock may remain held across it: another
    // CPU can enter and need the same lock before the first CPU resumes.
    #[unsafe(no_mangle)]
    pub static CARRICK_CPL0_DOORBELL_COUNT: SpinLock<u64> = SpinLock::new(0);

    /// Refusals caused by an ARM-only saved-frame leaf, distinct from Linux
    /// semantic forwards and from absent file/IPC/MM venues.
    #[unsafe(no_mangle)]
    pub static CARRICK_CPL0_ISA_UNSUPPORTED_FORWARDS: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);

    /// Host crossing evaluation and set from shared personality.
    pub use carrick_personality_linux::crossing::{
        evaluate_host_crossing, HostCrossingSet,
    };

    // The KVM fault fixture owns one exact MM and one host-backed prepared
    // page. These records stay live across the native syscall boundary.
    fixture_items! {
        pub(crate) static SHARED_FAULT_MAILBOX: carrick_el1_abi::FrameGrantMailbox =
            carrick_el1_abi::FrameGrantMailbox::new();
        pub(crate) static SHARED_COW_POOL: carrick_el1_abi::CowGrantPool =
            carrick_el1_abi::CowGrantPool::new();
        // Retained by the stopped fixture carrier until VM retirement.
        pub(crate) static FORK_RESIDENCY_ADDRESS: AtomicU64 = AtomicU64::new(0);
    }

    #[repr(C)]
    struct PageFaultStack {
        saved_gprs: [u64; 15],
        error: u64,
        rip: u64,
        cs: u64,
        rflags: u64,
        rsp: u64,
        ss: u64,
    }
    const _: () = {
        assert!(core::mem::offset_of!(PageFaultStack, error) == 120);
        assert!(core::mem::offset_of!(PageFaultStack, cs) == 136);
    };

    /// Vector 14 from CPL3: classify the native error then use the same
    /// reservation/editor/COW owner as ARM's data-abort policy.
    #[unsafe(no_mangle)]
    extern "C" fn carrick_x86_handle_user_page_fault(frame: &PageFaultStack) -> u64 {
        use carrick_el1::fault::dispatch_x86_fault_with_prepared;
        fixture_items! { use carrick_el1::fault::X86CowResolver; }
        use carrick_el1_abi::Action;
        // This is the single production user #PF entry. Settle published
        // translation debt before handling or reporting this fault.
        if carrick_el1::isa::x86::interrupt::service_shootdowns().is_err() {
            carrick_el1::isa::x86::fatal_entry_binding();
        }
        let far: u64;
        // SAFETY: CR2 is the architectural fault address for this #PF entry.
        unsafe { core::arch::asm!("mov {}, cr2", out(reg) far, options(nomem, nostack)) };
        let Some(fault) = decode_user_page_fault(frame.error, far, frame.cs) else {
            return 1;
        };
        let Some(binding) = carrick_el1::isa::x86::context::current_cpu_binding() else {
            return 2;
        };
        if binding.task_address == 0 || binding.counters_address == 0 {
            return 3;
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
            return 5;
        };
        fixture_stmt! {
        use carrick_core::mm::transfer::resolver::NoopPreparedResolver;
        use carrick_el1::fault::GrantMailboxes;
        let serve = |zone_address: carrick_guest_arch::KernelVa,
                     residency: &carrick_el1_abi::FrameGrantResidencyTable,
                     pool: &dyn carrick_el1_abi::CowGrantVenue,
                     mailbox: &carrick_el1_abi::FrameGrantMailbox| {
            // SAFETY: the boot owner published this supervisor-only zone and
            // retains it across the exact CPU's space-edit transaction.
            let zone = unsafe { &*(zone_address.raw() as *const carrick_sched_core::ZoneTables) };
            let words = InitialWords::fixture();
            let mut cow = X86CowResolver { words: &words, pool, residency, completion: None };
            let result = dispatch_x86_fault_with_prepared(
                carrick_guest_arch::CpuId::new(0), fault, counters, task,
                carrick_el1::substrate::sched::object_wait::space_access(
                    zone, slot,
                ),
                GrantMailboxes::own(mailbox),
                None::<carrick_el1::fault::PreparedFaultPath<'_, NoopPreparedResolver>>,
                &mut cow,
            );
            if result == Action::Served { 0 } else { 6 }
        };
            let lane = binding.scheduler_witness.load(Ordering::Acquire);
            if lane == super::lifecycle::LIFECYCLE_LANE
                || lane == super::lifecycle::LIFECYCLE_LANE + super::lifecycle::LIFECYCLE_STRIDE
            {
                let address = FORK_RESIDENCY_ADDRESS.load(Ordering::Acquire);
                if address == 0 { return 4; }
                // SAFETY: the fixture published and retains this aligned table.
                let residency = unsafe { &*(address as *const carrick_el1_abi::FrameGrantResidencyTable) };
                return serve(carrick_guest_arch::KernelVa::new(super::lifecycle::LIFECYCLE_ZONE), residency,
                    &SHARED_COW_POOL, &SHARED_FAULT_MAILBOX);
            }
        }
        let mm_key = task.mm.key.load(Ordering::Acquire);
        let Some(words) =
            anonymous::live_words(match carrick_el1_abi::ReservationMm::new(mm_key) {
                Some(mm) => mm,
                None => return 9,
            })
        else {
            return 9;
        };
        let layout =
            <carrick_el1::isa::x86::X86Backend as carrick_guest_arch::LayoutBackend>::KERNEL_LAYOUT;
        let Some(venues) = carrick_el1_abi::KernelFaultVenues::derive(layout)
            .and_then(carrick_el1_abi::KernelFaultVenues::require_upper_half)
        else {
            return 7;
        };
        // SAFETY: production KVM bootstrap maps and zero-initializes the
        // retained x86 kernel region at this typed upper-half layout before
        // admitting CPL3. The region owner keeps it live until CPU retirement.
        let (residency, portal, cow_pool) = unsafe {
            (
                &*(venues.residency.raw() as *const carrick_el1_abi::FrameGrantResidencyTable),
                &*(layout.portal.raw() as *const carrick_el1_abi::MmPortalSlots),
                &*(venues.cow_pool.raw() as *const carrick_el1_abi::CowGrantPool),
            )
        };
        // SAFETY: the boot owner retains the compact zone and its parked ABI.
        let zone = unsafe {
            &*(venues.zone.raw() as *const carrick_el1::memory::reservations::X86Cpl0Zone)
        };
        let roots = carrick_el1::memory::reservations::shared_x86_cpl0_guest();
        let spaces = carrick_core::wait::space_access(zone, slot, anonymous::initial_release);
        let supply = carrick_el1::fault::OwnerFaultSupply::new(portal);
        // SAFETY: the shared fault owner acquires the exact-MM editor before
        // every prepared commit; InitialWords retains its native context.
        let Some(prepared_mm) = core::num::NonZeroU64::new(mm_key) else {
            return 9;
        };
        let mut prepared =
            unsafe { carrick_el1::fault::X86PreparedResolver::under_editor(prepared_mm, &words) };
        let mut cow = carrick_el1::fault::X86CowResolver {
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
                cross_owner_grant(carrick_guest_arch::CpuId::new(binding.cpu_slot), fault.address);
            }
            return 0;
        }
        use carrick_el1::fault::OwnerFaultSupplyOutcome;
        match supply.outcome() {
            OwnerFaultSupplyOutcome::PolicyDeclined => 6,
            OwnerFaultSupplyOutcome::Unavailable => 9,
            OwnerFaultSupplyOutcome::CowSelected => {
                // The shared owner selected this exact inherited private page
                // and released its editor before the physical loan crossing.
                cross_owner_grant(carrick_guest_arch::CpuId::new(binding.cpu_slot), fault.address);
                let supply = carrick_el1::fault::OwnerFaultSupply::new(portal);
                let mut cow = carrick_el1::fault::X86CowResolver {
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
                // Guest COW owns the copy and descriptor stores. The retained
                // completion now settles physical aliases before user return.
                cross_owner_grant(carrick_guest_arch::CpuId::new(binding.cpu_slot), fault.address);
                0
            }
            OwnerFaultSupplyOutcome::Selected => {
                cross_owner_grant(carrick_guest_arch::CpuId::new(binding.cpu_slot), fault.address);
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
                >(
                    grant_slot,
                    &words,
                    residency,
                    target,
                    // The ISA executor already completed InitialWords' checked
                    // context drain before producing its Applied outcome.
                    || {},
                );
                drop(root);
                let applied = receipt.is_some_and(|receipt| {
                    matches!(
                        receipt.outcome,
                        carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome::Applied(_)
                    )
                });
                cross_owner_grant(carrick_guest_arch::CpuId::new(binding.cpu_slot), fault.address);
                if applied { 0 } else { 9 }
            }
        }
    }

    /// Forward the original hardware fault through the existing typed x86
    /// transport. x86 signal-handler installation is not bound in this lane;
    /// the host applies the shared default Linux signal policy to this record.
    #[cold]
    #[unsafe(no_mangle)]
    extern "C" fn carrick_x86_unresolved_user_page_fault(
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
        fixture_stmt! {
            // The terminal fixture fault can resume solely to witness queued
            // KICK settlement and its bounded completion doorbell.
            unsafe {
                core::arch::asm!("sti", "nop", "out dx, al",
                    in("dx") CONTROL_PORT, in("al") 0u8, options(nostack));
            }
        }
        halt()
    }

    fixture_items! {
        pub(crate) fn lifecycle_invariant_error(reason: super::lifecycle::LifecycleInvariant) -> ! {
            // SAFETY: terminal kernel custody error; report the named stage
            // without replaying a partially committed syscall on the host.
            unsafe { core::arch::asm!("out dx, al", in("dx") FATAL_PORT,
                in("rax") reason as u64, options(nostack, preserves_flags)); }
            halt()
        }
    }

    // A port exit may suspend this CPU while another CPU continues. The
    // admission value can only be produced after the lock guard is dropped.
    struct ExitAdmission;

    fn admit_exit() -> ExitAdmission {
        let mut count = CARRICK_CPL0_DOORBELL_COUNT.lock();
        *count = count.wrapping_add(1);
        core::mem::drop(count);
        ExitAdmission
    }

    fn write_port(port: u16, frame: &mut NativeFrame, _admission: ExitAdmission) {
        // SAFETY: CPL0 owns the declared control/forwarding transport.
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("rax") frame as *mut _ as u64,
                options(nostack, preserves_flags));
        }
    }

    pub(crate) fn doorbell(port: u16, frame: &mut NativeFrame) {
        write_port(port, frame, admit_exit());
    }

    fn fixture_edit(
        va: u64,
        sequence: core::num::NonZeroU64,
        operation: carrick_guest_arch::EditOperation,
    ) -> Result<carrick_mmu_core::x86::descriptor_txn::DescriptorReceipt, carrick_el1::isa::ArchError>
    {
        use carrick_guest_arch::{
            EditIntent, EditOwner, FrameGpa, GuestLen, KernelVa, MmuEditArch, RootGpa, TableWindow,
            UserRange, UserVa,
        };
        let root = RootGpa::page_aligned(FrameGpa::new(0x60_0000))
            .ok_or(carrick_el1::isa::ArchError::Unbound)?;
        let mm_key = carrick_el1::isa::x86::context::current_cpu_binding()
            .and_then(|binding| {
                if binding.task_address == 0 {
                    None
                } else {
                    let task =
                        unsafe { &*(binding.task_address as *const carrick_el1_abi::CurrentTask) };
                    core::num::NonZeroU64::new(
                        task.mm.key.load(core::sync::atomic::Ordering::Acquire),
                    )
                }
            })
            .unwrap_or(core::num::NonZeroU64::MIN);
        // SAFETY: this fixture runs one vCPU at a time with the retained
        // root, so each sequential native descriptor edit is exclusive.
        let owner = unsafe { EditOwner::issue(root, mm_key, sequence) };
        let range = UserRange::checked(UserVa::new(va), GuestLen::new(4096))
            .ok_or(carrick_el1::isa::ArchError::Unbound)?;
        let intent = EditIntent::checked(owner, range, operation, &[])
            .ok_or(carrick_el1::isa::ArchError::Unbound)?;
        let mut arch = carrick_el1::isa::x86::Kernel::new(carrick_el1::isa::x86::X86Backend);
        // SAFETY: KVM retains and maps the 448-page PML4 window under the
        // upper-half supervisor direct window; the sibling vCPU is stopped here.
        let tables = unsafe {
            TableWindow::issue(
                root.address(),
                KernelVa::new(DIRECT_VA + root.address().raw()),
                GuestLen::new(FIXTURE_PML4_CAPACITY),
            )
        }
        .ok_or(carrick_el1::isa::ArchError::Unbound)?;
        // SAFETY: the exact editor and mapped table window remain held until
        // the native transaction and its drain receipt have settled.
        unsafe { arch.execute_edit(intent, tables) }
    }

    /// One stopped-carrier fixture view of the retained supervisor direct
    /// window. The production MM owner receives its table authority from the
    /// portal instead of this fixed test grant.
    pub(crate) struct InitialWords {
        start: u64,
        end: u64,
        edit_root: Option<carrick_guest_arch::RootGpa>,
        working: Option<carrick_el1_abi::X86PrepareTableSpan>,
        context: Option<carrick_guest_arch::AddressContext<carrick_guest_arch::RootGpa>>,
    }
    impl InitialWords {
        pub(crate) fn fixture() -> Self {
            let root = carrick_el1::isa::x86::hardware_live_root()
                .unwrap_or_else(|_| carrick_el1::isa::x86::fatal_entry_binding());
            Self {
                start: 0x20_0000,
                end: 0xd4_0000,
                edit_root: Some(root),
                working: None,
                context: None,
            }
        }
        fn production(table_start: u64, table_end: u64) -> Self {
            Self {
                start: table_start,
                end: table_end,
                edit_root: None,
                working: anonymous::working_tables(),
                context: None,
            }
        }
        fn live(
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
            let in_grants =
                pa >= self.start && pa.checked_add(8).is_some_and(|end| end <= self.end);
            let source_root = if self.start == 0xd0_0000 {
                (0x60_0000..0x7c_0000).contains(&pa)
            } else {
                self.start >= 0x40_00000 && (0x60_0000..0x60_1000).contains(&pa)
            };
            let in_working = self.working.is_some_and(|span|
                span.contains_word(carrick_guest_arch::FrameGpa::new(pa)));
            if pa & 7 != 0 || !(in_grants || in_working || source_root) {
                return Err(DescriptorRefusal::TableOutsidePrimary);
            }
            let mapped = carrick_el1::isa::x86::user_tables::table_alias(
                carrick_guest_arch::FrameGpa::new(pa & !4095),
            )
            .ok_or(DescriptorRefusal::TableOutsidePrimary)?
            .raw()
                + (pa & 4095);
            // SAFETY: Cpl0Carrier retains this supervisor mapping for the VM
            // lifetime; the MM owner holds the stopped sibling and exact grant.
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
                use carrick_guest_arch::{GuestLen, MmuBackend, UserRange, UserVa};
                let binding = carrick_el1::isa::x86::context::current_cpu_binding()
                    .unwrap_or_else(|| carrick_el1::isa::x86::fatal_entry_binding());
                let zone_address = carrick_el1::isa::x86_kernel_layout().zone.raw();
                // SAFETY: the carrier retains this compact supervisor zone;
                // its occupancy authority selects every executing MM.
                let zone = unsafe {
                    &*(zone_address as *const carrick_el1::memory::reservations::X86Cpl0Zone)
                };
                let peer_live = (0..super::adapter::CPL0_CPU_COUNT).any(|cpu| {
                    cpu != binding.cpu_slot as usize
                        && carrick_sched_core::SlotId::from_index(cpu).is_some_and(|slot| {
                            zone.installed_space(slot) == context.mm.raw().get()
                        })
                });
                if peer_live {
                    if carrick_el1::isa::x86::interrupt::rendezvous_root(
                        context.root.address().raw(),
                    )
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
            // Unpublished initial roots need no drain. Live fixture edits are
            // licensed by the captured root, never by a fixed physical number.
            if let Some(root) = self.edit_root.filter(|root| {
                carrick_el1::isa::x86::hardware_live_root().is_ok_and(|live| live == *root)
            }) {
                // SAFETY: this CPU owns the exact live root. With no PCID or
                // global translations, MOV CR3 drains its old user leaves.
                unsafe {
                    core::arch::asm!("mov cr3, {}", in(reg) root.address().raw(), options(nostack,preserves_flags))
                }
            }
        }
    }

    pub(crate) struct InitialFrames {
        next_table: u64,
        next_data: u64,
    }
    impl InitialFrames {
        pub(crate) fn zeroed(pa: u64) {
            // SAFETY: these private fixture physical pages are mapped RW by
            // the one retained direct window and not reachable by user PTEs.
            unsafe { core::ptr::write_bytes((DIRECT_VA + pa) as *mut u8, 0, 4096) };
        }
    }
    impl carrick_el1::isa::x86::initial_mm::InitialFrameSource for InitialFrames {
        fn take_zeroed_table(&mut self) -> Option<carrick_guest_arch::RootGpa> {
            use carrick_guest_arch::{FrameGpa, RootGpa};
            if self.next_table >= 0xd4_0000 {
                return None;
            }
            let pa = self.next_table;
            self.next_table += 4096;
            Self::zeroed(pa);
            RootGpa::page_aligned(FrameGpa::new(pa))
        }
        fn take_zeroed_data(
            &mut self,
        ) -> Option<carrick_el1::isa::x86::initial_mm::InitialDataGrant> {
            use carrick_el1::isa::x86::initial_mm::InitialDataGrant;
            use carrick_guest_arch::{EditBacking, FrameGpa};
            if self.next_data >= 0xd1_0000 {
                return None;
            }
            let pa = self.next_data;
            self.next_data += 4096;
            Self::zeroed(pa);
            let identity = core::num::NonZeroU64::new(pa)?;
            Some(InitialDataGrant {
                frame: FrameGpa::new(pa),
                backing: EditBacking {
                    frame_id: identity,
                    mapping_id: identity,
                    owner_generation: core::num::NonZeroU64::MIN,
                    inventory_revision: core::num::NonZeroU64::MIN,
                },
            })
        }
        fn copy_guest_data(
            &mut self,
            grant: carrick_el1::isa::x86::initial_mm::InitialDataGrant,
            offset: u16,
            source: carrick_guest_arch::FrameGpa,
            len: u16,
        ) -> bool {
            let dest = grant.frame.raw();
            let from = source.raw();
            if !((0xd0_0000..0xd1_0000).contains(&dest) || (0x40_0000..0x41_0000).contains(&dest))
                || !(0x10_000..0x11_000).contains(&from)
                || from + u64::from(len) > 0x11_000
                || u64::from(offset) + u64::from(len) > 4096
            {
                return false;
            }
            // SAFETY: this stopped fixture identity-maps the staged user code
            // page and retains its disjoint private destination grant under
            // the supervisor direct window. The fixture has SMAP disabled.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    from as *const u8,
                    (DIRECT_VA + dest + u64::from(offset)) as *mut u8,
                    usize::from(len),
                );
            }
            true
        }
        fn write_data(
            &mut self,
            grant: carrick_el1::isa::x86::initial_mm::InitialDataGrant,
            offset: u16,
            bytes: &[u8],
        ) -> bool {
            let pa = grant.frame.raw();
            if !((0xd0_0000..0xd1_0000).contains(&pa) || (0x40_0000..0x41_0000).contains(&pa))
                || usize::from(offset)
                    .checked_add(bytes.len())
                    .is_none_or(|end| end > 4096)
            {
                return false;
            }
            // SAFETY: the source is the fixed RX fixture ELF and the private
            // destination grant is disjoint, writable and retained by KVM.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    (DIRECT_VA + pa + u64::from(offset)) as *mut u8,
                    bytes.len(),
                );
            }
            true
        }
    }

    #[unsafe(no_mangle)]
    extern "C" fn carrick_x86_enter(
        frame: &mut NativeFrame,
        binding: &CpuBinding,
        _early_xstate: &mut carrick_el1::isa::x86::context::scheduler::XsaveArea,
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
            super::user_fault_gate::install_persistent();
        }
        // Both retained scheduler witness fixtures qualify XCR0 and XSAVE
        // geometry before entry. Exercise the shared native context leaf while
        // preserving the exact current task and MM authority.
        fixture_stmt! { if binding.scheduler_witness.load(Ordering::Acquire) != 0 {
            let Ok(saved) = arch.save_context(frame) else {
                doorbell(FATAL_PORT, frame);
                halt();
            };
            if arch.load_context(frame, &saved).is_err() {
                doorbell(FATAL_PORT, frame);
                halt();
            }
        } }
        fixture_stmt! { if frame.rax == OBSERVE_NATIVE && fixture_dispatch_enabled!() {
            doorbell(CONTROL_PORT, frame);
            frame.rax = 0;
            return;
        } }
        if fixture_dispatch_enabled!() && frame.rax == OBSERVE_INITIAL_MM {
            use carrick_el1::isa::x86::initial_mm::{
                InitialImageRegion, InitialImageSpec, InitialSourceRange, InitialStackSpec,
                install_initial_image,
            };
            use carrick_guest_arch::{EditPermissions, MmuBackend};
            // The test stages one already-parsed ET_EXEC image in its RX code
            // page. No guest ELF parser or second host descriptor author runs.
            if frame.rdi != 0x10100 || !(0xc0..=0xf00).contains(&frame.rsi) {
                doorbell(FATAL_PORT, frame);
                halt();
            }
            // SAFETY: this exact RX user fixture page remains mapped under
            // the still-live source root until the new MM has copied its bytes.
            let elf =
                unsafe { core::slice::from_raw_parts(frame.rdi as *const u8, frame.rsi as usize) };
            if &elf[..4] != b"\x7fELF" {
                doorbell(FATAL_PORT, frame);
                halt();
            }
            let region = InitialImageRegion {
                start: carrick_guest_arch::UserVa::new(0x400000),
                len: carrick_guest_arch::GuestLen::new(4096),
                initialized_offset: carrick_guest_arch::GuestLen::new(0),
                initialized: InitialSourceRange {
                    start: carrick_guest_arch::FrameGpa::new(0x10100),
                    len: carrick_guest_arch::GuestLen::new(elf.len() as u64),
                },
                perms: EditPermissions {
                    readable: true,
                    writable: false,
                    executable: true,
                    user: true,
                },
            };
            let image = InitialImageSpec {
                regions: core::slice::from_ref(&region),
                stack: InitialStackSpec {
                    entry: 0x4000b0,
                    phdr: 0x400040,
                    phent: 56,
                    phnum: 1,
                    argv: &[b"/tiny"],
                    envp: &[],
                    random: [0x5a; 16],
                    stack_top: 0x7fff_0000,
                    stack_size: 0x4000,
                },
            };
            let Ok(source_root) = carrick_el1::isa::x86::hardware_live_root() else {
                doorbell(FATAL_PORT, frame);
                halt();
            };
            if source_root.address().raw() != 0x60_0000 {
                doorbell(FATAL_PORT, frame);
                halt();
            }
            let mut frames = if frame.rdx == 1 {
                InitialFrames {
                    next_table: 0x30_0000,
                    next_data: 0x40_0000,
                }
            } else {
                InitialFrames {
                    next_table: 0xd3_0000,
                    next_data: 0xd0_0000,
                }
            };
            // SAFETY: this stopped-carrier fixture owns the unpublished MM,
            // both disjoint zeroed frame ranges and the sole table editor.
            let loaded = unsafe {
                install_initial_image(
                    &InitialWords::fixture(),
                    &mut frames,
                    source_root,
                    core::num::NonZeroU64::MIN,
                    core::num::NonZeroU64::MIN,
                    &image,
                )
            };
            let Ok(loaded) = loaded else {
                doorbell(FATAL_PORT, frame);
                halt();
            };
            if loaded.publications.len() != 2
                || !loaded.context.authenticates(loaded.address)
                || loaded.context.frame[15] != 0x4000b0
                || loaded.context.frame[18] != loaded.stack_pointer
            {
                doorbell(FATAL_PORT, frame);
                halt();
            }
            let mut mmu = carrick_el1::isa::x86::X86Backend;
            if mmu.install_context(loaded.address).is_err() {
                doorbell(FATAL_PORT, frame);
                halt();
            }
            fixture_stmt! {
                if frame.rdx == 1
                    && !crate::process::admit_initial(binding, loaded.stack_pointer, loaded.address.root.address().raw())
                {
                    doorbell(FATAL_PORT, frame);
                    halt();
                }
            }
            frame.rcx = loaded.context.frame[15];
            frame.rsp = loaded.context.frame[18];
            frame.r11 = loaded.context.frame[17];
            frame.rax = 0;
            return;
        }
        if fixture_dispatch_enabled!() && frame.rax == 231
            && carrick_el1::isa::x86::hardware_live_root()
                .is_ok_and(|root| matches!(root.address().raw(), 0xd3_0000 | 0x30_0000))
        {
            // The stopped KVM fixture consumes exit_group as its terminal
            // observation; the production syscall owner is the shared kernel.
            doorbell(CONTROL_PORT, frame);
            return;
        }
        if fixture_dispatch_enabled!() && frame.rax == OBSERVE_MMU_ROOT {
            use carrick_guest_arch::MmuBackend;
            let mut arch = carrick_el1::isa::x86::X86Backend;
            frame.rax = arch.live_root().map_or(0, |root| root.address().raw());
            return;
        }
        if fixture_dispatch_enabled!() && frame.rax == OBSERVE_PORTAL_WINDOW {
            let root =
                carrick_el1::isa::x86::hardware_live_root().map_or(0, |root| root.address().raw());
            frame.rax = u64::from(
                carrick_el1::isa::x86::portal_root_is_live(root)
                    && !carrick_el1::isa::x86::portal_root_is_live(root + 4096),
            );
            return;
        }
        if fixture_dispatch_enabled!() && frame.rax == OBSERVE_FORK_TABLE_WINDOW {
            use carrick_el1::isa::x86::ForkDescriptorWords;
            use carrick_el1_abi::PortalForkTableArena;
            use carrick_mmu_core::x86::descriptor_txn::LiveDescriptorWords;
            let root =
                carrick_el1::isa::x86::hardware_live_root().map_or(0, |root| root.address().raw());
            let (Some(child), Some(parent)) = (
                PortalForkTableArena::new(0xd2_0000, 4096),
                PortalForkTableArena::new(0xd2_1000, 4096),
            ) else {
                frame.rax = 0;
                return;
            };
            // SAFETY: the KVM bootstrap retains the sole upper direct window
            // and both physical pages until this bounded witness completes.
            frame.rax = u64::from(
                unsafe { ForkDescriptorWords::checked(root, child, parent) }.is_ok_and(|words| {
                    words.load(child.base).is_ok()
                        && words.load(parent.base).is_ok()
                        && words.load(0xd2_2000).is_err()
                        && words.drain_succeeded()
                }),
            );
            return;
        }
        if fixture_dispatch_enabled!() && frame.rax == OBSERVE_RETIRE_REPOINT {
            use carrick_guest_arch::{
                EditBacking, EditCowAccess, EditOperation, EditPermissions, FrameGpa, GuestLen,
                UserRange, UserVa,
            };
            use carrick_mmu_core::x86::descriptor_txn::{DescriptorOutcome, DescriptorReceipt};
            let one = core::num::NonZeroU64::MIN;
            let backing = EditBacking {
                frame_id: one,
                mapping_id: one,
                owner_generation: one,
                inventory_revision: one,
            };
            let applied = |receipt: Result<DescriptorReceipt, carrick_el1::isa::ArchError>| {
                receipt
                    .is_ok_and(|value| matches!(value.outcome, DescriptorOutcome::Applied { .. }))
            };
            let Some(resident) = UserRange::checked(UserVa::new(0x3_7000), GuestLen::new(4096))
            else {
                frame.rax = 0;
                return;
            };
            if !matches!(frame.rdi, 0 | 2 | 3) {
                frame.rax = 0;
                return;
            }
            if frame.rdi == 3 {
                let retired = applied(fixture_edit(0x3_7000, one, EditOperation::Unmap));
                frame.rax = u64::from(retired);
                return;
            }
            let mapped = fixture_edit(
                0x3_7000,
                one,
                EditOperation::Prepare {
                    output: FrameGpa::new(0xd1_1000),
                    permissions: EditPermissions {
                        readable: true,
                        writable: true,
                        executable: false,
                        user: true,
                    },
                    resident,
                    backing,
                },
            );
            if frame.rdi == 2 {
                frame.rax = u64::from(applied(mapped));
                return;
            }
            let retired =
                applied(mapped) && applied(fixture_edit(0x3_7000, one, EditOperation::Unmap));
            let repointed = retired
                && applied(fixture_edit(
                    0x3_7000,
                    one,
                    EditOperation::CowRepoint {
                        old: FrameGpa::new(0xd1_1000),
                        new: FrameGpa::new(0xd1_5000),
                        backing,
                        access: EditCowAccess::RecordedPrivate,
                    },
                ));
            frame.rax = u64::from(repointed);
            return;
        }
        if fixture_dispatch_enabled!() && frame.rax == OBSERVE_MMU_DRAIN {
            use carrick_guest_arch::{
                AddressContext, ContextGeneration, FrameGpa, GuestLen, MmGeneration, MmuBackend,
                RootGpa, UserRange, UserVa,
            };
            let mut arch = carrick_el1::isa::x86::X86Backend;
            frame.rax = arch
                .live_root()
                .and_then(|_| {
                    let root = RootGpa::page_aligned(FrameGpa::new(frame.rsi))
                        .ok_or(carrick_el1::isa::ArchError::Unbound)?;
                    let context = AddressContext {
                        root,
                        mm: MmGeneration::new(core::num::NonZeroU64::MIN),
                        generation: ContextGeneration::new(core::num::NonZeroU64::MIN),
                    };
                    let range = UserRange::checked(UserVa::new(frame.rdi), GuestLen::new(4096))
                        .ok_or(carrick_el1::isa::ArchError::Unbound)?;
                    arch.request_invalidation(context, range)
                        .and_then(|ticket| arch.ack_drain(ticket))
                })
                .map_or(u64::MAX, |receipt| receipt.root().address().raw());
            return;
        }
        if fixture_dispatch_enabled!() && frame.rax == OBSERVE_DESCRIPTOR_PROTECT {
            use carrick_guest_arch::{
                EditBacking, EditOperation, EditPermissions, FrameGpa, GuestLen, UserRange, UserVa,
            };
            use carrick_mmu_core::x86::descriptor_txn::DescriptorOutcome;
            let one = core::num::NonZeroU64::MIN;
            let Some(resident) = UserRange::checked(UserVa::new(0x3_6000), GuestLen::new(4096))
            else {
                frame.rax = 0;
                return;
            };
            let prepared = fixture_edit(
                0x3_6000,
                one,
                EditOperation::Prepare {
                    output: FrameGpa::new(0xd1_6000),
                    permissions: EditPermissions {
                        readable: true,
                        writable: true,
                        executable: false,
                        user: true,
                    },
                    resident,
                    backing: EditBacking {
                        frame_id: one,
                        mapping_id: one,
                        owner_generation: one,
                        inventory_revision: one,
                    },
                },
            );
            if !matches!(prepared, Ok(receipt) if matches!(receipt.outcome, DescriptorOutcome::Applied { .. }))
            {
                frame.rax = 0;
                return;
            }
            let receipt = fixture_edit(
                0x3_6000,
                one,
                EditOperation::Protect {
                    permissions: EditPermissions {
                        readable: true,
                        writable: false,
                        executable: false,
                        user: true,
                    },
                },
            );
            frame.rax = match receipt {
                Ok(receipt) if matches!(receipt.outcome, DescriptorOutcome::Applied { .. }) => 1,
                Ok(_) => 0,
                Err(_) => {
                    doorbell(FATAL_PORT, frame);
                    halt();
                }
            };
            return;
        }
        if fixture_dispatch_enabled!() && frame.rax == OBSERVE_DESCRIPTOR_PREPARE_PUBLISH {
            use carrick_core::mm::transfer::resolver::PreparedPageResolver;
            use carrick_guest_arch::{
                EditBacking, EditLeafSize, EditOperation, EditPermissions, FrameGpa,
            };
            use carrick_mmu_core::aarch64::{GuestPreparedCommit, LeafAccess};
            use carrick_mmu_core::x86::descriptor_txn::DescriptorOutcome;
            let one = core::num::NonZeroU64::MIN;
            let backing = EditBacking {
                frame_id: one,
                mapping_id: one,
                owner_generation: one,
                inventory_revision: one,
            };
            let prepared = fixture_edit(
                0x3_2000,
                one,
                EditOperation::Map {
                    output: FrameGpa::new(0x9_0000),
                    permissions: EditPermissions {
                        readable: true,
                        writable: false,
                        executable: false,
                        user: true,
                    },
                    size: EditLeafSize::Page,
                    resident: false,
                    backing,
                },
            );
            match prepared {
                Ok(receipt) if matches!(receipt.outcome, DescriptorOutcome::Applied { .. }) => {}
                Ok(_) => {
                    frame.rax = 0;
                    return;
                }
                Err(_) => {
                    doorbell(FATAL_PORT, frame);
                    halt();
                }
            }
            // SAFETY: one fixture vCPU owns the MM and its retained table
            // alias throughout both the publication and the retry check.
            let words = InitialWords::fixture();
            let mut resolver =
                unsafe { carrick_el1::fault::X86PreparedResolver::under_editor(one, &words) };
            let published =
                resolver.commit_prepared(0x60_0000, 0x3_2000, 0x9_0000, LeafAccess::Read);
            match published {
                Ok(GuestPreparedCommit::Committed) => {}
                Err(carrick_mmu_core::aarch64::GuestPreparedCommitError::RollbackFailed) => {
                    doorbell(FATAL_PORT, frame);
                    halt();
                }
                _ => {
                    frame.rax = 0;
                    return;
                }
            }
            let retry = resolver.commit_prepared(0x60_0000, 0x3_2000, 0x9_0000, LeafAccess::Read);
            frame.rax = match retry {
                Ok(GuestPreparedCommit::AlreadyResident) => 1,
                Err(carrick_mmu_core::aarch64::GuestPreparedCommitError::RollbackFailed) => {
                    doorbell(FATAL_PORT, frame);
                    halt();
                }
                _ => 0,
            };
            return;
        }
        fixture_stmt! { if frame.rax == OBSERVE_SHARED_PREPARED_FAULT {
            use carrick_core::mm::transfer::resolver::NoopCowResolver;
            use carrick_el1::fault::{
                GrantMailboxes, PreparedFaultPath, X86PreparedResolver,
                dispatch_x86_fault_with_prepared,
            };
            use carrick_el1_abi::{Action, FrameGrantResidencyIdentity};
            use carrick_guest_arch::{
                Access, EditBacking, EditLeafSize, EditOperation, EditPermissions, FaultInfo,
                FrameGpa, UserVa,
            };
            use carrick_mmu_core::x86::descriptor_txn::DescriptorOutcome;

            let one = core::num::NonZeroU64::MIN;
            let prepared = fixture_edit(
                0x3_3000,
                one,
                EditOperation::Map {
                    output: FrameGpa::new(0x9_1000),
                    permissions: EditPermissions {
                        readable: true,
                        writable: false,
                        executable: false,
                        user: true,
                    },
                    size: EditLeafSize::Page,
                    resident: false,
                    backing: EditBacking {
                        frame_id: one,
                        mapping_id: one,
                        owner_generation: one,
                        inventory_revision: one,
                    },
                },
            );
            if !matches!(
                prepared,
                Ok(receipt) if matches!(receipt.outcome, DescriptorOutcome::Applied { .. })
            ) {
                doorbell(FATAL_PORT, frame);
                halt();
            }
            // SAFETY: the lifecycle KVM carrier retains these exact records
            // for this vCPU through the native entry and fault settlement.
            let task = unsafe { &*(binding.task_address as *const CurrentTask) };
            let zone = unsafe {
                &*(super::lifecycle::LIFECYCLE_ZONE as *const carrick_sched_core::ZoneTables)
            };
            let mm = task.mm.key.load(Ordering::Acquire);
            let Some(mm_key) = core::num::NonZeroU64::new(mm) else {
                doorbell(FATAL_PORT, frame);
                halt();
            };
            let layout = core::alloc::Layout::new::<carrick_el1_abi::FrameGrantResidencyTable>();
            // SAFETY: the global allocator returns an aligned block of this layout;
            // this fixture owns it exclusively until deallocated below.
            let ptr = unsafe { crate::rust_alloc::alloc::alloc(layout) };
            if ptr.is_null() {
                doorbell(FATAL_PORT, frame);
                halt();
            }
            // SAFETY: ptr is non-null, aligned and valid for FrameGrantResidencyTable.
            let residency = unsafe {
                let table_ptr = ptr.cast::<carrick_el1_abi::FrameGrantResidencyTable>();
                carrick_el1_abi::FrameGrantResidencyTable::init_in_place(table_ptr);
                &*table_ptr
            };
            if residency
                .publish(FrameGrantResidencyIdentity {
                    mm_key: mm,
                    semantic_base: 0x3_3000,
                    physical_ipa: 0x9_1000,
                    len: 4096,
                    mapping_id: 1,
                    frame_id: 1,
                    owner_generation: 1,
                    inventory_revision: 1,
                })
                .is_none()
            {
                doorbell(FATAL_PORT, frame);
                halt();
            }
            // SAFETY: the shared dispatcher acquires this MM's exact editor
            // before invoking the resolver, and the upper direct table window lives
            // for the whole KVM fixture.
            let words = InitialWords::fixture();
            let mut resolver = unsafe { X86PreparedResolver::under_editor(mm_key, &words) };
            // SAFETY: KVM retains this counter record for the bound vCPU.
            let counters = unsafe { &*(binding.counters_address as *const Counters) };
            let action = dispatch_x86_fault_with_prepared(
                carrick_guest_arch::CpuId::new(0),
                FaultInfo {
                    address: UserVa::new(0x3_3000),
                    access: Access::Read,
                    present: false,
                },
                counters,
                task,
                carrick_el1::substrate::sched::object_wait::space_access(
                    zone,
                    carrick_sched_core::SlotId::new(0),
                ),
                GrantMailboxes::own(&SHARED_FAULT_MAILBOX),
                Some(PreparedFaultPath::<_> {
                    residency,
                    resolver: &mut resolver,
                    roots: None,
                    file_slots: None,
                }),
                &mut NoopCowResolver,
            );
            frame.rax =
                u64::from(action == Action::Served && residency.is_guest_committed(mm, 0x3_3000));
            // SAFETY: ptr was returned for layout and has not escaped.
            unsafe { crate::rust_alloc::alloc::dealloc(ptr, layout) };
            return;
        }
        }
        fixture_stmt! { if frame.rax == OBSERVE_SHARED_COW_FAULT {
            use carrick_core::mm::transfer::resolver::NoopPreparedResolver;
            use carrick_el1::fault::{
                GrantMailboxes, X86CowResolver, dispatch_x86_fault_with_prepared,
            };
            use carrick_el1_abi::{Action, FrameGrantResidencyIdentity};
            use carrick_guest_arch::{
                Access, EditBacking, EditOperation, EditPermissions, FaultInfo, FrameGpa, GuestLen,
                UserVa,
            };
            use carrick_mmu_core::x86::descriptor_txn::{BackingIdentity, DescriptorOutcome};

            let one = core::num::NonZeroU64::MIN;
            let backing = BackingIdentity {
                frame_id: one,
                mapping_id: one,
                owner_generation: one,
                inventory_revision: one,
            };
            let map = fixture_edit(
                0x3_4000,
                one,
                EditOperation::Map {
                    output: FrameGpa::new(0xd1_1000),
                    permissions: EditPermissions {
                        readable: true,
                        writable: true,
                        executable: false,
                        user: true,
                    },
                    size: carrick_guest_arch::EditLeafSize::Page,
                    resident: true,
                    backing: EditBacking {
                        frame_id: one,
                        mapping_id: one,
                        owner_generation: one,
                        inventory_revision: one,
                    },
                },
            );
            let arm = fixture_edit(
                0x3_4000,
                core::num::NonZeroU64::new(2).unwrap_or(one),
                EditOperation::ArmCow {
                    kernel_only: false,
                    executable: false,
                    adopt_private: false,
                    asid_scoped: false,
                    excluded_ipa: FrameGpa::new(0),
                    excluded_len: GuestLen::new(0),
                },
            );
            if !matches!(map, Ok(receipt) if matches!(receipt.outcome, DescriptorOutcome::Applied { .. }))
                || !matches!(arm, Ok(receipt) if matches!(receipt.outcome, DescriptorOutcome::Applied { .. }))
            {
                doorbell(FATAL_PORT, frame);
                halt();
            }
            // SAFETY: the bootstrap direct window maps both retained frame
            // pages and this fixture excludes the sibling vCPU.
            unsafe {
                ((DIRECT_VA + 0xd1_1000) as *mut u8).write_volatile(0x5a);
                ((DIRECT_VA + 0xd1_5000) as *mut u8).write_volatile(0);
            }
            // SAFETY: the lifecycle carrier keeps task and zone records live.
            let task = unsafe { &*(binding.task_address as *const CurrentTask) };
            let zone = unsafe {
                &*(super::lifecycle::LIFECYCLE_ZONE as *const carrick_sched_core::ZoneTables)
            };
            let mm = task.mm.key.load(Ordering::Acquire);
            let layout = core::alloc::Layout::new::<carrick_el1_abi::FrameGrantResidencyTable>();
            // SAFETY: the allocation has this table's alignment and size and
            // remains owned by the fixture until the resolver returns.
            let ptr = unsafe { crate::rust_alloc::alloc::alloc(layout) };
            if ptr.is_null() {
                doorbell(FATAL_PORT, frame);
                halt();
            }
            // SAFETY: ptr is aligned, writable storage for the whole table.
            let residency = unsafe {
                let table = ptr.cast::<carrick_el1_abi::FrameGrantResidencyTable>();
                carrick_el1_abi::FrameGrantResidencyTable::init_in_place(table);
                &*table
            };
            let Some(old_slot) = residency.publish(FrameGrantResidencyIdentity {
                mm_key: mm,
                semantic_base: 0x3_4000,
                physical_ipa: 0xd1_1000,
                len: 4096,
                mapping_id: 1,
                frame_id: 1,
                owner_generation: 1,
                inventory_revision: 1,
            }) else {
                doorbell(FATAL_PORT, frame);
                halt();
            };
            let _ = old_slot;
            let Some(old_page) = residency.lookup(mm, 0x3_4000) else {
                doorbell(FATAL_PORT, frame);
                halt();
            };
            if !residency.record_commit(old_page)
                || SHARED_COW_POOL.publish(mm, 0xd1_4000, backing).is_none()
            {
                doorbell(FATAL_PORT, frame);
                halt();
            }
            let words = InitialWords::fixture();
            let mut cow = X86CowResolver {
                words: &words,
                pool: &SHARED_COW_POOL,
                residency,
                completion: None,
            };
            // SAFETY: this bound vCPU owns the counter record for its lifetime.
            let counters = unsafe { &*(binding.counters_address as *const Counters) };
            let action = dispatch_x86_fault_with_prepared(
                carrick_guest_arch::CpuId::new(0),
                FaultInfo {
                    address: UserVa::new(0x3_4000),
                    access: Access::Write,
                    present: true,
                },
                counters,
                task,
                carrick_el1::substrate::sched::object_wait::space_access(
                    zone,
                    carrick_sched_core::SlotId::new(0),
                ),
                GrantMailboxes::own(&SHARED_FAULT_MAILBOX),
                None::<carrick_el1::fault::PreparedFaultPath<'_, NoopPreparedResolver>>,
                &mut cow,
            );
            // SAFETY: both pages remain mapped in the supervisor direct window.
            let copied = unsafe {
                ((DIRECT_VA + 0xd1_1000) as *const u8).read_volatile() == 0x5a
                    && ((DIRECT_VA + 0xd1_5000) as *const u8).read_volatile() == 0x5a
            };
            frame.rax = u64::from(
                action == Action::Served
                    && copied
                    && residency.is_guest_committed(mm, 0x3_4000)
                    && cow.completion.is_some(),
            );
            // SAFETY: the fixture's table is no longer borrowed and ptr came
            // from this exact allocation layout.
            unsafe { crate::rust_alloc::alloc::dealloc(ptr, layout) };
            return;
        }
        }
        if fixture_dispatch_enabled!() && frame.rax == OBSERVE_ALLOCATOR {
            let layout = match core::alloc::Layout::from_size_align(128, 64) {
                Ok(layout) => layout,
                Err(_) => {
                    frame.rax = 0;
                    return;
                }
            };
            // SAFETY: the global allocator returns a block of this layout;
            // this fixture owns it exclusively until the matching dealloc.
            let ptr = core::hint::black_box(unsafe { crate::rust_alloc::alloc::alloc(layout) });
            if ptr.is_null() {
                frame.rax = 0;
                return;
            }
            // SAFETY: byte 127 is inside this exclusively owned allocation.
            unsafe { core::ptr::write_volatile(ptr.add(127), 0xa5) };
            // SAFETY: the same byte remains allocated until dealloc below.
            let valid = (ptr as usize & 63) == 0
                && (ptr as u64)
                    .checked_sub(carrick_el1_abi::X86_CPL0_BOOTSTRAP_METADATA_BASE)
                    .is_some_and(|offset| offset < carrick_el1_abi::EL1_BOOTSTRAP_METADATA_SIZE)
                && unsafe { core::ptr::read_volatile(ptr.add(127)) } == 0xa5;
            // SAFETY: ptr was returned for layout and has not escaped.
            unsafe { crate::rust_alloc::alloc::dealloc(ptr, layout) };
            frame.rax = u64::from(valid);
            return;
        }
        // SAFETY: bootstrap retains these supervisor-only records until the
        // VM/vCPUs retire; each binding names its issued current task.
        let task = unsafe { &*(binding.task_address as *const CurrentTask) };
        let counters = unsafe { &*(binding.counters_address as *const Counters) };
        let _user_fault_gate = super::user_fault_gate::install();
        if fixture_dispatch_enabled!()
            && frame.rax == carrick_el1::isa::x86::user_access::USER_ACCESS_WITNESS {
            frame.rax = carrick_el1::isa::x86::user_access::witness(task, frame.rdi, frame.rsi);
            return;
        }
        if fixture_dispatch_enabled!()
            && frame.rax == OBSERVE_CPL0_UACCESS_SHOOTDOWN
        {
            let address = frame.rdi;
            let word1 = carrick_el1::isa::x86::user_access::witness(task, address, 6);
            if word1 as i64 == -14 {
                frame.rax = 0xdead;
                return;
            }
            frame.rbx = word1;
            doorbell(FORWARD_PORT, frame);
            let word2 = carrick_el1::isa::x86::user_access::witness(task, address, 6);
            frame.rax = word2;
            doorbell(FORWARD_PORT, frame);
            return;
        }
        if fixture_dispatch_enabled!()
            && frame.rax == carrick_el1::isa::x86::transport::TRANSPORT_WITNESS {
            frame.rax = carrick_el1::isa::x86::transport::witness(frame.rdi);
            return;
        }
        if fixture_dispatch_enabled!()
            && frame.rax == carrick_el1::isa::x86::context::CONTEXT_WITNESS {
            frame.rax = carrick_el1::isa::x86::context::witness(frame.rdi);
            return;
        }
        if fixture_dispatch_enabled!()
            && frame.rax == carrick_el1::isa::x86::interrupt::INTERRUPT_WITNESS {
            frame.rax = carrick_el1::isa::x86::interrupt::witness(frame.rdi, frame.rsi);
            return;
        }
        binding.entries.fetch_add(1, Ordering::Relaxed);
        fixture_stmt! { if binding.scheduler_witness.load(Ordering::Acquire)
            == super::scheduler::PROGRESS_STATE {
            super::progress::entry_boundary();
        } }
        if binding.entry_kick.swap(0, Ordering::AcqRel) != 0 {
            doorbell(ENTRY_KICK_PORT, frame);
        }
        let Some(call) = carrick_personality_linux::entry::decode_x86_snapshot(frame.snapshot())
        else {
            evaluate_host_crossing(
                HostCrossingSet::X86,
                true,
                None,
                None,
                Some(&counters.refused),
                |ret| frame.rax = ret.raw() as u64,
            );
            binding.completions.fetch_add(1, Ordering::Relaxed);
            fixture_stmt! { if binding.scheduler_witness.load(Ordering::Acquire)
                == super::scheduler::PROGRESS_STATE {
                super::progress::return_boundary();
            } }
            if binding.return_kick.swap(0, Ordering::AcqRel) != 0 {
                doorbell(RETURN_KICK_PORT, frame);
            }
            if task.linux.has_pending_host_work() {
                task.linux.record_completed_with_work();
                doorbell(WORK_PORT, frame);
            }
            return;
        };
        binding
            .captured_stack
            .store(call.stack.raw(), Ordering::Release);
        let handled_by_fixture = fixture_expr!(crate::fixture_handled(frame, binding, task, counters, &call));
        if !handled_by_fixture {
            use carrick_personality_linux::dispatch::CompletionRoute;
            let layout = <carrick_el1::isa::x86::X86Backend as LayoutBackend>::KERNEL_LAYOUT;
            let cache_lookup = |handle: u32| {
                handle.checked_sub(1).and_then(|index| {
                    u64::from(index).checked_mul(carrick_el1_abi::DELEGATED_FILE_MAX_SIZE)
                }).and_then(|offset| {
                    layout.region.raw().checked_add(carrick_el1_abi::EL1_CACHE_OFFSET)?.checked_add(offset)
                }).map_or(core::ptr::null_mut(), |address| address as *mut u8)
            };
            let mut root_exit = None;
            let route = if fixture_dispatch_enabled!() {
                let mut native = NativeDispatch {
                    frame, call, publications: &binding.publications,
                    slot: carrick_guest_arch::SlotId::from_index(binding.cpu_slot as usize),
                };
                match carrick_x86_cpl0::production_boundary(dispatch::dispatch_syscall_with_lifecycle(
                    &mut native, counters, core::slice::from_ref(task),
                    &[], &[], &[], &[], &EMPTY_NAME_CACHE,
                    None::<dispatch::Zone<'_, sched::HardwareCpu, sched::HardwareUserWord>>,
                    None, Some(&GuestLifecycleVenue), None, cache_lookup,
                )) {
                    ProductionBoundary::Continue => CompletionRoute::Served,
                    ProductionBoundary::Work => CompletionRoute::WithWork,
                    ProductionBoundary::Forward => CompletionRoute::Forward,
                    ProductionBoundary::Invalid => CompletionRoute::InvalidCompletion,
                }
            } else {
                let mut anonymous = anonymous::X86AnonymousVenue::new(&call, task, binding.cpu_slot, frame.rcx);
                let slot = checked_scheduler_slot(carrick_guest_arch::CpuId::new(binding.cpu_slot))
                    .unwrap_or_else(|| initial_boot::fatal_boot());
                let source = native_execution::source(slot);
                let words = native_execution::capture(frame, _early_xstate);
                native_process::admit_root(words, source, task)
                    .unwrap_or_else(|_| initial_boot::fatal_boot());
                let mut service = native_process::Service::new(task, slot);
                let route = {
                    let (runtime, address) = native_process::runtime(source, task)
                        .unwrap_or_else(|_| initial_boot::fatal_boot());
                    let mut process = runtime.enter_registered(
                        native_process::registry(), source, task, address, rust_alloc::boxed::Box::new(words), &mut service,
                    )
                        .unwrap_or_else(|_| initial_boot::fatal_boot());
                    let mut native = NativeDispatch {
                        frame, call, publications: &binding.publications,
                        slot: carrick_guest_arch::SlotId::from_index(binding.cpu_slot as usize),
                    };
                    let route = dispatch::dispatch_syscall_with_native(
                        &mut native, counters, core::slice::from_ref(task),
                        &[], &[], &[], &[], &EMPTY_NAME_CACHE,
                        None::<dispatch::Zone<'_, sched::HardwareCpu, sched::HardwareUserWord>>,
                        None, Some(&GuestLifecycleVenue), Some(&mut *process),
                        Some(source), Some(&mut anonymous), cache_lookup,
                    );
                    root_exit = process.take_root_exit();
                    route
                };
                native_execution::migrate(slot);
                route
            };
            match route {
                CompletionRoute::Served => {}
                CompletionRoute::WithWork => doorbell(WORK_PORT, frame),
                CompletionRoute::Suspended => {
                    drop(_user_fault_gate);
                    if let Some(status) = root_exit {
                        let exit = carrick_el1_abi::NativeRootExit::new(
                            carrick_el1::personality::common_entry::execution_binding(task), status,
                        ).unwrap_or_else(|| initial_boot::fatal_boot());
                        // SAFETY: shared retirement authenticated this physical VM completion.
                        unsafe {
                            core::arch::asm!("out dx, al",
                                in("dx") carrick_el1_abi::NATIVE_ROOT_EXIT_PORT,
                                in("rax") &exit as *const _ as u64,
                                options(nostack, preserves_flags));
                        }
                        halt();
                    }
                    let slot = checked_scheduler_slot(carrick_guest_arch::CpuId::new(binding.cpu_slot))
                        .unwrap_or_else(|| initial_boot::fatal_boot());
                    native_execution::schedule(slot);
                }
                CompletionRoute::InvalidCompletion => {
                    doorbell(FATAL_PORT, frame); halt();
                }
                // The shared Linux completion owner already admitted an unported
                // crossing, or preserved a family fallback/handback transport.
                CompletionRoute::Forward => doorbell(FORWARD_PORT, frame),
            }
        }
        binding.completions.fetch_add(1, Ordering::Relaxed);
        fixture_stmt! { if binding.scheduler_witness.load(Ordering::Acquire)
            == super::scheduler::PROGRESS_STATE {
            super::progress::return_boundary();
        } }
        if binding.return_kick.swap(0, Ordering::AcqRel) != 0 {
            doorbell(RETURN_KICK_PORT, frame);
        }
        if task.linux.has_pending_host_work() {
            task.linux.record_completed_with_work();
            doorbell(WORK_PORT, frame);
        }
    }

    #[unsafe(no_mangle)]
    extern "C" fn carrick_x86_validate_return(frame: &mut NativeFrame) {
        if !frame.valid_user_return() {
            doorbell(FATAL_PORT, frame);
            halt();
        }
        if carrick_el1::isa::x86::interrupt::check_user_return_generation().is_err() {
            doorbell(FATAL_PORT, frame);
            halt();
        }
    }

    pub fn halt() -> ! {
        loop {
            // SAFETY: terminal CPL0 fatal path, never returns to user.
            unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
        }
    }
}

// The production macro removes every fixture state access; this image seam
// returns immediately there. Only the fixture image carries ordering holds.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub extern "Rust" fn carrick_fixture_hold_check(
    _table: &carrick_el1::isa::x86::context::native::ShootdownTable,
    _target_mode: u32,
) -> Result<(), carrick_el1::isa::ArchError> {
    fixture_stmt! {
        if _table.fixture_hold_ipi.load(core::sync::atomic::Ordering::Acquire) == _target_mode {
            // SAFETY: this fixture owns the identity-mapped control data page.
            // Release its running reader only after the edit reached this hold.
            unsafe { core::ptr::write_volatile(0x4_0008 as *mut u8, 1); }
            let Some(tsc_hz) = carrick_el1::isa::x86::interrupt::tsc_frequency() else {
                return Err(carrick_el1::isa::ArchError::Unbound);
            };
            let Some(limit) = tsc_hz.get().checked_mul(5) else {
                return Err(carrick_el1::isa::ArchError::Unbound);
            };
            let start = carrick_el1::isa::x86::interrupt::read_tsc();
            while _table.fixture_hold_ipi.load(core::sync::atomic::Ordering::Acquire) == _target_mode {
                if carrick_el1::isa::x86::interrupt::read_tsc().wrapping_sub(start) > limit {
                    return Err(carrick_el1::isa::ArchError::Busy);
                }
                core::hint::spin_loop();
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    kernel::halt()
}
