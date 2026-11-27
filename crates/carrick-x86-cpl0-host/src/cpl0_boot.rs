//! Shared CPL0 carrier and its retained guest-MM/metadata backing.
//! Hardware fixtures and the initial production process use the same image;
//! fixture observation ports remain separate from the production transport.
use crate::carrier_cpu::{CarrierChildBindings, FixtureWatchdog};
use crate::carrier_cpu::{
    CarrierCpu, CarrierCpuDebug, CarrierCpuIo, CarrierRootBinding, CarrierRunExit,
};
use crate::carrier_memory::{
    BackingExtent, BackingHandle, CarrierMemory, CarrierMemoryIo, InventoryTransaction,
    PreparedBacking,
};
use crate::guest_ram::{GuestRam, WindowKind};
use carrick_core_abi::{X86_CPL0_INITIAL_EXTENT_GPA, X86_CPL0_INITIAL_EXTENT_MAX_SIZE};
use carrick_core_abi::{
    X86_CPL0_INITIAL_EXTENT_VA, X86_INITIAL_BOOT_HEADER_GPA, X86_INITIAL_BOOT_MAGIC,
    X86_INITIAL_BOOT_VERSION, X86InitialBootHeader,
};
use carrick_core_abi::{
    X86_INITIAL_BOOT_LOADED, X86_INITIAL_BOOT_PORT, X86_INITIAL_MAX_REGIONS,
    X86_INITIAL_MAX_STRINGS, X86_INITIAL_RUNNER_READY_PORT, X86InitialBootGrant,
    X86InitialBootRegion, X86InitialBootRequest, X86InitialBootString,
};
use carrick_el1::memory::reservations::{
    LinuxReservationLayout, NoRootWait, X86Cpl0Reservations, X86Cpl0RootReleaseVenue, X86Cpl0Zone,
};
use carrick_el1_abi::GuestMmuPublication;
use carrick_el1_abi::{BlockedMask, Lifecycle};
use carrick_el1_abi::{
    Counters, CurrentTask, EL1_BOOTSTRAP_METADATA_SIZE, El1TaskId, ThreadControlSlot,
    ThreadLifecyclePage, X86_CPL0_BOOTSTRAP_METADATA_BASE, X86_CPL0_DYNAMIC_METADATA_BASE,
    X86_CPL0_REGION_BASE,
};
use carrick_el1_abi::{ReservationMm, ReservationRange};
use carrick_guest_arch::FrameGpa;
use carrick_guest_arch::{AddressContext, ContextGeneration, MmGeneration, RootGpa, UserVa};
use carrick_guest_mem::{CurrentMmMemory, GuestMemory, MemoryError};
use carrick_hal::{FrameCowAuthority, PhysicalFrameInventory};
#[cfg(test)]
use carrick_hal::{FrameEventCapacity, FrameInventoryEvent, MemPerms};
use carrick_hal::{FrameId, FrameLength, MappingGeneration, MappingId};
use carrick_hal::{TrapError, VcpuExit};
#[cfg(test)]
use carrick_kernel::kernel::{FrameInventoryAuthority, MmId, ObjectIdRegistry};
use carrick_mem::pml4::{Pml4MapSpec, pml4_tables};
use carrick_mmu_core::x86::descriptor_txn::{
    Access, BackingIdentity, DescriptorOp, DescriptorTxn, DescriptorTxnId, PageSpan, Permissions,
    translate_leaf,
};
use carrick_sched_core::spaces::notification::{SpaceAccess, SpaceReleaseVenue};
use carrick_sched_core::{SlotId, Waker};
use carrick_x86::cpl0_entry::*;
use carrick_x86::{BringupLayout, X86Reg};
use std::num::NonZeroU64;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock, RwLockWriteGuard};

pub mod boot_cpu {
    //! Desired stopped-CPU policy; backend observation and admission stay in KVM.
    use super::*;
    use carrick_hal::x8664_arch::X8664BootSysregs;
    use carrick_x86::{SegmentDescriptor, X86Vcpu};

    /// Values layered on the existing shared long-mode and fault-segment helpers.
    /// This is boot policy, not a running CPU snapshot or an execution capability.
    pub struct BootCpuState {
        cpu: carrick_guest_arch::CpuId,
        pub layout: BringupLayout,
        pub rip: u64,
        pub rsp: u64,
        pub fixture_rflags: Option<u64>,
        pub cr4_required: u64,
        pub cpuid_leaf7_required: u32,
        pub gdt_base: u64,
        pub idt_base: u64,
        pub tr: SegmentDescriptor,
        pub apic_base: Option<u64>,
        pub lstar: u64,
        pub star: u64,
        pub sfmask: u64,
        pub kernel_gs_base: u64,
    }

    impl BootCpuState {
        pub fn new(
            entry: u64,
            boot: &X8664BootSysregs,
            cpu: carrick_guest_arch::CpuId,
            hardware_interrupts: bool,
            production: bool,
        ) -> Result<Self, TrapError> {
            let slot = u64::from(cpu.raw());
            let mut layout = LAYOUT;
            layout.trampoline_base = entry;
            Ok(Self {
                cpu,
                layout,
                rip: USER_CODE + slot * 4096,
                rsp: 0x3_1ff0 + slot * 0x1_0000,
                fixture_rflags: (hardware_interrupts && !production)
                    .then_some(boot.rflags | (1 << 9)),
                cpuid_leaf7_required: if production { (1 << 7) | (1 << 20) } else { 0 },
                cr4_required: if production { (1 << 20) | (1 << 21) } else { 0 },
                gdt_base: DIRECT_VA + LAYOUT.gdt_base,
                idt_base: DIRECT_VA
                    + carrick_x86::fault_slot_gpa(carrick_x86::fault_idt_base(LAYOUT), slot)?,
                tr: SegmentDescriptor::tss64_busy(
                    DIRECT_VA
                        + carrick_x86::fault_slot_gpa(carrick_x86::fault_tss_base(LAYOUT), slot)?,
                ),
                apic_base: hardware_interrupts.then_some(
                    carrick_x86::interrupts::LAPIC_BASE | 0x800 | if slot == 0 { 0x100 } else { 0 },
                ),
                lstar: entry,
                star: boot.star,
                sfmask: boot.sfmask | (1 << 10) | (1 << 8) | (1 << 18),
                kernel_gs_base: METADATA_VA + BINDING_OFFSET + slot * STRIDE,
            })
        }

        /// Keep the original helper/setter order, including slot-zero bootstrap.
        pub fn program_entry<C: X86Vcpu>(&self, cpu: &mut C) -> Result<(), TrapError> {
            carrick_x86::program_longmode_entry(cpu, self.layout, self.rip, self.rsp)?;
            if let Some(flags) = self.fixture_rflags {
                cpu.set_gpr(X86Reg::Rflags, flags)?;
            }
            carrick_x86::program_fault_segments(cpu, LAYOUT, u64::from(self.cpu.raw()))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use carrick_hal::guest_arch::GuestArch;
        use carrick_hal::x8664_arch::X8664GuestArch;
        use carrick_x86::{GuestSegment, MsrInstall, X86Seg};

        #[derive(Default)]
        struct RecordingVcpu {
            gprs: Vec<(X86Reg, u64)>,
            segments: Vec<(X86Seg, GuestSegment)>,
        }
        impl X86Vcpu for RecordingVcpu {
            fn get_gpr(&self, _r: X86Reg) -> Result<u64, TrapError> {
                Ok(0)
            }
            fn set_gpr(&mut self, r: X86Reg, v: u64) -> Result<(), TrapError> {
                self.gprs.push((r, v));
                Ok(())
            }
            fn set_segment(
                &mut self,
                seg: X86Seg,
                descriptor: carrick_x86::SegmentDescriptor,
            ) -> Result<(), TrapError> {
                self.segments.push((seg, descriptor.into()));
                Ok(())
            }
            fn get_fs_base(&self) -> Result<u64, TrapError> {
                Ok(0)
            }
            fn set_fs_base(&mut self, _v: u64) -> Result<(), TrapError> {
                Ok(())
            }
            fn get_gs_base(&self) -> Result<u64, TrapError> {
                Ok(0)
            }
            fn set_gs_base(&mut self, _v: u64) -> Result<(), TrapError> {
                Ok(())
            }
            fn set_syscall_msrs(
                &mut self,
                _l: u64,
                _s: u64,
                _m: u64,
            ) -> Result<MsrInstall, TrapError> {
                Ok(MsrInstall::Direct)
            }
            fn get_fp(&self) -> Result<Option<[u8; 512]>, TrapError> {
                Ok(None)
            }
            fn set_fp(&mut self, _fx: &[u8; 512]) -> Result<bool, TrapError> {
                Ok(true)
            }
            fn run(&mut self) -> Result<carrick_x86::X86Exit, TrapError> {
                Err(TrapError::Hypervisor(
                    "RecordingVcpu::run unused".to_owned(),
                ))
            }
            fn enable_halt_exit(&mut self) -> Result<(), TrapError> {
                Ok(())
            }
        }

        #[test]
        fn boot_cpu_state_has_exact_values() {
            let boot = X8664GuestArch::bootstrap_sysregs();
            for production in [false, true] {
                for interrupts in [false, true] {
                    for slot in 0..2 {
                        // CPUID policy stays in the existing shared view; IDs are
                        // explicit backend observations, never inferred from slot.
                        let view = carrick_x86::cpuid::GuestCpuidView::x86_64_v3().with_apic_id(37);
                        assert_eq!(view.cpuid(1, 0).ebx >> 24, 37);
                        assert_eq!(
                            view.cpuid(7, 0).ebx & ((1 << 7) | (1 << 20)),
                            (1 << 7) | (1 << 20)
                        );
                        let state = BootCpuState::new(
                            0x12345000,
                            &boot,
                            carrick_guest_arch::CpuId::new(slot as u32),
                            interrupts,
                            production,
                        )
                        .unwrap();
                        assert_eq!(state.layout.trampoline_base, 0x12345000);
                        assert_eq!(state.rip, USER_CODE + slot * 4096);
                        assert_eq!(state.rsp, 0x31ff0 + slot * 0x10000);
                        assert_eq!(
                            state.fixture_rflags,
                            if interrupts && !production {
                                Some(0x202)
                            } else {
                                None
                            }
                        );
                        assert_eq!(
                            state.cpuid_leaf7_required,
                            if production { 0x100080 } else { 0 }
                        );
                        assert_eq!(state.cr4_required, if production { 0x300000 } else { 0 });
                        assert_eq!(state.gdt_base, DIRECT_VA + LAYOUT.gdt_base);
                        assert_eq!(
                            state.idt_base,
                            DIRECT_VA + carrick_x86::fault_idt_base(LAYOUT) + slot * 4096
                        );
                        assert_eq!(
                            state.tr.base(),
                            DIRECT_VA + carrick_x86::fault_tss_base(LAYOUT) + slot * 4096
                        );
                        assert_eq!(state.tr.limit(), 0x67);
                        assert_eq!(state.tr.access_rights(), 0x8b);
                        assert_eq!(
                            state.apic_base,
                            if interrupts {
                                Some(0xfee00800 | if slot == 0 { 0x100 } else { 0 })
                            } else {
                                None
                            }
                        );
                        assert_eq!(state.lstar, 0x12345000);
                        assert_eq!(state.star, boot.star);
                        assert_eq!(state.sfmask, boot.sfmask | 0x40500);
                        assert_eq!(
                            state.kernel_gs_base,
                            METADATA_VA + BINDING_OFFSET + slot * STRIDE
                        );
                        let mut cpu = RecordingVcpu::default();
                        state.program_entry(&mut cpu).unwrap();
                        let reg = |r| cpu.gprs.iter().rev().find(|(key, _)| *key == r).unwrap().1;
                        assert_eq!(reg(X86Reg::Cr0), 0x80010033);
                        assert_eq!(reg(X86Reg::Cr3), LAYOUT.pml4_base);
                        assert_eq!(reg(X86Reg::Cr4), boot.cr4);
                        assert_eq!(reg(X86Reg::Efer), boot.efer);
                        assert_eq!(reg(X86Reg::Rip), state.rip);
                        assert_eq!(reg(X86Reg::Rsp), state.rsp);
                        let seg = |r| {
                            cpu.segments
                                .iter()
                                .rev()
                                .find(|(key, _)| *key == r)
                                .unwrap()
                                .1
                        };
                        let cs = seg(X86Seg::Cs);
                        assert_eq!(cs.selector, 0x23);
                        assert_eq!(cs.limit, 0xffffffff);
                        assert_eq!(seg(X86Seg::Ss).selector, 0x1b);
                        assert_eq!(seg(X86Seg::Gdtr).base, LAYOUT.gdt_base);
                        assert_eq!(seg(X86Seg::Gdtr).limit, 39);
                        assert_eq!(seg(X86Seg::Idtr).limit, 4095);
                    }
                }
            }
        }
    }
}
pub use boot_cpu::BootCpuState;

/// Initialize the stopped carrier's GDT, fault stubs, private IDT/TSS/IST and
/// native IRQ gates in retained RAM, before registration or guest execution.
/// Both backends must use these exact descriptor bytes and supervisor aliases.
pub fn initialize_bootstrap_descriptors(
    ram: &mut GuestRam,
    boot: &carrick_hal::x8664_arch::X8664BootSysregs,
    hardware_interrupts: bool,
) -> Result<(), TrapError> {
    let gdt: Vec<u8> = boot
        .gdt
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    ram.write_gpa(LAYOUT.gdt_base, &gdt)
        .map_err(|e| fail(e.to_string()))?;
    carrick_x86::write_fault_tables_with(LAYOUT, |gpa, bytes| {
        ram.write_gpa(gpa, bytes).map_err(|e| fail(e.to_string()))
    })?;
    // Intel SDM vol. 3: 64-bit TSS IST1 occupies bytes 36..44; the IDT
    // gate's byte 4 selects IST1. Keep double faults off the syscall stack.
    // Reuse the existing descriptors/stubs rather than build another IDT.
    for index in 0..2 {
        let tss = carrick_x86::fault_slot_gpa(carrick_x86::fault_tss_base(LAYOUT), index)?;
        let fault_stack =
            carrick_x86::fault_slot_gpa(carrick_x86::fault_stack_base(LAYOUT), index)?;
        ram.write_gpa(tss + 4, &(DIRECT_VA + fault_stack + 4096).to_le_bytes())
            .map_err(|e| fail(e.to_string()))?;
        // The one-page IST1 (#DF) stacks sit back to back with no guard
        // (#369 guards the kernel stacks): the #DF handler's frame is
        // fixed and small, so it cannot reach the next CPU's page.
        let ist_top = DIRECT_VA + IST_STACK_BASE + (index + 1) * 4096;
        ram.write_gpa(tss + 36, &ist_top.to_le_bytes())
            .map_err(|e| fail(e.to_string()))?;
        let idt = carrick_x86::fault_slot_gpa(carrick_x86::fault_idt_base(LAYOUT), index)?;
        ram.write_gpa(idt + 8 * 16 + 4, &[1])
            .map_err(|e| fail(e.to_string()))?;
        for vector in 0..256_u64 {
            let gate_gpa = idt + vector * 16;
            let ptr = ram
                .host_ptr(gate_gpa, 16)
                .ok_or_else(|| fail("IDT gate backing"))?;
            // SAFETY: bootstrap owns retained, initialized IDT backing and
            // no vCPU can read it before publication completes.
            let gate = unsafe { core::slice::from_raw_parts(ptr, 16) };
            if gate[5] & 0x80 == 0 {
                continue;
            }
            let low = u16::from_le_bytes([gate[0], gate[1]]) as u64;
            let mid = u16::from_le_bytes([gate[6], gate[7]]) as u64;
            let high = u32::from_le_bytes([gate[8], gate[9], gate[10], gate[11]]) as u64;
            let entry = DIRECT_VA + low + (mid << 16) + (high << 32);
            ram.write_gpa(gate_gpa, &(entry as u16).to_le_bytes())
                .map_err(|e| fail(e.to_string()))?;
            ram.write_gpa(gate_gpa + 6, &((entry >> 16) as u16).to_le_bytes())
                .map_err(|e| fail(e.to_string()))?;
            ram.write_gpa(gate_gpa + 8, &((entry >> 32) as u32).to_le_bytes())
                .map_err(|e| fail(e.to_string()))?;
        }
    }
    if hardware_interrupts {
        use carrick_x86::interrupts::{
            IRQ_HEADER_GPA, IRQ_HEADER_MAGIC, KICK_VECTOR, PAGE_FAULT_VECTOR, RESCHED_VECTOR,
            SHOOTDOWN_VECTOR, TIMER_VECTOR,
        };
        let header = ram
            .read(IRQ_HEADER_GPA, 6 * size_of::<u64>())
            .map_err(|error| fail(format!("native IRQ header: {error}")))?;
        let mut words = [0_u64; 6];
        for (word, bytes) in words.iter_mut().zip(header.chunks_exact(8)) {
            *word = u64::from_le_bytes(
                bytes
                    .try_into()
                    .map_err(|_| fail("native IRQ header width"))?,
            );
        }
        if words[0] != IRQ_HEADER_MAGIC
            || words[1..]
                .iter()
                .any(|pc| !(IMAGE_VA..IMAGE_VA + IMAGE_SIZE).contains(pc))
        {
            return Err(fail("native IRQ header or entry outside image"));
        }
        for index in 0..2 {
            let idt = carrick_x86::fault_slot_gpa(carrick_x86::fault_idt_base(LAYOUT), index)?;
            for (vector, entry) in [
                TIMER_VECTOR,
                KICK_VECTOR,
                RESCHED_VECTOR,
                SHOOTDOWN_VECTOR,
                PAGE_FAULT_VECTOR,
            ]
            .into_iter()
            .zip(words[1..].iter().copied())
            {
                ram.write_gpa(
                    idt + u64::from(vector) * 16,
                    &carrick_x86::interrupts::interrupt_gate(entry),
                )
                .map_err(|error| fail(error.to_string()))?;
            }
        }
    }
    Ok(())
}

pub const RAM_SIZE: usize = 16 * 1024 * 1024;
pub const META_GPA: u64 = carrick_core_abi::X86_CPL0_METADATA_GPA;
pub const META_LEN: u64 = 0x10_0000;
pub const PRODUCTION_METADATA_GPA: u64 = META_GPA;
/// Bootstrap metadata has separate backing beyond the reserved initial image.
/// No address-space gap is allocated as host RAM.
pub const ALLOCATOR_GPA: u64 = {
    let metadata_end =
        META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET + size_of::<X86Cpl0Zone>() as u64;
    let image_end =
        X86_CPL0_INITIAL_EXTENT_GPA + carrick_core_abi::X86_CPL0_INITIAL_EXTENT_MAX_SIZE;
    let end = if metadata_end > image_end {
        metadata_end
    } else {
        image_end
    };
    end.next_multiple_of(0x20_0000)
};
pub const INITIAL_EXTENT_GPA: u64 = X86_CPL0_INITIAL_EXTENT_GPA;
const _: () = {
    assert!(
        META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET + size_of::<X86Cpl0Zone>() as u64
            <= INITIAL_EXTENT_GPA
    );
    assert!(
        INITIAL_EXTENT_GPA + carrick_core_abi::X86_CPL0_INITIAL_EXTENT_MAX_SIZE <= ALLOCATOR_GPA
    );
};
pub const KERNEL_REGION_GPA: u64 = 0x1_0000_0000;
/// Reserved before dynamic grants, including carriers with no IPC authority.
pub const IPC_WINDOW_GPA: u64 = 0x2_0000_0000;
pub const DYNAMIC_GRANT_GPA: u64 = IPC_WINDOW_GPA + carrick_el1_abi::EL1_IPC_SIZE;
pub const INITIAL_MM_KEY: u64 = 301;
/// The initial stack's top: the Linux personality's one stack placement,
/// shared with ARM, above every image base and mmap arena. A stack parked at
/// 2 GiB clipped a low image's whole arena to under 1 GiB (#2722).
pub const INITIAL_STACK_TOP: u64 = carrick_mem::memory::LINUX_STACK_TOP;
pub const INITIAL_STACK_SIZE: u64 = 0x1_0000;
/// The initial stack's whole reservation: Linux's default `RLIMIT_STACK`
/// (8 MiB), as on ARM. The carrier builds only the top
/// [`INITIAL_STACK_SIZE`] (argv, envp, auxv); the rest is supplied on first
/// touch, as Linux grows the stack VMA.
pub const INITIAL_STACK_RESERVATION: u64 = carrick_mem::memory::LINUX_STACK_SIZE;
const _: () = assert!(INITIAL_STACK_RESERVATION > INITIAL_STACK_SIZE);
// Place mmap at the next boundary after the image, preserving low-image space.
pub const INITIAL_ARENA_ALIGNMENT: u64 = 1024 * 1024 * 1024;
pub const COUNTERS_OFFSET: u64 = 0x1_0000;
pub const BINDING_OFFSET: u64 = 0x8000;
pub const TASK_OFFSET: u64 = 0x9000;
pub const CONTROL_OFFSET: u64 = 0xa000;
pub const ROUTES_OFFSET: u64 = 0xd000;
pub const SHOOTDOWN_OFFSET: u64 = 0xe000;
// All three per-CPU record arrays use this stride. Derive it from the
// control ABI: growing a member record must never overlap its live peer.
pub const STRIDE: u64 = size_of::<ThreadControlSlot>().next_power_of_two() as u64;
const _: () = {
    assert!(INITIAL_ARENA_ALIGNMENT.is_power_of_two());
    assert!(INITIAL_ARENA_ALIGNMENT.is_multiple_of(4096));
    assert!(size_of::<CpuBinding>() <= STRIDE as usize);
    assert!(size_of::<CurrentTask>() <= STRIDE as usize);
    assert!(size_of::<ThreadControlSlot>() <= STRIDE as usize);
    assert!(STRIDE.is_multiple_of(align_of::<CpuBinding>() as u64));
    assert!(STRIDE.is_multiple_of(align_of::<CurrentTask>() as u64));
    assert!(STRIDE.is_multiple_of(align_of::<ThreadControlSlot>() as u64));
    assert!(BINDING_OFFSET + 2 * STRIDE <= TASK_OFFSET);
    assert!(TASK_OFFSET + 2 * STRIDE <= CONTROL_OFFSET);
    assert!(CONTROL_OFFSET + 2 * STRIDE <= carrick_core_abi::X86_CPL0_ROOT_THREAD_CONTROLS_OFFSET);
    assert!(
        (carrick_el1_abi::THREAD_POOL_ENTRIES + 1) * size_of::<ThreadControlSlot>()
            <= carrick_core_abi::X86_CPL0_ROOT_THREAD_CONTROLS_SIZE as usize
    );
    assert!(
        carrick_core_abi::X86_CPL0_ROOT_THREAD_CONTROLS_OFFSET
            + carrick_core_abi::X86_CPL0_ROOT_THREAD_CONTROLS_SIZE
            <= ROUTES_OFFSET
    );
    assert!(ROUTES_OFFSET >= 0xc000 + 9 * size_of::<ThreadControlSlot>() as u64);
    assert!(ROUTES_OFFSET + size_of::<PublishedApicIds>() as u64 <= SHOOTDOWN_OFFSET);
    assert!(SHOOTDOWN_OFFSET + size_of::<ShootdownTable>() as u64 <= COUNTERS_OFFSET);
    assert!(
        carrick_core_abi::X86_CPL0_RESERVATIONS_OFFSET + size_of::<X86Cpl0Reservations>() as u64
            <= META_LEN
    );
};
pub const IST_STACK_BASE: u64 = 0xf0_0000;
pub const IMAGE_VA: u64 = carrick_el1_abi::X86_CPL0_SUPERVISOR_IMAGE_BASE;
pub const IMAGE_SIZE: u64 = carrick_el1_abi::X86_CPL0_SUPERVISOR_IMAGE_SIZE;
pub const IMAGE_GPA: u64 = carrick_el1_abi::X86_CPL0_SUPERVISOR_IMAGE_GPA;
pub const METADATA_VA: u64 = X86_CPL0_DYNAMIC_METADATA_BASE;
// Fork lifecycle stock: each 16 KiB slot holds a lifecycle page and, 4 KiB
// above it, the thread control slots. More records than CPUs keep a parent's
// fork from racing a reaped child that has not yet left its slot.
pub const FORK_LIFECYCLE_OFFSET: u64 = 0x8_8000;
pub const FORK_LIFECYCLE_STRIDE: u64 = carrick_hal::fork_stock::LIFECYCLE_SLOT_STRIDE;
pub const FORK_LIFECYCLE_SLOTS: u64 = 8;
const _: () = {
    assert!(
        carrick_core_abi::X86_CPL0_RESERVATIONS_OFFSET + size_of::<X86Cpl0Reservations>() as u64
            <= FORK_LIFECYCLE_OFFSET
    );
    assert!(FORK_LIFECYCLE_OFFSET.is_multiple_of(0x4000));
    assert!(
        carrick_hal::fork_stock::LIFECYCLE_CONTROLS_OFFSET
            + (carrick_el1_abi::THREAD_POOL_ENTRIES as u64 + 1)
                * size_of::<ThreadControlSlot>() as u64
            <= FORK_LIFECYCLE_STRIDE
    );
    assert!(
        size_of::<ThreadLifecyclePage>() as u64
            <= carrick_hal::fork_stock::LIFECYCLE_CONTROLS_OFFSET
    );
    assert!(FORK_LIFECYCLE_OFFSET + FORK_LIFECYCLE_SLOTS * FORK_LIFECYCLE_STRIDE <= META_LEN);
};
pub const USER_CODE: u64 = 0x1_0000;
pub use carrick_x86::cpl0_entry::DIRECT_VA;
// Startup stocks one initial MM and its first fork child's private COW branch.
// Later population admission remains bounded by actual available table grants.
const fn initial_copy_branch_table_credits() -> usize {
    2 * carrick_mmu_core::x86::copy_window::COW_COPY_TABLE_PAGES
}
/// The carrier's maintenance root is one dedicated initial table grant. It
/// is counted on top of the copy-branch credits so taking it never shrinks
/// the fork table stock the first fork was sized against.
pub const MAINTENANCE_ROOT_TABLE_CREDITS: usize = 1;
const fn initial_carrier_table_credits() -> usize {
    initial_copy_branch_table_credits() + MAINTENANCE_ROOT_TABLE_CREDITS
}
/// Initial table grants for `data_pages` user pages: the initial MM's worst
/// case (three tables per page plus its root) and the carrier credits.
pub const fn initial_table_grant_count(data_pages: usize) -> Option<usize> {
    let Some(tables) = data_pages.checked_mul(3) else {
        return None;
    };
    let Some(tables) = tables.checked_add(1) else {
        return None;
    };
    tables.checked_add(initial_carrier_table_credits())
}

/// Fixed physical base of the initial GDT (0x50_0000), immediately following the
/// 1 MiB fixture process lane tables (0x30_0000..0x40_0000) and data (0x40_0000..0x50_0000).
pub const GDT_BASE: u64 = 0x50_0000;
/// Fixed physical base of the shared PML4 page-table pool and initial boot root (0x60_0000).
/// Fixed by contract across the hardware carrier, carrick-x86 bringup, and CPL0 supervisor:
/// - Initial boot CR3 is 0x60_0000.
/// - The pool occupies `carrick_x86::X86_PML4_CAPACITY` bytes (0x1c_0000 bytes, 0x60_0000..0x7c_0000),
///   followed by fault structures (IDT, stubs, TSS, stack, records) spanning 0x7c_0000..0x81_0000.
/// - Compile-time assertion `LAYOUT.gdt_base < LAYOUT.pml4_base` strictly prevents any future
///   image extent expansion from silently overlapping this fixed root pool.
pub const PML4_BASE: u64 = 0x60_0000;

pub const LAYOUT: BringupLayout = BringupLayout {
    trampoline_base: IMAGE_GPA,
    gdt_base: GDT_BASE,
    pml4_base: PML4_BASE,
};
const _: () = {
    assert!(IMAGE_GPA.is_multiple_of(4096));
    assert!(IMAGE_SIZE.is_multiple_of(4096));
    assert!(IMAGE_GPA + IMAGE_SIZE <= 0x30_0000);
    assert!(IMAGE_GPA + IMAGE_SIZE <= LAYOUT.gdt_base);
    assert!(LAYOUT.gdt_base.is_multiple_of(4096));
    assert!(LAYOUT.gdt_base < LAYOUT.pml4_base);
    assert!(LAYOUT.pml4_base.is_multiple_of(4096));
    assert!(LAYOUT.pml4_base + carrick_x86::X86_PML4_CAPACITY as u64 <= META_GPA);
};
const _: () = assert!(FIXTURE_PML4_CAPACITY == carrick_x86::X86_PML4_CAPACITY);

/// Guest-physical address of initial frame grant `index`: grants follow
/// the staged boot records, page aligned, inside the initial extent. The
/// first unused table grant becomes the carrier's maintenance root.
pub fn initial_grant_gpa(frame_offset: usize, index: usize) -> FrameGpa {
    FrameGpa::new(INITIAL_EXTENT_GPA + (frame_offset + index * 4096) as u64)
}

pub fn fail(message: impl Into<String>) -> TrapError {
    TrapError::Hypervisor(message.into())
}

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum FixtureCpuidError {
    MissingLeafZero,
    FullTable,
}

pub const MAX_CPUID_ENTRIES: usize = 256;

#[repr(C)]
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::default::Default,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct CpuidEntry {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub padding: [u32; 3],
}

// The fixture uses CPUID only for the native CPU features admitted at boot,
// APIC topology, XSAVE x87/SSE/AVX, and the optional clock source.
pub fn fixture_cpuid_leaf(entry: &CpuidEntry) -> bool {
    match entry.function {
        0 | 1 | 0x8000_0000 | 0x8000_0001 | 0x8000_0007 | 0x8000_0008 => true,
        0x15 => entry.index == 0,
        7 => entry.index == 0, // SMEP, SMAP and native feature admission.
        0xb | 0x1f => entry.index <= 2, // APIC topology for the two CPUs.
        0xd => entry.index <= 2, // XCR0=x87|SSE|AVX, including XSAVE size.
        _ => false,
    }
}

pub fn fixture_cpuid_with_tsc_hz(
    entries: &mut Vec<CpuidEntry>,
    hz: u32,
) -> Result<(), FixtureCpuidError> {
    let mut selected: Vec<_> = entries.iter().copied().filter(fixture_cpuid_leaf).collect();
    let leaf0 = selected
        .iter()
        .position(|entry| entry.function == 0)
        .ok_or(FixtureCpuidError::MissingLeafZero)?;
    let existing = selected.iter().position(|entry| entry.function == 0x15);
    if existing.is_none() && selected.len() >= MAX_CPUID_ENTRIES {
        let vacant = selected.iter().enumerate().find_map(|(index, entry)| {
            (index != leaf0
                && entry.function == 0
                && entry.index == 0
                && entry.flags == 0
                && entry.eax == 0
                && entry.ebx == 0
                && entry.ecx == 0
                && entry.edx == 0
                && entry.padding == [0; 3])
                .then_some(index)
        });
        let Some(vacant) = vacant else {
            return Err(FixtureCpuidError::FullTable);
        };
        selected[vacant] = CpuidEntry {
            function: 0x15,
            eax: 1,
            ebx: 1,
            ecx: hz,
            ..Default::default()
        };
        selected[leaf0].eax = selected[leaf0].eax.max(0x15);
        *entries = selected;
        return Ok(());
    }
    let clock = CpuidEntry {
        function: 0x15,
        eax: 1,
        ebx: 1,
        ecx: hz,
        ..Default::default()
    };
    selected[leaf0].eax = selected[leaf0].eax.max(0x15);
    if let Some(existing) = existing {
        selected[existing] = clock;
    } else {
        selected.push(clock);
    }
    *entries = selected;
    Ok(())
}
/// The host's disposition of one Linux call forwarded by the shared guest.
pub enum InitialSyscallDisposition {
    Return(i64),
    Refused(carrick_abi::LinuxErrno),
    Exit(GuestExitStatus),
}

/// Physical services carry no guest Linux policy or host dispatch authority.
/// Authenticated terminal outcome from a stopped production CPU.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum PhysicalProcessExit {
    Exited(carrick_sched_core::process::TerminationStatus),
    RunFailed(carrick_core_abi::NativeRunFailureReport),
}

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum PhysicalCrossingFamily {
    OwnerGrant,
    RootExit,
    ChildRetire,
    RunFailure,
    /// Owed-return settlement doorbells (#1369 slice 3). They ride the
    /// owner-grant port, so each is also one `OwnerGrant` crossing.
    ReturnSettlement,
    /// The guest retired a closed space's entry and crossed so the carrier
    /// drains the fork quarantine waiting for it (#3030).
    SpaceRetired,
}
impl PhysicalCrossingFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerGrant => "owner_grant",
            Self::RootExit => "root_exit",
            Self::ChildRetire => "child_retire",
            Self::RunFailure => "run_failure",
            Self::ReturnSettlement => "return_settlement",
            Self::SpaceRetired => "space_retired",
        }
    }
}

#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
pub struct InitialReservationLimits {
    pub address: carrick_abi::LinuxRlimit,
    pub data: carrick_abi::LinuxRlimit,
}

impl InitialReservationLimits {
    pub const UNLIMITED: Self = Self {
        address: carrick_abi::LinuxRlimit::new(u64::MAX, u64::MAX),
        data: carrick_abi::LinuxRlimit::new(u64::MAX, u64::MAX),
    };
}

pub fn initial_reservation_layout(
    initial_break: UserVa,
    stack_top: UserVa,
    limits: InitialReservationLimits,
) -> Result<LinuxReservationLayout, TrapError> {
    let stack_base = stack_top
        .raw()
        .checked_sub(INITIAL_STACK_RESERVATION)
        .filter(|_| stack_top.raw() <= carrick_guest_arch::USER_CEILING)
        .ok_or_else(|| fail("initial stack layout"))?;
    let stack = ReservationRange::new(stack_base, stack_top.raw())
        .ok_or_else(|| fail("initial stack layout"))?;
    // The authenticated break is the highest page-rounded PT_LOAD end. The
    // production stack sits above every image base, but neither reservation
    // may depend on a fixed split address or assume the stack is above it.
    let ceiling = if initial_break.raw() <= stack.start() {
        stack.start()
    } else if initial_break.raw() >= stack.end() {
        carrick_guest_arch::USER_CEILING
    } else {
        return Err(fail("initial heap overlaps stack"));
    };
    // Keep at least one page for mmap when the stack/user boundary clips the
    // heap capacity. Neither hidden reservation allocates physical backing.
    let heap_ceiling = ceiling
        .checked_sub(4096)
        .ok_or_else(|| fail("initial heap layout"))?;
    let arena_start = initial_break
        .raw()
        .checked_add(INITIAL_ARENA_ALIGNMENT)
        .map(|end| end & !(INITIAL_ARENA_ALIGNMENT - 1))
        .map(|end| end.min(heap_ceiling))
        .ok_or_else(|| fail("initial heap layout"))?;
    let heap = ReservationRange::new(initial_break.raw(), arena_start)
        .ok_or_else(|| fail("initial heap layout"))?;
    let arena_end = arena_start
        .checked_add(carrick_mem::memory::LINUX_MMAP_SIZE)
        .ok_or_else(|| fail("initial mmap arena overflow"))?
        .min(ceiling);
    let arena = ReservationRange::new(arena_start, arena_end)
        .ok_or_else(|| fail("initial mmap arena layout"))?;
    Ok(LinuxReservationLayout {
        heap,
        arena,
        brk: initial_break.raw(),
        address_limit: limits.address.rlim_cur,
        data_limit: limits.data.rlim_cur,
        external_address_bytes: 0,
        external_data_bytes: 0,
    })
}

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct GuestExitStatus(u8);
impl GuestExitStatus {
    pub const fn from_linux_code(code: i32) -> Self {
        Self(code as u8)
    }

    pub const fn code(self) -> i32 {
        self.0 as i32
    }
}

pub fn backing_identity(ids: &dyn PhysicalFrameInventory) -> Result<BackingIdentity, TrapError> {
    let (frame, mapping) = ids
        .allocate_backing_ids()
        .map_err(|error| fail(error.to_string()))?;
    Ok(BackingIdentity {
        frame_id: NonZeroU64::new(frame.raw())
            .ok_or_else(|| fail("carrier frame identity zero"))?,
        mapping_id: NonZeroU64::new(mapping.raw())
            .ok_or_else(|| fail("carrier mapping identity zero"))?,
        owner_generation: NonZeroU64::MIN,
        inventory_revision: NonZeroU64::MIN,
    })
}

/// Refuse stale shared layouts before entering or publishing a guest image.
pub fn validate_layout_hash(found: u64) -> Result<(), TrapError> {
    let expected = carrick_el1_abi::EL1_ABI_LAYOUT_HASH;
    if found != expected {
        return Err(TrapError::ImageAbiMismatch { expected, found });
    }
    Ok(())
}

/// Authenticate the guest's mutable completion against the retained host
/// request before any reply field sizes a read, indexes a grant, or subtracts
/// a stack bound. The stopped carrier still owns all unpublished grants on
/// refusal, so dropping its inventory rolls the transaction back.
pub fn validate_initial_reply(
    request: &X86InitialBootRequest,
    reply: &X86InitialBootRequest,
    grant_count: usize,
    root_gpa: u64,
    initial_break: u64,
) -> Result<(), TrapError> {
    validate_layout_hash(reply.layout_hash)?;
    let host_grants = (request.table_grant_count as usize)
        .checked_add(request.data_grant_count as usize)
        .ok_or_else(|| fail("initial MM host grant count overflow"))?;
    let stack_base = request
        .stack_top
        .checked_sub(request.stack_size)
        .ok_or_else(|| fail("initial MM host stack underflow"))?;
    if reply.result_status != X86_INITIAL_BOOT_LOADED
        || reply.magic != request.magic
        || reply.version != request.version
        || reply.region_count != request.region_count
        || reply.entry != request.entry
        || reply.executable_entry != request.executable_entry
        || reply.interpreter_base != request.interpreter_base
        || reply.executable_region_count != request.executable_region_count
        || reply.image_features != request.image_features
        || reply.phdr != request.phdr
        || reply.phent != request.phent
        || reply.phnum != request.phnum
        || reply.argc != request.argc
        || reply.envc != request.envc
        || reply.regions_gpa != request.regions_gpa
        || reply.strings_gpa != request.strings_gpa
        || reply.grants_gpa != request.grants_gpa
        || reply.table_grant_count != request.table_grant_count
        || reply.data_grant_count != request.data_grant_count
        || reply.publications_gpa != request.publications_gpa
        || reply.publication_capacity != request.publication_capacity
        || reply.stack_top != request.stack_top
        || reply.stack_size != request.stack_size
        || reply.random != request.random
        || reply.extent_pages != request.extent_pages
        || reply.mm_key != request.mm_key
        || reply.generation != request.generation
        || host_grants != grant_count
        || request.table_grant_count == 0
        || request.data_grant_count == 0
        || reply.publication_count == 0
        || reply.publication_count != request.data_grant_count
        || reply.result_data_used != reply.publication_count
        || reply.result_root_gpa != root_gpa
        || reply.result_table_used == 0
        || reply.result_table_used > request.table_grant_count
        || reply.result_initial_break != initial_break
        || reply.result_rsp < stack_base
        || reply.result_rsp >= request.stack_top
    {
        return Err(fail("production initial MM reply identity"));
    }
    Ok(())
}

pub fn initial_stack_pages(
    image: &carrick_mem::x86_initial_image::X86InitialImage<'_>,
    argv: &[String],
    env: &[String],
) -> Result<usize, TrapError> {
    use carrick_el1::isa::x86_initial_mm::{InitialStackSpec, build_initial_stack};
    let argv_bytes: Vec<&[u8]> = argv.iter().map(|value| value.as_bytes()).collect();
    let env_bytes: Vec<&[u8]> = env.iter().map(|value| value.as_bytes()).collect();
    let _stack = build_initial_stack(&InitialStackSpec {
        entry: image.executable_entry,
        interpreter_base: image.interpreter_base,
        phdr: image.phdr,
        phent: image.phent,
        phnum: image.phnum,
        argv: &argv_bytes,
        envp: &env_bytes,
        random: [0; 16],
        stack_top: INITIAL_STACK_TOP,
        stack_size: INITIAL_STACK_SIZE,
        vdso: image.vdso_base().map(UserVa::new),
    })
    .map_err(|error| fail(format!("initial stack sizing: {error:?}")))?;
    // The guest owner backs the configured bootstrap stack, including its
    // zero prefix. Serialization still copies only the initialized tail.
    Ok((INITIAL_STACK_SIZE / 4096) as usize)
}

/// The shared successor validator's view of an x86 image: one row per
/// page-rounded PT_LOAD region, executable regions first.
pub fn x86_image_rows(
    image: &carrick_mem::x86_initial_image::X86InitialImage<'_>,
) -> Vec<carrick_core_abi::successor_image::ImageRow> {
    image
        .regions
        .iter()
        .map(|region| carrick_core_abi::successor_image::ImageRow {
            start: UserVa::new(region.start),
            len: carrick_guest_arch::GuestLen::new(region.end.saturating_sub(region.start)),
            initialized_offset: carrick_guest_arch::GuestLen::new(region.initialized_offset),
            initialized_len: carrick_guest_arch::GuestLen::new(region.file_bytes.len() as u64),
            readable: region.perms.read,
            writable: region.perms.write,
            executable: region.perms.execute,
        })
        .collect()
}

/// Import `image`'s rows and the stack reservation below the stack the
/// editor builds into an unadmitted reservation root, after the shared
/// successor validator accepts them. Boot and exec share this projection:
/// the carrier built each image page as a private frame (`Prepare`), so it
/// is root-editable private memory marked `IMAGE`, and the rest of the
/// stack reservation is private anonymous memory the ring supplies on
/// first touch. Boot then finishes its own import and inserts the stack it
/// built; an exec successor's import is finished by its adopter.
pub fn import_x86_image_rows<P: carrick_core::mm::reservation::ReservationPolicy>(
    model: &mut carrick_core::mm::reservation::Reservations<
        '_,
        P,
        carrick_el1::memory::reservations::X86Cpl0ReservationGeometry,
        carrick_sched_core::ParkedContextWords,
    >,
    image: &carrick_mem::x86_initial_image::X86InitialImage<'_>,
    stack_top: u64,
) -> Result<(), carrick_el1::memory::reservations::Refusal> {
    use carrick_core_abi::successor_image::{ImageGeometry, ImageStack, validate_image_rows};
    use carrick_el1::memory::reservations::Refusal;
    use carrick_el1_abi::{ReservationNodeFlags, ReservationProtection};
    let rows = x86_image_rows(image);
    validate_image_rows(
        &rows,
        image.executable_region_count,
        UserVa::new(image.entry),
        ImageStack {
            top: UserVa::new(stack_top),
            size: carrick_guest_arch::GuestLen::new(INITIAL_STACK_SIZE),
        },
        ImageGeometry::X86_64,
    )
    .map_err(|_| Refusal::Invalid)?;
    for region in &image.regions {
        let bits = u64::from(region.perms.read)
            | (u64::from(region.perms.write) << 1)
            | (u64::from(region.perms.execute) << 2);
        model.import_with(
            ReservationRange::new(region.start, region.end).ok_or(Refusal::Invalid)?,
            ReservationProtection::from_bits(bits).ok_or(Refusal::Invalid)?,
            ReservationNodeFlags::ANONYMOUS_PRIVATE.union(ReservationNodeFlags::IMAGE),
        )?;
    }
    // Below the stack the editor builds, the rest of the stack reservation
    // grows on first touch, as Linux grows the stack VMA (#1714: a fixed
    // 64 KiB stack faulted CPython's compiler).
    model.import_with(
        ReservationRange::new(
            stack_top
                .checked_sub(INITIAL_STACK_RESERVATION)
                .ok_or(Refusal::Invalid)?,
            stack_top - INITIAL_STACK_SIZE,
        )
        .ok_or(Refusal::Invalid)?,
        ReservationProtection::READ_WRITE,
        ReservationNodeFlags::ANONYMOUS_PRIVATE.union(ReservationNodeFlags::GROWSDOWN),
    )
}

pub fn record_bytes<T: Copy>(record: &T) -> &[u8] {
    // SAFETY: every caller passes a fully initialized fixed-layout ABI
    // record; its storage remains live for the returned borrow.
    unsafe { core::slice::from_raw_parts((record as *const T).cast::<u8>(), size_of::<T>()) }
}

pub fn append_records<T: Copy>(buffer: &mut Vec<u8>, records: &[T]) -> Result<u64, TrapError> {
    let offset = u64::try_from(buffer.len()).map_err(|_| fail("initial metadata offset"))?;
    for record in records {
        buffer.extend_from_slice(record_bytes(record));
    }
    INITIAL_EXTENT_GPA
        .checked_add(offset)
        .ok_or_else(|| fail("initial metadata address"))
}

pub struct InitialInventory {
    mm: MmGeneration,
    source: Arc<dyn PhysicalFrameInventory>,
    authority: Arc<dyn FrameCowAuthority>,
    receipt: Option<carrick_hal::UnpublishedFrameInventoryApply<dyn FrameCowAuthority>>,
    frames: Vec<(FrameGpa, BackingIdentity)>,
    length: FrameLength,
    expected: usize,
    committed: usize,
    guest_exposed: bool,
    rollback_fault: Arc<carrick_hal::physical_grants::PhysicalGrantRollback>,
}
impl InitialInventory {
    pub fn frames(&self) -> &[(FrameGpa, BackingIdentity)] {
        &self.frames
    }
    pub fn expect_publications(&mut self, count: usize) {
        self.expected = count;
    }
    pub fn guest_exposed(&self) -> bool {
        self.guest_exposed
    }

    pub fn stage(
        rollback_fault: Arc<carrick_hal::physical_grants::PhysicalGrantRollback>,
        source: Arc<dyn PhysicalFrameInventory>,
        gpas: impl IntoIterator<Item = FrameGpa>,
        table_grants: usize,
        frame_len: u64,
        owner: carrick_hal::GuestFrameOwner,
    ) -> Result<(Self, Vec<X86InitialBootGrant>), TrapError> {
        let mm = owner.native_mm;
        let staged = carrick_hal::physical_grants::StagedPhysicalGrants::stage(
            Arc::clone(&rollback_fault),
            Arc::clone(&source),
            gpas,
            table_grants,
            frame_len,
            owner,
        )?
        .handoff()?;
        let grants = staged
            .grants
            .into_iter()
            .map(|grant| X86InitialBootGrant {
                gpa: grant.gpa.raw(),
                frame_id: grant.identity.frame_id.get(),
                mapping_id: grant.identity.mapping_id.get(),
                owner_generation: grant.identity.owner_generation.get(),
                inventory_revision: grant.identity.inventory_revision.get(),
            })
            .collect();
        let authority = staged.authority;
        let receipt = staged.receipt;
        let frames = staged.frames;
        let length = staged.length;
        Ok((
            Self {
                mm,
                source,
                authority,
                receipt: Some(receipt),
                frames,
                length,
                expected: 0,
                committed: 0,
                guest_exposed: false,
                rollback_fault,
            },
            grants,
        ))
    }

    pub fn finish(&mut self) -> Result<(), TrapError> {
        if self.committed != self.expected {
            return Err(fail("initial inventory incomplete"));
        }
        self.receipt = None;
        Ok(())
    }
}
impl InventoryTransaction for InitialInventory {
    fn publish(&mut self) -> Result<(), crate::carrier_memory::MemoryError> {
        let receipt = self.receipt.as_ref().ok_or_else(|| {
            crate::carrier_memory::MemoryError("initial inventory receipt absent".into())
        })?;
        let mm = self.mm;
        if receipt.mm() != mm.raw() {
            return Err(crate::carrier_memory::MemoryError(
                "inventory MM mismatch".into(),
            ));
        }
        for &(gpa, identity) in &self.frames {
            let mapping = MappingId::from_kernel_allocation(identity.mapping_id);
            let frame = FrameId::from_kernel_allocation(identity.frame_id);
            if !receipt.authorizes(mapping, frame)
                || !self
                    .authority
                    .mapping_is_live(
                        mapping,
                        frame,
                        carrick_guest_mem::Gpa::new(gpa.raw()),
                        self.length,
                    )
                    .map_err(|error| crate::carrier_memory::MemoryError(error.to_string()))?
            {
                return Err(crate::carrier_memory::MemoryError(
                    "inventory frame missing".into(),
                ));
            }
        }
        Ok(())
    }
    fn commit(
        &mut self,
        publication: &GuestMmuPublication,
    ) -> Result<(), crate::carrier_memory::MemoryError> {
        if publication.outcome != GuestMmuPublication::APPLIED || self.committed >= self.expected {
            return Err(crate::carrier_memory::MemoryError(
                "initial inventory publication".into(),
            ));
        }
        self.committed += 1;
        self.guest_exposed = true;
        Ok(())
    }
    fn rollback(&mut self) -> Result<(), crate::carrier_memory::MemoryError> {
        if self.guest_exposed {
            return Err(crate::carrier_memory::MemoryError(
                "cannot roll back guest-exposed inventory without retirement".into(),
            ));
        }
        if let Some(receipt) = self.receipt.as_mut() {
            receipt.rollback().map_err(|error| {
                crate::carrier_memory::MemoryError(format!("initial inventory rollback: {error}"))
            })?;
        }
        self.receipt = None;
        self.committed = 0;
        Ok(())
    }
}
impl Drop for InitialInventory {
    fn drop(&mut self) {
        if self.receipt.is_some()
            && !self.guest_exposed
            && self.rollback().is_err()
            && let Some(receipt) = self.receipt.take()
        {
            self.rollback_fault.retain(receipt);
        }
    }
}

#[cfg(test)]
mod fixture_cpuid_tests {
    use super::*;

    #[test]
    fn full_cpuid_fixture_reuses_only_an_exact_zero_duplicate_of_leaf_zero() {
        let mut entries = vec![CpuidEntry::default(); MAX_CPUID_ENTRIES];
        entries[0].eax = 0x10;
        entries[1].function = 7;
        entries[1].ebx = (1 << 7) | (1 << 20);
        let features = entries[1];
        fixture_cpuid_with_tsc_hz(&mut entries, 2_000_000_000).expect("vacant duplicate reused");
        assert_eq!(entries.len(), MAX_CPUID_ENTRIES);
        assert_eq!(entries[0].eax, 0x15);
        assert_eq!(entries[1].ebx, features.ebx);
        assert_eq!(entries[2].function, 0x15);
        assert_eq!(entries[2].ecx, 2_000_000_000);
    }

    #[test]
    fn eighty_supported_leaves_leave_room_for_fixture_tsc() {
        let mut entries = vec![CpuidEntry {
            function: 0,
            eax: 0x16,
            ..Default::default()
        }];
        entries.extend(
            [1, 7, 0xd, 0x8000_0000, 0x8000_0001, 0x8000_0008].map(|function| CpuidEntry {
                function,
                ..Default::default()
            }),
        );
        entries.extend((entries.len()..80).map(|index| CpuidEntry {
            function: 0x100 + index as u32,
            ..Default::default()
        }));
        assert_eq!(entries.len(), 80);
        fixture_cpuid_with_tsc_hz(&mut entries, 2_000_000_000).unwrap();
        assert!(entries.len() < 80, "unused host leaves must be removed");
        assert!(
            entries
                .iter()
                .any(|entry| entry.function == 0x15 && entry.ecx == 2_000_000_000)
        );
        assert!(entries.iter().any(|entry| entry.function == 7));
        assert!(entries.iter().any(|entry| entry.function == 0xd));
    }

    #[test]
    fn missing_base_leaf_refuses_without_mutation() {
        let mut entries = (0..MAX_CPUID_ENTRIES)
            .map(|index| CpuidEntry {
                function: 0x100 + index as u32,
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let before = entries.clone();
        assert_eq!(
            fixture_cpuid_with_tsc_hz(&mut entries, 2_000_000_000),
            Err(FixtureCpuidError::MissingLeafZero)
        );
        assert_eq!(entries, before);
    }

    #[test]
    fn full_cpuid_table_reuses_its_existing_tsc_leaf() {
        let mut entries = vec![CpuidEntry {
            function: 0,
            eax: 7,
            ..Default::default()
        }];
        entries.extend((1..MAX_CPUID_ENTRIES).map(|index| CpuidEntry {
            function: if index == 17 {
                0x15
            } else {
                0x100 + index as u32
            },
            ..Default::default()
        }));
        assert_eq!(
            fixture_cpuid_with_tsc_hz(&mut entries, 2_000_000_000),
            Ok(())
        );
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.function == 0x15)
                .map(|entry| entry.ecx),
            Some(2_000_000_000)
        );
    }
}

#[derive(::core::fmt::Debug)]
pub struct Observation {
    pub result: i64,
    pub heads: [(u64, u32); 2],
    pub served: u64,
    pub forwarded: u64,
    pub semantic_host_exits: u64,
    pub entries: [u64; 2],
    pub publications: [u64; 2],
    pub completions: [u64; 2],
    pub kicks: u64,
    pub work_exits: u64,
    pub captured_stack: u64,
    pub returned_stack: u64,
    pub preserved_rbx: u64,
    pub host_yields: u64,
}

/// Stopped-vCPU structural observation, including refusal paths that cannot
/// return through the guest observation syscall. No semantic host service.
#[derive(::core::fmt::Debug)]
pub struct EntryState {
    pub bindings: [carrick_el1_abi::ExecutionBinding; 2],
    pub heads: [(u64, u32); 2],
    pub entries: [u64; 2],
    pub publications: [u64; 2],
    pub completions: [u64; 2],
    pub served: u64,
    pub host_forwards: u64,
}

/// The vCPUs drop before the VM, and its registered backing drops last.
/// No run handle or host pointer escapes this fixture owner.
#[path = "cpl0_anonymous.rs"]
pub mod anonymous_owner;

#[path = "cpl0_exec.rs"]
pub mod exec_service;

pub mod retained_slots;

mod stdio;
pub use stdio::StdioReleaseRefusal;

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum ForwardBindingRefusal {
    ContextMismatch,
    /// The stopped task is the root's leader, and the registered binding's
    /// execution generation is not the one its lifecycle record names.
    GenerationMismatch {
        stopped: u64,
        registered: u64,
    },
}

/// Who the stopped execution is in the process whose root it runs on.
///
/// The carrier registers one binding per root, issued to the process leader.
/// A `CLONE_VM` member shares that root and has its own execution
/// generation; it is the same process and never the leader. Serving it is a decision for the forward's
/// caller, made on this type: a member holds none of the leader's host task
/// authority (#2780).
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum ForwardSubject {
    /// The task the root's registered binding was issued to.
    Leader,
    /// Another member of the leader's thread group.
    Member {
        leader: carrick_el1_abi::EntryTaskKey,
        stopped: carrick_el1_abi::EntryTaskKey,
    },
}

#[derive(::core::clone::Clone, ::core::marker::Copy)]
struct ForwardExecution {
    cpu: carrick_guest_arch::CpuId,
    binding: carrick_el1_abi::ExecutionBinding,
    leader_task: carrick_el1_abi::EntryTaskKey,
    context: AddressContext<RootGpa>,
}

impl ForwardExecution {
    /// Authenticate the CR3-registered carrier binding against the execution
    /// the stopped CPU's own lifecycle record names. The address context
    /// must match for every subject. The registered execution generation is
    /// the leader's own (an `execve` advances it), so it authenticates only
    /// a stopped [`ForwardSubject::Leader`]. A `CLONE_VM` member carries the
    /// generation of its own birth, which says nothing about the leader's
    /// (#2832); the address context is what ties it to this image, because
    /// an `execve` leaves the process on a new MM with one thread. A
    /// member's own control slot issues no authority on the root, so it is
    /// never served as the leader.
    fn authenticate_typed(
        &self,
        binding: carrick_hal::guest_arch_binding::GuestArchBinding,
    ) -> Result<(), ForwardBindingRefusal> {
        if binding.context() != self.context {
            return Err(ForwardBindingRefusal::ContextMismatch);
        }
        if self.subject() == ForwardSubject::Leader
            && binding.task().execution.raw().get() != self.binding.generation.raw()
        {
            return Err(ForwardBindingRefusal::GenerationMismatch {
                stopped: self.binding.generation.raw(),
                registered: binding.task().execution.raw().get(),
            });
        }
        Ok(())
    }

    fn subject(&self) -> ForwardSubject {
        if self.binding.task == self.leader_task {
            ForwardSubject::Leader
        } else {
            ForwardSubject::Member {
                leader: self.leader_task,
                stopped: self.binding.task,
            }
        }
    }

    fn with_leader_task(mut self, leader_task: carrick_el1_abi::EntryTaskKey) -> Self {
        self.leader_task = leader_task;
        self
    }

    fn authenticate(
        &self,
        binding: carrick_hal::guest_arch_binding::GuestArchBinding,
        refusal: &str,
    ) -> Result<(), TrapError> {
        self.authenticate_typed(binding)
            .map_err(|reason| fail(format!("{refusal}: {reason:?}")))
    }
}

fn admit_forward_execution(
    cpu: carrick_guest_arch::CpuId,
    binding_cpu: carrick_guest_arch::CpuId,
    binding: carrick_el1_abi::ExecutionBinding,
    context: AddressContext<RootGpa>,
    live_root: RootGpa,
    owner_generation: ContextGeneration,
) -> Result<ForwardExecution, TrapError> {
    if cpu != binding_cpu
        || !binding.issued()
        || binding.thread_generation.raw() == 0
        || binding.mm.raw() != context.mm.raw().get()
        || live_root != context.root
        || owner_generation != context.generation
    {
        return Err(fail("stopped forward execution mismatch"));
    }
    Ok(ForwardExecution {
        cpu,
        binding,
        leader_task: binding.task,
        context,
    })
}

#[cfg(test)]
mod design_doc_tests {
    /// The design doc's x86 live-children limit is this stock's layout.
    #[test]
    fn design_doc_names_the_carrier_lifecycle_record_count_and_offset() {
        let doc = include_str!("../../../docs/design/arm-fork-stock-crossing.md");
        let text = doc.split_whitespace().collect::<Vec<_>>().join(" ");
        let claim = format!(
            "x86 CPL0 has **{} records** at metadata offset `{:#x}`",
            super::FORK_LIFECYCLE_SLOTS,
            super::FORK_LIFECYCLE_OFFSET,
        );
        assert!(text.contains(&claim), "doc must say: {claim}");
    }
}

#[cfg(test)]
mod forward_execution_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::carrier_cpu::tests::{TestIo, context_with_root};
    use crate::carrier_memory::test_support::{MemoryTestIo, TestMemoryIo};
    use carrick_hal::guest_arch_binding::GuestArchBinding;

    struct ForwardVenueFixture {
        _authority: Arc<FrameInventoryAuthority>,
        custody: BootstrapCustody<MemoryTestIo>,
        cpu: CarrierCpu<TestIo>,
        children: CarrierChildBindings,
        root_binding: GuestArchBinding,
    }

    impl ForwardVenueFixture {
        fn new() -> Self {
            Self::new_inner(false)
        }

        fn with_pod() -> Self {
            Self::new_inner(true)
        }

        fn new_inner(with_pod: bool) -> Self {
            let nz = |v| NonZeroU64::new(v).unwrap();
            let mut ram = GuestRam::new();
            ram.add_window(0, 0x2_0000, WindowKind::Private).unwrap();
            if with_pod {
                ram.add_window(
                    ALLOCATOR_GPA,
                    EL1_BOOTSTRAP_METADATA_SIZE as usize,
                    WindowKind::Private,
                )
                .unwrap();
            }
            let zone_end =
                carrick_core_abi::X86_CPL0_ZONE_OFFSET as usize + size_of::<X86Cpl0Zone>();
            let meta_bytes = ((zone_end + 4095) & !4095).max(META_LEN as usize);
            ram.add_window(META_GPA, meta_bytes, WindowKind::Private)
                .unwrap();
            // SAFETY: fresh private metadata window with no live vCPU or shared
            // reader; offsets match `prepare_boot` and static layout assertions.
            unsafe {
                let controls = ram
                    .host_ptr(
                        META_GPA + carrick_core_abi::X86_CPL0_ROOT_THREAD_CONTROLS_OFFSET,
                        carrick_core_abi::X86_CPL0_ROOT_THREAD_CONTROLS_SIZE as usize,
                    )
                    .unwrap()
                    .cast::<ThreadControlSlot>();
                for index in 0..=carrick_el1_abi::THREAD_POOL_ENTRIES {
                    controls.add(index).write(ThreadControlSlot::new());
                }
                for index in 0..2 {
                    let offset = index as u64 * STRIDE;
                    ram.host_ptr(
                        META_GPA + CONTROL_OFFSET + offset,
                        size_of::<ThreadControlSlot>(),
                    )
                    .unwrap()
                    .cast::<ThreadControlSlot>()
                    .write(ThreadControlSlot::new());
                    ram.host_ptr(META_GPA + TASK_OFFSET + offset, size_of::<CurrentTask>())
                        .unwrap()
                        .cast::<CurrentTask>()
                        .write(CurrentTask::new());
                    ram.host_ptr(META_GPA + BINDING_OFFSET + offset, size_of::<CpuBinding>())
                        .unwrap()
                        .cast::<CpuBinding>()
                        .write(bootstrap_cpu_binding(index, 0));
                }
            }
            let ram = Arc::new(ram);
            let mut memory =
                CarrierMemory::new(MemoryTestIo::new(TestMemoryIo::default())).unwrap();
            memory.install_bootstrap(Arc::clone(&ram)).unwrap();
            let authority = Arc::new(FrameInventoryAuthority::new());
            let frame_inventory = authority.physical_projection(Arc::new(ObjectIdRegistry::new()));
            let extent = Arc::new(
                BackingExtent::private(
                    FrameGpa::new(KERNEL_REGION_GPA),
                    carrick_el1_abi::EL1_REGION_SIZE as usize,
                )
                .unwrap(),
            );
            let file_binding = carrick_el1_abi::FileRegionBinding::new(
                carrick_el1_abi::FileRegionId::from_carrier(memory.identity().nonzero()),
                carrick_guest_arch::KernelVa::new(X86_CPL0_REGION_BASE),
                FrameGpa::new(KERNEL_REGION_GPA),
                carrick_guest_arch::GuestLen::new(carrick_el1_abi::EL1_REGION_SIZE),
            )
            .unwrap();
            // SAFETY: fresh private extent retained by `files` inside `BootstrapCustody`.
            let files =
                unsafe { BootstrapFileRegion::initialize(Arc::clone(&extent), file_binding) }
                    .unwrap();
            let kernel_region = if with_pod {
                let identity = backing_identity(&*frame_inventory).unwrap();
                Some(
                    memory
                        .install(&[PreparedBacking { extent, identity }])
                        .unwrap()[0],
                )
            } else {
                None
            };
            let pod = if with_pod {
                vec![anonymous_owner::KernelPodStorage::for_bootstrap()]
            } else {
                Vec::new()
            };
            let mut custody = BootstrapCustody::new(
                memory,
                ram,
                None,
                kernel_region,
                files,
                frame_inventory,
                pod,
            )
            .unwrap();
            let root_gpa = RootGpa::page_aligned(FrameGpa::new(0x2000)).unwrap();
            let initial_mm = MmGeneration::new(nz(INITIAL_MM_KEY));
            let initial = InitialTaskBinding {
                task: carrick_sched_core::process::TaskKey {
                    id: carrick_sched_core::process::TaskId::from_registry_allocation(
                        core::num::NonZeroI32::new(41).unwrap(),
                    ),
                    serial: carrick_sched_core::process::TaskSerial::from_raw_u64(7).unwrap(),
                },
                thread: carrick_sched_core::ThreadIdentity {
                    tid: 41,
                    serial: 101,
                    generation: 11,
                    file_table: 5,
                    ..Default::default()
                },
                mm: initial_mm,
            };
            custody.bind_initial_task_identity(initial).unwrap();
            custody
                .memory_mut()
                .install_root(
                    initial_mm.raw(),
                    AddressContext {
                        root: root_gpa,
                        mm: initial_mm,
                        generation: ContextGeneration::new(nz(1)),
                    },
                )
                .unwrap();
            custody
                .bind_execution(
                    0,
                    initial.task.serial,
                    carrick_el1_abi::ExecutionBinding {
                        task: carrick_el1_abi::EntryTaskKey::from_raw(41),
                        generation: carrick_el1_abi::SnapshotGeneration::from_raw(11),
                        mm: carrick_el1_abi::EntryMmKey::from_raw(INITIAL_MM_KEY),
                        thread_generation: carrick_el1_abi::EntryThreadGeneration::from_raw(101),
                    },
                    5,
                )
                .unwrap();
            let root_state = custody
                .worker_root_state(&context_with_root(1, root_gpa).hardware_image())
                .unwrap();
            let root_binding = root_state.binding();
            let cpu = CarrierCpu::new(TestIo {
                image: root_state.hardware_image(),
            })
            .unwrap();
            let children = cpu.child_binding_authority();
            Self {
                _authority: authority,
                custody,
                cpu,
                children,
                root_binding,
            }
        }

        fn install_child_mm(
            &mut self,
            root_pa: u64,
            mm_raw: u64,
            ctx_gen: u64,
            task_serial: u64,
            exec_gen: u64,
        ) -> GuestArchBinding {
            let nz = |v| NonZeroU64::new(v).unwrap();
            let context = AddressContext {
                root: RootGpa::page_aligned(FrameGpa::new(root_pa)).unwrap(),
                mm: MmGeneration::new(nz(mm_raw)),
                generation: ContextGeneration::new(nz(ctx_gen)),
            };
            self.custody
                .memory_mut()
                .install_root(nz(mm_raw), context)
                .unwrap();
            GuestArchBinding::x86(
                carrick_guest_arch::TaskIdentity {
                    carrier: self.root_binding.task().carrier,
                    task: carrick_guest_arch::TaskSerial::new(nz(task_serial)),
                    execution: carrick_guest_arch::ExecutionGeneration::new(nz(exec_gen)),
                },
                context,
            )
        }

        fn stop_child_on_peer(
            &mut self,
            arch_binding: GuestArchBinding,
            entry_key: carrick_el1_abi::EntryTaskKey,
            thread_serial: u64,
        ) {
            let birth_serial = carrick_sched_core::process::TaskSerial::from_raw_u64(
                arch_binding.task().task.raw().get(),
            )
            .unwrap();
            self.custody
                .bind_execution(
                    1,
                    birth_serial,
                    carrick_el1_abi::ExecutionBinding {
                        task: entry_key,
                        generation: carrick_el1_abi::SnapshotGeneration::from_raw(
                            arch_binding.task().execution.raw().get(),
                        ),
                        mm: carrick_el1_abi::EntryMmKey::from_raw(
                            arch_binding.context().mm.raw().get(),
                        ),
                        thread_generation: carrick_el1_abi::EntryThreadGeneration::from_raw(
                            thread_serial,
                        ),
                    },
                    6,
                )
                .unwrap();
            self.custody
                .0
                .binding(carrick_guest_arch::CpuId::new(1))
                .mm_owner_generation
                .store(
                    arch_binding.context().generation.raw().get(),
                    Ordering::Release,
                );
        }

        fn stop_clone_vm_sibling_on_peer(
            &mut self,
            arch_binding: GuestArchBinding,
            leader_key: carrick_el1_abi::EntryTaskKey,
            sibling_key: carrick_el1_abi::EntryTaskKey,
            sibling_serial: u64,
        ) {
            self.stop_child_on_peer(arch_binding, leader_key, 102);
            let page_offset = 0x4000u64;
            let sibling_slot_offset = carrick_core_abi::X86_CPL0_ROOT_THREAD_CONTROLS_OFFSET;
            let sibling_tid = u32::try_from(sibling_key.raw()).unwrap();
            let birth_serial = carrick_sched_core::process::TaskSerial::from_raw_u64(
                arch_binding.task().task.raw().get(),
            )
            .unwrap();
            // SAFETY: stopped bootstrap metadata initialized in `new`/`stop_child_on_peer`
            // at disjoint offsets (`0x4000` lifecycle page vs `0xb000` pool control slot).
            let (page, sibling_control): (&ThreadLifecyclePage, &ThreadControlSlot) = unsafe {
                (
                    self.custody.metadata(page_offset),
                    self.custody.metadata(sibling_slot_offset),
                )
            };
            let entry = page
                .stock_with_control(
                    0,
                    carrick_el1_abi::EntryIdentity {
                        tid: sibling_tid,
                        visible_tid: sibling_tid,
                        thread_serial: sibling_serial,
                        birth: carrick_core_abi::BirthSerial::of_task(birth_serial),
                        uid_credit: 0,
                    },
                    Some(carrick_guest_arch::KernelVa::new(
                        METADATA_VA + sibling_slot_offset,
                    )),
                )
                .unwrap();
            sibling_control
                .reset_for_birth(BlockedMask(0), 0, entry)
                .unwrap();
            assert!(sibling_control.publish_visible_tid(sibling_tid));
            page.thread_born().unwrap();
            let task = self.custody.stopped_task(1);
            task.set(
                El1TaskId::from_linux_tid(sibling_tid as i32),
                carrick_el1_abi::SnapshotGeneration::from_raw(
                    arch_binding.task().execution.raw().get(),
                ),
                6,
            );
            task.mm
                .key
                .store(arch_binding.context().mm.raw().get(), Ordering::Release);
            task.mm
                .thread_generation
                .store(sibling_serial, Ordering::Release);
            task.publish_lifecycle(METADATA_VA + page_offset, METADATA_VA + sibling_slot_offset);
        }

        fn enter_venue(
            &mut self,
            slot: u32,
            cr3_root: RootGpa,
        ) -> Result<ForwardExecution, TrapError> {
            let mut io = TestIo {
                image: context_with_root(1, cr3_root).hardware_image(),
            };
            let lease = StoppedCpuLease {
                cpu: carrick_guest_arch::CpuId::new(slot),
                io: &mut io,
            };
            ForwardVenue::new(&mut self.custody.0, lease, &self.children)
                .map(|venue| venue.execution)
        }
    }

    #[test]
    fn forward_venue_names_another_child_entry_key_a_member() {
        let mut fx = ForwardVenueFixture::new();
        let root_exec = fx
            .enter_venue(0, fx.root_binding.context().root)
            .expect("issued root task enters forward venue");
        assert_eq!(root_exec.authenticate_typed(fx.root_binding), Ok(()));
        assert_eq!(root_exec.subject(), ForwardSubject::Leader);

        let child = fx.install_child_mm(0x7000, 302, 2, 12, 22);
        let issued = carrick_el1_abi::EntryTaskKey::from_raw(42);
        fx.cpu
            .register_child_binding_with_entry_task(child, issued)
            .unwrap();

        fx.stop_child_on_peer(child, issued, 102);
        let matching = fx.enter_venue(1, child.context().root).unwrap();
        assert_eq!(matching.authenticate_typed(child), Ok(()));
        assert_eq!(matching.subject(), ForwardSubject::Leader);

        let mismatched = carrick_el1_abi::EntryTaskKey::from_raw(45);
        fx.stop_child_on_peer(child, mismatched, 105);
        let execution = fx.enter_venue(1, child.context().root).unwrap();
        assert_eq!(execution.authenticate_typed(child), Ok(()));
        assert_eq!(
            execution.subject(),
            ForwardSubject::Member {
                leader: issued,
                stopped: mismatched,
            }
        );
    }

    /// #2780: a member of the run's root is the root's member, whatever key
    /// its own stopped record carries; it never becomes the leader.
    #[test]
    fn forward_venue_names_a_root_member_a_member() {
        let mut fx = ForwardVenueFixture::new();
        let root = fx.root_binding;
        let leader = carrick_el1_abi::EntryTaskKey::from_raw(41);
        let member = carrick_el1_abi::EntryTaskKey::from_raw(43);
        fx.stop_child_on_peer(root, member, 103);
        let execution = fx
            .enter_venue(1, root.context().root)
            .expect("a root member enters the forward venue");
        assert_eq!(execution.authenticate_typed(root), Ok(()));
        assert_eq!(
            execution.subject(),
            ForwardSubject::Member {
                leader,
                stopped: member,
            }
        );
    }

    /// #2832: an `execve` gives the process leader a new execution
    /// generation, and the root's registered binding carries it. A thread
    /// born after the exec has its own generation. The registered generation
    /// authenticates the leader only; a stale leader is still refused.
    #[test]
    fn a_member_keeps_its_own_generation_after_the_leader_execs() {
        let (leader, context) = execution();
        let cpu = carrick_guest_arch::CpuId::new(1);
        let member = carrick_el1_abi::ExecutionBinding {
            task: carrick_el1_abi::EntryTaskKey::from_raw(43),
            generation: carrick_el1_abi::SnapshotGeneration::from_raw(1),
            ..leader
        };
        let exec_successor = carrier_binding(context, leader.generation.raw() + 1);
        let stopped_member =
            admit_forward_execution(cpu, cpu, member, context, context.root, context.generation)
                .expect("an issued member is admitted")
                .with_leader_task(leader.task);
        assert_eq!(
            stopped_member.subject(),
            ForwardSubject::Member {
                leader: leader.task,
                stopped: member.task,
            }
        );
        assert_eq!(stopped_member.authenticate_typed(exec_successor), Ok(()));

        let stale_leader =
            admit_forward_execution(cpu, cpu, leader, context, context.root, context.generation)
                .expect("the leader is admitted");
        assert_eq!(
            stale_leader.authenticate_typed(exec_successor),
            Err(ForwardBindingRefusal::GenerationMismatch {
                stopped: leader.generation.raw(),
                registered: leader.generation.raw() + 1,
            })
        );
    }

    #[test]
    fn forward_venue_admits_child_exec_successor_only_with_carried_key() {
        let mut fx = ForwardVenueFixture::new();
        let predecessor = fx.install_child_mm(0x7000, 302, 2, 12, 22);
        let issued = carrick_el1_abi::EntryTaskKey::from_raw(42);
        fx.cpu
            .register_child_binding_with_entry_task(predecessor, issued)
            .unwrap();

        let successor = predecessor
            .exec_successor(fx.install_child_mm(0x8000, 303, 3, 12, 23))
            .unwrap();
        fx.cpu
            .rebind_child_successor(successor, Some(predecessor.context().root), false)
            .unwrap();

        fx.stop_child_on_peer(successor, issued, 202);
        let admitted = fx.enter_venue(1, successor.context().root).unwrap();
        assert_eq!(admitted.authenticate_typed(successor), Ok(()));

        let other = carrick_el1_abi::EntryTaskKey::from_raw(45);
        fx.stop_child_on_peer(successor, other, 203);
        let wrong_key = fx.enter_venue(1, successor.context().root).unwrap();
        assert_eq!(admitted.subject(), ForwardSubject::Leader);
        assert_eq!(
            wrong_key.subject(),
            ForwardSubject::Member {
                leader: issued,
                stopped: other,
            }
        );

        fx.stop_child_on_peer(predecessor, issued, 102);
        let retired_predecessor = fx
            .enter_venue(1, predecessor.context().root)
            .err()
            .expect("retired predecessor root has no issued entry key");
        assert!(
            retired_predecessor
                .to_string()
                .contains("child forward root has no issued entry key")
        );
    }

    #[test]
    fn forward_venue_refuses_unregistered_child_root() {
        let mut fx = ForwardVenueFixture::new();
        let unregistered = fx.install_child_mm(0x9000, 304, 2, 14, 24);
        assert_eq!(
            fx.children.entry_task(unregistered.context().root).unwrap(),
            None
        );

        fx.stop_child_on_peer(
            unregistered,
            carrick_el1_abi::EntryTaskKey::from_raw(42),
            102,
        );
        let err = fx
            .enter_venue(1, unregistered.context().root)
            .err()
            .expect("unregistered child root must be refused");
        assert!(
            err.to_string()
                .contains("child forward root has no issued entry key"),
            "unexpected error: {err}"
        );

        fx.cpu.register_child_binding(unregistered).unwrap();
        assert_eq!(
            fx.children.entry_task(unregistered.context().root).unwrap(),
            None
        );
        let keyless_err = fx
            .enter_venue(1, unregistered.context().root)
            .err()
            .expect("keyless child root must be refused");
        assert!(
            keyless_err
                .to_string()
                .contains("child forward root has no issued entry key"),
            "unexpected error: {keyless_err}"
        );
    }

    #[test]
    fn forward_venue_names_clone_vm_sibling_a_member_of_the_child_root() {
        let mut fx = ForwardVenueFixture::new();
        let child = fx.install_child_mm(0x7000, 302, 2, 12, 22);
        let issued = carrick_el1_abi::EntryTaskKey::from_raw(42);
        let sibling = carrick_el1_abi::EntryTaskKey::from_raw(43);
        fx.cpu
            .register_child_binding_with_entry_task(child, issued)
            .unwrap();

        fx.stop_clone_vm_sibling_on_peer(child, issued, sibling, 103);
        let execution = fx.enter_venue(1, child.context().root).unwrap();
        let member = ForwardSubject::Member {
            leader: issued,
            stopped: sibling,
        };
        assert_eq!(execution.subject(), member);
        assert_eq!(execution.binding.task, sibling);
        assert_eq!(execution.leader_task, issued);

        // Even if the sibling's own control slot carries a matching birth
        // record, no host-issued authority for this child root makes it the
        // leader.
        let sibling_slot_offset = carrick_core_abi::X86_CPL0_ROOT_THREAD_CONTROLS_OFFSET;
        let birth_serial =
            carrick_sched_core::process::TaskSerial::from_raw_u64(child.task().task.raw().get())
                .unwrap();
        let self_birth = carrick_core::terminal::ThreadBirthIdentity::from_parts(
            sibling,
            carrick_core_abi::BirthSerial::of_task(birth_serial),
            carrick_core_abi::EntryThreadGeneration::from_raw(103),
        )
        .unwrap();
        // SAFETY: stopped bootstrap metadata at the pool control-slot offset.
        unsafe {
            *fx.custody.metadata_mut(sibling_slot_offset) = ThreadControlSlot::new();
            let sibling_control: &ThreadControlSlot = fx.custody.metadata(sibling_slot_offset);
            sibling_control
                .reset_for_host_birth(BlockedMask(0))
                .unwrap();
            assert!(sibling_control.publish_visible_tid(43));
            sibling_control.publish_host_birth_identity(self_birth);
        }
        let execution_with_slot_birth = fx.enter_venue(1, child.context().root).unwrap();
        assert_eq!(execution_with_slot_birth.subject(), member);
    }

    #[test]
    fn child_forward_rule_uses_issued_entry_key() {
        let mm = MmGeneration::new(NonZeroU64::new(302).unwrap());
        let stopped = carrick_el1_abi::EntryTaskKey::from_raw(43);
        let issued = carrick_el1_abi::EntryTaskKey::from_raw(42);
        let leader = forward_leader_task(None, mm, Some(issued)).unwrap();
        assert_eq!(leader, issued);
        assert!(
            forward_leader_task(None, mm, None).is_err(),
            "a child root without an issued entry key has no leader"
        );
        let successor_mm = MmGeneration::new(NonZeroU64::new(303).unwrap());
        assert_eq!(
            forward_leader_task(None, successor_mm, Some(issued)).unwrap(),
            issued,
            "exec successor keeps the predecessor's registered child key"
        );
        let (binding, context) = execution();
        let sibling = carrick_el1_abi::ExecutionBinding {
            task: stopped,
            ..binding
        };
        let cpu = carrick_guest_arch::CpuId::new(1);
        let admitted =
            admit_forward_execution(cpu, cpu, sibling, context, context.root, context.generation)
                .unwrap()
                .with_leader_task(leader);
        assert_eq!(
            admitted.authenticate_typed(carrier_binding(context, 12)),
            Ok(())
        );
        assert_eq!(
            admitted.subject(),
            ForwardSubject::Member {
                leader: issued,
                stopped,
            }
        );
    }

    /// #2142: after a root `execve`, the forward leader rule names the run
    /// root's TID for the successor MM only; the predecessor MM is no longer
    /// the root's, and a stale predecessor cannot rebind it again.
    #[test]
    fn root_exec_moves_the_forward_leader_rule_to_the_successor_mm() {
        use carrick_hal::guest_arch_binding::GuestArchBinding;
        let nz = |raw| NonZeroU64::new(raw).expect("nonzero");
        let initial = InitialTaskBinding {
            task: carrick_sched_core::process::TaskKey {
                id: carrick_sched_core::process::TaskId::from_registry_allocation(
                    core::num::NonZeroI32::new(41).expect("task id"),
                ),
                serial: carrick_sched_core::process::TaskSerial::from_raw_u64(7)
                    .expect("task serial"),
            },
            thread: carrick_sched_core::ThreadIdentity {
                tid: 41,
                serial: 101,
                generation: 1,
                file_table: 5,
                ..Default::default()
            },
            mm: MmGeneration::new(nz(302)),
        };
        let task = |execution| carrick_guest_arch::TaskIdentity {
            carrier: carrick_guest_arch::CarrierGeneration::new(nz(1)),
            task: carrick_guest_arch::TaskSerial::new(nz(7)),
            execution: carrick_guest_arch::ExecutionGeneration::new(nz(execution)),
        };
        let context = |root, mm, generation| AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(root)).expect("aligned root"),
            mm: MmGeneration::new(nz(mm)),
            generation: ContextGeneration::new(nz(generation)),
        };
        let predecessor = GuestArchBinding::x86(task(1), context(0x7000, 302, 9));
        let successor = GuestArchBinding::x86(task(1), context(0x9000, 303, 10));
        let child_key = carrick_el1_abi::EntryTaskKey::from_raw(42);
        assert_eq!(
            forward_leader_task(Some(initial), MmGeneration::new(nz(302)), None).unwrap(),
            carrick_el1_abi::EntryTaskKey::from_raw(41)
        );

        let replaced = initial
            .exec_successor(predecessor, successor, 202)
            .expect("exec successor of the exact root");
        assert_eq!(replaced.mm, successor.context().mm);
        assert_eq!(replaced.thread.tid, 41, "exec keeps the root's TID");
        assert_eq!(replaced.thread.serial, 202);
        assert_eq!(replaced.task, initial.task);
        assert_eq!(
            forward_leader_task(Some(replaced), MmGeneration::new(nz(303)), None).unwrap(),
            carrick_el1_abi::EntryTaskKey::from_raw(41)
        );
        assert_eq!(
            forward_leader_task(Some(replaced), MmGeneration::new(nz(303)), Some(child_key))
                .unwrap(),
            carrick_el1_abi::EntryTaskKey::from_raw(41),
            "another task's key cannot lead the run root"
        );
        assert_eq!(
            forward_leader_task(Some(replaced), MmGeneration::new(nz(302)), Some(child_key))
                .unwrap(),
            child_key,
            "the predecessor MM is no longer the root's"
        );
        assert!(
            replaced
                .exec_successor(predecessor, successor, 303)
                .is_err(),
            "a stale predecessor cannot rebind the replaced root"
        );
        assert!(
            initial
                .exec_successor(predecessor, predecessor, 202)
                .is_err(),
            "exec replaces the MM"
        );
    }

    #[test]
    fn complete_host_file_enforces_window_slot_budget_and_skips_unadmitted_inode() {
        use carrick_core::mm::window::WINDOW_CHUNK_BYTES;
        use carrick_core_abi::host_file::{
            HostFileHeader, HostFileOp, HostFileRequestView, MapSourceReply, encode, record_len,
            reply,
        };
        use carrick_hal::fork_stock::{
            HostBackingRead, HostBackingReadError, HostBackingRetention,
        };
        use std::os::fd::AsFd;

        struct FileSource {
            identity: carrick_el1_abi::HostBackingIdentity,
            file: std::fs::File,
        }
        impl HostBackingRetention for FileSource {
            fn identity(&self) -> carrick_el1_abi::HostBackingIdentity {
                self.identity
            }
            fn read(&self, _: HostBackingRead) -> Result<Vec<u8>, HostBackingReadError> {
                Err(HostBackingReadError::Unavailable)
            }
            fn host_file(&self) -> Option<std::os::fd::OwnedFd> {
                self.file.as_fd().try_clone_to_owned().ok()
            }
            fn host_file_metadata(&self) -> Option<carrick_hal::fork_stock::HostFileMetadata> {
                use std::os::unix::fs::MetadataExt;
                self.file
                    .metadata()
                    .ok()
                    .map(|meta| carrick_hal::fork_stock::HostFileMetadata {
                        device: meta.dev(),
                        inode: meta.ino(),
                        len: meta.len(),
                    })
            }
        }

        let path = std::env::temp_dir().join(format!(
            "carrick-complete-host-file-budget-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        file.set_len(WINDOW_CHUNK_BYTES * 8).unwrap();

        let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
        let live_pins = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        struct TrackedPin {
            _pin: Arc<dyn std::any::Any + Send + Sync>,
            live: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl Drop for TrackedPin {
            fn drop(&mut self) {
                self.live.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            }
        }
        let admit = |fd: std::os::fd::BorrowedFd<'_>| {
            let pin = dispatcher.admit_window_inode(fd)?;
            live_pins.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            Some(Arc::new(TrackedPin {
                _pin: pin,
                live: Arc::clone(&live_pins),
            }) as Arc<dyn std::any::Any + Send + Sync>)
        };

        let mut fx = ForwardVenueFixture::with_pod();
        let context = fx.root_binding.context();
        let root = context.root;
        let pod_va = carrick_guest_arch::KernelVa::new(X86_CPL0_BOOTSTRAP_METADATA_BASE);
        let pod_gpa = FrameGpa::new(ALLOCATOR_GPA);
        {
            use carrick_mmu_core::x86::descriptor_txn::{NX, PRESENT, WRITE};
            let va = pod_va.raw();
            let pdpt = 0x3000u64;
            let pd = 0x4000u64;
            let pt = 0x5000u64;
            let mut write_pte = |table: u64, shift: u32, entry: u64| {
                let offset = ((va >> shift) & 0x1ff) * 8;
                fx.custody
                    .0
                    ._vm
                    .write(FrameGpa::new(table + offset), &entry.to_le_bytes())
                    .unwrap();
            };
            write_pte(root.address().raw(), 39, pdpt | PRESENT | WRITE);
            write_pte(pdpt, 30, pd | PRESENT | WRITE);
            write_pte(pd, 21, pt | PRESENT | WRITE);
            write_pte(pt, 12, pod_gpa.raw() | PRESENT | WRITE | NX);
        }
        let available = fx.custody.0._vm.available_window_slots();
        assert!(available > 4);

        let make_record = |offset: u64, len: u64, handle_num: u64| {
            let mut bytes = vec![0u8; record_len(0, MapSourceReply::BYTES).unwrap()];
            encode(
                &mut bytes,
                HostFileHeader {
                    op: HostFileOp::MapShared,
                    table: [1, 2, 3],
                    fd: 4,
                    flags: 0,
                    args: [offset, len, 0, 0],
                },
                &[],
                MapSourceReply::BYTES,
            )
            .unwrap();
            let id = carrick_el1_abi::HostBackingIdentity::new(
                NonZeroU64::new(handle_num).unwrap(),
                NonZeroU64::MIN,
                0,
            );
            let encoded = MapSourceReply {
                handle: id.handle(),
                generation: id.generation(),
            }
            .encode();
            HostFileRequestView::parse(&mut bytes)
                .unwrap()
                .reply(0, &encoded)
                .unwrap();
            let source: Arc<dyn HostBackingRetention> = Arc::new(FileSource {
                identity: id,
                file: file.try_clone().unwrap(),
            });
            (bytes, id, source)
        };

        // 1. Oversized MapShared exceeding available_window_slots is refused with
        // counted-side ENOSYS, leaves GPA and window_slots unchanged, never admits
        // the inode to the shrink fence, and never retains the source.
        let (mut bytes, refused_id, refused_source) =
            make_record(0, (available as u64 + 1) * WINDOW_CHUNK_BYTES, 10);
        fx.custody.0._vm.write(pod_gpa, &bytes).unwrap();
        {
            let mut io = TestIo {
                image: context_with_root(1, root).hardware_image(),
            };
            let lease = StoppedCpuLease {
                cpu: carrick_guest_arch::CpuId::new(0),
                io: &mut io,
            };
            let mut venue = ForwardVenue::new(&mut fx.custody.0, lease, &fx.children).unwrap();
            let mut admitted_called = false;
            venue
                .complete_host_file(pod_va, &mut bytes, Some(refused_source), |fd| {
                    admitted_called = true;
                    admit(fd)
                })
                .unwrap();
            assert!(!admitted_called, "refused mapping must not pin inode");
        }
        let guest_bytes = fx.custody.0._vm.read(pod_gpa, bytes.len()).unwrap();
        let refused_reply = reply(&guest_bytes).unwrap();
        assert_eq!(
            refused_reply.result,
            carrick_abi::LINUX_ENOSYS.guest_retval()
        );
        assert!(refused_reply.output.is_empty());
        assert_eq!(fx.custody.0._vm.window_slots(), 0);
        assert_eq!(
            fx.custody.0.anonymous_next_gpa,
            FrameGpa::new(DYNAMIC_GRANT_GPA)
        );
        assert!(
            !fx.custody
                .0
                .sources_mut(context)
                .unwrap()
                .is_window(refused_id)
        );

        // 2. MapShared within budget admits the inode once, installs two chunk
        // slots, advances anonymous_next_gpa, and inherits the window source.
        let (mut bytes, ok_id, ok_source) = make_record(0, 2 * WINDOW_CHUNK_BYTES, 11);
        fx.custody.0._vm.write(pod_gpa, &bytes).unwrap();
        {
            let mut io = TestIo {
                image: context_with_root(1, root).hardware_image(),
            };
            let lease = StoppedCpuLease {
                cpu: carrick_guest_arch::CpuId::new(0),
                io: &mut io,
            };
            let mut venue = ForwardVenue::new(&mut fx.custody.0, lease, &fx.children).unwrap();
            let mut admitted_called = false;
            venue
                .complete_host_file(pod_va, &mut bytes, Some(ok_source), |fd| {
                    admitted_called = true;
                    admit(fd)
                })
                .unwrap();
            assert!(admitted_called);
            assert_eq!(live_pins.load(std::sync::atomic::Ordering::Acquire), 1);
        }
        let guest_bytes = fx.custody.0._vm.read(pod_gpa, bytes.len()).unwrap();
        assert_eq!(reply(&guest_bytes).unwrap().result, 0);
        assert_eq!(fx.custody.0._vm.window_slots(), 2);
        assert_eq!(
            fx.custody.0.anonymous_next_gpa,
            FrameGpa::new(DYNAMIC_GRANT_GPA + 2 * WINDOW_CHUNK_BYTES)
        );
        assert!(fx.custody.0.sources_mut(context).unwrap().is_window(ok_id));

        // 3. Re-mapping an already-installed chunk consumes zero slots.
        let (mut bytes, reuse_id, reuse_source) = make_record(0, WINDOW_CHUNK_BYTES, 12);
        fx.custody.0._vm.write(pod_gpa, &bytes).unwrap();
        {
            let mut io = TestIo {
                image: context_with_root(1, root).hardware_image(),
            };
            let lease = StoppedCpuLease {
                cpu: carrick_guest_arch::CpuId::new(0),
                io: &mut io,
            };
            let mut venue = ForwardVenue::new(&mut fx.custody.0, lease, &fx.children).unwrap();
            let mut admitted_called = false;
            venue
                .complete_host_file(pod_va, &mut bytes, Some(reuse_source), |fd| {
                    admitted_called = true;
                    admit(fd)
                })
                .unwrap();
            assert!(
                !admitted_called,
                "cached chunk reuse needs no new inode pin"
            );
            assert_eq!(live_pins.load(std::sync::atomic::Ordering::Acquire), 1);
        }
        let guest_bytes = fx.custody.0._vm.read(pod_gpa, bytes.len()).unwrap();
        assert_eq!(reply(&guest_bytes).unwrap().result, 0);
        assert_eq!(fx.custody.0._vm.window_slots(), 2);
        assert_eq!(
            fx.custody.0.anonymous_next_gpa,
            FrameGpa::new(DYNAMIC_GRANT_GPA + 2 * WINDOW_CHUNK_BYTES)
        );
        assert!(
            fx.custody
                .0
                .sources_mut(context)
                .unwrap()
                .is_window(reuse_id)
        );

        // 4. Recoverable slot install failure returns ENOSYS cleanly without
        // leaking window_slots, anonymous_next_gpa, or sources.
        let (mut bytes, err_id, err_source) =
            make_record(2 * WINDOW_CHUNK_BYTES, 2 * WINDOW_CHUNK_BYTES, 13);
        fx.custody.0._vm.write(pod_gpa, &bytes).unwrap();
        fx.custody.0._vm.vm().fail_region_call(1);
        {
            let mut io = TestIo {
                image: context_with_root(1, root).hardware_image(),
            };
            let lease = StoppedCpuLease {
                cpu: carrick_guest_arch::CpuId::new(0),
                io: &mut io,
            };
            let mut venue = ForwardVenue::new(&mut fx.custody.0, lease, &fx.children).unwrap();
            venue
                .complete_host_file(pod_va, &mut bytes, Some(err_source), admit)
                .unwrap();
        }
        fx.custody.0._vm.vm().clear_region_failure();
        let guest_bytes = fx.custody.0._vm.read(pod_gpa, bytes.len()).unwrap();
        let err_reply = reply(&guest_bytes).unwrap();
        assert_eq!(err_reply.result, carrick_abi::LINUX_ENOSYS.guest_retval());
        assert!(err_reply.output.is_empty());
        assert_eq!(fx.custody.0._vm.window_slots(), 2);
        assert_eq!(
            fx.custody.0.anonymous_next_gpa,
            FrameGpa::new(DYNAMIC_GRANT_GPA + 2 * WINDOW_CHUNK_BYTES)
        );
        assert!(!fx.custody.0.sources_mut(context).unwrap().is_window(err_id));
        assert_eq!(
            live_pins.load(std::sync::atomic::Ordering::Acquire),
            1,
            "failed slot installation must release its shrink-fence pin immediately (#2975 P0 2)"
        );

        // 5. Carrier teardown unmaps extents and drops all remaining shrink-fence pins.
        drop(fx);
        assert_eq!(
            live_pins.load(std::sync::atomic::Ordering::Acquire),
            0,
            "carrier teardown must release all shrink-fence pins (#2975 P0 2)"
        );
    }

    #[test]
    fn capture_host_file_release_window_rolls_back_unplaced_slots_and_preserves_shared_holders() {
        use carrick_core::mm::window::WINDOW_CHUNK_BYTES;
        use carrick_core_abi::host_file::{
            HostFileHeader, HostFileOp, HostFileRequestView, MapSourceReply, encode, record_len,
            reply,
        };
        use carrick_hal::fork_stock::{
            HostBackingRead, HostBackingReadError, HostBackingRetention,
        };
        use carrick_mmu_core::x86::descriptor_txn::{NX, PRESENT, WRITE};
        use std::os::fd::AsFd;

        struct FileSource {
            identity: carrick_el1_abi::HostBackingIdentity,
            file: std::fs::File,
        }
        impl HostBackingRetention for FileSource {
            fn identity(&self) -> carrick_el1_abi::HostBackingIdentity {
                self.identity
            }
            fn read(&self, _: HostBackingRead) -> Result<Vec<u8>, HostBackingReadError> {
                Err(HostBackingReadError::Unavailable)
            }
            fn host_file(&self) -> Option<std::os::fd::OwnedFd> {
                self.file.as_fd().try_clone_to_owned().ok()
            }
            fn host_file_metadata(&self) -> Option<carrick_hal::fork_stock::HostFileMetadata> {
                use std::os::unix::fs::MetadataExt;
                self.file
                    .metadata()
                    .ok()
                    .map(|meta| carrick_hal::fork_stock::HostFileMetadata {
                        device: meta.dev(),
                        inode: meta.ino(),
                        len: meta.len(),
                    })
            }
        }

        let path = std::env::temp_dir().join(format!(
            "carrick-release-window-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        file.set_len(WINDOW_CHUNK_BYTES * 4).unwrap();

        let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
        let live_pins = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        struct TrackedPin {
            _pin: Arc<dyn std::any::Any + Send + Sync>,
            live: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl Drop for TrackedPin {
            fn drop(&mut self) {
                self.live.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            }
        }
        let admit = |fd: std::os::fd::BorrowedFd<'_>| {
            let pin = dispatcher.admit_window_inode(fd)?;
            live_pins.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            Some(Arc::new(TrackedPin {
                _pin: pin,
                live: Arc::clone(&live_pins),
            }) as Arc<dyn std::any::Any + Send + Sync>)
        };

        let mut fx = ForwardVenueFixture::with_pod();
        let context = fx.root_binding.context();
        let root = context.root;
        let pod_va = carrick_guest_arch::KernelVa::new(X86_CPL0_BOOTSTRAP_METADATA_BASE);
        let pod_gpa = FrameGpa::new(ALLOCATOR_GPA);
        {
            let va = pod_va.raw();
            let mut write_pte = |table: u64, shift: u32, entry: u64| {
                let offset = ((va >> shift) & 0x1ff) * 8;
                fx.custody
                    .0
                    ._vm
                    .write(FrameGpa::new(table + offset), &entry.to_le_bytes())
                    .unwrap();
            };
            write_pte(root.address().raw(), 39, 0x3000 | PRESENT | WRITE);
            write_pte(0x3000, 30, 0x4000 | PRESENT | WRITE);
            write_pte(0x4000, 21, 0x5000 | PRESENT | WRITE);
            write_pte(0x5000, 12, pod_gpa.raw() | PRESENT | WRITE | NX);
        }
        let initial_avail = fx.custody.0._vm.available_window_slots();

        let install_map =
            |fx: &mut ForwardVenueFixture, offset: u64, len: u64, h: u64, input: &[u8]| {
                let mut bytes = vec![0u8; record_len(input.len(), MapSourceReply::BYTES).unwrap()];
                encode(
                    &mut bytes,
                    HostFileHeader {
                        op: HostFileOp::MapShared,
                        table: [1, 2, 3],
                        fd: 4,
                        flags: 0,
                        args: [offset, len, 0, 0],
                    },
                    input,
                    MapSourceReply::BYTES,
                )
                .unwrap();
                fx.custody.0._vm.write(pod_gpa, &bytes).unwrap();
                {
                    let mut io = TestIo {
                        image: context_with_root(1, root).hardware_image(),
                    };
                    let lease = StoppedCpuLease {
                        cpu: carrick_guest_arch::CpuId::new(0),
                        io: &mut io,
                    };
                    let mut venue =
                        ForwardVenue::new(&mut fx.custody.0, lease, &fx.children).unwrap();
                    bytes = venue.capture_host_file(pod_va, bytes.len()).unwrap();
                }
                let id = carrick_el1_abi::HostBackingIdentity::new(
                    NonZeroU64::new(h).unwrap(),
                    NonZeroU64::MIN,
                    0,
                );
                let encoded = MapSourceReply {
                    handle: id.handle(),
                    generation: id.generation(),
                }
                .encode();
                HostFileRequestView::parse(&mut bytes)
                    .unwrap()
                    .reply(0, &encoded)
                    .unwrap();
                let source: Arc<dyn HostBackingRetention> = Arc::new(FileSource {
                    identity: id,
                    file: file.try_clone().unwrap(),
                });
                fx.custody.0._vm.write(pod_gpa, &bytes).unwrap();
                {
                    let mut io = TestIo {
                        image: context_with_root(1, root).hardware_image(),
                    };
                    let lease = StoppedCpuLease {
                        cpu: carrick_guest_arch::CpuId::new(0),
                        io: &mut io,
                    };
                    let mut venue =
                        ForwardVenue::new(&mut fx.custody.0, lease, &fx.children).unwrap();
                    venue
                        .complete_host_file(pod_va, &mut bytes, Some(source), admit)
                        .unwrap();
                }
                id
            };

        let send_release = |fx: &mut ForwardVenueFixture,
                            id: carrick_el1_abi::HostBackingIdentity| {
            let mut bytes = vec![0u8; record_len(0, 0).unwrap()];
            encode(
                &mut bytes,
                HostFileHeader {
                    op: HostFileOp::ReleaseWindow,
                    table: [0; 3],
                    fd: -1,
                    flags: 0,
                    args: [id.handle().get(), id.generation().get(), 0, 0],
                },
                &[],
                0,
            )
            .unwrap();
            fx.custody.0._vm.write(pod_gpa, &bytes).unwrap();
            let mut io = TestIo {
                image: context_with_root(1, root).hardware_image(),
            };
            let lease = StoppedCpuLease {
                cpu: carrick_guest_arch::CpuId::new(0),
                io: &mut io,
            };
            let mut venue = ForwardVenue::new(&mut fx.custody.0, lease, &fx.children).unwrap();
            let mut captured = venue.capture_host_file(pod_va, bytes.len()).unwrap();
            venue
                .complete_host_file(pod_va, &mut captured, None, |_fd| None)
                .unwrap();
            let guest_bytes = fx.custody.0._vm.read(pod_gpa, captured.len()).unwrap();
            assert_eq!(reply(&guest_bytes).unwrap().result, 0);
        };

        // 1. Single unplaced two-chunk mapping rolls back completely: slots=0,
        // tail GPA rewinds to start, source released, shrink-fence pin dropped.
        let id1 = install_map(&mut fx, 0, 2 * WINDOW_CHUNK_BYTES, 31, &[]);
        assert_eq!(fx.custody.0._vm.window_slots(), 2);
        assert_eq!(live_pins.load(std::sync::atomic::Ordering::Acquire), 1);
        send_release(&mut fx, id1);
        assert_eq!(fx.custody.0._vm.window_slots(), 0);
        assert_eq!(fx.custody.0._vm.available_window_slots(), initial_avail);
        assert_eq!(
            fx.custody.0.anonymous_next_gpa,
            FrameGpa::new(DYNAMIC_GRANT_GPA)
        );
        assert_eq!(live_pins.load(std::sync::atomic::Ordering::Acquire), 0);
        assert!(!fx.custody.0.sources_mut(context).unwrap().is_window(id1));

        // 2. Overlapping holder: id_a covers chunk 0, id_b covers chunks 0..2.
        // Rolling back id_b keeps shared chunk 0 alive, revokes chunk 1, and
        // rewinds tail GPA to DYNAMIC_GRANT_GPA + WINDOW_CHUNK_BYTES.
        let id_a = install_map(&mut fx, 0, WINDOW_CHUNK_BYTES, 32, &[]);
        let id_b = install_map(&mut fx, 0, 2 * WINDOW_CHUNK_BYTES, 33, &[]);
        assert_eq!(fx.custody.0._vm.window_slots(), 2);
        assert_eq!(live_pins.load(std::sync::atomic::Ordering::Acquire), 2);
        send_release(&mut fx, id_b);
        assert_eq!(fx.custody.0._vm.window_slots(), 1);
        assert_eq!(live_pins.load(std::sync::atomic::Ordering::Acquire), 1);
        assert_eq!(
            fx.custody.0.anonymous_next_gpa,
            FrameGpa::new(DYNAMIC_GRANT_GPA + WINDOW_CHUNK_BYTES)
        );
        assert!(fx.custody.0.sources_mut(context).unwrap().is_window(id_a));

        // 3. Releasing a previously committed holder via MapSourceReply::decode_releases
        // marks chunk 0 committed so a later ReleaseWindow does not revoke it.
        let rel_bytes = MapSourceReply {
            handle: id_a.handle(),
            generation: id_a.generation(),
        }
        .encode();
        let id_c = install_map(&mut fx, 0, WINDOW_CHUNK_BYTES, 34, &rel_bytes);
        send_release(&mut fx, id_c);
        send_release(&mut fx, id_a);
        assert_eq!(fx.custody.0._vm.window_slots(), 1);
        assert_eq!(live_pins.load(std::sync::atomic::Ordering::Acquire), 1);

        drop(fx);
        assert_eq!(live_pins.load(std::sync::atomic::Ordering::Acquire), 0);
    }

    #[test]
    fn service_native_notice_treats_raced_window_publication_as_supplied() {
        use carrick_core::mm::window::WINDOW_CHUNK_BYTES;
        use carrick_core_abi::host_file::{
            HostFileHeader, HostFileOp, HostFileRequestView, MapSourceReply, encode, record_len,
        };
        use carrick_core_abi::service::{
            ServiceBirth, ServiceOperation, ServiceOrigin, ServiceResult, ServiceSelector,
        };
        use carrick_el1_abi::{
            PortalOperation, ReservationIncarnation, ReservationMm, ReservationProtection,
            ReservationRange,
        };
        use carrick_guest_arch::FaultInfo;
        use carrick_hal::fork_stock::{
            HostBackingRead, HostBackingReadError, HostBackingRetention,
        };
        use carrick_mmu_core::x86::descriptor_txn::{NX, PRESENT, USER, WRITE};
        use std::os::fd::AsFd;

        struct FileSource {
            identity: carrick_el1_abi::HostBackingIdentity,
            file: std::fs::File,
        }
        impl HostBackingRetention for FileSource {
            fn identity(&self) -> carrick_el1_abi::HostBackingIdentity {
                self.identity
            }
            fn read(&self, _: HostBackingRead) -> Result<Vec<u8>, HostBackingReadError> {
                Err(HostBackingReadError::Unavailable)
            }
            fn host_file(&self) -> Option<std::os::fd::OwnedFd> {
                self.file.as_fd().try_clone_to_owned().ok()
            }
            fn host_file_metadata(&self) -> Option<carrick_hal::fork_stock::HostFileMetadata> {
                use std::os::unix::fs::MetadataExt;
                self.file
                    .metadata()
                    .ok()
                    .map(|meta| carrick_hal::fork_stock::HostFileMetadata {
                        device: meta.dev(),
                        inode: meta.ino(),
                        len: meta.len(),
                    })
            }
        }
        fn dummy_entropy(
            _: &mut [u8],
        ) -> Result<(), carrick_core_abi::service::entropy::InvalidEntropyRecord> {
            Ok(())
        }

        let path = std::env::temp_dir().join(format!(
            "carrick-native-raced-window-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        file.set_len(WINDOW_CHUNK_BYTES).unwrap();

        let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
        let mut fx = ForwardVenueFixture::with_pod();
        fx.custody.0.bind_grant_portal().unwrap();
        let context = fx.root_binding.context();
        let root = context.root;
        let carrier_id = fx.custody.0._vm.identity().nonzero();
        let fault_va = 0x1000_0000u64;
        let pod_va = carrick_guest_arch::KernelVa::new(X86_CPL0_BOOTSTRAP_METADATA_BASE);
        let pod_gpa = FrameGpa::new(ALLOCATOR_GPA);
        let control_va = METADATA_VA + CONTROL_OFFSET;
        let control_gpa = META_GPA + CONTROL_OFFSET;
        {
            let mut write_pte = |table: u64, va: u64, shift: u32, entry: u64| {
                let offset = ((va >> shift) & 0x1ff) * 8;
                fx.custody
                    .0
                    ._vm
                    .write(FrameGpa::new(table + offset), &entry.to_le_bytes())
                    .unwrap();
            };
            // Kernel PDPT/PD at 0x3000/0x4000, separate PTs for pod_va (0x5000) and control (0x6000).
            write_pte(
                root.address().raw(),
                pod_va.raw(),
                39,
                0x3000 | PRESENT | WRITE,
            );
            write_pte(0x3000, pod_va.raw(), 30, 0x4000 | PRESENT | WRITE);
            write_pte(0x4000, pod_va.raw(), 21, 0x5000 | PRESENT | WRITE);
            write_pte(
                0x5000,
                pod_va.raw(),
                12,
                pod_gpa.raw() | PRESENT | WRITE | NX,
            );
            write_pte(0x4000, control_va, 21, 0x6000 | PRESENT | WRITE);
            write_pte(0x6000, control_va, 12, control_gpa | PRESENT | WRITE | NX);
            // User PT hierarchy at 0x7000/0x8000/0x9000 with an already-present leaf at fault_va
            // modelling a peer CPU publishing into the fault window before native service plans it.
            write_pte(
                root.address().raw(),
                fault_va,
                39,
                0x7000 | PRESENT | WRITE | USER,
            );
            write_pte(0x7000, fault_va, 30, 0x8000 | PRESENT | WRITE | USER);
            write_pte(0x8000, fault_va, 21, 0x9000 | PRESENT | WRITE | USER);
            write_pte(0x9000, fault_va, 12, 0x1_0000 | PRESENT | WRITE | USER);
        }

        // Admit a shared file window slot and host backing identity.
        let id = carrick_el1_abi::HostBackingIdentity::new(
            NonZeroU64::new(51).unwrap(),
            NonZeroU64::MIN,
            0,
        );
        let mut bytes = vec![0u8; record_len(0, MapSourceReply::BYTES).unwrap()];
        encode(
            &mut bytes,
            HostFileHeader {
                op: HostFileOp::MapShared,
                table: [1, 2, 3],
                fd: 4,
                flags: 0,
                args: [0, WINDOW_CHUNK_BYTES, 0, 0],
            },
            &[],
            MapSourceReply::BYTES,
        )
        .unwrap();
        HostFileRequestView::parse(&mut bytes)
            .unwrap()
            .reply(
                0,
                &MapSourceReply {
                    handle: id.handle(),
                    generation: id.generation(),
                }
                .encode(),
            )
            .unwrap();
        let source: Arc<dyn HostBackingRetention> = Arc::new(FileSource {
            identity: id,
            file: file.try_clone().unwrap(),
        });
        fx.custody.0._vm.write(pod_gpa, &bytes).unwrap();
        {
            let mut io = TestIo {
                image: context_with_root(1, root).hardware_image(),
            };
            let lease = StoppedCpuLease {
                cpu: carrick_guest_arch::CpuId::new(0),
                io: &mut io,
            };
            let mut venue = ForwardVenue::new(&mut fx.custody.0, lease, &fx.children).unwrap();
            venue
                .complete_host_file(pod_va, &mut bytes, Some(source), |fd| {
                    dispatcher.admit_window_inode(fd)
                })
                .unwrap();
        }
        // Clear the pod reply page before reusing pod_va for the fault reply slot.
        fx.custody.0._vm.write(pod_gpa, &vec![0u8; 4096]).unwrap();

        // Publish zone membership, service cell request, portal selection, and notice.
        let mm_key = INITIAL_MM_KEY;
        let ram = Arc::clone(&fx.custody.0.ram);
        let zone_ptr = ram
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            )
            .unwrap();
        let zone = unsafe { &*zone_ptr.cast::<X86Cpl0Zone>() };
        let space_idx = zone
            .spaces
            .publish_closed(mm_key, root.address().raw(), root.address().raw())
            .unwrap();
        let entry = zone.space_entry(NonZeroU64::new(mm_key).unwrap()).unwrap();
        entry
            .admit_notifications(
                NonZeroU64::MIN,
                &carrick_sched_core::BoundedSpin(0),
                &|_| {},
            )
            .unwrap();
        let wake_no_delivery = |_z: &X86Cpl0Zone,
                                _w: Waker,
                                _o: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| {};
        carrick_sched_core::spaces::notification::SpaceAccess::notified(SpaceReleaseVenue {
            zone,
            waker: Waker::Host,
            deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                &wake_no_delivery,
            ),
        })
        .open(space_idx);
        let record_id = zone
            .alloc_record(carrick_sched_core::ThreadIdentity {
                tid: 41,
                serial: 101,
                mm: mm_key,
                file_table: 5,
                generation: 11,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 1,
                lifecycle_page: METADATA_VA,
                control_slot: control_va,
            })
            .unwrap();
        let record = zone.record_ref(record_id);
        assert!(zone.mark_native_owned(record_id));
        let service_key =
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(record).unwrap();
        zone.bind_object_wait(service_key, &carrick_sched_core::ShortLockSpin, &|_| {})
            .unwrap();
        unsafe {
            zone.record(record_id)
                .publish_owner_continuation(carrick_sched_core::object_wait::OwnerEntry::Syscall);
        }

        let control_ptr = ram
            .host_ptr(META_GPA + CONTROL_OFFSET, size_of::<ThreadControlSlot>())
            .unwrap();
        let control: &ThreadControlSlot = unsafe { &*control_ptr.cast::<ThreadControlSlot>() };
        control.bind_zone_record(record);
        let member_custody =
            carrick_core::lifecycle::MemberControlCustody::retain(control).unwrap();
        member_custody.commit_registration();
        member_custody.commit_native_signal_owner();
        let mm_handle = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                carrier_id,
                ReservationMm::new(mm_key).unwrap(),
                NonZeroU64::MIN,
            )
        };
        let birth = ServiceBirth {
            origin: ServiceOrigin::Initial,
            process: carrick_sched_core::process::TaskKey {
                id: carrick_sched_core::process::TaskId::from_registry_allocation(
                    core::num::NonZeroI32::new(41).unwrap(),
                ),
                serial: carrick_sched_core::process::TaskSerial::from_raw_u64(7).unwrap(),
            },
            thread: carrick_el1_abi::EntryThreadGeneration::from_raw(101),
            record,
            mm: mm_handle,
        };
        control.service.bind(birth).unwrap();
        let fault_seq = NonZeroU64::MIN;
        let req = control
            .service
            .publish_with_reply(
                birth,
                carrick_el1_abi::SnapshotGeneration::from_raw(11),
                ServiceOperation::Fault(FaultInfo {
                    address: UserVa::new(fault_va),
                    access: carrick_guest_arch::Access::Read,
                    present: false,
                }),
                Some(fault_seq),
                Some(pod_va),
            )
            .unwrap();
        let window = carrick_el1_abi::PortalGrantWindow {
            operation: PortalOperation {
                carrier: carrier_id,
                mm: ReservationMm::new(mm_key).unwrap(),
                incarnation: NonZeroU64::MIN,
                sequence: fault_seq,
            },
            mapping_incarnation: ReservationIncarnation::new(1).unwrap(),
            range: ReservationRange::new(fault_va, fault_va + 4096).unwrap(),
            protection: ReservationProtection::READ_WRITE,
            fault_page: fault_va,
            host_backing: Some(id),
            fork_sequence: None,
        };
        assert!(
            fx.custody
                .0
                .grant_portal()
                .unwrap()
                .grant(0)
                .unwrap()
                .publish_fault_selection(fault_seq.get(), window)
        );
        fx.custody
            .0
            .task(carrick_guest_arch::CpuId::new(0))
            .service_notice
            .publish(ServiceSelector::from(req.identity))
            .unwrap();

        // Read the file supply outside carrier custody and service the native notice
        // via the exact production methods.
        let mut io = TestIo {
            image: context_with_root(1, root).hardware_image(),
        };
        let lease = StoppedCpuLease {
            cpu: carrick_guest_arch::CpuId::new(0),
            io: &mut io,
        };
        let supply = fx
            .custody
            .0
            .file_supply_request(&lease, true)
            .unwrap()
            .map(|r| r.read().unwrap());
        let step = fx
            .custody
            .0
            .service_native_notice(&lease, supply, dummy_entropy)
            .expect("raced native fault publication must settle for rerun, not fail the carrier (#2975 P0 7)");
        assert!(matches!(
            step,
            anonymous_owner::native_service::NativeNoticeStep::Settled
        ));
        assert_eq!(
            control.service.consume(req.identity),
            Ok(ServiceResult::Supplied),
            "raced window fault must complete as Supplied so the ring retries the user copy (#2975 P0 7)"
        );
        drop(member_custody);
    }

    #[test]
    fn complete_host_file_and_fault_supply_handle_unavailable_host_fd_gracefully() {
        use carrick_core::mm::window::WINDOW_CHUNK_BYTES;
        use carrick_core_abi::host_file::{
            HostFileHeader, HostFileOp, HostFileRequestView, MapSourceReply, encode, record_len,
            reply,
        };
        use carrick_core_abi::service::{
            ServiceBirth, ServiceOperation, ServiceOrigin, ServiceSelector,
        };
        use carrick_el1_abi::{
            PortalOperation, ReservationIncarnation, ReservationMm, ReservationProtection,
            ReservationRange,
        };
        use carrick_guest_arch::FaultInfo;
        use carrick_hal::fork_stock::{
            HostBackingRead, HostBackingReadError, HostBackingRetention,
        };
        use carrick_mmu_core::x86::descriptor_txn::{NX, PRESENT, USER, WRITE};
        use std::os::fd::AsFd;

        struct ToggleDupSource {
            identity: carrick_el1_abi::HostBackingIdentity,
            file: std::fs::File,
            allow_dup: Arc<std::sync::atomic::AtomicBool>,
        }
        impl HostBackingRetention for ToggleDupSource {
            fn identity(&self) -> carrick_el1_abi::HostBackingIdentity {
                self.identity
            }
            fn read(&self, _: HostBackingRead) -> Result<Vec<u8>, HostBackingReadError> {
                Err(HostBackingReadError::Unavailable)
            }
            fn host_file(&self) -> Option<std::os::fd::OwnedFd> {
                if self.allow_dup.load(std::sync::atomic::Ordering::Acquire) {
                    self.file.as_fd().try_clone_to_owned().ok()
                } else {
                    None
                }
            }
            fn host_file_metadata(&self) -> Option<carrick_hal::fork_stock::HostFileMetadata> {
                use std::os::unix::fs::MetadataExt;
                self.file
                    .metadata()
                    .ok()
                    .map(|meta| carrick_hal::fork_stock::HostFileMetadata {
                        device: meta.dev(),
                        inode: meta.ino(),
                        len: meta.len(),
                    })
            }
        }

        let path = std::env::temp_dir().join(format!(
            "carrick-unavailable-host-fd-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        file.set_len(WINDOW_CHUNK_BYTES).unwrap();

        let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
        let mut fx = ForwardVenueFixture::with_pod();
        fx.custody.0.bind_grant_portal().unwrap();
        let context = fx.root_binding.context();
        let root = context.root;
        let carrier_id = fx.custody.0._vm.identity().nonzero();
        let fault_va = 0x1000_0000u64;
        let pod_va = carrick_guest_arch::KernelVa::new(X86_CPL0_BOOTSTRAP_METADATA_BASE);
        let pod_gpa = FrameGpa::new(ALLOCATOR_GPA);
        let control_va = METADATA_VA + CONTROL_OFFSET;
        let control_gpa = META_GPA + CONTROL_OFFSET;
        {
            let mut write_pte = |table: u64, va: u64, shift: u32, entry: u64| {
                let offset = ((va >> shift) & 0x1ff) * 8;
                fx.custody
                    .0
                    ._vm
                    .write(FrameGpa::new(table + offset), &entry.to_le_bytes())
                    .unwrap();
            };
            write_pte(
                root.address().raw(),
                pod_va.raw(),
                39,
                0x3000 | PRESENT | WRITE,
            );
            write_pte(0x3000, pod_va.raw(), 30, 0x4000 | PRESENT | WRITE);
            write_pte(0x4000, pod_va.raw(), 21, 0x5000 | PRESENT | WRITE);
            write_pte(
                0x5000,
                pod_va.raw(),
                12,
                pod_gpa.raw() | PRESENT | WRITE | NX,
            );
            write_pte(0x4000, control_va, 21, 0x6000 | PRESENT | WRITE);
            write_pte(0x6000, control_va, 12, control_gpa | PRESENT | WRITE | NX);
            write_pte(
                root.address().raw(),
                fault_va,
                39,
                0x7000 | PRESENT | WRITE | USER,
            );
            write_pte(0x7000, fault_va, 30, 0x8000 | PRESENT | WRITE | USER);
            write_pte(0x8000, fault_va, 21, 0x9000 | PRESENT | WRITE | USER);
            write_pte(0x9000, fault_va, 12, 0x1_0000 | PRESENT | WRITE | USER);
        }

        let make_record = |handle_num: u64| {
            let id = carrick_el1_abi::HostBackingIdentity::new(
                NonZeroU64::new(handle_num).unwrap(),
                NonZeroU64::MIN,
                0,
            );
            let mut bytes = vec![0u8; record_len(0, MapSourceReply::BYTES).unwrap()];
            encode(
                &mut bytes,
                HostFileHeader {
                    op: HostFileOp::MapShared,
                    table: [1, 2, 3],
                    fd: 4,
                    flags: 0,
                    args: [0, WINDOW_CHUNK_BYTES, 0, 0],
                },
                &[],
                MapSourceReply::BYTES,
            )
            .unwrap();
            HostFileRequestView::parse(&mut bytes)
                .unwrap()
                .reply(
                    0,
                    &MapSourceReply {
                        handle: id.handle(),
                        generation: id.generation(),
                    }
                    .encode(),
                )
                .unwrap();
            (bytes, id)
        };

        let allow_dup = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (mut emfile_bytes, emfile_id) = make_record(61);
        let emfile_source: Arc<dyn HostBackingRetention> = Arc::new(ToggleDupSource {
            identity: emfile_id,
            file: file.try_clone().unwrap(),
            allow_dup: Arc::clone(&allow_dup),
        });
        fx.custody.0._vm.write(pod_gpa, &emfile_bytes).unwrap();
        {
            let mut io = TestIo {
                image: context_with_root(1, root).hardware_image(),
            };
            let lease = StoppedCpuLease {
                cpu: carrick_guest_arch::CpuId::new(0),
                io: &mut io,
            };
            let mut venue = ForwardVenue::new(&mut fx.custody.0, lease, &fx.children).unwrap();
            venue
                .complete_host_file(pod_va, &mut emfile_bytes, Some(emfile_source), |fd| {
                    dispatcher.admit_window_inode(fd)
                })
                .expect(
                    "EMFILE in host_file() must refuse MapShared with ENOSYS, not trap carrier",
                );
        }
        let guest_bytes = fx.custody.0._vm.read(pod_gpa, emfile_bytes.len()).unwrap();
        let refused_reply = reply(&guest_bytes).unwrap();
        assert_eq!(
            refused_reply.result,
            carrick_abi::LINUX_ENOSYS.guest_retval()
        );
        assert_eq!(fx.custody.0._vm.window_slots(), 0);

        allow_dup.store(true, std::sync::atomic::Ordering::Release);
        let (mut ok_bytes, ok_id) = make_record(62);
        let ok_source: Arc<dyn HostBackingRetention> = Arc::new(ToggleDupSource {
            identity: ok_id,
            file: file.try_clone().unwrap(),
            allow_dup: Arc::clone(&allow_dup),
        });
        fx.custody.0._vm.write(pod_gpa, &ok_bytes).unwrap();
        {
            let mut io = TestIo {
                image: context_with_root(1, root).hardware_image(),
            };
            let lease = StoppedCpuLease {
                cpu: carrick_guest_arch::CpuId::new(0),
                io: &mut io,
            };
            let mut venue = ForwardVenue::new(&mut fx.custody.0, lease, &fx.children).unwrap();
            venue
                .complete_host_file(pod_va, &mut ok_bytes, Some(ok_source), |fd| {
                    dispatcher.admit_window_inode(fd)
                })
                .unwrap();
        }
        allow_dup.store(false, std::sync::atomic::Ordering::Release);
        fx.custody.0._vm.write(pod_gpa, &vec![0u8; 4096]).unwrap();

        let mm_key = INITIAL_MM_KEY;
        let ram = Arc::clone(&fx.custody.0.ram);
        {
            let zone_ptr = ram
                .host_ptr(
                    META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                    size_of::<X86Cpl0Zone>(),
                )
                .unwrap();
            let zone = unsafe { &*zone_ptr.cast::<X86Cpl0Zone>() };
            let space_idx = zone
                .spaces
                .publish_closed(mm_key, root.address().raw(), root.address().raw())
                .unwrap();
            let entry = zone.space_entry(NonZeroU64::new(mm_key).unwrap()).unwrap();
            entry
                .admit_notifications(
                    NonZeroU64::MIN,
                    &carrick_sched_core::BoundedSpin(0),
                    &|_| {},
                )
                .unwrap();
            let wake_no_delivery = |_z: &X86Cpl0Zone,
                                    _w: Waker,
                                    _o: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
                '_,
                carrick_sched_core::ParkedContextWords,
            >| {};
            carrick_sched_core::spaces::notification::SpaceAccess::notified(SpaceReleaseVenue {
                zone,
                waker: Waker::Host,
                deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                    &wake_no_delivery,
                ),
            })
            .open(space_idx);
            let record_id = zone
                .alloc_record(carrick_sched_core::ThreadIdentity {
                    tid: 41,
                    serial: 101,
                    mm: mm_key,
                    file_table: 5,
                    generation: 11,
                    affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                    affinity: 1,
                    lifecycle_page: METADATA_VA,
                    control_slot: control_va,
                })
                .unwrap();
            let record = zone.record_ref(record_id);
            let control_ptr = ram
                .host_ptr(META_GPA + CONTROL_OFFSET, size_of::<ThreadControlSlot>())
                .unwrap();
            let control: &ThreadControlSlot = unsafe { &*control_ptr.cast::<ThreadControlSlot>() };
            control.bind_zone_record(record);
            let member_custody =
                carrick_core::lifecycle::MemberControlCustody::retain(control).unwrap();
            member_custody.commit_registration();
            member_custody.commit_native_signal_owner();
            let mm_handle = unsafe {
                carrick_el1_abi::El1MmHandle::from_admitted_owner(
                    carrier_id,
                    ReservationMm::new(mm_key).unwrap(),
                    NonZeroU64::MIN,
                )
            };
            let birth = ServiceBirth {
                origin: ServiceOrigin::Initial,
                process: carrick_sched_core::process::TaskKey {
                    id: carrick_sched_core::process::TaskId::from_registry_allocation(
                        core::num::NonZeroI32::new(41).unwrap(),
                    ),
                    serial: carrick_sched_core::process::TaskSerial::from_raw_u64(7).unwrap(),
                },
                thread: carrick_el1_abi::EntryThreadGeneration::from_raw(101),
                record,
                mm: mm_handle,
            };
            control.service.bind(birth).unwrap();
            let fault_seq = NonZeroU64::MIN;
            let _req = control
                .service
                .publish_with_reply(
                    birth,
                    carrick_el1_abi::SnapshotGeneration::from_raw(11),
                    ServiceOperation::Fault(FaultInfo {
                        address: UserVa::new(fault_va),
                        access: carrick_guest_arch::Access::Read,
                        present: false,
                    }),
                    Some(fault_seq),
                    Some(pod_va),
                )
                .unwrap();
            let window = carrick_el1_abi::PortalGrantWindow {
                operation: PortalOperation {
                    carrier: carrier_id,
                    mm: ReservationMm::new(mm_key).unwrap(),
                    incarnation: NonZeroU64::MIN,
                    sequence: fault_seq,
                },
                mapping_incarnation: ReservationIncarnation::new(1).unwrap(),
                range: ReservationRange::new(fault_va, fault_va + 4096).unwrap(),
                protection: ReservationProtection::READ_WRITE,
                fault_page: fault_va,
                host_backing: Some(ok_id),
                fork_sequence: None,
            };
            assert!(
                fx.custody
                    .0
                    .grant_portal()
                    .unwrap()
                    .grant(0)
                    .unwrap()
                    .publish_fault_selection(fault_seq.get(), window)
            );
            fx.custody
                .0
                .task(carrick_guest_arch::CpuId::new(0))
                .service_notice
                .publish(ServiceSelector::from(_req.identity))
                .unwrap();
            let mut io = TestIo {
                image: context_with_root(1, root).hardware_image(),
            };
            let lease = StoppedCpuLease {
                cpu: carrick_guest_arch::CpuId::new(0),
                io: &mut io,
            };
            let req = fx
                .custody
                .0
                .file_supply_request(&lease, true)
                .unwrap()
                .expect("fault notice must select FileSupplyRequest");
            req.read()
                .expect("first-touch FileSupplyRequest::read must stat without dup()");
            drop(member_custody);
        }
    }

    fn execution() -> (carrick_el1_abi::ExecutionBinding, AddressContext<RootGpa>) {
        (
            carrick_el1_abi::ExecutionBinding {
                task: carrick_el1_abi::EntryTaskKey::from_raw(42),
                generation: carrick_el1_abi::SnapshotGeneration::from_raw(12),
                mm: carrick_el1_abi::EntryMmKey::from_raw(302),
                thread_generation: carrick_el1_abi::EntryThreadGeneration::from_raw(102),
            },
            AddressContext {
                root: RootGpa::page_aligned(FrameGpa::new(0x7000)).expect("aligned root"),
                mm: MmGeneration::new(NonZeroU64::new(302).expect("MM")),
                generation: ContextGeneration::new(NonZeroU64::new(9).expect("incarnation")),
            },
        )
    }

    #[test]
    fn stopped_forward_refuses_wrong_cpu_mm_root_and_incarnation() {
        let (binding, context) = execution();
        let cpu = carrick_guest_arch::CpuId::new(1);
        assert!(
            admit_forward_execution(
                cpu,
                carrick_guest_arch::CpuId::new(0),
                binding,
                context,
                context.root,
                context.generation
            )
            .is_err()
        );
        let wrong_mm = carrick_el1_abi::ExecutionBinding {
            mm: carrick_el1_abi::EntryMmKey::from_raw(301),
            ..binding
        };
        assert!(
            admit_forward_execution(
                cpu,
                cpu,
                wrong_mm,
                context,
                context.root,
                context.generation
            )
            .is_err()
        );
        assert!(
            admit_forward_execution(
                cpu,
                cpu,
                binding,
                context,
                RootGpa::page_aligned(FrameGpa::new(0x6000)).expect("aligned root"),
                context.generation
            )
            .is_err()
        );
        assert!(
            admit_forward_execution(
                cpu,
                cpu,
                binding,
                context,
                context.root,
                ContextGeneration::new(NonZeroU64::new(8).expect("incarnation"))
            )
            .is_err()
        );
        let admitted =
            admit_forward_execution(cpu, cpu, binding, context, context.root, context.generation)
                .expect("exact lane1 owner");
        assert_eq!(admitted.cpu.raw(), 1);
        assert_eq!(admitted.binding, binding);
        assert_eq!(admitted.leader_task, binding.task);
        assert_eq!(admitted.context, context);
    }

    fn carrier_binding(
        context: AddressContext<RootGpa>,
        execution: u64,
    ) -> carrick_hal::guest_arch_binding::GuestArchBinding {
        carrick_hal::guest_arch_binding::GuestArchBinding::x86(
            carrick_guest_arch::TaskIdentity {
                carrier: carrick_guest_arch::CarrierGeneration::new(
                    NonZeroU64::new(5).expect("carrier"),
                ),
                task: carrick_guest_arch::TaskSerial::new(NonZeroU64::new(77).expect("serial")),
                execution: carrick_guest_arch::ExecutionGeneration::new(
                    NonZeroU64::new(execution).expect("execution"),
                ),
            },
            context,
        )
    }

    /// Every forward phase (idle-peer identity, capture, completion) admits a
    /// CR3-registered binding through this one comparison; a binding whose
    /// address context or execution generation names another issue of the
    /// task must not be served as the stopped execution, and a `CLONE_VM`
    /// sibling sharing the root's CR3 and generation is a member, never the
    /// leader.
    #[test]
    fn forward_binding_authentication_requires_exact_context_generation_and_task_id() {
        let (binding, context) = execution();
        let cpu = carrick_guest_arch::CpuId::new(1);
        let admitted =
            admit_forward_execution(cpu, cpu, binding, context, context.root, context.generation)
                .expect("exact lane1 owner");
        assert_eq!(
            admitted.authenticate_typed(carrier_binding(context, 12)),
            Ok(())
        );
        admitted
            .authenticate(carrier_binding(context, 12), "exact")
            .expect("exact binding");
        assert_eq!(
            admitted.authenticate_typed(carrier_binding(context, 13)),
            Err(ForwardBindingRefusal::GenerationMismatch {
                stopped: 12,
                registered: 13,
            })
        );
        assert!(
            admitted
                .authenticate(carrier_binding(context, 13), "stale generation")
                .is_err()
        );
        let other_root = AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(0x6000)).expect("aligned root"),
            ..context
        };
        assert_eq!(
            admitted.authenticate_typed(carrier_binding(other_root, 12)),
            Err(ForwardBindingRefusal::ContextMismatch)
        );
        assert!(
            admitted
                .authenticate(carrier_binding(other_root, 12), "other root")
                .is_err()
        );
        let other_incarnation = AddressContext {
            generation: ContextGeneration::new(NonZeroU64::new(8).expect("incarnation")),
            ..context
        };
        assert_eq!(
            admitted.authenticate_typed(carrier_binding(other_incarnation, 12)),
            Err(ForwardBindingRefusal::ContextMismatch)
        );
        assert!(
            admitted
                .authenticate(carrier_binding(other_incarnation, 12), "other incarnation")
                .is_err()
        );
        // Ruling 4 thread clause: a CLONE_VM sibling sharing root CR3 + INITIAL
        // generation has a distinct stopped task key from the leader's task key.
        let sibling_binding = carrick_el1_abi::ExecutionBinding {
            task: carrick_el1_abi::EntryTaskKey::from_raw(43),
            ..binding
        };
        let sibling_admitted = admit_forward_execution(
            cpu,
            cpu,
            sibling_binding,
            context,
            context.root,
            context.generation,
        )
        .expect("admitted stopped execution")
        .with_leader_task(binding.task);
        assert_eq!(
            sibling_admitted.authenticate_typed(carrier_binding(context, 12)),
            Ok(())
        );
        assert_eq!(admitted.subject(), ForwardSubject::Leader);
        assert_eq!(
            sibling_admitted.subject(),
            ForwardSubject::Member {
                leader: binding.task,
                stopped: carrick_el1_abi::EntryTaskKey::from_raw(43),
            }
        );
    }

    /// #2739: changing the installed slots away from an exec predecessor is
    /// necessary for reclaim, but it is not authority to consume the adopted
    /// predecessor before the ring's matching exec settlement arrives.  This
    /// drives the same BootstrapCustody drain an unrelated work doorbell uses.
    #[test]
    fn unrelated_drain_keeps_an_unsettled_root_exec_predecessor() {
        let mut fixture = ForwardVenueFixture::new();
        let predecessor = ReservationMm::new(INITIAL_MM_KEY).expect("predecessor MM");
        let successor = ReservationMm::new(INITIAL_MM_KEY + 1).expect("successor MM");
        let predecessor_context = fixture.root_binding.context();
        let carrier = fixture.custody.0.fork_stock.carrier();
        let execution = carrick_hal::fork_stock::GrantExecution::new(
            carrick_guest_arch::CpuId::new(0),
            carrick_el1_abi::ExecutionBinding {
                task: carrick_el1_abi::EntryTaskKey::from_raw(41),
                generation: carrick_el1_abi::SnapshotGeneration::from_raw(11),
                mm: carrick_el1_abi::EntryMmKey::from_raw(predecessor.raw()),
                thread_generation: carrick_el1_abi::EntryThreadGeneration::from_raw(101),
            },
            predecessor_context,
        );
        let successor_root = RootGpa::page_aligned(FrameGpa::new(0x3000)).expect("successor root");
        // SAFETY: this stopped fixture owns both synthetic MMs and uses the
        // handle only to exercise the production fork-stock adoption path.
        let successor_owner = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                carrier,
                successor,
                NonZeroU64::new(2).expect("successor generation"),
            )
        };
        // The neutral exec owner adopts the exact same predecessor/successor
        // pair. Its successful RootCustody settlement is the only release
        // authority the production custody coordinator may accept.
        let predecessor_owner = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                carrier,
                predecessor,
                predecessor_context.generation.raw(),
            )
        };
        let identity = carrick_core_abi::service::ServiceIdentity {
            birth: carrick_core_abi::service::ServiceBirth {
                origin: carrick_core_abi::service::ServiceOrigin::Initial,
                process: carrick_sched_core::process::TaskKey {
                    id: carrick_sched_core::process::TaskId::from_registry_allocation(
                        core::num::NonZeroI32::new(41).expect("task id"),
                    ),
                    serial: carrick_sched_core::process::TaskSerial::from_registry_allocation(
                        NonZeroU64::new(7).expect("task serial"),
                    ),
                },
                thread: carrick_el1_abi::EntryThreadGeneration::from_raw(101),
                record: carrick_sched_core::RecordRef {
                    id: carrick_sched_core::RecordId::from_raw(1).expect("record"),
                    incarnation: 1,
                },
                mm: predecessor_owner,
            },
            execution: carrick_el1_abi::SnapshotGeneration::from_raw(11),
            sequence: NonZeroU64::MIN,
        };
        let mut owner = carrick_hal::exec_owner::ExecPreparations::<()>::default();
        let adoption_receipt = owner
            .claim(
                identity,
                successor,
                NonZeroU64::new(2).expect("successor generation"),
            )
            .expect("root exec claim")
            .receipt();
        owner.stage(adoption_receipt, ()).expect("root exec stage");
        owner.seal(adoption_receipt).expect("root exec seal");
        let adoption = owner
            .adopt(adoption_receipt, predecessor)
            .expect("root exec adoption");

        let stock_receipt = fixture
            .custody
            .0
            .fork_stock
            .replace_for_exec_with_tables(
                carrick_hal::fork_stock::ExecPredecessorForm::Root,
                execution,
                successor_owner,
                successor_root,
                carrick_hal::fork_stock::ForkHostBackingCustody::default(),
                Vec::new(),
            )
            .map_err(|(error, _)| error)
            .expect("adopt root exec predecessor");
        assert_eq!(stock_receipt.predecessor(), predecessor);
        assert_eq!(stock_receipt.successor(), successor);
        fixture
            .custody
            .0
            .exec_predecessors
            .adopt(adoption.mm.receipt(), stock_receipt);

        let zone =
            anonymous_owner::retained_cow_zone(&fixture.custody.0.ram).expect("retained zone");
        assert!(
            (0..carrick_x86::cpl0_entry::CPL0_CPU_COUNT)
                .filter_map(|slot| u8::try_from(slot).ok())
                .all(
                    |slot| zone.installed_space(carrick_sched_core::SlotId::new(slot))
                        != predecessor.raw()
                ),
            "both stopped slots switched away from the predecessor"
        );

        fixture
            .custody
            .0
            .settle_exec_predecessors()
            .expect("unrelated quarantine drain");
        assert_eq!(
            fixture.custody.0.exec_predecessors.adopted_len(),
            1,
            "slot absence cannot spend an unsettled exec predecessor receipt"
        );
        assert_eq!(
            fixture.custody.0.exec_predecessors.release_permitted_len(),
            0,
            "the unrelated drain cannot grant release authority"
        );

        let carrick_hal::exec_owner::ExecSettlement::Root(settlement) = owner
            .settle(
                predecessor,
                successor,
                carrick_el1_abi::ExecCommitEffects::COMPLETE,
                carrick_hal::exec_owner::ExecSettleLane::RootCustody,
            )
            .expect("matching root settlement")
        else {
            panic!("initial exec settles as root custody");
        };
        assert!(
            fixture
                .custody
                .0
                .exec_predecessors
                .permit_release(settlement.settled()),
            "the exact typed settlement grants release authority"
        );
        assert_eq!(fixture.custody.0.exec_predecessors.adopted_len(), 0);
        assert_eq!(
            fixture.custody.0.exec_predecessors.release_permitted_len(),
            1
        );

        fixture
            .custody
            .0
            .settle_exec_predecessors()
            .expect("post-settlement predecessor release");
        assert_eq!(
            fixture.custody.0.exec_predecessors.release_permitted_len(),
            0,
            "the exact fork-stock receipt releases"
        );
        fixture
            .custody
            .0
            .settle_exec_predecessors()
            .expect("second drain has nothing to release");
        assert_eq!(
            fixture.custody.0.exec_predecessors.release_permitted_len(),
            0,
            "the receipt releases exactly once"
        );
    }

    /// #3132: the exec successor the stock now holds as a child, `mm` at
    /// `root`, owner generation 2.
    fn successor_context(mm: ReservationMm, root: u64) -> AddressContext<RootGpa> {
        AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(root)).expect("successor root"),
            mm: MmGeneration::new(NonZeroU64::new(mm.raw()).expect("successor MM")),
            generation: ContextGeneration::new(NonZeroU64::new(2).expect("generation")),
        }
    }

    /// #3132: move `predecessor` (running in `context`) to the exec
    /// successor `successor` at `successor_root`, through the production
    /// fork-stock replacement. The successor becomes a stock child.
    fn replace_for_exec(
        fixture: &mut ForwardVenueFixture,
        form: carrick_hal::fork_stock::ExecPredecessorForm,
        predecessor: ReservationMm,
        context: AddressContext<RootGpa>,
        successor: ReservationMm,
        successor_root: u64,
    ) -> carrick_hal::fork_stock::ExecPredecessorReceipt<()> {
        let carrier = fixture.custody.0.fork_stock.carrier();
        let execution = carrick_hal::fork_stock::GrantExecution::new(
            carrick_guest_arch::CpuId::new(0),
            carrick_el1_abi::ExecutionBinding {
                task: carrick_el1_abi::EntryTaskKey::from_raw(41),
                generation: carrick_el1_abi::SnapshotGeneration::from_raw(11),
                mm: carrick_el1_abi::EntryMmKey::from_raw(predecessor.raw()),
                thread_generation: carrick_el1_abi::EntryThreadGeneration::from_raw(101),
            },
            context,
        );
        // SAFETY: the stopped fixture owns the synthetic successor MM and
        // uses the handle only on the production fork-stock adoption path.
        let owner = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                carrier,
                successor,
                NonZeroU64::new(2).expect("successor generation"),
            )
        };
        fixture
            .custody
            .0
            .fork_stock
            .replace_for_exec_with_tables(
                form,
                execution,
                owner,
                RootGpa::page_aligned(FrameGpa::new(successor_root)).expect("successor root"),
                carrick_hal::fork_stock::ForkHostBackingCustody::default(),
                Vec::new(),
            )
            .map_err(|(error, _)| error)
            .expect("exec replacement")
    }

    /// #3132: give `mm` (rooted in `context`) the carrier state a run gives
    /// a child: its CR3 root and one private data memslot admitted only to
    /// it, so its release revokes that slot.
    fn admit_private_slot(fixture: &mut ForwardVenueFixture, context: AddressContext<RootGpa>) {
        let key = context.mm.raw();
        let memory = fixture.custody.memory_mut();
        memory.install_root(key, context).expect("child root");
        let tag = NonZeroU64::new(0x3132).expect("tag");
        let handle = memory
            .install(&[PreparedBacking {
                extent: Arc::new(
                    BackingExtent::private(FrameGpa::new(0x2_0000_0000), 4096)
                        .expect("private extent"),
                ),
                identity: crate::carrier_memory::BackingIdentity {
                    frame_id: tag,
                    mapping_id: tag,
                    owner_generation: tag,
                    inventory_revision: tag,
                },
            }])
            .expect("private slot")[0];
        let edge = memory.share(handle).expect("data edge");
        memory.attach_shared(key, &edge).expect("child admission");
    }

    /// #3132 confirming pre-review P0: a release that quarantines the
    /// carrier ends the run from the fork quarantine drain. The stock's
    /// release callback answers a bool, so without the drain's quarantine
    /// check the broken invariant reads as an ordinary deferral: the drain
    /// returns Ok and retries it forever while the guest keeps running.
    ///
    /// The retired child holds one private memslot; the injected failure of
    /// the memslot unregister inside `CarrierMemory::revoke`, reached only
    /// from the drain's release callback, quarantines the carrier.
    #[test]
    fn fork_quarantine_drain_ends_the_run_when_a_child_release_quarantines() {
        use carrick_hal::fork_stock::ExecPredecessorForm;
        let mut fixture = ForwardVenueFixture::with_pod();
        let root = ReservationMm::new(INITIAL_MM_KEY).expect("root MM");
        let child = ReservationMm::new(INITIAL_MM_KEY + 1).expect("child MM");
        let root_context = fixture.root_binding.context();
        replace_for_exec(
            &mut fixture,
            ExecPredecessorForm::Root,
            root,
            root_context,
            child,
            0x3000,
        );
        let context = successor_context(child, 0x3000);
        admit_private_slot(&mut fixture, context);
        let binding = carrick_el1_abi::ExecutionBinding {
            task: carrick_el1_abi::EntryTaskKey::from_raw(41),
            generation: carrick_el1_abi::SnapshotGeneration::from_raw(11),
            mm: carrick_el1_abi::EntryMmKey::from_raw(child.raw()),
            thread_generation: carrick_el1_abi::EntryThreadGeneration::from_raw(101),
        };
        let mut record =
            carrick_el1_abi::NativeChildRetire::new(binding, context).expect("retire record");
        fixture
            .custody
            .0
            .fork_stock
            .retire_child(
                carrick_hal::fork_stock::GrantExecution::new(
                    carrick_guest_arch::CpuId::new(0),
                    binding,
                    context,
                ),
                &mut record,
            )
            .expect("child retires into quarantine");
        assert!(!fixture.custody.0._vm.is_quarantined());
        let deferrals = fixture.custody.0.fork_stock.counters().reclaim_deferrals;

        fixture.custody.0._vm.vm().fail_region_call(0);
        let drained = fixture.custody.0.drain_fork_quarantine_in(root.into());
        fixture.custody.0._vm.vm().clear_region_failure();

        // The release ran and quarantined the carrier: the injected
        // unregister failed inside its revoke, and the stock deferred the
        // child the callback refused.
        assert!(
            fixture.custody.0._vm.is_quarantined(),
            "the child's release revoked its slot and the unregister failed"
        );
        assert!(fixture.custody.0.fork_stock.is_quarantined(child));
        assert_eq!(
            fixture.custody.0.fork_stock.counters().reclaim_deferrals,
            deferrals + 1,
            "the release callback refused the child"
        );
        assert!(
            drained.is_err(),
            "a quarantined carrier must end the run, not defer the child: {drained:?}"
        );
    }

    /// #3132 confirming pre-review P0, the exec half: a release-permitted
    /// CHILD exec predecessor whose release quarantines the carrier ends the
    /// run from `settle_exec_predecessors` (a root predecessor has no
    /// release callback). Without the check the receipt goes back to
    /// `release_permitted` and the drain returns Ok.
    #[test]
    fn exec_predecessor_drain_ends_the_run_when_a_child_release_quarantines() {
        use carrick_hal::fork_stock::ExecPredecessorForm;
        let mut fixture = ForwardVenueFixture::with_pod();
        let root = ReservationMm::new(INITIAL_MM_KEY).expect("root MM");
        let child = ReservationMm::new(INITIAL_MM_KEY + 1).expect("child MM");
        let successor = ReservationMm::new(INITIAL_MM_KEY + 2).expect("successor MM");
        let root_context = fixture.root_binding.context();
        replace_for_exec(
            &mut fixture,
            ExecPredecessorForm::Root,
            root,
            root_context,
            child,
            0x3000,
        );
        let context = successor_context(child, 0x3000);
        // The child execs in turn: it is the CHILD predecessor.
        let stock_receipt = replace_for_exec(
            &mut fixture,
            ExecPredecessorForm::Child,
            child,
            context,
            successor,
            0x4000,
        );
        assert_eq!(stock_receipt.predecessor(), child);
        admit_private_slot(&mut fixture, context);

        // The neutral exec owner's settlement grants release authority.
        let carrier = fixture.custody.0.fork_stock.carrier();
        // SAFETY: the synthetic child MM handle names this fixture's
        // carrier and is used only by the exec owner below.
        let child_owner = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                carrier,
                child,
                NonZeroU64::new(2).expect("child generation"),
            )
        };
        let identity = carrick_core_abi::service::ServiceIdentity {
            birth: carrick_core_abi::service::ServiceBirth {
                origin: carrick_core_abi::service::ServiceOrigin::Descendant,
                process: carrick_sched_core::process::TaskKey {
                    id: carrick_sched_core::process::TaskId::from_registry_allocation(
                        core::num::NonZeroI32::new(42).expect("task id"),
                    ),
                    serial: carrick_sched_core::process::TaskSerial::from_registry_allocation(
                        NonZeroU64::new(8).expect("task serial"),
                    ),
                },
                thread: carrick_el1_abi::EntryThreadGeneration::from_raw(101),
                record: carrick_sched_core::RecordRef {
                    id: carrick_sched_core::RecordId::from_raw(1).expect("record"),
                    incarnation: 1,
                },
                mm: child_owner,
            },
            execution: carrick_el1_abi::SnapshotGeneration::from_raw(11),
            sequence: NonZeroU64::MIN,
        };
        let mut owner = carrick_hal::exec_owner::ExecPreparations::<()>::default();
        let receipt = owner
            .claim(
                identity,
                successor,
                NonZeroU64::new(2).expect("successor generation"),
            )
            .expect("child exec claim")
            .receipt();
        owner.stage(receipt, ()).expect("child exec stage");
        owner.seal(receipt).expect("child exec seal");
        let adoption = owner.adopt(receipt, child).expect("child exec adoption");
        fixture
            .custody
            .0
            .exec_predecessors
            .adopt(adoption.mm.receipt(), stock_receipt);
        let carrick_hal::exec_owner::ExecSettlement::Child(settled) = owner
            .settle(
                child,
                successor,
                carrick_el1_abi::ExecCommitEffects::COMPLETE,
                carrick_hal::exec_owner::ExecSettleLane::Peer,
            )
            .expect("child settlement")
        else {
            panic!("a descendant's exec settles as a child");
        };
        assert!(fixture.custody.0.exec_predecessors.permit_release(settled));
        assert!(!fixture.custody.0._vm.is_quarantined());

        fixture.custody.0._vm.vm().fail_region_call(0);
        let settled = fixture.custody.0.settle_exec_predecessors();
        fixture.custody.0._vm.vm().clear_region_failure();

        assert!(
            fixture.custody.0._vm.is_quarantined(),
            "the predecessor's release revoked its slot and the unregister failed"
        );
        assert!(
            settled.is_err(),
            "a quarantined carrier must end the run, not keep the receipt: {settled:?}"
        );
    }
}

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
enum InitialPeerAdmission {
    Cold,
    Ready,
}

/// Stopped production CPUs after the bootstrap I/O receipts are complete.
/// Field order keeps both CPU handles ahead of retained physical backing.
pub struct ProductionWorkerParts<M: CarrierCpuIo, Mem: CarrierMemoryIo = M> {
    cpus: [CarrierCpu<M>; 2],
    custody: Cpl0HostCustody<Mem>,
    root_state: carrick_x86::arch_context::X86ArchContext,
}

/// Physical CPUs are claimed once by executor workers. Shared host custody
/// outlives every claimed CPU and is only entered for stopped host service.
/// Runtime-supplied Linux entropy handler; the VMM retains transport only.
pub type NativeEntropyService =
    fn(&mut [u8]) -> Result<(), carrick_core_abi::service::entropy::InvalidEntropyRecord>;

pub struct ProductionCpuFactory<M: CarrierCpuIo, Mem: CarrierMemoryIo = M> {
    native_entropy: NativeEntropyService,
    cpus: std::sync::Mutex<[Option<CarrierCpu<M>>; 2]>,
    custody: Arc<std::sync::Mutex<Cpl0HostCustody<Mem>>>,
    debug_cpus: [Arc<CarrierCpuDebug>; 2],
}

/// Bounded physical observations owned by the carrier.
pub struct ProductionPhysicalCapture {
    pub zone_census: String,
    pub vcpus: Vec<String>,
    pub unavailable: Vec<String>,
}

pub struct ProductionCpuLease<M: CarrierCpuIo, Mem: CarrierMemoryIo = M> {
    native_entropy: NativeEntropyService,
    cpu: CarrierCpu<M>,
    _custody: Arc<std::sync::Mutex<Cpl0HostCustody<Mem>>>,
    /// The run root's settled exec this lane served, until the executor
    /// takes it (#2142).
    root_exec: Option<exec_service::RootExecSettled>,
}
/// A forwarded frame copied out of a physical CPU's private CPL0 stack.
/// Another task may reuse that stack while this one waits; the frame is
/// restored only after its exact task and MM binding is loaded again.
pub struct ProductionForwardFrame {
    task: carrick_guest_arch::TaskIdentity,
    slot: carrick_guest_arch::CpuId,
    address: u64,
    execution: ForwardExecution,
    frame: NativeFrame,
}

impl ProductionForwardFrame {
    /// Who captured this forward: the root binding's leader, or a member.
    pub fn subject(&self) -> ForwardSubject {
        self.execution.subject()
    }
}

/// Bytes still reachable from a stopped task's CPL0 RSP. The physical stack
/// may be reused after the task releases its executor; its call chain belongs
/// to the task until it is reloaded on the same physical slot.
pub struct KernelStackSnapshot {
    slot: carrick_guest_arch::CpuId,
    start: u64,
    end: u64,
    bytes: Box<[u8]>,
}

impl KernelStackSnapshot {
    /// # Safety
    /// `source` must point to a stopped, readable mapping of `[base, end)`.
    unsafe fn capture(
        source: *const u8,
        base: u64,
        end: u64,
        rsp: u64,
        slot: carrick_guest_arch::CpuId,
    ) -> Result<Self, TrapError> {
        if rsp < base {
            return Err(fail("CPL0 RSP below private stack"));
        }
        let len = usize::try_from(
            end.checked_sub(rsp)
                .ok_or_else(|| fail("CPL0 RSP beyond stack"))?,
        )
        .map_err(|_| fail("CPL0 stack length overflow"))?;
        if len == 0 || len > carrick_el1_abi::X86_CPL0_KERNEL_STACK_SIZE as usize {
            return Err(fail("CPL0 RSP outside private stack"));
        }
        let offset = usize::try_from(rsp - base).map_err(|_| fail("CPL0 stack offset overflow"))?;
        let mut bytes = vec![0u8; len];
        // SAFETY: caller guarantees stopped guest memory; `bytes` is an owned
        // allocation, never a mutable reference into guest RAM.
        unsafe { std::ptr::copy_nonoverlapping(source.add(offset), bytes.as_mut_ptr(), len) };
        Ok(Self {
            slot,
            start: rsp,
            end,
            bytes: bytes.into_boxed_slice(),
        })
    }

    /// # Safety
    /// `destination` must point to the same stopped writable stack mapping.
    unsafe fn restore(
        &self,
        destination: *mut u8,
        base: u64,
        end: u64,
        slot: carrick_guest_arch::CpuId,
    ) -> Result<(), TrapError> {
        if self.slot != slot || self.end != end || self.start < base {
            return Err(fail("CPL0 stack restoration binding changed"));
        }
        let offset = usize::try_from(self.start - base)
            .map_err(|_| fail("CPL0 stack restoration offset overflow"))?;
        let extent = usize::try_from(
            end.checked_sub(base)
                .ok_or_else(|| fail("CPL0 stack extent underflow"))?,
        )
        .map_err(|_| fail("CPL0 stack extent overflow"))?;
        if offset.checked_add(self.bytes.len()) != Some(extent) {
            return Err(fail("CPL0 stack restoration extent changed"));
        }
        // SAFETY: caller guarantees stopped guest memory and exact binding.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.bytes.as_ptr(),
                destination.add(offset),
                self.bytes.len(),
            )
        };
        Ok(())
    }
}

fn exec_owner_census_of<Mem: CarrierMemoryIo>(
    custody: &std::sync::Mutex<Cpl0HostCustody<Mem>>,
) -> Result<carrick_hal::exec_owner::ExecOwnerCensus, TrapError> {
    let custody = custody
        .lock()
        .map_err(|_| fail("physical custody poisoned"))?;
    Ok(custody.exec_owner_census())
}

impl<M: CarrierCpuIo, Mem: CarrierMemoryIo> ProductionCpuLease<M, Mem> {
    pub const fn cpu(&self) -> &CarrierCpu<M> {
        &self.cpu
    }

    pub fn cpu_mut(&mut self) -> &mut CarrierCpu<M> {
        &mut self.cpu
    }

    /// Rebind the loaded run root to its `execve` successor: the carrier's
    /// shared root binding, this CPU's loaded custody and the forward leader
    /// rule all name the successor afterwards, or none changes.
    /// The run root's exec this lane settled (#2142), for the executor to
    /// commit. Guest entry stays refused until `retarget_root_exec` moves the
    /// root's custody to the settled successor.
    pub fn take_root_exec_settlement(&mut self) -> Option<exec_service::RootExecSettled> {
        self.root_exec.take()
    }

    /// The exec owner's census observed from this CPU lease.
    pub fn exec_owner_census(&self) -> Result<carrick_hal::exec_owner::ExecOwnerCensus, TrapError> {
        exec_owner_census_of(&self._custody)
    }

    pub fn retarget_root_exec(
        &mut self,
        predecessor: carrick_hal::guest_arch_binding::GuestArchBinding,
        successor: carrick_hal::guest_arch_binding::GuestArchBinding,
        successor_thread_serial: u64,
    ) -> Result<(), TrapError> {
        let mut custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let initial = custody
            .initial_task
            .ok_or_else(|| fail("root exec has no issued root task"))?
            .exec_successor(predecessor, successor, successor_thread_serial)?;
        self.cpu.retarget_loaded_exec(predecessor, successor)?;
        custody.initial_task = Some(initial);
        // The replaced image's private file sources die with it: the
        // successor's start empty, under its own address context (#2142).
        if custody
            .initial_sources
            .as_ref()
            .is_some_and(|(owner, _)| *owner == predecessor.context())
        {
            custody.initial_sources = None;
        }
        Ok(())
    }

    pub fn physical_slot(&self) -> Option<carrick_guest_arch::CpuId> {
        self.cpu.physical_slot()
    }

    /// Host view of the one ingress reservation while this physical lease
    /// pins its carrier. The queue uses atomic slot publication on both sides.
    pub fn signal_ingress(&self) -> Result<&carrick_el1_abi::SharedSignalIngressQueue, TrapError> {
        let custody = self
            ._custody
            .lock()
            .map_err(|_| fail("CPL0 signal ingress custody poisoned"))?;
        let queue = custody.metadata::<carrick_el1_abi::SharedSignalIngressQueue>(
            carrick_el1_abi::EL1_SIGNAL_INGRESS_OFFSET,
        ) as *const _;
        drop(custody);
        // SAFETY: this lease retains the carrier custody and its mapped ABI
        // region through the returned borrow; queue access is atomic.
        Ok(unsafe { &*queue })
    }

    pub fn fixture_run_until_native_kick(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
    ) -> Result<CarrierRunExit, TrapError> {
        let watchdog = M::Watchdog::start();
        let result = watchdog.during_guest(|| self.cpu.fixture_run_until_kick(task));
        if watchdog.expired() {
            return Err(fail("native wait fixture guest interval deadline"));
        }
        result
    }

    /// Run a live native fixture.
    pub fn fixture_run_loaded(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
    ) -> Result<crate::carrier_cpu::StoppedTaskExit, TrapError> {
        let watchdog = M::Watchdog::start();
        let result = watchdog.during_guest(|| self.cpu.run_loaded(task));
        if watchdog.expired() {
            return Err(fail("native fixture guest interval deadline"));
        }
        result
    }

    /// Run the real idle peer.
    pub fn fixture_run_idle_peer(&mut self) -> Result<CarrierRunExit, TrapError> {
        let watchdog = M::Watchdog::start();
        let result = watchdog.during_guest(|| self.run_idle_peer());
        if watchdog.expired() {
            return Err(fail("native peer fixture guest interval deadline"));
        }
        result
    }

    /// Receive a fixture stdout byte from the real idle peer's stopped frame.
    /// MM and execution identity still come from the authenticated live venue.
    pub fn fixture_idle_peer_write(&mut self, exit: &CarrierRunExit) -> Result<Vec<u8>, TrapError> {
        if *exit != CarrierRunExit::SyscallTrap {
            return Err(fail("idle peer fixture requires write crossing"));
        }
        let task = self.idle_peer_task()?;
        let (bytes, token) = self.capture_forward(task, |venue, frame| {
            if (frame.rax, frame.rdi, frame.rdx) != (1, 1, 1) {
                return Err(fail("peer fixture only receives one stdout byte"));
            }
            venue
                .read_bytes_raw(frame.rsi, 1)
                .map_err(|error| fail(error.to_string()))
        })?;
        self.complete_forward(task, token, 1)?;
        Ok(bytes)
    }

    /// Resolve and authenticate the exact guest task stopped on the idle peer.
    /// The physical peer slot itself is never a task identity.
    pub fn idle_peer_task(&mut self) -> Result<carrick_guest_arch::TaskIdentity, TrapError> {
        let children = self.cpu.child_binding_authority();
        let mut custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let execution = self.cpu.with_idle_peer_io(|io| {
            let slot = carrick_guest_arch::CpuId::new(1);
            Ok(
                ForwardVenue::new(&mut custody, StoppedCpuLease { cpu: slot, io }, &children)?
                    .execution,
            )
        })?;
        drop(custody);
        let binding = self.cpu.registered_task_binding(execution.context.root)?;
        execution.authenticate(binding, "idle peer forward binding mismatch")?;
        Ok(binding.task())
    }

    /// Whether a reschedule may save the host root lease here: the loaded
    /// CPU stands on the lease's root ([`CarrierCpu::can_save_loaded`]), in
    /// user mode or in CPL0 supervisor code, and the CPL0 execution issued on
    /// this slot is the lease's own leader thread. A `CLONE_THREAD` member
    /// sharing the root, a forked child or the maintenance root never stands
    /// in for the leader's saved image (#2962). Every save the executor
    /// starts for a reschedule, after a kick or after a completed crossing,
    /// checks this one rule.
    pub fn can_save_loaded_leader(
        &self,
        task: carrick_guest_arch::TaskIdentity,
    ) -> Result<bool, TrapError> {
        if !self.cpu.can_save_loaded(task)? {
            return Ok(false);
        }
        let Some(slot) = self.physical_slot() else {
            return Ok(true);
        };
        let custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let Some(initial) = custody.initial_task else {
            return Ok(true);
        };
        let current = custody.task(slot);
        let binding = carrick_core::entry::binding(&current.execution, &current.mm);
        Ok(binding.issued()
            && binding.task == carrick_el1_abi::EntryTaskKey::from_raw(initial.thread.tid)
            && binding.mm.raw() == initial.mm.raw().get())
    }

    pub fn save_kernel_stack(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
    ) -> Result<Option<KernelStackSnapshot>, TrapError> {
        let slot = self
            .physical_slot()
            .ok_or_else(|| fail("production CPU has no physical slot"))?;
        let custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        self.cpu.with_stopped_io(task, |io| {
            let rsp = io.get_gpr(X86Reg::Rsp)?;
            if rsp < DIRECT_VA {
                return Ok(None);
            }
            let end = custody
                .binding(slot)
                .kernel_stack
                .checked_add(carrick_el1_abi::X86_CPL0_KERNEL_STACK_TOP_RESERVE)
                .ok_or_else(|| fail("CPL0 stack top overflow"))?;
            let base = end
                .checked_sub(carrick_el1_abi::X86_CPL0_KERNEL_STACK_SIZE)
                .ok_or_else(|| fail("CPL0 stack base underflow"))?;
            let source = custody
                .ram
                .host_ptr(
                    base - DIRECT_VA,
                    carrick_el1_abi::X86_CPL0_KERNEL_STACK_SIZE as usize,
                )
                .ok_or_else(|| fail("CPL0 stack backing absent"))?;
            // SAFETY: this exact task and CPU are stopped, and the backing
            // spans the verified private stack.
            unsafe { KernelStackSnapshot::capture(source, base, end, rsp, slot).map(Some) }
        })
    }

    pub fn restore_kernel_stack(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
        snapshot: &KernelStackSnapshot,
    ) -> Result<(), TrapError> {
        let slot = self
            .physical_slot()
            .ok_or_else(|| fail("production CPU has no physical slot"))?;
        let custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        self.cpu.with_stopped_io(task, |_io| {
            let end = custody
                .binding(slot)
                .kernel_stack
                .checked_add(carrick_el1_abi::X86_CPL0_KERNEL_STACK_TOP_RESERVE)
                .ok_or_else(|| fail("CPL0 stack top overflow"))?;
            let base = end
                .checked_sub(carrick_el1_abi::X86_CPL0_KERNEL_STACK_SIZE)
                .ok_or_else(|| fail("CPL0 stack base underflow"))?;
            let destination = custody
                .ram
                .host_ptr(
                    base - DIRECT_VA,
                    carrick_el1_abi::X86_CPL0_KERNEL_STACK_SIZE as usize,
                )
                .ok_or_else(|| fail("CPL0 stack backing absent"))?;
            // SAFETY: the exact task is loaded but stopped, and the snapshot
            // authenticates the physical stack before copying.
            unsafe { snapshot.restore(destination, base, end, slot) }
        })
    }

    pub fn arm_idle_kick(&mut self, kick: &M::KickHandle) -> Result<(), TrapError> {
        self.cpu.arm_idle_kick(kick)
    }
    pub fn arm_loaded_kick(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
        kick: &M::KickHandle,
    ) -> Result<(), TrapError> {
        self.cpu.arm_loaded_kick(task, kick)
    }

    pub fn capture_fault_record(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
        first: u32,
    ) -> Result<carrick_x86::FaultDoorbellRecord, TrapError> {
        let slot = self
            .physical_slot()
            .ok_or_else(|| fail("fault exit has no physical slot"))?;
        let mut words = vec![first];
        while words.len() < carrick_x86::X86_FAULT_RECORD_U32_WORDS {
            let stopped = self.cpu.run_loaded(task)?;
            let crate::carrier_cpu::CarrierRunExit::FaultDoorbellWord(word) = stopped.exit else {
                return Err(fail("fault record interrupted"));
            };
            words.push(word);
        }
        self.finish_captured_fault_record(slot, &words)
    }

    pub fn capture_idle_peer_fault_record(
        &mut self,
        first: u32,
    ) -> Result<carrick_x86::FaultDoorbellRecord, TrapError> {
        self.cpu.audit_unloaded_peer()?;
        let mut words = vec![first];
        while words.len() < carrick_x86::X86_FAULT_RECORD_U32_WORDS {
            let crate::carrier_cpu::CarrierRunExit::FaultDoorbellWord(word) =
                self.cpu.run_idle_peer()?
            else {
                return Err(fail("fault record interrupted"));
            };
            words.push(word);
        }
        self.finish_captured_fault_record(carrick_guest_arch::CpuId::new(1), &words)
    }

    fn finish_captured_fault_record(
        &self,
        slot: carrick_guest_arch::CpuId,
        words: &[u32],
    ) -> Result<carrick_x86::FaultDoorbellRecord, TrapError> {
        let record = carrick_x86::FaultDoorbellRecord::from_u32_words(words)?;
        let custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let reason = custody.binding(slot).fault_reason.load(Ordering::Acquire);
        if record.vector == 14
            && carrick_el1_abi::X86FaultDisposition::from_raw(reason)
                != Some(carrick_el1_abi::X86FaultDisposition::PolicyDeclined)
        {
            return Err(fail(format!(
                "kernel fault policy refused: reason {reason:#x}, {record:x?}"
            )));
        }
        Ok(record)
    }

    pub fn run_idle_peer(&mut self) -> Result<CarrierRunExit, TrapError> {
        self.cpu.run_idle_peer()
    }

    pub fn audit_unloaded_peer(&self) -> Result<(), TrapError> {
        self.cpu.audit_unloaded_peer()
    }

    pub fn service_idle_peer_doorbell(
        &mut self,
        exit: &CarrierRunExit,
        on_work: impl FnOnce(bool, Option<carrick_el1_abi::HostWorkDoorbell>),
    ) -> Result<Option<PhysicalProcessExit>, TrapError> {
        self.service_idle_peer_doorbell_with_host_file(
            exit,
            on_work,
            &mut |_, _| Err(carrick_hal::fork_stock::NativeHostFileRefused),
            &mut refuse_native_exec,
        )
    }

    pub fn service_idle_peer_doorbell_with_host_file(
        &mut self,
        exit: &CarrierRunExit,
        on_work: impl FnOnce(bool, Option<carrick_el1_abi::HostWorkDoorbell>),
        host_file: &mut NativeHostFileService<'_>,
        exec: &mut NativeExecLoadService<'_>,
    ) -> Result<Option<PhysicalProcessExit>, TrapError> {
        let CarrierRunExit::PhysicalDoorbell { port, .. } = exit else {
            return Err(fail("idle peer service requires physical doorbell"));
        };
        // A carrier without a runtime resource service has no fs authority.
        // Authenticate the synchronous request, then leave its record refused.
        if *port == carrick_core_abi::service::ROOT_FORK_SEED_PORT {
            self.service_root_fork_seed(None, |_| (false, None))?;
            return Ok(None);
        }
        let file = if *port == OWNER_GRANT_PORT || *port == NATIVE_SERVICE_PORT {
            self.read_owner_file(None, *port == NATIVE_SERVICE_PORT)?
        } else {
            None
        };
        let mut custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let native_entropy = self.native_entropy;
        let mut work_flags = None;
        let mut pending_file = None;
        let mut pending_exec = None;
        let mut exec_rebind = None;
        let mut take_work = false;
        let (exit, register_child, unregister_child) = self.cpu.with_idle_peer_io(|io| {
            let lease = StoppedCpuLease {
                cpu: carrick_guest_arch::CpuId::new(1),
                io,
            };
            let served = match *port {
                OWNER_GRANT_PORT => {
                    custody.owner_grant_crossings = custody
                        .owner_grant_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    custody.service_anonymous_grant(&lease, file)?;
                    Ok((None, None, None))
                }
                carrick_el1_abi::FORK_STOCK_PORT => {
                    custody.owner_grant_crossings = custody
                        .owner_grant_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    let child_binding = custody.service_fork_stock(&lease)?;
                    Ok((None, child_binding, None))
                }
                carrick_el1_abi::NATIVE_EXEC_PORT => {
                    match custody.service_native_exec(&lease, carrick_hal::exec_owner::ExecSettleLane::Peer)? {
                        exec_service::NativeExecCrossing::Settled { successor, predecessor } => {
                            exec_rebind = Some((successor, predecessor));
                        }
                        // The exec owner hands a root settlement on this
                        // lane back before anything changes.
                        exec_service::NativeExecCrossing::RootSettled(_) => {
                            return Err(fail("root exec settled on the idle peer"));
                        }
                        exec_service::NativeExecCrossing::Answered => {}
                    }
                    Ok((None, None, None))
                }
                carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT => {
                    custody.child_retire_crossings = custody
                        .child_retire_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    let live_root = lease.io.get_gpr(X86Reg::Cr3)? & !0xfff;
                    let root_gpa = RootGpa::page_aligned(FrameGpa::new(live_root))
                        .ok_or_else(|| fail("unaligned child retire CR3"))?;
                    let retire_result = custody.service_child_retire(&lease);
                    Ok((None, None, Some((root_gpa, retire_result))))
                }
                carrick_el1_abi::NATIVE_SPACE_RETIRED_PORT => {
                    custody.service_space_retired(&lease)?;
                    Ok((None, None, None))
                }
                carrick_core_abi::NATIVE_RUN_FAILURE_PORT => {
                    let cause = custody.service_run_failure(&lease)?;
                    custody.run_failure_crossings = custody
                        .run_failure_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    Ok((Some(PhysicalProcessExit::RunFailed(cause)), None, None))
                }
                carrick_core_abi::NATIVE_ROOT_EXIT_PORT => {
                    custody.root_exit_crossings = custody
                        .root_exit_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    custody
                        .service_root_exit(&lease)
                        .map(|status| (Some(PhysicalProcessExit::Exited(status)), None, None))
                }
                NATIVE_SERVICE_PORT => {
                    match custody.service_native_notice(&lease, file, native_entropy)? {
                        anonymous_owner::native_service::NativeNoticeStep::HostFile(pending) => {
                            pending_file = Some(pending);
                        }
                        anonymous_owner::native_service::NativeNoticeStep::Exec(pending) => {
                            pending_exec = Some(pending);
                        }
                        anonymous_owner::native_service::NativeNoticeStep::Settled => {}
                    }
                    Ok((None, None, None))
                }
                WORK_PORT => {
                    if let Ok(execution) = custody.physical_execution(&lease) {
                        custody.drain_fork_quarantine(execution)?;
                    } else if let Some(maintenance) = custody.maintenance_root {
                        let live = RootGpa::page_aligned(FrameGpa::new(lease.io.get_gpr(X86Reg::Cr3)?))
                            .ok_or_else(|| fail("work root alignment"))?;
                        if let Some(venue) = carrick_hal::fork_stock::ReclaimExecution::maintenance_root(live, maintenance) {
                            custody.drain_fork_quarantine_in(venue)?;
                        }
                    }
                    take_work = true;
                    Ok((None, None, None))
                }
                _ => {
                    if *port == FATAL_PORT
                        && let Some(detail) = crate::ring_panic::fatal_port_panic_detail(&custody._vm, |reg| lease.io.get_gpr(reg))?
                    {
                        return Err(fail(detail));
                    }
                    let detail = format!(
                        "unexpected idle peer physical doorbell {port:#x}: rax={:#x} rip={:#x} rsp={:#x} cr3={:#x}",
                        lease.io.get_gpr(X86Reg::Rax)?, lease.io.get_gpr(X86Reg::Rip)?,
                        lease.io.get_gpr(X86Reg::Rsp)?, lease.io.get_gpr(X86Reg::Cr3)?,
                    );
                    Err(fail(detail))
                }
            }?;
            // Any crossing can advance the fork stock's release, which only
            // flags a parked exec's row: every crossing the guest continues
            // from ends with the probe (a root exit or run failure ends it).
            if served.0.is_none() {
                custody.probe_parked_execs(lease.cpu)?;
            }
            if take_work {
                work_flags = Some(take_production_work_boundary(custody.task(lease.cpu))?);
            }
            Ok(served)
        })?;
        if let Some((child_binding, entry_task)) = register_child {
            self.cpu
                .register_child_binding_with_entry_task(child_binding, entry_task)?;
        }
        if let Some((live_root, retire_result)) = unregister_child {
            self.cpu.unregister_child_binding(live_root)?;
            retire_result?;
        }
        if let Some((successor, predecessor)) = exec_rebind {
            let root_successor = custody
                .initial_task
                .is_some_and(|initial| initial.mm == successor.context().mm);
            self.cpu
                .rebind_child_successor(successor, predecessor, root_successor)?;
        }
        if let Some(PhysicalProcessExit::Exited(_) | PhysicalProcessExit::RunFailed(_)) = exit {
            self.cpu.clear_child_bindings()?;
        }
        let executable = pending_file.as_ref().and_then(|pending| {
            custody.native_file_executable(pending.ticket.request().identity.birth, &pending.record)
        });
        drop(custody);
        if let Some(pending) = pending_exec {
            let loaded = exec(
                pending.ticket.request().identity.birth.origin,
                &pending.payload,
            );
            let mut custody = self
                ._custody
                .lock()
                .map_err(|_| fail("physical custody poisoned"))?;
            self.cpu.with_idle_peer_io(|io| {
                let lease = StoppedCpuLease {
                    cpu: carrick_guest_arch::CpuId::new(1),
                    io,
                };
                custody.finish_native_exec(&lease, pending, loaded)?;
                custody.probe_parked_execs(lease.cpu)
            })?;
        }
        if let Some(mut pending) = pending_file {
            let served = host_file(
                NativeHostFileCaller {
                    birth: pending.ticket.request().identity.birth,
                    executable,
                },
                &mut pending.record,
            );
            let mut custody = self
                ._custody
                .lock()
                .map_err(|_| fail("physical custody poisoned"))?;
            let accepted = served.is_ok();
            self.cpu.with_idle_peer_io(|io| {
                let lease = StoppedCpuLease {
                    cpu: carrick_guest_arch::CpuId::new(1),
                    io,
                };
                custody.finish_native_host_file(&lease, *pending, served)?;
                custody.probe_parked_execs(lease.cpu)
            })?;
            if accepted {
                custody.idle_peer_host_files = custody
                    .idle_peer_host_files
                    .checked_add(1)
                    .ok_or_else(|| fail("idle peer host-file counter exhausted"))?;
            }
        }
        if let Some((served, doorbell)) = work_flags {
            on_work(served, doorbell);
        }
        Ok(exit)
    }

    pub fn is_idle_peer_slot(&self) -> bool {
        self.physical_slot() == Some(carrick_guest_arch::CpuId::new(1))
    }

    pub fn capture_forward<R>(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
        forward: impl FnOnce(&mut ForwardVenue<'_, M, Mem>, &NativeFrame) -> Result<R, TrapError>,
    ) -> Result<(R, ProductionForwardFrame), TrapError> {
        let slot = self
            .physical_slot()
            .ok_or_else(|| fail("production CPU has no physical slot"))?;
        let mut custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let children = self.cpu.child_binding_authority();
        self.cpu.with_forward_io(task, |io, active_binding| {
            let address = io.get_gpr(X86Reg::Rax)?;
            let stack_end = checked_stack_end(custody.binding(slot).kernel_stack)
                .ok_or_else(|| fail("forward kernel stack overflow"))?;
            let gpa = checked_private_stack_frame_gpa(stack_end, address, size_of::<NativeFrame>())
                .ok_or_else(|| fail("forward frame outside private kernel stack"))?;
            let ptr = custody
                .ram
                .host_ptr(gpa, size_of::<NativeFrame>())
                .ok_or_else(|| fail("forward frame backing"))?
                .cast::<NativeFrame>();
            // SAFETY: guest execution stopped after the exact frame publication; no
            // guest instruction runs while this copy is made.
            let frame = unsafe { *ptr };
            let mut venue =
                ForwardVenue::new(&mut custody, StoppedCpuLease { cpu: slot, io }, &children)?;
            let execution = venue.execution;
            execution.authenticate(active_binding, "forward capture MM binding mismatch")?;
            let result = forward(&mut venue, &frame)?;
            custody.host_forwards = custody
                .host_forwards
                .checked_add(1)
                .ok_or_else(|| fail("host forward counter exhausted"))?;
            if slot == carrick_guest_arch::CpuId::new(1) {
                custody.idle_peer_forwards = custody
                    .idle_peer_forwards
                    .checked_add(1)
                    .ok_or_else(|| fail("idle peer forward counter exhausted"))?;
            }
            Ok((
                result,
                ProductionForwardFrame {
                    task,
                    slot,
                    address,
                    execution,
                    frame,
                },
            ))
        })
    }

    pub fn complete_forward(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
        token: ProductionForwardFrame,
        value: i64,
    ) -> Result<(), TrapError> {
        if token.task != task || self.physical_slot() != Some(token.slot) {
            return Err(fail("forward completion task or physical slot changed"));
        }
        let mut custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let children = self.cpu.child_binding_authority();
        self.cpu.with_forward_io(task, |io, active_binding| {
            let lease = StoppedCpuLease {
                cpu: token.slot,
                io,
            };
            let current = ForwardVenue::new(&mut custody, lease, &children)?.execution;
            if current.binding != token.execution.binding
                || current.context != token.execution.context
            {
                return Err(fail("forward completion MM binding changed"));
            }
            current.authenticate(active_binding, "forward completion MM binding changed")?;
            let stack_end = checked_stack_end(custody.binding(token.slot).kernel_stack)
                .ok_or_else(|| fail("forward completion kernel stack overflow"))?;
            let gpa =
                checked_private_stack_frame_gpa(stack_end, token.address, size_of::<NativeFrame>())
                    .ok_or_else(|| fail("forward completion frame outside private kernel stack"))?;
            let ptr = custody
                .ram
                .host_ptr(gpa, size_of::<NativeFrame>())
                .ok_or_else(|| fail("forward completion frame backing"))?
                .cast::<NativeFrame>();
            let mut frame = token.frame;
            frame.rax = value as u64;
            // SAFETY: the exact stopped task owns this private kernel stack
            // after reloading its saved CPU image. Restore the whole frame
            // because another task may have used the stack during the wait.
            unsafe { ptr.write(frame) };
            Ok(())
        })
    }

    /// Service a retained forward after the exact task has regained a CPU.
    /// The frame remains owned by the task until `complete_forward` consumes it.
    pub fn with_retained_forward<R>(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
        token: &ProductionForwardFrame,
        service: impl FnOnce(&mut ForwardVenue<'_, M, Mem>) -> Result<R, TrapError>,
    ) -> Result<R, TrapError> {
        if token.task != task || self.physical_slot() != Some(token.slot) {
            return Err(fail("retained forward task or physical slot changed"));
        }
        let mut custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let children = self.cpu.child_binding_authority();
        self.cpu.with_forward_io(task, |io, active_binding| {
            let lease = StoppedCpuLease {
                cpu: token.slot,
                io,
            };
            let mut venue = ForwardVenue::new(&mut custody, lease, &children)?;
            venue
                .execution
                .authenticate(active_binding, "retained forward MM binding changed")?;
            if venue.execution.binding != token.execution.binding
                || venue.execution.context != token.execution.context
            {
                return Err(fail("retained forward MM binding changed"));
            }
            service(&mut venue)
        })
    }

    /// Synchronous root-only fs seed transport. Resource authority is supplied
    /// by the runtime; the carrier authenticates only execution and storage.
    pub fn service_root_fork_seed(
        &mut self,
        task: Option<carrick_guest_arch::TaskIdentity>,
        service: impl FnOnce(
            &mut carrick_core_abi::service::RootForkSeed,
        ) -> (
            bool,
            Option<Arc<dyn carrick_hal::fork_stock::ExecutableIdentity>>,
        ),
    ) -> Result<(), TrapError> {
        use carrick_core_abi::service::RootForkSeed;
        use carrick_guest_arch::KernelVa;
        let cpu = self
            .physical_slot()
            .ok_or_else(|| fail("seed CPU absent"))?;
        let custody = self
            ._custody
            .lock()
            .map_err(|_| fail("seed custody poisoned"))?;
        let capture = |io: &mut M| {
            let lease = StoppedCpuLease { cpu, io };
            let execution = custody.physical_execution(&lease)?;
            let initial = custody
                .initial_task
                .ok_or_else(|| fail("seed root absent"))?;
            if execution.context.mm != initial.mm {
                return Err(fail("fork seed requested outside the root"));
            }
            let address = KernelVa::new(lease.io.get_gpr(X86Reg::Rdi)?);
            let pointer = custody.native_service_pointer(
                execution.context,
                address,
                size_of::<RootForkSeed>(),
                align_of::<RootForkSeed>(),
            )?;
            // SAFETY: supervisor translation and retained RAM were authenticated
            // above. The stopped entry owns the box through this synchronous call.
            let record = unsafe { *pointer.cast::<RootForkSeed>() };
            Ok((execution, address, record))
        };
        let (execution, address, mut record) = match task {
            Some(task) => self.cpu.with_stopped_io(task, capture)?,
            None => self.cpu.with_idle_peer_io(capture)?,
        };
        drop(custody);
        if record.requested().is_none() {
            return Err(fail("seed request invalid"));
        }
        let (served, executable) = service(&mut record);
        if !served {
            return Ok(());
        }
        let mut custody = self
            ._custody
            .lock()
            .map_err(|_| fail("seed custody poisoned"))?;
        let finish = |io: &mut M| {
            let lease = StoppedCpuLease { cpu, io };
            let current = custody.physical_execution(&lease)?;
            if current.context != execution.context || current.binding != execution.binding {
                return Err(fail("seed execution changed"));
            }
            if let Some(executable) = executable {
                custody
                    .sources_mut(current.context)?
                    .bind_executable(executable);
            }
            let pointer = custody.native_service_pointer(
                current.context,
                address,
                size_of::<RootForkSeed>(),
                align_of::<RootForkSeed>(),
            )?;
            // SAFETY: same stopped execution and retained supervisor storage.
            unsafe {
                pointer.cast::<RootForkSeed>().write(record);
            }
            Ok(())
        };
        match task {
            Some(task) => self.cpu.with_stopped_io(task, finish),
            None => self.cpu.with_idle_peer_io(finish),
        }
    }

    /// Service one physical doorbell on the stopped worker CPU. Task
    /// identity is supplied by the executor's claimed binding, never by the
    /// doorbell payload or the physical slot.
    pub fn service_physical_doorbell(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
        exit: &CarrierRunExit,
        on_work: impl FnOnce(bool, Option<carrick_el1_abi::HostWorkDoorbell>),
    ) -> Result<Option<PhysicalProcessExit>, TrapError> {
        self.service_physical_doorbell_with_host_file(
            task,
            exit,
            on_work,
            &mut |_, _| Err(carrick_hal::fork_stock::NativeHostFileRefused),
            &mut refuse_native_exec,
        )
    }

    pub fn service_physical_doorbell_with_host_file(
        &mut self,
        task: carrick_guest_arch::TaskIdentity,
        exit: &CarrierRunExit,
        on_work: impl FnOnce(bool, Option<carrick_el1_abi::HostWorkDoorbell>),
        host_file: &mut NativeHostFileService<'_>,
        exec: &mut NativeExecLoadService<'_>,
    ) -> Result<Option<PhysicalProcessExit>, TrapError> {
        let CarrierRunExit::PhysicalDoorbell { port, .. } = exit else {
            return Err(fail("physical service requires a doorbell exit"));
        };
        if *port == carrick_core_abi::service::ROOT_FORK_SEED_PORT {
            self.service_root_fork_seed(Some(task), |_| (false, None))?;
            return Ok(None);
        }
        let slot = self
            .physical_slot()
            .ok_or_else(|| fail("production CPU has no physical slot"))?;
        let file = if matches!(
            production_port(*port),
            Some(ProductionPort::OwnerGrant | ProductionPort::NativeService)
        ) {
            self.read_owner_file(Some(task), *port == NATIVE_SERVICE_PORT)?
        } else {
            None
        };
        let mut custody = self
            ._custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let native_entropy = self.native_entropy;
        let mut work_flags = None;
        let mut pending_file = None;
        let mut pending_exec = None;
        let mut exec_rebind = None;
        let mut root_exec = None;
        let mut take_work = false;
        let (exit, register_child, unregister_child) = self.cpu.with_stopped_io(task, |io| {
            let lease = StoppedCpuLease { cpu: slot, io };
            let served = match production_port(*port) {
                Some(ProductionPort::OwnerGrant) => {
                    custody.owner_grant_crossings = custody
                        .owner_grant_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    custody.service_anonymous_grant(&lease, file)?;
                    Ok((None, None, None))
                }
                Some(ProductionPort::ForkStock) => {
                    custody.owner_grant_crossings = custody
                        .owner_grant_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    let child_binding = custody.service_fork_stock(&lease)?;
                    Ok((None, child_binding, None))
                }
                Some(ProductionPort::NativeExec) => {
                    match custody.service_native_exec(&lease, carrick_hal::exec_owner::ExecSettleLane::RootCustody)? {
                        exec_service::NativeExecCrossing::Settled { successor, predecessor } => {
                            exec_rebind = Some((successor, predecessor));
                        }
                        exec_service::NativeExecCrossing::RootSettled(settled) => {
                            root_exec = Some(settled);
                        }
                        exec_service::NativeExecCrossing::Answered => {}
                    }
                    Ok((None, None, None))
                }
                Some(ProductionPort::ChildRetire) => {
                    custody.child_retire_crossings = custody
                        .child_retire_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    let live_root = lease.io.get_gpr(X86Reg::Cr3)? & !0xfff;
                    let root_gpa = RootGpa::page_aligned(FrameGpa::new(live_root))
                        .ok_or_else(|| fail("unaligned child retire CR3"))?;
                    let retire_result = custody.service_child_retire(&lease);
                    Ok((None, None, Some((root_gpa, retire_result))))
                }
                Some(ProductionPort::SpaceRetired) => {
                    custody.service_space_retired(&lease)?;
                    Ok((None, None, None))
                }
                Some(ProductionPort::RunFailure) => {
                    let cause = custody.service_run_failure(&lease)?;
                    custody.run_failure_crossings = custody.run_failure_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    Ok((Some(PhysicalProcessExit::RunFailed(cause)), None, None))
                }
                Some(ProductionPort::RootExit) => {
                    custody.root_exit_crossings = custody
                        .root_exit_crossings
                        .checked_add(1)
                        .ok_or_else(|| fail("physical crossing counter exhausted"))?;
                    custody.service_root_exit(&lease).map(|status| (Some(PhysicalProcessExit::Exited(status)), None, None))
                }
                Some(ProductionPort::NativeService) => {
                    match custody.service_native_notice(&lease, file, native_entropy)? {
                        anonymous_owner::native_service::NativeNoticeStep::HostFile(pending) => {
                            pending_file = Some(pending);
                        }
                        anonymous_owner::native_service::NativeNoticeStep::Exec(pending) => {
                            pending_exec = Some(pending);
                        }
                        anonymous_owner::native_service::NativeNoticeStep::Settled => {}
                    }
                    Ok((None, None, None))
                }
                Some(ProductionPort::Work) => {
                    if let Ok(execution) = custody.physical_execution(&lease) {
                        custody.drain_fork_quarantine(execution)?;
                    } else if let Some(maintenance) = custody.maintenance_root {
                        let live = RootGpa::page_aligned(FrameGpa::new(lease.io.get_gpr(X86Reg::Cr3)?))
                            .ok_or_else(|| fail("work root alignment"))?;
                        if let Some(venue) = carrick_hal::fork_stock::ReclaimExecution::maintenance_root(live, maintenance) {
                            custody.drain_fork_quarantine_in(venue)?;
                        }
                    }
                    take_work = true;
                    Ok((None, None, None))
                }
                None => {
                    if *port == FATAL_PORT
                        && let Some(detail) = crate::ring_panic::fatal_port_panic_detail(&custody._vm, |reg| lease.io.get_gpr(reg))?
                    {
                        return Err(fail(detail));
                    }
                    let binding = custody.binding(slot);
                    let rip = lease.io.get_gpr(X86Reg::Rip).unwrap_or(0);
                    let rax = lease.io.get_gpr(X86Reg::Rax).unwrap_or(0);
                    Err(fail(format!(
                        "unexpected physical production port {port:#x} at rip {rip:#x} rax {rax:#x}; outer fault active {}, address {:#x}, reason {}",
                        binding.fault_active.load(Ordering::Acquire),
                        binding.fault_address.load(Ordering::Acquire),
                        binding.fault_reason.load(Ordering::Acquire),
                    )))
                }
            }?;
            // Any crossing can advance the fork stock's release, which only
            // flags a parked exec's row: every crossing the guest continues
            // from ends with the probe (a root exit or run failure ends it).
            if served.0.is_none() {
                custody.probe_parked_execs(lease.cpu)?;
            }
            if take_work {
                work_flags = Some(take_production_work_boundary(custody.task(slot))?);
            }
            Ok(served)
        })?;
        if let Some((child_binding, entry_task)) = register_child {
            self.cpu
                .register_child_binding_with_entry_task(child_binding, entry_task)?;
        }
        if let Some((live_root, retire_result)) = unregister_child {
            self.cpu.unregister_child_binding(live_root)?;
            retire_result?;
        }
        if let Some((successor, predecessor)) = exec_rebind {
            let root_successor = custody
                .initial_task
                .is_some_and(|initial| initial.mm == successor.context().mm);
            self.cpu
                .rebind_child_successor(successor, predecessor, root_successor)?;
        }
        if let Some(settled) = root_exec {
            // Guest entry on this CPU is refused until the executor consumes
            // the settlement through `retarget_root_exec`.
            let state = self.cpu.begin_root_exec_settlement(settled.successor())?;
            if self.root_exec.replace(settled.with_state(state)).is_some() {
                return Err(fail(
                    "a second root exec settled before the first was consumed",
                ));
            }
        }
        if let Some(PhysicalProcessExit::Exited(_) | PhysicalProcessExit::RunFailed(_)) = exit {
            self.cpu.clear_child_bindings()?;
        }
        let executable = pending_file.as_ref().and_then(|pending| {
            custody.native_file_executable(pending.ticket.request().identity.birth, &pending.record)
        });
        drop(custody);
        if let Some(pending) = pending_exec {
            let loaded = exec(
                pending.ticket.request().identity.birth.origin,
                &pending.payload,
            );
            let mut custody = self
                ._custody
                .lock()
                .map_err(|_| fail("physical custody poisoned"))?;
            self.cpu.with_stopped_io(task, |io| {
                let lease = StoppedCpuLease { cpu: slot, io };
                custody.finish_native_exec(&lease, pending, loaded)?;
                custody.probe_parked_execs(lease.cpu)
            })?;
        }
        if let Some(mut pending) = pending_file {
            let served = host_file(
                NativeHostFileCaller {
                    birth: pending.ticket.request().identity.birth,
                    executable,
                },
                &mut pending.record,
            );
            let mut custody = self
                ._custody
                .lock()
                .map_err(|_| fail("physical custody poisoned"))?;
            self.cpu.with_stopped_io(task, |io| {
                let lease = StoppedCpuLease { cpu: slot, io };
                custody.finish_native_host_file(&lease, *pending, served)?;
                custody.probe_parked_execs(lease.cpu)
            })?;
        }
        if let Some((served, doorbell)) = work_flags {
            on_work(served, doorbell);
        }
        Ok(exit)
    }
}

/// The carrier's exec loader for a native exec's staged payload, a fork
/// child's (#2235) or the run root's (#2142), invoked with physical custody
/// and CPU-I/O borrows released: the shared request parse, resolver and x86
/// image checks, or the exec's errno. The origin is the lineage the ticket's
/// authenticated service identity names: the root's request resolves under
/// the root's own filesystem authority, which the carrier retains.
pub type NativeExecLoadService<'a> = dyn FnMut(
        carrick_core_abi::service::ServiceOrigin,
        &[u8],
    ) -> Result<exec_service::NativeExecLoad, carrick_abi::LinuxErrno>
    + 'a;

/// A carrier with no exec capability leaves the exec unrouted: the
/// carrier's counted ENOSYS.
fn refuse_native_exec(
    _: carrick_core_abi::service::ServiceOrigin,
    _: &[u8],
) -> Result<exec_service::NativeExecLoad, carrick_abi::LinuxErrno> {
    Err(carrick_abi::LINUX_ENOSYS)
}

impl<Mem: CarrierMemoryIo> Cpl0HostCustody<Mem> {
    /// Retain the executable of the already authenticated stopped service member.
    /// Both the owner incarnation and the live physical stock entry must agree.
    fn native_file_executable(
        &mut self,
        birth: carrick_core_abi::service::ServiceBirth,
        record: &[u8],
    ) -> Option<Arc<dyn carrick_hal::fork_stock::ExecutableIdentity>> {
        use carrick_core_abi::host_file::{HostFileOp, request_parts};
        let (header, _, _) = request_parts(record)?;
        if header.op != HostFileOp::Readlinkat
            || birth.origin != carrick_core_abi::service::ServiceOrigin::Descendant
        {
            return None;
        }
        let mm = birth.mm.mm();
        if self.fork_stock.child_owner(mm) != Some(birth.mm) || self.fork_stock.is_quarantined(mm) {
            return None;
        }
        let root = self.fork_stock.child_root(mm)?;
        self.fork_stock.child_physical_mut(mm, root)?.executable()
    }
}

/// Caller authority retained before releasing the stopped carrier custody.
pub struct NativeHostFileCaller {
    pub birth: carrick_core_abi::service::ServiceBirth,
    pub executable: Option<Arc<dyn carrick_hal::fork_stock::ExecutableIdentity>>,
}

/// Host-file handler invoked with physical custody and CPU-I/O borrows released.
/// Serves one native host-file record for the requesting member (its birth
/// origin and zone record), writing the reply in place or answering a
/// host-readiness wait.
pub type NativeHostFileService<'a> = dyn FnMut(
        NativeHostFileCaller,
        &mut [u8],
    ) -> Result<
        carrick_hal::fork_stock::NativeHostFileReply,
        carrick_hal::fork_stock::NativeHostFileRefused,
    > + 'a;

enum ProductionPort {
    OwnerGrant,
    ForkStock,
    NativeExec,
    ChildRetire,
    SpaceRetired,
    RunFailure,
    RootExit,
    NativeService,
    Work,
}

fn production_port(port: u16) -> Option<ProductionPort> {
    match port {
        OWNER_GRANT_PORT => Some(ProductionPort::OwnerGrant),
        carrick_el1_abi::FORK_STOCK_PORT => Some(ProductionPort::ForkStock),
        carrick_el1_abi::NATIVE_EXEC_PORT => Some(ProductionPort::NativeExec),
        carrick_el1_abi::NATIVE_CHILD_RETIRE_PORT => Some(ProductionPort::ChildRetire),
        carrick_el1_abi::NATIVE_SPACE_RETIRED_PORT => Some(ProductionPort::SpaceRetired),
        carrick_core_abi::NATIVE_RUN_FAILURE_PORT => Some(ProductionPort::RunFailure),
        carrick_core_abi::NATIVE_ROOT_EXIT_PORT => Some(ProductionPort::RootExit),
        WORK_PORT => Some(ProductionPort::Work),
        NATIVE_SERVICE_PORT => Some(ProductionPort::NativeService),
        _ => None,
    }
}

fn take_production_work_boundary(
    task: &CurrentTask,
) -> Result<(bool, Option<carrick_el1_abi::HostWorkDoorbell>), TrapError> {
    let state = &task.linux;
    let boundary = state.take_served_boundary();
    if matches!(
        boundary,
        Some(
            carrick_el1_abi::ServedBoundary::ReplayOriginal { .. }
                | carrick_el1_abi::ServedBoundary::ForwardOriginal { .. }
        )
    ) {
        return Err(fail("x86 work boundary cannot replay a completed syscall"));
    }
    let doorbell = state.take_host_work_doorbell();
    if boundary.is_none() && doorbell.is_none() {
        return Err(fail("x86 work port without owed boundary work"));
    }
    Ok((boundary.is_some(), doorbell))
}

#[cfg(test)]
mod production_work_port_tests {
    use super::{
        CurrentTask, ProductionPort, WORK_PORT, production_port, take_production_work_boundary,
    };

    #[test]
    fn completed_cpl0_work_has_a_production_boundary() {
        assert!(matches!(
            production_port(WORK_PORT),
            Some(ProductionPort::Work)
        ));
    }

    #[test]
    fn work_boundary_consumes_only_the_stopped_tasks_flags_once() {
        let stopped = CurrentTask::new();
        let peer = CurrentTask::new();
        stopped.linux.record_completed_with_work();
        stopped.linux.mark_pending_host_work();
        peer.linux.record_completed_with_work();
        peer.linux.mark_pending_host_work();

        let (served, doorbell) = take_production_work_boundary(&stopped).unwrap();
        assert!(served);
        doorbell.expect("stopped task doorbell").settled();
        assert!(take_production_work_boundary(&stopped).is_err());
        assert!(peer.linux.has_pending_host_work());
        let (served, doorbell) = take_production_work_boundary(&peer).unwrap();
        assert!(served);
        doorbell.expect("peer doorbell").settled();
    }
}

impl<M: CarrierCpuIo, Mem: CarrierMemoryIo> ProductionCpuFactory<M, Mem> {
    /// Attach per-exit mirrors only after the run's debug endpoint is live.
    pub fn attach_debug(&self) {
        let mut cpus = self
            .cpus
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (cpu, debug) in cpus.iter_mut().zip(self.debug_cpus.iter()) {
            if let Some(cpu) = cpu {
                cpu.attach_debug(Arc::clone(debug));
            }
        }
    }

    /// Read the physical zone without taking an execution lease or entering
    /// the guest. A held host custody is reported, never waited on by the debugger.
    pub fn capture_physical_state(&self) -> ProductionPhysicalCapture {
        let mut capture = ProductionPhysicalCapture {
            zone_census: String::new(),
            vcpus: (0..2)
                .map(|index| self.debug_cpus[index].render(index))
                .collect(),
            unavailable: Vec::new(),
        };
        match self.custody.try_lock() {
            Ok(custody) => {
                if let Some(pointer) = custody.ram.host_ptr(
                    META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                    size_of::<X86Cpl0Zone>(),
                ) {
                    // SAFETY: the retained, initialized zone uses atomic
                    // readers for this deliberately non-coherent census.
                    let zone = unsafe { &*pointer.cast::<X86Cpl0Zone>() };
                    if zone.write_census(&mut capture.zone_census).is_err() {
                        capture
                            .unavailable
                            .push("zone census formatting failed".to_owned());
                    }
                } else {
                    capture.unavailable.push("zone backing absent".to_owned());
                }
                for index in 0..2 {
                    let task = custody.task(carrick_guest_arch::CpuId::new(index));
                    if task
                        .write_census(index as usize, &mut capture.zone_census)
                        .is_err()
                    {
                        capture
                            .unavailable
                            .push("current task census formatting failed".to_owned());
                    }
                    capture.vcpus[index as usize].push_str(&format!(
                        " actual_guest_run={} pending_host_work={} served_with_work={}",
                        custody.actual_run[index as usize].load(Ordering::Acquire) != 0,
                        task.linux.has_pending_host_work(),
                        task.linux.served_word(),
                    ));
                }
            }
            Err(_) => capture
                .unavailable
                .push("physical custody busy; pending host work unavailable".to_owned()),
        }
        capture
    }

    /// Place an already runnable fixture task using the real claim/run queues.
    /// Both CPUs must be stopped. Parked waiters are deliberately refused.
    pub fn fixture_place_native_thread(
        &self,
        tid: El1TaskId,
        cpu: carrick_guest_arch::CpuId,
    ) -> Result<(), TrapError> {
        self.fixture_place_native_thread_policy(tid, cpu, false)
    }

    /// Bind a queued, unhomed fixture thread to its actor CPU while stopped.
    /// Queue placement alone permits the other CPU to steal the child while
    /// its parent parks (an idle CPU steals any queued thread its affinity
    /// allows). A fixture holding that CPU stopped would then strand
    /// the child there instead of exercising the intended peer exit path.
    pub fn fixture_pin_native_thread(
        &self,
        tid: El1TaskId,
        cpu: carrick_guest_arch::CpuId,
    ) -> Result<(), TrapError> {
        self.fixture_place_native_thread_policy(tid, cpu, true)
    }

    fn fixture_place_native_thread_policy(
        &self,
        tid: El1TaskId,
        cpu: carrick_guest_arch::CpuId,
        pin_thread: bool,
    ) -> Result<(), TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let pointer = custody
            .ram
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            )
            .ok_or_else(|| fail("fixture native zone backing"))?;
        // SAFETY: boot initialized the aligned zone in this retained window.
        let zone = unsafe { &*pointer.cast::<X86Cpl0Zone>() };
        let record = (1..carrick_sched_core::ZONE_RECORDS as u32)
            .filter_map(carrick_sched_core::RecordId::from_raw)
            .find(|id| {
                zone.record(*id).identity().tid == tid.raw()
                    && matches!(
                        zone.record(*id).claim(),
                        carrick_sched_core::Claim::Queued { .. }
                    )
            })
            .ok_or_else(|| {
                let live: Vec<_> = (1..carrick_sched_core::ZONE_RECORDS as u32)
                    .filter_map(carrick_sched_core::RecordId::from_raw)
                    .filter_map(|id| {
                        let row = zone.record(id);
                        (row.claim() != carrick_sched_core::Claim::Free)
                            .then_some((row.identity(), row.claim()))
                    })
                    .collect();
                fail(format!(
                    "fixture task {} is not queued: {live:?}",
                    tid.raw()
                ))
            })?;
        if zone.record(record).home().is_some() || cpu.raw() >= 2 {
            return Err(fail(
                "fixture placement requires an unhomed task and live CPU",
            ));
        }
        let slot = SlotId::new(cpu.raw() as u8);
        let sink = custody.carrier_zone_wake()?;
        if zone.claim_for_host(
            zone.record_ref(record),
            None,
            carrick_sched_core::Handback::Resumed,
            &carrick_sched_core::BoundedSpin(0),
            &|owned| custody.complete_object_wake(cpu, &*sink, owned),
        ) != carrick_sched_core::HostClaim::Claimed
            || sink.take_undelivered().is_some()
        {
            return Err(fail("fixture queue placement refused"));
        }
        if pin_thread {
            // The host owns this exact unhomed queued thread, and a Host
            // claim has no live park timer. Use the existing home-release
            // primitive to publish its actor affinity: it clears a slot's
            // host home only when that home names this record, so a target
            // CPU running its own home thread (CPU 0's root) keeps it.
            let _ = zone.unhome(slot, record, 1 << cpu.raw());
        }
        if zone.requeue_on(slot, record).is_none() {
            return Err(fail("fixture queue placement refused"));
        }
        Ok(())
    }

    /// Observe an idle actor boundary after its queue guard has been released.
    /// This changes no scheduler claim, receipt readiness or wake generation.
    pub fn fixture_native_cpu_idle(
        &self,
        cpu: carrick_guest_arch::CpuId,
    ) -> Result<bool, TrapError> {
        if cpu.raw() >= 2 {
            return Err(fail("unknown native fixture CPU"));
        }
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let pointer = custody
            .ram
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            )
            .ok_or_else(|| fail("fixture native zone backing"))?;
        // SAFETY: boot initialized the aligned zone in this retained window.
        let zone = unsafe { &*pointer.cast::<X86Cpl0Zone>() };
        let slot = SlotId::new(cpu.raw() as u8);
        let Some(_guard) = zone.slot_lock(slot, &carrick_sched_core::BoundedSpin(0)) else {
            return Ok(false);
        };
        Ok(
            zone.slot(slot).state() == carrick_sched_core::SlotState::IdleWfi
                && zone.slot(slot).current().is_none()
                && zone.slot(slot).queued() == 0,
        )
    }

    /// Atomic fixture census of the actual native wait enrollment.
    /// The fixture retains this task generation; no lifecycle is completed here.
    pub fn fixture_native_wait_state(
        &self,
        tid: El1TaskId,
    ) -> Result<(carrick_sched_core::Claim, u64, u64), TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let pointer = custody
            .ram
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            )
            .ok_or_else(|| fail("fixture native zone backing"))?;
        // SAFETY: boot initialized the aligned zone in this retained window.
        let zone = unsafe { &*pointer.cast::<X86Cpl0Zone>() };
        let record = (1..carrick_sched_core::ZONE_RECORDS as u32)
            .filter_map(carrick_sched_core::RecordId::from_raw)
            .map(|id| zone.record(id))
            .find(|row| {
                row.identity().tid == tid.raw()
                    && (row.claim() != carrick_sched_core::Claim::Free || row.home().is_some())
            })
            .ok_or_else(|| fail("native wait record absent"))?;
        Ok((
            record.claim(),
            zone.counters.el1_parks.load(Ordering::Acquire),
            zone.counters.el1_wakes.load(Ordering::Acquire),
        ))
    }

    /// Fixture census of a stopped waker's host debt: the zone's misplaced
    /// wake count and whether `cpu`'s task rang its pending-host-work
    /// doorbell (`WakeEffects::owes_host_boundary`). Changes nothing.
    pub fn fixture_native_wake_debt(
        &self,
        cpu: carrick_guest_arch::CpuId,
    ) -> Result<(u64, bool), TrapError> {
        if cpu.raw() >= 2 {
            return Err(fail("unknown native fixture CPU"));
        }
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let pointer = custody
            .ram
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            )
            .ok_or_else(|| fail("fixture native zone backing"))?;
        // SAFETY: boot initialized the aligned zone in this retained window.
        let zone = unsafe { &*pointer.cast::<X86Cpl0Zone>() };
        Ok((
            zone.counters.el1_misplaced.load(Ordering::Acquire),
            custody.task(cpu).linux.has_pending_host_work(),
        ))
    }

    /// Run `body` while the host holds `cpu`'s run-queue lock, so a guest
    /// wake that targets that slot finds it busy (its bounded spin gives up)
    /// and falls back to the waker's own queue. Changes no claim itself.
    pub fn fixture_with_slot_locked<R>(
        &self,
        cpu: carrick_guest_arch::CpuId,
        body: impl FnOnce() -> R,
    ) -> Result<R, TrapError> {
        if cpu.raw() >= 2 {
            return Err(fail("unknown native fixture CPU"));
        }
        let pointer = {
            let custody = self
                .custody
                .lock()
                .map_err(|_| fail("physical custody poisoned"))?;
            custody
                .ram
                .host_ptr(
                    META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                    size_of::<X86Cpl0Zone>(),
                )
                .ok_or_else(|| fail("fixture native zone backing"))?
        };
        // SAFETY: boot initialized the aligned zone in this retained window,
        // and this factory (borrowed for the whole call) retains the RAM.
        let zone = unsafe { &*pointer.cast::<X86Cpl0Zone>() };
        let guard = zone
            .slot_lock(
                SlotId::new(cpu.raw() as u8),
                &carrick_sched_core::BoundedSpin(0),
            )
            .ok_or_else(|| fail("fixture slot lock busy"))?;
        let result = body();
        drop(guard);
        Ok(result)
    }

    /// Whether a guest CPU holds futex bucket `bucket`'s lock now (a waker
    /// inside its wake). Takes and drops the lock if free; changes nothing.
    pub fn fixture_futex_bucket_held(&self, bucket: usize) -> Result<bool, TrapError> {
        if bucket >= carrick_sched_core::ZONE_BUCKETS {
            return Err(fail("unknown fixture futex bucket"));
        }
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let pointer = custody
            .ram
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            )
            .ok_or_else(|| fail("fixture native zone backing"))?;
        // SAFETY: boot initialized the aligned zone in this retained window.
        let zone = unsafe { &*pointer.cast::<X86Cpl0Zone>() };
        Ok(zone
            .lock(bucket, &carrick_sched_core::BoundedSpin(0))
            .is_none())
    }

    /// Snapshot while this factory still retains the carrier metadata mapping.
    pub fn syscall_counters(&self) -> Result<Counters, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let counters: &Counters = custody.metadata(COUNTERS_OFFSET);
        Ok(counters.copy_snapshot())
    }

    pub fn refusal_count(&self, nr: carrick_abi::NativeNr) -> Result<u64, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let counters: &Counters = custody.metadata(COUNTERS_OFFSET);
        let index = usize::try_from(nr.raw())
            .ok()
            .filter(|index| *index < 512)
            .unwrap_or(512);
        Ok(counters.refused[index].load(Ordering::Acquire))
    }

    pub fn refusal_overflow_count(&self) -> Result<u64, TrapError> {
        self.refusal_count(carrick_abi::NativeNr(512))
    }

    pub fn robust_list_head(&self, index: usize) -> Result<u64, TrapError> {
        if index >= 2 {
            return Err(fail("unknown CPL0 task"));
        }
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let slot: &ThreadControlSlot = custody.metadata(CONTROL_OFFSET + index as u64 * STRIDE);
        Ok(slot.robust_list().0)
    }

    pub fn fixture_pending_irqs(&self, index: usize) -> Result<u32, TrapError> {
        if index >= 2 {
            return Err(fail("unknown CPL0 CPU slot"));
        }
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody
            .binding(carrick_guest_arch::CpuId::new(index as u32))
            .pending_irqs
            .load(Ordering::Acquire))
    }

    /// Publish owed work on the stopped slot's bound task for a live hardware
    /// doorbell witness. The next guest boundary must service this exact bit.
    pub fn fixture_mark_current_host_work(
        &self,
        slot: carrick_guest_arch::CpuId,
    ) -> Result<(), TrapError> {
        if slot.raw() >= 2 {
            return Err(fail("unknown CPL0 CPU slot"));
        }
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        custody.task(slot).linux.mark_pending_host_work();
        Ok(())
    }

    /// Route one hardware interrupt to a stopped production CPU. The IRQ is
    /// pending before its next KVM entry; no scheduler or service state is
    /// changed by the fixture.
    pub fn fixture_inject_irq(
        &self,
        slot: carrick_guest_arch::CpuId,
        vector: u8,
    ) -> Result<(), TrapError> {
        if slot.raw() >= 2 {
            return Err(fail("unknown CPL0 CPU slot"));
        }
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        custody
            ._vm
            .vm()
            .signal_msi(
                carrick_x86::interrupts::LAPIC_BASE as u32 | (slot.raw() << 12),
                u32::from(vector),
            )
            .map_err(|error| fail(format!("fixture IRQ injection: {error}")))
    }

    pub fn user_fault_state(&self, index: usize) -> Result<(u64, u64, u64, u64, u64), TrapError> {
        if index >= 2 {
            return Err(fail("unknown CPL0 task"));
        }
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let binding = custody.binding(carrick_guest_arch::CpuId::new(index as u32));
        let frame = binding.fault_frame.load(Ordering::Acquire);
        let (error, pc) = if frame == 0 {
            (0, 0)
        } else {
            let bytes = custody
                ._vm
                .read(
                    checked_fault_error_gpa(frame).ok_or_else(|| fail("fault frame overflow"))?,
                    16,
                )
                .map_err(|error| fail(error.to_string()))?;
            (
                u64::from_le_bytes(
                    bytes[..8]
                        .try_into()
                        .map_err(|_| fail("fault error width"))?,
                ),
                u64::from_le_bytes(bytes[8..].try_into().map_err(|_| fail("fault PC width"))?),
            )
        };
        Ok((
            binding.fault_active.load(Ordering::Acquire),
            binding.fault_address.load(Ordering::Acquire),
            error,
            pc,
            binding.fault_reason.load(Ordering::Acquire),
        ))
    }

    /// Lend authenticated file records only while every physical CPU is stopped.
    /// The capability and retained owner remain borrowed for the whole callback.
    pub fn with_stopped_file_tables<R>(
        &self,
        inspect: impl FnOnce(&StoppedFileTables<'_>) -> R,
    ) -> Result<R, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let tables = custody
            .file_tables(custody.files.registration.binding())
            .map_err(|error| fail(format!("stopped file tables: {error:?}")))?;
        Ok(inspect(&tables))
    }

    /// Read an aligned diagnostic atomic in the retained supervisor image.
    /// Resolve `address` from the exact loaded image, rather than a host symbol.
    pub fn supervisor_diagnostic_counter(
        &self,
        address: carrick_guest_arch::KernelVa,
    ) -> Result<u64, TrapError> {
        let offset = address
            .raw()
            .checked_sub(IMAGE_VA)
            .filter(|offset| offset.is_multiple_of(8) && *offset <= IMAGE_SIZE - 8)
            .ok_or_else(|| fail("diagnostic counter outside supervisor image"))?;
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let pointer = custody
            .ram
            .host_ptr(IMAGE_GPA + offset, 8)
            .ok_or_else(|| fail("diagnostic counter backing absent"))?;
        // SAFETY: the supervisor image is retained, page-aligned and initialized;
        // the bounded, aligned word is read atomically, including during execution.
        let word = unsafe { &*pointer.cast::<std::sync::atomic::AtomicU64>() };
        Ok(word.load(Ordering::Acquire))
    }

    pub fn initial_execution_witness(&self) -> Result<(u64, u64), TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok((
            custody
                .binding(carrick_guest_arch::CpuId::new(0))
                .entries
                .load(Ordering::Acquire),
            custody.host_forwards,
        ))
    }

    /// Host forwards served for a task stopped on the idle peer (CPU 1).
    pub fn idle_peer_forward_witness(&self) -> Result<u64, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.idle_peer_forwards)
    }

    /// Authenticated host-file requests completed on the idle peer (CPU 1).
    pub fn idle_peer_host_file_witness(&self) -> Result<u64, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.idle_peer_host_files)
    }

    pub fn anonymous_private_pages(&self) -> Result<u64, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.private_anonymous_witness.private_pages())
    }

    pub fn anonymous_private_mms(&self) -> Result<Vec<PrivateAnonymousMmEvidence>, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.anonymous_private_mms())
    }

    pub fn cross_mm_private_aliases(&self) -> Result<u64, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.cross_mm_private_aliases())
    }

    pub fn peer_active_private_grants(&self) -> Result<u64, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.peer_active_private_grants())
    }

    /// Owner-grant windows the run placed on large host pages: a 2 MiB GPA
    /// with a 2 MiB-aligned host mapping, which the hypervisor can map with
    /// one stage-2 entry (#3105).
    pub fn large_page_windows(&self) -> Result<u64, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.large_page_windows)
    }

    /// Cross-CPU translation drains the run published: each is one
    /// shootdown request (an IPI to every other CPU running the edited MM
    /// and a wait for its acknowledgement). A drain the editing CPU served
    /// alone, with no peer running the MM, publishes none (#3105).
    pub fn shootdown_rendezvous(&self) -> Result<u64, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let pointer = custody
            .ram
            .host_ptr(META_GPA + SHOOTDOWN_OFFSET, size_of::<ShootdownTable>())
            .ok_or_else(|| fail("shootdown table backing"))?;
        // SAFETY: boot initialized the retained table before any CPU ran;
        // its generation counter is atomic and only ever incremented.
        let table = unsafe { &*pointer.cast::<ShootdownTable>() };
        Ok(table.next_generation.load(Ordering::Acquire))
    }

    pub fn physical_crossing_counts(
        &self,
    ) -> Result<[(PhysicalCrossingFamily, u64); 6], TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok([
            (
                PhysicalCrossingFamily::OwnerGrant,
                custody.owner_grant_crossings,
            ),
            (
                PhysicalCrossingFamily::RootExit,
                custody.root_exit_crossings,
            ),
            (
                PhysicalCrossingFamily::ChildRetire,
                custody.child_retire_crossings,
            ),
            (
                PhysicalCrossingFamily::RunFailure,
                custody.run_failure_crossings,
            ),
            (
                PhysicalCrossingFamily::ReturnSettlement,
                custody.return_settlement_counters.doorbells,
            ),
            (
                PhysicalCrossingFamily::SpaceRetired,
                custody.space_retired_crossings,
            ),
        ])
    }

    /// The most KVM memslots the carrier held at once (#3099).
    pub fn peak_memslots(&self) -> Result<u64, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody._vm.peak_slot_count() as u64)
    }

    /// The KVM memslots the carrier holds now (#3099).
    pub fn live_memslots(&self) -> Result<u64, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody._vm.slot_count() as u64)
    }

    pub fn fork_admission_refusal(
        &self,
    ) -> Result<Option<carrick_hal::fork_stock::ForkAdmissionRefusal>, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.fork_stock.admission_refusal())
    }

    pub fn fork_stock_counters(
        &self,
    ) -> Result<carrick_hal::fork_stock::ForkStockCounters, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.fork_stock_counters())
    }

    pub fn fork_stock_release_waiters(&self) -> Result<usize, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.fork_stock.release_waiters())
    }

    /// Fork-stock table pages the carrier can issue now: the reusable stock
    /// and the never-issued reserve it draws from.
    pub fn fork_table_capacity(&self) -> Result<usize, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.fork_stock.table_capacity())
    }

    /// Run `body` (a CPU's run, no crossing service) while the host holds
    /// the one quarantined fork child's reservation root under physical
    /// custody, as a cross-MM owed-return settlement does. A crossing
    /// serviced after `body` returns waits for that hold's release.
    #[cfg(feature = "test-support")]
    pub fn fixture_with_quarantined_root_held<R>(
        &self,
        body: impl FnOnce() -> R,
    ) -> Result<R, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        custody.fixture_with_quarantined_root_held(body)
    }

    /// Run `body` (CPU runs and crossing services) while one borrower holds
    /// the one quarantined fork child's live notification lease, as a
    /// foreign-holder wait that enrols on that MM's release does without
    /// its reservation root (`carrick_core::wait::coordinate_holder_release_wait`).
    /// The lease is released only after `body` returns.
    #[cfg(feature = "test-support")]
    pub fn fixture_with_quarantined_notifications_borrowed<R>(
        &self,
        body: impl FnOnce() -> R,
    ) -> Result<R, TrapError> {
        let (ram, mm) = {
            let custody = self
                .custody
                .lock()
                .map_err(|_| fail("physical custody poisoned"))?;
            let [mm] = custody.fork_stock.quarantined_mms()[..] else {
                return Err(fail(
                    "fixture notification borrow needs exactly one quarantined child",
                ));
            };
            (Arc::clone(&custody.ram), mm)
        };
        let zone = anonymous_owner::retained_cow_zone(&ram)?;
        let lease = NonZeroU64::new(mm.raw())
            .and_then(|mm| zone.space_entry(mm))
            .ok_or_else(|| fail("fixture quarantined child unpublished"))?
            .live_notifications()
            .map_err(|error| fail(format!("fixture quarantined notifications: {error:?}")))?;
        let result = body();
        drop(lease);
        Ok(result)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn fixture_hold_fork_stock(
        &self,
        left: usize,
    ) -> Result<carrick_hal::fork_stock::SuccessorTables, TrapError> {
        let mut custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        let count = custody.fork_stock.table_capacity().saturating_sub(left);
        custody
            .fork_stock
            .reserve_successor_tables(count)
            .map_err(|error| fail(format!("hold fork stock: {error:?}")))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn fixture_release_fork_stock(
        &self,
        held: carrick_hal::fork_stock::SuccessorTables,
    ) -> Result<(), TrapError> {
        let mut custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        custody.fork_stock.return_successor_tables(held);
        Ok(())
    }

    /// Retire the exec rows the run left unadopted, once every CPU lane of
    /// this carrier has stopped (#2799). Returns the rows retired.
    pub fn retire_exec_preparations_at_carrier_exit(&self) -> Result<usize, TrapError> {
        let mut custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        custody.retire_native_execs_at_carrier_exit()
    }

    /// The exec owner's census observed through the production carrier.
    pub fn exec_owner_census(&self) -> Result<carrick_hal::exec_owner::ExecOwnerCensus, TrapError> {
        exec_owner_census_of(&self.custody)
    }

    /// Settlement work observed through the production carrier.
    pub fn return_settlement_counters(
        &self,
    ) -> Result<anonymous_owner::ReturnSettlementCounters, TrapError> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| fail("physical custody poisoned"))?;
        Ok(custody.return_settlement_counters)
    }

    pub fn claim(&self, slot: usize) -> Result<ProductionCpuLease<M, Mem>, TrapError> {
        let mut cpus = self.cpus.lock().map_err(|_| fail("CPU factory poisoned"))?;
        let cpu = cpus
            .get_mut(slot)
            .and_then(Option::take)
            .ok_or_else(|| fail("physical CPU already claimed or absent"))?;
        if cpu.physical_slot() != Some(carrick_guest_arch::CpuId::new(slot as u32)) {
            return Err(fail("claimed CPU physical identity mismatch"));
        }
        Ok(ProductionCpuLease {
            native_entropy: self.native_entropy,
            cpu,
            _custody: Arc::clone(&self.custody),
            root_exec: None,
        })
    }
}

impl<M: CarrierCpuIo, Mem: CarrierMemoryIo> ProductionWorkerParts<M, Mem> {
    /// Both CPUs share one root binding issued from `root_state` itself;
    /// callers cannot supply a second, possibly different, root binding.
    pub fn new(
        mut cpus: [CarrierCpu<M>; 2],
        custody: BootstrapCustody<Mem>,
        root_state: carrick_x86::arch_context::X86ArchContext,
    ) -> Self {
        let root = CarrierRootBinding::issued(root_state.binding());
        for cpu in &mut cpus {
            cpu.bind_root(root.clone());
        }
        Self {
            cpus,
            custody: custody.0,
            root_state,
        }
    }

    pub fn into_factory(
        self,
        native_entropy: NativeEntropyService,
    ) -> (
        carrick_x86::arch_context::X86ArchContext,
        ProductionCpuFactory<M, Mem>,
    ) {
        let Self {
            cpus,
            custody,
            root_state,
        } = self;
        let debug_cpus: [Arc<CarrierCpuDebug>; 2] =
            std::array::from_fn(|_| Arc::new(CarrierCpuDebug::default()));
        (
            root_state,
            ProductionCpuFactory {
                native_entropy,
                cpus: std::sync::Mutex::new(cpus.map(Some)),
                custody: Arc::new(std::sync::Mutex::new(custody)),
                debug_cpus,
            },
        )
    }
    pub fn root_state(&self) -> &carrick_x86::arch_context::X86ArchContext {
        &self.root_state
    }
}
/// The kernel graph's issued root identity for the first production task.
/// Physical CPU slots never manufacture these values.
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
pub struct InitialTaskBinding {
    pub task: carrick_sched_core::process::TaskKey,
    pub thread: carrick_sched_core::ThreadIdentity,
    pub mm: MmGeneration,
}

impl InitialTaskBinding {
    /// The run root after `execve` from `predecessor` to `successor`. Exec
    /// keeps the Linux task and TID; the MM, the thread serial and the
    /// execution generation are the successor's. A predecessor that is not
    /// this exact root is stale.
    pub fn exec_successor(
        self,
        predecessor: carrick_hal::guest_arch_binding::GuestArchBinding,
        successor: carrick_hal::guest_arch_binding::GuestArchBinding,
        successor_thread_serial: u64,
    ) -> Result<Self, TrapError> {
        if self.mm != predecessor.context().mm
            || self.task.serial.raw() != predecessor.task().task.raw().get()
            || self.thread.generation != predecessor.task().execution.raw().get()
            || successor_thread_serial == 0
        {
            return Err(fail("root exec names a stale initial task"));
        }
        let successor = predecessor.exec_successor(successor)?;
        let mut thread = self.thread;
        thread.serial = successor_thread_serial;
        thread.generation = successor.task().execution.raw().get();
        Ok(Self {
            task: self.task,
            thread,
            mm: successor.context().mm,
        })
    }
}

/// The process leader of the MM a stopped forward runs on. The run root
/// leads its own MM by its issued TID; a descendant's leader is the entry
/// key its fork settlement issued (`issued`, `None` on the root's MM). The
/// stopped task's own key never chooses the leader: a member differs from it
/// and is a [`ForwardSubject::Member`].
fn forward_leader_task(
    initial: Option<InitialTaskBinding>,
    mm: MmGeneration,
    issued: Option<carrick_el1_abi::EntryTaskKey>,
) -> Result<carrick_el1_abi::EntryTaskKey, TrapError> {
    let leader = match initial {
        Some(initial) if mm == initial.mm => {
            carrick_el1_abi::EntryTaskKey::from_raw(initial.thread.tid)
        }
        _ => issued.ok_or_else(|| fail("child forward root has no issued entry key"))?,
    };
    if leader.raw() == 0 {
        return Err(fail("stopped forward task has no issued entry key"));
    }
    Ok(leader)
}

/// A single movable view into metadata retained by `Cpl0HostCustody`.
/// Deliberately neither `Clone` nor `Sync`.
struct RetainedMetadataPtr(NonNull<u8>);

impl RetainedMetadataPtr {
    fn as_ptr(&self) -> *mut u8 {
        self.0.as_ptr()
    }
}

// SAFETY: only the enclosing exclusive custody can access this pointer. Its
// GuestRam and registered backing live in that same custody, so moving this
// non-cloneable view to another thread cannot outlive or alias its storage.
unsafe impl Send for RetainedMetadataPtr {}

/// Registration and mapping have one custody. Registration drops first,
/// withdrawing publication while its own backing remains mapped.
struct RetainedFileRegion {
    registration: carrick_el1_abi::FileRegionRegistration,
    execution: Arc<RwLock<()>>,
    _backing: Arc<BackingExtent>,
}

/// Host file references own exclusive execution admission against `run_member`.
/// The single-step fixture bypasses it under exclusive mutable carrier custody;
/// M1 `CarrierMachine::create_stopped` has no F2 admission or file registration.
/// Atomics alone and the host image's descriptor lock are not this proof.
///
/// Limit (F3/F4 constraint): acquisition checks only the fd-map transaction word.
/// A kicked CPU can still hold a `DelegatedFile` inode lock. This proof does not
/// establish inode-lock quiescence for `objects()` / `opens()`; host operations
/// needing those locks can still stall on a paused guest owner.
pub struct StoppedFileTables<'a> {
    tables: carrick_el1_abi::FileTables<'a>,
    _stopped: RwLockWriteGuard<'a, ()>,
}

impl<'a> core::ops::Deref for StoppedFileTables<'a> {
    type Target = carrick_el1_abi::FileTables<'a>;
    fn deref(&self) -> &Self::Target {
        &self.tables
    }
}

// SAFETY: moved only inside exclusive carrier custody. The non-cloning
// registration never escapes its retained backing, and tables use atomics
// and their existing inode/descriptor owners for concurrent guest access.
unsafe impl Send for RetainedFileRegion {}

pub(crate) struct WindowSlotEntry {
    pub(crate) handle: BackingHandle,
    pub(crate) gpa: FrameGpa,
    pub(crate) identity: BackingIdentity,
    pub(crate) _inode_lease: Arc<dyn std::any::Any + Send + Sync>,
    pub(crate) committed: bool,
    pub(crate) pending_holders: std::collections::BTreeSet<(NonZeroU64, NonZeroU64)>,
}

/// One coordinator owns physical backing, grants and retained metadata.
/// CPU execution leases are disjoint from this custody, so stopped host service
/// never borrows the carrier or a simultaneously running peer CPU.
pub(crate) struct Cpl0HostCustody<M: CarrierMemoryIo> {
    pub(crate) _vm: CarrierMemory<M>,
    pub(crate) ram: Arc<GuestRam>,
    birth_live: BirthSourceRevocation,
    initial_extent: Option<(BackingHandle, usize)>,
    pub(crate) clock_vvar: Option<carrick_mem::vdso::X86NativeVvar>,
    _kernel_region: Option<BackingHandle>,
    files: RetainedFileRegion,
    frame_inventory: Arc<dyn PhysicalFrameInventory>,
    pub(crate) private_anonymous_witness: crate::cpl0_private_witness::PrivateAnonymousWitness,
    actual_run: Arc<[AtomicU32; 2]>,
    kernel_pod_storage: Vec<anonymous_owner::KernelPodStorage>,
    initial_inventory: Option<InitialInventory>,
    initial_rollback_fault: Arc<carrick_hal::physical_grants::PhysicalGrantRollback>,
    peer_entry: Option<carrick_guest_arch::KernelVa>,
    peer_admission: InitialPeerAdmission,
    initial_task: Option<InitialTaskBinding>,
    /// The zone's stdio descriptions, admitted once at boot (#2820).
    stdio: stdio::StdioCustody,
    /// The ISA-neutral fork stock, loans and child quarantine.
    fork_stock: carrick_hal::fork_stock::ForkStock<
        carrick_hal::fork_stock::UntaggedRoots,
        carrick_hal::fork_stock::ForkHostBackingCustody,
    >,
    initial_sources: Option<(
        AddressContext<RootGpa>,
        carrick_hal::fork_stock::ForkHostBackingCustody,
    )>,
    maintenance_root: Option<RootGpa>,
    anonymous_next_gpa: FrameGpa,
    /// Owner-grant windows placed on large host pages (#3105).
    large_page_windows: u64,
    /// The carrier's exec owner (#2305): its receipts, reserved at claim,
    /// the successors staged before their arm, the requests parked on the
    /// fork stock's release, and the adopted execs awaiting settlement.
    exec_owner: exec_service::X86ExecOwner,
    /// Adopted exec predecessor custody, split before and after the exact
    /// exec-owner settlement grants release authority.
    exec_predecessors: exec_service::ExecPredecessorCustody,
    /// The run root's adopted exec awaiting its settlement (#2142): the
    /// successor MM and the loader's Kernel half, which the settlement hands
    /// to the executor. At most one: the root has one thread group.
    root_exec_load: Option<(
        carrick_hal::exec_owner::AuthenticatedExecMm,
        exec_service::RootExecLoad,
    )>,
    /// Per CPU: the owner-selected window this CPU's member is serving. The
    /// ring settles or withdraws it before the member can park.
    anonymous_pending: [Option<anonymous_owner::PendingPrepare>; 2],
    /// The carrier's memory-ownership core (#3061): its MMs, their editor
    /// record, and the copy-on-write grants each MM owns (#2749).
    mm_core: anonymous_owner::X86MmCore,
    native_backing_pending:
        std::collections::BTreeMap<carrick_guest_arch::KernelVa, anonymous_owner::PendingPrepare>,
    /// Refused or withdrawn backings settled while their MM's exclusion was
    /// busy: cancelled at that MM's next exclusion.
    cancelled_backing_pending: Vec<anonymous_owner::PendingPrepare>,
    /// Shared file window slots (#1338), by host device, inode and 2 MiB
    /// chunk: a host `mmap(MAP_SHARED)` of the chunk installed once and kept
    /// for the run, with its GPA, backing identity, and shrink-fence lease.
    /// Declared after `_vm` so carrier teardown unmaps host extents before
    /// unregistering inodes (#2975 P0 2).
    window_slots: std::collections::BTreeMap<(u64, u64, u64), WindowSlotEntry>,
    owner_grant_crossings: u64,
    /// Serializes every settlement of an MM's owed returns (#1369 slice 3).
    return_settlement: carrick_hal::return_settlement::SettlementLock,
    return_settlement_counters: anonymous_owner::ReturnSettlementCounters,
    /// Fixture-held editors of a full owed-return table's holders (#1482).
    #[cfg(feature = "test-support")]
    fixture_holder_hold: Option<Arc<anonymous_owner::OwedReturnHolderHold>>,
    root_exit_crossings: u64,
    child_retire_crossings: u64,
    /// [`carrick_el1_abi::NATIVE_SPACE_RETIRED_PORT`] crossings (#3030).
    space_retired_crossings: u64,
    run_failure_crossings: u64,
    metadata_base: RetainedMetadataPtr,
    host_forwards: u64,
    /// Host forwards captured from a task stopped on the idle peer (CPU 1),
    /// so a fixture can prove where EL1 placed the forwarding task.
    idle_peer_forwards: u64,
    idle_peer_host_files: u64,
    host_yields: u64,
    kicks: u64,
    work_exits: u64,
}

impl<M: CarrierMemoryIo> Drop for Cpl0HostCustody<M> {
    fn drop(&mut self) {
        self.birth_live.retire();
        // The carrier's MMs end with it: their unsettled copy-on-write grants
        // come back here (each was exposed to the guest, so its inventory
        // keeps the extent through teardown). A host edit still open is a
        // broken invariant.
        match self.mm_core.retire_all_mms() {
            Ok(grants) => drop(grants),
            Err(_) => carrick_el1_linux::dispatch::invalid_completion(
                carrick_el1_linux::dispatch::NativeInvariant::PhysicalCustody(
                    carrick_el1_linux::dispatch::PhysicalCustodyInvariant::CoreDroppedHolding,
                ),
            ),
        }
        // Unwind the inventory first. Its destructor only records a refused
        // retirement; this carrier observer chooses the existing fail-stop.
        drop(self.initial_inventory.take());
        if self.initial_rollback_fault.failed() {
            carrick_el1_linux::dispatch::invalid_completion(
                carrick_el1_linux::dispatch::NativeInvariant::PhysicalCustody(
                    carrick_el1_linux::dispatch::PhysicalCustodyInvariant::InventoryRollbackFailed,
                ),
            );
        }
    }
}

/// Exclusive physical CPU custody while the executor vCPU has returned.
pub(crate) struct StoppedCpuLease<'a, I: CarrierCpuIo> {
    cpu: carrick_guest_arch::CpuId,
    io: &'a mut I,
}

/// Host crossings see only their stopped physical lane and exact MM owner.
/// Process policy and task selection remain in the shared guest owner.
pub struct ForwardVenue<'a, M: CarrierCpuIo, Mem: CarrierMemoryIo = M> {
    custody: &'a mut Cpl0HostCustody<Mem>,
    lease: StoppedCpuLease<'a, M>,
    execution: ForwardExecution,
}

impl<M: CarrierMemoryIo> Cpl0HostCustody<M> {
    pub fn ipc_table_map(
        &self,
    ) -> Result<Arc<dyn carrick_el1_abi::ipc_tables::IpcTableMapBacking>, TrapError> {
        let base = self
            .files
            ._backing
            .host_base()
            .map_err(|e| fail(e.to_string()))?;
        Ok(Arc::new(RetainedIpcTableMap {
            _backing: Arc::clone(&self.files._backing),
            base,
        }))
    }

    /// Lend the stdio custody beside the file tables, only while every
    /// physical CPU is stopped and no guest descriptor transaction is open.
    fn with_stdio<R>(
        &mut self,
        edit: impl FnOnce(&mut stdio::StdioCustody, &carrick_el1_abi::FileTables<'_>) -> R,
    ) -> Result<R, TrapError> {
        let _stopped = self
            .files
            .execution
            .try_write()
            .map_err(|_| fail("stdio tables while a CPU runs"))?;
        let tables = self
            .files
            .registration
            .tables(self.files.registration.binding())
            .map_err(|error| fail(format!("stdio tables: {error:?}")))?;
        if tables.fd_map()[0].mutation_active() {
            return Err(fail("stdio tables inside a guest descriptor transaction"));
        }
        Ok(edit(&mut self.stdio, &tables))
    }

    pub fn file_tables(
        &self,
        binding: carrick_el1_abi::FileRegionBinding,
    ) -> Result<StoppedFileTables<'_>, carrick_el1_abi::FileRegionError> {
        let stopped = self
            .files
            .execution
            .try_write()
            .map_err(|_| carrick_el1_abi::FileRegionError::Running)?;
        let tables = self.files.registration.tables(binding)?;
        // A kick may stop CPL0 inside a descriptor transaction. Execution
        // exclusion prevents reentry while its shared lock state is checked.
        if tables.fd_map()[0].mutation_active() {
            return Err(carrick_el1_abi::FileRegionError::MutationActive);
        }
        Ok(StoppedFileTables {
            tables,
            _stopped: stopped,
        })
    }

    fn metadata<T>(&self, offset: u64) -> &T {
        // SAFETY: the retained owner initialized each aligned record before
        // publication. Callers access atomic metadata or their stopped lane.
        unsafe { &*self.metadata_base.as_ptr().add(offset as usize).cast::<T>() }
    }

    pub fn task(&self, cpu: carrick_guest_arch::CpuId) -> &CurrentTask {
        self.metadata(TASK_OFFSET + u64::from(cpu.raw()) * STRIDE)
    }

    pub fn binding(&self, cpu: carrick_guest_arch::CpuId) -> &CpuBinding {
        self.metadata(BINDING_OFFSET + u64::from(cpu.raw()) * STRIDE)
    }
}

impl<'a, M: CarrierCpuIo, Mem: CarrierMemoryIo> ForwardVenue<'a, M, Mem> {
    fn new(
        custody: &'a mut Cpl0HostCustody<Mem>,
        lease: StoppedCpuLease<'a, M>,
        children: &CarrierChildBindings,
    ) -> Result<Self, TrapError> {
        let cpu = lease.cpu;
        let task = custody.task(cpu);
        let binding = carrick_core::entry::binding(&task.execution, &task.mm);
        let mm = NonZeroU64::new(binding.mm.raw()).ok_or_else(|| fail("stopped forward MM"))?;
        let context = custody
            ._vm
            .root(mm)
            .ok_or_else(|| fail("stopped forward root"))?;
        let native = custody.binding(cpu);
        let root = RootGpa::page_aligned(FrameGpa::new(lease.io.get_gpr(X86Reg::Cr3)?))
            .ok_or_else(|| fail("stopped forward CR3 alignment"))?;
        let generation = ContextGeneration::new(
            NonZeroU64::new(native.mm_owner_generation.load(Ordering::Acquire))
                .ok_or_else(|| fail("stopped forward address incarnation"))?,
        );
        let issued = if custody
            .initial_task
            .is_some_and(|initial| initial.mm == context.mm)
        {
            None
        } else {
            children.entry_task(context.root)?
        };
        let leader_task = forward_leader_task(custody.initial_task, context.mm, issued)?;
        let execution = admit_forward_execution(
            cpu,
            carrick_guest_arch::CpuId::new(native.cpu_slot),
            binding,
            context,
            root,
            generation,
        )?
        .with_leader_task(leader_task);
        Ok(Self {
            custody,
            lease,
            execution,
        })
    }

    pub fn cpu(&self) -> carrick_guest_arch::CpuId {
        self.execution.cpu
    }

    /// Who is stopped here: the root binding's leader, or a member of it.
    pub fn subject(&self) -> ForwardSubject {
        self.execution.subject()
    }

    /// The stopped task released the last reference to a stdio description:
    /// RDI the binding, RSI the description handle, RDX its incarnation. Only
    /// the exact description the carrier admitted, once, is accepted; the
    /// answer is the stdio descriptor number it was admitted as.
    pub fn release_stdio(
        &mut self,
        binding: u64,
        handle: u64,
        incarnation: u64,
    ) -> Result<i32, TrapError> {
        let handle = u32::try_from(handle)
            .map_err(|_| fail(format!("host object release handle {handle} out of range")))?;
        self.custody
            .stdio
            .release(
                binding,
                carrick_el1_linux::file_table::ReleasedDescription {
                    handle,
                    incarnation,
                },
            )
            .map_err(|refusal| fail(refusal.to_string()))
    }

    /// Authenticate that the stopped task's own CPL0 file table holds a live
    /// writable open description bound to `expected`.
    pub fn stopped_task_has_writable_host_object(
        &self,
        expected: carrick_el1_abi::HostObjectBinding,
    ) -> Result<bool, TrapError> {
        let file_table = self
            .custody
            .task(self.execution.cpu)
            .linux
            .file_table
            .load(Ordering::Acquire)
            .max(1);
        let region = self.custody.binding(self.execution.cpu).file_region;
        let tables = self
            .custody
            .files
            .registration
            .tables(region)
            .map_err(|error| fail(format!("stopped task file tables: {error:?}")))?;
        let _guard = carrick_el1_abi::lock_fd_map(tables.fd_map());
        Ok(tables
            .fd_map()
            .iter()
            .take(carrick_el1_abi::FD_MAP_CAPACITY)
            .any(|slot| {
                let inc = slot.incarnation.load(Ordering::Acquire);
                if inc == 0
                    || inc == carrick_el1_abi::FdMapSlot::CLAIMED
                    || slot.file_table.load(Ordering::Relaxed) != file_table
                {
                    return false;
                }
                let handle = slot.handle.load(Ordering::Relaxed);
                handle
                    .checked_sub(1)
                    .and_then(|idx| tables.opens().get(idx as usize))
                    .is_some_and(|open| {
                        open.state.load(Ordering::Acquire) == carrick_el1_abi::DELEGATED_STATE_GUEST
                            && open.flags.load(Ordering::Acquire)
                                & carrick_el1_abi::DELEGATED_FLAG_WRITABLE
                                != 0
                            && open.host_object() == Some(expected)
                    })
            }))
    }
}

fn checked_readiness_region(base: u64, offset: u64, length: usize, extent: u64) -> Option<u64> {
    let length = u64::try_from(length).ok()?;
    (offset.checked_add(length)? <= extent)
        .then(|| base.checked_add(offset))
        .flatten()
}

pub fn checked_stack_end(kernel_stack: u64) -> Option<u64> {
    kernel_stack.checked_add(carrick_el1_abi::X86_CPL0_KERNEL_STACK_TOP_RESERVE)
}

pub fn checked_private_stack_frame_gpa(stack_end: u64, address: u64, length: usize) -> Option<u64> {
    let stack_start = stack_end.checked_sub(carrick_el1_abi::X86_CPL0_KERNEL_STACK_SIZE)?;
    let length = u64::try_from(length).ok()?;
    if address & 7 != 0 || address < stack_start || address.checked_add(length)? > stack_end {
        return None;
    }
    let gpa = address.checked_sub(DIRECT_VA)?;
    gpa.checked_add(length)?;
    Some(gpa)
}

pub fn checked_fault_error_gpa(frame: u64) -> Option<FrameGpa> {
    let gpa = frame.checked_sub(DIRECT_VA)?.checked_add(120)?;
    gpa.checked_add(16)?;
    Some(FrameGpa::new(gpa))
}

#[cfg(test)]
mod readiness_span_tests {
    #[test]
    fn supervisor_readiness_span_rejects_host_address_overflow() {
        assert_eq!(
            super::checked_readiness_region(u64::MAX - 8, 16, 16, 64),
            None
        );
        assert_eq!(
            super::checked_readiness_region(0x1000, 16, 16, 32),
            Some(0x1010)
        );
        assert_eq!(super::checked_readiness_region(0x1000, 17, 16, 32), None);
    }

    #[test]
    fn private_stack_and_fault_frame_reject_wrapped_metadata() {
        assert_eq!(super::checked_stack_end(u64::MAX), None);
        assert_eq!(super::checked_private_stack_frame_gpa(8, 0, 16), None);
        assert_eq!(super::checked_fault_error_gpa(0), None);
        assert_eq!(super::checked_fault_error_gpa(super::DIRECT_VA - 1), None);
    }
}

impl<'a, M: CarrierCpuIo, Mem: CarrierMemoryIo> ForwardVenue<'a, M, Mem> {
    /// Inspect a typed readiness batch in the stopped task's supervisor
    /// region. The batch stays on its task-owned kernel stack or heap while
    /// an owned continuation releases the physical CPU.
    pub fn with_host_readiness_entries<R>(
        &mut self,
        address: u64,
        count: usize,
        use_entries: impl FnOnce(&mut [carrick_el1_abi::HostReadinessEntry]) -> R,
    ) -> Result<R, TrapError> {
        if count > 1024 {
            return Err(fail("host readiness batch exceeds poll bound"));
        }
        if count == 0 {
            // Zero-fd poll carries only a deadline. No guest pointer is
            // dereferenced, and an empty Rust slice need not have a guest VA.
            return Ok(use_entries(&mut []));
        }
        let length = count
            .checked_mul(size_of::<carrick_el1_abi::HostReadinessEntry>())
            .ok_or_else(|| fail("host readiness batch length overflow"))?;
        let region = if let Some(offset) = address.checked_sub(X86_CPL0_BOOTSTRAP_METADATA_BASE)
            && offset < EL1_BOOTSTRAP_METADATA_SIZE
        {
            Some((ALLOCATOR_GPA, offset, EL1_BOOTSTRAP_METADATA_SIZE))
        } else if let Some(offset) = address.checked_sub(X86_CPL0_REGION_BASE)
            && offset < carrick_el1_abi::EL1_REGION_SIZE
        {
            Some((KERNEL_REGION_GPA, offset, carrick_el1_abi::EL1_REGION_SIZE))
        } else {
            None
        };
        let (region_gpa, offset, region_len) = region.ok_or_else(|| {
            fail(format!(
                "host readiness batch outside supervisor region: {address:#x}"
            ))
        })?;
        if !address
            .is_multiple_of(core::mem::align_of::<carrick_el1_abi::HostReadinessEntry>() as u64)
        {
            return Err(fail("host readiness batch outside supervisor region"));
        }
        let gpa = checked_readiness_region(region_gpa, offset, length, region_len)
            .ok_or_else(|| fail("host readiness batch outside supervisor region"))?;
        let ptr = self
            .custody
            .ram
            .host_ptr(gpa, length)
            .ok_or_else(|| fail("host readiness batch has no backing"))?
            .cast::<carrick_el1_abi::HostReadinessEntry>();
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|_| fail("host readiness batch allocation failed"))?;
        for index in 0..count {
            // SAFETY: the checked span contains `count` aligned records. The
            // stopped task owns this batch; no Rust reference to guest RAM is
            // created while another vCPU may access the physical backing.
            entries.push(unsafe { core::ptr::read_volatile(ptr.add(index)) });
        }
        let result = use_entries(&mut entries);
        for (index, entry) in entries.into_iter().enumerate() {
            // SAFETY: the same checked span remains live through this stopped
            // carrier service; the write publishes only the staged record.
            unsafe { core::ptr::write_volatile(ptr.add(index), entry) };
        }
        Ok(result)
    }

    fn authenticate_initial_copy_page(
        &self,
        output: FrameGpa,
        address: u64,
    ) -> Result<(), MemoryError> {
        let page = output.raw() & !4095;
        let mm_key = self.execution.binding.mm.raw();
        let identity = self
            .custody
            ._vm
            .frame_identity(
                NonZeroU64::new(mm_key).ok_or(MemoryError::Unsupported)?,
                FrameGpa::new(page),
            )
            .map_err(|_| MemoryError::OutOfBounds { address, length: 1 })?;
        let row = self
            .custody
            .frame_inventory
            .bind(self.execution.context.into())
            .live_mapping_row(MappingId::from_kernel_allocation(identity.mapping_id))
            .ok_or(MemoryError::OutOfBounds { address, length: 1 })?;
        if row.frame != FrameId::from_kernel_allocation(identity.frame_id)
            || row.generation != MappingGeneration::from_backend_counter(identity.owner_generation)
            || page < row.gpa.raw()
            || page.checked_add(4096).is_none_or(|end| {
                row.gpa
                    .raw()
                    .checked_add(row.length.raw())
                    .is_none_or(|limit| end > limit)
            })
        {
            return Err(MemoryError::OutOfBounds { address, length: 1 });
        }
        Ok(())
    }
}

impl<M: CarrierCpuIo, Mem: CarrierMemoryIo> GuestMemory for ForwardVenue<'_, M, Mem> {
    fn read_bytes_prefix(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        // This bounded crossing copy has one frame of host storage at a time.
        // A later inaccessible page leaves Linux the already readable prefix.
        let limit = length.min(1024 * 1024);
        let mut bytes = Vec::new();
        while bytes.len() < limit {
            let Some(va) = address.checked_add(bytes.len() as u64) else {
                break;
            };
            let count = ((4096 - (va & 4095)) as usize).min(limit - bytes.len());
            match self.read_bytes_raw(va, count) {
                Ok(page) => bytes.extend(page),
                Err(error) if bytes.is_empty() => return Err(error),
                Err(_) => break,
            }
        }
        Ok(bytes)
    }

    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let ceiling =
            carrick_hal::guest_arch::UserVaCeiling::for_abi(carrick_abi::LinuxGuestAbi::X86_64)
                .exclusive_end();
        if length != 0
            && (address >= ceiling
                || address
                    .checked_add(length as u64)
                    .is_none_or(|end| end > ceiling))
        {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        let root = self.execution.context.root;
        let mut bytes = Vec::new();
        while bytes.len() < length {
            let va = address
                .checked_add(bytes.len() as u64)
                .ok_or(MemoryError::OutOfBounds { address, length })?;
            let leaf = translate_leaf(
                &self.custody._vm.words(),
                root,
                UserVa::new(va),
                Access::Read,
                true,
            )
            .map_err(|_| MemoryError::OutOfBounds {
                address: va,
                length,
            })?;
            self.authenticate_initial_copy_page(leaf.output, va)?;
            let count = (4096 - (va & 4095)) as usize;
            let count = count.min(length - bytes.len());
            let page = self.custody._vm.read(leaf.output, count).map_err(|_| {
                MemoryError::OutOfBounds {
                    address: va,
                    length,
                }
            })?;
            // A caller can request far more bytes than its live MM maps.
            // Admit storage only as each stage-1 page proves readable.
            bytes
                .try_reserve(page.len())
                .map_err(|_| MemoryError::MetadataAllocation)?;
            bytes.extend(page);
        }
        Ok(bytes)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let ceiling =
            carrick_hal::guest_arch::UserVaCeiling::for_abi(carrick_abi::LinuxGuestAbi::X86_64)
                .exclusive_end();
        if !bytes.is_empty()
            && (address >= ceiling
                || address
                    .checked_add(bytes.len() as u64)
                    .is_none_or(|end| end > ceiling))
        {
            return Err(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }
        let root = self.execution.context.root;
        let mut written = 0;
        while written < bytes.len() {
            let va = address
                .checked_add(written as u64)
                .ok_or(MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                })?;
            let leaf = translate_leaf(
                &self.custody._vm.words(),
                root,
                UserVa::new(va),
                Access::Write,
                true,
            )
            .map_err(|_| MemoryError::OutOfBounds {
                address: va,
                length: bytes.len(),
            })?;
            self.authenticate_initial_copy_page(leaf.output, va)?;
            let count = ((4096 - (va & 4095)) as usize).min(bytes.len() - written);
            self.custody
                ._vm
                .write(leaf.output, &bytes[written..written + count])
                .map_err(|_| MemoryError::OutOfBounds {
                    address: va,
                    length: bytes.len(),
                })?;
            written += count;
        }
        Ok(())
    }
}

impl<M: CarrierCpuIo, Mem: CarrierMemoryIo> CurrentMmMemory for ForwardVenue<'_, M, Mem> {}

impl<M: CarrierCpuIo, Mem: CarrierMemoryIo> carrick_guest_arch::CurrentMmMemory
    for ForwardVenue<'_, M, Mem>
{
    fn write_bytes(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), carrick_guest_arch::UserMemoryFault> {
        carrick_guest_mem::GuestMemory::write_bytes(self, address, bytes)
            .map_err(|_| carrick_guest_arch::UserMemoryFault)
    }
}

impl<M: CarrierCpuIo, Mem: CarrierMemoryIo> carrick_hal::x8664_arch::SegmentBaseRegs
    for ForwardVenue<'_, M, Mem>
{
    type Error = TrapError;
    fn seg_set_fs_base(&mut self, address: u64) -> Result<(), TrapError> {
        self.lease.io.set_fs_base(address)
    }

    fn seg_get_fs_base(&self) -> Result<u64, TrapError> {
        self.lease.io.get_fs_base()
    }

    fn seg_set_gs_base(&mut self, address: u64) -> Result<(), TrapError> {
        // FORWARD_PORT stops after SYSCALL's SWAPGS: GS is the kernel CPU
        // binding and KERNEL_GS_BASE holds the user's value until IRET swaps
        // them back. Never replace the live supervisor GS binding here.
        const KERNEL_GS_BASE: u32 = 0xc000_0102;
        self.lease.io.write_msr(KERNEL_GS_BASE, address)
    }

    fn seg_get_gs_base(&self) -> Result<u64, TrapError> {
        const KERNEL_GS_BASE: u32 = 0xc000_0102;
        self.lease.io.read_msr(KERNEL_GS_BASE)
    }
}

#[cfg(test)]
mod kernel_stack_tests {
    use super::*;

    #[test]
    fn a_saved_task_restores_its_entire_live_cpl0_call_chain() {
        let mut stack = vec![0u8; 256];
        for (index, byte) in stack.iter_mut().enumerate().skip(128) {
            *byte = index as u8;
        }
        let original = stack.clone();
        let slot = carrick_guest_arch::CpuId::new(0);
        let saved =
            unsafe { KernelStackSnapshot::capture(stack.as_ptr(), 0x1000, 0x1100, 0x1080, slot) }
                .expect("valid CPL0 stack");
        stack.fill(0xa5);
        unsafe { saved.restore(stack.as_mut_ptr(), 0x1000, 0x1100, slot) }
            .expect("same physical stack");
        assert_eq!(&stack[128..], &original[128..]);
        assert!(stack[..128].iter().all(|byte| *byte == 0xa5));
        assert!(
            unsafe {
                saved.restore(
                    stack.as_mut_ptr(),
                    0x1000,
                    0x1100,
                    carrick_guest_arch::CpuId::new(1),
                )
            }
            .is_err()
        );
    }
}

#[cfg(test)]
mod initial_reply_tests {
    use super::*;
    use carrick_core_abi::{X86_INITIAL_BOOT_MAGIC, X86_INITIAL_BOOT_VERSION};

    #[test]
    fn shared_physical_staging_rolls_back_before_exposure() {
        let authority = Arc::new(FrameInventoryAuthority::new());
        let ids = Arc::new(ObjectIdRegistry::new());
        let staged = carrick_hal::physical_grants::StagedPhysicalGrants::stage(
            Arc::default(),
            authority.physical_projection(ids),
            [FrameGpa::new(0x2_0000_0000)],
            0,
            4096,
            carrick_hal::GuestFrameOwner {
                native_mm: MmGeneration::new(NonZeroU64::new(INITIAL_MM_KEY).unwrap()),
                root_generation: ContextGeneration::new(NonZeroU64::MIN),
            },
        )
        .unwrap();
        let grant = staged.grants()[0];
        let bound = Arc::clone(staged.authority());
        let mapping = MappingId::from_kernel_allocation(grant.identity.mapping_id);
        let frame = FrameId::from_kernel_allocation(grant.identity.frame_id);
        let length = FrameLength::from_mapping_extent(NonZeroU64::new(4096).unwrap());
        let before = bound
            .mapping_is_live(
                mapping,
                frame,
                carrick_guest_mem::Gpa::new(grant.gpa.raw()),
                length,
            )
            .unwrap();
        assert!(before);
        drop(staged);
        let after = bound
            .mapping_is_live(
                mapping,
                frame,
                carrick_guest_mem::Gpa::new(grant.gpa.raw()),
                length,
            )
            .unwrap();
        assert!(!after);
    }

    #[test]
    fn unwind_rollback_refusal_returns_control_to_the_carrier_observer() {
        let authority = Arc::new(FrameInventoryAuthority::new());
        let ids = Arc::new(ObjectIdRegistry::new());
        let (inventory, _) = InitialInventory::stage(
            Arc::default(),
            authority.physical_projection(Arc::clone(&ids)),
            [FrameGpa::new(0x2_0000_0000)],
            0,
            4096,
            carrick_hal::GuestFrameOwner {
                native_mm: MmGeneration::new(NonZeroU64::new(INITIAL_MM_KEY).unwrap()),
                root_generation: ContextGeneration::new(NonZeroU64::MIN),
            },
        )
        .unwrap();
        authority
            .rollback_unpublished_apply(inventory.receipt.as_ref().unwrap())
            .unwrap();
        let fault = Arc::clone(&inventory.rollback_fault);
        let retained_authority = Arc::downgrade(&inventory.authority);
        drop(inventory);
        assert!(fault.failed());
        assert!(
            retained_authority.upgrade().is_some(),
            "refused rollback must retain its authority and receipt"
        );
        // The carrier observer, rather than this destructor, chooses the
        // existing fail-stop transport after all owned custody is unwound.
    }

    #[test]
    fn refused_initial_rollback_retains_the_exact_physical_receipt() {
        let authority = Arc::new(FrameInventoryAuthority::new());
        let ids = Arc::new(ObjectIdRegistry::new());
        let (mut inventory, _) = InitialInventory::stage(
            Arc::default(),
            authority.physical_projection(Arc::clone(&ids)),
            [FrameGpa::new(0x2_0000_0000)],
            0,
            4096,
            carrick_hal::GuestFrameOwner {
                native_mm: MmGeneration::new(NonZeroU64::new(INITIAL_MM_KEY).unwrap()),
                root_generation: ContextGeneration::new(NonZeroU64::MIN),
            },
        )
        .unwrap();
        // Another exact retirement makes this rollback refuse; failure must
        // retain the receipt rather than silently consuming physical custody.
        authority
            .rollback_unpublished_apply(inventory.receipt.as_ref().unwrap())
            .unwrap();
        assert!(inventory.rollback().is_err());
        assert!(
            inventory.receipt.is_some(),
            "failed rollback consumed its physical receipt"
        );
        // The fixture itself performed retirement above; no live mapping or
        // unresolved physical custody remains to retry when it leaves scope.
        inventory.receipt = None;
    }

    #[test]
    fn inventory_retains_two_live_owner_selected_mms() {
        let authority = Arc::new(FrameInventoryAuthority::new());
        let ids = Arc::new(ObjectIdRegistry::new());
        let owners = [INITIAL_MM_KEY, INITIAL_MM_KEY + 1];
        let mut staged = Vec::new();
        for (index, owner) in owners.into_iter().enumerate() {
            let mm = MmId::from_raw_u64(owner).unwrap();
            let (mut inventory, _) = InitialInventory::stage(
                Arc::default(),
                authority.physical_projection(Arc::clone(&ids)),
                [FrameGpa::new(0x2_0000_0000 + index as u64 * 4096)],
                0,
                4096,
                carrick_hal::GuestFrameOwner {
                    native_mm: MmGeneration::new(NonZeroU64::new(mm.raw()).unwrap()),
                    root_generation: ContextGeneration::new(NonZeroU64::MIN),
                },
            )
            .expect("owner-selected inventory");
            assert_eq!(
                inventory.receipt.as_ref().unwrap().mm().get(),
                mm.raw(),
                "stage-2 inventory must retain the selected MM, not the initial MM"
            );
            inventory.publish().expect("exact MM inventory publication");
            staged.push(inventory);
        }
        assert_ne!(
            staged[0].frames[0].1.mapping_id,
            staged[1].frames[0].1.mapping_id
        );
        assert_ne!(staged[0].frames[0].0, staged[1].frames[0].0);
        for inventory in &mut staged {
            inventory.rollback().unwrap();
        }
    }

    #[test]
    fn initial_inventory_refuses_a_receipt_from_another_mm() {
        let authority = Arc::new(FrameInventoryAuthority::new());
        let ids = Arc::new(ObjectIdRegistry::new());
        let (mut inventory, _) = InitialInventory::stage(
            Arc::default(),
            authority.physical_projection(Arc::clone(&ids)),
            [FrameGpa::new(0x2_0000_0000)],
            0,
            4096,
            carrick_hal::GuestFrameOwner {
                native_mm: MmGeneration::new(
                    NonZeroU64::new(INITIAL_MM_KEY).expect("initial inventory MM"),
                ),
                root_generation: ContextGeneration::new(NonZeroU64::MIN),
            },
        )
        .expect("initial MM inventory");
        inventory.rollback().expect("original custody rollback");
        let mut reservation = authority
            .reserve(&ids, 1, 1, FrameEventCapacity::for_event_count(2).unwrap())
            .expect("foreign MM transaction");
        let transaction = reservation.transaction();
        let frame = reservation.claim_frame().unwrap();
        let mapping = reservation.claim_mapping().unwrap();
        let generation = MappingGeneration::from_backend_counter(NonZeroU64::MIN);
        reservation
            .push(FrameInventoryEvent::PrepareMapping {
                transaction,
                frame,
                mapping,
                generation,
                gpa: carrick_guest_mem::Gpa::new(0x2_0000_1000),
                length: inventory.length,
                permissions: MemPerms {
                    read: true,
                    write: true,
                    exec: false,
                },
            })
            .unwrap();
        reservation
            .push(FrameInventoryEvent::PublishMapping {
                transaction,
                mapping,
                generation,
            })
            .unwrap();
        let foreign = carrick_hal::UnpublishedFrameInventoryApply::apply(
            authority
                .physical_projection(Arc::clone(&ids))
                .bind(carrick_hal::GuestFrameOwner {
                    native_mm: MmGeneration::new(NonZeroU64::new(INITIAL_MM_KEY + 1).unwrap()),
                    root_generation: ContextGeneration::new(NonZeroU64::MIN),
                }),
            reservation.commit(()),
        )
        .expect("foreign MM receipt");
        // Settle the original unpublished receipt independently, then replace
        // only the receipt. The MM refusal must precede frame authentication.
        inventory.receipt = Some(foreign);
        assert_eq!(inventory.publish().unwrap_err().0, "inventory MM mismatch");
    }

    #[test]
    fn initial_inventory_refuses_a_grant_with_a_different_gpa() {
        let (mut inventory, _) = InitialInventory::stage(
            Arc::default(),
            Arc::new(FrameInventoryAuthority::new())
                .physical_projection(Arc::new(ObjectIdRegistry::new())),
            [FrameGpa::new(0x2_0000_0000)],
            0,
            4096,
            carrick_hal::GuestFrameOwner {
                native_mm: MmGeneration::new(
                    NonZeroU64::new(INITIAL_MM_KEY).expect("initial inventory MM"),
                ),
                root_generation: ContextGeneration::new(NonZeroU64::MIN),
            },
        )
        .expect("fresh exact inventory grant");
        inventory.frames[0].0 = FrameGpa::new(0x2_0000_1000);
        assert!(
            inventory.publish().is_err(),
            "a mapping/frame pair does not authorize another GPA"
        );
    }

    #[test]
    fn unverified_guest_completion_keeps_inventory_custody_until_vm_teardown() {
        for exposed in [false, true] {
            let authority = Arc::new(FrameInventoryAuthority::new());
            let (mut inventory, _) = InitialInventory::stage(
                Arc::default(),
                authority.physical_projection(Arc::new(ObjectIdRegistry::new())),
                [FrameGpa::new(0x2_0000_0000)],
                0,
                4096,
                carrick_hal::GuestFrameOwner {
                    native_mm: MmGeneration::new(
                        NonZeroU64::new(INITIAL_MM_KEY).expect("initial inventory MM"),
                    ),
                    root_generation: ContextGeneration::new(NonZeroU64::MIN),
                },
            )
            .expect("fresh physical grant");
            inventory.guest_exposed = exposed;
            if exposed {
                assert!(
                    inventory.rollback().is_err(),
                    "unverified completion cannot authorize rollback"
                );
            }
            drop(inventory);
            assert_eq!(authority.snapshot().mappings.len(), usize::from(exposed));
        }
    }

    #[test]
    fn initial_inventory_publishes_data_frames_without_table_grants() {
        let base = INITIAL_EXTENT_GPA + 0x20_000;
        let authority = Arc::new(FrameInventoryAuthority::new());
        let (inventory, grants) = InitialInventory::stage(
            Arc::default(),
            authority.physical_projection(Arc::new(ObjectIdRegistry::new())),
            (0..4).map(|index| FrameGpa::new(base + index * 4096)),
            2,
            4096,
            carrick_hal::GuestFrameOwner {
                native_mm: MmGeneration::new(
                    NonZeroU64::new(INITIAL_MM_KEY).expect("initial inventory MM"),
                ),
                root_generation: ContextGeneration::new(NonZeroU64::MIN),
            },
        )
        .expect("staged exact grants");
        assert_eq!(grants.len(), 4);
        assert_eq!(inventory.frames.len(), 2);
        let rows = authority.snapshot().mappings;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].gpa.raw(), grants[2].gpa);
        assert_eq!(rows[1].gpa.raw(), grants[3].gpa);
    }

    /// An exec successor reuses the boot inventory transaction unchanged:
    /// its tables are reserved fork-stock pages and its data frames another
    /// grant, neither one contiguous run. Only the data frames get mappings.
    #[test]
    fn successor_inventory_stages_stock_tables_and_data_frames_in_runs() {
        let page = |gpa| RootGpa::page_aligned(FrameGpa::new(gpa)).unwrap();
        let mut stock: Vec<RootGpa> = [0x40_0000, 0x40_1000, 0x50_0000, 0x50_1000]
            .map(page)
            .to_vec();
        let tables = carrick_hal::fork_stock::take_successor_table_runs(&mut stock, 3).unwrap();
        let base = INITIAL_EXTENT_GPA + 0x20_000;
        let data = [base, base + 4096, base + 0x10_000].map(FrameGpa::new);
        let authority = Arc::new(FrameInventoryAuthority::new());
        let (inventory, grants) = InitialInventory::stage(
            Arc::default(),
            authority.physical_projection(Arc::new(ObjectIdRegistry::new())),
            tables
                .iter()
                .map(|table| table.address())
                .chain(data.iter().copied()),
            tables.len(),
            4096,
            carrick_hal::GuestFrameOwner {
                native_mm: MmGeneration::new(NonZeroU64::new(INITIAL_MM_KEY).unwrap()),
                root_generation: ContextGeneration::new(NonZeroU64::MIN),
            },
        )
        .expect("staged multi-run grants");
        let granted: Vec<FrameGpa> = grants
            .iter()
            .map(|grant| FrameGpa::new(grant.gpa))
            .collect();
        let runs = carrick_core_abi::successor_image::frame_runs(&granted, 4096).unwrap();
        assert_eq!(runs.len(), 4, "two table runs, then two data runs");
        assert_eq!(inventory.frames.len(), data.len());
        let rows = authority.snapshot().mappings;
        assert_eq!(
            rows.iter().map(|row| row.gpa.raw()).collect::<Vec<_>>(),
            data.map(FrameGpa::raw).to_vec()
        );
    }

    #[test]
    fn corrupted_guest_reply_cannot_change_host_grant_or_stack_geometry() {
        let request = X86InitialBootRequest {
            magic: X86_INITIAL_BOOT_MAGIC,
            version: X86_INITIAL_BOOT_VERSION,
            layout_hash: carrick_el1_abi::EL1_ABI_LAYOUT_HASH,
            table_grant_count: 5,
            data_grant_count: 2,
            publication_capacity: 2,
            publications_gpa: INITIAL_EXTENT_GPA + 4096,
            stack_top: INITIAL_STACK_TOP,
            stack_size: INITIAL_STACK_SIZE,
            mm_key: INITIAL_MM_KEY,
            generation: 1,
            ..Default::default()
        };
        let valid = X86InitialBootRequest {
            result_status: X86_INITIAL_BOOT_LOADED,
            publication_count: 2,
            result_data_used: 2,
            result_table_used: 2,
            result_root_gpa: INITIAL_EXTENT_GPA + 0x2000,
            result_initial_break: 0x401000,
            result_rsp: INITIAL_STACK_TOP - 16,
            ..request
        };
        assert!(
            validate_initial_reply(&request, &valid, 7, valid.result_root_gpa, 0x401000).is_ok()
        );
        let stale = X86InitialBootRequest {
            layout_hash: valid.layout_hash ^ 1,
            ..valid
        };
        assert!(matches!(
            validate_initial_reply(&request, &stale, 7, valid.result_root_gpa, 0x401000),
            Err(TrapError::ImageAbiMismatch { .. })
        ));
        for corrupted in [
            X86InitialBootRequest {
                table_grant_count: u32::MAX,
                ..valid
            },
            X86InitialBootRequest {
                publication_capacity: u32::MAX,
                ..valid
            },
            X86InitialBootRequest {
                publications_gpa: u64::MAX,
                ..valid
            },
            X86InitialBootRequest {
                stack_top: 0,
                ..valid
            },
            X86InitialBootRequest {
                stack_size: u64::MAX,
                ..valid
            },
            X86InitialBootRequest {
                publication_count: u32::MAX,
                ..valid
            },
            X86InitialBootRequest {
                result_table_used: u32::MAX,
                ..valid
            },
        ] {
            assert!(
                validate_initial_reply(&request, &corrupted, 7, valid.result_root_gpa, 0x401000)
                    .is_err(),
                "accepted corrupted guest reply: {corrupted:?}"
            );
        }
    }
}

#[derive(::core::fmt::Debug)]
pub struct LifecycleObservation {
    pub births: u64,
    pub retirements: u64,
    pub wakes: u64,
    pub live: u32,
    pub state: Option<(u64, carrick_el1_abi::EntryState)>,
    pub entries: u64,
    pub completions: u64,
    pub served: [u64; 3],
    pub forwards: u64,
    pub words: [u64; 8],
    pub parked_parent_result: u64,
    /// Timer leases still held in the shared zone's timer index.
    pub timer_nodes: usize,
}

#[cfg(test)]
mod cpl0_layout_tests {
    use super::*;
    // x86.mm.initial-image: the static PIE load shape observed in busybox:musl.
    // Only ELF headers are needed to prove reservation placement; no VM or
    // backing proportional to the virtual heap/mmap capacity is allocated.
    fn static_pie_elf() -> Vec<u8> {
        let mut bytes = vec![0; 0x200];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4..7].copy_from_slice(&[2, 1, 1]);
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN, no PT_INTERP
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x203e5u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&4u16.to_le_bytes());
        for (index, (address, memory_size, flags)) in [
            (0u64, 0x80f0u64, 4u32),
            (0x9000, 0xee36e, 5),
            (0xf8000, 0x328bc, 4),
            (0x12ba70, 0x50c0, 6),
        ]
        .into_iter()
        .enumerate()
        {
            let header = &mut bytes[64 + index * 56..64 + (index + 1) * 56];
            header[..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
            header[4..8].copy_from_slice(&flags.to_le_bytes());
            header[16..24].copy_from_slice(&address.to_le_bytes());
            if index == 0 {
                header[32..40].copy_from_slice(&0x200u64.to_le_bytes());
            }
            header[40..48].copy_from_slice(&memory_size.to_le_bytes());
            header[48..56].copy_from_slice(&0x1000u64.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn static_pie_reservations_follow_image_break_below_the_stack() {
        let elf = static_pie_elf();
        let program = carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).unwrap();
        let image = carrick_mem::x86_initial_image::prepare_x86_elf(&program).unwrap();
        let initial_break = image.regions.iter().map(|region| region.end).max().unwrap();
        assert_eq!(initial_break, 0x88_0013_1000);
        assert!(initial_break > 0x4000_0000);
        assert!(initial_break < INITIAL_STACK_TOP - INITIAL_STACK_RESERVATION);
        let layout = initial_reservation_layout(
            UserVa::new(initial_break),
            UserVa::new(INITIAL_STACK_TOP),
            InitialReservationLimits::UNLIMITED,
        )
        .expect("static PIE heap and mmap reservations must follow its loaded image");
        assert_eq!(layout.brk, initial_break);
        assert_eq!(layout.heap.start(), initial_break);
        assert_eq!(layout.heap.end(), layout.arena.start());
        assert_eq!(layout.heap.end(), 0x88_4000_0000);
        assert_eq!(layout.arena.len(), carrick_mem::memory::LINUX_MMAP_SIZE);
        assert!(layout.arena.end() <= INITIAL_STACK_TOP - INITIAL_STACK_RESERVATION);
        assert!(
            image
                .regions
                .iter()
                .all(|region| region.end <= layout.heap.start())
        );
    }

    #[test]
    fn low_image_reservations_keep_the_whole_arena_below_the_stack_and_retain_launch_limits() {
        let limits = InitialReservationLimits {
            address: carrick_abi::LinuxRlimit::new(0x2000_0000, 0x3000_0000),
            data: carrick_abi::LinuxRlimit::new(0x1000_0000, 0x2000_0000),
        };
        let address_limit = limits.address.rlim_cur;
        let data_limit = limits.data.rlim_cur;
        for initial_break in [
            0x40_1000,
            0x2000_0000,
            0x4000_0000,
            0x4000_1000,
            INITIAL_STACK_TOP - INITIAL_STACK_RESERVATION - 8192,
        ] {
            let layout = initial_reservation_layout(
                UserVa::new(initial_break),
                UserVa::new(INITIAL_STACK_TOP),
                limits,
            )
            .unwrap();
            assert_eq!(layout.brk, initial_break);
            assert_eq!(layout.heap.start(), initial_break);
            assert!(layout.heap.len() <= INITIAL_ARENA_ALIGNMENT);
            if initial_break < 0x4000_0000 {
                assert_eq!(layout.heap.len(), 0x4000_0000 - initial_break);
            }
            assert_eq!(layout.heap.end(), layout.arena.start());
            let stack_base = INITIAL_STACK_TOP - INITIAL_STACK_RESERVATION;
            if initial_break < stack_base - 8192 {
                // #2722: the stack no longer clips a low image's arena, so a
                // multi-GiB reservation has a gap to land in.
                assert_eq!(layout.arena.len(), carrick_mem::memory::LINUX_MMAP_SIZE);
                assert!(layout.arena.end() <= stack_base);
            } else {
                // Only a break directly under the stack is clipped by it.
                assert_eq!(layout.arena.len(), 4096);
                assert_eq!(layout.arena.end(), stack_base);
            }
            assert_eq!(layout.address_limit, address_limit);
            assert_eq!(layout.data_limit, data_limit);
            assert_eq!(layout.external_address_bytes, 0);
            assert_eq!(layout.external_data_bytes, 0);
        }
    }

    #[test]
    fn initial_reservations_refuse_stack_collision_unaligned_and_exhausted_ranges() {
        let stack_base = INITIAL_STACK_TOP - INITIAL_STACK_RESERVATION;
        for initial_break in [
            0x40_1001,
            stack_base - 4096,
            stack_base,
            stack_base + 4096,
            carrick_guest_arch::USER_CEILING - 4096,
            carrick_guest_arch::USER_CEILING,
            u64::MAX - 4095,
        ] {
            assert!(
                initial_reservation_layout(
                    UserVa::new(initial_break),
                    UserVa::new(INITIAL_STACK_TOP),
                    InitialReservationLimits::UNLIMITED,
                )
                .is_err(),
                "invalid break {initial_break:#x} must not publish reservations"
            );
        }
        for stack_top in [
            0,
            INITIAL_STACK_RESERVATION - 4096,
            INITIAL_STACK_TOP + 1,
            u64::MAX,
        ] {
            assert!(
                initial_reservation_layout(
                    UserVa::new(0x40_1000),
                    UserVa::new(stack_top),
                    InitialReservationLimits::UNLIMITED,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn high_image_arena_is_bounded_by_canonical_user_end() {
        for (initial_break, arena_len) in [
            (
                carrick_guest_arch::USER_CEILING - INITIAL_ARENA_ALIGNMENT - 4096,
                INITIAL_ARENA_ALIGNMENT,
            ),
            (carrick_guest_arch::USER_CEILING - 8192, 4096),
        ] {
            let layout = initial_reservation_layout(
                UserVa::new(initial_break),
                UserVa::new(INITIAL_STACK_TOP),
                InitialReservationLimits::UNLIMITED,
            )
            .unwrap();
            assert_eq!(layout.heap.start(), initial_break);
            assert_eq!(layout.heap.end(), layout.arena.start());
            assert_eq!(layout.heap.len(), 4096);
            assert_eq!(layout.arena.len(), arena_len);
            assert_eq!(layout.arena.end(), carrick_guest_arch::USER_CEILING);
        }
    }

    #[test]
    fn cpl0_supervisor_image_extent_ordering_alignment_and_nonoverlap() {
        assert_eq!(IMAGE_GPA, carrick_el1_abi::X86_CPL0_SUPERVISOR_IMAGE_GPA);
        assert_eq!(IMAGE_SIZE, carrick_el1_abi::X86_CPL0_SUPERVISOR_IMAGE_SIZE);
        assert_eq!(IMAGE_SIZE, 0x20_0000); // 2 MiB

        // Page alignment for image and layout structures
        assert!(IMAGE_GPA.is_multiple_of(4096));
        assert!(IMAGE_SIZE.is_power_of_two());
        assert!(IMAGE_SIZE.is_multiple_of(4096));
        assert!(LAYOUT.gdt_base.is_multiple_of(4096));
        assert!(LAYOUT.pml4_base.is_multiple_of(4096));

        // Strict non-overlap: image ends at or before fixture process tables (0x30_0000)
        const { assert!(IMAGE_GPA + IMAGE_SIZE <= 0x30_0000) };
        // Image exclusive end <= GDT base
        const { assert!(IMAGE_GPA + IMAGE_SIZE <= LAYOUT.gdt_base) };
        // Ordering: GDT base < PML4 base < fault structures < metadata
        const { assert!(LAYOUT.gdt_base < LAYOUT.pml4_base) };
        assert!(LAYOUT.pml4_base + carrick_x86::X86_PML4_CAPACITY as u64 <= META_GPA);

        let stub_start = carrick_x86::fault_stub_base(LAYOUT);
        let stub_end = carrick_x86::fault_tss_base(LAYOUT);
        let idt_base = carrick_x86::fault_idt_base(LAYOUT);
        assert!(IMAGE_GPA + IMAGE_SIZE <= idt_base);
        assert!(idt_base < stub_start);
        assert!(stub_start < stub_end);
        assert!(stub_end < META_GPA);
    }
}

pub use crate::cpl0_private_witness::PrivateAnonymousMmEvidence;

struct RetainedIpcTableMap {
    _backing: Arc<BackingExtent>,
    base: carrick_guest_mem::HostVa,
}
impl carrick_el1_abi::ipc_tables::IpcTableMapBacking for RetainedIpcTableMap {
    fn table_map(&self) -> &carrick_el1_abi::ipc_tables::IpcTableMap {
        // SAFETY: constructed only from the complete authenticated file extent;
        // the Arc owns its storage independently of carrier registration.
        unsafe {
            &*((self.base.raw() + carrick_el1_abi::EL1_IPC_TABLE_MAP_OFFSET as usize)
                as *const carrick_el1_abi::ipc_tables::IpcTableMap)
        }
    }
}

pub struct BootstrapFileRegion(RetainedFileRegion);
impl BootstrapFileRegion {
    /// Publish only after the original IPC allocations and slot source are mapped.
    pub fn publish_ipc_window(&self) -> Result<(), TrapError> {
        let tables = self
            .0
            .registration
            .tables(self.0.registration.binding())
            .map_err(|e| fail(format!("IPC table map: {e:?}")))?;
        tables.ipc_table_map().publish_window();
        Ok(())
    }

    /// # Safety
    /// `backing` must cover the entire writable binding extent and remain
    /// exclusively unpublished during initialization: no other registration,
    /// guest or table reference may access it. Its mapping must remain live
    /// until this registration is dropped.
    pub unsafe fn initialize(
        backing: Arc<BackingExtent>,
        binding: carrick_el1_abi::FileRegionBinding,
    ) -> Result<Self, TrapError> {
        let host = backing
            .host_base()
            .map_err(|error| fail(error.to_string()))?;
        let mapped = NonNull::new(host.raw() as *mut u8).ok_or_else(|| fail("null file region"))?;
        // SAFETY: this unpublished extent is exclusively initialized here and
        // retained with its registration in the same non-cloneable owner.
        let registration =
            unsafe { carrick_el1_abi::FileRegionRegistration::initialize(mapped, binding) }
                .map_err(|error| fail(format!("file region publication: {error:?}")))?;
        Ok(Self(RetainedFileRegion {
            registration,
            execution: Arc::new(RwLock::new(())),
            _backing: backing,
        }))
    }
}

/// Linearizes physical teardown against all retained host issuance handles.
struct BirthSourceRevocation(Arc<std::sync::RwLock<bool>>);
impl BirthSourceRevocation {
    fn new() -> Self {
        Self(Arc::new(std::sync::RwLock::new(true)))
    }
    fn retire(&self) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
    }
}
impl Drop for BirthSourceRevocation {
    fn drop(&mut self) {
        self.retire();
    }
}

#[derive(::core::clone::Clone)]
struct PhysicalBirthSource {
    live: Arc<std::sync::RwLock<bool>>,
    _ram: Arc<GuestRam>,
    zone: NonNull<X86Cpl0Zone>,
    identity: carrick_hal::birth_serial::BirthSourceIdentity,
}
impl core::fmt::Debug for PhysicalBirthSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("PhysicalBirthSource")
            .field(&self.identity)
            .finish()
    }
}
impl PhysicalBirthSource {
    fn new(
        ram: Arc<GuestRam>,
        identity: carrick_hal::birth_serial::BirthSourceIdentity,
        live: Arc<std::sync::RwLock<bool>>,
    ) -> Result<Self, carrick_hal::birth_serial::BirthSourceError> {
        use carrick_hal::birth_serial::BirthSourceError;
        let pointer = ram
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            )
            .ok_or(BirthSourceError::StaleOwner)?;
        if !(pointer as usize).is_multiple_of(core::mem::align_of::<X86Cpl0Zone>()) {
            return Err(BirthSourceError::StaleOwner);
        }
        let zone =
            NonNull::new(pointer.cast::<X86Cpl0Zone>()).ok_or(BirthSourceError::StaleOwner)?;
        Ok(Self {
            _ram: ram,
            zone,
            identity,
            live,
        })
    }
}
// SAFETY: zone is derived once from the retained initialized GuestRam. Only
// atomic issuers and leaf-locked namespace are accessed under the
// physical-custody revocation guard.
unsafe impl Send for PhysicalBirthSource {}
unsafe impl Sync for PhysicalBirthSource {}
impl carrick_hal::birth_serial::RetainedBirthZone for PhysicalBirthSource {
    type Context = carrick_sched_core::ParkedContextWords;
    fn source_identity(&self) -> &carrick_hal::birth_serial::BirthSourceIdentity {
        &self.identity
    }
    fn with_retained_zone<T>(
        &self,
        op: impl FnOnce(&X86Cpl0Zone) -> T,
    ) -> Result<T, carrick_hal::birth_serial::BirthSourceError> {
        use carrick_hal::birth_serial::BirthSourceError;
        let live = self.live.read().map_err(|_| BirthSourceError::StaleOwner)?;
        if !*live {
            return Err(BirthSourceError::StaleOwner);
        }
        // SAFETY: physical bootstrap initialized this zone in immutable windows;
        // the owning Arc<GuestRam> retains every mapped byte through this borrow.
        Ok(op(unsafe { self.zone.as_ref() }))
    }
}

pub struct BootstrapCustody<M: CarrierMemoryIo>(Cpl0HostCustody<M>);

impl<M: CarrierMemoryIo> BootstrapCustody<M> {
    pub fn new(
        memory: CarrierMemory<M>,
        ram: Arc<GuestRam>,
        initial_extent: Option<(BackingHandle, usize)>,
        kernel_region: Option<BackingHandle>,
        files: BootstrapFileRegion,
        frame_inventory: Arc<dyn PhysicalFrameInventory>,
        kernel_pod_storage: Vec<anonymous_owner::KernelPodStorage>,
    ) -> Result<Self, TrapError> {
        let metadata_base = RetainedMetadataPtr(
            NonNull::new(
                ram.host_ptr(META_GPA, META_LEN as usize)
                    .ok_or_else(|| fail("retained metadata backing"))?,
            )
            .ok_or_else(|| fail("null metadata backing"))?,
        );
        let fork_stock = carrick_hal::fork_stock::ForkStock::new(
            memory.identity().nonzero(),
            carrick_hal::fork_stock::ForkControlCapacity::unused(KERNEL_REGION_GPA),
            carrick_hal::fork_stock::UntaggedRoots,
        );
        // The carrier launches the boot task: the table it names gets the
        // zone's one stdio admission before any guest instruction runs
        // (#2820). A boot record naming no table (0) leaves admission to the
        // first table the carrier binds.
        // SAFETY: the retained metadata holds the aligned boot task record,
        // initialized by `prepare_boot` or zeroed (all-zero atomics are a
        // valid record); nothing runs before this custody exists.
        let boot_table = unsafe {
            metadata_base
                .0
                .as_ptr()
                .add(TASK_OFFSET as usize)
                .cast::<CurrentTask>()
                .as_ref()
        }
        .ok_or_else(|| fail("boot task metadata"))?
        .linux
        .file_table
        .load(Ordering::Acquire);
        let mut stdio = stdio::StdioCustody::default();
        if boot_table != 0 {
            let tables = files
                .0
                .registration
                .tables(files.0.registration.binding())
                .map_err(|error| fail(format!("boot stdio tables: {error:?}")))?;
            stdio
                .bind_table(
                    tables.fd_map(),
                    tables.opens(),
                    tables.objects(),
                    boot_table,
                )
                .map_err(|error| fail(format!("boot stdio admission: {error:?}")))?;
        }
        let mm_core = anonymous_owner::new_mm_core(memory.identity());
        Ok(Self(Cpl0HostCustody {
            _vm: memory,
            ram,
            birth_live: BirthSourceRevocation::new(),
            initial_extent,
            clock_vvar: None,
            _kernel_region: kernel_region,
            files: files.0,
            frame_inventory,
            private_anonymous_witness: Default::default(),
            actual_run: Arc::new(std::array::from_fn(|_| AtomicU32::new(0))),
            kernel_pod_storage,
            initial_inventory: None,
            initial_rollback_fault: Arc::default(),
            peer_entry: None,
            peer_admission: InitialPeerAdmission::Cold,
            initial_task: None,
            stdio,
            fork_stock,
            maintenance_root: None,
            anonymous_next_gpa: FrameGpa::new(DYNAMIC_GRANT_GPA),
            large_page_windows: 0,
            exec_owner: exec_service::X86ExecOwner::default(),
            exec_predecessors: exec_service::ExecPredecessorCustody::default(),
            root_exec_load: None,
            anonymous_pending: [None, None],
            mm_core,
            native_backing_pending: std::collections::BTreeMap::new(),
            cancelled_backing_pending: Vec::new(),
            window_slots: std::collections::BTreeMap::new(),
            owner_grant_crossings: 0,
            return_settlement: carrick_hal::return_settlement::SettlementLock::new(),
            return_settlement_counters: Default::default(),
            #[cfg(feature = "test-support")]
            fixture_holder_hold: None,
            root_exit_crossings: 0,
            child_retire_crossings: 0,
            space_retired_crossings: 0,
            run_failure_crossings: 0,
            metadata_base,
            initial_sources: None,
            host_forwards: 0,
            idle_peer_forwards: 0,
            idle_peer_host_files: 0,
            host_yields: 0,
            kicks: 0,
            work_exits: 0,
        }))
    }
    pub fn memory(&self) -> &CarrierMemory<M> {
        &self.0._vm
    }
    pub fn memory_mut(&mut self) -> &mut CarrierMemory<M> {
        &mut self.0._vm
    }
    /// Hold every holder's editor at the first full owed-return table drain
    /// and hand back the venue that releases them (#1482 P0-1 witness).
    #[cfg(feature = "test-support")]
    pub fn fixture_hold_owed_return_holders(
        &mut self,
    ) -> anonymous_owner::OwedReturnHolderRelease<M> {
        let hold = anonymous_owner::OwedReturnHolderHold::armed();
        self.0.fixture_holder_hold = Some(Arc::clone(&hold));
        anonymous_owner::OwedReturnHolderRelease::new(
            hold,
            Arc::clone(&self.0.ram),
            self.0._vm.clone_vm(),
        )
    }
    pub fn ram(&self) -> &Arc<GuestRam> {
        &self.0.ram
    }
    pub fn frame_inventory(&self) -> &Arc<dyn PhysicalFrameInventory> {
        &self.0.frame_inventory
    }
    /// Available only while this stopped bootstrap owns the initialized zone.
    pub fn birth_serial_source(
        &self,
    ) -> Result<Arc<dyn carrick_hal::birth_serial::BirthSerialSource>, TrapError> {
        let identity = carrick_hal::birth_serial::BirthSourceIdentity::from_backend_identity(
            self.0._vm.clone_vm(),
            self.0._vm.identity().nonzero(),
            NonZeroU64::MIN,
        );
        let source =
            PhysicalBirthSource::new(self.0.ram.clone(), identity, self.0.birth_live.0.clone())
                .map_err(|error| fail(format!("physical birth source: {error}")))?;
        Ok(Arc::new(source))
    }
    pub fn initial_task(&self) -> Option<InitialTaskBinding> {
        self.0.initial_task
    }
    pub fn set_initial_task(&mut self, task: InitialTaskBinding) {
        self.0.initial_task = Some(task);
    }
    pub fn initial_inventory_custody(&self) -> bool {
        self.0.initial_inventory.as_ref().is_some_and(|initial| {
            Arc::ptr_eq(&self.0.frame_inventory, &initial.source)
                && initial.frames.len() == initial.expected
                && initial.frames.iter().all(|(_, identity)| {
                    initial
                        .authority
                        .live_mapping_row(MappingId::from_kernel_allocation(identity.mapping_id))
                        .is_some()
                })
        })
    }
    pub fn has_initial_inventory(&self) -> bool {
        self.0.initial_inventory.is_some()
    }
    pub fn retain_initial_inventory(&mut self, inventory: InitialInventory) {
        self.0.initial_inventory = Some(inventory);
    }
    pub fn rollback_fault(&self) -> Arc<carrick_hal::physical_grants::PhysicalGrantRollback> {
        Arc::clone(&self.0.initial_rollback_fault)
    }
    pub fn set_clock_vvar(&mut self, clock_vvar: Option<carrick_mem::vdso::X86NativeVvar>) {
        self.0.clock_vvar = clock_vvar;
    }

    pub fn initial_extent(&self) -> Option<(BackingHandle, usize)> {
        self.0.initial_extent
    }
    pub fn peer_entry(&self) -> Option<carrick_guest_arch::KernelVa> {
        self.0.peer_entry
    }
    pub fn set_peer_entry(&mut self, entry: carrick_guest_arch::KernelVa) {
        self.0.peer_entry = Some(entry);
    }
    pub fn peer_ready(&self) -> bool {
        self.0.peer_admission == InitialPeerAdmission::Ready
    }
    pub fn admit_peer(&mut self) {
        self.0.peer_admission = InitialPeerAdmission::Ready;
    }
    pub fn actual_run(&self) -> &Arc<[AtomicU32; 2]> {
        &self.0.actual_run
    }
    pub fn file_execution(&self) -> &Arc<RwLock<()>> {
        &self.0.files.execution
    }
    pub fn file_region_binding(&self) -> carrick_el1_abi::FileRegionBinding {
        self.0.files.registration.binding()
    }
    pub fn ipc_table_map(
        &self,
    ) -> Result<Arc<dyn carrick_el1_abi::ipc_tables::IpcTableMapBacking>, TrapError> {
        self.0.ipc_table_map()
    }

    pub fn carrier_zone_wake(
        &self,
    ) -> Result<
        Arc<dyn carrick_sched_core::CarrierZoneWake<carrick_sched_core::ParkedContextWords>>,
        TrapError,
    > {
        self.0.carrier_zone_wake()
    }

    pub fn file_tables(
        &self,
        binding: carrick_el1_abi::FileRegionBinding,
    ) -> Result<StoppedFileTables<'_>, carrick_el1_abi::FileRegionError> {
        self.0.file_tables(binding)
    }
    pub fn fixture_file_mutation_active(
        &self,
        binding: carrick_el1_abi::FileRegionBinding,
    ) -> Result<bool, carrick_el1_abi::FileRegionError> {
        Ok(self.0.files.registration.tables(binding)?.fd_map()[0].mutation_active())
    }
    pub fn retire_file_region(&mut self) {
        self.0.files.registration.retire();
    }
    pub fn maintenance_root(&self) -> Option<RootGpa> {
        self.0.maintenance_root
    }
    pub fn bind_grant_portal(&self) -> Result<(), TrapError> {
        self.0.bind_grant_portal()
    }
    pub fn install_fork_stock(
        &mut self,
        context: AddressContext<RootGpa>,
        unused: Vec<RootGpa>,
        reserve: carrick_hal::fork_stock::TableReserve,
    ) -> Result<(), TrapError> {
        self.0.install_fork_stock(context, unused, reserve)
    }
    pub fn fork_stock_counters(&self) -> carrick_hal::fork_stock::ForkStockCounters {
        self.0.fork_stock_counters()
    }
    pub fn exec_owner_census(&self) -> carrick_hal::exec_owner::ExecOwnerCensus {
        self.0.exec_owner_census()
    }
    pub fn anonymous_private_pages(&self) -> u64 {
        self.0.private_anonymous_witness.private_pages()
    }
    pub fn host_forwards(&self) -> u64 {
        self.0.host_forwards
    }
    pub fn host_yields(&self) -> u64 {
        self.0.host_yields
    }
    pub fn kicks(&self) -> u64 {
        self.0.kicks
    }
    pub fn work_exits(&self) -> u64 {
        self.0.work_exits
    }
    pub fn record_host_forward(&mut self) {
        self.0.host_forwards += 1;
    }
    pub fn record_host_yield(&mut self) {
        self.0.host_yields += 1;
    }
    pub fn record_kick(&mut self) {
        self.0.kicks += 1;
    }
    pub fn record_work_exit(&mut self) {
        self.0.work_exits += 1;
    }
    /// What this carrier's owed-return settlements did (#1369 slice 3).
    pub fn return_settlement_counters(&self) -> anonymous_owner::ReturnSettlementCounters {
        self.0.return_settlement_counters
    }
    pub fn physical_crossing_counts(&self) -> [(PhysicalCrossingFamily, u64); 6] {
        [
            (
                PhysicalCrossingFamily::OwnerGrant,
                self.0.owner_grant_crossings,
            ),
            (PhysicalCrossingFamily::RootExit, self.0.root_exit_crossings),
            (
                PhysicalCrossingFamily::ChildRetire,
                self.0.child_retire_crossings,
            ),
            (
                PhysicalCrossingFamily::RunFailure,
                self.0.run_failure_crossings,
            ),
            (
                PhysicalCrossingFamily::ReturnSettlement,
                self.0.return_settlement_counters.doorbells,
            ),
            (
                PhysicalCrossingFamily::SpaceRetired,
                self.0.space_retired_crossings,
            ),
        ]
    }
    /// # Safety
    /// The stopped bootstrap owner must select an initialized, aligned record
    /// at `offset`, and retain exclusive access for non-atomic mutations.
    pub unsafe fn metadata<T>(&self, offset: u64) -> &T {
        self.0.metadata(offset)
    }
    /// # Safety
    /// The stopped bootstrap owner must select an initialized, aligned record
    /// at `offset`, and retain exclusive access for the returned borrow.
    pub unsafe fn metadata_mut<T>(&mut self, offset: u64) -> &mut T {
        // SAFETY: the caller upholds the record initialization, alignment, and
        // exclusive-access contract; the borrow cannot outlive this custody.
        unsafe { &mut *self.0.metadata_base.0.as_ptr().add(offset as usize).cast() }
    }
}

#[cfg(test)]
static_assertions::assert_impl_all!(RetainedMetadataPtr: Send);
#[cfg(test)]
static_assertions::assert_not_impl_any!(RetainedMetadataPtr: Clone, Sync);
#[cfg(test)]
static_assertions::assert_impl_all!(Cpl0HostCustody<crate::carrier_memory::test_support::MemoryTestIo>: Send);
#[cfg(test)]
static_assertions::assert_not_impl_any!(Cpl0HostCustody<crate::carrier_memory::test_support::MemoryTestIo>: Clone, Sync);

#[cfg(test)]
mod birth_source_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use carrick_hal::birth_serial::{BirthSerialSource, BirthSourceError, BirthSourceIdentity};

    #[test]
    fn bootstrap_metadata_records_are_disjoint_before_root_binding() {
        // The stopped carrier initializes both CPUs before rebinding CPU 0.
        // Every record must fit its stride or CPU 1 corrupts CPU 0 custody.
        for (offset, size, next) in [
            (BINDING_OFFSET, size_of::<CpuBinding>() as u64, TASK_OFFSET),
            (TASK_OFFSET, size_of::<CurrentTask>() as u64, CONTROL_OFFSET),
            (
                CONTROL_OFFSET,
                size_of::<ThreadControlSlot>() as u64,
                0xb000,
            ),
        ] {
            assert!(
                size <= STRIDE,
                "record at {offset:#x}: {size} bytes exceed stride {STRIDE}"
            );
            assert!(offset + STRIDE + size <= next);
        }
        let mut ram = GuestRam::new();
        ram.add_window(
            META_GPA,
            META_LEN as usize,
            crate::guest_ram::WindowKind::Shared,
        )
        .unwrap();
        for index in 0..2 {
            let ptr = ram
                .host_ptr(
                    META_GPA + CONTROL_OFFSET + index * STRIDE,
                    size_of::<ThreadControlSlot>(),
                )
                .unwrap()
                .cast::<ThreadControlSlot>();
            // SAFETY: private stopped backing, aligned and disjoint by the
            // layout assertions above, exactly as in carrier bootstrap.
            unsafe { ptr.write(ThreadControlSlot::new()) };
            // SAFETY: initialized above, retained by ram until the test ends.
            let control = unsafe { &*ptr };
            control
                .reset_for_host_birth(carrick_el1_abi::BlockedMask(0))
                .unwrap();
            assert!(control.publish_visible_tid(41 + index as u32));
        }
        let control = |index| {
            let ptr = ram
                .host_ptr(
                    META_GPA + CONTROL_OFFSET + index * STRIDE,
                    size_of::<ThreadControlSlot>(),
                )
                .unwrap()
                .cast::<ThreadControlSlot>();
            // SAFETY: initialized, aligned disjoint records retained by ram.
            unsafe { &*ptr }
        };
        // Root admission resets CPU 0 after both provisional controls exist.
        control(0)
            .reset_for_host_birth(carrick_el1_abi::BlockedMask(0))
            .unwrap();
        assert!(control(0).publish_visible_tid(7));
        assert_eq!(control(0).visible_tid(), Some(7));
        assert_eq!(control(1).visible_tid(), Some(42));
        control(1)
            .reset_for_host_birth(carrick_el1_abi::BlockedMask(0))
            .unwrap();
        assert_eq!(control(0).visible_tid(), Some(7));
    }

    fn source() -> (BirthSourceRevocation, PhysicalBirthSource) {
        let mut ram = GuestRam::new();
        ram.add_window(
            META_GPA,
            (carrick_core_abi::X86_CPL0_ZONE_OFFSET as usize + size_of::<X86Cpl0Zone>() + 4095)
                & !4095,
            crate::guest_ram::WindowKind::Shared,
        )
        .unwrap();
        let ram = Arc::new(ram);
        let revocation = BirthSourceRevocation::new();
        let identity = BirthSourceIdentity::from_backend_identity(
            ram.clone(),
            NonZeroU64::MIN,
            NonZeroU64::MIN,
        );
        let source = PhysicalBirthSource::new(ram, identity, revocation.0.clone()).unwrap();
        (revocation, source)
    }
    #[test]
    fn physical_birth_source_retains_bytes_but_refuses_retired_custody() {
        let (custody, source) = source();
        let weak_backing = Arc::downgrade(&source._ram);
        assert_eq!(source.allocate(source.identity()).unwrap().get(), 1);
        assert_eq!(
            source.allocate_mm(source.identity()).unwrap().raw(),
            NonZeroU64::MIN
        );
        let peer = source.clone();
        drop(custody); // Same revocation owner as Cpl0HostCustody::drop.
        assert!(weak_backing.upgrade().is_some());
        assert_eq!(
            source.allocate_mm(source.identity()),
            Err(BirthSourceError::StaleOwner)
        );
        assert_eq!(
            peer.adopt_initial_mm(
                peer.identity(),
                carrick_guest_arch::MmGeneration::new(NonZeroU64::MIN)
            ),
            Err(BirthSourceError::StaleOwner)
        );
        assert_eq!(
            source.allocate(source.identity()),
            Err(BirthSourceError::StaleOwner)
        );
        assert_eq!(
            peer.advance_past(peer.identity(), NonZeroU64::MAX),
            Err(BirthSourceError::StaleOwner)
        );
        assert_eq!(
            peer.adopt_initial(peer.identity(), NonZeroU64::MIN),
            Err(BirthSourceError::StaleOwner)
        );
        drop(peer);
        drop(source);
        assert!(weak_backing.upgrade().is_none());
    }
    #[test]
    fn physical_birth_source_rejects_another_generation_one_and_live_handoff() {
        let (_first_custody, first) = source();
        let (_second_custody, second) = source();
        assert_ne!(first.identity(), second.identity());
        assert_eq!(
            first.allocate_mm(second.identity()),
            Err(BirthSourceError::StaleOwner)
        );
        assert_eq!(
            first.allocate_mm(first.identity()).unwrap().raw(),
            core::num::NonZeroU64::MIN
        );
        assert!(
            first
                .adopt_initial_mm(
                    first.identity(),
                    carrick_guest_arch::MmGeneration::new(core::num::NonZeroU64::MIN)
                )
                .is_err()
        );
        assert_eq!(
            first.allocate(second.identity()),
            Err(BirthSourceError::StaleOwner)
        );
        first
            .adopt_initial(first.identity(), NonZeroU64::new(103).unwrap())
            .unwrap();
        assert_eq!(first.allocate(first.identity()).unwrap().get(), 104);
        assert_eq!(
            first.adopt_initial(first.identity(), NonZeroU64::new(500).unwrap()),
            Err(BirthSourceError::StaleOwner)
        );
        assert_eq!(first.allocate(first.identity()).unwrap().get(), 105);
        assert_eq!(second.allocate(second.identity()).unwrap().get(), 1);
    }
}

#[cfg(test)]
mod bootstrap_descriptor_tests {
    use super::*;
    use crate::guest_ram::WindowKind;
    use carrick_hal::guest_arch::GuestArch;
    use carrick_hal::x8664_arch::X8664GuestArch;
    use carrick_x86::interrupts::*;

    fn word(ram: &GuestRam, gpa: u64) -> u64 {
        u64::from_le_bytes(ram.read(gpa, 8).unwrap().try_into().unwrap())
    }

    #[test]
    fn initialize_bootstrap_descriptors_has_exact_bytes() {
        for hardware_interrupts in [false, true] {
            let mut ram = GuestRam::new();
            ram.add_window(0, RAM_SIZE, WindowKind::Private).unwrap();
            let boot = X8664GuestArch::bootstrap_sysregs();
            let entries = [
                IMAGE_VA + 16,
                IMAGE_VA + 32,
                IMAGE_VA + 48,
                IMAGE_VA + 64,
                IMAGE_VA + 80,
            ];
            ram.write_gpa(IRQ_HEADER_GPA, &IRQ_HEADER_MAGIC.to_le_bytes())
                .unwrap();
            for (index, entry) in entries.iter().enumerate() {
                ram.write_gpa(
                    IRQ_HEADER_GPA + 8 * (index as u64 + 1),
                    &entry.to_le_bytes(),
                )
                .unwrap();
            }
            initialize_bootstrap_descriptors(&mut ram, &boot, hardware_interrupts).unwrap();
            // Fixed architectural encodings, independent of the serializer.
            for (index, expected) in [
                0,
                0x0020_9b00_0000_0000,
                0x0000_9300_0000_0000,
                0x0000_f300_0000_0000,
                0x0020_fb00_0000_0000,
            ]
            .into_iter()
            .enumerate()
            {
                assert_eq!(word(&ram, LAYOUT.gdt_base + index as u64 * 8), expected);
            }
            for slot in 0..2 {
                let idt =
                    carrick_x86::fault_slot_gpa(carrick_x86::fault_idt_base(LAYOUT), slot).unwrap();
                let stub = carrick_x86::fault_slot_gpa(carrick_x86::fault_stub_base(LAYOUT), slot)
                    .unwrap();
                for vector in 0..256_u64 {
                    let irq = [
                        TIMER_VECTOR,
                        KICK_VECTOR,
                        RESCHED_VECTOR,
                        SHOOTDOWN_VECTOR,
                        PAGE_FAULT_VECTOR,
                    ]
                    .iter()
                    .position(|&v| u64::from(v) == vector)
                    .filter(|_| hardware_interrupts);
                    let fault = [0, 6, 8, 10, 11, 12, 13, 14, 16, 17, 19].contains(&vector);
                    let mut expected = [0_u8; 16];
                    if fault || irq.is_some() {
                        let entry = irq.map_or(DIRECT_VA + stub + vector * 128, |i| entries[i]);
                        expected[0..2].copy_from_slice(&(entry as u16).to_le_bytes());
                        expected[2..4].copy_from_slice(&8_u16.to_le_bytes());
                        expected[4] = u8::from(vector == 8);
                        expected[5] = 0x8e;
                        expected[6..8].copy_from_slice(&((entry >> 16) as u16).to_le_bytes());
                        expected[8..12].copy_from_slice(&((entry >> 32) as u32).to_le_bytes());
                    }
                    assert_eq!(
                        ram.read(idt + vector * 16, 16).unwrap(),
                        expected,
                        "interrupts={hardware_interrupts} slot={slot} vector={vector}"
                    );
                }
                let tss =
                    carrick_x86::fault_slot_gpa(carrick_x86::fault_tss_base(LAYOUT), slot).unwrap();
                let stack =
                    carrick_x86::fault_slot_gpa(carrick_x86::fault_stack_base(LAYOUT), slot)
                        .unwrap();
                assert_eq!(word(&ram, tss + 4), DIRECT_VA + stack + 4096);
                assert_eq!(
                    word(&ram, tss + 36),
                    DIRECT_VA + IST_STACK_BASE + (slot + 1) * 4096
                );
                for offset in [12, 20, 44, 52, 60, 68, 76, 84] {
                    assert_eq!(word(&ram, tss + offset), 0);
                }
            }
        }
    }
}

pub mod fixture_maps {
    //! Shared fixture map geometry for stopped CPL0 bootstrap preparation.
    use crate as carrick_x86_cpl0_host;
    use carrick_guest_arch::FrameGpa;
    use carrick_mem::pml4::Pml4MapSpec;
    use carrick_sched_core::{ParkedContextWords, ZoneTables};
    use carrick_x86::cpl0_scheduler::*;
    use carrick_x86::interrupts::*;

    pub const FIRST_ROOT: u64 = 0x60_0000;
    pub const PROGRESS_ZONE_GPA: u64 = (carrick_x86_cpl0_host::cpl0_boot::ALLOCATOR_GPA
        + carrick_el1_abi::EL1_BOOTSTRAP_METADATA_SIZE)
        .next_multiple_of(0x20_0000);
    // The guest and host must name the same retained sidecars when the shared
    // lifecycle layout moves. Boot publication and stopped observation use this
    // translation, rather than keeping a second physical placement constant.
    pub const LIFECYCLE_LANES_GPA: FrameGpa = FrameGpa::new(
        PROGRESS_ZONE_GPA
            + (carrick_x86::cpl0_lifecycle::LIFECYCLE_LANE
                - carrick_x86::cpl0_lifecycle::LIFECYCLE_ZONE),
    );
    // boot_lifecycle shares this mapping, including its two fixed sidecars.
    pub const SUPERVISOR_BYTES: u64 = (carrick_x86::cpl0_lifecycle::LIFECYCLE_LANE - PROGRESS_ZONE
        + carrick_x86::cpl0_lifecycle::LIFECYCLE_STRIDE
        + size_of::<carrick_x86::cpl0_lifecycle::LifecycleLane>() as u64)
        .next_multiple_of(4096);
    pub const PROGRESS_STATE_GPA: u64 = PROGRESS_ZONE_GPA + (PROGRESS_STATE - PROGRESS_ZONE);
    // Table walkers use the shared bootstrap direct-window authority. Keep roots
    // in low RAM even when the scheduler's independent backing grows past it.
    pub const SECOND_ROOT: u64 = (carrick_x86_cpl0_host::cpl0_boot::META_GPA
        + carrick_x86_cpl0_host::cpl0_boot::META_LEN)
        .next_multiple_of(4096);
    const _: () = {
        use carrick_x86::cpl0_lifecycle::{LIFECYCLE_STRIDE, LIFECYCLE_ZONE, LifecycleLane};

        assert!(
            FIRST_ROOT + carrick_x86::X86_PML4_CAPACITY
                <= carrick_x86_cpl0_host::cpl0_boot::META_GPA
        );
        assert!(
            SECOND_ROOT + carrick_x86::X86_PML4_CAPACITY
                <= carrick_x86_cpl0_host::cpl0_boot::RAM_SIZE as u64
        );
        assert!(
            SECOND_ROOT + carrick_x86::X86_PML4_CAPACITY
                <= carrick_el1_abi::X86_CPL0_DIRECT_WINDOW_BYTES
        );
        assert!(
            PROGRESS_ZONE_GPA + size_of::<ZoneTables<ParkedContextWords>>() as u64
                <= PROGRESS_STATE_GPA
        );
        assert!(
            PROGRESS_STATE_GPA + size_of::<ProgressState>() as u64 <= LIFECYCLE_LANES_GPA.raw()
        );
        assert!(SECOND_ROOT.is_multiple_of(4096));
        assert!(LIFECYCLE_ZONE == PROGRESS_ZONE);
        let lanes_gpa = LIFECYCLE_LANES_GPA.raw();
        assert!(SECOND_ROOT + carrick_x86::X86_PML4_CAPACITY <= lanes_gpa);
        assert!(lanes_gpa.is_multiple_of(align_of::<LifecycleLane>() as u64));
        assert!(LIFECYCLE_STRIDE.is_multiple_of(align_of::<LifecycleLane>() as u64));
        assert!(size_of::<LifecycleLane>() as u64 <= LIFECYCLE_STRIDE);
        assert!(
            lanes_gpa + LIFECYCLE_STRIDE + size_of::<LifecycleLane>() as u64
                <= PROGRESS_ZONE_GPA + SUPERVISOR_BYTES
        );
        let direct = carrick_el1_abi::X86_CPL0_DIRECT_VA + PROGRESS_ZONE_GPA;
        assert!(
            direct + SUPERVISOR_BYTES <= PROGRESS_ZONE
                || PROGRESS_ZONE + SUPERVISOR_BYTES <= direct
        );
        assert!(direct + SUPERVISOR_BYTES <= carrick_el1_abi::X86_CPL0_REGION_BASE);
        assert!(PROGRESS_ZONE + SUPERVISOR_BYTES <= carrick_el1_abi::X86_CPL0_REGION_BASE);
        assert!(
            PROGRESS_ZONE_GPA + SUPERVISOR_BYTES
                <= carrick_x86_cpl0_host::cpl0_boot::KERNEL_REGION_GPA
        );
        // The interrupt witness has a separate window above allocator backing.
        assert!(
            PROGRESS_ZONE_GPA
                >= carrick_x86_cpl0_host::cpl0_boot::ALLOCATOR_GPA
                    + carrick_el1_abi::EL1_BOOTSTRAP_METADATA_SIZE
        );
    };
    pub fn supervisor_maps() -> [Pml4MapSpec; 2] {
        [
            Pml4MapSpec {
                va: PROGRESS_ZONE,
                gpa: PROGRESS_ZONE_GPA,
                len: SUPERVISOR_BYTES,
                user: false,
                write: true,
                exec: false,
            },
            lapic_map(),
        ]
    }

    pub fn lapic_map() -> Pml4MapSpec {
        Pml4MapSpec {
            va: carrick_x86::interrupts::LAPIC_VA,
            gpa: LAPIC_BASE,
            len: 4096,
            user: false,
            write: true,
            exec: false,
        }
    }
    pub fn data_map(index: u64) -> Pml4MapSpec {
        Pml4MapSpec {
            va: PROGRESS_DATA,
            gpa: PROGRESS_DATA + index * 4096,
            len: 4096,
            user: true,
            write: true,
            exec: false,
        }
    }
}

/// Owned neutral preparation retained through memory installation and CPU admission.
/// Moving this value preserves the original RAM and authority backing allocations.
pub struct PreparedBoot {
    pub ram: Arc<GuestRam>,
    pub plan: carrick_mem::elf::LoadPlan,
    pub boot: carrick_hal::x8664_arch::X8664BootSysregs,
    pub hardware_interrupts: bool,
    pub fixture_copy: bool,
    pub table_capacity: usize,
    pub ipc_backings: Vec<PreparedBacking>,
    pub ipc_generation: Option<NonZeroU64>,
    pub kernel_pod_storage: Vec<anonymous_owner::KernelPodStorage>,
}

fn bootstrap_cpu_binding(index: usize, scheduler_witness: u64) -> CpuBinding {
    let offset = index as u64 * STRIDE;
    CpuBinding {
        kernel_stack: DIRECT_VA + carrick_el1_abi::x86_cpl0_kernel_stack_end_gpa(index)
            - carrick_el1_abi::X86_CPL0_KERNEL_STACK_TOP_RESERVE,
        user_stack: 0,
        self_address: METADATA_VA + BINDING_OFFSET + offset,
        task_address: METADATA_VA + TASK_OFFSET + offset,
        counters_address: METADATA_VA + COUNTERS_OFFSET,
        entry_kick: AtomicU32::new(0),
        return_kick: AtomicU32::new(0),
        entries: AtomicU64::new(0),
        publications: AtomicU64::new(0),
        completions: AtomicU64::new(0),
        captured_stack: AtomicU64::new(0),
        scheduler_witness: AtomicU64::new(scheduler_witness),
        cpu_slot: index as u32,
        tsc_hz: AtomicU64::new(0),
        wake_routes_address: METADATA_VA + ROUTES_OFFSET,
        apic_timer_hz: AtomicU64::new(0),
        pending_irqs: AtomicU32::new(0),
        shootdown_table_address: METADATA_VA + SHOOTDOWN_OFFSET,
        fault_active: AtomicU64::new(0),
        fault_frame: AtomicU64::new(0),
        fault_address: AtomicU64::new(0),
        fault_reason: AtomicU64::new(0),
        mm_owner_generation: AtomicU64::new(1),
        last_seen_generation: AtomicU64::new(0),
        file_region: carrick_el1_abi::FileRegionBinding::UNPUBLISHED,
        cr4_snapshot: AtomicU64::new(0),
        owed_resched: core::array::from_fn(|_| AtomicU64::new(0)),
        icr_failing_since: AtomicU64::new(0),
    }
}

/// Prepare retained RAM and bindings before backend memory registration.
pub fn prepare_boot(
    frame_inventory: &dyn PhysicalFrameInventory,
    bytes: &[u8],
    programs: [&[u8]; 2],
    interrupts: bool,
    initial_extent_bytes: Option<usize>,
    fixture_image: bool,
    ipc: Option<Arc<dyn carrick_el1_abi::IpcWindowBacking>>,
) -> Result<PreparedBoot, TrapError> {
    let hardware_interrupts = interrupts || initial_extent_bytes.is_some();
    let plan = carrick_mem::elf::plan_elf_load_bytes_for(bytes, 62)
        .map_err(|e| fail(format!("CPL0 ELF: {e}")))?;
    if !(IMAGE_VA..IMAGE_VA + IMAGE_SIZE).contains(&plan.entry) {
        return Err(fail("CPL0 entry outside its supervisor image"));
    }
    let mut ram = GuestRam::new();
    if initial_extent_bytes.is_some() {
        let zone_end = carrick_core_abi::X86_CPL0_ZONE_OFFSET as usize + size_of::<X86Cpl0Zone>();
        let region_bytes = (zone_end + 4095) & !4095;
        ram.add_window(0, META_GPA as usize, WindowKind::Private)
            .map_err(|e| fail(e.to_string()))?;
        ram.add_window(PRODUCTION_METADATA_GPA, region_bytes, WindowKind::Private)
            .map_err(|e| fail(e.to_string()))?;
    } else {
        ram.add_window(0, RAM_SIZE, WindowKind::Private)
            .map_err(|e| fail(e.to_string()))?;
        if interrupts {
            ram.add_window(
                fixture_maps::PROGRESS_ZONE_GPA,
                fixture_maps::SUPERVISOR_BYTES as usize,
                WindowKind::Private,
            )
            .map_err(|e| fail(e.to_string()))?;
        }
    }
    ram.add_window(
        ALLOCATOR_GPA,
        EL1_BOOTSTRAP_METADATA_SIZE as usize,
        WindowKind::Private,
    )
    .map_err(|e| fail(e.to_string()))?;
    let kernel_pod_storage = anonymous_owner::retained_kernel_pod_storage(&plan.segments);
    let mut maps = Vec::new();
    for segment in &plan.segments {
        let end = segment
            .virtual_address
            .checked_add(segment.memory_size)
            .ok_or_else(|| fail("CPL0 segment overflow"))?;
        if segment.virtual_address < IMAGE_VA || end > IMAGE_VA + IMAGE_SIZE {
            return Err(fail("CPL0 segment outside its supervisor image"));
        }
        let start = segment.file_offset as usize;
        let data = bytes
            .get(start..start + segment.file_size as usize)
            .ok_or_else(|| fail("CPL0 segment file bounds"))?;
        let gpa = IMAGE_GPA + segment.virtual_address - IMAGE_VA;
        ram.write_gpa(gpa, data).map_err(|e| fail(e.to_string()))?;
        let va = segment.virtual_address & !0xfff;
        maps.push(Pml4MapSpec {
            va,
            gpa: IMAGE_GPA + va - IMAGE_VA,
            len: ((end + 0xfff) & !0xfff) - va,
            user: false,
            write: segment.perms.write,
            exec: segment.perms.execute,
        });
    }
    if initial_extent_bytes.is_some() {
        let bytes = ram
            .read(
                X86_INITIAL_BOOT_HEADER_GPA,
                size_of::<X86InitialBootHeader>(),
            )
            .map_err(|error| fail(error.to_string()))?;
        // SAFETY: read returned a complete header; byte storage may be unaligned.
        let header = unsafe {
            bytes
                .as_ptr()
                .cast::<X86InitialBootHeader>()
                .read_unaligned()
        };
        if header.magic != X86_INITIAL_BOOT_MAGIC || header.version != X86_INITIAL_BOOT_VERSION {
            return Err(fail("production image boot header invalid"));
        }
        validate_layout_hash(header.layout_hash)?;
    }
    // Existing x86 descriptor/TSS/IDT machinery, including private stacks
    // and exception stubs, remains the hardware authority.
    let stub_start = carrick_x86::fault_stub_base(LAYOUT);
    let stub_end = carrick_x86::fault_tss_base(LAYOUT);
    if !(IMAGE_GPA + IMAGE_SIZE < stub_start && stub_start < stub_end && stub_end < META_GPA) {
        return Err(fail("CPL0 stub outside direct window"));
    }
    // Retained exception stubs execute from their supervisor alias. The
    // page tables, private IDTs, TSS, stacks and records need write access
    // but must never be executable in that alias.
    for (start, end, write, exec) in [
        (IMAGE_GPA + IMAGE_SIZE, stub_start, true, false),
        (stub_start, stub_end, false, true),
        (stub_end, META_GPA, true, false),
    ] {
        maps.push(Pml4MapSpec {
            va: DIRECT_VA + start,
            gpa: start,
            len: end - start,
            user: false,
            write,
            exec,
        });
    }
    maps.push(Pml4MapSpec {
        va: DIRECT_VA + META_GPA,
        gpa: META_GPA,
        len: if initial_extent_bytes.is_some() {
            ((carrick_core_abi::X86_CPL0_ZONE_OFFSET as usize + size_of::<X86Cpl0Zone>() + 4095)
                & !4095) as u64
        } else {
            0x40_0000
        },
        user: false,
        write: true,
        exec: false,
    });
    maps.push(Pml4MapSpec {
        va: METADATA_VA,
        gpa: META_GPA,
        len: META_LEN,
        user: false,
        write: true,
        exec: false,
    });
    if initial_extent_bytes.is_some() {
        maps.push(Pml4MapSpec {
            va: METADATA_VA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
            gpa: PRODUCTION_METADATA_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
            len: (size_of::<X86Cpl0Zone>() as u64 + 4095) & !4095,
            user: false,
            write: true,
            exec: false,
        });
    }
    maps.push(Pml4MapSpec {
        va: X86_CPL0_BOOTSTRAP_METADATA_BASE,
        gpa: ALLOCATOR_GPA,
        len: EL1_BOOTSTRAP_METADATA_SIZE,
        user: false,
        write: true,
        exec: false,
    });
    if let Some(len) = initial_extent_bytes {
        maps.push(Pml4MapSpec {
            va: X86_CPL0_INITIAL_EXTENT_VA,
            gpa: INITIAL_EXTENT_GPA,
            len: len as u64,
            user: false,
            write: true,
            exec: false,
        });
    }
    maps.push(Pml4MapSpec {
        va: X86_CPL0_REGION_BASE,
        gpa: KERNEL_REGION_GPA,
        len: carrick_el1_abi::EL1_REGION_SIZE,
        user: false,
        write: true,
        exec: false,
    });

    // These aliases map the authority's original allocations, never a copy.
    const IPC_GPA: u64 = IPC_WINDOW_GPA;
    let mut ipc_backings = Vec::new();
    let mut ipc_generation = None;
    if let Some(owner) = ipc {
        use crate::carrier_memory::IpcWindowPart;
        let window = unsafe {
            carrick_el1_abi::IpcWindow::new(
                owner.directory_ptr() as usize,
                owner.directory_len(),
                owner.pool_ptr() as usize,
                owner.pool_len(),
            )
        }
        .ok_or_else(|| fail("invalid IPC window geometry"))?;
        ipc_generation = Some(
            window
                .attach()
                .map_err(|e| fail(format!("IPC window attachment: {e:?}")))?
                .operation_slot_generation(),
        );
        for (part, va, gpa) in [
            (
                IpcWindowPart::Directory,
                carrick_el1_abi::X86_CPL0_IPC_BASE,
                IPC_GPA,
            ),
            (
                IpcWindowPart::Pool,
                carrick_el1_abi::X86_CPL0_IPC_POOL_BASE,
                IPC_GPA + carrick_el1_abi::EL1_IPC_DIRECTORY_SPAN,
            ),
        ] {
            let extent = Arc::new(
                BackingExtent::ipc_window(FrameGpa::new(gpa), Arc::clone(&owner), part)
                    .map_err(|e| fail(e.to_string()))?,
            );
            maps.push(Pml4MapSpec {
                va,
                gpa,
                len: extent.len as u64,
                user: false,
                write: true,
                exec: false,
            });
            ipc_backings.push(PreparedBacking {
                extent,
                identity: backing_identity(frame_inventory)?,
            });
        }
    }

    for (index, program) in programs.iter().enumerate() {
        if program.is_empty() {
            continue;
        }
        if program.len() > 4096 {
            return Err(fail("CPL0 fixture exceeds one code page"));
        }
        let code = USER_CODE + index as u64 * 4096;
        ram.write_gpa(code, program)
            .map_err(|e| fail(e.to_string()))?;
        maps.push(Pml4MapSpec {
            va: code,
            gpa: code,
            len: 4096,
            user: true,
            write: false,
            exec: true,
        });
        let stack = 0x3_0000 + index as u64 * 0x1_0000;
        maps.push(Pml4MapSpec {
            va: stack,
            gpa: stack,
            len: 8192,
            user: true,
            write: true,
            exec: false,
        });
    }
    if interrupts {
        maps.push(Pml4MapSpec {
            va: DIRECT_VA + fixture_maps::PROGRESS_ZONE_GPA,
            gpa: fixture_maps::PROGRESS_ZONE_GPA,
            len: fixture_maps::SUPERVISOR_BYTES,
            user: false,
            write: true,
            exec: false,
        });
        maps.extend(fixture_maps::supervisor_maps());
        maps.push(fixture_maps::data_map(0));
    } else if hardware_interrupts {
        maps.push(fixture_maps::lapic_map());
    }
    // CPL0 ordinary loads/copies can race a page-table publication after
    // preflight. Keep every bootstrap supervisor leaf outside the user
    // range so a changed lower-half leaf cannot expose kernel backing.
    if maps
        .iter()
        .any(|map| !map.user && map.va < 0x0000_8000_0000_0000)
    {
        return Err(fail("CPL0 supervisor map in user range"));
    }
    // Fixture bootstrap roots reserve an exclusive zero suffix for the
    // same private copy branch that production initial-MM admission owns.
    // The constructor cannot allocate these pages into any other branch.
    let fixture_copy = fixture_image && initial_extent_bytes.is_none();
    let table_capacity = (carrick_x86::X86_PML4_CAPACITY as usize)
        .checked_sub(if fixture_copy {
            carrick_mmu_core::x86::copy_window::COW_COPY_TABLE_PAGES * 4096
        } else {
            0
        })
        .ok_or_else(|| fail("fixture private copy table capacity"))?;
    // Every CPU's kernel stack guard stays unmapped in the direct window
    // the stacks run on (#369), whatever bootstrap map would cover it.
    let guards: Vec<(u64, u64)> = carrick_el1_abi::x86_cpl0_kernel_stack_guards().collect();
    let tables = pml4_tables(
        &carrick_mem::pml4::punch_holes(&maps, &guards),
        LAYOUT.pml4_base,
        table_capacity,
    )
    .map_err(|e| fail(format!("CPL0 tables: {e:?}")))?;
    ram.write_gpa(LAYOUT.pml4_base, &tables)
        .map_err(|e| fail(e.to_string()))?;
    if interrupts {
        let last = maps.last_mut().ok_or_else(|| fail("progress data map"))?;
        *last = fixture_maps::data_map(1);
        let second = pml4_tables(
            &carrick_mem::pml4::punch_holes(&maps, &guards),
            fixture_maps::SECOND_ROOT,
            table_capacity,
        )
        .map_err(|e| fail(format!("second progress root: {e:?}")))?;
        ram.write_gpa(fixture_maps::SECOND_ROOT, &second)
            .map_err(|e| fail(e.to_string()))?;
    }
    let boot = <carrick_hal::x8664_arch::X8664GuestArch as carrick_hal::guest_arch::GuestArch>::bootstrap_sysregs();
    initialize_bootstrap_descriptors(&mut ram, &boot, hardware_interrupts)?;
    // SAFETY: private zeroed backing; typed objects fit and are aligned.
    // They are initialized before registration or any guest execution.
    unsafe {
        let page = ram
            .host_ptr(META_GPA, size_of::<ThreadLifecyclePage>())
            .ok_or_else(|| fail("lifecycle page backing"))?
            .cast::<ThreadLifecyclePage>();
        page.write(ThreadLifecyclePage::new());
        // Retained empty control storage, shared by real native births.
        // Identity issuance and all live/runnable publication stay in ring.
        let controls = ram
            .host_ptr(
                META_GPA + carrick_core_abi::X86_CPL0_ROOT_THREAD_CONTROLS_OFFSET,
                carrick_core_abi::X86_CPL0_ROOT_THREAD_CONTROLS_SIZE as usize,
            )
            .ok_or_else(|| fail("native root thread control backing"))?
            .cast::<ThreadControlSlot>();
        for index in 0..=carrick_el1_abi::THREAD_POOL_ENTRIES {
            controls.add(index).write(ThreadControlSlot::new());
        }
        (*page)
            .thread_born()
            .ok_or_else(|| fail("second live task admission"))?;
        let counters = ram
            .host_ptr(META_GPA + COUNTERS_OFFSET, size_of::<Counters>())
            .ok_or_else(|| fail("counter backing"))?
            .cast::<Counters>();
        counters.write(Counters::new());
        let routes = ram
            .host_ptr(META_GPA + ROUTES_OFFSET, size_of::<PublishedApicIds>())
            .ok_or_else(|| fail("APIC route table backing"))?
            .cast::<PublishedApicIds>();
        routes.write(PublishedApicIds::new());
        let shootdown = ram
            .host_ptr(META_GPA + SHOOTDOWN_OFFSET, size_of::<ShootdownTable>())
            .ok_or_else(|| fail("shootdown table backing"))?
            .cast::<ShootdownTable>();
        shootdown.write(ShootdownTable::new());
        for index in 0..2 {
            let offset = index as u64 * STRIDE;
            let slot = ram
                .host_ptr(
                    META_GPA + CONTROL_OFFSET + offset,
                    size_of::<ThreadControlSlot>(),
                )
                .ok_or_else(|| fail("control slot backing"))?
                .cast::<ThreadControlSlot>();
            slot.write(ThreadControlSlot::new());
            (*slot)
                .reset_for_host_birth(BlockedMask(0))
                .map_err(|_| fail("control slot still owned by graph"))?;
            if !(*slot).publish_visible_tid(41 + index as u32) {
                return Err(fail("issued slot identity"));
            }
            let birth = carrick_core::terminal::ThreadBirthIdentity::from_parts(
                carrick_core_abi::EntryTaskKey::from_raw(41 + index as u64),
                carrick_core_abi::BirthSerial::of_task(
                    carrick_sched_core::process::TaskSerial::from_raw_u64(11 + index as u64)
                        .ok_or_else(|| fail("issued slot birth serial"))?,
                ),
                carrick_core_abi::EntryThreadGeneration::from_raw(101 + index as u64),
            )
            .ok_or_else(|| fail("issued slot birth identity"))?;
            (*slot).publish_host_birth_identity(birth);
            let task = ram
                .host_ptr(META_GPA + TASK_OFFSET + offset, size_of::<CurrentTask>())
                .ok_or_else(|| fail("current task backing"))?
                .cast::<CurrentTask>();
            task.write(CurrentTask::new());
            (*task).set(
                El1TaskId::from_linux_tid(41 + index as i32),
                carrick_el1_abi::SnapshotGeneration::from_raw(11 + index as u64),
                5,
            );
            (*task)
                .mm
                .thread_generation
                .store(101 + index as u64, Ordering::Release);
            (*task).mm.key.store(201 + index as u64, Ordering::Release);
            (*shootdown).members[index].publish(
                if interrupts && index == 1 {
                    fixture_maps::SECOND_ROOT
                } else {
                    LAYOUT.pml4_base
                },
                201 + index as u64,
                1,
            );
            (*task).publish_lifecycle(METADATA_VA, METADATA_VA + CONTROL_OFFSET + offset);
            let binding = ram
                .host_ptr(META_GPA + BINDING_OFFSET + offset, size_of::<CpuBinding>())
                .ok_or_else(|| fail("CPU binding backing"))?
                .cast::<CpuBinding>();
            let witness = if fixture_image && interrupts && index == 0 {
                carrick_x86::cpl0_scheduler::PROGRESS_STATE
            } else {
                0
            };
            binding.write(bootstrap_cpu_binding(index, witness));
        }
    }
    let ram = Arc::new(ram);
    Ok(PreparedBoot {
        ram,
        plan,
        boot,
        hardware_interrupts,
        fixture_copy,
        table_capacity,
        ipc_backings,
        ipc_generation,
        kernel_pod_storage,
    })
}

/// Backend memory registered for a stopped carrier, before CPU creation.
pub struct BootMemory<M: CarrierMemoryIo> {
    pub memory: CarrierMemory<M>,
    pub files: BootstrapFileRegion,
    pub kernel_region: Option<BackingHandle>,
    pub initial_extent: Option<(BackingHandle, usize)>,
}

/// Register `prepared` with a backend carrier VM: the retained bootstrap
/// windows and IPC backings, the fixture copy windows, the kernel file region
/// with its fault records, the initial extent and each CPU's file binding.
/// Shared by every backend; only VM creation and slot registration differ.
pub fn install_boot_memory<M: CarrierMemoryIo>(
    vm: M,
    frame_inventory: &dyn PhysicalFrameInventory,
    prepared: &PreparedBoot,
    interrupts: bool,
    initial_extent_bytes: Option<usize>,
) -> Result<BootMemory<M>, TrapError> {
    let PreparedBoot {
        ram,
        fixture_copy,
        table_capacity,
        ipc_backings,
        ipc_generation,
        ..
    } = prepared;
    let (fixture_copy, table_capacity, ipc_generation) =
        (*fixture_copy, *table_capacity, *ipc_generation);
    let mut memory = CarrierMemory::new(vm).map_err(|e| fail(e.to_string()))?;
    memory
        .install_bootstrap(Arc::clone(ram))
        .map_err(|e| fail(e.to_string()))?;
    if !ipc_backings.is_empty() {
        memory
            .install(ipc_backings)
            .map_err(|e| fail(e.to_string()))?;
        let zone = ram
            .host_ptr(
                PRODUCTION_METADATA_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
                size_of::<X86Cpl0Zone>(),
            )
            .ok_or_else(|| fail("IPC operation slot zone"))?;
        // SAFETY: the production zone was initialized above and remains
        // retained; no vCPU has been created or entered.
        let zone = unsafe { &*zone.cast::<X86Cpl0Zone>() };
        zone.bind_ipc_operation_slots(
            ipc_generation.ok_or_else(|| fail("IPC slot generation missing"))?,
            &carrick_sched_core::BoundedSpin(0),
            &|owned| {
                let _ = owned.into_parts();
            },
        )
        .map_err(|e| fail(format!("IPC slot binding: {e:?}")))?;
    }
    if fixture_copy {
        let mut roots = vec![LAYOUT.pml4_base];
        if interrupts {
            roots.push(fixture_maps::SECOND_ROOT);
        }
        for base in roots {
            let root = RootGpa::page_aligned(FrameGpa::new(base))
                .ok_or_else(|| fail("fixture copy root alignment"))?;
            let mut grants = [root; carrick_mmu_core::x86::copy_window::COW_COPY_TABLE_PAGES];
            for (index, grant) in grants.iter_mut().enumerate() {
                let pa = base
                    .checked_add(table_capacity as u64)
                    .and_then(|pa| pa.checked_add(index as u64 * 4096))
                    .ok_or_else(|| fail("fixture copy table grant overflow"))?;
                *grant = RootGpa::page_aligned(FrameGpa::new(pa))
                    .ok_or_else(|| fail("fixture copy table grant alignment"))?;
            }
            carrick_mmu_core::x86::copy_window::provision_cow_copy_window(
                &memory.words(),
                root,
                grants,
            )
            .map_err(|reason| fail(format!("fixture private copy branch: {reason:?}")))?;
        }
    }
    let identity = backing_identity(frame_inventory)?;
    let extent = Arc::new(
        BackingExtent::private(
            FrameGpa::new(KERNEL_REGION_GPA),
            carrick_el1_abi::EL1_REGION_SIZE as usize,
        )
        .map_err(|e| fail(e.to_string()))?,
    );
    let file_binding = carrick_el1_abi::FileRegionBinding::new(
        carrick_el1_abi::FileRegionId::from_carrier(memory.identity().nonzero()),
        carrick_guest_arch::KernelVa::new(X86_CPL0_REGION_BASE),
        FrameGpa::new(KERNEL_REGION_GPA),
        carrick_guest_arch::GuestLen::new(carrick_el1_abi::EL1_REGION_SIZE),
    )
    .map_err(|e| fail(format!("file region binding: {e:?}")))?;
    // SAFETY: this fresh private extent covers the complete binding and
    // has no guest, registration or table users yet. RetainedFileRegion
    // keeps the same mapping alive through registration destruction.
    let files = unsafe { BootstrapFileRegion::initialize(Arc::clone(&extent), file_binding) }?;
    if !ipc_backings.is_empty() {
        files.publish_ipc_window()?;
    }
    let handles = memory
        .install(&[PreparedBacking { extent, identity }])
        .map_err(|e| fail(e.to_string()))?;
    let kernel_region = Some(handles[0]);
    let initial_extent = if let Some(len) = initial_extent_bytes {
        let identity = backing_identity(frame_inventory)?;
        let extent = BackingExtent::private(FrameGpa::new(INITIAL_EXTENT_GPA), len)
            .map_err(|e| fail(e.to_string()))?;
        let handles = memory
            .install(&[PreparedBacking {
                extent: Arc::new(extent),
                identity,
            }])
            .map_err(|e| fail(e.to_string()))?;
        Some((handles[0], len))
    } else {
        None
    };
    memory
        .initialize_fault_records(FrameGpa::new(KERNEL_REGION_GPA))
        .map_err(|error| fail(error.to_string()))?;
    for index in 0..2 {
        let binding = ram
            .host_ptr(
                META_GPA + BINDING_OFFSET + index as u64 * STRIDE,
                size_of::<CpuBinding>(),
            )
            .ok_or_else(|| fail("file CPU binding"))?
            .cast::<CpuBinding>();
        // SAFETY: initialized retained binding; vCPUs have not been created.
        unsafe {
            (*binding).file_region = file_binding;
        }
    }
    Ok(BootMemory {
        memory,
        files,
        kernel_region,
        initial_extent,
    })
}

/// Size one private retained aperture for the host-staged PT_LOAD bytes,
/// the boot record, guest-owned table/data grants and the page-table
/// reserve: the image must fit the supervisor-aliased window, and the
/// aperture is the whole window, so every MM's page tables can grow into
/// it on demand. The mapping is reserved, never committed up front.
pub fn initial_extent_bytes_for(
    image: &carrick_mem::x86_initial_image::X86InitialImage<'_>,
    argv: &[String],
    env: &[String],
) -> Result<usize, TrapError> {
    const PAGE: usize = 4096;
    const MAX_BYTES: usize = X86_CPL0_INITIAL_EXTENT_MAX_SIZE as usize;
    let mut image_pages = 0usize;
    let mut initialized = 0usize;
    for region in &image.regions {
        let pages = usize::try_from((region.end - region.start) / PAGE as u64)
            .map_err(|_| fail("initial image page count"))?;
        image_pages = image_pages
            .checked_add(pages)
            .ok_or_else(|| fail("initial image pages"))?;
        initialized = initialized
            .checked_add(region.file_bytes.len())
            .ok_or_else(|| fail("initial image bytes"))?;
    }
    let strings = argv
        .iter()
        .chain(env)
        .try_fold(0usize, |sum, value| sum.checked_add(value.len()))
        .ok_or_else(|| fail("initial argv/env bytes"))?;
    let user_pages = image_pages
        .checked_add(initial_stack_pages(image, argv, env)?)
        .ok_or_else(|| fail("initial user pages"))?;
    let table_pages =
        initial_table_grant_count(user_pages).ok_or_else(|| fail("initial table grant count"))?;
    let grants = table_pages
        .checked_add(user_pages)
        .ok_or_else(|| fail("initial grant count"))?;
    let string_count = argv
        .len()
        .checked_add(env.len())
        .ok_or_else(|| fail("initial string count"))?;
    let region_bytes = image
        .regions
        .len()
        .checked_mul(size_of::<carrick_core_abi::X86InitialBootRegion>())
        .ok_or_else(|| fail("initial region metadata"))?;
    let string_bytes = string_count
        .checked_mul(size_of::<carrick_core_abi::X86InitialBootString>())
        .ok_or_else(|| fail("initial string metadata"))?;
    let metadata = size_of::<carrick_core_abi::X86InitialBootRequest>()
        .checked_add(region_bytes)
        .and_then(|n| n.checked_add(string_bytes))
        .and_then(|n| {
            n.checked_add(grants.checked_mul(size_of::<carrick_core_abi::X86InitialBootGrant>())?)
        })
        .and_then(|n| {
            n.checked_add(
                user_pages.checked_mul(size_of::<carrick_el1_abi::GuestMmuPublication>())?,
            )
        })
        .and_then(|n| n.checked_add(initialized))
        .and_then(|n| n.checked_add(strings))
        .and_then(|n| n.checked_add(PAGE * 8)) // bounded alignment and argv terminators
        .ok_or_else(|| fail("initial request capacity"))?;
    let metadata_pages = metadata
        .checked_add(PAGE - 1)
        .ok_or_else(|| fail("initial metadata alignment"))?
        / PAGE;
    let total_pages = metadata_pages
        .checked_add(grants)
        .ok_or_else(|| fail("initial extent pages"))?;
    let bytes = total_pages
        .checked_mul(PAGE)
        .and_then(|bytes| bytes.checked_add(anonymous_owner::prepare_table_working_bytes()?))
        .ok_or_else(|| fail("initial extent size"))?;
    if bytes > MAX_BYTES {
        return Err(fail("initial image exceeds carrier memory budget"));
    }
    // The rest of the window is the page-table reserve (#3017): every MM's
    // tables come from this one retained, supervisor-aliased extent, and
    // their number follows the guest's address spaces, not this image. The
    // private mapping is reserved, not committed: a reserve page costs host
    // memory only once a table is drawn from it and written.
    Ok(MAX_BYTES)
}

/// One stopped kernel entry on a carrier CPU: kernel CS/SS, the given GS
/// base with `KERNEL_GS_BASE` zero, and `RFLAGS` = 2.
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
pub struct KernelEntry {
    pub rip: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub gs_base: u64,
}

/// What a stopped CPL0 carrier backend supplies to the shared initial-MM
/// admission ([`load_guest_mm`]): its custody, and its stopped CPUs' state,
/// kernel entry and run-to-exit. KVM and the soft carrier implement it.
pub trait Cpl0BootCarrier {
    type Memory: CarrierMemoryIo;
    fn custody(&self) -> &BootstrapCustody<Self::Memory>;
    fn custody_mut(&mut self) -> &mut BootstrapCustody<Self::Memory>;
    fn cpu_count(&self) -> usize;
    fn cpu_gpr(&self, index: usize, reg: X86Reg) -> Result<u64, TrapError>;
    fn enter_kernel(&mut self, index: usize, entry: KernelEntry) -> Result<(), TrapError>;
    fn run_cpu(&mut self, index: usize) -> Result<VcpuExit, TrapError>;
    fn append_debug_state(&self, index: usize, detail: &mut String);
}

/// The guest MM owner supplies the executable and stack publication here.
/// This is the sole unbound seam between a stopped production carrier and
/// EL0 admission; no fixture user page is used as an ELF loader.
pub fn load_guest_mm<C: Cpl0BootCarrier>(
    carrier: &mut C,
    image: &carrick_mem::x86_initial_image::X86InitialImage<'_>,
    argv: &[String],
    env: &[String],
    limits: InitialReservationLimits,
) -> Result<(), TrapError> {
    let (_, extent_len) = carrier
        .custody()
        .initial_extent()
        .ok_or_else(|| fail("initial extent absent"))?;
    if image.regions.is_empty()
        || image.regions.len() > X86_INITIAL_MAX_REGIONS
        || argv.len() + env.len() > X86_INITIAL_MAX_STRINGS
    {
        return Err(fail("initial image request population"));
    }
    let mut staged = vec![0; size_of::<X86InitialBootRequest>()];
    let regions_offset = staged.len();
    staged.resize(
        regions_offset + image.regions.len() * size_of::<X86InitialBootRegion>(),
        0,
    );
    let strings_offset = staged.len();
    staged.resize(
        strings_offset + (argv.len() + env.len()) * size_of::<X86InitialBootString>(),
        0,
    );
    let grants_offset = staged.len();
    let image_pages: usize = image
        .regions
        .iter()
        .map(|r| ((r.end - r.start) / 4096) as usize)
        .sum();
    let data_grants = image_pages
        .checked_add(initial_stack_pages(image, argv, env)?)
        .ok_or_else(|| fail("initial data grants"))?;
    let table_grants =
        initial_table_grant_count(data_grants).ok_or_else(|| fail("initial table grants"))?;
    let grant_count = table_grants
        .checked_add(data_grants)
        .ok_or_else(|| fail("initial grants"))?;
    staged.resize(
        grants_offset + grant_count * size_of::<X86InitialBootGrant>(),
        0,
    );
    let publications_offset = staged.len();
    staged.resize(
        publications_offset + data_grants * size_of::<carrick_el1_abi::GuestMmuPublication>(),
        0,
    );
    let mut regions = Vec::with_capacity(image.regions.len());
    for region in &image.regions {
        let source_gpa = append_records(&mut staged, region.file_bytes)?;
        regions.push(X86InitialBootRegion {
            start: region.start,
            len: region.end - region.start,
            initialized_offset: region.initialized_offset,
            source_gpa,
            initialized_len: region.file_bytes.len() as u64,
            permissions: u64::from(region.perms.read)
                | (u64::from(region.perms.write) << 1)
                | (u64::from(region.perms.execute) << 2),
        });
    }
    let mut strings = Vec::with_capacity(argv.len() + env.len());
    for value in argv.iter().chain(env) {
        if value.as_bytes().contains(&0) {
            return Err(fail("NUL in initial argv/env"));
        }
        let source_gpa = append_records(&mut staged, value.as_bytes())?;
        strings.push(X86InitialBootString {
            source_gpa,
            len: value.len() as u64,
        });
    }
    let frame_offset = staged
        .len()
        .checked_add(4095)
        .ok_or_else(|| fail("initial frame alignment"))?
        & !4095;
    if frame_offset
        .checked_add(grant_count * 4096)
        .is_none_or(|end| end > extent_len)
    {
        return Err(fail("initial extent too small for frame grants"));
    }
    let occupied_end = frame_offset
        .checked_add(grant_count * 4096)
        .ok_or_else(|| fail("initial occupied physical extent"))?;
    let working = anonymous_owner::prepare_table_suffix(extent_len, occupied_end)
        .ok_or_else(|| fail("initial records/grants overlap Prepare working stock"))?;
    let reserve = anonymous_owner::initial_table_reserve(occupied_end, working)
        .ok_or_else(|| fail("initial table reserve"))?;
    let (mut inventory, grants) = InitialInventory::stage(
        carrier.custody().rollback_fault(),
        Arc::clone(carrier.custody().frame_inventory()),
        (0..grant_count).map(|index| initial_grant_gpa(frame_offset, index)),
        table_grants,
        4096,
        carrick_hal::GuestFrameOwner {
            native_mm: MmGeneration::new(
                NonZeroU64::new(carrier.custody().initial_mm_key())
                    .ok_or_else(|| fail("initial inventory MM"))?,
            ),
            root_generation: ContextGeneration::new(NonZeroU64::MIN),
        },
    )?;
    let outcome = (|| -> Result<(), TrapError> {
        inventory
            .publish()
            .map_err(|error| fail(error.to_string()))?;
        let (handle, _) = carrier
            .custody()
            .initial_extent()
            .ok_or_else(|| fail("initial extent handle"))?;
        carrier
            .custody_mut()
            .memory_mut()
            .bind_frame_identities(handle, inventory.frames())
            .map_err(|error| fail(error.to_string()))?;
        // The guest editor's no-op invalidation is valid only while this
        // unpublished root cannot be in any live vCPU TLB. Both vCPUs are
        // stopped here; reject a reused root before the first descriptor edit.
        for index in 0..carrier.cpu_count() {
            if carrier.cpu_gpr(index, X86Reg::Cr3)?
                == grants
                    .first()
                    .ok_or_else(|| fail("initial root grant absent"))?
                    .gpa
            {
                return Err(fail("initial root already live in a vCPU"));
            }
        }
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|error| fail(format!("initial random: {error}")))?;
        let request = X86InitialBootRequest {
            magic: X86_INITIAL_BOOT_MAGIC,
            version: X86_INITIAL_BOOT_VERSION,
            layout_hash: carrick_el1_abi::EL1_ABI_LAYOUT_HASH,
            region_count: image.regions.len() as u32,
            executable_region_count: image.executable_region_count as u32,
            executable_entry: image.executable_entry,
            interpreter_base: image.interpreter_base,
            image_features: if image.has_vdso {
                carrick_core_abi::X86_INITIAL_HAS_VDSO
            } else {
                0
            },
            entry: image.entry,
            phdr: image.phdr,
            phent: image.phent,
            phnum: image.phnum,
            argc: argv.len() as u16,
            envc: env.len() as u16,
            regions_gpa: INITIAL_EXTENT_GPA + regions_offset as u64,
            strings_gpa: INITIAL_EXTENT_GPA + strings_offset as u64,
            grants_gpa: INITIAL_EXTENT_GPA + grants_offset as u64,
            table_grant_count: table_grants as u32,
            data_grant_count: data_grants as u32,
            publications_gpa: INITIAL_EXTENT_GPA + publications_offset as u64,
            publication_capacity: data_grants as u32,
            publication_count: 0,
            stack_top: INITIAL_STACK_TOP,
            stack_size: INITIAL_STACK_SIZE,
            random,
            result_root_gpa: 0,
            result_rsp: 0,
            result_status: carrick_core_abi::X86_INITIAL_BOOT_PENDING,
            extent_pages: (extent_len / 4096) as u32,
            mm_key: carrier.custody().initial_mm_key(),
            generation: 1,
            result_table_used: 0,
            result_data_used: 0,
            result_initial_break: 0,
        };
        staged[..size_of::<X86InitialBootRequest>()].copy_from_slice(record_bytes(&request));
        staged[regions_offset..strings_offset].copy_from_slice(unsafe {
            core::slice::from_raw_parts(
                regions.as_ptr().cast::<u8>(),
                regions.len() * size_of::<X86InitialBootRegion>(),
            )
        });
        staged[strings_offset..grants_offset].copy_from_slice(unsafe {
            core::slice::from_raw_parts(
                strings.as_ptr().cast::<u8>(),
                strings.len() * size_of::<X86InitialBootString>(),
            )
        });
        staged[grants_offset..publications_offset].copy_from_slice(unsafe {
            core::slice::from_raw_parts(
                grants.as_ptr().cast::<u8>(),
                grants.len() * size_of::<X86InitialBootGrant>(),
            )
        });
        carrier
            .custody_mut()
            .memory_mut()
            .write(FrameGpa::new(INITIAL_EXTENT_GPA), &staged)
            .map_err(|error| fail(error.to_string()))?;
        let header = carrier
            .custody()
            .ram()
            .host_ptr(
                X86_INITIAL_BOOT_HEADER_GPA,
                size_of::<X86InitialBootHeader>(),
            )
            .ok_or_else(|| fail("production image boot header absent"))?;
        // SAFETY: the fixed image header is retained but may not be aligned
        // by the byte-oriented RAM window abstraction.
        let header = unsafe { header.cast::<X86InitialBootHeader>().read_unaligned() };
        if header.magic != X86_INITIAL_BOOT_MAGIC
            || header.version != X86_INITIAL_BOOT_VERSION
            || !(IMAGE_VA..IMAGE_VA + IMAGE_SIZE).contains(&header.entry_va)
            || !(IMAGE_VA..IMAGE_VA + IMAGE_SIZE).contains(&header.peer_entry_va)
        {
            return Err(fail("production image boot header invalid"));
        }
        validate_layout_hash(header.layout_hash)?;
        carrier
            .custody_mut()
            .set_peer_entry(carrick_guest_arch::KernelVa::new(header.peer_entry_va));
        // SAFETY: prepare_boot initialized the retained slot-0 binding.
        let kernel_stack =
            unsafe { carrier.custody().metadata::<CpuBinding>(BINDING_OFFSET) }.kernel_stack;
        carrier.enter_kernel(
            0,
            KernelEntry {
                rip: header.entry_va,
                rdi: X86_CPL0_INITIAL_EXTENT_VA,
                rsp: kernel_stack,
                gs_base: METADATA_VA + BINDING_OFFSET,
            },
        )?;
        let exit = carrier.run_cpu(0)?;
        if matches!(exit, VcpuExit::Kicked) {
            return Err(fail("production initial MM cancelled"));
        }
        if !matches!(
            exit,
            VcpuExit::IoOut {
                port: X86_INITIAL_BOOT_PORT,
                ..
            }
        ) {
            let mut detail = "unexpected production initial MM exit".to_owned();
            carrier.append_debug_state(0, &mut detail);
            return Err(fail(detail));
        }
        if carrier.cpu_gpr(0, X86Reg::Rax)? != X86_CPL0_INITIAL_EXTENT_VA {
            return Err(fail("production initial MM request pointer"));
        }
        let reply = carrier
            .custody()
            .memory()
            .read(
                FrameGpa::new(INITIAL_EXTENT_GPA),
                size_of::<X86InitialBootRequest>(),
            )
            .map_err(|error| fail(error.to_string()))?;
        // SAFETY: this fixed-size copy is exactly one initialized ABI record.
        let reply = unsafe {
            reply
                .as_ptr()
                .cast::<X86InitialBootRequest>()
                .read_unaligned()
        };
        if reply.result_status != X86_INITIAL_BOOT_LOADED {
            return Err(fail(format!(
                "production initial MM refused: status {}",
                reply.result_status
            )));
        }
        validate_initial_reply(
            &request,
            &reply,
            grants.len(),
            grants
                .first()
                .ok_or_else(|| fail("initial root grant absent"))?
                .gpa,
            image
                .regions
                .iter()
                .take(image.executable_region_count)
                .map(|region| region.end)
                .max()
                .unwrap_or(0),
        )?;
        let mm = NonZeroU64::new(reply.mm_key).ok_or_else(|| fail("initial MM key"))?;
        let generation =
            NonZeroU64::new(reply.generation).ok_or_else(|| fail("initial MM generation"))?;
        let root = RootGpa::page_aligned(FrameGpa::new(reply.result_root_gpa))
            .ok_or_else(|| fail("initial root alignment"))?;
        let context = AddressContext {
            root,
            mm: MmGeneration::new(mm),
            generation: ContextGeneration::new(generation),
        };
        let publication_bytes = carrier
            .custody()
            .memory()
            .read(
                FrameGpa::new(reply.publications_gpa),
                reply.publication_count as usize * size_of::<GuestMmuPublication>(),
            )
            .map_err(|error| fail(error.to_string()))?;
        let mut publications = Vec::with_capacity(reply.publication_count as usize);
        for chunk in publication_bytes.chunks_exact(size_of::<GuestMmuPublication>()) {
            // SAFETY: one complete fixed-layout guest ABI publication was
            // copied from retained memory while this vCPU is stopped.
            publications.push(unsafe {
                chunk
                    .as_ptr()
                    .cast::<GuestMmuPublication>()
                    .read_unaligned()
            });
        }
        let linked_tables = publications.iter().try_fold(1usize, |count, publication| {
            if publication.revision != GuestMmuPublication::REVISION
                || publication.outcome != GuestMmuPublication::APPLIED
                || publication.mm_key != mm.get()
                || publication.root_gpa != root.address().raw()
                || publication.generation != generation.get()
                || publication.span_len != 4096
            {
                return None;
            }
            count.checked_add(publication.tables_linked as usize)
        });
        let linked_tables =
            linked_tables.ok_or_else(|| fail("initial publication table receipt count"))?;
        let copy_tables = carrick_mmu_core::x86::copy_window::cow_copy_table_frames(
            &carrier.custody().memory().words(),
            root,
        )
        .map_err(|_| fail("initial private copy branch"))?;
        let total_tables = linked_tables
            .checked_add(copy_tables.len())
            .ok_or_else(|| fail("initial publication table receipt overflow"))?;
        if total_tables != reply.result_table_used as usize {
            return Err(fail("initial publication table receipt count"));
        }
        let copy_grants = grants
            .get(linked_tables..total_tables)
            .ok_or_else(|| fail("initial copy table grant range"))?;
        if !copy_tables
            .iter()
            .zip(copy_grants)
            .all(|(table, grant)| table.address().raw() == grant.gpa)
        {
            return Err(fail("initial copy table grant identity"));
        }
        carrier
            .custody_mut()
            .memory_mut()
            .install_root(mm, context)
            .map_err(|error| fail(error.to_string()))?;
        // Descriptor transaction identity names only user mapping tables;
        // the separately authenticated private branch is not a user edit.
        let tables: Vec<RootGpa> = grants
            .get(1..linked_tables)
            .ok_or_else(|| fail("initial table grant range"))?
            .iter()
            .map(|grant| {
                RootGpa::page_aligned(FrameGpa::new(grant.gpa))
                    .ok_or_else(|| fail("initial table grant"))
            })
            .collect::<Result<_, _>>()?;
        inventory.expect_publications(publications.len());
        let mut used_tables = 0usize;
        for (index, publication) in publications.into_iter().enumerate() {
            let perms = if let Some(region) = image.regions.iter().find(|region| {
                region.start <= publication.span_va && publication.span_va < region.end
            }) {
                Permissions {
                    writable: region.perms.write,
                    executable: region.perms.execute,
                    user: true,
                }
            } else if publication.span_va
                >= reply
                    .stack_top
                    .checked_sub(reply.stack_size)
                    .ok_or_else(|| fail("initial stack bound"))?
                && publication.span_va < reply.stack_top
            {
                Permissions {
                    writable: true,
                    executable: false,
                    user: true,
                }
            } else {
                return Err(fail("initial publication outside ELF and stack"));
            };
            let grant_index = table_grants
                .checked_add(index)
                .ok_or_else(|| fail("initial data grant index overflow"))?;
            let grant = *grants
                .get(grant_index)
                .ok_or_else(|| fail("initial data grant absent"))?;
            let output = FrameGpa::new(grant.gpa);
            let identity = BackingIdentity {
                frame_id: NonZeroU64::new(grant.frame_id)
                    .ok_or_else(|| fail("initial frame identity"))?,
                mapping_id: NonZeroU64::new(grant.mapping_id)
                    .ok_or_else(|| fail("initial mapping identity"))?,
                owner_generation: NonZeroU64::new(grant.owner_generation)
                    .ok_or_else(|| fail("initial owner generation"))?,
                inventory_revision: NonZeroU64::new(grant.inventory_revision)
                    .ok_or_else(|| fail("initial inventory revision"))?,
            };
            let txn = DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: mm,
                    generation,
                },
                root,
                // The unpublished builder owns private frames for both
                // PT_LOAD segments and the initial anonymous stack. Keep
                // the exact publication operation aligned with that owner.
                op: DescriptorOp::Prepare {
                    span: PageSpan::new(publication.span_va, 4096),
                    output,
                    permissions: perms,
                    resident: PageSpan::new(publication.span_va, 4096),
                    backing: identity,
                },
                // The guest grants only the tables linked by this page,
                // not the unused stock for the rest of the image.
                tables: tables
                    .get(
                        used_tables
                            ..used_tables
                                .checked_add(publication.tables_linked as usize)
                                .ok_or_else(|| fail("initial table receipt overflow"))?,
                    )
                    .ok_or_else(|| fail("initial table receipt count"))?,
            };
            carrier
                .custody_mut()
                .memory_mut()
                .publish(
                    &txn,
                    publication,
                    crate::carrier_memory::SettlementCustody::EditorHeld,
                    &mut inventory,
                )
                .map_err(|error| fail(error.to_string()))?;
            used_tables = used_tables
                .checked_add(publication.tables_linked as usize)
                .ok_or_else(|| fail("initial table receipt overflow"))?;
        }
        publish_production_reservations(
            carrier.custody_mut(),
            mm,
            root,
            reply.result_initial_break,
            reply.stack_top,
            image,
            limits,
        )?;
        inventory.finish()?;
        carrier.custody_mut().bind_grant_portal()?;
        let unused = grants
            .get(reply.result_table_used as usize..table_grants)
            .ok_or_else(|| fail("initial unused table grants"))?
            .iter()
            .map(|grant| {
                RootGpa::page_aligned(FrameGpa::new(grant.gpa))
                    .ok_or_else(|| fail("initial unused table alignment"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        carrier
            .custody_mut()
            .install_fork_stock(context, unused, reserve)?;
        match carrier.run_cpu(0)? {
            VcpuExit::IoOut {
                port: X86_INITIAL_RUNNER_READY_PORT,
                ..
            } if carrier.cpu_gpr(0, X86Reg::Rax)? == X86_CPL0_INITIAL_EXTENT_VA => {}
            VcpuExit::Kicked => return Err(fail("initial runner cancelled")),
            _ => return Err(fail("initial runner did not install its MM")),
        }
        if carrier.cpu_gpr(0, X86Reg::Cr3)? != root.address().raw() {
            return Err(fail("initial runner installed a different MM"));
        }
        Ok(())
    })();
    let outcome = match outcome {
        Err(error) if !inventory.guest_exposed() => match inventory.rollback() {
            Ok(()) => Err(error),
            Err(rollback) => Err(fail(format!(
                "initial boot rollback: {rollback}; original: {error}"
            ))),
        },
        result => result,
    };
    // Retain failed physical custody until the carrier retires; rollback
    // refusal never consumes its receipt or publishes a ready guest.
    carrier.custody_mut().retain_initial_inventory(inventory);
    outcome
}

fn publish_production_reservations<M: CarrierMemoryIo>(
    custody: &mut BootstrapCustody<M>,
    mm_key: NonZeroU64,
    root: RootGpa,
    initial_break: u64,
    stack_top: u64,
    image: &carrick_mem::x86_initial_image::X86InitialImage<'_>,
    limits: InitialReservationLimits,
) -> Result<(), TrapError> {
    let layout =
        initial_reservation_layout(UserVa::new(initial_break), UserVa::new(stack_top), limits)?;
    let table = custody
        .ram()
        .host_ptr(
            META_GPA + carrick_core_abi::X86_CPL0_RESERVATIONS_OFFSET,
            size_of::<X86Cpl0Reservations>(),
        )
        .ok_or_else(|| fail("production reservation backing"))?
        .cast::<X86Cpl0Reservations>();
    let zone = custody
        .ram()
        .host_ptr(
            META_GPA + carrick_core_abi::X86_CPL0_ZONE_OFFSET,
            size_of::<X86Cpl0Zone>(),
        )
        .ok_or_else(|| fail("production zone backing"))?
        .cast::<X86Cpl0Zone>();
    // SAFETY: both pointers belong to one retained, zeroed and aligned
    // carrier metadata window. The stopped vCPU cannot race publication.
    let (table, zone) = unsafe { (&*table, &*zone) };
    let mm = ReservationMm::new(mm_key.get()).ok_or_else(|| fail("reservation MM key"))?;
    let index = zone
        .spaces
        .publish_closed(mm.raw(), root.address().raw(), 0)
        .ok_or_else(|| fail("production space publication"))?;
    table
        .publish(index.index(), mm, layout)
        .map_err(|error| fail(format!("production reservation publication: {error:?}")))?;
    let wake_error = std::cell::RefCell::new(None);
    let deliver = |zone: &X86Cpl0Zone,
                   waker: Waker,
                   owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
        '_,
        carrick_sched_core::ParkedContextWords,
    >| {
        if let Err(error) = unexpected_boot_wake(zone, waker, owned) {
            *wake_error.borrow_mut() = Some(error);
        }
    };
    let release = SpaceReleaseVenue {
        zone,
        waker: Waker::Host,
        deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(&deliver),
    };
    X86Cpl0RootReleaseVenue::new(table, release)
        .map_err(|error| fail(format!("production root authority: {error:?}")))?
        .lock(index.index(), mm, &NoRootWait)
        .and_then(|mut model| {
            import_x86_image_rows(&mut model, image, stack_top)?;
            model.finish_import()?;
            model.insert_opaque(
                ReservationRange::new(stack_top - INITIAL_STACK_SIZE, stack_top)
                    .ok_or(carrick_el1::memory::reservations::Refusal::Invalid)?,
                carrick_el1_abi::ReservationProtection::READ_WRITE,
                carrick_el1_abi::ReservationNodeFlags::PRIVATE
                    .union(carrick_el1_abi::ReservationNodeFlags::GROWSDOWN),
            )
        })
        .map_err(|error| fail(format!("production root admission: {error:?}")))?;
    SpaceAccess::notified(release).open(index);
    if let Some(error) = wake_error.into_inner() {
        return Err(error);
    }
    let slot = SlotId::new(0);
    zone.drive_and_publish(
        slot,
        1,
        mm.raw(),
        Some(0),
        carrick_sched_core::AffinitySource::UNBOUND,
    );
    zone.enter_guest(slot);
    zone.install_space(slot, mm.raw())
        .ok_or_else(|| fail("production installed MM"))?;
    let task = custody.initial_task();
    let tid = task.map_or(41, |root| root.thread.tid);
    let serial = task.map_or(101, |root| root.thread.serial);
    let generation = task.map_or(11, |root| root.thread.generation);
    let file_table = task.map_or(5, |root| root.thread.file_table);
    let affinity = task.map_or(3, |root| {
        if root.thread.affinity == 0 {
            3
        } else {
            root.thread.affinity
        }
    });
    let birth_serial = task
        .map(|root| root.task.serial)
        .or_else(|| carrick_sched_core::process::TaskSerial::from_raw_u64(11))
        .ok_or_else(|| fail("production root birth serial"))?;
    custody.bind_execution(
        0,
        birth_serial,
        carrick_el1_abi::ExecutionBinding {
            task: carrick_el1_abi::EntryTaskKey::from_raw(tid),
            generation: carrick_el1_abi::SnapshotGeneration::from_raw(generation),
            mm: carrick_el1_abi::EntryMmKey::from_raw(mm.raw()),
            thread_generation: carrick_el1_abi::EntryThreadGeneration::from_raw(serial),
        },
        file_table,
    )?;
    custody.stopped_task(0).publish_visible_pid(tid as u32);
    zone.current_or_new(
        slot,
        carrick_sched_core::ThreadIdentity {
            tid,
            serial,
            mm: mm.raw(),
            file_table,
            generation,
            affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
            affinity,
            lifecycle_page: METADATA_VA,
            control_slot: METADATA_VA + CONTROL_OFFSET,
        },
    )
    .map_err(|_| fail("production scheduler record exhausted"))?;
    Ok(())
}

pub fn unexpected_boot_wake(
    _: &X86Cpl0Zone,
    _: Waker,
    owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
        '_,
        carrick_sched_core::ParkedContextWords,
    >,
) -> Result<(), TrapError> {
    let mut handed = false;
    let (_, effects) = owned.deliver_handbacks(&mut |_| handed = true);
    if handed || effects != carrick_sched_core::WakeEffects::default() {
        return Err(fail(
            "boot-only publication unexpectedly released a live guest waiter",
        ));
    }
    Ok(())
}

/// An event a stopped CPU was delivering when it left the guest. The CPU
/// finishes delivering it, into CPL0, before it runs any other instruction.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum PendingEvent {
    /// An external or IPI vector, already accepted by the local APIC.
    Interrupt { vector: u8 },
    /// An architectural exception.
    Exception { vector: u8 },
    /// A non-maskable interrupt.
    Nmi,
}

/// Where a stopped production CPU resumes, as its run admission reads it
/// once before reentry. Each class has exactly one answer to shootdown debt,
/// and every caller matches all of them.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum StoppedCpu {
    /// CS.DPL 0. The ring takes a queued KICK at its next interruptible point.
    Kernel,
    /// CPL3 with IF set, no interrupt shadow and no event in delivery: the
    /// next instruction is a user instruction, and a KICK queued before
    /// reentry is taken ahead of it.
    UserInterruptible,
    /// CPL3 with an event in delivery. The event enters CPL0 before any user
    /// instruction runs, and a KICK queued behind it is taken no later than
    /// the IRET back to user mode.
    UserEventPending { event: PendingEvent, rip: u64 },
    /// CPL3 in an STI or MOV SS interrupt shadow: left alone, the shadowed
    /// user instruction retires before a queued KICK is taken.
    UserShadowed { rip: u64 },
    /// CPL3 with IF clear. Linux user code cannot mask interrupts here, so
    /// this is a broken invariant, not a stop to schedule around.
    UserInterruptsMasked { rip: u64 },
    /// A privilege level the production carrier never runs (CPL 1 or 2, or a
    /// CS whose selector RPL disagrees with its DPL).
    Unsupported { cpl: u8, rip: u64 },
}

impl StoppedCpu {
    /// Classify a stopped x86 CPU from its architectural state.
    pub fn classify(
        cs_dpl: u8,
        cs_selector: u16,
        rip: u64,
        rflags: u64,
        shadow: bool,
        event: Option<PendingEvent>,
    ) -> Self {
        const IF: u64 = 1 << 9;
        match (cs_dpl, cs_selector & 3) {
            (0, _) => Self::Kernel,
            (3, 3) => match event {
                Some(event) => Self::UserEventPending { event, rip },
                None if rflags & IF == 0 => Self::UserInterruptsMasked { rip },
                None if shadow => Self::UserShadowed { rip },
                None => Self::UserInterruptible,
            },
            (cpl, _) => Self::Unsupported { cpl, rip },
        }
    }
}

/// The backend operations one production CPU's run admission needs: the
/// stopped CPU's class, a KICK queued to the CPU's own APIC before reentry,
/// and one guest run.
pub trait ProductionMemberCpu {
    /// Where the stopped CPU resumes.
    fn stopped(&self) -> Result<StoppedCpu, TrapError>;
    /// End a stopped CPL3 CPU's interrupt shadow, so a queued KICK is taken
    /// before the shadowed instruction. At CPL3 in long mode an interrupt
    /// switches to the CPL0 stack and IRET restores SS:RSP exactly, so the
    /// interrupt blocking is invisible to the user program. MOV SS also
    /// defers a single-step trap and suppresses an instruction breakpoint on
    /// the shadowed instruction; with TF or DR7 armed, ending the shadow can
    /// move that one debug event by an instruction (#3076 follow-up). Running
    /// the shadowed instruction first would instead use a translation its
    /// editor has already retired.
    fn end_user_interrupt_shadow(&mut self) -> Result<(), TrapError>;
    /// Queue `KICK_VECTOR` to this CPU's own local APIC, durable across the
    /// reentry that follows.
    fn queue_reentry_kick(&mut self) -> Result<(), TrapError>;
    fn run_guest(&mut self) -> Result<VcpuExit, TrapError>;
}

/// Run one production CPU under the shared file-execution admission and the
/// shootdown table's running/ack protocol. A CPU entering with shootdown
/// debt is kicked so the ring settles that debt before user code resumes.
///
/// Debt at a stop is "not now", never a refusal: an editor's rendezvous does
/// not wait for a stopped CPU, so the editor may already have returned and
/// its old frames may be reused. Every stop class therefore reenters with the
/// KICK ordered ahead of the next user instruction, and only a stop no
/// production CPU can reach is fatal.
pub fn run_production_member<C: ProductionMemberCpu>(
    cpu: &mut C,
    table: &ShootdownTable,
    slot: usize,
    actual_run: Option<&AtomicU32>,
    execution: &RwLock<()>,
) -> Result<VcpuExit, TrapError> {
    let _running = execution.try_read().map_err(|error| match error {
        std::sync::TryLockError::WouldBlock => TrapError::ExecutionAdmissionBusy,
        std::sync::TryLockError::Poisoned(_) => TrapError::ExecutionAdmissionPoisoned,
    })?;
    let member = table
        .members
        .get(slot)
        .ok_or_else(|| fail("unknown CPL0 CPU slot"))?;
    struct RunningAdmission<'a>(&'a AtomicU32);
    impl Drop for RunningAdmission<'_> {
        fn drop(&mut self) {
            self.0.store(0, Ordering::Release);
        }
    }
    // A sender that observes this release either targets the live vCPU or
    // races this pre-run scan, which queues its durable MSI before KVM_RUN.
    member.running.store(1, Ordering::Release);
    let running_admission = RunningAdmission(&member.running);
    let stop = cpu.stopped()?;
    let has_debt = table.requests.iter().any(|request| {
        request.generation.load(Ordering::Acquire) > request.served[slot].load(Ordering::Acquire)
    });
    if has_debt {
        match stop {
            // The ring takes the KICK at its next interruptible point, and
            // settles debt itself before it touches user memory.
            StoppedCpu::Kernel => {}
            // The KICK is taken ahead of the next user instruction.
            StoppedCpu::UserInterruptible => {}
            // The event enters CPL0 first. An APIC vector in delivery is in
            // service at priority class 0xe or above, so the KICK waits in the
            // local APIC until the handler's EOI. Every event's return to user
            // mode then reaches IF set, with the KICK pending, before any
            // user instruction; the ring's user-return generation check also
            // settles the debt on that path.
            StoppedCpu::UserEventPending { .. } => {}
            // The shadowed user instruction would otherwise run on the stale
            // translation; end the shadow so the KICK comes first.
            StoppedCpu::UserShadowed { .. } => cpu.end_user_interrupt_shadow()?,
            StoppedCpu::UserInterruptsMasked { .. } | StoppedCpu::Unsupported { .. } => {
                return Err(fail(format!(
                    "shootdown debt at a stop no production CPU reaches: {stop:?}"
                )));
            }
        }
        cpu.queue_reentry_kick()?;
    }
    let actual_guard = actual_run.map(|flag| {
        flag.store(1, Ordering::Release);
        RunningAdmission(flag)
    });
    let result = cpu.run_guest()?;
    drop(actual_guard);
    drop(running_admission);
    if cpu.stopped()? == StoppedCpu::UserInterruptible {
        // The host may release a sender after this vCPU has stopped, but
        // leaves `served` behind until native KICK settles debt on reentry.
        for request in &table.requests {
            let generation = request.generation.load(Ordering::Acquire);
            if generation != 0 {
                request.ack[slot].store(generation, Ordering::Release);
            }
        }
    }
    Ok(result)
}

impl<M: CarrierMemoryIo> BootstrapCustody<M> {
    /// Replace the bootstrap's provisional identity with the exact root
    /// issued by the shared kernel, before the initial MM is admitted.
    pub fn bind_initial_task_identity(
        &mut self,
        identity: InitialTaskBinding,
    ) -> Result<(), TrapError> {
        if self.initial_task().is_some()
            || self.has_initial_inventory()
            || self
                .actual_run()
                .iter()
                .any(|flag| flag.load(Ordering::Acquire) != 0)
            || identity.thread.tid != identity.task.id.raw() as u64
            || identity.thread.serial == 0
            || identity.thread.file_table == 0
            || identity.thread.generation == 0
            || identity.thread.mm != 0
            || identity.thread.lifecycle_page != 0
            || identity.thread.control_slot != 0
        {
            return Err(fail("initial task binding requires stopped root admission"));
        }
        let tid = u32::try_from(identity.thread.tid)
            .map_err(|_| fail("initial task TID outside guest ABI"))?;
        let birth = carrick_core::terminal::ThreadBirthIdentity::from_parts(
            carrick_core_abi::EntryTaskKey::from_raw(identity.thread.tid),
            carrick_core_abi::BirthSerial::of_task(identity.task.serial),
            carrick_core_abi::EntryThreadGeneration::from_raw(identity.thread.serial),
        )
        .ok_or_else(|| fail("initial root birth identity"))?;
        let control = self.stopped_slot(0);
        control
            .reset_for_host_birth(BlockedMask(0))
            .map_err(|_| fail("control slot still owned by graph"))?;
        if !control.publish_visible_tid(tid) {
            return Err(fail("initial root control slot identity"));
        }
        control.publish_host_birth_identity(birth);
        let provisional = self
            .stopped_task(0)
            .linux
            .file_table
            .load(Ordering::Acquire);
        self.0
            .with_stdio(|stdio, tables| {
                stdio.rename_unstarted(
                    tables.fd_map(),
                    tables.opens(),
                    tables.objects(),
                    provisional,
                    identity.thread.file_table,
                )
            })?
            .map_err(|error| fail(format!("initial root stdio table: {error:?}")))?;
        let task = self.stopped_task(0);
        task.set(
            El1TaskId::from_linux_tid(identity.task.id.raw()),
            carrick_el1_abi::SnapshotGeneration::from_raw(identity.thread.generation),
            identity.thread.file_table,
        );
        task.mm
            .thread_generation
            .store(identity.thread.serial, Ordering::Release);
        task.publish_visible_pid(tid);
        self.set_initial_task(identity);
        Ok(())
    }
    pub fn initial_mm_key(&self) -> u64 {
        self.initial_task()
            .map_or(INITIAL_MM_KEY, |identity| identity.mm.raw().get())
    }
    /// The issued root task's state for the executor hand-off: its binding
    /// (carrier, task serial, execution generation, initial MM context) over
    /// `image`, the stopped root CPU, with the resume payload marked.
    pub fn worker_root_state(
        &self,
        image: &carrick_x86::X86VcpuSnapshot,
    ) -> Result<carrick_x86::arch_context::X86ArchContext, TrapError> {
        let root = self
            .initial_task()
            .ok_or_else(|| fail("worker handoff has no issued root task"))?;
        let mm = NonZeroU64::new(self.initial_mm_key()).ok_or_else(|| fail("initial MM key"))?;
        let context = self
            .memory()
            .root(mm)
            .ok_or_else(|| fail("worker handoff has no initial MM"))?;
        let binding = carrick_hal::guest_arch_binding::GuestArchBinding::x86(
            carrick_guest_arch::TaskIdentity {
                carrier: carrick_guest_arch::CarrierGeneration::new(
                    self.memory().identity().nonzero(),
                ),
                task: carrick_guest_arch::TaskSerial::new(
                    NonZeroU64::new(root.task.serial.raw())
                        .ok_or_else(|| fail("worker root task serial"))?,
                ),
                execution: carrick_guest_arch::ExecutionGeneration::new(
                    NonZeroU64::new(root.thread.generation)
                        .ok_or_else(|| fail("worker root execution generation"))?,
                ),
            },
            context,
        );
        let mut resume = [0; carrick_hal::threaded::X86_TASK_RESUME_PAYLOAD_LEN];
        resume[56..64].copy_from_slice(&carrick_hal::threaded::X86_TASK_RESUME_MAGIC.to_le_bytes());
        carrick_x86::arch_context::X86ArchContext::capture(binding, image, resume)
    }
    fn stopped_task(&self, index: usize) -> &CurrentTask {
        // SAFETY: the stopped bootstrap owns initialized metadata at these offsets.
        unsafe { self.metadata(TASK_OFFSET + index as u64 * STRIDE) }
    }
    fn stopped_slot(&self, index: usize) -> &ThreadControlSlot {
        // SAFETY: the stopped bootstrap owns initialized metadata at these offsets.
        unsafe { self.metadata(CONTROL_OFFSET + index as u64 * STRIDE) }
    }
    /// Qualify separate exact task/MM owners, even with reused visible IDs.
    /// All vCPUs are stopped under this exclusively borrowed fixture carrier.
    pub fn bind_execution(
        &mut self,
        index: usize,
        birth_serial: carrick_sched_core::process::TaskSerial,
        binding: carrick_el1_abi::ExecutionBinding,
        file_table: u64,
    ) -> Result<(), TrapError> {
        if index >= 2
            || !binding.issued()
            || binding.mm.raw() == 0
            || binding.thread_generation.raw() == 0
            || file_table == 0
        {
            return Err(fail("invalid CPL0 fixture execution binding"));
        }
        if index == 0
            && let Some(root) = self.initial_task()
            && (birth_serial != root.task.serial
                || root.thread.tid != binding.task.raw()
                || root.thread.serial != binding.thread_generation.raw())
        {
            return Err(fail(
                "initial root execution binding mismatches retained birth",
            ));
        }
        let tid = i32::try_from(binding.task.raw()).map_err(|_| fail("fixture task range"))?;
        let birth = carrick_core::terminal::ThreadBirthIdentity::from_parts(
            binding.task,
            carrick_core_abi::BirthSerial::of_task(birth_serial),
            binding.thread_generation,
        )
        .ok_or_else(|| fail("fixture birth identity"))?;
        let page_offset = index as u64 * 0x4000;
        let slot_offset = CONTROL_OFFSET + index as u64 * STRIDE;
        // SAFETY: exclusively stopped fixture vCPUs, initialized retained and
        // aligned metadata. Neither page/control reference escapes the owner;
        // each task's fresh page and control slot occupy disjoint metadata.
        unsafe {
            *self.metadata_mut(page_offset) = ThreadLifecyclePage::new();
            *self.metadata_mut(slot_offset) = ThreadControlSlot::new();
        }
        if !self.stopped_slot(index).publish_visible_tid(tid as u32) {
            return Err(fail("fixture visible task publication"));
        }
        self.stopped_slot(index).publish_host_birth_identity(birth);
        self.0
            .with_stdio(|stdio, tables| {
                stdio.bind_table(
                    tables.fd_map(),
                    tables.opens(),
                    tables.objects(),
                    file_table,
                )
            })?
            .map_err(|error| fail(format!("initial task stdio table: {error:?}")))?;
        let task = self.stopped_task(index);
        task.set(
            El1TaskId::from_linux_tid(tid),
            binding.generation,
            file_table,
        );
        task.mm.key.store(binding.mm.raw(), Ordering::Release);
        task.mm
            .thread_generation
            .store(binding.thread_generation.raw(), Ordering::Release);
        task.publish_lifecycle(METADATA_VA + page_offset, METADATA_VA + slot_offset);
        Ok(())
    }
}
