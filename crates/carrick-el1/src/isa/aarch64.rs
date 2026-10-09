//! AArch64 EL1 implementation of the existing guest-architecture projections.
//! Unbound owner operations return an explicit refusal until their native
//! custody can be passed without changing the existing EL1 call path.

use super::ArchError;
use crate::substrate::sched::{ThreadCpu, UserWord, hw};
use carrick_el1_abi::{CurrentTask, ThreadCtx, TrapFrame};
use carrick_guest_arch::{
    Access, AddressContext, ArchTypes, CopyProgress, CounterFrequency, CounterTick, CpuId,
    CpuTarget, CrossingBackend, Deadline, EntryBackend, EntryEvent, FatalReport, FrameGpa,
    GuestIsa, GuestLen, InterruptAck, InterruptBackend, InterruptReason, KernelStackPointer,
    MmuBackend, NativeAbi, NativeEntrySnapshot, NativeReturnWord, RootGpa, UserRange, UserReturn,
    UserVa, WakeToken,
};
use core::num::NonZeroU64;

pub struct Aarch64Backend;

pub type Kernel = carrick_guest_arch::Arch<Aarch64Backend>;

/// Construct the sealed kernel-facing adapter for EL1.
pub const fn kernel_arch() -> impl carrick_guest_arch::KernelArch {
    carrick_guest_arch::Arch::new(Aarch64Backend)
}

pub(crate) fn hardware_live_ttbr() -> u64 {
    let ttbr: u64;
    // SAFETY: EL1 reads the live TTBR0 register without changing execution.
    unsafe {
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr, options(nomem, nostack));
    }
    ttbr
}

pub(crate) fn yield_host_effect() {
    // SAFETY: the carrier resumes this exact EL1 stack after the HVC service.
    unsafe {
        core::arch::asm!("hvc #1", clobber_abi("C"));
    }
}

pub(crate) fn cross_hvc_fork_stock(record_gpa: u64, cpu: u64) -> Result<(), ()> {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let mut status: u64 = carrick_el1_abi::GRANT_OP_FORK_STOCK;
        unsafe {
            core::arch::asm!(
                "hvc #6",
                inout("x0") status,
                in("x1") record_gpa,
                in("x2") cpu,
                in("x3") 0u64,
                options(nostack)
            );
        }
        if status != 0 {
            return Err(());
        }
        Ok(())
    }
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    {
        let _ = (record_gpa, cpu);
        Ok(())
    }
}

pub(crate) fn cross_hvc_root_exit(record_gpa: u64, cpu: u64) -> Result<(), ()> {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let mut status: u64 = carrick_el1_abi::GRANT_OP_ROOT_EXIT;
        unsafe {
            core::arch::asm!(
                "hvc #6",
                inout("x0") status,
                in("x1") record_gpa,
                in("x2") cpu,
                in("x3") 0u64,
                options(nostack)
            );
        }
        if status != 0 {
            return Err(());
        }
        Ok(())
    }
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    {
        let _ = (record_gpa, cpu);
        Ok(())
    }
}

impl ArchTypes for Aarch64Backend {
    type Error = ArchError;
    type NativeFrame = TrapFrame;
    type SavedContext = ThreadCtx;
    type Context = ThreadCtx;
    type Root = RootGpa;
    type MmOwner = CurrentTask;
    type DrainTicket = ();
    type DrainReceipt = ();
    type UserTransfer = ();
    type HardwareInterrupt = u32;
    type InterruptMask = hw::IrqGuard;
}

impl EntryBackend for Aarch64Backend {
    fn current_stack_pointer(&mut self) -> Result<KernelStackPointer, Self::Error> {
        Ok(KernelStackPointer::new(hw::read_current_sp()))
    }
    fn decode_entry(&mut self, _frame: &TrapFrame) -> Result<EntryEvent, Self::Error> {
        Err(ArchError::Unbound)
    }
    fn snapshot<'a>(
        &mut self,
        frame: &'a TrapFrame,
    ) -> Result<NativeEntrySnapshot<'a, TrapFrame>, Self::Error> {
        Ok(NativeEntrySnapshot {
            isa: GuestIsa::Aarch64,
            abi: NativeAbi::Aarch64El0,
            frame,
        })
    }
    fn set_result(
        &mut self,
        frame: &mut TrapFrame,
        result: NativeReturnWord,
    ) -> Result<(), Self::Error> {
        frame.x[0] = result.0;
        Ok(())
    }
    fn save_context(&mut self, frame: &TrapFrame) -> Result<ThreadCtx, Self::Error> {
        let mut context = ThreadCtx::ZERO;
        hw::HardwareCpu.save(frame, &mut context);
        Ok(context)
    }
    fn load_context(
        &mut self,
        frame: &mut TrapFrame,
        saved: &ThreadCtx,
    ) -> Result<(), Self::Error> {
        hw::HardwareCpu.load(frame, saved);
        Ok(())
    }
    fn prepare_user_return(&mut self, _frame: &TrapFrame) -> Result<UserReturn, Self::Error> {
        Err(ArchError::Unbound)
    }
}

impl MmuBackend for Aarch64Backend {
    fn live_root(&mut self) -> Result<RootGpa, Self::Error> {
        let ttbr = hardware_live_ttbr();
        RootGpa::page_aligned(FrameGpa::new(ttbr & 0x0000_ffff_ffff_f000)).ok_or(ArchError::Unbound)
    }
    fn read_user_word(
        &mut self,
        owner: &CurrentTask,
        address: UserVa,
        width: GuestLen,
    ) -> Result<u64, Self::Error> {
        match width.raw() {
            4 => hw::HardwareUserWord
                .read_u32(owner, address.raw())
                .map(u64::from),
            8 => hw::HardwareUserWord.read_u64(owner, address.raw()),
            _ => return Err(ArchError::InvalidWidth),
        }
        .ok_or(ArchError::Unbound)
    }
    fn validate_user_access(
        &mut self,
        _owner: &CurrentTask,
        range: UserRange,
        access: Access,
    ) -> Result<GuestLen, Self::Error> {
        use crate::substrate::file::MemoryValidator;
        let len = usize::try_from(range.len().raw()).map_err(|_| ArchError::Unbound)?;
        let checked =
            match access {
                Access::Read => crate::substrate::file::HardwareValidator
                    .readable_bytes(range.start().raw(), len),
                Access::Write => crate::substrate::file::HardwareValidator
                    .writable_bytes(range.start().raw(), len),
                Access::Execute => return Err(ArchError::Unbound),
            };
        Ok(GuestLen::new(checked as u64))
    }
    fn install_context(&mut self, _context: AddressContext<RootGpa>) -> Result<(), Self::Error> {
        Err(ArchError::Unbound)
    }
    fn request_invalidation(
        &mut self,
        _context: AddressContext<RootGpa>,
        _range: UserRange,
    ) -> Result<(), Self::Error> {
        Err(ArchError::Unbound)
    }
    fn ack_drain(&mut self, _ticket: ()) -> Result<(), Self::Error> {
        Err(ArchError::Unbound)
    }
    fn copy_user_chunk(
        &mut self,
        _transfer: &mut (),
        _limit: GuestLen,
    ) -> Result<CopyProgress, Self::Error> {
        Err(ArchError::Unbound)
    }
}

impl InterruptBackend for Aarch64Backend {
    fn counter(&mut self) -> Result<CounterTick, Self::Error> {
        Ok(CounterTick::new(hw::HardwareCpu.now()))
    }
    fn frequency(&mut self) -> Result<CounterFrequency, Self::Error> {
        NonZeroU64::new(hw::HardwareCpu.freq())
            .map(CounterFrequency::new)
            .ok_or(ArchError::Unbound)
    }
    fn arm_timer(&mut self, deadline: Option<Deadline>) -> Result<(), Self::Error> {
        hw::HardwareCpu.set_timer(deadline.map(|deadline| deadline.0.raw()));
        Ok(())
    }
    fn send_wake(&mut self, target: CpuTarget, _token: WakeToken) -> Result<(), Self::Error> {
        let slot = carrick_sched_core::SlotId::from_index(target.cpu.raw() as usize)
            .ok_or(ArchError::Unbound)?;
        // SAFETY: the carrier maps and retains the zone table through this
        // EL1 execution epoch; the target slot is bounds-checked above.
        let zone =
            unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_sched_core::ZoneTables) };
        let route = zone.slot(slot).sgi_target();
        if route == 0 {
            return Err(ArchError::Unbound);
        }
        hw::HardwareCpu.send_sgi(route | (u64::from(carrick_el1_abi::GIC_RESCHED_INTID) << 24));
        Ok(())
    }
    fn ack_interrupt(&mut self) -> Result<Option<InterruptAck<u32>>, Self::Error> {
        let id = hw::HardwareCpu.ack_irq();
        if id == carrick_el1_abi::GIC_SPURIOUS_INTID {
            return Ok(None);
        }
        let reason = if id == carrick_el1_abi::GIC_VTIMER_INTID {
            InterruptReason::Timer
        } else {
            InterruptReason::External
        };
        Ok(Some(InterruptAck {
            reason,
            hardware: id,
        }))
    }
    fn end_interrupt(&mut self, ack: InterruptAck<u32>) -> Result<(), Self::Error> {
        hw::HardwareCpu.end_irq(ack.hardware);
        Ok(())
    }
    fn mask_interrupts(&mut self) -> hw::IrqGuard {
        hw::disable_irq_save()
    }
    fn restore_interrupts(&mut self, mask: hw::IrqGuard) -> Result<(), Self::Error> {
        hw::restore_irq(mask);
        Ok(())
    }
    fn park_until_interrupt(&mut self) -> Result<(), Self::Error> {
        hw::HardwareCpu.wait_for_interrupt();
        Ok(())
    }
    fn current_cpu(&mut self) -> CpuId {
        let sp = hw::read_current_sp();
        let Some(offset) = sp.checked_sub(carrick_el1_abi::EL1_STACKS_BASE) else {
            hw::fatal_entry_binding()
        };
        if offset >= carrick_el1_abi::EL1_STACK_SLOTS * carrick_el1_abi::EL1_STACK_SIZE {
            hw::fatal_entry_binding()
        }
        CpuId::new((offset / carrick_el1_abi::EL1_STACK_SIZE) as u32)
    }
}

impl CrossingBackend for Aarch64Backend {
    fn yield_host_effect(&mut self) -> Result<(), Self::Error> {
        yield_host_effect();
        Ok(())
    }
    fn report_fatal(&mut self, _report: FatalReport) -> ! {
        hw::fatal_entry_binding()
    }
}

/// Authenticated terminal crossing; the carrier owns run cleanup and exit 125.
pub fn complete_native_run_failure(
    binding: carrick_el1_abi::ExecutionBinding,
    reason: carrick_el1_abi::NativeRunFailureReason,
) -> ! {
    let record = carrick_el1_abi::NativeRunFailure::new(binding, reason);
    // SAFETY: EL1 retains this initialized supervisor-stack record until the
    // stopped CPU's exact execution is authenticated and the carrier stops.
    unsafe {
        core::arch::asm!("hvc #3",
            in("x0") carrick_el1_abi::NATIVE_RUN_FAILURE_SENTINEL,
            in("x1") &record as *const _ as u64,
            options(nostack));
    }
    hw::fatal_entry_binding()
}


