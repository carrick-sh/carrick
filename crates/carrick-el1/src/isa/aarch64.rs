//! AArch64 EL1 implementation of the existing guest-architecture projections.
//! Unbound owner operations return an explicit refusal until their native
//! custody can be passed without changing the existing EL1 call path.

use super::ArchError;
use crate::substrate::sched::{ThreadCpu, UserWord, hw};
use carrick_el1_abi::{Aarch64ParkedContext, CurrentTask, ThreadCtx, TrapFrame};
use carrick_guest_arch::{
    Access, AddressContext, ArchTypes, CopyProgress, CounterFrequency, CounterTick, CpuId,
    CpuTarget, CrossingBackend, Deadline, EntryBackend, EntryEvent, FatalReport, FrameGpa,
    GuestIsa, GuestLen, InterruptAck, InterruptBackend, InterruptReason, KernelStackPointer,
    MmuBackend, NativeAbi, NativeEntrySnapshot, NativeReturnWord, RootGpa, UserRange, UserReturn,
    UserVa, WakeToken,
};
use core::num::NonZeroU64;

pub struct Aarch64Backend;

/// Check the actual publication frame against this execution lane's stack.
/// Deriving the slot from SP would silently accept an adjacent CPU's stack.
#[inline(always)]
pub fn check_process_stack(slot: carrick_el1_abi::SlotId) {
    let sp: u64;
    // SAFETY: EL1 reads its own current stack pointer.
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack));
    }
    let base =
        carrick_el1_abi::EL1_STACKS_BASE + u64::from(slot.raw()) * carrick_el1_abi::EL1_STACK_SIZE;
    assert!(
        (base..base + carrick_el1_abi::EL1_STACK_SIZE).contains(&sp),
        "native process publication exceeded its CPU stack"
    );
}

pub type Kernel = carrick_guest_arch::Arch<Aarch64Backend>;

/// Construct the sealed kernel-facing adapter for EL1.
pub const fn kernel_arch() -> impl carrick_guest_arch::KernelArch {
    carrick_guest_arch::Arch::new(Aarch64Backend)
}

pub fn hardware_live_ttbr() -> u64 {
    let ttbr: u64;
    // SAFETY: EL1 reads the live TTBR0 register without changing execution.
    unsafe {
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr, options(nomem, nostack));
    }
    ttbr
}

pub fn yield_host_effect() {
    // SAFETY: the carrier resumes this exact EL1 stack after the HVC service.
    unsafe {
        core::arch::asm!("hvc #1", clobber_abi("C"));
    }
}

/// A failure-only diagnostic; its reply never changes the original verdict.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub fn cross_hvc_fork_refusal(record: &carrick_el1_abi::NativeForkDiagnostic) {
    // SAFETY: the synchronous crossing retains this aligned, bounded record.
    unsafe {
        core::arch::asm!("hvc #6",
            inlateout("x0") carrick_el1_abi::GRANT_OP_FORK_REFUSAL => _,
            inlateout("x1") record as *const _ as u64 => _,
            inlateout("x2") 0u64 => _, inlateout("x3") 0u64 => _,
            options(nostack));
    }
}

/// Synchronously discharge a host residency notification without GIC support.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub fn cross_hvc_residency_kick(slot: carrick_sched_core::SlotId) -> Result<(), ArchError> {
    let mut status = carrick_el1_abi::GRANT_OP_RESIDENCY_KICK;
    // SAFETY: the issued slot names retained carrier state; HVC resumes this stack.
    unsafe {
        core::arch::asm!("hvc #6", inout("x0") status,
            inlateout("x1") u64::from(slot.raw()) => _,
            inlateout("x2") 0u64 => _, inlateout("x3") 0u64 => _, options(nostack));
    }
    if status == carrick_el1_abi::METADATA_GRANT_SUCCESS {
        Ok(())
    } else {
        Err(ArchError::Unbound)
    }
}

pub fn cross_hvc_fork_stock(record_gpa: u64, cpu: u64) -> Result<(), u64> {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let mut status: u64 = carrick_el1_abi::GRANT_OP_FORK_STOCK;
        unsafe {
            core::arch::asm!(
                "hvc #6",
                inout("x0") status,
                inlateout("x1") record_gpa => _,
                inlateout("x2") cpu => _,
                inlateout("x3") 0u64 => _,
                options(nostack)
            );
        }
        if status != 0 {
            return Err(status);
        }
        Ok(())
    }
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    {
        let _ = (record_gpa, cpu);
        Ok(())
    }
}

// `Err(())` is the carrier's single refusal; callers own its meaning.
#[allow(clippy::result_unit_err)]
pub fn cross_hvc_root_exit(record_gpa: u64, cpu: u64) -> Result<(), ()> {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let mut status: u64 = carrick_el1_abi::GRANT_OP_ROOT_EXIT;
        unsafe {
            core::arch::asm!(
                "hvc #6",
                inout("x0") status,
                inlateout("x1") record_gpa => _,
                inlateout("x2") cpu => _,
                inlateout("x3") 0u64 => _,
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

// `Err(())` is the carrier's single refusal; callers own its meaning.
#[allow(clippy::result_unit_err)]
pub fn cross_hvc_child_retire(record_gpa: u64, cpu: u64) -> Result<(), ()> {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let mut status: u64 = carrick_el1_abi::GRANT_OP_CHILD_RETIRE;
        unsafe {
            core::arch::asm!(
                "hvc #6",
                inout("x0") status,
                inlateout("x1") record_gpa => _,
                inlateout("x2") cpu => _,
                inlateout("x3") 0u64 => _,
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

// `Err(())` is the carrier's single refusal; callers own its meaning.
#[allow(clippy::result_unit_err)]
pub fn cross_hvc_wait_channel_wake(mm: u64, address: u64, cpu: u64) -> Result<(), ()> {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let mut status = carrick_el1_abi::GRANT_OP_WAIT_CHANNEL_WAKE;
        // SAFETY: synchronous stopped-CPU service retains the owned wait channel.
        unsafe {
            core::arch::asm!("hvc #6", inout("x0") status,
            inlateout("x1") mm => _, inlateout("x2") address => _, inlateout("x3") cpu => _, options(nostack));
        }
        (status == carrick_el1_abi::METADATA_GRANT_SUCCESS)
            .then_some(())
            .ok_or(())
    }
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    {
        let _ = (mm, address, cpu);
        Err(())
    }
}

/// Apply the shared physical retirement owner after leaving the child's root.
#[allow(clippy::result_unit_err)]
pub fn cross_hvc_child_reclaim(mm: u64, cpu: u64) -> Result<(), ()> {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let mut status = carrick_el1_abi::GRANT_OP_CHILD_RECLAIM;
        // SAFETY: synchronous crossing; the terminal slot authenticates the MM.
        unsafe {
            core::arch::asm!("hvc #6", inout("x0") status,
                inlateout("x1") mm => _, inlateout("x2") 0u64 => _,
                inlateout("x3") cpu => _, options(nostack));
        }
        (status == carrick_el1_abi::METADATA_GRANT_SUCCESS)
            .then_some(())
            .ok_or(())
    }
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    {
        let _ = (mm, cpu);
        Err(())
    }
}

/// Consume the prepared native exec selected by the caller-owned adoption
/// record while this CPU and its predecessor execution are synchronously
/// stopped at the owner crossing.
#[allow(clippy::result_unit_err)]
pub fn cross_hvc_exec_adopt(record_gpa: u64, cpu: u64) -> Result<(), ()> {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let mut status = carrick_el1_abi::GRANT_OP_EXEC_ADOPT;
        // SAFETY: the HVC retains this aligned stack record until its typed
        // accepted/refused reply has been published.
        unsafe {
            core::arch::asm!("hvc #6", inout("x0") status,
                inlateout("x1") record_gpa => _, inlateout("x2") cpu => _,
                inlateout("x3") 0u64 => _, options(nostack));
        }
        (status == carrick_el1_abi::METADATA_GRANT_SUCCESS)
            .then_some(())
            .ok_or(())
    }
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    {
        let _ = (record_gpa, cpu);
        Err(())
    }
}

/// Settle the predecessor after the stopped execution has switched to its
/// successor MM. The carrier authenticates both identities against its
/// retained one-shot predecessor receipt.
#[allow(clippy::result_unit_err)]
pub fn cross_hvc_exec_settle(predecessor: u64, successor: u64, cpu: u64) -> Result<(), ()> {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let mut status = carrick_el1_abi::GRANT_OP_EXEC_SETTLE;
        // SAFETY: synchronous crossing; the stopped successor execution and
        // retained predecessor receipt authenticate both MM words.
        unsafe {
            core::arch::asm!("hvc #6", inout("x0") status,
                inlateout("x1") predecessor => _, inlateout("x2") successor => _,
                inlateout("x3") cpu => _, options(nostack));
        }
        (status == carrick_el1_abi::METADATA_GRANT_SUCCESS)
            .then_some(())
            .ok_or(())
    }
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    {
        let _ = (predecessor, successor, cpu);
        Err(())
    }
}

/// Return an unadopted successor preparation to the carrier. The stopped
/// predecessor execution plus the one-shot receipt authenticate the owner.
#[allow(clippy::result_unit_err)]
pub fn cross_hvc_exec_cancel(record_gpa: u64, cpu: u64) -> Result<(), ()> {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let mut status = carrick_el1_abi::GRANT_OP_EXEC_CANCEL;
        // SAFETY: synchronous crossing; the record remains on this stopped
        // CPU's EL1 stack until the carrier replies.
        unsafe {
            core::arch::asm!("hvc #6", inout("x0") status,
                inlateout("x1") record_gpa => _, inlateout("x2") cpu => _,
                options(nostack));
        }
        (status == carrick_el1_abi::METADATA_GRANT_SUCCESS)
            .then_some(())
            .ok_or(())
    }
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    {
        let _ = (record_gpa, cpu);
        Err(())
    }
}

/// Ask the stopped carrier to supply the COW page selected in this slot's
/// portal record. The host authenticates that record against the live root.
// `Err(())` is the carrier's single refusal; callers own its meaning.
#[allow(clippy::result_unit_err)]
pub fn cross_hvc_cow_supply(address: u64, cpu: u64) -> Result<(), ()> {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let mut status = carrick_el1_abi::GRANT_OP_COW_SUPPLY;
        // SAFETY: the synchronous crossing retains this slot's published
        // selection until the carrier consumes its exact record.
        unsafe {
            core::arch::asm!("hvc #6", inout("x0") status,
                inlateout("x1") address => _, inlateout("x2") cpu => _,
                inlateout("x3") 0u64 => _, options(nostack));
        }
        (status == carrick_el1_abi::METADATA_GRANT_SUCCESS)
            .then_some(())
            .ok_or(())
    }
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    {
        let _ = (address, cpu);
        Err(())
    }
}

/// An exact running task's bounded EL1 transfer.
pub struct Aarch64UserTransfer {
    owner: core::ptr::NonNull<CurrentTask>,
    user: UserVa,
    kernel: core::ptr::NonNull<u8>,
    total: GuestLen,
    completed: GuestLen,
    direction: carrick_guest_arch::TransferDirection,
}

impl Aarch64UserTransfer {
    pub fn advance(&mut self, limit: GuestLen) -> Result<CopyProgress, ArchError> {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            let remaining = self.total.raw() - self.completed.raw();
            if remaining == 0 || limit.raw() == 0 {
                return Ok(CopyProgress {
                    completed: GuestLen::new(0),
                    remaining: GuestLen::new(remaining),
                });
            }
            let cur_user = self.user.raw() + self.completed.raw();
            let page_offset = cur_user & 4095;
            let page_remaining = 4096 - page_offset;
            let chunk_len = (limit.raw().min(remaining).min(page_remaining)) as usize;

            // SAFETY: the caller of `open_user_transfer` authenticates the typed MM owner
            // reference and guarantees it remains valid and bound to this task across
            // the transfer's progression.
            let task = unsafe { self.owner.as_ref() };

            let success = match self.direction {
                carrick_guest_arch::TransferDirection::FromUser => {
                    // SAFETY: `task` is authenticated above. `cur_user` was checked against
                    // the canonical lower-half range; EL1 exception fixup safely catches any
                    // unmapped or invalid user memory page fault.
                    unsafe {
                        let kptr = self.kernel.as_ptr().add(self.completed.raw() as usize);
                        crate::substrate::file::copy_from_user_guarded(
                            task,
                            kptr,
                            cur_user as *const u8,
                            chunk_len,
                        )
                    }
                }
                carrick_guest_arch::TransferDirection::ToUser => {
                    // SAFETY: `task` is authenticated above. `cur_user` was checked against
                    // the canonical lower-half range; EL1 exception fixup safely catches any
                    // unmapped or read-only user memory page fault.
                    unsafe {
                        let kptr = self.kernel.as_ptr().add(self.completed.raw() as usize);
                        crate::substrate::file::copy_to_user_guarded(
                            task,
                            cur_user as *mut u8,
                            kptr,
                            chunk_len,
                        )
                    }
                }
            };
            if !success {
                return Err(ArchError::Fault);
            }
            self.completed = GuestLen::new(self.completed.raw() + chunk_len as u64);
            let new_remaining = self.total.raw() - self.completed.raw();
            Ok(CopyProgress {
                completed: GuestLen::new(chunk_len as u64),
                remaining: GuestLen::new(new_remaining),
            })
        }
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        {
            let _ = limit;
            Err(ArchError::Unbound)
        }
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
    type UserTransfer = Aarch64UserTransfer;
    type HardwareInterrupt = u32;
    type InterruptMask = hw::IrqGuard;
}

impl carrick_guest_arch::DefaultMmOwner for Aarch64Backend {}

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
        let mut context = Aarch64ParkedContext::ZERO;
        hw::HardwareCpu.save(frame, &mut context);
        Ok(context.native)
    }
    fn load_context(
        &mut self,
        frame: &mut TrapFrame,
        saved: &ThreadCtx,
    ) -> Result<(), Self::Error> {
        hw::HardwareCpu.load(frame, &Aarch64ParkedContext::from_register(*saved, 0, 0, 0));
        Ok(())
    }
    fn prepare_user_return(&mut self, _frame: &TrapFrame) -> Result<UserReturn, Self::Error> {
        Err(ArchError::Unbound)
    }
    fn user_stack_pointer(&mut self, frame: &TrapFrame) -> Result<UserVa, Self::Error> {
        crate::isa::aarch64_user_stack_pointer(frame)
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
    fn open_user_transfer(
        &mut self,
        owner: &Self::MmOwner,
        user: UserVa,
        kernel: core::ptr::NonNull<u8>,
        len: GuestLen,
        direction: carrick_guest_arch::TransferDirection,
    ) -> Result<Self::UserTransfer, Self::Error> {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        {
            if !crate::isa::lower_half_range(user.raw(), len.raw()) {
                return Err(ArchError::OutOfBounds);
            }
            Ok(Aarch64UserTransfer {
                owner: core::ptr::NonNull::from(owner),
                user,
                kernel,
                total: len,
                completed: GuestLen::new(0),
                direction,
            })
        }
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        {
            let _ = (owner, user, kernel, len, direction);
            Err(ArchError::Unbound)
        }
    }
    fn copy_user_chunk(
        &mut self,
        transfer: &mut Self::UserTransfer,
        limit: GuestLen,
    ) -> Result<CopyProgress, Self::Error> {
        transfer.advance(limit)
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
            unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
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
    reason: carrick_core_abi::NativeRunFailureReason,
) -> ! {
    let record = carrick_core_abi::NativeRunFailure::new(binding, reason);
    // SAFETY: EL1 retains this initialized supervisor-stack record until the
    // stopped CPU's exact execution is authenticated and the carrier stops.
    unsafe {
        core::arch::asm!("hvc #3",
            in("x0") carrick_core_abi::NATIVE_RUN_FAILURE_SENTINEL,
            in("x1") &record as *const _ as u64,
            options(nostack));
    }
    hw::fatal_entry_binding()
}

/// Read the EL0 stack register at the native trap boundary.
///
/// # Safety
/// The caller is on the native trap path of the thread whose EL0 stack it reads.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub unsafe fn signal_stack() -> carrick_guest_arch::UserVa {
    let sp: u64;
    unsafe {
        core::arch::asm!("mrs {}, sp_el0", out(reg) sp, options(nomem, nostack));
    }
    carrick_guest_arch::UserVa::new(sp)
}

/// Publish a validated EL0 stack register at the native trap boundary.
///
/// # Safety
/// The caller is on the native trap path of the resuming thread and `sp` was
/// validated for that thread's EL0 address space.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub unsafe fn set_signal_stack(sp: carrick_guest_arch::UserVa) {
    unsafe {
        core::arch::asm!("msr sp_el0, {}", in(reg) sp.raw(), options(nomem, nostack));
    }
}
