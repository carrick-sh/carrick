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

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Siginfo {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    _pad0: i32,
    si_addr: u64,
    _pad: [u8; 128 - 24],
}

impl Siginfo {
    const fn empty() -> Self {
        Self {
            si_signo: 0,
            si_errno: 0,
            si_code: 0,
            _pad0: 0,
            si_addr: 0,
            _pad: [0; 128 - 24],
        }
    }

    fn ref_from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() >= core::mem::size_of::<Self>() {
            Some(unsafe { &*(bytes.as_ptr() as *const Self) })
        } else {
            None
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SignalStack {
    ss_sp: u64,
    ss_flags: i32,
    _pad0: u32,
    ss_size: u64,
}

impl SignalStack {
    const fn empty() -> Self {
        Self {
            ss_sp: 0,
            ss_flags: 0,
            _pad0: 0,
            ss_size: 0,
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SignalContext {
    fault_address: u64,
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
    _pad: [u8; 8],
    __reserved: [u8; 4096],
}

impl SignalContext {
    const fn empty() -> Self {
        Self {
            fault_address: 0,
            regs: [0; 31],
            sp: 0,
            pc: 0,
            pstate: 0,
            _pad: [0; 8],
            __reserved: [0; 4096],
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ucontext {
    uc_flags: u64,
    uc_link: u64,
    uc_stack: SignalStack,
    uc_sigmask: u64,
    _pad: [u8; 120],
    _pad2: [u8; 8],
    uc_mcontext: SignalContext,
}

impl Ucontext {
    const fn empty() -> Self {
        Self {
            uc_flags: 0,
            uc_link: 0,
            uc_stack: SignalStack::empty(),
            uc_sigmask: 0,
            _pad: [0; 120],
            _pad2: [0; 8],
            uc_mcontext: SignalContext::empty(),
        }
    }
}

const ARM64_SIGFRAME_MAGIC: u64 = 0x4361_7272_6963_6b53;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Arm64Sigframe {
    siginfo: Siginfo,
    ucontext: Ucontext,
    magic: u64,
    signum: u32,
    _pad0: u32,
    saved_x: [u64; 31],
    saved_pc: u64,
    saved_sp: u64,
    saved_spsr: u64,
    _reserved: [u64; 6],
}

impl Arm64Sigframe {
    const fn empty() -> Self {
        Self {
            siginfo: Siginfo::empty(),
            ucontext: Ucontext::empty(),
            magic: ARM64_SIGFRAME_MAGIC,
            signum: 0,
            _pad0: 0,
            saved_x: [0; 31],
            saved_pc: 0,
            saved_sp: 0,
            saved_spsr: 0,
            _reserved: [0; 6],
        }
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }

    fn ref_from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() >= core::mem::size_of::<Self>() {
            Some(unsafe { &*(bytes.as_ptr() as *const Self) })
        } else {
            None
        }
    }
}

impl carrick_guest_arch::SignalBackend for Aarch64Backend {
    fn setup_signal_frame<'a>(
        &mut self,
        frame: &mut TrapFrame,
        params: carrick_guest_arch::SignalFrameParams,
        siginfo: Option<&'a [u8]>,
        copy_out: &mut dyn FnMut(UserVa, &[u8]) -> bool,
    ) -> Result<UserVa, Self::Error> {
        let frame_size = core::mem::size_of::<Arm64Sigframe>() as u64;
        let new_sp = (params.sp.raw().saturating_sub(frame_size)) & !15;

        let mut sigframe = Arm64Sigframe::empty();
        sigframe.signum = params.signum as u32;
        sigframe.saved_pc = frame.elr;
        sigframe.saved_spsr = frame.spsr;
        sigframe.saved_sp = params.sp.raw();
        sigframe.saved_x = frame.x;
        sigframe.ucontext.uc_sigmask = params.mask;

        if let Some(bytes) = siginfo {
            if let Some(info) = Siginfo::ref_from_bytes(bytes) {
                sigframe.siginfo = *info;
            }
        } else {
            let mut info = Siginfo::empty();
            info.si_signo = params.signum;
            info.si_code = params.sigcode;
            info.si_addr = params.fault_addr;
            sigframe.siginfo = info;
        }

        let frame_bytes = sigframe.as_bytes();
        if !copy_out(UserVa::new(new_sp), frame_bytes) {
            return Err(ArchError::InvalidFrame);
        }

        let info_addr = new_sp + core::mem::offset_of!(Arm64Sigframe, siginfo) as u64;
        let uc_addr = new_sp + core::mem::offset_of!(Arm64Sigframe, ucontext) as u64;

        frame.elr = params.handler.raw();
        frame.x[0] = params.signum as u64;
        frame.x[1] = info_addr;
        frame.x[2] = uc_addr;
        frame.x[30] = params.restorer.map_or(0, |r| r.raw());

        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        unsafe {
            core::arch::asm!("msr sp_el0, {}", in(reg) new_sp, options(nomem, nostack));
        }

        Ok(UserVa::new(new_sp))
    }

    fn restore_signal_frame(
        &mut self,
        frame: &mut TrapFrame,
        copy_in: &mut dyn FnMut(&mut [u8], UserVa) -> bool,
    ) -> Result<u64, Self::Error> {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        let sp_val = {
            let sp: u64;
            unsafe {
                core::arch::asm!("mrs {}, sp_el0", out(reg) sp, options(nomem, nostack));
            }
            sp
        };
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        let sp_val = 0u64;

        let sp = UserVa::new(sp_val);
        let mut bytes = [0u8; core::mem::size_of::<Arm64Sigframe>()];
        if !copy_in(&mut bytes, sp) {
            return Err(ArchError::InvalidFrame);
        }
        let Some(sigframe) = Arm64Sigframe::ref_from_bytes(&bytes) else {
            return Err(ArchError::InvalidFrame);
        };

        if !super::signal_resume_is_el0(sigframe.saved_spsr) {
            return Err(ArchError::InvalidFrame);
        }
        frame.x = sigframe.saved_x;
        frame.elr = sigframe.saved_pc;
        frame.spsr = sigframe.saved_spsr;

        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        unsafe {
            core::arch::asm!("msr sp_el0, {}", in(reg) sigframe.saved_sp, options(nomem, nostack));
        }

        Ok(sigframe.ucontext.uc_sigmask)
    }
}
