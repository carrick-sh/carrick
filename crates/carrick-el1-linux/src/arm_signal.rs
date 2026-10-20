//! Pure ARM frame publication used by the native backend and VM-free tests.
use carrick_el1::isa::ArchError;
extern crate alloc;
use alloc::vec::Vec;
use carrick_el1_abi::TrapFrame;
use carrick_personality_linux::signal::arm;
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
use carrick_personality_linux::signal::arm::RtSigframe;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
struct ArmSignalMachine {
    backend: LinuxAarch64Backend,
    user_sp: carrick_guest_arch::UserVa,
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl super::signal_delivery::SignalMachine<carrick_sched_core::Aarch64ParkedContext>
    for ArmSignalMachine
{
    type Backend = LinuxAarch64Backend;

    fn backend(&mut self) -> &mut Self::Backend {
        &mut self.backend
    }

    fn user_sp(&self, _frame: &TrapFrame) -> carrick_guest_arch::UserVa {
        self.user_sp
    }

    fn restart(
        &self,
        frame: &mut TrapFrame,
        original: &carrick_sched_core::Aarch64ParkedContext,
    ) -> bool {
        frame.x[0] = original.syscall_return();
        if let Some(pc) = frame.elr.checked_sub(4) {
            frame.elr = pc;
            true
        } else {
            false
        }
    }

    fn restart_forwarded(&self, frame: &mut TrapFrame) -> Option<bool> {
        restart_forwarded_frame(frame)
    }

    fn group_exit_custody(
        &self,
        _task: &carrick_el1_abi::CurrentTask,
    ) -> carrick_personality_linux::dispatch::CompletionRoute {
        carrick_personality_linux::dispatch::CompletionRoute::InvalidCompletion
    }
}

/// The synthetic mailbox checkpoint puts the original syscall arg0 in FAR;
/// no guest fault uses FAR on this entry. A handler with SA_RESTART rewinds
/// the interrupted SVC only for the shared restartable-call policy. The
/// restart-eligible mailbox marker authenticates the continuation's untimed
/// wait; a timed wait uses the distinct no-restart marker.
pub(crate) fn restart_forwarded_frame(frame: &mut TrapFrame) -> Option<bool> {
    if frame.esr != 0xfffe
        || frame.x[0] != carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64
        || !carrick_signal_core::is_native_restartable_syscall(frame.x[8])
    {
        return None;
    }
    rewind_forwarded_frame(frame)
}

/// Rewind an interrupted restart-class forwarded SVC for `SA_RESTART` or when
/// no handler runs at the checkpoint (`WaitDecision::Continue`).
fn rewind_forwarded_frame(frame: &mut TrapFrame) -> Option<bool> {
    let Some(pc) = frame.elr.checked_sub(4) else {
        return Some(false);
    };
    frame.x[0] = frame.far;
    frame.elr = pc;
    Some(true)
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
#[inline(never)]
pub(crate) fn deliver_on_user_return<X: super::aarch64_process::ForkStockCrossing>(
    task: &carrick_el1_abi::CurrentTask,
    process: &mut super::native_process_runtime::NativeProcessEntry<
        '_,
        'static,
        super::aarch64_process::Mm,
        carrick_sched_core::Aarch64ParkedContext,
        super::aarch64_process::Aarch64NativeProcessService<'static, X>,
    >,
    frame: &mut TrapFrame,
) -> Option<carrick_personality_linux::dispatch::CompletionRoute> {
    use crate::sched::ThreadCpu;
    use zerocopy::IntoBytes;

    if !(process.signal_checkpoint_needed()
        || (frame.esr == 0xfffe
            && frame.x[0] == carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64))
    {
        return None;
    }
    let mut saved = crate::rust_alloc::boxed::Box::new(carrick_el1_abi::Aarch64ParkedContext::ZERO);
    crate::sched::HardwareCpu.save(frame, &mut saved);
    let mut fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
    fp.vregs = saved.native.v;
    fp.fpsr = saved.native.fpsr as u32;
    fp.fpcr = saved.native.fpcr as u32;
    let sp = unsafe { carrick_el1::isa::aarch64::signal_stack() };
    super::signal_delivery::deliver_signal_on_syscall_return(
        task,
        process,
        frame,
        fp.as_bytes(),
        &mut ArmSignalMachine {
            backend: LinuxAarch64Backend,
            user_sp: sp,
        },
    )
}

/// Internal EL0t DAIF mask stored in `TrapFrame.spsr` and `ThreadCtx.pstate` across the EL1
/// kernel. In `El1IrqMode::Gic`, the EL1 vector hook (`carrick-mem::write_el1_hook`) clears
/// `PSTATE.I` (`0x80`) from `TrapFrame.spsr` right before `msr spsr_el1, x1; eret`; in both
/// modes, `(TrapFrame.spsr & 0x3c0) | PSTATE_I == 0x3c0` is the required internal DAIF return
/// invariant alongside any preserved legal EL0 user flags (`AARCH64_EL0_USER_PSTATE_MASK`).
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
const AARCH64_INTERNAL_EL0_RETURN_DAIF: u64 = 0x3c0;

#[cfg(any(
    test,
    feature = "host-test",
    all(target_os = "none", target_arch = "aarch64")
))]
const fn public_el0_pstate(internal_spsr: u64) -> u64 {
    internal_spsr & carrick_syscall_abi::AARCH64_EL0_USER_PSTATE_MASK
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
const fn internal_el0_return_spsr(public_pstate: u64) -> u64 {
    (public_pstate & carrick_syscall_abi::AARCH64_EL0_USER_PSTATE_MASK)
        | AARCH64_INTERNAL_EL0_RETURN_DAIF
}

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(crate) fn restore(
    frame: &mut TrapFrame,
    signal: &RtSigframe,
    fpstate: &mut [u8],
    signal_sp: carrick_guest_arch::UserVa,
) -> Result<(u64, u64, carrick_personality_linux::abi::thread::AltStack), ArchError> {
    use zerocopy::IntoBytes;
    let resume =
        arm::decode(signal.as_bytes(), signal_sp, true).map_err(|_| ArchError::InvalidFrame)?;
    let stack = carrick_personality_linux::signal::restored_altstack(
        resume.stack,
        carrick_guest_arch::GuestIsa::Aarch64,
    )
    .ok_or(ArchError::InvalidFrame)?;
    let fp = resume.fpsimd.ok_or(ArchError::InvalidFrame)?;
    if fpstate.len() != fp.as_bytes().len() {
        return Err(ArchError::InvalidFrame);
    }
    fpstate.copy_from_slice(fp.as_bytes());
    frame.x = resume.regs;
    frame.elr = resume.pc.raw();
    frame.spsr = internal_el0_return_spsr(resume.pstate);
    Ok((resume.mask.signals().bits(), resume.sp.raw(), stack))
}

#[cfg(any(
    test,
    feature = "host-test",
    all(target_os = "none", target_arch = "aarch64")
))]
fn frame_copy_buffer(len: usize) -> Result<Vec<u8>, ArchError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| ArchError::InvalidFrame)?;
    // Capacity was admitted above, so this only initializes already owned
    // bytes. Allocation failure takes the ordinary sigreturn failure path.
    bytes.resize(len, 0);
    Ok(bytes)
}

/// Apply the already validated public return state to the next hardware
/// context. The ISA leaf loads this context only after every copy and record
/// check has succeeded, so a malformed frame publishes no partial registers.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(crate) fn apply_restored_context(
    context: &mut carrick_sched_core::ThreadCtx,
    frame: &TrapFrame,
    fp: &carrick_syscall_abi::LinuxFpsimdContext,
    sp: u64,
) {
    context.x = frame.x;
    context.pc = frame.elr;
    context.pstate = internal_el0_return_spsr(frame.spsr);
    context.sp_el0 = sp;
    context.v = fp.vregs;
    context.fpsr = u64::from(fp.fpsr);
    context.fpcr = u64::from(fp.fpcr);
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
#[inline(never)]
pub(crate) fn restore_live_arm_signal_frame(
    frame: &mut TrapFrame,
    copy_in: &mut dyn carrick_personality_linux::lifecycle::UserCopy,
) -> Result<carrick_personality_linux::signal::RestoredSignalFrame, carrick_syscall_abi::LinuxErrno>
{
    use crate::sched::ThreadCpu;
    use carrick_personality_linux::signal::SignalBackend;
    use zerocopy::IntoBytes;

    // The audited switch leaf is the sole reader/writer of EL0 FP/SIMD.
    // Retain the context off the 16 KiB EL1 stack until validation commits.
    let mut saved = crate::rust_alloc::boxed::Box::new(carrick_el1_abi::Aarch64ParkedContext::ZERO);
    crate::sched::HardwareCpu.save(frame, &mut saved);
    let mut fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
    fp.vregs = saved.native.v;
    fp.fpsr = saved.native.fpsr as u32;
    fp.fpcr = saved.native.fpcr as u32;
    let mask = LinuxAarch64Backend
        .restore_signal_frame(frame, fp.as_mut_bytes(), &mut |dst, src| {
            copy_in.copy_in(dst, src)
        })
        .map_err(|_| carrick_syscall_abi::LINUX_EFAULT)?;
    // restore_signal_frame validates and then publishes SP_EL0. Re-read it
    // only after success; a failed copy leaves the saved hardware untouched.
    let restored_sp = unsafe { carrick_el1::isa::aarch64::signal_stack().raw() };
    apply_restored_context(&mut saved.native, frame, &fp, restored_sp);
    crate::sched::HardwareCpu.load(frame, &saved);
    Ok(mask)
}

#[cfg(any(
    test,
    feature = "host-test",
    all(target_os = "none", target_arch = "aarch64")
))]
pub(crate) fn build(
    frame: &TrapFrame,
    params: carrick_personality_linux::signal::SignalFrameParams,
    siginfo: Option<&[u8]>,
    fpstate: &[u8],
) -> Result<(carrick_guest_arch::UserVa, Vec<u8>), ArchError> {
    use carrick_syscall_abi::{LinuxFpsimdContext, LinuxSiginfo};
    use zerocopy::FromBytes;
    let fp = LinuxFpsimdContext::ref_from_bytes(fpstate).map_err(|_| ArchError::InvalidFrame)?;
    let mut bytes = frame_copy_buffer(core::mem::size_of::<arm::SignalFrame>())?;
    let signal =
        arm::SignalFrame::mut_from_bytes(&mut bytes).map_err(|_| ArchError::InvalidFrame)?;
    let context = &mut signal.rt.ucontext.uc_mcontext;
    context.regs = frame.x;
    context.pc = frame.elr;
    context.sp = params.interrupted_sp.raw();
    context.pstate = public_el0_pstate(frame.spsr);
    context.fault_address = params.fault_addr;
    signal.rt.ucontext.uc_stack = params.stack;
    signal.rt.ucontext.uc_sigmask = params.mask.signals().bits();
    signal.rt.siginfo = if let Some(bytes) = siginfo {
        LinuxSiginfo::read_from_bytes(bytes).map_err(|_| ArchError::InvalidFrame)?
    } else {
        let mut info = LinuxSiginfo::empty();
        info.si_signo = params.signal.number();
        info.si_code = params.sigcode;
        info.si_addr = params.fault_addr;
        info
    };
    arm::encode(signal, Some(fp), None).map_err(|_| ArchError::InvalidFrame)?;
    let sp =
        arm::stack_pointer(params.sp, None, bytes.len()).map_err(|_| ArchError::InvalidFrame)?;
    Ok((sp, bytes))
}

#[cfg(any(
    test,
    feature = "host-test",
    all(target_os = "none", target_arch = "aarch64")
))]
use carrick_guest_arch::UserVa;
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
use zerocopy::FromBytes;

/// The Linux signal-frame codec over the neutral ARM backend's types.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub struct LinuxAarch64Backend;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl carrick_guest_arch::ArchTypes for LinuxAarch64Backend {
    type Error =
        <carrick_el1::isa::aarch64::Aarch64Backend as carrick_guest_arch::ArchTypes>::Error;
    type NativeFrame =
        <carrick_el1::isa::aarch64::Aarch64Backend as carrick_guest_arch::ArchTypes>::NativeFrame;
    type SavedContext =
        <carrick_el1::isa::aarch64::Aarch64Backend as carrick_guest_arch::ArchTypes>::SavedContext;
    type Context =
        <carrick_el1::isa::aarch64::Aarch64Backend as carrick_guest_arch::ArchTypes>::Context;
    type Root = <carrick_el1::isa::aarch64::Aarch64Backend as carrick_guest_arch::ArchTypes>::Root;
    type MmOwner =
        <carrick_el1::isa::aarch64::Aarch64Backend as carrick_guest_arch::ArchTypes>::MmOwner;
    type DrainTicket =
        <carrick_el1::isa::aarch64::Aarch64Backend as carrick_guest_arch::ArchTypes>::DrainTicket;
    type DrainReceipt =
        <carrick_el1::isa::aarch64::Aarch64Backend as carrick_guest_arch::ArchTypes>::DrainReceipt;
    type UserTransfer =
        <carrick_el1::isa::aarch64::Aarch64Backend as carrick_guest_arch::ArchTypes>::UserTransfer;
    type HardwareInterrupt = <carrick_el1::isa::aarch64::Aarch64Backend as carrick_guest_arch::ArchTypes>::HardwareInterrupt;
    type InterruptMask =
        <carrick_el1::isa::aarch64::Aarch64Backend as carrick_guest_arch::ArchTypes>::InterruptMask;
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl carrick_personality_linux::signal::SignalBackend for LinuxAarch64Backend {
    fn setup_signal_frame<'a>(
        &mut self,
        frame: &mut TrapFrame,
        params: carrick_personality_linux::signal::SignalFrameParams,
        siginfo: Option<&'a [u8]>,
        _fpstate: &[u8],
        copy_out: &mut dyn FnMut(UserVa, &[u8]) -> bool,
    ) -> Result<UserVa, Self::Error> {
        setup_arm_signal_frame(frame, params, siginfo, _fpstate, copy_out)
    }

    fn restore_signal_frame(
        &mut self,
        frame: &mut TrapFrame,
        _fpstate: &mut [u8],
        copy_in: &mut dyn FnMut(&mut [u8], UserVa) -> bool,
    ) -> Result<carrick_personality_linux::signal::RestoredSignalFrame, Self::Error> {
        let sp_val = unsafe { carrick_el1::isa::aarch64::signal_stack().raw() };
        let sp = UserVa::new(sp_val);
        // A public frame is over 4 KiB. Keep the admitted copy off the 16 KiB
        // EL1 stack and borrow it throughout decode.
        let mut bytes = frame_copy_buffer(arm::PUBLIC_FRAME_LEN)?;
        if !copy_in(&mut bytes, sp) {
            return Err(ArchError::InvalidFrame);
        }
        let Some(sigframe) = RtSigframe::ref_from_bytes(&bytes).ok() else {
            return Err(ArchError::InvalidFrame);
        };

        let (mask, saved_sp, stack) = restore(frame, sigframe, _fpstate, sp)?;

        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        unsafe {
            carrick_el1::isa::aarch64::set_signal_stack(UserVa::new(saved_sp));
        }

        Ok(carrick_personality_linux::signal::RestoredSignalFrame {
            mask: carrick_signal_core::policy::SigBlockMask::blocking_all_of(
                carrick_signal_core::SignalSet::from_bits(mask),
            ),
            stack,
        })
    }
}

/// Shared frame publication for the native backend and its host-path witness.
#[cfg(any(
    test,
    feature = "host-test",
    all(target_os = "none", target_arch = "aarch64")
))]
#[inline(never)]
pub(crate) fn setup_arm_signal_frame(
    frame: &mut TrapFrame,
    params: carrick_personality_linux::signal::SignalFrameParams,
    siginfo: Option<&[u8]>,
    fpstate: &[u8],
    copy_out: &mut dyn FnMut(UserVa, &[u8]) -> bool,
) -> Result<UserVa, ArchError> {
    let (sp, sigframe) = build(frame, params, siginfo, fpstate)?;
    let new_sp = sp.raw();

    if !copy_out(UserVa::new(new_sp), &sigframe) {
        return Err(ArchError::InvalidFrame);
    }

    let info_addr = new_sp;
    let uc_addr = new_sp + arm::UCONTEXT_OFFSET as u64;

    frame.elr = params.handler.raw();
    frame.x[0] = params.signal.number() as u64;
    frame.x[1] = info_addr;
    frame.x[2] = uc_addr;
    frame.x[29] = new_sp + arm::FRAME_RECORD_OFFSET as u64;
    frame.x[30] = params.restorer.map_or(
        carrick_syscall_abi::LINUX_SIGRETURN_TRAMPOLINE_BASE,
        UserVa::raw,
    );

    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    unsafe {
        carrick_el1::isa::aarch64::set_signal_stack(UserVa::new(new_sp));
    }

    Ok(UserVa::new(new_sp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_guest_arch::UserVa;
    use carrick_syscall_abi::LinuxFpsimdContext;
    use zerocopy::{FromBytes, IntoBytes};

    #[test]
    fn forwarded_read_restart_replays_original_arg_only_at_native_checkpoint() {
        let mut read = TrapFrame {
            esr: 0xfffe,
            ..Default::default()
        };
        read.x[0] = carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64;
        read.x[8] = 63; // ARM read
        read.far = 0x1234; // mailbox arg0, not a fault address
        read.elr = 0x8004;
        assert_eq!(restart_forwarded_frame(&mut read), Some(true));
        assert_eq!(read.x[0], 0x1234);
        assert_eq!(read.elr, 0x8000);

        let mut timed_recv = TrapFrame {
            esr: 0xfffd, // host continuation with SO_RCVTIMEO
            ..Default::default()
        };
        timed_recv.x[0] = carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64;
        timed_recv.x[8] = 207; // ARM recvfrom
        timed_recv.far = 0x1234;
        timed_recv.elr = 0x8004;
        assert_eq!(restart_forwarded_frame(&mut timed_recv), None);
        assert_eq!(
            timed_recv.x[0],
            carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64
        );
        assert_eq!(timed_recv.elr, 0x8004);

        for nr in [202, 242, 207, 212] {
            let mut socket = TrapFrame {
                esr: 0xfffe,
                ..Default::default()
            };
            socket.x[0] = carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64;
            socket.x[8] = nr;
            socket.far = 0x5678;
            socket.elr = 0x9004;
            assert_eq!(restart_forwarded_frame(&mut socket), Some(true));
            assert_eq!((socket.x[0], socket.elr), (0x5678, 0x9000));
        }

        let mut ppoll = TrapFrame {
            esr: 0xfffe,
            ..Default::default()
        };
        ppoll.x[0] = carrick_syscall_abi::LINUX_EINTR.guest_retval() as u64;
        ppoll.x[8] = 73; // ARM ppoll always returns EINTR
        ppoll.far = 0x5678;
        ppoll.elr = 0x9004;
        assert_eq!(restart_forwarded_frame(&mut ppoll), None);
        assert_eq!(ppoll.elr, 0x9004);
    }

    fn valid() -> RtSigframe {
        let mut signal = RtSigframe {
            siginfo: carrick_syscall_abi::LinuxSiginfo::empty(),
            ucontext: carrick_syscall_abi::LinuxUcontext::empty(),
        };
        let fp = LinuxFpsimdContext::empty();
        signal.ucontext.uc_mcontext.__reserved[..fp.as_bytes().len()]
            .copy_from_slice(fp.as_bytes());
        signal.ucontext.uc_mcontext.regs[0] = 0x1234;
        signal.ucontext.uc_mcontext.pc = 0x10000;
        signal.ucontext.uc_mcontext.sp = 0x20000;
        signal
    }
    #[test]
    fn built_frame_carries_ucontext_fpsimd_stack_and_frame_record() {
        use carrick_guest_arch::UserVa;
        use carrick_personality_linux::signal::SignalFrameParams;
        let mut frame = TrapFrame::default();
        frame.x[0] = 42;
        frame.x[29] = 0x8000;
        frame.x[30] = 0x9000;
        frame.elr = 0x10000;
        let fp = LinuxFpsimdContext::empty();
        let params = SignalFrameParams {
            stack: carrick_syscall_abi::LinuxSignalStack::empty(),
            signal: carrick_signal_core::policy::Signal::from_number(10).unwrap(),
            sigcode: 0,
            fault_addr: 0,
            sp: UserVa::new(0x20000),
            interrupted_sp: UserVa::new(0x20000),
            handler: UserVa::new(0x30000),
            restorer: Some(UserVa::new(0x40000)),
            mask: carrick_signal_core::policy::SigBlockMask::blocking_all_of(
                carrick_signal_core::SignalSet::from_bits(8),
            ),
        };
        let (sp, signal) = build(&frame, params, None, fp.as_bytes()).unwrap();
        assert_eq!(sp.raw() & 15, 0);
        let signal = arm::SignalFrame::ref_from_bytes(&signal).unwrap();
        let context = signal.rt.ucontext.uc_mcontext;
        let regs = context.regs;
        assert_eq!(regs[0], 42);
        let record = signal.frame_record;
        assert_eq!(&record[..2], &[0x8000, 0x9000]);
        assert_eq!(&context.__reserved[..528], fp.as_bytes());
        assert_eq!(&context.__reserved[528..536], &[0; 8]);
        let mask = signal.rt.ucontext.uc_sigmask;
        assert_eq!(mask, 8);
        let (_, without_restorer) = build(
            &frame,
            SignalFrameParams {
                restorer: None,
                ..params
            },
            None,
            fp.as_bytes(),
        )
        .expect("glibc ARM actions use the mapped user trampoline");
        let saved_pc = arm::SignalFrame::ref_from_bytes(&without_restorer)
            .unwrap()
            .rt
            .ucontext
            .uc_mcontext
            .pc;
        assert_eq!(saved_pc, frame.elr);
    }

    #[test]
    fn ucontext_is_the_resume_authority() {
        let signal = valid();
        let mut frame = TrapFrame::default();
        let (_, sp, _) = restore(&mut frame, &signal, &mut [0; 528], UserVa::new(0x40000)).unwrap();
        assert_eq!(frame.x[0], 0x1234);
        assert_eq!(frame.elr, 0x10000);
        assert_eq!(sp, 0x20000);
    }
    #[test]
    fn arm_public_return_restores_saved_autodisarm_altstack() {
        let mut signal = valid();
        signal.ucontext.uc_stack = carrick_syscall_abi::LinuxSignalStack {
            ss_sp: 0x10_0000,
            ss_flags: carrick_syscall_abi::LINUX_SS_AUTODISARM as i32,
            _pad0: 0,
            ss_size: 8192,
        };
        let mut frame = TrapFrame::default();
        let (_, _, restored_stack) =
            restore(&mut frame, &signal, &mut [0; 528], UserVa::new(0x40000)).unwrap();
        let sp = restored_stack.sp;
        let size = restored_stack.size;
        let flags = restored_stack.flags;
        assert_eq!(sp, 0x10_0000);
        assert_eq!(size, 8192);
        assert_eq!(flags, carrick_syscall_abi::LINUX_SS_AUTODISARM as u32);
    }
    #[test]
    fn forged_ucontext_el1_is_refused_without_publication() {
        let mut signal = valid();
        signal.ucontext.uc_mcontext.pstate = 5;
        let mut frame = TrapFrame::default();
        let original = frame;
        assert_eq!(
            restore(&mut frame, &signal, &mut [0; 528], UserVa::new(0x40000)),
            Err(ArchError::InvalidFrame)
        );
        assert_eq!(frame, original);
    }
    #[test]
    fn masked_exceptions_aarch32_and_invalid_fpsimd_size_are_refused() {
        for pstate in [0x10, 1 << 6, 1 << 7, 1 << 8, 1 << 9] {
            let mut signal = valid();
            signal.ucontext.uc_mcontext.pstate = pstate;
            let mut output = [0x55; 528];
            assert!(
                restore(
                    &mut TrapFrame::default(),
                    &signal,
                    &mut output,
                    UserVa::new(0x40000)
                )
                .is_err()
            );
            assert!(output.iter().all(|byte| *byte == 0x55));
        }
        let mut signal = valid();
        signal.ucontext.uc_mcontext.__reserved[4..8].copy_from_slice(&0_u32.to_le_bytes());
        assert!(
            restore(
                &mut TrapFrame::default(),
                &signal,
                &mut [0; 528],
                UserVa::new(0x40000)
            )
            .is_err()
        );
    }

    #[test]
    fn fpsimd_magic_is_required() {
        let mut signal = valid();
        let mut frame = TrapFrame::default();
        signal.ucontext.uc_mcontext.__reserved[0] ^= 1;
        assert!(restore(&mut frame, &signal, &mut [0; 528], UserVa::new(0x40000)).is_err());
    }
    #[test]
    fn fpsimd_payload_is_restored() {
        let mut signal = valid();
        let mut fp = LinuxFpsimdContext::empty();
        fp.vregs[7] = 0xabc;
        let len = fp.as_bytes().len();
        signal.ucontext.uc_mcontext.__reserved[..len].copy_from_slice(fp.as_bytes());
        let mut output = [0; 528];
        restore(
            &mut TrapFrame::default(),
            &signal,
            &mut output,
            UserVa::new(0x40000),
        )
        .unwrap();
        assert_eq!(output.as_slice(), fp.as_bytes());
    }

    #[test]
    fn arm_public_signal_frame_roundtrip_has_no_private_magic() {
        assert_eq!(
            carrick_personality_linux::dispatch::route_aarch64(139, u64::MAX),
            carrick_personality_linux::dispatch::Family::Signal(
                carrick_personality_linux::signal::SignalCall::RtSigreturn
            ),
            "native ARM return must stay in-ring, never reach carrier frame restoration"
        );
        let signal = valid();
        assert_eq!(signal.as_bytes().len(), arm::PUBLIC_FRAME_LEN);
        let mut frame = TrapFrame::default();
        let mut output = [0; 528];
        let (_, sp, _) = restore(&mut frame, &signal, &mut output, UserVa::new(0x40000))
            .expect("a public Linux ucontext has no private authentication trailer");
        assert_eq!(frame.x[0], 0x1234);
        assert_eq!(frame.elr, 0x10000);
        assert_eq!(sp, 0x20000);
        assert_eq!(output.as_slice(), LinuxFpsimdContext::empty().as_bytes());
    }

    #[test]
    fn arm_restored_public_frame_replaces_gprs_and_fpsimd_in_live_context() {
        let mut context = carrick_sched_core::ThreadCtx::ZERO;
        let mut frame = TrapFrame::default();
        frame.x[0] = 0x1234_5678;
        frame.elr = 0x4000;
        frame.spsr = 0;
        let mut fp = LinuxFpsimdContext::empty();
        fp.vregs[7] = 0x1234_5678_9abc_def0;
        fp.fpsr = 0x55;
        fp.fpcr = 0xaa;
        apply_restored_context(&mut context, &frame, &fp, 0x8000);
        assert_eq!(context.x[0], frame.x[0]);
        assert_eq!(context.pc, frame.elr);
        assert_eq!(context.sp_el0, 0x8000);
        let expected_v = fp.vregs[7];
        let expected_fpsr = fp.fpsr;
        let expected_fpcr = fp.fpcr;
        assert_eq!(context.v[7], expected_v);
        assert_eq!(context.fpsr, u64::from(expected_fpsr));
        assert_eq!(context.fpcr, u64::from(expected_fpcr));
    }

    #[test]
    fn sigreturn_frame_allocation_failure_is_a_frame_error() {
        assert!(matches!(
            frame_copy_buffer(usize::MAX),
            Err(ArchError::InvalidFrame)
        ));
        assert_eq!(
            frame_copy_buffer(arm::PUBLIC_FRAME_LEN).unwrap().len(),
            arm::PUBLIC_FRAME_LEN
        );
    }

    #[test]
    fn arm_public_signal_frame_fpsimd_need_not_be_first() {
        let mut signal = valid();
        let records = &mut signal.ucontext.uc_mcontext.__reserved;
        records.copy_within(0..528, 16);
        records[..16].fill(0);
        records[..4].copy_from_slice(&0x4553_5201_u32.to_le_bytes());
        records[4..8].copy_from_slice(&16_u32.to_le_bytes());
        assert!(
            restore(
                &mut TrapFrame::default(),
                &signal,
                &mut [0; 528],
                UserVa::new(0x40000)
            )
            .is_ok()
        );
    }

    fn refused_without_publication(signal: RtSigframe) {
        let mut frame = TrapFrame::default();
        frame.x[0] = 0x55;
        let original = frame;
        let mut fpstate = [0x55; 528];
        assert_eq!(
            restore(&mut frame, &signal, &mut fpstate, UserVa::new(0x40000)),
            Err(ArchError::InvalidFrame)
        );
        assert_eq!(frame, original);
        assert_eq!(fpstate, [0x55; 528]);
    }

    #[test]
    fn arm_public_signal_frame_duplicate_fpsimd_is_refused() {
        let mut signal = valid();
        signal
            .ucontext
            .uc_mcontext
            .__reserved
            .copy_within(0..528, 528);
        refused_without_publication(signal);
    }

    #[test]
    fn arm_public_signal_frame_bad_record_lengths_are_refused() {
        for size in [0_u32, 8, 15, 17, u32::MAX] {
            let mut signal = valid();
            let records = &mut signal.ucontext.uc_mcontext.__reserved;
            records[528..532].copy_from_slice(&0x4553_5201_u32.to_le_bytes());
            records[532..536].copy_from_slice(&size.to_le_bytes());
            refused_without_publication(signal);
        }
    }

    #[test]
    fn arm_public_return_rejects_invalid_altstack_before_register_publication() {
        let mut signal = valid();
        signal.ucontext.uc_stack.ss_flags = 0x4000;
        refused_without_publication(signal);
    }

    #[test]
    fn arm_public_signal_frame_half_terminator_is_refused() {
        let mut signal = valid();
        signal.ucontext.uc_mcontext.__reserved[532..536].copy_from_slice(&16_u32.to_le_bytes());
        refused_without_publication(signal);
    }

    #[test]
    fn arm_public_signal_frame_missing_terminator_is_refused() {
        let mut signal = valid();
        let records = &mut signal.ucontext.uc_mcontext.__reserved;
        records[528..532].copy_from_slice(&0x4553_5201_u32.to_le_bytes());
        records[532..536].copy_from_slice(&3568_u32.to_le_bytes());
        refused_without_publication(signal);
    }

    #[test]
    fn arm_signal_delivery_masks_internal_daif_and_preserves_el0_user_pstate_flags() {
        use carrick_personality_linux::signal::SignalFrameParams;
        use carrick_syscall_abi::AARCH64_EL0_USER_PSTATE_MASK;

        let fp = LinuxFpsimdContext::empty();
        // Positive controls: internal EL0 SPSR carries either masked DAIF (0x3c0) or GIC-unmasked
        // IRQ DAIF (0x340) plus legal EL0 condition/execution flags (e.g. Z+C = 0x6000_0000 from
        // the native arm64 oracle, all admitted EL0 user bits NZCV|DIT|SSBS, or zero).
        for internal_daif in [0x3c0_u64, 0x340_u64] {
            for user_flags in [0_u64, 0x6000_0000_u64, AARCH64_EL0_USER_PSTATE_MASK] {
                let mut frame = TrapFrame::default();
                frame.x[0] = 0xdead_beef;
                frame.elr = 0x10000;
                frame.spsr = user_flags | internal_daif;
                let params = SignalFrameParams {
                    stack: carrick_syscall_abi::LinuxSignalStack::empty(),
                    signal: carrick_signal_core::policy::Signal::from_number(10).unwrap(),
                    sigcode: 0,
                    fault_addr: 0,
                    sp: UserVa::new(0x20000),
                    interrupted_sp: UserVa::new(0x20000),
                    handler: UserVa::new(0x30000),
                    restorer: Some(UserVa::new(0x40000)),
                    mask: carrick_signal_core::policy::SigBlockMask::NONE,
                };
                let (handler_sp, bytes) = build(&frame, params, None, fp.as_bytes()).expect(
                    "valid interrupted EL0 SPSR with internal DAIF must build a public frame",
                );
                let built = arm::SignalFrame::ref_from_bytes(&bytes).unwrap();
                let public_pstate = built.rt.ucontext.uc_mcontext.pstate;
                assert_eq!(
                    public_pstate, user_flags,
                    "public uc_mcontext.pstate must expose legal EL0 flags without internal DAIF bits"
                );
                assert_eq!(public_pstate & !AARCH64_EL0_USER_PSTATE_MASK, 0);

                // Roundtrip restore must re-apply internal EL0 DAIF mask (0x3c0) while preserving
                // the guest's legal EL0 user flags in both TrapFrame.spsr and ThreadCtx.pstate.
                let mut restored_frame = TrapFrame::default();
                let mut restored_fp = [0_u8; 528];
                let (_, restored_sp, _) =
                    restore(&mut restored_frame, &built.rt, &mut restored_fp, handler_sp)
                        .expect("public frame built from interrupted EL0 state must restore");
                assert_eq!(restored_frame.spsr, user_flags | 0x3c0);
                let mut thread_ctx = carrick_sched_core::ThreadCtx::ZERO;
                apply_restored_context(&mut thread_ctx, &restored_frame, &fp, restored_sp);
                assert_eq!(thread_ctx.pstate, user_flags | 0x3c0);
            }
        }

        // Negative controls: any privileged/internal bit in public ucontext.uc_mcontext.pstate
        // (EL1h 0x5, AArch32 0x10, any DAIF bit 0x40..0x200, IL 1<<20, PAN 1<<22) is rejected
        // before mutating TrapFrame, FPSIMD, or ThreadCtx.
        for bad_bit in [
            0x5_u64,
            0x10,
            1 << 6,
            1 << 7,
            1 << 8,
            1 << 9,
            0x3c0,
            1 << 20,
            1 << 22,
        ] {
            let mut forged = valid();
            forged.ucontext.uc_mcontext.pstate = 0x6000_0000 | bad_bit;
            refused_without_publication(forged);
        }
    }

    #[test]
    fn arm_public_return_restores_internal_daif_and_preserves_el0_user_flags() {
        use carrick_syscall_abi::AARCH64_EL0_USER_PSTATE_MASK;

        let fp = LinuxFpsimdContext::empty();
        // Standalone restore-only witness: starts from an already valid public RtSigframe
        // (independent of build()) with legal EL0 user flags in uc_mcontext.pstate.
        // Internal authority: carrick-mem/src/memory.rs:5078-5083 (write_el1_hook) loads
        // TrapFrame.spsr and, when El1IrqMode::Gic is active, clears PSTATE.I (0x80) via
        // `bic x1, x1, #0x80` right before `msr spsr_el1, x1`; carrick-mem/src/memory/
        // el1_hook_kick.rs:533 requires internal DAIF bits `(spsr & 0x3c0) | PSTATE_I == 0x3c0`
        // (EL0_DAIF_MASKED) on every EL0 return. Therefore restore() and apply_restored_context()
        // must re-apply the canonical internal EL0 DAIF mask (0x3c0) while preserving legal
        // EL0 user flags in `AARCH64_EL0_USER_PSTATE_MASK`.
        for user_flags in [0_u64, 0x6000_0000_u64, AARCH64_EL0_USER_PSTATE_MASK] {
            let mut signal = valid();
            signal.ucontext.uc_mcontext.pstate = user_flags;
            let mut restored_frame = TrapFrame::default();
            let mut restored_fp = [0_u8; 528];
            let (_, restored_sp, _) = restore(
                &mut restored_frame,
                &signal,
                &mut restored_fp,
                UserVa::new(0x40000),
            )
            .expect("valid public RtSigframe must decode and restore");
            assert_eq!(
                restored_frame.spsr,
                user_flags | 0x3c0,
                "restore must re-apply internal EL0 DAIF mask (0x3c0) to TrapFrame.spsr"
            );
            let mut thread_ctx = carrick_sched_core::ThreadCtx::ZERO;
            apply_restored_context(&mut thread_ctx, &restored_frame, &fp, restored_sp);
            assert_eq!(
                thread_ctx.pstate,
                user_flags | 0x3c0,
                "apply_restored_context must preserve internal EL0 DAIF mask (0x3c0) in ThreadCtx.pstate"
            );
        }
    }

    #[test]
    fn arm_signal_delivery_separates_interrupted_sp_from_altstack_placement() {
        use carrick_personality_linux::abi::thread::AltStack;
        use carrick_personality_linux::signal::{SignalFrameParams, delivery_stack};
        use carrick_signal_core::policy::{SigBlockMask, Signal};

        // Reproduces the exact delivery_stack -> SignalFrameParams -> setup_arm_signal_frame
        // pipeline from signal_delivery::deliver_signal_with_control.
        let deliver_case = |altstack: AltStack, on_stack: bool, interrupted_sp_raw: u64| {
            let interrupted_sp = UserVa::new(interrupted_sp_raw);
            let (sp, stack) = delivery_stack(altstack, interrupted_sp, on_stack)
                .expect("delivery_stack selection must succeed");
            let params = SignalFrameParams {
                stack,
                signal: Signal::from_number(10).unwrap(),
                sigcode: 0,
                fault_addr: 0,
                handler: UserVa::new(0x7000),
                restorer: Some(UserVa::new(0x8000)),
                mask: SigBlockMask::NONE,
                sp,
                interrupted_sp,
            };
            let mut frame = TrapFrame {
                elr: 0x10000,
                spsr: 0x6000_0000 | 0x3c0,
                ..Default::default()
            };
            let fp = LinuxFpsimdContext::empty();
            let mut written: Option<(UserVa, Vec<u8>)> = None;
            let handler_sp = setup_arm_signal_frame(
                &mut frame,
                params,
                None,
                fp.as_bytes(),
                &mut |va, bytes| {
                    written = Some((va, bytes.to_vec()));
                    true
                },
            )
            .expect("setup_arm_signal_frame must succeed");
            let (written_va, written_bytes) = written.expect("signal frame bytes must be written");
            assert_eq!(written_va, handler_sp);
            let decoded = arm::SignalFrame::ref_from_bytes(&written_bytes).unwrap();
            (handler_sp.raw(), *decoded)
        };

        let altstack = AltStack {
            sp: 0x10_0000,
            size: 0x4000,
            flags: 0,
        };
        let main_sp = 0x20_0000_u64;

        // 1. SA_ONSTACK when off-altstack: frame is placed on altstack [0x10_0000, 0x10_4000),
        // while saved uc_mcontext.sp preserves the interrupted user SP (0x20_0000).
        let (onstack_handler_sp, onstack_frame) = deliver_case(altstack, true, main_sp);
        assert!(
            (0x10_0000..0x10_4000).contains(&onstack_handler_sp),
            "SA_ONSTACK handler SP {onstack_handler_sp:#x} must be placed on the alternate stack"
        );
        let saved_sp = onstack_frame.rt.ucontext.uc_mcontext.sp;
        let saved_pstate = onstack_frame.rt.ucontext.uc_mcontext.pstate;
        let saved_stack = onstack_frame.rt.ucontext.uc_stack;
        assert_eq!(
            saved_sp, main_sp,
            "uc_mcontext.sp under SA_ONSTACK must preserve interrupted user SP, not altstack top"
        );
        assert_eq!(saved_pstate, 0x6000_0000);
        let saved_stack_fields = (saved_stack.ss_sp, saved_stack.ss_size, saved_stack.ss_flags);
        assert_eq!(saved_stack_fields, (0x10_0000, 0x4000, 0));

        // 2. Counterexample: enabled altstack, but handler registered WITHOUT SA_ONSTACK:
        // frame is placed on the normal stack below main_sp, saved uc_mcontext.sp is main_sp,
        // and uc_stack still records the configured altstack without forcing altstack placement.
        let (non_onstack_sp, non_onstack_frame) = deliver_case(altstack, false, main_sp);
        assert!(
            non_onstack_sp < main_sp && non_onstack_sp > 0x1f_0000,
            "non-SA_ONSTACK handler SP {non_onstack_sp:#x} must stay on the interrupted stack"
        );
        let non_onstack_saved_sp = non_onstack_frame.rt.ucontext.uc_mcontext.sp;
        let non_onstack_stack = non_onstack_frame.rt.ucontext.uc_stack;
        assert_eq!(non_onstack_saved_sp, main_sp);
        let non_onstack_stack_fields = (
            non_onstack_stack.ss_sp,
            non_onstack_stack.ss_size,
            non_onstack_stack.ss_flags,
        );
        assert_eq!(non_onstack_stack_fields, (0x10_0000, 0x4000, 0));

        // 3. Nested SA_ONSTACK: interrupted SP is already on altstack (onstack_handler_sp).
        // Delivery must grow down from onstack_handler_sp (not reset to altstack top 0x10_4000),
        // preserve uc_mcontext.sp == onstack_handler_sp, and report SS_ONSTACK in uc_stack.ss_flags.
        let (nested_sp, nested_frame) = deliver_case(altstack, true, onstack_handler_sp);
        assert!(
            nested_sp < onstack_handler_sp && nested_sp >= 0x10_0000,
            "nested SA_ONSTACK SP {nested_sp:#x} must grow down from outer altstack SP {onstack_handler_sp:#x}"
        );
        let nested_saved_sp = nested_frame.rt.ucontext.uc_mcontext.sp;
        let nested_flags = nested_frame.rt.ucontext.uc_stack.ss_flags;
        assert_eq!(nested_saved_sp, onstack_handler_sp);
        assert_eq!(nested_flags, carrick_syscall_abi::LINUX_SS_ONSTACK as i32);

        // 4. Disabled altstack control: frame is placed below main_sp, uc_mcontext.sp == main_sp,
        // and uc_stack reports SS_DISABLE.
        let (disabled_sp, disabled_frame) = deliver_case(AltStack::DISABLED, true, main_sp);
        assert_eq!(disabled_sp, non_onstack_sp);
        let disabled_saved_sp = disabled_frame.rt.ucontext.uc_mcontext.sp;
        let disabled_flags = disabled_frame.rt.ucontext.uc_stack.ss_flags;
        assert_eq!(disabled_saved_sp, main_sp);
        assert_eq!(disabled_flags, carrick_syscall_abi::LINUX_SS_DISABLE as i32);
    }
}
