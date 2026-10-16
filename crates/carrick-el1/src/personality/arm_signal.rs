//! Pure ARM frame publication used by the native backend and VM-free tests.
use crate::isa::ArchError;
#[cfg(target_os = "none")]
use crate::rust_alloc::vec::Vec;
use carrick_el1_abi::TrapFrame;
use carrick_personality_linux::signal::arm::{self, RtSigframe};
#[cfg(not(target_os = "none"))]
use std::vec::Vec;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
struct ArmSignalMachine {
    backend: crate::isa::aarch64::Aarch64Backend,
    user_sp: carrick_guest_arch::UserVa,
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl super::signal_delivery::SignalMachine<carrick_sched_core::Aarch64ParkedContext>
    for ArmSignalMachine
{
    type Backend = crate::isa::aarch64::Aarch64Backend;

    fn backend(&mut self) -> &mut Self::Backend {
        &mut self.backend
    }

    fn user_sp(&self, _frame: &TrapFrame) -> carrick_guest_arch::UserVa {
        self.user_sp
    }

    fn restart(
        &self,
        frame: &mut TrapFrame,
        original: carrick_sched_core::Aarch64ParkedContext,
    ) -> bool {
        frame.x[0] = original.syscall_return();
        if let Some(pc) = frame.elr.checked_sub(4) {
            frame.elr = pc;
            true
        } else {
            false
        }
    }

    fn group_exit_custody(
        &self,
        _task: &carrick_el1_abi::CurrentTask,
    ) -> carrick_personality_linux::dispatch::CompletionRoute {
        carrick_personality_linux::dispatch::CompletionRoute::InvalidCompletion
    }
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

    let mut saved = crate::rust_alloc::boxed::Box::new(carrick_el1_abi::Aarch64ParkedContext::ZERO);
    crate::sched::HardwareCpu.save(frame, &mut saved);
    let mut fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
    fp.vregs = saved.native.v;
    fp.fpsr = saved.native.fpsr as u32;
    fp.fpcr = saved.native.fpcr as u32;
    let sp = unsafe { crate::isa::aarch64::signal_stack() };
    super::signal_delivery::deliver_signal_on_syscall_return(
        task,
        process,
        frame,
        fp.as_bytes(),
        &mut ArmSignalMachine {
            backend: crate::isa::aarch64::Aarch64Backend,
            user_sp: sp,
        },
    )
}

pub(crate) fn restore(
    frame: &mut TrapFrame,
    signal: &RtSigframe,
    fpstate: &mut [u8],
    signal_sp: carrick_guest_arch::UserVa,
) -> Result<(u64, u64), ArchError> {
    use zerocopy::IntoBytes;
    let resume =
        arm::decode(signal.as_bytes(), signal_sp, true).map_err(|_| ArchError::InvalidFrame)?;
    let fp = resume.fpsimd.ok_or(ArchError::InvalidFrame)?;
    if fpstate.len() != fp.as_bytes().len() {
        return Err(ArchError::InvalidFrame);
    }
    fpstate.copy_from_slice(fp.as_bytes());
    frame.x = resume.regs;
    frame.elr = resume.pc.raw();
    frame.spsr = resume.pstate;
    Ok((resume.mask.signals().bits(), resume.sp.raw()))
}

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
pub(crate) fn apply_restored_context(
    context: &mut carrick_sched_core::ThreadCtx,
    frame: &TrapFrame,
    fp: &carrick_syscall_abi::LinuxFpsimdContext,
    sp: u64,
) {
    context.x = frame.x;
    context.pc = frame.elr;
    context.pstate = frame.spsr;
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
) -> Result<carrick_signal_core::policy::SigBlockMask, carrick_syscall_abi::LinuxErrno> {
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
    let mask = crate::isa::aarch64::Aarch64Backend
        .restore_signal_frame(frame, fp.as_mut_bytes(), &mut |dst, src| {
            copy_in.copy_in(dst, src)
        })
        .map_err(|_| carrick_syscall_abi::LINUX_EFAULT)?;
    // restore_signal_frame validates and then publishes SP_EL0. Re-read it
    // only after success; a failed copy leaves the saved hardware untouched.
    let restored_sp = unsafe { crate::isa::aarch64::signal_stack().raw() };
    apply_restored_context(&mut saved.native, frame, &fp, restored_sp);
    crate::sched::HardwareCpu.load(frame, &saved);
    Ok(mask)
}

pub(crate) fn build(
    frame: &TrapFrame,
    params: carrick_personality_linux::signal::SignalFrameParams,
    siginfo: Option<&[u8]>,
    fpstate: &[u8],
) -> Result<(carrick_guest_arch::UserVa, arm::SignalFrame), ArchError> {
    use carrick_syscall_abi::{LinuxFpsimdContext, LinuxSiginfo, LinuxSignalContext};
    use zerocopy::{FromBytes, IntoBytes};
    let fp = LinuxFpsimdContext::read_from_bytes(fpstate).map_err(|_| ArchError::InvalidFrame)?;
    let mut context = LinuxSignalContext::empty();
    context.regs = frame.x;
    context.pc = frame.elr;
    context.sp = params.sp.raw();
    context.pstate = frame.spsr;
    context.fault_address = params.fault_addr;
    let info = if let Some(bytes) = siginfo {
        LinuxSiginfo::read_from_bytes(bytes).map_err(|_| ArchError::InvalidFrame)?
    } else {
        let mut info = LinuxSiginfo::empty();
        info.si_signo = params.signal.number();
        info.si_code = params.sigcode;
        info.si_addr = params.fault_addr;
        info
    };
    let signal = arm::encode(context, params.stack, params.mask, info, Some(fp), None)
        .map_err(|_| ArchError::InvalidFrame)?;
    let sp = arm::stack_pointer(params.sp, None, signal.as_bytes().len())
        .map_err(|_| ArchError::InvalidFrame)?;
    Ok((sp, signal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_guest_arch::UserVa;
    use carrick_syscall_abi::LinuxFpsimdContext;
    use zerocopy::IntoBytes;
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
            handler: UserVa::new(0x30000),
            restorer: Some(UserVa::new(0x40000)),
            mask: carrick_signal_core::policy::SigBlockMask::blocking_all_of(
                carrick_signal_core::SignalSet::from_bits(8),
            ),
        };
        let (sp, signal) = build(&frame, params, None, fp.as_bytes()).unwrap();
        assert_eq!(sp.raw() & 15, 0);
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
        let saved_pc = without_restorer.rt.ucontext.uc_mcontext.pc;
        assert_eq!(saved_pc, frame.elr);
    }

    #[test]
    fn ucontext_is_the_resume_authority() {
        let signal = valid();
        let mut frame = TrapFrame::default();
        let (_, sp) = restore(&mut frame, &signal, &mut [0; 528], UserVa::new(0x40000)).unwrap();
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
        assert_eq!(restored_stack.sp, 0x10_0000);
        assert_eq!(restored_stack.size, 8192);
        assert_eq!(restored_stack.flags, carrick_syscall_abi::LINUX_SS_AUTODISARM as u32);
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
        let (_, sp) = restore(&mut frame, &signal, &mut output, UserVa::new(0x40000))
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
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
use carrick_guest_arch::UserVa;
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
use zerocopy::{FromBytes, IntoBytes};

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl carrick_personality_linux::signal::SignalBackend for crate::isa::aarch64::Aarch64Backend {
    fn setup_signal_frame<'a>(
        &mut self,
        frame: &mut TrapFrame,
        params: carrick_personality_linux::signal::SignalFrameParams,
        siginfo: Option<&'a [u8]>,
        _fpstate: &[u8],
        copy_out: &mut dyn FnMut(UserVa, &[u8]) -> bool,
    ) -> Result<UserVa, Self::Error> {
        let (sp, sigframe) = build(frame, params, siginfo, _fpstate)?;
        let new_sp = sp.raw();

        let frame_bytes = sigframe.as_bytes();
        if !copy_out(UserVa::new(new_sp), frame_bytes) {
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
            crate::isa::aarch64::set_signal_stack(UserVa::new(new_sp));
        }

        Ok(UserVa::new(new_sp))
    }

    fn restore_signal_frame(
        &mut self,
        frame: &mut TrapFrame,
        _fpstate: &mut [u8],
        copy_in: &mut dyn FnMut(&mut [u8], UserVa) -> bool,
    ) -> Result<carrick_signal_core::policy::SigBlockMask, Self::Error> {
        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        let sp_val = { unsafe { crate::isa::aarch64::signal_stack().raw() } };
        #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
        let sp_val = 0u64;

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

        let (mask, saved_sp) = restore(frame, sigframe, _fpstate, sp)?;

        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        unsafe {
            crate::isa::aarch64::set_signal_stack(UserVa::new(saved_sp));
        }

        Ok(carrick_signal_core::policy::SigBlockMask::blocking_all_of(
            carrick_signal_core::SignalSet::from_bits(mask),
        ))
    }
}
