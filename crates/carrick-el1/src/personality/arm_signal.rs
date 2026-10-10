//! Pure ARM frame publication used by the native backend and VM-free tests.
use crate::isa::ArchError;
use carrick_el1_abi::TrapFrame;
use carrick_syscall_abi::CarrickSigframe;

pub(crate) fn restore(
    frame: &mut TrapFrame,
    signal: &CarrickSigframe,
    fpstate: &mut [u8],
) -> Result<(u64, u64), ArchError> {
    use carrick_syscall_abi::{CARRICK_SIGFRAME_MAGIC, LINUX_FPSIMD_MAGIC, LinuxFpsimdContext};
    use zerocopy::FromBytes;
    let context = signal.ucontext.uc_mcontext;
    let fp_len = core::mem::size_of::<LinuxFpsimdContext>();
    let fp_bytes = &context.__reserved[..fp_len];
    let fp = LinuxFpsimdContext::read_from_bytes(fp_bytes).map_err(|_| ArchError::InvalidFrame)?;
    // Validate the entire record before publishing registers or SIMD state.
    if signal.magic != CARRICK_SIGFRAME_MAGIC
        || !crate::isa::signal_resume_is_el0(context.pstate)
        || fp.magic != LINUX_FPSIMD_MAGIC
        || fp.size as usize != fp_len
        || fpstate.len() != fp_len
        || context.sp & 15 != 0
        || context.pc & 3 != 0
    {
        return Err(ArchError::InvalidFrame);
    }
    fpstate.copy_from_slice(fp_bytes);
    frame.x = context.regs;
    frame.elr = context.pc;
    frame.spsr = context.pstate;
    Ok((signal.ucontext.uc_sigmask, context.sp))
}

pub(crate) fn build(
    frame: &TrapFrame,
    params: carrick_guest_arch::SignalFrameParams,
    siginfo: Option<&[u8]>,
    fpstate: &[u8],
) -> Result<(carrick_guest_arch::UserVa, CarrickSigframe), ArchError> {
    use carrick_syscall_abi::{LINUX_FPSIMD_MAGIC, LinuxFpsimdContext, LinuxSiginfo};
    use zerocopy::FromBytes;
    let fp = LinuxFpsimdContext::read_from_bytes(fpstate).map_err(|_| ArchError::InvalidFrame)?;
    if !crate::isa::signal_resume_is_el0(frame.spsr)
        || fp.magic != LINUX_FPSIMD_MAGIC
        || fp.size as usize != core::mem::size_of::<LinuxFpsimdContext>()
        || params.restorer.is_none()
    {
        return Err(ArchError::InvalidFrame);
    }
    let new_sp = params
        .sp
        .raw()
        .checked_sub(core::mem::size_of::<CarrickSigframe>() as u64)
        .ok_or(ArchError::InvalidFrame)?
        & !15;
    let mut signal = CarrickSigframe::empty();
    signal.signum = params.signal.number() as u32;
    signal.saved_pc = frame.elr;
    signal.saved_spsr = frame.spsr;
    signal.saved_sp = params.sp.raw();
    signal.saved_x = frame.x;
    signal.ucontext.uc_sigmask = params.mask.signals().bits();
    signal.ucontext.uc_stack = params.stack;
    signal.ucontext.uc_mcontext.regs = frame.x;
    signal.ucontext.uc_mcontext.pc = frame.elr;
    signal.ucontext.uc_mcontext.sp = params.sp.raw();
    signal.ucontext.uc_mcontext.pstate = frame.spsr;
    signal.ucontext.uc_mcontext.fault_address = params.fault_addr;
    signal.ucontext.uc_mcontext.__reserved[..fpstate.len()].copy_from_slice(fpstate);
    signal._reserved[0] = frame.x[29];
    signal._reserved[1] = frame.x[30];
    signal.siginfo = if let Some(bytes) = siginfo {
        LinuxSiginfo::read_from_bytes(bytes).map_err(|_| ArchError::InvalidFrame)?
    } else {
        let mut info = LinuxSiginfo::empty();
        info.si_signo = params.signal.number();
        info.si_code = params.sigcode;
        info.si_addr = params.fault_addr;
        info
    };
    Ok((carrick_guest_arch::UserVa::new(new_sp), signal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_syscall_abi::{CARRICK_SIGFRAME_MAGIC, LinuxFpsimdContext};
    use zerocopy::IntoBytes;
    fn valid() -> CarrickSigframe {
        let mut signal = CarrickSigframe::empty();
        signal.magic = CARRICK_SIGFRAME_MAGIC;
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
        use carrick_guest_arch::{SignalFrameParams, UserVa};
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
        let context = signal.ucontext.uc_mcontext;
        let regs = context.regs;
        assert_eq!(regs[0], 42);
        let record = signal._reserved;
        assert_eq!(&record[..2], &[0x8000, 0x9000]);
        assert_eq!(&context.__reserved[..528], fp.as_bytes());
        assert_eq!(&context.__reserved[528..536], &[0; 8]);
        let mask = signal.ucontext.uc_sigmask;
        assert_eq!(mask, 8);
        assert!(
            build(
                &frame,
                SignalFrameParams {
                    restorer: None,
                    ..params
                },
                None,
                fp.as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn ucontext_is_the_resume_authority() {
        let signal = valid();
        let mut frame = TrapFrame::default();
        let (_, sp) = restore(&mut frame, &signal, &mut [0; 528]).unwrap();
        assert_eq!(frame.x[0], 0x1234);
        assert_eq!(frame.elr, 0x10000);
        assert_eq!(sp, 0x20000);
    }
    #[test]
    fn forged_ucontext_el1_is_refused_without_publication() {
        let mut signal = valid();
        signal.ucontext.uc_mcontext.pstate = 5;
        let mut frame = TrapFrame::default();
        let original = frame;
        assert_eq!(
            restore(&mut frame, &signal, &mut [0; 528]),
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
            assert!(restore(&mut TrapFrame::default(), &signal, &mut output).is_err());
            assert!(output.iter().all(|byte| *byte == 0x55));
        }
        let mut signal = valid();
        signal.ucontext.uc_mcontext.__reserved[4..8].copy_from_slice(&0_u32.to_le_bytes());
        assert!(restore(&mut TrapFrame::default(), &signal, &mut [0; 528]).is_err());
    }

    #[test]
    fn frame_and_fpsimd_magic_are_required() {
        let mut signal = valid();
        let mut frame = TrapFrame::default();
        signal.magic = 0;
        assert!(restore(&mut frame, &signal, &mut [0; 528]).is_err());
        signal.magic = CARRICK_SIGFRAME_MAGIC;
        signal.ucontext.uc_mcontext.__reserved[0] ^= 1;
        assert!(restore(&mut frame, &signal, &mut [0; 528]).is_err());
    }
    #[test]
    fn fpsimd_payload_is_restored() {
        let mut signal = valid();
        let mut fp = LinuxFpsimdContext::empty();
        fp.vregs[7] = 0xabc;
        let len = fp.as_bytes().len();
        signal.ucontext.uc_mcontext.__reserved[..len].copy_from_slice(fp.as_bytes());
        let mut output = [0; 528];
        restore(&mut TrapFrame::default(), &signal, &mut output).unwrap();
        assert_eq!(output.as_slice(), fp.as_bytes());
    }
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
use carrick_guest_arch::UserVa;
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
use carrick_syscall_abi::CarrickSigframe as Arm64Sigframe;
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
use zerocopy::{FromBytes, IntoBytes};

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
impl carrick_guest_arch::SignalBackend for crate::isa::aarch64::Aarch64Backend {
    fn setup_signal_frame<'a>(
        &mut self,
        frame: &mut TrapFrame,
        params: carrick_guest_arch::SignalFrameParams,
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

        let info_addr = new_sp + core::mem::offset_of!(Arm64Sigframe, siginfo) as u64;
        let uc_addr = new_sp + core::mem::offset_of!(Arm64Sigframe, ucontext) as u64;

        frame.elr = params.handler.raw();
        frame.x[0] = params.signal.number() as u64;
        frame.x[1] = info_addr;
        frame.x[2] = uc_addr;
        frame.x[29] = new_sp + core::mem::offset_of!(Arm64Sigframe, _reserved) as u64;
        frame.x[30] = params.restorer.ok_or(ArchError::InvalidFrame)?.raw();

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
        let mut bytes = [0u8; core::mem::size_of::<Arm64Sigframe>()];
        if !copy_in(&mut bytes, sp) {
            return Err(ArchError::InvalidFrame);
        }
        let Some(sigframe) = Arm64Sigframe::read_from_bytes(&bytes).ok() else {
            return Err(ArchError::InvalidFrame);
        };

        let (mask, saved_sp) = restore(frame, &sigframe, _fpstate)?;

        #[cfg(all(target_os = "none", target_arch = "aarch64"))]
        unsafe {
            crate::isa::aarch64::set_signal_stack(UserVa::new(saved_sp));
        }

        Ok(carrick_signal_core::policy::SigBlockMask::blocking_all_of(
            carrick_signal_core::SignalSet::from_bits(mask),
        ))
    }
}
