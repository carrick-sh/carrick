//! x86_64 signal frame setup and restoration for in-guest Linux personality.
use carrick_guest_arch::{
    ReturnKind, SignalBackend, SignalFrameParams, UserFlags, UserReturn, UserVa,
};

use crate::isa::ArchError;
use crate::isa::x86::X86Backend;
use crate::isa::x86::context::native::NativeFrame;

use carrick_syscall_abi::{
    LinuxSiginfo as Siginfo, X8664Rtsigframe as RtSigframe, X8664Ucontext as Ucontext,
};
use zerocopy::{FromBytes, IntoBytes};

impl X86Backend {
    #[inline(never)]
    pub fn setup_signal_frame_with_resume<'a>(
        &mut self,
        frame: &mut NativeFrame,
        params: SignalFrameParams,
        resume: UserReturn,
        siginfo: Option<&'a [u8]>,
        fpstate: &[u8],
        copy_out: &mut dyn FnMut(UserVa, &[u8]) -> bool,
    ) -> Result<UserVa, ArchError> {
        // 1. Determine stack location
        // On x86_64, user stack has a 128-byte red zone:
        const FP_BYTES: usize = carrick_sched_core::X86_XSAVE_BYTES;
        if fpstate.len() != FP_BYTES {
            return Err(ArchError::InvalidFrame);
        }
        let sp = params
            .sp
            .raw()
            .checked_sub(128)
            .ok_or(ArchError::InvalidFrame)?;
        let fp_address = sp
            .checked_sub((FP_BYTES + 4) as u64)
            .ok_or(ArchError::InvalidFrame)?
            & !63;
        let frame_size = core::mem::size_of::<RtSigframe>() as u64;
        let new_sp = (fp_address
            .checked_sub(frame_size)
            .ok_or(ArchError::InvalidFrame)?
            & !15)
            .checked_sub(8)
            .ok_or(ArchError::InvalidFrame)?;
        // Both syscall and page-fault delivery use this codec. Reject a guest
        // target before copying or publishing return words: the final return
        // validator protects supervisor invariants and must never see this fault.
        if !carrick_sched_core::valid_user_return_words(
            params.handler.raw(),
            new_sp,
            resume.flags.raw() & !((1 << 10) | (1 << 8)),
        ) {
            return Err(ArchError::InvalidFrame);
        }
        let mut fp_image = [0u8; FP_BYTES + 4];
        fp_image[..FP_BYTES].copy_from_slice(fpstate);
        fp_image[5] = 0; // reserved high byte of abridged x87 tag word
        for slot in 0..8 {
            fp_image[42 + slot * 16..48 + slot * 16].fill(0);
        }
        fp_image[416..464].fill(0);
        fp_image[520..576].fill(0);
        let descriptor = carrick_syscall_abi::X8664FpxSwBytes {
            magic1: carrick_syscall_abi::X8664_FP_XSTATE_MAGIC1,
            extended_size: (FP_BYTES + 4) as u32,
            xfeatures: 7,
            xstate_size: FP_BYTES as u32,
            reserved: [0; 7],
        };
        fp_image[464..512].copy_from_slice(descriptor.as_bytes());
        fp_image[FP_BYTES..]
            .copy_from_slice(&carrick_syscall_abi::X8664_FP_XSTATE_MAGIC2.to_le_bytes());

        // 2. Build the frame
        let mut rtsigframe = RtSigframe::empty();
        rtsigframe.pretcode = params.restorer.map_or(0, |r| r.raw());
        rtsigframe.uc.uc_flags = 1;
        rtsigframe.uc.uc_link = 0;
        rtsigframe.uc.uc_stack = params.stack;
        rtsigframe.uc.uc_sigmask = params.mask.signals().bits();

        // Populate uc_mcontext with current register values from frame
        rtsigframe.uc.uc_mcontext.r8 = frame.r8;
        rtsigframe.uc.uc_mcontext.r9 = frame.r9;
        rtsigframe.uc.uc_mcontext.r10 = frame.r10;
        rtsigframe.uc.uc_mcontext.r11 = frame.user_r11;
        rtsigframe.uc.uc_mcontext.r12 = frame.r12;
        rtsigframe.uc.uc_mcontext.r13 = frame.r13;
        rtsigframe.uc.uc_mcontext.r14 = frame.r14;
        rtsigframe.uc.uc_mcontext.r15 = frame.r15;
        rtsigframe.uc.uc_mcontext.rdi = frame.rdi;
        rtsigframe.uc.uc_mcontext.rsi = frame.rsi;
        rtsigframe.uc.uc_mcontext.rbp = frame.rbp;
        rtsigframe.uc.uc_mcontext.rbx = frame.rbx;
        rtsigframe.uc.uc_mcontext.rdx = frame.rdx;
        rtsigframe.uc.uc_mcontext.rax = frame.rax;
        rtsigframe.uc.uc_mcontext.rcx = frame.user_rcx;
        rtsigframe.uc.uc_mcontext.rsp = resume.stack.raw();
        rtsigframe.uc.uc_mcontext.rip = resume.pc.raw(); // saved RIP from syscall entry
        rtsigframe.uc.uc_mcontext.eflags = resume.flags.raw(); // saved RFLAGS from syscall entry
        rtsigframe.uc.uc_mcontext.cs = carrick_syscall_abi::LINUX_X8664_USER_CS;
        rtsigframe.uc.uc_mcontext.ss = carrick_syscall_abi::LINUX_X8664_USER_DS;
        rtsigframe.uc.uc_mcontext.fpstate = fp_address;

        // Populate siginfo
        if let Some(bytes) = siginfo {
            if let Ok(info) = Siginfo::read_from_bytes(bytes).map_err(|_| ArchError::InvalidFrame) {
                rtsigframe.info = info;
            }
        } else {
            let mut info = Siginfo::empty();
            info.si_signo = params.signal.number();
            info.si_code = params.sigcode;
            info.si_addr = params.fault_addr;
            rtsigframe.info = info;
        }

        // 3. Write frame to user stack
        let frame_bytes = rtsigframe.as_bytes();
        if !copy_out(UserVa::new(fp_address), &fp_image)
            || !copy_out(UserVa::new(new_sp), frame_bytes)
        {
            return Err(ArchError::InvalidFrame);
        }

        // 4. Set up registers for handler invocation
        let info_addr = new_sp + core::mem::offset_of!(RtSigframe, info) as u64;
        let uc_addr = new_sp + core::mem::offset_of!(RtSigframe, uc) as u64;

        frame.r11 = resume.flags.raw() & !((1 << 10) | (1 << 8));
        frame.rcx = params.handler.raw(); // user RIP
        frame.rsp = new_sp; // user RSP
        frame.rdi = params.signal.number() as u64; // arg 1: signum
        frame.rsi = info_addr; // arg 2: siginfo_t*
        frame.rdx = uc_addr; // arg 3: ucontext_t*
        frame.rax = 0;

        Ok(UserVa::new(new_sp))
    }
}

impl SignalBackend for X86Backend {
    fn setup_signal_frame<'a>(
        &mut self,
        frame: &mut NativeFrame,
        params: SignalFrameParams,
        siginfo: Option<&'a [u8]>,
        fpstate: &[u8],
        copy_out: &mut dyn FnMut(UserVa, &[u8]) -> bool,
    ) -> Result<UserVa, Self::Error> {
        self.setup_signal_frame_with_resume(
            frame,
            params,
            UserReturn {
                pc: UserVa::new(frame.rcx),
                stack: UserVa::new(frame.rsp),
                flags: UserFlags::new(frame.r11),
                kind: ReturnKind::ExceptionReturn,
            },
            siginfo,
            fpstate,
            copy_out,
        )
    }

    #[inline(never)]
    fn restore_signal_frame(
        &mut self,
        frame: &mut NativeFrame,
        fpstate: &mut [u8],
        copy_in: &mut dyn FnMut(&mut [u8], UserVa) -> bool,
    ) -> Result<carrick_signal_core::policy::SigBlockMask, Self::Error> {
        let uc_addr = UserVa::new(frame.rsp);
        let mut uc_bytes = [0u8; core::mem::size_of::<Ucontext>()];
        if !copy_in(&mut uc_bytes, uc_addr) {
            return Err(ArchError::InvalidFrame);
        }
        let Ok(uc) = Ucontext::read_from_bytes(&uc_bytes) else {
            return Err(ArchError::InvalidFrame);
        };

        let flags = carrick_sched_core::signal_return_flags(frame.r11, uc.uc_mcontext.eflags);
        if !carrick_sched_core::valid_user_return_words(
            uc.uc_mcontext.rip,
            uc.uc_mcontext.rsp,
            flags,
        ) {
            return Err(ArchError::InvalidFrame);
        }

        const FP_BYTES: usize = carrick_sched_core::X86_XSAVE_BYTES;
        if fpstate.len() != FP_BYTES {
            return Err(ArchError::InvalidFrame);
        }
        let mut restored_fp = [0u8; FP_BYTES];
        let fp_address = uc.uc_mcontext.fpstate;
        if fp_address == 0 {
            // Missing fpstate restores architectural initial x87/SSE state.
            restored_fp[..2].copy_from_slice(&0x037fu16.to_le_bytes());
            restored_fp[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
            restored_fp[512..520].copy_from_slice(&3u64.to_le_bytes());
        } else {
            if !copy_in(&mut restored_fp[..512], UserVa::new(fp_address)) {
                return Err(ArchError::InvalidFrame);
            }
            let descriptor =
                carrick_syscall_abi::X8664FpxSwBytes::read_from_bytes(&restored_fp[464..512])
                    .map_err(|_| ArchError::InvalidFrame)?;
            if descriptor.magic1 == carrick_syscall_abi::X8664_FP_XSTATE_MAGIC1 {
                if descriptor.xstate_size != FP_BYTES as u32
                    || descriptor.extended_size != (FP_BYTES + 4) as u32
                    || descriptor.xfeatures & !7 != 0
                {
                    return Err(ArchError::InvalidFrame);
                }
                let tail = fp_address.checked_add(512).ok_or(ArchError::InvalidFrame)?;
                let mut extended = [0u8; FP_BYTES - 512 + 4];
                if !copy_in(&mut extended, UserVa::new(tail))
                    || extended[FP_BYTES - 512..]
                        != carrick_syscall_abi::X8664_FP_XSTATE_MAGIC2.to_le_bytes()
                {
                    return Err(ArchError::InvalidFrame);
                }
                restored_fp[512..].copy_from_slice(&extended[..FP_BYTES - 512]);
                let mut feature_bytes = [0; 8];
                feature_bytes.copy_from_slice(&restored_fp[512..520]);
                if u64::from_le_bytes(feature_bytes) & !7 != 0
                    || restored_fp[520..576].iter().any(|byte| *byte != 0)
                {
                    return Err(ArchError::InvalidFrame);
                }
            } else if descriptor.magic1 == 0 {
                restored_fp[512..520].copy_from_slice(&3u64.to_le_bytes());
            } else {
                return Err(ArchError::InvalidFrame);
            }
            let mut mxcsr_bytes = [0; 4];
            mxcsr_bytes.copy_from_slice(&restored_fp[24..28]);
            let mut mask_bytes = [0; 4];
            mask_bytes.copy_from_slice(&fpstate[28..32]);
            let mask = u32::from_le_bytes(mask_bytes);
            let mask = if mask == 0 { 0xffbf } else { mask };
            if u32::from_le_bytes(mxcsr_bytes) & !mask != 0 {
                return Err(ArchError::InvalidFrame);
            }
        }
        fpstate.copy_from_slice(&restored_fp);

        // Publish only after all guest-controlled resume words have passed validation.
        frame.r8 = uc.uc_mcontext.r8;
        frame.r9 = uc.uc_mcontext.r9;
        frame.r10 = uc.uc_mcontext.r10;
        frame.r11 = flags;
        frame.user_r11 = uc.uc_mcontext.r11;
        frame.r12 = uc.uc_mcontext.r12;
        frame.r13 = uc.uc_mcontext.r13;
        frame.r14 = uc.uc_mcontext.r14;
        frame.r15 = uc.uc_mcontext.r15;
        frame.rdi = uc.uc_mcontext.rdi;
        frame.rsi = uc.uc_mcontext.rsi;
        frame.rbp = uc.uc_mcontext.rbp;
        frame.rbx = uc.uc_mcontext.rbx;
        frame.rdx = uc.uc_mcontext.rdx;
        frame.rax = uc.uc_mcontext.rax;
        frame.rcx = uc.uc_mcontext.rip;
        frame.user_rcx = uc.uc_mcontext.rcx;
        frame.rsp = uc.uc_mcontext.rsp;

        Ok(carrick_signal_core::policy::SigBlockMask::blocking_all_of(
            carrick_signal_core::SignalSet::from_bits(uc.uc_sigmask),
        ))
    }
}
