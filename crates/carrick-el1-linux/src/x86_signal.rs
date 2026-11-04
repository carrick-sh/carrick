//! x86_64 signal frame setup and restoration for in-guest Linux personality.
use carrick_guest_arch::{ReturnKind, UserFlags, UserReturn, UserVa};
#[cfg(target_os = "none")]
use carrick_personality_linux::signal::SignalBackend;
use carrick_personality_linux::signal::SignalFrameParams;

use carrick_el1::isa::ArchError;
#[cfg(target_os = "none")]
use carrick_el1::isa::x86::X86Backend;
#[cfg(target_os = "none")]
use carrick_el1::isa::x86::context::native::NativeFrame;

// Compile the production frame record and codec in the VM-free suite too.
#[cfg(test)]
#[path = "../../carrick-x86/src/cpl0_entry.rs"]
#[allow(dead_code)]
mod native_test_frame;
#[cfg(test)]
use native_test_frame::NativeFrame;

use carrick_syscall_abi::{
    LinuxSiginfo as Siginfo, X8664Rtsigframe as RtSigframe, X8664Ucontext as Ucontext,
};
use zerocopy::{FromBytes, IntoBytes};

/// The Linux signal-frame codec over the neutral x86 backend's types.
pub struct LinuxX86Backend;

#[cfg(target_os = "none")]
impl carrick_guest_arch::ArchTypes for LinuxX86Backend {
    type Error = <X86Backend as carrick_guest_arch::ArchTypes>::Error;
    type NativeFrame = <X86Backend as carrick_guest_arch::ArchTypes>::NativeFrame;
    type SavedContext = <X86Backend as carrick_guest_arch::ArchTypes>::SavedContext;
    type Context = <X86Backend as carrick_guest_arch::ArchTypes>::Context;
    type Root = <X86Backend as carrick_guest_arch::ArchTypes>::Root;
    type MmOwner = <X86Backend as carrick_guest_arch::ArchTypes>::MmOwner;
    type DrainTicket = <X86Backend as carrick_guest_arch::ArchTypes>::DrainTicket;
    type DrainReceipt = <X86Backend as carrick_guest_arch::ArchTypes>::DrainReceipt;
    type UserTransfer = <X86Backend as carrick_guest_arch::ArchTypes>::UserTransfer;
    type HardwareInterrupt = <X86Backend as carrick_guest_arch::ArchTypes>::HardwareInterrupt;
    type InterruptMask = <X86Backend as carrick_guest_arch::ArchTypes>::InterruptMask;
}

impl LinuxX86Backend {
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

#[cfg(target_os = "none")]
impl SignalBackend for LinuxX86Backend {
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

    fn restore_signal_frame(
        &mut self,
        frame: &mut NativeFrame,
        fpstate: &mut [u8],
        copy_in: &mut dyn FnMut(&mut [u8], UserVa) -> bool,
    ) -> Result<carrick_personality_linux::signal::RestoredSignalFrame, Self::Error> {
        self.restore_frame(frame, fpstate, copy_in)
    }
}

impl LinuxX86Backend {
    #[inline(never)]
    fn restore_frame(
        &mut self,
        frame: &mut NativeFrame,
        fpstate: &mut [u8],
        copy_in: &mut dyn FnMut(&mut [u8], UserVa) -> bool,
    ) -> Result<carrick_personality_linux::signal::RestoredSignalFrame, ArchError> {
        let uc_addr = UserVa::new(frame.rsp);
        let mut uc_bytes = [0u8; core::mem::size_of::<Ucontext>()];
        if !copy_in(&mut uc_bytes, uc_addr) {
            return Err(ArchError::InvalidFrame);
        }
        let Ok(uc) = Ucontext::read_from_bytes(&uc_bytes) else {
            return Err(ArchError::InvalidFrame);
        };
        let stack = carrick_personality_linux::signal::restored_altstack(
            uc.uc_stack,
            carrick_guest_arch::GuestIsa::X86_64,
        )
        .ok_or(ArchError::InvalidFrame)?;

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

        Ok(carrick_personality_linux::signal::RestoredSignalFrame {
            mask: carrick_signal_core::policy::SigBlockMask::blocking_all_of(
                carrick_signal_core::SignalSet::from_bits(uc.uc_sigmask),
            ),
            stack,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_guest_arch::{X86Register, X86Registers};
    use carrick_signal_core::policy::{SigBlockMask, Signal};

    const STACK_BASE: usize = 0x10_000;
    const STACK_TOP: usize = 0x14_000;
    const FP_BYTES: usize = carrick_sched_core::X86_XSAVE_BYTES;

    fn interrupted() -> NativeFrame {
        NativeFrame {
            r15: 15,
            r14: 14,
            r13: 13,
            r12: 12,
            rbp: 6,
            rbx: 3,
            r9: 9,
            r8: 8,
            r10: 10,
            rdx: 2,
            rsi: 4,
            rdi: 5,
            rax: 1,
            rcx: 0x40_1000,
            r11: 0x202,
            rsp: STACK_TOP as u64,
            user_rcx: 0x1234,
            user_r11: 0x5678,
        }
    }

    fn xstate() -> [u8; FP_BYTES] {
        let mut state = [0; FP_BYTES];
        state[..2].copy_from_slice(&0x027fu16.to_le_bytes());
        state[2..4].copy_from_slice(&0x2800u16.to_le_bytes());
        state[4] = 0xff;
        state[24..28].copy_from_slice(&0x5f80u32.to_le_bytes());
        state[28..32].copy_from_slice(&0xffffu32.to_le_bytes());
        for slot in 0..8 {
            state[32 + slot * 16..42 + slot * 16].fill(0x10 + slot as u8);
        }
        for register in 0..16 {
            state[160 + register * 16..176 + register * 16].fill(0x40 + register as u8);
            state[576 + register * 16..592 + register * 16].fill(0x80 + register as u8);
        }
        state[512..520].copy_from_slice(&7u64.to_le_bytes());
        state
    }

    fn publish(frame: &mut NativeFrame, fp: &[u8]) -> (Vec<u8>, usize) {
        let mut memory = vec![0; STACK_TOP - STACK_BASE];
        let params = SignalFrameParams {
            stack: carrick_syscall_abi::LinuxSignalStack {
                ss_flags: carrick_syscall_abi::LINUX_SS_DISABLE as i32,
                ..carrick_syscall_abi::LinuxSignalStack::empty()
            },
            signal: Signal::from_number(10).unwrap(),
            sigcode: 0,
            fault_addr: 0,
            sp: UserVa::new(frame.rsp),
            interrupted_sp: UserVa::new(frame.rsp),
            handler: UserVa::new(0x40_2000),
            restorer: Some(UserVa::new(0x40_3000)),
            mask: SigBlockMask::blocking_all_of(carrick_signal_core::SignalSet::from_bits(1 << 9)),
        };
        let resume = UserReturn {
            pc: UserVa::new(frame.rcx),
            stack: UserVa::new(frame.rsp),
            flags: UserFlags::new(frame.r11),
            kind: ReturnKind::ExceptionReturn,
        };
        let mut copies = Vec::new();
        let sp = LinuxX86Backend
            .setup_signal_frame_with_resume(
                frame,
                params,
                resume,
                None,
                fp,
                &mut |address, bytes| {
                    let start = address.raw() as usize - STACK_BASE;
                    memory[start..start + bytes.len()].copy_from_slice(bytes);
                    copies.push(bytes.len());
                    true
                },
            )
            .unwrap();
        assert_eq!(copies, [FP_BYTES + 4, core::mem::size_of::<RtSigframe>()]);
        assert_eq!(sp.raw() & 15, 8);
        // The handler's RET consumes pretcode before rt_sigreturn reads uc.
        frame.rsp = sp.raw() + 8;
        let uc_start = frame.rsp as usize - STACK_BASE;
        let uc = Ucontext::read_from_bytes(
            &memory[uc_start..uc_start + core::mem::size_of::<Ucontext>()],
        )
        .unwrap();
        let fp_start = uc.uc_mcontext.fpstate as usize - STACK_BASE;
        assert_eq!((fp_start + STACK_BASE) & 63, 0);
        (memory, fp_start)
    }

    fn restore(
        frame: &mut NativeFrame,
        fp: &mut [u8],
        memory: &[u8],
    ) -> Result<carrick_personality_linux::signal::RestoredSignalFrame, ArchError> {
        LinuxX86Backend.restore_frame(frame, fp, &mut |bytes, address| {
            let Some(start) = (address.raw() as usize).checked_sub(STACK_BASE) else {
                return false;
            };
            let Some(source) = memory.get(start..start + bytes.len()) else {
                return false;
            };
            bytes.copy_from_slice(source);
            true
        })
    }

    #[test]
    fn signal_frame_round_trip_preserves_gprs_x87_sse_and_avx() {
        let original = interrupted();
        let fp = xstate();
        let mut frame = original;
        let (memory, _) = publish(&mut frame, &fp);
        frame = NativeFrame {
            rsp: frame.rsp,
            r11: frame.r11,
            r15: 115,
            r14: 114,
            r13: 113,
            r12: 112,
            rbp: 106,
            rbx: 103,
            r9: 109,
            r8: 108,
            r10: 110,
            rdx: 102,
            rsi: 104,
            rdi: 105,
            rax: 101,
            rcx: 0x40_4000,
            user_rcx: 0xaaaa,
            user_r11: 0xbbbb,
        };
        let mut returned_fp = [0xee; FP_BYTES];
        // The live CPU's MXCSR capability mask is an input to validation.
        returned_fp[28..32].copy_from_slice(&fp[28..32]);
        let result = restore(&mut frame, &mut returned_fp, &memory).unwrap();
        for register in [
            X86Register::Rax,
            X86Register::Rbx,
            X86Register::Rcx,
            X86Register::Rdx,
            X86Register::Rsi,
            X86Register::Rdi,
            X86Register::Rbp,
            X86Register::Rsp,
            X86Register::R8,
            X86Register::R9,
            X86Register::R10,
            X86Register::R11,
            X86Register::R12,
            X86Register::R13,
            X86Register::R14,
            X86Register::R15,
        ] {
            assert_eq!(
                frame.read(register),
                original.read(register),
                "{register:?}"
            );
        }
        assert_eq!(frame.user_rcx, original.user_rcx);
        assert_eq!(frame.user_r11, original.user_r11);
        assert_eq!(&returned_fp[..464], &fp[..464]);
        assert_eq!(&returned_fp[512..], &fp[512..]);
        assert_eq!(result.mask.signals().bits(), 1 << 9);
    }

    #[test]
    fn invalid_signal_xstate_does_not_publish_registers_or_fp_state() {
        for corruption in [24, 512, 520, FP_BYTES] {
            let mut frame = interrupted();
            let (mut memory, fp_start) = publish(&mut frame, &xstate());
            // Invalid MXCSR, unsupported xfeature, reserved header, bad magic2.
            if corruption == 24 {
                memory[fp_start + 27] = 0x80;
            } else {
                memory[fp_start + corruption] ^= 0x80;
            }
            let before = format!("{frame:?}");
            let mut fp = xstate();
            assert!(matches!(
                restore(&mut frame, &mut fp, &memory),
                Err(ArchError::InvalidFrame)
            ));
            assert_eq!(format!("{frame:?}"), before);
            assert_eq!(fp, xstate());
        }
    }
}
