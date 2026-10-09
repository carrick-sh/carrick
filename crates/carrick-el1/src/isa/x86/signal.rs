//! x86_64 signal frame setup and restoration for in-guest Linux personality.
use carrick_guest_arch::{SignalBackend, SignalFrameParams, UserVa};

use super::X86Backend;
use super::context::native::NativeFrame;
use crate::isa::ArchError;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Siginfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub _pad0: i32,
    pub si_addr: u64,
    pub _pad: [u8; 128 - 24],
}

impl Siginfo {
    pub const fn empty() -> Self {
        Self {
            si_signo: 0,
            si_errno: 0,
            si_code: 0,
            _pad0: 0,
            si_addr: 0,
            _pad: [0; 128 - 24],
        }
    }

    pub fn ref_from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() >= core::mem::size_of::<Self>() {
            Some(unsafe { &*(bytes.as_ptr() as *const Self) })
        } else {
            None
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalStack {
    pub ss_sp: u64,
    pub ss_flags: i32,
    pub _pad0: u32,
    pub ss_size: u64,
}

impl SignalStack {
    pub const fn empty() -> Self {
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
pub struct Sigcontext {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub eflags: u64,
    pub cs: u16,
    pub gs: u16,
    pub fs: u16,
    pub ss: u16,
    pub err: u64,
    pub trapno: u64,
    pub oldmask: u64,
    pub cr2: u64,
    pub fpstate: u64,
    pub reserved: [u64; 8],
}

impl Sigcontext {
    pub const fn empty() -> Self {
        Self {
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rdi: 0,
            rsi: 0,
            rbp: 0,
            rbx: 0,
            rdx: 0,
            rax: 0,
            rcx: 0,
            rsp: 0,
            rip: 0,
            eflags: 0,
            cs: 0,
            gs: 0,
            fs: 0,
            ss: 0,
            err: 0,
            trapno: 0,
            oldmask: 0,
            cr2: 0,
            fpstate: 0,
            reserved: [0; 8],
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ucontext {
    pub uc_flags: u64,
    pub uc_link: u64,
    pub uc_stack: SignalStack,
    pub uc_mcontext: Sigcontext,
    pub uc_sigmask: u64,
}

impl Ucontext {
    pub const fn empty() -> Self {
        Self {
            uc_flags: 0,
            uc_link: 0,
            uc_stack: SignalStack::empty(),
            uc_mcontext: Sigcontext::empty(),
            uc_sigmask: 0,
        }
    }

    pub fn ref_from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() >= core::mem::size_of::<Self>() {
            Some(unsafe { &*(bytes.as_ptr() as *const Self) })
        } else {
            None
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtSigframe {
    pub pretcode: u64,
    pub uc: Ucontext,
    pub info: Siginfo,
    pub fpstate_pad: [u8; 16],
    pub fpstate: [u8; 0],
}

impl RtSigframe {
    pub const fn empty() -> Self {
        Self {
            pretcode: 0,
            uc: Ucontext::empty(),
            info: Siginfo::empty(),
            fpstate_pad: [0; 16],
            fpstate: [],
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}

impl SignalBackend for X86Backend {
    #[inline(never)]
    fn setup_signal_frame<'a>(
        &mut self,
        frame: &mut NativeFrame,
        params: SignalFrameParams,
        siginfo: Option<&'a [u8]>,
        copy_out: &mut dyn FnMut(UserVa, &[u8]) -> bool,
    ) -> Result<UserVa, Self::Error> {
        // 1. Determine stack location
        // On x86_64, user stack has a 128-byte red zone:
        let sp = params.sp.raw().wrapping_sub(128);
        let frame_size = core::mem::size_of::<RtSigframe>() as u64;
        let new_sp = ((sp.saturating_sub(frame_size)) & !15).wrapping_sub(8);

        // 2. Build the frame
        let mut rtsigframe = RtSigframe::empty();
        rtsigframe.pretcode = params.restorer.map_or(0, |r| r.raw());
        rtsigframe.uc.uc_flags = 0;
        rtsigframe.uc.uc_link = 0;
        rtsigframe.uc.uc_stack = SignalStack::empty();
        rtsigframe.uc.uc_sigmask = params.mask;

        // Populate uc_mcontext with current register values from frame
        rtsigframe.uc.uc_mcontext.r8 = frame.r8;
        rtsigframe.uc.uc_mcontext.r9 = frame.r9;
        rtsigframe.uc.uc_mcontext.r10 = frame.r10;
        rtsigframe.uc.uc_mcontext.r11 = frame.r11;
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
        rtsigframe.uc.uc_mcontext.rcx = frame.rcx;
        rtsigframe.uc.uc_mcontext.rsp = frame.rsp;
        rtsigframe.uc.uc_mcontext.rip = frame.rcx; // saved RIP from syscall entry
        rtsigframe.uc.uc_mcontext.eflags = frame.r11; // saved RFLAGS from syscall entry
        rtsigframe.uc.uc_mcontext.cs = 0x33;

        // Populate siginfo
        if let Some(bytes) = siginfo {
            if let Ok(info) = Siginfo::ref_from_bytes(bytes).ok_or(ArchError::InvalidFrame) {
                rtsigframe.info = *info;
            }
        } else {
            let mut info = Siginfo::empty();
            info.si_signo = params.signum;
            info.si_code = params.sigcode;
            info.si_addr = params.fault_addr;
            rtsigframe.info = info;
        }

        // 3. Write frame to user stack
        let frame_bytes = rtsigframe.as_bytes();
        if !copy_out(UserVa::new(new_sp), frame_bytes) {
            return Err(ArchError::InvalidFrame);
        }

        // 4. Set up registers for handler invocation
        let info_addr = new_sp + core::mem::offset_of!(RtSigframe, info) as u64;
        let uc_addr = new_sp + core::mem::offset_of!(RtSigframe, uc) as u64;

        frame.rcx = params.handler.raw(); // user RIP
        frame.rsp = new_sp; // user RSP
        frame.rdi = params.signum as u64; // arg 1: signum
        frame.rsi = info_addr; // arg 2: siginfo_t*
        frame.rdx = uc_addr; // arg 3: ucontext_t*
        frame.rax = 0;

        Ok(UserVa::new(new_sp))
    }

    #[inline(never)]
    fn restore_signal_frame(
        &mut self,
        frame: &mut NativeFrame,
        copy_in: &mut dyn FnMut(&mut [u8], UserVa) -> bool,
    ) -> Result<u64, Self::Error> {
        let uc_addr = UserVa::new(frame.rsp);
        let mut uc_bytes = [0u8; core::mem::size_of::<Ucontext>()];
        if !copy_in(&mut uc_bytes, uc_addr) {
            return Err(ArchError::InvalidFrame);
        }
        let Some(uc) = Ucontext::ref_from_bytes(&uc_bytes) else {
            return Err(ArchError::InvalidFrame);
        };

        // Restore registers
        frame.r8 = uc.uc_mcontext.r8;
        frame.r9 = uc.uc_mcontext.r9;
        frame.r10 = uc.uc_mcontext.r10;
        frame.r11 = uc.uc_mcontext.eflags;
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
        frame.rsp = uc.uc_mcontext.rsp;

        Ok(uc.uc_sigmask)
    }
}
