//! In-guest signal ABI structures and constants.

use carrick_syscall_abi::LinuxErrno;

pub const RT_SIGSET_SIZE: u64 = 8;
pub const LINUX_SIGSET_WORDS: usize = 1;
pub const LINUX_SIGINFO_SIZE: usize = 128;
pub const LINUX_UCONTEXT_SIGMASK_PAD_BYTES: usize = 120;
pub const LINUX_AARCH64_SIGCONTEXT_RESERVED_BYTES: usize = 4096;

pub const LINUX_SI_USER: i32 = 0;
pub const LINUX_SI_KERNEL: i32 = 128;
pub const LINUX_SI_QUEUE: i32 = -1;
pub const LINUX_SI_TIMER: i32 = -2;
pub const LINUX_SI_MESGQ: i32 = -3;
pub const LINUX_SI_TKILL: i32 = -6;
pub const LINUX_POLL_MSG: i32 = 3;

pub const LINUX_EPERM: LinuxErrno = LinuxErrno::new(1);
pub const LINUX_ESRCH: LinuxErrno = LinuxErrno::new(3);
pub const LINUX_EINTR: LinuxErrno = LinuxErrno::new(4);
pub const LINUX_EBADF: LinuxErrno = LinuxErrno::new(9);
pub const LINUX_ECHILD: LinuxErrno = carrick_syscall_abi::LINUX_ECHILD;
pub const LINUX_EAGAIN: LinuxErrno = carrick_syscall_abi::LINUX_EAGAIN;
pub const LINUX_EFAULT: LinuxErrno = carrick_syscall_abi::LINUX_EFAULT;
pub const LINUX_EINVAL: LinuxErrno = carrick_syscall_abi::LINUX_EINVAL;
pub const LINUX_ENOSYS: LinuxErrno = LinuxErrno::new(38);

#[repr(C, packed)]
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
    ::zerocopy::FromBytes,
    ::zerocopy::IntoBytes,
    ::zerocopy::KnownLayout,
    ::zerocopy::Immutable,
    ::zerocopy::Unaligned,
)]
pub struct LinuxSigaction {
    pub sa_handler: u64,
    pub sa_flags: u64,
    pub sa_restorer: u64,
    pub sa_mask: [u64; LINUX_SIGSET_WORDS],
}

impl LinuxSigaction {
    pub const fn empty() -> Self {
        Self {
            sa_handler: 0,
            sa_flags: 0,
            sa_restorer: 0,
            sa_mask: [0; LINUX_SIGSET_WORDS],
        }
    }
}

#[repr(C, packed)]
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
    ::zerocopy::FromBytes,
    ::zerocopy::IntoBytes,
    ::zerocopy::KnownLayout,
    ::zerocopy::Immutable,
    ::zerocopy::Unaligned,
)]
pub struct LinuxSiginfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub _pad0: i32,
    pub si_addr: u64,
    pub _pad: [u8; LINUX_SIGINFO_SIZE - 24],
}

impl LinuxSiginfo {
    pub const fn empty() -> Self {
        Self {
            si_signo: 0,
            si_errno: 0,
            si_code: 0,
            _pad0: 0,
            si_addr: 0,
            _pad: [0; LINUX_SIGINFO_SIZE - 24],
        }
    }

    pub fn kill(si_signo: i32, si_code: i32, si_pid: i32, si_uid: u32) -> Self {
        let mut s = Self::empty();
        s.si_signo = si_signo;
        s.si_code = si_code;
        s.si_addr = (u64::from(si_uid) << 32) | u64::from(si_pid as u32);
        s
    }

    pub fn rt_queue(si_signo: i32, si_pid: i32, si_uid: u32, si_value: i64) -> Self {
        let mut s = Self::kill(si_signo, LINUX_SI_QUEUE, si_pid, si_uid);
        s._pad[0..8].copy_from_slice(&si_value.to_le_bytes());
        s
    }
}

#[repr(C, packed)]
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
    ::zerocopy::FromBytes,
    ::zerocopy::IntoBytes,
    ::zerocopy::KnownLayout,
    ::zerocopy::Immutable,
    ::zerocopy::Unaligned,
)]
pub struct LinuxSignalStack {
    pub ss_sp: u64,
    pub ss_flags: i32,
    pub _pad0: u32,
    pub ss_size: u64,
}

impl LinuxSignalStack {
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
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
    ::zerocopy::FromBytes,
    ::zerocopy::IntoBytes,
    ::zerocopy::KnownLayout,
    ::zerocopy::Immutable,
    ::zerocopy::Unaligned,
)]
pub struct LinuxSignalContext {
    pub fault_address: u64,
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub _pad: [u8; 8],
    pub __reserved: [u8; LINUX_AARCH64_SIGCONTEXT_RESERVED_BYTES],
}

impl LinuxSignalContext {
    pub const fn empty() -> Self {
        Self {
            fault_address: 0,
            regs: [0; 31],
            sp: 0,
            pc: 0,
            pstate: 0,
            _pad: [0; 8],
            __reserved: [0; LINUX_AARCH64_SIGCONTEXT_RESERVED_BYTES],
        }
    }
}

#[repr(C, packed)]
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
    ::zerocopy::FromBytes,
    ::zerocopy::IntoBytes,
    ::zerocopy::KnownLayout,
    ::zerocopy::Immutable,
    ::zerocopy::Unaligned,
)]
pub struct LinuxUcontext {
    pub uc_flags: u64,
    pub uc_link: u64,
    pub uc_stack: LinuxSignalStack,
    pub uc_sigmask: u64,
    pub _pad: [u8; LINUX_UCONTEXT_SIGMASK_PAD_BYTES],
    pub _pad2: [u8; 8],
    pub uc_mcontext: LinuxSignalContext,
}

impl LinuxUcontext {
    pub const fn empty() -> Self {
        Self {
            uc_flags: 0,
            uc_link: 0,
            uc_stack: LinuxSignalStack::empty(),
            uc_sigmask: 0,
            _pad: [0; LINUX_UCONTEXT_SIGMASK_PAD_BYTES],
            _pad2: [0; 8],
            uc_mcontext: LinuxSignalContext::empty(),
        }
    }
}

pub const CARRICK_SIGFRAME_MAGIC: u64 = 0x4361_7272_6963_6b53;

#[repr(C, packed)]
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
    ::zerocopy::FromBytes,
    ::zerocopy::IntoBytes,
    ::zerocopy::KnownLayout,
    ::zerocopy::Immutable,
    ::zerocopy::Unaligned,
)]
pub struct CarrickSigframe {
    pub siginfo: LinuxSiginfo,
    pub ucontext: LinuxUcontext,
    pub magic: u64,
    pub signum: u32,
    pub _pad0: u32,
    pub saved_x: [u64; 31],
    pub saved_pc: u64,
    pub saved_sp: u64,
    pub saved_spsr: u64,
    pub _reserved: [u64; 6],
}

impl CarrickSigframe {
    pub const fn empty() -> Self {
        Self {
            siginfo: LinuxSiginfo::empty(),
            ucontext: LinuxUcontext::empty(),
            magic: CARRICK_SIGFRAME_MAGIC,
            signum: 0,
            _pad0: 0,
            saved_x: [0; 31],
            saved_pc: 0,
            saved_sp: 0,
            saved_spsr: 0,
            _reserved: [0; 6],
        }
    }
}

#[repr(C, packed)]
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
    ::zerocopy::FromBytes,
    ::zerocopy::IntoBytes,
    ::zerocopy::KnownLayout,
    ::zerocopy::Immutable,
    ::zerocopy::Unaligned,
)]
pub struct X8664Sigcontext {
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

impl X8664Sigcontext {
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
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
    ::zerocopy::FromBytes,
    ::zerocopy::IntoBytes,
    ::zerocopy::KnownLayout,
    ::zerocopy::Immutable,
    ::zerocopy::Unaligned,
)]
pub struct X8664Ucontext {
    pub uc_flags: u64,
    pub uc_link: u64,
    pub uc_stack: LinuxSignalStack,
    pub uc_mcontext: X8664Sigcontext,
    pub uc_sigmask: u64,
}

impl X8664Ucontext {
    pub const fn empty() -> Self {
        Self {
            uc_flags: 0,
            uc_link: 0,
            uc_stack: LinuxSignalStack::empty(),
            uc_mcontext: X8664Sigcontext::empty(),
            uc_sigmask: 0,
        }
    }
}

#[repr(C, packed)]
#[derive(
    ::core::fmt::Debug,
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
    ::zerocopy::FromBytes,
    ::zerocopy::IntoBytes,
    ::zerocopy::KnownLayout,
    ::zerocopy::Immutable,
    ::zerocopy::Unaligned,
)]
pub struct X8664Rtsigframe {
    pub pretcode: u64,
    pub uc: X8664Ucontext,
    pub info: LinuxSiginfo,
    pub fpstate_pad: [u8; 16],
    pub fpstate: [u8; 0],
}

impl X8664Rtsigframe {
    pub const fn empty() -> Self {
        Self {
            pretcode: 0,
            uc: X8664Ucontext::empty(),
            info: LinuxSiginfo::empty(),
            fpstate_pad: [0; 16],
            fpstate: [],
        }
    }
}
