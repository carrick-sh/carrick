//! In-guest signal ABI structures and constants.

pub use carrick_syscall_abi::{
    LINUX_AARCH64_SIGCONTEXT_RESERVED_BYTES, LINUX_EAGAIN, LINUX_EBADF, LINUX_ECHILD, LINUX_EFAULT,
    LINUX_EINTR, LINUX_EINVAL, LINUX_ENOSYS, LINUX_EPERM, LINUX_ESRCH, LINUX_POLL_MSG,
    LINUX_RT_SIGSET_SIZE as RT_SIGSET_SIZE, LINUX_SI_KERNEL, LINUX_SI_MESGQ, LINUX_SI_QUEUE,
    LINUX_SI_TIMER, LINUX_SI_TKILL, LINUX_SI_USER, LINUX_SIGINFO_SIZE, LINUX_SIGSET_WORDS,
    LINUX_UCONTEXT_SIGMASK_PAD_BYTES,
};

// One wire-format definition is shared with host delivery and both ring ISAs.
pub use carrick_syscall_abi::{
    CARRICK_SIGFRAME_MAGIC, CarrickSigframe, LinuxSigaction, LinuxSiginfo, LinuxSignalContext,
    LinuxSignalStack, LinuxUcontext, X8664Rtsigframe, X8664Sigcontext, X8664Ucontext,
};
