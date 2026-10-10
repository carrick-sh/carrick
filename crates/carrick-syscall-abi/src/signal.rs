//! Canonical signal wire records shared by the public ABI facade and guest personality.
/// Number of u64s in the kernel ABI sigset_t. Linux uapi defines
/// `_NSIG=64` and `_NSIG_WORDS = _NSIG / _NSIG_BPW = 1`, so the
/// kernel's `sigset_t` is a single 8-byte word and the kernel-level
/// `struct sigaction` (what `rt_sigaction` reads/writes) is therefore
/// 24 (handler+flags+restorer) + 8 (mask) = 32 bytes total. Writing
/// past those 32 bytes back into the caller's stack frame clobbers
/// the caller's saved `x30` and crashes the guest with PC=0.
pub const LINUX_SIGSET_WORDS: usize = 1;
pub const LINUX_KERNEL_SIGSET_SIZE: u64 = 8;

// Linux SIGxxx numbers (aarch64/generic, POSIX) — the authoritative table.
// The trailing comment is the macOS host number ONLY when it differs (the
// translation lives in host_signal.rs `SIGNUM_XLATE`); no comment means the
// number is identical on both kernels. Two Linux signals have NO macOS
// equivalent and cannot be faithfully delivered to a host process: SIGSTKFLT
// (16, macOS 16 is SIGURG) and SIGPWR (30, macOS 30 is SIGUSR1).
pub const LINUX_SIGHUP: i32 = 1;
pub const LINUX_SIGINT: i32 = 2;
pub const LINUX_SIGQUIT: i32 = 3;
pub const LINUX_SIGILL: i32 = 4;
pub const LINUX_SIGTRAP: i32 = 5;
pub const LINUX_SIGABRT: i32 = 6;
pub const LINUX_SIGBUS: i32 = 7; // macOS 10
pub const LINUX_SIGFPE: i32 = 8;
pub const LINUX_SIGKILL: i32 = 9;
pub const LINUX_SIGUSR1: i32 = 10; // macOS 30
pub const LINUX_SIGSEGV: i32 = 11;
pub const LINUX_SIGUSR2: i32 = 12; // macOS 31
pub const LINUX_SIGPIPE: i32 = 13;
pub const LINUX_SIGALRM: i32 = 14;
pub const LINUX_SIGTERM: i32 = 15;
pub const LINUX_SIGSTKFLT: i32 = 16; // no macOS equivalent
pub const LINUX_SIGCHLD: i32 = 17; // macOS 20; default action = Ignore
pub const LINUX_SIGCONT: i32 = 18; // macOS 19
pub const LINUX_SIGSTOP: i32 = 19; // macOS 17
pub const LINUX_SIGTSTP: i32 = 20; // macOS 18
pub const LINUX_SIGTTIN: i32 = 21; // background tty read → stop
pub const LINUX_SIGTTOU: i32 = 22; // background tty write/ctl → stop
pub const LINUX_SIGURG: i32 = 23; // macOS 16; default action = Ignore
pub const LINUX_SIGXCPU: i32 = 24;
pub const LINUX_SIGXFSZ: i32 = 25;

// Linux signal-frame `si_code` values for synchronous memory faults. These
// are guest ABI values, not host `libc` constants (the numeric domains happen
// to overlap on Darwin today).
pub const LINUX_SEGV_MAPERR: i32 = 1;
pub const LINUX_SEGV_ACCERR: i32 = 2;
pub const LINUX_BUS_ADRALN: i32 = 1;
pub const LINUX_BUS_ADRERR: i32 = 2;
pub const LINUX_SIGVTALRM: i32 = 26;
pub const LINUX_SIGPROF: i32 = 27;
pub const LINUX_SIGWINCH: i32 = 28; // default action = Ignore
pub const LINUX_SIGIO: i32 = 29; // macOS 23 (a.k.a. SIGPOLL)
pub const LINUX_SIGPWR: i32 = 30; // no macOS equivalent
pub const LINUX_SIGSYS: i32 = 31; // macOS 12

/// `SIG_DFL` / `SIG_IGN` handler sentinel values stored in `sa_handler`.
pub const LINUX_SIG_DFL: u64 = 0;
pub const LINUX_SIG_IGN: u64 = 1;

/// `sa_flags` bit: the `sa_restorer` field is valid. When CLEAR the kernel
/// `SA_NOCLDSTOP`: do not generate SIGCHLD when children stop.
pub const LINUX_SA_NOCLDSTOP: u64 = 0x0000_0001;

/// `SA_NOCLDWAIT`: do not transform children into zombies on exit.
pub const LINUX_SA_NOCLDWAIT: u64 = 0x0000_0002;

/// `SA_RESTORER`: caller installed an explicit restorer. Linux on AArch64
/// IGNORES `sa_restorer` (whatever garbage it holds) and returns from the
/// handler via the VDSO sigreturn trampoline. glibc on aarch64 never sets this
/// — so carrick must synthesise its own trampoline unless this bit is present.
pub const LINUX_SA_RESTORER: u64 = 0x0400_0000;

/// `SA_ONSTACK`: deliver this signal on the alternate signal stack installed
/// via `sigaltstack(2)`, if one is present. Go installs its runtime signal
/// handlers with this flag.
pub const LINUX_SA_ONSTACK: u64 = 0x0800_0000;

/// `SA_RESTART`: a blocking, restartable syscall interrupted by this handler is
/// transparently restarted (the kernel's `ERESTARTSYS` path) instead of failing
/// with `EINTR`. LTP's `tst_test` installs SA_RESTART handlers for its
/// SIGALRM/SIGUSR1 timeout+heartbeat, so the parent's `SAFE_WAITPID` reap must
/// restart when one fires — without this carrick surfaced EINTR and TBROK'd
/// nearly the whole suite.
pub const LINUX_SA_RESTART: u64 = 0x1000_0000;

/// `SA_NODEFER`: do NOT automatically block the signal being delivered while its
/// own handler runs (the default is to block it, so a handler can't re-enter
/// itself). With this set the handler can be re-entered by the same signal.
/// CPython's `faulthandler` registers its user-signal handler with SA_NODEFER
/// and, on `chain=True`, restores the previously-installed handler and re-raises
/// the signal so that handler runs too — that re-raise must reach the restored
/// handler synchronously, which only works if the signal is left unblocked.
pub const LINUX_SA_NODEFER: u64 = 0x4000_0000;

/// `SA_RESETHAND`: reset the handler to `SIG_DFL` on entry (one-shot handler).
pub const LINUX_SA_RESETHAND: u64 = 0x8000_0000;

/// `SA_SIGINFO`: use the three-argument `sa_sigaction` handler form.
pub const LINUX_SA_SIGINFO: u64 = 0x0000_0004;

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

pub const LINUX_SIGINFO_SIZE: usize = 128;
pub const LINUX_UCONTEXT_SIGMASK_PAD_BYTES: usize = 120;
pub const LINUX_AARCH64_SIGCONTEXT_RESERVED_BYTES: usize = 4096;

pub const LINUX_SI_USER: i32 = 0;
/// Kernel-generated signal without a more specific positive `si_code`.
/// Carrick uses this for architecturally synchronous faults such as user-mode
/// x86 `#GP(0)`/`#SS(0)`, matching Linux's guest ABI value.
pub const LINUX_SI_KERNEL: i32 = 128;
/// `si_code` for a `sigqueue(3)`/`rt_sigqueueinfo(2)`-delivered signal — the
/// handler's `si_value` carries the sender's payload.
pub const LINUX_SI_QUEUE: i32 = -1;
/// `si_code` for POSIX timer expirations (`timer_create(2)`/`timer_settime(2)`).
pub const LINUX_SI_TIMER: i32 = -2;
/// `si_code` for POSIX message-queue notifications (`mq_notify` with
/// `SIGEV_SIGNAL`). Carries the sender identity and `sigev_value`.
pub const LINUX_SI_MESGQ: i32 = -3;
/// `si_code` for a `tkill(2)`/`tgkill(2)`-delivered signal (and glibc/musl
/// `raise(3)`, which uses `tgkill`). Distinct from `SI_USER` (`kill(2)`).
pub const LINUX_SI_TKILL: i32 = -6;
/// `si_code` for poll/fasync/dnotify signals carrying `si_fd`.
pub const LINUX_POLL_MSG: i32 = 3;
/// SIGCHLD causes from sigaction(2).
pub const LINUX_CLD_EXITED: i32 = 1;
pub const LINUX_CLD_KILLED: i32 = 2;
pub const LINUX_CLD_DUMPED: i32 = 3;

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

    /// Build an SI_USER/SI_TKILL/SI_QUEUE "_kill"-family siginfo carrying the
    /// sender's identity. On Linux aarch64 the `_sifields` union begins at
    /// offset 16, and the `_kill` member is `{ int si_pid; uint si_uid; }` —
    /// the same 8 bytes occupied by `si_addr` for the fault family. On
    /// little-endian, packing `si_pid` in the low word and `si_uid` in the high
    /// word reproduces that layout exactly, so a guest reading `info->si_pid` /
    /// `info->si_uid` sees the sender's pid/uid.
    pub fn kill(si_signo: i32, si_code: i32, si_pid: i32, si_uid: u32) -> Self {
        let mut s = Self::empty();
        s.si_signo = si_signo;
        s.si_code = si_code;
        s.si_addr = (u64::from(si_uid) << 32) | u64::from(si_pid as u32);
        s
    }

    /// Build an `SI_QUEUE` real-time siginfo carrying the sender's identity AND
    /// `si_value` (sigval). The `_rt` union member is
    /// `{ int si_pid; uint si_uid; sigval si_value; }` at offsets 16/20/24 on
    /// aarch64: si_pid/si_uid share `si_addr`'s 8 bytes (see [`Self::kill`]), and
    /// the 8-byte `si_value` immediately follows at offset 24 — the start of
    /// `_pad`. So a guest reading `info->si_value.sival_int`/`.sival_ptr` sees
    /// what `sigqueue(3)`/`rt_sigqueueinfo(2)` passed.
    pub fn rt_queue(si_signo: i32, si_pid: i32, si_uid: u32, si_value: i64) -> Self {
        let mut s = Self::kill(si_signo, LINUX_SI_QUEUE, si_pid, si_uid);
        s._pad[0..8].copy_from_slice(&si_value.to_le_bytes());
        s
    }

    /// Build an `SI_MESGQ` message-queue notification siginfo carrying
    /// `sigev_value`. Linux uses the same `_rt` payload layout as `SI_QUEUE`:
    /// `{ si_pid, si_uid, sigval si_value }`.
    pub fn message_queue(si_signo: i32, si_pid: i32, si_uid: u32, si_value: i64) -> Self {
        let mut s = Self::kill(si_signo, LINUX_SI_MESGQ, si_pid, si_uid);
        s._pad[0..8].copy_from_slice(&si_value.to_le_bytes());
        s
    }

    /// Build a SIGPOLL/SIGIO-family siginfo carrying `{ si_band, si_fd }`.
    /// On Linux aarch64 the `_sigpoll` member is `{ long si_band; int si_fd; }`
    /// at offsets 16 and 24, so `si_band` occupies `si_addr` and `si_fd` starts
    /// the trailing pad.
    pub fn sigpoll(si_signo: i32, si_code: i32, si_band: i64, si_fd: i32) -> Self {
        let mut s = Self::empty();
        s.si_signo = si_signo;
        s.si_code = si_code;
        s.si_addr = si_band as u64;
        s._pad[0..4].copy_from_slice(&si_fd.to_le_bytes());
        s
    }

    /// Build a child-exit siginfo (`CLD_*`) carrying
    /// `{ si_pid, si_uid, si_status }` at Linux's 64-bit offsets 16/20/24.
    pub fn child_exit(
        si_signo: i32,
        si_pid: i32,
        si_uid: u32,
        si_code: i32,
        si_status: i32,
    ) -> Self {
        let mut s = Self::kill(si_signo, si_code, si_pid, si_uid);
        s._pad[0..4].copy_from_slice(&si_status.to_le_bytes());
        s
    }

    /// Build an `SI_TIMER` siginfo for a POSIX timer expiration (`timer_create(2)`).
    /// On Linux aarch64/x86_64, `_timer` occupies:
    ///   offset 16: `int si_tid` (4 bytes)
    ///   offset 20: `int si_overrun` (4 bytes)
    ///   offset 24: `sigval si_sigval` (8 bytes)
    /// In little-endian, `si_tid` and `si_overrun` pack into `si_addr` exactly like `kill`.
    pub fn timer(si_signo: i32, si_tid: i32, si_overrun: i32, si_value: i64) -> Self {
        let mut s = Self::empty();
        s.si_signo = si_signo;
        s.si_code = LINUX_SI_TIMER;
        s.si_addr = (u64::from(si_overrun as u32) << 32) | u64::from(si_tid as u32);
        s._pad[0..8].copy_from_slice(&si_value.to_le_bytes());
        s
    }

    /// Build an `SI_KERNEL` siginfo for kernel-generated signals such as `setitimer`.
    pub fn kernel(si_signo: i32) -> Self {
        let mut s = Self::empty();
        s.si_signo = si_signo;
        s.si_code = LINUX_SI_KERNEL;
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

/// `_aarch64_ctx.magic` for the FP/SIMD context record the kernel places in
/// `sigcontext.__reserved`. The guest's signal handler and `rt_sigreturn` rely
/// on V0–V31 + FPSR/FPCR being saved here and restored, exactly as Linux does
/// (`arch/arm64/include/uapi/asm/sigcontext.h`). Without it, a handler that
/// touches SIMD (e.g. aarch64 `memcpy`) silently corrupts the interrupted
/// thread's vector state.
pub const LINUX_FPSIMD_MAGIC: u32 = 0x4650_8001;

/// AArch64 `struct fpsimd_context`: the FP/SIMD register record stored at the
/// start of `sigcontext.__reserved`. `vregs` holds V0–V31 as 128-bit values.
/// `#[repr(C, packed)]` matches the kernel's contiguous layout (head 8, fpsr 4,
/// fpcr 4, vregs 512 = 528 bytes; `vregs` at offset 16).
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
pub struct LinuxFpsimdContext {
    pub magic: u32,
    pub size: u32,
    pub fpsr: u32,
    pub fpcr: u32,
    pub vregs: [u128; 32],
}

impl LinuxFpsimdContext {
    pub const fn empty() -> Self {
        Self {
            magic: LINUX_FPSIMD_MAGIC,
            size: core::mem::size_of::<Self>() as u32,
            fpsr: 0,
            fpcr: 0,
            vregs: [0; 32],
        }
    }
}

/// Magic value placed in `CarrickSigframe::magic` so `rt_sigreturn` can
/// detect a misaligned / corrupt frame and refuse to restore garbage.
pub const CARRICK_SIGFRAME_MAGIC: u64 = 0x4361_7272_6963_6b53; // 'CarrickS'

/// Carrick's signal frame layout. `siginfo` and `ucontext` are placed FIRST
/// (matching Linux's `struct rt_sigframe` order) because Rosetta's signal
/// trampoline reconstructs the `siginfo` pointer with `mov x1, sp` — i.e. it
/// assumes `siginfo` sits at `SP+0`. `inject_signal` sets x1/x2 via
/// `offset_of!`, so glibc and Go are unaffected by the field ordering here.
/// The private authentication fields (`magic`, `saved_x`, …) follow after and
/// are consumed only by Carrick's own `rt_sigreturn` handler.
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
    // siginfo / ucontext MUST be first — Rosetta trampoline: `mov x1, sp`.
    pub siginfo: LinuxSiginfo,
    pub ucontext: LinuxUcontext,
    // Private authentication / restoration state follows.
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

// ─── x86-64 rt_sigframe (M3d) ────────────────────────────────────────────────
//
// The Linux x86-64 signal frame a guest handler runs on. Layout derived
// CLEAN-ROOM from the x86-64 psABI, sigreturn(2)/signal(7), the Intel SDM
// (FXSAVE area), and the <sys/ucontext.h> REG_* gregset indices — NOT from
// kernel/glibc/UAPI source. Every field is naturally 8-byte aligned, so
// `packed` (for unaligned zerocopy access at the guest SP) yields the identical
// byte layout the kernel produces. The running 104 fixture is the oracle.

/// Standard-format XSAVE legacy area size (Intel SDM Vol. 1, XSAVE area).
pub const X8664_XSAVE_LEGACY_LEN: usize = 512;
/// Standard-format XSAVE header size, immediately after the legacy area.
pub const X8664_XSAVE_HEADER_LEN: usize = 64;
/// Smallest standard-format XSAVE image: legacy area plus XSAVE header.
pub const X8664_XSAVE_MIN_LEN: usize = X8664_XSAVE_LEGACY_LEN + X8664_XSAVE_HEADER_LEN;
/// Carrick's hard upper bound for a guest signal XSAVE image. Component ranges
/// derived from CPUID leaf 0xD must fit this bound before a frame is emitted.
pub const X8664_XSAVE_AREA_MAX_LEN: usize = 16 * 1024;
/// Offset of Linux's software-reserved xstate descriptor in the legacy area.
pub const X8664_FP_XSTATE_SW_BYTES_OFFSET: usize = 464;
/// Linux-described marker identifying an extended x86 FP state frame (`FPXS`).
pub const X8664_FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
/// Final marker at the end of the Linux-advertised extended fpstate (`FPXE`).
pub const X8664_FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
/// Size of the trailing `FP_XSTATE_MAGIC2` word.
pub const X8664_FP_XSTATE_MAGIC2_SIZE: usize = core::mem::size_of::<u32>();
/// XSAVE component number for PKRU. Native x86 virtualizes it outside the
/// hardware image so guest key-0 restrictions can never revoke gateway access.
pub const X8664_XFEATURE_PKRU: u32 = 9;
/// Ring-3 code selector installed by Carrick's Linux/x86_64 guest ABI.
pub const LINUX_X8664_USER_CS: u16 = 0x23;
/// Ring-3 data/stack selector installed by Carrick's Linux/x86_64 guest ABI.
pub const LINUX_X8664_USER_DS: u16 = 0x1b;

/// Linux's 48-byte software descriptor in the final bytes of the legacy FXSAVE
/// area. `xstate_size` covers only the standard XSAVE image; `extended_size`
/// reaches through final MAGIC2. Carrick frames place their private trailer in
/// that advertised interval between `xstate_size` and MAGIC2, so an exact Linux-
/// compatible extent copy retains it. Layout and semantics are verified against
/// clean-room signal-frame probes; component offsets come from CPUID leaf 0xD.
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
pub struct X8664FpxSwBytes {
    pub magic1: u32,
    pub extended_size: u32,
    pub xfeatures: u64,
    pub xstate_size: u32,
    pub reserved: [u32; 7],
}

impl X8664FpxSwBytes {
    pub const fn empty() -> Self {
        Self {
            magic1: 0,
            extended_size: 0,
            xfeatures: 0,
            xstate_size: 0,
            reserved: [0; 7],
        }
    }
}

/// x86-64 512-byte XSAVE legacy area (Intel SDM Vol. 1, XSAVE). Unlike the old
/// XMM/YMM approximation this models the complete x87/SSE legacy payload and
/// the Linux software descriptor occupying its final 48 bytes.
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
pub struct X8664Fpstate {
    pub cwd: u16,
    pub swd: u16,
    pub ftw: u16,
    pub fop: u16,
    pub rip: u64,
    pub rdp: u64,
    pub mxcsr: u32,
    pub mxcr_mask: u32,
    pub st_space: [u32; 32],
    pub xmm_space: [u32; 64],
    pub padding: [u32; 12],
    pub sw_reserved: X8664FpxSwBytes,
}

impl X8664Fpstate {
    pub const fn empty() -> Self {
        Self {
            cwd: 0,
            swd: 0,
            ftw: 0,
            fop: 0,
            rip: 0,
            rdp: 0,
            mxcsr: 0,
            mxcr_mask: 0,
            st_space: [0; 32],
            xmm_space: [0; 64],
            padding: [0; 12],
            sw_reserved: X8664FpxSwBytes::empty(),
        }
    }
}

/// XSAVE header at standard-image byte 512. Compact format is forbidden in a
/// Linux signal frame: `xcomp_bv` must be zero and all reserved words zero.
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
pub struct X8664XsaveHeader {
    pub xstate_bv: u64,
    pub xcomp_bv: u64,
    pub reserved: [u64; 6],
}

impl X8664XsaveHeader {
    pub const fn empty() -> Self {
        Self {
            xstate_bv: 0,
            xcomp_bv: 0,
            reserved: [0; 6],
        }
    }
}

/// Carrick-private virtual-state trailer. Version 3 places it after the
/// standard-format XSAVE image and before final MAGIC2, inside Linux's
/// advertised `extended_size`. A handler that copies or relocates exactly that
/// extent therefore retains virtual PKRU and non-REX x87 selectors. Keeping the
/// state in the guest frame also makes nested delivery self-contained without a
/// host-side frame map.
pub const CARRICK_X8664_XSTATE_TRAILER_MAGIC: u64 = 0x3154_5358_4b52_4143;
pub const CARRICK_X8664_XSTATE_TRAILER_VERSION: u16 = 3;

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
pub struct CarrickX8664XstateTrailer {
    pub magic: u64,
    pub version: u16,
    pub size: u16,
    pub virtual_pkru: u32,
    /// Virtual non-REX x87 instruction-pointer selector. This is kept outside
    /// the hardware FXSAVE64 image so a host selector can never enter a guest
    /// signal frame.
    pub virtual_x87_fcs: u16,
    /// Virtual non-REX x87 data-pointer selector.
    pub virtual_x87_fds: u16,
    pub reserved: [u32; 3],
}

impl CarrickX8664XstateTrailer {
    pub const fn new(virtual_pkru: u32, virtual_x87_fcs: u16, virtual_x87_fds: u16) -> Self {
        Self {
            magic: CARRICK_X8664_XSTATE_TRAILER_MAGIC,
            version: CARRICK_X8664_XSTATE_TRAILER_VERSION,
            size: core::mem::size_of::<Self>() as u16,
            virtual_pkru,
            virtual_x87_fcs,
            virtual_x87_fds,
            reserved: [0; 3],
        }
    }
}

/// x86-64 `struct sigcontext` / `mcontext` (256 bytes). The gregset order IS the
/// ABI (`<sys/ucontext.h>` `REG_*` indices 0–22 / x86-64 psABI):
/// r8..r15, rdi,rsi,rbp,rbx,rdx,rax,rcx,rsp, rip, eflags, then cs/gs/fs/ss
/// (which alias the packed `REG_CSGSFS` u64: cs | gs<<16 | fs<<32 | ss<<48).
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
    pub fpstate: u64, // guest pointer to the X8664Fpstate (or 0)
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

/// x86-64 signal-frame `ucontext` prefix (304 bytes). The live Linux/amd64
/// signal frame places the one-word kernel sigmask at offset 296, followed
/// immediately by `siginfo` in the enclosing `rt_sigframe`; userspace runtimes
/// model a larger `ucontext_t`, but the extra bytes overlap following frame
/// fields in the kernel-provided stack image.
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

/// Fixed prefix of the Linux x86-64 `rt_sigframe`. The standard-format XSAVE
/// image starts at the zero-sized `fpstate` marker (byte 456) and has a runtime
/// CPUID-derived length, followed by Carrick's private trailer and final MAGIC2;
/// all three are covered by `extended_size`. Keeping only the invariant prefix
/// in the Rust type prevents `size_of` from being mistaken for the dynamic
/// frame extent.
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

pub const X8664_RTSIGFRAME_FPSTATE_OFFSET: usize = core::mem::offset_of!(X8664Rtsigframe, fpstate);

// Compile-time ABI size guards (x86-64 psABI / Intel SDM). A layout drift fails
// the BUILD rather than producing a silently-wrong guest signal frame.
const _: () = assert!(core::mem::size_of::<X8664FpxSwBytes>() == 48);
const _: () = assert!(core::mem::size_of::<X8664Fpstate>() == X8664_XSAVE_LEGACY_LEN);
const _: () = assert!(core::mem::offset_of!(X8664Fpstate, sw_reserved) == 464);
const _: () = assert!(core::mem::size_of::<X8664XsaveHeader>() == X8664_XSAVE_HEADER_LEN);
const _: () = assert!(core::mem::size_of::<CarrickX8664XstateTrailer>() == 32);
const _: () = assert!(core::mem::size_of::<X8664Sigcontext>() == 256);
const _: () = assert!(core::mem::size_of::<X8664Ucontext>() == 304);
const _: () = assert!(X8664_RTSIGFRAME_FPSTATE_OFFSET == 456);
const _: () = assert!(core::mem::size_of::<X8664Rtsigframe>() == 456);

#[cfg(test)]
mod x8664_sigframe_tests {
    use super::*;

    /// The gregset byte offsets must equal the psABI `REG_*` index × 8
    /// (`<sys/ucontext.h>`): REG_R8=0, REG_RDI=8, REG_RAX=13, REG_RCX=14,
    /// REG_RSP=15, REG_RIP=16, REG_EFL=17. A wrong order makes a handler read
    /// the wrong register out of `ucontext`.
    #[test]
    fn sigcontext_gregset_order_matches_psabi() {
        assert_eq!(core::mem::offset_of!(X8664Sigcontext, r8), 0);
        assert_eq!(core::mem::offset_of!(X8664Sigcontext, rdi), 8 * 8);
        assert_eq!(core::mem::offset_of!(X8664Sigcontext, rdx), 12 * 8);
        assert_eq!(core::mem::offset_of!(X8664Sigcontext, rax), 13 * 8);
        assert_eq!(core::mem::offset_of!(X8664Sigcontext, rcx), 14 * 8);
        assert_eq!(core::mem::offset_of!(X8664Sigcontext, rsp), 15 * 8);
        assert_eq!(core::mem::offset_of!(X8664Sigcontext, rip), 16 * 8);
        assert_eq!(core::mem::offset_of!(X8664Sigcontext, eflags), 17 * 8);
        // cs/gs/fs/ss alias the REG_CSGSFS u64 at index 18.
        assert_eq!(core::mem::offset_of!(X8664Sigcontext, cs), 18 * 8);
    }

    /// Kernel `struct rt_sigframe` field order observed on Linux/amd64:
    /// pretcode(0), ucontext after the return address, siginfo at ucontext+304,
    /// and fpstate at ucontext+448.
    #[test]
    fn rtsigframe_field_order() {
        assert_eq!(core::mem::offset_of!(X8664Rtsigframe, pretcode), 0);
        assert_eq!(core::mem::offset_of!(X8664Rtsigframe, uc), 8);
        assert_eq!(core::mem::offset_of!(X8664Rtsigframe, info), 8 + 304);
        assert_eq!(core::mem::offset_of!(X8664Rtsigframe, fpstate), 8 + 448);
    }

    /// `ucontext`: uc_mcontext follows uc_flags(8) + uc_link(8) + uc_stack(24).
    #[test]
    fn ucontext_mcontext_offset() {
        assert_eq!(
            core::mem::offset_of!(X8664Ucontext, uc_mcontext),
            8 + 8 + 24
        );
        assert_eq!(core::mem::offset_of!(X8664Ucontext, uc_sigmask), 296);
    }

    #[test]
    fn rtsigframe_offsets_match_linux_amd64_oracle() {
        let uc = core::mem::offset_of!(X8664Rtsigframe, uc);
        assert_eq!(uc, 8);
        assert_eq!(core::mem::offset_of!(X8664Rtsigframe, info) - uc, 304);
        assert_eq!(core::mem::offset_of!(X8664Rtsigframe, fpstate) - uc, 448);
        assert_eq!(core::mem::offset_of!(X8664Ucontext, uc_sigmask), 296);
        assert_eq!(core::mem::size_of::<X8664Ucontext>(), 304);
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
pub struct LinuxSigaltstack {
    pub ss_sp: u64,
    pub ss_flags: i32,
    pub __pad: u32,
    pub ss_size: u64,
}

impl LinuxSigaltstack {
    pub const fn empty() -> Self {
        Self {
            ss_sp: 0,
            ss_flags: 0,
            __pad: 0,
            ss_size: 0,
        }
    }

    pub const fn disabled() -> Self {
        Self {
            ss_sp: 0,
            ss_flags: 2, // SS_DISABLE
            __pad: 0,
            ss_size: 0,
        }
    }
}

pub const LINUX_RT_SIGSET_SIZE: u64 = 8;
pub const LINUX_SS_ONSTACK: u64 = 1;
pub const LINUX_SS_DISABLE: u64 = 2;
pub const LINUX_SS_AUTODISARM: u64 = 0x8000_0000;

/// EL0 signal-return PSTATE: NZCV, SSBS and DIT are user-modifiable. All mode,
/// interrupt-mask and privileged state bits must remain clear.
pub const LINUX_AARCH64_SIGNAL_USER_PSTATE_MASK: u64 = 0xf000_0000 | (1 << 12) | (1 << 24);
