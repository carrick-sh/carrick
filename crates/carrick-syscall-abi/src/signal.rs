//! Linux signal action wire constants shared by host and guest kernels.
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
