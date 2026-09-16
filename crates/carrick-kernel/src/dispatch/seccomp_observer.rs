//! Syscall policy, observer chaining, interceptors, and preflight preparation.
//!
//! Applies launch-time container security policy (Docker default seccomp),
//! guest seccomp filter evaluation, trusted interceptor transforms, observer
//! callbacks, and syscall flag validation before dispatch.

use std::sync::Arc;

use crate::compat::{CompatEvent, CompatReporter};
use crate::linux_abi::{
    LINUX_AT_EMPTY_PATH, LINUX_AT_SYMLINK_NOFOLLOW, LINUX_EFD_CLOEXEC, LINUX_EFD_NONBLOCK,
    LINUX_EFD_SEMAPHORE, LINUX_EPOLL_CLOEXEC, LINUX_O_CLOEXEC, LINUX_O_NONBLOCK,
    LINUX_SOCKET_TYPE_SUPPORTED_MASK, LinuxAtFlags, LinuxOpenFlags, LinuxSocketTypeFlags,
};

use crate::dispatch::DispatchError;
use crate::dispatch::SyscallDispatcher;
use crate::dispatch::outcome::DispatchOutcome;
use crate::dispatch::request::{
    PreparedDispatch, PreparedSyscall, SyscallRequest, merge_policy_terminal,
};
use crate::dispatch::time;
use crate::linux_abi::LinuxErrno;

/// (syscall_number, arg_index, supported_mask) for every syscall that
/// takes a `flags`-style argument with a well-defined supported bit
/// set on aarch64 Linux. The dispatch entry point consults this table
/// BEFORE the handler runs, so any flag bit the guest sets that we
/// don't recognise produces a `UnknownSyscallFlags` event in the
/// compat report (and a `unknown-syscall-flags` USDT probe firing)
/// regardless of whether the individual handler validates flags
/// itself. Add entries here as new flag-bearing syscalls land.
const SYSCALL_FLAG_VALIDATORS: &[(u64, u32, u64)] = &[
    // eventfd2(initval, flags): EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC
    (
        19,
        1,
        LINUX_EFD_SEMAPHORE | LINUX_EFD_NONBLOCK | LINUX_EFD_CLOEXEC,
    ),
    // epoll_create1(flags): EPOLL_CLOEXEC
    (20, 0, LINUX_EPOLL_CLOEXEC),
    // dup3(oldfd, newfd, flags): O_CLOEXEC
    (24, 2, LINUX_O_CLOEXEC),
    // unlinkat(dirfd, pathname, flags): AT_REMOVEDIR (0x200) plus the
    // AT_EMPTY_PATH/AT_SYMLINK_NOFOLLOW pair we accept elsewhere
    (
        35,
        2,
        0x200 | LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW,
    ),
    // renameat2(olddirfd, oldpath, newdirfd, newpath, flags):
    // RENAME_NOREPLACE(1)|EXCHANGE(2)|WHITEOUT(4)
    (276, 4, 0x1 | 0x2 | 0x4),
    // openat(dirfd, pathname, flags, mode): the open flags we recognise
    // — a superset that covers RDONLY/WRONLY/RDWR + the standard mods.
    // Bits are kept liberal because openat is the most-touched syscall.
    (56, 2, LinuxOpenFlags::SUPPORTED_MASK),
    // pipe2(pipefd, flags): O_CLOEXEC | O_NONBLOCK
    (59, 1, LINUX_O_CLOEXEC | LINUX_O_NONBLOCK),
    // signalfd4(fd, mask, sizemask, flags): SFD_NONBLOCK | SFD_CLOEXEC
    (74, 3, LINUX_O_NONBLOCK | LINUX_O_CLOEXEC),
    // timerfd_create(clockid, flags): TFD_NONBLOCK | TFD_CLOEXEC
    (85, 1, LINUX_O_NONBLOCK | LINUX_O_CLOEXEC),
    // timerfd_settime(fd, flags, ...): TFD_TIMER_ABSTIME (1) | TFD_TIMER_CANCEL_ON_SET (2)
    (86, 1, 0x1 | 0x2),
    // utimensat(dirfd, pathname, times, flags): AT_SYMLINK_NOFOLLOW (0x100)
    (88, 3, LINUX_AT_SYMLINK_NOFOLLOW),
    // socket/socketpair type: low bits are a socket-kind enum, high bits are SOCK_* flags.
    (198, 1, LINUX_SOCKET_TYPE_SUPPORTED_MASK),
    (199, 1, LINUX_SOCKET_TYPE_SUPPORTED_MASK),
    // accept4(sockfd, addr, addrlen, flags): SOCK_NONBLOCK | SOCK_CLOEXEC
    (242, 3, LinuxSocketTypeFlags::SUPPORTED_MASK as u64),
    // close_range(first, last, flags): CLOSE_RANGE_UNSHARE(2) | CLOEXEC(4)
    (436, 2, 0x2 | 0x4),
    // openat2 — checked inside open_how, but the syscall flag arg is unused
    // statx(dirfd, pathname, flags, mask, statxbuf): AT_* flags
    (291, 2, LinuxAtFlags::STATX_SUPPORTED_MASK),
    // faccessat2(dirfd, pathname, mode, flags)
    (
        439,
        3,
        LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW | 0x200, /* AT_EACCESS */
    ),
];

/// Systematic unknown-flag detector for syscalls.
///
/// Every syscall that takes a "flags" argument knows which bits are
/// actually defined by the Linux ABI. If the guest passes a bit we
/// don't recognise, something has drifted — either the guest's libc
/// is newer than ours, or we forgot to wire a flag. Either way, it
/// shouldn't be silent. This helper records the unknown bits via the
/// reporter (so the JSON compat report aggregates them) and via the
/// `unknown-syscall-flags` USDT probe (so dtrace can fire on it
/// live), then returns the unknown bits so the caller can decide
/// whether to EINVAL or proceed.
///
/// Usage:
/// ```ignore
/// let unknown = check_syscall_flags(
///     reporter, /*nr=*/ 56, /*name=*/ "openat", /*arg_index=*/ 2,
///     flags, OPENAT_SUPPORTED_MASK,
/// );
/// if unknown != 0 {
///     return DispatchOutcome::Errno { errno: LINUX_EINVAL };
/// }
/// ```
pub fn check_syscall_flags(
    reporter: &CompatReporter,
    number: u64,
    name: &str,
    argument_index: u32,
    value: u64,
    supported_mask: u64,
) -> u64 {
    let unknown = value & !supported_mask;
    if unknown != 0 {
        reporter.record(CompatEvent::unknown_syscall_flags(
            number,
            name,
            argument_index,
            unknown,
        ));
    }
    unknown
}

impl SyscallDispatcher {
    /// Apply a launch-time container syscall policy (the `carrick run` /
    /// `--security-opt seccomp=…` resolution) with no capability grant —
    /// the bare `run-elf`/unit-test shape. Must be called before the guest
    /// boots — the field is then read-only and inherited across guest
    /// fork/execve like a Linux seccomp filter. `Unconfined` clears it.
    pub fn apply_seccomp_policy(&mut self, policy: carrick_spec::SeccompPolicy) {
        self.install_container_policy(
            policy,
            crate::namespace::process::CapabilitySet::docker_default(),
        );
    }

    /// Apply the launch-time policy from the container's OWN capability set,
    /// because Docker's profile is capability-conditional: the same
    /// `--cap-add SYS_ADMIN` that raises the capability set also lifts the
    /// profile's denial of `bpf`/`unshare`/`setns`/`io_uring`. The grant and
    /// the policy now come from one authority (`Container::granted_caps`), so
    /// they cannot disagree the way a static grant applied in a different
    /// order could. Must be called before the guest boots.
    pub fn apply_launch_privileges(
        &mut self,
        policy: carrick_spec::SeccompPolicy,
        container: &crate::kernel::container::Container,
    ) {
        self.install_container_policy(policy, container.granted_caps());
    }

    fn install_container_policy(
        &mut self,
        policy: carrick_spec::SeccompPolicy,
        caps: crate::namespace::process::CapabilitySet,
    ) {
        let policy_model = match policy {
            carrick_spec::SeccompPolicy::ContainerDefault => Some(
                crate::container_policy::ContainerPolicy::docker_model_with_capabilities(
                    caps.effective,
                ),
            ),
            carrick_spec::SeccompPolicy::Unconfined => None,
        };
        let user_observers = self
            .observers
            .as_ref()
            .map(|c| c.user_observers().to_vec())
            .unwrap_or_default();
        if policy_model.is_some() || !user_observers.is_empty() {
            self.observers = Some(Arc::new(crate::observe::ObserverChain::new(
                policy_model,
                user_observers,
            )));
        } else {
            self.observers = None;
        }
    }

    pub fn install_observer(&mut self, observer: Arc<dyn crate::observe::SyscallObserver>) {
        let policy = self.observers.as_ref().and_then(|c| c.policy().cloned());
        let mut user_observers = self
            .observers
            .as_ref()
            .map(|c| c.user_observers().to_vec())
            .unwrap_or_default();
        user_observers.push(observer);
        self.observers = Some(Arc::new(crate::observe::ObserverChain::new(
            policy,
            user_observers,
        )));
    }

    pub fn observers(&self) -> Option<&Arc<crate::observe::ObserverChain>> {
        self.observers.as_ref()
    }

    /// Append one trusted interceptor while the dispatcher is still being
    /// prepared. Each registration replaces the stored immutable chain; no
    /// execution-time mutation surface is exposed.
    pub fn install_interceptor(
        &mut self,
        interceptor: Arc<dyn crate::observe::SyscallInterceptor>,
    ) {
        let chain = match self.interceptors.as_ref() {
            Some(chain) => chain.with_appended(interceptor),
            None => crate::observe::intercept::InterceptorChain::new(vec![interceptor]),
        };
        self.interceptors = Some(Arc::new(chain));
    }

    #[cfg(test)]
    pub(crate) fn interceptors(&self) -> Option<&Arc<crate::observe::intercept::InterceptorChain>> {
        self.interceptors.as_ref()
    }

    pub fn set_observers(&mut self, observers: Option<Arc<crate::observe::ObserverChain>>) {
        self.observers = observers;
    }

    #[cfg(test)]
    pub(crate) fn container_policy(&self) -> Option<&crate::container_policy::ContainerPolicy> {
        self.observers.as_ref().and_then(|c| c.policy())
    }

    /// Evaluate installed seccomp filters against `request` before its handler
    /// runs. Returns `Some(outcome)` when a filter blocks the call (ERRNO →
    /// that errno; KILL/TRAP → terminate, fail-closed), or `None` to allow it.
    /// Fast path: no lock when no filter is installed.
    fn seccomp_precheck(&self, request: &SyscallRequest) -> Option<DispatchOutcome> {
        if !self.seccomp.is_active() {
            return None;
        }
        // Feed the filter the guest's ISA-native arch + syscall number. Using
        // the canonical (aarch64) number or a hardcoded aarch64 arch makes an
        // x86_64 guest fail its own Docker/libseccomp profile, which gates on
        // `arch == AUDIT_ARCH_X86_64` then switches on x86_64 syscall numbers.
        let data = crate::seccomp::SeccompData::for_guest(
            request.native_number.raw() as i32,
            request.guest_abi,
            request.args.0,
        );
        let ret = self.seccomp.check(&data);
        match ret & crate::seccomp::SECCOMP_RET_ACTION_FULL {
            crate::seccomp::SECCOMP_RET_ALLOW
            | crate::seccomp::SECCOMP_RET_LOG
            | crate::seccomp::SECCOMP_RET_TRACE => None,
            crate::seccomp::SECCOMP_RET_ERRNO => {
                // RET_DATA is the errno, clamped to the kernel's 0..=4095 range.
                // data == 0 is allowed by the ABI and makes the syscall return
                // 0 (-0): not a LinuxErrno domain value, so surface it as a
                // plain 0 return — the guest-visible retval is identical.
                let errno = (ret & crate::seccomp::SECCOMP_RET_DATA).min(4095) as i32;
                Some(if errno == 0 {
                    DispatchOutcome::Returned { value: 0 }
                } else {
                    DispatchOutcome::Errno {
                        errno: LinuxErrno::new(errno),
                    }
                })
            }
            // KILL_PROCESS / KILL_THREAD / TRAP (and any unmodelled action): fail
            // closed by KILLING the guest with SIGSYS — a real signal DEATH, so a
            // waiting parent sees WIFSIGNALED + SIGSYS (libseccomp's own tests and
            // container runtimes check exactly that), not WIFEXITED(159). Using
            // `Exit{128+31}` produced the same shell $? but the wrong wait status.
            // A *catchable* SIGSYS with SYS_SECCOMP si_code for RET_TRAP is a
            // follow-up.
            crate::seccomp::SECCOMP_RET_KILL_PROCESS
            | crate::seccomp::SECCOMP_RET_KILL_THREAD
            | crate::seccomp::SECCOMP_RET_TRAP => Some(DispatchOutcome::SignalDeath {
                signum: crate::linux_abi::LINUX_SIGSYS,
            }),
            _ => Some(DispatchOutcome::SignalDeath {
                signum: crate::linux_abi::LINUX_SIGSYS,
            }),
        }
    }

    /// Apply every one-time syscall transform and policy layer in the single
    /// authoritative order, then publish the effective entry exactly once.
    pub(crate) fn prepare_syscall(
        &self,
        kernel: &crate::kernel::KernelContext,
        original: SyscallRequest,
        reporter: &CompatReporter,
    ) -> Result<PreparedDispatch, DispatchError> {
        let original_args = original.args;
        let process = crate::observe::ProcessInfo::new(kernel);
        let interception = match self.interceptors.as_ref() {
            Some(chain) => chain.apply(&process, &original)?,
            None => crate::observe::intercept::Interception {
                effective_args: original_args,
                proposed: None,
            },
        };
        let mut syscall = PreparedSyscall {
            original_args,
            request: SyscallRequest {
                args: interception.effective_args,
                ..original
            },
        };
        let mut terminal = None;

        // Launch policy is authoritative over a trusted interceptor proposal.
        if let Some(chain) = self.observers.as_ref()
            && let Some(action) = chain.check_policy(&process, &syscall.effective_info())
        {
            match action {
                crate::observe::SyscallAction::Allow => {}
                crate::observe::SyscallAction::Deny(errno) => {
                    reporter.record(CompatEvent::partial_syscall(
                        syscall.request.number.raw(),
                        syscall.effective_info().name(),
                        syscall.request.args,
                        "denied by launch-time container syscall policy (Docker default-seccomp model)",
                    ));
                    merge_policy_terminal(&mut terminal, DispatchOutcome::Errno { errno });
                }
                crate::observe::SyscallAction::Kill(signal) => {
                    merge_policy_terminal(
                        &mut terminal,
                        DispatchOutcome::SignalDeath { signum: signal.0 },
                    );
                }
                crate::observe::SyscallAction::Short(count) => {
                    if crate::observe::is_shortable_syscall(syscall.request.number) {
                        syscall.request.args.0[2] =
                            (syscall.request.args.0[2] as usize).min(count) as u64;
                    }
                }
            }
        }

        // Guest seccomp validates the effective request and may veto a proposal.
        if let Some(outcome) = self.seccomp_precheck(&syscall.request) {
            merge_policy_terminal(&mut terminal, outcome);
        }

        // User observers see the same effective request the handler will receive.
        if let Some(chain) = self.observers.as_ref()
            && chain.has_user_observers()
        {
            match chain.on_user_syscall(&process, &syscall.effective_info()) {
                crate::observe::SyscallAction::Allow => {}
                crate::observe::SyscallAction::Deny(errno) => {
                    merge_policy_terminal(&mut terminal, DispatchOutcome::Errno { errno });
                }
                crate::observe::SyscallAction::Kill(signal) => {
                    merge_policy_terminal(
                        &mut terminal,
                        DispatchOutcome::SignalDeath { signum: signal.0 },
                    );
                }
                crate::observe::SyscallAction::Short(count) => {
                    if crate::observe::is_shortable_syscall(syscall.request.number) {
                        syscall.request.args.0[2] =
                            (syscall.request.args.0[2] as usize).min(count) as u64;
                    }
                }
            }
        }

        // CPU/resource policy remains a one-time entry check and cannot be
        // bypassed by a trusted terminal proposal.
        if terminal.is_none()
            && let Err(outcome) = time::check_cpu_limits(kernel)
        {
            terminal = Some(outcome);
        }

        let name = syscall.effective_info().name();
        for (number, arg_index, mask) in SYSCALL_FLAG_VALIDATORS {
            if *number == syscall.request.number.raw() {
                check_syscall_flags(
                    reporter,
                    syscall.request.number.raw(),
                    name,
                    *arg_index,
                    syscall.request.arg(*arg_index as usize),
                    *mask,
                );
            }
        }
        reporter.record(CompatEvent::SyscallEntry {
            number: syscall.request.number.raw(),
            name: ::std::borrow::Cow::Borrowed(name),
            args: syscall.request.args,
        });
        if syscall.original_args != syscall.request.args {
            reporter.record(CompatEvent::SyscallRewrite {
                number: syscall.request.number.raw(),
                name: ::std::borrow::Cow::Borrowed(name),
                original_args: syscall.original_args,
                effective_args: syscall.request.args,
            });
        }

        let proposed = interception.proposed.map(|outcome| match outcome.errno {
            Some(errno) => DispatchOutcome::Errno { errno },
            None => DispatchOutcome::Returned {
                value: outcome.value,
            },
        });
        match terminal.or(proposed) {
            Some(outcome) => Ok(PreparedDispatch::Complete { syscall, outcome }),
            None => Ok(PreparedDispatch::Invoke(syscall)),
        }
    }

    pub(crate) fn identity_fast_path_enabled(&self) -> bool {
        // The EL1 shim answers identity syscalls without a dispatch, so it must
        // be off whenever a guest filter is active OR an observer requests full visibility.
        !self.requires_syscall_traps()
    }

    pub(crate) fn requires_syscall_traps(&self) -> bool {
        self.interceptors.is_some()
            || self.seccomp.is_active()
            || self.observers.as_ref().is_some_and(|chain| {
                chain.wants_fast_path_visibility() == crate::observe::FastPathVisibility::Required
            })
    }

    /// Live gate consumed by JIT contexts. The launch-time policy is
    /// immutable once execution starts; guest seccomp transitions flip the
    /// returned atomic word from 1 to 0 before publishing their filter.
    #[allow(dead_code)]
    pub(crate) fn identity_fast_path_word(&self) -> Option<&std::sync::atomic::AtomicU32> {
        if self.interceptors.is_some()
            || self.observers.as_ref().is_some_and(|chain| {
                chain.wants_fast_path_visibility() == crate::observe::FastPathVisibility::Required
            })
        {
            None
        } else {
            Some(self.seccomp.identity_fast_path_word())
        }
    }
}
