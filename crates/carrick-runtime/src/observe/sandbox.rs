//! Sandbox preset composition observer.

use super::policy::{PolicyObserver, PolicyRule};
use super::{
    ExitStatus, FastPathVisibility, ProcessInfo, SyscallAction, SyscallInfo, SyscallObserver,
    SyscallOutcome,
};
use crate::dispatch::Signal;
use carrick_abi::{CanonicalNr, LinuxErrno};
use std::sync::Arc;

/// High-level preset security profiles composed by [`SandboxObserver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxPreset {
    /// Denies socket creation, connection, and listening.
    NoNetwork,
    /// Denies filesystem mutations (unlinkat, mkdirat, renameat, rmdir, truncate, fchmod, fchown).
    ReadOnlyFs,
    /// Denies process creation and execution (clone, clone3, execve, execveat, unshare, setns).
    NoNewProcesses,
}

impl SandboxPreset {
    /// Expand the preset into concrete typed rules on a [`PolicyObserver`].
    pub fn apply_to(&self, policy: &mut PolicyObserver) {
        match self {
            Self::NoNetwork => {
                // Deny socket operations
                const SYS_SOCKET: u64 = 198;
                const SYS_SOCKETPAIR: u64 = 199;
                const SYS_BIND: u64 = 200;
                const SYS_LISTEN: u64 = 201;
                const SYS_ACCEPT: u64 = 202;
                const SYS_CONNECT: u64 = 203;
                const SYS_SENDTO: u64 = 206;
                const SYS_RECVFROM: u64 = 207;
                const SYS_ACCEPT4: u64 = 242;

                for nr in [
                    SYS_SOCKET,
                    SYS_SOCKETPAIR,
                    SYS_BIND,
                    SYS_LISTEN,
                    SYS_ACCEPT,
                    SYS_CONNECT,
                    SYS_SENDTO,
                    SYS_RECVFROM,
                    SYS_ACCEPT4,
                ] {
                    policy.add_rule(PolicyRule::deny(CanonicalNr(nr), carrick_abi::LINUX_EPERM));
                }
            }
            Self::ReadOnlyFs => {
                // Deny mutating FS operations
                const SYS_MKDIRAT: u64 = 34;
                const SYS_UNLINKAT: u64 = 35;
                const SYS_RENAMEAT: u64 = 38;
                const SYS_TRUNCATE: u64 = 45;
                const SYS_FTRUNCATE: u64 = 46;
                const SYS_FCHMODAT: u64 = 53;
                const SYS_FCHOWNAT: u64 = 54;
                const SYS_RENAMEAT2: u64 = 276;

                for nr in [
                    SYS_MKDIRAT,
                    SYS_UNLINKAT,
                    SYS_RENAMEAT,
                    SYS_TRUNCATE,
                    SYS_FTRUNCATE,
                    SYS_FCHMODAT,
                    SYS_FCHOWNAT,
                    SYS_RENAMEAT2,
                ] {
                    policy.add_rule(PolicyRule::deny(CanonicalNr(nr), carrick_abi::LINUX_EROFS));
                }
            }
            Self::NoNewProcesses => {
                // Deny process spawning and namespace changes
                const SYS_UNSHARE: u64 = 97;
                const SYS_CLONE: u64 = 220;
                const SYS_EXECVE: u64 = 221;
                const SYS_SETNS: u64 = 268;
                const SYS_EXECVEAT: u64 = 281;
                const SYS_CLONE3: u64 = 435;

                for nr in [
                    SYS_UNSHARE,
                    SYS_CLONE,
                    SYS_EXECVE,
                    SYS_SETNS,
                    SYS_EXECVEAT,
                    SYS_CLONE3,
                ] {
                    policy.add_rule(PolicyRule::deny(CanonicalNr(nr), carrick_abi::LINUX_EPERM));
                }
            }
        }
    }
}

/// Composite sandbox observer that combines standard presets and custom sub-observers.
#[derive(Clone, Default)]
pub struct SandboxObserver {
    policy: PolicyObserver,
    sub_observers: Vec<Arc<dyn SyscallObserver>>,
    fast_path_visibility: FastPathVisibility,
}

impl SandboxObserver {
    pub const fn new() -> Self {
        Self {
            policy: PolicyObserver::new(),
            sub_observers: Vec::new(),
            fast_path_visibility: FastPathVisibility::Blind,
        }
    }

    pub fn with_preset(preset: SandboxPreset) -> Self {
        let mut sandbox = Self::new();
        sandbox.add_preset(preset);
        sandbox
    }

    pub fn add_preset(&mut self, preset: SandboxPreset) -> &mut Self {
        preset.apply_to(&mut self.policy);
        self
    }

    pub fn with_preset_chained(mut self, preset: SandboxPreset) -> Self {
        self.add_preset(preset);
        self
    }

    pub fn add_observer(&mut self, observer: Arc<dyn SyscallObserver>) -> &mut Self {
        if observer.wants_fast_path_visibility() == FastPathVisibility::Required {
            self.fast_path_visibility = FastPathVisibility::Required;
        }
        self.sub_observers.push(observer);
        self
    }

    pub fn with_observer(mut self, observer: Arc<dyn SyscallObserver>) -> Self {
        self.add_observer(observer);
        self
    }

    pub fn deny(mut self, nr: CanonicalNr, errno: LinuxErrno) -> Self {
        self.policy = self.policy.deny(nr, errno);
        self
    }

    pub fn kill(mut self, nr: CanonicalNr, signal: Signal) -> Self {
        self.policy = self.policy.kill(nr, signal);
        self
    }

    pub fn require_fast_path_visibility(mut self) -> Self {
        self.fast_path_visibility = FastPathVisibility::Required;
        self.policy = self.policy.require_fast_path_visibility();
        self
    }

    pub fn policy(&self) -> &PolicyObserver {
        &self.policy
    }

    pub fn sub_observers(&self) -> &[Arc<dyn SyscallObserver>] {
        &self.sub_observers
    }
}

impl SyscallObserver for SandboxObserver {
    fn on_syscall(&self, p: &ProcessInfo<'_>, s: &SyscallInfo<'_>) -> SyscallAction {
        let action = self.policy.on_syscall(p, s);
        if action != SyscallAction::Allow {
            return action;
        }
        for obs in &self.sub_observers {
            let action = obs.on_syscall(p, s);
            if action != SyscallAction::Allow {
                return action;
            }
        }
        SyscallAction::Allow
    }

    fn on_syscall_return(&self, p: &ProcessInfo<'_>, s: &SyscallInfo<'_>, o: &SyscallOutcome) {
        self.policy.on_syscall_return(p, s, o);
        for obs in &self.sub_observers {
            obs.on_syscall_return(p, s, o);
        }
    }

    fn on_process_create(&self, parent: &ProcessInfo<'_>, child: crate::kernel::TaskKey) {
        self.policy.on_process_create(parent, child);
        for obs in &self.sub_observers {
            obs.on_process_create(parent, child);
        }
    }

    fn on_exec(&self, p: &ProcessInfo<'_>, exe: &[u8], argv: &[&[u8]]) -> SyscallAction {
        let action = self.policy.on_exec(p, exe, argv);
        if action != SyscallAction::Allow {
            return action;
        }
        for obs in &self.sub_observers {
            let action = obs.on_exec(p, exe, argv);
            if action != SyscallAction::Allow {
                return action;
            }
        }
        SyscallAction::Allow
    }

    fn on_process_exit(&self, p: &ProcessInfo<'_>, status: ExitStatus) {
        self.policy.on_process_exit(p, status);
        for obs in &self.sub_observers {
            obs.on_process_exit(p, status);
        }
    }

    fn wants_fast_path_visibility(&self) -> FastPathVisibility {
        self.fast_path_visibility
    }
}
