//! Sandbox preset composition observer.

use super::policy::{PolicyObserver, PolicyRule};
use super::{
    ExitStatus, FastPathVisibility, ProcessInfo, SyscallAction, SyscallInfo, SyscallObserver,
    SyscallOutcome,
};
use crate::dispatch::Signal;
use carrick_abi::{CanonicalNr, LinuxErrno};
use std::sync::Arc;

fn syscall_nr(name: &'static str) -> Option<CanonicalNr> {
    carrick_abi::syscall::lookup_aarch64_by_name(name).map(|entry| CanonicalNr(entry.number))
}

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
                for name in [
                    "socket",
                    "socketpair",
                    "bind",
                    "listen",
                    "accept",
                    "connect",
                    "sendto",
                    "recvfrom",
                    "accept4",
                ] {
                    if let Some(nr) = syscall_nr(name) {
                        policy.add_rule(PolicyRule::deny(nr, carrick_abi::LINUX_EPERM));
                    }
                }
            }
            Self::ReadOnlyFs => {
                for name in [
                    "mkdirat",
                    "unlinkat",
                    "renameat",
                    "truncate",
                    "ftruncate",
                    "fchmodat",
                    "fchownat",
                    "renameat2",
                ] {
                    if let Some(nr) = syscall_nr(name) {
                        policy.add_rule(PolicyRule::deny(nr, carrick_abi::LINUX_EROFS));
                    }
                }
            }
            Self::NoNewProcesses => {
                for name in ["unshare", "clone", "execve", "setns", "execveat", "clone3"] {
                    if let Some(nr) = syscall_nr(name) {
                        policy.add_rule(PolicyRule::deny(nr, carrick_abi::LINUX_EPERM));
                    }
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
    blind_spot_accepted: bool,
}

impl SandboxObserver {
    pub const fn new() -> Self {
        Self {
            policy: PolicyObserver::new(),
            sub_observers: Vec::new(),
            blind_spot_accepted: false,
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

    pub fn accept_fast_path_blind_spot(mut self) -> Self {
        self.blind_spot_accepted = true;
        self.policy = self.policy.accept_fast_path_blind_spot();
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
        if self.blind_spot_accepted {
            return FastPathVisibility::Blind;
        }
        if self.policy.wants_fast_path_visibility() == FastPathVisibility::Required {
            return FastPathVisibility::Required;
        }
        for obs in &self.sub_observers {
            if obs.wants_fast_path_visibility() == FastPathVisibility::Required {
                return FastPathVisibility::Required;
            }
        }
        FastPathVisibility::Blind
    }
}
