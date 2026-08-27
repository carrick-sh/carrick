//! Observer pipeline for syscalls, lifecycle events, and process accounting.

pub mod audit;
pub mod budget;
pub mod fault;
pub mod policy;
pub mod sandbox;

pub use audit::{AuditEvent, AuditObserver};
pub use budget::{BudgetCounters, BudgetResource, BudgetSnapshot, ExceedAction, ResourceBudget};
pub use fault::{
    FaultAction, FaultCondition, FaultInjector, FaultPredicate, FaultRule, FaultRuleBuilder,
    SyscallBitset,
};
pub use policy::{ArgFilter, PolicyObserver, PolicyRule};
pub use sandbox::{SandboxObserver, SandboxPreset};

use crate::dispatch::Signal;
use carrick_abi::{CanonicalNr, LinuxErrno};
use std::sync::Arc;

use crate::kernel::{LinuxWaitStatus, TaskKey, ThreadKey};

/// Action returned by a [`SyscallObserver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyscallAction {
    #[default]
    Allow,
    Deny(LinuxErrno),
    Kill(Signal),
    /// Short I/O: clamp requested read/write/send/recv count to `n` bytes.
    Short(usize),
}

/// Returns true if `nr` is a read/write/send/recv syscall whose byte count can be clamped.
pub fn is_shortable_syscall(nr: CanonicalNr) -> bool {
    matches!(
        nr.raw(),
        63 | 64 | 65 | 66 | 67 | 68 | 206 | 207 | 211 | 212
    )
}

/// Requested fast-path visibility for an observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FastPathVisibility {
    #[default]
    Blind,
    Required,
}

/// Process exit outcome delivered to [`SyscallObserver::on_process_exit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    Exited(i32),
    Signaled(Signal),
}

impl ExitStatus {
    pub const fn from_wait_status(status: LinuxWaitStatus) -> Self {
        let raw = status.raw();
        let sig = raw & 0x7f;
        if sig != 0 {
            Self::Signaled(Signal(sig))
        } else {
            Self::Exited((raw >> 8) & 0xff)
        }
    }

    pub const fn from_code(code: i32) -> Self {
        Self::Exited(code)
    }

    pub const fn from_signal(signal: Signal) -> Self {
        Self::Signaled(signal)
    }

    pub const fn success(&self) -> bool {
        matches!(self, Self::Exited(0))
    }

    pub const fn code(&self) -> Option<i32> {
        match self {
            Self::Exited(code) => Some(*code),
            Self::Signaled(_) => None,
        }
    }

    pub const fn signal(&self) -> Option<Signal> {
        match self {
            Self::Exited(_) => None,
            Self::Signaled(sig) => Some(*sig),
        }
    }
}

/// Borrowed snapshot of process identity and credentials for an observer event.
///
/// Zero-allocation view into the coherent [`crate::kernel::KernelContext`].
#[derive(Debug, Clone, Copy)]
pub struct ProcessInfo<'a> {
    context: &'a crate::kernel::KernelContext,
}

impl<'a> ProcessInfo<'a> {
    pub const fn new(context: &'a crate::kernel::KernelContext) -> Self {
        Self { context }
    }

    pub fn pid(&self) -> i32 {
        self.context.task().key().id.raw()
    }

    pub fn tid(&self) -> i32 {
        self.context.thread().key().tid.raw()
    }

    pub fn task_key(&self) -> TaskKey {
        self.context.task().key()
    }

    pub fn thread_key(&self) -> ThreadKey {
        self.context.thread().key()
    }

    pub fn parent_task_key(&self) -> Option<TaskKey> {
        self.context.parent_at_capture()
    }

    pub fn pgrp(&self) -> crate::kernel::ProcessGroupId {
        self.context.task().process_group()
    }

    pub fn session_id(&self) -> crate::kernel::SessionId {
        self.context.task().session()
    }

    pub fn ruid(&self) -> carrick_abi::NsUid {
        self.context.task().process_credentials().ruid()
    }

    pub fn euid(&self) -> carrick_abi::NsUid {
        self.context.task().process_credentials().euid()
    }

    pub fn rgid(&self) -> carrick_abi::NsGid {
        self.context.task().process_credentials().rgid()
    }

    pub fn egid(&self) -> carrick_abi::NsGid {
        self.context.task().process_credentials().egid()
    }

    pub fn context(&self) -> &'a crate::kernel::KernelContext {
        self.context
    }
}

/// Borrowed snapshot of a syscall request and its ABI table entry.
///
/// Zero-allocation view into [`crate::dispatch::SyscallRequest`] and static table metadata.
#[derive(Debug, Clone, Copy)]
pub struct SyscallInfo<'a> {
    request: &'a crate::dispatch::SyscallRequest,
}

impl<'a> SyscallInfo<'a> {
    /// Borrow a request. The ABI table entry is resolved lazily by
    /// [`Self::table_entry`]: constructing this view sits on the lockless
    /// dispatch hot path and runs for every guest syscall whether or not any
    /// observer is installed, so it must not do the table binary search that
    /// only `name()`/`table_entry()` actually need.
    pub const fn new(request: &'a crate::dispatch::SyscallRequest) -> Self {
        Self { request }
    }

    pub fn canonical_number(&self) -> carrick_abi::CanonicalNr {
        self.request.number
    }

    pub fn number(&self) -> u64 {
        self.request.number.raw()
    }

    pub fn native_number(&self) -> u64 {
        self.request.native_number.raw()
    }

    pub fn name(&self) -> &'static str {
        self.table_entry().map_or("unknown", |entry| entry.name)
    }

    pub fn args(&self) -> [u64; 6] {
        self.request.args.0
    }

    pub fn arg(&self, index: usize) -> u64 {
        self.request.arg(index)
    }

    pub fn raw_args(&self) -> carrick_observability::compat::SyscallArgs {
        self.request.args
    }

    pub fn guest_abi(&self) -> carrick_abi::LinuxGuestAbi {
        self.request.guest_abi
    }

    pub fn current_guest_sp(&self) -> Option<u64> {
        self.request.current_guest_sp
    }

    pub fn table_entry(&self) -> Option<&'static carrick_abi::syscall::Syscall> {
        carrick_abi::syscall::lookup_aarch64(self.request.number.raw())
    }

    pub fn request(&self) -> &'a crate::dispatch::SyscallRequest {
        self.request
    }
}

/// Final outcome of a completed syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallOutcome {
    pub value: i64,
    pub errno: Option<LinuxErrno>,
}

impl SyscallOutcome {
    pub const fn from_retval(value: i64) -> Self {
        Self {
            value,
            errno: LinuxErrno::from_guest_retval(value),
        }
    }

    pub const fn returned(value: i64) -> Self {
        Self { value, errno: None }
    }

    pub const fn errno(errno: LinuxErrno) -> Self {
        Self {
            value: errno.guest_retval(),
            errno: Some(errno),
        }
    }

    pub const fn is_ok(&self) -> bool {
        self.errno.is_none()
    }
}

/// The observer trait for observing and filtering Linux syscalls and process lifecycle.
pub trait SyscallObserver: Send + Sync {
    fn on_syscall(&self, _p: &ProcessInfo<'_>, _s: &SyscallInfo<'_>) -> SyscallAction {
        SyscallAction::Allow
    }
    fn on_syscall_return(&self, _p: &ProcessInfo<'_>, _s: &SyscallInfo<'_>, _o: &SyscallOutcome) {}
    fn on_process_create(&self, _parent: &ProcessInfo<'_>, _child: TaskKey) {}
    fn on_exec(&self, _p: &ProcessInfo<'_>, _exe: &[u8], _argv: &[&[u8]]) -> SyscallAction {
        SyscallAction::Allow
    }
    fn on_process_exit(&self, _p: &ProcessInfo<'_>, _status: ExitStatus) {}
    fn wants_fast_path_visibility(&self) -> FastPathVisibility {
        FastPathVisibility::Blind
    }
}

impl SyscallObserver for carrick_observability::compat::CompatReporter {
    fn on_syscall_return(&self, _p: &ProcessInfo<'_>, s: &SyscallInfo<'_>, o: &SyscallOutcome) {
        self.record(carrick_observability::compat::CompatEvent::SyscallReturn {
            number: s.number(),
            name: std::borrow::Cow::Borrowed(s.name()),
            retval: o.value,
            errno: o.errno.map(|e| e.get()),
        });
    }
}

/// An ordered chain of observers combining built-in policy/reporting and user-installed observers.
#[derive(Clone)]
pub struct ObserverChain {
    policy: Option<crate::container_policy::ContainerPolicy>,
    observers: Vec<Arc<dyn SyscallObserver>>,
    fast_path_visibility: FastPathVisibility,
}

impl ObserverChain {
    pub(crate) fn new(
        policy: Option<crate::container_policy::ContainerPolicy>,
        observers: Vec<Arc<dyn SyscallObserver>>,
    ) -> Self {
        let mut fast_path_visibility = FastPathVisibility::Blind;
        if policy
            .as_ref()
            .is_some_and(|p| p.wants_fast_path_visibility() == FastPathVisibility::Required)
        {
            fast_path_visibility = FastPathVisibility::Required;
        }
        for obs in &observers {
            if obs.wants_fast_path_visibility() == FastPathVisibility::Required {
                fast_path_visibility = FastPathVisibility::Required;
                break;
            }
        }
        Self {
            policy,
            observers,
            fast_path_visibility,
        }
    }

    pub fn has_policy(&self) -> bool {
        self.policy.is_some()
    }

    pub(crate) fn policy(&self) -> Option<&crate::container_policy::ContainerPolicy> {
        self.policy.as_ref()
    }

    pub fn check_policy(&self, p: &ProcessInfo<'_>, s: &SyscallInfo<'_>) -> Option<SyscallAction> {
        if let Some(ref pol) = self.policy {
            let action = pol.on_syscall(p, s);
            if action != SyscallAction::Allow {
                return Some(action);
            }
        }
        None
    }

    pub fn has_user_observers(&self) -> bool {
        !self.observers.is_empty()
    }

    pub fn user_observers(&self) -> &[Arc<dyn SyscallObserver>] {
        &self.observers
    }

    pub fn on_user_syscall(&self, p: &ProcessInfo<'_>, s: &SyscallInfo<'_>) -> SyscallAction {
        for obs in &self.observers {
            let action = obs.on_syscall(p, s);
            if action != SyscallAction::Allow {
                return action;
            }
        }
        SyscallAction::Allow
    }

    pub fn on_syscall_return(&self, p: &ProcessInfo<'_>, s: &SyscallInfo<'_>, o: &SyscallOutcome) {
        if let Some(ref pol) = self.policy {
            pol.on_syscall_return(p, s, o);
        }
        for obs in &self.observers {
            obs.on_syscall_return(p, s, o);
        }
    }

    pub fn on_process_create(&self, parent: &ProcessInfo<'_>, child: TaskKey) {
        if let Some(ref pol) = self.policy {
            pol.on_process_create(parent, child);
        }
        for obs in &self.observers {
            obs.on_process_create(parent, child);
        }
    }

    pub fn on_exec(&self, p: &ProcessInfo<'_>, exe: &[u8], argv: &[&[u8]]) -> SyscallAction {
        if let Some(ref pol) = self.policy {
            let action = pol.on_exec(p, exe, argv);
            if action != SyscallAction::Allow {
                return action;
            }
        }
        for obs in &self.observers {
            let action = obs.on_exec(p, exe, argv);
            if action != SyscallAction::Allow {
                return action;
            }
        }
        SyscallAction::Allow
    }

    pub fn on_process_exit(&self, p: &ProcessInfo<'_>, status: ExitStatus) {
        if let Some(ref pol) = self.policy {
            pol.on_process_exit(p, status);
        }
        for obs in &self.observers {
            obs.on_process_exit(p, status);
        }
    }

    pub fn wants_fast_path_visibility(&self) -> FastPathVisibility {
        self.fast_path_visibility
    }
}

#[cfg(test)]
mod tests;
