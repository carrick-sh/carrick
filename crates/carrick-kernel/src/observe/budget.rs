//! Resource budget quota and live counters on [`crate::kernel::Container`].
//!
//! # Theory of operation
//!
//! [`ResourceBudget`] defines enforceable quotas on a container:
//! - Processes (checked at `PreparedFork::commit` / fork reservation)
//! - Syscalls (checked at dispatch admission; fast-path shim calls recorded separately)
//! - CPU time (measured from task ledgers as wall-clock duration inside `hv_vcpu_run`)
//! - Memory (committed virtual address space maintained in `MemState`)
//! - Bytes written (checked and clamped at write/send path)
//!
//! All counters are live and atomic; [`ResourceBudget::counters`] returns a
//! generation-stamped [`BudgetSnapshot`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use carrick_abi::LinuxErrno;
use serde::{Deserialize, Serialize};

use super::{
    ExitStatus, FastPathVisibility, ProcessInfo, SyscallAction, SyscallInfo, SyscallObserver,
    SyscallOutcome,
};
use crate::dispatch::Signal;
use crate::kernel::TaskKey;

/// Which resource triggered a budget exceed event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetResource {
    Processes,
    Syscalls,
    CpuTime,
    Memory,
    BytesWritten,
}

impl std::fmt::Display for BudgetResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Processes => write!(f, "processes"),
            Self::Syscalls => write!(f, "syscalls"),
            Self::CpuTime => write!(f, "cpu_time"),
            Self::Memory => write!(f, "memory"),
            Self::BytesWritten => write!(f, "bytes_written"),
        }
    }
}

/// Action to take when a resource budget quota is exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExceedAction {
    /// Terminate the task or container with `SIGKILL`.
    #[default]
    Kill,
    /// Deliver a specific signal (e.g. `SIGXCPU`).
    Signal(Signal),
    /// Return `errno` to the calling syscall (e.g. `EAGAIN`, `ENOMEM`, `EFBIG`).
    Errno(LinuxErrno),
}

/// Live, generation-stamped snapshot of container budget counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetSnapshot {
    /// Monotonic generation incremented on counter mutations.
    pub generation: u64,
    /// Current number of live processes in the container.
    pub processes: u64,
    /// Total syscalls dispatched to user handlers.
    pub syscalls: u64,
    /// Syscalls served by fast-path shims (e.g. EL1 getpid/gettid).
    pub fast_path_syscalls: u64,
    /// Total guest CPU duration (wall-clock time inside `hv_vcpu_run`).
    pub cpu_time: Duration,
    /// Committed virtual address space in bytes across the container.
    pub committed_memory_bytes: u64,
    /// Total bytes written via write/writev/pwrite/sendto/sendmsg.
    pub bytes_written: u64,
}

/// Shared atomic counter store for a container's resource budget.
#[derive(Debug, Default)]
pub struct BudgetCounters {
    generation: AtomicU64,
    processes: AtomicU64,
    syscalls: AtomicU64,
    fast_path_syscalls: AtomicU64,
    cpu_time_us: AtomicU64,
    committed_memory_bytes: AtomicU64,
    bytes_written: AtomicU64,
}

impl BudgetCounters {
    pub fn new() -> Self {
        Self {
            generation: AtomicU64::new(1),
            processes: AtomicU64::new(1), // Root process starts at 1
            syscalls: AtomicU64::new(0),
            fast_path_syscalls: AtomicU64::new(0),
            cpu_time_us: AtomicU64::new(0),
            committed_memory_bytes: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
        }
    }

    #[inline]
    fn bump_gen(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    pub fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            generation: self.generation.load(Ordering::Acquire),
            processes: self.processes.load(Ordering::Acquire),
            syscalls: self.syscalls.load(Ordering::Acquire),
            fast_path_syscalls: self.fast_path_syscalls.load(Ordering::Acquire),
            cpu_time: Duration::from_micros(self.cpu_time_us.load(Ordering::Acquire)),
            committed_memory_bytes: self.committed_memory_bytes.load(Ordering::Acquire),
            bytes_written: self.bytes_written.load(Ordering::Acquire),
        }
    }

    pub fn processes(&self) -> u64 {
        self.processes.load(Ordering::Acquire)
    }

    pub fn syscalls(&self) -> u64 {
        self.syscalls.load(Ordering::Acquire)
    }

    pub fn fast_path_syscalls(&self) -> u64 {
        self.fast_path_syscalls.load(Ordering::Acquire)
    }

    pub fn cpu_time_us(&self) -> u64 {
        self.cpu_time_us.load(Ordering::Acquire)
    }

    pub fn committed_memory_bytes(&self) -> u64 {
        self.committed_memory_bytes.load(Ordering::Acquire)
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written.load(Ordering::Acquire)
    }
}

/// Quotas and observer for a container's resource consumption.
#[derive(Debug, Clone)]
pub struct ResourceBudget {
    max_processes: Option<u64>,
    max_syscalls: Option<u64>,
    max_cpu_time: Option<Duration>,
    max_memory_bytes: Option<u64>,
    max_bytes_written: Option<u64>,
    on_exceed: ExceedAction,
    counters: Arc<BudgetCounters>,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceBudget {
    pub fn new() -> Self {
        Self {
            max_processes: None,
            max_syscalls: None,
            max_cpu_time: None,
            max_memory_bytes: None,
            max_bytes_written: None,
            on_exceed: ExceedAction::Kill,
            counters: Arc::new(BudgetCounters::new()),
        }
    }

    pub fn max_processes(mut self, n: u64) -> Self {
        self.max_processes = Some(n);
        self
    }

    pub fn max_syscalls(mut self, n: u64) -> Self {
        self.max_syscalls = Some(n);
        self
    }

    pub fn max_cpu_time(mut self, duration: Duration) -> Self {
        self.max_cpu_time = Some(duration);
        self
    }

    pub fn max_memory(mut self, bytes: u64) -> Self {
        self.max_memory_bytes = Some(bytes);
        self
    }

    pub fn max_memory_bytes(mut self, bytes: u64) -> Self {
        self.max_memory_bytes = Some(bytes);
        self
    }

    pub fn max_bytes_written(mut self, bytes: u64) -> Self {
        self.max_bytes_written = Some(bytes);
        self
    }

    pub fn on_exceed(mut self, action: ExceedAction) -> Self {
        self.on_exceed = action;
        self
    }

    pub fn is_empty(&self) -> bool {
        self.max_processes.is_none()
            && self.max_syscalls.is_none()
            && self.max_cpu_time.is_none()
            && self.max_memory_bytes.is_none()
            && self.max_bytes_written.is_none()
    }

    pub fn record_syscall(&self, fast_path: bool) {
        if fast_path {
            self.counters
                .fast_path_syscalls
                .fetch_add(1, Ordering::AcqRel);
        } else {
            self.counters.syscalls.fetch_add(1, Ordering::AcqRel);
        }
        self.counters.bump_gen();
    }

    pub fn max_processes_limit(&self) -> Option<u64> {
        self.max_processes
    }

    pub fn max_syscalls_limit(&self) -> Option<u64> {
        self.max_syscalls
    }

    pub fn max_cpu_time_limit(&self) -> Option<Duration> {
        self.max_cpu_time
    }

    pub fn max_memory_limit(&self) -> Option<u64> {
        self.max_memory_bytes
    }

    pub fn max_bytes_written_limit(&self) -> Option<u64> {
        self.max_bytes_written
    }

    pub fn exceed_action(&self) -> ExceedAction {
        self.on_exceed
    }

    pub fn raw_counters(&self) -> &Arc<BudgetCounters> {
        &self.counters
    }

    /// Return a generation-stamped snapshot of live resource counters.
    pub fn counters(&self) -> BudgetSnapshot {
        self.counters.snapshot()
    }

    /// Check and account for a new process creation (`fork`/`clone`).
    ///
    /// Called during `PreparedFork::commit`. If the new process would exceed
    /// `max_processes`, returns `Err(on_exceed)`. Otherwise increments process count.
    pub fn check_process_creation(&self) -> Result<(), ExceedAction> {
        if let Some(max) = self.max_processes {
            let current = self.counters.processes.load(Ordering::Acquire);
            if current >= max {
                return Err(self.on_exceed);
            }
        }
        self.counters.processes.fetch_add(1, Ordering::AcqRel);
        self.counters.bump_gen();
        Ok(())
    }

    /// Record process exit, decrementing the live process counter.
    pub fn record_process_exit(&self) {
        let prev = self.counters.processes.load(Ordering::Acquire);
        if prev > 0 {
            self.counters.processes.fetch_sub(1, Ordering::AcqRel);
            self.counters.bump_gen();
        }
    }

    /// Check and account for a dispatched syscall.
    pub fn check_and_record_syscall(&self) -> Result<(), ExceedAction> {
        let count = self.counters.syscalls.fetch_add(1, Ordering::AcqRel) + 1;
        self.counters.bump_gen();
        if let Some(max) = self.max_syscalls {
            if count > max {
                return Err(self.on_exceed);
            }
        }
        Ok(())
    }

    /// Record a fast-path shim syscall.
    pub fn record_fast_path_syscall(&self) {
        self.counters
            .fast_path_syscalls
            .fetch_add(1, Ordering::AcqRel);
        self.counters.syscalls.fetch_add(1, Ordering::AcqRel);
        self.counters.bump_gen();
    }

    /// Check committed virtual memory growth against `max_memory_bytes`.
    pub fn check_memory_grow(&self, current: u64, grow: u64) -> Result<(), ExceedAction> {
        let total = current.saturating_add(grow);
        if let Some(max) = self.max_memory_bytes {
            if total > max {
                return Err(self.on_exceed);
            }
        }
        self.counters
            .committed_memory_bytes
            .store(total, Ordering::Release);
        self.counters.bump_gen();
        Ok(())
    }

    /// Record updated committed memory size.
    pub fn record_committed_memory(&self, bytes: u64) {
        self.counters
            .committed_memory_bytes
            .store(bytes, Ordering::Release);
        self.counters.bump_gen();
    }

    /// Check write bytes against `max_bytes_written` and clamp if near boundary.
    ///
    /// Returns `Ok(clamped_len)` (which may be `<= requested_len`), or `Err(on_exceed)`
    /// if budget is completely exhausted.
    pub fn check_and_clamp_write(&self, requested: u64) -> Result<u64, ExceedAction> {
        if let Some(max) = self.max_bytes_written {
            let current = self.counters.bytes_written.load(Ordering::Acquire);
            if current >= max {
                return Err(self.on_exceed);
            }
            let rem = max.saturating_sub(current);
            Ok(requested.min(rem))
        } else {
            Ok(requested)
        }
    }

    /// Record completed write bytes.
    pub fn record_bytes_written(&self, bytes: u64) {
        if bytes > 0 {
            self.counters
                .bytes_written
                .fetch_add(bytes, Ordering::AcqRel);
            self.counters.bump_gen();
        }
    }

    /// Check task CPU against `max_cpu_time`.
    ///
    /// Guest CPU time is wall-clock duration inside `hv_vcpu_run`.
    pub fn check_cpu_time(&self, cpu_us: u64) -> Option<ExceedAction> {
        self.counters.cpu_time_us.store(cpu_us, Ordering::Release);
        if let Some(max) = self.max_cpu_time {
            if Duration::from_micros(cpu_us) >= max {
                return Some(self.on_exceed);
            }
        }
        None
    }
}

impl SyscallObserver for ResourceBudget {
    fn on_syscall(&self, _p: &ProcessInfo<'_>, s: &SyscallInfo<'_>) -> SyscallAction {
        if let Err(action) = self.check_and_record_syscall() {
            return match action {
                ExceedAction::Kill => SyscallAction::Kill(Signal(carrick_abi::LINUX_SIGKILL)),
                ExceedAction::Signal(sig) => SyscallAction::Kill(sig),
                ExceedAction::Errno(errno) => SyscallAction::Deny(errno),
            };
        }

        // For write syscalls, check bytes written boundary
        let nr = s.canonical_number().raw();
        if nr == 64 || nr == 68 || nr == 206 {
            // write(fd, buf, count), pwrite64(fd, buf, count, offset), sendto(fd, buf, len, ...)
            let requested = s.arg(2);
            match self.check_and_clamp_write(requested) {
                Ok(clamped) if (clamped as usize) < (requested as usize) => {
                    return SyscallAction::Short(clamped as usize);
                }
                Ok(_) => {}
                Err(ExceedAction::Kill) => {
                    return SyscallAction::Kill(Signal(carrick_abi::LINUX_SIGKILL));
                }
                Err(ExceedAction::Signal(sig)) => {
                    return SyscallAction::Kill(sig);
                }
                Err(ExceedAction::Errno(errno)) => {
                    return SyscallAction::Deny(errno);
                }
            }
        }

        SyscallAction::Allow
    }

    fn on_syscall_return(
        &self,
        _p: &ProcessInfo<'_>,
        s: &SyscallInfo<'_>,
        outcome: &SyscallOutcome,
    ) {
        let nr = s.canonical_number().raw();
        if matches!(nr, 64 | 66 | 68 | 206 | 211) {
            // write, writev, pwrite64, sendto, sendmsg
            if outcome.is_ok() && outcome.value > 0 {
                self.record_bytes_written(outcome.value as u64);
            }
        }
    }

    fn on_process_create(&self, _parent: &ProcessInfo<'_>, _child: TaskKey) {
        // Tracked by PreparedFork::commit
    }

    fn on_process_exit(&self, _p: &ProcessInfo<'_>, _status: ExitStatus) {
        self.record_process_exit();
    }

    fn wants_fast_path_visibility(&self) -> FastPathVisibility {
        FastPathVisibility::Required
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::SyscallRequest;
    use crate::kernel::{Container, Kernel, KernelContext, RootBootstrap};
    use crate::observe::{ProcessInfo, SyscallInfo};
    use carrick_abi::{LINUX_EDQUOT, LINUX_ENOSPC};
    use carrick_observability::compat::SyscallArgs;

    fn nr(name: &str) -> u64 {
        carrick_abi::syscall::lookup_aarch64_by_name(name)
            .expect("valid syscall name")
            .number
    }

    fn test_kernel_context(task_id: i32) -> KernelContext {
        let bootstrap = RootBootstrap::for_reference_model(
            task_id,
            crate::thread::ThreadId::synthetic_for_tests(task_id),
            format!("test-budget-{task_id}"),
        )
        .expect("root bootstrap");
        Kernel::bootstrap_root(bootstrap).expect("root kernel").1
    }

    fn make_req(number: u64, args: [u64; 6]) -> SyscallRequest {
        SyscallRequest::new(number, SyscallArgs(args))
    }

    #[test]
    fn budget_disabled_path_costs_nothing() {
        let budget = ResourceBudget::new();
        assert!(budget.is_empty());
        assert_eq!(budget.max_processes_limit(), None);
        assert_eq!(budget.max_memory_limit(), None);
        assert_eq!(budget.check_cpu_time(1_000_000), None);
        assert!(budget.check_process_creation().is_ok());
    }

    #[test]
    fn budget_syscall_quota_enforcement() {
        let budget = ResourceBudget::new()
            .max_syscalls(3)
            .on_exceed(ExceedAction::Errno(LINUX_EDQUOT));
        let ctx = test_kernel_context(1);
        let proc = ProcessInfo::new(&ctx);
        let req = make_req(nr("getpid"), [0; 6]);
        let getpid_info = SyscallInfo::new(&req);

        // 1st, 2nd, 3rd allowed
        assert_eq!(budget.on_syscall(&proc, &getpid_info), SyscallAction::Allow);
        assert_eq!(budget.on_syscall(&proc, &getpid_info), SyscallAction::Allow);
        assert_eq!(budget.on_syscall(&proc, &getpid_info), SyscallAction::Allow);

        // 4th denied with EDQUOT
        assert_eq!(
            budget.on_syscall(&proc, &getpid_info),
            SyscallAction::Deny(LINUX_EDQUOT)
        );

        let snap = budget.counters();
        assert_eq!(snap.syscalls, 4);
        assert!(snap.generation >= 4);
    }

    #[test]
    fn budget_two_process_fork_inheritance_and_shared_budget() {
        let budget = Arc::new(
            ResourceBudget::new()
                .max_processes(2)
                .max_syscalls(10)
                .on_exceed(ExceedAction::Kill),
        );
        let container =
            Arc::new(Container::for_reference_model().with_resource_budget(Arc::clone(&budget)));
        let bootstrap = RootBootstrap::for_reference_model(
            100,
            crate::thread::ThreadId::synthetic_for_tests(100),
            "parent".to_string(),
        )
        .expect("root bootstrap")
        .with_container(container);
        let (kernel, parent) = Kernel::bootstrap_root(bootstrap).expect("parent context");

        // Initial process: 1
        assert_eq!(budget.raw_counters().processes(), 1);

        let fork_plan = || {
            crate::kernel::ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty())
                .expect("fork plan")
        };

        // First fork: allowed (now 2 processes)
        let res = kernel
            .reserve_fork(&parent, fork_plan(), "child-1".to_string(), None)
            .expect("first child fork allowed");
        let _child = res
            .prepare_reference(crate::thread::ThreadId::synthetic_for_tests(101))
            .expect("prepare child-1")
            .commit()
            .expect("commit child-1");
        assert_eq!(budget.raw_counters().processes(), 2);

        // Second fork: exceeds max_processes (2) -> rejected with ProcessLimitExceeded
        let err = kernel.reserve_fork(&parent, fork_plan(), "child-2".to_string(), None);
        assert!(err.is_err(), "second child fork must exceed process budget");

        // Both processes share the same budget syscall counter
        let parent_proc = ProcessInfo::new(&parent);
        let req = make_req(nr("getpid"), [0; 6]);
        let getpid_info = SyscallInfo::new(&req);
        assert_eq!(
            budget.on_syscall(&parent_proc, &getpid_info),
            SyscallAction::Allow
        );

        // Child process exit decrements the process count
        budget.record_process_exit();
        assert_eq!(budget.raw_counters().processes(), 1);

        // Now another fork can succeed!
        let res2 = kernel
            .reserve_fork(&parent, fork_plan(), "child-3".to_string(), None)
            .expect("child fork allowed after exit");
        let _child2 = res2
            .prepare_reference(crate::thread::ThreadId::synthetic_for_tests(103))
            .expect("prepare child-3")
            .commit()
            .expect("commit child-3");
        assert_eq!(budget.raw_counters().processes(), 2);
    }

    #[test]
    fn budget_partial_write_clamping_at_boundary() {
        let budget = ResourceBudget::new()
            .max_bytes_written(100)
            .on_exceed(ExceedAction::Errno(LINUX_ENOSPC));
        let ctx1 = test_kernel_context(1);
        let ctx2 = test_kernel_context(2);
        let proc1 = ProcessInfo::new(&ctx1);
        let proc2 = ProcessInfo::new(&ctx2);

        // Process 1 requests writing 60 bytes -> allowed full length
        let req_60 = make_req(nr("write"), [0, 0, 60, 0, 0, 0]);
        let write_60 = SyscallInfo::new(&req_60);
        assert_eq!(budget.on_syscall(&proc1, &write_60), SyscallAction::Allow);
        budget.on_syscall_return(
            &proc1,
            &write_60,
            &crate::observe::SyscallOutcome::returned(60),
        );
        assert_eq!(budget.raw_counters().bytes_written(), 60);

        // Process 2 requests writing 50 bytes -> clamped to 40 bytes (100 - 60)
        let req_50 = make_req(nr("write"), [0, 0, 50, 0, 0, 0]);
        let write_50 = SyscallInfo::new(&req_50);
        assert_eq!(
            budget.on_syscall(&proc2, &write_50),
            SyscallAction::Short(40)
        );
        budget.on_syscall_return(
            &proc2,
            &write_50,
            &crate::observe::SyscallOutcome::returned(40),
        );
        assert_eq!(budget.raw_counters().bytes_written(), 100);

        // Process 1 requests writing more -> denied with ENOSPC
        let req_10 = make_req(nr("write"), [0, 0, 10, 0, 0, 0]);
        let write_10 = SyscallInfo::new(&req_10);
        assert_eq!(
            budget.on_syscall(&proc1, &write_10),
            SyscallAction::Deny(LINUX_ENOSPC)
        );
    }

    #[test]
    fn budget_generation_stamps_are_monotonic() {
        let budget = ResourceBudget::new();
        let s1 = budget.counters();
        budget.record_syscall(false);
        let s2 = budget.counters();
        budget.record_bytes_written(10);
        let s3 = budget.counters();

        assert!(s2.generation > s1.generation);
        assert!(s3.generation > s2.generation);
        assert_eq!(s3.syscalls, 1);
        assert_eq!(s3.bytes_written, 10);
    }
}
