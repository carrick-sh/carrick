//! Fault injection observer for syscalls and process lifecycle.
//!
//! # Theory of operation
//!
//! [`FaultInjector`] is a [`super::SyscallObserver`] that injects failures, delays,
//! truncated I/O, or signals into guest syscall execution. Rules are compiled
//! through [`carrick_abi::syscall`] into a canonical-number bitset for fast lookup.
//!
//! Counting and probability state is keyed strictly on [`crate::kernel::TaskKey`],
//! never a host pid, ensuring multiple guest processes maintain independent fault ledgers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use carrick_abi::{CanonicalNr, LinuxErrno};

use super::{FastPathVisibility, ProcessInfo, SyscallAction, SyscallInfo, SyscallObserver};
use crate::dispatch::Signal;
use crate::kernel::TaskKey;

/// A compact bitset of canonical syscall numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallBitset {
    standard: [u64; 8],
    extra: Vec<CanonicalNr>,
    match_all: bool,
}

impl Default for SyscallBitset {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallBitset {
    pub const fn new() -> Self {
        Self {
            standard: [0; 8],
            extra: Vec::new(),
            match_all: false,
        }
    }

    pub const fn all() -> Self {
        Self {
            standard: [!0; 8],
            extra: Vec::new(),
            match_all: true,
        }
    }

    pub fn insert(&mut self, nr: CanonicalNr) {
        let raw = nr.raw();
        if raw < 512 {
            let idx = (raw / 64) as usize;
            let bit = raw % 64;
            self.standard[idx] |= 1 << bit;
        } else if !self.extra.contains(&nr) {
            self.extra.push(nr);
        }
    }

    pub fn contains(&self, nr: CanonicalNr) -> bool {
        if self.match_all {
            return true;
        }
        let raw = nr.raw();
        if raw < 512 {
            let idx = (raw / 64) as usize;
            let bit = raw % 64;
            (self.standard[idx] & (1 << bit)) != 0
        } else {
            self.extra.contains(&nr)
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.match_all && self.standard.iter().all(|&w| w == 0) && self.extra.is_empty()
    }
}

/// Type alias for dynamic custom predicate in [`FaultCondition::When`].
pub type FaultPredicate = Arc<dyn Fn(&ProcessInfo<'_>, &SyscallInfo<'_>) -> bool + Send + Sync>;

/// A condition evaluated before a fault action is taken.
#[derive(Clone)]
pub enum FaultCondition {
    /// Always inject the fault.
    Always,
    /// Inject with probability `[0.0, 1.0]` using a deterministic seed.
    Probability { probability: f64, seed: u64 },
    /// Inject only after `count` matching invocations on the target task.
    AfterCount(u64),
    /// Inject only within `duration` of the injector's creation.
    ForDuration(Duration),
    /// Custom predicate.
    When(FaultPredicate),
    /// All sub-conditions must match.
    And(Vec<FaultCondition>),
    /// At least one sub-condition must match.
    Or(Vec<FaultCondition>),
}

impl std::fmt::Debug for FaultCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Always => write!(f, "Always"),
            Self::Probability { probability, seed } => {
                write!(f, "Probability({probability}, seed={seed})")
            }
            Self::AfterCount(n) => write!(f, "AfterCount({n})"),
            Self::ForDuration(d) => write!(f, "ForDuration({d:?})"),
            Self::When(_) => write!(f, "When(<fn>)"),
            Self::And(conds) => f.debug_tuple("And").field(conds).finish(),
            Self::Or(conds) => f.debug_tuple("Or").field(conds).finish(),
        }
    }
}

/// Deterministic pseudo-random number generator (splitmix64).
fn splitmix64(state: u64) -> u64 {
    let mut z = state.wrapping_add(0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// The action to perform when a fault rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultAction {
    /// Return `errno` immediately before the syscall handler executes.
    Errno(LinuxErrno),
    /// Short I/O: clamp requested read/write/send/recv count to `n` bytes.
    Short(usize),
    /// Delay the calling thread via the container's virtual time scheduler.
    Delay(Duration),
    /// Delay then return `errno`.
    DelayThenErrno(Duration, LinuxErrno),
    /// Delay then clamp count to `n`.
    DelayThenShort(Duration, usize),
    /// Kill the calling process (or task) with `signal`.
    Kill(Signal),
    /// Delay then kill.
    DelayThenKill(Duration, Signal),
}

/// A single compiled fault injection rule.
#[derive(Debug, Clone)]
pub struct FaultRule {
    pub syscalls: SyscallBitset,
    pub condition: FaultCondition,
    pub action: FaultAction,
}

impl FaultRule {
    pub fn matches_syscall(&self, nr: CanonicalNr) -> bool {
        self.syscalls.contains(nr)
    }
}

#[derive(Debug)]
struct FaultState {
    task_counts: HashMap<(TaskKey, CanonicalNr), u64>,
    created_at: Instant,
}

/// Fault injection observer.
#[derive(Clone)]
pub struct FaultInjector {
    rules: Vec<FaultRule>,
    state: Arc<Mutex<FaultState>>,
}

impl Default for FaultInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl FaultInjector {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            state: Arc::new(Mutex::new(FaultState {
                task_counts: HashMap::new(),
                created_at: Instant::now(),
            })),
        }
    }

    pub fn with_rule(mut self, rule: FaultRule) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn add_rule(&mut self, rule: FaultRule) -> &mut Self {
        self.rules.push(rule);
        self
    }

    pub fn rules(&self) -> &[FaultRule] {
        &self.rules
    }

    /// Begin defining a rule for the named syscall.
    pub fn on(self, name: &str) -> FaultRuleBuilder {
        let mut bitset = SyscallBitset::new();
        if let Some(entry) = carrick_abi::syscall::lookup_aarch64_by_name(name) {
            bitset.insert(CanonicalNr(entry.number));
        }
        FaultRuleBuilder {
            injector: self,
            syscalls: bitset,
            condition: FaultCondition::Always,
        }
    }

    /// Begin defining a rule for a raw syscall number.
    pub fn on_nr(self, nr: u64) -> FaultRuleBuilder {
        let mut bitset = SyscallBitset::new();
        bitset.insert(CanonicalNr(nr));
        FaultRuleBuilder {
            injector: self,
            syscalls: bitset,
            condition: FaultCondition::Always,
        }
    }

    /// Begin defining a rule matching any syscall.
    pub fn on_any(self) -> FaultRuleBuilder {
        FaultRuleBuilder {
            injector: self,
            syscalls: SyscallBitset::all(),
            condition: FaultCondition::Always,
        }
    }

    /// Convenience: inject `ENOMEM` on `mmap`, `brk`, `mremap` after `count` allocations.
    pub fn oom_after(count: u64) -> Self {
        let mut bitset = SyscallBitset::new();
        for name in &["mmap", "brk", "mremap"] {
            if let Some(entry) = carrick_abi::syscall::lookup_aarch64_by_name(name) {
                bitset.insert(CanonicalNr(entry.number));
            }
        }
        let rule = FaultRule {
            syscalls: bitset,
            condition: FaultCondition::AfterCount(count),
            action: FaultAction::Errno(carrick_abi::LINUX_ENOMEM),
        };
        Self::new().with_rule(rule)
    }

    /// Convenience: inject `ECONNREFUSED` on all network connection / socket operations.
    pub fn network_partition() -> Self {
        let mut bitset = SyscallBitset::new();
        for name in &[
            "connect", "sendto", "sendmsg", "recvfrom", "recvmsg", "socket", "bind", "listen",
            "accept", "accept4",
        ] {
            if let Some(entry) = carrick_abi::syscall::lookup_aarch64_by_name(name) {
                bitset.insert(CanonicalNr(entry.number));
            }
        }
        let rule = FaultRule {
            syscalls: bitset,
            condition: FaultCondition::Always,
            action: FaultAction::Errno(carrick_abi::LINUX_ECONNREFUSED),
        };
        Self::new().with_rule(rule)
    }

    /// Convenience: inject `latency` delay on filesystem operations.
    pub fn slow_disk(latency: Duration) -> Self {
        let mut bitset = SyscallBitset::new();
        for name in &[
            "openat",
            "read",
            "write",
            "pread64",
            "pwrite64",
            "readv",
            "writev",
            "fsync",
            "fdatasync",
            "close",
            "statx",
            "newfstatat",
            "unlinkat",
            "mkdirat",
        ] {
            if let Some(entry) = carrick_abi::syscall::lookup_aarch64_by_name(name) {
                bitset.insert(CanonicalNr(entry.number));
            }
        }
        let rule = FaultRule {
            syscalls: bitset,
            condition: FaultCondition::Always,
            action: FaultAction::Delay(latency),
        };
        Self::new().with_rule(rule)
    }

    fn eval_condition(
        cond: &FaultCondition,
        p: &ProcessInfo<'_>,
        s: &SyscallInfo<'_>,
        state: &mut FaultState,
    ) -> bool {
        match cond {
            FaultCondition::Always => true,
            FaultCondition::Probability { probability, seed } => {
                let key = (p.task_key(), s.canonical_number());
                let count = state.task_counts.get(&key).copied().unwrap_or(0);
                let rand_val = splitmix64(
                    seed.wrapping_add(p.task_key().serial.raw())
                        .wrapping_add(count << 16),
                );
                let threshold = (probability.clamp(0.0, 1.0) * (u64::MAX as f64)) as u64;
                rand_val <= threshold
            }
            FaultCondition::AfterCount(n) => {
                let key = (p.task_key(), s.canonical_number());
                let count = state.task_counts.get(&key).copied().unwrap_or(0);
                count > *n
            }
            FaultCondition::ForDuration(duration) => state.created_at.elapsed() <= *duration,
            FaultCondition::When(predicate) => predicate(p, s),
            FaultCondition::And(conds) => {
                conds.iter().all(|c| Self::eval_condition(c, p, s, state))
            }
            FaultCondition::Or(conds) => conds.iter().any(|c| Self::eval_condition(c, p, s, state)),
        }
    }
}

impl SyscallObserver for FaultInjector {
    fn on_syscall(&self, p: &ProcessInfo<'_>, s: &SyscallInfo<'_>) -> SyscallAction {
        if self.rules.is_empty() {
            return SyscallAction::Allow;
        }

        let nr = s.canonical_number();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Increment count for this (TaskKey, CanonicalNr)
        let key = (p.task_key(), nr);
        let count_slot = state.task_counts.entry(key).or_insert(0);
        *count_slot = count_slot.saturating_add(1);

        for rule in &self.rules {
            if !rule.matches_syscall(nr) {
                continue;
            }
            if Self::eval_condition(&rule.condition, p, s, &mut state) {
                // Execute action
                match rule.action {
                    FaultAction::Errno(errno) => return SyscallAction::Deny(errno),
                    FaultAction::Short(n) => return SyscallAction::Short(n),
                    FaultAction::Delay(dur) => {
                        drop(state);
                        p.context().task().container().clock().delay(dur);
                        return SyscallAction::Allow;
                    }
                    FaultAction::DelayThenErrno(dur, errno) => {
                        drop(state);
                        p.context().task().container().clock().delay(dur);
                        return SyscallAction::Deny(errno);
                    }
                    FaultAction::DelayThenShort(dur, n) => {
                        drop(state);
                        p.context().task().container().clock().delay(dur);
                        return SyscallAction::Short(n);
                    }
                    FaultAction::Kill(sig) => return SyscallAction::Kill(sig),
                    FaultAction::DelayThenKill(dur, sig) => {
                        drop(state);
                        p.context().task().container().clock().delay(dur);
                        return SyscallAction::Kill(sig);
                    }
                }
            }
        }

        SyscallAction::Allow
    }

    fn wants_fast_path_visibility(&self) -> FastPathVisibility {
        for rule in &self.rules {
            if rule.syscalls.match_all {
                return FastPathVisibility::Required;
            }
            for &fast_nr in super::policy::FAST_PATH_SYSCALL_NUMBERS {
                if rule.syscalls.contains(CanonicalNr(fast_nr)) {
                    return FastPathVisibility::Required;
                }
            }
        }
        FastPathVisibility::Blind
    }

    fn on_process_exit(&self, p: &ProcessInfo<'_>, _status: crate::observe::ExitStatus) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let task_key = p.task_key();
        state.task_counts.retain(|(k, _), _| *k != task_key);
    }
}

/// Builder for constructing rules on a [`FaultInjector`].
pub struct FaultRuleBuilder {
    injector: FaultInjector,
    syscalls: SyscallBitset,
    condition: FaultCondition,
}

impl FaultRuleBuilder {
    pub fn on_syscall(mut self, name: &str) -> Self {
        if let Some(entry) = carrick_abi::syscall::lookup_aarch64_by_name(name) {
            self.syscalls.insert(CanonicalNr(entry.number));
        }
        self
    }

    pub fn or(self, name: &str) -> Self {
        self.on_syscall(name)
    }

    pub fn or_syscall(self, name: &str) -> Self {
        self.on_syscall(name)
    }

    pub fn or_nr(mut self, nr: u64) -> Self {
        self.syscalls.insert(CanonicalNr(nr));
        self
    }

    pub fn when(
        mut self,
        predicate: impl Fn(&ProcessInfo<'_>, &SyscallInfo<'_>) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.condition = FaultCondition::When(Arc::new(predicate));
        self
    }

    pub fn probability(mut self, probability: f64) -> Self {
        self.condition = FaultCondition::Probability {
            probability,
            seed: 0x5a5a_a5a5_1234_5678,
        };
        self
    }

    pub fn probability_with_seed(mut self, probability: f64, seed: u64) -> Self {
        self.condition = FaultCondition::Probability { probability, seed };
        self
    }

    pub fn after_count(mut self, count: u64) -> Self {
        self.condition = FaultCondition::AfterCount(count);
        self
    }

    pub fn for_duration(mut self, duration: Duration) -> Self {
        self.condition = FaultCondition::ForDuration(duration);
        self
    }

    pub fn condition(mut self, condition: FaultCondition) -> Self {
        self.condition = condition;
        self
    }

    pub fn fail_with(self, errno: LinuxErrno) -> FaultInjector {
        self.finish(FaultAction::Errno(errno))
    }

    pub fn short(self, n: usize) -> FaultInjector {
        self.finish(FaultAction::Short(n))
    }

    pub fn delay(self, duration: Duration) -> FaultInjector {
        self.finish(FaultAction::Delay(duration))
    }

    pub fn kill(self, signal: Signal) -> FaultInjector {
        self.finish(FaultAction::Kill(signal))
    }

    pub fn action(self, action: FaultAction) -> FaultInjector {
        self.finish(action)
    }

    fn finish(mut self, action: FaultAction) -> FaultInjector {
        self.injector.rules.push(FaultRule {
            syscalls: self.syscalls,
            condition: self.condition,
            action,
        });
        self.injector
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::SyscallRequest;
    use crate::kernel::{Kernel, KernelContext, RootBootstrap};
    use crate::observe::{ProcessInfo, SyscallInfo};
    use carrick_abi::{LINUX_EACCES, LINUX_ENOMEM, LINUX_SIGKILL};
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
            format!("test-fault-{task_id}"),
        )
        .expect("root bootstrap");
        Kernel::bootstrap_root(bootstrap).expect("root kernel").1
    }

    fn make_req(number: u64, args: [u64; 6]) -> SyscallRequest {
        SyscallRequest::new(number, SyscallArgs(args))
    }

    #[test]
    fn oom_after_injects_enomem_after_count() {
        let injector = FaultInjector::oom_after(2);
        let ctx = test_kernel_context(1);
        let proc = ProcessInfo::new(&ctx);
        let mmap_req = make_req(nr("mmap"), [0; 6]);
        let mmap_info = SyscallInfo::new(&mmap_req);
        let read_req = make_req(nr("read"), [0; 6]);
        let read_info = SyscallInfo::new(&read_req);

        // Unrelated syscall is unaffected
        assert_eq!(injector.on_syscall(&proc, &read_info), SyscallAction::Allow);

        // First 2 mmaps are allowed
        assert_eq!(injector.on_syscall(&proc, &mmap_info), SyscallAction::Allow);
        assert_eq!(injector.on_syscall(&proc, &mmap_info), SyscallAction::Allow);

        // 3rd and subsequent are denied with ENOMEM
        assert_eq!(
            injector.on_syscall(&proc, &mmap_info),
            SyscallAction::Deny(LINUX_ENOMEM)
        );
        assert_eq!(
            injector.on_syscall(&proc, &mmap_info),
            SyscallAction::Deny(LINUX_ENOMEM)
        );
    }

    #[test]
    fn network_partition_injects_econnrefused() {
        let injector = FaultInjector::network_partition();
        let ctx = test_kernel_context(1);
        let proc = ProcessInfo::new(&ctx);
        let connect_req = make_req(nr("connect"), [0; 6]);
        let connect_info = SyscallInfo::new(&connect_req);
        let sendto_req = make_req(nr("sendto"), [0; 6]);
        let sendto_info = SyscallInfo::new(&sendto_req);

        assert_eq!(
            injector.on_syscall(&proc, &connect_info),
            SyscallAction::Deny(carrick_abi::LINUX_ECONNREFUSED)
        );
        assert_eq!(
            injector.on_syscall(&proc, &sendto_info),
            SyscallAction::Deny(carrick_abi::LINUX_ECONNREFUSED)
        );
    }

    #[test]
    fn slow_disk_injects_delay() {
        let injector = FaultInjector::slow_disk(Duration::from_millis(5));
        let ctx = test_kernel_context(1);
        let proc = ProcessInfo::new(&ctx);
        let read_req = make_req(nr("read"), [0; 6]);
        let read_info = SyscallInfo::new(&read_req);

        assert_eq!(injector.on_syscall(&proc, &read_info), SyscallAction::Allow);
    }

    #[test]
    fn short_write_action() {
        let injector = FaultInjector::new().on("write").short(42);
        let ctx = test_kernel_context(1);
        let proc = ProcessInfo::new(&ctx);
        let write_req = make_req(nr("write"), [0, 0, 100, 0, 0, 0]);
        let write_info = SyscallInfo::new(&write_req);

        assert_eq!(
            injector.on_syscall(&proc, &write_info),
            SyscallAction::Short(42)
        );
    }

    #[test]
    fn kill_action() {
        let injector = FaultInjector::new()
            .on("unlinkat")
            .kill(Signal(LINUX_SIGKILL));
        let ctx = test_kernel_context(1);
        let proc = ProcessInfo::new(&ctx);
        let unlink_req = make_req(nr("unlinkat"), [0; 6]);
        let unlink_info = SyscallInfo::new(&unlink_req);

        assert_eq!(
            injector.on_syscall(&proc, &unlink_info),
            SyscallAction::Kill(Signal(LINUX_SIGKILL))
        );
    }

    #[test]
    fn probability_condition_is_deterministic() {
        let injector = FaultInjector::new()
            .on("read")
            .probability_with_seed(0.5, 12345)
            .fail_with(LINUX_EACCES);
        let ctx = test_kernel_context(1);
        let proc = ProcessInfo::new(&ctx);
        let read_req = make_req(nr("read"), [0; 6]);
        let read_info = SyscallInfo::new(&read_req);

        let mut denied = 0;
        let mut allowed = 0;
        for _ in 0..100 {
            match injector.on_syscall(&proc, &read_info) {
                SyscallAction::Deny(LINUX_EACCES) => denied += 1,
                SyscallAction::Allow => allowed += 1,
                _ => panic!("unexpected action"),
            }
        }
        assert!(denied > 20 && denied < 80);
        assert!(allowed > 20 && allowed < 80);
    }

    #[test]
    fn task_scoped_counts_are_independent() {
        let injector = FaultInjector::oom_after(1);
        let ctx1 = test_kernel_context(1);
        let ctx2 = test_kernel_context(2);
        let proc1 = ProcessInfo::new(&ctx1);
        let proc2 = ProcessInfo::new(&ctx2);
        let mmap_req = make_req(nr("mmap"), [0; 6]);
        let mmap_info = SyscallInfo::new(&mmap_req);

        // Proc 1 call 1: allowed
        assert_eq!(
            injector.on_syscall(&proc1, &mmap_info),
            SyscallAction::Allow
        );
        // Proc 1 call 2: denied
        assert_eq!(
            injector.on_syscall(&proc1, &mmap_info),
            SyscallAction::Deny(LINUX_ENOMEM)
        );

        // Proc 2 has independent count: call 1 allowed!
        assert_eq!(
            injector.on_syscall(&proc2, &mmap_info),
            SyscallAction::Allow
        );
        // Proc 2 call 2: denied
        assert_eq!(
            injector.on_syscall(&proc2, &mmap_info),
            SyscallAction::Deny(LINUX_ENOMEM)
        );

        // On process exit, state is cleared
        injector.on_process_exit(&proc1, crate::observe::ExitStatus::Exited(0));
        // Next invocation for proc1 restarts counter
        assert_eq!(
            injector.on_syscall(&proc1, &mmap_info),
            SyscallAction::Allow
        );
    }
}
