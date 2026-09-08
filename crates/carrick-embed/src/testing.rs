//! Test-facing conveniences: a reusable [`TestContainer`], the one-liner
//! [`run_in_container`], and [`ResultAssert`] for fluent assertions on a
//! [`ContainerResult`]. Guest-running uses of these belong in tests executed
//! by the signed `just test-embed` recipe.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

pub mod invariants;

pub use crate::testing::invariants::{
    EveryChildRuns, ExitBudget, ExitBudgetMatcher, FirstTouchNeverDelivered, InvariantKind,
    NoOrphanZombie, NoWakeOfReapedTask, ProcessGraphLiveness,
};
use crate::{
    AuditObserver, ContainerBuilder, ContainerResult, EmbedError, ImageStore, PullPolicy,
    SyscallInterceptor, SyscallObserver,
};
use carrick_runtime::observe::KernelAuditor;

/// Read-only lifecycle telemetry for Carrick's own signed topology tests.
/// This is not part of the stable embedding API.
#[cfg(feature = "test-support")]
pub fn carrier_snapshot(
    carrier: &crate::Carrier,
) -> Result<carrick_runtime::CarrierSnapshot, EmbedError> {
    carrier.snapshot()
}

/// One image, many commands: each [`Self::run`] builds a fresh
/// [`ContainerBuilder`] with captured stdio, so tests read the guest's bytes
/// from the returned [`ContainerResult`].
#[derive(Clone)]
pub struct TestContainer {
    image: String,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    user: Option<String>,
    hostname: Option<String>,
    mounts: Vec<(String, String, bool)>,
    security_opts: Vec<String>,
    cap_add: Vec<String>,
    max_traps: Option<usize>,
    store: Option<ImageStore>,
    pull: Option<PullPolicy>,
    observers: Vec<Arc<dyn SyscallObserver>>,
    interceptors: Vec<Arc<dyn SyscallInterceptor>>,
    auditors: Vec<Arc<dyn KernelAuditor>>,
    disabled_invariants: BTreeSet<InvariantKind>,
    /// `None` until a test body arms `EveryChildRuns` — see
    /// [`Self::every_child_runs_timeout`].
    every_child_runs_timeout: Option<Duration>,
    /// `None` until a test body arms `ExitBudget` — see [`Self::exit_budget`].
    exit_budget: Option<(ExitBudgetMatcher, Duration)>,
    deadline: Option<std::time::Duration>,
}

impl std::fmt::Debug for TestContainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestContainer")
            .field("image", &self.image)
            .field("env", &self.env)
            .field("workdir", &self.workdir)
            .field("user", &self.user)
            .field("hostname", &self.hostname)
            .field("mounts", &self.mounts)
            .field("max_traps", &self.max_traps)
            .field("store", &self.store)
            .field("pull", &self.pull)
            .field("observers_count", &self.observers.len())
            .field("interceptors_count", &self.interceptors.len())
            .field("deadline", &self.deadline)
            .finish()
    }
}

impl TestContainer {
    pub fn new(image: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            env: Vec::new(),
            workdir: None,
            user: None,
            hostname: None,
            mounts: Vec::new(),
            security_opts: Vec::new(),
            cap_add: Vec::new(),
            max_traps: None,
            store: None,
            pull: None,
            observers: Vec::new(),
            interceptors: Vec::new(),
            auditors: Vec::new(),
            disabled_invariants: BTreeSet::new(),
            every_child_runs_timeout: None,
            exit_budget: None,
            deadline: None,
        }
    }

    /// Turn off one of the STRUCTURAL invariants that ship on by default
    /// ([`InvariantKind::NoOrphanZombie`], [`InvariantKind::ProcessGraphLiveness`],
    /// [`InvariantKind::NoWakeOfReapedTask`],
    /// [`InvariantKind::FirstTouchNeverDelivered`]).
    ///
    /// The TIMED invariants ([`InvariantKind::EveryChildRuns`],
    /// [`InvariantKind::ExitBudget`]) are not on by default, so naming one here
    /// only guarantees it stays off even if a later builder call arms it.
    pub fn without_invariant(mut self, invariant: InvariantKind) -> Self {
        self.disabled_invariants.insert(invariant);
        self
    }

    pub fn auditor(mut self, auditor: Arc<dyn KernelAuditor>) -> Self {
        self.auditors.push(auditor);
        self
    }

    /// ARM the timed [`EveryChildRuns`] invariant with `timeout`.
    ///
    /// Off unless a test body calls this: the bound is a number a human chose
    /// for one test's workload, so it cannot be a container-wide default. A
    /// legitimately slow first child (image resolution, a cold guest) is not a
    /// kernel defect, and defaulting it on aborted every long run.
    pub fn every_child_runs_timeout(mut self, timeout: Duration) -> Self {
        self.every_child_runs_timeout = Some(timeout);
        self
    }

    /// ARM the timed [`ExitBudget`] invariant: tasks matched by `select` must
    /// reach `exit_settled` within `within`.
    ///
    /// Off unless a test body calls this, for the same reason as
    /// [`Self::every_child_runs_timeout`] — a wall-clock exit budget is a
    /// per-test assertion, not a property of every container. A default 10 s
    /// budget aborted the probe lane's first case (image resolution plus a
    /// cold guest) with `exceeded exit budget of 10s`.
    pub fn exit_budget(mut self, select: ExitBudgetMatcher, within: Duration) -> Self {
        self.exit_budget = Some((select, within));
        self
    }

    /// The built-in invariants this container installs, in install order.
    ///
    /// The four STRUCTURAL invariants are load-independent judgements about
    /// the kernel graph, so they ship ON and come off only through
    /// [`Self::without_invariant`]. The two TIMED invariants appear ONLY when
    /// a test body armed them ([`Self::every_child_runs_timeout`],
    /// [`Self::exit_budget`]): a wall-clock bound is a number a human chose
    /// for one workload, and as a container-wide default it turns any
    /// legitimately long run into a kernel abort.
    fn invariant_auditors(&self) -> Vec<(InvariantKind, Arc<dyn KernelAuditor>)> {
        let structural: [(InvariantKind, Arc<dyn KernelAuditor>); 4] = [
            (InvariantKind::NoOrphanZombie, Arc::new(NoOrphanZombie)),
            (
                InvariantKind::ProcessGraphLiveness,
                Arc::new(ProcessGraphLiveness),
            ),
            (
                InvariantKind::NoWakeOfReapedTask,
                Arc::new(NoWakeOfReapedTask),
            ),
            (
                InvariantKind::FirstTouchNeverDelivered,
                Arc::new(FirstTouchNeverDelivered),
            ),
        ];
        let mut installed: Vec<(InvariantKind, Arc<dyn KernelAuditor>)> = structural
            .into_iter()
            .filter(|(kind, _)| !self.disabled_invariants.contains(kind))
            .collect();

        if let Some(timeout) = self.every_child_runs_timeout
            && !self
                .disabled_invariants
                .contains(&InvariantKind::EveryChildRuns)
        {
            installed.push((
                InvariantKind::EveryChildRuns,
                Arc::new(EveryChildRuns::new(timeout)),
            ));
        }
        if let Some((select, within)) = &self.exit_budget
            && !self
                .disabled_invariants
                .contains(&InvariantKind::ExitBudget)
        {
            installed.push((
                InvariantKind::ExitBudget,
                Arc::new(ExitBudget::new(select.clone(), *within)),
            ));
        }
        installed
    }

    /// Bound every [`Self::run`] by wall clock, ending in a POST-MORTEM.
    ///
    /// On expiry the kernel is aborted through the one fail-closed sink and
    /// the run returns [`EmbedError::KernelAborted`] carrying the kernel
    /// graph, its findings and the event ring — instead of a host `SIGKILL`
    /// that leaves an exit code and nothing to read.
    ///
    /// This is a TEST budget, so it is a number a human chose and can be wrong
    /// under load; the always-on `ProcessGraphLiveness` invariant is the
    /// load-independent one. Use this as a backstop and read the post-mortem
    /// before believing it.
    pub fn deadline(mut self, budget: std::time::Duration) -> Self {
        self.deadline = Some(budget);
        self
    }

    /// See [`ContainerBuilder::post_mortem_dir`]. Installed for the host
    /// process the moment it is called, so the capture lands there even if the
    /// abort fires before this container's builder is materialised.
    pub fn post_mortem_dir(self, dir: impl Into<std::path::PathBuf>) -> Self {
        carrick_runtime::kernel::debug::PostMortem::install_dir(dir.into());
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn workdir(mut self, path: impl Into<String>) -> Self {
        self.workdir = Some(path.into());
        self
    }

    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    pub fn security_opt(mut self, option: impl Into<String>) -> Self {
        self.security_opts.push(option.into());
        self
    }

    pub fn cap_add(mut self, capability: impl Into<String>) -> Self {
        self.cap_add.push(capability.into());
        self
    }

    pub fn mount(mut self, host: impl Into<String>, guest: impl Into<String>) -> Self {
        self.mounts.push((host.into(), guest.into(), false));
        self
    }

    pub fn mount_readonly(mut self, host: impl Into<String>, guest: impl Into<String>) -> Self {
        self.mounts.push((host.into(), guest.into(), true));
        self
    }

    pub fn max_traps(mut self, max_traps: usize) -> Self {
        self.max_traps = Some(max_traps);
        self
    }

    pub fn image_store(mut self, store: ImageStore) -> Self {
        self.store = Some(store);
        self
    }

    pub fn pull_policy(mut self, pull: PullPolicy) -> Self {
        self.pull = Some(pull);
        self
    }

    pub fn observer(mut self, observer: Arc<dyn SyscallObserver>) -> Self {
        self.observers.push(observer);
        self
    }

    pub fn interceptor(mut self, interceptor: Arc<dyn SyscallInterceptor>) -> Self {
        self.interceptors.push(interceptor);
        self
    }

    /// The builder one `run` would execute (exposed so request-level tests
    /// can check the lowering without a guest).
    pub fn builder<I, S>(&self, argv: I) -> ContainerBuilder
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut builder = ContainerBuilder::from_image(self.image.clone()).command(argv);
        for (key, value) in &self.env {
            builder = builder.env(key.clone(), value.clone());
        }
        if let Some(workdir) = &self.workdir {
            builder = builder.workdir(workdir.clone());
        }
        if let Some(user) = &self.user {
            builder = builder.user(user.clone());
        }
        if let Some(hostname) = &self.hostname {
            builder = builder.hostname(hostname.clone());
        }
        for option in &self.security_opts {
            builder = builder.security_opt(option.clone());
        }
        for capability in &self.cap_add {
            builder = builder.cap_add(capability.clone());
        }
        for (host, guest, readonly) in &self.mounts {
            if *readonly {
                builder = builder.mount_readonly(host.clone(), guest.clone());
            } else {
                builder = builder.mount(host.clone(), guest.clone());
            }
        }
        if let Some(max_traps) = self.max_traps {
            builder = builder.max_traps(max_traps);
        }
        if let Some(store) = &self.store {
            builder = builder.image_store(store.clone());
        }
        if let Some(pull) = self.pull {
            builder = builder.pull_policy(pull);
        }
        for obs in &self.observers {
            builder = builder.observer(Arc::clone(obs));
        }
        for interceptor in &self.interceptors {
            builder = builder.interceptor(Arc::clone(interceptor));
        }
        for (_kind, auditor) in self.invariant_auditors() {
            builder = builder.auditor(auditor);
        }
        for auditor in &self.auditors {
            builder = builder.auditor(Arc::clone(auditor));
        }
        builder
    }

    /// Run `argv` to completion (blocking; needs a signed executable).
    pub fn run<I, S>(&self, argv: I) -> Result<ContainerResult, EmbedError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let builder = self.builder(argv);
        match self.deadline {
            Some(budget) => crate::deadline::run_with_deadline(builder, budget),
            None => builder.run_blocking(),
        }
    }

    /// Run `argv` with a fresh [`AuditObserver`] installed with fast-path visibility enabled.
    ///
    /// Returns both the [`ContainerResult`] and the [`AuditObserver`] holding the recorded events.
    pub fn run_with_audit<I, S>(
        &self,
        argv: I,
    ) -> Result<(ContainerResult, Arc<AuditObserver>), EmbedError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let audit = Arc::new(AuditObserver::new().require_fast_path_visibility());
        let mut builder = self.builder(argv);
        builder = builder.observer(Arc::clone(&audit) as Arc<dyn SyscallObserver>);
        let result = builder.run_blocking()?;
        Ok((result, audit))
    }
}

/// `ContainerBuilder::from_image(image).command(cmd).run_blocking()`.
pub fn run_in_container(image: &str, cmd: &[&str]) -> Result<ContainerResult, EmbedError> {
    ContainerBuilder::from_image(image)
        .command(cmd.iter().copied())
        .run_blocking()
}

/// Fluent assertions; each returns `&Self` so they chain.
pub trait ResultAssert {
    fn assert_success(&self) -> &Self;
    fn assert_exit_code(&self, code: i32) -> &Self;
    fn assert_stdout_contains(&self, needle: &str) -> &Self;
    fn assert_stderr_contains(&self, needle: &str) -> &Self;
}

impl ResultAssert for ContainerResult {
    fn assert_success(&self) -> &Self {
        assert!(
            self.success(),
            "expected a successful run; exit_code={} signal={:?} trap_limit_hit={} stderr={:?}",
            self.exit_code,
            self.signal,
            self.trap_limit_hit,
            self.stderr_utf8()
        );
        self
    }

    fn assert_exit_code(&self, code: i32) -> &Self {
        assert_eq!(
            self.exit_code,
            code,
            "unexpected exit code; stderr={:?}",
            self.stderr_utf8()
        );
        self
    }

    fn assert_stdout_contains(&self, needle: &str) -> &Self {
        let stdout = self.stdout_utf8();
        assert!(
            stdout.contains(needle),
            "stdout does not contain {needle:?}; stdout={stdout:?}"
        );
        self
    }

    fn assert_stderr_contains(&self, needle: &str) -> &Self {
        let stderr = self.stderr_utf8();
        assert!(
            stderr.contains(needle),
            "stderr does not contain {needle:?}; stderr={stderr:?}"
        );
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CompatReport;

    struct ContinueInterceptor;

    impl crate::SyscallInterceptor for ContinueInterceptor {
        fn intercept(
            &self,
            _process: &crate::ProcessInfo<'_>,
            _call: &crate::InterceptedSyscall<'_>,
        ) -> crate::InterceptAction {
            crate::InterceptAction::Continue
        }
    }

    fn result(exit_code: i32, stdout: &str, stderr: &str) -> ContainerResult {
        ContainerResult {
            exit_code,
            signal: None,
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            trap_limit_hit: false,
            traps: 1,
            compat: CompatReport::default(),
            terminal_reason: None,
        }
    }

    #[test]
    fn assertions_chain_on_a_passing_result() {
        result(0, "hello world\n", "warn\n")
            .assert_success()
            .assert_exit_code(0)
            .assert_stdout_contains("hello")
            .assert_stderr_contains("warn");
    }

    #[test]
    #[should_panic(expected = "expected a successful run")]
    fn assert_success_panics_on_a_nonzero_exit() {
        result(3, "", "").assert_success();
    }

    #[test]
    #[should_panic(expected = "stdout does not contain")]
    fn assert_stdout_contains_panics_and_names_the_needle() {
        result(0, "abc", "").assert_stdout_contains("zzz");
    }

    #[test]
    fn test_container_builds_a_captured_request_per_run() {
        let container = TestContainer::new("ubuntu:24.04")
            .env("K", "v")
            .security_opt("seccomp=unconfined")
            .cap_add("SYS_TIME")
            .max_traps(9);
        let request = container.builder(["/bin/true"]).to_run_request().unwrap();
        assert_eq!(request.image_ref, "ubuntu:24.04");
        assert_eq!(request.args, vec!["/bin/true".to_string()]);
        assert_eq!(request.env_overrides, vec!["K=v".to_string()]);
        assert_eq!(request.security_opts, ["seccomp=unconfined"]);
        assert_eq!(request.cap_add, ["SYS_TIME"]);
        assert_eq!(request.max_traps, 9);
        assert_eq!(request.stdio, crate::StdioMode::Captured);
    }

    #[test]
    fn test_container_preserves_interceptor_registration_order() {
        let first: Arc<dyn crate::SyscallInterceptor> = Arc::new(ContinueInterceptor);
        let second: Arc<dyn crate::SyscallInterceptor> = Arc::new(ContinueInterceptor);
        let container = TestContainer::new("ubuntu:24.04")
            .interceptor(Arc::clone(&first))
            .interceptor(Arc::clone(&second));

        assert_eq!(container.interceptors.len(), 2);
        assert!(Arc::ptr_eq(&container.interceptors[0], &first));
        assert!(Arc::ptr_eq(&container.interceptors[1], &second));
    }

    fn installed_kinds(container: &TestContainer) -> Vec<InvariantKind> {
        container
            .invariant_auditors()
            .into_iter()
            .map(|(kind, _)| kind)
            .collect()
    }

    const STRUCTURAL: [InvariantKind; 4] = [
        InvariantKind::NoOrphanZombie,
        InvariantKind::ProcessGraphLiveness,
        InvariantKind::NoWakeOfReapedTask,
        InvariantKind::FirstTouchNeverDelivered,
    ];

    /// The four STRUCTURAL invariants ship on; the two TIMED ones do not.
    ///
    /// A default `ExitBudget { Any, 10s }` aborted the first case of every
    /// `just conformance-probes` shard with `exceeded exit budget of 10s`,
    /// because image resolution plus a cold guest legitimately takes longer
    /// than a bound nobody in that test chose.
    #[test]
    fn timed_invariants_are_not_armed_by_default() {
        let container = TestContainer::new("ubuntu:24.04");
        assert_eq!(container.every_child_runs_timeout, None);
        assert_eq!(container.exit_budget, None);
        assert_eq!(installed_kinds(&container), STRUCTURAL.to_vec());
    }

    #[test]
    fn arming_a_timed_invariant_installs_exactly_that_auditor() {
        let base = TestContainer::new("ubuntu:24.04");

        let with_budget = base
            .clone()
            .exit_budget(ExitBudgetMatcher::Any, Duration::from_secs(30));
        assert_eq!(
            with_budget.exit_budget,
            Some((ExitBudgetMatcher::Any, Duration::from_secs(30)))
        );
        assert_eq!(
            installed_kinds(&with_budget),
            [STRUCTURAL.as_slice(), &[InvariantKind::ExitBudget]].concat()
        );

        let with_children = base
            .clone()
            .every_child_runs_timeout(Duration::from_secs(7));
        assert_eq!(
            with_children.every_child_runs_timeout,
            Some(Duration::from_secs(7))
        );
        assert_eq!(
            installed_kinds(&with_children),
            [STRUCTURAL.as_slice(), &[InvariantKind::EveryChildRuns]].concat()
        );

        let with_both = with_budget.every_child_runs_timeout(Duration::from_secs(7));
        assert_eq!(
            installed_kinds(&with_both),
            [
                STRUCTURAL.as_slice(),
                &[InvariantKind::EveryChildRuns, InvariantKind::ExitBudget]
            ]
            .concat()
        );
    }

    /// `without_invariant` still governs the structural invariants, and still
    /// wins over an armed timed one.
    #[test]
    fn without_invariant_removes_structural_and_overrides_an_armed_timed_one() {
        let container =
            TestContainer::new("ubuntu:24.04").without_invariant(InvariantKind::NoOrphanZombie);
        assert_eq!(
            installed_kinds(&container),
            [
                InvariantKind::ProcessGraphLiveness,
                InvariantKind::NoWakeOfReapedTask,
                InvariantKind::FirstTouchNeverDelivered,
            ]
        );

        let armed_then_disabled = TestContainer::new("ubuntu:24.04")
            .exit_budget(ExitBudgetMatcher::Any, Duration::from_secs(30))
            .without_invariant(InvariantKind::ExitBudget);
        assert_eq!(installed_kinds(&armed_then_disabled), STRUCTURAL.to_vec());
    }
}

/// A trusted interceptor that stretches the scheduling window around the
/// syscalls a race reproducer names, by sleeping on the executor thread
/// BEFORE dispatch. It never changes a result: it only lets the rest of the
/// carrier run while one task sits at its syscall boundary, which is what a
/// preempted executor looks like under host load — without the host load.
/// Deterministic given the same syscall stream: the delay for the `n`-th
/// matching call is `(n * 7919) % (max_micros + 1)` microseconds.
#[derive(Debug)]
pub struct SyscallJitter {
    names: Vec<&'static str>,
    max_micros: u64,
    matched: std::sync::atomic::AtomicU64,
}

impl SyscallJitter {
    /// Jitter every syscall whose name is in `names` by up to `max_micros`.
    pub fn new(names: impl IntoIterator<Item = &'static str>, max_micros: u64) -> Self {
        Self {
            names: names.into_iter().collect(),
            max_micros,
            matched: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// How many syscalls this jitter has stretched so far.
    pub fn matched(&self) -> u64 {
        self.matched.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl SyscallInterceptor for SyscallJitter {
    fn intercept(
        &self,
        _process: &carrick_runtime::observe::ProcessInfo<'_>,
        call: &carrick_runtime::observe::InterceptedSyscall<'_>,
    ) -> carrick_runtime::observe::InterceptAction {
        if self.names.contains(&call.name()) {
            let n = self
                .matched
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let micros = n.wrapping_mul(7919) % (self.max_micros + 1);
            if micros > 0 {
                std::thread::sleep(std::time::Duration::from_micros(micros));
            }
        }
        carrick_runtime::observe::InterceptAction::Continue
    }
}

/// A deterministic, seeded PRNG for the scheduling policies below.
///
/// `rand` is not a dependency of this crate and a scheduling policy must not
/// take a lock to answer a placement, so this is a plain xorshift64* over one
/// atomic word: `fetch_update` is wait-free, and every draw advances the same
/// stream, so a seed plus a call COUNT reproduces a decision exactly.
#[derive(Debug)]
struct SeededStream {
    state: std::sync::atomic::AtomicU64,
    draws: std::sync::atomic::AtomicU64,
}

impl SeededStream {
    fn new(seed: u64) -> Self {
        Self {
            // xorshift is degenerate at zero, so no seed may reach it.
            state: std::sync::atomic::AtomicU64::new(seed | 1),
            draws: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn next(&self) -> u64 {
        use std::sync::atomic::Ordering;
        self.draws.fetch_add(1, Ordering::Relaxed);
        let mut drawn = 0u64;
        let _ = self
            .state
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                let mut x = current;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                drawn = x;
                Some(x)
            });
        drawn
    }

    /// Draws taken so far. A test asserts on this to prove the policy was
    /// actually consulted rather than silently bypassed — the mechanism only
    /// calls `pick_next`/`steal` when `inspects_queues()` is true, so a policy
    /// that forgets to override it looks correct and decides nothing.
    fn draws(&self) -> u64 {
        self.draws.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// A scheduling policy that makes the WORST legal choice it can, seeded so the
/// choice sequence is reproducible.
///
/// The point is not fairness or throughput; it is to drive the mechanism's own
/// transitions — claims, steals, settlements, generation observation — through
/// orderings that the default policy's locality rules make rare. The design
/// (`docs/superpowers/specs/2026-09-07-guest-cpu-scheduler-design.md`, phase 2)
/// names this as the policy hook's first consumer, precisely so a race in the
/// scheduler is reproduced THROUGH THE SCHEDULER rather than only through host
/// load or syscall jitter.
///
/// Every answer stays inside the contract: `select_cpu` returns an
/// affinity-allowed CPU below `cpu_count()`, `pick_next` returns a task that
/// is in the view it was handed, and `steal` never names the stealer as its
/// own victim. A policy cannot express an unsafe scheduling decision — the
/// mechanism re-validates affinity and the exact generation either way — so
/// "adversarial" here means maximally cache-hostile and maximally
/// order-shuffling, never invalid.
#[derive(Debug)]
pub struct AdversarialPolicy {
    cpu_count: usize,
    stream: SeededStream,
}

impl AdversarialPolicy {
    /// `cpu_count` guest CPUs, decisions drawn from `seed`.
    pub fn new(cpu_count: usize, seed: u64) -> Self {
        Self {
            cpu_count: cpu_count.clamp(1, carrick_hal::MAX_GUEST_CPUS),
            stream: SeededStream::new(seed),
        }
    }

    /// How many decisions this policy has been asked for.
    pub fn decisions(&self) -> u64 {
        self.stream.draws()
    }
}

impl carrick_hal::SchedulingPolicy for AdversarialPolicy {
    fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    fn select_cpu(&self, placement: &carrick_hal::TaskPlacement<'_>) -> carrick_hal::GuestCpuId {
        // Anywhere the affinity mask allows EXCEPT `last_cpu` when there is a
        // choice: the default policy's whole placement rule is locality, so
        // the adversary spends every wake migrating.
        let allowed: Vec<carrick_hal::GuestCpuId> = (0..self.cpu_count)
            .map(|index| carrick_hal::GuestCpuId::new(index as u32))
            .filter(|cpu| placement.affinity.is_allowed(*cpu))
            .collect();
        if allowed.is_empty() {
            return placement
                .last_cpu
                .unwrap_or(carrick_hal::GuestCpuId::new(0));
        }
        let elsewhere: Vec<carrick_hal::GuestCpuId> = allowed
            .iter()
            .copied()
            .filter(|cpu| Some(*cpu) != placement.last_cpu)
            .collect();
        let pool = if elsewhere.is_empty() {
            &allowed
        } else {
            &elsewhere
        };
        pool[(self.stream.next() % pool.len() as u64) as usize]
    }

    fn inspects_queues(&self) -> bool {
        true
    }

    fn pick_next(&self, view: &carrick_hal::CpuQueueView<'_>) -> Option<carrick_hal::TaskKey> {
        // Not the FIFO head: run the queue in a shuffled order so a settlement
        // is as likely to race a late row as an early one.
        if view.queued.is_empty() {
            return None;
        }
        Some(view.queued[(self.stream.next() % view.queued.len() as u64) as usize])
    }

    fn steal(
        &self,
        cpu: carrick_hal::GuestCpuId,
        victims: &[carrick_hal::CpuQueueView<'_>],
    ) -> Option<(carrick_hal::GuestCpuId, carrick_hal::TaskKey)> {
        // Steal at every opportunity, from a random victim and a random
        // position, rather than the mechanism's longest-queue-tail scan.
        let stealable: Vec<&carrick_hal::CpuQueueView<'_>> = victims
            .iter()
            .filter(|view| view.cpu != cpu && !view.queued.is_empty())
            .collect();
        if stealable.is_empty() {
            return None;
        }
        let view = stealable[(self.stream.next() % stealable.len() as u64) as usize];
        let task = view.queued[(self.stream.next() % view.queued.len() as u64) as usize];
        Some((view.cpu, task))
    }

    fn on_tick(&self, _cpu: carrick_hal::GuestCpuId) -> carrick_hal::PreemptOrContinue {
        // Preempt on every tick: maximal switching, maximal settlement churn.
        carrick_hal::PreemptOrContinue::Preempt
    }
}

/// One scheduling decision, as recorded by [`RecordReplay`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulingDecision {
    SelectCpu {
        task: carrick_hal::TaskKey,
        cpu: carrick_hal::GuestCpuId,
    },
    PickNext {
        cpu: carrick_hal::GuestCpuId,
        task: Option<carrick_hal::TaskKey>,
    },
    Steal {
        cpu: carrick_hal::GuestCpuId,
        stolen: Option<(carrick_hal::GuestCpuId, carrick_hal::TaskKey)>,
    },
}

/// Records an inner policy's decision sequence, then replays it.
///
/// Recording answers exactly what the inner policy answers and appends the
/// decision; replaying answers from the recording in order. This is what turns
/// an [`AdversarialPolicy`] run that DID reproduce a defect into a fixed
/// artifact: the seed reproduces the draw sequence, and the recording
/// reproduces the decision sequence even when the draws are consumed in a
/// different interleaving.
///
/// Replay is best-effort by construction and says so: a recorded answer that
/// no longer applies (a CPU the task's affinity now forbids, a task that is
/// not in the queue view being offered) is DISCARDED and the inner policy
/// answers instead, because the mechanism re-validates every answer anyway and
/// a policy that insisted would only be ignored. `divergences()` counts those,
/// so a test can assert a replay actually followed its recording rather than
/// silently degenerating into a second live run.
#[derive(Debug)]
pub struct RecordReplay {
    inner: Arc<dyn carrick_hal::SchedulingPolicy>,
    recording: parking_lot::Mutex<Vec<SchedulingDecision>>,
    replay: bool,
    cursor: std::sync::atomic::AtomicUsize,
    divergences: std::sync::atomic::AtomicU64,
}

impl RecordReplay {
    /// Record `inner`'s decisions.
    pub fn recording(inner: Arc<dyn carrick_hal::SchedulingPolicy>) -> Self {
        Self {
            inner,
            recording: parking_lot::Mutex::new(Vec::new()),
            replay: false,
            cursor: std::sync::atomic::AtomicUsize::new(0),
            divergences: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Replay `recorded`, falling back to `inner` where a recorded answer no
    /// longer applies.
    pub fn replaying(
        inner: Arc<dyn carrick_hal::SchedulingPolicy>,
        recorded: Vec<SchedulingDecision>,
    ) -> Self {
        Self {
            inner,
            recording: parking_lot::Mutex::new(recorded),
            replay: true,
            cursor: std::sync::atomic::AtomicUsize::new(0),
            divergences: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The decisions recorded so far, in order.
    pub fn recorded(&self) -> Vec<SchedulingDecision> {
        self.recording.lock().clone()
    }

    /// Recorded answers that no longer applied on replay.
    pub fn divergences(&self) -> u64 {
        self.divergences.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn record(&self, decision: SchedulingDecision) {
        if !self.replay {
            self.recording.lock().push(decision);
        }
    }

    /// The next recorded decision, or `None` when recording or exhausted.
    fn next_recorded(&self) -> Option<SchedulingDecision> {
        if !self.replay {
            return None;
        }
        let index = self
            .cursor
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.recording.lock().get(index).copied()
    }

    fn diverged(&self) {
        self.divergences
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl carrick_hal::SchedulingPolicy for RecordReplay {
    fn cpu_count(&self) -> usize {
        self.inner.cpu_count()
    }

    fn select_cpu(&self, placement: &carrick_hal::TaskPlacement<'_>) -> carrick_hal::GuestCpuId {
        if let Some(SchedulingDecision::SelectCpu { task, cpu }) = self.next_recorded() {
            if task == placement.task && placement.affinity.is_allowed(cpu) {
                return cpu;
            }
            self.diverged();
        }
        let cpu = self.inner.select_cpu(placement);
        self.record(SchedulingDecision::SelectCpu {
            task: placement.task,
            cpu,
        });
        cpu
    }

    fn inspects_queues(&self) -> bool {
        self.inner.inspects_queues()
    }

    fn pick_next(&self, view: &carrick_hal::CpuQueueView<'_>) -> Option<carrick_hal::TaskKey> {
        if let Some(SchedulingDecision::PickNext { cpu, task }) = self.next_recorded() {
            match task {
                Some(task) if cpu == view.cpu && view.queued.contains(&task) => {
                    return Some(task);
                }
                None if cpu == view.cpu && view.queued.is_empty() => return None,
                _ => self.diverged(),
            }
        }
        let task = self.inner.pick_next(view);
        self.record(SchedulingDecision::PickNext {
            cpu: view.cpu,
            task,
        });
        task
    }

    fn steal(
        &self,
        cpu: carrick_hal::GuestCpuId,
        victims: &[carrick_hal::CpuQueueView<'_>],
    ) -> Option<(carrick_hal::GuestCpuId, carrick_hal::TaskKey)> {
        if let Some(SchedulingDecision::Steal {
            cpu: recorded_cpu,
            stolen,
        }) = self.next_recorded()
        {
            let still_applies = match stolen {
                Some((victim, task)) => victims
                    .iter()
                    .any(|view| view.cpu == victim && view.queued.contains(&task)),
                None => true,
            };
            if recorded_cpu == cpu && still_applies {
                return stolen;
            }
            self.diverged();
        }
        let stolen = self.inner.steal(cpu, victims);
        self.record(SchedulingDecision::Steal { cpu, stolen });
        stolen
    }

    fn on_tick(&self, cpu: carrick_hal::GuestCpuId) -> carrick_hal::PreemptOrContinue {
        self.inner.on_tick(cpu)
    }

    fn on_runnable(&self, task: carrick_hal::TaskKey, cpu: carrick_hal::GuestCpuId) {
        self.inner.on_runnable(task, cpu);
    }

    fn on_block(&self, task: carrick_hal::TaskKey, cpu: carrick_hal::GuestCpuId) {
        self.inner.on_block(task, cpu);
    }

    fn on_exit(&self, task: carrick_hal::TaskKey, cpu: carrick_hal::GuestCpuId) {
        self.inner.on_exit(task, cpu);
    }
}

#[cfg(test)]
mod scheduling_policy_tests {
    use super::{AdversarialPolicy, RecordReplay, SchedulingDecision};
    use carrick_hal::{
        CpuAffinity, CpuLoad, CpuQueueView, GuestCpuId, GuestCpuPolicy, PreemptOrContinue,
        SchedulingPolicy, TaskKey, TaskPlacement,
    };
    use std::sync::Arc;

    fn placement<'a>(task: u64, last: Option<u32>, cpus: &'a [CpuLoad]) -> TaskPlacement<'a> {
        TaskPlacement {
            task: TaskKey::new(task),
            last_cpu: last.map(GuestCpuId::new),
            affinity: CpuAffinity::all(cpus.len()),
            cpus,
        }
    }

    /// Adversarial means cache-hostile, never invalid: the answer is always a
    /// CPU the affinity mask allows, and it is never `last_cpu` while another
    /// allowed CPU exists.
    #[test]
    fn the_adversary_migrates_but_stays_inside_the_affinity_mask() {
        let policy = AdversarialPolicy::new(4, 12_345);
        let cpus = [CpuLoad::default(); 4];
        for _ in 0..64 {
            let chosen = policy.select_cpu(&placement(7, Some(2), &cpus));
            assert!(chosen.as_usize() < 4);
            assert_ne!(chosen, GuestCpuId::new(2), "the adversary never stays put");
        }

        // A one-CPU mask leaves nothing to migrate to, so the pin still wins.
        let pinned = TaskPlacement {
            task: TaskKey::new(7),
            last_cpu: Some(GuestCpuId::new(2)),
            affinity: CpuAffinity::single(GuestCpuId::new(2)),
            cpus: &cpus,
        };
        assert_eq!(policy.select_cpu(&pinned), GuestCpuId::new(2));
        assert!(policy.decisions() > 0, "the policy recorded its draws");
    }

    #[test]
    fn the_adversary_only_ever_names_a_task_it_was_offered() {
        let policy = AdversarialPolicy::new(2, 999);
        assert!(policy.inspects_queues(), "or it is never consulted at all");
        let queued: Vec<TaskKey> = (1..=5).map(TaskKey::new).collect();
        let view = CpuQueueView {
            cpu: GuestCpuId::new(0),
            queued: &queued,
        };
        for _ in 0..32 {
            let picked = policy.pick_next(&view).expect("a non-empty queue");
            assert!(queued.contains(&picked));
        }
        assert_eq!(
            policy.pick_next(&CpuQueueView {
                cpu: GuestCpuId::new(0),
                queued: &[],
            }),
            None
        );
        assert_eq!(
            policy.on_tick(GuestCpuId::new(0)),
            PreemptOrContinue::Preempt
        );
    }

    #[test]
    fn the_adversary_never_steals_from_itself() {
        let policy = AdversarialPolicy::new(3, 4_242);
        let mine: Vec<TaskKey> = vec![TaskKey::new(1)];
        let theirs: Vec<TaskKey> = vec![TaskKey::new(2), TaskKey::new(3)];
        let views = [
            CpuQueueView {
                cpu: GuestCpuId::new(0),
                queued: &mine,
            },
            CpuQueueView {
                cpu: GuestCpuId::new(1),
                queued: &theirs,
            },
        ];
        for _ in 0..32 {
            let (victim, task) = policy
                .steal(GuestCpuId::new(0), &views)
                .expect("a loaded victim");
            assert_eq!(victim, GuestCpuId::new(1));
            assert!(theirs.contains(&task));
        }
        // Nothing to take is not a steal.
        assert_eq!(policy.steal(GuestCpuId::new(0), &[]), None);
    }

    /// The same seed reproduces the same decision sequence, which is the only
    /// reason an adversarial run is worth reporting: a failing interleaving
    /// gets a name.
    #[test]
    fn a_seed_reproduces_the_decision_sequence() {
        let cpus = [CpuLoad::default(); 4];
        let draw = |seed: u64| {
            let policy = AdversarialPolicy::new(4, seed);
            (0..32)
                .map(|_| policy.select_cpu(&placement(7, None, &cpus)))
                .collect::<Vec<_>>()
        };
        assert_eq!(draw(7), draw(7));
        assert_ne!(draw(7), draw(8));
    }

    #[test]
    fn a_recording_replays_its_own_decisions() {
        let cpus = [CpuLoad::default(); 4];
        let inner: Arc<dyn SchedulingPolicy> = Arc::new(AdversarialPolicy::new(4, 55));
        let recorder = RecordReplay::recording(Arc::clone(&inner));
        let live: Vec<GuestCpuId> = (0..16)
            .map(|task| recorder.select_cpu(&placement(task, None, &cpus)))
            .collect();
        let recorded = recorder.recorded();
        assert_eq!(recorded.len(), 16);

        // A different inner policy proves the answers come from the RECORDING.
        let replay = RecordReplay::replaying(
            Arc::new(GuestCpuPolicy::new(4)) as Arc<dyn SchedulingPolicy>,
            recorded,
        );
        let replayed: Vec<GuestCpuId> = (0..16)
            .map(|task| replay.select_cpu(&placement(task, None, &cpus)))
            .collect();
        assert_eq!(replayed, live);
        assert_eq!(replay.divergences(), 0);
    }

    /// A recorded answer that no longer applies is discarded, counted, and the
    /// inner policy answers — the mechanism re-validates every answer anyway,
    /// so insisting would only be ignored silently.
    #[test]
    fn a_stale_recorded_answer_diverges_instead_of_lying() {
        let cpus = [CpuLoad::default(); 4];
        let replay = RecordReplay::replaying(
            Arc::new(GuestCpuPolicy::new(4)) as Arc<dyn SchedulingPolicy>,
            vec![SchedulingDecision::SelectCpu {
                task: TaskKey::new(1),
                cpu: GuestCpuId::new(3),
            }],
        );
        // CPU 3 is not in this task's affinity mask any more.
        let pinned = TaskPlacement {
            task: TaskKey::new(1),
            last_cpu: None,
            affinity: CpuAffinity::single(GuestCpuId::new(0)),
            cpus: &cpus,
        };
        assert_eq!(replay.select_cpu(&pinned), GuestCpuId::new(0));
        assert_eq!(replay.divergences(), 1);
    }
}
