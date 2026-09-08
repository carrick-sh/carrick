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
    every_child_runs_timeout: Duration,
    exit_budget_matcher: ExitBudgetMatcher,
    exit_budget_timeout: Duration,
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
            every_child_runs_timeout: Duration::from_secs(5),
            exit_budget_matcher: ExitBudgetMatcher::Any,
            exit_budget_timeout: Duration::from_secs(10),
            deadline: None,
        }
    }

    pub fn without_invariant(mut self, invariant: InvariantKind) -> Self {
        self.disabled_invariants.insert(invariant);
        self
    }

    pub fn auditor(mut self, auditor: Arc<dyn KernelAuditor>) -> Self {
        self.auditors.push(auditor);
        self
    }

    pub fn every_child_runs_timeout(mut self, timeout: Duration) -> Self {
        self.every_child_runs_timeout = timeout;
        self
    }

    pub fn exit_budget(mut self, select: ExitBudgetMatcher, within: Duration) -> Self {
        self.exit_budget_matcher = select;
        self.exit_budget_timeout = within;
        self
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
        if !self
            .disabled_invariants
            .contains(&InvariantKind::NoOrphanZombie)
        {
            builder = builder.auditor(Arc::new(NoOrphanZombie));
        }
        if !self
            .disabled_invariants
            .contains(&InvariantKind::ProcessGraphLiveness)
        {
            builder = builder.auditor(Arc::new(ProcessGraphLiveness));
        }
        if !self
            .disabled_invariants
            .contains(&InvariantKind::NoWakeOfReapedTask)
        {
            builder = builder.auditor(Arc::new(NoWakeOfReapedTask));
        }
        if !self
            .disabled_invariants
            .contains(&InvariantKind::FirstTouchNeverDelivered)
        {
            builder = builder.auditor(Arc::new(FirstTouchNeverDelivered));
        }
        if !self
            .disabled_invariants
            .contains(&InvariantKind::EveryChildRuns)
        {
            builder = builder.auditor(Arc::new(EveryChildRuns::new(self.every_child_runs_timeout)));
        }
        if !self
            .disabled_invariants
            .contains(&InvariantKind::ExitBudget)
        {
            builder = builder.auditor(Arc::new(ExitBudget::new(
                self.exit_budget_matcher.clone(),
                self.exit_budget_timeout,
            )));
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
