use std::sync::{Arc, Mutex};

use carrick_observability::compat::{CompatReporter, SyscallArgs};
use carrick_spec::SeccompPolicy;

use super::*;
use crate::dispatch::{LinearMemory, SyscallDispatcher, SyscallRequest};
use crate::kernel::{
    CloneObjectMode, Kernel, KernelContext, LinuxWaitStatus, RootBootstrap, TaskKey,
};
use crate::linux_abi::{LINUX_EACCES, LINUX_EPERM, LINUX_SIGKILL, LinuxErrno};

const SYS_GETPID: u64 = 172;
const SYS_UNSHARE: u64 = 97;

#[derive(Default)]
struct RecordingObserver {
    syscalls: Mutex<Vec<(u64, i32)>>,
    returns: Mutex<Vec<(u64, i64)>>,
    process_creates: Mutex<Vec<(TaskKey, TaskKey)>>,
    execs: Mutex<Vec<(i32, Vec<u8>)>>,
    exits: Mutex<Vec<(i32, ExitStatus)>>,
}

impl SyscallObserver for RecordingObserver {
    fn on_syscall(&self, p: &ProcessInfo<'_>, s: &SyscallInfo<'_>) -> SyscallAction {
        self.syscalls.lock().unwrap().push((s.number(), p.pid()));
        SyscallAction::Allow
    }

    fn on_syscall_return(&self, _p: &ProcessInfo<'_>, s: &SyscallInfo<'_>, o: &SyscallOutcome) {
        self.returns.lock().unwrap().push((s.number(), o.value));
    }

    fn on_process_create(&self, parent: &ProcessInfo<'_>, child: TaskKey) {
        self.process_creates
            .lock()
            .unwrap()
            .push((parent.task_key(), child));
    }

    fn on_exec(&self, p: &ProcessInfo<'_>, exe: &[u8], _argv: &[&[u8]]) -> SyscallAction {
        self.execs.lock().unwrap().push((p.pid(), exe.to_vec()));
        SyscallAction::Allow
    }

    fn on_process_exit(&self, p: &ProcessInfo<'_>, status: ExitStatus) {
        self.exits.lock().unwrap().push((p.pid(), status));
    }
}

struct DenySyscallObserver {
    target_nr: u64,
    deny_errno: LinuxErrno,
}

impl SyscallObserver for DenySyscallObserver {
    fn on_syscall(&self, _p: &ProcessInfo<'_>, s: &SyscallInfo<'_>) -> SyscallAction {
        if s.number() == self.target_nr {
            SyscallAction::Deny(self.deny_errno)
        } else {
            SyscallAction::Allow
        }
    }
}

struct KillSyscallObserver {
    target_nr: u64,
    signal: Signal,
}

impl SyscallObserver for KillSyscallObserver {
    fn on_syscall(&self, _p: &ProcessInfo<'_>, s: &SyscallInfo<'_>) -> SyscallAction {
        if s.number() == self.target_nr {
            SyscallAction::Kill(self.signal)
        } else {
            SyscallAction::Allow
        }
    }
}

struct FastPathReqObserver;

impl SyscallObserver for FastPathReqObserver {
    fn wants_fast_path_visibility(&self) -> FastPathVisibility {
        FastPathVisibility::Required
    }
}

fn test_kernel_context() -> KernelContext {
    let bootstrap = RootBootstrap::for_reference_model(
        1,
        crate::thread::ThreadId::synthetic_for_tests(1),
        "test-observe".to_owned(),
    )
    .expect("root bootstrap");
    Kernel::bootstrap_root(bootstrap).expect("root kernel").1
}

#[test]
fn test_zero_overhead_when_no_observers() {
    let dispatcher = SyscallDispatcher::new();
    assert!(dispatcher.observers().is_none());
    assert!(dispatcher.container_policy().is_none());
    assert!(dispatcher.identity_fast_path_enabled());
}

#[test]
fn test_container_policy_as_first_observer() {
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.apply_seccomp_policy(SeccompPolicy::ContainerDefault);
    assert!(dispatcher.observers().is_some());
    assert!(dispatcher.container_policy().is_some());

    let ctx = test_kernel_context();
    let reporter = CompatReporter::default();
    let mut mem = LinearMemory::new(0, vec![0u8; 4096]);
    let tid = crate::thread::ThreadId::from_guest_supplied_tid(1);
    let registry = crate::thread::ThreadRegistry::new(tid);
    let futex = crate::thread::FutexTable::new();

    // unshare is denied by default Docker policy
    let req = SyscallRequest::new(SYS_UNSHARE, SyscallArgs([0; 6]));
    let outcome = dispatcher
        .dispatch_threaded(&ctx, req, &mut mem, &reporter, tid, &registry, &futex)
        .expect("dispatch");
    assert_eq!(
        outcome,
        crate::dispatch::DispatchOutcome::Errno { errno: LINUX_EPERM }
    );
}

#[test]
fn test_user_observer_deny_and_pipeline_order() {
    let mut dispatcher = SyscallDispatcher::new();
    let deny_obs = Arc::new(DenySyscallObserver {
        target_nr: SYS_GETPID,
        deny_errno: LINUX_EACCES,
    });
    dispatcher.install_observer(deny_obs);

    let ctx = test_kernel_context();
    let reporter = CompatReporter::default();
    let mut mem = LinearMemory::new(0, vec![0u8; 4096]);
    let tid = crate::thread::ThreadId::from_guest_supplied_tid(1);
    let registry = crate::thread::ThreadRegistry::new(tid);
    let futex = crate::thread::FutexTable::new();

    let req = SyscallRequest::new(SYS_GETPID, SyscallArgs([0; 6]));
    let outcome = dispatcher
        .dispatch_threaded(&ctx, req, &mut mem, &reporter, tid, &registry, &futex)
        .expect("dispatch");
    assert_eq!(
        outcome,
        crate::dispatch::DispatchOutcome::Errno {
            errno: LINUX_EACCES
        }
    );
}

#[test]
fn test_user_observer_kill() {
    let mut dispatcher = SyscallDispatcher::new();
    let kill_obs = Arc::new(KillSyscallObserver {
        target_nr: SYS_GETPID,
        signal: Signal(LINUX_SIGKILL),
    });
    dispatcher.install_observer(kill_obs);

    let ctx = test_kernel_context();
    let reporter = CompatReporter::default();
    let mut mem = LinearMemory::new(0, vec![0u8; 4096]);
    let tid = crate::thread::ThreadId::from_guest_supplied_tid(1);
    let registry = crate::thread::ThreadRegistry::new(tid);
    let futex = crate::thread::FutexTable::new();

    let req = SyscallRequest::new(SYS_GETPID, SyscallArgs([0; 6]));
    let outcome = dispatcher
        .dispatch_threaded(&ctx, req, &mut mem, &reporter, tid, &registry, &futex)
        .expect("dispatch");
    assert_eq!(
        outcome,
        crate::dispatch::DispatchOutcome::SignalDeath {
            signum: LINUX_SIGKILL
        }
    );
}

#[test]
fn test_fork_inheritance_and_lifecycle_events() {
    let mut parent_dispatcher = SyscallDispatcher::new();
    let recorder = Arc::new(RecordingObserver::default());
    parent_dispatcher.install_observer(recorder.clone());

    let parent_tid = crate::thread::ThreadId::from_guest_supplied_tid(1);
    let child_tid = crate::thread::ThreadId::from_guest_supplied_tid(2);

    let child_dispatcher = parent_dispatcher.fork_clone_in_process_with_mm_mode(
        parent_tid,
        child_tid,
        100,
        101,
        CloneObjectMode::Share,
    );

    // Child inherited observer chain
    assert!(child_dispatcher.observers().is_some());
    let chain = child_dispatcher.observers().unwrap();
    assert_eq!(chain.user_observers().len(), 1);

    let ctx = test_kernel_context();
    let p = ProcessInfo::new(&ctx);

    // Lifecycle: process create
    let child_ctx = test_kernel_context();
    let child_key = child_ctx.task().key();
    chain.on_process_create(&p, child_key);
    assert_eq!(recorder.process_creates.lock().unwrap().len(), 1);
    assert_eq!(recorder.process_creates.lock().unwrap()[0].1, child_key);

    // Lifecycle: exec
    let argv: [&[u8]; 1] = [b"/bin/sh"];
    let action = chain.on_exec(&p, b"/bin/sh", &argv);
    assert_eq!(action, SyscallAction::Allow);
    assert_eq!(recorder.execs.lock().unwrap().len(), 1);
    assert_eq!(recorder.execs.lock().unwrap()[0].1, b"/bin/sh");

    // Lifecycle: exit
    let exit_status = ExitStatus::Exited(0);
    chain.on_process_exit(&p, exit_status);
    assert_eq!(recorder.exits.lock().unwrap().len(), 1);
    assert_eq!(recorder.exits.lock().unwrap()[0].1, ExitStatus::Exited(0));
}

#[test]
fn test_fast_path_visibility_control() {
    let mut dispatcher = SyscallDispatcher::new();
    assert!(dispatcher.identity_fast_path_enabled());

    // Installing an observer that requires fast path visibility disables the shim
    dispatcher.install_observer(Arc::new(FastPathReqObserver));
    assert!(!dispatcher.identity_fast_path_enabled());
    assert!(dispatcher.identity_fast_path_word().is_none());
}

#[test]
fn test_audit_observer_bounded_ring() {
    let audit = Arc::new(AuditObserver::with_capacity(4));
    let ctx = test_kernel_context();
    let p = ProcessInfo::new(&ctx);

    for i in 1..=10 {
        let req = SyscallRequest::new(i, SyscallArgs([i; 6]));
        let s = SyscallInfo::new(&req);
        let outcome = SyscallOutcome::returned(0);
        audit.on_syscall(&p, &s);
        audit.on_syscall_return(&p, &s, &outcome);
    }

    assert_eq!(audit.len(), 4);
    assert_eq!(audit.dropped_count(), 16);

    let events = audit.drain();
    assert_eq!(events.len(), 4);
    assert_eq!(audit.len(), 0);
}

#[test]
fn test_exit_status_conversion() {
    let exited = ExitStatus::from_wait_status(LinuxWaitStatus::from_wait_encoding(0x2a00));
    assert_eq!(exited, ExitStatus::Exited(42));

    let signaled = ExitStatus::from_wait_status(LinuxWaitStatus::from_wait_encoding(9));
    assert_eq!(signaled, ExitStatus::Signaled(Signal(9)));
}

#[test]
fn test_policy_observer_typed_rules() {
    use carrick_abi::CanonicalNr;

    let mut policy = PolicyObserver::new();
    policy.add_rule(PolicyRule::deny(CanonicalNr(SYS_GETPID), LINUX_EACCES));
    policy.add_rule(
        PolicyRule::deny(CanonicalNr(SYS_UNSHARE), LINUX_EPERM)
            .with_arg_filter(ArgFilter::exact(0, 0x20000000)),
    );

    let ctx = test_kernel_context();
    let p = ProcessInfo::new(&ctx);

    // SYS_GETPID matches by canonical number
    let req_getpid = SyscallRequest::new(SYS_GETPID, SyscallArgs([0; 6]));
    let s_getpid = SyscallInfo::new(&req_getpid);
    assert_eq!(
        policy.on_syscall(&p, &s_getpid),
        SyscallAction::Deny(LINUX_EACCES)
    );

    // SYS_UNSHARE without matching arg filter allows
    let req_unshare_0 = SyscallRequest::new(SYS_UNSHARE, SyscallArgs([0; 6]));
    let s_unshare_0 = SyscallInfo::new(&req_unshare_0);
    assert_eq!(policy.on_syscall(&p, &s_unshare_0), SyscallAction::Allow);

    // SYS_UNSHARE with matching arg filter denies
    let req_unshare_match =
        SyscallRequest::new(SYS_UNSHARE, SyscallArgs([0x20000000, 0, 0, 0, 0, 0]));
    let s_unshare_match = SyscallInfo::new(&req_unshare_match);
    assert_eq!(
        policy.on_syscall(&p, &s_unshare_match),
        SyscallAction::Deny(LINUX_EPERM)
    );
}

#[test]
fn test_sandbox_observer_preset_composition() {
    use carrick_abi::CanonicalNr;

    // Compose NoNetwork + ReadOnlyFs + custom rule
    let sandbox = SandboxObserver::with_preset(SandboxPreset::NoNetwork)
        .with_preset_chained(SandboxPreset::ReadOnlyFs)
        .deny(CanonicalNr(SYS_GETPID), LINUX_EACCES);

    let ctx = test_kernel_context();
    let p = ProcessInfo::new(&ctx);

    // Network socket (198) denied by NoNetwork
    let req_socket = SyscallRequest::new(198, SyscallArgs([2, 1, 0, 0, 0, 0]));
    let s_socket = SyscallInfo::new(&req_socket);
    assert_eq!(
        sandbox.on_syscall(&p, &s_socket),
        SyscallAction::Deny(LINUX_EPERM)
    );

    // FS unlinkat (35) denied by ReadOnlyFs with EROFS
    let req_unlink = SyscallRequest::new(35, SyscallArgs([0; 6]));
    let s_unlink = SyscallInfo::new(&req_unlink);
    assert_eq!(
        sandbox.on_syscall(&p, &s_unlink),
        SyscallAction::Deny(carrick_abi::LINUX_EROFS)
    );

    // Custom getpid rule denied
    let req_getpid = SyscallRequest::new(SYS_GETPID, SyscallArgs([0; 6]));
    let s_getpid = SyscallInfo::new(&req_getpid);
    assert_eq!(
        sandbox.on_syscall(&p, &s_getpid),
        SyscallAction::Deny(LINUX_EACCES)
    );
}

#[test]
fn test_compat_reporter_as_observer_on_return() {
    let reporter = Arc::new(CompatReporter::default());
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.install_observer(reporter.clone());

    let chain = dispatcher.observers().unwrap();
    let ctx = test_kernel_context();
    let p = ProcessInfo::new(&ctx);
    let req = SyscallRequest::new(SYS_GETPID, SyscallArgs([0; 6]));
    let s = SyscallInfo::new(&req);
    let outcome = SyscallOutcome::returned(42);

    chain.on_syscall_return(&p, &s, &outcome);

    let report = reporter.snapshot();
    assert_eq!(report.summary.syscall_returns_ok, 1);
}
