use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use carrick_abi::{LinuxGuestAbi, NativeNr};
use carrick_observability::compat::{CompatReporter, SyscallArgs};
use carrick_spec::SeccompPolicy;
use proptest::prelude::*;

use super::intercept::InterceptorChain;
use super::*;
use crate::dispatch::{
    DispatchOutcome, LinearMemory, SyscallDispatcher, SyscallRequest, ThreadCtx,
};
use crate::kernel::{
    CloneObjectMode, Kernel, KernelContext, LinuxWaitStatus, RootBootstrap, TaskKey,
};
use crate::linux_abi::{LINUX_EACCES, LINUX_EPERM, LINUX_SIGKILL, LinuxErrno};

const SYS_GETPID: u64 = 172;
const SYS_UNSHARE: u64 = 97;

fn dispatch_req(
    dispatcher: &mut SyscallDispatcher,
    number: u64,
    args: [u64; 6],
) -> DispatchOutcome {
    let ctx = test_kernel_context();
    let reporter = CompatReporter::default();
    let mut mem = LinearMemory::new(0, vec![0u8; 4096]);
    let tid = crate::thread::ThreadId::from_guest_supplied_tid(1);
    let registry = crate::thread::ThreadRegistry::new(tid);
    let futex = crate::thread::FutexTable::new();
    let req = SyscallRequest::new(number, SyscallArgs(args));
    dispatcher
        .dispatch_threaded(
            &ctx,
            req,
            &mut mem,
            &reporter,
            ThreadCtx::new(tid, &registry, &futex),
        )
        .expect("dispatch")
}

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

struct ContinueInterceptor;

impl SyscallInterceptor for ContinueInterceptor {
    fn intercept(
        &self,
        _process: &ProcessInfo<'_>,
        _call: &InterceptedSyscall<'_>,
    ) -> InterceptAction {
        InterceptAction::Continue
    }
}

fn assert_interceptor_bounds<T: SyscallInterceptor + Send + Sync>() {}

#[test]
fn syscall_args_are_immutable_six_words() {
    let original = SyscallArgs::new([10, 11, 12, 13, 14, 15]);
    let rewritten = original
        .with_arg(0, 100)
        .expect("first scalar argument is writable")
        .with_arg(5, 500)
        .expect("sixth scalar argument is writable");

    assert_eq!(original.words(), [10, 11, 12, 13, 14, 15]);
    assert_eq!(original.get(0), Some(10));
    assert_eq!(original.get(5), Some(15));
    assert_eq!(rewritten.words(), [100, 11, 12, 13, 14, 500]);
    assert_eq!(rewritten.get(0), Some(100));
    assert_eq!(rewritten.get(5), Some(500));
    assert_eq!(
        original.with_arg(6, 600),
        Err(SyscallArgIndexError { index: 6 })
    );
}

#[test]
fn intercepted_syscall_preserves_request_identity_and_original_arguments() {
    let original_args = SyscallArgs::new([1, 2, 3, 4, 5, 6]);
    let request = SyscallRequest::new(64, original_args)
        .with_guest_abi(LinuxGuestAbi::X86_64)
        .with_current_guest_sp(Some(0xfeed_cafe));
    let request = SyscallRequest {
        native_number: NativeNr(1),
        ..request
    };
    let effective_args = original_args
        .with_arg(0, 9)
        .expect("first scalar argument is writable");
    let call = InterceptedSyscall::new(&request, effective_args);

    assert_eq!(call.canonical_number(), request.number);
    assert_eq!(call.native_number(), 1);
    assert_eq!(call.guest_abi(), LinuxGuestAbi::X86_64);
    assert_eq!(call.current_guest_sp(), Some(0xfeed_cafe));
    assert_eq!(call.original_args(), original_args);
    assert_eq!(call.effective_args(), SyscallArgs::new([9, 2, 3, 4, 5, 6]));
}

#[test]
fn interceptor_contract_is_thread_safe() {
    assert_interceptor_bounds::<ContinueInterceptor>();
}

struct RewriteInterceptor {
    observed_args: Arc<Mutex<Vec<[u64; 6]>>>,
    rewrite: SyscallArgs,
}

impl SyscallInterceptor for RewriteInterceptor {
    fn intercept(
        &self,
        _process: &ProcessInfo<'_>,
        call: &InterceptedSyscall<'_>,
    ) -> InterceptAction {
        self.observed_args
            .lock()
            .expect("recording mutex is not poisoned")
            .push(call.effective_args().words());
        InterceptAction::RewriteArgs(self.rewrite)
    }
}

struct ActionInterceptor {
    calls: Arc<AtomicUsize>,
    action: InterceptAction,
}

impl SyscallInterceptor for ActionInterceptor {
    fn intercept(
        &self,
        _process: &ProcessInfo<'_>,
        _call: &InterceptedSyscall<'_>,
    ) -> InterceptAction {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.action
    }
}

struct PanicInterceptor;

impl SyscallInterceptor for PanicInterceptor {
    fn intercept(
        &self,
        _process: &ProcessInfo<'_>,
        _call: &InterceptedSyscall<'_>,
    ) -> InterceptAction {
        panic!("interceptor panic must remain contained")
    }
}

#[test]
fn interceptor_chain_applies_cumulative_rewrites_without_mutating_original_request() {
    let original = SyscallArgs::new([1, 2, 3, 4, 5, 6]);
    let request = SyscallRequest::new(64, original);
    let observed_args = Arc::new(Mutex::new(Vec::new()));
    let chain = InterceptorChain::new(vec![
        Arc::new(RewriteInterceptor {
            observed_args: Arc::clone(&observed_args),
            rewrite: SyscallArgs::new([10, 11, 12, 13, 14, 15]),
        }),
        Arc::new(RewriteInterceptor {
            observed_args: Arc::clone(&observed_args),
            rewrite: SyscallArgs::new([20, 21, 22, 23, 24, 25]),
        }),
    ]);
    let context = test_kernel_context();

    let result = chain
        .apply(&ProcessInfo::new(&context), &request)
        .expect("rewriting chain succeeds");

    assert_eq!(
        *observed_args
            .lock()
            .expect("recording mutex is not poisoned"),
        vec![[1, 2, 3, 4, 5, 6], [10, 11, 12, 13, 14, 15]]
    );
    assert_eq!(result.effective_args.words(), [20, 21, 22, 23, 24, 25]);
    assert_eq!(result.proposed, None);
    assert_eq!(request.args.words(), [1, 2, 3, 4, 5, 6]);
}

#[test]
fn interceptor_chain_return_stops_later_interceptors() {
    let calls = Arc::new(AtomicUsize::new(0));
    let chain = InterceptorChain::new(vec![
        Arc::new(ActionInterceptor {
            calls: Arc::clone(&calls),
            action: InterceptAction::Return(42),
        }),
        Arc::new(ActionInterceptor {
            calls: Arc::clone(&calls),
            action: InterceptAction::Continue,
        }),
    ]);
    let context = test_kernel_context();
    let request = SyscallRequest::new(64, SyscallArgs::new([0; 6]));

    let result = chain
        .apply(&ProcessInfo::new(&context), &request)
        .expect("returning chain succeeds");

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(result.proposed, Some(SyscallOutcome::returned(42)));
}

#[test]
fn interceptor_chain_errno_stops_later_interceptors() {
    let calls = Arc::new(AtomicUsize::new(0));
    let chain = InterceptorChain::new(vec![
        Arc::new(ActionInterceptor {
            calls: Arc::clone(&calls),
            action: InterceptAction::Errno(LINUX_EACCES),
        }),
        Arc::new(ActionInterceptor {
            calls: Arc::clone(&calls),
            action: InterceptAction::Continue,
        }),
    ]);
    let context = test_kernel_context();
    let request = SyscallRequest::new(64, SyscallArgs::new([0; 6]));

    let result = chain
        .apply(&ProcessInfo::new(&context), &request)
        .expect("errno chain succeeds");

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(result.proposed, Some(SyscallOutcome::errno(LINUX_EACCES)));
}

#[test]
fn interceptor_chain_empty_preserves_request_without_proposed_outcome() {
    let request = SyscallRequest::new(64, SyscallArgs::new([1, 2, 3, 4, 5, 6]));
    let context = test_kernel_context();

    let result = InterceptorChain::default()
        .apply(&ProcessInfo::new(&context), &request)
        .expect("empty chain succeeds");

    assert_eq!(result.effective_args, request.args);
    assert_eq!(result.proposed, None);
}

#[test]
fn interceptor_chain_lowers_callback_panic_to_calling_container_id() {
    let context = test_kernel_context();
    let process = ProcessInfo::new(&context);
    let request = SyscallRequest::new(64, SyscallArgs::new([0; 6]));
    let chain = InterceptorChain::new(vec![Arc::new(PanicInterceptor)]);

    let error = chain
        .apply(&process, &request)
        .expect_err("panicking interceptor must fail through DispatchError");

    assert!(matches!(
        error,
        crate::dispatch::DispatchError::InterceptorPanicked { container_id }
            if container_id == context.container().id()
    ));
}

proptest! {
    #[test]
    fn interceptor_rewrites_preserve_request_identity(
        original in any::<[u64; 6]>(),
        original_number in any::<u64>(),
        original_native_number in any::<u64>(),
        rewrites in prop::collection::vec(any::<[u64; 6]>(), 0..16),
    ) {
        let request = SyscallRequest {
            native_number: NativeNr(original_native_number),
            ..SyscallRequest::new(original_number, SyscallArgs::new(original))
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let interceptors = rewrites
            .iter()
            .copied()
            .map(|rewrite| {
                Arc::new(ActionInterceptor {
                    calls: Arc::clone(&calls),
                    action: InterceptAction::RewriteArgs(SyscallArgs::new(rewrite)),
                }) as Arc<dyn SyscallInterceptor>
            })
            .collect();
        let context = test_kernel_context();

        let result = InterceptorChain::new(interceptors)
            .apply(&ProcessInfo::new(&context), &request)
            .expect("rewrite chain succeeds");
        let expected_last = rewrites.last().copied().unwrap_or(original);

        prop_assert_eq!(result.effective_args.words(), expected_last);
        prop_assert_eq!(request.args.words(), original);
        prop_assert_eq!(request.number.raw(), original_number);
        prop_assert_eq!(request.native_number.raw(), original_native_number);
    }

    #[test]
    fn interceptor_chain_terminal_action_stops_all_later_callbacks(
        (rewrites, terminal_position) in prop::collection::vec(any::<[u64; 6]>(), 1..16)
            .prop_flat_map(|rewrites| (Just(rewrites.clone()), 0..rewrites.len())),
    ) {
        let calls = Arc::new(AtomicUsize::new(0));
        let interceptors = rewrites
            .iter()
            .copied()
            .enumerate()
            .map(|(position, rewrite)| {
                let action = if position == terminal_position {
                    InterceptAction::Return(42)
                } else {
                    InterceptAction::RewriteArgs(SyscallArgs::new(rewrite))
                };
                Arc::new(ActionInterceptor {
                    calls: Arc::clone(&calls),
                    action,
                }) as Arc<dyn SyscallInterceptor>
            })
            .collect();
        let context = test_kernel_context();
        let request = SyscallRequest::new(64, SyscallArgs::new([0; 6]));

        let result = InterceptorChain::new(interceptors)
            .apply(&ProcessInfo::new(&context), &request)
            .expect("terminal chain succeeds");

        prop_assert_eq!(calls.load(Ordering::SeqCst), terminal_position + 1);
        prop_assert_eq!(result.proposed, Some(SyscallOutcome::returned(42)));
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
fn process_info_exposes_container_identity() {
    let context = test_kernel_context();
    let process = ProcessInfo::new(&context);

    assert_eq!(process.container_id(), context.task().container().id());
    assert_eq!(
        process.run_id(),
        context.task().container().run_id().clone()
    );
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
        .dispatch_threaded(
            &ctx,
            req,
            &mut mem,
            &reporter,
            ThreadCtx::new(tid, &registry, &futex),
        )
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
        .dispatch_threaded(
            &ctx,
            req,
            &mut mem,
            &reporter,
            ThreadCtx::new(tid, &registry, &futex),
        )
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
        .dispatch_threaded(
            &ctx,
            req,
            &mut mem,
            &reporter,
            ThreadCtx::new(tid, &registry, &futex),
        )
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

#[test]
fn test_deny_all_policy_derives_fast_path_visibility() {
    // Deny-all policy automatically requires fast-path visibility
    let policy = PolicyObserver::with_default_action(SyscallAction::Deny(LINUX_EPERM));
    assert_eq!(
        policy.wants_fast_path_visibility(),
        FastPathVisibility::Required
    );

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.install_observer(Arc::new(policy));
    assert!(!dispatcher.identity_fast_path_enabled());
    assert!(dispatcher.identity_fast_path_word().is_none());

    // Dispatching getpid through dispatcher is observed and denied
    let outcome = dispatch_req(&mut dispatcher, SYS_GETPID, [0; 6]);
    assert_eq!(outcome, DispatchOutcome::Errno { errno: LINUX_EPERM });

    // Opt-out explicitly accepts the blind spot
    let policy_opt_out = PolicyObserver::with_default_action(SyscallAction::Deny(LINUX_EPERM))
        .accept_fast_path_blind_spot();
    assert_eq!(
        policy_opt_out.wants_fast_path_visibility(),
        FastPathVisibility::Blind
    );
}

#[test]
fn test_deny_getpid_rule_derives_fast_path_visibility() {
    use carrick_abi::CanonicalNr;

    let policy = PolicyObserver::new().deny(CanonicalNr(SYS_GETPID), LINUX_EACCES);
    assert_eq!(
        policy.wants_fast_path_visibility(),
        FastPathVisibility::Required
    );

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.install_observer(Arc::new(policy));
    assert!(!dispatcher.identity_fast_path_enabled());

    let outcome = dispatch_req(&mut dispatcher, SYS_GETPID, [0; 6]);
    assert_eq!(
        outcome,
        DispatchOutcome::Errno {
            errno: LINUX_EACCES
        }
    );
}

#[test]
fn test_sandbox_observer_propagates_derived_fast_path_visibility() {
    use carrick_abi::CanonicalNr;

    let sandbox = SandboxObserver::new().deny(CanonicalNr(SYS_GETPID), LINUX_EACCES);
    assert_eq!(
        sandbox.wants_fast_path_visibility(),
        FastPathVisibility::Required
    );

    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.install_observer(Arc::new(sandbox));
    assert!(!dispatcher.identity_fast_path_enabled());

    let outcome = dispatch_req(&mut dispatcher, SYS_GETPID, [0; 6]);
    assert_eq!(
        outcome,
        DispatchOutcome::Errno {
            errno: LINUX_EACCES
        }
    );
}

#[test]
fn test_all_sandbox_preset_syscalls_exist_in_abi_table() {
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
        "mkdirat",
        "unlinkat",
        "renameat",
        "truncate",
        "ftruncate",
        "fchmodat",
        "fchownat",
        "renameat2",
        "unshare",
        "clone",
        "execve",
        "setns",
        "execveat",
        "clone3",
    ] {
        assert!(
            carrick_abi::syscall::lookup_aarch64_by_name(name).is_some(),
            "syscall {name} must exist in canonical ABI table"
        );
    }
}
