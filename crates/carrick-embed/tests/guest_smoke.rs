//! First signed end-to-end tests for `carrick-embed`: a real HVF guest booted
//! from a cargo test executable, compared against the shipped CLI on the
//! same image and command, with each stdio sink proven.
//!
//! Run ONLY through `just test-embed` (scripts/test-signed.sh): it signs this
//! executable with the hypervisor entitlement, exports `CARRICK_RUN_ID`, and
//! runs it under `RUST_TEST_THREADS=1`. A bare `cargo test` fails here with
//! `EmbedError::Entitlement` — by design, never a skip.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use carrick_embed::testing::ResultAssert;
use carrick_embed::{
    AuditEvent, AuditObserver, ContainerBuilder, ContainerResult, EmbedError, InterceptAction,
    InterceptedSyscall, LinuxErrno, ProcessInfo, StdioConfig, SyscallInterceptor, SyscallObserver,
    SyscallOutcome,
};
#[cfg(feature = "test-support")]
use carrick_embed::{Carrier, FilterVfs};
use carrick_image::{ImageStore, PullPolicy};

const HELLO: &[u8] = b"hello world\n";
const INTERCEPT_STDOUT: &[u8] = b"INTERCEPT_STDOUT\n";
const NATIVE_STDERR: &[u8] = b"NATIVE_STDERR\n";

/// The conformance gate's per-case budget (`CASE_DEADLINE`,
/// `crates/carrick-cli/tests/conformance.rs:169`).
const CLI_DEADLINE: Duration = Duration::from_secs(45);

fn hello_builder(store: &ImageStore) -> ContainerBuilder {
    ContainerBuilder::from_image(common::SMOKE_IMAGE)
        .image_store(store.clone())
        .pull_policy(PullPolicy::Missing)
        .command(["echo", "hello world"])
}

fn assert_clean_exit(result: &ContainerResult) {
    assert!(
        result.success(),
        "exit_code={} signal={:?} trap_limit_hit={}",
        result.exit_code,
        result.signal.is_some(),
        result.trap_limit_hit
    );
    assert_eq!(result.exit_code, 0);
    assert!(result.signal.is_none(), "guest was killed by a signal");
    assert!(!result.trap_limit_hit, "trap limit hit");
}

struct IdentityInterceptor;

impl SyscallInterceptor for IdentityInterceptor {
    fn intercept(
        &self,
        _process: &ProcessInfo<'_>,
        call: &InterceptedSyscall<'_>,
    ) -> InterceptAction {
        match call.name() {
            "getuid" => InterceptAction::Return(4242),
            "getpid" => InterceptAction::Return(31337),
            "clock_gettime" => InterceptAction::Errno(LinuxErrno::new(1)),
            _ => InterceptAction::Continue,
        }
    }
}

struct StdoutToStderr;

impl SyscallInterceptor for StdoutToStderr {
    fn intercept(
        &self,
        _process: &ProcessInfo<'_>,
        call: &InterceptedSyscall<'_>,
    ) -> InterceptAction {
        if call.name() == "write" && call.effective_args().get(0) == Some(1) {
            InterceptAction::RewriteArgs(
                call.effective_args()
                    .with_arg(0, 2)
                    .expect("fd is syscall argument zero"),
            )
        } else {
            InterceptAction::Continue
        }
    }
}

#[cfg(feature = "test-support")]
struct AlphaTopologyInterceptor;

#[cfg(feature = "test-support")]
impl SyscallInterceptor for AlphaTopologyInterceptor {
    fn intercept(
        &self,
        _process: &ProcessInfo<'_>,
        call: &InterceptedSyscall<'_>,
    ) -> InterceptAction {
        match call.name() {
            "getuid" => InterceptAction::Return(4242),
            "write" if call.effective_args().get(0) == Some(1) => InterceptAction::RewriteArgs(
                call.effective_args()
                    .with_arg(0, 2)
                    .expect("fd is syscall argument zero"),
            ),
            _ => InterceptAction::Continue,
        }
    }
}

struct PanicOnGetuid;

impl SyscallInterceptor for PanicOnGetuid {
    fn intercept(
        &self,
        _process: &ProcessInfo<'_>,
        call: &InterceptedSyscall<'_>,
    ) -> InterceptAction {
        if call.name() == "getuid" {
            panic!("intentional interceptor panic")
        }
        InterceptAction::Continue
    }
}

fn syscall_event_counts(events: &[AuditEvent], name: &str) -> (usize, usize) {
    let entries = events
        .iter()
        .filter(|event| {
            matches!(event, AuditEvent::Syscall { syscall_name, .. } if *syscall_name == name)
        })
        .count();
    let returns = events
        .iter()
        .filter(|event| {
            matches!(event, AuditEvent::SyscallReturn { syscall_name, .. } if *syscall_name == name)
        })
        .count();
    (entries, returns)
}

fn syscall_return_outcomes(events: &[AuditEvent], name: &str) -> Vec<SyscallOutcome> {
    events
        .iter()
        .filter_map(|event| match event {
            AuditEvent::SyscallReturn {
                syscall_name,
                outcome,
                ..
            } if *syscall_name == name => Some(*outcome),
            _ => None,
        })
        .collect()
}

#[test]
fn syscall_interceptor_rewrites_and_replaces() {
    let _guard = common::guest_lock();

    let identity_audit = Arc::new(AuditObserver::new());
    let identity = common::run_or_fail(
        common::interceptor_probe_builder("identity")
            .interceptor(Arc::new(IdentityInterceptor))
            .observer(Arc::clone(&identity_audit) as Arc<dyn SyscallObserver>)
            .run_blocking(),
    );
    assert_clean_exit(&identity);
    assert_eq!(
        identity.stdout_utf8(),
        "uid=4242 uid_errno=0\npid=31337 pid_errno=0\nclock_rc=-1 clock_errno=1\n"
    );
    assert!(identity.stderr.is_empty(), "{}", identity.stderr_utf8());
    let identity_events = identity_audit.events();
    for name in ["getuid", "getpid", "clock_gettime"] {
        assert_eq!(
            syscall_event_counts(&identity_events, name),
            (1, 1),
            "{name}"
        );
    }
    assert_eq!(
        syscall_return_outcomes(&identity_events, "getuid"),
        [SyscallOutcome::returned(4242)]
    );
    assert_eq!(
        syscall_return_outcomes(&identity_events, "getpid"),
        [SyscallOutcome::returned(31337)]
    );
    assert_eq!(
        syscall_return_outcomes(&identity_events, "clock_gettime"),
        [SyscallOutcome::errno(LinuxErrno::new(1))]
    );

    let write_audit = Arc::new(AuditObserver::new());
    let write = common::run_or_fail(
        common::interceptor_probe_builder("write")
            .interceptor(Arc::new(StdoutToStderr))
            .observer(Arc::clone(&write_audit) as Arc<dyn SyscallObserver>)
            .run_blocking(),
    );
    assert_clean_exit(&write);
    assert!(write.stdout.is_empty(), "{}", write.stdout_utf8());
    assert_eq!(
        write.stderr,
        [INTERCEPT_STDOUT, NATIVE_STDERR].concat(),
        "{}",
        write.stderr_utf8()
    );

    let write_events = write_audit.events();
    assert_eq!(syscall_event_counts(&write_events, "write"), (2, 2));
    assert_eq!(
        syscall_return_outcomes(&write_events, "write"),
        [
            SyscallOutcome::returned(INTERCEPT_STDOUT.len() as i64),
            SyscallOutcome::returned(NATIVE_STDERR.len() as i64),
        ]
    );
    let entries = write_events.iter().filter_map(|event| match event {
        AuditEvent::Syscall {
            syscall_name: "write",
            args,
            original_args,
            ..
        } => Some((*args, *original_args)),
        _ => None,
    });
    let entries = entries.collect::<Vec<_>>();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].0[0], 2, "observer must see effective fd");
    assert_eq!(
        entries[0].1.map(|args| args[0]),
        Some(1),
        "rewritten entry must preserve original fd"
    );
    assert_eq!(entries[1].0[0], 2);
    assert_eq!(entries[1].1, None, "unchanged fd has no duplicate args");
}

#[test]
fn syscall_interceptor_panic_is_contained() {
    let _guard = common::guest_lock();
    let prepared = {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build image-resolution runtime");
        runtime
            .block_on(
                common::interceptor_probe_builder("identity")
                    .interceptor(Arc::new(PanicOnGetuid))
                    .prepare(),
            )
            .expect("prepare interceptor probe")
    };
    let expected = prepared.launch().container_id;
    let error = prepared
        .execute()
        .expect_err("panicking interceptor must terminate only its container");
    assert!(
        matches!(
            &error,
            EmbedError::InterceptorPanicked { container_id } if *container_id == expected
        ),
        "expected typed panic for {expected:?}, got {error:?}"
    );
    assert!(
        std::process::id() > 0,
        "host test process survived the callback panic"
    );
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::await_holding_lock)]
async fn explicit_carrier_runs_two_isolated_containers() {
    let _guard = common::guest_lock();
    let gate = tempfile::tempdir().expect("rendezvous directory");
    let gate_path = gate.path().to_string_lossy().into_owned();
    let store = ImageStore::default_for_user();
    let carrier = Carrier::new().expect("explicit carrier");
    let observation = carrier.clone();
    let alpha_audit = Arc::new(AuditObserver::new());
    let beta_audit = Arc::new(AuditObserver::new());

    let command = |role: &str, exit: i32| {
        vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            format!(
                "echo shell_pid=$$; /opt/carrick/interceptor-probe identity; \
                 hostname; cat /opt/carrick/marker; \
                 : > /gate/{role}.ready; while [ ! -f /gate/release ]; do sleep 0.02; done; \
                 exit {exit}"
            ),
        ]
    };
    let alpha_vfs = FilterVfs::new(Box::new(common::interceptor_probe_vfs(Some(
        b"alpha-vfs\n",
    ))))
    .readonly(true);
    let beta_vfs =
        FilterVfs::new(Box::new(common::interceptor_probe_vfs(Some(b"beta-vfs\n")))).readonly(true);
    let alpha = carrier
        .container(common::SMOKE_IMAGE)
        .image_store(store.clone())
        .pull_policy(PullPolicy::Missing)
        .hostname("alpha-host")
        .mount(&gate_path, "/gate")
        .command(command("alpha", 7))
        .vfs_mount("/opt/carrick", Box::new(alpha_vfs))
        .interceptor(Arc::new(AlphaTopologyInterceptor))
        .observer(Arc::clone(&alpha_audit) as Arc<dyn SyscallObserver>);
    let beta = carrier
        .container(common::SMOKE_IMAGE)
        .image_store(store)
        .pull_policy(PullPolicy::Missing)
        .hostname("beta-host")
        .mount(&gate_path, "/gate")
        .command(command("beta", 0))
        .vfs_mount("/opt/carrick", Box::new(beta_vfs))
        .observer(Arc::clone(&beta_audit) as Arc<dyn SyscallObserver>);

    let alpha_run = tokio::spawn(alpha.run());
    let beta_run = tokio::spawn(beta.run());
    let rendezvous = tokio::time::timeout(Duration::from_secs(20), async {
        while !(gate.path().join("alpha.ready").exists() && gate.path().join("beta.ready").exists())
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if rendezvous.is_err() {
        let snapshot = carrick_embed::testing::carrier_snapshot(&observation)
            .expect("deadline carrier snapshot");
        std::fs::write(gate.path().join("release"), b"diagnostic-release")
            .expect("release surviving guest after deadline");
        let alpha_finished = alpha_run.is_finished();
        let beta_finished = beta_run.is_finished();
        let alpha_result = tokio::time::timeout(Duration::from_secs(10), alpha_run).await;
        let beta_result = tokio::time::timeout(Duration::from_secs(10), beta_run).await;
        panic!(
            "both containers did not reach the live barrier: alpha_finished={} \
             beta_finished={} alpha_marker={} beta_marker={} snapshot={snapshot:?} \
             alpha_result={alpha_result:?} beta_result={beta_result:?}",
            alpha_finished,
            beta_finished,
            gate.path().join("alpha.ready").exists(),
            gate.path().join("beta.ready").exists(),
        );
    }

    let live = carrick_embed::testing::carrier_snapshot(&observation).expect("live snapshot");
    assert_eq!(live.state, carrick_runtime::CarrierAdmissionState::Open);
    assert_eq!(live.vm_create_success_events, 1);
    assert_eq!(live.vm_lifecycle_violations, 0);
    assert_eq!(live.kernel_graphs, 1);
    assert_eq!(live.runtime_directories, 1);
    assert_eq!(live.registered_containers, 2);
    assert_eq!(live.live_containers, 2);
    assert_eq!(live.live_workers, Some(2));
    let inits = live.container_inits.expect("container init census");
    assert_eq!(inits.len(), 2);
    assert_ne!(inits[0].container_id, inits[1].container_id);
    assert_ne!(inits[0].internal_task_id, inits[1].internal_task_id);
    assert!(inits.iter().all(|init| init.namespace_pid == 1));

    std::fs::write(gate.path().join("release"), b"release").expect("release guests");
    let (alpha_result, beta_result) = tokio::join!(alpha_run, beta_run);
    let alpha_result = alpha_result.expect("alpha join").expect("alpha runtime");
    let beta_result = beta_result.expect("beta join").expect("beta runtime");
    assert_eq!(alpha_result.exit_code, 7);
    assert!(alpha_result.stdout.is_empty());
    let alpha_text = alpha_result.stderr_utf8();
    assert!(alpha_text.contains("uid=4242 uid_errno=0"), "{alpha_text}");
    assert!(alpha_text.contains("shell_pid=1"), "{alpha_text}");
    assert!(alpha_text.contains("alpha-host"), "{alpha_text}");
    assert!(alpha_text.contains("alpha-vfs"), "{alpha_text}");
    beta_result.assert_success();
    let beta_text = beta_result.stdout_utf8();
    assert!(beta_text.contains("uid=0 uid_errno=0"), "{beta_text}");
    assert!(beta_text.contains("shell_pid=1"), "{beta_text}");
    assert!(beta_text.contains("beta-host"), "{beta_text}");
    assert!(beta_text.contains("beta-vfs"), "{beta_text}");
    let alpha_getuid = syscall_event_counts(&alpha_audit.events(), "getuid");
    let beta_getuid = syscall_event_counts(&beta_audit.events(), "getuid");
    assert!(alpha_getuid.0 >= 1, "alpha observer missed getuid");
    assert!(beta_getuid.0 >= 1, "beta observer missed getuid");
    assert_eq!(alpha_getuid.0, alpha_getuid.1, "alpha audit is incomplete");
    assert_eq!(beta_getuid.0, beta_getuid.1, "beta audit is incomplete");

    let retired =
        carrick_embed::testing::carrier_snapshot(&observation).expect("post-retirement snapshot");
    assert_eq!(retired.registered_containers, 0);
    assert_eq!(retired.live_containers, 0);
    assert_eq!(retired.live_tasks, Some(0));
    assert_eq!(retired.live_pid_regions, Some(0));
    assert_eq!(retired.live_mounts, Some(0));
    assert_eq!(retired.live_job_groups, Some(0));
    assert_eq!(retired.live_workers, Some(0));
    carrier.shutdown().await.expect("carrier shutdown");
    assert_eq!(
        carrick_embed::testing::carrier_snapshot(&observation)
            .expect("closed snapshot")
            .state,
        carrick_runtime::CarrierAdmissionState::Closed
    );
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::await_holding_lock)]
async fn explicit_carrier_interceptor_panic_does_not_cancel_sibling() {
    let _guard = common::guest_lock();
    let gate = tempfile::tempdir().expect("rendezvous directory");
    let gate_path = gate.path().to_string_lossy().into_owned();
    let store = ImageStore::default_for_user();
    let carrier = Carrier::new().expect("explicit carrier");
    let observation = carrier.clone();
    let beta_audit = Arc::new(AuditObserver::new());

    let alpha = carrier
        .container(common::SMOKE_IMAGE)
        .image_store(store.clone())
        .pull_policy(PullPolicy::Missing)
        .command(["/opt/carrick/interceptor-probe", "identity"])
        .vfs_mount(
            "/opt/carrick",
            Box::new(FilterVfs::new(Box::new(common::interceptor_probe_vfs(None))).readonly(true)),
        )
        .interceptor(Arc::new(PanicOnGetuid));
    let beta = carrier
        .container(common::SMOKE_IMAGE)
        .image_store(store)
        .pull_policy(PullPolicy::Missing)
        .mount(&gate_path, "/gate")
        .command([
            "/bin/sh",
            "-c",
            ": > /gate/beta.ready; while [ ! -f /gate/release ]; do sleep 0.02; done; \
             /opt/carrick/interceptor-probe identity; echo beta-survived",
        ])
        .vfs_mount(
            "/opt/carrick",
            Box::new(FilterVfs::new(Box::new(common::interceptor_probe_vfs(None))).readonly(true)),
        )
        .observer(Arc::clone(&beta_audit) as Arc<dyn SyscallObserver>);

    let alpha_run = tokio::spawn(alpha.run());
    let beta_run = tokio::spawn(beta.run());
    tokio::time::timeout(Duration::from_secs(20), async {
        while !gate.path().join("beta.ready").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("beta live rendezvous");
    let alpha_error = tokio::time::timeout(Duration::from_secs(20), alpha_run)
        .await
        .expect("alpha panic deadline")
        .expect("alpha join")
        .expect_err("alpha interceptor panic must be contained");
    assert!(matches!(
        alpha_error,
        EmbedError::InterceptorPanicked { .. }
    ));
    let live = carrick_embed::testing::carrier_snapshot(&observation).expect("live snapshot");
    assert_eq!(live.state, carrick_runtime::CarrierAdmissionState::Open);
    assert_eq!(live.registered_containers, 1);
    assert_eq!(live.live_containers, 1);
    assert_eq!(live.vm_create_success_events, 1);

    std::fs::write(gate.path().join("release"), b"release").expect("release beta");
    let beta_result = beta_run
        .await
        .expect("beta join")
        .expect("beta must survive alpha panic");
    beta_result.assert_success();
    let beta_text = beta_result.stdout_utf8();
    assert!(beta_text.contains("uid=0 uid_errno=0"), "{beta_text}");
    assert!(beta_text.contains("beta-survived"), "{beta_text}");
    let beta_getuid = syscall_event_counts(&beta_audit.events(), "getuid");
    assert!(beta_getuid.0 >= 1);
    assert_eq!(beta_getuid.0, beta_getuid.1);
    assert_eq!(
        carrick_embed::testing::carrier_snapshot(&observation)
            .expect("retired snapshot")
            .registered_containers,
        0
    );
    carrier.shutdown().await.expect("carrier shutdown");
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::await_holding_lock)]
async fn explicit_carrier_early_exit_leaves_sibling_live() {
    let _guard = common::guest_lock();
    let gate = tempfile::tempdir().expect("rendezvous directory");
    let gate_path = gate.path().to_string_lossy().into_owned();
    let store = ImageStore::default_for_user();
    let carrier = Carrier::new().expect("explicit carrier");
    let observation = carrier.clone();
    let alpha = carrier
        .container(common::SMOKE_IMAGE)
        .image_store(store.clone())
        .pull_policy(PullPolicy::Missing)
        .command(["/bin/true"]);
    let beta = carrier
        .container(common::SMOKE_IMAGE)
        .image_store(store)
        .pull_policy(PullPolicy::Missing)
        .mount(&gate_path, "/gate")
        .command([
            "/bin/sh",
            "-c",
            ": > /gate/beta.ready; while [ ! -f /gate/release ]; do sleep 0.02; done; \
             echo beta-survived",
        ]);

    let alpha_run = tokio::spawn(alpha.run());
    let beta_run = tokio::spawn(beta.run());
    let alpha_result = tokio::time::timeout(Duration::from_secs(20), alpha_run)
        .await
        .expect("alpha exit deadline")
        .expect("alpha join")
        .expect("alpha runtime");
    alpha_result.assert_success();
    tokio::time::timeout(Duration::from_secs(20), async {
        while !gate.path().join("beta.ready").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("beta live rendezvous");
    let live = carrick_embed::testing::carrier_snapshot(&observation).expect("live snapshot");
    assert_eq!(live.state, carrick_runtime::CarrierAdmissionState::Open);
    assert_eq!(live.registered_containers, 1);
    assert_eq!(live.live_containers, 1);
    assert_eq!(live.live_workers, Some(1));

    std::fs::write(gate.path().join("release"), b"release").expect("release beta");
    let beta_result = beta_run
        .await
        .expect("beta join")
        .expect("beta must survive alpha exit");
    beta_result.assert_success();
    assert!(beta_result.stdout_utf8().contains("beta-survived"));
    carrier.shutdown().await.expect("carrier shutdown");
}

#[cfg(feature = "test-support")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::await_holding_lock)]
async fn explicit_carrier_shutdown_cancels_a_live_guest_and_joins_it() {
    let _guard = common::guest_lock();
    let gate = tempfile::tempdir().expect("rendezvous directory");
    let gate_path = gate.path().to_string_lossy().into_owned();
    let carrier = Carrier::new().expect("explicit carrier");
    let observation = carrier.clone();
    let blocked = carrier
        .container(common::SMOKE_IMAGE)
        .image_store(ImageStore::default_for_user())
        .pull_policy(PullPolicy::Missing)
        .mount(&gate_path, "/gate")
        .command([
            "/bin/sh",
            "-c",
            ": > /gate/ready; while [ ! -f /gate/release ]; do sleep 0.02; done",
        ]);
    let blocked_run = tokio::spawn(blocked.run());
    tokio::time::timeout(Duration::from_secs(20), async {
        while !gate.path().join("ready").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("guest live rendezvous");
    assert_eq!(
        carrick_embed::testing::carrier_snapshot(&observation)
            .expect("live snapshot")
            .live_containers,
        1
    );

    let shutdown = tokio::spawn(carrier.shutdown());
    let run_result = tokio::time::timeout(Duration::from_secs(20), blocked_run)
        .await
        .expect("cancelled guest join deadline")
        .expect("cancelled guest task join");
    if let Ok(result) = run_result {
        assert_ne!(
            result.exit_code, 0,
            "shutdown-cancelled guest cannot succeed"
        );
    }
    tokio::time::timeout(Duration::from_secs(20), shutdown)
        .await
        .expect("carrier shutdown deadline")
        .expect("shutdown task")
        .expect("shutdown result");
    let closed = carrick_embed::testing::carrier_snapshot(&observation).expect("closed snapshot");
    assert_eq!(closed.state, carrick_runtime::CarrierAdmissionState::Closed);
    assert_eq!(closed.registered_containers, 0);
    assert_eq!(closed.live_tasks, Some(0));
    assert_eq!(closed.live_job_groups, Some(0));
}

#[test]
fn captured_stdout_is_hello_world() {
    let _guard = common::guest_lock();
    let store = ImageStore::default_for_user();
    let result = common::run_or_fail(
        hello_builder(&store)
            .stdout(StdioConfig::Captured)
            .stderr(StdioConfig::Captured)
            .run_blocking(),
    );
    assert_clean_exit(&result);
    assert_eq!(result.stdout, HELLO, "stdout={:?}", result.stdout_utf8());
    assert_eq!(result.stdout_utf8(), "hello world\n");
    assert_eq!(result.stderr, b"", "stderr={:?}", result.stderr_utf8());
}

#[test]
fn captured_stdio_round_trips_guest_output_and_exit_code() {
    let _guard = common::guest_lock();
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([
                "/bin/sh",
                "-c",
                "echo hello-from-embed; echo to-stderr 1>&2; exit 7",
            ])
            .run_blocking(),
    );
    result
        .assert_exit_code(7)
        .assert_stdout_contains("hello-from-embed");
    assert_eq!(result.stdout_utf8(), "hello-from-embed\n");
    assert_eq!(result.stderr_utf8(), "to-stderr\n");
    assert!(!result.success());
    assert_eq!(result.signal, None);
}

struct CliRun {
    streamed_stdout: Vec<u8>,
    envelope: serde_json::Value,
    status: i32,
}

fn split_json_envelope(stdout: &[u8]) -> (Vec<u8>, serde_json::Value) {
    let start = if stdout.starts_with(b"{\n") {
        0
    } else {
        stdout
            .windows(3)
            .position(|w| w == b"\n{\n")
            .map(|i| i + 1)
            .unwrap_or_else(|| {
                panic!(
                    "no JSON envelope in `carrick run --json` stdout: {:?}",
                    String::from_utf8_lossy(stdout)
                )
            })
    };
    let envelope = serde_json::from_slice(&stdout[start..]).expect("parse --json envelope");
    (stdout[..start].to_vec(), envelope)
}

fn run_cli_json(store: &ImageStore) -> CliRun {
    let bin = common::repo_root().join("target/release/carrick");
    assert!(
        bin.exists(),
        "{} missing: `just test-embed` depends on `build`",
        bin.display()
    );
    let run_id = format!("{}-cli", common::run_id());
    let child = Command::new(&bin)
        .args([
            "run",
            "--json",
            "--pull",
            "missing",
            common::SMOKE_IMAGE,
            "echo",
            "hello world",
        ])
        .env("CARRICK_RUN_ID", &run_id)
        .env("CARRICK_HOME", store.root())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("spawn target/release/carrick");
    let pgid: libc::pid_t = libc::pid_t::try_from(child.id()).expect("child pid fits pid_t");
    let done = Arc::new(AtomicBool::new(false));
    let watchdog = {
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            let start = Instant::now();
            while !done.load(Ordering::Relaxed) {
                if start.elapsed() > CLI_DEADLINE {
                    // SAFETY: kill(2) on the child's own process group; the
                    // pgid was created by `process_group(0)` above.
                    let _ = unsafe { libc::kill(-pgid, libc::SIGKILL) };
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    };
    let output = child.wait_with_output().expect("wait for carrick run");
    done.store(true, Ordering::Relaxed);
    watchdog.join().expect("watchdog thread");
    let status = output.status.code().unwrap_or_else(|| {
        panic!(
            "carrick run died by signal (deadline {CLI_DEADLINE:?}?): {:?}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let (streamed_stdout, envelope) = split_json_envelope(&output.stdout);
    CliRun {
        streamed_stdout,
        envelope,
        status,
    }
}

#[test]
fn library_result_matches_cli_run() {
    let _guard = common::guest_lock();
    let store = ImageStore::default_for_user();

    let cli = run_cli_json(&store);
    assert_eq!(cli.status, 0, "carrick run exit status");
    assert_eq!(
        cli.streamed_stdout,
        HELLO,
        "cli stdout={:?}",
        String::from_utf8_lossy(&cli.streamed_stdout)
    );
    assert_eq!(cli.envelope["exit_code"], serde_json::json!(0));
    assert_eq!(cli.envelope["trap_limit_hit"], serde_json::json!(false));

    let lib = common::run_or_fail(
        hello_builder(&store)
            .stdout(StdioConfig::Captured)
            .stderr(StdioConfig::Captured)
            .run_blocking(),
    );
    assert_clean_exit(&lib);
    assert_eq!(
        lib.stdout, cli.streamed_stdout,
        "library stdout != CLI stdout"
    );
    assert_eq!(
        i64::from(lib.exit_code),
        cli.envelope["exit_code"].as_i64().expect("exit_code"),
        "library exit code != CLI exit code"
    );
    assert_eq!(
        lib.trap_limit_hit,
        cli.envelope["trap_limit_hit"]
            .as_bool()
            .expect("trap_limit_hit")
    );
}

struct StdoutRedirect {
    saved: libc::c_int,
}

impl StdoutRedirect {
    fn install(file: &std::fs::File) -> Self {
        std::io::stdout().flush().expect("flush real stdout");
        let saved = unsafe { libc::dup(libc::STDOUT_FILENO) };
        assert!(saved >= 0, "dup(1) failed");
        let rc = unsafe { libc::dup2(file.as_raw_fd(), libc::STDOUT_FILENO) };
        assert_eq!(rc, libc::STDOUT_FILENO, "dup2(file, 1) failed");
        Self { saved }
    }
}

impl Drop for StdoutRedirect {
    fn drop(&mut self) {
        unsafe {
            libc::dup2(self.saved, libc::STDOUT_FILENO);
            libc::close(self.saved);
        }
    }
}

#[test]
fn inherit_streams_to_the_carrier_stdout() {
    let _guard = common::guest_lock();
    let store = ImageStore::default_for_user();
    let mut sink = tempfile::tempfile().expect("tempfile");
    let result = {
        let _redirect = StdoutRedirect::install(&sink);
        common::run_or_fail(
            hello_builder(&store)
                .stdout(StdioConfig::Inherit)
                .stderr(StdioConfig::Captured)
                .run_blocking(),
        )
    };
    assert_clean_exit(&result);
    assert!(
        result.stdout.is_empty(),
        "Inherit must not also capture: {:?}",
        result.stdout_utf8()
    );
    let mut seen = Vec::new();
    sink.seek(SeekFrom::Start(0)).expect("rewind");
    sink.read_to_end(&mut seen).expect("read fd-1 sink");
    assert_eq!(
        seen,
        HELLO,
        "carrier fd 1 received {:?}",
        String::from_utf8_lossy(&seen)
    );
}

#[derive(Clone, Default)]
struct SharedSink(Arc<Mutex<Vec<u8>>>);

impl SharedSink {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl Write for SharedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn piped_delivers_stdout_and_stderr_to_caller_writers() {
    let _guard = common::guest_lock();
    let store = ImageStore::default_for_user();
    let out = SharedSink::default();
    let err = SharedSink::default();
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .image_store(store.clone())
            .pull_policy(PullPolicy::Missing)
            .command(["/bin/sh", "-c", "echo hello world; echo to-stderr 1>&2"])
            .stdout(StdioConfig::Piped(Box::new(out.clone())))
            .stderr(StdioConfig::Piped(Box::new(err.clone())))
            .run_blocking(),
    );
    assert_clean_exit(&result);
    assert_eq!(
        out.bytes(),
        HELLO,
        "piped stdout={:?}",
        String::from_utf8_lossy(&out.bytes())
    );
    assert_eq!(
        err.bytes(),
        b"to-stderr\n",
        "piped stderr={:?}",
        String::from_utf8_lossy(&err.bytes())
    );
    assert!(
        result.stdout.is_empty() && result.stderr.is_empty(),
        "Piped must not also capture"
    );
}

#[test]
fn env_workdir_and_hostname_reach_the_guest() {
    let _guard = common::guest_lock();
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(["/bin/sh", "-c", "echo $GREETING; pwd; hostname"])
            .env("GREETING", "hi")
            .workdir("/tmp")
            .hostname("embedded-host")
            .run_blocking(),
    );
    result.assert_success();
    assert_eq!(result.stdout_utf8(), "hi\n/tmp\nembedded-host\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn async_run_executes_on_the_blocking_pool() {
    let _guard = common::guest_lock();
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(["/bin/sh", "-c", "echo async-ok"])
            .run()
            .await,
    );
    result.assert_success().assert_stdout_contains("async-ok");
}

#[test]
fn a_trap_limit_is_reported_not_erred() {
    let _guard = common::guest_lock();
    let previous_wall = std::env::var_os("CARRICK_MAX_WALL_MS");
    // SAFETY: `just test-embed` runs this binary with RUST_TEST_THREADS=1 and
    // the guest lock excludes every other HVF test while the override is live.
    unsafe { std::env::set_var("CARRICK_MAX_WALL_MS", "0") };
    let run = ContainerBuilder::from_image(common::SMOKE_IMAGE)
        .pull_policy(PullPolicy::Missing)
        // Redirected shell writes make the watchdog observe a real guest
        // trap without growing the captured output.
        .command(["/bin/sh", "-c", "while :; do echo x >/dev/null; done"])
        .max_traps(0)
        .run_blocking();
    match previous_wall {
        Some(value) => unsafe { std::env::set_var("CARRICK_MAX_WALL_MS", value) },
        None => unsafe { std::env::remove_var("CARRICK_MAX_WALL_MS") },
    }
    let result = common::run_or_fail(run);
    assert!(result.trap_limit_hit);
    assert!(!result.success());
}

#[test]
fn exit_budget_aborts_when_child_sleeps_past_budget() {
    let _guard = common::guest_lock();
    let result = ContainerBuilder::from_image(common::SMOKE_IMAGE)
        .pull_policy(PullPolicy::Missing)
        .command(["/bin/sh", "-c", "sleep 2"])
        .auditor(Arc::new(carrick_embed::testing::ExitBudget::new(
            carrick_embed::testing::ExitBudgetMatcher::Any,
            Duration::from_millis(100),
        )))
        .run_blocking();
    match result {
        Err(EmbedError::CarrierFailed { reason }) => {
            assert!(
                reason.contains("exit budget") || reason.contains("ExitBudgetExceeded"),
                "reason={reason}"
            );
        }
        other => panic!("expected CarrierFailed with ExitBudgetExceeded, got {other:?}"),
    }
}
