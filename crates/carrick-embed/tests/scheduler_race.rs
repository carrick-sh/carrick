//! Race reproducers for the carrier scheduler, run in-process through the
//! embed API with `SyscallJitter` stretching the boundaries a race needs.
//! Signed lane only (`just test-embed scheduler_race`).
//!
//! `go_types_survives_exec_exit_jitter`: the load-coupled carrier abort
//! `scheduler generation observer lost exact transition … AuthorityMismatch`
//! reproduced 4 of 6 times under cargo-build host load on 2026-09-07 with
//! `go_types.test` (fork+exec storms of `go build`). This test replaces the
//! host load with deterministic jitter on the syscalls that move execution
//! generations. It is RED when the carrier aborts (the process dies, so the
//! harness reports the test as failed) and green when the run completes,
//! whatever the guest's own verdict.
mod common;

use std::sync::Arc;

use carrick_embed::testing::SyscallJitter;
use carrick_embed::{ContainerBuilder, ImageStore, PullPolicy, SyscallInterceptor};

const GO_IMAGE: &str = "localhost:5005/carrick-go-conformance:1.24";

#[test]
fn go_types_survives_exec_exit_jitter() {
    let _guest = common::guest_lock();
    let jitter = Arc::new(SyscallJitter::new(
        [
            "execve",
            "exit_group",
            "exit",
            "wait4",
            "waitid",
            "futex",
            "clone",
            "clone3",
        ],
        2_000,
    ));
    let result = ContainerBuilder::from_image(GO_IMAGE)
        .image_store(ImageStore::default_for_user())
        .pull_policy(PullPolicy::Missing)
        .workdir("/usr/local/go/src/go/types")
        .command([
            "/conformance/go_types.test",
            "-test.run",
            "TestCheck|TestMapping|TestIssue",
            "-test.short",
        ])
        .interceptor(Arc::clone(&jitter) as Arc<dyn SyscallInterceptor>)
        .run_blocking()
        .expect("container ran to completion without a carrier abort");
    assert!(
        jitter.matched() > 100,
        "jitter never engaged: {} matching syscalls",
        jitter.matched()
    );
    assert!(
        result.signal.is_none(),
        "guest killed by signal {:?}",
        result.signal
    );
}

/// The container-exit bound for `go_types_exit_publishes_every_process_job`.
///
/// This is NOT a performance assertion. The defect it guards is an
/// `HvpatchLoopResult` that is never published, which makes
/// `wait_process_jobs` wait forever: the only thing the bound has to separate
/// is "returned" from "never returns". It is therefore set far above any
/// starved run this shared host has produced, so load cannot decide it.
const CONTAINER_EXIT_BOUND: std::time::Duration = std::time::Duration::from_secs(20 * 60);

/// A container whose workload has FINISHED must let the carrier exit.
///
/// `go_types` is a fork/exec storm of multi-threaded processes, which is the
/// exact shape that stranded a process job: a post-`execve` leader that lost
/// the `exit_group` claim to one of its own Go runtime threads settled without
/// publishing its logical result, and nothing else could publish it. The guest
/// printed `PASS`, every Kernel task retired, every executor went idle, and the
/// carrier's main thread waited in `HvpatchLoopResult::wait` for the life of
/// the process. Jitter on the exit-path syscalls widens the settlement window
/// the same way host load did.
#[test]
fn go_types_exit_publishes_every_process_job() {
    let _guest = common::guest_lock();
    let jitter = Arc::new(SyscallJitter::new(
        ["execve", "exit_group", "exit", "wait4", "waitid", "futex"],
        2_000,
    ));
    let run_jitter = Arc::clone(&jitter);
    let (sender, receiver) = std::sync::mpsc::channel();
    // The run owns a carrier that cannot be cancelled from outside, so the
    // bound is enforced by NOT joining this thread: a wedge fails the test
    // instead of hanging the suite.
    std::thread::Builder::new()
        .name("carrick-exit-bound".to_owned())
        .spawn(move || {
            let outcome = ContainerBuilder::from_image(GO_IMAGE)
                .image_store(ImageStore::default_for_user())
                .pull_policy(PullPolicy::Missing)
                .workdir("/usr/local/go/src/go/types")
                .command([
                    "/conformance/go_types.test",
                    "-test.run",
                    "TestCheck|TestMapping",
                    "-test.short",
                ])
                .interceptor(run_jitter as Arc<dyn SyscallInterceptor>)
                .run_blocking()
                .map(|result| (result.exit_code, result.signal));
            let _ = sender.send(outcome);
        })
        .expect("spawn the bounded exit-storm run");

    let outcome = receiver.recv_timeout(CONTAINER_EXIT_BOUND).expect(
        "the container never returned: a finished process job's result was never published",
    );
    let (exit_code, signal) = outcome.expect("container ran to completion without a carrier abort");
    assert!(signal.is_none(), "guest killed by signal {signal:?}");
    assert_eq!(exit_code, 0, "go_types reported a guest failure");
    assert!(
        jitter.matched() > 100,
        "jitter never engaged: {} matching syscalls",
        jitter.matched()
    );
}

/// The scheduler's own transitions, driven through the SCHEDULER.
///
/// The design (phase 2) names an adversarial policy as the policy hook's first
/// consumer for a reason the round-2 crash makes concrete: the load-coupled
/// abort lives in claim/settle/generation-observation orderings, and host load
/// or syscall jitter only reaches them by accident. `AdversarialPolicy` reaches
/// them on purpose — it migrates every wake off `last_cpu`, runs each queue in
/// a shuffled order, steals at every opportunity and preempts on every tick —
/// with a seed, so a failing interleaving has a name.
///
/// Three seeds, because one seed is one interleaving family. RED when the
/// carrier aborts (the process dies and the harness reports a failure) or when
/// the guest is killed; green when the run completes, whatever the guest's own
/// verdict. The policy is also asserted to have been CONSULTED: the mechanism
/// only calls `pick_next`/`steal` when `inspects_queues()` is true, so a policy
/// that is installed but never asked would make this test a very slow no-op.
#[test]
fn go_types_survives_an_adversarial_scheduling_policy() {
    let _guest = common::guest_lock();
    for seed in [1_u64, 0x9E37_79B9_7F4A_7C15, 0xDEAD_BEEF_CAFE_F00D] {
        // The guest CPU count comes from the ONE authority the design names,
        // never from a second reading of the host: the policy's `cpu_count()`
        // is also the guest's `nproc`.
        let policy = Arc::new(carrick_embed::testing::AdversarialPolicy::new(
            carrick_runtime::kernel::scheduler::default_guest_cpu_count(),
            seed,
        ));
        let result = ContainerBuilder::from_image(GO_IMAGE)
            .image_store(ImageStore::default_for_user())
            .pull_policy(PullPolicy::Missing)
            .workdir("/usr/local/go/src/go/types")
            .command([
                "/conformance/go_types.test",
                "-test.run",
                "TestCheck|TestMapping",
                "-test.short",
            ])
            .scheduler(Arc::clone(&policy) as Arc<dyn carrick_embed::SchedulingPolicy>)
            .run_blocking()
            .unwrap_or_else(|error| {
                panic!("seed {seed:#x}: container aborted under the adversarial policy: {error}")
            });
        assert!(
            policy.decisions() > 100,
            "seed {seed:#x}: the policy was installed but barely consulted ({} decisions)",
            policy.decisions()
        );
        assert!(
            result.signal.is_none(),
            "seed {seed:#x}: guest killed by signal {:?}",
            result.signal
        );
    }
}
