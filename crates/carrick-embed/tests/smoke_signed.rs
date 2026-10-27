//! `just smoke-signed` (#893): the fast signed first-boot smoke.
//!
//! Most signed rounds that die do so in their first second, deterministically:
//! a bootstrap fatal, a refused root exit, or a successor bootstrap that cannot
//! reacquire what its predecessor retired (#855 lost nine rounds this way).
//! These tests drive the shortest production shapes that reach each of those
//! paths with existing guest programs only (the static el1-sched fixture and
//! the canonical image's shell), so one narrowed signed invocation
//! (`CARRICK_TEST_TARGET=smoke_signed`, filter `smoke_`) proves them in about
//! a second of guest time. The assertions are semantic (exit status and
//! output), not operational budgets: budget contracts stay with their owning
//! suites (`el1_sched`, `el1_fork_exec`).
//!
//! `#[ignore]`d cases are known red on main and tracked; `just smoke-signed`
//! runs them with `--include-ignored` and records them as informational, so
//! they are observed on every run without deciding its verdict.
//!
//! Run ONLY through `just smoke-signed` or `just test-embed smoke_`
//! (scripts/test-signed.sh signs this executable). HV_DENIED is a failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::{Duration, Instant};

use carrick_embed::{Carrier, ContainerResult, PullPolicy};

/// Every smoke case finishes in well under a second on a healthy carrier; a
/// hang is reaped and reported, never waited out.
const CASE_BOUND: Duration = Duration::from_secs(30);

/// Reports one case's wall time on drop, also while unwinding from a failed
/// assertion; `carrick-xtask smoke-signed` reads these lines into its receipt.
struct CaseClock {
    name: &'static str,
    start: Instant,
}

impl CaseClock {
    fn start(name: &'static str) -> Self {
        Self {
            name,
            start: Instant::now(),
        }
    }
}

impl Drop for CaseClock {
    fn drop(&mut self) {
        println!(
            "smoke-signed: case={} wall_ms={} panicking={}",
            self.name,
            self.start.elapsed().as_millis(),
            std::thread::panicking()
        );
    }
}

fn describe(result: &ContainerResult) -> String {
    format!(
        "exit_code={} stdout={:?} stderr={:?}",
        result.exit_code,
        result.stdout_utf8(),
        result.stderr_utf8()
    )
}

/// One container of the el1-sched fixture on `carrier`.
fn run_el1_sched(carrier: &Carrier, args: &[&str]) -> ContainerResult {
    let mut command = vec![common::EL1_SCHED_FIXTURE.to_owned()];
    command.extend(args.iter().map(|arg| (*arg).to_owned()));
    let _watchdog = common::Watchdog::start(CASE_BOUND);
    common::run_or_fail(
        carrier
            .container(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(command)
            .vfs_mount("/opt/carrick", Box::new(common::el1_sched_vfs()))
            .run_blocking(),
    )
}

/// One `/bin/sh -c` container of the canonical image on `carrier`.
fn run_shell(carrier: &Carrier, script: &str) -> ContainerResult {
    let _watchdog = common::Watchdog::start(CASE_BOUND);
    common::run_or_fail(
        carrier
            .container(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(["/bin/sh", "-c", script])
            .run_blocking(),
    )
}

/// Bootstrap, clean root exit, and successor bootstraps in ONE carrier: the
/// #855 smoke shape (`el1_sched_host_blocked_read_resumes_by_guest_scheduling`
/// runs four such arms at 1,000/6,000 round trips). A 1,000-round-trip
/// host-served socket ping-pong grows the root's page-table arenas, so the
/// root-MM retirement on exit and the successor's reacquisition of the same
/// pooled root slot are both exercised. Three roots: two successors.
#[test]
fn smoke_root_exit_then_successor_bootstrap_in_one_carrier() {
    let _guard = common::guest_lock();
    let _clock = CaseClock::start("smoke_root_exit_then_successor_bootstrap_in_one_carrier");
    let carrier = common::carrier_or_fail();
    for root in 1..=3 {
        let result = run_el1_sched(&carrier, &["sock-pingpong", "1000"]);
        assert!(result.success(), "root {root}: {}", describe(&result));
        assert!(
            result.stdout_utf8().contains("sock-pingpong iters=1000"),
            "root {root} did not complete its round trips: {}",
            describe(&result)
        );
    }
}

/// Pipe round trips that block in the guest: the el1-sched fixture's two
/// threads hand a byte back and forth over two pipes (the workload of
/// `el1_ipc_pipe_blocking_roundtrips`, without its EL1 counter budget).
#[test]
fn smoke_pipe_round_trips_complete() {
    let _guard = common::guest_lock();
    let _clock = CaseClock::start("smoke_pipe_round_trips_complete");
    let carrier = common::carrier_or_fail();
    let result = run_el1_sched(&carrier, &["pipe-pingpong", "256"]);
    assert!(result.success(), "{}", describe(&result));
    assert!(
        result.stdout_utf8().contains("pipe-pingpong iters=256"),
        "{}",
        describe(&result)
    );
}

/// One root exec: the root shell replaces itself with a program that writes.
/// Since #740 slice 4 root exec takes the host route with the task's live
/// authority (the shape of `el1_fork_exec::native_root_exec_replaces_pid1_shell`).
#[test]
fn smoke_exec_replaces_root_image() {
    let _guard = common::guest_lock();
    let _clock = CaseClock::start("smoke_exec_replaces_root_image");
    let carrier = common::carrier_or_fail();
    let result = run_shell(&carrier, "exec /bin/echo exec_done");
    assert!(result.success(), "{}", describe(&result));
    assert_eq!(result.stdout_utf8(), "exec_done\n", "{}", describe(&result));
}

/// Fork, wait, and exec in a native fork child: a child forks and exits, a
/// second child reuses its retired slot and `execve`s a raw no-libc
/// successor that answers over in-zone pipes, and the parent waits for both
/// (one round of `el1_fork_exec::native_child_exec_after_reusing_a_retired_slot`).
/// Root exec takes the host route since #740 slice 4; this is the in-ring
/// child exec path.
#[test]
fn smoke_native_child_exec_after_fork_and_wait() {
    let _guard = common::guest_lock();
    let _clock = CaseClock::start("smoke_native_child_exec_after_fork_and_wait");
    let carrier = common::carrier_or_fail();
    let _watchdog = common::Watchdog::start(CASE_BOUND);
    common::reused_slot_native_child_exec(carrier.container(common::SMOKE_IMAGE));
}

/// One fork, pipe round trips between two live processes, and one wait: the
/// el1-sched fixture's `two-process` mode forks, ping-pongs a byte with its
/// child over pipes, then `waitpid`s and checks the child's exit status (the
/// workload of `el1_sched_two_processes_share_vcpus`, without its scheduling
/// budget). Known red on main 0b2da9439 and cb8187f11f: the parent completes its round trips
/// but the forked child never reports and exits unsuccessfully
/// (`child_ok=false`); `el1_sched_two_processes_share_vcpus` fails the same
/// way. Tracked with the native-fork follow-ups of #740 (#841, #894).
#[test]
#[ignore = "known red on main: forked native child exits unsuccessfully (#740 follow-ups)"]
fn smoke_fork_pipe_then_wait_reaps_child() {
    let _guard = common::guest_lock();
    let _clock = CaseClock::start("smoke_fork_pipe_then_wait_reaps_child");
    let carrier = common::carrier_or_fail();
    let result = run_el1_sched(&carrier, &["two-process", "200"]);
    assert!(result.success(), "{}", describe(&result));
    let stdout = result.stdout_utf8();
    assert!(
        stdout.contains("two-process child round_trips=200 ")
            && stdout.contains("two-process parent round_trips=200 ")
            && stdout.contains("child_ok=true"),
        "{}",
        describe(&result)
    );
}
