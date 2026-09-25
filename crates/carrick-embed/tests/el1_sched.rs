//! EL1 plan 1b signed tests: guest threads that hand off through a private
//! futex switch inside the guest at EL1, with no host exit and no host
//! condvar wake, and the host still reaches a thread parked in-guest for
//! signals, `exit_group` and `execve`.
//!
//! Run ONLY through `just test-embed el1_sched` (scripts/test-signed.sh, which
//! also builds the static `fixtures/embed-el1-sched` guest): it signs the test
//! executable with the hypervisor entitlement and runs it under
//! `RUST_TEST_THREADS=1`. HV_DENIED is a failure, never a skip.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use carrick_abi::{NsGid, NsUid};
use carrick_embed::{
    Carrier, ContainerResult, EmbedError, InMemoryFileVfs, PullPolicy, reset_el1_counters,
    vcpu_run_exits_total,
};

const FIXTURE: &str = "/opt/carrick/el1-sched";

fn carrier_or_fail() -> Carrier {
    for _ in 0..50 {
        match Carrier::new() {
            Ok(carrier) => return carrier,
            Err(EmbedError::Entitlement) => panic!(
                "HV_DENIED (0xfae94007): run through scripts/test-signed.sh; \
                 a bare cargo test cannot boot a guest"
            ),
            Err(EmbedError::CarrierAlreadyActive) => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("carrier initialization failed: {error}"),
        }
    }
    panic!("carrier initialization timed out waiting for a prior carrier to retire");
}

/// The static el1-sched fixture, mounted executable at `/opt/carrick`.
fn el1_sched_vfs() -> InMemoryFileVfs {
    let fixture = common::repo_root().join("target/embed-fixtures/el1-sched-aarch64");
    let bytes = std::fs::read(&fixture).unwrap_or_else(|error| {
        panic!(
            "read {}: {error}; scripts/test-signed.sh must build the fixture first \
             (scripts/build-embed-el1-sched.sh)",
            fixture.display()
        )
    });
    let vfs = InMemoryFileVfs::new();
    vfs.add_file_with_metadata(FIXTURE, bytes, 0o755, NsUid::ROOT, NsGid::ROOT, 0)
        .expect("install executable el1-sched fixture");
    vfs
}

/// The carrier process's own CPU time (user + system) in nanoseconds. The
/// carrier runs in this test process, so this is carrier CPU.
fn carrier_cpu_ns() -> u64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: getrusage writes the struct it is given.
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    assert_eq!(rc, 0, "getrusage");
    let tv = |tv: libc::timeval| tv.tv_sec as u64 * 1_000_000_000 + tv.tv_usec as u64 * 1_000;
    tv(usage.ru_utime) + tv(usage.ru_stime)
}

struct Measured {
    result: ContainerResult,
    exits: u64,
    cpu_ns: u64,
    wall: Duration,
}

fn run_fixture(carrier: &Carrier, args: &[&str], timeout: Duration) -> Measured {
    let mut command = vec![FIXTURE.to_owned()];
    command.extend(args.iter().map(|arg| (*arg).to_owned()));
    let watchdog = common::Watchdog::start(timeout);
    let exits_before = vcpu_run_exits_total();
    let cpu_before = carrier_cpu_ns();
    let start = std::time::Instant::now();
    let result = common::run_or_fail(
        carrier
            .container(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(command)
            .vfs_mount("/opt/carrick", Box::new(el1_sched_vfs()))
            .run_blocking(),
    );
    let wall = start.elapsed();
    let cpu_ns = carrier_cpu_ns() - cpu_before;
    let exits = vcpu_run_exits_total() - exits_before;
    watchdog.disarm();
    Measured {
        result,
        exits,
        cpu_ns,
        wall,
    }
}

fn describe(measured: &Measured) -> String {
    format!(
        "exit {} signal {:?} stdout {:?} stderr {:?}",
        measured.result.exit_code,
        measured.result.signal,
        measured.result.stdout_utf8(),
        measured.result.stderr_utf8()
    )
}

fn field(stdout: &str, key: &str) -> f64 {
    stdout
        .split_whitespace()
        .find_map(|token| token.strip_prefix(key)?.strip_prefix('=')?.parse().ok())
        .unwrap_or_else(|| panic!("no {key}= in {stdout:?}"))
}

/// Contract `kernel.el1.futex-handoff`: two threads of one process that
/// ping-pong through `FUTEX_WAIT_PRIVATE`/`FUTEX_WAKE_PRIVATE` switch inside
/// the guest. The budget is affine in the round-trip count: runs of `SHORT`
/// and `LONG` round trips differ by `LONG - SHORT` round trips, and the
/// carrier's host exits (every `hv_vcpu_run` return) over that difference
/// must be zero in steady state (below 0.01 per round trip: a host
/// preemption kick every few milliseconds is allowed, one exit per handoff
/// is not). Startup, teardown and convergence cost cancel in the difference.
#[test]
fn el1_sched_futex_handoff_has_no_host_exits() {
    const SHORT: u64 = 5_000;
    const LONG: u64 = 55_000;
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let mut runs = Vec::new();
    for iters in [SHORT, LONG, SHORT, LONG] {
        let measured = run_fixture(
            &carrier,
            &["pingpong", &iters.to_string()],
            Duration::from_secs(120),
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        let stdout = measured.result.stdout_utf8();
        println!(
            "el1-sched pingpong iters={iters} exits={} carrier_cpu_ns={} wall_ms={} {}",
            measured.exits,
            measured.cpu_ns,
            measured.wall.as_millis(),
            stdout.trim()
        );
        runs.push((
            iters,
            measured.exits,
            measured.cpu_ns,
            field(&stdout, "p50_ns"),
        ));
    }
    let span = (LONG - SHORT) as f64;
    let mut worst_exits_per_rt: f64 = 0.0;
    for pair in runs.chunks(2) {
        let (short, long) = (&pair[0], &pair[1]);
        let exits_per_rt = (long.1 as f64 - short.1 as f64) / span;
        let cpu_ns_per_rt = (long.2 as f64 - short.2 as f64) / span;
        println!(
            "el1-sched futex-handoff exits_per_round_trip={exits_per_rt:.4} \
             carrier_cpu_ns_per_round_trip={cpu_ns_per_rt:.0} p50_ns={:.0}",
            long.3
        );
        worst_exits_per_rt = worst_exits_per_rt.max(exits_per_rt);
    }
    assert!(
        worst_exits_per_rt < 0.01,
        "a futex handoff between two guest threads cost {worst_exits_per_rt:.3} host exits \
         per round trip; the in-guest (EL1) handoff must cost none in steady state"
    );
}

/// A signal to a thread parked in a futex wait is delivered: the handler
/// runs, and without `SA_RESTART` the wait returns `EINTR`. With
/// `SA_RESTART` the handler runs too; whether the wait then restarts is
/// reported, not asserted (Carrick returns `EINTR` there today, on the host
/// path as in-guest; see the 1b design note).
#[test]
fn el1_sched_signal_reaches_a_parked_thread() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let measured = run_fixture(&carrier, &["signal"], Duration::from_secs(90));
    let stdout = measured.result.stdout_utf8();
    println!("el1-sched signal {}", stdout.trim());
    assert!(measured.result.success(), "{}", describe(&measured));
    assert_eq!(field(&stdout, "eintr_result"), -4.0, "{stdout:?}");
    assert_eq!(field(&stdout, "usr1_handled"), 1.0, "{stdout:?}");
    assert_eq!(field(&stdout, "usr2_handled"), 1.0, "{stdout:?}");
}

/// `exit_group` completes while sibling threads are parked in futex waits
/// (in-guest and host-parked) and a pair is handing off.
#[test]
fn el1_sched_exit_group_with_parked_threads() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    for _ in 0..5 {
        let measured = run_fixture(&carrier, &["exit-group"], Duration::from_secs(90));
        println!(
            "el1-sched exit-group exit={} wall_ms={}",
            measured.result.exit_code,
            measured.wall.as_millis()
        );
        assert_eq!(measured.result.exit_code, 42, "{}", describe(&measured));
    }
}

/// `execve` from a non-leader thread while siblings are parked in futex waits
/// replaces the image: the successor runs and exits normally.
#[test]
fn el1_sched_exec_from_a_sibling_with_parked_threads() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    for _ in 0..5 {
        let carrier = carrier_or_fail();
        let measured = run_fixture(&carrier, &["exec"], Duration::from_secs(90));
        println!(
            "el1-sched exec {} wall_ms={}",
            measured.result.stdout_utf8().trim(),
            measured.wall.as_millis()
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        assert_eq!(measured.result.stdout_utf8(), "exec-child ok\n");
    }
}
