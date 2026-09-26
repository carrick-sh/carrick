//! EL1 plan 1b and 1c signed tests: guest threads that hand off through a
//! private futex switch inside the guest at EL1, on one vCPU or across vCPUs,
//! with no host exit and no host condvar wake; timed waits end on the guest
//! virtual timer; compute loops are preempted in-guest; idle vCPUs park in
//! WFI at no host cost; and the host still reaches a thread parked in-guest
//! for signals, `exit_group` and `execve`.
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

/// The zone's counters (shared EL1 memory, zeroed with each carrier), so a
/// test proves its threads were parked and switched in-guest rather than
/// passing on the host path.
#[derive(Clone, Copy, Debug, Default)]
struct ZoneCounts {
    el1_parks: u64,
    el1_switches: u64,
    host_parks: u64,
    signal_claims: u64,
    control_claims: u64,
    cross_wakes: u64,
    sgis: u64,
    preemptions: u64,
    migrations: u64,
    timeouts: u64,
    idle_entries: u64,
    wfi_entries: u64,
    idle_exits: u64,
    misplaced: u64,
}

impl ZoneCounts {
    fn read() -> Self {
        let Some(zone) = carrick_el1_abi::zone_tables() else {
            return Self::default();
        };
        let counters = &zone.counters;
        let load = |counter: &std::sync::atomic::AtomicU64| {
            counter.load(std::sync::atomic::Ordering::Relaxed)
        };
        Self {
            el1_parks: load(&counters.el1_parks),
            el1_switches: load(&counters.el1_switches),
            host_parks: load(&counters.host_parks),
            signal_claims: load(&counters.host_claims[carrick_el1_abi::Handback::Signal as usize]),
            control_claims: load(
                &counters.host_claims[carrick_el1_abi::Handback::Control as usize],
            ),
            cross_wakes: load(&counters.el1_cross_wakes),
            sgis: load(&counters.el1_sgis),
            preemptions: load(&counters.el1_preemptions),
            migrations: load(&counters.el1_migrations),
            timeouts: load(&counters.el1_timeouts),
            idle_entries: load(&counters.el1_idle_entries),
            wfi_entries: load(&counters.el1_wfi_entries),
            idle_exits: load(&counters.el1_idle_exits),
            misplaced: load(&counters.el1_misplaced),
        }
    }

    fn since(self, before: Self) -> Self {
        Self {
            el1_parks: self.el1_parks - before.el1_parks,
            el1_switches: self.el1_switches - before.el1_switches,
            host_parks: self.host_parks - before.host_parks,
            signal_claims: self.signal_claims - before.signal_claims,
            control_claims: self.control_claims - before.control_claims,
            cross_wakes: self.cross_wakes - before.cross_wakes,
            sgis: self.sgis - before.sgis,
            preemptions: self.preemptions - before.preemptions,
            migrations: self.migrations - before.migrations,
            timeouts: self.timeouts - before.timeouts,
            idle_entries: self.idle_entries - before.idle_entries,
            wfi_entries: self.wfi_entries - before.wfi_entries,
            idle_exits: self.idle_exits - before.idle_exits,
            misplaced: self.misplaced - before.misplaced,
        }
    }
}

struct Measured {
    result: ContainerResult,
    exits: u64,
    cpu_ns: u64,
    wall: Duration,
    zone: ZoneCounts,
}

fn run_fixture(carrier: &Carrier, args: &[&str], timeout: Duration) -> Measured {
    let mut command = vec![FIXTURE.to_owned()];
    command.extend(args.iter().map(|arg| (*arg).to_owned()));
    let watchdog = common::Watchdog::start(timeout);
    let exits_before = vcpu_run_exits_total();
    let zone_before = ZoneCounts::read();
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
    let zone = ZoneCounts::read().since(zone_before);
    watchdog.disarm();
    Measured {
        result,
        exits,
        cpu_ns,
        wall,
        zone,
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
            "el1-sched pingpong iters={iters} exits={} carrier_cpu_ns={} wall_ms={} zone={:?} {}",
            measured.exits,
            measured.cpu_ns,
            measured.wall.as_millis(),
            measured.zone,
            stdout.trim()
        );
        // Each round trip is two handoffs; nearly all must be in-guest.
        assert!(
            measured.zone.el1_switches >= iters,
            "only {:?} in-guest switches for {iters} round trips",
            measured.zone
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
    println!(
        "el1-sched signal zone={:?} {}",
        measured.zone,
        stdout.trim()
    );
    assert!(measured.result.success(), "{}", describe(&measured));
    // The waiters were parked in the zone and the signals won their records.
    assert!(
        measured.zone.signal_claims >= 2,
        "signals did not claim zone-parked waiters: {:?}",
        measured.zone
    );
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
            "el1-sched exit-group exit={} wall_ms={} zone={:?}",
            measured.result.exit_code,
            measured.wall.as_millis(),
            measured.zone
        );
        assert_eq!(measured.result.exit_code, 42, "{}", describe(&measured));
        assert!(
            measured.zone.el1_parks > 0 && measured.zone.control_claims > 0,
            "exit_group did not reach threads parked in the zone: {:?}",
            measured.zone
        );
        // Part (e) of `kernel.el1.guest-scheduler`: the siblings parked with
        // nothing to switch to idled their vCPUs in EL1, and exit_group's
        // kicks forced those vCPUs out. Whether an idle vCPU reached WFI or
        // was still polling (or stealing the handing-off pair's threads,
        // EL1 plan 1d) when the kick came is timing; the WFI path itself is
        // `el1_sched_signal_reaches_a_wfi_parked_vcpu`.
        assert!(
            measured.zone.idle_entries > 0 && measured.zone.idle_exits > 0,
            "exit_group did not reach threads on idle vCPUs: {:?}",
            measured.zone
        );
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
            "el1-sched exec {} wall_ms={} zone={:?}",
            measured.result.stdout_utf8().trim(),
            measured.wall.as_millis(),
            measured.zone
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        assert!(
            measured.zone.el1_parks > 0 && measured.zone.control_claims > 0,
            "the exec drain did not reach threads parked in the zone: {:?}",
            measured.zone
        );
        assert!(
            measured.zone.wfi_entries > 0 && measured.zone.idle_exits > 0,
            "the exec drain did not reach threads on vCPUs parked in WFI: {:?}",
            measured.zone
        );
        assert_eq!(measured.result.stdout_utf8(), "exec-child ok\n");
    }
}

/// Contract `kernel.el1.guest-scheduler` (EL1 plan 1c), part (a): two threads
/// pinned to different guest CPUs ping-pong through
/// `FUTEX_WAIT_PRIVATE`/`FUTEX_WAKE_PRIVATE`, each computing for a while with
/// the turn, so every handoff wakes a thread parked on the OTHER vCPU: the
/// waker queues it there and, if that vCPU parked in WFI, sends it an SGI.
/// Two regimes: 5 us of work (the partner's vCPU is still polling) and
/// 200 us (it has parked in WFI). The budget is the affine one of the 1b
/// handoff: host exits over the difference of a long and a short run stay
/// below 0.01 per round trip, and every round trip woke across vCPUs
/// in-guest (plus an SGI per round trip in the WFI regime). Handoff latency
/// is reported.
#[test]
fn el1_sched_cross_vcpu_handoff_has_no_host_exits() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    for (work_us, short, long) in [(5u64, 2_000u64, 22_000u64), (200, 300, 3_300)] {
        let mut runs = Vec::new();
        for iters in [short, long, short, long] {
            let measured = run_fixture(
                &carrier,
                &["pinned-pingpong", &iters.to_string(), &work_us.to_string()],
                Duration::from_secs(120),
            );
            let stdout = measured.result.stdout_utf8();
            println!(
                "el1-sched pinned-pingpong iters={iters} work_us={work_us} exits={} \
                 carrier_cpu_ns={} wall_ms={} zone={:?} {}",
                measured.exits,
                measured.cpu_ns,
                measured.wall.as_millis(),
                measured.zone,
                stdout.trim()
            );
            assert!(measured.result.success(), "{}", describe(&measured));
            assert!(
                measured.zone.cross_wakes >= iters,
                "only {} in-guest cross-vCPU wakes for {iters} round trips: {:?}",
                measured.zone.cross_wakes,
                measured.zone
            );
            if work_us > 100 {
                assert!(
                    measured.zone.sgis >= iters,
                    "the partner's vCPU was not woken from WFI by SGI: {:?}",
                    measured.zone
                );
            }
            runs.push((
                iters,
                measured.exits,
                measured.cpu_ns,
                field(&stdout, "handoff_p50_ns"),
            ));
        }
        let span = (long - short) as f64;
        let mut worst: f64 = 0.0;
        for pair in runs.chunks(2) {
            let (short, long) = (&pair[0], &pair[1]);
            let exits_per_rt = (long.1 as f64 - short.1 as f64) / span;
            let cpu_ns_per_rt = (long.2 as f64 - short.2 as f64) / span;
            println!(
                "el1-sched cross-vcpu-handoff work_us={work_us} \
                 exits_per_round_trip={exits_per_rt:.4} \
                 carrier_cpu_ns_per_round_trip={cpu_ns_per_rt:.0} handoff_p50_ns={:.0}",
                long.3
            );
            worst = worst.max(exits_per_rt);
        }
        assert!(
            worst < 0.01,
            "a futex handoff between threads on different vCPUs ({work_us} us of work per \
             turn) cost {worst:.3} host exits per round trip; the in-guest (EL1) cross-vCPU \
             handoff must cost none in steady state"
        );
    }
}

/// Part (b): a 1 ms `FUTEX_WAIT_PRIVATE` timeout ends in EL1 on the virtual
/// timer. Every wait returns `ETIMEDOUT`, never before its deadline (the
/// fixture fails otherwise), the host exits per wait over the difference of
/// two run lengths stay below 0.01, and EL1 counted the timeouts. Lateness
/// past the deadline is reported.
#[test]
fn el1_sched_timed_wait_times_out_in_guest() {
    const SHORT: u64 = 200;
    const LONG: u64 = 1_200;
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let mut runs = Vec::new();
    for iters in [SHORT, LONG, SHORT, LONG] {
        let measured = run_fixture(
            &carrier,
            &["timed-wait", &iters.to_string()],
            Duration::from_secs(120),
        );
        let stdout = measured.result.stdout_utf8();
        println!(
            "el1-sched timed-wait iters={iters} exits={} carrier_cpu_ns={} wall_ms={} zone={:?} {}",
            measured.exits,
            measured.cpu_ns,
            measured.wall.as_millis(),
            measured.zone,
            stdout.trim()
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        assert!(
            measured.zone.timeouts >= iters,
            "only {} timeouts ended in-guest for {iters} waits: {:?}",
            measured.zone.timeouts,
            measured.zone
        );
        runs.push((iters, measured.exits, field(&stdout, "late_p50_ns")));
    }
    let span = (LONG - SHORT) as f64;
    let mut worst: f64 = 0.0;
    for pair in runs.chunks(2) {
        let exits_per_wait = (pair[1].1 as f64 - pair[0].1 as f64) / span;
        println!(
            "el1-sched timed-wait exits_per_wait={exits_per_wait:.4} late_p50_ns={:.0}",
            pair[1].2
        );
        worst = worst.max(exits_per_wait);
    }
    assert!(
        worst < 0.01,
        "a timed futex wait cost {worst:.3} host exits; EL1 must end it on the virtual timer"
    );
}

/// Part (c): two threads that compute without a syscall share one vCPU (the
/// main thread wakes a sibling onto its own run queue, then both count).
/// Both make progress, through EL1 timer preemption at EL0 rather than a
/// host exit.
#[test]
fn el1_sched_preemption_reaches_compute_loops() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    for _ in 0..3 {
        let measured = run_fixture(&carrier, &["compute-pair", "300"], Duration::from_secs(60));
        let stdout = measured.result.stdout_utf8();
        println!(
            "el1-sched compute-pair exits={} wall_ms={} zone={:?} {}",
            measured.exits,
            measured.wall.as_millis(),
            measured.zone,
            stdout.trim()
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        let (a, b) = (field(&stdout, "a_count"), field(&stdout, "b_count"));
        assert!(a > 0.0 && b > 0.0, "{stdout:?}");
        assert!(
            measured.zone.preemptions >= 2,
            "the compute loops were not preempted in-guest: {:?}",
            measured.zone
        );
    }
}

/// Part (d): with every thread blocked (four in untimed waits, one in a
/// timed wait) the carrier costs almost no host CPU: the idle vCPUs park in
/// WFI. The CPU of a 500 ms and a 2500 ms idle window differ by less than
/// 1% of one core over the extra two seconds.
#[test]
fn el1_sched_idle_carrier_costs_no_host_cpu() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let mut runs = Vec::new();
    for ms in [500u64, 2500, 500, 2500] {
        let measured = run_fixture(
            &carrier,
            &["idle-carrier", &ms.to_string()],
            Duration::from_secs(60),
        );
        let stdout = measured.result.stdout_utf8();
        println!(
            "el1-sched idle-carrier ms={ms} exits={} carrier_cpu_ns={} wall_ms={} zone={:?} {}",
            measured.exits,
            measured.cpu_ns,
            measured.wall.as_millis(),
            measured.zone,
            stdout.trim()
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        assert!(
            measured.zone.wfi_entries > 0 && measured.zone.idle_entries >= 4,
            "the blocked threads did not idle their vCPUs in WFI: {:?}",
            measured.zone
        );
        runs.push((measured.cpu_ns, measured.exits));
    }
    let mut worst: f64 = 0.0;
    for pair in runs.chunks(2) {
        let cpu_fraction = (pair[1].0 as f64 - pair[0].0 as f64) / 2e9;
        let exits_per_s = (pair[1].1 as f64 - pair[0].1 as f64) / 2.0;
        println!(
            "el1-sched idle-carrier cpu_fraction_of_one_core={cpu_fraction:.5} \
             exits_per_idle_second={exits_per_s:.1}"
        );
        worst = worst.max(cpu_fraction);
    }
    assert!(
        worst < 0.01,
        "an idle carrier burned {:.2}% of a core",
        worst * 100.0
    );
}

/// Part (e), signals: a thread parked with nothing else to run idles its
/// vCPU in EL1 (in WFI past the spin); each of 200 signals must reach it (the
/// host kick forces the WFI-parked vCPU out), its handler runs and its wait
/// returns `EINTR`.
#[test]
fn el1_sched_signal_reaches_a_wfi_parked_vcpu() {
    const ROUNDS: u64 = 200;
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let measured = run_fixture(
        &carrier,
        &["wfi-signal", &ROUNDS.to_string()],
        Duration::from_secs(120),
    );
    let stdout = measured.result.stdout_utf8();
    println!(
        "el1-sched wfi-signal exits={} wall_ms={} zone={:?} {}",
        measured.exits,
        measured.wall.as_millis(),
        measured.zone,
        stdout.trim()
    );
    assert!(measured.result.success(), "{}", describe(&measured));
    assert_eq!(field(&stdout, "eintr"), ROUNDS as f64, "{stdout:?}");
    assert!(
        measured.zone.idle_exits >= ROUNDS && measured.zone.wfi_entries >= ROUNDS,
        "the signals did not reach vCPUs parked in WFI: {:?}",
        measured.zone
    );
}

/// The PSTATE a guest signal handler reads from its `ucontext` is unchanged
/// by the EL0 interrupt policy of the in-guest scheduler: Carrick has always
/// shown EL0t with DAIF set (0x3c0), for a signal at a syscall boundary and
/// for one that interrupts computation after in-guest futex service.
#[test]
fn el1_sched_pstate_seen_by_the_guest_is_unchanged() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let measured = run_fixture(&carrier, &["pstate"], Duration::from_secs(60));
    let stdout = measured.result.stdout_utf8();
    println!("el1-sched pstate {}", stdout.trim());
    assert!(measured.result.success(), "{}", describe(&measured));
    assert!(
        stdout.contains("sync_daif=0x3c0 async_daif=0x3c0 sync_el=0 async_el=0"),
        "{stdout:?}"
    );
}
