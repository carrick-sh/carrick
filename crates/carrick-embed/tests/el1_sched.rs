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

#[path = "../../../fixtures/embed-el1-sched/src/sample_buffer.rs"]
mod sample_buffer;

use std::time::Duration;

use carrick_abi::{NsGid, NsUid};
use carrick_embed::{
    Carrier, ContainerResult, EmbedError, InMemoryFileVfs, PullPolicy, read_el1_counters,
    reset_el1_counters, vcpu_hvc_not_svc_reasons, vcpu_hvc_not_svc_total, vcpu_run_exit_classes,
    vcpu_run_exits_total,
};

const FIXTURE: &str = "/opt/carrick/el1-sched";

#[test]
fn measured_sample_backing_is_fixed_across_short_and_long_runs() {
    for (short, long) in [(5_000, 55_000), (200, 1_200)] {
        let short_samples = sample_buffer::measured_samples(short, long);
        let long_samples = sample_buffer::measured_samples(long, long);
        assert_eq!(short_samples.capacity(), long_samples.capacity());
        assert!(short_samples.capacity() >= long);
        assert!(short_samples.is_empty());
        assert!(long_samples.is_empty());
    }
}

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
    steals: u64,
    service_exits: u64,
    service_placements: u64,
    ready_placements: u64,
    service_adoptions: u64,
    exit_adoptions: u64,
    host_handbacks: u64,
    host_queue_claims: u64,
    host_executor_parks: u64,
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
            steals: load(&counters.el1_steals),
            service_exits: load(&counters.el1_service_exits),
            service_placements: load(&counters.host_service_placements),
            ready_placements: load(&counters.host_ready_placements),
            service_adoptions: load(&counters.service_adoptions),
            exit_adoptions: load(&counters.exit_adoptions),
            host_handbacks: load(&counters.host_handbacks),
            host_queue_claims: load(&counters.host_queue_claims),
            host_executor_parks: load(&counters.host_executor_parks),
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
            steals: self.steals - before.steals,
            service_exits: self.service_exits - before.service_exits,
            service_placements: self.service_placements - before.service_placements,
            ready_placements: self.ready_placements - before.ready_placements,
            service_adoptions: self.service_adoptions - before.service_adoptions,
            exit_adoptions: self.exit_adoptions - before.exit_adoptions,
            host_handbacks: self.host_handbacks - before.host_handbacks,
            host_queue_claims: self.host_queue_claims - before.host_queue_claims,
            host_executor_parks: self.host_executor_parks - before.host_executor_parks,
        }
    }
}

struct Measured {
    result: ContainerResult,
    exits: u64,
    hvc_not_svc: u64,
    hvc_not_svc_reasons: carrick_el1_abi::HvcNotSvcCounts,
    exit_classes: [u64; carrick_el1_abi::HostExitClass::COUNT],
    el1_exit_reasons: [u64; carrick_el1_abi::El1ExitReason::COUNT],
    forwarded_syscalls: Vec<(usize, u64)>,
    host_work_publications: [u64; carrick_el1_abi::HostWorkPublishReason::COUNT],
    cpu_ns: u64,
    wall: Duration,
    zone: ZoneCounts,
}

fn run_fixture(carrier: &Carrier, args: &[&str], timeout: Duration) -> Measured {
    let mut command = vec![FIXTURE.to_owned()];
    command.extend(args.iter().map(|arg| (*arg).to_owned()));
    let watchdog = common::Watchdog::start(timeout);
    let exits_before = vcpu_run_exits_total();
    let not_svc_before = vcpu_hvc_not_svc_total();
    let not_svc_reasons_before = vcpu_hvc_not_svc_reasons();
    let classes_before = vcpu_run_exit_classes();
    let reasons_before = read_el1_counters()
        .map_or([0; carrick_el1_abi::El1ExitReason::COUNT], |c| {
            std::array::from_fn(|i| c.exit_reasons[i].load(std::sync::atomic::Ordering::Relaxed))
        });
    let forwarded_before = read_el1_counters().map_or([0; 512], |c| {
        std::array::from_fn(|i| c.forwarded[i].load(std::sync::atomic::Ordering::Relaxed))
    });
    let host_work_before = carrick_el1_abi::host_work_publication_counts();
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
    let hvc_not_svc = vcpu_hvc_not_svc_total() - not_svc_before;
    let mut hvc_not_svc_reasons = vcpu_hvc_not_svc_reasons();
    for i in 0..carrick_el1_abi::HvcNotSvcReason::COUNT {
        hvc_not_svc_reasons.by_ec[i] -= not_svc_reasons_before.by_ec[i];
        hvc_not_svc_reasons.fault_status[i] -= not_svc_reasons_before.fault_status[i];
    }
    for i in 0..carrick_el1_abi::HvcSysregKind::COUNT {
        hvc_not_svc_reasons.sysreg[i] -= not_svc_reasons_before.sysreg[i];
    }
    hvc_not_svc_reasons.emulated_sys64 -= not_svc_reasons_before.emulated_sys64;
    assert_eq!(
        hvc_not_svc_reasons.by_ec.iter().sum::<u64>(),
        hvc_not_svc,
        "unattributed HVC #2 non-SVC return"
    );
    let exit_classes = vcpu_run_exit_classes();
    let exit_classes = std::array::from_fn(|i| exit_classes[i] - classes_before[i]);
    assert_eq!(
        exit_classes.iter().sum::<u64>(),
        exits,
        "unattributed HVF return"
    );
    let el1_exit_reasons =
        read_el1_counters().map_or([0; carrick_el1_abi::El1ExitReason::COUNT], |c| {
            std::array::from_fn(|i| {
                c.exit_reasons[i]
                    .load(std::sync::atomic::Ordering::Relaxed)
                    .saturating_sub(reasons_before[i])
            })
        });
    let forwarded_syscalls = read_el1_counters().map_or_else(Vec::new, |c| {
        (0..512)
            .filter_map(|nr| {
                let count = c.forwarded[nr]
                    .load(std::sync::atomic::Ordering::Relaxed)
                    .saturating_sub(forwarded_before[nr]);
                (count != 0).then_some((nr, count))
            })
            .collect()
    });
    let host_work_after = carrick_el1_abi::host_work_publication_counts();
    let host_work_publications = std::array::from_fn(|i| host_work_after[i] - host_work_before[i]);
    let zone = ZoneCounts::read().since(zone_before);
    watchdog.disarm();
    Measured {
        result,
        exits,
        hvc_not_svc,
        hvc_not_svc_reasons,
        exit_classes,
        el1_exit_reasons,
        forwarded_syscalls,
        host_work_publications,
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

fn exit_breakdown(measured: &Measured) -> String {
    use carrick_el1_abi::HostExitClass as C;
    let c = &measured.exit_classes;
    format!(
        "canceled:{} idle:{} kick:{} syscall:{} metadata:{} maintenance:{} fault:{} other:{}",
        c[C::Canceled as usize],
        c[C::Idle as usize],
        c[C::Kick as usize],
        c[C::Syscall as usize],
        c[C::Metadata as usize],
        c[C::Maintenance as usize],
        c[C::Fault as usize],
        c[C::Other as usize],
    )
}

fn hvc_not_svc_breakdown(measured: &Measured) -> String {
    use carrick_el1_abi::HvcSysregKind as S;
    let counts = &measured.hvc_not_svc_reasons;
    let nonzero = |values: &[u64]| {
        values
            .iter()
            .enumerate()
            .filter_map(|(code, count)| (*count != 0).then_some((code, *count)))
            .collect::<Vec<_>>()
    };
    format!(
        "hvc_fn:2,ec:{:?},fsc:{:?},sysreg:cntfrq:{}|cntvct:{}|ctr:{}|dczid:{}|feature_id:{}|other:{},emulated_sys64:{}",
        nonzero(&counts.by_ec),
        nonzero(&counts.fault_status),
        counts.sysreg[S::Cntfrq as usize],
        counts.sysreg[S::Cntvct as usize],
        counts.sysreg[S::Ctr as usize],
        counts.sysreg[S::Dczid as usize],
        counts.sysreg[S::FeatureId as usize],
        counts.sysreg[S::Other as usize],
        counts.emulated_sys64
    )
}

fn host_work_breakdown(measured: &Measured) -> String {
    use carrick_el1_abi::HostWorkPublishReason as R;
    let counts = &measured.host_work_publications;
    format!(
        "slot:{} all:{} task:{} file_table:{}",
        counts[R::DirectSlot as usize],
        counts[R::AllSlots as usize],
        counts[R::ExactTask as usize],
        counts[R::FileTable as usize],
    )
}

fn el1_reason_breakdown(measured: &Measured) -> String {
    use carrick_el1_abi::El1ExitReason as R;
    let r = &measured.el1_exit_reasons;
    format!(
        "idle_host_work:{} idle_entry_host_work:{} service:{} interrupt_host_work:{}",
        r[R::IdleHostWork as usize],
        r[R::IdleEntryHostWork as usize],
        r[R::Service as usize],
        r[R::InterruptHostWork as usize],
    )
}

fn field(stdout: &str, key: &str) -> f64 {
    stdout
        .split_whitespace()
        .find_map(|token| token.strip_prefix(key)?.strip_prefix('=')?.parse().ok())
        .unwrap_or_else(|| panic!("no {key}= in {stdout:?}"))
}

/// Contract `kernel.el1.futex-handoff`: two threads of one process, pinned
/// to one guest CPU, that ping-pong through
/// `FUTEX_WAIT_PRIVATE`/`FUTEX_WAKE_PRIVATE` switch inside the guest (the
/// cross-vCPU handoff is `el1_sched_cross_vcpu_handoff_has_no_host_exits`).
/// The budget is affine in the round-trip count: runs of `SHORT`
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
            "el1-sched pingpong iters={iters} exits={} host_classes={} hvc_not_svc={} hvc_not_svc_reasons={} el1_reasons={} host_work={} forwarded_by_nr={:?} carrier_cpu_ns={} wall_ms={} zone={:?} {}",
            measured.exits,
            exit_breakdown(&measured),
            measured.hvc_not_svc,
            hvc_not_svc_breakdown(&measured),
            el1_reason_breakdown(&measured),
            host_work_breakdown(&measured),
            measured.forwarded_syscalls,
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
        // Part (e) of `kernel.el1.guest-scheduler`: exit_group reached the
        // siblings parked in the zone (the control claims above). Since EL1
        // plan 1d an idle vCPU is an executor waiting in the guest with no
        // thread, so a parked sibling holds no vCPU to force out; the WFI
        // path itself is `el1_sched_signal_reaches_a_wfi_parked_vcpu`.
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
        // Since EL1 plan 1d an idle vCPU is an executor waiting in the guest
        // with no thread: the drain reaches the parked siblings through their
        // records (the control claims above), not through their vCPUs.
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
            "el1-sched timed-wait iters={iters} exits={} host_classes={} hvc_not_svc={} hvc_not_svc_reasons={} el1_reasons={} host_work={} forwarded_by_nr={:?} carrier_cpu_ns={} wall_ms={} zone={:?} {}",
            measured.exits,
            exit_breakdown(&measured),
            measured.hvc_not_svc,
            hvc_not_svc_breakdown(&measured),
            el1_reason_breakdown(&measured),
            host_work_breakdown(&measured),
            measured.forwarded_syscalls,
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
        if measured.cpu_ns > measured.wall.as_nanos() as u64 / 2
            && let Some(zone) = carrick_el1_abi::zone_tables()
        {
            // A busy idle carrier: what the vCPUs hold is the evidence.
            let mut census = String::new();
            let _ = zone.write_census(&mut census);
            println!("el1-sched idle-carrier busy; zone census:\n{census}");
        }
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

/// Contract `kernel.el1.guest-run-queue` (EL1 plan 1d), part (a): a thread
/// blocked in a host-served syscall (a pipe `read`) is resumed by the guest's
/// scheduler. Two threads hand a byte back and forth over two pipes, so every
/// turn blocks one in a host read and completes it from the other. The
/// completed read becomes a service record in an EL1 run queue, and the
/// executor of the vCPU EL1 runs it on serves it: no host run queue holds
/// the thread and no host executor parks on a run-queue condvar waiting for
/// it. Over the difference of a long and a short run, host run-queue claims
/// and host executor parks per round trip must be zero in steady state
/// (below 0.01), and every round trip is served through service records.
/// Red: the same binary with `CARRICK_EL1_SCHED=0`, where completions go to
/// host run queues (about two claims and two parks per round trip).
#[test]
fn el1_sched_host_blocked_read_resumes_by_guest_scheduling() {
    const SHORT: u64 = 1_000;
    const LONG: u64 = 6_000;
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let mut runs = Vec::new();
    for iters in [SHORT, LONG, SHORT, LONG] {
        let measured = run_fixture(
            &carrier,
            &["pipe-pingpong", &iters.to_string()],
            Duration::from_secs(120),
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        let stdout = measured.result.stdout_utf8();
        println!(
            "el1-sched pipe-pingpong iters={iters} exits={} carrier_cpu_ns={} wall_ms={} zone={:?} {}",
            measured.exits,
            measured.cpu_ns,
            measured.wall.as_millis(),
            measured.zone,
            stdout.trim()
        );
        runs.push((
            iters,
            measured.zone,
            measured.cpu_ns,
            field(&stdout, "rt_p50_ns"),
        ));
    }
    let span = (LONG - SHORT) as f64;
    for pair in runs.chunks(2) {
        let (short, long) = (&pair[0], &pair[1]);
        let per = |f: fn(&ZoneCounts) -> u64| (f(&long.1) as f64 - f(&short.1) as f64) / span;
        let claims = per(|z| z.host_queue_claims);
        let parks = per(|z| z.host_executor_parks);
        let services = per(|z| z.service_adoptions);
        let cpu = (long.2 as f64 - short.2 as f64) / span;
        println!(
            "el1-sched host-blocked-read host_queue_claims_per_rt={claims:.4} \
             host_executor_parks_per_rt={parks:.4} service_adoptions_per_rt={services:.3} \
             carrier_cpu_ns_per_rt={cpu:.0} rt_p50_ns={:.0}",
            long.3
        );
        assert!(
            claims < 0.01 && parks < 0.01,
            "a thread blocked in a host read went through host run queues: \
             {claims:.3} claims and {parks:.3} executor parks per round trip"
        );
        assert!(
            services >= 1.0,
            "completed host reads were not served through the guest's run queues \
             ({services:.3} service adoptions per round trip)"
        );
    }
}

/// Contract `kernel.el1.guest-run-queue`, two live processes sharing vCPUs:
/// each of a parent and its forked child runs a futex ping-pong between two
/// threads pinned to guest CPUs 0 and 1, so both processes' threads hand off
/// on the same two vCPUs at once. Both processes must complete every round
/// trip (the child's exit status reaches the parent's `waitpid`), and every
/// handoff is an in-guest wake. The host exits per round trip over the
/// difference of a long and a short run are reported: EL1 does not switch
/// address spaces (plan 1d leaves that open), so a vCPU that turns from one
/// process's thread to the other's goes through its executor, and this
/// number is the baseline an in-guest address-space switch must remove. It
/// is bounded so a regression to host scheduling fails.
#[test]
fn el1_sched_two_processes_share_vcpus() {
    const SHORT: u64 = 500;
    const LONG: u64 = 3_000;
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let mut runs = Vec::new();
    for iters in [SHORT, LONG, SHORT, LONG] {
        let measured = run_fixture(
            &carrier,
            &["two-process", &iters.to_string()],
            Duration::from_secs(120),
        );
        let stdout = measured.result.stdout_utf8();
        println!(
            "el1-sched two-process iters={iters} exits={} carrier_cpu_ns={} wall_ms={} zone={:?} {}",
            measured.exits,
            measured.cpu_ns,
            measured.wall.as_millis(),
            measured.zone,
            stdout.trim()
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        assert!(
            stdout.contains(&format!("two-process child round_trips={iters} "))
                && stdout.contains(&format!("two-process parent round_trips={iters} "))
                && stdout.contains("child_ok=true"),
            "both processes must complete every round trip: {stdout:?}"
        );
        runs.push((iters, measured.exits, measured.zone, measured.cpu_ns));
    }
    let span = 2.0 * (LONG - SHORT) as f64;
    for pair in runs.chunks(2) {
        let (short, long) = (&pair[0], &pair[1]);
        let exits = (long.1 as f64 - short.1 as f64) / span;
        let per = |f: fn(&ZoneCounts) -> u64| (f(&long.2) as f64 - f(&short.2) as f64) / span;
        let cross = per(|z| z.cross_wakes);
        let services = per(|z| z.service_exits);
        let claims = per(|z| z.host_queue_claims);
        let cpu = (long.3 as f64 - short.3 as f64) / span;
        println!(
            "el1-sched two-process exits_per_rt={exits:.3} cross_wakes_per_rt={cross:.3} \
             service_exits_per_rt={services:.3} host_queue_claims_per_rt={claims:.4} \
             carrier_cpu_ns_per_rt={cpu:.0}"
        );
        assert!(
            claims < 0.01,
            "two processes' handoffs went through host run queues: {claims:.3} per round trip"
        );
        // 6.2-6.4 per round trip at 1d, where each turn of a vCPU between
        // the two address spaces went through its executor. EL1 now switches
        // TTBR0/TTBR1 itself (contract `kernel.el1.address-space-switch`), so
        // a turn costs no exit.
        assert!(
            exits < 1.0,
            "two processes sharing vCPUs cost {exits:.3} host exits per round trip"
        );
    }
}

/// Part (a) continued: a thread whose host-served `read` completes, queued
/// on a vCPU that runs a thread computing without syscalls (both pinned to
/// one guest CPU), gets that vCPU within the in-guest scheduler's slice. The
/// host cannot send the reschedule SGI; its placement forces the vCPU out and
/// the run loop raises it (with IRQs unmasked at EL0) so the slice starts.
#[test]
fn el1_sched_host_woken_thread_preempts_a_compute_loop() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    for _ in 0..3 {
        let measured = run_fixture(&carrier, &["pipe-compute", "300"], Duration::from_secs(60));
        let stdout = measured.result.stdout_utf8();
        println!(
            "el1-sched pipe-compute exits={} zone={:?} {}",
            measured.exits,
            measured.zone,
            stdout.trim()
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        let first = field(&stdout, "b_first_ms");
        assert!(
            (0.0..100.0).contains(&first),
            "the woken thread waited {first} ms behind a computing one"
        );
    }
}

/// Contract `kernel.mm.address-space-occupancy` (EL1 increment 2, first-touch checkpoint):
/// two live processes, each running twice as many writer threads as guest
/// CPUs (pairs handing a turn off through private futexes, so EL1 switches
/// them on shared vCPUs, each writing and reading back its own page), an
/// editor churning `mmap`/`mprotect`/`madvise`/`munmap` (stage-1 pauses of
/// its MM, which must drain every vCPU running it), and a forker that forks
/// while the writers run (fork's COW pause must drain every writer's vCPU:
/// a vCPU it missed keeps a writable translation, and the child would see
/// the parent's later writes) and vforks (a second process on the same MM).
/// Every page reads back what its writer wrote, every fork child sees a
/// stable snapshot, and every child exits 0.
#[test]
fn el1_sched_mm_occupancy_two_processes() {
    const FORKS: u64 = 150;
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let measured = run_fixture(
        &carrier,
        &["mm-occupancy", &FORKS.to_string()],
        Duration::from_secs(240),
    );
    let stdout = measured.result.stdout_utf8();
    println!(
        "el1-sched mm-occupancy exits={} carrier_cpu_ns={} wall_ms={} zone={:?} {}",
        measured.exits,
        measured.cpu_ns,
        measured.wall.as_millis(),
        measured.zone,
        stdout.trim()
    );
    assert!(measured.result.success(), "{}", describe(&measured));
    let report = validate_mm_occupancy_stdout(&stdout, FORKS).expect("valid mm-occupancy report");
    assert!(report.child_ok, "child process failed: {report:?}");
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MmOccupancyRoleReport {
    role: String,
    writers: usize,
    forks: u64,
    edits: u64,
    edit_failures: u64,
    edit_errors: String,
    torn: u64,
    snapshot_changes: u64,
    child_failures: u64,
    join_failures: u64,
    ok: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MmOccupancyReport {
    parent: MmOccupancyRoleReport,
    child: MmOccupancyRoleReport,
    child_ok: bool,
}

fn parse_role_line(
    line: &str,
    expected_role: &str,
    expected_forks: u64,
) -> Result<MmOccupancyRoleReport, String> {
    let mut tokens = line.split_whitespace();
    let prefix = tokens.next().ok_or_else(|| "empty line".to_string())?;
    if prefix != "mm-occupancy" {
        return Err(format!("expected 'mm-occupancy' prefix, got '{prefix}'"));
    }
    let role = tokens
        .next()
        .ok_or_else(|| "missing role token".to_string())?;
    if role != expected_role {
        return Err(format!("expected role '{expected_role}', got '{role}'"));
    }

    let mut writers = None;
    let mut forks = None;
    let mut edits = None;
    let mut edit_failures = None;
    let mut edit_errors = None;
    let mut torn = None;
    let mut snapshot_changes = None;
    let mut child_failures = None;
    let mut join_failures = None;
    let mut ok = None;

    for token in tokens {
        let (key, value) = token
            .split_once('=')
            .ok_or_else(|| format!("invalid key-value token: '{token}'"))?;
        match key {
            "writers" => {
                let v = value
                    .parse::<usize>()
                    .map_err(|e| format!("invalid writers '{value}': {e}"))?;
                if writers.is_some() {
                    return Err("duplicate writers key".to_string());
                }
                writers = Some(v);
            }
            "forks" => {
                let v = value
                    .parse::<u64>()
                    .map_err(|e| format!("invalid forks '{value}': {e}"))?;
                if forks.is_some() {
                    return Err("duplicate forks key".to_string());
                }
                forks = Some(v);
            }
            "edits" => {
                let v = value
                    .parse::<u64>()
                    .map_err(|e| format!("invalid edits '{value}': {e}"))?;
                if edits.is_some() {
                    return Err("duplicate edits key".to_string());
                }
                edits = Some(v);
            }
            "edit_failures" => {
                let v = value
                    .parse::<u64>()
                    .map_err(|e| format!("invalid edit_failures '{value}': {e}"))?;
                if edit_failures.is_some() {
                    return Err("duplicate edit_failures key".to_string());
                }
                edit_failures = Some(v);
            }
            "edit_errors" => {
                if edit_errors.is_some() || value.is_empty() {
                    return Err("duplicate or empty edit_errors key".to_string());
                }
                edit_errors = Some(value.to_string());
            }
            "torn" => {
                let v = value
                    .parse::<u64>()
                    .map_err(|e| format!("invalid torn '{value}': {e}"))?;
                if torn.is_some() {
                    return Err("duplicate torn key".to_string());
                }
                torn = Some(v);
            }
            "snapshot_changes" => {
                let v = value
                    .parse::<u64>()
                    .map_err(|e| format!("invalid snapshot_changes '{value}': {e}"))?;
                if snapshot_changes.is_some() {
                    return Err("duplicate snapshot_changes key".to_string());
                }
                snapshot_changes = Some(v);
            }
            "child_failures" => {
                let v = value
                    .parse::<u64>()
                    .map_err(|e| format!("invalid child_failures '{value}': {e}"))?;
                if child_failures.is_some() {
                    return Err("duplicate child_failures key".to_string());
                }
                child_failures = Some(v);
            }
            "join_failures" => {
                let v = value
                    .parse::<u64>()
                    .map_err(|e| format!("invalid join_failures '{value}': {e}"))?;
                if join_failures.is_some() {
                    return Err("duplicate join_failures key".to_string());
                }
                join_failures = Some(v);
            }
            "ok" => {
                let v = value
                    .parse::<bool>()
                    .map_err(|e| format!("invalid ok '{value}': {e}"))?;
                if ok.is_some() {
                    return Err("duplicate ok key".to_string());
                }
                ok = Some(v);
            }
            other => {
                return Err(format!("unexpected key '{other}' in line: '{line}'"));
            }
        }
    }

    let writers = writers.ok_or_else(|| "missing writers counter".to_string())?;
    let forks = forks.ok_or_else(|| "missing forks counter".to_string())?;
    let edits = edits.ok_or_else(|| "missing edits counter".to_string())?;
    let edit_failures = edit_failures.ok_or_else(|| "missing edit_failures counter".to_string())?;
    let edit_errors = edit_errors.unwrap_or_else(|| "none".to_string());
    let torn = torn.ok_or_else(|| "missing torn counter".to_string())?;
    let snapshot_changes =
        snapshot_changes.ok_or_else(|| "missing snapshot_changes counter".to_string())?;
    let child_failures =
        child_failures.ok_or_else(|| "missing child_failures counter".to_string())?;
    let join_failures = join_failures.ok_or_else(|| "missing join_failures counter".to_string())?;
    let ok = ok.ok_or_else(|| "missing ok flag".to_string())?;

    if writers < 4 || (writers % 2) != 0 {
        return Err(format!(
            "writers must be at least 4 and even, saw {writers}"
        ));
    }
    if forks != expected_forks {
        return Err(format!(
            "expected forks={expected_forks}, saw forks={forks}"
        ));
    }
    if edits == 0 {
        return Err("edits must be non-zero".to_string());
    }
    if edit_failures != 0 {
        return Err(format!(
            "edit_failures must be 0, saw {edit_failures}: {edit_errors}"
        ));
    }
    if torn != 0 {
        return Err(format!("torn must be 0, saw {torn}"));
    }
    if snapshot_changes != 0 {
        return Err(format!(
            "snapshot_changes must be 0, saw {snapshot_changes}"
        ));
    }
    if child_failures != 0 {
        return Err(format!("child_failures must be 0, saw {child_failures}"));
    }
    if join_failures != 0 {
        return Err(format!("join_failures must be 0, saw {join_failures}"));
    }
    if !ok {
        return Err("role report ok must be true".to_string());
    }

    Ok(MmOccupancyRoleReport {
        role: expected_role.to_string(),
        writers,
        forks,
        edits,
        edit_failures,
        edit_errors,
        torn,
        snapshot_changes,
        child_failures,
        join_failures,
        ok,
    })
}

fn validate_mm_occupancy_stdout(
    stdout: &str,
    expected_forks: u64,
) -> Result<MmOccupancyReport, String> {
    let parent_line = stdout
        .lines()
        .find(|line| line.starts_with("mm-occupancy parent "))
        .ok_or_else(|| "missing parent report line".to_string())?;
    let parent = parse_role_line(parent_line, "parent", expected_forks)?;

    let child_line = stdout
        .lines()
        .find(|line| line.starts_with("mm-occupancy child "))
        .ok_or_else(|| "missing child report line".to_string())?;
    let child = parse_role_line(child_line, "child", expected_forks)?;

    let child_ok_line = stdout
        .lines()
        .find(|line| line.starts_with("mm-occupancy child_ok="))
        .ok_or_else(|| "missing child_ok line".to_string())?;
    let child_ok = match child_ok_line.strip_prefix("mm-occupancy child_ok=") {
        Some("true") => true,
        Some("false") => false,
        _ => return Err(format!("invalid child_ok line: '{child_ok_line}'")),
    };
    if !child_ok {
        return Err("child_ok must be true".to_string());
    }

    Ok(MmOccupancyReport {
        parent,
        child,
        child_ok,
    })
}

#[test]
fn occupancy_report_accepts_valid_tight_report() {
    let stdout = "\
mm-occupancy parent writers=8 forks=150 edits=42 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child writers=8 forks=150 edits=45 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child_ok=true
";
    let report = validate_mm_occupancy_stdout(stdout, 150).expect("valid report must parse");
    assert_eq!(report.parent.edits, 42);
    assert_eq!(report.child.edits, 45);
    assert!(report.child_ok);
}

#[test]
fn occupancy_report_rejects_zero_edits() {
    let stdout = "\
mm-occupancy parent writers=8 forks=150 edits=0 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child writers=8 forks=150 edits=45 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child_ok=true
";
    assert!(
        validate_mm_occupancy_stdout(stdout, 150).is_err(),
        "zero parent edits must be rejected"
    );
}

#[test]
fn occupancy_report_rejects_legacy_missing_counters_transcript() {
    let stdout = "\
mm-occupancy parent writers=8 forks=150 edits=0 torn=0 snapshot_changes=0 child_failures=0 ok=true
mm-occupancy child writers=8 forks=150 edits=0 torn=0 snapshot_changes=0 child_failures=0 ok=true
mm-occupancy child_ok=true
";
    assert!(
        validate_mm_occupancy_stdout(stdout, 150).is_err(),
        "legacy unmetered transcript with missing counters must be rejected"
    );
}

#[test]
fn occupancy_report_rejects_edit_failures() {
    let stdout = "\
mm-occupancy parent writers=8 forks=150 edits=42 edit_failures=2 edit_errors=munmap:12,mprotect_ro:16 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child writers=8 forks=150 edits=45 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child_ok=true
";
    let error = validate_mm_occupancy_stdout(stdout, 150).unwrap_err();
    assert!(error.contains("munmap:12,mprotect_ro:16"), "{error}");
}

#[test]
fn occupancy_report_rejects_join_failures() {
    let stdout = "\
mm-occupancy parent writers=8 forks=150 edits=42 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=1 ok=true
mm-occupancy child writers=8 forks=150 edits=45 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child_ok=true
";
    assert!(
        validate_mm_occupancy_stdout(stdout, 150).is_err(),
        "worker join failures must be rejected"
    );
}

#[test]
fn occupancy_report_rejects_torn_writes() {
    let stdout = "\
mm-occupancy parent writers=8 forks=150 edits=42 edit_failures=0 torn=1 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child writers=8 forks=150 edits=45 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child_ok=true
";
    assert!(
        validate_mm_occupancy_stdout(stdout, 150).is_err(),
        "torn writes must be rejected"
    );
}

#[test]
fn occupancy_report_rejects_snapshot_changes() {
    let stdout = "\
mm-occupancy parent writers=8 forks=150 edits=42 edit_failures=0 torn=0 snapshot_changes=1 child_failures=0 join_failures=0 ok=true
mm-occupancy child writers=8 forks=150 edits=45 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child_ok=true
";
    assert!(
        validate_mm_occupancy_stdout(stdout, 150).is_err(),
        "snapshot changes must be rejected"
    );
}

#[test]
fn occupancy_report_rejects_child_failures() {
    let stdout = "\
mm-occupancy parent writers=8 forks=150 edits=42 edit_failures=0 torn=0 snapshot_changes=0 child_failures=1 join_failures=0 ok=true
mm-occupancy child writers=8 forks=150 edits=45 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child_ok=true
";
    assert!(
        validate_mm_occupancy_stdout(stdout, 150).is_err(),
        "child failures must be rejected"
    );
}

#[test]
fn occupancy_report_rejects_fork_count_mismatch() {
    let stdout = "\
mm-occupancy parent writers=8 forks=100 edits=42 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child writers=8 forks=150 edits=45 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child_ok=true
";
    assert!(
        validate_mm_occupancy_stdout(stdout, 150).is_err(),
        "fork count mismatch must be rejected"
    );
}

#[test]
fn occupancy_report_rejects_failed_child_ok() {
    let stdout = "\
mm-occupancy parent writers=8 forks=150 edits=42 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child writers=8 forks=150 edits=45 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child_ok=false
";
    assert!(
        validate_mm_occupancy_stdout(stdout, 150).is_err(),
        "child_ok=false must be rejected"
    );
}

#[test]
fn occupancy_report_rejects_missing_child_ok() {
    let stdout = "\
mm-occupancy parent writers=8 forks=150 edits=42 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child writers=8 forks=150 edits=45 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
";
    assert!(
        validate_mm_occupancy_stdout(stdout, 150).is_err(),
        "missing child_ok line must be rejected"
    );
}

#[test]
fn occupancy_report_rejects_missing_role_line() {
    let stdout = "\
mm-occupancy parent writers=8 forks=150 edits=42 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child_ok=true
";
    assert!(
        validate_mm_occupancy_stdout(stdout, 150).is_err(),
        "missing child role line must be rejected"
    );
}

#[test]
fn occupancy_report_rejects_malformed_counter_values() {
    let stdout = "\
mm-occupancy parent writers=8 forks=150 edits=invalid edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child writers=8 forks=150 edits=45 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child_ok=true
";
    assert!(
        validate_mm_occupancy_stdout(stdout, 150).is_err(),
        "malformed counter values must be rejected"
    );
}

#[test]
fn occupancy_report_rejects_spurious_ok_substring() {
    let stdout = "\
mm-occupancy parent writers=8 forks=150 edits=42 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=false fake=ok=true
mm-occupancy child writers=8 forks=150 edits=45 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child_ok=true
";
    assert!(
        validate_mm_occupancy_stdout(stdout, 150).is_err(),
        "spurious ok substring with ok=false must be rejected"
    );
}

#[test]
fn occupancy_report_rejects_odd_writers() {
    let stdout = "\
mm-occupancy parent writers=7 forks=150 edits=42 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child writers=8 forks=150 edits=45 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child_ok=true
";
    assert!(
        validate_mm_occupancy_stdout(stdout, 150).is_err(),
        "odd writer counts must be rejected"
    );
}

#[test]
fn occupancy_report_rejects_insufficient_writers() {
    let stdout = "\
mm-occupancy parent writers=2 forks=150 edits=42 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child writers=8 forks=150 edits=45 edit_failures=0 torn=0 snapshot_changes=0 child_failures=0 join_failures=0 ok=true
mm-occupancy child_ok=true
";
    assert!(
        validate_mm_occupancy_stdout(stdout, 150).is_err(),
        "writer counts below four must be rejected"
    );
}

/// Contract `kernel.el1.anonymous-first-touch` (EL1 increment 2, first-touch checkpoint):
/// two live fork-related processes freshly touch private anonymous memory at the
/// same inherited virtual range across 256, 1024, and 4096 pages per process.
///
/// Semantics: each process verifies initial zero-fill, writes distinct role values,
/// reads them back, and verifies they remain intact after both processes have written.
///
/// Structural invariant: anonymous first-touch faults must be serviced in guest EL1
/// without per-page host fault service exits. The measured incremental host-exit slope
/// across scales must be < 0.125 exits per added page (both processes count).
///
/// This witness is expected to be red while faults are serviced by the host.
/// Only a recorded signed run establishes the measured failure.
#[test]
fn el1_memory_first_touch_stays_in_guest() {
    const SCALES: [u64; 3] = [256, 1024, 4096];
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let mut runs = Vec::new();
    for pages in SCALES {
        let measured = run_fixture(
            &carrier,
            &["first-touch", &pages.to_string()],
            Duration::from_secs(120),
        );
        let stdout = measured.result.stdout_utf8();
        println!(
            "el1-sched first-touch pages={pages} exits={} carrier_cpu_ns={} wall_ms={} zone={:?} {}",
            measured.exits,
            measured.cpu_ns,
            measured.wall.as_millis(),
            measured.zone,
            stdout.trim()
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        assert!(
            stdout.contains(&format!("first-touch child pages={pages} ok=true"))
                && stdout.contains(&format!(
                    "first-touch parent pages={pages} child_ok=true ok=true"
                )),
            "both processes must complete first-touch at scale {pages}: {stdout:?}"
        );
        runs.push((pages, measured.exits, measured.cpu_ns));
    }

    for pair in runs.windows(2) {
        let (p0, exits0, _cpu0) = pair[0];
        let (p1, exits1, _cpu1) = pair[1];
        let added_pages = 2.0 * (p1 as f64 - p0 as f64);
        let exit_slope = (exits1 as f64 - exits0 as f64) / added_pages;
        println!(
            "el1-sched first-touch slope {p0}->{p1} pages (added={added_pages}): \
             exits_diff={} slope={exit_slope:.4} exits/page",
            exits1 as i64 - exits0 as i64,
        );
        assert!(
            exit_slope < 0.125,
            "first-touch host-exit slope across scale {p0} -> {p1} was {exit_slope:.4} exits/page \
             (both processes count, added={added_pages}); contract ceiling is <0.125 exits per added page"
        );
    }
}

/// Contract `kernel.el1.anonymous-retirement` (EL1 increment 2): repeated
/// same-VA anonymous replacement must remain zero-filled, return every exact
/// EL1 frame-grant lease, physically reuse a returned lease, and keep host
/// exits sublinear in the number of guest pages.
#[test]
fn el1_anonymous_mapping_retirement_returns_and_reuses_frames() {
    const SCALES: [u64; 3] = [256, 1024, 4096];
    const ROUNDS: u64 = 4;
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let mut runs = Vec::new();

    for pages in SCALES {
        let before = carrick_embed::el1_frame_grant_stats();
        let counters_before = read_el1_counters().map_or((0, 0), |counters| {
            (
                counters.served[215].load(std::sync::atomic::Ordering::Relaxed),
                counters.forwarded[215].load(std::sync::atomic::Ordering::Relaxed),
            )
        });
        let measured = run_fixture(
            &carrier,
            &[
                "mapping-retirement",
                &pages.to_string(),
                &ROUNDS.to_string(),
            ],
            Duration::from_secs(120),
        );
        let after = carrick_embed::el1_frame_grant_stats();
        let counters_after = read_el1_counters().map_or((0, 0), |counters| {
            (
                counters.served[215].load(std::sync::atomic::Ordering::Relaxed),
                counters.forwarded[215].load(std::sync::atomic::Ordering::Relaxed),
            )
        });
        let served_munmap = counters_after.0 - counters_before.0;
        let forwarded_munmap = counters_after.1 - counters_before.1;
        let grants = after.grants_succeeded - before.grants_succeeded;
        let returns = after.returns_completed - before.returns_completed;
        let reused = after.reused_grants - before.reused_grants;
        let bytes_granted = after.bytes_granted - before.bytes_granted;
        let bytes_returned = after.bytes_returned - before.bytes_returned;
        let stdout = measured.result.stdout_utf8();
        println!(
            "el1-sched mapping-retirement pages={pages} rounds={ROUNDS} exits={} served_munmap={served_munmap} forwarded_munmap={forwarded_munmap} grants={grants} returns={returns} reused={reused} bytes_granted={bytes_granted} bytes_returned={bytes_returned} {}",
            measured.exits,
            stdout.trim(),
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        assert!(
            stdout.contains(&format!("mapping-retirement pages={pages} rounds={ROUNDS}"))
                && stdout.contains("zero=true writes=true unmaps=true"),
            "signed fixture did not prove same-VA replacement semantics: {stdout:?}"
        );
        assert!(grants > 0, "workload published no EL1 frame grants");
        assert_eq!(returns, grants, "every exact EL1 grant must return");
        assert_eq!(
            bytes_returned, bytes_granted,
            "every granted physical byte must return"
        );
        assert!(reused > 0, "repeated mapping never reused a returned IPA");
        assert_eq!(
            served_munmap,
            ROUNDS + 1,
            "EL1 must retire every target munmap plus the fixed eligible runtime cleanup"
        );
        assert_eq!(
            forwarded_munmap, 1,
            "only the fixed untagged runtime cleanup may forward"
        );
        runs.push((pages, measured.exits));
    }

    for pair in runs.windows(2) {
        let (p0, exits0) = pair[0];
        let (p1, exits1) = pair[1];
        let added_pages = ROUNDS as f64 * (p1 - p0) as f64;
        let exit_slope = (exits1 as f64 - exits0 as f64) / added_pages;
        println!(
            "el1-sched mapping-retirement slope {p0}->{p1} pages rounds={ROUNDS}: exits_diff={} slope={exit_slope:.4} exits/page/round",
            exits1 as i64 - exits0 as i64,
        );
        assert!(
            exit_slope < 0.125,
            "mapping-retirement host-exit slope {exit_slope:.4} exceeds <0.125 exits per added page per round"
        );
    }
}

#[derive(Debug, Clone, Copy)]
struct PermissionRun {
    pages: u64,
    rounds: u64,
    exits: u64,
    served_mprotect: u64,
    forwarded_mprotect: u64,
    faults: u64,
    grants: u64,
    returns: u64,
    bytes_granted: u64,
    bytes_returned: u64,
}

fn permission_counter_snapshot() -> (u64, u64, u64) {
    read_el1_counters().map_or((0, 0, 0), |counters| {
        (
            counters.served[226].load(std::sync::atomic::Ordering::Relaxed),
            counters.forwarded[226].load(std::sync::atomic::Ordering::Relaxed),
            counters
                .fault_taken
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    })
}

/// Contract `kernel.el1.anonymous-permissions` (EL1 increment 2): resident
/// anonymous `mprotect` transitions are served by EL1, preserve contents, and
/// deny disallowed reads/writes with Linux `SEGV_ACCERR`. Pure permission edits
/// neither churn frame grants nor grow host exits with the number of pages.
#[test]
fn el1_anonymous_permission_transitions_stay_in_guest() {
    const SCALE_ROUNDS: u64 = 4;
    const SCALES: [u64; 3] = [256, 1024, 4096];
    const ROUND_PAIR: [u64; 2] = [2, 18];
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let mut runs = Vec::new();

    for (pages, rounds) in SCALES
        .into_iter()
        .map(|pages| (pages, SCALE_ROUNDS))
        .chain(ROUND_PAIR.into_iter().map(|rounds| (256, rounds)))
    {
        let counters_before = permission_counter_snapshot();
        let grants_before = carrick_embed::el1_frame_grant_stats();
        let measured = run_fixture(
            &carrier,
            &[
                "permission-transitions",
                &pages.to_string(),
                &rounds.to_string(),
            ],
            Duration::from_secs(120),
        );
        let grants_after = carrick_embed::el1_frame_grant_stats();
        let counters_after = permission_counter_snapshot();
        let stdout = measured.result.stdout_utf8();
        let run = PermissionRun {
            pages,
            rounds,
            exits: measured.exits,
            served_mprotect: counters_after.0 - counters_before.0,
            forwarded_mprotect: counters_after.1 - counters_before.1,
            faults: counters_after.2 - counters_before.2,
            grants: grants_after.grants_succeeded - grants_before.grants_succeeded,
            returns: grants_after.returns_completed - grants_before.returns_completed,
            bytes_granted: grants_after.bytes_granted - grants_before.bytes_granted,
            bytes_returned: grants_after.bytes_returned - grants_before.bytes_returned,
        };
        println!(
            "el1-sched permission-transitions pages={pages} rounds={rounds} exits={} served_mprotect={} forwarded_mprotect={} faults={} grants={} returns={} bytes_granted={} bytes_returned={} {}",
            run.exits,
            run.served_mprotect,
            run.forwarded_mprotect,
            run.faults,
            run.grants,
            run.returns,
            run.bytes_granted,
            run.bytes_returned,
            stdout.trim(),
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        assert!(
            stdout.contains(&format!(
                "permission-transitions pages={pages} rounds={rounds}"
            )) && stdout.contains(&format!(
                "write_faults={rounds} read_faults={rounds} signal_errors=0 transition_failures=0 byte_failures=0 preserved=true segv_accerr=true unmap=true"
            )),
            "permission transition semantics were not complete: {stdout:?}"
        );
        assert_eq!(run.returns, run.grants, "every initial grant must return");
        assert_eq!(
            run.bytes_returned, run.bytes_granted,
            "every initially granted byte must return"
        );
        runs.push(run);
    }

    for run in &runs {
        assert_eq!(
            run.served_mprotect,
            4 * run.rounds,
            "EL1 must serve every protection transition: {run:?}"
        );
        assert_eq!(
            run.forwarded_mprotect, 1,
            "only the process signal-stack guard may cross the host boundary: {run:?}"
        );
        assert!(
            run.faults >= 2 * run.rounds,
            "both denied accesses must enter EL1: {run:?}"
        );
    }

    for pair in runs[..SCALES.len()].windows(2) {
        let added_pages = SCALE_ROUNDS as f64 * (pair[1].pages - pair[0].pages) as f64;
        let slope = (pair[1].exits as f64 - pair[0].exits as f64) / added_pages;
        println!(
            "el1-sched permission-transitions page-slope {}->{} rounds={SCALE_ROUNDS}: exits_diff={} slope={slope:.4} exits/page/round",
            pair[0].pages,
            pair[1].pages,
            pair[1].exits as i64 - pair[0].exits as i64,
        );
        assert!(
            slope < 0.125,
            "permission-transition host-exit slope {slope:.4} exceeds <0.125 exits per added page per round"
        );
    }

    let short = runs[SCALES.len()];
    let long = runs[SCALES.len() + 1];
    let exit_slope = (long.exits as f64 - short.exits as f64) / (long.rounds - short.rounds) as f64;
    println!(
        "el1-sched permission-transitions round-slope pages={} {}->{}: exits_diff={} slope={exit_slope:.4} exits/round",
        short.pages,
        short.rounds,
        long.rounds,
        long.exits as i64 - short.exits as i64,
    );
    assert!(
        exit_slope < 4.5,
        "permission-transition host-exit slope {exit_slope:.4} exceeds the two denied-signal cycles plus noise per round"
    );
    assert_eq!(
        long.grants, short.grants,
        "additional pure permission rounds must not allocate frame grants"
    );
    assert_eq!(
        long.bytes_granted, short.bytes_granted,
        "additional pure permission rounds must not allocate frame bytes"
    );
}

/// EL1 data-abort entry verification: a stage-1 permission fault in guest user code
/// enters the EL1 vector image, increments EL1 fault_taken counter, restores complete
/// architectural context and forwards through host fault handling to guest SIGSEGV.
/// After the signal handler upgrades permissions with mprotect, store retry succeeds
/// and all registers (including arbitrary x8, x16/x17, GPRs) and SP are preserved.
#[test]
fn el1_memory_fault_entry_preserves_context() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    assert!(
        read_el1_counters().is_none(),
        "reset_el1_counters must clear any stale snapshot before carrier execution"
    );
    let carrier = carrier_or_fail();
    let measured = run_fixture(&carrier, &["fault-entry"], Duration::from_secs(30));
    assert!(measured.result.success(), "{}", describe(&measured));
    let stdout = measured.result.stdout_utf8();
    assert!(
        stdout.contains("fault-entry ok"),
        "fixture fault-entry must succeed and preserve context: {stdout:?}"
    );

    let el1_active = std::env::var("CARRICK_EL1").as_deref() != Ok("0");
    if el1_active {
        let counters =
            read_el1_counters().expect("EL1 counters must be populated when EL1 is enabled");
        let faults = counters
            .fault_taken
            .load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            faults >= 1,
            "expected at least 1 EL1 fault entry in live carrier counters under EL1 enabled, got {faults}"
        );
    } else {
        let faults = read_el1_counters()
            .map(|c| c.fault_taken.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(0);
        assert_eq!(
            faults, 0,
            "disabled EL1 control (CARRICK_EL1=0) must report 0 EL1 fault entries, got {faults}"
        );
    }
}

/// EL1 elastic metadata allocator verification: executes the real in-guest
/// allocator and actual asynchronous host extent grant/return transport,
/// forces dynamic growth beyond the bootstrap arena, verifies memory integrity
/// and reuse, checks host grant and return counters, and exercises simulated
/// host grant refusal followed by successful retry recovery.
#[test]
fn el1_metadata_allocator_grows_and_returns_extents() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    carrick_runtime::reset_metadata_grant_state();
    assert!(
        read_el1_counters().is_none(),
        "reset_el1_counters must clear any stale snapshot before carrier execution"
    );

    let carrier = carrier_or_fail();

    // Phase 1: Basic allocations, arbitrary alignments (16..4096), payload pattern verification
    let measured_basic = run_fixture(
        &carrier,
        &["metadata-allocator", "basic"],
        Duration::from_secs(30),
    );
    assert!(
        measured_basic.result.success(),
        "{}",
        describe(&measured_basic)
    );
    let stdout_basic = measured_basic.result.stdout_utf8();
    assert!(
        stdout_basic.contains("metadata-allocator basic ok"),
        "fixture metadata-allocator basic must succeed: {stdout_basic:?}"
    );

    // Phase 2: Force dynamic growth crossing 9 MiB bootstrap into dynamic extents (allocating 10 MiB)
    let measured_growth = run_fixture(
        &carrier,
        &["metadata-allocator", "growth"],
        Duration::from_secs(30),
    );
    assert!(
        measured_growth.result.success(),
        "{}",
        describe(&measured_growth)
    );
    let stdout_growth = measured_growth.result.stdout_utf8();
    assert!(
        stdout_growth.contains("metadata-allocator growth ok"),
        "fixture metadata-allocator growth must succeed: {stdout_growth:?}"
    );

    let stats_growth = carrick_runtime::metadata_grant_stats();
    println!("metadata_grant_stats after growth: {stats_growth:?}");
    assert!(
        stats_growth.grants_succeeded >= 1,
        "expected at least 1 dynamic extent granted by host, got {}",
        stats_growth.grants_succeeded
    );
    assert!(
        stats_growth.returns_completed >= 1,
        "expected at least 1 dynamic extent returned to host, got {}",
        stats_growth.returns_completed
    );
    assert_eq!(
        stats_growth.bytes_granted, stats_growth.bytes_returned,
        "all granted dynamic bytes must be completely returned to host upon deallocation"
    );

    // Phase 3: Arm host grant denial failpoint, verify data preservation, and recovery retry
    carrick_runtime::arm_deny_next_metadata_grant();
    let measured_denial = run_fixture(
        &carrier,
        &["metadata-allocator", "denial"],
        Duration::from_secs(30),
    );
    assert!(
        measured_denial.result.success(),
        "{}",
        describe(&measured_denial)
    );
    let stdout_denial = measured_denial.result.stdout_utf8();
    assert!(
        stdout_denial.contains("metadata-allocator denial ok"),
        "fixture metadata-allocator denial must succeed: {stdout_denial:?}"
    );

    let stats_total = carrick_runtime::metadata_grant_stats();
    println!("metadata_grant_stats final: {stats_total:?}");
    assert!(
        stats_total.grants_denied >= 1,
        "expected at least 1 grant denial from armed failpoint, got {}",
        stats_total.grants_denied
    );
    assert_eq!(
        stats_total.bytes_granted, stats_total.bytes_returned,
        "all granted dynamic bytes across all phases must be completely returned to host"
    );
}

/// Concurrent users of the actual guest allocator must complete with unrelated
/// host service work, return every dynamic byte, and stay within the watchdog.
#[test]
fn el1_metadata_allocator_concurrent_growth() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    carrick_runtime::reset_metadata_grant_state();
    let carrier = carrier_or_fail();
    let measured = run_fixture(
        &carrier,
        &["metadata-allocator", "concurrent"],
        Duration::from_secs(30),
    );
    assert!(measured.result.success(), "{}", describe(&measured));
    assert!(
        measured
            .result
            .stdout_utf8()
            .contains("workers=4 rounds=16 failures=0 host_calls=1024 host_failures=0"),
        "{}",
        describe(&measured)
    );
    let stats = carrick_runtime::metadata_grant_stats();
    assert!(stats.grants_succeeded > 0, "no dynamic growth: {stats:?}");
    assert_eq!(
        stats.grants_denied, 0,
        "unexpected capacity refusal: {stats:?}"
    );
    assert_eq!(stats.grants_succeeded, stats.returns_completed, "{stats:?}");
    assert_eq!(stats.bytes_granted, stats.bytes_returned, "{stats:?}");
    let counters = read_el1_counters().expect("EL1 counters after guest");
    assert!(
        counters.forwarded[160].load(std::sync::atomic::Ordering::Relaxed) >= 1024,
        "uname must execute through host service, not just a guest fast path"
    );
}

/// Sample live DAIF immediately before real guest metadata grant/return HVCs.
/// Growth completion alone cannot prove the no-host-wait-while-masked contract.
#[test]
fn el1_metadata_allocator_host_wait_requires_unmasked_irq() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    carrick_runtime::reset_metadata_grant_state();
    let carrier = carrier_or_fail();
    let measured = run_fixture(
        &carrier,
        &["metadata-allocator", "irq"],
        Duration::from_secs(30),
    );
    let stats = carrick_runtime::metadata_grant_stats();
    assert!(
        stats.grants_succeeded > 0,
        "must exercise real growth: {stats:?}"
    );
    assert!(
        stats.returns_completed > 0,
        "must exercise real return: {stats:?}"
    );
    assert_eq!(
        stats.inline_hvc_traps, 0,
        "metadata growth/return must unwind through pending host work, not synchronously trap from masked EL1: {stats:?}"
    );
    assert!(
        measured.result.success(),
        "metadata host waits must enter with DAIF.I clear; fixture rc counts masked waits: {}",
        describe(&measured)
    );
    assert!(
        measured
            .result
            .stdout_utf8()
            .contains("metadata-allocator irq ok")
    );
}

/// Fork COW resolution verification: forks 100 times with private anonymous
/// pages armed read-only for COW. 4 guest threads concurrently write to the
/// pages, taking write permission faults. EL1 serves the faults in-guest by
/// upgrading descriptors to AP_RW and invalidating ASIDs without host exits.
/// Parent and child verify memory isolation and integrity.
#[test]
fn el1_fork_cow_resolves_in_guest() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let measured = run_fixture(
        &carrier,
        &["fork-cow", "100", "16"],
        Duration::from_secs(60),
    );
    assert!(measured.result.success(), "{}", describe(&measured));
    let stdout = measured.result.stdout_utf8();
    assert!(
        stdout.contains("fork-cow forks=100 pages=16 ok=true"),
        "fixture fork-cow must succeed and verify isolation: {stdout:?}"
    );

    let el1_active = std::env::var("CARRICK_EL1").as_deref() != Ok("0");
    if el1_active {
        let counters =
            read_el1_counters().expect("EL1 counters must be populated when EL1 is enabled");
        let faults = counters
            .fault_taken
            .load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            faults >= 100,
            "expected at least 100 EL1 fault entries for 100 fork-COW rounds, got {faults}"
        );
    }
}

/// Retain a real parent's notification snapshot across its guest-visible reap.
/// The marker prevents the parent from exiting before snapshot capture; the
/// auditor then delays only that notification until the root reaps the parent.
#[test]
fn el1_sched_delayed_notification_survives_parent_reap() {
    use carrick_kernel::kernel::TaskKey;
    use carrick_kernel::observe::{
        AuditVerdict, ForkKind, InterceptAction, InterceptedSyscall, KernelAuditor, ProcessInfo,
        SyscallInterceptor,
    };
    use std::sync::{Arc, Condvar, Mutex};

    #[derive(Default)]
    struct State {
        target: Option<TaskKey>,
        captured: bool,
        reaped: bool,
        timed_out: bool,
        markers: usize,
        reaped_wake_rejections: usize,
        events: Vec<&'static str>,
    }
    #[derive(Default)]
    struct Gate {
        state: Mutex<State>,
        changed: Condvar,
    }
    impl KernelAuditor for Gate {
        fn fork_admitted(&self, _parent: TaskKey, child: TaskKey, kind: ForkKind) -> AuditVerdict {
            if matches!(kind, ForkKind::Fork) {
                self.state.lock().unwrap().target.get_or_insert(child);
            }
            AuditVerdict::Continue
        }

        fn child_exit_notification_captured(&self, parent: TaskKey) -> AuditVerdict {
            let mut state = self.state.lock().unwrap();
            if state.target != Some(parent) {
                return AuditVerdict::Continue;
            }
            state.events.push("captured");
            state.captured = true;
            self.changed.notify_all();
            let (mut state, timeout) = self
                .changed
                .wait_timeout_while(state, Duration::from_secs(5), |state| !state.reaped)
                .unwrap();
            state.timed_out |= timeout.timed_out() && !state.reaped;
            state.events.push("released");
            AuditVerdict::Continue
        }

        fn wake_rejected(
            &self,
            target: TaskKey,
            reason: carrick_kernel::observe::WakeRejectionReason,
        ) -> AuditVerdict {
            let mut state = self.state.lock().unwrap();
            if state.target == Some(target)
                && reason == carrick_kernel::observe::WakeRejectionReason::Reaped
            {
                state.reaped_wake_rejections += 1;
            }
            AuditVerdict::Continue
        }

        fn reaped(&self, _parent: TaskKey, child: TaskKey) -> AuditVerdict {
            let mut state = self.state.lock().unwrap();
            if state.target == Some(child) {
                state.events.push("reaped");
                state.reaped = true;
                self.changed.notify_all();
            }
            AuditVerdict::Continue
        }
    }
    impl SyscallInterceptor for Gate {
        fn intercept(
            &self,
            _process: &ProcessInfo<'_>,
            call: &InterceptedSyscall<'_>,
        ) -> InterceptAction {
            if call.name() == "sched_yield" && call.original_args().0[0] == 0x454c314e {
                let mut state = self.state.lock().unwrap();
                state.markers += 1;
                let (mut state, timeout) = self
                    .changed
                    .wait_timeout_while(state, Duration::from_secs(5), |state| !state.captured)
                    .unwrap();
                state.timed_out |= timeout.timed_out() && !state.captured;
            }
            InterceptAction::Continue
        }
    }

    let _guard = common::guest_lock();
    let _watchdog = common::Watchdog::start(Duration::from_secs(30));
    let carrier = carrier_or_fail();
    #[cfg(feature = "conformance-metrics")]
    let scope = carrick_observability::work_meter::WorkMeter::default().new_scope();
    let gate = Arc::new(Gate::default());
    let builder = carrier
        .container(common::SMOKE_IMAGE)
        .pull_policy(PullPolicy::Missing)
        .command([FIXTURE, "delayed-parent-notification"])
        .vfs_mount("/opt/carrick", Box::new(el1_sched_vfs()))
        .auditor(gate.clone())
        .interceptor(gate.clone());
    #[cfg(feature = "conformance-metrics")]
    let builder = builder.work_scope(scope.clone());
    let result = common::run_or_fail(builder.run_blocking());
    assert!(result.success(), "{}", result.stdout_utf8());
    assert!(
        result
            .stdout_utf8()
            .contains("delayed-parent-notification reaped=1")
    );
    let state = gate.state.lock().unwrap();
    assert!(
        !state.timed_out,
        "lifecycle rendezvous timed out: {:?}",
        state.events
    );
    assert_eq!(state.markers, 1);
    assert_eq!(state.events, ["captured", "reaped", "released"]);
    assert_eq!(
        state.reaped_wake_rejections, 0,
        "delayed notification used reaped wake authority"
    );
    #[cfg(feature = "conformance-metrics")]
    {
        use carrick_conformance_contract::{
            Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
            SemanticAssertion, WorkMetric, WorkSnapshot, evaluate,
        };
        use sha2::{Digest, Sha256};
        let registry = ContractRegistry::load(&common::repo_root()).unwrap();
        let contract = registry
            .require("kernel.wait.child-exit-notification-lifecycle")
            .unwrap();
        let observation = ContractObservation {
            contract_id: ContractId::new("kernel.wait.child-exit-notification-lifecycle").unwrap(),
            layer: ExecutionLayer::EmbedStructural,
            implementation_revision: format!(
                "sha256:{:x}",
                Sha256::new()
                    .chain_update(include_bytes!("el1_sched.rs"))
                    .chain_update(include_bytes!(
                        "../../carrick-runtime/src/vcpu_loop/wait_wake.rs"
                    ))
                    .finalize()
            ),
            fixture_identity: contract.fixture.clone(),
            scale: 1,
            semantic_assertions: vec![SemanticAssertion::pass(
                "captured_reaped_released_without_stale_wake",
            )],
            work: Some(scope.snapshot().expect("complete scoped notification work")),
            timing: None,
            completeness: Completeness::Complete,
        };
        println!("{}", serde_json::to_string(&observation).unwrap());
        evaluate(contract, std::slice::from_ref(&observation)).unwrap();
        for (visits, attempts, wakes) in [(3, 2, 1), (2, 3, 1), (2, 2, 2)] {
            let mut excess = observation.clone();
            let mut work = WorkSnapshot::new();
            work.insert(WorkMetric::ChildExitNotificationThreadVisits, visits)
                .unwrap();
            work.insert(WorkMetric::ChildExitNotificationWakeAttempts, attempts)
                .unwrap();
            work.insert(WorkMetric::ChildExitNotificationWakeDeliveries, wakes)
                .unwrap();
            excess.work = Some(work);
            assert!(
                evaluate(contract, &[excess]).is_err(),
                "excess notification work escaped"
            );
        }
    }
    println!(
        "el1 delayed notification ordering={:?} markers={}",
        state.events, state.markers
    );
}

/// Feasibility witness for the deferred-capture auditor on real guest work.
/// This does not establish retirement/reuse ordering or close the contract.
#[test]
fn el1_sched_deferred_handback_capture_observes_guest_records() {
    use carrick_kernel::observe::{AuditVerdict, KernelAuditor};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Capture {
        records: Mutex<Vec<carrick_el1_abi::RecordRef>>,
    }
    impl KernelAuditor for Capture {
        fn zone_handbacks_captured(&self, records: &[carrick_el1_abi::RecordRef]) -> AuditVerdict {
            self.records.lock().unwrap().extend_from_slice(records);
            AuditVerdict::Continue
        }
    }

    let _guard = common::guest_lock();
    let _watchdog = common::Watchdog::start(Duration::from_secs(30));
    let carrier = carrier_or_fail();
    let capture = Arc::new(Capture::default());
    let result = common::run_or_fail(
        carrier
            .container(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([FIXTURE, "two-process", "200"])
            .vfs_mount("/opt/carrick", Box::new(el1_sched_vfs()))
            .auditor(capture.clone())
            .run_blocking(),
    );
    assert!(result.success(), "{}", result.stdout_utf8());
    assert!(result.stdout_utf8().contains("child_ok=true"));
    let records = capture.records.lock().unwrap();
    println!("deferred handback real guest captures: {records:?}");
    assert!(
        !records.is_empty(),
        "guest workload did not exercise the deferred capture boundary"
    );
}
