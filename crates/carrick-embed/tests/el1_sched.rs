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
    Carrier, ContainerResult, EmbedError, InMemoryFileVfs, PullPolicy, hvpatch_task_loads_total,
    read_el1_counters, reset_el1_counters, vcpu_hvc_not_svc_reasons, vcpu_hvc_not_svc_total,
    vcpu_run_exit_classes, vcpu_run_exits_total,
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
    /// Pipe/eventfd calls EL1 left for the host, by `IpcLeave` index.
    ipc_leaves: [u64; carrick_el1_abi::IpcLeave::COUNT],
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
    let ipc_leaves_before = read_el1_counters()
        .map_or([0; carrick_el1_abi::IpcLeave::COUNT], |c| {
            std::array::from_fn(|i| c.ipc_leaves[i].load(std::sync::atomic::Ordering::Relaxed))
        });
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
    let ipc_leaves = read_el1_counters().map_or([0; carrick_el1_abi::IpcLeave::COUNT], |c| {
        std::array::from_fn(|i| {
            c.ipc_leaves[i]
                .load(std::sync::atomic::Ordering::Relaxed)
                .saturating_sub(ipc_leaves_before[i])
        })
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
        ipc_leaves,
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

/// Nonzero `IpcLeave` counts, as `(reason, count)`.
fn ipc_leaves_breakdown(measured: &Measured) -> Vec<(&'static str, u64)> {
    use carrick_el1_abi::IpcLeave as L;
    [
        (L::NoTable, "no_table"),
        (L::TableContended, "table_contended"),
        (L::TableRefused, "table_refused"),
        (L::PinContended, "pin_contended"),
        (L::PinRefused, "pin_refused"),
        (L::NoOperationRecord, "no_operation_record"),
        (L::CopyInFault, "copy_in_fault"),
        (L::StaleOperation, "stale_operation"),
        (L::ForeignOperation, "foreign_operation"),
        (L::FlagsRefused, "flags_refused"),
        (L::ObjectBusy, "object_busy"),
        (L::ObjectBusyHost, "object_busy_host"),
        (L::ObjectBusyEl1, "object_busy_el1"),
        (L::TransferRefused, "transfer_refused"),
        (L::ParkRefused, "park_refused"),
        (L::BrokenFirst, "broken_first"),
        (L::FaultFirst, "fault_first"),
        (L::SigpipeHandback, "sigpipe_handback"),
        (L::Restart, "restart"),
        (L::EpollSigmask, "epoll_sigmask"),
        (L::EpollHostItems, "epoll_host_items"),
        (L::EpollTimedWait, "epoll_timed_wait"),
        (L::EpollCopyOut, "epoll_copy_out"),
    ]
    .into_iter()
    .filter_map(|(reason, name)| {
        let count = measured.ipc_leaves[reason as usize];
        (count != 0).then_some((name, count))
    })
    .collect()
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

/// Host vector I/O and guest scalar I/O mutate the same pipe/eventfd state.
#[test]
fn el1_ipc_mixed_venue_roundtrips() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    for kind in ["pipe", "eventfd"] {
        let measured = run_fixture(&carrier, &["ipc-mixed", kind], Duration::from_secs(60));
        println!(
            "IPC mixed {kind} zone={:?} forwarded={:?} {}",
            measured.zone,
            measured.forwarded_syscalls,
            describe(&measured)
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        assert_eq!(
            measured.result.stdout_utf8().trim(),
            format!("ipc-mixed kind={kind} completed=128")
        );
        for nr in [65, 66] {
            let count = measured
                .forwarded_syscalls
                .iter()
                .find(|(n, _)| *n == nr)
                .map_or(0, |(_, count)| *count);
            assert!(
                count >= 128,
                "host vector operations missing: {:?}",
                measured.forwarded_syscalls
            );
        }
        assert!(
            measured.zone.el1_parks >= 64,
            "guest blocking missing: {:?}",
            measured.zone
        );
    }
}

/// Independent inherited-table replacement and final-close qualification.
#[test]
fn el1_ipc_inherited_descriptor_lifetime() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let measured = run_fixture(&carrier, &["ipc-lifetime"], Duration::from_secs(60));
    println!(
        "IPC lifetime zone={:?} forwarded={:?} {}",
        measured.zone,
        measured.forwarded_syscalls,
        describe(&measured)
    );
    assert!(measured.result.success(), "{}", describe(&measured));
    assert_eq!(
        measured.result.stdout_utf8().trim(),
        "ipc-lifetime completed=128 reused=1 eof=1 child_exit=0"
    );
    assert!(measured.zone.el1_parks >= 128, "{:?}", measured.zone);
}

/// Concurrent production pipe/eventfd pairs. Whole-run counters establish
/// repeated guest blocking; exact scoped work/exit acceptance remains separate.
#[test]
fn el1_ipc_pairs_blocking() {
    ipc_blocking_population("ipc-pairs");
}

#[test]
fn el1_ipc_two_processes_blocking() {
    ipc_blocking_population("ipc-processes");
}

fn ipc_blocking_population(mode: &str) {
    const ROUNDS: u64 = 128;
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let mut failures = Vec::new();
    for kind in ["pipe", "eventfd"] {
        for pairs in [1u64, 8, 64] {
            let before = read_el1_counters()
                .map(|c| [63, 64].map(|nr| c.served[nr].load(std::sync::atomic::Ordering::Relaxed)))
                .unwrap_or([0; 2]);
            let measured = run_fixture(
                &carrier,
                &[mode, kind, &pairs.to_string(), &ROUNDS.to_string()],
                Duration::from_secs(60),
            );
            println!(
                "IPC pairs {kind} n={pairs}: zone={:?} forwarded={:?} ipc_leaves={:?} host_work={} exits={} el1_reasons={} {}",
                measured.zone,
                measured.forwarded_syscalls,
                ipc_leaves_breakdown(&measured),
                host_work_breakdown(&measured),
                exit_breakdown(&measured),
                el1_reason_breakdown(&measured),
                describe(&measured)
            );
            assert!(measured.result.success(), "{}", describe(&measured));
            assert!(
                measured
                    .result
                    .stdout_utf8()
                    .contains(&format!("completed={}", pairs * ROUNDS))
            );
            let counters = read_el1_counters().expect("real EL1 counters");
            let served =
                [63, 64].map(|nr| counters.served[nr].load(std::sync::atomic::Ordering::Relaxed));
            println!("IPC pairs {kind} n={pairs} served before={before:?} after={served:?}");
            if served[0] - before[0] < 2 * pairs * ROUNDS
                || served[1] - before[1] < 2 * pairs * ROUNDS
            {
                failures.push(format!(
                    "{kind} n={pairs}: IPC fell back; served before={before:?} after={served:?}"
                ));
            }
            if measured.zone.el1_parks < pairs * ROUNDS {
                failures.push(format!(
                    "{kind} n={pairs}: insufficient IPC parks {:?}",
                    measured.zone
                ));
            }
            let reads = measured
                .forwarded_syscalls
                .iter()
                .find(|(nr, _)| *nr == 63)
                .map_or(0, |(_, n)| *n);
            if reads >= pairs * ROUNDS {
                failures.push(format!(
                    "{kind} n={pairs}: read continuations fell back: {reads}"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Production IPC continuation witness using the existing two-pipe fixture.
/// Its only repeated blocking operations are pipe reads; thread startup and
/// join cannot account for a park population proportional to the loop.
#[test]
fn el1_ipc_pipe_blocking_roundtrips() {
    const ROUNDS: usize = 256;
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let measured = run_fixture(
        &carrier,
        &["pipe-pingpong", &ROUNDS.to_string()],
        Duration::from_secs(60),
    );
    println!(
        "IPC blocking whole-run observation: {}",
        describe(&measured)
    );
    assert!(measured.result.success(), "{}", describe(&measured));
    assert!(
        measured
            .result
            .stdout_utf8()
            .contains("pipe-pingpong iters=256")
    );
    let counters = read_el1_counters().expect("real EL1 counters");
    let reads = counters.served[63].load(std::sync::atomic::Ordering::Relaxed);
    let writes = counters.served[64].load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        reads >= 2 * ROUNDS as u64 && writes >= 2 * ROUNDS as u64,
        "IPC must execute in EL1: served reads={reads} writes={writes}"
    );
    assert!(
        measured.zone.el1_parks >= ROUNDS as u64,
        "pipe reads must park in EL1: {:?}",
        measured.zone
    );
    let forwarded_reads = measured
        .forwarded_syscalls
        .iter()
        .find(|(nr, _)| *nr == 63)
        .map_or(0, |(_, n)| *n);
    assert!(
        forwarded_reads < ROUNDS as u64,
        "read continuation fell back on every round: {forwarded_reads}"
    );
}

/// Per-round-trip host-scheduling rates of `mode` over the difference of a
/// long and a short run (two pairs, interleaved).
struct PingPongRates {
    claims: f64,
    parks: f64,
    services: f64,
    handbacks: f64,
}

fn pingpong_rates(mode: &str) -> Vec<PingPongRates> {
    const SHORT: u64 = 1_000;
    const LONG: u64 = 6_000;
    let carrier = carrier_or_fail();
    let mut runs = Vec::new();
    for iters in [SHORT, LONG, SHORT, LONG] {
        let measured = run_fixture(
            &carrier,
            &[mode, &iters.to_string()],
            Duration::from_secs(120),
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        let stdout = measured.result.stdout_utf8();
        assert!(
            stdout.contains(&format!("{mode} iters={iters}")),
            "{mode} did not complete: {stdout}"
        );
        println!(
            "el1-sched {mode} iters={iters} exits={} carrier_cpu_ns={} wall_ms={} zone={:?} {}",
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
    runs.chunks(2)
        .map(|pair| {
            let (short, long) = (&pair[0], &pair[1]);
            let per = |f: fn(&ZoneCounts) -> u64| (f(&long.1) as f64 - f(&short.1) as f64) / span;
            let rates = PingPongRates {
                claims: per(|z| z.host_queue_claims),
                parks: per(|z| z.host_executor_parks),
                services: per(|z| z.service_adoptions),
                handbacks: per(|z| z.host_handbacks),
            };
            let cpu = (long.2 as f64 - short.2 as f64) / span;
            println!(
                "el1-sched {mode} host_queue_claims_per_rt={:.4} \
                 host_executor_parks_per_rt={:.4} service_adoptions_per_rt={:.3} \
                 host_handbacks_per_rt={:.3} carrier_cpu_ns_per_rt={cpu:.0} rt_p50_ns={:.0}",
                rates.claims, rates.parks, rates.services, rates.handbacks, long.3
            );
            rates
        })
        .collect()
}

/// Contract `kernel.el1.guest-run-queue` (EL1 plan 1d), part (a): a thread
/// blocked in a host-served syscall is resumed by the guest's scheduler.
/// Pipes are in-zone EL1 IPC objects and no longer host-served, so the
/// witness is a `read` on an `AF_UNIX` socketpair (`IpcBacking::Host`: EL1
/// forwards it and the host completes it). Two threads hand a byte back and
/// forth over two socketpairs, so every turn blocks one in a host read and
/// completes it from the other. The completed read becomes a service record
/// in an EL1 run queue, and the executor of the vCPU EL1 runs it on serves
/// it: no host run queue holds the thread and no host executor parks on a
/// run-queue condvar waiting for it. Over the difference of a long and a
/// short run, host run-queue claims and host executor parks per round trip
/// must be zero in steady state (below 0.01), and every round trip is served
/// through service records.
/// Red: the same binary with `CARRICK_EL1_SCHED=0`, where completions go to
/// host run queues (about two claims and two parks per round trip).
#[test]
fn el1_sched_host_blocked_read_resumes_by_guest_scheduling() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    for rates in pingpong_rates("sock-pingpong") {
        assert!(
            rates.claims < 0.01 && rates.parks < 0.01,
            "a thread blocked in a host read went through host run queues: \
             {:.3} claims and {:.3} executor parks per round trip",
            rates.claims,
            rates.parks
        );
        assert!(
            rates.services >= 1.0,
            "completed host reads were not served through the guest's run queues \
             ({:.3} service adoptions per round trip)",
            rates.services
        );
    }
}

/// The in-guest counterpart of the host-blocked-read witness: a pipe `read`
/// is served entirely by EL1's IPC objects, so a pipe ping-pong needs no
/// host service at all. Over the difference of a long and a short run,
/// host run-queue claims, host executor parks and host handbacks per round
/// trip are zero (below 0.01); the guest run queue serves no per-turn
/// service record either (service adoptions stay a startup constant, so the
/// per-round-trip rate is below 0.01).
#[test]
fn el1_sched_pipe_pingpong_stays_in_guest() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    for rates in pingpong_rates("pipe-pingpong") {
        assert!(
            rates.claims < 0.01 && rates.parks < 0.01 && rates.handbacks < 0.01,
            "an in-guest pipe read reached the host scheduler: {:.3} claims, {:.3} executor \
             parks and {:.3} handbacks per round trip",
            rates.claims,
            rates.parks,
            rates.handbacks
        );
        assert!(
            rates.services < 0.01,
            "an in-guest pipe read was served as a host service record \
             ({:.3} service adoptions per round trip)",
            rates.services
        );
    }
}

/// Contract `kernel.el1.epoll-zone`, structural part: an eventfd round trip
/// through an epoll whose set holds only in-zone objects (libuv's
/// MessagePort shape: post the peer's eventfd, block in `epoll_wait` on your
/// own) needs no host exit in steady state. Over the differences of three
/// run lengths (1000, 3000, 6000 round trips), host exits per round trip and
/// forwarded `epoll_pwait` (nr 22) per round trip must both be below 0.01.
/// Red before the in-zone epoll: every turn forwards one `epoll_pwait` per
/// side, and every served eventfd write and read returns through the host to
/// deliver the wake it owes the host-side epoll.
#[test]
fn el1_epoll_eventfd_pingpong_stays_in_guest() {
    const LENGTHS: [u64; 3] = [1_000, 3_000, 6_000];
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let mut runs = Vec::new();
    for iters in LENGTHS {
        let measured = run_fixture(
            &carrier,
            &["epoll-pingpong", &iters.to_string()],
            Duration::from_secs(120),
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        let stdout = measured.result.stdout_utf8();
        assert!(
            stdout.contains(&format!("epoll-pingpong iters={iters}")),
            "epoll-pingpong did not complete: {stdout}"
        );
        let epoll_forwards = measured
            .forwarded_syscalls
            .iter()
            .find(|(nr, _)| *nr == 22)
            .map_or(0, |(_, n)| *n);
        println!(
            "el1-sched epoll-pingpong iters={iters} exits={} epoll_pwait_forwarded={epoll_forwards} \
             exit_classes={} el1_reasons={} host_work={} carrier_cpu_ns={} zone={:?} {}",
            measured.exits,
            exit_breakdown(&measured),
            el1_reason_breakdown(&measured),
            host_work_breakdown(&measured),
            measured.cpu_ns,
            measured.zone,
            stdout.trim()
        );
        runs.push((iters, measured.exits, epoll_forwards, measured.cpu_ns));
    }
    let mut failures = Vec::new();
    for pair in runs.windows(2) {
        let (short, long) = (pair[0], pair[1]);
        let span = (long.0 - short.0) as f64;
        let exits = (long.1 as f64 - short.1 as f64) / span;
        let forwards = (long.2 as f64 - short.2 as f64) / span;
        let cpu = (long.3 as f64 - short.3 as f64) / span;
        println!(
            "el1-sched epoll-pingpong {}..{} exits_per_rt={exits:.4} \
             epoll_pwait_forwarded_per_rt={forwards:.4} carrier_cpu_ns_per_rt={cpu:.0}",
            short.0, long.0
        );
        if exits >= 0.01 || forwards >= 0.01 {
            failures.push(format!(
                "eventfd round trip through an in-zone epoll reached the host ({}..{}): \
                 {exits:.3} exits and {forwards:.3} forwarded epoll_pwait per round trip",
                short.0, long.0
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
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
    carrick_kernel::mprotect_diag::reset();
    let carrier = carrier_or_fail();
    let census_before = carrick_runtime::trap::alias_retirement_census();
    let measured = run_fixture(
        &carrier,
        &["mm-occupancy", &FORKS.to_string()],
        Duration::from_secs(240),
    );
    let census = carrick_runtime::trap::alias_retirement_census();
    let stdout = measured.result.stdout_utf8();
    println!(
        "el1-sched mm-occupancy exits={} carrier_cpu_ns={} wall_ms={} zone={:?} mprotect_enomem_sites=[{}] alias_retirement_restarts={} alias_stale_incarnation_co_holders={} {}",
        measured.exits,
        measured.cpu_ns,
        measured.wall.as_millis(),
        measured.zone,
        carrick_kernel::mprotect_diag::report_line(),
        census.restarts - census_before.restarts,
        census.stale_incarnation_co_holders - census_before.stale_incarnation_co_holders,
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

/// One `key=value` report line. Malformed tokens, duplicate keys and keys the
/// caller did not name are rejected, so a fixture cannot smuggle an
/// unvalidated counter past the witness.
struct ReportLine<'a> {
    line: &'a str,
    fields: std::collections::BTreeMap<&'a str, &'a str>,
}

impl<'a> ReportLine<'a> {
    /// The first line that starts with the words `lead` and continues with
    /// `key=value` tokens only.
    fn find(transcript: &'a str, lead: &[&str], allowed: &[&str]) -> Result<Self, String> {
        let label = lead.join(" ");
        let line = transcript
            .lines()
            .find(|line| {
                let mut words = line.split_whitespace();
                lead.iter().all(|word| words.next() == Some(word))
                    && words.next().is_none_or(|next| next.contains('='))
            })
            .ok_or_else(|| format!("missing `{label}` report line"))?;
        let mut fields = std::collections::BTreeMap::new();
        for token in line.split_whitespace().skip(lead.len()) {
            let (key, value) = token
                .split_once('=')
                .ok_or_else(|| format!("malformed token `{token}` in line: {line}"))?;
            if !allowed.contains(&key) {
                return Err(format!("unexpected key `{key}` in line: {line}"));
            }
            if fields.insert(key, value).is_some() {
                return Err(format!("duplicate key `{key}` in line: {line}"));
            }
        }
        Ok(Self { line, fields })
    }

    fn raw(&self, key: &str) -> Result<&'a str, String> {
        self.fields
            .get(key)
            .copied()
            .ok_or_else(|| format!("missing {key} counter in line: {}", self.line))
    }

    fn u64(&self, key: &str) -> Result<u64, String> {
        let value = self.raw(key)?;
        value
            .parse::<u64>()
            .map_err(|error| format!("invalid {key} `{value}`: {error}"))
    }

    fn flag(&self, key: &str) -> Result<bool, String> {
        let value = self.raw(key)?;
        value
            .parse::<bool>()
            .map_err(|error| format!("invalid {key} `{value}`: {error}"))
    }
}

/// One process's fork-COW report: the pages that role wrote after the fork and
/// then read back intact, counted by the fixture as it verified them.
#[derive(Clone, Debug, PartialEq, Eq)]
struct El1MemoryCowRoleReport {
    writers: u64,
    pages: u64,
    verified_pages: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct El1MemoryCowReport {
    parent: El1MemoryCowRoleReport,
    child: El1MemoryCowRoleReport,
    cow_pages: u64,
    guest_faults: u64,
    /// Completed host COW transactions credited by the carrier's MMs during
    /// the run (`carrick_embed::host_cow_snapshot` delta). Never a fault-exit
    /// count.
    host_cow_resolutions: u64,
    /// MMs the carrier admitted during the run; proves the ledger observed the
    /// workload's fork children rather than reading zero from nothing.
    host_cow_mms: u64,
    host_fault_exits: u64,
    exits: u64,
    grants: u64,
    returns: u64,
    bytes_granted: u64,
    bytes_returned: u64,
}

fn parse_cow_role_line(
    transcript: &str,
    role: &str,
    forks: u64,
    pages: u64,
) -> Result<El1MemoryCowRoleReport, String> {
    let line = ReportLine::find(
        transcript,
        &["fork-cow", role],
        &["writers", "forks", "pages", "verified_pages", "ok"],
    )?;
    if !line.flag("ok")? {
        return Err(format!("{role} report ok must be true"));
    }
    let writers = line.u64("writers")?;
    if writers < 2 {
        return Err(format!("{role} writers must be at least 2, saw {writers}"));
    }
    if line.u64("forks")? != forks {
        return Err(format!(
            "expected forks={forks}, saw forks={}",
            line.u64("forks")?
        ));
    }
    if line.u64("pages")? != pages {
        return Err(format!(
            "expected pages={pages}, saw pages={}",
            line.u64("pages")?
        ));
    }
    let verified_pages = line.u64("verified_pages")?;
    if verified_pages != forks * pages {
        return Err(format!(
            "{role} verified_pages ({verified_pages}) != forks*pages ({})",
            forks * pages
        ));
    }
    Ok(El1MemoryCowRoleReport {
        writers,
        pages,
        verified_pages,
    })
}

/// Parse and cross-check a fork-COW transcript: the fixture's own role lines
/// and summary, then the host's `el1-memory cow` observation line. This checks
/// that the report is well formed, internally consistent and fully observed;
/// whether COW was resolved by EL1 is asserted separately
/// ([`cow_ownership_violation`]) so a malformed report and a red ownership
/// witness stay distinguishable.
fn validate_el1_memory_cow_report(
    transcript: &str,
    forks: u64,
    pages: u64,
) -> Result<El1MemoryCowReport, String> {
    let parent = parse_cow_role_line(transcript, "parent", forks, pages)?;
    let child = parse_cow_role_line(transcript, "child", forks, pages)?;

    let summary = ReportLine::find(
        transcript,
        &["fork-cow"],
        &["forks", "pages", "cow_pages", "isolation_ok", "ok"],
    )?;
    if summary.u64("forks")? != forks || summary.u64("pages")? != pages {
        return Err(format!(
            "summary forks/pages ({}/{}) != expected ({forks}/{pages})",
            summary.u64("forks")?,
            summary.u64("pages")?
        ));
    }
    let cow_pages = summary.u64("cow_pages")?;
    if cow_pages == 0 {
        return Err("cow_pages must be non-zero".to_owned());
    }
    if cow_pages != parent.verified_pages + child.verified_pages {
        return Err(format!(
            "cow_pages ({cow_pages}) != parent+child verified_pages ({})",
            parent.verified_pages + child.verified_pages
        ));
    }
    if !summary.flag("isolation_ok")? {
        return Err("isolation_ok must be true".to_owned());
    }
    if !summary.flag("ok")? {
        return Err("summary ok must be true".to_owned());
    }

    let host = ReportLine::find(
        transcript,
        &["el1-memory", "cow"],
        &[
            "guest_faults",
            "host_cow_resolutions",
            "host_cow_mms",
            "host_fault_exits",
            "exits",
            "grants",
            "returns",
            "bytes_granted",
            "bytes_returned",
            "ok",
        ],
    )?;
    let report = El1MemoryCowReport {
        parent,
        child,
        cow_pages,
        guest_faults: host.u64("guest_faults")?,
        host_cow_resolutions: host.u64("host_cow_resolutions")?,
        host_cow_mms: host.u64("host_cow_mms")?,
        host_fault_exits: host.u64("host_fault_exits")?,
        exits: host.u64("exits")?,
        grants: host.u64("grants")?,
        returns: host.u64("returns")?,
        bytes_granted: host.u64("bytes_granted")?,
        bytes_returned: host.u64("bytes_returned")?,
    };
    if !host.flag("ok")? {
        return Err("host ok flag must be true".to_owned());
    }
    if report.guest_faults == 0 {
        return Err("guest_faults must be non-zero".to_owned());
    }
    if report.host_cow_mms < forks {
        return Err(format!(
            "host COW ledger admitted {} MMs for {forks} forks: the ledger did not observe the workload",
            report.host_cow_mms
        ));
    }
    if report.host_fault_exits > report.exits {
        return Err(format!(
            "host_fault_exits ({}) exceeds total exits ({})",
            report.host_fault_exits, report.exits
        ));
    }
    if report.returns != report.grants {
        return Err(format!(
            "incorrect frame accounting: returns ({}) != grants ({})",
            report.returns, report.grants
        ));
    }
    if report.bytes_returned != report.bytes_granted {
        return Err(format!(
            "incorrect frame accounting: bytes_returned ({}) != bytes_granted ({})",
            report.bytes_returned, report.bytes_granted
        ));
    }
    let ceiling = forks * pages / 4 + 64;
    if report.exits > ceiling {
        return Err(format!(
            "per-page host exits detected: exits={} exceeds ceiling {ceiling} for forks={forks} pages={pages}",
            report.exits
        ));
    }
    Ok(report)
}

/// The ownership claim of `kernel.el1.fork-cow`: no COW transaction completed
/// on the host. Host fault exits are reported but are not this quantity.
fn cow_ownership_violation(report: &El1MemoryCowReport) -> Option<String> {
    (report.host_cow_resolutions != 0).then(|| {
        format!(
            "host completed {} COW resolutions across {} MMs; EL1 must resolve COW in guest",
            report.host_cow_resolutions, report.host_cow_mms
        )
    })
}

#[cfg(test)]
mod cow_report_tests {
    use super::*;

    const PARENT: &str = "fork-cow parent writers=4 forks=20 pages=16 verified_pages=320 ok=true";
    const CHILD: &str = "fork-cow child writers=4 forks=20 pages=16 verified_pages=320 ok=true";
    const SUMMARY: &str = "fork-cow forks=20 pages=16 cow_pages=640 isolation_ok=true ok=true";
    const HOST: &str = "el1-memory cow guest_faults=640 host_cow_resolutions=0 host_cow_mms=21 host_fault_exits=0 exits=12 grants=16 returns=16 bytes_granted=65536 bytes_returned=65536 ok=true";

    fn transcript(lines: &[&str]) -> String {
        lines.join("\n") + "\n"
    }

    fn rejects(lines: &[&str], needle: &str) {
        let err = validate_el1_memory_cow_report(&transcript(lines), 20, 16).unwrap_err();
        assert!(err.contains(needle), "wanted `{needle}` in `{err}`");
    }

    fn with_host(replace: (&str, &str)) -> String {
        assert!(HOST.contains(replace.0), "test edits an existing field");
        HOST.replacen(replace.0, replace.1, 1)
    }

    #[test]
    fn accepts_valid_transcript() {
        let report =
            validate_el1_memory_cow_report(&transcript(&[PARENT, CHILD, SUMMARY, HOST]), 20, 16)
                .unwrap();
        assert_eq!(report.cow_pages, 640);
        assert_eq!(report.host_cow_resolutions, 0);
        assert_eq!(report.host_cow_mms, 21);
        assert_eq!(cow_ownership_violation(&report), None);
    }

    #[test]
    fn host_resolved_cow_is_a_well_formed_report_with_an_ownership_violation() {
        let host = with_host(("host_cow_resolutions=0", "host_cow_resolutions=320"));
        let report =
            validate_el1_memory_cow_report(&transcript(&[PARENT, CHILD, SUMMARY, &host]), 20, 16)
                .expect("a red ownership witness is not a malformed report");
        let violation = cow_ownership_violation(&report).unwrap();
        assert!(violation.contains("320 COW resolutions"), "{violation}");
    }

    #[test]
    fn fault_exits_are_not_host_cow_resolutions() {
        // Host fault exits alone never count as a host COW resolution.
        let host = with_host(("host_fault_exits=0", "host_fault_exits=9"));
        let report =
            validate_el1_memory_cow_report(&transcript(&[PARENT, CHILD, SUMMARY, &host]), 20, 16)
                .unwrap();
        assert_eq!(report.host_fault_exits, 9);
        assert_eq!(cow_ownership_violation(&report), None);
    }

    #[test]
    fn rejects_legacy_unmetered_transcript() {
        rejects(&["fork-cow forks=20 pages=16 ok=true"], "`fork-cow parent`");
    }

    #[test]
    fn rejects_missing_host_cow_counters() {
        let no_resolutions = HOST.replace(" host_cow_resolutions=0", "");
        rejects(
            &[PARENT, CHILD, SUMMARY, &no_resolutions],
            "missing host_cow_resolutions counter",
        );
        let no_mms = HOST.replace(" host_cow_mms=21", "");
        rejects(&[PARENT, CHILD, SUMMARY, &no_mms], "missing host_cow_mms");
        let no_exits = HOST.replace(" host_fault_exits=0", "");
        rejects(
            &[PARENT, CHILD, SUMMARY, &no_exits],
            "missing host_fault_exits",
        );
    }

    #[test]
    fn rejects_a_ledger_that_did_not_observe_the_forks() {
        let host = with_host(("host_cow_mms=21", "host_cow_mms=0"));
        rejects(
            &[PARENT, CHILD, SUMMARY, &host],
            "did not observe the workload",
        );
        let host = with_host(("host_cow_mms=21", "host_cow_mms=19"));
        rejects(
            &[PARENT, CHILD, SUMMARY, &host],
            "admitted 19 MMs for 20 forks",
        );
    }

    #[test]
    fn rejects_fault_exits_exceeding_total_exits() {
        let host = with_host(("host_fault_exits=0", "host_fault_exits=20"));
        rejects(
            &[PARENT, CHILD, SUMMARY, &host],
            "host_fault_exits (20) exceeds total exits (12)",
        );
    }

    #[test]
    fn rejects_zero_guest_faults_and_zero_cow_pages() {
        let host = with_host(("guest_faults=640", "guest_faults=0"));
        rejects(
            &[PARENT, CHILD, SUMMARY, &host],
            "guest_faults must be non-zero",
        );
        let summary = SUMMARY.replace("cow_pages=640", "cow_pages=0");
        rejects(
            &[PARENT, CHILD, &summary, HOST],
            "cow_pages must be non-zero",
        );
    }

    #[test]
    fn rejects_cow_pages_that_disagree_with_role_observations() {
        let summary = SUMMARY.replace("cow_pages=640", "cow_pages=641");
        rejects(
            &[PARENT, CHILD, &summary, HOST],
            "cow_pages (641) != parent+child",
        );
    }

    #[test]
    fn rejects_unverified_or_zero_role_pages() {
        let parent = PARENT.replace("verified_pages=320", "verified_pages=0");
        rejects(
            &[&parent, CHILD, SUMMARY, HOST],
            "parent verified_pages (0)",
        );
        let child = CHILD.replace("verified_pages=320", "verified_pages=319");
        rejects(
            &[PARENT, &child, SUMMARY, HOST],
            "child verified_pages (319)",
        );
    }

    #[test]
    fn rejects_frame_accounting_mismatches() {
        let host = with_host(("returns=16", "returns=8"));
        rejects(
            &[PARENT, CHILD, SUMMARY, &host],
            "returns (8) != grants (16)",
        );
        let host = with_host(("bytes_returned=65536", "bytes_returned=32768"));
        rejects(
            &[PARENT, CHILD, SUMMARY, &host],
            "bytes_returned (32768) != bytes_granted (65536)",
        );
    }

    #[test]
    fn rejects_per_page_exits() {
        let host = with_host(("exits=12", "exits=500"));
        rejects(
            &[PARENT, CHILD, SUMMARY, &host],
            "per-page host exits detected",
        );
    }

    #[test]
    fn rejects_isolation_and_role_failures() {
        let summary = SUMMARY.replace("isolation_ok=true", "isolation_ok=false");
        rejects(
            &[PARENT, CHILD, &summary, HOST],
            "isolation_ok must be true",
        );
        let child = CHILD.replace("ok=true", "ok=false");
        rejects(
            &[PARENT, &child, SUMMARY, HOST],
            "child report ok must be true",
        );
    }

    #[test]
    fn rejects_fork_and_page_count_mismatches() {
        rejects(
            &[
                &PARENT.replace("forks=20", "forks=10"),
                CHILD,
                SUMMARY,
                HOST,
            ],
            "expected forks=20",
        );
        rejects(
            &[&PARENT.replace("pages=16", "pages=8"), CHILD, SUMMARY, HOST],
            "expected pages=16",
        );
    }

    #[test]
    fn rejects_missing_lines_duplicates_and_unknown_keys() {
        rejects(&[CHILD, SUMMARY, HOST], "`fork-cow parent` report line");
        rejects(&[PARENT, CHILD, SUMMARY], "`el1-memory cow` report line");
        let dup = format!("{HOST} exits=13");
        rejects(&[PARENT, CHILD, SUMMARY, &dup], "duplicate key `exits`");
        let unknown = format!("{HOST} extra=1");
        rejects(
            &[PARENT, CHILD, SUMMARY, &unknown],
            "unexpected key `extra`",
        );
    }
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

/// Contract `kernel.mm.tlb-maintenance-budget` (host-lane stage-1 editing):
/// publishing an EL1 frame grant over a range with no valid translation needs
/// no TLB invalidation (AArch64 never caches an invalid translation), so first
/// touches add no TLB-maintenance host round trips (`hvc #1`, exit class
/// `Maintenance`). Measured as the slope of maintenance exits against frame
/// grants between two scales of `mapping-retirement` (map, touch every page,
/// unmap), so process start and exit cancel. Before: one maintenance exit per
/// grant publication.
#[test]
fn el1_tlb_frame_grant_publication_costs_no_maintenance() {
    const SCALES: [u64; 2] = [256, 2048];
    const ROUNDS: u64 = 4;
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let mut runs = Vec::new();
    for pages in SCALES {
        let before = carrick_embed::el1_frame_grant_stats();
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
        let grants = after.grants_succeeded - before.grants_succeeded;
        let maintenance =
            measured.exit_classes[carrick_el1_abi::HostExitClass::Maintenance as usize];
        println!(
            "el1-sched tlb-budget mapping-retirement pages={pages} rounds={ROUNDS} grants={grants} maintenance_exits={maintenance} exits={}",
            measured.exits
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        assert!(grants > 0, "workload published no EL1 frame grants");
        runs.push((grants, maintenance));
    }
    let (g0, m0) = runs[0];
    let (g1, m1) = runs[1];
    let added = m1.saturating_sub(m0);
    println!(
        "el1-sched tlb-budget grants {g0}->{g1}: maintenance {m0}->{m1} (+{added}) over {ROUNDS} rounds"
    );
    // The larger scale's munmap leaves EL1 for the host and retires valid
    // leaves: one invalidation per round is required, and that is all the
    // added work may be. Each added grant must cost none.
    assert!(
        added <= ROUNDS,
        "{} added frame grants cost {added} TLB-maintenance exits (budget: {ROUNDS}, one per \
         host munmap); an invalid->valid publication needs none",
        g1 - g0
    );
}

/// Correctness half of the TLB-maintenance contract: a page a worker on one
/// vCPU keeps hot must not stay reachable through a stale translation after
/// another vCPU `mprotect`s it read-only or `munmap`s it. Every round's write
/// probe and read probe must fault exactly once, and the read after `munmap`
/// must see a fresh zero page.
#[test]
fn el1_tlb_cross_vcpu_mm_edits_leave_no_stale_translation() {
    const ROUNDS: u64 = 300;
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let measured = run_fixture(
        &carrier,
        &["cross-vcpu-stale", &ROUNDS.to_string()],
        Duration::from_secs(120),
    );
    let stdout = measured.result.stdout_utf8();
    println!(
        "el1-sched cross-vcpu-stale exits={} maintenance_exits={} {}",
        measured.exits,
        measured.exit_classes[carrick_el1_abi::HostExitClass::Maintenance as usize],
        stdout.trim()
    );
    assert!(measured.result.success(), "{}", describe(&measured));
    assert!(
        stdout.contains(&format!(
            "cross-vcpu-stale rounds={ROUNDS} write_faults={ROUNDS} read_faults={ROUNDS} stale_reads=0 errors=0 timeouts=0 ok=true"
        )),
        "a stale stage-1 translation survived a cross-vCPU mm edit: {stdout:?}"
    );
}

/// Contract `kernel.mm.tlb-maintenance-budget` (required invalidations): a
/// running thread's `mprotect` restriction, `mprotect` restore and `munmap`
/// of a touched page each need a TLB invalidation, and none may cost a host
/// TLB-maintenance round trip: the thread's own vCPU issues it, broadcast,
/// on its way back to EL0. Measured as slopes between two round counts of
/// `tlb-edit-budget` (a two-thread MM editing a host-mapped private file
/// page; three required invalidations per round), so process start and exit
/// cancel: required invalidations the
/// host issued (`ResumeInvalidationStats::issued_by_host`) must not grow.
/// The Maintenance exit-class slope is printed too; it also counts stale
/// first-touch fault retries and task loads, which are not invalidations an
/// edit requires.
#[test]
fn el1_tlb_running_thread_mm_edits_cost_no_maintenance() {
    const ROUNDS: [u64; 2] = [4, 36];
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let mut runs = Vec::new();
    for rounds in ROUNDS {
        let before = carrick_embed::resume_invalidation_stats();
        let measured = run_fixture(
            &carrier,
            &["tlb-edit-budget", &rounds.to_string()],
            Duration::from_secs(120),
        );
        let after = carrick_embed::resume_invalidation_stats();
        let maintenance =
            measured.exit_classes[carrick_el1_abi::HostExitClass::Maintenance as usize];
        let owed = after.owed - before.owed;
        let on_return = after.issued_on_return - before.issued_on_return;
        let by_host = after.issued_by_host - before.issued_by_host;
        let stdout = measured.result.stdout_utf8();
        println!(
            "el1-sched tlb-edit-budget rounds={rounds} owed={owed} issued_on_return={on_return} \
             issued_by_host={by_host} maintenance_exits={maintenance} exits={} {}",
            measured.exits,
            stdout.trim()
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        assert!(
            stdout.contains(&format!("tlb-edit-budget rounds={rounds} errors=0 ok=true")),
            "{stdout:?}"
        );
        runs.push((owed, by_host, maintenance));
    }
    let added_rounds = ROUNDS[1] - ROUNDS[0];
    let owed = runs[1].0.saturating_sub(runs[0].0);
    let by_host = runs[1].1.saturating_sub(runs[0].1);
    let maintenance = runs[1].2 as i64 - runs[0].2 as i64;
    println!(
        "el1-sched tlb-edit-budget over {added_rounds} added rounds: owed +{owed}, issued by \
         host +{by_host}, maintenance exits {maintenance:+}"
    );
    assert!(
        owed >= 3 * added_rounds,
        "{added_rounds} added rounds owed only {owed} invalidations to their returns"
    );
    assert_eq!(
        by_host, 0,
        "{added_rounds} added rounds of required invalidations cost {by_host} host \
         TLB-maintenance round trips (budget: 0)"
    );
}

/// A deterministic replay of the fixture's late sibling initialization:
/// allocate an alternate-stack-sized region while the measured page is
/// unmapped. The file's private window must exclude that allocation.
#[test]
fn el1_tlb_mm_edit_window_excludes_sibling_allocations() {
    let _guard = common::guest_lock();
    let carrier = carrier_or_fail();
    let measured = run_fixture(
        &carrier,
        &["tlb-edit-budget", "36", "force-gap-allocation"],
        Duration::from_secs(120),
    );
    let stdout = measured.result.stdout_utf8();
    println!("{stdout}");
    assert!(
        stdout.contains("forced_gap=true sibling_gap_overlaps=false"),
        "a sibling allocated the measured page during its munmap/MAP_FIXED gap: {stdout}"
    );
    assert!(measured.result.success(), "{}", describe(&measured));
}

/// The stale-translation half of the TLB-maintenance contract with more than
/// one other vCPU running the MM: workers on guest CPUs 1 and 2 keep a page
/// hot while CPU 0 `mprotect`s it read-only and `munmap`s it. Every worker's
/// next write and next read must fault.
#[test]
fn el1_tlb_cross_vcpu_mm_edits_leave_no_stale_translation_on_any_thread() {
    const ROUNDS: u64 = 300;
    const WORKERS: u64 = 2;
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let measured = run_fixture(
        &carrier,
        &[
            "tlb-stale-threads",
            &ROUNDS.to_string(),
            &WORKERS.to_string(),
        ],
        Duration::from_secs(120),
    );
    let stdout = measured.result.stdout_utf8();
    println!(
        "el1-sched tlb-stale-threads exits={} maintenance_exits={} {}",
        measured.exits,
        measured.exit_classes[carrick_el1_abi::HostExitClass::Maintenance as usize],
        stdout.trim()
    );
    assert!(measured.result.success(), "{}", describe(&measured));
    assert!(
        stdout.contains(&format!(
            "tlb-stale-threads rounds={ROUNDS} workers={WORKERS} expected_faults={} \
             faults={:?} stale=0 errors=0 timeouts=0 ok=true",
            2 * ROUNDS,
            [2 * ROUNDS; WORKERS as usize]
        )),
        "a stale stage-1 translation survived a cross-vCPU mm edit: {stdout:?}"
    );
}

/// Fork and exec around required invalidations: a writable translation a
/// worker on CPU 1 holds must not survive the fork's copy-on-write arming
/// (its post-fork write must not reach the child), and a page unmapped just
/// before `execve` must not stay reachable from CPU 1 in the new image.
#[test]
fn el1_tlb_fork_and_exec_leave_no_stale_translation() {
    const ROUNDS: u64 = 50;
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let fork = run_fixture(
        &carrier,
        &["tlb-fork-stale", &ROUNDS.to_string()],
        Duration::from_secs(120),
    );
    let stdout = fork.result.stdout_utf8();
    println!(
        "el1-sched tlb-fork-stale exits={} {}",
        fork.exits,
        stdout.trim()
    );
    assert!(fork.result.success(), "{}", describe(&fork));
    assert!(
        stdout.contains(&format!(
            "tlb-fork-stale rounds={ROUNDS} child_failures=0 parent_failures=0 errors=0 \
             timeouts=0 ok=true"
        )),
        "{stdout:?}"
    );
    let exec = run_fixture(&carrier, &["tlb-exec-stale"], Duration::from_secs(120));
    let stdout = exec.result.stdout_utf8();
    println!(
        "el1-sched tlb-exec-stale exits={} {}",
        exec.exits,
        stdout.trim()
    );
    assert!(exec.result.success(), "{}", describe(&exec));
    assert!(
        stdout
            .contains("tlb-exec-stale faults=1 stale_reads=0 seen=0x0 errors=0 timeouts=0 ok=true"),
        "{stdout:?}"
    );
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

/// Hold the actual host owner before mapping backing. Other allocator users
/// must park exact records, rather than spending their 258-attempt budget.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn el1_metadata_allocator_delayed_owner_parks_participants() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    carrick_runtime::reset_metadata_grant_state();
    let carrier = carrier_or_fail();
    // Admit only the barrier-synchronized 10 MiB transaction, not startup
    // metadata requests that can occur before the four workers exist.
    let probe = carrick_vmm_hvf::metadata_grant::arm_delayed_metadata_request(10 * 1024 * 1024);
    let monitor = std::thread::spawn(move || {
        use carrick_vmm_hvf::metadata_grant::MetadataDelayObservation;
        let mut owner = false;
        let mut parked = 0;
        let mut boundaries = 0;
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            let observation = probe
                .events
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()));
            match observation.unwrap_or_else(|error| panic!("delayed metadata owner observation: {error}; owner={owner} parked={parked} boundaries={boundaries}")) {
                MetadataDelayObservation::OwnerClaimed => owner = true,
                MetadataDelayObservation::Contended { parked: count } => {
                    parked = parked.max(count);
                    boundaries += 1;
                    if parked >= 3 {
                        break;
                    }
                }
            }
        }
        // Drop releases the owner before the test evaluates either verdict.
        drop(probe);
        (owner, parked, boundaries)
    });
    let measured = run_fixture(
        &carrier,
        &["metadata-allocator", "concurrent"],
        Duration::from_secs(30),
    );
    let (owner, parked, boundaries) = monitor.join().expect("metadata delay monitor");
    println!(
        "metadata delayed owner claimed={owner} parked={parked} losing_boundaries={boundaries}"
    );
    assert!(
        owner && parked >= 3,
        "metadata participants must release execution capacity on owned records: parked={parked} losing_boundaries={boundaries}; {}",
        describe(&measured)
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
    assert_eq!(stats.grants_denied, 0, "{stats:?}");
    assert_eq!(stats.grants_succeeded, stats.returns_completed, "{stats:?}");
    assert_eq!(stats.bytes_granted, stats.bytes_returned, "{stats:?}");
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

/// Contract `kernel.el1.fork-cow`: fork COW resolution verification.
/// Forks across three scales with private anonymous pages armed read-only for
/// COW; four guest threads per process concurrently write them, taking write
/// permission faults. EL1 must resolve those faults in the guest, so the
/// carrier's host COW ledger must record no completed host COW transaction.
/// Parent and child verify memory isolation and integrity.
///
/// Observations: `host_cow_resolutions` is the delta of the CARRIER-scoped
/// `carrick_embed::host_cow_snapshot()` (every MM the carrier admitted,
/// surviving their retirement; `checked_delta` rejects a missing or different
/// carrier). It is not the host fault-exit count, which is reported beside it.
///
/// Expected RED until guest-owned COW lands: today the host `cow_engine`
/// completes the transactions and this assertion names the count. Only a
/// recorded signed run establishes the measured failure.
#[test]
fn el1_fork_cow_resolves_in_guest() {
    const FORKS: u64 = 20;
    const SCALES: [u64; 3] = [16, 64, 256];
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    // The carrier VM (and its host-COW ledger) is published by its first
    // container run. Baselines taken before that read incomplete and must
    // never be differenced, so warm the carrier with a one-fork workload
    // first; every measured delta then lies inside one live ledger.
    run_fixture(&carrier, &["fork-cow", "1", "1"], Duration::from_secs(120));
    assert!(
        carrick_embed::host_cow_snapshot().complete,
        "warm-up must publish the carrier's host COW ledger"
    );
    let mut runs = Vec::new();

    for pages in SCALES {
        let grants_before = carrick_embed::el1_frame_grant_stats();
        let cow_before = carrick_embed::host_cow_snapshot();
        let pool_before = el1_cow_pool_counters();
        let faults_before = read_el1_counters().map_or(0, |c| {
            c.fault_taken.load(std::sync::atomic::Ordering::Relaxed)
        });
        let measured = run_fixture(
            &carrier,
            &["fork-cow", &FORKS.to_string(), &pages.to_string()],
            Duration::from_secs(120),
        );
        let cow = carrick_embed::host_cow_snapshot()
            .checked_delta(&cow_before)
            .expect("host COW ledger must be complete and belong to the same carrier");
        // Which lane the workload's MMs actually ran on: a host-resolved COW
        // count means little without knowing the guest lane was selected.
        println!(
            "el1-sched fork-cow pages={pages} guest_lane_selected={} guest_lane_refused={} \
             refused[census,no_resolver,unsynced,hatch]={:?} deferred={}",
            cow.guest_lane_selected,
            cow.guest_lane_refused,
            cow.guest_lane_refused_reasons,
            cow.guest_lane_deferred
        );
        // Guest EL1 COW: resolved in EL1, declined to the host by reason,
        // and what the host provisioned and settled for it.
        let pool_after = el1_cow_pool_counters();
        println!(
            "el1-sched fork-cow pages={pages} el1_cow_resolved={} \
             el1_cow_declined[unmapped,not_cow_armed,not_el1_private,no_write_intent,\
             unreachable,pool_empty,editor_busy,refused]={:?} \
             guest_cow_provisioned={} guest_cow_settled={} \
             host_cow_resolutions={} \
             host_cow_by_path[stage_fault,syscall_copy_out,backing_maintenance,\
             privileged_internal,foreign_publication]={:?} host_cow_max_per_mm={} \
             guest_lane_host_cow_by_path[same order]={:?} \
             host_lane_samples[cause=never_selected,pending_no_backing,pending_no_manager,\
             pending_unsynced_edits,pending_awaiting_bind,authority_mismatch][site=initial_bind,\
             fork_plan,host_cow]={:?}",
            pool_after.0.saturating_sub(pool_before.0),
            core::array::from_fn::<u64, { carrick_el1_abi::COW_DECLINE_REASONS }, _>(|i| {
                pool_after.1[i].saturating_sub(pool_before.1[i])
            }),
            cow.guest_cow_provisioned,
            cow.guest_cow_settled,
            cow.host_cow_resolutions,
            cow.host_cow_by_path,
            cow.host_cow_max_per_mm,
            cow.guest_lane_host_cow_by_path,
            cow.host_lane_samples,
        );
        let grants_after = carrick_embed::el1_frame_grant_stats();
        let faults_after = read_el1_counters().map_or(0, |c| {
            c.fault_taken.load(std::sync::atomic::Ordering::Relaxed)
        });

        let faults = faults_after.saturating_sub(faults_before);
        let grants = grants_after
            .grants_succeeded
            .saturating_sub(grants_before.grants_succeeded);
        let returns = grants_after
            .returns_completed
            .saturating_sub(grants_before.returns_completed);
        let bytes_granted = grants_after
            .bytes_granted
            .saturating_sub(grants_before.bytes_granted);
        let bytes_returned = grants_after
            .bytes_returned
            .saturating_sub(grants_before.bytes_returned);
        let host_fault_exits =
            measured.exit_classes[carrick_el1_abi::HostExitClass::Fault as usize];

        assert!(measured.result.success(), "{}", describe(&measured));
        let stdout = measured.result.stdout_utf8();
        let host_line = format!(
            "el1-memory cow guest_faults={faults} host_cow_resolutions={} host_cow_mms={} host_fault_exits={host_fault_exits} exits={} grants={grants} returns={returns} bytes_granted={bytes_granted} bytes_returned={bytes_returned} ok={}",
            cow.host_cow_resolutions,
            cow.admitted_mms,
            measured.exits,
            measured.result.success()
        );
        let transcript = format!("{}\n{}", stdout.trim(), host_line);
        println!(
            "el1-sched fork-cow forks={FORKS} pages={pages} exits={} {host_line}",
            measured.exits
        );
        println!(
            "el1-sched fork-cow pages={pages} exit_classes={} forwarded_syscalls={:?}",
            exit_breakdown(&measured),
            measured.forwarded_syscalls,
        );
        let report = validate_el1_memory_cow_report(&transcript, FORKS, pages)
            .unwrap_or_else(|error| panic!("invalid fork-cow report: {error}\n{transcript}"));

        assert!(
            report.guest_faults >= FORKS * pages,
            "expected at least {} guest fault entries, got {}",
            FORKS * pages,
            report.guest_faults
        );
        if let Some(violation) = cow_ownership_violation(&report) {
            panic!(
                "fork-cow pages={pages}: {violation} (host fault exits {host_fault_exits}, guest faults {faults})"
            );
        }
        runs.push((pages, measured.exits));
    }

    for pair in runs.windows(2) {
        let (p0, exits0) = pair[0];
        let (p1, exits1) = pair[1];
        let added_pages = (FORKS as f64) * (p1 as f64 - p0 as f64);
        let exit_slope = (exits1 as f64 - exits0 as f64) / added_pages;
        println!(
            "el1-sched fork-cow slope {p0}->{p1} pages (added={added_pages}): \
             exits_diff={} slope={exit_slope:.4} exits/page",
            exits1 as i64 - exits0 as i64,
        );
        assert!(
            exit_slope < 0.125,
            "fork-cow host-exit slope {exit_slope:.4} exceeds ceiling <0.125 exits per added page"
        );
    }
}

/// The carrier pool's guest COW counters: (resolved, declined by reason).
fn el1_cow_pool_counters() -> (u64, [u64; carrick_el1_abi::COW_DECLINE_REASONS]) {
    carrick_el1_abi::cow_grant_pool_host()
        .map_or((0, [0; carrick_el1_abi::COW_DECLINE_REASONS]), |pool| {
            (pool.resolved(), pool.declined())
        })
}

/// Contract `kernel.el1.anonymous-reservations`: anonymous `mmap` (including
/// `MAP_FIXED` replacement) and `brk` growth/shrink are served by EL1, with
/// memory committed lazily on first touch.
///
/// Forwarding is asserted structurally: the forwarded `mmap`/`brk` count must
/// be identical at every scale (fixed runtime start-up cost only), never
/// growing with the number of reservations.
///
/// Expected RED until guest-owned reservations land (`mmap`/`brk` still
/// forward per call). Only a recorded signed run establishes the failure.
#[test]
fn el1_anonymous_reservations_stay_in_guest() {
    const SCALES: [usize; 3] = [64, 256, 1024];
    const MMAP: usize = 222;
    const BRK: usize = 214;
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let counters = || {
        read_el1_counters().map_or([0; 4], |c| {
            let load = |counter: &std::sync::atomic::AtomicU64| {
                counter.load(std::sync::atomic::Ordering::Relaxed)
            };
            [
                load(&c.served[MMAP]),
                load(&c.forwarded[MMAP]),
                load(&c.served[BRK]),
                load(&c.forwarded[BRK]),
            ]
        })
    };
    let mut runs = Vec::new();

    for count in SCALES {
        let before = counters();
        let measured = run_fixture(
            &carrier,
            &["anonymous-reservations", &count.to_string()],
            Duration::from_secs(120),
        );
        let after = counters();
        let [served_mmap, forwarded_mmap, served_brk, forwarded_brk] =
            std::array::from_fn(|i| after[i].saturating_sub(before[i]));

        let stdout = measured.result.stdout_utf8();
        println!(
            "el1-sched anonymous-reservations count={count} exits={} served_mmap={served_mmap} forwarded_mmap={forwarded_mmap} served_brk={served_brk} forwarded_brk={forwarded_brk} {}",
            measured.exits,
            stdout.trim()
        );

        assert!(measured.result.success(), "{}", describe(&measured));
        assert!(
            stdout.contains(&format!("anonymous-reservations count={count} "))
                && stdout.contains("ok=true"),
            "anonymous reservations failed: {stdout:?}"
        );
        assert!(
            served_mmap >= count as u64,
            "EL1 must serve every anonymous mmap: expected >= {count} served, got {served_mmap}"
        );
        assert!(
            served_brk >= 2,
            "EL1 must serve brk growth and shrink: expected >= 2 served, got {served_brk}"
        );
        runs.push((count, measured.exits, forwarded_mmap, forwarded_brk));
    }

    for pair in runs.windows(2) {
        let (c0, exits0, fmmap0, fbrk0) = pair[0];
        let (c1, exits1, fmmap1, fbrk1) = pair[1];
        assert_eq!(
            fmmap1, fmmap0,
            "forwarded mmap grew with reservations {c0}->{c1} ({fmmap0} -> {fmmap1}): per-call forwarding"
        );
        assert_eq!(
            fbrk1, fbrk0,
            "forwarded brk grew with reservations {c0}->{c1} ({fbrk0} -> {fbrk1}): per-call forwarding"
        );
        let exit_slope = (exits1 as f64 - exits0 as f64) / (c1 - c0) as f64;
        println!(
            "el1-sched anonymous-reservations slope {c0}->{c1}: exits_diff={} slope={exit_slope:.4} exits/reservation",
            exits1 as i64 - exits0 as i64,
        );
        assert!(
            exit_slope < 0.125,
            "anonymous-reservations host-exit slope {exit_slope:.4} exceeds <0.125 exits per added reservation"
        );
    }
}

/// Per-syscall served/forwarded counters for the delegated-root witnesses.
const DELEGATED_SYSCALLS: [(&str, usize); 3] = [("mmap", 222), ("munmap", 215), ("mprotect", 226)];

fn delegated_counters() -> [[u64; 2]; 3] {
    read_el1_counters().map_or([[0; 2]; 3], |c| {
        DELEGATED_SYSCALLS.map(|(_, nr)| {
            [
                c.served[nr].load(std::sync::atomic::Ordering::Relaxed),
                c.forwarded[nr].load(std::sync::atomic::Ordering::Relaxed),
            ]
        })
    })
}

/// Contract `kernel.el1.delegated-root-fork`: a delegated parent and its forked
/// child concurrently `mmap`, `munmap` and `mprotect` their own address spaces
/// (plus a pre-fork COW-shared region). Each process compares its own
/// `/proc/self/maps` with the exact rows the operation sequence implies after
/// every step, so a cross-MM row or a missing split is a mismatch.
///
/// Each round issues 2 mmap, 5 munmap and 2 mprotect per process. The target:
/// EL1 serves all of them on both delegated MMs and forwards a count that does
/// not grow with the rounds.
///
/// Expected RED until S3 lands: EL1 does not yet serve mmap/munmap/mprotect on
/// a delegated (forked) MM, so the served lower bounds and the constant
/// forwarded count fail while the semantic maps checks may already pass. Only a
/// recorded signed run establishes the measured failure.
#[test]
fn el1_delegated_root_concurrent_vma_ops() {
    const ROUNDS: [u64; 3] = [8, 32, 128];
    const PER_ROUND: [u64; 3] = [2, 5, 2];
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let mut runs = Vec::new();
    for rounds in ROUNDS {
        let before = delegated_counters();
        let measured = run_fixture(
            &carrier,
            &["delegated-root-vma", &rounds.to_string()],
            Duration::from_secs(120),
        );
        let after = delegated_counters();
        let stdout = measured.result.stdout_utf8();
        let mut served = [0u64; 3];
        let mut forwarded = [0u64; 3];
        for i in 0..3 {
            served[i] = after[i][0].saturating_sub(before[i][0]);
            forwarded[i] = after[i][1].saturating_sub(before[i][1]);
        }
        println!(
            "el1-sched delegated-root-vma rounds={rounds} exits={} served[mmap,munmap,mprotect]={served:?} forwarded[mmap,munmap,mprotect]={forwarded:?} {}",
            measured.exits,
            stdout.trim()
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        for role in ["parent", "child"] {
            assert!(
                stdout.contains(&format!("delegated-root-vma role={role} rounds={rounds} "))
                    && stdout.contains("map_mismatches=0 semantic_failures=0 ok=true"),
                "{role}: /proc/self/maps or isolation mismatch: {stdout:?}"
            );
        }
        assert!(
            stdout.contains(&format!(
                "delegated-root-vma summary rounds={rounds} parent_ok=true child_ok=true"
            )),
            "delegated-root-vma summary failed: {stdout:?}"
        );
        for i in 0..3 {
            let expected = 2 * PER_ROUND[i] * rounds;
            assert!(
                served[i] >= expected,
                "EL1 must serve every delegated-MM {}: expected >= {expected} served, got {} (forwarded {})",
                DELEGATED_SYSCALLS[i].0,
                served[i],
                forwarded[i]
            );
        }
        runs.push((rounds, forwarded));
    }
    for pair in runs.windows(2) {
        for (i, (name, _)) in DELEGATED_SYSCALLS.iter().enumerate() {
            assert_eq!(
                pair[1].1[i], pair[0].1[i],
                "forwarded {name} grew with rounds {}->{} ({} -> {}): per-call forwarding on a delegated MM",
                pair[0].0, pair[1].0, pair[0].1[i], pair[1].1[i]
            );
        }
    }
}

/// Contract `kernel.el1.delegated-root-fork`: `MAP_FIXED` in the forked child
/// over pages still COW-shared with the parent (one range untouched, one
/// already COW-broken) leaves the parent's bytes intact, and a parent
/// `MAP_FIXED` over a range the child still shares leaves the child's bytes
/// intact. Each round performs 3 `MAP_FIXED` replacements plus the
/// fixture's own setup.
///
/// Expected RED until S3 lands: `MAP_FIXED` over COW-shared pages on a
/// delegated MM is not yet served by EL1, so the served lower bound and the
/// constant forwarded-mmap count fail. The byte-integrity checks are the
/// Linux semantics and may already pass.
#[test]
fn el1_delegated_root_map_fixed_over_cow_pages() {
    const PAGES: u64 = 64;
    const ROUNDS: [u64; 3] = [4, 16, 64];
    const MMAP: usize = 222;
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let mut runs = Vec::new();
    for rounds in ROUNDS {
        let before = delegated_counters()[0];
        let grants_before = carrick_embed::el1_frame_grant_stats();
        let measured = run_fixture(
            &carrier,
            &[
                "delegated-root-fixed-cow",
                &PAGES.to_string(),
                &rounds.to_string(),
            ],
            Duration::from_secs(120),
        );
        let after = delegated_counters()[0];
        let grants_after = carrick_embed::el1_frame_grant_stats();
        let served = after[0].saturating_sub(before[0]);
        let forwarded = after[1].saturating_sub(before[1]);
        let stdout = measured.result.stdout_utf8();
        println!(
            "el1-sched delegated-root-fixed-cow pages={PAGES} rounds={rounds} exits={} served_mmap[{MMAP}]={served} forwarded_mmap={forwarded} grants={} returns={} {}",
            measured.exits,
            grants_after.grants_succeeded - grants_before.grants_succeeded,
            grants_after.returns_completed - grants_before.returns_completed,
            stdout.trim()
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        assert!(
            stdout.contains(&format!(
                "delegated-root-fixed-cow pages={PAGES} rounds={rounds} fixed_maps={} ok=true",
                3 * rounds
            )),
            "MAP_FIXED over COW pages corrupted a peer or failed: {stdout:?}"
        );
        assert!(
            served >= 3 * rounds,
            "EL1 must serve every MAP_FIXED replacement on a delegated MM: expected >= {} served, got {served} (forwarded {forwarded})",
            3 * rounds
        );
        runs.push((rounds, forwarded));
    }
    for pair in runs.windows(2) {
        assert_eq!(
            pair[1].1, pair[0].1,
            "forwarded mmap grew with rounds {}->{} ({} -> {}): per-call forwarding over COW pages",
            pair[0].0, pair[1].0, pair[0].1, pair[1].1
        );
    }
}

/// Deterministic fork, then a parent stage-1 pause that kicks every vCPU, then
/// the child's first pipe read (the n=1 case where 511 of 512 slots were
/// marked). Two intercepted `sched_yield` markers bracket that read in the
/// child; the host's per-reason `host_work_publications` is sampled at each, so
/// the printed delta is exactly the work published around the forwarded read
/// (the two forwarded markers themselves are identical for every sample and
/// are the instrument's perturbation).
///
/// Target asserted: a single forwarded read marks at most one slot and never
/// broadcasts to all slots. The bound is the director's to tighten once the
/// signed receipt names the exact per-reason delta.
///
/// Expected RED while the forwarded first read of a freshly forked child still
/// publishes pending host work to every slot (`AllSlots` greater than zero).
#[test]
fn el1_delegated_root_kick_then_first_read_publications() {
    use carrick_kernel::observe::{
        InterceptAction, InterceptedSyscall, ProcessInfo, SyscallInterceptor,
    };
    use std::sync::{Arc, Mutex};

    const BEFORE: u64 = 0x4b49_434b_0001;
    const AFTER: u64 = 0x4b49_434b_0002;
    type Counts = [u64; carrick_el1_abi::HostWorkPublishReason::COUNT];

    #[derive(Default)]
    struct Samples {
        marks: Mutex<Vec<(u64, Counts)>>,
    }
    impl SyscallInterceptor for Samples {
        fn intercept(
            &self,
            _process: &ProcessInfo<'_>,
            call: &InterceptedSyscall<'_>,
        ) -> InterceptAction {
            if call.name() == "sched_yield" {
                let marker = call.original_args().0[0];
                if marker == BEFORE || marker == AFTER {
                    self.marks
                        .lock()
                        .unwrap()
                        .push((marker, carrick_el1_abi::host_work_publication_counts()));
                }
            }
            InterceptAction::Continue
        }
    }

    let _guard = common::guest_lock();
    let _watchdog = common::Watchdog::start(Duration::from_secs(60));
    reset_el1_counters();
    let carrier = carrier_or_fail();
    for rounds in [1u64, 4] {
        let samples = Arc::new(Samples::default());
        let result = common::run_or_fail(
            carrier
                .container(common::SMOKE_IMAGE)
                .pull_policy(PullPolicy::Missing)
                .command([FIXTURE, "kick-first-read", &rounds.to_string()])
                .vfs_mount("/opt/carrick", Box::new(el1_sched_vfs()))
                .interceptor(samples.clone())
                .run_blocking(),
        );
        let stdout = result.stdout_utf8();
        assert!(result.success(), "{stdout:?} {:?}", result.stderr_utf8());
        assert!(
            stdout.contains(&format!("kick-first-read rounds={rounds} ok=true")),
            "kick-first-read failed: {stdout:?}"
        );
        let marks = samples.marks.lock().unwrap();
        assert_eq!(
            marks.len() as u64,
            2 * rounds,
            "expected one before/after marker pair per round: {marks:?}"
        );
        let mut failures = Vec::new();
        for (round, pair) in marks.chunks(2).enumerate() {
            assert_eq!(
                (pair[0].0, pair[1].0),
                (BEFORE, AFTER),
                "marker order {marks:?}"
            );
            let delta: Counts = std::array::from_fn(|i| pair[1].1[i] - pair[0].1[i]);
            use carrick_el1_abi::HostWorkPublishReason as R;
            println!(
                "el1-sched kick-first-read rounds={rounds} round={round} host_work_publications delta slot:{} all:{} task:{} file_table:{}",
                delta[R::DirectSlot as usize],
                delta[R::AllSlots as usize],
                delta[R::ExactTask as usize],
                delta[R::FileTable as usize],
            );
            if delta[R::AllSlots as usize] != 0 || delta.iter().sum::<u64>() > 1 {
                failures.push(format!("round {round}: delta {delta:?}"));
            }
        }
        assert!(
            failures.is_empty(),
            "forwarded first read published pending host work beyond one slot: {}",
            failures.join("; ")
        );
    }
}

/// Contract `kernel.el1.anonymous-retirement`: `madvise(MADV_DONTNEED)` and
/// process exit without `munmap`, under a live fork peer, return every granted
/// frame, keep the peer's memory intact and let returned frames be reused.
///
/// Expected RED until discard and exit accounting is complete; only a recorded
/// signed run establishes the measured failure.
#[test]
fn el1_anonymous_discard_and_exit_return_frames() {
    const SCALES: [u64; 3] = [256, 1024, 4096];
    const ROUNDS: u64 = 4;
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let mut runs = Vec::new();

    for pages in SCALES {
        let before = carrick_embed::el1_frame_grant_stats();
        let measured = run_fixture(
            &carrier,
            &[
                "anonymous-discard-and-exit",
                &pages.to_string(),
                &ROUNDS.to_string(),
            ],
            Duration::from_secs(120),
        );
        let after = carrick_embed::el1_frame_grant_stats();

        let grants = after.grants_succeeded - before.grants_succeeded;
        let returns = after.returns_completed - before.returns_completed;
        let reused = after.reused_grants - before.reused_grants;
        let bytes_granted = after.bytes_granted - before.bytes_granted;
        let bytes_returned = after.bytes_returned - before.bytes_returned;

        let stdout = measured.result.stdout_utf8();
        println!(
            "el1-sched anonymous-discard-and-exit pages={pages} rounds={ROUNDS} exits={} grants={grants} returns={returns} reused={reused} bytes_granted={bytes_granted} bytes_returned={bytes_returned} {}",
            measured.exits,
            stdout.trim()
        );

        assert!(measured.result.success(), "{}", describe(&measured));
        assert!(
            stdout.contains(&format!(
                "anonymous-discard-and-exit pages={pages} rounds={ROUNDS} dontneed_ok=true exit_ok=true zero_ok=true ok=true"
            )),
            "discard and exit semantics incomplete: {stdout:?}"
        );
        assert!(grants > 0, "workload published no EL1 frame grants");
        assert_eq!(
            returns, grants,
            "every exact EL1 grant across discard and exit must return"
        );
        assert_eq!(
            bytes_returned, bytes_granted,
            "every granted physical byte must return after discard and exit"
        );
        assert!(
            reused > 0,
            "repeated mapping across rounds must physically reuse returned frames"
        );
        runs.push((pages, measured.exits));
    }

    for pair in runs.windows(2) {
        let (p0, exits0) = pair[0];
        let (p1, exits1) = pair[1];
        let added_pages = (ROUNDS as f64) * (p1 - p0) as f64;
        let exit_slope = (exits1 as f64 - exits0 as f64) / added_pages;
        println!(
            "el1-sched anonymous-discard-and-exit slope {p0}->{p1} pages rounds={ROUNDS}: exits_diff={} slope={exit_slope:.4} exits/page/round",
            exits1 as i64 - exits0 as i64,
        );
        assert!(
            exit_slope < 0.125,
            "discard-and-exit host-exit slope {exit_slope:.4} exceeds ceiling <0.125 exits per added page per round"
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
///
/// Captures happen when an executor vacates its zone slot (`step_away` for a
/// blocking host wait, or `leave_slot`) while a host-owned record, such as a
/// completed host-served read's service record, is still queued there. The
/// workload is therefore the pinned host-served `sock-pingpong` (both threads
/// on guest CPU 0, `AF_UNIX` socketpairs): the old `two-process` workload's
/// blocking is a futex/pipe hand-off served in the guest, so it never
/// produces a host-owned record to capture.
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
            .command([FIXTURE, "sock-pingpong", "2000", "pinned"])
            .vfs_mount("/opt/carrick", Box::new(el1_sched_vfs()))
            .auditor(capture.clone())
            .run_blocking(),
    );
    assert!(result.success(), "{}", result.stdout_utf8());
    assert!(result.stdout_utf8().contains("sock-pingpong iters=2000"));
    let records = capture.records.lock().unwrap();
    println!("deferred handback real guest captures: {records:?}");
    assert!(
        !records.is_empty(),
        "guest workload did not exercise the deferred capture boundary"
    );
}

// ---------------------------------------------------------------------------
// Contract `kernel.el1.thread-lifecycle` (stage L0 witnesses).
//
// Every fixture mode asserts LINUX semantics only and must print `ok=true` on
// native arm64 Docker (`el1-sched <mode>` run directly). The structural
// assertions read the zone counters and are the part that is red today.
// Run: `just test-embed el1_thread_lifecycle_` (one filter; serial).

/// Thread-lifecycle syscalls by aarch64 number.
const THREAD_SYSCALLS: [(&str, usize); 6] = [
    ("clone", 220),
    ("exit", 93),
    ("rt_sigprocmask", 135),
    ("sigaltstack", 132),
    ("set_robust_list", 99),
    ("gettid", 178),
];

/// `[served, forwarded]` per thread-lifecycle syscall.
fn thread_counters() -> [[u64; 2]; 6] {
    read_el1_counters().map_or([[0; 2]; 6], |c| {
        THREAD_SYSCALLS.map(|(_, nr)| {
            [
                c.served[nr].load(std::sync::atomic::Ordering::Relaxed),
                c.forwarded[nr].load(std::sync::atomic::Ordering::Relaxed),
            ]
        })
    })
}

/// Run one witness mode and assert its Linux-semantic line. Returns the
/// measurement, the stdout and the per-syscall `[served, forwarded]` deltas.
fn thread_witness(
    carrier: &Carrier,
    mode: &str,
    args: &[&str],
    timeout: Duration,
) -> (Measured, String, [[u64; 2]; 6]) {
    let mut argv = vec![mode];
    argv.extend_from_slice(args);
    let before = thread_counters();
    let measured = run_fixture(carrier, &argv, timeout);
    let after = thread_counters();
    let delta = std::array::from_fn(|i| {
        [
            after[i][0].saturating_sub(before[i][0]),
            after[i][1].saturating_sub(before[i][1]),
        ]
    });
    let stdout = measured.result.stdout_utf8();
    println!(
        "el1-sched {mode} {args:?} exits={} served/forwarded[clone,exit,rt_sigprocmask,sigaltstack,set_robust_list,gettid]={delta:?}\n{}",
        measured.exits,
        stdout.trim()
    );
    assert!(measured.result.success(), "{mode}: {}", describe(&measured));
    let summary = format!("{mode} summary parent_ok=true child_ok=true ok=true");
    let single = stdout
        .lines()
        .any(|line| line.starts_with(&format!("{mode} ")) && line.ends_with("ok=true"));
    assert!(
        stdout.contains(&summary) || (single && !stdout.contains("ok=false")),
        "{mode}: Linux-semantic check failed: {stdout:?}"
    );
    (measured, stdout, delta)
}

/// Stage L0(a): spawn/join slope. Four threads are spawned and joined per
/// round in each of two live processes. The Linux semantics (every thread
/// runs once) must hold; the structural target is that thread exit is born in
/// the zone: fewer than 0.05 forwarded `exit` calls per thread added across
/// scales (the fractional slope is asserted here; the schema cannot express
/// it). Forwarded counts of the other per-thread calls are printed.
///
/// Expected RED today: every thread exit forwards (slope about 1.0).
#[test]
fn el1_thread_lifecycle_spawn_slope() {
    const PER_ROUND: u64 = 4;
    const PROCESSES: u64 = 2;
    const ROUNDS: [u64; 3] = [16, 64, 256];
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let mut runs = Vec::new();
    for rounds in ROUNDS {
        let (measured, _, delta) = thread_witness(
            &carrier,
            "thread-spawn-slope",
            &[&PER_ROUND.to_string(), &rounds.to_string()],
            Duration::from_secs(120),
        );
        runs.push((rounds * PER_ROUND * PROCESSES, measured.exits, delta));
    }
    for pair in runs.windows(2) {
        let (threads0, exits0, delta0) = &pair[0];
        let (threads1, exits1, delta1) = &pair[1];
        let added = (threads1 - threads0) as f64;
        let mut report = Vec::new();
        for (i, (name, _)) in THREAD_SYSCALLS.iter().enumerate() {
            let slope = (delta1[i][1] as f64 - delta0[i][1] as f64) / added;
            report.push(format!("{name}={slope:.4}"));
        }
        println!(
            "el1-sched thread-spawn-slope threads {threads0}->{threads1} forwarded-per-added-thread [{}] exits_per_thread={:.4}",
            report.join(" "),
            (*exits1 as f64 - *exits0 as f64) / added
        );
        let exit_slope = (delta1[1][1] as f64 - delta0[1][1] as f64) / added;
        assert!(
            exit_slope < 0.05,
            "forwarded thread exits per added thread {exit_slope:.4} must be < 0.05 \
             (threads {threads0}->{threads1}: exit forwarded {} -> {})",
            delta0[1][1],
            delta1[1][1]
        );
    }
}

/// Stage L0(b): the parent `tgkill`s a `CLONE_THREAD` child the moment `clone`
/// returns. The child's `gettid` equals the `PARENT_SETTID` value and the
/// clone result; the signal handler ran on that tid; `/proc/self/task` lists
/// it; a second process `kill(tid)`s it. Semantic; the host lane may already
/// pass it, and the thread lifecycle must keep it green when births move into
/// the zone.
#[test]
fn el1_thread_lifecycle_tgkill_right_after_clone() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    thread_witness(
        &carrier,
        "tgkill-after-clone",
        &["16"],
        Duration::from_secs(120),
    );
}

/// Stage L0(c): mask Dekker storm. One thread blocks and unblocks a
/// real-time signal in a loop while another process `sigqueue`s 2000 distinct
/// values: each is delivered exactly once. A process-directed signal while one
/// thread blocks it goes to the other thread, in both directions.
#[test]
fn el1_thread_lifecycle_mask_storm_exactly_once() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    thread_witness(&carrier, "mask-storm", &["2000"], Duration::from_secs(180));
    thread_witness(
        &carrier,
        "signal-retarget",
        &["32"],
        Duration::from_secs(120),
    );
}

/// Stage L0(d): after `join` (CLEARTID) the tid leaves `/proc/self/task`, and
/// a tid still listed is not handed to a new thread.
#[test]
fn el1_thread_lifecycle_cleartid_tid_reuse() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    thread_witness(&carrier, "tid-reuse", &["100"], Duration::from_secs(180));
}

/// Stage L0(e): `RLIMIT_NPROC` counts threads uid-wide. As an unprivileged uid
/// (the fixture drops from root), a clone and a fork at the limit fail
/// `EAGAIN` while a peer process of that uid, with its own limit, forks; the
/// smallest admitting limit counts both processes; with limit L and C
/// existing tasks exactly L - C held threads are admitted (refused when the
/// uid already has >= L tasks) and exiting threads free their slots. The uid is
/// 34567 rather than 1000 so a Docker host's own uid-1000 tasks cannot shift
/// the count. Oracle: native Docker.
#[test]
fn el1_thread_lifecycle_rlimit_nproc_exact() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    thread_witness(&carrier, "nproc-limit", &[], Duration::from_secs(180));
}

/// Stage L0(f): `fork` during an 8-thread clone storm; every child has
/// exactly one thread (its own tid equals its pid) and can clone again.
#[test]
fn el1_thread_lifecycle_fork_during_clone_storm() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    thread_witness(&carrier, "fork-storm", &["16"], Duration::from_secs(180));
}

/// Stage L0(g): `exit_group` and `execve` from one thread during a clone storm
/// leave no surviving thread and do not hang; the exec image is a
/// single-threaded process in the victim's pid.
#[test]
fn el1_thread_lifecycle_exit_group_and_exec_during_clone_storm() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    thread_witness(
        &carrier,
        "exit-group-storm",
        &["4"],
        Duration::from_secs(180),
    );
    thread_witness(&carrier, "exec-storm", &["4"], Duration::from_secs(180));
}

/// Stage L0(h): `PTRACE_O_TRACECLONE` reports the clone event, yields the new
/// tid through `PTRACE_GETEVENTMSG` and auto-attaches the new thread (initial
/// SIGSTOP stop). Needs only `PTRACE_TRACEME` (no `CAP_SYS_PTRACE`). If the
/// carrier has no ptrace, this fails with the tracee's errno named: that is
/// the gate the thread lifecycle must keep closed for traced tasks.
#[test]
fn el1_thread_lifecycle_ptrace_traceclone() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    thread_witness(&carrier, "ptrace-clone", &[], Duration::from_secs(120));
}

/// Stage L0(h): a seccomp filter that returns `EPERM` for thread clones
/// refuses the clone, creates no task and still admits `fork`, while an
/// unfiltered peer keeps spawning threads.
#[test]
fn el1_thread_lifecycle_seccomp_clone_filter() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    thread_witness(&carrier, "seccomp-clone", &[], Duration::from_secs(120));
}

/// Stage L0(j): 192 threads per process, in two live processes, parked in
/// private futex waits and pipe polls (far beyond the executor pool's default
/// worker count) all complete: a guest wait releases execution capacity.
#[test]
fn el1_thread_lifecycle_parked_threads_beyond_executor_pool() {
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    thread_witness(&carrier, "futex-flood", &["192"], Duration::from_secs(180));
}

/// Contract `kernel.el1.task-load-entry` (persistent-executor task load):
/// installing a task on an executor's vCPU (TTBR0/TCR/ASID plus the
/// register file) costs no extra `hv_vcpu_run` round trip. The new context
/// reaches the PE at the task's own next entry, which is a context
/// synchronization event, so a separate EL1 DSB/ISB trampoline run before
/// it (one `Maintenance` exit per load) is pure overhead. Measured as the
/// slope of maintenance exits against completed host task loads between
/// two scales of a workload whose waits the host serves, so process start
/// and exit cancel. Before: one maintenance exit per load.
#[test]
fn el1_task_load_costs_no_host_round_trip() {
    const SCALES: [u64; 2] = [100, 400];
    const WORKLOAD: &str = "sock-pingpong";
    let _guard = common::guest_lock();
    reset_el1_counters();
    let carrier = carrier_or_fail();
    let mut runs = Vec::new();
    for iters in SCALES {
        let loads_before = hvpatch_task_loads_total();
        let measured = run_fixture(
            &carrier,
            &[WORKLOAD, &iters.to_string(), "pinned"],
            Duration::from_secs(120),
        );
        let loads = hvpatch_task_loads_total() - loads_before;
        let maintenance =
            measured.exit_classes[carrick_el1_abi::HostExitClass::Maintenance as usize];
        println!(
            "el1-sched task-load-budget {WORKLOAD} iters={iters} loads={loads} maintenance_exits={maintenance} exits={}",
            measured.exits
        );
        assert!(measured.result.success(), "{}", describe(&measured));
        runs.push((loads, maintenance));
    }
    let (l0, m0) = runs[0];
    let (l1, m1) = runs[1];
    let added_loads = l1.saturating_sub(l0);
    let added = m1.saturating_sub(m0);
    println!("el1-sched task-load-budget loads {l0}->{l1}: maintenance {m0}->{m1} (+{added})");
    assert!(
        added_loads >= SCALES[1] - SCALES[0],
        "the workload must load a task per host-served wait: {added_loads} added loads for {} added waits",
        SCALES[1] - SCALES[0]
    );
    assert_eq!(
        added, 0,
        "{added_loads} added task loads cost {added} TLB-maintenance-class host round trips; a task load needs none"
    );
}
