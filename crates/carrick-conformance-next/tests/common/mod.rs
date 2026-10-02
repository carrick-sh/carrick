//! Shared helpers for carrick-conformance-next guest-running tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use carrick_conformance_next::{EmbedError, PullPolicy, TestContainer};

/// The canonical conformance image: arm64 Ubuntu 24.04.
pub const SMOKE_IMAGE: &str = "docker.io/library/ubuntu:24.04";

include!(concat!(env!("OUT_DIR"), "/shard_arrays.rs"));

/// Per-probe additions to the generic container launch request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProbeLaunchPolicy {
    pub security_opt: Option<&'static str>,
    pub cap_add: Option<&'static str>,
}

const SPECIAL_PROBE_LAUNCH_POLICIES: &[(&str, ProbeLaunchPolicy)] = &[
    (
        "syslogstate",
        ProbeLaunchPolicy {
            security_opt: None,
            cap_add: Some("SYSLOG"),
        },
    ),
    (
        "adjtimexmodel",
        ProbeLaunchPolicy {
            security_opt: None,
            cap_add: Some("SYS_TIME"),
        },
    ),
    (
        "clocksettimevdso",
        ProbeLaunchPolicy {
            security_opt: None,
            cap_add: Some("SYS_TIME"),
        },
    ),
    (
        // Same fanotify_init privilege as pipeblockedge.
        "fanotifyondir",
        ProbeLaunchPolicy {
            security_opt: None,
            cap_add: Some("SYS_ADMIN"),
        },
    ),
    (
        // fanotify_init needs CAP_SYS_ADMIN; without it both the Docker oracle
        // and Carrick fail the group creation and the fanotify lines become
        // vacuous (the documented under-privileged-oracle inversion).
        "pipeblockedge",
        ProbeLaunchPolicy {
            security_opt: None,
            cap_add: Some("SYS_ADMIN"),
        },
    ),
    (
        "clonefilesexec",
        ProbeLaunchPolicy {
            security_opt: Some("seccomp=unconfined"),
            cap_add: None,
        },
    ),
    (
        "clonefileshare",
        ProbeLaunchPolicy {
            security_opt: Some("seccomp=unconfined"),
            cap_add: None,
        },
    ),
    (
        "usernsisolation",
        ProbeLaunchPolicy {
            security_opt: Some("seccomp=unconfined"),
            cap_add: None,
        },
    ),
];

/// Derive launch additions from a probe name, independent of shard placement.
pub fn probe_launch_policy(name: &str) -> ProbeLaunchPolicy {
    SPECIAL_PROBE_LAUNCH_POLICIES
        .iter()
        .find_map(|(probe, policy)| (*probe == name).then(|| policy.clone()))
        .unwrap_or_default()
}

/// Build the fully configured container used by every generic probe shard.
pub fn generic_probe_container(
    probe_name: &str,
    probe_path: &Path,
    probeinit_path: &Path,
) -> TestContainer {
    let policy = probe_launch_policy(probe_name);
    let mut container = TestContainer::new(SMOKE_IMAGE)
        .pull_policy(PullPolicy::Missing)
        // The label names this probe's wedge-capture directory; the budget is
        // the measured one for this probe. Both are per-probe because a
        // capture attributable only by pid is what the `forkstackstorm` spin
        // left behind.
        .label(probe_name)
        .carrier_budget(std::time::Duration::from_millis(
            carrick_conformance_next::probe_steady_budget_ms(probe_name),
        ))
        .mount_readonly(probe_path.display().to_string(), "/tmp/p")
        .mount_readonly(probeinit_path.display().to_string(), "/tmp/carrick-init");

    if let Some(option) = policy.security_opt {
        container = container.security_opt(option);
    }
    if let Some(capability) = policy.cap_add {
        container = container.cap_add(capability);
    }
    container
}

/// Generic probes whose Docker result is deliberately not committed as a
/// static oracle. The old gate quarantines these for timing sensitivity or
/// excludes them from its routine regression lane; they remain live-oracle
/// work and must not make the ordinary cached lane depend on Docker.
pub const LIVE_ORACLE_PROBES: &[&str] = &[
    "clockgetres",
    "forksleepfork",
    "futexextra",
    "futexghost",
    "futexrequeue",
    "futexshare",
    "futexsharedalias",
    "futexwakecount",
    "iouring",
    "iouringenterflag",
    "itimer",
    "kernelidentity",
    "manythreads",
    "mmapfileforkwriteback",
    "mmaprecl",
    "mtforkcorrupt",
    "netpoll",
    "pauseeintr",
    "pidnsinitreap",
    "posixtimers",
    "ppollsig",
    "ppollwaitset",
    "pselecteintr",
    "selecttimeout",
    "sigchld",
    "sigprofvdso",
    "splicenetpoll",
    "timeclock",
    "timeextra",
    "timersettimeabs",
    "tlbibroadcast",
    "waitexitstorm",
    "waitsiblingsigchld",
    "windowcoherence",
];

/// Probes that cannot share an embedded test process after they fail. Keep
/// these on the old out-of-process lane until the runtime teardown is fixed.
pub const OUT_OF_PROCESS_PROBES: &[&str] = &["execfromthread", "vforkexecthread"];

/// Complete arm64 baseline mismatch inventory. Every shard derives its local
/// subset from these global lists so adding a probe cannot silently orphan a
/// known gap when the deterministic modulo partition moves.
pub const MUSL_BASELINE_GAPS: &[&str] = &[];

pub const GNU_BASELINE_GAPS: &[&str] = &[];

pub fn needs_live_oracle(probe: &str) -> bool {
    LIVE_ORACLE_PROBES.contains(&probe)
}

pub fn runs_in_cached_lane(probe: &str) -> bool {
    !needs_live_oracle(probe) && !OUT_OF_PROCESS_PROBES.contains(&probe)
}

pub fn probe_filter_allows(probe: &str) -> bool {
    std::env::var("CARRICK_PROBE_FILTER").map_or(true, |requested| {
        requested
            .split(',')
            .map(str::trim)
            .any(|name| name == probe)
    })
}

pub fn select_cached_probes<'a>(probes: &'a [&'a str], requested: Option<&str>) -> Vec<&'a str> {
    let requested = requested.map(|names| {
        names
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .collect::<std::collections::BTreeSet<_>>()
    });

    probes
        .iter()
        .copied()
        .filter(|probe| runs_in_cached_lane(probe))
        .filter(|probe| requested.as_ref().is_none_or(|names| names.contains(probe)))
        .collect()
}

#[test]
fn special_probe_container_lowers_required_privileges() {
    let cases = [
        ("syslogstate", &["SYSLOG"][..], &[][..]),
        ("clocksettimevdso", &["SYS_TIME"][..], &[][..]),
        ("adjtimexmodel", &["SYS_TIME"][..], &[][..]),
        ("pipeblockedge", &["SYS_ADMIN"][..], &[][..]),
        ("fanotifyondir", &["SYS_ADMIN"][..], &[][..]),
        ("usernsisolation", &[][..], &["seccomp=unconfined"][..]),
        ("clonefileshare", &[][..], &["seccomp=unconfined"][..]),
        ("clonefilesexec", &[][..], &["seccomp=unconfined"][..]),
    ];

    for (probe, expected_cap_add, expected_security_opts) in cases {
        let container =
            generic_probe_container(probe, Path::new("/tmp/probe"), Path::new("/tmp/probeinit"));
        let request = container
            .builder(["/tmp/carrick-init"])
            .to_run_request()
            .expect("lower generic probe request");

        assert_eq!(
            request.cap_add, expected_cap_add,
            "wrong cap_add for {probe}"
        );
        assert_eq!(
            request.security_opts, expected_security_opts,
            "wrong security_opts for {probe}"
        );
    }
}

#[test]
fn special_policy_names_are_unique_in_the_generic_shard_union() {
    let shards = [SHARD_0_PROBES, SHARD_1_PROBES, SHARD_2_PROBES];
    let mut union = std::collections::BTreeSet::new();
    for probe in shards.iter().flat_map(|shard| shard.iter().copied()) {
        assert!(
            union.insert(probe),
            "duplicate probe in shard union: {probe}"
        );
    }
    assert_eq!(
        union.len(),
        SHARD_0_PROBES.len() + SHARD_1_PROBES.len() + SHARD_2_PROBES.len(),
        "generic shard arrays must form a unique union"
    );
    let inv_path = repo_root().join("conformance-probes/probe-inventory.json");
    let inventory =
        carrick_xtask::probe_inventory::load_inventory(&inv_path).expect("load probe inventory");
    let expected_partition = carrick_xtask::probe_inventory::derive_partition(&inventory);
    let expected_generic: std::collections::BTreeSet<&str> = expected_partition
        .generic_names
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        union, expected_generic,
        "generic shard union must remain complete"
    );

    for (special, _) in SPECIAL_PROBE_LAUNCH_POLICIES {
        let occurrences = shards
            .iter()
            .map(|shard| shard.iter().filter(|probe| **probe == *special).count())
            .sum::<usize>();
        assert_eq!(
            occurrences, 1,
            "special launch-policy probe {special} must occur exactly once across the shard union"
        );
    }
}

#[test]
fn cached_probe_selection_honors_requested_filter_and_lane_classification() {
    let probes = ["acceptsock", "clockgetres", "telemetrymap"];

    assert_eq!(
        select_cached_probes(&probes, Some("telemetrymap")),
        vec!["telemetrymap"]
    );
    assert_eq!(
        select_cached_probes(&probes, Some("acceptsock, telemetrymap")),
        vec!["acceptsock", "telemetrymap"]
    );
    assert_eq!(
        select_cached_probes(&probes, None),
        vec!["acceptsock", "telemetrymap"]
    );
}

#[test]
fn retained_probe_manifest_matches_classification() {
    let manifest = std::fs::read_to_string(
        repo_root().join("scripts/conformance/retained-generic-probes.txt"),
    )
    .expect("read retained generic probe manifest");
    let actual = manifest.lines().collect::<std::collections::BTreeSet<_>>();
    let expected = LIVE_ORACLE_PROBES
        .iter()
        .chain(OUT_OF_PROCESS_PROBES)
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected);
}

/// Run one embedded container while host fd 0 is an already-EOF pipe, matching
/// the old direct-probe transport and Docker's `-i` pipe after payload upload.
/// Callers must hold [`guest_lock`] because fd 0 is process-global.
pub fn with_empty_stdin_pipe<T>(run: impl FnOnce() -> T) -> T {
    struct RestoreStdin(i32);

    impl Drop for RestoreStdin {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a live duplicate of fd 0 owned by this guard.
            unsafe {
                libc::dup2(self.0, libc::STDIN_FILENO);
                libc::close(self.0);
            }
        }
    }

    // SAFETY: all returned fds are checked, uniquely owned here, and closed.
    unsafe {
        let saved = libc::dup(libc::STDIN_FILENO);
        assert!(saved >= 0, "failed to duplicate host stdin");
        let restore = RestoreStdin(saved);
        let mut pipe_fds = [-1; 2];
        assert_eq!(
            libc::pipe(pipe_fds.as_mut_ptr()),
            0,
            "failed to create stdin pipe"
        );
        libc::close(pipe_fds[1]);
        assert_eq!(
            libc::dup2(pipe_fds[0], libc::STDIN_FILENO),
            libc::STDIN_FILENO,
            "failed to install stdin pipe"
        );
        libc::close(pipe_fds[0]);
        let outcome = run();
        drop(restore);
        outcome
    }
}

/// Run one probe container and print its wall-clock cost on a grep-able line.
///
/// A carrier budget is only defensible if it comes from a measured
/// distribution: the gate log is the only place that distribution exists, and
/// without an elapsed field per row the constant could only be guessed. The
/// line is emitted for every probe, matching or not, so a green gate is itself
/// the measurement.
pub fn timed_probe_run<T>(label: &str, run: impl FnOnce() -> T) -> T {
    let started = std::time::Instant::now();
    let outcome = run();
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    eprintln!("PROBE ELAPSED {label} elapsed_ms={elapsed_ms}");
    outcome
}

static GUEST_LOCK: Mutex<()> = Mutex::new(());

/// Serialize guest-running tests inside one process.
pub fn guest_lock() -> MutexGuard<'static, ()> {
    GUEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn empty_stdin_transport_is_an_eof_fifo() {
    let _guard = guest_lock();
    with_empty_stdin_pipe(|| {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `stat` is a valid output pointer and fd 0 is installed above.
        assert_eq!(
            unsafe { libc::fstat(libc::STDIN_FILENO, stat.as_mut_ptr()) },
            0
        );
        // SAFETY: fstat succeeded and initialized the structure.
        let stat = unsafe { stat.assume_init() };
        assert_eq!(stat.st_mode & libc::S_IFMT, libc::S_IFIFO);
        let mut byte = 0u8;
        // SAFETY: the one-byte destination is valid; the pipe's writer is closed.
        assert_eq!(
            unsafe { libc::read(libc::STDIN_FILENO, (&mut byte as *mut u8).cast(), 1) },
            0
        );
    });
}

/// The repository root (`crates/carrick-conformance-next` is two levels down).
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("carrick-conformance-next lives under crates/carrick-conformance-next")
        .to_path_buf()
}

/// Unwrap a container run, converting `EmbedError::Entitlement` into a loud failure.
pub fn run_or_fail<T>(outcome: Result<T, EmbedError>) -> T {
    run_named_or_fail("container", outcome)
}

pub fn run_named_or_fail<T>(case: &str, outcome: Result<T, EmbedError>) -> T {
    match outcome {
        Ok(result) => result,
        Err(EmbedError::Entitlement) => panic!(
            "{case}: HV_DENIED (0xfae94007): this test executable lacks \
             com.apple.security.hypervisor. Run it through `just test-conformance-next` \
             or `scripts/test-signed.sh carrick-conformance-next`."
        ),
        Err(err) => panic!("{case}: container run failed: {err}"),
    }
}

/// The run id exported by the test runner.
pub fn run_id() -> String {
    std::env::var("CARRICK_RUN_ID")
        .ok()
        .filter(|id| !id.is_empty())
        .expect(
            "CARRICK_RUN_ID must be set: scripts/test-signed.sh exports it so \
             scripts/sudo/kill.sh can reap this run's guests",
        )
}
