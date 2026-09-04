//! Shared helpers for carrick-conformance-next guest-running tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use carrick_conformance_next::{EmbedError, PullPolicy, TestContainer};

/// The canonical conformance image: arm64 Ubuntu 24.04.
pub const SMOKE_IMAGE: &str = "docker.io/library/ubuntu:24.04";

/// Exact materialized list of 148 sorted unique probe names for generic shard 0.
///
/// Conceptually defined as:
/// - class: "conformance"
/// - excluded: false
/// - runner: "generic"
/// - sorted lexicographically
/// - enumerated from index 0
/// - retained where index % 3 == 0
pub const SHARD_0_PROBES: &[&str] = &[
    "abortdeath",
    "accounting",
    "aliassize",
    "bigallocfree",
    "blockingpipewrite",
    "budget_two_proc",
    "childsubreaper",
    "clockcoherence",
    "clocksettimevdso",
    "clone3pidfdsig",
    "cloneexithandled",
    "clonefileshare",
    "closedstdio",
    "copyrangeflags",
    "cpucount",
    "devnullseek",
    "dirops",
    "dsrconstantpool",
    "epollcluster",
    "epolletmanyhup",
    "epollforkeventfd",
    "epolloutxthread",
    "epollstaledel",
    "eventwaitmatrix",
    "execfromthread",
    "execsig",
    "execvenonutf8",
    "exitgroupthreads",
    "fallocatebig",
    "fcntlgetlk",
    "fcntlofdlock",
    "fcntlstdio",
    "fdstatus",
    "fifoepolleof",
    "fileaccessmode",
    "forkcow",
    "forkfiletable",
    "forkheapalloc",
    "forkshared",
    "forksnapshot",
    "fsescapeguard",
    "fstatatflags",
    "futexdeadline",
    "futexforkwakegroups",
    "futexpingpong",
    "futexrequeue",
    "futexsharedto",
    "futexwakeexact",
    "getrandomvdsofork",
    "hugepage",
    "ioctlcluster",
    "iouringenterflag",
    "ipv6recvhoplimit",
    "itimerprofidle",
    "killchld",
    "killreap",
    "killuidperm",
    "legacyfs",
    "linkstat",
    "ltpcheckpoint",
    "lxattr",
    "mapfixed",
    "mcastjoingroup",
    "memfdsealmatrix",
    "memflagmatrix",
    "mkdirsetgid",
    "mmapcage",
    "mmapexecshared",
    "mmapfileshare_mt",
    "mmapprivfile",
    "mmaptrimprotect",
    "mmsgmatrix",
    "mqnotifycrossproc",
    "mremapmove",
    "msgctlstat",
    "mtforkcorrupt",
    "nanosleeprem",
    "nativex18",
    "netifmcast",
    "newmountapi",
    "nsfsioctl",
    "oomscoreadj",
    "openat2valid",
    "openempty",
    "overlaysymlink",
    "pathnonutf8",
    "pendingunblock",
    "pidnsinitsig",
    "pidnswait",
    "pipelargewrite",
    "pollevent",
    "ppollsig",
    "prctlerrors",
    "preadv2flags",
    "procconfigloop",
    "procladder_epollmgr",
    "proclife",
    "procprctlview",
    "procselfstatleader",
    "procstat",
    "protnonesyscall",
    "ptraceinvaliderrno",
    "ptracesigdeath",
    "ptracetraceme",
    "ptyflagmatrix",
    "readpasteof",
    "recverrqueue",
    "reparenttoinit",
    "rlimitnproc",
    "robustlist",
    "rosharedbus",
    "rtsigtimedwaitsiginfo",
    "schedgetattr",
    "schedthread",
    "seccompexec",
    "selecttimeout",
    "semctlrange",
    "sendfilebadf",
    "setidthreadchurn",
    "sharedanonfutexfork",
    "shmrdonly",
    "sigchld",
    "signalexit",
    "signals",
    "sigqueueusr1",
    "sigsuspendxthread",
    "sigwaitalarm",
    "sigwaitthread",
    "sotimeo",
    "splicenetpoll",
    "statfdino",
    "symlinkmknod",
    "sysinfo",
    "sysvmsgwake",
    "sysvshm",
    "termiosflow",
    "threadcommname",
    "threadstatstate",
    "timeextra",
    "tlsswitch",
    "traceexecstop",
    "udplitesock",
    "unicodenorm",
    "usernsmap",
    "vdsosymbols",
    "vforkvmshare",
    "waitexitstorm",
    "waitidspec",
    "waitsiblingsigchld",
    "xsignal",
];

/// Exact materialized Shard 1 probe list: index % 3 == 1 over generic conformance probes.
pub const SHARD_1_PROBES: &[&str] = &[
    "acceptsock",
    "adjtimexstate",
    "altstacktid",
    "bigread",
    "brkheapgrow",
    "cachestatpages",
    "chmodfollowsymlink",
    "clockgetres",
    "clone3args",
    "clone3signalflight",
    "cloneexitsig",
    "clonefsumask",
    "cluster10errno",
    "coredumpbit",
    "credtransition",
    "dirdac",
    "dirrenamecache",
    "dupclosestdin",
    "epolletblockedhup",
    "epolletpipeeof",
    "epollinmemwake",
    "epollpri",
    "etchostnamefile",
    "execfailsurvive",
    "execpermitchurn",
    "execsocket",
    "execvereset",
    "exitstatus127",
    "faultaddr",
    "fcntllease",
    "fcntlowner",
    "fdio",
    "fexecveprobe",
    "fifoforkeof",
    "flocklock",
    "forkexecpthread",
    "forkfpreclaim",
    "forkhighva",
    "forksigwalk",
    "forksplicestage",
    "fsetfl",
    "fsx",
    "futexextra",
    "futexghost",
    "futexprivatewakeexact",
    "futexshare",
    "futexwaiterstates",
    "getrandomflags",
    "getrandomvdsoloop",
    "icmp",
    "iopriovhangup",
    "iouringsqpoll",
    "ipv6sendhoplimit",
    "kernelidentity",
    "killfault",
    "killrt",
    "lchownsymlink",
    "lifecycleflagmatrix",
    "linuxsysinfo",
    "ltpcheckpointexec",
    "mailboxregs",
    "mapfixedfork",
    "mem",
    "memfdsecret",
    "memmap",
    "mknoddevnode",
    "mmapcluster",
    "mmapfile",
    "mmapmunmap",
    "mmaprecl",
    "mmapv8align",
    "mock_network_socket",
    "mqueue",
    "mremapsharedshrink",
    "msgoverflow",
    "mtidlesleep",
    "nativebrk",
    "net",
    "netlink_route",
    "nicepriority",
    "oappendroundtrip",
    "opathfd",
    "openbrokensymlinkcreate",
    "openexcldir",
    "patherrno",
    "pauseeintr",
    "pidfdprocdir",
    "pidnsorphanreap",
    "pidtaskdomain",
    "pipemass",
    "posixtimers",
    "ppollunblock",
    "prctlnnp",
    "preadvwronly",
    "procid",
    "procladder_mixed",
    "procpeerdir",
    "procselfdir",
    "procsignalmask",
    "procstatstate",
    "pselecteintr",
    "ptracekillcont",
    "ptracesignalstop",
    "ptyfionbio",
    "ptyforkreopen",
    "readwronly",
    "recvmsgtrunc",
    "rlimitasdata",
    "rlimitresource",
    "roprotect",
    "rtsigqueueinfo",
    "saresethand",
    "schedparam",
    "scmrightsfds",
    "seekholedata",
    "selfhostnameresolve",
    "semgetnsems",
    "setfsid",
    "setpgidparentgroup",
    "shmlinkat",
    "sigactionresetinfo",
    "siginfo",
    "signalfd4",
    "sigpairrace",
    "sigreenter",
    "sigtimedwaitintr",
    "sigwaitblock",
    "sockbufreuseport",
    "spawnflagmatrix",
    "splicepipe",
    "streamdestmatrix",
    "syncfilerange",
    "sysvmsg",
    "sysvsem",
    "telemetrymap",
    "tgsigqueue",
    "threadrecycle",
    "threadstatuscount",
    "timersettimeabs",
    "tmpfileatime",
    "ttyencoding",
    "udpreuseaddr",
    "unlinkatbindmount",
    "usernswrite",
    "vforkexecthread",
    "vfs_mount_rw",
    "waitidcputime",
    "waitpgid",
    "writevpartial",
    "xthreadsig",
];

/// Exact materialized list of generic conformance probes for shard 2 (index % 3 == 2).
/// Hard-asserted to have exactly 150 sorted unique names.
pub const SHARD_2_PROBES: &[&str] = &[
    "accessx",
    "alarmretval",
    "archiveflagmatrix",
    "bindunixnode",
    "bsd_signal_xlate",
    "capbsetisolation",
    "chmodsetgid",
    "clocknanosleepcpu",
    "clone3exithandled",
    "clonebasic",
    "clonefilesexec",
    "clonestack",
    "connrefused",
    "coredumpfile",
    "ctrel0",
    "dirfdnotdir",
    "dnotify",
    "epollclosenodel",
    "epolletchildhup",
    "epollexclusive",
    "epolloutrearm",
    "epollpwait",
    "eventfdsignalmatrix",
    "execfatalstatus",
    "execpipe",
    "execthreads",
    "exitgroupmainthreads",
    "expectcontinue",
    "fchmoddir",
    "fcntllock",
    "fcntlpipesz",
    "fdstat",
    "fgetflcreate",
    "fifonode",
    "forkaltstack",
    "forkfault",
    "forkfpregs",
    "forkreadexitcow",
    "forksleepfork",
    "forkstackstorm",
    "fsmeta",
    "futexcheckpointexit",
    "futexforkrequeue",
    "futexpilock",
    "futexrealtime",
    "futexsharedalias",
    "futexwakecount",
    "getrandomvdso",
    "getsocknameval",
    "inotifymatrix",
    "iouring",
    "iovecedge",
    "itimer",
    "keydeny",
    "killgroup",
    "killtarget",
    "legacyaio",
    "linkatflag",
    "loopbacksubnet",
    "lutimesym",
    "manythreads",
    "maskfork",
    "memfdcreate",
    "memfdsharedcoherence",
    "mincoreedge",
    "mlock2",
    "mmapdevzero",
    "mmapfileforkwriteback",
    "mmapprivatefiletrack",
    "mmapreuse",
    "mmapzerofill",
    "mprotectexec",
    "mremapgrow",
    "mremapshrink",
    "msyncalign",
    "mtsigrelease",
    "nativeetexecfork",
    "netflagmatrix",
    "netpoll",
    "nofiledefault",
    "odirectory",
    "openat2resolve",
    "openeloop",
    "otmpfileforkexec",
    "pathflagmatrix",
    "pauseinterrupt2",
    "pidnsinitreap",
    "pidnsroot",
    "pipeextra",
    "pipeszcrossend",
    "ppid",
    "prctldumpable",
    "preadspecial",
    "preemptsigstorm",
    "procladder",
    "procladder_mt",
    "procpeermem",
    "procselfpid",
    "procsignalmulti",
    "procstatussig",
    "ptraceattach",
    "ptracesequence",
    "ptracestop",
    "ptyfionread",
    "ptypair",
    "recursionguard",
    "renameexchange",
    "rlimitnofile",
    "rlimitroundtrip",
    "roreadwrite",
    "rtsigqueueinfoxthread",
    "schedaffinitysibling",
    "schedprio",
    "seccompenforce",
    "selectnfds",
    "selfraise",
    "semtimedop",
    "setgroupsroundtrip",
    "shared_buffer_mmap",
    "shmnestedfork",
    "sigbadstack",
    "siglongjmpaltstack",
    "signalfdread",
    "sigpipewrite",
    "sigstopjobcontrol",
    "sigunblockpending",
    "sigwaitmatrix",
    "sockoptdomainproto",
    "splicematrix",
    "spliceunixpoll",
    "symlinkfollow",
    "syscallregpreserve",
    "sysvmsgselect",
    "sysvsemstat",
    "termiosbits",
    "threadbarrier",
    "threadspawn",
    "timeclock",
    "timeschildren",
    "tmpfilewrite",
    "udpconnectunspec",
    "uffdpolicy",
    "usernsisolation",
    "vdsogtod",
    "vforkpid",
    "vmsplicepipe",
    "waitidsiuid",
    "waitrestart",
    "xprocsigign",
    "zerolenio",
];

/// Per-probe additions to the generic container launch request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProbeLaunchPolicy {
    pub security_opt: Option<&'static str>,
    pub cap_add: Option<&'static str>,
}

const SPECIAL_PROBE_LAUNCH_POLICIES: &[(&str, ProbeLaunchPolicy)] = &[
    (
        "clocksettimevdso",
        ProbeLaunchPolicy {
            security_opt: None,
            cap_add: Some("SYS_TIME"),
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
    // The committed Docker result is only `Terminated`, so the old lane's
    // apparent match is not assertion-level evidence.
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
    "pselecteintr",
    "selecttimeout",
    "sigchld",
    "splicenetpoll",
    "timeclock",
    "timeextra",
    "timersettimeabs",
    "waitexitstorm",
    "waitsiblingsigchld",
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
        ("clocksettimevdso", &["SYS_TIME"][..], &[][..]),
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
    assert_eq!(union.len(), 450, "generic shard union must remain complete");

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
