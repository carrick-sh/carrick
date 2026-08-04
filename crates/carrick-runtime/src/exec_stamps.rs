//! Env-gated monotonic stamps for the native guest process lifecycle.
//!
//! The PID-preserving host self-reexec (`native_exec_capsule`) pays a fixed
//! per-exec cost that the USDT lifecycle probes can only measure while a
//! DTrace consumer is attached — and an attached consumer inflates exactly the
//! term under study (dyld re-registers the binary's DOF section with the
//! kernel on every exec, and an active session makes that rendezvous much
//! more expensive). These stamps are the untraced instrument: with
//! `CARRICK_EXEC_STAMPS=<path>` set, each phase appends one typed
//! `EXECSTAMP2` line to `<path>`. Every record carries monotonic wall time,
//! cumulative process CPU, and cumulative calling-thread CPU. Fork-parent and
//! reap records additionally name the exact child; reap records carry the
//! child's exact `wait4` rusage.
//!
//! Beyond the exec chain itself, the gauge covers the surrounding
//! fork/exit/reap lifecycle (the 2026-08-03 exec-window attribution needed
//! the wall between one guest exec and the next fully partitioned): the
//! parent's fork dispatch (`CloneEnter`/`CloneParentReturn`), the child's
//! first post-fork instruction (`ForkChildStart`), the exiting image's
//! teardown (`ExitBegin`/`PreHostExit`), and the parent's terminal reap
//! (`WaitReaped`). A `pid`'s lines therefore interleave across images and
//! roles; consumers must key on (pid, phase) pairs, not assume one chain per
//! pid.
//!
//! `CLOCK_MONOTONIC_RAW` is boot-stable and survives `execve`, so deltas
//! between the pre-exec image and the post-exec image of the same pid are
//! meaningful; a single `O_APPEND` write per stamp keeps concurrent guest
//! processes line-atomic. Each lifecycle seam is off after one `getenv` unless
//! the variable is set.

use std::os::fd::AsRawFd as _;

const VALID_MONOTONIC: u8 = 1;
const VALID_PROCESS_CPU: u8 = 2;
const VALID_THREAD_CPU: u8 = 4;
const VALID_RELATED_CPU: u8 = 8;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RelatedProcess {
    pid: u32,
    link_id: u64,
    status: i32,
    user_ns: u64,
    system_ns: u64,
    usage_valid: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct StampMetrics {
    valid: u8,
    mono_ns: u64,
    process_user_ns: u64,
    process_system_ns: u64,
    thread_user_ns: u64,
    thread_system_ns: u64,
}

/// Ordered phases of one guest process lifecycle under the native backend:
/// fork, execve chain, exit, reap. An enum rather than free strings so the
/// producer and any parser agree on the vocabulary (typed-domain rule: no
/// stringly-typed phase names).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecStampPhase {
    /// Parent image: guest fork/clone dispatch entered (`handle_native_fork`).
    CloneEnter,
    /// Child image: first stamp after `fork(2)` returned 0, before any
    /// post-fork runtime repair.
    ForkChildStart,
    /// Parent image: fork dispatch returns the child pid to the guest.
    CloneParentReturn,
    /// Old image: guest `execve` dispatch entered (fork-child path).
    ExecveDispatch,
    /// Old image: capsule snapshot/preparation begins.
    CapsulePrepare,
    /// Old image: immediately before the host `execve` of the carrick binary.
    PreExec,
    /// New image: first statement of `main` (kernel exec + dyld + static
    /// initializers are the delta from `PreExec`).
    MainEntry,
    /// New image: process environment configured and USDT probes registered.
    ProbesReady,
    /// New image: private resume entry reached (CLI dispatch done).
    ResumeEntry,
    /// New image: dispatcher rebuilt and fd table restored.
    DispatcherReady,
    /// New image: replacement guest image mapped (prepared-image validate +
    /// map, or the legacy reload).
    ImageMapped,
    /// New image: process runtime fully rebuilt (shared-translation store,
    /// signal plumbing, thread runtime); the next work is the thread
    /// translator and the entry block's translation.
    RuntimeReady,
    /// Exiting image: `exit_group` (or last-thread `exit`) dispatch reached;
    /// everything from here to `PreHostExit` is carrick's own process
    /// teardown (profile finalize, censuses, exit-status publication).
    ExitBegin,
    /// Exiting image: immediately before the host `_exit(2)` of a forked
    /// guest child. The delta to the parent's `WaitReaped` is host kernel
    /// address-space teardown plus parent wake latency.
    PreHostExit,
    /// The native runtime has completed process-exit finalization and is
    /// returning the guest status to its caller. This precedes Rust drop/unwind
    /// work and exists on every normal native `ProcessExit` route.
    RuntimeReturn,
    /// Parent image: `wait4` completed a terminal reap of a child.
    WaitReaped,
    /// Top-level Carrick supervisor after the complete guest tree was reaped.
    /// Process counters describe the supervisor; related counters carry its
    /// transitive `RUSAGE_CHILDREN` total.
    RunComplete,
}

impl ExecStampPhase {
    fn name(self) -> &'static str {
        match self {
            Self::CloneEnter => "clone-enter",
            Self::ForkChildStart => "fork-child-start",
            Self::CloneParentReturn => "clone-parent-return",
            Self::ExecveDispatch => "execve-dispatch",
            Self::CapsulePrepare => "capsule-prepare",
            Self::PreExec => "pre-exec",
            Self::MainEntry => "main-entry",
            Self::ProbesReady => "probes-ready",
            Self::ResumeEntry => "resume-entry",
            Self::DispatcherReady => "dispatcher-ready",
            Self::ImageMapped => "image-mapped",
            Self::RuntimeReady => "runtime-ready",
            Self::ExitBegin => "exit-begin",
            Self::PreHostExit => "pre-host-exit",
            Self::RuntimeReturn => "runtime-return",
            Self::WaitReaped => "wait-reaped",
            Self::RunComplete => "run-complete",
        }
    }
}

static FORK_LINK_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Allocate a nonzero fork-attempt identity in this host process. The key is
/// `(parent_pid, link_id)`: a fork child inherits the sequence and may later
/// allocate the same numeric id under its different PID without ambiguity.
pub fn next_fork_link_id() -> u64 {
    FORK_LINK_SEQUENCE
        .fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |value| value.checked_add(1),
        )
        .ok()
        .and_then(|previous| previous.checked_add(1))
        .unwrap_or(0)
}

/// Append one stamp line if `CARRICK_EXEC_STAMPS` names a file. Failures are
/// swallowed: a diagnostic gauge must never turn into a guest-visible error.
pub fn stamp(phase: ExecStampPhase) {
    stamp_record(phase, RelatedProcess::default());
}

/// Stamp a fork-side phase and bind it to the other host process. The child
/// PID is known only after `fork(2)`, so `CloneEnter` remains unbound while
/// `ForkChildStart` and `CloneParentReturn` name one another exactly.
pub fn stamp_fork(phase: ExecStampPhase, link_id: u64, related_pid: u32) {
    stamp_record(
        phase,
        RelatedProcess {
            pid: related_pid,
            link_id,
            ..RelatedProcess::default()
        },
    );
}

/// Stamp one terminal reap with the exact host child and the `wait4(2)` rusage
/// returned for it. Darwin includes the child's descendants in this rusage;
/// the census therefore uses it as exact total-child evidence and computes a
/// post-`PreHostExit` residual only for leaf children.
pub fn stamp_wait_reaped(child_pid: u32, status: i32, usage: &libc::rusage) {
    let (user_ns, system_ns, usage_valid) = match rusage_ns(usage) {
        Some((user_ns, system_ns)) => (user_ns, system_ns, true),
        None => (0, 0, false),
    };
    stamp_record(
        ExecStampPhase::WaitReaped,
        RelatedProcess {
            pid: child_pid,
            status,
            user_ns,
            system_ns,
            usage_valid,
            ..RelatedProcess::default()
        },
    );
}

/// Stamp the top-level run's exact transitive child CPU denominator after all
/// guests have been reaped. The CLI performs the top-level PID identity check
/// before calling this function.
pub fn stamp_run_complete() {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `getrusage` fills a correctly sized out-buffer for
    // RUSAGE_CHILDREN. A failure remains an invalid related-usage bit that the
    // census rejects.
    let usage_valid = unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut usage) } == 0;
    let (user_ns, system_ns, usage_valid) = if usage_valid {
        match rusage_ns(&usage) {
            Some((user_ns, system_ns)) => (user_ns, system_ns, true),
            None => (0, 0, false),
        }
    } else {
        (0, 0, false)
    };
    stamp_record(
        ExecStampPhase::RunComplete,
        RelatedProcess {
            user_ns,
            system_ns,
            usage_valid,
            ..RelatedProcess::default()
        },
    );
}

fn stamp_record(phase: ExecStampPhase, related: RelatedProcess) {
    let Some(path) = std::env::var_os("CARRICK_EXEC_STAMPS") else {
        return;
    };
    let metrics = capture_metrics();
    let pid = std::process::id();
    let line = format!(
        "EXECSTAMP2|pid={pid}|phase={}|valid={}|mono_ns={}|process_user_ns={}|\
         process_system_ns={}|thread_user_ns={}|thread_system_ns={}|related_pid={}|\
         link_id={}|related_status={}|related_user_ns={}|related_system_ns={}\n",
        phase.name(),
        metrics.valid
            | if related.usage_valid {
                VALID_RELATED_CPU
            } else {
                0
            },
        metrics.mono_ns,
        metrics.process_user_ns,
        metrics.process_system_ns,
        metrics.thread_user_ns,
        metrics.thread_system_ns,
        related.pid,
        related.link_id,
        related.status,
        related.user_ns,
        related.system_ns,
    );
    if let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        write_one_append(file.as_raw_fd(), line.as_bytes());
    }
}

fn capture_metrics() -> StampMetrics {
    let mut metrics = StampMetrics::default();
    if let Some(mono_ns) = monotonic_raw_ns() {
        metrics.valid |= VALID_MONOTONIC;
        metrics.mono_ns = mono_ns;
    }
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `getrusage` fills a correctly sized out-buffer for RUSAGE_SELF.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } == 0
        && let Some((user_ns, system_ns)) = rusage_ns(&usage)
    {
        metrics.valid |= VALID_PROCESS_CPU;
        metrics.process_user_ns = user_ns;
        metrics.process_system_ns = system_ns;
    }
    if let Some((user_us, system_us)) = crate::host_proc::self_thread_cpu_us()
        && let (Some(user_ns), Some(system_ns)) =
            (user_us.checked_mul(1_000), system_us.checked_mul(1_000))
    {
        metrics.valid |= VALID_THREAD_CPU;
        metrics.thread_user_ns = user_ns;
        metrics.thread_system_ns = system_ns;
    }
    metrics
}

fn rusage_ns(usage: &libc::rusage) -> Option<(u64, u64)> {
    fn timeval_ns(value: libc::timeval) -> Option<u64> {
        u64::try_from(value.tv_sec)
            .ok()?
            .checked_mul(1_000_000_000)?
            .checked_add(u64::try_from(value.tv_usec).ok()?.checked_mul(1_000)?)
    }
    Some((timeval_ns(usage.ru_utime)?, timeval_ns(usage.ru_stime)?))
}

fn write_one_append(fd: libc::c_int, bytes: &[u8]) {
    loop {
        // SAFETY: `bytes` is a valid readable buffer for this call. A regular
        // file opened O_APPEND serializes the offset selection and this one
        // write as one append operation.
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        }
        // A short/error write deliberately leaves an invalid/truncated export
        // for the census to reject. Never issue a second fragment that could
        // interleave with another process's record.
        return;
    }
}

fn monotonic_raw_ns() -> Option<u64> {
    #[cfg(target_os = "macos")]
    let clock = libc::CLOCK_MONOTONIC_RAW;
    #[cfg(not(target_os = "macos"))]
    let clock = libc::CLOCK_MONOTONIC;
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(clock, &mut ts) } != 0 {
        return None;
    }
    u64::try_from(ts.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(ts.tv_nsec).ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_appends_one_line_per_phase_when_gated() {
        let dir = tempfile::tempdir().expect("stamp tempdir");
        let path = dir.path().join("stamps.txt");
        // SAFETY: env mutation is process-global; this test is the only
        // writer of this variable in the suite and restores it before
        // returning, and the runtime suite runs single-threaded
        // (RUST_TEST_THREADS=1 per the `just test` recipe).
        unsafe { std::env::set_var("CARRICK_EXEC_STAMPS", &path) };
        stamp(ExecStampPhase::PreExec);
        stamp(ExecStampPhase::MainEntry);
        // SAFETY: as above.
        unsafe { std::env::remove_var("CARRICK_EXEC_STAMPS") };
        stamp(ExecStampPhase::RuntimeReady);
        let contents = std::fs::read_to_string(&path).expect("stamp file");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "ungated stamp must not write: {contents}");
        let pid = std::process::id();
        assert!(lines[0].starts_with(&format!(
            "EXECSTAMP2|pid={pid}|phase=pre-exec|valid=7|mono_ns="
        )));
        assert!(lines[1].starts_with(&format!(
            "EXECSTAMP2|pid={pid}|phase=main-entry|valid=7|mono_ns="
        )));
        for line in lines {
            assert!(line.contains("|process_user_ns="), "{line}");
            assert!(line.contains("|process_system_ns="), "{line}");
            assert!(line.contains("|thread_user_ns="), "{line}");
            assert!(line.contains("|thread_system_ns="), "{line}");
            assert!(line.ends_with(
                "|related_pid=0|link_id=0|related_status=0|related_user_ns=0|related_system_ns=0"
            ));
        }
    }

    #[test]
    fn related_and_reap_records_bind_the_exact_child() {
        let dir = tempfile::tempdir().expect("stamp tempdir");
        let path = dir.path().join("stamps.txt");
        // SAFETY: this suite is serialized by the repository's test recipe.
        unsafe { std::env::set_var("CARRICK_EXEC_STAMPS", &path) };
        stamp_fork(ExecStampPhase::CloneParentReturn, 17, 4242);
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        usage.ru_utime.tv_sec = 1;
        usage.ru_utime.tv_usec = 2;
        usage.ru_stime.tv_sec = 3;
        usage.ru_stime.tv_usec = 4;
        stamp_wait_reaped(4242, 7 << 8, &usage);
        // SAFETY: as above.
        unsafe { std::env::remove_var("CARRICK_EXEC_STAMPS") };

        let contents = std::fs::read_to_string(&path).expect("stamp file");
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "{contents}");
        assert!(lines[0].contains("|phase=clone-parent-return|valid=7|"));
        assert!(lines[0].ends_with(
            "|related_pid=4242|link_id=17|related_status=0|related_user_ns=0|related_system_ns=0"
        ));
        assert!(lines[1].contains("|phase=wait-reaped|valid=15|"));
        assert!(lines[1].ends_with(
            "|related_pid=4242|link_id=0|related_status=1792|related_user_ns=1000002000|related_system_ns=3000004000"
        ));
    }

    #[test]
    fn run_completion_carries_the_transitive_child_cpu_denominator() {
        let dir = tempfile::tempdir().expect("stamp tempdir");
        let path = dir.path().join("stamps.txt");
        // SAFETY: this suite is serialized by the repository's test recipe.
        unsafe { std::env::set_var("CARRICK_EXEC_STAMPS", &path) };
        stamp_run_complete();
        // SAFETY: as above.
        unsafe { std::env::remove_var("CARRICK_EXEC_STAMPS") };
        let contents = std::fs::read_to_string(&path).expect("stamp file");
        let line = contents.trim_end();
        assert!(line.contains("|phase=run-complete|valid=15|"), "{line}");
        assert!(line.contains("|related_pid=0|link_id=0|related_status=0|"));
    }
}
