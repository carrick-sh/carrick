//! Env-gated monotonic stamps for the native guest process lifecycle.
//!
//! The PID-preserving host self-reexec (`native_exec_capsule`) pays a fixed
//! per-exec cost that the USDT lifecycle probes can only measure while a
//! DTrace consumer is attached — and an attached consumer inflates exactly the
//! term under study (dyld re-registers the binary's DOF section with the
//! kernel on every exec, and an active session makes that rendezvous much
//! more expensive). These stamps are the untraced instrument: with
//! `CARRICK_EXEC_STAMPS=<path>` set, each phase appends one
//! `EXECSTAMP1|pid=<pid>|phase=<name>|mono_ns=<ns>` line to `<path>`.
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
//! processes line-atomic. Off (one `getenv`) unless the variable is set.

use std::io::Write;

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
    /// Parent image: `wait4` completed a terminal reap of a child.
    WaitReaped,
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
            Self::WaitReaped => "wait-reaped",
        }
    }
}

/// Append one stamp line if `CARRICK_EXEC_STAMPS` names a file. Failures are
/// swallowed: a diagnostic gauge must never turn into a guest-visible error.
pub fn stamp(phase: ExecStampPhase) {
    let Some(path) = std::env::var_os("CARRICK_EXEC_STAMPS") else {
        return;
    };
    let now_ns = monotonic_raw_ns();
    let pid = std::process::id();
    let line = format!(
        "EXECSTAMP1|pid={pid}|phase={}|mono_ns={now_ns}\n",
        phase.name()
    );
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = file.write_all(line.as_bytes());
    }
}

fn monotonic_raw_ns() -> u64 {
    #[cfg(target_os = "macos")]
    let clock = libc::CLOCK_MONOTONIC_RAW;
    #[cfg(not(target_os = "macos"))]
    let clock = libc::CLOCK_MONOTONIC;
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(clock, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
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
        assert!(lines[0].starts_with(&format!("EXECSTAMP1|pid={pid}|phase=pre-exec|mono_ns=")));
        assert!(lines[1].starts_with(&format!("EXECSTAMP1|pid={pid}|phase=main-entry|mono_ns=")));
    }
}
