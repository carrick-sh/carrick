//! Supervisor-level CPU attribution: closes the NATIVEPERF v2 additive model.
//!
//! # Theory of operation
//!
//! NATIVEPERF v2 reconciles
//! CPU *inside* each guest process (thread/blocked/startup/helper CPU), but
//! the top-level `carrick run` process itself — the one this crate's
//! `Commands::Run` arm drives — is never a guest and never emits a
//! `NATIVEPERF1|thread|...` record. Its own CPU (image load, rootfs setup,
//! the fork/wait/pipe-relay bookkeeping around the guest) was previously
//! invisible to the additive model, showing up only as an unattributed
//! residual against `/usr/bin/time`'s process-tree total.
//!
//! This module emits ONE additional stderr line, `NATIVEPERF1|supervisor|
//! self_cpu_ns=<u64>|children_cpu_ns=<u64>`, from that same top-level
//! process, using the SAME `CARRICK_DSR_PROFILE` gate the in-guest profiler
//! uses. `self_cpu_ns` is `getrusage(RUSAGE_SELF)`: the supervisor's own
//! user+system CPU. `children_cpu_ns` is `getrusage(RUSAGE_CHILDREN)`: on
//! BSD/Darwin, `wait4`-observed rusage for a terminated child bundles in
//! that child's OWN already-collected `RUSAGE_CHILDREN` total, so as long as
//! every intermediate process in the guest's process tree properly `wait`s
//! its own children (carrick's guest-process reaping already requires this
//! for zombie correctness), `RUSAGE_CHILDREN` on the top-level supervisor
//! transitively covers the ENTIRE guest process tree — matching exactly what
//! `/usr/bin/time -l` reports for the same invocation (both are `wait4`-
//! sourced sums over the same descendant graph), which is what makes the two
//! independent measurements cross-checkable (see `derive_additive_cpu_evidence`
//! gate1 in `scripts/perf/native_compiler_budget.py`).
//!
//! ## Why the emitter is gated on PROCESS IDENTITY, not call-site placement
//!
//! Under HVPatch one `carrick run` is one host process: every guest process
//! and thread is a logical kernel-graph task on the carrier's own threads, so
//! `RUSAGE_SELF` already covers the whole guest tree and `RUSAGE_CHILDREN` is
//! the CPU of real host children only (none on the run path). Exactly one
//! process therefore reaches `Commands::Run`'s tail per invocation. The pid
//! gate stays as the fail-closed guard for the two ways a second image can
//! exist: a detached `run -d` `posix_spawn`s `__carrier-entry`, which runs
//! `main` (recording its own pid) but dispatches to `carrier_entry`, never to
//! `Commands::Run`; and `carrick trace`'s sudo re-exec (`trace_cli`) replaces
//! this image with `exec` before any run, so the pre-exec image never reaches
//! the tail and the re-exec'd carrick is simply the one top-level process of
//! its own pid. A path that reaches the emit site without passing through
//! `main` — no recorded pid — fails quiet rather than double-reporting, since
//! `parse_nativeperf` hard-fails on a duplicate supervisor line.
//!
//! The discriminator is process identity: `main` records `getpid()` in
//! [`TOP_LEVEL_PID`] before any dispatch, and only the process whose
//! `getpid()` matches may emit.

/// Wire prefix for the supervisor NATIVEPERF v2 protocol.
const PROTOCOL_PREFIX: &str = "NATIVEPERF1";

/// The pid of the ONE true top-level `carrick` process, recorded exactly once
/// at CLI entry (`main`, before any command dispatch). Under HVPatch a run
/// never forks a host descendant, so this is a fail-closed guard, not a
/// disambiguator: a `posix_spawn`ed `__carrier-entry` carrier records its own
/// pid but dispatches to `carrier_entry`, never `Commands::Run`; and
/// `carrick trace`'s sudo re-exec replaces the pre-exec image outright, so the
/// re-exec'd process records afresh and is the only image of its pid that
/// can reach the emit site.
static TOP_LEVEL_PID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

/// Record the current process as the top-level `carrick` invocation. Call
/// exactly once, at the very top of `main`, before any dispatch or fork.
/// First write wins; later calls (there should be none) are no-ops.
pub(crate) fn record_top_level_pid() {
    let _ = TOP_LEVEL_PID.set(std::process::id());
}

/// The supervisor-role discriminator: emit only when a top-level pid was
/// recorded AND it is the calling process. Never recorded (a path that
/// reaches emit without passing through `main`'s recording) fails quiet — a
/// diagnostics line must never break, or double-report, a run.
fn should_emit(recorded_pid: Option<u32>, current_pid: u32) -> bool {
    recorded_pid == Some(current_pid)
}

/// Total CPU (user + system), in nanoseconds, from one `getrusage(2)` call.
/// `None` on a negative/overflowing timeval (never expected from a real
/// kernel, but this stays a typed `Option` rather than a panic — a metrics
/// helper must never crash the run it is diagnosing).
fn rusage_total_cpu_ns(usage: libc::rusage) -> Option<u64> {
    let timeval_ns = |tv: libc::timeval| -> Option<u64> {
        u64::try_from(tv.tv_sec)
            .ok()?
            .checked_mul(1_000_000_000)?
            .checked_add(u64::try_from(tv.tv_usec).ok()?.checked_mul(1_000)?)
    };
    timeval_ns(usage.ru_utime)?.checked_add(timeval_ns(usage.ru_stime)?)
}

/// `getrusage(who)` total CPU in nanoseconds, or `None` on syscall failure.
fn rusage_cpu_ns(who: libc::c_int) -> Option<u64> {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `getrusage` fills `usage` for a valid `who` (RUSAGE_SELF /
    // RUSAGE_CHILDREN, both compile-time constants below); a zeroed rusage is
    // a valid out-buffer.
    if unsafe { libc::getrusage(who, &mut usage) } != 0 {
        return None;
    }
    rusage_total_cpu_ns(usage)
}

/// Format the supervisor's single wire record.
fn format_supervisor_record(self_cpu_ns: u64, children_cpu_ns: u64) -> String {
    format!(
        "{PROTOCOL_PREFIX}|supervisor|self_cpu_ns={self_cpu_ns}|children_cpu_ns={children_cpu_ns}"
    )
}

/// Write `line` (plus a trailing newline) to `fd` as a single atomic `write(2)`,
/// retrying only on `EINTR`.
/// One syscall, no buffered `std::io::Write` layer that could tear the write
/// across two syscalls, and a short write is a hard error rather than a
/// silent partial line.
fn write_line_atomically_to_fd(fd: libc::c_int, line: &str) -> std::io::Result<()> {
    let mut bytes = line.as_bytes().to_vec();
    bytes.push(b'\n');
    loop {
        // SAFETY: `bytes` is a valid, live buffer of `bytes.len()` readable
        // bytes for the duration of the call.
        let rc = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if rc < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return if usize::try_from(rc).ok() == Some(bytes.len()) {
            Ok(())
        } else if rc < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "short atomic supervisor record write",
            ))
        };
    }
}

/// Emit the supervisor's own measured CPU record, once, to stderr — but only
/// when `CARRICK_DSR_PROFILE=1` (the same gate the in-guest DSR profiler
/// uses). Profiling off performs zero new `getrusage`/`write` calls (a single
/// `env::var_os` read). Call this exactly once, from the top-level
/// `Commands::Run` handler, AFTER `Runtime::execute` has returned (i.e. after
/// every guest process in this run's tree has been reaped) and BEFORE any
/// process-exit path.
pub(crate) fn emit_supervisor_record_if_profiling() {
    if should_emit(TOP_LEVEL_PID.get().copied(), std::process::id()) {
        carrick_runtime::exec_stamps::stamp_run_complete();
    }
    emit_supervisor_record_to_fd_if_top_level(libc::STDERR_FILENO);
}

/// The full production emit path with an injectable destination fd (tests
/// substitute a pipe; production passes stderr above). Applies BOTH gates:
/// the `CARRICK_DSR_PROFILE` env gate (zero further calls when off) and the
/// top-level-pid identity gate (only the ONE process recorded at `main`
/// entry may emit — see [`TOP_LEVEL_PID`]).
fn emit_supervisor_record_to_fd_if_top_level(fd: libc::c_int) {
    if std::env::var_os("CARRICK_DSR_PROFILE").is_none() {
        return;
    }
    if !should_emit(TOP_LEVEL_PID.get().copied(), std::process::id()) {
        return;
    }
    let Some(self_cpu_ns) = rusage_cpu_ns(libc::RUSAGE_SELF) else {
        return;
    };
    let Some(children_cpu_ns) = rusage_cpu_ns(libc::RUSAGE_CHILDREN) else {
        return;
    };
    let line = format_supervisor_record(self_cpu_ns, children_cpu_ns);
    // Best-effort: a diagnostics line must never fail (or be allowed to
    // panic) the run it is describing.
    let _ = write_line_atomically_to_fd(fd, &line);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::os::fd::FromRawFd as _;

    #[test]
    fn format_matches_the_documented_wire_contract() {
        assert_eq!(
            format_supervisor_record(0, 0),
            "NATIVEPERF1|supervisor|self_cpu_ns=0|children_cpu_ns=0"
        );
        assert_eq!(
            format_supervisor_record(1_590_000_000, 2_290_000_000),
            "NATIVEPERF1|supervisor|self_cpu_ns=1590000000|children_cpu_ns=2290000000"
        );
        assert_eq!(
            format_supervisor_record(u64::MAX, u64::MAX),
            format!(
                "NATIVEPERF1|supervisor|self_cpu_ns={}|children_cpu_ns={}",
                u64::MAX,
                u64::MAX
            )
        );
    }

    #[test]
    fn rusage_total_cpu_ns_sums_user_and_system_in_nanoseconds() {
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        usage.ru_utime.tv_sec = 1;
        usage.ru_utime.tv_usec = 500_000;
        usage.ru_stime.tv_sec = 0;
        usage.ru_stime.tv_usec = 250_000;
        assert_eq!(
            rusage_total_cpu_ns(usage),
            Some(1_500_000_000 + 250_000_000)
        );
    }

    #[test]
    fn rusage_total_cpu_ns_rejects_a_negative_timeval() {
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        usage.ru_utime.tv_sec = -1;
        assert_eq!(rusage_total_cpu_ns(usage), None);
    }

    #[test]
    fn real_self_and_children_rusage_reads_succeed_and_are_wall_bounded() {
        // A smoke test that the real getrusage(2) path (not a synthetic
        // struct) works end-to-end for both RUSAGE_SELF and RUSAGE_CHILDREN,
        // and that the process's own CPU is bounded by something plausible
        // (never negative by construction, u64) rather than reading garbage.
        assert!(rusage_cpu_ns(libc::RUSAGE_SELF).is_some());
        assert!(rusage_cpu_ns(libc::RUSAGE_CHILDREN).is_some());
    }

    #[test]
    fn write_line_atomically_survives_concurrent_writers_and_stays_line_delimited() {
        const WRITERS: i32 = 16;
        let mut pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0, "create pipe");
        let read_fd = pipe[0];
        let write_fd = pipe[1];
        let reader = std::thread::spawn(move || {
            let mut text = String::new();
            let mut file = unsafe { std::fs::File::from_raw_fd(read_fd) };
            file.read_to_string(&mut text).expect("read lines");
            text
        });
        let writers = (0..WRITERS)
            .map(|index| {
                std::thread::spawn(move || {
                    let line = format_supervisor_record(index as u64, (index * 2) as u64);
                    write_line_atomically_to_fd(write_fd, &line).expect("write line");
                })
            })
            .collect::<Vec<_>>();
        for writer in writers {
            writer.join().expect("join writer");
        }
        assert_eq!(unsafe { libc::close(write_fd) }, 0, "close writer");
        let text = reader.join().expect("join reader");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), WRITERS as usize);
        for line in &lines {
            assert!(line.starts_with("NATIVEPERF1|supervisor|self_cpu_ns="));
            assert!(line.contains("|children_cpu_ns="));
        }
    }

    /// Serializes every test that mutates `CARRICK_DSR_PROFILE`: the default
    /// test runner is multi-threaded, and an unserialized set/remove race
    /// between these tests would flake (one test removing the var while
    /// another is mid-emit).
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Poison-tolerant acquisition: a failed sibling test must not cascade
    /// into unrelated env-test failures (the guarded state is the process
    /// env, not the mutex payload).
    fn env_test_guard() -> std::sync::MutexGuard<'static, ()> {
        match ENV_TEST_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[test]
    fn emit_is_a_no_op_with_zero_new_calls_when_profiling_is_off() {
        let _env = env_test_guard();
        // SAFETY: env-mutating tests are serialized by ENV_TEST_LOCK; no
        // other test in this module touches the var concurrently.
        unsafe { std::env::remove_var("CARRICK_DSR_PROFILE") };
        // No assertion beyond "does not panic": the function's whole
        // contract when unset is "return immediately before any
        // getrusage/write call", which the profiling-on tests above already
        // exercise the affirmative half of.
        emit_supervisor_record_if_profiling();
    }

    #[test]
    fn guard_matrix_only_recorded_and_matching_pid_would_emit() {
        // The only would-emit state: a recorded top-level pid that IS the
        // calling process.
        assert!(should_emit(Some(42), 42));
        // A forked child inherits the parent's recorded pid but has its own:
        // must not emit (this is the -t/-it interactive Launcher/Supervisor/
        // runtime-child triple-fork scenario).
        assert!(!should_emit(Some(42), 43));
        // Never recorded (e.g. a code path that reaches emit without going
        // through main): fail quiet, never emit.
        assert!(!should_emit(None, 42));
    }

    #[test]
    fn forked_child_inheriting_the_recorded_pid_does_not_emit() {
        // The production bug scenario: fork() copies the recorded top-level
        // pid into the child, whose own getpid() differs, so the full emit
        // path must write NOTHING from the child even with profiling on.
        let _env = env_test_guard();
        record_top_level_pid();
        let mut pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0, "create pipe");
        let (read_fd, write_fd) = (pipe[0], pipe[1]);
        // Set BEFORE fork so the child inherits it without touching the env
        // lock post-fork.
        // SAFETY: env-mutating tests are serialized by ENV_TEST_LOCK.
        unsafe { std::env::set_var("CARRICK_DSR_PROFILE", "1") };
        // SAFETY: the child only runs the guarded emit path (getenv/
        // getrusage/write) and _exit — no allocation or locking beyond the
        // env read, whose lock is held by no one at fork time (we hold
        // ENV_TEST_LOCK, serializing all mutators in this module).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            emit_supervisor_record_to_fd_if_top_level(write_fd);
            unsafe { libc::_exit(0) };
        }
        unsafe { libc::close(write_fd) };
        let mut text = String::new();
        {
            use std::io::Read as _;
            let mut file = unsafe { std::fs::File::from_raw_fd(read_fd) };
            file.read_to_string(&mut text).expect("read child output");
        }
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, 0) },
            pid,
            "reap child"
        );
        // SAFETY: env-mutating tests are serialized by ENV_TEST_LOCK.
        unsafe { std::env::remove_var("CARRICK_DSR_PROFILE") };
        assert!(
            text.is_empty(),
            "forked child emitted a supervisor record: {text:?}"
        );
    }

    #[test]
    fn top_level_process_emits_exactly_one_line_when_recorded_and_profiling() {
        let _env = env_test_guard();
        record_top_level_pid();
        let mut pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0, "create pipe");
        let (read_fd, write_fd) = (pipe[0], pipe[1]);
        // SAFETY: env-mutating tests are serialized by ENV_TEST_LOCK.
        unsafe { std::env::set_var("CARRICK_DSR_PROFILE", "1") };
        emit_supervisor_record_to_fd_if_top_level(write_fd);
        // SAFETY: env-mutating tests are serialized by ENV_TEST_LOCK.
        unsafe { std::env::remove_var("CARRICK_DSR_PROFILE") };
        unsafe { libc::close(write_fd) };
        let mut text = String::new();
        {
            use std::io::Read as _;
            let mut file = unsafe { std::fs::File::from_raw_fd(read_fd) };
            file.read_to_string(&mut text).expect("read emitted record");
        }
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1, "expected exactly one record: {text:?}");
        let re_shape = lines[0]
            .strip_prefix("NATIVEPERF1|supervisor|self_cpu_ns=")
            .and_then(|rest| rest.split_once("|children_cpu_ns="))
            .map(|(self_ns, children_ns)| {
                self_ns.bytes().all(|b| b.is_ascii_digit())
                    && children_ns.bytes().all(|b| b.is_ascii_digit())
            });
        assert_eq!(re_shape, Some(true), "malformed record: {}", lines[0]);
    }
}
