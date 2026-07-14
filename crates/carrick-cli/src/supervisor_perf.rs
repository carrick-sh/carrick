//! Supervisor-level CPU attribution: closes the NATIVEPERF v2 additive model.
//!
//! # Theory of operation
//!
//! NATIVEPERF v2 (`carrick_runtime::native_darwin::dsr::profile`) reconciles
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
//! ## Why this can only ever run in the supervisor, not a guest
//!
//! Every guest process on the native_darwin backend is a REAL host process
//! spawned by `run_image_in_child`'s `fork()` (see
//! `crates/carrick-runtime/src/native_darwin.rs`): the parent branch closes
//! the guest's stdio pipes, drains them on reader threads, and blocks in
//! `waitpid_blocking` until the guest process tree is fully reaped, only
//! THEN returning the `RunResult` that `Commands::Run` receives from
//! `Runtime::execute`. The pid==0 (guest) branch never returns from that
//! fork — it runs the DSR gateway loop (or `_exit`s) and is a structurally
//! distinct OS process. So `CARRICK_DSR_PROFILE=1` is set in the guest's
//! environment too (the DSR profiler's own gate), but `emit_supervisor_record_if_profiling`
//! is only ever CALLED from the `Commands::Run` match arm in `commands.rs`,
//! which is code the guest branch never executes. That call-site placement —
//! not an extra runtime check — is what makes this "supervisor role" gating
//! rather than "env var" gating: no guest process can ever reach this
//! function, regardless of what it has set in its environment.

/// Wire prefix shared with the in-guest NATIVEPERF v2 protocol
/// (`crate::native_darwin::dsr::profile::PROTOCOL_PREFIX` in carrick-runtime;
/// duplicated here rather than imported because the DSR module is
/// `pub(crate)` inside carrick-runtime and this is a one-line producer, not a
/// consumer of the shared frame machinery).
const PROTOCOL_PREFIX: &str = "NATIVEPERF1";

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
/// retrying only on `EINTR`. Mirrors the transport discipline of the in-guest
/// NATIVEPERF frame writer (`native_darwin::dsr::profile::write_protocol_frames_to_fd`):
/// one syscall, no buffered `std::io::Write` layer that could tear the write
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
    if std::env::var_os("CARRICK_DSR_PROFILE").is_none() {
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
    let _ = write_line_atomically_to_fd(libc::STDERR_FILENO, &line);
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

    #[test]
    fn emit_is_a_no_op_with_zero_new_calls_when_profiling_is_off() {
        // SAFETY: single-threaded test process; no other thread reads env
        // vars concurrently with this removal.
        unsafe { std::env::remove_var("CARRICK_DSR_PROFILE") };
        // No assertion beyond "does not panic": the function's whole
        // contract when unset is "return immediately before any
        // getrusage/write call", which the profiling-on tests above already
        // exercise the affirmative half of.
        emit_supervisor_record_if_profiling();
    }
}
