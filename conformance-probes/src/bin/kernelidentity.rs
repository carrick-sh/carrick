//! Cohesive Linux task-identity probe for Carrick's in-process kernel lane.
//!
//! The probe reports relationships, not run-specific PID values. It covers the
//! leader PID/TID, `/proc/self/stat`, process groups and sessions; a forked
//! descendant; self and cross-task `kill`/`tgkill`; all four `kill(2)` selector
//! shapes; process-group wait; and identity/disposition behavior across exec.

use conformance_probes::{errno, install_handler, install_ign, report};
use std::ffi::CString;
use std::sync::atomic::{AtomicU32, Ordering};

const SIG_USR1: u32 = 1 << 0;
const SIG_USR2: u32 = 1 << 1;
const SIG_TERM: u32 = 1 << 2;
const SIG_CHLD: u32 = 1 << 3;
const ALL_CHILD_SIGNALS: u32 = SIG_USR1 | SIG_USR2 | SIG_TERM | SIG_CHLD;

static CHILD_SIGNALS: AtomicU32 = AtomicU32::new(0);

extern "C" fn child_signal(signum: libc::c_int) {
    let bit = match signum {
        libc::SIGUSR1 => SIG_USR1,
        libc::SIGUSR2 => SIG_USR2,
        libc::SIGTERM => SIG_TERM,
        libc::SIGCHLD => SIG_CHLD,
        _ => 0,
    };
    CHILD_SIGNALS.fetch_or(bit, Ordering::SeqCst);
}

#[derive(Clone, Copy)]
struct ProcIdentity {
    pid: i32,
    ppid: i32,
    pgrp: i32,
    session: i32,
}

fn proc_identity() -> Option<ProcIdentity> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let rparen = stat.rfind(')')?;
    let mut fields = stat[rparen + 1..].split_whitespace();
    let _state = fields.next()?;
    Some(ProcIdentity {
        ppid: fields.next()?.parse().ok()?,
        pgrp: fields.next()?.parse().ok()?,
        session: fields.next()?.parse().ok()?,
        pid: stat[..stat.find(' ')?].parse().ok()?,
    })
}

fn gettid() -> i32 {
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

fn exact_write(fd: i32, value: u64) -> bool {
    let bytes = value.to_ne_bytes();
    unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) == bytes.len() as isize }
}

fn exact_read(fd: i32) -> Option<u64> {
    let mut bytes = [0_u8; 8];
    let got = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
    (got == bytes.len() as isize).then(|| u64::from_ne_bytes(bytes))
}

fn make_pipe() -> Option<[i32; 2]> {
    let mut fds = [-1_i32; 2];
    (unsafe { libc::pipe(fds.as_mut_ptr()) } == 0).then_some(fds)
}

fn wait_exited(pid: i32) -> Option<i32> {
    let mut status = 0_i32;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    (waited == pid && libc::WIFEXITED(status)).then(|| libc::WEXITSTATUS(status))
}

fn query_disposition(signum: i32) -> Option<libc::sighandler_t> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    (unsafe { libc::sigaction(signum, std::ptr::null(), &mut action) } == 0)
        .then_some(action.sa_sigaction)
}

fn child_identity_and_signal_case(parent_pid: i32, parent_sid: i32) -> (u64, u64, bool, bool) {
    let Some(ready) = make_pipe() else {
        return (0, 0, false, false);
    };
    let Some(result) = make_pipe() else {
        return (0, 0, false, false);
    };
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::close(ready[0]);
            libc::close(result[0]);
        }
        CHILD_SIGNALS.store(0, Ordering::SeqCst);
        let handlers = [libc::SIGUSR1, libc::SIGUSR2, libc::SIGTERM, libc::SIGCHLD]
            .into_iter()
            .all(|signum| unsafe { install_handler(signum, child_signal, 0) });
        let group_created = unsafe { libc::setpgid(0, 0) } == 0;
        let pid = unsafe { libc::getpid() };
        let tid = gettid();
        let ppid = unsafe { libc::getppid() };
        let pgrp = unsafe { libc::getpgrp() };
        let sid = unsafe { libc::getsid(0) };
        let proc = proc_identity();
        let ready_ok = exact_write(ready[1], 1);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while CHILD_SIGNALS.load(Ordering::SeqCst) != ALL_CHILD_SIGNALS
            && std::time::Instant::now() < deadline
        {
            unsafe { libc::sched_yield() };
        }
        let mut bits = 0_u64;
        bits |= u64::from(handlers && group_created && ready_ok) << 0;
        bits |= u64::from(pid > parent_pid && pid < 64) << 1;
        bits |= u64::from(tid == pid && ppid == parent_pid) << 2;
        bits |= u64::from(pgrp == pid && sid == parent_sid) << 3;
        bits |= u64::from(proc.is_some_and(|stat| {
            stat.pid == pid && stat.ppid == ppid && stat.pgrp == pgrp && stat.session == sid
        })) << 4;
        bits |= u64::from(CHILD_SIGNALS.load(Ordering::SeqCst) == ALL_CHILD_SIGNALS) << 5;
        bits |= u64::from(tid == pid) << 6;
        bits |= u64::from(ppid == parent_pid) << 7;
        let _ = exact_write(result[1], bits);
        unsafe { libc::_exit(0) }
    }
    unsafe {
        libc::close(ready[1]);
        libc::close(result[1]);
    }
    if child <= 0 || exact_read(ready[0]) != Some(1) {
        return (0, 0, false, false);
    }
    // Exercise the broadcast encoding and the `killpg(1)` alias while a known
    // eligible child is live, so both Linux arms deterministically succeed.
    let broadcast_live = unsafe { libc::kill(-1, 0) } == 0;
    let negative_pgid_one_live = unsafe { libc::killpg(1, 0) } == 0;
    let kill_zero = unsafe { libc::kill(child, 0) } == 0;
    let kill_sent = unsafe { libc::kill(child, libc::SIGUSR1) } == 0;
    let tgkill_zero = unsafe { libc::syscall(libc::SYS_tgkill, child, child, 0) } == 0;
    let tgkill_sent = unsafe { libc::syscall(libc::SYS_tgkill, child, child, libc::SIGUSR2) } == 0;
    let group_sent = unsafe { libc::kill(-child, libc::SIGTERM) } == 0;
    // SIGCHLD is the historical early-xsig path: it must land in the target's
    // kernel queue without using the guest pid as an xsig host key or nudge.
    let xsig_shape_sent = unsafe { libc::kill(child, libc::SIGCHLD) } == 0;
    let bits = exact_read(result[0]).unwrap_or(0);
    let waited_group = {
        let mut status = 0_i32;
        let waited = unsafe { libc::waitpid(-child, &mut status, 0) };
        waited == child && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    };
    let mut call_bits = 0_u64;
    call_bits |= u64::from(kill_zero) << 0;
    call_bits |= u64::from(kill_sent) << 1;
    call_bits |= u64::from(tgkill_zero) << 2;
    call_bits |= u64::from(tgkill_sent) << 3;
    call_bits |= u64::from(group_sent) << 4;
    call_bits |= u64::from(xsig_shape_sent) << 5;
    call_bits |= u64::from(waited_group) << 6;
    (bits, call_bits, broadcast_live, negative_pgid_one_live)
}

fn session_case() -> bool {
    let Some(result) = make_pipe() else {
        return false;
    };
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe { libc::close(result[0]) };
        let pid = unsafe { libc::getpid() };
        let created = unsafe { libc::setsid() } == pid;
        let pgrp = unsafe { libc::getpgrp() };
        let sid = unsafe { libc::getsid(0) };
        let proc_matches = proc_identity()
            .is_some_and(|stat| stat.pid == pid && stat.pgrp == pid && stat.session == pid);
        let _ = exact_write(
            result[1],
            u64::from(created && pgrp == pid && sid == pid && proc_matches),
        );
        unsafe { libc::_exit(0) }
    }
    unsafe { libc::close(result[1]) };
    let matched = exact_read(result[0]) == Some(1);
    matched && wait_exited(child) == Some(0)
}

fn exec_stage2(args: &[String]) -> ! {
    let parsed = (|| {
        let expected_pid = args.get(2)?.parse::<i32>().ok()?;
        let expected_pgrp = args.get(3)?.parse::<i32>().ok()?;
        let expected_sid = args.get(4)?.parse::<i32>().ok()?;
        let fd = args.get(5)?.parse::<i32>().ok()?;
        Some((expected_pid, expected_pgrp, expected_sid, fd))
    })();
    let Some((expected_pid, expected_pgrp, expected_sid, fd)) = parsed else {
        unsafe { libc::_exit(3) }
    };
    let pid = unsafe { libc::getpid() };
    let tid = gettid();
    let pgrp = unsafe { libc::getpgrp() };
    let sid = unsafe { libc::getsid(0) };
    let proc_matches = proc_identity()
        .is_some_and(|stat| stat.pid == pid && stat.pgrp == pgrp && stat.session == sid);
    let caught_reset = query_disposition(libc::SIGUSR1) == Some(libc::SIG_DFL);
    let ignored_preserved = query_disposition(libc::SIGPIPE) == Some(libc::SIG_IGN);
    let mut bits = 0_u64;
    bits |= u64::from(pid == expected_pid && tid == expected_pid) << 0;
    bits |= u64::from(pgrp == expected_pgrp && sid == expected_sid) << 1;
    bits |= u64::from(proc_matches) << 2;
    bits |= u64::from(caught_reset && ignored_preserved) << 3;
    let wrote = exact_write(fd, bits);
    unsafe { libc::_exit(if wrote { 0 } else { 4 }) }
}

fn exec_identity_case(exe: &str) -> (u64, bool) {
    let Some(result) = make_pipe() else {
        return (0, false);
    };
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe { libc::close(result[0]) };
        let _ = unsafe { libc::setpgid(0, 0) };
        let _ = unsafe { install_handler(libc::SIGUSR1, child_signal, 0) };
        let _ = unsafe { install_ign(libc::SIGPIPE) };
        let pid = unsafe { libc::getpid() };
        let pgrp = unsafe { libc::getpgrp() };
        let sid = unsafe { libc::getsid(0) };
        let values = [
            CString::new(exe).unwrap(),
            CString::new("exec-stage2").unwrap(),
            CString::new(pid.to_string()).unwrap(),
            CString::new(pgrp.to_string()).unwrap(),
            CString::new(sid.to_string()).unwrap(),
            CString::new(result[1].to_string()).unwrap(),
        ];
        let argv = [
            values[0].as_ptr(),
            values[1].as_ptr(),
            values[2].as_ptr(),
            values[3].as_ptr(),
            values[4].as_ptr(),
            values[5].as_ptr(),
            std::ptr::null(),
        ];
        let envp = [std::ptr::null()];
        unsafe {
            libc::execve(values[0].as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(5)
        }
    }
    unsafe { libc::close(result[1]) };
    let bits = exact_read(result[0]).unwrap_or(0);
    (bits, wait_exited(child) == Some(0))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("exec-stage2") {
        exec_stage2(&args);
    }

    let pid = unsafe { libc::getpid() };
    let tid = gettid();
    let pgrp = unsafe { libc::getpgrp() };
    let sid = unsafe { libc::getsid(0) };
    let stat = proc_identity();
    let root_low_linux_id = (1..64).contains(&pid);
    let root_leader_tid_matches = tid == pid;
    let root_group_and_session_are_init = pgrp == 1 && sid == 1;
    let root_proc_identity_matches =
        stat.is_some_and(|value| value.pid == pid && value.pgrp == pgrp && value.session == sid);

    let positive_pid_one_live = unsafe { libc::kill(1, 0) } == 0;
    let target_zero_live = unsafe { libc::kill(0, 0) } == 0;
    let selector_errno = errno();

    let (child_bits, signal_call_bits, broadcast_live, negative_pgid_one_live) =
        child_identity_and_signal_case(pid, sid);
    let session_matches = session_case();
    let (exec_bits, exec_child_exited_zero) = exec_identity_case(&args[0]);

    report!(
        root_low_linux_id = root_low_linux_id,
        root_leader_tid_matches = root_leader_tid_matches,
        root_group_and_session_are_init = root_group_and_session_are_init,
        root_proc_identity_matches = root_proc_identity_matches,
        positive_pid_one_live = positive_pid_one_live,
        target_zero_live = target_zero_live,
        broadcast_live = broadcast_live,
        negative_pgid_one_live = negative_pgid_one_live,
        selector_errno_nonnegative = selector_errno >= 0,
        child_setup_ready = child_bits & (1 << 0) != 0,
        child_id_is_linux_shaped = child_bits & (1 << 1) != 0,
        child_tid_ppid_match = child_bits & (1 << 2) != 0,
        child_tid_matches_pid = child_bits & (1 << 6) != 0,
        child_ppid_matches_parent = child_bits & (1 << 7) != 0,
        child_process_group_session_match = child_bits & (1 << 3) != 0,
        child_proc_identity_matches = child_bits & (1 << 4) != 0,
        child_received_kill_tgkill_group_and_xsig_shape = child_bits & (1 << 5) != 0,
        kill_child_zero_succeeded = signal_call_bits & (1 << 0) != 0,
        kill_child_signal_succeeded = signal_call_bits & (1 << 1) != 0,
        tgkill_child_zero_succeeded = signal_call_bits & (1 << 2) != 0,
        tgkill_child_signal_succeeded = signal_call_bits & (1 << 3) != 0,
        kill_child_group_succeeded = signal_call_bits & (1 << 4) != 0,
        kill_child_xsig_shape_succeeded = signal_call_bits & (1 << 5) != 0,
        waitpid_child_group_succeeded = signal_call_bits & (1 << 6) != 0,
        cross_signal_calls_succeeded = signal_call_bits == 0x7f,
        session_identity_matches = session_matches,
        exec_pid_tid_persist = exec_bits & (1 << 0) != 0,
        exec_group_session_persist = exec_bits & (1 << 1) != 0,
        exec_proc_identity_matches = exec_bits & (1 << 2) != 0,
        exec_signal_dispositions_reset_and_preserve = exec_bits & (1 << 3) != 0,
        exec_child_exited_zero = exec_child_exited_zero,
    );
}
