//! Cohesive Linux task-identity probe for Carrick's in-process kernel lane.
//!
//! The probe reports relationships, not run-specific PID values. It covers the
//! leader PID/TID, `/proc/self/stat`, process groups and sessions; a forked
//! descendant; self and cross-task `kill`/`tgkill`; all four `kill(2)` selector
//! shapes; process-group wait; and identity/disposition behavior across exec.

use conformance_probes::{errno, install_handler, install_ign, report};
use std::ffi::CString;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

const SIG_USR1: u32 = 1 << 0;
const SIG_USR2: u32 = 1 << 1;
const SIG_TERM: u32 = 1 << 2;
const SIG_CHLD: u32 = 1 << 3;
const ALL_CHILD_SIGNALS: u32 = SIG_USR1 | SIG_USR2 | SIG_TERM | SIG_CHLD;

static CHILD_SIGNALS: AtomicU32 = AtomicU32::new(0);
static ROOT_SIGNALS: AtomicU32 = AtomicU32::new(0);
static LEADER_CLEARTID: AtomicI32 = AtomicI32::new(-1);

extern "C" fn root_signal(signum: libc::c_int) {
    let bit = match signum {
        libc::SIGUSR1 => SIG_USR1,
        libc::SIGUSR2 => SIG_USR2,
        libc::SIGTERM => SIG_TERM,
        _ => 0,
    };
    ROOT_SIGNALS.fetch_or(bit, Ordering::SeqCst);
}

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
    loop {
        let mut bytes = [0_u8; 8];
        let got = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
        if got == -1 && errno() == libc::EINTR {
            continue;
        }
        return (got == bytes.len() as isize).then(|| u64::from_ne_bytes(bytes));
    }
}

fn make_pipe() -> Option<[i32; 2]> {
    let mut fds = [-1_i32; 2];
    (unsafe { libc::pipe(fds.as_mut_ptr()) } == 0).then_some(fds)
}

fn wait_for_bits(bits: &AtomicU32, expected: u32) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while bits.load(Ordering::SeqCst) & expected != expected
        && std::time::Instant::now() < deadline
    {
        unsafe { libc::sched_yield() };
    }
    bits.load(Ordering::SeqCst) & expected == expected
}

fn wait_exited(pid: i32) -> Option<i32> {
    loop {
        let mut status = 0_i32;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited == -1 && errno() == libc::EINTR {
            continue;
        }
        return (waited == pid && libc::WIFEXITED(status))
            .then(|| libc::WEXITSTATUS(status));
    }
}

fn wait_status(pid: i32, options: i32) -> Option<i32> {
    loop {
        let mut status = 0_i32;
        let waited = unsafe { libc::waitpid(pid, &mut status, options) };
        if waited == -1 && errno() == libc::EINTR {
            continue;
        }
        return (waited == pid).then_some(status);
    }
}

fn query_disposition(signum: i32) -> Option<libc::sighandler_t> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    (unsafe { libc::sigaction(signum, std::ptr::null(), &mut action) } == 0)
        .then_some(action.sa_sigaction)
}

fn self_signal_case(pid: i32, tid: i32) -> (bool, bool) {
    ROOT_SIGNALS.store(0, Ordering::SeqCst);
    let handlers = [libc::SIGUSR1, libc::SIGUSR2]
        .into_iter()
        .all(|signum| unsafe { install_handler(signum, root_signal, 0) });
    let kill_ok = unsafe { libc::kill(pid, libc::SIGUSR1) } == 0;
    let kill_delivered = wait_for_bits(&ROOT_SIGNALS, SIG_USR1);
    let tgkill_ok = unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGUSR2) } == 0;
    let tgkill_delivered = wait_for_bits(&ROOT_SIGNALS, SIG_USR1 | SIG_USR2);
    (
        handlers && kill_ok && kill_delivered,
        handlers && tgkill_ok && tgkill_delivered,
    )
}

fn child_sends_parent_signal(parent_pid: i32, group: bool) -> bool {
    let Some(result) = make_pipe() else {
        return false;
    };
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe { libc::close(result[0]) };
        let own_handler = !group || unsafe { install_handler(libc::SIGTERM, child_signal, 0) };
        CHILD_SIGNALS.store(0, Ordering::SeqCst);
        let target = if group { 0 } else { parent_pid };
        let sent = unsafe { libc::kill(target, libc::SIGTERM) } == 0;
        let own_delivery = !group || wait_for_bits(&CHILD_SIGNALS, SIG_TERM);
        let _ = exact_write(result[1], u64::from(own_handler && sent && own_delivery));
        unsafe { libc::_exit(0) }
    }
    unsafe { libc::close(result[1]) };
    let sent = exact_read(result[0]) == Some(1);
    sent && wait_exited(child) == Some(0)
}

fn child_sends_parent_terminal_stop(parent_pid: i32, group: bool) -> bool {
    let Some(result) = make_pipe() else {
        return false;
    };
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe { libc::close(result[0]) };
        // The group form targets the sender too. Ignore only the sender's copy;
        // the parent retains SIG_DFL, which is the PID-1 immunity under test.
        let prepared = !group || unsafe { install_ign(libc::SIGTSTP) };
        let target = if group { 0 } else { parent_pid };
        let sent = unsafe { libc::kill(target, libc::SIGTSTP) } == 0;
        let _ = exact_write(result[1], u64::from(prepared && sent));
        unsafe { libc::_exit(0) }
    }
    unsafe { libc::close(result[1]) };
    let sent = exact_read(result[0]) == Some(1);
    sent && wait_exited(child) == Some(0)
}

fn pid_one_signal_immunity_case(parent_pid: i32) -> (bool, bool, bool, bool) {
    // Guest init has no SIGTERM handler here. Linux accepts both sends but
    // suppresses its default-lethal action; the group sender catches its own
    // copy so the group arm can report success.
    let default_positive = child_sends_parent_signal(parent_pid, false);
    let default_group = child_sends_parent_signal(parent_pid, true);

    ROOT_SIGNALS.fetch_and(!SIG_TERM, Ordering::SeqCst);
    let handler_installed = unsafe { install_handler(libc::SIGTERM, root_signal, 0) };
    let handled_send = child_sends_parent_signal(parent_pid, false);
    let handled_delivery = wait_for_bits(&ROOT_SIGNALS, SIG_TERM);
    (
        default_positive && default_group,
        handler_installed,
        handled_send,
        handled_delivery,
    )
}

fn pid_one_terminal_stop_immunity_case(parent_pid: i32) -> bool {
    child_sends_parent_terminal_stop(parent_pid, false)
        && child_sends_parent_terminal_stop(parent_pid, true)
}

fn job_control_case(parent_pid: i32) -> [bool; 7] {
    let Some(ready) = make_pipe() else {
        return [false; 7];
    };
    let Some(release) = make_pipe() else {
        return [false; 7];
    };
    let Some(resumed) = make_pipe() else {
        return [false; 7];
    };
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::close(ready[0]);
            libc::close(release[1]);
            libc::close(resumed[0]);
        }
        let announced = exact_write(ready[1], 1);
        let released = exact_read(release[0]) == Some(1);
        let resumed_parent = exact_write(resumed[1], u64::from(announced && released));
        unsafe { libc::_exit(if resumed_parent { 0 } else { 7 }) }
    }
    unsafe {
        libc::close(ready[1]);
        libc::close(release[0]);
        libc::close(resumed[1]);
    }
    if child <= 0 || exact_read(ready[0]) != Some(1) {
        return [false; 7];
    }

    let stop_sent = unsafe { libc::kill(child, libc::SIGSTOP) } == 0;
    let stopped = stop_sent
        && wait_status(child, libc::WUNTRACED)
            .is_some_and(|status| libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP);
    // Reaching this exact task identity after the child stopped proves the
    // sender stayed runnable; a host-process SIGSTOP would park both tasks.
    let parent_runnable = stopped && unsafe { libc::getpid() } == parent_pid;
    let continue_sent = parent_runnable && unsafe { libc::kill(child, libc::SIGCONT) } == 0;
    let continued = continue_sent
        && wait_status(child, libc::WCONTINUED).is_some_and(|status| libc::WIFCONTINUED(status));
    let released = continued && exact_write(release[1], 1);
    let child_resumed = released && exact_read(resumed[0]) == Some(1);
    let child_exited = child_resumed && wait_exited(child) == Some(0);
    [
        stop_sent,
        stopped,
        parent_runnable,
        continue_sent,
        continued,
        child_resumed,
        child_exited,
    ]
}

fn call_denied(operation: impl FnOnce() -> libc::c_int) -> bool {
    let result = operation();
    result == -1 && errno() == libc::EPERM
}

fn credential_denial_case() -> [bool; 3] {
    let Some(ready) = make_pipe() else {
        return [false; 3];
    };
    let Some(release) = make_pipe() else {
        return [false; 3];
    };
    let target = unsafe { libc::fork() };
    if target == 0 {
        unsafe {
            libc::close(ready[0]);
            libc::close(release[1]);
        }
        let prepared =
            unsafe { libc::setpgid(0, 0) } == 0 && unsafe { libc::setuid(2000) } == 0;
        let announced = exact_write(ready[1], u64::from(prepared));
        let released = exact_read(release[0]) == Some(1);
        unsafe { libc::_exit(if prepared && announced && released { 0 } else { 6 }) }
    }
    unsafe {
        libc::close(ready[1]);
        libc::close(release[0]);
    }
    if target <= 0 {
        return [false; 3];
    }
    if exact_read(ready[0]) != Some(1) {
        let _ = exact_write(release[1], 1);
        let _ = wait_exited(target);
        return [false; 3];
    }

    let Some(result) = make_pipe() else {
        return [false; 3];
    };
    let sender = unsafe { libc::fork() };
    if sender == 0 {
        unsafe { libc::close(result[0]) };
        let changed = unsafe { libc::setuid(1000) } == 0;
        let positive = call_denied(|| unsafe { libc::kill(target, 0) });
        let thread = call_denied(|| unsafe {
            libc::syscall(libc::SYS_tgkill, target, target, 0) as libc::c_int
        });
        let group = call_denied(|| unsafe { libc::kill(-target, 0) });
        let mut bits = 0_u64;
        bits |= u64::from(changed && positive) << 0;
        bits |= u64::from(changed && thread) << 1;
        bits |= u64::from(changed && group) << 2;
        let _ = exact_write(result[1], bits);
        unsafe { libc::_exit(0) }
    }
    unsafe { libc::close(result[1]) };
    let bits = exact_read(result[0]).unwrap_or(0);
    let sender_ok = wait_exited(sender) == Some(0);
    let released = exact_write(release[1], 1);
    let target_ok = wait_exited(target) == Some(0);
    let complete = sender_ok && released && target_ok;
    std::array::from_fn(|index| complete && bits & (1 << index) != 0)
}

fn leader_exit_signal_case() -> [bool; 8] {
    let Some(ready) = make_pipe() else {
        return [false; 8];
    };
    let Some(result) = make_pipe() else {
        return [false; 8];
    };
    let target = unsafe { libc::fork() };
    if target == 0 {
        unsafe {
            libc::close(ready[0]);
            libc::close(result[0]);
        }
        CHILD_SIGNALS.store(0, Ordering::SeqCst);
        let prepared = unsafe { libc::setpgid(0, 0) } == 0
            && [libc::SIGUSR1, libc::SIGUSR2]
                .into_iter()
                .all(|signum| unsafe { install_handler(signum, child_signal, 0) });
        let leader_tid = gettid();
        LEADER_CLEARTID.store(leader_tid, Ordering::SeqCst);
        let cleartid_armed = unsafe {
            libc::syscall(
                libc::SYS_set_tid_address,
                LEADER_CLEARTID.as_ptr(),
            ) as i32
        } == leader_tid;
        let sibling = std::thread::Builder::new()
            .name("leader-exit-survivor".to_owned())
            .spawn(move || {
                let deadline =
                    std::time::Instant::now() + std::time::Duration::from_secs(3);
                while LEADER_CLEARTID.load(Ordering::SeqCst) != 0
                    && std::time::Instant::now() < deadline
                {
                    unsafe { libc::sched_yield() };
                }
                let leader_exited = LEADER_CLEARTID.load(Ordering::SeqCst) == 0;
                let setup = u64::from(prepared && cleartid_armed)
                    | (u64::from(leader_exited) << 1);
                let announced = exact_write(ready[1], setup);
                let delivered = wait_for_bits(&CHILD_SIGNALS, SIG_USR1 | SIG_USR2);
                let _ = exact_write(result[1], u64::from(announced && delivered));
                unsafe { libc::_exit(0) }
            });
        if sibling.is_err() {
            let _ = exact_write(ready[1], 0);
            unsafe { libc::_exit(8) }
        }
        // Leave the thread-group leader while the sibling remains live. Linux
        // keeps the TGID addressable for process/group signals even though the
        // exact leader TID no longer names a live thread.
        unsafe {
            libc::syscall(libc::SYS_exit, 0);
            libc::_exit(9)
        }
    }
    unsafe {
        libc::close(ready[1]);
        libc::close(result[1]);
    }
    let setup = exact_read(ready[0]).unwrap_or(0);
    if target <= 0 || setup == 0 {
        return [false; 8];
    }
    // The ready byte is published only after Linux cleared the leader's exact
    // set_tid_address word, an authoritative exit barrier, while the sibling
    // keeps the thread group live.
    let prepared = setup & 1 != 0;
    let leader_gone = setup & 2 != 0;
    let positive_zero = leader_gone && unsafe { libc::kill(target, 0) } == 0;
    let group_zero = leader_gone && unsafe { libc::kill(-target, 0) } == 0;
    let positive_signal = leader_gone && unsafe { libc::kill(target, libc::SIGUSR1) } == 0;
    let group_signal = leader_gone && unsafe { libc::kill(-target, libc::SIGUSR2) } == 0;
    let sibling_delivered = exact_read(result[0]) == Some(1);
    let child_exited = wait_exited(target) == Some(0);
    [
        prepared,
        leader_gone,
        positive_zero,
        group_zero,
        positive_signal,
        group_signal,
        sibling_delivered,
        child_exited,
    ]
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
        let all_signals = wait_for_bits(&CHILD_SIGNALS, ALL_CHILD_SIGNALS);
        let mut bits = 0_u64;
        bits |= u64::from(handlers && group_created && ready_ok) << 0;
        bits |= u64::from(pid > parent_pid && pid < 64) << 1;
        bits |= u64::from(tid == pid && ppid == parent_pid) << 2;
        bits |= u64::from(pgrp == pid && sid == parent_sid) << 3;
        bits |= u64::from(proc.is_some_and(|stat| {
            stat.pid == pid && stat.ppid == ppid && stat.pgrp == pgrp && stat.session == sid
        })) << 4;
        bits |= u64::from(all_signals) << 5;
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
    let root_exact_linux_init = pid == 1 && tid == 1;
    let root_leader_tid_matches = tid == pid;
    let root_group_and_session_are_init = pgrp == 1 && sid == 1;
    let root_proc_identity_matches =
        stat.is_some_and(|value| value.pid == pid && value.pgrp == pgrp && value.session == sid);

    let positive_pid_one_live = unsafe { libc::kill(1, 0) } == 0;
    let target_zero_live = unsafe { libc::kill(0, 0) } == 0;
    let selector_errno = errno();
    let (self_kill_signal_delivered, self_tgkill_signal_delivered) = self_signal_case(pid, tid);
    let (
        pid_one_default_signal_immunity,
        pid_one_handler_installed,
        pid_one_handled_send_succeeded,
        pid_one_handled_signal_delivered,
    ) = pid_one_signal_immunity_case(pid);
    let pid_one_terminal_stop_immunity = pid_one_terminal_stop_immunity_case(pid);
    let job_control = job_control_case(pid);
    let credential_results = credential_denial_case();
    let leader_exit = leader_exit_signal_case();

    let (child_bits, signal_call_bits, broadcast_live, negative_pgid_one_live) =
        child_identity_and_signal_case(pid, sid);
    let session_matches = session_case();
    let (exec_bits, exec_child_exited_zero) = exec_identity_case(&args[0]);

    report!(
        root_exact_linux_init = root_exact_linux_init,
        root_leader_tid_matches = root_leader_tid_matches,
        root_group_and_session_are_init = root_group_and_session_are_init,
        root_proc_identity_matches = root_proc_identity_matches,
        positive_pid_one_live = positive_pid_one_live,
        target_zero_live = target_zero_live,
        broadcast_live = broadcast_live,
        negative_pgid_one_live = negative_pgid_one_live,
        selector_errno_nonnegative = selector_errno >= 0,
        self_kill_signal_delivered = self_kill_signal_delivered,
        self_tgkill_signal_delivered = self_tgkill_signal_delivered,
        pid_one_default_signal_immunity = pid_one_default_signal_immunity,
        pid_one_handler_installed = pid_one_handler_installed,
        pid_one_handled_send_succeeded = pid_one_handled_send_succeeded,
        pid_one_handled_signal_delivered = pid_one_handled_signal_delivered,
        pid_one_terminal_stop_immunity = pid_one_terminal_stop_immunity,
        job_control_stop_send_succeeded = job_control[0],
        job_control_wait_reported_sigstop = job_control[1],
        job_control_sender_remained_runnable = job_control[2],
        job_control_continue_send_succeeded = job_control[3],
        job_control_wait_reported_continued = job_control[4],
        job_control_child_resumed = job_control[5],
        job_control_child_exited_zero = job_control[6],
        credential_positive_signal_zero_denied = credential_results[0],
        credential_tgkill_signal_zero_denied = credential_results[1],
        credential_group_signal_zero_denied = credential_results[2],
        leader_exit_setup_ready = leader_exit[0],
        leader_exit_observed = leader_exit[1],
        leader_exit_positive_signal_zero_succeeded = leader_exit[2],
        leader_exit_group_signal_zero_succeeded = leader_exit[3],
        leader_exit_positive_signal_succeeded = leader_exit[4],
        leader_exit_group_signal_succeeded = leader_exit[5],
        leader_exit_sibling_received_signals = leader_exit[6],
        leader_exit_child_exited_zero = leader_exit[7],
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
