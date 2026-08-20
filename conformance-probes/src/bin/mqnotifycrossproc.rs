//! Cross-process POSIX `mq_notify(3)` probe.
//!
//! The parent owns an empty queue and installs a one-shot notification before
//! releasing a forked child to send one message. The signal case verifies the
//! full kernel-generated `siginfo_t`: `SI_MESGQ`, sender PID/real UID, and the
//! registered value. The second case exercises musl's `SIGEV_THREAD` wrapper:
//! a helper thread owned by the parent must invoke the callback when the child
//! sends. This is deliberately cross-process; self-notification would miss
//! process-identity and kernel wake-routing bugs.
//!
//! The complete SIGEV_THREAD phase runs in an independently killable worker,
//! bounding the musl wrapper itself as well as its callback. All descriptors
//! and names are cleaned up. Every pipe, signal, callback, and reap wait has a
//! deadline. Output contains booleans only; the unique queue
//! names, PIDs, UIDs, values, and elapsed times are never printed.

use conformance_probes::{errno, report};
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const WAIT_DEADLINE: Duration = Duration::from_secs(4);
const CLEANUP_DEADLINE: Duration = Duration::from_secs(1);
const SIGNAL_VALUE: usize = 0x51a7;
const THREAD_VALUE: usize = 0x7ead;
const MESSAGE: &[u8] = b"x";

static THREAD_CALLED: AtomicBool = AtomicBool::new(false);
static THREAD_OBSERVED_VALUE: AtomicUsize = AtomicUsize::new(0);

extern "C" {
    // Rust libc omits this declaration for musl even though musl exports the
    // POSIX wrapper. It is essential for SIGEV_THREAD: musl translates the
    // callback request into the kernel's mq-notification protocol.
    fn mq_notify(mqd: libc::mqd_t, event: *const libc::sigevent) -> libc::c_int;
}

#[derive(Clone, Copy, Default)]
struct ChildReport {
    present: bool,
    pid: libc::pid_t,
    ruid: libc::uid_t,
    send_ok: bool,
}

#[derive(Default)]
struct SignalResults {
    queue_opened: bool,
    registered: bool,
    child_sent: bool,
    received: bool,
    code_is_mesgq: bool,
    sender_pid_matches_child: bool,
    sender_uid_matches_child_ruid: bool,
    value_matches: bool,
    child_reaped: bool,
}

#[derive(Clone, Copy, Default)]
struct ThreadResults {
    queue_opened: bool,
    registered: bool,
    child_sent: bool,
    callback_ran: bool,
    value_matches: bool,
    child_reaped: bool,
}

impl ThreadResults {
    const ENCODED_LEN: usize = 6;

    fn encode(self) -> [u8; Self::ENCODED_LEN] {
        [
            u8::from(self.queue_opened),
            u8::from(self.registered),
            u8::from(self.child_sent),
            u8::from(self.callback_ran),
            u8::from(self.value_matches),
            u8::from(self.child_reaped),
        ]
    }

    fn decode(bytes: [u8; Self::ENCODED_LEN]) -> Option<Self> {
        if bytes.iter().any(|byte| *byte > 1) {
            return None;
        }
        Some(Self {
            queue_opened: bytes[0] == 1,
            registered: bytes[1] == 1,
            child_sent: bytes[2] == 1,
            callback_ran: bytes[3] == 1,
            value_matches: bytes[4] == 1,
            child_reaped: bytes[5] == 1,
        })
    }

    fn exercised(self) -> bool {
        self.queue_opened && self.registered && self.child_sent
    }
}

extern "C" fn thread_callback(value: libc::sigval) {
    THREAD_OBSERVED_VALUE.store(value.sival_ptr as usize, Ordering::Release);
    THREAD_CALLED.store(true, Ordering::Release);
}

fn poll_fd(fd: i32, events: i16, deadline: Instant) -> bool {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining_ms = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
        let mut pfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, remaining_ms.max(1)) };
        if rc > 0 {
            return pfd.revents & (events | libc::POLLHUP | libc::POLLERR) != 0;
        }
        if rc == -1 && errno() == libc::EINTR {
            continue;
        }
        return false;
    }
}

unsafe fn write_exact(fd: i32, bytes: &[u8]) -> bool {
    let mut offset = 0;
    while offset < bytes.len() {
        let rc = libc::write(
            fd,
            bytes[offset..].as_ptr().cast::<libc::c_void>(),
            bytes.len() - offset,
        );
        if rc > 0 {
            offset += rc as usize;
        } else if rc != -1 || errno() != libc::EINTR {
            return false;
        }
    }
    true
}

fn read_exact_bounded(fd: i32, bytes: &mut [u8], deadline: Instant) -> bool {
    let mut offset = 0;
    while offset < bytes.len() {
        if !poll_fd(fd, libc::POLLIN, deadline) {
            return false;
        }
        let rc = unsafe {
            libc::read(
                fd,
                bytes[offset..].as_mut_ptr().cast::<libc::c_void>(),
                bytes.len() - offset,
            )
        };
        if rc > 0 {
            offset += rc as usize;
        } else if rc == 0 || (rc == -1 && errno() != libc::EINTR) {
            return false;
        }
    }
    true
}

unsafe fn make_pipe() -> Option<[i32; 2]> {
    let mut fds = [-1; 2];
    (libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) == 0).then_some(fds)
}

/// Fork a child before notification registration. It waits for a release byte,
/// sends exactly one nonblocking queue message, reports its identity/result,
/// and exits. This avoids forking a process after musl creates its notification
/// helper thread.
unsafe fn spawn_sender(mqd: libc::mqd_t) -> Option<(libc::pid_t, i32, i32)> {
    let release = make_pipe()?;
    let result = match make_pipe() {
        Some(pipe) => pipe,
        None => {
            libc::close(release[0]);
            libc::close(release[1]);
            return None;
        }
    };

    let child = libc::fork();
    if child == 0 {
        libc::close(release[1]);
        libc::close(result[0]);
        let deadline = Instant::now() + WAIT_DEADLINE;
        let mut start = [0u8; 1];
        let released = read_exact_bounded(release[0], &mut start, deadline);
        libc::close(release[0]);

        // Linux SI_MESGQ identifies the sender by REAL uid. When privileged,
        // make real/effective differ without changing the inherited queue
        // descriptor, so an effective-uid implementation is observably wrong.
        let ruid = libc::getuid();
        let identity_ready = if ruid == 0 {
            (libc::geteuid() != ruid || libc::seteuid(65_534) == 0) && libc::geteuid() != ruid
        } else {
            true
        };
        let send_ok = released
            && identity_ready
            && libc::mq_send(
                mqd,
                MESSAGE.as_ptr().cast::<libc::c_char>(),
                MESSAGE.len(),
                0,
            ) == 0;

        let pid = libc::getpid().to_ne_bytes();
        let ruid = ruid.to_ne_bytes();
        let sent = [u8::from(send_ok)];
        let _ = write_exact(result[1], &pid);
        let _ = write_exact(result[1], &ruid);
        let _ = write_exact(result[1], &sent);
        libc::close(result[1]);
        libc::_exit(0);
    }

    libc::close(release[0]);
    libc::close(result[1]);
    if child < 0 {
        libc::close(release[1]);
        libc::close(result[0]);
        return None;
    }
    Some((child, release[1], result[0]))
}

fn release_sender(fd: i32) {
    unsafe {
        let _ = write_exact(fd, &[1]);
        libc::close(fd);
    }
}

fn read_child_report(fd: i32) -> ChildReport {
    let deadline = Instant::now() + WAIT_DEADLINE;
    let mut bytes =
        [0u8; core::mem::size_of::<libc::pid_t>() + core::mem::size_of::<libc::uid_t>() + 1];
    let present = read_exact_bounded(fd, &mut bytes, deadline);
    unsafe { libc::close(fd) };
    if !present {
        return ChildReport::default();
    }
    let pid_end = core::mem::size_of::<libc::pid_t>();
    let uid_end = pid_end + core::mem::size_of::<libc::uid_t>();
    let pid = libc::pid_t::from_ne_bytes(bytes[..pid_end].try_into().unwrap());
    let ruid = libc::uid_t::from_ne_bytes(bytes[pid_end..uid_end].try_into().unwrap());
    ChildReport {
        present: true,
        pid,
        ruid,
        send_ok: bytes[uid_end] == 1,
    }
}

unsafe fn reap_bounded(pid: libc::pid_t) -> bool {
    let deadline = Instant::now() + WAIT_DEADLINE;
    loop {
        let mut status = 0;
        let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
        if rc == pid {
            return libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        }
        if rc == -1 && errno() != libc::EINTR {
            return false;
        }
        if Instant::now() >= deadline {
            let _ = libc::kill(pid, libc::SIGKILL);
            let cleanup = Instant::now() + CLEANUP_DEADLINE;
            loop {
                let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
                if rc == pid || (rc == -1 && errno() != libc::EINTR) {
                    return false;
                }
                if Instant::now() >= cleanup {
                    return false;
                }
                libc::usleep(1_000);
            }
        }
        libc::usleep(1_000);
    }
}

unsafe fn open_queue(name: &CString) -> libc::mqd_t {
    let mut attr: libc::mq_attr = core::mem::zeroed();
    attr.mq_maxmsg = 4;
    attr.mq_msgsize = 8;
    libc::mq_open(
        name.as_ptr(),
        libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0o600 as libc::mode_t,
        &attr as *const libc::mq_attr,
    )
}

unsafe fn signal_phase(name: &CString) -> SignalResults {
    let mut result = SignalResults::default();
    let _ = libc::mq_unlink(name.as_ptr());
    let mqd = open_queue(name);
    if mqd < 0 {
        return result;
    }
    result.queue_opened = true;

    let Some((child, release_fd, report_fd)) = spawn_sender(mqd) else {
        libc::mq_close(mqd);
        libc::mq_unlink(name.as_ptr());
        return result;
    };

    let mut set: libc::sigset_t = core::mem::zeroed();
    libc::sigemptyset(&mut set);
    libc::sigaddset(&mut set, libc::SIGUSR1);
    let mask_ok = libc::sigprocmask(libc::SIG_BLOCK, &set, core::ptr::null_mut()) == 0;

    let mut event: libc::sigevent = core::mem::zeroed();
    event.sigev_notify = libc::SIGEV_SIGNAL;
    event.sigev_signo = libc::SIGUSR1;
    event.sigev_value.sival_ptr = SIGNAL_VALUE as *mut libc::c_void;
    result.registered = mask_ok && mq_notify(mqd, &event) == 0;
    release_sender(release_fd);

    let mut info: libc::siginfo_t = core::mem::zeroed();
    let timeout = libc::timespec {
        tv_sec: WAIT_DEADLINE.as_secs().try_into().unwrap(),
        tv_nsec: 0,
    };
    let wait_rc = libc::sigtimedwait(&set, &mut info, &timeout);
    let child_report = read_child_report(report_fd);
    result.child_sent = child_report.present && child_report.send_ok;
    result.received = wait_rc == libc::SIGUSR1;
    result.code_is_mesgq = result.received && info.si_code == libc::SI_MESGQ;
    result.sender_pid_matches_child = result.received
        && child_report.present
        && child_report.pid == child
        && info.si_pid() == child_report.pid;
    result.sender_uid_matches_child_ruid =
        result.received && child_report.present && info.si_uid() == child_report.ruid;
    result.value_matches = result.received && info.si_value().sival_ptr as usize == SIGNAL_VALUE;
    result.child_reaped = reap_bounded(child);

    libc::mq_close(mqd);
    libc::mq_unlink(name.as_ptr());
    result
}

/// Populate the callback/attribute arm hidden by Rust libc's `sigevent`
/// binding. Carrick's probe matrix is 64-bit aarch64/x86_64; both Linux ABIs
/// place the 48-byte notification union at byte 16 of the 64-byte structure.
unsafe fn thread_event() -> libc::sigevent {
    assert_eq!(core::mem::size_of::<libc::sigevent>(), 64);
    let mut event: libc::sigevent = core::mem::zeroed();
    event.sigev_notify = libc::SIGEV_THREAD;
    event.sigev_value.sival_ptr = THREAD_VALUE as *mut libc::c_void;
    let union = (&mut event as *mut libc::sigevent)
        .cast::<u8>()
        .add(16)
        .cast::<usize>();
    union.write(thread_callback as *const () as usize);
    union.add(1).write(0); // default pthread attributes
    event
}

/// Run inside the independently killable worker. The sender is forked before
/// `mq_notify(SIGEV_THREAD)` can create musl's helper thread.
unsafe fn thread_phase_worker(name: &CString) -> ThreadResults {
    let mut result = ThreadResults::default();
    THREAD_CALLED.store(false, Ordering::Release);
    THREAD_OBSERVED_VALUE.store(0, Ordering::Release);
    let _ = libc::mq_unlink(name.as_ptr());
    let mqd = open_queue(name);
    if mqd < 0 {
        return result;
    }
    result.queue_opened = true;

    let Some((child, release_fd, report_fd)) = spawn_sender(mqd) else {
        libc::mq_close(mqd);
        libc::mq_unlink(name.as_ptr());
        return result;
    };

    let event = thread_event();
    result.registered = mq_notify(mqd, &event) == 0;
    release_sender(release_fd);

    let deadline = Instant::now() + WAIT_DEADLINE;
    while !THREAD_CALLED.load(Ordering::Acquire) && Instant::now() < deadline {
        libc::usleep(1_000);
    }
    result.callback_ran = THREAD_CALLED.load(Ordering::Acquire);
    result.value_matches =
        result.callback_ran && THREAD_OBSERVED_VALUE.load(Ordering::Acquire) == THREAD_VALUE;
    let child_report = read_child_report(report_fd);
    result.child_sent = child_report.present && child_report.send_ok;
    result.child_reaped = reap_bounded(child);

    libc::mq_close(mqd);
    libc::mq_unlink(name.as_ptr());
    result
}

/// `Some(status_ok)` means the worker was consumed; `None` means it is still
/// live at the deadline and must be killed.
unsafe fn wait_worker_until(pid: libc::pid_t, deadline: Instant) -> Option<bool> {
    loop {
        let mut status = 0;
        let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
        if rc == pid {
            return Some(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        }
        if rc == -1 && errno() != libc::EINTR {
            return Some(false);
        }
        if Instant::now() >= deadline {
            return None;
        }
        libc::usleep(1_000);
    }
}

unsafe fn kill_worker_tree_and_reap(pid: libc::pid_t) {
    // The worker becomes a process-group leader before it forks the sender, so
    // a stuck libc wrapper cannot leave that sender behind. Confirm ownership
    // before signaling the group; always signal the exact worker as fallback.
    if libc::getpgid(pid) == pid {
        let _ = libc::kill(-pid, libc::SIGKILL);
    }
    let _ = libc::kill(pid, libc::SIGKILL);
    let deadline = Instant::now() + CLEANUP_DEADLINE;
    let mut status = 0;
    loop {
        let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
        if rc == pid || (rc == -1 && errno() != libc::EINTR) || Instant::now() >= deadline {
            return;
        }
        libc::usleep(1_000);
    }
}

/// Isolate the complete musl SIGEV_THREAD path behind a process boundary.
/// `mq_notify(3)` is a libc wrapper and is not specified to block, but a broken
/// implementation must still produce deterministic `false` lines rather than
/// wedge the conformance harness.
unsafe fn thread_phase_bounded(name: &CString) -> ThreadResults {
    // Clear any stale name before even allocating the supervision pipe; the
    // worker repeats this immediately before its own create.
    let _ = libc::mq_unlink(name.as_ptr());
    let Some(result_pipe) = make_pipe() else {
        return ThreadResults::default();
    };
    let worker = libc::fork();
    if worker == 0 {
        libc::close(result_pipe[0]);
        let _ = libc::setpgid(0, 0);
        let result = thread_phase_worker(name);
        let wrote = write_exact(result_pipe[1], &result.encode());
        libc::close(result_pipe[1]);
        libc::_exit(i32::from(!wrote));
    }

    libc::close(result_pipe[1]);
    if worker < 0 {
        libc::close(result_pipe[0]);
        return ThreadResults::default();
    }
    let _ = libc::setpgid(worker, worker);

    let deadline = Instant::now() + WAIT_DEADLINE;
    let mut encoded = [0u8; ThreadResults::ENCODED_LEN];
    let got_result = read_exact_bounded(result_pipe[0], &mut encoded, deadline);
    libc::close(result_pipe[0]);
    let worker_ok = match wait_worker_until(worker, deadline) {
        Some(status_ok) => status_ok,
        None => {
            kill_worker_tree_and_reap(worker);
            false
        }
    };
    // The worker normally unlinks after closing its descriptor. This parent
    // fallback also cleans the namespace if the libc wrapper had to be killed.
    let _ = libc::mq_unlink(name.as_ptr());

    if got_result && worker_ok {
        ThreadResults::decode(encoded).unwrap_or_default()
    } else {
        ThreadResults::default()
    }
}

fn main() {
    unsafe {
        let pid = libc::getpid();
        let signal_name = CString::new(format!("/carrick-mqnotify-{pid}-signal")).unwrap();
        let thread_name = CString::new(format!("/carrick-mqnotify-{pid}-thread")).unwrap();

        let signal = signal_phase(&signal_name);
        report!(
            signal_queue_opened = signal.queue_opened,
            signal_notification_registered = signal.registered,
            signal_child_sent = signal.child_sent,
            signal_received = signal.received,
            signal_code_is_mesgq = signal.code_is_mesgq,
            signal_sender_pid_matches_child = signal.sender_pid_matches_child,
            signal_sender_uid_matches_child_ruid = signal.sender_uid_matches_child_ruid,
            signal_value_matches = signal.value_matches,
            signal_child_reaped = signal.child_reaped,
        );

        let thread = thread_phase_bounded(&thread_name);
        report!(
            thread_exercised = thread.exercised(),
            thread_queue_opened = thread.queue_opened,
            thread_notification_registered = thread.registered,
            thread_child_sent = thread.child_sent,
            thread_callback_ran = thread.callback_ran,
            thread_value_matches = thread.value_matches,
            thread_child_reaped = thread.child_reaped,
        );
    }
}
