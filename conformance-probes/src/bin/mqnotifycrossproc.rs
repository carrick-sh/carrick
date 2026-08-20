//! Cross-process POSIX `mq_notify(3)` probe.
//!
//! The parent owns an empty queue and installs a one-shot notification before
//! releasing a forked child to send one message. The signal case verifies the
//! full kernel-generated `siginfo_t`: `SI_MESGQ`, sender PID/UID, and the
//! registered value. The second case exercises musl's `SIGEV_THREAD` wrapper:
//! a helper thread owned by the parent must invoke the callback when the child
//! sends. This is deliberately cross-process; self-notification would miss
//! process-identity and kernel wake-routing bugs.
//!
//! All descriptors and names are cleaned up. Every pipe, signal, callback, and
//! reap wait has a deadline. Output contains booleans only; the unique queue
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
    euid: libc::uid_t,
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
    sender_uid_matches_child_euid: bool,
    value_matches: bool,
    child_reaped: bool,
}

#[derive(Default)]
struct ThreadResults {
    queue_opened: bool,
    registered: bool,
    child_sent: bool,
    callback_ran: bool,
    value_matches: bool,
    child_reaped: bool,
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
        let send_ok = released
            && libc::mq_send(
                mqd,
                MESSAGE.as_ptr().cast::<libc::c_char>(),
                MESSAGE.len(),
                0,
            ) == 0;

        let pid = libc::getpid().to_ne_bytes();
        let euid = libc::geteuid().to_ne_bytes();
        let sent = [u8::from(send_ok)];
        let _ = write_exact(result[1], &pid);
        let _ = write_exact(result[1], &euid);
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
    let euid = libc::uid_t::from_ne_bytes(bytes[pid_end..uid_end].try_into().unwrap());
    ChildReport {
        present: true,
        pid,
        euid,
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
    result.sender_uid_matches_child_euid =
        result.received && child_report.present && info.si_uid() == child_report.euid;
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

unsafe fn thread_phase(name: &CString) -> ThreadResults {
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
            signal_sender_uid_matches_child_euid = signal.sender_uid_matches_child_euid,
            signal_value_matches = signal.value_matches,
            signal_child_reaped = signal.child_reaped,
        );

        let thread = thread_phase(&thread_name);
        report!(
            thread_exercised = true,
            thread_queue_opened = thread.queue_opened,
            thread_notification_registered = thread.registered,
            thread_child_sent = thread.child_sent,
            thread_callback_ran = thread.callback_ran,
            thread_value_matches = thread.value_matches,
            thread_child_reaped = thread.child_reaped,
        );
    }
}
