//! NVMM async host-signal pump.
//!
//! Mirrors the KVM/bhyve split: tiny async handlers publish pending bits and
//! poke a self-pipe; one normal thread drains the pipe, peeks child exits, then
//! kicks all vCPUs and wakes futex waiters.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

use carrick_hal::{PlatformFutex, VcpuRegistry};

use crate::nvmm_signum::host_to_linux_signum;

const PUMP_SIGNALS: [i32; 4] = [libc::SIGHUP, libc::SIGINT, libc::SIGQUIT, libc::SIGTERM];

static SELF_PIPE_W: AtomicI32 = AtomicI32::new(-1);
static SELF_PIPE_R: AtomicI32 = AtomicI32::new(-1);
static PUMP_STOP: AtomicBool = AtomicBool::new(false);
static PUMP_THREAD: Mutex<Option<std::thread::JoinHandle<()>>> = Mutex::new(None);
static FORK_OLD_SIGNAL_MASK: Mutex<Option<libc::sigset_t>> = Mutex::new(None);
static SIGCHLD_INSTALLED: AtomicBool = AtomicBool::new(false);
static PUMP_STARTED: AtomicBool = AtomicBool::new(false);

extern "C" fn sigchld_handler(_signum: libc::c_int) {
    poke();
}

fn install_sigchld_handler() {
    if SIGCHLD_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    // SAFETY: zeroed sigaction is the documented empty action form; the handler
    // only writes one byte to the pump pipe.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = sigchld_handler as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = libc::SA_RESTART | libc::SA_NOCLDSTOP;
        libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut());
    }
}

fn pump_signal_set() -> libc::sigset_t {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        for &sig in &PUMP_SIGNALS {
            libc::sigaddset(&mut set, sig);
        }
    }
    set
}

/// Block host-pumped signals while a guest fork is in the child reinit window.
pub fn block_pump_signals_for_fork() {
    let mut old: libc::sigset_t = unsafe { std::mem::zeroed() };
    let set = pump_signal_set();
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old) };
    if rc == 0 {
        *FORK_OLD_SIGNAL_MASK
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(old);
    }
}

/// Restore the mask saved by [`block_pump_signals_for_fork`].
pub fn restore_pump_signals_after_fork() {
    let old = FORK_OLD_SIGNAL_MASK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    if let Some(old) = old {
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        }
    }
}

fn reap_exited_watches() {
    const CLD_EXITED: i32 = 1;
    const CLD_KILLED: i32 = 2;
    const CLD_DUMPED: i32 = 3;
    for pid in carrick_signal_core::child_watch::tracked_pids() {
        if pid <= 0 {
            continue;
        }
        // SAFETY: siginfo_t is a plain C output struct for waitid.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: waitid with P_PID and a valid output pointer; WNOWAIT peeks the
        // zombie so the guest's later wait4 still reaps it.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
            )
        };
        if rc != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error();
            if errno == Some(libc::ECHILD) || errno == Some(libc::ESRCH) {
                let _ = carrick_signal_core::child_watch::take(pid);
            }
            continue;
        }
        // SAFETY: POSIX siginfo child-exit accessor.
        let si_pid = unsafe { info.si_pid() };
        if si_pid != pid || !matches!(info.si_code, CLD_EXITED | CLD_KILLED | CLD_DUMPED) {
            continue;
        }
        if let Some((parent_tid, exit_signal)) = carrick_signal_core::child_watch::take(pid)
            && exit_signal != 0
        {
            carrick_signal_core::child_watch::record_siginfo(
                parent_tid,
                exit_signal,
                carrick_signal_core::child_watch::ChildExitSiginfo {
                    si_code: info.si_code,
                    host_pid: si_pid,
                    // SAFETY: POSIX siginfo child-exit accessors.
                    host_uid: unsafe { info.si_uid() },
                    host_status: unsafe { info.si_status() },
                },
            );
            carrick_signal_core::publish_pending_for(parent_tid, exit_signal);
        }
    }
}

extern "C" fn pump_handler(host_signum: libc::c_int) {
    let linux_signum = host_to_linux_signum(host_signum);
    if let Some(bit) = carrick_signal_core::pending_bit(linux_signum) {
        carrick_signal_core::proc_pending_fetch_or(bit);
    }
    poke();
}

pub fn poke() {
    let w = SELF_PIPE_W.load(Ordering::Relaxed);
    if w >= 0 {
        let byte = [0u8; 1];
        // SAFETY: write(2) is async-signal-safe. Errors are harmless because the
        // pending bits remain set and a full pipe already has a wake queued.
        unsafe {
            libc::write(w, byte.as_ptr() as *const libc::c_void, 1);
        }
    }
}

fn install_handlers() {
    for &sig in &PUMP_SIGNALS {
        // SAFETY: zeroed sigaction is the documented empty action form; the
        // handler only writes to atomics and a pipe.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = pump_handler as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = libc::SA_RESTART;
            libc::sigaction(sig, &action, std::ptr::null_mut());
        }
    }
    install_sigchld_handler();
}

fn make_self_pipe() -> i32 {
    let mut fds = [0i32; 2];
    // SAFETY: pipe2 fills two fds on success.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if rc != 0 {
        return -1;
    }
    SELF_PIPE_W.store(fds[1], Ordering::SeqCst);
    SELF_PIPE_R.store(fds[0], Ordering::SeqCst);
    fds[0]
}

fn spawn_pump_thread(read_fd: i32, registry: Arc<dyn VcpuRegistry>, futex: Arc<dyn PlatformFutex>) {
    let handle = std::thread::Builder::new()
        .name("carrick-vmm-nvmm-sig-pump".to_string())
        .spawn(move || {
            let mut pfd = libc::pollfd {
                fd: read_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let mut drain = [0u8; 64];
            loop {
                if PUMP_STOP.load(Ordering::SeqCst) {
                    return;
                }
                // SAFETY: poll over one live fd.
                let n = unsafe { libc::poll(&mut pfd, 1, -1) };
                if PUMP_STOP.load(Ordering::SeqCst) {
                    return;
                }
                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return;
                }
                loop {
                    // SAFETY: drain buffer is valid for reads.
                    let r = unsafe {
                        libc::read(
                            read_fd,
                            drain.as_mut_ptr() as *mut libc::c_void,
                            drain.len(),
                        )
                    };
                    if r <= 0 || (r as usize) < drain.len() {
                        break;
                    }
                }
                reap_exited_watches();
                registry.kick_all();
                futex.notify_signal_pending();
            }
        });
    if let Ok(h) = handle {
        *PUMP_THREAD.lock().unwrap_or_else(|e| e.into_inner()) = Some(h);
    }
}

pub fn stop_pump_for_fork() -> bool {
    let handle = PUMP_THREAD.lock().unwrap_or_else(|e| e.into_inner()).take();
    let Some(handle) = handle else {
        return false;
    };
    PUMP_STOP.store(true, Ordering::SeqCst);
    poke();
    let _ = handle.join();
    let w = SELF_PIPE_W.swap(-1, Ordering::SeqCst);
    if w >= 0 {
        // SAFETY: closing a live fd.
        unsafe { libc::close(w) };
    }
    let r = SELF_PIPE_R.swap(-1, Ordering::SeqCst);
    if r >= 0 {
        // SAFETY: closing a live fd.
        unsafe { libc::close(r) };
    }
    PUMP_STOP.store(false, Ordering::SeqCst);
    PUMP_STARTED.store(false, Ordering::SeqCst);
    true
}

pub fn start_pump(registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>) {
    install_handlers();
    if PUMP_STARTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    let read_fd = make_self_pipe();
    if read_fd < 0 {
        return;
    }
    spawn_pump_thread(read_fd, Arc::clone(registry), Arc::clone(futex));
    poke();
}

pub fn reinit_after_fork(registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>) {
    let stale_w = SELF_PIPE_W.swap(-1, Ordering::SeqCst);
    if stale_w >= 0 {
        // SAFETY: closing an inherited fd.
        unsafe { libc::close(stale_w) };
    }
    let stale_r = SELF_PIPE_R.swap(-1, Ordering::SeqCst);
    if stale_r >= 0 {
        // SAFETY: closing an inherited fd.
        unsafe { libc::close(stale_r) };
    }
    *PUMP_THREAD.lock().unwrap_or_else(|e| e.into_inner()) = None;
    PUMP_STOP.store(false, Ordering::SeqCst);
    carrick_signal_core::child_watch::clear();
    PUMP_STARTED.store(false, Ordering::SeqCst);
    SIGCHLD_INSTALLED.store(false, Ordering::SeqCst);
    start_pump(registry, futex);
}

pub fn reset_state_for_supervisor_fork() {
    let stale_w = SELF_PIPE_W.swap(-1, Ordering::SeqCst);
    if stale_w >= 0 {
        // SAFETY: closing an inherited fd.
        unsafe { libc::close(stale_w) };
    }
    let stale_r = SELF_PIPE_R.swap(-1, Ordering::SeqCst);
    if stale_r >= 0 {
        // SAFETY: closing an inherited fd.
        unsafe { libc::close(stale_r) };
    }
    *PUMP_THREAD.lock().unwrap_or_else(|e| e.into_inner()) = None;
    PUMP_STOP.store(false, Ordering::SeqCst);
    carrick_signal_core::child_watch::clear();
    PUMP_STARTED.store(false, Ordering::SeqCst);
    SIGCHLD_INSTALLED.store(false, Ordering::SeqCst);
}
