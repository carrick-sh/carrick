//! Warm executable PTRACE_POKETEXT publication and RX-COW isolation probe.

use conformance_probes::{errno, report};
use core::ffi::c_void;

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".global carrick_ptrace_text_target",
    ".type carrick_ptrace_text_target,%function",
    ".p2align 3",
    "carrick_ptrace_text_target:",
    "mov w0, #42",
    "ret",
);

unsafe extern "C" {
    fn carrick_ptrace_text_target() -> u64;
}

fn write_u64(fd: i32, value: u64) -> bool {
    let bytes = value.to_ne_bytes();
    unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) == bytes.len() as isize }
}

fn read_u64(fd: i32) -> Option<u64> {
    let mut pollfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut pollfd, 1, 5_000) } != 1 {
        return None;
    }
    let mut bytes = [0_u8; 8];
    let read = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
    (read == bytes.len() as isize).then(|| u64::from_ne_bytes(bytes))
}

fn wait_for(pid: i32) -> Option<i32> {
    let mut status = 0;
    for _ in 0..500 {
        let observed = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if observed == pid {
            return Some(status);
        }
        if observed < 0 {
            return None;
        }
        unsafe { libc::usleep(10_000) };
    }
    None
}

#[derive(Clone, Copy)]
struct PtraceOutcome {
    ok: bool,
    errno: i32,
}

impl PtraceOutcome {
    const fn skipped() -> Self {
        Self {
            ok: false,
            errno: 0,
        }
    }

    fn from_return(rc: libc::c_long) -> Self {
        Self {
            ok: rc == 0,
            errno: if rc == 0 { 0 } else { errno() },
        }
    }
}

fn poketext(pid: i32, value: u32) -> PtraceOutcome {
    let word = u64::from(value) | (u64::from(0xd65f_03c0_u32) << 32);
    PtraceOutcome::from_return(unsafe {
        libc::ptrace(
            libc::PTRACE_POKETEXT,
            pid,
            carrick_ptrace_text_target as *mut c_void,
            word as usize as *mut c_void,
        )
    })
}

#[derive(Clone, Copy)]
struct PeekOutcome {
    errno: i32,
    word: Option<u64>,
}

impl PeekOutcome {
    const fn skipped() -> Self {
        Self {
            errno: 0,
            word: None,
        }
    }
}

fn peektext(pid: i32) -> PeekOutcome {
    unsafe {
        *libc::__errno_location() = 0;
        let value = libc::ptrace(
            libc::PTRACE_PEEKTEXT,
            pid,
            carrick_ptrace_text_target as *mut c_void,
            core::ptr::null_mut::<c_void>(),
        );
        let observed_errno = errno();
        if value == -1 && observed_errno != 0 {
            PeekOutcome {
                errno: observed_errno,
                word: None,
            }
        } else {
            PeekOutcome {
                errno: 0,
                word: Some(value as u64),
            }
        }
    }
}

fn ptrace_cont(pid: i32) -> bool {
    ptrace_cont_with_signal(pid, 0)
}

fn ptrace_cont_with_signal(pid: i32, signal: i32) -> bool {
    ptrace_cont_outcome(pid, signal).ok
}

fn ptrace_cont_outcome(pid: i32, signal: i32) -> PtraceOutcome {
    PtraceOutcome::from_return(unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            core::ptr::null_mut::<c_void>(),
            signal,
        )
    })
}

fn force_kill_and_drain(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    unsafe {
        for _ in 0..500 {
            let _ = libc::kill(pid, libc::SIGKILL);
            let _ = libc::ptrace(
                libc::PTRACE_KILL,
                pid,
                core::ptr::null_mut::<c_void>(),
                core::ptr::null_mut::<c_void>(),
            );
            let _ = ptrace_cont_with_signal(pid, libc::SIGKILL);

            let mut status = 0;
            let observed = libc::waitpid(pid, &mut status, libc::WNOHANG);
            if observed == pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
                return true;
            }
            if observed < 0 && errno() == libc::ECHILD {
                return true;
            }
            if libc::kill(pid, 0) < 0 && errno() == libc::ESRCH {
                return true;
            }
            libc::usleep(10_000);
        }
    }
    false
}

fn terminal_status(status: Option<i32>) -> bool {
    status.is_some_and(|status| libc::WIFEXITED(status) || libc::WIFSIGNALED(status))
}

fn main() {
    unsafe {
        if libc::signal(libc::SIGPIPE, libc::SIG_IGN) == libc::SIG_ERR {
            report!(setup_ok = false);
            return;
        }
        let mut trace_result = [-1; 2];
        let mut peer_start = [-1; 2];
        let mut peer_result = [-1; 2];
        if libc::pipe(trace_result.as_mut_ptr()) != 0
            || libc::pipe(peer_start.as_mut_ptr()) != 0
            || libc::pipe(peer_result.as_mut_ptr()) != 0
        {
            report!(setup_ok = false);
            return;
        }

        let peer = libc::fork();
        if peer < 0 {
            report!(setup_ok = false);
            return;
        }
        if peer == 0 {
            libc::close(peer_start[1]);
            libc::close(peer_result[0]);
            let mut command = 0_u8;
            if libc::read(peer_start[0], (&mut command as *mut u8).cast(), 1) != 1 {
                libc::_exit(70);
            }
            let value = carrick_ptrace_text_target();
            libc::_exit(if write_u64(peer_result[1], value) {
                0
            } else {
                71
            });
        }

        let tracee = libc::fork();
        if tracee < 0 {
            let command = [1_u8];
            let _ = libc::write(peer_start[1], command.as_ptr().cast(), 1);
            libc::close(peer_start[1]);
            let peer_status = wait_for(peer);
            if !terminal_status(peer_status) && !force_kill_and_drain(peer) {
                libc::_exit(77);
            }
            report!(setup_ok = false);
            return;
        }
        if tracee == 0 {
            libc::close(trace_result[0]);
            let mut unblocked: libc::sigset_t = core::mem::zeroed();
            let signal_state_normalized = libc::sigemptyset(&mut unblocked) == 0
                && libc::sigprocmask(libc::SIG_SETMASK, &unblocked, core::ptr::null_mut()) == 0
                && libc::signal(libc::SIGSEGV, libc::SIG_DFL) != libc::SIG_ERR;
            if !signal_state_normalized
                || libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    core::ptr::null_mut::<c_void>(),
                    core::ptr::null_mut::<c_void>(),
                ) != 0
            {
                libc::_exit(72);
            }
            if !write_u64(trace_result[1], carrick_ptrace_text_target()) {
                libc::_exit(73);
            }
            libc::raise(libc::SIGSTOP);
            if !write_u64(trace_result[1], carrick_ptrace_text_target()) {
                libc::_exit(74);
            }
            libc::raise(libc::SIGSTOP);
            if !write_u64(trace_result[1], carrick_ptrace_text_target()) {
                libc::_exit(75);
            }
            libc::raise(libc::SIGSTOP);
            // Ptrace text writes are privileged kernel copies only. The guest
            // mapping must remain RX, so this direct store must terminate the
            // logical tracee with SIGSEGV before RET.
            core::ptr::write_volatile(carrick_ptrace_text_target as *mut u32, 0xd65f_03c0);
            libc::_exit(76);
        }

        libc::close(trace_result[1]);
        libc::close(peer_start[0]);
        libc::close(peer_result[1]);

        let warm = read_u64(trace_result[0]);
        let stop_42 = wait_for(tracee);
        let stopped_42 =
            stop_42.is_some_and(|s| libc::WIFSTOPPED(s) && libc::WSTOPSIG(s) == libc::SIGSTOP);
        let poke_43 = if stopped_42 {
            poketext(tracee, 0x5280_0560)
        } else {
            PtraceOutcome::skipped()
        };
        let post_fail_peek = if stopped_42 && !poke_43.ok && poke_43.errno == libc::EIO {
            peektext(tracee)
        } else {
            PeekOutcome::skipped()
        };
        let continue_43 = if poke_43.ok {
            ptrace_cont_outcome(tracee, 0)
        } else {
            PtraceOutcome::skipped()
        };
        let patch_43 = stopped_42 && poke_43.ok && continue_43.ok;
        let after_43 = read_u64(trace_result[0]);
        let stop_43 = wait_for(tracee);
        let stopped_43 =
            stop_43.is_some_and(|s| libc::WIFSTOPPED(s) && libc::WSTOPSIG(s) == libc::SIGSTOP);
        let patch_44 = stopped_43 && poketext(tracee, 0x5280_0580).ok && ptrace_cont(tracee);
        let after_44 = read_u64(trace_result[0]);
        let stop_44 = wait_for(tracee);
        let stopped_44 =
            stop_44.is_some_and(|s| libc::WIFSTOPPED(s) && libc::WSTOPSIG(s) == libc::SIGSTOP);

        let command = [1_u8];
        let peer_released = libc::write(peer_start[1], command.as_ptr().cast(), 1) == 1;
        let peer_value = read_u64(peer_result[0]);
        let peer_status = wait_for(peer);
        let peer_terminally_reaped = terminal_status(peer_status) || force_kill_and_drain(peer);
        if !peer_terminally_reaped {
            libc::_exit(78);
        }
        let peer_succeeded =
            peer_status.is_some_and(|s| libc::WIFEXITED(s) && libc::WEXITSTATUS(s) == 0);

        let store_resumed = stopped_44 && ptrace_cont(tracee);
        let store_stop = wait_for(tracee);
        let stopped_signal = store_stop
            .filter(|s| libc::WIFSTOPPED(*s))
            .map(|s| libc::WSTOPSIG(s));
        let store_stopped = store_resumed && stopped_signal == Some(libc::SIGSEGV);
        let store_signal_delivered =
            store_stopped && ptrace_cont_with_signal(tracee, libc::SIGSEGV);
        let store_terminal = if store_signal_delivered {
            wait_for(tracee)
        } else {
            None
        };
        let store_fault = store_signal_delivered
            && store_stopped
            && store_terminal
                .is_some_and(|s| libc::WIFSIGNALED(s) && libc::WTERMSIG(s) == libc::SIGSEGV);
        if !store_fault && !force_kill_and_drain(tracee) {
            libc::_exit(77);
        }

        report!(
            planned_stop_42_sigstop = stopped_42,
            poketext_43_ok = poke_43.ok,
            poketext_43_errno = poke_43.errno,
            post_fail_peek_errno = post_fail_peek.errno,
            post_fail_peek_is_42 = post_fail_peek.word
                == Some(u64::from(0x5280_0540_u32) | (u64::from(0xd65f_03c0_u32) << 32)),
            ptrace_cont_43_ok = continue_43.ok,
            ptrace_cont_43_errno = continue_43.errno,
            warm_42 = warm == Some(42),
            patch_43_ok = patch_43,
            executed_43 = after_43 == Some(43),
            patch_44_ok = patch_44,
            executed_44 = after_44 == Some(44),
            peer_remains_42 = peer_released && peer_value == Some(42) && peer_succeeded,
            guest_store_faulted = store_fault,
        );
    }
}
