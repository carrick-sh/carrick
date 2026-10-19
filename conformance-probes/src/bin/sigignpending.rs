//! sigaction(2) disposition installs against pending signals, rt_sigaction
//! argument validation, and the execve(2) disposition reset.
//!
//! Linux contract (man-pages: signal(7), sigaction(2), sigpending(2),
//! execve(2)):
//! - Setting SIG_IGN for a pending signal discards it, blocked or not, from
//!   the process and from every thread; so does SIG_DFL when the default
//!   action is to ignore. Installing a handler leaves it pending.
//! - sigpending(2) reports pending-and-blocked signals for the caller.
//! - SIGKILL/SIGSTOP cannot be caught or ignored (EINVAL), are never blocked
//!   (absent from a read-back sa_mask), and may still be queried.
//! - execve resets caught signals to SIG_DFL, keeps ignored ones ignored, and
//!   preserves the pending set and the signal mask.
//!
//! The error-order lines (`err_*`) pin one order for the raw syscall:
//! sigsetsize, then an unreadable `act` (EFAULT), then the signal number;
//! an unwritable `oldact` faults after the install commits. They are
//! predictions for the Docker oracle to confirm.
//!
//! Deterministic numbers only; every cross-thread wait is bounded (5 s) and
//! a failed exec prints the post-exec keys as -1.

use std::ffi::CString;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::mpsc;
use std::time::Duration;

static DELIVERED_USR1: AtomicI32 = AtomicI32::new(0);
static DELIVERED_TERM: AtomicI32 = AtomicI32::new(0);
const WAIT: Duration = Duration::from_secs(5);

extern "C" fn on_usr1(_: i32) {
    DELIVERED_USR1.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn on_term(_: i32) {
    DELIVERED_TERM.fetch_add(1, Ordering::SeqCst);
}

/// The kernel's `struct sigaction` (asm-generic with SA_RESTORER, as arm64).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct KernelSigaction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

unsafe fn raw_sigaction(sig: i64, act: usize, old: usize, size: i64) -> i32 {
    if libc::syscall(libc::SYS_rt_sigaction, sig, act, old, size) == 0 {
        0
    } else {
        *libc::__errno_location()
    }
}

unsafe fn set(sig: i32, handler: usize) {
    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = handler;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(sig, &sa, std::ptr::null_mut());
}

unsafe fn disposition(sig: i32) -> usize {
    let mut old: libc::sigaction = std::mem::zeroed();
    libc::sigaction(sig, std::ptr::null(), &mut old);
    old.sa_sigaction
}

unsafe fn mask(how: i32, sig: i32) {
    let mut set: libc::sigset_t = std::mem::zeroed();
    libc::sigemptyset(&mut set);
    libc::sigaddset(&mut set, sig);
    libc::pthread_sigmask(how, &set, std::ptr::null_mut());
}

unsafe fn pending(sig: i32) -> i32 {
    let mut set: libc::sigset_t = std::mem::zeroed();
    libc::sigemptyset(&mut set);
    libc::sigpending(&mut set);
    libc::sigismember(&set, sig)
}

unsafe fn blocked(sig: i32) -> i32 {
    let mut set: libc::sigset_t = std::mem::zeroed();
    libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut set);
    libc::sigismember(&set, sig)
}

fn post_exec() {
    unsafe {
        println!(
            "exec_caught_reset={}",
            i32::from(disposition(libc::SIGUSR1) == libc::SIG_DFL)
        );
        println!(
            "exec_ignored_kept={}",
            i32::from(disposition(libc::SIGUSR2) == libc::SIG_IGN)
        );
        println!("exec_pending_kept={}", pending(libc::SIGUSR1));
        println!("exec_mask_kept={}", blocked(libc::SIGUSR1));
        set(libc::SIGUSR1, libc::SIG_IGN);
        println!("exec_pending_after_ign={}", pending(libc::SIGUSR1));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("post") {
        post_exec();
        return;
    }
    unsafe {
        // Thread-directed pending (raise is tgkill on self), then SIG_IGN.
        set(libc::SIGUSR1, on_usr1 as *const () as usize);
        mask(libc::SIG_BLOCK, libc::SIGUSR1);
        libc::raise(libc::SIGUSR1);
        println!("ign_pending_before={}", pending(libc::SIGUSR1));
        set(libc::SIGUSR1, libc::SIG_IGN);
        println!("ign_pending_after={}", pending(libc::SIGUSR1));
        set(libc::SIGUSR1, on_usr1 as *const () as usize);
        mask(libc::SIG_UNBLOCK, libc::SIGUSR1);
        println!(
            "ign_delivered_after_unblock={}",
            DELIVERED_USR1.load(Ordering::SeqCst)
        );

        // Process-directed pending.
        mask(libc::SIG_BLOCK, libc::SIGUSR2);
        libc::kill(libc::getpid(), libc::SIGUSR2);
        println!("proc_pending_before={}", pending(libc::SIGUSR2));
        set(libc::SIGUSR2, libc::SIG_IGN);
        println!("proc_pending_after_ign={}", pending(libc::SIGUSR2));
        mask(libc::SIG_UNBLOCK, libc::SIGUSR2);

        // Another thread's pending signal: the main thread's SIG_IGN reaches it.
        mask(libc::SIG_BLOCK, libc::SIGALRM);
        let (tid_tx, tid_rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let (seen_tx, seen_rx) = mpsc::channel();
        let sibling = std::thread::spawn(move || {
            let _ = tid_tx.send(libc::syscall(libc::SYS_gettid) as i32);
            if go_rx.recv_timeout(WAIT).is_err() {
                return;
            }
            let _ = seen_tx.send(pending(libc::SIGALRM));
            if go_rx.recv_timeout(WAIT).is_err() {
                return;
            }
            let _ = seen_tx.send(pending(libc::SIGALRM));
        });
        let tid = tid_rx.recv_timeout(WAIT).unwrap_or(-1);
        libc::syscall(libc::SYS_tgkill, libc::getpid(), tid, libc::SIGALRM);
        let _ = go_tx.send(());
        println!(
            "thread_pending_before={}",
            seen_rx.recv_timeout(WAIT).unwrap_or(-1)
        );
        set(libc::SIGALRM, libc::SIG_IGN);
        let _ = go_tx.send(());
        println!(
            "thread_pending_after_ign={}",
            seen_rx.recv_timeout(WAIT).unwrap_or(-1)
        );
        let _ = sibling.join();
        mask(libc::SIG_UNBLOCK, libc::SIGALRM);

        // SIG_DFL whose default is ignore discards; a handler keeps it pending.
        mask(libc::SIG_BLOCK, libc::SIGURG);
        libc::raise(libc::SIGURG);
        println!("dfl_ignore_pending_before={}", pending(libc::SIGURG));
        set(libc::SIGURG, libc::SIG_DFL);
        println!("dfl_ignore_pending_after={}", pending(libc::SIGURG));
        mask(libc::SIG_UNBLOCK, libc::SIGURG);
        mask(libc::SIG_BLOCK, libc::SIGTERM);
        libc::raise(libc::SIGTERM);
        set(libc::SIGTERM, on_term as *const () as usize);
        println!("handler_pending_after_install={}", pending(libc::SIGTERM));
        mask(libc::SIG_UNBLOCK, libc::SIGTERM);
        println!(
            "handler_delivered_after_unblock={}",
            DELIVERED_TERM.load(Ordering::SeqCst)
        );

        // rt_sigaction argument validation and its error order.
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let bad = libc::mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        ) as usize;
        let size = 8; // the kernel sigset_t, not libc's
        let act = KernelSigaction {
            handler: on_usr1 as *const () as u64,
            ..KernelSigaction::default()
        };
        let act_ptr = &act as *const KernelSigaction as usize;
        let full_mask = KernelSigaction {
            mask: u64::MAX,
            ..act
        };
        let full_ptr = &full_mask as *const KernelSigaction as usize;
        let mut old = KernelSigaction {
            handler: 0xdead,
            ..KernelSigaction::default()
        };
        let old_ptr = &mut old as *mut KernelSigaction as usize;
        println!("err_sigsetsize={}", raw_sigaction(10, act_ptr, 0, 4));
        println!("err_kill_badact={}", raw_sigaction(9, bad, 0, size));
        println!("err_sig0_badact={}", raw_sigaction(0, bad, 0, size));
        println!("err_sig65_badact={}", raw_sigaction(65, bad, 0, size));
        println!("err_kill_act={}", raw_sigaction(9, act_ptr, 0, size));
        println!("err_stop_act={}", raw_sigaction(19, act_ptr, 0, size));
        println!("err_sig0_query={}", raw_sigaction(0, 0, old_ptr, size));
        println!("err_sig65_query={}", raw_sigaction(65, 0, old_ptr, size));
        println!("kill_query_rc={}", raw_sigaction(9, 0, old_ptr, size));
        println!(
            "kill_query_handler={}",
            std::ptr::read_volatile(old_ptr as *const u64)
        );
        println!("badold_errno={}", raw_sigaction(12, act_ptr, bad, size));
        println!(
            "badold_installed={}",
            i32::from(disposition(libc::SIGUSR2) == on_usr1 as *const () as usize)
        );
        raw_sigaction(12, full_ptr, 0, size);
        raw_sigaction(12, 0, old_ptr, size);
        println!(
            "mask_readback={:#x}",
            std::ptr::read_volatile(std::ptr::addr_of!(
                (*(old_ptr as *const KernelSigaction)).mask
            ))
        );
        libc::munmap(bad as *mut libc::c_void, page);

        // execve: caught SIGUSR1 (blocked, pending) and ignored SIGUSR2.
        set(libc::SIGUSR1, on_usr1 as *const () as usize);
        set(libc::SIGUSR2, libc::SIG_IGN);
        mask(libc::SIG_BLOCK, libc::SIGUSR1);
        libc::raise(libc::SIGUSR1);
        let prog = CString::new(args[0].clone()).unwrap_or_else(|_| CString::new("/").unwrap());
        let post = CString::new("post").unwrap();
        let argv = [prog.as_ptr(), post.as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null::<libc::c_char>()];
        libc::execve(prog.as_ptr(), argv.as_ptr(), envp.as_ptr());
    }
    for key in [
        "exec_caught_reset",
        "exec_ignored_kept",
        "exec_pending_kept",
        "exec_mask_kept",
        "exec_pending_after_ign",
    ] {
        println!("{key}=-1");
    }
}
