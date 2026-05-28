//! Blocking signal-wait probe. Linux treats rt_sigtimedwait(..., timeout=NULL)
//! as an indefinite wait: if no signal from the set is pending yet, the caller
//! blocks until one arrives, then dequeues it synchronously. This stands in for
//! the LTP sigwait/sigwaitinfo/sigtimedwait/rt_sigtimedwait family.
//!
//! Deterministic output only. The child sends SIGUSR1 after a pipe-synchronised
//! start; the parent reports booleans for the returned signal, siginfo, handler
//! non-delivery, and child reap.

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};

static HANDLER_COUNT: AtomicU32 = AtomicU32::new(0);
static THREAD_READY: AtomicBool = AtomicBool::new(false);
static THREAD_RC: AtomicI32 = AtomicI32::new(-1);
static THREAD_ERRNO: AtomicI32 = AtomicI32::new(-1);
static THREAD_INFO_SIG: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_usr1(_: i32) {
    HANDLER_COUNT.fetch_add(1, Ordering::SeqCst);
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

unsafe fn install_handler(sig: i32) {
    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = on_usr1 as *const () as usize;
    sa.sa_flags = 0;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(sig, &sa, std::ptr::null_mut());
}

unsafe fn block_signal(sig: i32) {
    let mut set: libc::sigset_t = std::mem::zeroed();
    libc::sigemptyset(&mut set);
    libc::sigaddset(&mut set, sig);
    libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
}

extern "C" fn thread_waiter(_arg: *mut libc::c_void) -> *mut libc::c_void {
    unsafe {
        let sig = libc::SIGUSR2;
        block_signal(sig);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, sig);
        let mut info: libc::siginfo_t = std::mem::zeroed();
        THREAD_READY.store(true, Ordering::SeqCst);
        let rc = libc::syscall(
            libc::SYS_rt_sigtimedwait,
            &set as *const libc::sigset_t,
            &mut info as *mut libc::siginfo_t,
            std::ptr::null::<libc::timespec>(),
            8usize,
        ) as i32;
        THREAD_RC.store(rc, Ordering::SeqCst);
        THREAD_ERRNO.store(if rc < 0 { errno() } else { 0 }, Ordering::SeqCst);
        THREAD_INFO_SIG.store(info.si_signo, Ordering::SeqCst);
    }
    std::ptr::null_mut()
}

fn main() {
    unsafe {
        let sig = libc::SIGUSR1;
        install_handler(sig);
        block_signal(sig);
        HANDLER_COUNT.store(0, Ordering::SeqCst);

        let mut pipefd = [0i32; 2];
        let pipe_ok = libc::pipe(pipefd.as_mut_ptr()) == 0;
        if !pipe_ok {
            println!("sigwait_pipe_ok=false");
            return;
        }

        let parent = libc::getpid();
        let pid = libc::fork();
        if pid == 0 {
            libc::close(pipefd[1]);
            let mut byte = 0u8;
            let _ = libc::read(pipefd[0], &mut byte as *mut u8 as *mut libc::c_void, 1);
            libc::usleep(50_000);
            libc::kill(parent, sig);
            libc::_exit(0);
        }
        libc::close(pipefd[0]);
        let byte = [1u8];
        let _ = libc::write(pipefd[1], byte.as_ptr() as *const libc::c_void, 1);
        libc::close(pipefd[1]);

        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, sig);
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let rc = libc::syscall(
            libc::SYS_rt_sigtimedwait,
            &set as *const libc::sigset_t,
            &mut info as *mut libc::siginfo_t,
            std::ptr::null::<libc::timespec>(),
            8usize,
        ) as i64;
        let wait_errno = if rc < 0 { errno() } else { 0 };

        let mut status = 0i32;
        let wrc = libc::wait4(pid, &mut status, 0, std::ptr::null_mut());
        let child_reaped =
            wrc == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;

        println!("rt_sigtimedwait_null_returned_sig={}", rc == sig as i64);
        println!("rt_sigtimedwait_null_errno={}", wait_errno);
        println!("rt_sigtimedwait_null_info_sig={}", info.si_signo == sig);
        println!(
            "rt_sigtimedwait_consumed_not_handled={}",
            HANDLER_COUNT.load(Ordering::SeqCst) == 0
        );
        println!("rt_sigtimedwait_child_reaped={child_reaped}");

        install_handler(libc::SIGUSR2);
        let mut thread: libc::pthread_t = std::mem::zeroed();
        let created = libc::pthread_create(
            &mut thread,
            std::ptr::null(),
            thread_waiter,
            std::ptr::null_mut(),
        ) == 0;
        if created {
            while !THREAD_READY.load(Ordering::SeqCst) {
                std::hint::spin_loop();
            }
            libc::usleep(50_000);
            let kill_ok = libc::pthread_kill(thread, libc::SIGUSR2) == 0;
            let join_ok = libc::pthread_join(thread, std::ptr::null_mut()) == 0;
            println!("pthread_sigtimedwait_kill_ok={kill_ok}");
            println!(
                "pthread_sigtimedwait_returned_sig={}",
                THREAD_RC.load(Ordering::SeqCst) == libc::SIGUSR2
            );
            println!(
                "pthread_sigtimedwait_errno={}",
                THREAD_ERRNO.load(Ordering::SeqCst)
            );
            println!(
                "pthread_sigtimedwait_info_sig={}",
                THREAD_INFO_SIG.load(Ordering::SeqCst) == libc::SIGUSR2
            );
            println!("pthread_sigtimedwait_join_ok={join_ok}");
        } else {
            println!("pthread_sigtimedwait_kill_ok=false");
            println!("pthread_sigtimedwait_returned_sig=false");
            println!("pthread_sigtimedwait_errno=-1");
            println!("pthread_sigtimedwait_info_sig=false");
            println!("pthread_sigtimedwait_join_ok=false");
        }
    }
}
