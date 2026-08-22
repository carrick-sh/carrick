//! POSIX job control probe: verifies that SIGSTOP actually stops execution of
//! the target task (rather than just marking it stopped while continuing to
//! run), that wait4(WUNTRACED) reports WIFSTOPPED, that the task makes no
//! progress while stopped, that SIGCONT resumes it, that wait4(WCONTINUED)
//! reports WIFCONTINUED, and that the task resumes advancing.
//!
//! Deterministic output: booleans only.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
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

fn main() {
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if page == libc::MAP_FAILED {
        println!("mmap_ok=false");
        return;
    }
    let counter = unsafe { &*(page as *const AtomicU64) };
    counter.store(0, Ordering::SeqCst);

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Child increments counter in a tight loop until killed.
        loop {
            counter.fetch_add(1, Ordering::Relaxed);
            std::hint::spin_loop();
        }
    }

    // Wait until child has started running and incremented counter
    while counter.load(Ordering::SeqCst) == 0 {
        std::thread::sleep(Duration::from_millis(1));
    }

    // Parent: SIGSTOP the child
    let stop_sent = unsafe { libc::kill(pid, libc::SIGSTOP) } == 0;
    let stopped = wait_status(pid, libc::WUNTRACED)
        .is_some_and(|status| libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP);

    // Parent samples the counter twice ~200ms apart while stopped: the two
    // samples MUST be equal — this is the assertion that distinguishes a real
    // stop from the current lie.
    let sample1 = counter.load(Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(200));
    let sample2 = counter.load(Ordering::SeqCst);
    let stopped_frozen = sample1 == sample2;

    // SIGCONT
    let cont_sent = unsafe { libc::kill(pid, libc::SIGCONT) } == 0;
    let continued = wait_status(pid, libc::WCONTINUED)
        .is_some_and(|status| libc::WIFCONTINUED(status));

    // Wait for counter to advance again
    let before_resume = sample2;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut resumed_advances = false;
    while std::time::Instant::now() < deadline {
        if counter.load(Ordering::SeqCst) > before_resume {
            resumed_advances = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    // SIGKILL and reap
    let kill_sent = unsafe { libc::kill(pid, libc::SIGKILL) } == 0;
    let reaped = wait_status(pid, 0)
        .is_some_and(|status| libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL);

    println!("stop_sent={stop_sent}");
    println!("stopped={stopped}");
    println!("stopped_frozen={stopped_frozen}");
    println!("cont_sent={cont_sent}");
    println!("continued={continued}");
    println!("resumed_advances={resumed_advances}");
    println!("kill_sent={kill_sent}");
    println!("reaped={reaped}");
}
