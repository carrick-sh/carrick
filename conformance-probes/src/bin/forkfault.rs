//! Fault delivery in a forked (NOT exec'd) child: LTP's tst_test framework
//! forks and runs the test function in the child, so a synchronous SIGSEGV
//! there must be delivered to the child's handler exactly as in the parent.
//! The x86/KVM lane historically crashed the whole child with a KVM_RUN
//! EFAULT instead of injecting the handler (LTP mmap05's TBROK "Child
//! returned with 125"). Bounded: the child recovers via mprotect-in-handler
//! (the same pattern as `roprotect`), the parent waitpid()s with a status
//! check, and nothing blocks indefinitely (a wedged child is killed by the
//! harness case deadline).

use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};

static FAULT_COUNT: AtomicUsize = AtomicUsize::new(0);
static LAST_CODE: AtomicI64 = AtomicI64::new(-1);
static FIX_PAGE: AtomicU64 = AtomicU64::new(0);

const PAGE: usize = 4096;

extern "C" fn handler(_sig: i32, info: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    let n = FAULT_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    unsafe {
        if n == 1 {
            LAST_CODE.store((*info).si_code as i64, Ordering::SeqCst);
        }
        if n > 8 {
            libc::_exit(3);
        }
        let page = FIX_PAGE.load(Ordering::SeqCst);
        if page == 0 {
            libc::_exit(4);
        }
        libc::mprotect(
            page as *mut libc::c_void,
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
        );
    }
}

fn child() -> ! {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut()) != 0 {
            libc::_exit(5);
        }
        let p = libc::mmap(
            std::ptr::null_mut(),
            PAGE,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            libc::_exit(6);
        }
        FIX_PAGE.store(p as u64, Ordering::SeqCst);
        let _ = std::ptr::read_volatile(p as *const u64);
        // Reached only after the handler recovered the page.
        let faults = FAULT_COUNT.load(Ordering::SeqCst);
        let code = LAST_CODE.load(Ordering::SeqCst);
        // Encode (faulted, ACCERR) into the exit status: 0 = fault delivered
        // with SEGV_ACCERR; 1 = delivered with some other si_code; 2 = the
        // read never faulted.
        if faults == 0 {
            libc::_exit(2);
        }
        if code == 2 {
            libc::_exit(0);
        }
        libc::_exit(1);
    }
}

extern "C" fn exit_handler(_sig: i32, info: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    // Report-and-exit handler (the LTP mmap05 shape): 0 = SEGV_ACCERR, 1 = any
    // other si_code. No recovery — the child's whole job was to fault.
    unsafe {
        let code = (*info).si_code;
        libc::_exit(if code == 2 { 0 } else { 1 });
    }
}

/// The exact LTP mmap05 shape that crashed the whole child on the x86/KVM lane
/// (KVM_RUN EFAULT → TBROK "Child returned with 125"): a file-backed
/// `MAP_SHARED` mapping with `PROT_NONE` — carrick's live-alias path installed
/// a PRESENT guest leaf over host backing that is itself `PROT_NONE`, so the
/// guest's read reached unreadable host memory instead of faulting cleanly.
fn file_none_child() -> ! {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = exit_handler as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut()) != 0 {
            libc::_exit(5);
        }
        let path = c"/tmp/forkfault_file".as_ptr();
        let fd = libc::open(path, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o600);
        if fd < 0 {
            libc::_exit(6);
        }
        if libc::ftruncate(fd, PAGE as libc::off_t) != 0 {
            libc::_exit(6);
        }
        let p = libc::mmap(
            std::ptr::null_mut(),
            PAGE,
            libc::PROT_NONE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        if p == libc::MAP_FAILED {
            libc::_exit(6);
        }
        let _ = std::ptr::read_volatile(p as *const u64);
        // Reached only if the read did NOT fault.
        libc::_exit(2);
    }
}

fn run_child(tag: &str, f: fn() -> !) {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            f();
        }
        if pid < 0 {
            println!("fork FAIL");
            return;
        }
        let mut status = 0;
        if libc::waitpid(pid, &mut status, 0) != pid {
            println!("waitpid FAIL");
            return;
        }
        let exited = libc::WIFEXITED(status);
        let exit_code = if exited {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        let signaled = libc::WIFSIGNALED(status);
        println!("{tag}_exited={exited}");
        println!("{tag}_signaled={signaled}");
        println!("{tag}_code={exit_code}");
        println!("{tag}_fault_delivered_accerr={}", exit_code == 0);
    }
}

fn main() {
    run_child("child", child);
    run_child("filenone", file_none_child);
    println!("DONE");
}
