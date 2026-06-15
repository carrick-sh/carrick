//! SP4.4 fixture: install a SA_SIGINFO SIGSEGV handler, perform a null store,
//! and verify carrick delivers a Linux-shaped SIGSEGV with SEGV_MAPERR and
//! si_addr == 0. The handler exits directly; returning would correctly re-run
//! the faulting store and fault again.

const LINUX_SEGV_MAPERR: i32 = 1;

extern "C" fn handler(sig: i32, info: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    let ok = if info.is_null() {
        false
    } else {
        // SAFETY: SA_SIGINFO supplies a valid siginfo pointer.
        let info = unsafe { &*info };
        let addr = unsafe { info.si_addr() } as usize;
        sig == libc::SIGSEGV
            && info.si_signo == libc::SIGSEGV
            && info.si_code == LINUX_SEGV_MAPERR
            && addr == 0
    };
    let (fd, msg, code) = if ok {
        (1, b"sigsegv-ok\n".as_slice(), 0)
    } else {
        (2, b"sigsegv-bad\n".as_slice(), 1)
    };
    unsafe {
        libc::write(fd, msg.as_ptr().cast(), msg.len());
        libc::_exit(code);
    }
}

fn main() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction =
            handler as extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void) as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut()) != 0 {
            libc::write(2, b"sigaction-failed\n".as_ptr().cast(), 17);
            std::process::exit(2);
        }

        core::arch::asm!(
            "mov qword ptr [0], rax",
            in("rax") 1_u64,
            options(nostack, preserves_flags)
        );
        libc::write(2, b"no-sigsegv\n".as_ptr().cast(), 11);
        std::process::exit(3);
    }
}
