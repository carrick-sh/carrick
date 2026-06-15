//! SP4.4 fixture: integer divide-by-zero and verify SIGFPE/FPE_INTDIV.

const LINUX_FPE_INTDIV: i32 = 1;

static mut EXPECTED_RIP: usize = 0;

extern "C" fn handler(sig: i32, info: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    let ok = if info.is_null() {
        false
    } else {
        // SAFETY: SA_SIGINFO supplies a valid siginfo pointer.
        let info = unsafe { &*info };
        let addr = unsafe { info.si_addr() } as usize;
        let expected = unsafe { EXPECTED_RIP };
        sig == libc::SIGFPE
            && info.si_signo == libc::SIGFPE
            && info.si_code == LINUX_FPE_INTDIV
            && addr == expected
    };
    let (fd, msg, code) = if ok {
        (1, b"sigfpe-ok\n".as_slice(), 0)
    } else {
        (2, b"sigfpe-bad\n".as_slice(), 1)
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
        if libc::sigaction(libc::SIGFPE, &sa, std::ptr::null_mut()) != 0 {
            libc::write(2, b"sigaction-failed\n".as_ptr().cast(), 17);
            std::process::exit(2);
        }

        let expected = std::ptr::addr_of_mut!(EXPECTED_RIP);
        core::arch::asm!(
            "lea rax, [rip + 2f]",
            "mov qword ptr [{expected}], rax",
            "mov rax, 1",
            "xor rdx, rdx",
            "xor rcx, rcx",
            "2:",
            "div rcx",
            expected = in(reg) expected,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            options(nostack)
        );
        libc::write(2, b"no-sigfpe\n".as_ptr().cast(), 10);
        std::process::exit(3);
    }
}
