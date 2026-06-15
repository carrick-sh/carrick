//! SP4.4 fixture: execute UD2 and verify Linux-shaped SIGILL/ILL_ILLOPN.

const LINUX_ILL_ILLOPN: i32 = 2;

static mut EXPECTED_RIP: usize = 0;

extern "C" fn handler(sig: i32, info: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    let ok = if info.is_null() {
        false
    } else {
        // SAFETY: SA_SIGINFO supplies a valid siginfo pointer.
        let info = unsafe { &*info };
        let addr = unsafe { info.si_addr() } as usize;
        let expected = unsafe { EXPECTED_RIP };
        sig == libc::SIGILL
            && info.si_signo == libc::SIGILL
            && info.si_code == LINUX_ILL_ILLOPN
            && addr == expected
    };
    let (fd, msg, code) = if ok {
        (1, b"sigill-ok\n".as_slice(), 0)
    } else {
        (2, b"sigill-bad\n".as_slice(), 1)
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
        if libc::sigaction(libc::SIGILL, &sa, std::ptr::null_mut()) != 0 {
            libc::write(2, b"sigaction-failed\n".as_ptr().cast(), 17);
            std::process::exit(2);
        }

        let expected = std::ptr::addr_of_mut!(EXPECTED_RIP);
        core::arch::asm!(
            "lea rax, [rip + 2f]",
            "mov qword ptr [{expected}], rax",
            "2:",
            "ud2",
            expected = in(reg) expected,
            out("rax") _,
            options(nostack)
        );
        libc::write(2, b"no-sigill\n".as_ptr().cast(), 10);
        std::process::exit(3);
    }
}
