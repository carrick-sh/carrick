//! SP4.4 fixture: write to a present read-only anonymous mapping and verify
//! carrick delivers Linux-shaped SIGSEGV/SEGV_ACCERR with si_addr in that page.

const LINUX_SEGV_ACCERR: i32 = 2;

static mut PAGE: *mut libc::c_void = std::ptr::null_mut();

extern "C" fn handler(sig: i32, info: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    let ok = if info.is_null() {
        false
    } else {
        // SAFETY: SA_SIGINFO supplies a valid siginfo pointer.
        let info = unsafe { &*info };
        let addr = unsafe { info.si_addr() } as usize;
        let page = unsafe { PAGE } as usize;
        sig == libc::SIGSEGV
            && info.si_signo == libc::SIGSEGV
            && info.si_code == LINUX_SEGV_ACCERR
            && addr >= page
            && addr < page + 4096
    };
    let (fd, msg, code) = if ok {
        (1, b"sigsegv-accerr-ok\n".as_slice(), 0)
    } else {
        (2, b"sigsegv-accerr-bad\n".as_slice(), 1)
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

        PAGE = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if PAGE == libc::MAP_FAILED {
            libc::write(2, b"mmap-failed\n".as_ptr().cast(), 12);
            std::process::exit(3);
        }

        core::ptr::write_volatile(PAGE.cast::<u64>(), 0xfeed_face_cafe_beef);
        libc::write(2, b"no-sigsegv\n".as_ptr().cast(), 11);
        std::process::exit(4);
    }
}
