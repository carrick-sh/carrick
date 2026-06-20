//! Verifies the syscall-path PROT_NONE gate: a syscall whose buffer is in a
//! `PROT_NONE` region must EFAULT, exactly as Linux does — even though the host
//! backing is physically accessible. Without the gate carrick's syscall copies
//! reach the backing directly (the x86 GuestMemory gap).
//!
//! Uses a real temp file (write sink) + /dev/zero (read source) so neither check
//! depends on pipe buffering — write(fd, p, n) makes the kernel READ p (a real
//! file actually copies the buffer, unlike /dev/null which discards it),
//! read(fd, p, n) makes the kernel WRITE p; both must EFAULT when p is PROT_NONE.
//! Then mprotect(RW) and confirm the gate clears (set_no_access(false)).
//! Heap-/stdio-free: raw write + exit code.
//!   exit 0  "protnone=OK"               (read+write EFAULT, then succeed after RW)
//!   exit 80 "protnone=READ-NOT-GATED"   (kernel READ of PROT_NONE buf succeeded)
//!   exit 81 "protnone=WRITE-NOT-GATED"  (kernel WRITE to PROT_NONE buf succeeded)
//!   exit 82 "protnone=NO-CLEAR"         (gate didn't clear after mprotect RW)
//!   exit 83 "protnone=ERR"              (setup failed)

use std::os::raw::c_void;

fn emit(s: &str) {
    unsafe {
        libc::write(1, s.as_ptr() as *const c_void, s.len());
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn main() {
    unsafe {
        let sink = libc::open(
            b"/tmp/pnsink\0".as_ptr() as *const _,
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        );
        let devzero = libc::open(b"/dev/zero\0".as_ptr() as *const _, libc::O_RDONLY);
        if sink < 0 || devzero < 0 {
            emit("protnone=ERR open\n");
            libc::_exit(83);
        }

        let page = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if page == libc::MAP_FAILED {
            emit("protnone=ERR mmap\n");
            libc::_exit(83);
        }
        *(page as *mut u8) = 0x5A; // touch it (commit) before revoking access
        if libc::mprotect(page, 4096, libc::PROT_NONE) != 0 {
            emit("protnone=ERR mprotect\n");
            libc::_exit(83);
        }

        // 1) kernel READS the PROT_NONE buffer (write syscall) -> EFAULT.
        let n = libc::write(sink, page, 16);
        if !(n < 0 && errno() == libc::EFAULT) {
            emit("protnone=READ-NOT-GATED\n");
            libc::_exit(80);
        }

        // 2) kernel WRITES the PROT_NONE buffer (read syscall) -> EFAULT.
        let n = libc::read(devzero, page, 16);
        if !(n < 0 && errno() == libc::EFAULT) {
            emit("protnone=WRITE-NOT-GATED\n");
            libc::_exit(81);
        }

        // 3) mprotect back to RW clears the gate (set_no_access(false)); both
        //    directions now succeed.
        if libc::mprotect(page, 4096, libc::PROT_READ | libc::PROT_WRITE) != 0 {
            emit("protnone=ERR mprotect2\n");
            libc::_exit(83);
        }
        if libc::write(sink, page, 16) != 16 || libc::read(devzero, page, 16) != 16 {
            emit("protnone=NO-CLEAR\n");
            libc::_exit(82);
        }

        emit("protnone=OK\n");
        libc::_exit(0);
    }
}
