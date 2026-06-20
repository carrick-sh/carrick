//! Verifies the syscall-path WRITE-PERMISSION gate: a syscall that makes the
//! kernel WRITE into a guest READ-ONLY (`PROT_READ`) mapping must EFAULT, exactly
//! as Linux does — even though the host backing is physically writable. Without
//! the gate carrick's x86 `write_bytes` copies into the read-only backing (the
//! second half of the #7 PROT_NONE work; the x86 analog of HVF's
//! `validate_guest_write_range`).
//!
//! Against a freshly `mprotect(PROT_READ)`'d page:
//!   - read(/dev/zero, ro_ptr, 16)  -> kernel WRITES ro_ptr  -> EFAULT (the gate)
//!   - write(file,     ro_ptr, 16)  -> kernel READS  ro_ptr  -> OK (reads are fine)
//! Then mprotect(RW) and confirm the write-into succeeds (gate cleared).
//! Heap-/stdio-free: raw write + exit code.
//!   exit 0  "ro=OK"               (read-into EFAULTs, read-from OK, RW clears it)
//!   exit 80 "ro=WRITE-NOT-GATED"  (kernel write into the RO page succeeded)
//!   exit 81 "ro=READ-FROM-BLOCKED"(reading FROM the RO page wrongly failed)
//!   exit 82 "ro=NO-CLEAR"         (gate didn't clear after mprotect RW)
//!   exit 83 "ro=ERR"              (setup failed)

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
            b"/tmp/rosink\0".as_ptr() as *const _,
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        );
        let devzero = libc::open(b"/dev/zero\0".as_ptr() as *const _, libc::O_RDONLY);
        if sink < 0 || devzero < 0 {
            emit("ro=ERR open\n");
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
            emit("ro=ERR mmap\n");
            libc::_exit(83);
        }
        *(page as *mut u8) = 0x5A; // touch + leave readable content
        if libc::mprotect(page, 4096, libc::PROT_READ) != 0 {
            emit("ro=ERR mprotect\n");
            libc::_exit(83);
        }

        // 1) kernel WRITES the read-only buffer (read syscall) -> EFAULT.
        let n = libc::read(devzero, page, 16);
        if !(n < 0 && errno() == libc::EFAULT) {
            emit("ro=WRITE-NOT-GATED\n");
            libc::_exit(80);
        }

        // 2) kernel READS the read-only buffer (write syscall) -> OK (reads allowed).
        let n = libc::write(sink, page, 16);
        if n != 16 {
            emit("ro=READ-FROM-BLOCKED\n");
            libc::_exit(81);
        }

        // 3) mprotect back to RW clears the gate; the kernel write now succeeds.
        if libc::mprotect(page, 4096, libc::PROT_READ | libc::PROT_WRITE) != 0 {
            emit("ro=ERR mprotect2\n");
            libc::_exit(83);
        }
        if libc::read(devzero, page, 16) != 16 {
            emit("ro=NO-CLEAR\n");
            libc::_exit(82);
        }

        emit("ro=OK\n");
        libc::_exit(0);
    }
}
