#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::*;

static PATH: [u8; 10] = *b"/etc/motd\0";
static MISSING: [u8; 13] = *b"/etc/missing\0";
static MESSAGE: [u8; 7] = *b"fchown\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        if syscall3(SYS_FCHOWN, 1, 0, 0) != EROFS {
            exit(10);
        }
        if syscall3(SYS_FCHOWN, 999, 0, 0) != EBADF {
            exit(11);
        }
        let fd = syscall4(SYS_OPENAT, AT_FDCWD, PATH.as_ptr() as u64, 0, 0);
        if fd < 0 {
            exit(12);
        }
        if syscall3(SYS_FCHOWN, fd as u64, 0, 0) != EROFS {
            exit(13);
        }
        if syscall5(SYS_FCHOWNAT, AT_FDCWD, PATH.as_ptr() as u64, 0, 0, 0) != EROFS {
            exit(14);
        }
        if syscall5(SYS_FCHOWNAT, AT_FDCWD, MISSING.as_ptr() as u64, 0, 0, 0) != ENOENT {
            exit(15);
        }
        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(16);
        }
        exit(0);
    }
}
