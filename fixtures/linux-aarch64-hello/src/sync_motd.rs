#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::*;

static PATH: [u8; 10] = *b"/etc/motd\0";
static MESSAGE: [u8; 5] = *b"sync\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        if syscall0(SYS_SYNC) != 0 {
            exit(10);
        }
        let fd = syscall4(SYS_OPENAT, AT_FDCWD, PATH.as_ptr() as u64, 0, 0);
        if fd < 0 {
            exit(11);
        }
        if syscall1(SYS_FSYNC, fd as u64) != 0 {
            exit(12);
        }
        if syscall1(SYS_FDATASYNC, fd as u64) != 0 {
            exit(13);
        }
        if syscall1(SYS_FSYNC, 999) != EBADF {
            exit(14);
        }
        if syscall1(SYS_FDATASYNC, 999) != EBADF {
            exit(15);
        }
        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(16);
        }
        exit(0);
    }
}
