#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::*;

static PATH: [u8; 10] = *b"/etc/motd\0";
static MESSAGE: [u8; 10] = *b"ftruncate\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        if syscall2(SYS_FTRUNCATE, 1, 0) != EINVAL {
            exit(10);
        }
        if syscall2(SYS_FTRUNCATE, 2, 0) != EINVAL {
            exit(11);
        }
        if syscall2(SYS_FTRUNCATE, 999, 0) != EBADF {
            exit(12);
        }
        if syscall2(SYS_FTRUNCATE, 1, (-1_i64) as u64) != EINVAL {
            exit(13);
        }
        let fd = syscall4(SYS_OPENAT, AT_FDCWD, PATH.as_ptr() as u64, 0, 0);
        if fd < 0 {
            exit(14);
        }
        if syscall2(SYS_FTRUNCATE, fd as u64, 0) != EBADF {
            exit(15);
        }
        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(16);
        }
        exit(0);
    }
}
