#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::*;

static PATH: [u8; 10] = *b"/etc/motd\0";
static MISSING: [u8; 13] = *b"/etc/missing\0";
static MESSAGE: [u8; 9] = *b"truncate\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        if syscall2(SYS_TRUNCATE, PATH.as_ptr() as u64, 0) != EROFS {
            exit(10);
        }
        if syscall2(SYS_TRUNCATE, MISSING.as_ptr() as u64, 0) != ENOENT {
            exit(11);
        }
        if syscall2(SYS_TRUNCATE, PATH.as_ptr() as u64, (-1_i64) as u64) != EINVAL {
            exit(12);
        }
        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(13);
        }
        exit(0);
    }
}
