#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::*;

static EXISTING: [u8; 10] = *b"/etc/motd\0";
static FRESH: [u8; 13] = *b"/etc/new-dir\0";
static EMPTY: [u8; 1] = *b"\0";
static MESSAGE: [u8; 8] = *b"mkdirat\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        if syscall3(SYS_MKDIRAT, AT_FDCWD, EXISTING.as_ptr() as u64, 0o755) != EEXIST {
            exit(10);
        }
        if syscall3(SYS_MKDIRAT, AT_FDCWD, FRESH.as_ptr() as u64, 0o755) != EROFS {
            exit(11);
        }
        if syscall3(SYS_MKDIRAT, AT_FDCWD, EMPTY.as_ptr() as u64, 0o755) != ENOENT {
            exit(12);
        }
        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(13);
        }
        exit(0);
    }
}
