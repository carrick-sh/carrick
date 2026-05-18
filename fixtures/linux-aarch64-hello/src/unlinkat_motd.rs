#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::*;

static MOTD: [u8; 10] = *b"/etc/motd\0";
static CONFD: [u8; 12] = *b"/etc/conf.d\0";
static MISSING: [u8; 13] = *b"/etc/missing\0";
static MESSAGE: [u8; 9] = *b"unlinkat\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        if syscall3(SYS_UNLINKAT, AT_FDCWD, MOTD.as_ptr() as u64, 0) != EROFS {
            exit(10);
        }
        if syscall3(SYS_UNLINKAT, AT_FDCWD, MOTD.as_ptr() as u64, AT_REMOVEDIR) != ENOTDIR {
            exit(11);
        }
        if syscall3(SYS_UNLINKAT, AT_FDCWD, CONFD.as_ptr() as u64, 0) != EISDIR {
            exit(12);
        }
        if syscall3(SYS_UNLINKAT, AT_FDCWD, CONFD.as_ptr() as u64, AT_REMOVEDIR) != EROFS {
            exit(13);
        }
        if syscall3(SYS_UNLINKAT, AT_FDCWD, MISSING.as_ptr() as u64, 0) != ENOENT {
            exit(14);
        }
        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(15);
        }
        exit(0);
    }
}
