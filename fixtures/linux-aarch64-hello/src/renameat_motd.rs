#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::*;

static SOURCE: [u8; 10] = *b"/etc/motd\0";
static TARGET: [u8; 14] = *b"/etc/motd.bak\0";
static MISSING: [u8; 13] = *b"/etc/missing\0";
static MESSAGE: [u8; 9] = *b"renameat\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        if syscall4(
            SYS_RENAMEAT,
            AT_FDCWD,
            SOURCE.as_ptr() as u64,
            AT_FDCWD,
            TARGET.as_ptr() as u64,
        ) != EROFS
        {
            exit(10);
        }
        if syscall4(
            SYS_RENAMEAT,
            AT_FDCWD,
            MISSING.as_ptr() as u64,
            AT_FDCWD,
            TARGET.as_ptr() as u64,
        ) != ENOENT
        {
            exit(11);
        }
        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(12);
        }
        exit(0);
    }
}
