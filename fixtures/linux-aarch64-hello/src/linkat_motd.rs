#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::*;

static SOURCE: [u8; 10] = *b"/etc/motd\0";
static MISSING: [u8; 13] = *b"/etc/missing\0";
static NEW_LINK: [u8; 14] = *b"/etc/new-link\0";
static MESSAGE: [u8; 7] = *b"linkat\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        if syscall5(
            SYS_LINKAT,
            AT_FDCWD,
            SOURCE.as_ptr() as u64,
            AT_FDCWD,
            NEW_LINK.as_ptr() as u64,
            0,
        ) != EROFS
        {
            exit(10);
        }
        if syscall5(
            SYS_LINKAT,
            AT_FDCWD,
            SOURCE.as_ptr() as u64,
            AT_FDCWD,
            SOURCE.as_ptr() as u64,
            0,
        ) != EEXIST
        {
            exit(11);
        }
        if syscall5(
            SYS_LINKAT,
            AT_FDCWD,
            MISSING.as_ptr() as u64,
            AT_FDCWD,
            NEW_LINK.as_ptr() as u64,
            0,
        ) != ENOENT
        {
            exit(12);
        }
        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(13);
        }
        exit(0);
    }
}
