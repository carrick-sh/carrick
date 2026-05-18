#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::*;

static TARGET: [u8; 7] = *b"target\0";
static EXISTING: [u8; 10] = *b"/etc/motd\0";
static NEW_LINK: [u8; 14] = *b"/etc/new-link\0";
static MESSAGE: [u8; 10] = *b"symlinkat\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        if syscall3(
            SYS_SYMLINKAT,
            TARGET.as_ptr() as u64,
            AT_FDCWD,
            EXISTING.as_ptr() as u64,
        ) != EEXIST
        {
            exit(10);
        }
        if syscall3(
            SYS_SYMLINKAT,
            TARGET.as_ptr() as u64,
            AT_FDCWD,
            NEW_LINK.as_ptr() as u64,
        ) != EROFS
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
