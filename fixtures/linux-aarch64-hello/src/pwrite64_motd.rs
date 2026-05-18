#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::*;

static PATH: [u8; 10] = *b"/etc/motd\0";
static PAYLOAD: [u8; 8] = *b"payload!";
static MESSAGE: [u8; 7] = *b"pwrite\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        if syscall4(
            SYS_PWRITE64,
            1,
            PAYLOAD.as_ptr() as u64,
            PAYLOAD.len() as u64,
            0,
        ) != ESPIPE
        {
            exit(10);
        }
        if syscall4(
            SYS_PWRITE64,
            2,
            PAYLOAD.as_ptr() as u64,
            PAYLOAD.len() as u64,
            0,
        ) != ESPIPE
        {
            exit(11);
        }
        if syscall4(
            SYS_PWRITE64,
            999,
            PAYLOAD.as_ptr() as u64,
            PAYLOAD.len() as u64,
            0,
        ) != EBADF
        {
            exit(12);
        }
        let fd = syscall4(SYS_OPENAT, AT_FDCWD, PATH.as_ptr() as u64, 0, 0);
        if fd < 0 {
            exit(13);
        }
        if syscall4(
            SYS_PWRITE64,
            fd as u64,
            PAYLOAD.as_ptr() as u64,
            PAYLOAD.len() as u64,
            0,
        ) != EBADF
        {
            exit(14);
        }
        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(15);
        }
        exit(0);
    }
}
