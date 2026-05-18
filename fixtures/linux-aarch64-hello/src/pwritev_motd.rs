#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::*;

#[repr(C)]
struct Iovec {
    base: u64,
    len: u64,
}

static PATH: [u8; 10] = *b"/etc/motd\0";
static HEAD: [u8; 4] = *b"head";
static TAIL: [u8; 9] = *b"tailpiece";
static MESSAGE: [u8; 8] = *b"pwritev\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let iov = [
        Iovec {
            base: HEAD.as_ptr() as u64,
            len: HEAD.len() as u64,
        },
        Iovec {
            base: TAIL.as_ptr() as u64,
            len: TAIL.len() as u64,
        },
    ];
    unsafe {
        if syscall4(SYS_PWRITEV, 1, iov.as_ptr() as u64, iov.len() as u64, 0) != ESPIPE {
            exit(10);
        }
        if syscall4(SYS_PWRITEV, 2, iov.as_ptr() as u64, iov.len() as u64, 0) != ESPIPE {
            exit(11);
        }
        if syscall4(SYS_PWRITEV, 999, iov.as_ptr() as u64, iov.len() as u64, 0) != EBADF {
            exit(12);
        }
        let fd = syscall4(SYS_OPENAT, AT_FDCWD, PATH.as_ptr() as u64, 0, 0);
        if fd < 0 {
            exit(13);
        }
        if syscall4(
            SYS_PWRITEV,
            fd as u64,
            iov.as_ptr() as u64,
            iov.len() as u64,
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
