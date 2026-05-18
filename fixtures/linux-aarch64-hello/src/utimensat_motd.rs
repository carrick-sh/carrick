#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::*;

#[repr(C)]
#[derive(Copy, Clone)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

static PATH: [u8; 10] = *b"/etc/motd\0";
static MISSING: [u8; 13] = *b"/etc/missing\0";
static MESSAGE: [u8; 10] = *b"utimensat\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let now_pair: [Timespec; 2] = [
        Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_NOW,
        },
        Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_NOW,
        },
    ];
    let invalid_pair: [Timespec; 2] = [
        Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        Timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000_001,
        },
    ];
    unsafe {
        if syscall4(
            SYS_UTIMENSAT,
            AT_FDCWD,
            PATH.as_ptr() as u64,
            now_pair.as_ptr() as u64,
            0,
        ) != EROFS
        {
            exit(10);
        }
        if syscall4(SYS_UTIMENSAT, AT_FDCWD, PATH.as_ptr() as u64, 0, 0) != EROFS {
            exit(11);
        }
        if syscall4(SYS_UTIMENSAT, AT_FDCWD, MISSING.as_ptr() as u64, 0, 0) != ENOENT {
            exit(12);
        }
        if syscall4(
            SYS_UTIMENSAT,
            AT_FDCWD,
            PATH.as_ptr() as u64,
            invalid_pair.as_ptr() as u64,
            0,
        ) != EINVAL
        {
            exit(13);
        }
        if syscall4(
            SYS_UTIMENSAT,
            AT_FDCWD,
            PATH.as_ptr() as u64,
            now_pair.as_ptr() as u64,
            0xdead,
        ) != EINVAL
        {
            exit(14);
        }
        if syscall4(SYS_UTIMENSAT, 999, 0, now_pair.as_ptr() as u64, 0) != EBADF {
            exit(15);
        }
        let fd = syscall4(SYS_OPENAT, AT_FDCWD, PATH.as_ptr() as u64, 0, 0);
        if fd < 0 {
            exit(16);
        }
        if syscall4(SYS_UTIMENSAT, fd as u64, 0, now_pair.as_ptr() as u64, 0) != EROFS {
            exit(17);
        }
        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(18);
        }
        exit(0);
    }
}
