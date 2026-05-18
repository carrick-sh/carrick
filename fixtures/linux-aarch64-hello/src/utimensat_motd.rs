#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_OPENAT: u64 = 56;
const SYS_WRITE: u64 = 64;
const SYS_UTIMENSAT: u64 = 88;
const SYS_EXIT: u64 = 93;

const AT_FDCWD: u64 = (-100_i64) as u64;
const EROFS: i64 = -30;
const EBADF: i64 = -9;
const ENOENT: i64 = -2;
const EINVAL: i64 = -22;

const UTIME_NOW: i64 = (1 << 30) - 1;

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

unsafe fn syscall1(number: u64, arg0: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") arg0 as i64 => ret,
            in("x8") number,
            options(nostack)
        );
    }
    ret
}

unsafe fn syscall3(number: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") arg0 as i64 => ret,
            in("x1") arg1,
            in("x2") arg2,
            in("x8") number,
            options(nostack)
        );
    }
    ret
}

unsafe fn syscall4(number: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") arg0 as i64 => ret,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            in("x8") number,
            options(nostack)
        );
    }
    ret
}

fn exit(code: u64) -> ! {
    unsafe {
        let _ = syscall1(SYS_EXIT, code);
    }
    loop {}
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}
