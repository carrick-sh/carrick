#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_FCHMOD: u64 = 52;
const SYS_FCHMODAT: u64 = 53;
const SYS_OPENAT: u64 = 56;
const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;

const AT_FDCWD: u64 = (-100_i64) as u64;
const EROFS: i64 = -30;
const EBADF: i64 = -9;
const ENOENT: i64 = -2;

static PATH: [u8; 10] = *b"/etc/motd\0";
static MISSING: [u8; 13] = *b"/etc/missing\0";
static MESSAGE: [u8; 7] = *b"fchmod\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        if syscall2(SYS_FCHMOD, 1, 0o644) != EROFS {
            exit(10);
        }
        if syscall2(SYS_FCHMOD, 999, 0o644) != EBADF {
            exit(11);
        }
        let fd = syscall4(SYS_OPENAT, AT_FDCWD, PATH.as_ptr() as u64, 0, 0);
        if fd < 0 {
            exit(12);
        }
        if syscall2(SYS_FCHMOD, fd as u64, 0o600) != EROFS {
            exit(13);
        }
        if syscall4(SYS_FCHMODAT, AT_FDCWD, PATH.as_ptr() as u64, 0o644, 0) != EROFS {
            exit(14);
        }
        if syscall4(SYS_FCHMODAT, AT_FDCWD, MISSING.as_ptr() as u64, 0o644, 0) != ENOENT {
            exit(15);
        }
        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(16);
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

unsafe fn syscall2(number: u64, arg0: u64, arg1: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") arg0 as i64 => ret,
            in("x1") arg1,
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
