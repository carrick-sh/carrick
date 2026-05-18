#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_OPENAT: u64 = 56;
const SYS_WRITE: u64 = 64;
const SYS_PWRITEV: u64 = 70;
const SYS_EXIT: u64 = 93;

const AT_FDCWD: u64 = (-100_i64) as u64;
const ESPIPE: i64 = -29;
const EBADF: i64 = -9;

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
        let stdout_pwritev = syscall4(SYS_PWRITEV, 1, iov.as_ptr() as u64, iov.len() as u64, 0);
        if stdout_pwritev != ESPIPE {
            exit(10);
        }
        let stderr_pwritev = syscall4(SYS_PWRITEV, 2, iov.as_ptr() as u64, iov.len() as u64, 0);
        if stderr_pwritev != ESPIPE {
            exit(11);
        }
        let bad_pwritev = syscall4(SYS_PWRITEV, 999, iov.as_ptr() as u64, iov.len() as u64, 0);
        if bad_pwritev != EBADF {
            exit(12);
        }
        let fd = syscall4(SYS_OPENAT, AT_FDCWD, PATH.as_ptr() as u64, 0, 0);
        if fd < 0 {
            exit(13);
        }
        let rootfs_pwritev = syscall4(
            SYS_PWRITEV,
            fd as u64,
            iov.as_ptr() as u64,
            iov.len() as u64,
            0,
        );
        if rootfs_pwritev != EBADF {
            exit(14);
        }
        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(15);
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
