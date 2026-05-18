#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_MKDIRAT: u64 = 34;
const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;

const AT_FDCWD: u64 = (-100_i64) as u64;
const EEXIST: i64 = -17;
const EROFS: i64 = -30;
const ENOENT: i64 = -2;

static EXISTING: [u8; 10] = *b"/etc/motd\0";
static FRESH: [u8; 13] = *b"/etc/new-dir\0";
static EMPTY: [u8; 1] = *b"\0";
static MESSAGE: [u8; 8] = *b"mkdirat\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        if syscall3(SYS_MKDIRAT, AT_FDCWD, EXISTING.as_ptr() as u64, 0o755) != EEXIST {
            exit(10);
        }
        if syscall3(SYS_MKDIRAT, AT_FDCWD, FRESH.as_ptr() as u64, 0o755) != EROFS {
            exit(11);
        }
        if syscall3(SYS_MKDIRAT, AT_FDCWD, EMPTY.as_ptr() as u64, 0o755) != ENOENT {
            exit(12);
        }
        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(13);
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
