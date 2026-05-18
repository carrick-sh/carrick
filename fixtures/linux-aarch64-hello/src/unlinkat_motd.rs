#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_UNLINKAT: u64 = 35;
const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;

const AT_FDCWD: u64 = (-100_i64) as u64;
const AT_REMOVEDIR: u64 = 0x200;
const EROFS: i64 = -30;
const EISDIR: i64 = -21;
const ENOTDIR: i64 = -20;
const ENOENT: i64 = -2;

static MOTD: [u8; 10] = *b"/etc/motd\0";
static CONFD: [u8; 12] = *b"/etc/conf.d\0";
static MISSING: [u8; 13] = *b"/etc/missing\0";
static MESSAGE: [u8; 9] = *b"unlinkat\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        if syscall3(SYS_UNLINKAT, AT_FDCWD, MOTD.as_ptr() as u64, 0) != EROFS {
            exit(10);
        }
        if syscall3(SYS_UNLINKAT, AT_FDCWD, MOTD.as_ptr() as u64, AT_REMOVEDIR) != ENOTDIR {
            exit(11);
        }
        if syscall3(SYS_UNLINKAT, AT_FDCWD, CONFD.as_ptr() as u64, 0) != EISDIR {
            exit(12);
        }
        if syscall3(SYS_UNLINKAT, AT_FDCWD, CONFD.as_ptr() as u64, AT_REMOVEDIR) != EROFS {
            exit(13);
        }
        if syscall3(SYS_UNLINKAT, AT_FDCWD, MISSING.as_ptr() as u64, 0) != ENOENT {
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
