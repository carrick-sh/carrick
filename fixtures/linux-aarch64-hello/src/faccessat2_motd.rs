#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_OPENAT: u64 = 56;
const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;
const SYS_FACCESSAT2: u64 = 439;

const AT_FDCWD: u64 = (-100_i64) as u64;
const AT_EACCESS: u64 = 0x200;
const AT_EMPTY_PATH: u64 = 0x1000;
const R_OK: u64 = 4;
const W_OK: u64 = 2;
const EACCES: i64 = 13;

static PATH: [u8; 10] = *b"/etc/motd\0";
static EMPTY_PATH: [u8; 1] = [0];
static MESSAGE: [u8; 11] = *b"faccessat2\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        if syscall4(SYS_FACCESSAT2, AT_FDCWD, PATH.as_ptr() as u64, R_OK, AT_EACCESS) != 0 {
            exit(10);
        }
        if syscall4(SYS_FACCESSAT2, AT_FDCWD, PATH.as_ptr() as u64, W_OK, AT_EACCESS) != -EACCES
        {
            exit(11);
        }

        let fd = syscall4(SYS_OPENAT, AT_FDCWD, PATH.as_ptr() as u64, 0, 0);
        if fd < 0 {
            exit(12);
        }
        if syscall4(
            SYS_FACCESSAT2,
            fd as u64,
            EMPTY_PATH.as_ptr() as u64,
            R_OK,
            AT_EMPTY_PATH,
        ) != 0
        {
            exit(13);
        }

        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(14);
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
