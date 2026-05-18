#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_SYMLINKAT: u64 = 36;
const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;

const AT_FDCWD: u64 = (-100_i64) as u64;
const EROFS: i64 = -30;
const EEXIST: i64 = -17;

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
