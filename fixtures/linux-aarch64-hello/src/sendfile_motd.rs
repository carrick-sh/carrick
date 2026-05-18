#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_OPENAT: u64 = 56;
const SYS_SENDFILE: u64 = 71;
const SYS_EXIT: u64 = 93;

const AT_FDCWD: u64 = (-100_i64) as u64;

static PATH: [u8; 10] = *b"/etc/motd\0";
static mut OFFSET: u64 = 0;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let fd = syscall4(SYS_OPENAT, AT_FDCWD, PATH.as_ptr() as u64, 0, 0);
        if fd < 0 {
            exit(10);
        }
        let sent = syscall4(
            SYS_SENDFILE,
            1,
            fd as u64,
            core::ptr::addr_of_mut!(OFFSET) as u64,
            64,
        );
        if sent <= 0 {
            exit(11);
        }
        if core::ptr::addr_of!(OFFSET).read_volatile() as i64 != sent {
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
