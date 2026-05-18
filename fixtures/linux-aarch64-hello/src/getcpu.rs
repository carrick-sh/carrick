#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;
const SYS_GETCPU: u64 = 168;

static MESSAGE: [u8; 7] = *b"getcpu\n";
static mut CPU: u32 = 99;
static mut NODE: u32 = 99;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let got = syscall3(
            SYS_GETCPU,
            core::ptr::addr_of_mut!(CPU) as u64,
            core::ptr::addr_of_mut!(NODE) as u64,
            0,
        );
        if got != 0 {
            exit(10);
        }
        if core::ptr::read_volatile(core::ptr::addr_of!(CPU)) != 0 {
            exit(11);
        }
        if core::ptr::read_volatile(core::ptr::addr_of!(NODE)) != 0 {
            exit(12);
        }
        if syscall3(SYS_GETCPU, 0, 0, 0) != 0 {
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
