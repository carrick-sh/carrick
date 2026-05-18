#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;
const SYS_CLOCK_NANOSLEEP: u64 = 115;

const CLOCK_MONOTONIC: u64 = 1;

static MESSAGE: [u8; 16] = *b"clock nanosleep\n";
static mut DELAY: LinuxTimespec = LinuxTimespec {
    tv_sec: 0,
    tv_nsec: 1_000_000,
};

#[repr(C, packed)]
struct LinuxTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let slept = syscall4(
            SYS_CLOCK_NANOSLEEP,
            CLOCK_MONOTONIC,
            0,
            core::ptr::addr_of_mut!(DELAY) as u64,
            core::ptr::null_mut::<LinuxTimespec>() as u64,
        );
        if slept != 0 {
            exit(10);
        }
        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(11);
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
