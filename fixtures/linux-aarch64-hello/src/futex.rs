#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;
const SYS_FUTEX: u64 = 98;

const FUTEX_WAIT_PRIVATE: u64 = 128;
const FUTEX_WAKE_PRIVATE: u64 = 129;
const EAGAIN: i64 = 11;
const ETIMEDOUT: i64 = 110;

static MESSAGE: [u8; 6] = *b"futex\n";
static mut WORD: u32 = 7;
static mut TIMEOUT: LinuxTimespec = LinuxTimespec {
    tv_sec: 0,
    tv_nsec: 0,
};

#[repr(C, packed)]
struct LinuxTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let wake = syscall4(
            SYS_FUTEX,
            core::ptr::addr_of_mut!(WORD) as u64,
            FUTEX_WAKE_PRIVATE,
            1,
            0,
        );
        if wake != 0 {
            exit(10);
        }

        let mismatch = syscall4(
            SYS_FUTEX,
            core::ptr::addr_of_mut!(WORD) as u64,
            FUTEX_WAIT_PRIVATE,
            8,
            0,
        );
        if mismatch != -EAGAIN {
            exit(11);
        }

        let timed = syscall4(
            SYS_FUTEX,
            core::ptr::addr_of_mut!(WORD) as u64,
            FUTEX_WAIT_PRIVATE,
            7,
            core::ptr::addr_of_mut!(TIMEOUT) as u64,
        );
        if timed != -ETIMEDOUT {
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
