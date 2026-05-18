#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;
const SYS_MEMBARRIER: u64 = 283;

const MEMBARRIER_CMD_QUERY: u64 = 0;
const MEMBARRIER_CMD_GLOBAL: u64 = 1;
const MEMBARRIER_CMD_FLAG_CPU: u64 = 1;
const EINVAL: i64 = 22;

static MESSAGE: [u8; 11] = *b"membarrier\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let supported = syscall3(SYS_MEMBARRIER, MEMBARRIER_CMD_QUERY, 0, 0);
        if supported != 0 {
            exit(10);
        }

        let flagged = syscall3(
            SYS_MEMBARRIER,
            MEMBARRIER_CMD_QUERY,
            MEMBARRIER_CMD_FLAG_CPU,
            0,
        );
        if flagged != -EINVAL {
            exit(11);
        }

        let global = syscall3(SYS_MEMBARRIER, MEMBARRIER_CMD_GLOBAL, 0, 0);
        if global != -EINVAL {
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
