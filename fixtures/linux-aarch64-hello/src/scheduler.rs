#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;
const SYS_SCHED_GETAFFINITY: u64 = 123;
const SYS_SCHED_YIELD: u64 = 124;

const AFFINITY_BYTES: usize = 8;

static MESSAGE: [u8; 10] = *b"scheduler\n";
static mut AFFINITY: [u8; AFFINITY_BYTES] = [0; AFFINITY_BYTES];

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let yielded = syscall0(SYS_SCHED_YIELD);
        if yielded != 0 {
            exit(10);
        }

        let affinity = syscall3(
            SYS_SCHED_GETAFFINITY,
            0,
            AFFINITY_BYTES as u64,
            core::ptr::addr_of_mut!(AFFINITY) as u64,
        );
        if affinity != AFFINITY_BYTES as i64 {
            exit(11);
        }
        let first = core::ptr::read_volatile(core::ptr::addr_of!(AFFINITY[0]));
        if first != 1 {
            exit(12);
        }
        for index in 1..AFFINITY_BYTES {
            if core::ptr::read_volatile(core::ptr::addr_of!(AFFINITY[index])) != 0 {
                exit(13);
            }
        }

        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(14);
        }
        exit(0);
    }
}

unsafe fn syscall0(number: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #0",
            lateout("x0") ret,
            in("x8") number,
            options(nostack)
        );
    }
    ret
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
