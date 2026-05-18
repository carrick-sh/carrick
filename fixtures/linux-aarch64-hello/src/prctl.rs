#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;
const SYS_PRCTL: u64 = 167;

const PR_GET_DUMPABLE: u64 = 3;
const PR_SET_DUMPABLE: u64 = 4;
const PR_SET_NAME: u64 = 15;
const PR_GET_NAME: u64 = 16;

static MESSAGE: [u8; 6] = *b"prctl\n";
static NAME: [u8; 14] = *b"carrick-prctl\0";
static mut GOT_NAME: [u8; 16] = [0; 16];

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let dumpable = syscall1(SYS_PRCTL, PR_GET_DUMPABLE);
        if dumpable != 1 {
            exit(10);
        }
        if syscall2(SYS_PRCTL, PR_SET_DUMPABLE, 0) != 0 {
            exit(11);
        }
        if syscall1(SYS_PRCTL, PR_GET_DUMPABLE) != 0 {
            exit(12);
        }
        if syscall2(SYS_PRCTL, PR_SET_NAME, NAME.as_ptr() as u64) != 0 {
            exit(13);
        }
        if syscall2(
            SYS_PRCTL,
            PR_GET_NAME,
            core::ptr::addr_of_mut!(GOT_NAME) as u64,
        ) != 0
        {
            exit(14);
        }
        for index in 0..NAME.len() {
            if core::ptr::read_volatile(core::ptr::addr_of!(GOT_NAME[index])) != NAME[index] {
                exit(15);
            }
        }

        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(16);
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

unsafe fn syscall2(number: u64, arg0: u64, arg1: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") arg0 as i64 => ret,
            in("x1") arg1,
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
