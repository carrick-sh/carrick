#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_OPENAT: u64 = 56;
const SYS_PIPE2: u64 = 59;
const SYS_SPLICE: u64 = 76;
const SYS_EXIT: u64 = 93;

const AT_FDCWD: u64 = (-100_i64) as u64;
const SPLICE_F_MORE: u64 = 4;

static PATH: [u8; 10] = *b"/etc/motd\0";
static mut FDS: [i32; 2] = [0; 2];
static mut OFFSET: u64 = 0;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let fd = syscall4(SYS_OPENAT, AT_FDCWD, PATH.as_ptr() as u64, 0, 0);
        if fd < 0 {
            exit(10);
        }
        let pipe_ret = syscall2(SYS_PIPE2, core::ptr::addr_of_mut!(FDS) as u64, 0);
        if pipe_ret != 0 {
            exit(11);
        }

        let read_fd = core::ptr::addr_of!(FDS[0]).read_volatile() as u64;
        let write_fd = core::ptr::addr_of!(FDS[1]).read_volatile() as u64;
        let moved = syscall6(
            SYS_SPLICE,
            fd as u64,
            core::ptr::addr_of_mut!(OFFSET) as u64,
            write_fd,
            0,
            64,
            SPLICE_F_MORE,
        );
        if moved <= 0 {
            exit(12);
        }
        if core::ptr::addr_of!(OFFSET).read_volatile() != moved as u64 {
            exit(13);
        }

        let copied = syscall6(SYS_SPLICE, read_fd, 0, 1, 0, moved as u64, 0);
        if copied != moved {
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

unsafe fn syscall6(
    number: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") arg0 as i64 => ret,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            in("x4") arg4,
            in("x5") arg5,
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
