#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_OPENAT: u64 = 56;
const SYS_WRITE: u64 = 64;
const SYS_PREADV: u64 = 69;
const SYS_EXIT: u64 = 93;

const AT_FDCWD: u64 = (-100_i64) as u64;

static PATH: [u8; 10] = *b"/etc/motd\0";
static mut FIRST: [u8; 3] = [0; 3];
static mut SECOND: [u8; 5] = [0; 5];

#[repr(C, packed)]
struct LinuxIovec {
    iov_base: u64,
    iov_len: u64,
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let fd = syscall4(SYS_OPENAT, AT_FDCWD, PATH.as_ptr() as u64, 0, 0);
        if fd < 0 {
            exit(10);
        }

        let mut iovecs = [
            LinuxIovec {
                iov_base: core::ptr::addr_of_mut!(FIRST) as u64,
                iov_len: 3,
            },
            LinuxIovec {
                iov_base: core::ptr::addr_of_mut!(SECOND) as u64,
                iov_len: 5,
            },
        ];
        let read = syscall4(SYS_PREADV, fd as u64, iovecs.as_mut_ptr() as u64, 2, 7);
        if read != 8 {
            exit(11);
        }
        if syscall3(SYS_WRITE, 1, core::ptr::addr_of!(FIRST) as u64, 3) != 3 {
            exit(12);
        }
        if syscall3(SYS_WRITE, 1, core::ptr::addr_of!(SECOND) as u64, 5) != 5 {
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
