#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_READ: u64 = 63;
const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;
const SYS_OPENAT2: u64 = 437;

const AT_FDCWD: u64 = (-100_i64) as u64;
const O_WRONLY: u64 = 1;
const EINVAL: i64 = 22;

static PATH: [u8; 10] = *b"/etc/motd\0";
static mut BUFFER: [u8; 32] = [0; 32];

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let readonly = OpenHow {
            flags: 0,
            mode: 0,
            resolve: 0,
        };
        let fd = syscall4(
            SYS_OPENAT2,
            AT_FDCWD,
            PATH.as_ptr() as u64,
            core::ptr::addr_of!(readonly) as u64,
            core::mem::size_of::<OpenHow>() as u64,
        );
        if fd < 0 {
            exit(10);
        }

        let writable = OpenHow {
            flags: O_WRONLY,
            mode: 0,
            resolve: 0,
        };
        if syscall4(
            SYS_OPENAT2,
            AT_FDCWD,
            PATH.as_ptr() as u64,
            core::ptr::addr_of!(writable) as u64,
            core::mem::size_of::<OpenHow>() as u64,
        ) != -EINVAL
        {
            exit(11);
        }

        let read = syscall3(SYS_READ, fd as u64, core::ptr::addr_of_mut!(BUFFER) as u64, 32);
        if read <= 0 {
            exit(12);
        }
        let wrote = syscall3(SYS_WRITE, 1, core::ptr::addr_of!(BUFFER) as u64, read as u64);
        if wrote != read {
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
