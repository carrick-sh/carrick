#![allow(dead_code)]

use core::arch::asm;
use core::panic::PanicInfo;

pub const SYS_SETXATTR: u64 = 5;
pub const SYS_GETXATTR: u64 = 8;
pub const SYS_LISTXATTR: u64 = 11;
pub const SYS_GETCWD: u64 = 17;
pub const SYS_MKNODAT: u64 = 33;
pub const SYS_MKDIRAT: u64 = 34;
pub const SYS_UNLINKAT: u64 = 35;
pub const SYS_SYMLINKAT: u64 = 36;
pub const SYS_LINKAT: u64 = 37;
pub const SYS_RENAMEAT: u64 = 38;
pub const SYS_TRUNCATE: u64 = 45;
pub const SYS_FTRUNCATE: u64 = 46;
pub const SYS_FALLOCATE: u64 = 47;
pub const SYS_FCHMOD: u64 = 52;
pub const SYS_FCHMODAT: u64 = 53;
pub const SYS_FCHOWNAT: u64 = 54;
pub const SYS_FCHOWN: u64 = 55;
pub const SYS_OPENAT: u64 = 56;
pub const SYS_CLOSE: u64 = 57;
pub const SYS_READ: u64 = 63;
pub const SYS_WRITE: u64 = 64;
pub const SYS_PWRITE64: u64 = 68;
pub const SYS_PWRITEV: u64 = 70;
pub const SYS_SYNC: u64 = 81;
pub const SYS_FSYNC: u64 = 82;
pub const SYS_FDATASYNC: u64 = 83;
pub const SYS_UTIMENSAT: u64 = 88;
pub const SYS_EXIT: u64 = 93;

pub const AT_FDCWD: u64 = (-100_i64) as u64;
pub const AT_REMOVEDIR: u64 = 0x200;
pub const AT_EMPTY_PATH: u64 = 0x1000;

pub const EBADF: i64 = -9;
pub const ENOENT: i64 = -2;
pub const ENOTDIR: i64 = -20;
pub const EISDIR: i64 = -21;
pub const EINVAL: i64 = -22;
pub const ESPIPE: i64 = -29;
pub const EROFS: i64 = -30;
pub const ENOSYS: i64 = -38;
pub const EEXIST: i64 = -17;
pub const ENOTSUP: i64 = -95;

pub const UTIME_NOW: i64 = (1 << 30) - 1;
pub const UTIME_OMIT: i64 = (1 << 30) - 2;

pub unsafe fn syscall0(number: u64) -> i64 {
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

pub unsafe fn syscall1(number: u64, arg0: u64) -> i64 {
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

pub unsafe fn syscall2(number: u64, arg0: u64, arg1: u64) -> i64 {
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

pub unsafe fn syscall3(number: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
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

pub unsafe fn syscall4(number: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
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

pub unsafe fn syscall5(
    number: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
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
            in("x8") number,
            options(nostack)
        );
    }
    ret
}

pub unsafe fn syscall6(
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

pub fn exit(code: u64) -> ! {
    unsafe {
        let _ = syscall1(SYS_EXIT, code);
    }
    loop {}
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}
