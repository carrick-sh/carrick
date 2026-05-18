#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_OPENAT: u64 = 56;
const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;
const SYS_STATX: u64 = 291;

const AT_FDCWD: u64 = (-100_i64) as u64;
const AT_EMPTY_PATH: u64 = 0x1000;
const STATX_BASIC_STATS: u32 = 0x7ff;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const EXPECTED_SIZE: u64 = 14;

static PATH: [u8; 10] = *b"/etc/motd\0";
static EMPTY_PATH: [u8; 1] = [0];
static MESSAGE: [u8; 6] = *b"statx\n";
static mut STATX: [u8; 256] = [0; 256];

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        if syscall5(
            SYS_STATX,
            AT_FDCWD,
            PATH.as_ptr() as u64,
            0,
            STATX_BASIC_STATS as u64,
            core::ptr::addr_of_mut!(STATX) as u64,
        ) != 0
        {
            exit(10);
        }
        assert_regular_motd_statx(11);

        let fd = syscall4(SYS_OPENAT, AT_FDCWD, PATH.as_ptr() as u64, 0, 0);
        if fd < 0 {
            exit(12);
        }
        if syscall5(
            SYS_STATX,
            fd as u64,
            EMPTY_PATH.as_ptr() as u64,
            AT_EMPTY_PATH,
            STATX_BASIC_STATS as u64,
            core::ptr::addr_of_mut!(STATX) as u64,
        ) != 0
        {
            exit(13);
        }
        assert_regular_motd_statx(14);

        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(15);
        }
        exit(0);
    }
}

unsafe fn assert_regular_motd_statx(code: u64) {
    let statx = core::ptr::addr_of!(STATX) as *const u8;
    let mask = unsafe { read_u32(statx, 0) };
    let blksize = unsafe { read_u32(statx, 4) };
    let mode = unsafe { read_u16(statx, 28) } as u32;
    let size = unsafe { read_u64(statx, 40) };
    let blocks = unsafe { read_u64(statx, 48) };

    if mask & STATX_BASIC_STATS != STATX_BASIC_STATS {
        exit(code);
    }
    if blksize != 4096 {
        exit(code + 1);
    }
    if mode & S_IFMT != S_IFREG || mode & 0o777 != 0o644 {
        exit(code + 2);
    }
    if size != EXPECTED_SIZE {
        exit(code + 3);
    }
    if blocks != 1 {
        exit(code + 4);
    }
}

unsafe fn read_u16(base: *const u8, offset: usize) -> u16 {
    unsafe { core::ptr::read_unaligned(base.add(offset) as *const u16) }
}

unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    unsafe { core::ptr::read_unaligned(base.add(offset) as *const u32) }
}

unsafe fn read_u64(base: *const u8, offset: usize) -> u64 {
    unsafe { core::ptr::read_unaligned(base.add(offset) as *const u64) }
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

unsafe fn syscall5(number: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> i64 {
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
