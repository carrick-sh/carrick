#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 64;
const SYS_CAPGET: u64 = 90;
const SYS_CAPSET: u64 = 91;
const SYS_PERSONALITY: u64 = 92;
const SYS_EXIT: u64 = 93;

const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
const PERSONALITY_QUERY: u64 = 0xffff_ffff;
const ADDR_NO_RANDOMIZE: u64 = 0x0040_0000;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

static MESSAGE: [u8; 18] = *b"process bootstrap\n";
static mut HEADER: CapabilityHeader = CapabilityHeader {
    version: LINUX_CAPABILITY_VERSION_3,
    pid: 0,
};
static mut DATA: [CapabilityData; 2] = [CapabilityData {
    effective: 0,
    permitted: 0,
    inheritable: 0,
}; 2];

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let capget = syscall2(
            SYS_CAPGET,
            core::ptr::addr_of_mut!(HEADER) as u64,
            core::ptr::addr_of_mut!(DATA) as u64,
        );
        if capget != 0 {
            exit(10);
        }
        if core::ptr::addr_of!(DATA).read_volatile()[0].effective != 0 {
            exit(11);
        }

        let capset = syscall2(
            SYS_CAPSET,
            core::ptr::addr_of_mut!(HEADER) as u64,
            core::ptr::addr_of_mut!(DATA) as u64,
        );
        if capset != 0 {
            exit(12);
        }

        let previous = syscall1(SYS_PERSONALITY, PERSONALITY_QUERY);
        if previous != 0 {
            exit(13);
        }
        let previous = syscall1(SYS_PERSONALITY, ADDR_NO_RANDOMIZE);
        if previous != 0 {
            exit(14);
        }
        let current = syscall1(SYS_PERSONALITY, PERSONALITY_QUERY);
        if current != ADDR_NO_RANDOMIZE as i64 {
            exit(15);
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
