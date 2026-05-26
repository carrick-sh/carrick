// munmap must make the freed range fault during guest EL0 execution.
//
// Maps a RW page, writes it (ok), munmaps it, then reads it back. If carrick's
// stage-1 invalidate + EL1 TLBI worked, the read faults -> SIGSEGV (no handler)
// -> carrick reports 128+11 = 139. If the unmap was not made guest-visible the
// read wrongly succeeds and we reach exit_group(42). Host exit 139 = PASS.

#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_EXIT_GROUP: u64 = 94;
const SYS_MMAP: u64 = 222;
const SYS_MUNMAP: u64 = 215;

const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let p = syscall6(
            SYS_MMAP,
            0,
            4096,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            (-1_i64) as u64,
            0,
        );
        if p < 0 {
            exit(10);
        }
        let cell = p as *mut u32;
        core::ptr::write_volatile(cell, 0xdead_beef);

        if syscall3(SYS_MUNMAP, p as u64, 4096, 0) != 0 {
            exit(11);
        }

        // Use-after-munmap: should fault.
        let _ = core::ptr::read_volatile(cell);
        exit(42);
    }
}

unsafe fn syscall1(number: u64, arg0: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!("svc #0", inlateout("x0") arg0 as i64 => ret, in("x8") number, options(nostack));
    }
    ret
}

unsafe fn syscall3(number: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!("svc #0", inlateout("x0") arg0 as i64 => ret, in("x1") arg1, in("x2") arg2, in("x8") number, options(nostack));
    }
    ret
}

unsafe fn syscall6(number: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!("svc #0", inlateout("x0") arg0 as i64 => ret, in("x1") arg1, in("x2") arg2, in("x3") arg3, in("x4") arg4, in("x5") arg5, in("x8") number, options(nostack));
    }
    ret
}

fn exit(code: u64) -> ! {
    unsafe {
        let _ = syscall1(SYS_EXIT_GROUP, code);
    }
    loop {}
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}
