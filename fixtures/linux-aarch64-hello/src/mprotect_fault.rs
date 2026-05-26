// mprotect(PROT_NONE) must fault during guest EL0 execution.
//
// Maps a RW private-anon page, writes to it (succeeds), then mprotect()s it
// PROT_NONE and reads it back. If carrick's stage-1 page-table edit + EL1 TLBI
// trampoline worked, the read faults -> SIGSEGV with no handler -> the guest is
// terminated (carrick reports 128+11 = 139). If the protection change was NOT
// made guest-visible (stale TLB), the read wrongly succeeds and we reach
// exit_group(42). So: host exit 139 = PASS, exit 42 = FAIL (TLBI didn't take).

#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_EXIT_GROUP: u64 = 94;
const SYS_MMAP: u64 = 222;
const SYS_MPROTECT: u64 = 226;

const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const PROT_NONE: u64 = 0x0;
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
        // Writable now.
        core::ptr::write_volatile(cell, 0x1234_5678);

        let r = syscall3(SYS_MPROTECT, p as u64, 4096, PROT_NONE);
        if r != 0 {
            exit(11);
        }

        // Should fault: read of a PROT_NONE page. If the stage-1 edit + TLBI
        // took effect the guest never returns from this load.
        let _ = core::ptr::read_volatile(cell);

        // Reached only if the read did NOT fault — the protection was not
        // guest-visible. Signal the failure with a distinctive code.
        exit(42);
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
        let _ = syscall1(SYS_EXIT_GROUP, code);
    }
    loop {}
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}
