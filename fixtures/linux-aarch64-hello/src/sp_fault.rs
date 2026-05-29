// GPR_TABLE[31] out-of-bounds: a faulting load whose base register is SP
// (Rn==31) must be delivered to the guest as SIGSEGV. carrick's EL0-fault
// diagnostic does `GPR_TABLE[rn]` with rn possibly 31 into a `[Reg; 31]`
// (crates/carrick-hvf/src/trap.rs:1751-1752) -> host index-out-of-bounds panic.
//
// We mmap a PROT_NONE page, point SP into it, and execute `ldr x0,[sp]` (Rn=31).
// Real Linux: SIGSEGV with no handler -> the process dies by signal (host exit
// 139 = 128+11). carrick: a host-side index-OOB panic ("GUEST ABORT") fired
// while merely DECODING the fault, before the SIGSEGV could be synthesized.
//
// So: exit 139 (killed by SIGSEGV) = correct/Linux; a carrick GUEST ABORT or
// exit 42 (load did not fault) = the bug.

#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_EXIT_GROUP: u64 = 94;
const SYS_MMAP: u64 = 222;

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
            PROT_NONE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            (-1_i64) as u64,
            0,
        );
        if p < 0 {
            exit(10);
        }
        // Point SP into the PROT_NONE page (16-byte aligned) and do an
        // SP-relative load: the faulting instruction's base register is SP, so
        // the decoded Rn == 31. After this we never use the real stack again.
        let sp_target = (p as u64) + 2048;
        asm!(
            "mov sp, {sp}",
            "ldr x0, [sp]",
            sp = in(reg) sp_target,
            out("x0") _,
            options(nostack),
        );
        // Reached only if the SP-relative load did NOT fault.
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
