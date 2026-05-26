// MAP_PRIVATE | MAP_ANONYMOUS must be COW-isolated across fork(2).
//
// Maps a PRIVATE-anon page, stores a sentinel, forks. The child overwrites the
// page with a different value and exits; the parent wait4s and re-reads. The
// parent must still see ITS sentinel (the child's write was isolated by
// carrick's sparse mincore snapshot, not shared). exit_group(0) iff isolated;
// exit_group(2) if the parent observed the child's value (broken isolation).
//
// Complements shared_mmap_fork (which proves MAP_SHARED IS visible across
// fork). Together they prove the fork memory model after the durable-memory
// rework: shared backings shared, private backings snapshotted.

#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 64;
const SYS_CLONE: u64 = 220;
const SYS_EXIT_GROUP: u64 = 94;
const SYS_WAIT4: u64 = 260;
const SYS_MMAP: u64 = 222;

const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;
const SIGCHLD: u64 = 17;

static MESSAGE: [u8; 8] = *b"private\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let mapped = syscall6(
            SYS_MMAP,
            0,
            4096,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            (-1_i64) as u64,
            0,
        );
        if mapped < 0 {
            exit(10);
        }
        let cell = mapped as *mut u32;
        core::ptr::write_volatile(cell, 100);

        let pid = syscall6(SYS_CLONE, SIGCHLD, 0, 0, 0, 0, 0);
        if pid < 0 {
            exit(11);
        }
        if pid == 0 {
            // Child: overwrite (must NOT be visible to the parent).
            core::ptr::write_volatile(cell, 999);
            exit(0);
        }

        let _ = syscall6(SYS_WAIT4, pid as u64, 0, 0, 0, 0, 0);
        let seen = core::ptr::read_volatile(cell);
        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(12);
        }
        if seen == 100 { exit(0) } else { exit(2) }
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
