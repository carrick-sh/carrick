// MAP_SHARED | MAP_ANONYMOUS coherence across fork(2).
//
// Maps one shared-anon page, clones a child (the encoding musl's fork()
// uses), has the child store a sentinel into the shared page and exit, then
// the parent wait4s and reads the page back. exit_group(0) iff the parent
// observes the child's store — i.e. the mapping is genuinely shared, not a
// private snapshot. This is the durable regression probe for the stable
// shared aperture (the page lives in the boot-mapped MAP_SHARED aperture, so
// fork(2) inherits the same host backing).

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
const MAP_SHARED: u64 = 0x01;
const MAP_ANONYMOUS: u64 = 0x20;
const SIGCHLD: u64 = 17;

static MESSAGE: [u8; 7] = *b"shared\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let mapped = syscall6(
            SYS_MMAP,
            0,
            4096,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS,
            (-1_i64) as u64,
            0,
        );
        if mapped < 0 {
            exit(10);
        }
        let cell = mapped as *mut u32;
        core::ptr::write_volatile(cell, 11);

        let pid = syscall6(SYS_CLONE, SIGCHLD, 0, 0, 0, 0, 0);
        if pid < 0 {
            exit(11);
        }
        if pid == 0 {
            // Child: store the sentinel into the shared page and exit.
            core::ptr::write_volatile(cell, 42);
            exit(0);
        }

        // Parent: reap the child, then observe the shared page.
        let _ = syscall6(SYS_WAIT4, pid as u64, 0, 0, 0, 0, 0);
        let seen = core::ptr::read_volatile(cell);
        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(12);
        }
        if seen == 42 { exit(0) } else { exit(2) }
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
