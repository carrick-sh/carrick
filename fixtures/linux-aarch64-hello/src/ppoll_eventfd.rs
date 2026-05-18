#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_EVENTFD2: u64 = 19;
const SYS_READ: u64 = 63;
const SYS_WRITE: u64 = 64;
const SYS_PPOLL: u64 = 73;
const SYS_EXIT: u64 = 93;

const EFD_NONBLOCK: u64 = 0o4000;
const POLLIN: i16 = 0x0001;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

static MESSAGE: [u8; 12] = *b"ppoll ready\n";
static mut READY: PollFd = PollFd {
    fd: -1,
    events: POLLIN,
    revents: 0,
};
static mut COUNTER: u64 = 0;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let eventfd = syscall2(SYS_EVENTFD2, 1, EFD_NONBLOCK);
        if eventfd < 0 {
            exit(10);
        }

        core::ptr::addr_of_mut!(READY).write(PollFd {
            fd: eventfd as i32,
            events: POLLIN,
            revents: 0,
        });
        let ready = syscall5(
            SYS_PPOLL,
            core::ptr::addr_of_mut!(READY) as u64,
            1,
            0,
            0,
            0,
        );
        if ready != 1 {
            exit(11);
        }
        let ready_fd = core::ptr::addr_of!(READY).read_volatile();
        if ready_fd.revents & POLLIN != POLLIN {
            exit(12);
        }

        let read = syscall3(
            SYS_READ,
            eventfd as u64,
            core::ptr::addr_of_mut!(COUNTER) as u64,
            core::mem::size_of::<u64>() as u64,
        );
        if read != core::mem::size_of::<u64>() as i64 {
            exit(13);
        }
        if core::ptr::addr_of!(COUNTER).read_volatile() != 1 {
            exit(14);
        }

        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(15);
        }
        exit(0);
    }
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

unsafe fn syscall5(
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

fn exit(code: u64) -> ! {
    unsafe {
        let _ = syscall2(SYS_EXIT, code, 0);
    }
    loop {}
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}
