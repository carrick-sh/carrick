//! Runtime-free witness of the ARM crossing policy, including terminal delivery.
#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

#[repr(C)]
struct Timespec {
    seconds: i64,
    nanoseconds: i64,
}
#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let uid = unsafe { syscall(174, [0; 6]) };
    let message: &[u8] = if uid == -38 {
        b"ring-first strict\n"
    } else if uid >= 0 {
        b"ring-first forward\n"
    } else {
        exit(10);
    };
    if unsafe { syscall(172, [0; 6]) } <= 0 {
        exit(11);
    }
    let mut now = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    if unsafe { syscall(113, [1, (&mut now as *mut Timespec) as u64, 0, 0, 0, 0]) } != 0 {
        exit(12);
    }
    // The only descriptor wait is bounded. A lost readiness notification
    // fails the witness instead of parking it forever. Output fits PIPE_BUF.
    let mut fd = PollFd {
        fd: 1,
        events: 4,
        revents: 0,
    };
    let timeout = Timespec {
        seconds: 5,
        nanoseconds: 0,
    };
    let ready = unsafe {
        syscall(
            73,
            [
                (&mut fd as *mut PollFd) as u64,
                1,
                (&timeout as *const Timespec) as u64,
                0,
                0,
                0,
            ],
        )
    };
    if ready != 1 || fd.revents & 4 == 0 {
        exit(13);
    }
    if unsafe {
        syscall(
            64,
            [1, message.as_ptr() as u64, message.len() as u64, 0, 0, 0],
        )
    } != message.len() as i64
    {
        exit(14);
    }
    exit(0);
}

unsafe fn syscall(number: u64, args: [u64; 6]) -> i64 {
    let result: i64;
    unsafe {
        asm!("svc #0", inlateout("x0") args[0] as i64 => result,
            in("x1") args[1], in("x2") args[2], in("x3") args[3],
            in("x4") args[4], in("x5") args[5], in("x8") number,
            options(nostack));
    }
    result
}

fn exit(status: u64) -> ! {
    unsafe {
        syscall(94, [status, 0, 0, 0, 0, 0]);
    }
    // A terminal syscall returning is a failed kernel contract. Trap rather
    // than hiding it behind an infinite guest loop.
    unsafe {
        asm!("brk #0", options(noreturn));
    }
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    exit(15)
}
