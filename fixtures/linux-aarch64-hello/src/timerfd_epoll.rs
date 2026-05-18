#![no_main]
#![no_std]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 64;
const SYS_EXIT: u64 = 93;
const SYS_EPOLL_CREATE1: u64 = 20;
const SYS_EPOLL_CTL: u64 = 21;
const SYS_EPOLL_PWAIT: u64 = 22;
const SYS_READ: u64 = 63;
const SYS_TIMERFD_CREATE: u64 = 85;
const SYS_TIMERFD_SETTIME: u64 = 86;

const CLOCK_MONOTONIC: u64 = 1;
const TFD_NONBLOCK: u64 = 0o4000;
const TFD_TIMER_ABSTIME: u64 = 1;
const EPOLL_CTL_ADD: u64 = 1;
const EPOLLIN: u32 = 0x001;

#[repr(C, packed)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C, packed)]
struct Itimerspec {
    it_interval: Timespec,
    it_value: Timespec,
}

#[repr(C, packed)]
struct EpollEvent {
    events: u32,
    data: u64,
}

static TIMER: Itimerspec = Itimerspec {
    it_interval: Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    },
    it_value: Timespec {
        tv_sec: 0,
        tv_nsec: 1,
    },
};
static MESSAGE: [u8; 14] = *b"timerfd ready\n";

static mut WANTED: EpollEvent = EpollEvent {
    events: EPOLLIN,
    data: 0x544d,
};
static mut READY: EpollEvent = EpollEvent { events: 0, data: 0 };
static mut EXPIRATIONS: u64 = 0;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let timerfd = syscall2(SYS_TIMERFD_CREATE, CLOCK_MONOTONIC, TFD_NONBLOCK);
        if timerfd < 0 {
            exit(10);
        }

        let epfd = syscall1(SYS_EPOLL_CREATE1, 0);
        if epfd < 0 {
            exit(11);
        }

        let ctl = syscall4(
            SYS_EPOLL_CTL,
            epfd as u64,
            EPOLL_CTL_ADD,
            timerfd as u64,
            core::ptr::addr_of_mut!(WANTED) as u64,
        );
        if ctl < 0 {
            exit(12);
        }

        let settime = syscall4(
            SYS_TIMERFD_SETTIME,
            timerfd as u64,
            TFD_TIMER_ABSTIME,
            core::ptr::addr_of!(TIMER) as u64,
            0,
        );
        if settime < 0 {
            exit(13);
        }

        let ready = syscall6(
            SYS_EPOLL_PWAIT,
            epfd as u64,
            core::ptr::addr_of_mut!(READY) as u64,
            1,
            0,
            0,
            0,
        );
        if ready != 1 {
            exit(14);
        }

        let read = syscall3(
            SYS_READ,
            timerfd as u64,
            core::ptr::addr_of_mut!(EXPIRATIONS) as u64,
            core::mem::size_of::<u64>() as u64,
        );
        if read != core::mem::size_of::<u64>() as i64 {
            exit(15);
        }
        if core::ptr::addr_of!(EXPIRATIONS).read_volatile() == 0 {
            exit(16);
        }

        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(17);
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
        let _ = syscall1(SYS_EXIT, code);
    }
    loop {}
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}
