//! io_uring_setup must not report SQPOLL support unless the runtime actually
//! has a submission-queue polling worker. Docker's default seccomp blocks
//! io_uring_setup entirely, so the oracle path is "unavailable"; Carrick must
//! either be unavailable for SQPOLL or reject it, not hand back a half-working
//! ring that waits forever for a kernel thread that does not exist.

const SYS_IO_URING_SETUP: libc::c_long = 425;
const IORING_SETUP_SQPOLL: u32 = 1 << 1;

#[repr(C)]
#[derive(Default)]
struct IoUringParams {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: [u32; 10],
    cq_off: [u32; 10],
}

fn main() {
    let mut params = IoUringParams {
        flags: IORING_SETUP_SQPOLL,
        ..IoUringParams::default()
    };
    let fd = unsafe { libc::syscall(SYS_IO_URING_SETUP, 8u64, &mut params) } as i32;
    let ok = if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
        false
    } else {
        let errno = unsafe { *libc::__errno_location() };
        matches!(
            errno,
            libc::EINVAL | libc::EPERM | libc::EACCES | libc::ENOSYS
        )
    };
    println!("sqpoll_rejected_or_unavailable={ok}");
}
