//! Saturate blocking POSIX mqueue calls beyond the persistent executor budget.
//!
//! Worker announcement occurs immediately before the blocking syscall. The
//! parent waits for every announcement before changing queue occupancy;
//! yielding is only a scheduling aid, never evidence that a worker blocked.
//! The conformance harness owns the outer starvation timeout.

use std::ffi::CString;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

const WORKERS: usize = 32;
const MSG_SIZE: usize = 8;

#[repr(C)]
struct MqAttr {
    flags: i64,
    maxmsg: i64,
    msgsize: i64,
    curmsgs: i64,
    reserved: [i64; 4],
}

unsafe fn mq_open(name: &CString, flags: i32, attr: *const MqAttr) -> i32 {
    unsafe { libc::syscall(libc::SYS_mq_open, name.as_ptr(), flags, 0o600, attr) as i32 }
}

unsafe fn mq_send(fd: i32, bytes: &[u8]) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_mq_timedsend,
            fd,
            bytes.as_ptr(),
            bytes.len(),
            0u32,
            std::ptr::null::<libc::timespec>(),
        )
    }
}

unsafe fn mq_receive(fd: i32, bytes: &mut [u8]) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_mq_timedreceive,
            fd,
            bytes.as_mut_ptr(),
            bytes.len(),
            std::ptr::null_mut::<u32>(),
            std::ptr::null::<libc::timespec>(),
        )
    }
}

fn run(receive: bool) -> bool {
    let name = CString::new(format!(
        "carrick_mq_progress_{}_{}",
        std::process::id(),
        receive as u8
    ))
    .unwrap();
    unsafe { libc::syscall(libc::SYS_mq_unlink, name.as_ptr()) };
    let attr = MqAttr {
        flags: 0,
        maxmsg: 1,
        msgsize: MSG_SIZE as i64,
        curmsgs: 0,
        reserved: [0; 4],
    };
    let fd = unsafe { mq_open(&name, libc::O_CREAT | libc::O_RDWR, &attr) };
    if fd < 0 {
        return false;
    }
    if !receive && unsafe { mq_send(fd, &[0x53; MSG_SIZE]) } != 0 {
        return false;
    }

    let barrier = Arc::new(Barrier::new(WORKERS + 1));
    let announced = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();
    for id in 0..WORKERS {
        let barrier = Arc::clone(&barrier);
        let announced = Arc::clone(&announced);
        let completed = Arc::clone(&completed);
        workers.push(std::thread::spawn(move || {
            let mut message = [id as u8; MSG_SIZE];
            barrier.wait();
            announced.fetch_add(1, Ordering::Release);
            let rc = if receive {
                unsafe { mq_receive(fd, &mut message) }
            } else {
                unsafe { mq_send(fd, &message) }
            };
            let succeeded = if receive {
                rc == MSG_SIZE as i64
            } else {
                rc == 0
            };
            if succeeded {
                completed.fetch_add(1, Ordering::Release);
            }
        }));
    }
    barrier.wait();
    while announced.load(Ordering::Acquire) != WORKERS {
        std::thread::yield_now();
    }

    let release_fd = unsafe { mq_open(&name, libc::O_RDWR | libc::O_NONBLOCK, std::ptr::null()) };
    if release_fd < 0 {
        return false;
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut released = 0;
    let mut message = [0x52; MSG_SIZE];
    let target = if receive { WORKERS } else { WORKERS + 1 };
    while released < target && Instant::now() < deadline {
        let rc = if receive {
            unsafe { mq_send(release_fd, &message) }
        } else {
            unsafe { mq_receive(release_fd, &mut message) }
        };
        let succeeded = if receive {
            rc == 0
        } else {
            rc == MSG_SIZE as i64
        };
        if succeeded {
            released += 1;
        } else {
            std::thread::yield_now();
        }
    }
    while completed.load(Ordering::Acquire) != WORKERS && Instant::now() < deadline {
        std::thread::yield_now();
    }
    while workers.iter().any(|worker| !worker.is_finished()) && Instant::now() < deadline {
        std::thread::yield_now();
    }
    let finished = workers.iter().all(std::thread::JoinHandle::is_finished);
    let joined = finished && workers.into_iter().all(|worker| worker.join().is_ok());
    let ok =
        released == target && completed.load(Ordering::Acquire) == WORKERS && finished && joined;
    unsafe {
        libc::close(fd);
        libc::close(release_fd);
        libc::syscall(libc::SYS_mq_unlink, name.as_ptr());
    }
    ok
}

fn main() {
    let receive = run(true);
    println!("receive_progress={receive}");
    if !receive {
        std::process::exit(1);
    }
    let send = run(false);
    println!("send_progress={send}");
    if !send {
        std::process::exit(1);
    }
}
