//! A child that takes a shared-memory RobustLock and is SIGKILLed must be
//! recoverable via force_break from the surviving process.
#![allow(clippy::panic, clippy::unwrap_used)]

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use carrick_kernel::domains::{HostPid, ProcessGeneration};
use carrick_kernel::lock::{LockOwner, RobustLock};
use carrick_kernel::wait::SpinYield;

#[repr(C)]
struct Shared {
    lock: RobustLock,
    child_holds: AtomicU32,
}

fn map_shared() -> &'static Shared {
    let size = std::mem::size_of::<Shared>();
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_SHARED,
            -1,
            0,
        )
    };
    assert!(ptr != libc::MAP_FAILED);
    unsafe { &*(ptr as *const Shared) }
}

#[test]
fn kill9_holder_is_recoverable() {
    let shared = map_shared();
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let me = LockOwner {
            pid: HostPid::new(unsafe { libc::getpid() } as u32),
            generation: ProcessGeneration::new(1),
        };
        let g = shared
            .lock
            .lock(me, &SpinYield, Duration::from_secs(5))
            .unwrap_or_else(|_| std::process::exit(2));
        shared.child_holds.store(1, Ordering::Release);
        std::mem::forget(g);
        loop {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while shared.child_holds.load(Ordering::Acquire) == 0 {
        assert!(std::time::Instant::now() < deadline, "child never locked");
        std::thread::yield_now();
    }

    unsafe {
        libc::kill(child, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(child, &mut status, 0);
    }

    let survivor = LockOwner {
        pid: HostPid::new(unsafe { libc::getpid() } as u32),
        generation: ProcessGeneration::new(2),
    };
    assert!(
        shared
            .lock
            .lock(survivor, &SpinYield, Duration::from_millis(50))
            .is_err()
    );
    let dead = shared.lock.holder().unwrap();
    assert_eq!(dead.pid.raw(), child as u32);
    assert!(shared.lock.force_break(dead));
    let _g = shared
        .lock
        .lock(survivor, &SpinYield, Duration::from_secs(1))
        .unwrap_or_else(|_| panic!("lock after break"));
}
