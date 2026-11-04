//! Same-process wait4/vfork dependency, also run on native Linux.
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

unsafe fn byte(fd: i32) -> bool {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let mut b = 0u8;
    unsafe {
        libc::poll(&mut p, 1, 5000) == 1
            && libc::read(fd, (&mut b as *mut u8).cast(), 1) == 1
            && b == 7
    }
}
extern "C" fn child(arg: *mut libc::c_void) -> i32 {
    let fd = arg as isize as i32;
    let b = 7u8;
    unsafe {
        let ok = libc::write(fd, (&b as *const u8).cast(), 1) == 1;
        libc::_exit(if ok { 0 } else { 1 });
    }
}

pub fn run(waiters: usize) -> i32 {
    assert!(waiters > 0 && waiters <= 128);
    // One CPU makes early clone return observable before its child can run.
    // The 32-waiter row still retains all live threads and the default pool.
    let mut saved: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&saved), &mut saved) },
        0
    );
    let cpu = (0..libc::CPU_SETSIZE as usize)
        .find(|&cpu| unsafe { libc::CPU_ISSET(cpu, &saved) })
        .unwrap();
    let mut one: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::CPU_SET(cpu, &mut one);
    }
    assert_eq!(
        unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&one), &one) },
        0
    );
    let mut pipe = [-1; 2];
    let mut release = [-1; 2];
    assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
    assert_eq!(
        unsafe { libc::pipe2(release.as_mut_ptr(), libc::O_NONBLOCK) },
        0
    );
    let entered = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::new();
    for _ in 0..waiters {
        let entered = entered.clone();
        threads.push(std::thread::spawn(move || {
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                // Only B can release this child, after B's vfork returns.
                unsafe { libc::_exit(if byte(pipe[0]) { 0 } else { 1 }) }
            }
            assert!(pid > 0);
            entered.fetch_add(1, Ordering::Release);
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert_eq!(status, 0);
        }));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while entered.load(Ordering::Acquire) != waiters {
        assert!(Instant::now() < deadline, "waiter births must complete");
        std::thread::yield_now();
    }
    // libc clone supplies a private child stack: no vfork return through a
    // Rust caller's stack frame. Only async-signal-safe calls run in child.
    let mut stack = vec![0u8; 65536];
    let top = ((stack.as_mut_ptr() as usize + stack.len()) & !15) as *mut libc::c_void;
    let pid = unsafe {
        libc::clone(
            child,
            top,
            libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD,
            release[1] as isize as *mut libc::c_void,
        )
    };
    assert!(pid > 0);
    let mut marker = 0u8;
    assert_eq!(
        unsafe { libc::read(release[0], (&mut marker as *mut u8).cast(), 1) },
        1,
        "vfork returned before its child released it"
    );
    assert_eq!(marker, 7);
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert_eq!(status, 0);
    let bytes = vec![7u8; waiters];
    assert_eq!(
        unsafe { libc::write(pipe[1], bytes.as_ptr().cast(), bytes.len()) },
        waiters as isize
    );
    for thread in threads {
        thread.join().unwrap();
    }
    for fd in [pipe[0], pipe[1], release[0], release[1]] {
        assert_eq!(unsafe { libc::close(fd) }, 0);
    }
    assert_eq!(
        unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&saved), &saved) },
        0
    );
    println!("thread-continuation ok waiters={waiters}");
    0
}
