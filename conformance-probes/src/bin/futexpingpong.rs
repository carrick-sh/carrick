//! Cross-process FUTEX_WAKE reliability probe (lost-wake detector).
//!
//! Two processes ping-pong a `turn` flag in a `MAP_SHARED` file word using the
//! SHARED (cross-process, no `FUTEX_PRIVATE_FLAG`) futex path — exactly what
//! carrick routes through Darwin `os_sync`/`__ulock`. On real Linux a
//! `FUTEX_WAKE` always reaches a parked `FUTEX_WAIT`, so no waiter ever blocks to
//! its timeout: `lost_wake_detected=false`. A dropped cross-process wake makes a
//! waiter block until its 2s timeout while the peer has ALREADY advanced the
//! flag — that mismatch (ETIMEDOUT yet the word moved) is the lost wake.
//!
//! Deterministic output (booleans only). Runs under `--fs host` so the
//! `MAP_SHARED` file becomes a real host `MAP_SHARED` (the inter-process
//! rendezvous carrick keys `__ulock` on). run-elf's rootfs is empty, so we
//! mkdir /tmp + create the backing file ourselves.

const FUTEX_WAIT: i64 = 0; // SHARED (no FUTEX_PRIVATE_FLAG)
const FUTEX_WAKE: i64 = 1;

fn futex_wait(addr: *const u32, val: u32, ms: i64) -> i32 {
    let ts = libc::timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    };
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            addr,
            FUTEX_WAIT,
            val,
            &ts as *const libc::timespec,
            std::ptr::null::<u32>(),
            0u32,
        ) as i32
    }
}

fn futex_wake(addr: *const u32, n: i32) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            addr,
            FUTEX_WAKE,
            n,
            std::ptr::null::<libc::timespec>(),
            std::ptr::null::<u32>(),
            0u32,
        )
    }
}

fn main() {
    let n_iter: u32 = 5000;
    unsafe { libc::mkdir(b"/tmp\0".as_ptr() as *const libc::c_char, 0o777) };
    let fd = unsafe {
        libc::open(
            b"/tmp/futex_pp.bin\0".as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_CREAT,
            0o600,
        )
    };
    assert!(fd >= 0, "open backing file");
    assert_eq!(unsafe { libc::ftruncate(fd, 4096) }, 0, "ftruncate");
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    assert_ne!(base, libc::MAP_FAILED, "mmap MAP_SHARED");
    let turn = base as *mut u32; // 0 = parent's turn, 1 = child's turn
    // a separate flag word (idempotent set, race-free for a boolean signal)
    let lost = unsafe { (base as *mut u8).add(64) } as *mut u32;
    // diagnostic counters in shared mem: parent iter @ +128, child iter @ +192,
    // child-done marker @ +256.
    let p_iter = unsafe { (base as *mut u8).add(128) } as *mut u32;
    let c_iter = unsafe { (base as *mut u8).add(192) } as *mut u32;
    let c_done = unsafe { (base as *mut u8).add(256) } as *mut u32;
    unsafe {
        turn.write_volatile(0);
        lost.write_volatile(0);
        p_iter.write_volatile(0);
        c_iter.write_volatile(0);
        c_done.write_volatile(0);
    }

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        // child: wait for turn==1, then hand back (turn=0 + wake parent)
        for it in 0..n_iter {
            unsafe { c_iter.write_volatile(it) };
            loop {
                if unsafe { turn.read_volatile() } == 1 {
                    break;
                }
                let rc = futex_wait(turn, 0, 500);
                if rc == -1 {
                    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                    if e == libc::ETIMEDOUT && unsafe { turn.read_volatile() } == 1 {
                        unsafe { lost.write_volatile(1) }; // peer advanced; our wake was lost
                        break;
                    }
                }
            }
            unsafe { turn.write_volatile(0) };
            futex_wake(turn, 1);
        }
        unsafe { c_done.write_volatile(0xDEAD) };
        unsafe { libc::_exit(0) };
    }

    // parent: hand to child (turn=1 + wake), wait for turn==0
    for it in 0..n_iter {
        unsafe { p_iter.write_volatile(it) };
        unsafe { turn.write_volatile(1) };
        futex_wake(turn, 1);
        loop {
            if unsafe { turn.read_volatile() } == 0 {
                break;
            }
            let rc = futex_wait(turn, 1, 500);
            if rc == -1 {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if e == libc::ETIMEDOUT && unsafe { turn.read_volatile() } == 0 {
                    unsafe { lost.write_volatile(1) };
                    break;
                }
            }
        }
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    // Linux: the ping-pong always completes via wakes -> no lost wake.
    println!(
        "lost_wake_detected={}",
        unsafe { lost.read_volatile() } != 0
    );
    println!("completed=true");
}
