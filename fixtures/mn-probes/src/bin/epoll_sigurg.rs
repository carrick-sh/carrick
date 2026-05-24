// Probe C — epoll netpoller-shape PLUS the same SIGURG storm. Each worker owns
// one epoll fd watching one socketpair end and bounces a byte with a driver
// thread ROUNDS times (epoll_pwait -> read -> write). A sysmon storms the
// workers with SIGURG throughout.
//
// If the epoll-only baseline passes at high P but this hangs, signal delivery
// is corrupting the epoll wait path. Prints "PROBE_C_OK <rounds>".
use std::env;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

static PREEMPTS: AtomicU64 = AtomicU64::new(0);

extern "C" fn on_sigurg(_sig: i32, _info: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    PREEMPTS.fetch_add(1, Ordering::Relaxed);
}

fn install_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_sigurg as usize;
        sa.sa_flags = libc::SA_RESTART | libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        assert_eq!(
            libc::sigaction(libc::SIGURG, &sa, std::ptr::null_mut()),
            0,
            "sigaction(SIGURG) failed"
        );
    }
}

fn gettid() -> i32 {
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

fn read_byte(fd: i32) -> Option<u8> {
    let mut b = [0u8; 1];
    let n = unsafe { libc::read(fd, b.as_mut_ptr() as *mut _, 1) };
    if n == 1 {
        Some(b[0])
    } else {
        None
    }
}

fn write_byte(fd: i32, b: u8) -> bool {
    let buf = [b];
    unsafe { libc::write(fd, buf.as_ptr() as *const _, 1) == 1 }
}

fn main() {
    let mut args = env::args().skip(1);
    let channels: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(8);
    let rounds: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(20_000);

    install_handler();
    spawn_watchdog(Duration::from_secs(40), "PROBE_C_TIMEOUT");

    let pid = unsafe { libc::getpid() };
    let tids: Arc<Mutex<Vec<i32>>> = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));

    // Per channel: a socketpair. worker watches sv[1] via its own epoll; driver
    // drives sv[0].
    let mut driver_fds = Vec::new();
    let mut worker_handles = Vec::new();
    for _ in 0..channels {
        let mut sv = [0i32; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair failed");
        let (driver_end, worker_end) = (sv[0], sv[1]);
        driver_fds.push(driver_end);

        let tids = Arc::clone(&tids);
        worker_handles.push(thread::spawn(move || {
            tids.lock().unwrap().push(gettid());
            let ep = unsafe { libc::epoll_create1(0) };
            assert!(ep >= 0, "epoll_create1 failed");
            let mut ev = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: worker_end as u64,
            };
            assert_eq!(
                unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, worker_end, &mut ev) },
                0,
                "epoll_ctl ADD failed"
            );
            let mut got = 0u64;
            while got < rounds {
                let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
                let n = unsafe { libc::epoll_pwait(ep, out.as_mut_ptr(), 4, 1000, std::ptr::null()) };
                if n < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    panic!("epoll_pwait: {e}");
                }
                if n == 0 {
                    continue; // 1s timeout slice; re-wait
                }
                if let Some(b) = read_byte(worker_end) {
                    // echo back to driver
                    if !write_byte(worker_end, b) {
                        panic!("worker echo write failed");
                    }
                    got += 1;
                }
            }
            unsafe { libc::close(ep) };
        }));
    }

    // Driver: bounce a byte through every channel `rounds` times.
    let driver = {
        let driver_fds = driver_fds.clone();
        thread::spawn(move || {
            for &fd in &driver_fds {
                write_byte(fd, 1); // prime
            }
            let mut per = vec![0u64; driver_fds.len()];
            let mut remaining = driver_fds.len();
            while remaining > 0 {
                for (i, &fd) in driver_fds.iter().enumerate() {
                    if per[i] >= rounds {
                        continue;
                    }
                    if let Some(b) = read_byte(fd) {
                        per[i] += 1;
                        if per[i] >= rounds {
                            remaining -= 1;
                        } else {
                            write_byte(fd, b);
                        }
                    }
                }
            }
        })
    };

    // Sysmon SIGURG storm.
    let sysmon = {
        let tids = Arc::clone(&tids);
        let done = Arc::clone(&done);
        thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let snapshot = tids.lock().unwrap().clone();
                for tid in snapshot {
                    unsafe {
                        libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGURG);
                    }
                }
                thread::sleep(Duration::from_micros(50));
            }
        })
    };

    for h in worker_handles {
        h.join().unwrap();
    }
    driver.join().unwrap();
    done.store(true, Ordering::Relaxed);
    sysmon.join().unwrap();

    for &fd in &driver_fds {
        unsafe { libc::close(fd) };
    }
    println!(
        "PROBE_C_OK {rounds} preempts={}",
        PREEMPTS.load(Ordering::Relaxed)
    );
}

fn spawn_watchdog(budget: Duration, msg: &'static str) {
    let start = Instant::now();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(200));
        if start.elapsed() >= budget {
            eprintln!("{msg} preempts={}", PREEMPTS.load(Ordering::Relaxed));
            std::process::exit(2);
        }
    });
}
