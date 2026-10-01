//! Host-read source isolation under a concurrent unmap.
//!
//! `write(2)`/`pwritev(2)` read the caller's buffer while the syscall runs. If
//! a sibling thread unmaps (or `MAP_FIXED`-replaces) that buffer meanwhile,
//! Linux keeps every page it is copying referenced until the copy ends: the
//! write either completes with the old bytes, comes up short, or fails with
//! `EFAULT`, and any freshly mapped replacement page reads zero (or the
//! sibling's own refill). It can never read a page that another process owns
//! by then.
//!
//! Process P writes a 1 MiB `'A'`-filled anonymous buffer to a regular file
//! from one thread while a sibling thread loops `munmap` + `MAP_FIXED` remap +
//! refill of the same buffer. Process Q (a forked child, so a different
//! address space) keeps first-touching fresh anonymous pages with `'B'`,
//! taking whatever physical pages were released most recently. After every
//! write P reads the file back: only `'A'` and `'\0'` bytes may appear. A
//! `'B'` byte means P's host write read a page that Q owned at the time.
//!
//! Every value printed is deterministic on Linux (booleans and zero-valued
//! violation counters; the number of race rounds reached is never printed),
//! and every wait is bounded.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const LEN: usize = 1 << 20;
const WRITES: usize = 2000;
/// The race runs for this long (or `WRITES` rounds); only violation counters
/// are printed, so the round count reached never affects the output.
const RACE_FOR: Duration = Duration::from_secs(4);
const NEIGHBOR_LEN: usize = 1 << 20;
const BOUND: Duration = Duration::from_secs(20);

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[derive(Default)]
struct Tally {
    calls: usize,
    progressed: usize,
    foreign: usize,
    unexpected_bytes: usize,
    unexpected_errno: usize,
    over_report: usize,
}

fn map_buffer(at: *mut libc::c_void, fixed: bool) -> *mut u8 {
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | if fixed { libc::MAP_FIXED } else { 0 };
    let ptr = unsafe { libc::mmap(at, LEN, libc::PROT_READ | libc::PROT_WRITE, flags, -1, 0) };
    if ptr == libc::MAP_FAILED {
        return std::ptr::null_mut();
    }
    let ptr = ptr as *mut u8;
    unsafe { std::ptr::write_bytes(ptr, b'A', LEN) };
    ptr
}

fn neighbor(stop: *const AtomicBool) -> ! {
    // Q: keep taking fresh pages and stamping them 'B' until told to stop.
    let deadline = Instant::now() + BOUND;
    let stop = unsafe { &*stop };
    while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                NEIGHBOR_LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if page == libc::MAP_FAILED {
            unsafe { libc::_exit(2) };
        }
        unsafe {
            std::ptr::write_bytes(page as *mut u8, b'B', NEIGHBOR_LEN);
            libc::munmap(page, NEIGHBOR_LEN);
        }
    }
    unsafe { libc::_exit(0) }
}

fn verify(fd: i32, written: usize, check: &mut [u8], tally: &mut Tally) {
    if written == 0 {
        return;
    }
    let got = unsafe { libc::pread(fd, check.as_mut_ptr().cast(), written, 0) };
    if got != written as isize {
        tally.over_report += 1;
        return;
    }
    for &byte in &check[..written] {
        match byte {
            b'A' | 0 => {}
            b'B' => tally.foreign += 1,
            _ => tally.unexpected_bytes += 1,
        }
    }
}

fn record(n: isize, tally: &mut Tally) -> usize {
    tally.calls += 1;
    if n < 0 {
        if errno() != libc::EFAULT {
            tally.unexpected_errno += 1;
        }
        return 0;
    }
    let n = n as usize;
    if n > LEN {
        tally.over_report += 1;
        return 0;
    }
    if n > 0 {
        tally.progressed += 1;
    }
    n
}

fn main() {
    // Shared stop word for Q: a MAP_SHARED page survives the fork.
    let shared = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if shared == libc::MAP_FAILED {
        println!("setup=mmap_shared_failed");
        return;
    }
    let stop_q = shared as *const AtomicBool;
    let q = unsafe { libc::fork() };
    if q == 0 {
        neighbor(stop_q);
    }
    if q < 0 {
        println!("setup=fork_failed");
        return;
    }

    let path = b"/tmp/hostreadunmap.out\0";
    let fd = unsafe {
        libc::open(
            path.as_ptr().cast(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        )
    };
    let buf = map_buffer(std::ptr::null_mut(), false);
    if fd < 0 || buf.is_null() {
        println!("setup=open_or_mmap_failed");
        unsafe {
            (*stop_q).store(true, Ordering::Release);
            libc::kill(q, libc::SIGKILL);
            libc::waitpid(q, std::ptr::null_mut(), 0);
        }
        return;
    }
    let buf_addr = buf as usize;

    let stop_remap = Arc::new(AtomicBool::new(false));
    let remap_cycles = Arc::new(AtomicUsize::new(0));
    let remap_failures = Arc::new(AtomicUsize::new(0));
    let remapper = {
        let stop = Arc::clone(&stop_remap);
        let cycles = Arc::clone(&remap_cycles);
        let failures = Arc::clone(&remap_failures);
        std::thread::spawn(move || {
            let deadline = Instant::now() + BOUND;
            while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
                let at = buf_addr as *mut libc::c_void;
                unsafe { libc::munmap(at, LEN) };
                if map_buffer(at, true) != buf_addr as *mut u8 {
                    failures.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                cycles.fetch_add(1, Ordering::Relaxed);
            }
        })
    };

    let mut check = vec![0_u8; LEN];
    let mut write_tally = Tally::default();
    let mut pwritev_tally = Tally::default();
    let deadline = Instant::now() + RACE_FOR;
    for _ in 0..WRITES {
        if Instant::now() >= deadline {
            break;
        }
        unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
        let n = unsafe { libc::write(fd, buf as *const libc::c_void, LEN) };
        let n = record(n, &mut write_tally);
        verify(fd, n, &mut check, &mut write_tally);

        let iov = [
            libc::iovec {
                iov_base: buf.cast(),
                iov_len: LEN / 2,
            },
            libc::iovec {
                iov_base: unsafe { buf.add(LEN / 2) }.cast(),
                iov_len: LEN / 2,
            },
        ];
        let n = unsafe { libc::pwritev(fd, iov.as_ptr(), 2, 0) };
        let n = record(n, &mut pwritev_tally);
        verify(fd, n, &mut check, &mut pwritev_tally);
    }

    stop_remap.store(true, Ordering::Release);
    let _ = remapper.join();
    unsafe { (*stop_q).store(true, Ordering::Release) };
    // Q polls the stop word; bound its exit, then reap it either way.
    let mut status = 0;
    let reap_deadline = Instant::now() + Duration::from_secs(5);
    let mut reaped = false;
    while Instant::now() < reap_deadline {
        if unsafe { libc::waitpid(q, &mut status, libc::WNOHANG) } == q {
            reaped = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if !reaped {
        unsafe {
            libc::kill(q, libc::SIGKILL);
            libc::waitpid(q, &mut status, 0);
        }
    }
    unsafe {
        libc::close(fd);
        libc::unlink(path.as_ptr().cast());
    }

    for (name, tally) in [("write", &write_tally), ("pwritev", &pwritev_tally)] {
        println!("{name}_called={}", tally.calls > 0);
        println!("{name}_made_progress={}", tally.progressed > 0);
        println!("{name}_foreign_bytes={}", tally.foreign);
        println!("{name}_unexpected_bytes={}", tally.unexpected_bytes);
        println!("{name}_unexpected_errno={}", tally.unexpected_errno);
        println!("{name}_length_mismatch={}", tally.over_report);
    }
    println!(
        "remapper_cycled={}",
        remap_cycles.load(Ordering::Relaxed) > 0
    );
    println!(
        "remapper_failures={}",
        remap_failures.load(Ordering::Relaxed)
    );
    println!(
        "neighbor_clean_exit={}",
        reaped && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    );
}
