//! Perf probe: CPython-shaped anonymous arena churn.
//!
//! `cpython-call` issues ~3,200 `mmap` and ~3,100 `munmap` calls in one run:
//! obmalloc allocates 256 KiB (Python 3.12: 1 MiB) arenas, touches them page
//! by page as objects are carved out, and frees whole arenas back with
//! `munmap`. Per-op cost of that cycle is the lever for the compute-bound
//! CPython suites, so this probe measures exactly that cycle:
//!   - `arena_churn_us`: ITERS × (mmap 256 KiB, touch every 4 KiB page, munmap)
//!   - `arena_pool_us`: keep POOL arenas live, rotate the oldest each iteration
//!   - `arena_untouched_us`: mmap + munmap without touching (VMA cost only)
//! Output is `key=value` lines parsed by the perf gate.

use std::time::Instant;

const ARENA: usize = 256 * 1024;
const PAGE: usize = 4096;
const ITERS: usize = 2000;
const POOL: usize = 64;

unsafe fn map() -> *mut u8 {
    let p = libc::mmap(
        std::ptr::null_mut(),
        ARENA,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    assert!(p != libc::MAP_FAILED, "mmap failed");
    p as *mut u8
}

unsafe fn touch(p: *mut u8) {
    let mut off = 0;
    while off < ARENA {
        p.add(off).write_volatile(1);
        off += PAGE;
    }
}

fn main() {
    unsafe {
        let start = Instant::now();
        for _ in 0..ITERS {
            let p = map();
            touch(p);
            assert_eq!(libc::munmap(p as *mut _, ARENA), 0);
        }
        let churn = start.elapsed().as_micros();

        let mut pool: Vec<*mut u8> = (0..POOL).map(|_| map()).collect();
        for p in &pool {
            touch(*p);
        }
        let start = Instant::now();
        for i in 0..ITERS {
            let slot = i % POOL;
            assert_eq!(libc::munmap(pool[slot] as *mut _, ARENA), 0);
            let p = map();
            touch(p);
            pool[slot] = p;
        }
        let pooled = start.elapsed().as_micros();
        for p in pool {
            libc::munmap(p as *mut _, ARENA);
        }

        let start = Instant::now();
        for _ in 0..ITERS {
            let p = map();
            assert_eq!(libc::munmap(p as *mut _, ARENA), 0);
        }
        let untouched = start.elapsed().as_micros();

        println!("arena_churn_us={churn}");
        println!("arena_pool_us={pooled}");
        println!("arena_untouched_us={untouched}");
        println!("iters={ITERS}");
        println!("arena_bytes={ARENA}");
    }
}
