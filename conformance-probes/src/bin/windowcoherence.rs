//! Fault window memory coherence reproducer probe.
//!
//! Exercises the 64 KiB anonymous fault window invariants:
//! 1. 4 threads each owning 8 MiB private anonymous mappings.
//! 2. Sparse touches in 64 KiB windows (non-monotonic order, e.g. chunk 1 then chunk 0).
//! 3. `mprotect(PROT_NONE)` -> `mprotect(RW)` partial window re-protection (Go sysReserve/sysMap).
//! 4. `mmap(MAP_FIXED)` over portions of anonymous windows.
//! 5. `madvise(MADV_DONTNEED)` on sub-ranges (verifying zero on refault).
//! 6. `fork()` child verification and COW isolation while parent continues writing.

use std::sync::atomic::{AtomicUsize, Ordering};

const PAGE_SIZE: usize = 4096;
const COMPOUND_SIZE: usize = 16384;
const WINDOW_SIZE: usize = 65536;
const REGION_SIZE: usize = 8 * 1024 * 1024; // 8 MiB per thread
const NUM_THREADS: usize = 4;
const ITERS: usize = 40;

static PATTERN_MISMATCHES: AtomicUsize = AtomicUsize::new(0);
static NONZERO_AFTER_DONTNEED: AtomicUsize = AtomicUsize::new(0);
static NONZERO_PRISTINE: AtomicUsize = AtomicUsize::new(0);
static CHILD_MISMATCHES: AtomicUsize = AtomicUsize::new(0);

#[inline]
fn canary(addr: usize, iter: usize) -> u64 {
    0xCAFE_BABE_0000_0000u64
        ^ ((iter as u64) << 32)
        ^ (addr as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

struct XorShift {
    state: u64,
}

impl XorShift {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x8a5b_f789_0831_4961 } else { seed },
        }
    }

    fn next_u32(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        (x & 0xFFFF_FFFF) as u32
    }
}

// Fragment local mapping table so self.mappings has out-of-order entries
fn fragment_mappings() {
    let mut ptrs = Vec::new();
    for _ in 0..16 {
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                65536,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p != libc::MAP_FAILED {
            ptrs.push(p);
        }
    }
    for (i, &p) in ptrs.iter().enumerate() {
        if i % 2 == 1 {
            unsafe {
                libc::munmap((p as *mut u8).add(16384) as *mut libc::c_void, 16384);
            }
        }
    }
}

struct CrossThreadArg {
    base: *mut u8,
    step: *const AtomicUsize,
    pipe_fd: libc::c_int,
    thread_id: usize,
}

unsafe impl Send for CrossThreadArg {}
unsafe impl Sync for CrossThreadArg {}

extern "C" fn cross_thread_worker(arg_ptr: *mut libc::c_void) -> *mut libc::c_void {
    let arg = unsafe { &*(arg_ptr as *const CrossThreadArg) };
    let base = arg.base;
    let step = unsafe { &*arg.step };
    let pipe_fd = arg.pipe_fd;

    if arg.thread_id == 0 {
        // Step 1: Thread 0 touches offset 0 KiB (chunk 0 of 64 KiB window)
        let p_0k = base as *mut u64;
        unsafe { p_0k.write_volatile(0xCCCC_7777_8888_9999) };

        // Signal Thread 1
        step.store(1, Ordering::Release);
    } else {
        // Wait for Thread 0 (step 1)
        while step.load(Ordering::Acquire) != 1 {
            std::hint::spin_loop();
        }

        // Thread 1: read from pipe into offset 16 KiB (chunk 1 of the 64 KiB window that Thread 0 widened)
        let p_16k = unsafe { base.add(16 * 1024) as *mut libc::c_void };
        let n = unsafe { libc::read(pipe_fd, p_16k, 8) };
        if n != 8 {
            let err = unsafe { *libc::__errno_location() };
            eprintln!(
                "REPRODUCED CORRUPTION: sibling read into offset 16K returned {n}, errno={err}"
            );
            PATTERN_MISMATCHES.fetch_add(1, Ordering::Relaxed);
        } else {
            let val = unsafe { *(p_16k as *const u64) };
            if val != 0x1122_3344_5566_7788 {
                eprintln!(
                    "REPRODUCED CORRUPTION: sibling read expected 0x1122334455667788, got 0x{val:x}"
                );
                PATTERN_MISMATCHES.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    std::ptr::null_mut()
}

fn test_cross_thread_window() {
    let size = 2 * 1024 * 1024;
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return;
    }
    let base = ptr as *mut u8;
    eprintln!("test_cross_thread_window: ptr = {:p}", ptr);
    let step = AtomicUsize::new(0);

    let mut pipe_fds = [0 as libc::c_int; 2];
    unsafe {
        libc::pipe(pipe_fds.as_mut_ptr());
        let val: u64 = 0x1122_3344_5566_7788;
        libc::write(pipe_fds[1], &val as *const u64 as *const libc::c_void, 8);
    }

    let mut t0: libc::pthread_t = 0 as libc::pthread_t;
    let mut t1: libc::pthread_t = 0 as libc::pthread_t;
    let arg0 = CrossThreadArg {
        base,
        step: &step as *const AtomicUsize,
        pipe_fd: pipe_fds[0],
        thread_id: 0,
    };
    let arg1 = CrossThreadArg {
        base,
        step: &step as *const AtomicUsize,
        pipe_fd: pipe_fds[0],
        thread_id: 1,
    };

    unsafe {
        libc::pthread_create(
            &mut t0,
            std::ptr::null(),
            cross_thread_worker,
            &arg0 as *const CrossThreadArg as *mut libc::c_void,
        );
        libc::pthread_create(
            &mut t1,
            std::ptr::null(),
            cross_thread_worker,
            &arg1 as *const CrossThreadArg as *mut libc::c_void,
        );
        libc::pthread_join(t0, std::ptr::null_mut());
        libc::pthread_join(t1, std::ptr::null_mut());
        libc::close(pipe_fds[0]);
        libc::close(pipe_fds[1]);
        libc::munmap(ptr, size);
    }
}

struct WorkerArg {
    thread_id: usize,
}

extern "C" fn worker_thread(arg: *mut libc::c_void) -> *mut libc::c_void {
    let arg = unsafe { &*(arg as *const WorkerArg) };
    let tid = arg.thread_id;
    let mut rng = XorShift::new(0x1234_5678_9ABC_DEF0 ^ ((tid as u64 + 1) * 0x517C_C1B7_2722_0A95));

    fragment_mappings();

    let region = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            REGION_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if region == libc::MAP_FAILED {
        return std::ptr::null_mut();
    }
    let base = region as *mut u8;

    let reserve_size = 16 * 1024 * 1024;
    let reserve = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            reserve_size,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let reserve_base = if reserve != libc::MAP_FAILED {
        reserve as *mut u8
    } else {
        std::ptr::null_mut()
    };

    let total_pages = REGION_SIZE / PAGE_SIZE;
    let _num_windows = REGION_SIZE / WINDOW_SIZE;
    let mut written = vec![false; total_pages];
    let mut page_iter = vec![0usize; total_pages];

    // Dedicated range for fork tests: pages 0..64. General workload uses 64..total_pages.
    let workload_start_page = 64;
    let workload_pages = total_pages - workload_start_page;
    let workload_windows = workload_pages / (WINDOW_SIZE / PAGE_SIZE);

    for iter in 1..=ITERS {
        // Step 1: Touch pages sparsely in random order within chosen windows.
        // Specifically exercise non-monotonic touches: touch higher chunks in window first,
        // then lower chunks (e.g. chunk 1 at 16K, chunk 2 at 32K, then chunk 0 at 0).
        let w = (rng.next_u32() as usize) % workload_windows;
        let window_start_page = workload_start_page + w * (WINDOW_SIZE / PAGE_SIZE);
        let _window_base = unsafe { base.add(window_start_page * PAGE_SIZE) };

        let order = if iter % 2 == 0 {
            [4, 8, 12, 0] // pages: 4 (16K), 8 (32K), 12 (48K), 0 (0K)
        } else {
            [12, 0, 4, 8]
        };

        for &page_in_w in &order {
            let page_idx = window_start_page + page_in_w;
            let page_addr = unsafe { base.add(page_idx * PAGE_SIZE) };

            if !written[page_idx] {
                let val = unsafe { *(page_addr as *const u64) };
                if val != 0 {
                    NONZERO_PRISTINE.fetch_add(1, Ordering::Relaxed);
                }
            }

            let c = canary(page_addr as usize, iter);
            unsafe {
                *(page_addr as *mut u64) = c;
                *((page_addr as *mut u64).add(511)) = c ^ 0x5555_5555_5555_5555;
            }
            written[page_idx] = true;
            page_iter[page_idx] = iter;

            // Verify previously written sibling pages in this window still hold patterns
            for &sibling_page in &order {
                let sib_idx = window_start_page + sibling_page;
                if written[sib_idx] {
                    let sib_addr = unsafe { base.add(sib_idx * PAGE_SIZE) };
                    let expected = canary(sib_addr as usize, page_iter[sib_idx]);
                    let actual = unsafe { *(sib_addr as *const u64) };
                    if actual != expected {
                        PATTERN_MISMATCHES.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        // Step 2: Go sysReserve / sysMap pattern on reserve_base:
        // mprotect sub-range NONE -> RW in 64 KiB pieces
        if !reserve_base.is_null() {
            let res_w = (rng.next_u32() as usize) % (reserve_size / WINDOW_SIZE);
            let res_addr = unsafe { reserve_base.add(res_w * WINDOW_SIZE) };
            let rc = unsafe {
                libc::mprotect(
                    res_addr as *mut libc::c_void,
                    WINDOW_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            };
            if rc == 0 {
                // Touch chunk 1 (offset 16 KiB) first
                let p_chunk1 = unsafe { res_addr.add(COMPOUND_SIZE) as *mut u64 };
                let c1 = canary(p_chunk1 as usize, iter);
                unsafe { p_chunk1.write_volatile(c1) };

                // Then touch chunk 0 (offset 0)
                let p_chunk0 = res_addr as *mut u64;
                let c0 = canary(p_chunk0 as usize, iter);
                unsafe { p_chunk0.write_volatile(c0) };

                // Verify chunk 1 was not wiped by chunk 0's fault window
                let read1 = unsafe { p_chunk1.read_volatile() };
                if read1 != c1 {
                    PATTERN_MISMATCHES.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        // Step 3: madvise(MADV_DONTNEED) random sub-range
        if iter % 4 == 0 {
            let madv_w = (rng.next_u32() as usize) % workload_windows;
            let madv_start = workload_start_page + madv_w * (WINDOW_SIZE / PAGE_SIZE) + 4;
            let madv_addr = unsafe { base.add(madv_start * PAGE_SIZE) };
            unsafe {
                libc::madvise(
                    madv_addr as *mut libc::c_void,
                    COMPOUND_SIZE,
                    libc::MADV_DONTNEED,
                );
            }
            let read_zero = unsafe { *(madv_addr as *const u64) };
            if read_zero != 0 {
                NONZERO_AFTER_DONTNEED.fetch_add(1, Ordering::Relaxed);
            }
            for p in madv_start..(madv_start + 4) {
                written[p] = false;
            }
        }

        // Step 4: mmap(MAP_FIXED) a new anonymous mapping over a 16 KiB piece
        if iter % 7 == 0 {
            let fixed_w = (rng.next_u32() as usize) % workload_windows;
            let fixed_start = workload_start_page + fixed_w * (WINDOW_SIZE / PAGE_SIZE) + 8;
            let fixed_addr = unsafe { base.add(fixed_start * PAGE_SIZE) };
            let fixed = unsafe {
                libc::mmap(
                    fixed_addr as *mut libc::c_void,
                    COMPOUND_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };
            if fixed != libc::MAP_FAILED {
                let val = unsafe { *(fixed_addr as *const u64) };
                if val != 0 {
                    NONZERO_PRISTINE.fetch_add(1, Ordering::Relaxed);
                }
                for p in fixed_start..(fixed_start + 4) {
                    written[p] = false;
                }
            }
        }

        // Step 5: fork() a child that verifies its own copy and writes a different pattern
        if tid == 0 && iter % 10 == 0 {
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                // Child: verify all stable written pages in workload area
                let mut mismatches = 0usize;
                for p in workload_start_page..total_pages {
                    if written[p] {
                        let page_addr = unsafe { base.add(p * PAGE_SIZE) };
                        let expected = canary(page_addr as usize, page_iter[p]);
                        let actual = unsafe { *(page_addr as *const u64) };
                        if actual != expected {
                            mismatches += 1;
                        }
                    }
                }
                // Child writes different pattern to dedicated fork pages (0..16)
                for p in 0..16 {
                    let page_addr = unsafe { base.add(p * PAGE_SIZE) as *mut u64 };
                    unsafe { page_addr.write_volatile(0xDEAD_BEEF_CAFE_0000) };
                }
                unsafe { libc::_exit(if mismatches == 0 { 0 } else { 1 }) };
            } else if pid > 0 {
                // Parent keeps writing to dedicated fork pages (16..32) while child runs
                for p in 16..32 {
                    let page_addr = unsafe { base.add(p * PAGE_SIZE) as *mut u64 };
                    let c = canary(page_addr as usize, iter + 1000);
                    unsafe { page_addr.write_volatile(c) };
                }
                let mut status = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
                if libc::WIFEXITED(status) {
                    let code = libc::WEXITSTATUS(status);
                    if code != 0 {
                        CHILD_MISMATCHES.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    CHILD_MISMATCHES.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    // Final verification of all written pages in workload area
    for p in workload_start_page..total_pages {
        if written[p] {
            let page_addr = unsafe { base.add(p * PAGE_SIZE) };
            let expected = canary(page_addr as usize, page_iter[p]);
            let actual = unsafe { *(page_addr as *const u64) };
            let actual_tail = unsafe { *((page_addr as *const u64).add(511)) };
            if actual != expected || actual_tail != (expected ^ 0x5555_5555_5555_5555) {
                PATTERN_MISMATCHES.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    if !reserve_base.is_null() {
        unsafe { libc::munmap(reserve, reserve_size) };
    }
    unsafe { libc::munmap(region, REGION_SIZE) };

    std::ptr::null_mut()
}

fn main() {
    test_cross_thread_window();

    let mut threads = [0 as libc::pthread_t; NUM_THREADS];
    let mut args: Vec<WorkerArg> = (0..NUM_THREADS)
        .map(|i| WorkerArg { thread_id: i })
        .collect();

    for i in 0..NUM_THREADS {
        let rc = unsafe {
            libc::pthread_create(
                &mut threads[i],
                std::ptr::null(),
                worker_thread,
                &mut args[i] as *mut WorkerArg as *mut libc::c_void,
            )
        };
        if rc != 0 {
            eprintln!("pthread_create failed: {rc}");
            std::process::exit(1);
        }
    }

    for i in 0..NUM_THREADS {
        unsafe { libc::pthread_join(threads[i], std::ptr::null_mut()) };
    }

    let pattern_mismatches = PATTERN_MISMATCHES.load(Ordering::SeqCst);
    let nonzero_after_dontneed = NONZERO_AFTER_DONTNEED.load(Ordering::SeqCst);
    let nonzero_pristine = NONZERO_PRISTINE.load(Ordering::SeqCst);
    let child_mismatches = CHILD_MISMATCHES.load(Ordering::SeqCst);

    println!("pattern_mismatches={pattern_mismatches}");
    println!("nonzero_after_dontneed={nonzero_after_dontneed}");
    println!("nonzero_pristine={nonzero_pristine}");
    println!("child_mismatches={child_mismatches}");

    if pattern_mismatches != 0
        || nonzero_after_dontneed != 0
        || nonzero_pristine != 0
        || child_mismatches != 0
    {
        std::process::exit(1);
    }
}
