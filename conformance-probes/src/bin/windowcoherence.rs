//! Fault window memory coherence probe.
//!
//! Every observation is a deterministic counter that Linux answers with zero:
//! a page must read back exactly what was last written to it, a fresh or
//! discarded anonymous page must read zero, and none of that may depend on
//! which thread mapped, unmapped or touched the page.
//!
//! Scenarios, in the order they run:
//! 0. `sibling_handoff_first_touch`: threads created while siblings first-touch
//!    fresh private anonymous chunks and others spin in guest. The reducer for
//!    the Go startup SEGV_MAPERR: a sibling's first-run rebind of the MM's
//!    frame-COW runtime binding landed inside another task's first-touch
//!    quiesce, and the publication was refused and lowered to SIGSEGV.
//! 1. `compound_retirement`: four pages of one 16 KiB compound, three of them
//!    unmapped from another thread; the survivor keeps its bytes and its
//!    frame while a fresh mapping is written.
//! 2. `fragment_stress`: random page-granular `munmap`, `MAP_FIXED` remaps,
//!    `MADV_DONTNEED` and fresh mappings over a window-materialized region,
//!    once single-threaded and once with every unmap/remap issued from a
//!    short-lived sibling thread. The sibling variant is the reducer for the
//!    wide-window corruption: a partial unmap from a sibling left the other
//!    threads' backing rows spanning the retired page, and the page's next
//!    incarnation revalidated a retired frame (livelock on a stage-2 fault,
//!    or silently stale bytes).
//! 3. `partial_unmap_reuse`: one page of a compound unmapped and re-mapped
//!    `MAP_FIXED` from a sibling, read back from the original thread.
//! 4. The original cross-thread window read, the 4-thread 8 MiB workload
//!    (non-monotonic touches, `mprotect` re-protection, `MADV_DONTNEED`,
//!    `MAP_FIXED`, fork verification).
//!
//! `WINDOWCOHERENCE_TRACE=1` narrates the stress ops on stderr (`=2` also
//! every verification read); `WINDOWCOHERENCE_FAST=1` skips the stress.

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
            state: if seed == 0 {
                0x8a5b_f789_0831_4961
            } else {
                seed
            },
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

/// Deterministic reducer for the wide-window partial-unmap hazard.
///
/// Thread A first-touches page 0 of a fresh anonymous mapping, which under
/// the fault window materializes the whole 16 KiB compound as ONE backing
/// row on A's executor, then writes a pattern into page 1 of that compound.
/// Thread B `munmap`s page 1 alone (a PARTIAL unmap of A's row) and maps a
/// fresh anonymous page back over the same VA with `MAP_FIXED`. Linux hands
/// A a zero page on its next touch; a stale row on A that still spans the
/// unmapped page instead revalidates the old leaf and resurrects the old
/// bytes. The same sequence performed entirely on A is the control.
///
/// The second half retires the rest of the compound from B, then lets A
/// write through its (possibly resurrected) page-1 leaf while B owns a fresh
/// mapping: if A's leaf still names the retired frame, B's fresh mapping
/// can observe A's write.
struct ReuseArg {
    base: *mut u8,
    fresh: *mut u8,
    step: *const AtomicUsize,
    role: usize,
}

unsafe impl Send for ReuseArg {}
unsafe impl Sync for ReuseArg {}

static REUSE_STALE_SIBLING: AtomicUsize = AtomicUsize::new(0);
static REUSE_STALE_SAME: AtomicUsize = AtomicUsize::new(0);
static REUSE_FRESH_SEES_SIBLING_WRITE: AtomicUsize = AtomicUsize::new(0);

fn wait_step(step: &AtomicUsize, want: usize) {
    while step.load(Ordering::Acquire) != want {
        std::hint::spin_loop();
    }
}

extern "C" fn reuse_worker(arg_ptr: *mut libc::c_void) -> *mut libc::c_void {
    let arg = unsafe { &*(arg_ptr as *const ReuseArg) };
    let step = unsafe { &*arg.step };
    let base = arg.base;
    let page1 = unsafe { base.add(PAGE_SIZE) };
    if arg.role == 0 {
        // A: first touch page 0 (widens to the compound), then page 1.
        unsafe {
            (base as *mut u64).write_volatile(0x0101_0101_0101_0101);
            (page1 as *mut u64).write_volatile(0xA5A5_A5A5_A5A5_A5A5);
        }
        step.store(1, Ordering::Release);
        wait_step(step, 2);
        // B unmapped page 1 and mapped a fresh anonymous page over it.
        let v = unsafe { (page1 as *const u64).read_volatile() };
        REUSE_STALE_SIBLING.store(v as usize, Ordering::Relaxed);
        // Same-thread control: repeat the partial unmap + MAP_FIXED on A.
        unsafe {
            (page1 as *mut u64).write_volatile(0xB6B6_B6B6_B6B6_B6B6);
            libc::munmap(page1 as *mut libc::c_void, PAGE_SIZE);
            let p = libc::mmap(
                page1 as *mut libc::c_void,
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            );
            if p != page1 as *mut libc::c_void {
                REUSE_STALE_SAME.store(usize::MAX, Ordering::Relaxed);
            } else {
                let v = (page1 as *const u64).read_volatile();
                REUSE_STALE_SAME.store(v as usize, Ordering::Relaxed);
            }
        }
        step.store(3, Ordering::Release);
        wait_step(step, 4);
        // B retired the rest of the compound and owns a fresh mapping whose
        // first page it touched. Write through A's page-1 leaf.
        unsafe { (page1 as *mut u64).write_volatile(0xC7C7_C7C7_C7C7_C7C7) };
        step.store(5, Ordering::Release);
    } else {
        wait_step(step, 1);
        unsafe {
            libc::munmap(page1 as *mut libc::c_void, PAGE_SIZE);
            let p = libc::mmap(
                page1 as *mut libc::c_void,
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            );
            if p != page1 as *mut libc::c_void {
                REUSE_STALE_SIBLING.store(usize::MAX, Ordering::Relaxed);
            }
        }
        step.store(2, Ordering::Release);
        wait_step(step, 3);
        unsafe {
            // Retire pages 0, 2 and 3: the compound's last semantic owners.
            libc::munmap(base as *mut libc::c_void, PAGE_SIZE);
            libc::munmap(base.add(2 * PAGE_SIZE) as *mut libc::c_void, 2 * PAGE_SIZE);
            // Fresh mapping; touching page 0 materializes its compound.
            (arg.fresh as *mut u64).write_volatile(0x0F0F_0F0F_0F0F_0F0F);
        }
        step.store(4, Ordering::Release);
        wait_step(step, 5);
        let mut seen = 0usize;
        for p in 0..4 {
            let v = unsafe { (arg.fresh.add(p * PAGE_SIZE) as *const u64).read_volatile() };
            if v == 0xC7C7_C7C7_C7C7_C7C7 {
                seen = p + 1;
            }
        }
        REUSE_FRESH_SEES_SIBLING_WRITE.store(seen, Ordering::Relaxed);
    }
    std::ptr::null_mut()
}

fn test_partial_unmap_reuse() {
    let map = |len: usize| unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    // Two separate compound-aligned regions; `fresh` is mapped up front so
    // its VA is fixed, but it is not touched until the retired frame exists.
    let region = map(COMPOUND_SIZE * 2);
    let fresh = map(COMPOUND_SIZE * 2);
    if region == libc::MAP_FAILED || fresh == libc::MAP_FAILED {
        println!("partial_unmap_reuse=mmap_failed");
        return;
    }
    let align = |p: *mut libc::c_void| {
        let a = (p as usize + COMPOUND_SIZE - 1) & !(COMPOUND_SIZE - 1);
        a as *mut u8
    };
    let base = align(region);
    let fresh_base = align(fresh);
    let step = AtomicUsize::new(0);
    let args = [
        ReuseArg {
            base,
            fresh: fresh_base,
            step: &step,
            role: 0,
        },
        ReuseArg {
            base,
            fresh: fresh_base,
            step: &step,
            role: 1,
        },
    ];
    let mut threads = [0 as libc::pthread_t; 2];
    for i in 0..2 {
        unsafe {
            libc::pthread_create(
                &mut threads[i],
                std::ptr::null(),
                reuse_worker,
                &args[i] as *const ReuseArg as *mut libc::c_void,
            );
        }
    }
    for t in threads {
        unsafe { libc::pthread_join(t, std::ptr::null_mut()) };
    }
    println!(
        "partial_unmap_reuse_sibling_stale=0x{:x}",
        REUSE_STALE_SIBLING.load(Ordering::Relaxed)
    );
    println!(
        "partial_unmap_reuse_same_thread_stale=0x{:x}",
        REUSE_STALE_SAME.load(Ordering::Relaxed)
    );
    println!(
        "retired_frame_fresh_mapping_sees_sibling_write={}",
        REUSE_FRESH_SEES_SIBLING_WRITE.load(Ordering::Relaxed)
    );
    unsafe {
        libc::munmap(region, COMPOUND_SIZE * 2);
        libc::munmap(fresh, COMPOUND_SIZE * 2);
    }
}

/// Single-threaded fragment stress: random page-granular `munmap`,
/// `MAP_FIXED` re-map, `MADV_DONTNEED` and fresh-mapping allocations over a
/// region whose compounds were materialized by the fault window, with every
/// page's expected content tracked. Any page that reads back something other
/// than its tracked content is a coherence failure: a fresh or discarded
/// page that is not zero (stale frame resurrected, or a frame shared with a
/// live mapping) or a written page whose pattern changed (its frame was
/// retired and handed to someone else while its leaf still named it).
#[derive(Clone, Copy, PartialEq, Eq)]
enum PageState {
    Unmapped,
    Zero,
    Pattern(u32),
}

fn fragment_stress(seed: u64, cross_thread: bool) -> (usize, usize, usize) {
    const PAGES: usize = 256; // 1 MiB region = 16 windows of 64 KiB
    const FRESH: usize = 64; // fresh 16 KiB mappings kept live
    // The cross-thread variant spawns a thread per unmap/remap, which is the
    // expensive part under a VMM; 1200 iterations keep the run inside the
    // gate budget while still reaching the iteration (663 with this seed) at
    // which the pre-fix binary livelocked on a stale row.
    let iters: u32 = if cross_thread { 1200 } else { 4000 };
    let region = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            PAGES * PAGE_SIZE + WINDOW_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if region == libc::MAP_FAILED {
        return (usize::MAX, 0, 0);
    }
    let base = ((region as usize + WINDOW_SIZE - 1) & !(WINDOW_SIZE - 1)) as *mut u8;
    if std::env::var_os("WINDOWCOHERENCE_TRACE").is_some() {
        eprintln!(
            "fragment_stress cross_thread={cross_thread} region={:#x} base={:#x}",
            region as usize, base as usize
        );
    }
    let mut state = [PageState::Zero; PAGES];
    let mut rng = XorShift::new(seed);
    let mut fresh: Vec<(*mut u8, u32)> = Vec::new();
    let mut stale_fresh = 0usize;
    let mut lost_pattern = 0usize;
    let mut nonzero_reuse = 0usize;
    let page_ptr = |i: usize| unsafe { base.add(i * PAGE_SIZE) as *mut u64 };
    let pattern = |i: usize, tag: u32| 0x5A5A_0000_0000_0000u64 ^ ((tag as u64) << 20) ^ (i as u64);
    // Helper executed on another thread when `cross_thread` is set: page
    // unmaps and MAP_FIXED remaps come from a sibling executor so its local
    // rows, not the mutating thread's, are the ones that go stale.
    let run_remote = |f: &mut (dyn FnMut() + Send)| {
        if cross_thread {
            std::thread::scope(|scope| {
                scope.spawn(|| f());
            });
        } else {
            f();
        }
    };
    for iter in 1..=iters {
        let op = rng.next_u32() % 16;
        let i = (rng.next_u32() as usize) % PAGES;
        if std::env::var_os("WINDOWCOHERENCE_TRACE").is_some() {
            eprintln!(
                "iter={iter} op={op} page={i} state={:?}",
                match state[i] {
                    PageState::Unmapped => 0u32,
                    PageState::Zero => 1,
                    PageState::Pattern(t) => 2 + t,
                }
            );
        }
        match op {
            0..=6 => {
                // Touch/write a page with a fresh pattern.
                if state[i] != PageState::Unmapped {
                    if state[i] == PageState::Zero {
                        let v = unsafe { page_ptr(i).read_volatile() };
                        if v != 0 {
                            nonzero_reuse += 1;
                        }
                    }
                    unsafe { page_ptr(i).write_volatile(pattern(i, iter)) };
                    state[i] = PageState::Pattern(iter);
                }
            }
            7..=8 => {
                // munmap 1..3 pages (fragmenting compounds).
                // Only pages this test still owns: a hole it opened earlier
                // may since have been reused by the allocator or by a fresh
                // mapping, exactly as on Linux.
                let n = 1 + (rng.next_u32() as usize) % 3;
                let mut end = i;
                while end < (i + n).min(PAGES) && state[end] != PageState::Unmapped {
                    end += 1;
                }
                if end > i {
                    let ptr = page_ptr(i) as usize;
                    if std::env::var_os("WINDOWCOHERENCE_TRACE").is_some() {
                        eprintln!("munmap pages {i}..{end}");
                    }
                    run_remote(&mut || unsafe {
                        libc::munmap(ptr as *mut libc::c_void, (end - i) * PAGE_SIZE);
                    });
                    for s in state[i..end].iter_mut() {
                        *s = PageState::Unmapped;
                    }
                }
            }
            9..=10 => {
                // MAP_FIXED a fresh anonymous mapping over 1..3 pages this
                // test still owns (never over a hole someone else may have
                // reused).
                let n = 1 + (rng.next_u32() as usize) % 3;
                let mut end = i;
                while end < (i + n).min(PAGES) && state[end] != PageState::Unmapped {
                    end += 1;
                }
                if end == i {
                    continue;
                }
                let ptr = page_ptr(i) as usize;
                let len = (end - i) * PAGE_SIZE;
                if std::env::var_os("WINDOWCOHERENCE_TRACE").is_some() {
                    eprintln!("mapfixed pages {i}..{end}");
                }
                let mut ok = false;
                run_remote(&mut || unsafe {
                    ok = libc::mmap(
                        ptr as *mut libc::c_void,
                        len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                        -1,
                        0,
                    ) as usize
                        == ptr;
                });
                if ok {
                    for s in state[i..end].iter_mut() {
                        *s = PageState::Zero;
                    }
                }
            }
            11 => {
                // MADV_DONTNEED 1..3 mapped pages.
                let n = 1 + (rng.next_u32() as usize) % 3;
                let end = (i + n).min(PAGES);
                if state[i..end].iter().all(|s| *s != PageState::Unmapped) {
                    if std::env::var_os("WINDOWCOHERENCE_TRACE").is_some() {
                        eprintln!("dontneed pages {i}..{end}");
                    }
                    unsafe {
                        libc::madvise(
                            page_ptr(i) as *mut libc::c_void,
                            (end - i) * PAGE_SIZE,
                            libc::MADV_DONTNEED,
                        );
                    }
                    for s in state[i..end].iter_mut() {
                        *s = PageState::Zero;
                    }
                }
            }
            _ => {
                // Fresh 16 KiB mapping: must read zero; keep it live with a pattern.
                let p = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        COMPOUND_SIZE,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                if p != libc::MAP_FAILED
                    && (p as usize) >= base as usize
                    && (p as usize) < base as usize + PAGES * PAGE_SIZE
                {
                    // Linux (and carrick) may place the fresh mapping in a
                    // hole the region's own unmaps opened: those pages are
                    // region pages again, tracked as zero.
                    let first = (p as usize - base as usize) / PAGE_SIZE;
                    for q in first..(first + 4).min(PAGES) {
                        let v = unsafe { page_ptr(q).read_volatile() };
                        if v != 0 {
                            stale_fresh += 1;
                        }
                        state[q] = PageState::Zero;
                    }
                } else if p != libc::MAP_FAILED {
                    let p = p as *mut u8;
                    for q in 0..4 {
                        let v = unsafe { (p.add(q * PAGE_SIZE) as *const u64).read_volatile() };
                        if v != 0 {
                            stale_fresh += 1;
                        }
                        unsafe {
                            (p.add(q * PAGE_SIZE) as *mut u64).write_volatile(pattern(q, iter))
                        };
                    }
                    if std::env::var_os("WINDOWCOHERENCE_TRACE").is_some() {
                        eprintln!("fresh {:#x}", p as usize);
                    }
                    fresh.push((p, iter));
                    if fresh.len() > FRESH {
                        let (old, _) = fresh.remove((rng.next_u32() as usize) % fresh.len());
                        unsafe { libc::munmap(old as *mut libc::c_void, COMPOUND_SIZE) };
                    }
                }
            }
        }
        // Verify every tracked page after each op.
        let trace = std::env::var("WINDOWCOHERENCE_TRACE").is_ok_and(|v| v == "2");
        for (j, s) in state.iter().enumerate() {
            if let PageState::Pattern(tag) = *s {
                if trace {
                    eprintln!("verify page={j} tag={tag}");
                }
                let v = unsafe { page_ptr(j).read_volatile() };
                if v != pattern(j, tag) {
                    lost_pattern += 1;
                    unsafe { page_ptr(j).write_volatile(pattern(j, tag)) };
                }
            }
        }
        for &(p, tag) in &fresh {
            for q in 0..4 {
                if trace {
                    eprintln!("verify fresh={:#x} q={q} tag={tag}", p as usize);
                }
                let v = unsafe { (p.add(q * PAGE_SIZE) as *const u64).read_volatile() };
                if v != pattern(q, tag) {
                    lost_pattern += 1;
                    unsafe { (p.add(q * PAGE_SIZE) as *mut u64).write_volatile(pattern(q, tag)) };
                }
            }
        }
    }
    if std::env::var_os("WINDOWCOHERENCE_TRACE").is_some() {
        eprintln!("teardown");
    }
    for (p, _) in fresh {
        unsafe { libc::munmap(p as *mut libc::c_void, COMPOUND_SIZE) };
    }
    // Unmap only what this test still owns: holes it opened may since have
    // been handed to the allocator (a blanket unmap of the region would tear
    // down a live malloc chunk, on Linux exactly as here).
    let region_end = region as usize + PAGES * PAGE_SIZE + WINDOW_SIZE;
    let mut owned: Vec<(usize, usize)> = Vec::new();
    if (region as usize) < base as usize {
        owned.push((region as usize, base as usize));
    }
    for (j, s) in state.iter().enumerate() {
        if *s != PageState::Unmapped {
            owned.push((
                base as usize + j * PAGE_SIZE,
                base as usize + (j + 1) * PAGE_SIZE,
            ));
        }
    }
    let tail = base as usize + PAGES * PAGE_SIZE;
    if tail < region_end {
        owned.push((tail, region_end));
    }
    for (s, e) in owned {
        unsafe { libc::munmap(s as *mut libc::c_void, e - s) };
    }
    (stale_fresh, lost_pattern, nonzero_reuse)
}

fn test_fragment_stress() {
    for (name, cross) in [("local", false), ("cross_thread", true)] {
        let (stale_fresh, lost_pattern, nonzero_reuse) =
            fragment_stress(0x9E37_79B9_7F4A_7C15, cross);
        println!("fragment_stress_{name}_stale_fresh={stale_fresh}");
        println!("fragment_stress_{name}_lost_pattern={lost_pattern}");
        println!("fragment_stress_{name}_nonzero_reuse={nonzero_reuse}");
        if stale_fresh != 0 || lost_pattern != 0 || nonzero_reuse != 0 {
            FRAGMENT_STRESS_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
    }
}

static FRAGMENT_STRESS_FAILURES: AtomicUsize = AtomicUsize::new(0);

/// Fatal-fault reporter: a SIGSEGV inside the stress is a probe failure with
/// an address; report it on stderr so the run names the page, then die with
/// the signal's conventional status.
extern "C" fn segv_reporter(sig: libc::c_int, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    unsafe {
        let addr = if info.is_null() {
            0
        } else {
            (*info).si_addr() as usize
        };
        let pc = if ctx.is_null() {
            0
        } else {
            let uc = ctx as *const libc::ucontext_t;
            (*uc).uc_mcontext.pc as usize
        };
        let msg = format!("FATAL_SIGNAL sig={sig} addr={addr:#x} pc={pc:#x}\n");
        libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
        libc::_exit(128 + sig);
    }
}

fn install_segv_reporter() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = segv_reporter
            as extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void)
            as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGBUS, &sa, std::ptr::null_mut());
    }
}

/// Deterministic reducer for the compound-retirement hazard.
///
/// Four pages of one 16 KiB compound are touched and patterned on the main
/// thread. Another thread then unmaps three of them (a PARTIAL unmap of the
/// compound); the surviving page must keep its bytes and its frame. A fresh
/// mapping is then allocated and written from the main thread: if the
/// survivor's frame was retired under it, the fresh mapping is handed the
/// recycled frame and the survivor observes the fresh mapping's write (or,
/// unpooled, the survivor's leaf names an unmapped frame and every access
/// faults). The same sequence with the unmap on the main thread is the
/// control.
fn compound_retirement(remote: bool, keep: usize) -> (u64, u64) {
    let map = |len: usize| unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let region = map(COMPOUND_SIZE * 2);
    if region == libc::MAP_FAILED {
        return (u64::MAX, u64::MAX);
    }
    let base = ((region as usize + COMPOUND_SIZE - 1) & !(COMPOUND_SIZE - 1)) as *mut u8;
    let pattern = |q: usize| 0x7A7A_0000_0000_0000u64 ^ (q as u64 + 1) ^ ((keep as u64) << 8);
    for q in 0..4 {
        unsafe { (base.add(q * PAGE_SIZE) as *mut u64).write_volatile(pattern(q)) };
    }
    // Unmap every page but `keep`, in one or two calls.
    let unmap = |ptr: usize, len: usize| unsafe {
        libc::munmap(ptr as *mut libc::c_void, len);
    };
    let pieces: Vec<(usize, usize)> = if keep == 0 {
        vec![(base as usize + PAGE_SIZE, 3 * PAGE_SIZE)]
    } else if keep == 3 {
        vec![(base as usize, 3 * PAGE_SIZE)]
    } else {
        vec![
            (base as usize, keep * PAGE_SIZE),
            (
                base as usize + (keep + 1) * PAGE_SIZE,
                (3 - keep) * PAGE_SIZE,
            ),
        ]
    };
    for (ptr, len) in pieces {
        if remote {
            std::thread::scope(|scope| {
                scope.spawn(move || unmap(ptr, len));
            });
        } else {
            unmap(ptr, len);
        }
    }
    let survivor = unsafe { base.add(keep * PAGE_SIZE) as *mut u64 };
    let after_unmap = unsafe { survivor.read_volatile() };
    // Fresh compound: written from this thread; the survivor must not move.
    let fresh = map(COMPOUND_SIZE * 2);
    let mut after_fresh = after_unmap;
    if fresh != libc::MAP_FAILED {
        let fresh_base = ((fresh as usize + COMPOUND_SIZE - 1) & !(COMPOUND_SIZE - 1)) as *mut u8;
        for q in 0..4 {
            unsafe {
                (fresh_base.add(q * PAGE_SIZE) as *mut u64).write_volatile(0x7777_7777_7777_7777)
            };
        }
        after_fresh = unsafe { survivor.read_volatile() };
        unsafe { libc::munmap(fresh, COMPOUND_SIZE * 2) };
    }
    unsafe {
        libc::munmap(survivor as *mut libc::c_void, PAGE_SIZE);
        if (region as usize) < base as usize {
            libc::munmap(region, base as usize - region as usize);
        }
        let tail = base as usize + COMPOUND_SIZE;
        let end = region as usize + COMPOUND_SIZE * 2;
        if tail < end {
            libc::munmap(tail as *mut libc::c_void, end - tail);
        }
    }
    (after_unmap ^ pattern(keep), after_fresh ^ pattern(keep))
}

static COMPOUND_RETIREMENT_FAILURES: AtomicUsize = AtomicUsize::new(0);

fn test_compound_retirement() {
    for (name, remote) in [("local", false), ("sibling", true)] {
        for keep in 0..4 {
            let (after_unmap, after_fresh) = compound_retirement(remote, keep);
            println!("compound_retirement_{name}_keep{keep}_after_unmap_xor=0x{after_unmap:x}");
            println!("compound_retirement_{name}_keep{keep}_after_fresh_xor=0x{after_fresh:x}");
            if after_unmap != 0 || after_fresh != 0 {
                COMPOUND_RETIREMENT_FAILURES.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Deterministic reducer for the Go startup `SIGSEGV` (SEGV_MAPERR) on the
/// first touch of a chunk the same thread just `mmap`ed.
///
/// Linux never faults a first touch inside a live private anonymous VMA. Under
/// carrick that touch materializes backing through the MM-scoped frame-COW
/// runtime binding: the faulting task reads the binding, quiesces the MM's
/// vCPUs through it, then re-reads the binding and REFUSES the publication if
/// it changed ("sparse publication MM changed during quiesce"), which the
/// runtime lowers to SIGSEGV. Every new sibling thread's first run rebinds
/// that same MM binding with its own authority object, so a thread being
/// created while a sibling is inside its first-touch quiesce is enough.
///
/// Shape: two threads busy in guest (so every quiesce has vCPUs to kick and
/// drain, widening the window), two threads that `mmap` fresh private
/// anonymous chunks of random page counts, write and read back the first
/// word, and `munmap`; one thread creating and joining short-lived siblings
/// `SIBLING_HANDOFF_SPAWNS` times. A SEGV ends the process through the fatal
/// signal reporter (`FATAL_SIGNAL sig=11`), so the two summary lines below
/// are missing from the transcript; a wrong byte counts as a mismatch.
const SIBLING_HANDOFF_SPAWNS: usize = 1500;
static SIBLING_HANDOFF_TOUCH_MISMATCHES: AtomicUsize = AtomicUsize::new(0);

fn test_sibling_handoff_first_touch() {
    use std::sync::atomic::AtomicBool;
    let stop = AtomicBool::new(false);
    let touches = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..2 {
            scope.spawn(|| {
                let mut x = 0x9e37_79b9_7f4a_7c15u64;
                while !stop.load(Ordering::Relaxed) {
                    x = std::hint::black_box(x).wrapping_mul(0x2545_f491_4f6c_dd1d);
                }
            });
        }
        for t in 0..2usize {
            let stop = &stop;
            let touches = &touches;
            scope.spawn(move || {
                let mut rng = XorShift::new(0x5eed_0000_0000_0001 ^ ((t as u64 + 1) << 32));
                while !stop.load(Ordering::Relaxed) {
                    let pages = 1 + (rng.next_u32() as usize % 96);
                    let len = pages * PAGE_SIZE;
                    let ptr = unsafe {
                        libc::mmap(
                            std::ptr::null_mut(),
                            len,
                            libc::PROT_READ | libc::PROT_WRITE,
                            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                            -1,
                            0,
                        )
                    };
                    if ptr == libc::MAP_FAILED {
                        break;
                    }
                    let canary = canary(ptr as usize, touches.load(Ordering::Relaxed));
                    let word = ptr as *mut u64;
                    unsafe {
                        word.write_volatile(canary);
                        if word.read_volatile() != canary {
                            SIBLING_HANDOFF_TOUCH_MISMATCHES.fetch_add(1, Ordering::Relaxed);
                        }
                        libc::munmap(ptr, len);
                    }
                    touches.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
        let mut spawned = 0usize;
        for _ in 0..SIBLING_HANDOFF_SPAWNS {
            if std::thread::spawn(|| {}).join().is_ok() {
                spawned += 1;
            }
        }
        stop.store(true, Ordering::Relaxed);
        println!("sibling_handoff_spawns={spawned}");
    });
    println!(
        "sibling_handoff_touch_mismatches={}",
        SIBLING_HANDOFF_TOUCH_MISMATCHES.load(Ordering::Relaxed)
    );
    eprintln!(
        "test_sibling_handoff_first_touch: touches = {}",
        touches.load(Ordering::Relaxed)
    );
}

fn main() {
    install_segv_reporter();
    test_sibling_handoff_first_touch();
    test_compound_retirement();
    if std::env::var_os("WINDOWCOHERENCE_FAST").is_none() {
        test_fragment_stress();
    }
    test_partial_unmap_reuse();
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
        || REUSE_STALE_SIBLING.load(Ordering::Relaxed) != 0
        || REUSE_STALE_SAME.load(Ordering::Relaxed) != 0
        || REUSE_FRESH_SEES_SIBLING_WRITE.load(Ordering::Relaxed) != 0
        || FRAGMENT_STRESS_FAILURES.load(Ordering::Relaxed) != 0
        || COMPOUND_RETIREMENT_FAILURES.load(Ordering::Relaxed) != 0
        || SIBLING_HANDOFF_TOUCH_MISMATCHES.load(Ordering::Relaxed) != 0
    {
        std::process::exit(1);
    }
}
