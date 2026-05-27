//! MAP_SHARED fork-coherence reducer for the LTP `tst_run_tcases` segfault.
//!
//! That fault traces to LTP's results/checkpoint page — a MAP_SHARED file
//! mapping carrick backs at the 0x90_0000_0000 shared aperture — being
//! INCOHERENT across fork: the library reads the test child's results and gets
//! garbage (a node value of 17), corrupting a list it walks. The real shape is
//! a 3-level fork (library → runner → test) where the shared page is created in
//! the middle process and writes flow in BOTH directions.
//!
//! This probe reproduces exactly that: a MAP_SHARED page seeded by the parent,
//! a child and grandchild that each read the ancestors' writes and add their
//! own, then the ancestors read the descendants' writes back. Every visibility
//! check is a deterministic boolean. On real Linux all are `true` (host
//! MAP_SHARED is fully fork-coherent). A `false` under carrick pinpoints the
//! direction/level whose stage-2 mapping of the 0x90 window went stale.
//!
//! Run with `--fs host` (the shared aperture only engages for a real host file
//! → host MAP_SHARED; `--fs memory` falls back to a private snapshot).

use std::sync::atomic::{compiler_fence, Ordering};

const A: u64 = 0xAAAA_0000_0000_0001;
const B: u64 = 0xBBBB_0000_0000_0002;
const C: u64 = 0xCCCC_0000_0000_0003;

unsafe fn put(map: *mut u64, idx: usize, v: u64) {
    std::ptr::write_volatile(map.add(idx), v);
    compiler_fence(Ordering::SeqCst);
}
unsafe fn get(map: *mut u64, idx: usize) -> u64 {
    compiler_fence(Ordering::SeqCst);
    std::ptr::read_volatile(map.add(idx))
}

/// Spin until word `idx` reads `want`, or a deadline — so a broken-coherence
/// read returns the wrong value (false) instead of hanging.
unsafe fn wait_for(map: *mut u64, idx: usize, want: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if get(map, idx) == want {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::hint::spin_loop();
    }
}

fn main() {
    unsafe {
        libc::mkdir(b"/tmp\0".as_ptr() as *const libc::c_char, 0o777);
        let path = b"/tmp/carrick_forkshared_ipc\0";
        let fd = libc::open(
            path.as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        );
        if fd < 0 {
            println!("setup=false");
            return;
        }
        libc::ftruncate(fd, 4096);
        // MAP_SHARED RW file mapping — carrick routes this to the 0x90 aperture.
        let map = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        ) as *mut u64;
        if map == libc::MAP_FAILED as *mut u64 {
            println!("setup=false");
            return;
        }
        // Layout: [0]=A (parent pre-fork), [1]=B (child), [2]=C (grandchild),
        // [3..]=status flags the ancestors poll for the descendants' reads.
        put(map, 0, A);
        put(map, 3, 0);
        put(map, 4, 0);

        let child = libc::fork();
        if child == 0 {
            // ---- child (mirrors the LTP "runner") ----
            // Sees the parent's pre-fork write?
            let child_sees_parent = get(map, 0) == A;
            put(map, 1, B); // child's write, parent must see it

            let grand = libc::fork();
            if grand == 0 {
                // ---- grandchild (mirrors the actual test process) ----
                // Sees both ancestors' writes across two fork levels?
                let gc_sees_parent = get(map, 0) == A;
                let gc_sees_child = get(map, 1) == B;
                put(map, 2, C); // grandchild's write
                put(map, 5, if gc_sees_parent && gc_sees_child { 1 } else { 9 });
                libc::_exit(0);
            }
            // child waits grandchild, then checks it saw the grandchild's write.
            let mut st = 0;
            while libc::wait4(grand, &mut st, 0, std::ptr::null_mut()) < 0 {}
            let child_sees_grand = get(map, 2) == C;
            put(map, 3, if child_sees_parent && child_sees_grand { 1 } else { 9 });
            libc::_exit(0);
        }

        // ---- parent (mirrors the LTP library) ----
        let mut st = 0;
        while libc::wait4(child, &mut st, 0, std::ptr::null_mut()) < 0 {}

        // Parent must see the child's and grandchild's writes (the broken
        // direction in read01: library reads the test process's results).
        let parent_sees_child = wait_for(map, 1, B);
        let parent_sees_grand = wait_for(map, 2, C);
        let descendants_ok = get(map, 5) == 1; // grandchild saw both ancestors
        let child_chain_ok = get(map, 3) == 1; // child saw parent + grandchild

        println!("parent_sees_child_write={parent_sees_child}");
        println!("parent_sees_grandchild_write={parent_sees_grand}");
        println!("grandchild_saw_ancestors={descendants_ok}");
        println!("child_saw_parent_and_grandchild={child_chain_ok}");
    }
}
