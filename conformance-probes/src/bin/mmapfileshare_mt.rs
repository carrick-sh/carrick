//! MULTI-THREADED MAP_SHARED file coherence — the missing discriminator for the
//! `go build` telemetry-counter crash.
//!
//! The single-threaded `mmapfile` probe passes under carrick `--fs host`, yet
//! `go build` crashes reading 0x0 out of a MAP_SHARED counter file. The fresh
//! trace shows the mapping is `forked=0` (a fresh exec'd VM), distinct IPA,
//! rc=0 — so the stale "post-fork stage-2 coherence" story does NOT apply. The
//! one uncontrolled difference left is THREADS: Go's telemetry counter is mmap'd
//! on one OS thread (vCPU) and read by a goroutine that can run on ANOTHER
//! thread (another vCPU). carrick uses a per-thread HVF vCPU, so a sibling vCPU
//! reading a freshly `hv_vm_map`'d alias window may not see it coherently.
//!
//! This probe reproduces that ordering deterministically:
//!   1. spawn K worker threads (→ K sibling vCPUs) and PARK them on a flag,
//!      BEFORE any alias mapping exists — exactly like Go's runtime threads,
//!   2. the MAIN thread creates a file, writes a known header via the fd, and
//!      `mmap(MAP_SHARED)`s it (establishing the alias window on the main vCPU),
//!   3. release the workers; each reads the header THROUGH the mapping on its
//!      OWN vCPU and reports whether it saw the header or stale zeros.
//!
//! Output is deterministic (booleans + an invariant count), so the harness can
//! diff carrick vs docker line-for-line. On a coherent VM every reader sees the
//! header (`readers_match=K/K`); a sibling-vCPU coherence gap shows `<K`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const HEADER: u64 = 0x4361_7272_6963_6b21; // "Carrick!"
const K: usize = 4;
const FILE_LEN: usize = 16384; // match Go's 16 KiB minFileLen

fn main() {
    unsafe {
        libc::mkdir(c"/tmp".as_ptr(), 0o777);
    }
    let fd = unsafe {
        libc::open(
            c"/tmp/mmapfileshare_mt".as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        )
    };
    if fd < 0 {
        println!("open FAIL");
        return;
    }
    // Sparse-extend to 16 KiB the way Go does (pwrite at the last byte), NOT a
    // plain ftruncate — Go writes its header via the fd, then mmaps and reads it
    // back through the mapping, so the header must be visible via the alias.
    let zero = 0u8;
    if unsafe {
        libc::pwrite(
            fd,
            &zero as *const u8 as *const _,
            1,
            (FILE_LEN - 1) as libc::off_t,
        )
    } != 1
    {
        println!("extend FAIL");
        return;
    }
    println!("open_extend ok");

    // `release` gates the workers; `ready` counts workers that have parked, so
    // we KNOW all K sibling vCPUs exist before the mapping is established.
    let release = Arc::new(AtomicU64::new(0));
    let ready = Arc::new(AtomicUsize::new(0));
    // Workers receive the mapping address through this shared atomic (published
    // by the main thread AFTER mmap). 0 = not yet mapped.
    let map_addr = Arc::new(AtomicU64::new(0));
    let matches = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..K {
        let release = Arc::clone(&release);
        let ready = Arc::clone(&ready);
        let map_addr = Arc::clone(&map_addr);
        let matches = Arc::clone(&matches);
        handles.push(std::thread::spawn(move || {
            // Park on a sibling vCPU BEFORE the alias window is mapped.
            ready.fetch_add(1, Ordering::SeqCst);
            let mut spins: u64 = 0;
            while release.load(Ordering::SeqCst) == 0 {
                spins += 1;
                if spins > 2_000_000_000 {
                    return; // bounded: never hang the harness
                }
                std::hint::spin_loop();
            }
            // Read the header THROUGH the mapping on THIS vCPU.
            let addr = map_addr.load(Ordering::SeqCst);
            if addr == 0 {
                return;
            }
            let v = unsafe { std::ptr::read_volatile(addr as *const u64) };
            if v == HEADER {
                matches.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    // Wait (bounded) for all workers to be parked on their vCPUs.
    let mut spins: u64 = 0;
    while ready.load(Ordering::SeqCst) < K {
        spins += 1;
        if spins > 2_000_000_000 {
            println!("workers_park FAIL");
            return;
        }
        std::hint::spin_loop();
    }
    println!("workers_parked ok n={K}");

    // Write the header via the fd, THEN map MAP_SHARED on the main vCPU.
    if unsafe { libc::pwrite(fd, &HEADER as *const u64 as *const _, 8, 0) } != 8 {
        println!("write_header FAIL");
        return;
    }
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            FILE_LEN,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        println!("mmap_shared FAIL");
        return;
    }
    // Main vCPU reads its own mapping — control (expected to always match).
    let main_v = unsafe { std::ptr::read_volatile(addr as *const u64) };
    println!("main_saw_header {}", main_v == HEADER);

    // Publish the address and release the sibling readers.
    map_addr.store(addr as u64, Ordering::SeqCst);
    release.store(1, Ordering::SeqCst);

    for h in handles {
        let _ = h.join();
    }
    println!("readers_match {}/{}", matches.load(Ordering::SeqCst), K);
    println!("DONE");
}
