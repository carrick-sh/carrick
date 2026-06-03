//! MAP_SHARED file-mapping conformance: a plain store works, but an ATOMIC
//! read-modify-write (LDADD/LDXR) on a file-backed MAP_SHARED page is what Go's
//! telemetry counter does, and it faults under carrick `--fs host` while docker
//! handles it. Each step prints a deterministic line; the harness diffs carrick
//! vs Linux line-for-line, so the first missing line pinpoints the failing op.
//!
//! run-elf's rootfs is empty, so /tmp is created first; the file lives there so
//! the MAP_SHARED mapping is backed by a real host file under `--fs host`.

use std::sync::atomic::{AtomicU64, Ordering};

fn main() {
    unsafe {
        libc::mkdir(c"/tmp".as_ptr(), 0o777);
    }
    let len: usize = 4096;
    let fd = unsafe {
        libc::open(
            c"/tmp/mmapfile_probe".as_ptr(),
            libc::O_RDWR | libc::O_CREAT,
            0o644,
        )
    };
    if fd < 0 {
        println!("open FAIL");
        return;
    }
    if unsafe { libc::ftruncate(fd, len as libc::off_t) } != 0 {
        println!("ftruncate FAIL");
        return;
    }
    println!("open_ftruncate ok");

    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
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
    println!("mmap_shared ok");

    // 1. plain store + readback through the mapping (control — known to work).
    unsafe {
        *(addr as *mut u64) = 0x1122_3344_5566_7788;
    }
    let rb = unsafe { *(addr as *const u64) };
    println!("plain_store ok rb_match={}", rb == 0x1122_3344_5566_7788);

    // 2. ATOMIC fetch_add on the file-backed page (the telemetry counter pattern).
    let atom = unsafe { &*(addr as *const AtomicU64) };
    atom.store(0, Ordering::SeqCst);
    let prev = atom.fetch_add(1, Ordering::SeqCst);
    let now = atom.load(Ordering::SeqCst);
    println!("atomic_add ok prev={prev} now={now}");

    // 3. atomic at a non-zero offset (counters live in an array).
    let atom2 = unsafe { &*((addr as *const u8).add(64) as *const AtomicU64) };
    atom2.store(0, Ordering::SeqCst);
    let p2 = atom2.fetch_add(7, Ordering::SeqCst);
    println!(
        "atomic_add_off64 ok prev={p2} now={}",
        atom2.load(Ordering::SeqCst)
    );

    // 4. compare-exchange (LDXR/STXR loop) on the mapping.
    let res = atom.compare_exchange(1, 42, Ordering::SeqCst, Ordering::SeqCst);
    println!("cmpxchg ok matched={}", res.is_ok());

    // 5. flush back to the file.
    let r = unsafe { libc::msync(addr, len, libc::MS_SYNC) };
    println!("msync ok rc={r}");

    println!("DONE");
}
