//! mremap shrink must UNMAP the freed tail (Linux semantics).
//!
//! carrick's mremap MREMAP_MAYMOVE shrink returned old_address but left the
//! freed tail [old+new_size, old+old_size) MAPPED (a leak). The stale bytes
//! there were eventually misread by glibc's malloc as a chunk header →
//! "Fatal glibc error: mremap_chunk: assertion failed aligned_OK" in
//! multiprocessing TestIgnoreEINTR (recv_bytes(CONN_MAX_SIZE)). The fix reclaims
//! the tail exactly as munmap does.
//!
//! This probe exercises the raw mremap(2) syscall (so it's allocator-agnostic —
//! musl is fine): map a region, shrink it, and confirm in a forked child that
//! the freed tail now FAULTS (unmapped) while the kept head still reads. On
//! Linux the tail is unmapped; with the bug it stays readable. Deterministic
//! booleans; the child's fault is observed via its exit signal, never the
//! parent's.

const PAGE: usize = 4096;
const BIG: usize = 512 * PAGE; // 2 MiB
const KEEP: usize = PAGE; // shrink to one page

fn main() {
    // Map a private anonymous region and touch every page so it's fully backed.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            BIG,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let mapped = p != libc::MAP_FAILED;
    println!("mmap_ok={mapped}");
    if !mapped {
        println!("shrink_ok=false\nkept_readable=false\ntail_unmapped=false");
        return;
    }
    let base = p as *mut u8;
    unsafe {
        for i in (0..BIG).step_by(PAGE) {
            *base.add(i) = 0xAB;
        }
    }

    // Shrink to one page. MREMAP_MAYMOVE; Linux returns the same addr here.
    let np = unsafe { libc::mremap(p, BIG, KEEP, libc::MREMAP_MAYMOVE) };
    let shrink_ok = np != libc::MAP_FAILED;
    println!("shrink_ok={shrink_ok}");
    let head = if shrink_ok { np as *mut u8 } else { base };

    // The kept head page is still readable.
    let kept = unsafe { std::ptr::read_volatile(head) } == 0xAB;
    println!("kept_readable={kept}");

    // A forked child touches the FREED tail (well past KEEP). On Linux that page
    // is unmapped → the child dies by SIGSEGV. With the leak it reads fine → the
    // child exits 0. Observe via the child's exit signal (deterministic boolean).
    let tail = unsafe { head.add(BIG / 2) }; // 1 MiB in — solidly in the freed tail
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let v = unsafe { std::ptr::read_volatile(tail) };
        std::hint::black_box(v);
        unsafe { libc::_exit(0) }; // reached only if the tail is STILL mapped (bug)
    }
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let tail_unmapped = libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSEGV;
    println!("tail_unmapped={tail_unmapped}");
}
