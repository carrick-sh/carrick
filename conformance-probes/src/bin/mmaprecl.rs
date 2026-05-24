//! mmap arena reclaim: allocate+touch+free a 64 MiB anonymous mapping many more
//! times than fit in the arena. Without reclaim the cumulative bump exhausts the
//! arena and a later mmap fails. Also verify a reused region reads back ZERO
//! (anonymous-mmap contract), not stale data. Deterministic booleans.

const CHUNK: usize = 64 * 1024 * 1024; // 64 MiB, like a Go heap arena
const ITERS: usize = 800; // 800 * 64 MiB = 50 GiB cumulative > 32 GiB arena

fn main() {
    unsafe { run() }
}

unsafe fn run() {
    let mut all_ok = true;
    let mut reuse_zero = true;
    for i in 0..ITERS {
        let p = libc::mmap(
            std::ptr::null_mut(),
            CHUNK,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            all_ok = false;
            break;
        }
        let bytes = p as *mut u8;
        // On a reused range, this must read 0 before we write (zeroed on reuse).
        if i > 0 && *bytes != 0 {
            reuse_zero = false;
        }
        *bytes = 0xAB; // dirty the first page so reuse must re-zero it
        *bytes.add(CHUNK - 1) = 0xCD; // touch the last page too
        libc::munmap(p, CHUNK);
    }
    println!("churn_ok={all_ok}");
    println!("reuse_zero={reuse_zero}");
}
