//! Main-thread stack growth toward RLIMIT_STACK.
//!
//! Linux maps the main thread's stack lazily and grows it on demand up to
//! `RLIMIT_STACK` (8 MiB by default); a process may recurse through most of
//! that without any `mmap`. CPython's `test_compiler_recursion_limit`
//! recurses in the C compiler and segfaulted under carrick where Docker
//! passes, which is the shape this probe isolates.
//!
//! Invariants encoded, all boolean:
//!
//!   * `RLIMIT_STACK` soft limit reads as 8 MiB.
//!   * The main thread can recurse through ~6 MiB of stack (96 frames of
//!     64 KiB, each frame touched) and return.
//!   * A pthread created with the default attributes can do the same
//!     (glibc/musl default thread stacks are >= 8 MiB / 128 KiB: musl's
//!     default is small, so the thread is created with an explicit 8 MiB).
//!
//! Deterministic output: booleans only.

use conformance_probes::report;

const FRAME: usize = 64 * 1024;
const DEPTH: usize = 96; // ~6 MiB

#[inline(never)]
fn burn(depth: usize, seed: u8) -> u64 {
    let mut pad = [seed; FRAME];
    // Touch every page so the frame is really committed.
    let mut i = 0;
    while i < FRAME {
        pad[i] = pad[i].wrapping_add(depth as u8);
        i += 4096;
    }
    let below = if depth == 0 { 0 } else { burn(depth - 1, seed.wrapping_add(1)) };
    std::hint::black_box(&pad);
    below + u64::from(pad[FRAME - 1])
}

fn main() {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_STACK, &mut lim) };
    let rlimit_stack_is_8mib = rc == 0 && lim.rlim_cur == 8 * 1024 * 1024;

    let main_deep = burn(DEPTH, 1) > 0;

    let thread_deep = std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| burn(DEPTH, 7) > 0)
        .expect("spawn")
        .join()
        .unwrap_or(false);

    report!(
        rlimit_stack_is_8mib = rlimit_stack_is_8mib,
        main_thread_recurses_6mib = main_deep,
        thread_recurses_6mib = thread_deep,
    );
}
