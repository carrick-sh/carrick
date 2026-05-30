//! Multithreaded-fork PARENT-heap-corruption reducer.
//!
//! Mirrors CPython's test_subprocess.test_double_close_on_error under
//! accumulation: a sibling thread churns `pipe(2)`s (like the test's `open_fds`
//! thread) while the MAIN thread repeatedly `fork()`s a child that fails to
//! `execve` a nonexistent command and `_exit`s (like `Popen(NONEXISTING_CMD,
//! stdin/stdout/stderr=PIPE)`). The parent reaps each child.
//!
//! On real Linux the long-lived multithreaded parent's heap is untouched by all
//! this. Under carrick the parent SEGV'd after ~130 such cycles in the full
//! suite, dereferencing a heap pointer that had been overwritten with garbage
//! (the fault showed x19 == 0x7878787878787878). That's the bug this probe
//! tries to reproduce deterministically: a large heap canary region is verified
//! after every fork; if carrick's multithreaded-fork quiesce/snapshot corrupts
//! the parent, a canary flips (canaries_intact=false) or the probe itself
//! crashes — either way it DIFFs against Docker, which prints all-true.
//!
//! Deterministic booleans only. A SIGALRM watchdog converts a wedge into output.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

/// Sibling thread: create pipes with a 1 ms cadence, concurrently with the
/// main thread's forks — exactly the window where a multithreaded fork must
/// quiesce a sibling that is mid-syscall. Bounds its fd use so we don't EMFILE.
extern "C" fn pipe_churner(_: *mut c_void) -> *mut c_void {
    let mut fds: Vec<i32> = Vec::new();
    while !STOP.load(Ordering::Relaxed) {
        let mut p = [0i32; 2];
        if unsafe { libc::pipe(p.as_mut_ptr()) } == 0 {
            fds.push(p[0]);
            fds.push(p[1]);
        }
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        };
        unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
        if fds.len() > 256 {
            for fd in fds.drain(..) {
                unsafe { libc::close(fd) };
            }
        }
    }
    std::ptr::null_mut()
}

const N_CANARY: usize = 1 << 16; // 64Ki u64 = 512 KiB heap canary region
const ITERS: usize = 400; // well past the ~130 cycles seen in the full suite

#[inline]
fn canary(i: usize) -> u64 {
    0xCA11_AB1E_0000_0000u64 ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

fn main() {
    use std::io::Write;
    unsafe { libc::alarm(25) };

    // Heap canary region kept alive across every fork.
    let buf: Vec<u64> = (0..N_CANARY).map(canary).collect();

    let mut tid: libc::pthread_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::pthread_create(
            &mut tid,
            std::ptr::null(),
            pipe_churner,
            std::ptr::null_mut(),
        )
    };
    println!("thread_started={}", rc == 0);
    let _ = std::io::stdout().flush();

    // Let the churner enter its loop before we start forking.
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 50_000_000,
    };
    unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };

    let bogus = c"/nonexisting_i_hope_mtforkcorrupt";
    let argv = [bogus.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null()];

    let mut forks_ok = 0usize;
    let mut first_corrupt_iter: i64 = -1;
    for it in 0..ITERS {
        // Heap churn each iteration, like CPython object allocation between
        // subprocess spawns — gives any stray write a fresh target.
        let churn: Vec<u64> = (0..2048).map(|x| canary(x ^ it)).collect();
        std::hint::black_box(&churn);

        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // Child: set up 3 stdio pipes like Popen(PIPE,PIPE,PIPE), then fail
            // to exec — must _exit without returning into Rust.
            unsafe {
                libc::execve(bogus.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
        } else if pid > 0 {
            let mut st = 0i32;
            unsafe { libc::waitpid(pid, &mut st, 0) };
            forks_ok += 1;
        }

        // Verify the parent's heap canaries survived the fork+reap.
        if first_corrupt_iter < 0 {
            for (i, &v) in buf.iter().enumerate() {
                if v != canary(i) {
                    first_corrupt_iter = it as i64;
                    break;
                }
            }
        }
        std::hint::black_box(&buf);
    }
    STOP.store(true, Ordering::Relaxed);

    println!("forks_done={}", forks_ok == ITERS);
    println!("canaries_intact={}", first_corrupt_iter < 0);
}
