//! #3042: a native fork child's two live threads read(2) into one
//! copy-on-write page at once. The kernel's copy, not a user store, is the
//! page's first write in the child, so the user-copy supply must serve the
//! fork child's copy-on-write stock. Both reads land, every other byte of the
//! child's page is the parent's, and the parent's page is unchanged.
#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Barrier};

const ROUNDS: u8 = 32;
const PAGE: usize = 4096;
const OFFSETS: [usize; 2] = [0, 2048];
const MESSAGES: [&[u8; 8]; 2] = [b"CARRICK0", b"CARRICK1"];

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

/// The fork child's half. Its exit code names the first step that differs
/// from Linux: 0 when every check held.
fn child(page: usize, fill: u8) -> i32 {
    // Queue each worker's message first, so each read copies out at once.
    let mut pipes = [[-1i32; 2]; 2];
    for (pipe, message) in pipes.iter_mut().zip(MESSAGES) {
        if unsafe { libc::pipe(pipe.as_mut_ptr()) } != 0 {
            return 10;
        }
        if unsafe { libc::write(pipe[1], message.as_ptr().cast(), message.len()) } != 8 {
            return 11;
        }
    }
    let barrier = Arc::new(Barrier::new(OFFSETS.len()));
    let workers: Vec<_> = (0..OFFSETS.len())
        .map(|i| {
            let barrier = Arc::clone(&barrier);
            let fd = pipes[i][0];
            std::thread::spawn(move || {
                barrier.wait();
                let target = (page + OFFSETS[i]) as *mut libc::c_void;
                match unsafe { libc::read(fd, target, 8) } {
                    8 => 0,
                    rc if rc < 0 => 100 + errno(),
                    _ => 12,
                }
            })
        })
        .collect();
    for worker in workers {
        match worker.join() {
            Ok(0) => {}
            Ok(code) => return code,
            Err(_) => return 13,
        }
    }
    let bytes = unsafe { std::slice::from_raw_parts(page as *const u8, PAGE) };
    for (offset, message) in OFFSETS.iter().zip(MESSAGES) {
        if &bytes[*offset..*offset + 8] != message {
            return 20;
        }
    }
    let read_range = |j: usize| OFFSETS.iter().any(|offset| (*offset..*offset + 8).contains(&j));
    if bytes
        .iter()
        .enumerate()
        .any(|(j, byte)| !read_range(j) && *byte != fill)
    {
        return 21;
    }
    0
}

fn main() {
    for round in 0..ROUNDS {
        let fill = 0x40 + round;
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED, "mmap errno {}", errno());
        // Resident and private before the fork: the fork arms it
        // copy-on-write in both processes.
        unsafe { std::ptr::write_bytes(page.cast::<u8>(), fill, PAGE) };
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork errno {}", errno());
        if pid == 0 {
            let code = child(page as usize, fill);
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, 0) },
            pid,
            "waitpid errno {}",
            errno()
        );
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            println!(
                "round={round} child_exited={} child_code={} child_signal={}",
                libc::WIFEXITED(status),
                libc::WEXITSTATUS(status),
                if libc::WIFSIGNALED(status) {
                    libc::WTERMSIG(status)
                } else {
                    0
                }
            );
            std::process::exit(1);
        }
        let bytes = unsafe { std::slice::from_raw_parts(page.cast::<u8>(), PAGE) };
        if bytes.iter().any(|byte| *byte != fill) {
            println!("round={round} parent_page_changed=true");
            std::process::exit(1);
        }
        assert_eq!(unsafe { libc::munmap(page, PAGE) }, 0);
    }
    println!(
        "source_sha256={}",
        option_env!("CARRICK_COW_READ_THREADS_SOURCE_SHA256").unwrap_or("unknown")
    );
    println!("rounds={ROUNDS}\nthreads={}\ncow_read_ok=true", OFFSETS.len());
}
