//! flock(2) real advisory locking. carrick forwards flock to the macOS kernel
//! on host-backed fds, so two independent open descriptions of the same file
//! genuinely conflict: an exclusive lock held on one fd makes a LOCK_NB
//! exclusive request on the other fail with EAGAIN (EWOULDBLOCK), and the lock
//! is reacquirable after LOCK_UN. Plus the errno edges: bad fd → EBADF, bad
//! operation → EINVAL. Stands in for LTP flock04 / flock06.
//!
//! Deterministic booleans (no fd numbers / timing), diffed line-exact
//! carrick-vs-Linux.

use conformance_probes::errno;
use std::ffi::CString;

fn open(path: &str, flags: i32, mode: u32) -> i32 {
    let c = CString::new(path).unwrap();
    unsafe { libc::open(c.as_ptr(), flags, mode as libc::c_uint) }
}

fn main() {
    unsafe {
        let p = "/tmp/flocklk";
        let fd1 = open(p, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
        let fd2 = open(p, libc::O_RDWR, 0);

        println!("flock_ex_ok={}", libc::flock(fd1, libc::LOCK_EX) == 0);

        // A second, independent fd on the same file can't take an exclusive lock
        // while fd1 holds one (LOCK_NB → EAGAIN, not a block).
        let conflict = libc::flock(fd2, libc::LOCK_EX | libc::LOCK_NB);
        println!(
            "flock_conflict_eagain={}",
            conflict == -1 && errno() == libc::EAGAIN
        );

        println!("flock_un_ok={}", libc::flock(fd1, libc::LOCK_UN) == 0);

        // After the unlock the contending fd acquires it.
        println!(
            "flock_reacquire_ok={}",
            libc::flock(fd2, libc::LOCK_EX | libc::LOCK_NB) == 0
        );

        if fd1 >= 0 {
            libc::close(fd1);
        }
        if fd2 >= 0 {
            libc::close(fd2);
        }

        // Errno edge: a bad fd is EBADF. (A bad OPERATION → EINVAL on mainline
        // Linux and carrick, but the Docker LinuxKit arm64 kernel disagrees, so
        // that case is covered by carrick's behavior + the LTP test, not asserted
        // here — the documented Docker-kernel-artifact exclusion.)
        println!(
            "flock_badfd_ebadf={}",
            libc::flock(-1, libc::LOCK_EX) == -1 && errno() == libc::EBADF
        );

        flock_worker_progress_probe();
    }
}

/// Thirty-two independent open descriptions contend on a parent-held flock.
/// The parent is the only thread that releases the initial lock.  Thus a
/// carrier whose bounded executor set is occupied in blocking `flock` calls
/// must schedule the runnable parent before any worker can complete.
///
/// The parent polls the fixed completion pipe for at most five seconds before
/// joining.  If executor starvation prevents the parent from running, this is
/// the final observation in `main`; the external conformance harness bounds
/// and reaps that full-starvation case.
fn flock_worker_progress_probe() {
    const WORKERS: usize = 32;
    let mut path = b"/tmp/carrick-flock-worker-progress.XXXXXX\0".to_vec();
    let parent_fd = unsafe { libc::mkstemp(path.as_mut_ptr() as *mut libc::c_char) };
    if parent_fd < 0 {
        println!("flock_worker_setup_errno={}", errno());
        return;
    }
    if unsafe { libc::flock(parent_fd, libc::LOCK_EX) } != 0 {
        let error = errno();
        unsafe {
            libc::close(parent_fd);
            libc::unlink(path.as_ptr() as *const libc::c_char);
        }
        println!("flock_worker_setup_errno={error}");
        return;
    }

    // Each worker needs its own open-file description: dup'ing the parent's
    // fd would share flock ownership and eliminate the intended contention.
    // Open all descriptions before the barrier, then unlink the inode so
    // concurrent probe processes cannot collide on a pathname.
    let mut worker_fds = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let fd = unsafe { libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDWR) };
        if fd < 0 {
            let error = errno();
            for worker_fd in worker_fds {
                unsafe { libc::close(worker_fd) };
            }
            unsafe {
                libc::flock(parent_fd, libc::LOCK_UN);
                libc::close(parent_fd);
                libc::unlink(path.as_ptr() as *const libc::c_char);
            }
            println!("flock_worker_setup_errno={error}");
            return;
        }
        worker_fds.push(fd);
    }
    unsafe { libc::unlink(path.as_ptr() as *const libc::c_char) };

    let mut completions = [-1_i32; 2];
    if unsafe { libc::pipe(completions.as_mut_ptr()) } != 0 {
        let error = errno();
        unsafe {
            for worker_fd in worker_fds {
                libc::close(worker_fd);
            }
            libc::flock(parent_fd, libc::LOCK_UN);
            libc::close(parent_fd);
        }
        println!("flock_worker_setup_errno={error}");
        return;
    }
    let [completion_read, completion_write] = completions;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(WORKERS + 1));
    let mut workers = Vec::with_capacity(WORKERS);
    for fd in worker_fds {
        let barrier = std::sync::Arc::clone(&barrier);
        let worker = std::thread::Builder::new().spawn(move || {
            barrier.wait();
            let acquired = fd >= 0 && unsafe { libc::flock(fd, libc::LOCK_EX) } == 0;
            let unlocked = acquired && unsafe { libc::flock(fd, libc::LOCK_UN) } == 0;
            unsafe { libc::close(fd) };
            let success = acquired && unlocked;
            let marker = [u8::from(success)];
            let _ = unsafe { libc::write(completion_write, marker.as_ptr() as *const _, 1) };
            success
        });
        match worker {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                unsafe {
                    libc::flock(parent_fd, libc::LOCK_UN);
                    libc::close(parent_fd);
                    libc::close(completion_read);
                    libc::close(completion_write);
                }
                println!(
                    "flock_worker_setup_errno={}",
                    error.raw_os_error().unwrap_or(-1)
                );
                // Existing workers are fixed-barrier waiters.  Returning ends
                // this diagnostic process and lets the OS reclaim them.
                return;
            }
        }
    }

    barrier.wait();
    println!("flock_worker_startup={WORKERS}");
    // Give the worker cohort an opportunity to enter the blocking syscall;
    // only the parent performs the release below.
    std::thread::sleep(std::time::Duration::from_millis(10));
    let unlock_ok = unsafe { libc::flock(parent_fd, libc::LOCK_UN) } == 0;
    println!("flock_worker_parent_unlock={unlock_ok}");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut completion_count = 0_usize;
    let mut completion_successes = 0_usize;
    while completion_count < WORKERS && std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let mut pollfd = libc::pollfd {
            fd: completion_read,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pollfd, 1, remaining.as_millis().min(100) as i32) };
        if ready <= 0 {
            continue;
        }
        let mut markers = [0_u8; WORKERS];
        let read = unsafe {
            libc::read(
                completion_read,
                markers.as_mut_ptr() as *mut _,
                markers.len(),
            )
        };
        if read <= 0 {
            break;
        }
        let read = read as usize;
        completion_count += read;
        completion_successes += markers[..read]
            .iter()
            .filter(|marker| **marker == 1)
            .count();
    }
    println!("flock_worker_completion_count={completion_count}");
    println!("flock_worker_completion_successes={completion_successes}");

    unsafe {
        libc::close(parent_fd);
        libc::close(completion_read);
        libc::close(completion_write);
    }
    if completion_count != WORKERS {
        // Do not join a worker that did not report completion: close is not a
        // portable cancellation mechanism for a blocked flock.
        return;
    }
    let joined = workers
        .into_iter()
        .filter_map(|worker| worker.join().ok())
        .filter(|ok| *ok)
        .count();
    println!("flock_worker_join_successes={joined}");
}
