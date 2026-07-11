//! Many forked processes waiting on a shared futex can be cmp-requeued and woken.
//!
//! This is the process-scale shape behind LTP `futex_cmp_requeue01`: a parent
//! forks many children, each child parks once in shared `FUTEX_WAIT`, then the
//! parent uses `FUTEX_CMP_REQUEUE` to wake a subset, move another subset to a
//! second futex word, and finally wake the destination. The output is
//! deliberately boolean-only so it remains a deterministic Docker-vs-Carrick
//! conformance probe.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use conformance_probes::errno;

const SYS_FUTEX: libc::c_long = libc::SYS_futex;
const FUTEX_WAIT: libc::c_int = 0;
const FUTEX_WAKE: libc::c_int = 1;
const FUTEX_CMP_REQUEUE: libc::c_int = 4;
const WAKE_COUNT: u32 = 300;
const REQUEUE_COUNT: u32 = 500;
const WAITERS: usize = 1000;
const WAKE_ALL: u32 = i32::MAX as u32;

#[repr(C)]
struct SharedPage {
    word0: u32,
    word1: u32,
    returned: u32,
    normal_wakes: u32,
    timed_out: u32,
    other_returns: u32,
}

unsafe fn futex_wait(addr: *mut u32, value: u32, timeout: &libc::timespec) -> libc::c_long {
    libc::syscall(
        SYS_FUTEX,
        addr,
        FUTEX_WAIT,
        value,
        timeout as *const libc::timespec,
    )
}

unsafe fn futex_wake(addr: *mut u32, count: u32) -> libc::c_long {
    libc::syscall(
        SYS_FUTEX,
        addr,
        FUTEX_WAKE,
        count,
        std::ptr::null::<libc::timespec>(),
    )
}

unsafe fn futex_cmp_requeue(
    from: *mut u32,
    wake: u32,
    requeue: u32,
    to: *mut u32,
    compare: u32,
) -> libc::c_long {
    libc::syscall(
        SYS_FUTEX,
        from,
        FUTEX_CMP_REQUEUE,
        wake,
        requeue as u64,
        to,
        compare as u64,
    )
}

unsafe fn make_pipe() -> Option<[libc::c_int; 2]> {
    let mut fds = [-1, -1];
    if libc::pipe(fds.as_mut_ptr()) == 0 {
        Some(fds)
    } else {
        None
    }
}

unsafe fn read_ready(fd: libc::c_int, deadline: Instant) -> usize {
    let mut total = 0usize;
    while total < WAITERS && Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout_ms = remaining.as_millis().clamp(1, 50) as libc::c_int;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = libc::poll(&mut pfd, 1, timeout_ms);
        if rc <= 0 {
            continue;
        }
        let mut buf = [0u8; 128];
        let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
        if n > 0 {
            total += n as usize;
        }
    }
    total
}

unsafe fn wait_for_returned(counter: *const u32, target: u32, deadline: Instant) -> u32 {
    let atomic = &*(counter as *const AtomicU32);
    let mut observed = atomic.load(Ordering::SeqCst);
    while observed < target && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
        observed = atomic.load(Ordering::SeqCst);
    }
    observed
}

unsafe fn reap_children(pids: &[libc::pid_t], deadline: Instant) -> (usize, bool) {
    let mut done = vec![false; pids.len()];
    let mut exited_ok = 0usize;
    while exited_ok < pids.len() && Instant::now() < deadline {
        for (idx, &pid) in pids.iter().enumerate() {
            if done[idx] {
                continue;
            }
            let mut status = 0;
            let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
            if rc == pid {
                done[idx] = true;
                if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                    exited_ok += 1;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    for (idx, &pid) in pids.iter().enumerate() {
        if !done[idx] {
            libc::kill(pid, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
        }
    }
    (exited_ok, exited_ok == pids.len())
}

fn main() {
    unsafe {
        let print_counts = std::env::args().any(|arg| arg == "counts");
        let page = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if page == libc::MAP_FAILED {
            println!("shared_map_ok=false");
            return;
        }
        let shared = page as *mut SharedPage;
        let word0 = &mut (*shared).word0 as *mut u32;
        let word1 = &mut (*shared).word1 as *mut u32;
        let returned = &mut (*shared).returned as *mut u32;
        let normal_wakes = &mut (*shared).normal_wakes as *mut u32;
        let timed_out = &mut (*shared).timed_out as *mut u32;
        let other_returns = &mut (*shared).other_returns as *mut u32;
        *word0 = 0;
        *word1 = 0;
        *returned = 0;
        *normal_wakes = 0;
        *timed_out = 0;
        *other_returns = 0;

        let Some(ready_pipe) = make_pipe() else {
            println!("shared_map_ok=true");
            println!("pipe_ok=false");
            return;
        };

        let mut pids = Vec::with_capacity(WAITERS);
        let mut fork_failures = 0usize;
        for _ in 0..WAITERS {
            let pid = libc::fork();
            if pid == 0 {
                libc::close(ready_pipe[0]);
                let byte = [1u8];
                let _ = libc::write(
                    ready_pipe[1],
                    byte.as_ptr() as *const libc::c_void,
                    byte.len(),
                );
                libc::close(ready_pipe[1]);
                let timeout = libc::timespec {
                    tv_sec: 10,
                    tv_nsec: 0,
                };
                let rc = futex_wait(word0, 0, &timeout);
                if rc == 0 {
                    (&*(normal_wakes as *const AtomicU32)).fetch_add(1, Ordering::SeqCst);
                } else if rc == -1 && errno() == libc::ETIMEDOUT {
                    (&*(timed_out as *const AtomicU32)).fetch_add(1, Ordering::SeqCst);
                } else {
                    (&*(other_returns as *const AtomicU32)).fetch_add(1, Ordering::SeqCst);
                }
                (&*(returned as *const AtomicU32)).fetch_add(1, Ordering::SeqCst);
                libc::_exit(0);
            }
            if pid > 0 {
                pids.push(pid);
            } else {
                fork_failures += 1;
            }
        }
        libc::close(ready_pipe[1]);

        let ready = read_ready(ready_pipe[0], Instant::now() + Duration::from_secs(20));
        libc::close(ready_pipe[0]);
        std::thread::sleep(Duration::from_millis(250));

        let moved = futex_cmp_requeue(word0, WAKE_COUNT, REQUEUE_COUNT, word1, 0);
        let returned_after_requeue = wait_for_returned(
            returned,
            WAKE_COUNT,
            Instant::now() + Duration::from_secs(20),
        );
        let wake1 = futex_wake(word1, WAKE_ALL);
        *word0 = 1;
        let wake0 = futex_wake(word0, WAKE_ALL);
        let final_returned = wait_for_returned(
            returned,
            pids.len() as u32,
            Instant::now() + Duration::from_secs(40),
        );
        let (exited_ok, all_exited_ok) =
            reap_children(&pids, Instant::now() + Duration::from_secs(40));

        println!("shared_map_ok=true");
        println!("pipe_ok=true");
        if print_counts {
            println!("pre_wait_pipe_count={ready}");
            println!("cmp_requeue_return_count={moved}");
            println!("returned_after_requeue_count={returned_after_requeue}");
            println!("wake_destination_count={wake1}");
            println!("wake_original_count={wake0}");
            println!("final_returned_count={final_returned}");
            println!(
                "normal_wakes_count={}",
                (&*(normal_wakes as *const AtomicU32)).load(Ordering::SeqCst)
            );
            println!(
                "timed_out_count={}",
                (&*(timed_out as *const AtomicU32)).load(Ordering::SeqCst)
            );
            println!(
                "other_returns_count={}",
                (&*(other_returns as *const AtomicU32)).load(Ordering::SeqCst)
            );
        }
        println!("fork_failures_zero={}", fork_failures == 0);
        println!("forked_all={}", pids.len() == WAITERS);
        println!("ready_all={}", ready == pids.len());
        println!(
            "cmp_requeue_returned_requested={}",
            moved == i64::from(WAKE_COUNT + REQUEUE_COUNT) as libc::c_long
        );
        println!(
            "only_direct_wake_returned_before_dest={}",
            returned_after_requeue == WAKE_COUNT
        );
        println!(
            "wake_destination_count_expected={}",
            wake1 == i64::from(REQUEUE_COUNT) as libc::c_long
        );
        println!("wake_original_nonnegative={}", wake0 >= 0);
        println!(
            "wake_original_count_expected={}",
            wake0 == (WAITERS as u32 - WAKE_COUNT - REQUEUE_COUNT) as libc::c_long
        );
        println!(
            "returned_count_expected={}",
            final_returned == WAITERS as u32
        );
        println!("returned_all={}", final_returned == pids.len() as u32);
        println!(
            "normal_wake_count_expected={}",
            (&*(normal_wakes as *const AtomicU32)).load(Ordering::SeqCst) == WAITERS as u32
        );
        println!(
            "timeout_count_zero={}",
            (&*(timed_out as *const AtomicU32)).load(Ordering::SeqCst) == 0
        );
        println!(
            "other_return_count_zero={}",
            (&*(other_returns as *const AtomicU32)).load(Ordering::SeqCst) == 0
        );
        println!("children_exited_all={all_exited_ok}");
        println!("children_exit_count_ok={}", exited_ok == pids.len());

        libc::munmap(page, 4096);
    }
}
