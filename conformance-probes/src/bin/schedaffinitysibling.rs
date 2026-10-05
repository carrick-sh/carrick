//! A sibling TID names that exact thread's CPU mask. Changing it must leave
//! the caller's mask intact; queries from either thread must agree. In the
//! sibling, getpid() still names the leader rather than the calling thread.
use conformance_probes::report;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

type Mask = [u8; 128];

fn get(pid: i32) -> (Mask, i32) {
    let mut mask = [0; 128];
    let rc = unsafe {
        libc::syscall(
            libc::SYS_sched_getaffinity,
            pid,
            mask.len(),
            mask.as_mut_ptr(),
        )
    };
    let errno = if rc < 0 {
        unsafe { *libc::__errno_location() }
    } else {
        0
    };
    (mask, errno)
}

fn set(pid: i32, mask: &Mask) -> i32 {
    let rc = unsafe { libc::syscall(libc::SYS_sched_setaffinity, pid, mask.len(), mask.as_ptr()) };
    if rc < 0 {
        unsafe { *libc::__errno_location() }
    } else {
        0
    }
}

fn main() {
    let (caller_before, caller_get_errno) = get(0);
    let leader = unsafe { libc::getpid() };
    let (ready_tx, ready_rx) = mpsc::channel();
    let (query_tx, query_rx) = mpsc::channel();
    let (answer_tx, answer_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) as i32 };
        // Read the child's own mask before exposing its TID. Besides checking
        // inheritance, this makes the witness name a host-admitted thread;
        // guest-only Born/zone ownership is sequenced separately after N1.
        let initial = get(0);
        let _ = ready_tx.send((tid, initial));
        if query_rx.recv_timeout(Duration::from_secs(5)).is_ok() {
            let _ = answer_tx.send((get(0), get(leader)));
        }
    });
    let (tid, (worker_initial_mask, worker_initial_errno)) = ready_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or((-1, ([0; 128], libc::ETIMEDOUT)));
    let (sibling_before, sibling_get_errno) = get(tid);
    let same_mask_set_errno = set(tid, &sibling_before);
    report!(sibling_affinity_ok = tid > 0 && sibling_get_errno == 0 && same_mask_set_errno == 0);

    // Pick from the actual allowed set: Docker's cpuset need not include CPU 0.
    let mut requested = [0; 128];
    if let Some((byte, bit)) = caller_before.iter().enumerate().find_map(|(byte, bits)| {
        (0..8)
            .find(|bit| bits & (1 << bit) != 0)
            .map(|bit| (byte, bit))
    }) {
        requested[byte] = 1 << bit;
    }
    let changed_set_errno = set(tid, &requested);
    let (caller_after, caller_after_errno) = get(0);
    let (sibling_after, sibling_after_errno) = get(tid);
    let _ = query_tx.send(());
    let answer = answer_rx.recv_timeout(Duration::from_secs(5));
    let ((worker_mask, worker_errno), (leader_mask, leader_errno)) =
        answer.unwrap_or((([0; 128], libc::ETIMEDOUT), ([0; 128], libc::ETIMEDOUT)));
    let _ = worker.join();
    report!(
        distinct_masks_exercised = caller_before != requested
            && caller_before == sibling_before
            && caller_before == worker_initial_mask
    );
    report!(caller_mask_unchanged = caller_before == caller_after);
    report!(sibling_mask_from_caller = sibling_after == requested);
    report!(sibling_mask_from_sibling = worker_mask == requested);
    report!(leader_mask_from_sibling = leader_mask == caller_before);
    report!(caller_get_errno = caller_get_errno);
    report!(sibling_get_errno = sibling_get_errno);
    report!(same_mask_set_errno = same_mask_set_errno);
    report!(changed_set_errno = changed_set_errno);
    report!(caller_after_errno = caller_after_errno);
    report!(sibling_after_errno = sibling_after_errno);
    report!(worker_get_errno = worker_errno);
    report!(worker_initial_errno = worker_initial_errno);
    report!(leader_get_errno = leader_errno);
}
