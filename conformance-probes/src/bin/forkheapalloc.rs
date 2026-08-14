//! Fork-private heap COW must preserve allocator metadata, not just payload
//! bytes. Seed and free a heap allocation before fork, then force the parent to
//! reuse that allocator state after the child exits. A copied frame with stale
//! or wrong bytes makes this tiny post-fork allocation return null or abort.

use conformance_probes::{reap, report};

fn main() {
    let tiny = String::from("seed");
    let tiny_ok = tiny == "seed";
    drop(tiny);
    let seeded: Vec<u8> = (0..10_240).map(|index| (index as u8).wrapping_mul(7)).collect();
    let seed_ok = seeded[0] == 0 && seeded[257] == 7;
    drop(seeded);

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::_exit(17) };
    }
    let (reaped, status) = unsafe { reap(pid) };
    let result = format!("exit:{}", libc::WEXITSTATUS(status));
    report!(
        seed_ok = (seed_ok && tiny_ok),
        child_reaped = (reaped == pid && libc::WIFEXITED(status)),
        post_fork_heap_alloc = (result == "exit:17"),
    );
}
