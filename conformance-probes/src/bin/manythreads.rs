//! More concurrent threads than the HVF vCPU cap — the vCPU admission gate.
//!
//! carrick binds one Hypervisor.framework vCPU per guest thread for the thread's
//! whole lifetime, and HVF caps the number of vCPUs that may exist concurrently
//! in a VM (`hv_vm_get_max_vcpu_count`, 64 on Apple Silicon). A guest that runs
//! more threads than the cap (CPython `test_queue.test_many_threads` spawns 50
//! producers + 50 consumers = 100) used to make `hv_vcpu_create` return
//! HV_NO_RESOURCES; because the `clone` syscall had ALREADY reported the new tid
//! as success, the thread that failed to get a vCPU silently never ran and any
//! join on it deadlocked → 150 s TIMEOUT. The fix gates sibling-thread vCPU
//! creation on a semaphore sized to the cap: `clone` still succeeds (matching
//! Linux, which has no such cap), the new thread simply waits for a vCPU slot
//! to free (another thread exits) before it is scheduled.
//!
//! This probe spawns N=96 threads — comfortably above the 64 cap — each of which
//! does a trivial unit of work and exits, so slots recycle. On Linux all 96 run.
//! Under carrick the gate must let all 96 complete (up to ~60 truly concurrent;
//! the rest are admitted as earlier ones exit) instead of deadlocking.
//!
//! Deterministic output: booleans only — never the thread count's raw timing or
//! ids. The assertion is the RELATIONSHIP "every spawned thread ran and joined".

use conformance_probes::report;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

const N: u32 = 96;

fn main() {
    let ran = Arc::new(AtomicU32::new(0));
    let mut handles = Vec::with_capacity(N as usize);
    let mut spawn_ok = true;

    for _ in 0..N {
        let ran = Arc::clone(&ran);
        match std::thread::Builder::new().spawn(move || {
            // A trivial, terminating unit of work: touch some thread-local
            // state so the thread genuinely executes guest code on its vCPU,
            // then exit (freeing its vCPU slot for a gated sibling).
            let mut acc: u64 = 0;
            for i in 0..1000u64 {
                acc = acc.wrapping_add(i);
            }
            std::hint::black_box(acc);
            ran.fetch_add(1, Ordering::SeqCst);
        }) {
            Ok(h) => handles.push(h),
            Err(_) => {
                spawn_ok = false;
                break;
            }
        }
    }

    let spawned = handles.len() as u32;
    let mut join_ok = true;
    for h in handles {
        if h.join().is_err() {
            join_ok = false;
        }
    }
    let all_ran = ran.load(Ordering::SeqCst) == spawned;

    report!(
        // Every one of the N threads was spawnable (clone never failed even
        // though N exceeds the HVF vCPU cap).
        spawned_all = spawn_ok && spawned == N,
        // Every spawned thread joined cleanly...
        joined_all = join_ok,
        // ...and actually executed its body (none was a phantom thread whose
        // vCPU never started — the bug this gate fixes).
        all_threads_ran = all_ran,
    );
}
