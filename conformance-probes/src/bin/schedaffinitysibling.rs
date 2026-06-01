//! sched_getaffinity/sched_setaffinity must accept a live SIBLING thread's TID
//! (not just 0 / getpid()). libuv's uv_thread_setaffinity/getaffinity pass the
//! target thread's tid; thread_affinity exercises this on a worker.
//!
//! Carrick's resolve_affinity_target only recognized pid==0/getpid() (SelfProc)
//! or a host-pid in the guest process tree (OtherGuest); a synthetic sibling
//! guest ThreadId matched neither, so it returned ESRCH. (sched_getscheduler/
//! getparam already accept sibling tids — affinity just never got that branch.)
//!
//!  * sibling_affinity_ok: sched_getaffinity(sibling_tid) succeeds and
//!    sched_setaffinity(sibling_tid, <same mask>) returns 0.

use conformance_probes::report;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::thread;
use std::time::Duration;

const SYS_GETTID: libc::c_long = 178;
const SYS_SCHED_SETAFFINITY: libc::c_long = 122;
const SYS_SCHED_GETAFFINITY: libc::c_long = 123;

fn main() {
    let tid = Arc::new(AtomicI32::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let tid_w = Arc::clone(&tid);
    let stop_w = Arc::clone(&stop);
    let worker = thread::spawn(move || {
        tid_w.store(
            unsafe { libc::syscall(SYS_GETTID) as i32 },
            Ordering::Release,
        );
        while !stop_w.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(1));
        }
    });
    for _ in 0..1000 {
        if tid.load(Ordering::Acquire) != 0 {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    let t = tid.load(Ordering::Acquire);
    unsafe {
        // cpu_set_t is 128 bytes (glibc CPU_SETSIZE=1024).
        let mut mask = [0u8; 128];
        let getr = libc::syscall(
            SYS_SCHED_GETAFFINITY,
            t as libc::c_long,
            128 as libc::c_long,
            mask.as_mut_ptr() as libc::c_long,
        );
        let get_errno = if getr < 0 {
            *libc::__errno_location()
        } else {
            0
        };
        let setr = libc::syscall(
            SYS_SCHED_SETAFFINITY,
            t as libc::c_long,
            128 as libc::c_long,
            mask.as_ptr() as libc::c_long,
        );
        let set_errno = if setr < 0 {
            *libc::__errno_location()
        } else {
            0
        };
        // Do NOT print the raw tid/errnos — `t` is a non-deterministic thread
        // id (carrick host pid vs Docker ns-tid) and the gate compares stderr
        // too, so a raw-tid diagnostic DIFFs under concurrent load. The boolean
        // verdict is the deterministic contract.
        let _ = (get_errno, set_errno);
        report!(sibling_affinity_ok = getr > 0 && setr == 0);
    }
    stop.store(true, Ordering::Release);
    let _ = worker.join();
}
