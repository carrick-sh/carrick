//! Per-thread names: prctl(PR_SET_NAME) names the CALLING thread, and another
//! thread's name is read via /proc/self/task/<tid>/comm. glibc's
//! pthread_setname_np(self)/getname_np use exactly these, and libuv's
//! uv_thread_setname/getname (thread_name test) depend on them.
//!
//! Carrick had no per-thread name store (prctl set a single process-wide name)
//! and no /proc/self/task/<tid>/comm routing (the `self` + task/<tid>/ path
//! matched no synthetic arm → ENOENT). A worker that prctl-sets its own name
//! could not be read back by tid.
//!
//!  * per_thread_comm_ok: a worker sets its name via prctl; the main thread
//!    reads "worker-thread" from /proc/self/task/<worker_tid>/comm, and the
//!    main thread's own prctl name round-trips via its task/<tid>/comm.

use conformance_probes::report;
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::thread;
use std::time::Duration;

const SYS_GETTID: libc::c_long = 178;
const PR_SET_NAME: libc::c_int = 15;

fn set_name(name: &str) {
    let mut buf = [0u8; 16];
    let b = name.as_bytes();
    let n = b.len().min(15);
    buf[..n].copy_from_slice(&b[..n]);
    unsafe {
        libc::prctl(PR_SET_NAME, buf.as_ptr() as libc::c_ulong, 0, 0, 0);
    }
}

fn read_comm(tid: i32) -> Option<String> {
    let mut s = String::new();
    std::fs::File::open(format!("/proc/self/task/{tid}/comm"))
        .ok()?
        .read_to_string(&mut s)
        .ok()?;
    Some(s.trim_end_matches('\n').to_string())
}

fn main() {
    let main_tid = unsafe { libc::syscall(SYS_GETTID) as i32 };
    set_name("mainthread");

    let wtid = Arc::new(AtomicI32::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let wtid_w = Arc::clone(&wtid);
    let stop_w = Arc::clone(&stop);
    let worker = thread::spawn(move || {
        set_name("worker-thread");
        wtid_w.store(
            unsafe { libc::syscall(SYS_GETTID) as i32 },
            Ordering::Release,
        );
        while !stop_w.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(1));
        }
    });
    for _ in 0..1000 {
        if wtid.load(Ordering::Acquire) != 0 {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    let wt = wtid.load(Ordering::Acquire);

    let worker_comm = read_comm(wt);
    let main_comm = read_comm(main_tid);
    eprintln!("main_tid={main_tid} wt={wt} main_comm={main_comm:?} worker_comm={worker_comm:?}");

    report!(
        per_thread_comm_ok = worker_comm.as_deref() == Some("worker-thread")
            && main_comm.as_deref() == Some("mainthread")
    );

    stop.store(true, Ordering::Release);
    let _ = worker.join();
}
