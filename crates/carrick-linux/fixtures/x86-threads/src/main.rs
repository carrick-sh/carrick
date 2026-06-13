//! M3c thread fixture (audit #1): spawns a `std::thread` worker that writes and
//! reads a `thread_local!` (forcing a TLS access through FS.base), then the main
//! thread `join`s it (a futex wait). Raw `libc::write` avoids cross-thread
//! buffered-stdout surprises.
//!
//! Cross-compiled static x86_64-unknown-linux-musl (non-PIE ET_EXEC) by
//! build.sh. Run under carrick-kvm it proves the x86 KVM clone(CLONE_THREAD)
//! sibling-vCPU path: a fresh sibling vCPU on the same VM, seeded with RAX=0,
//! RSP=child stack, FS.base=tls, RIP=SYSRETQ. If the clone tls/child_tid arg
//! order is normalized WRONG, the worker's TLS access faults and "worker-ok" is
//! never printed.
use std::cell::Cell;
use std::thread;

thread_local! {
    static MARKER: Cell<u32> = const { Cell::new(0) };
}

fn main() {
    let h = thread::spawn(|| {
        // TLS write+read via FS.base. SIGSEGVs if the sibling's fs.base (the
        // clone `tls` arg) was seeded with the wrong value.
        MARKER.with(|m| m.set(42));
        let v = MARKER.with(|m| m.get());
        if v == 42 {
            unsafe { libc::write(1, b"worker-ok\n".as_ptr() as *const _, 10) };
        }
    });
    h.join().expect("join worker thread");
    unsafe { libc::write(1, b"main-ok\n".as_ptr() as *const _, 8) };
}
