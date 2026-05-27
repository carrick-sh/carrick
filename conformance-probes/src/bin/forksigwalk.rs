//! Reducer for the LTP `tst_run_tcases` segfault. That fault is a list-walk in
//! the library process dereferencing a corrupted node (value 17 = SIGCHLD)
//! after the test child is reaped — a guest store of bad data, SIGCHLD-
//! correlated, reached once the wait4 reap works. This probe reproduces the
//! essential shape WITHOUT the LTP framework so it runs non-root via run-elf
//! (the fault has a root-confounder under `carrick trace`):
//!
//!   * a parent that owns a linked list (both heap- and .bss/global-backed,
//!     nodes linked at offset 8 like the LTP struct),
//!   * SIGCHLD + SIGUSR1 handlers installed SA_RESTART (as LTP's test procs do),
//!   * repeated fork/reap cycles where the child fires SIGUSR1 at the parent
//!     (LTP's heartbeat) right as the parent blocks in waitpid,
//!   * after each reap: walk both lists and verify every node is intact, and
//!     verify the reaped child's status is WIFEXITED(0) — not a bogus signal
//!     status (the 17 smells like a mis-encoded wait status leaking into memory).
//!
//! Deterministic booleans only. A `false` (or a runaway walk caught by the
//! bound) pinpoints the corruption; all-true means this shape is clean and the
//! repro needs more LTP-specific structure.

use std::sync::atomic::{AtomicU32, Ordering};

static USR1: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_chld(_: i32) {}
extern "C" fn on_usr1(_: i32) {
    USR1.fetch_add(1, Ordering::SeqCst);
}

#[repr(C)]
struct Node {
    data: u64,
    next: *mut Node, // offset 8, mirrors the LTP list link
    pad: [u64; 24],  // ~200-byte nodes like the LTP struct (offsets 0x18/0xd0 live)
}

const N: u64 = 48;
// A global (.bss) list head, so we also exercise the data-segment case the LTP
// `results`/`tst_test` globals live in.
static mut GLOBAL_HEAD: *mut Node = std::ptr::null_mut();

unsafe fn install(sig: i32, h: extern "C" fn(i32), flags: i32) {
    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = h as usize;
    sa.sa_flags = flags;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(sig, &sa, std::ptr::null_mut());
}

unsafe fn build_list() -> *mut Node {
    let mut head: *mut Node = std::ptr::null_mut();
    for i in (0..N).rev() {
        let node = Box::into_raw(Box::new(Node {
            data: 0xC0DE_0000 + i,
            next: head,
            pad: [0xABCD; 24],
        }));
        head = node;
    }
    head
}

/// Walk the list, verifying node `data` is the expected sentinel sequence and
/// `next` never points off into garbage. Bounded so a corrupted `next` (e.g.
/// the 17 node) yields `false` instead of a wild deref / hang.
unsafe fn list_intact(head: *mut Node) -> bool {
    let mut p = head;
    let mut idx = 0u64;
    while !p.is_null() {
        if idx > N {
            return false; // runaway: a `next` was corrupted into a cycle/garbage
        }
        if (*p).data != 0xC0DE_0000 + idx {
            return false;
        }
        p = (*p).next;
        idx += 1;
    }
    idx == N
}

fn main() {
    unsafe {
        install(libc::SIGCHLD, on_chld, libc::SA_RESTART);
        install(libc::SIGUSR1, on_usr1, libc::SA_RESTART);
        let heap_head = build_list();
        GLOBAL_HEAD = build_list();

        let mut heap_ok = true;
        let mut global_ok = true;
        let mut status_ok = true;

        for _ in 0..64 {
            let pid = libc::fork();
            if pid == 0 {
                // Child: heartbeat SIGUSR1 at the parent (interrupts its
                // waitpid; SA_RESTART must restart it), then exit cleanly.
                libc::kill(libc::getppid(), libc::SIGUSR1);
                libc::_exit(0);
            }
            // Parent: blocking reap; loop past any EINTR.
            let mut st: libc::c_int = 0;
            loop {
                let r = libc::wait4(pid, &mut st, 0, std::ptr::null_mut());
                if r == -1 && *libc::__errno_location() == libc::EINTR {
                    continue;
                }
                break;
            }
            // The child exited(0): status must be WIFEXITED, code 0 — never a
            // bogus WIFSIGNALED (which would carry a signal number like 17).
            if !(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0) {
                status_ok = false;
            }
            if !list_intact(heap_head) {
                heap_ok = false;
            }
            if !list_intact(GLOBAL_HEAD) {
                global_ok = false;
            }
            if !(heap_ok && global_ok && status_ok) {
                break;
            }
        }

        println!("heap_list_intact={heap_ok}");
        println!("global_list_intact={global_ok}");
        println!("wait_status_ok={status_ok}");
        println!("sigusr1_seen={}", USR1.load(Ordering::SeqCst) > 0);
    }
}
