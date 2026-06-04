//! Two DISTINCT standard signals that are pending at the same time must BOTH be
//! delivered. The parent blocks SIGUSR1+SIGUSR2, a child sends one of each while
//! they're blocked (so both become pending together), then the parent unblocks.
//! On real Linux both handlers run (the kernel keeps a per-signal pending set);
//! the parent sees usr1=1 usr2=1 both=1.
//!
//! carrick regression target (LTP kill10's signal-storm hang): a single
//! process-directed PENDING slot stores the LAST cross-process signum and
//! overwrites the previous one — so the second `kill` clobbers the first, the
//! parent only ever sees one signal, and a process waiting on the other (e.g.
//! kill10's master counting acks from BOTH managers) blocks forever. With the
//! single-slot bug this prints both=0; the fix (per-signum accumulation) → both=1.
//! Deterministic: the pipe handshake guarantees both signals are pending before
//! the unblock, so no timing window is involved.
use std::sync::atomic::{AtomicI32, Ordering};

static G1: AtomicI32 = AtomicI32::new(0);
static G2: AtomicI32 = AtomicI32::new(0);

extern "C" fn h1(_s: libc::c_int) {
    G1.fetch_add(1, Ordering::SeqCst);
}
extern "C" fn h2(_s: libc::c_int) {
    G2.fetch_add(1, Ordering::SeqCst);
}

unsafe fn wr(fd: i32) {
    let b = [1u8];
    libc::write(fd, b.as_ptr() as *const libc::c_void, 1);
}
unsafe fn rd(fd: i32) {
    let mut b = [0u8; 1];
    libc::read(fd, b.as_mut_ptr() as *mut libc::c_void, 1);
}

fn main() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_sigaction = h1 as usize;
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
        sa.sa_sigaction = h2 as usize;
        libc::sigaction(libc::SIGUSR2, &sa, std::ptr::null_mut());

        let mut to_child = [0i32; 2];
        let mut to_parent = [0i32; 2];
        libc::pipe(to_child.as_mut_ptr());
        libc::pipe(to_parent.as_mut_ptr());
        let parent = libc::getpid();

        let pid = libc::fork();
        if pid == 0 {
            rd(to_child[0]); // wait until the parent has blocked both signals
            libc::kill(parent, libc::SIGUSR1);
            libc::kill(parent, libc::SIGUSR2);
            wr(to_parent[1]); // tell the parent both were sent
            libc::usleep(500_000);
            libc::_exit(0);
        }

        // Block both, then let the child send them so BOTH are pending at once.
        let mut block: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut block);
        libc::sigaddset(&mut block, libc::SIGUSR1);
        libc::sigaddset(&mut block, libc::SIGUSR2);
        libc::sigprocmask(libc::SIG_BLOCK, &block, std::ptr::null_mut());

        wr(to_child[1]); // parent has blocked both
        rd(to_parent[0]); // child has sent both → both are pending+blocked now

        // Unblock: the kernel must deliver BOTH pending signals.
        libc::sigprocmask(libc::SIG_UNBLOCK, &block, std::ptr::null_mut());
        // Settle: give the runtime a syscall boundary to run both handlers.
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000,
        };
        libc::nanosleep(&ts, std::ptr::null_mut());

        let g1 = G1.load(Ordering::SeqCst);
        let g2 = G2.load(Ordering::SeqCst);
        println!(
            "usr1={} usr2={} both={}",
            g1.min(1),
            g2.min(1),
            ((g1 >= 1) && (g2 >= 1)) as i32
        );
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
    }
}
