//! Cross-process SIGCHLD-to-handler probe (the real LTP kill12 dependency): a
//! forked child sends SIGCHLD to its parent (kill(getppid(),SIGCHLD)) WHILE
//! ALIVE; the parent's SIGCHLD handler must run. carrick installs no host
//! SIGCHLD handler (it routes child-EXIT via the pump), so a guest-SENT SIGCHLD
//! may never reach the parent's guest handler → kill12's parent spins waiting
//! for the child's readiness. Deterministic: prints caught=0/1. The child stays
//! alive during the parent's check so a 1 can only come from the SENT signal,
//! not the exit-SIGCHLD.
use std::sync::atomic::{AtomicI32, Ordering};
static GOT: AtomicI32 = AtomicI32::new(0);
extern "C" fn on_chld(_s: libc::c_int) { GOT.store(1, Ordering::SeqCst); }
fn main() { unsafe {
    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = on_chld as usize;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(libc::SIGCHLD, &sa, std::ptr::null_mut());
    let mut ready = [0i32; 2];
    libc::pipe(ready.as_mut_ptr());
    let pid = libc::fork();
    if pid == 0 {
        libc::usleep(200_000);
        libc::kill(libc::getppid(), libc::SIGCHLD);
        libc::write(ready[1], b"r".as_ptr() as *const libc::c_void, 1);
        libc::usleep(2_000_000); // stay alive past the parent's check
        libc::_exit(0);
    }
    let mut b = [0u8; 1];
    libc::read(ready[0], b.as_mut_ptr() as *mut libc::c_void, 1);
    libc::usleep(300_000); // let the SENT SIGCHLD be delivered (child still alive)
    println!("caught={}", GOT.load(Ordering::SeqCst));
    let mut st = 0; libc::waitpid(pid, &mut st, 0);
} }
