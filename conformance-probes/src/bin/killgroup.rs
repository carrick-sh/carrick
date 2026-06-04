//! Process-group signal delivery probe: does a FORKED child, BLOCKED in
//! `pause()`, receive a `kill(0, SIGUSR1)` sent to the caller's process group?
//!
//! This is the reduced form of LTP `kill02`'s core: the parent and a forked
//! child share a process group; the parent signals the group with `kill(0)`;
//! the child's handler must run (waking it out of `pause`). carrick delivers a
//! cross-process signal via a host `kill` → `handle_routed` → a published
//! pending signal; the forked child must WAKE from `pause` and run the handler.
//!
//! Deterministic: prints a single boolean. The child arms `alarm(4)` (with a
//! no-op SIGALRM handler) as a backstop so a broken delivery yields `false`
//! after ~4s instead of hanging the harness. `pause()` (a real block), not a
//! poll loop, is essential — a poll loop would re-check the flag and mask the
//! exact wakeup bug under test.

use std::sync::atomic::{AtomicI32, Ordering};

static CAUGHT: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_usr1(_sig: libc::c_int) {
    CAUGHT.store(1, Ordering::SeqCst);
}
extern "C" fn on_alrm(_sig: libc::c_int) {
    // No-op: its only job is to make pause() return if SIGUSR1 never arrives.
}

fn main() {
    unsafe {
        // Be our own process-group leader so kill(0) is scoped to us + the child
        // (never the launcher's group).
        libc::setpgid(0, 0);

        // Install handlers BEFORE fork so BOTH processes catch SIGUSR1 (a
        // default-disposition SIGUSR1 would terminate the parent, which is also
        // in the target group) and so the child can backstop with SIGALRM.
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_usr1 as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
        let mut sa2: libc::sigaction = std::mem::zeroed();
        sa2.sa_sigaction = on_alrm as usize;
        libc::sigemptyset(&mut sa2.sa_mask);
        libc::sigaction(libc::SIGALRM, &sa2, std::ptr::null_mut());

        let mut ready = [0i32; 2];
        let mut caught = [0i32; 2];
        libc::pipe(ready.as_mut_ptr());
        libc::pipe(caught.as_mut_ptr());

        let pid = libc::fork();
        if pid == 0 {
            // CHILD: signal readiness, then BLOCK in pause() awaiting SIGUSR1.
            libc::write(ready[1], b"r".as_ptr() as *const libc::c_void, 1);
            libc::alarm(4); // backstop so a lost wakeup doesn't hang the harness
            libc::pause();
            let v: &[u8] = if CAUGHT.load(Ordering::SeqCst) == 1 {
                b"1"
            } else {
                b"0"
            };
            libc::write(caught[1], v.as_ptr() as *const libc::c_void, 1);
            libc::_exit(0);
        }

        // PARENT: wait for the child to be ready + in pause(), then signal the
        // whole process group, then read the child's verdict.
        let mut b = [0u8; 1];
        libc::read(ready[0], b.as_mut_ptr() as *mut libc::c_void, 1);
        // Small settle so the child is parked in pause() before we signal.
        libc::usleep(200_000);
        libc::kill(0, libc::SIGUSR1);
        let mut verdict = [0u8; 1];
        libc::read(caught[0], verdict.as_mut_ptr() as *mut libc::c_void, 1);
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        println!("child_caught_group_kill0={}", verdict[0] as char);
    }
}
