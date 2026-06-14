//! SP4.1 fixture: async host->guest signal delivery at an ARBITRARY ring-3 PC.
//!
//! The main thread installs a SA_SIGINFO SIGUSR1 handler, then spins in a TIGHT
//! ALU loop with NO syscalls in the loop body. A SIBLING guest thread (spawned
//! via `std::thread::spawn`, i.e. `clone(CLONE_THREAD|CLONE_VM|...)` → a sibling
//! bhyve vCPU on the shared VM) busy-spins briefly so the main thread is firmly
//! mid-loop, then `tgkill`s the main thread with SIGUSR1.
//!
//! Because the main thread is NOT at a syscall boundary, the only way the loop
//! can terminate is the async kick interrupting the running vCPU: the kick
//! surfaces as `VM_EXITCODE_BOGUS` → `next_syscall` returns `Ok(None)` → the
//! generic loop reads `current_pc()` and delivers the pending SIGUSR1 at that
//! arbitrary `interrupted_pc`, runs the handler (sets `DELIVERED`), returns
//! through musl's `__restore_rt` → rt_sigreturn → resume the loop. The loop then
//! observes `DELIVERED` and prints "asyncsig-ok".
//!
//! The `i > 5e9` guard is the BOUNDED-LATENCY assertion: a working kick fires in
//! microseconds; an un-interrupted loop hits the bound and `_exit(2)`s with
//! "asyncsig-timeout" (RED). Static x86_64-unknown-linux-musl (non-PIE ET_EXEC).
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// Set by the handler when SIGUSR1 is delivered. The tight loop reads this with
/// NO syscall, so the kick is the ONLY way out.
static DELIVERED: AtomicBool = AtomicBool::new(false);
/// The handler stores `info->si_signo` for a sanity check (a wrong signo means a
/// mis-delivered frame, not a clean SP4.1 success).
static GOT_SIGNO: AtomicI32 = AtomicI32::new(0);

extern "C" fn handler(_sig: i32, info: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    let signo = if info.is_null() {
        -1
    } else {
        // SAFETY: the kernel/carrick supplies a valid siginfo for SA_SIGINFO.
        unsafe { (*info).si_signo }
    };
    GOT_SIGNO.store(signo, Ordering::SeqCst);
    DELIVERED.store(true, Ordering::SeqCst);
}

/// `gettid(2)` raw — musl 0.2 libc has no `gettid` wrapper on this target, and
/// the syscall is the robust way to get the thread's kernel tid (the tgkill
/// target). x86-64 SYS_gettid = 186.
fn gettid() -> libc::pid_t {
    // SAFETY: gettid takes no args and never fails.
    unsafe { libc::syscall(186) as libc::pid_t }
}

fn main() {
    // Install the SA_SIGINFO SIGUSR1 handler.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction =
            handler as extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void) as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut()) != 0 {
            libc::write(2, b"sigaction-failed\n".as_ptr() as *const _, 17);
            libc::_exit(3);
        }
    }

    // The PID + the MAIN thread's tid (the tgkill target). Captured BEFORE the
    // tight loop (a syscall here is fine — it is outside the loop body).
    let pid = unsafe { libc::getpid() };
    let main_tid = gettid();

    // Spawn the sibling (a sibling vCPU on the shared VM). It busy-spins briefly
    // so the main thread is firmly mid-loop, then tgkills the main thread.
    std::thread::spawn(move || {
        // Short syscall-free busy spin so the main thread is in its tight loop
        // when the signal lands (the kick must interrupt a RUNNING vCPU).
        let mut s: u64 = 0;
        while s < 50_000_000 {
            s = s.wrapping_add(1);
            core::hint::black_box(s);
        }
        // tgkill(pid, main_tid, SIGUSR1). x86-64 SYS_tgkill = 234.
        // SAFETY: a well-formed tgkill to a live thread.
        unsafe {
            libc::syscall(234, pid as i64, main_tid as i64, libc::SIGUSR1 as i64);
        }
    });

    // The TIGHT, SYSCALL-FREE loop: the ONLY exit is the async kick interrupting
    // this vCPU at an arbitrary ring-3 PC → handler sets DELIVERED → resume here.
    // `black_box` on a volatile counter keeps the loop un-elided.
    let mut i: u64 = 0;
    while !DELIVERED.load(Ordering::Relaxed) {
        i = i.wrapping_add(1);
        core::hint::black_box(i);
        if i > 5_000_000_000 {
            // The kick never interrupted the loop (delivery or latency failure).
            unsafe {
                libc::write(2, b"asyncsig-timeout\n".as_ptr() as *const _, 17);
                libc::_exit(2);
            }
        }
    }

    // Delivered. Sanity-check the siginfo signo, then report success.
    if GOT_SIGNO.load(Ordering::SeqCst) == libc::SIGUSR1 {
        unsafe { libc::write(1, b"asyncsig-ok\n".as_ptr() as *const _, 12) };
        unsafe { libc::_exit(0) };
    } else {
        unsafe { libc::write(2, b"asyncsig-bad-signo\n".as_ptr() as *const _, 19) };
        unsafe { libc::_exit(1) };
    }
}
