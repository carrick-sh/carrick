//! SP3.2 fixture: proves the interrupted XMM state survives a signal whose
//! handler clobbers XMM. Seeds xmm0 = a known sentinel via inline asm, installs
//! a handler that overwrites xmm0 with a different value, `raise`s the signal,
//! and after rt_sigreturn reads xmm0 back and asserts it equals the sentinel.
//! RED under the Option-C baseline (FP not round-tripped → the clobber leaks
//! back), GREEN once carrick-bhyve round-trips FP via the guest-side
//! FXSAVE/FXRSTOR stub. Static x86_64-unknown-linux-musl (non-PIE ET_EXEC).
use std::arch::asm;
use std::sync::atomic::{AtomicI32, Ordering};

static RAN: AtomicI32 = AtomicI32::new(0);

extern "C" fn handler(_sig: i32, _info: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    // Clobber xmm0 with a value distinct from the main thread's sentinel. If the
    // signal frame did NOT save+restore the interrupted xmm0, this clobber will
    // leak back to `main` (fp-bad). When FP round-trips, rt_sigreturn restores
    // the pre-signal xmm0 and `main` observes the sentinel (fp-ok).
    let clobber: u64 = 0xDEAD_BEEF_DEAD_BEEF;
    // SAFETY: writing xmm0 inside the handler; declaring `out("xmm0") _` tells
    // the compiler this asm clobbers xmm0 (it does, deliberately).
    unsafe { asm!("movq xmm0, {v}", v = in(reg) clobber, out("xmm0") _) };
    RAN.store(1, Ordering::SeqCst);
}

fn main() {
    let sentinel: u64 = 0x0123_4567_89AB_CDEF;
    let observed: u64;
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction =
            handler as extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void) as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut()) != 0 {
            libc::write(2, b"sigaction-failed\n".as_ptr() as *const _, 17);
            std::process::exit(2);
        }

        // We CANNOT keep xmm0 live across a Rust `libc::raise` call: the SysV
        // call ABI lets the callee clobber xmm0 (it is caller-saved), so the
        // compiler would not preserve our seeded value across the call. Instead
        // do it all in ONE asm block: seed xmm0 = sentinel, deliver the signal
        // via a raw `kill(getpid, SIGUSR1)` syscall (which the SysV ABI does NOT
        // let clobber xmm regs — the kernel preserves all but rax/rcx/r11), then
        // read xmm0 back AFTER the handler ran. A self-targeted signal is
        // delivered synchronously before the kill syscall returns, so the
        // handler (the xmm0 clobber) runs between the `syscall` and the readback.
        //
        // x86-64 syscall numbers: kill = 62. SIGUSR1 (Linux signum) = 10. We do
        // NOT declare xmm0 as a clobber: keeping it out of the clobber list is
        // what pins the value live across the whole block (the test's invariant).
        let pid = libc::getpid();
        asm!(
            "movq xmm0, {sent}",      // seed xmm0 = sentinel
            "mov rax, 62",            // __NR_kill (x86_64) = 62
            "mov rdi, {pid:r}",       // arg0 = pid (kill target = self)
            "mov rsi, 10",            // arg1 = SIGUSR1 (Linux signum 10)
            "syscall",                // kill(pid, SIGUSR1) — delivered synchronously
            "movq {obs}, xmm0",       // read xmm0 back AFTER the handler ran
            sent = in(reg) sentinel,
            pid = in(reg) pid,
            obs = out(reg) observed,
            out("rax") _,
            out("rcx") _,
            out("r11") _,
            out("rdi") _,
            out("rsi") _,
        );
    }
    if RAN.load(Ordering::SeqCst) == 1 && observed == sentinel {
        unsafe { libc::write(1, b"fp-ok\n".as_ptr() as *const _, 6) };
    } else {
        unsafe { libc::write(2, b"fp-bad\n".as_ptr() as *const _, 6) };
        std::process::exit(1);
    }
}
