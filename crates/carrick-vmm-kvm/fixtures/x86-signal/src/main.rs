//! M3d signal fixture (audit #1): installs a SA_SIGINFO SIGUSR1 handler,
//! `raise()`s the signal, and verifies (a) the handler ran with the correct
//! `siginfo.si_signo`, and (b) execution RESUMED here after `rt_sigreturn`.
//!
//! Cross-compiled static x86_64-unknown-linux-musl (non-PIE ET_EXEC). Run under
//! carrick-kvm it proves the x86 `rt_sigframe` round-trip: build_sigframe writes
//! the frame + enters the handler (RDI=signum, RSI=&siginfo, RDX=&ucontext,
//! RIP=handler), the handler returns through musl's `__restore_rt` →
//! `rt_sigreturn`, and restore_sigframe restores the pre-signal state so `main`
//! continues.
use std::sync::atomic::{AtomicI32, Ordering};

/// Packs the handler's `sig` arg (low 16) and `info->si_signo` (high 16) so the
/// main thread can verify BOTH after `raise` returns.
static GOT: AtomicI32 = AtomicI32::new(0);

extern "C" fn handler(sig: i32, info: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    let info_signo = if info.is_null() {
        -1
    } else {
        // SAFETY: the kernel/carrick supplies a valid siginfo for SA_SIGINFO.
        unsafe { (*info).si_signo }
    };
    GOT.store((sig & 0xffff) | (info_signo << 16), Ordering::SeqCst);
}

fn main() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction =
            handler as extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void) as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        // musl's sigaction wrapper sets SA_RESTORER + sa_restorer = __restore_rt
        // automatically on x86-64 (the kernel mandates a restorer there).
        if libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut()) != 0 {
            libc::write(2, b"sigaction-failed\n".as_ptr() as *const _, 17);
            std::process::exit(2);
        }
        libc::raise(libc::SIGUSR1);
    }
    // Reached only if the handler ran AND rt_sigreturn resumed us here.
    let got = GOT.load(Ordering::SeqCst);
    let sig = got & 0xffff;
    let info_signo = (got >> 16) & 0xffff;
    if sig == libc::SIGUSR1 && info_signo == libc::SIGUSR1 {
        unsafe { libc::write(1, b"signal-ok\n".as_ptr() as *const _, 10) };
    } else {
        unsafe { libc::write(2, b"signal-bad\n".as_ptr() as *const _, 11) };
        std::process::exit(1);
    }
}
