//! SP4.4 fixture: perform a null store with no installed SIGSEGV handler.
//! Carrick should apply Linux's default SIGSEGV action, observed by the harness
//! as exit code 128 + SIGSEGV = 139.

fn main() {
    unsafe {
        // Exercise the no-handler/default-action path through the same
        // rt_sigaction prelude as the handled fixture, but leave SIGSEGV at
        // SIG_DFL. A fault before any rt_sigaction currently hits a separate
        // bhyve hidden-state issue.
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut()) != 0 {
            libc::write(2, b"sigaction-failed\n".as_ptr().cast(), 17);
            std::process::exit(2);
        }
        core::arch::asm!(
            "mov qword ptr [0], rax",
            in("rax") 1_u64,
            options(nostack, preserves_flags)
        );
        libc::write(2, b"no-sigsegv\n".as_ptr().cast(), 11);
        std::process::exit(3);
    }
}
