//! Linux force_sigsegv: when a signal's frame cannot be written to the target
//! user stack, the kernel terminates the whole thread-group by SIGSEGV — it does
//! NOT crash the kernel and does NOT silently drop the signal. Here the handler
//! is SA_ONSTACK with an alternate signal stack that is PROT_NONE, so the frame
//! write necessarily fails.
//!
//! carrick previously turned an inject failure into a fatal host error (main
//! thread) or a silently-vanished sibling (deadlocking peers). M1b routes it to
//! a term_signal=SIGSEGV termination. Crash-class: the dangerous op runs in a
//! forked child; the parent reports how the child died.
//!
//! Linux + fixed carrick: child WIFSIGNALED with WTERMSIG == SIGSEGV.

use conformance_probes::{reap, report};

extern "C" fn on_usr1(_: i32) {}

unsafe fn deliver_on_bad_altstack() -> ! {
    // A PROT_NONE region used as the alternate signal stack: the kernel cannot
    // write the signal frame there, so delivery must force SIGSEGV.
    let size: usize = 65536;
    let page = libc::mmap(
        core::ptr::null_mut(),
        size,
        libc::PROT_NONE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if page == libc::MAP_FAILED {
        libc::_exit(90);
    }
    let ss = libc::stack_t {
        ss_sp: page,
        ss_flags: 0,
        ss_size: size,
    };
    if libc::sigaltstack(&ss, core::ptr::null_mut()) != 0 {
        libc::_exit(91);
    }
    let mut sa: libc::sigaction = core::mem::zeroed();
    sa.sa_sigaction = on_usr1 as *const () as usize;
    sa.sa_flags = libc::SA_ONSTACK;
    libc::sigemptyset(&mut sa.sa_mask);
    if libc::sigaction(libc::SIGUSR1, &sa, core::ptr::null_mut()) != 0 {
        libc::_exit(92);
    }
    libc::raise(libc::SIGUSR1);
    // Reached only if the frame was (wrongly) delivered onto a PROT_NONE stack.
    libc::_exit(0);
}

fn main() {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            deliver_on_bad_altstack();
        }
        let (_, status) = reap(pid);
        report!(
            child_killed_by_signal = libc::WIFSIGNALED(status),
            child_wtermsig_sigsegv =
                libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSEGV,
        );
    }
}
