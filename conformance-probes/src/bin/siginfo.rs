//! SI_USER siginfo: a `kill(2)`-delivered signal carries the SENDER's identity.
//! An `SA_SIGINFO` handler must observe `si_code == SI_USER`, `si_pid ==`
//! sender pid, `si_uid ==` sender uid. carrick previously synthesised an
//! all-zero SI_USER siginfo (si_pid == 0), diverging from Linux for the
//! sender-pid field.
//!
//! Scope: this probe locks the `kill(2)` self-target case (the canonical
//! "extend LinuxSiginfo with si_pid/si_uid" deliverable). `tkill`/`tgkill`
//! (which deliver `si_code == SI_TKILL`, used by glibc/musl `raise(3)`) and
//! cross-process sender identity route through the shared thread-signal and
//! host-kill paths and are a documented compat-gap follow-up — not asserted
//! here, so this probe stays a clean line-exact MATCH.
//!
//! Deterministic: every field is asserted as a boolean relationship against
//! the caller's own getpid()/getuid() — never a raw pid/uid.

use conformance_probes::report;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

static SI_CODE: AtomicI32 = AtomicI32::new(i32::MIN);
static SI_PID: AtomicI32 = AtomicI32::new(-1);
static SI_UID: AtomicI32 = AtomicI32::new(-1);
static GOT: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_usr1(_sig: i32, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    if !info.is_null() {
        unsafe {
            SI_CODE.store((*info).si_code, Ordering::SeqCst);
            SI_PID.store((*info).si_pid(), Ordering::SeqCst);
            SI_UID.store((*info).si_uid() as i32, Ordering::SeqCst);
        }
    }
    GOT.fetch_add(1, Ordering::SeqCst);
}

fn main() {
    unsafe {
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = on_usr1 as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGUSR1, &sa, core::ptr::null_mut()) != 0 {
            report!(setup_ok = false);
            return;
        }

        let pid = libc::getpid();
        let uid = libc::getuid();

        // kill(self, SIGUSR1): unblocked + handler installed → delivered before
        // control returns to user space, so the handler has run by here.
        let rc = libc::kill(pid, libc::SIGUSR1);

        report!(
            siginfo_kill_rc_zero = rc == 0,
            siginfo_handler_ran_once = GOT.load(Ordering::SeqCst) == 1,
            siginfo_si_code_is_si_user = SI_CODE.load(Ordering::SeqCst) == 0, // SI_USER
            siginfo_si_pid_is_sender = SI_PID.load(Ordering::SeqCst) == pid,
            siginfo_si_uid_is_sender = SI_UID.load(Ordering::SeqCst) == uid as i32,
        );
    }
}
