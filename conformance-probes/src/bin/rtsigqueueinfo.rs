//! rt_sigqueueinfo(2): queue a real-time signal with a caller-supplied
//! siginfo whose `si_value` payload is delivered to the SA_SIGINFO handler.
//! Stands in for LTP `rt_sigqueueinfo01`/`sigqueue01` and the rt-signal
//! payload-propagation class.
//!
//! Two invariants encoded as separate report lines so a partial fix shows up
//! distinct from a total miss:
//!
//!   1. **delivery**: a SIGRTMIN queued via `rt_sigqueueinfo(getpid(),
//!      SIGRTMIN, &info)` runs the registered handler exactly once.
//!
//!   2. **payload propagation**: the `si_value.sival_int` field the caller
//!      put in the supplied siginfo arrives in the handler's `siginfo_t`.
//!      This is the carrick KNOWN gap (signal.rs note: "caller-supplied
//!      siginfo is not yet propagated to the guest handler; carrick
//!      synthesizes it"). Exposing this as a deterministic `false` on
//!      carrick / `true` on Linux is the WHOLE POINT of the probe.

use conformance_probes::{block_signal, errno, report, unblock_signal};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

const PAYLOAD: i32 = 0x00CA_FE42;
static HITS: AtomicU32 = AtomicU32::new(0);
static OBSERVED_VALUE: AtomicI32 = AtomicI32::new(0);
static OBSERVED_SIGNO: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_rt(_sig: i32, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    HITS.fetch_add(1, Ordering::SeqCst);
    if !info.is_null() {
        unsafe {
            OBSERVED_SIGNO.store((*info).si_signo, Ordering::SeqCst);
            let sival = siginfo_sival_int(&*info);
            OBSERVED_VALUE.store(sival, Ordering::SeqCst);
        }
    }
}

/// Extract `si_value.sival_int` from a `siginfo_t` by reading the raw uapi
/// byte layout. The Linux kernel writes si_value at a well-defined offset
/// inside `_sifields._rt`. After the leading `si_signo` (i32), `si_errno`
/// (i32), `si_code` (i32), `__pad0` (i32, present on 64-bit), and
/// `si_pid` + `si_uid` (two i32) come the rt-specific fields — putting
/// `si_value.sival_int` at byte offset 0x18 on aarch64. musl's `siginfo_t`
/// field names vary across versions, so the offset is the stable contract.
unsafe fn siginfo_sival_int(info: &libc::siginfo_t) -> i32 {
    let base = info as *const libc::siginfo_t as *const u8;
    let sival_int_ptr = base.add(0x18) as *const i32;
    core::ptr::read(sival_int_ptr)
}

unsafe fn install_sigaction_siginfo(sig: i32) -> bool {
    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = on_rt as *const () as usize;
    sa.sa_flags = libc::SA_SIGINFO;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(sig, &sa, std::ptr::null_mut()) == 0
}

fn main() {
    unsafe {
        let sig = libc::SIGRTMIN();
        let install_ok = install_sigaction_siginfo(sig);
        if !install_ok {
            report!(install_ok = false);
            return;
        }

        // Block while queuing so the rt_sigqueueinfo returns BEFORE the
        // handler runs — eliminates handler-vs-syscall race in the report.
        let _ = block_signal(sig);

        // Build a SI_QUEUE-style siginfo with the desired payload. The kernel
        // re-stamps si_signo to `sig` and si_code to SI_QUEUE for the target.
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let info_bytes = &mut info as *mut libc::siginfo_t as *mut u8;
        core::ptr::write(info_bytes.add(0) as *mut i32, sig); // si_signo
        core::ptr::write(info_bytes.add(8) as *mut i32, libc::SI_QUEUE); // si_code
        core::ptr::write(info_bytes.add(0x18) as *mut i32, PAYLOAD); // sival_int

        let pid = libc::getpid();
        let rc = libc::syscall(
            libc::SYS_rt_sigqueueinfo,
            pid as i64,
            sig as i64,
            &info as *const _,
        ) as i32;
        let queue_errno = if rc < 0 { errno() } else { 0 };

        // Unblock to let the handler run, then poll until it has.
        let _ = unblock_signal(sig);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while HITS.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
            std::hint::spin_loop();
        }

        let delivered = HITS.load(Ordering::SeqCst) >= 1;
        let signo_matches = OBSERVED_SIGNO.load(Ordering::SeqCst) == sig;
        let payload_propagated = OBSERVED_VALUE.load(Ordering::SeqCst) == PAYLOAD;

        report!(
            rt_sigqueueinfo_rc_ok = rc == 0,
            rt_sigqueueinfo_errno = queue_errno,
            handler_delivered = delivered,
            handler_signo_matches = signo_matches,
            handler_sival_int_propagated = payload_propagated,
        );
    }
}
