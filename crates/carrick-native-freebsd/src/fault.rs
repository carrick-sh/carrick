//! The FreeBSD/amd64 guest-fault shim: turns host signals raised by
//! translated guest code into typed gateway exits.
//!
//! When SIGSEGV/SIGBUS/SIGFPE/SIGILL interrupts execution INSIDE the
//! registered code cache, the handler reads the amd64 `mcontext_t`, records
//! the fault (signal, `si_code`, `si_addr`, host RIP) through the gateway
//! context still pinned in `mc_r15`, and rewrites `mc_rip` to the lane's
//! signal exit stub. `sigreturn` then "resumes" at the stub with the guest's
//! registers live, and the gateway's shared exit tail surfaces the fault as
//! a `Signal` exit to the run loop — a guest fault, not a host crash.
//! Faults OUTSIDE the code cache restore the pre-install disposition and
//! return, so the faulting instruction re-fires into the old handler (or the
//! default core dump): host bugs stay loud.
//!
//! ## Handler discipline (load-bearing)
//!
//! The handler can run while the GUEST fs base is installed (the gateway
//! swaps fsbase for the whole translated run), so host TLS is poison here:
//! no allocation, no panic paths, no `std` conveniences — only signal-async
//! reads of process globals and raw stores through the context pointer. The
//! kernel's `sigreturn` restores the interrupted `mc_fsbase` itself, and the
//! signal exit stub restores the host base from the context afterwards.
//!
//! This shim deliberately does not know the gateway context's layout: the
//! lane hands it the signal-stub address and the byte offset of the neutral
//! [`FaultRecord`](carrick_dsr::fault::FaultRecord) inside the context.

use std::io;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU64, Ordering};

use carrick_dsr::fault::FaultRecord;

/// The signals a translated guest instruction can raise synchronously.
const GUEST_FAULT_SIGNALS: [libc::c_int; 4] =
    [libc::SIGSEGV, libc::SIGBUS, libc::SIGFPE, libc::SIGILL];

// Process-global shim state. Plain atomics — the handler must be able to
// read them without locks, TLS, or allocation. A zero code-cache base means
// "nothing registered": the handler treats every fault as a host fault.
static CODE_BASE: AtomicU64 = AtomicU64::new(0);
static CODE_LEN: AtomicU64 = AtomicU64::new(0);
static SIGNAL_STUB: AtomicU64 = AtomicU64::new(0);
static KICK_STUB: AtomicU64 = AtomicU64::new(0);
static KICK_RESTORE_RCX_OFFSET: AtomicU64 = AtomicU64::new(0);
static KICK_SCRATCH_RCX_OFFSET: AtomicU64 = AtomicU64::new(0);
static FAULT_RECORD_OFFSET: AtomicU64 = AtomicU64::new(0);

// The dispositions replaced at install time, restored when a fault is NOT
// ours. Written once by `install_fault_redirect` before any redirect can
// fire; the handler only reads.
static OLD_ACTIONS: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

fn signal_index(signal: libc::c_int) -> Option<usize> {
    GUEST_FAULT_SIGNALS.iter().position(|&s| s == signal)
}

/// Register the dual-map JIT's EXEC alias as the translated-code region. A
/// fault whose RIP lands inside `[exec_base, exec_base + len)` is a guest
/// fault; everything else stays a host fault. One region per process (the
/// runtime owns one code cache); re-registering replaces the previous one.
pub fn register_code_region(exec_base: u64, len: u64) {
    // Order matters for a concurrent fault: publish the length first so a
    // nonzero base never pairs with a stale zero length.
    CODE_LEN.store(len, Ordering::Release);
    CODE_BASE.store(exec_base, Ordering::Release);
}

/// Remove the registered region (e.g. when the cache unmaps in tests). Any
/// later fault is treated as a host fault.
pub fn unregister_code_region() {
    CODE_BASE.store(0, Ordering::Release);
    CODE_LEN.store(0, Ordering::Release);
}

/// Install the guest-fault redirect for SIGSEGV/SIGBUS/SIGFPE/SIGILL.
///
/// `signal_stub` is the lane's signal exit stub (e.g.
/// `carrick_dsr_x86::gateway::signal_stub_addr()`); `fault_record_offset` is
/// the byte offset of the [`FaultRecord`] inside the object the pinned
/// context register (`%r15`) points at during translated execution (e.g.
/// `carrick_dsr_x86::gateway::CTX_FAULT_RECORD`).
pub fn install_fault_redirect(signal_stub: u64, fault_record_offset: u32) -> io::Result<()> {
    SIGNAL_STUB.store(signal_stub, Ordering::Release);
    FAULT_RECORD_OFFSET.store(u64::from(fault_record_offset), Ordering::Release);

    for (i, &signal) in GUEST_FAULT_SIGNALS.iter().enumerate() {
        // SAFETY: a well-formed sigaction installation; the handler obeys
        // the module's signal-async discipline.
        unsafe {
            let mut action: libc::sigaction = MaybeUninit::zeroed().assume_init();
            action.sa_sigaction = native_fault_handler as unsafe extern "C" fn(_, _, _) as usize;
            // SA_ONSTACK: honor a sigaltstack when the thread set one up (the
            // runtime's thread loop does — a guest stack overflow cannot run
            // the handler on the very stack that overflowed).
            action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
            libc::sigemptyset(&mut action.sa_mask);
            let mut old: libc::sigaction = MaybeUninit::zeroed().assume_init();
            if libc::sigaction(signal, &action, &mut old) != 0 {
                return Err(io::Error::last_os_error());
            }
            // Preserve the replaced disposition's handler for the not-ours
            // path. (Flags/mask are not round-tripped: the not-ours path
            // reinstalls the handler address with default flags, which is
            // faithful for SIG_DFL/SIG_IGN — the common pre-install states —
            // and close enough for a crash-reporting predecessor.)
            OLD_ACTIONS[i].store(old.sa_sigaction as u64, Ordering::Release);
        }
    }
    Ok(())
}

/// Signal-safe description of one transient guest-RCX spill used by emitted
/// control-flow probes. Both offsets are relative to the context pinned in
/// `%r15`; zero disables recovery.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KickRcxRecovery {
    pub active_offset: u32,
    pub scratch_offset: u32,
}

/// Install a non-restarting asynchronous kick. Outside translated code the
/// empty handler merely interrupts the current host syscall. Inside the JIT
/// cache it rewrites RIP to `kick_stub`, giving the runtime the same typed
/// boundary that a VMM backend gets when its vCPU run call is kicked.
pub fn install_kick_redirect(
    signal: libc::c_int,
    kick_stub: u64,
    rcx_recovery: KickRcxRecovery,
) -> io::Result<()> {
    KICK_STUB.store(kick_stub, Ordering::Release);
    KICK_SCRATCH_RCX_OFFSET.store(u64::from(rcx_recovery.scratch_offset), Ordering::Release);
    KICK_RESTORE_RCX_OFFSET.store(u64::from(rcx_recovery.active_offset), Ordering::Release);
    // SAFETY: well-formed SA_SIGINFO action; the handler is async-signal-safe.
    unsafe {
        let mut action: libc::sigaction = MaybeUninit::zeroed().assume_init();
        action.sa_sigaction = native_kick_handler as unsafe extern "C" fn(_, _, _) as usize;
        action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Kick handler: no allocation, TLS, locks, or libc calls. A signal outside
/// translated code returns normally, causing a blocking host syscall to report
/// EINTR because the action intentionally omits SA_RESTART.
unsafe extern "C" fn native_kick_handler(
    _signal: libc::c_int,
    _info: *mut libc::siginfo_t,
    ucontext: *mut libc::c_void,
) {
    // SAFETY: the kernel supplies a valid ucontext to SA_SIGINFO handlers.
    unsafe {
        let uc = ucontext.cast::<libc::ucontext_t>();
        let mc = &mut (*uc).uc_mcontext;
        let base = CODE_BASE.load(Ordering::Acquire);
        let len = CODE_LEN.load(Ordering::Acquire);
        let stub = KICK_STUB.load(Ordering::Acquire);
        let rip = mc.mc_rip as u64;
        if base != 0 && stub != 0 && rip >= base && rip < base.saturating_add(len) {
            // A return-cache probe may be interrupted after spilling and then
            // borrowing guest RCX. Repair the kernel's saved register before
            // sigreturn reaches the ordinary kick stub. Volatile accesses are
            // required because emitted code, not Rust, owns these fields while
            // translated execution is live.
            let restore_offset = KICK_RESTORE_RCX_OFFSET.load(Ordering::Acquire);
            let scratch_offset = KICK_SCRATCH_RCX_OFFSET.load(Ordering::Acquire);
            if restore_offset != 0 && scratch_offset != 0 {
                let ctx = mc.mc_r15 as u64;
                let active = (ctx + restore_offset) as *mut u32;
                if active.read_volatile() != 0 {
                    mc.mc_rcx =
                        ((ctx + scratch_offset) as *const u64).read_volatile() as libc::register_t;
                    active.write_volatile(0);
                }
            }
            // Translated execution pins the gateway context in r15. Sigreturn
            // restores all guest registers, then the kick stub captures them
            // through the ordinary common exit path.
            mc.mc_rip = stub as libc::register_t;
        }
    }
}

/// The signal handler. Signal-async discipline: NO TLS (the guest fs base
/// may be live), no allocation, no panics — straight-line loads/stores only.
unsafe extern "C" fn native_fault_handler(
    signal: libc::c_int,
    info: *mut libc::siginfo_t,
    ucontext: *mut libc::c_void,
) {
    // SAFETY: the kernel hands a valid ucontext_t/siginfo_t to SA_SIGINFO
    // handlers; all global reads are atomic.
    unsafe {
        let uc = ucontext.cast::<libc::ucontext_t>();
        let mc = &mut (*uc).uc_mcontext;

        let base = CODE_BASE.load(Ordering::Acquire);
        let len = CODE_LEN.load(Ordering::Acquire);
        let stub = SIGNAL_STUB.load(Ordering::Acquire);
        let rip = mc.mc_rip as u64;

        let in_translated_code =
            base != 0 && stub != 0 && rip >= base && rip < base.saturating_add(len);
        if in_translated_code {
            // Translated execution pins the gateway context in %r15; the
            // fault record lives at the lane-provided offset inside it.
            let ctx = mc.mc_r15 as u64;
            let record = (ctx + FAULT_RECORD_OFFSET.load(Ordering::Acquire)) as *mut FaultRecord;
            (*record).signal = signal;
            (*record).code = (*info).si_code;
            (*record).addr = (*info).si_addr as u64;
            (*record).host_rip = rip;
            // Land in the signal exit stub on sigreturn; every guest
            // register (and the guest fsbase) is restored by the kernel, and
            // the stub's shared tail captures them into the snapshot.
            mc.mc_rip = stub as libc::register_t;
            return;
        }

        // Not ours: put back the replaced disposition and return. The
        // faulting instruction re-executes and the fault re-fires into the
        // old handler / default action (core dump) — host bugs stay loud.
        let old_handler = signal_index(signal)
            .map(|i| OLD_ACTIONS[i].load(Ordering::Acquire))
            .unwrap_or(libc::SIG_DFL as u64);
        let mut action: libc::sigaction = MaybeUninit::zeroed().assume_init();
        action.sa_sigaction = old_handler as usize;
        action.sa_flags =
            if old_handler == libc::SIG_DFL as u64 || old_handler == libc::SIG_IGN as u64 {
                0
            } else {
                libc::SA_SIGINFO
            };
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(signal, &action, std::ptr::null_mut());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct RecoveryContext {
        pad: u64,
        scratch_rcx: u64,
        active: u32,
    }

    #[test]
    fn kick_repairs_an_active_emitter_rcx_spill() {
        let mut context = RecoveryContext {
            pad: 0,
            scratch_rcx: 0x1122_3344_5566_7788,
            active: 1,
        };
        let mut ucontext: libc::ucontext_t = unsafe { std::mem::zeroed() };
        ucontext.uc_mcontext.mc_rip = 0x1010;
        ucontext.uc_mcontext.mc_r15 = std::ptr::addr_of_mut!(context) as libc::register_t;
        ucontext.uc_mcontext.mc_rcx = 0xDEAD;

        CODE_LEN.store(0x100, Ordering::Release);
        CODE_BASE.store(0x1000, Ordering::Release);
        KICK_STUB.store(0x2000, Ordering::Release);
        KICK_SCRATCH_RCX_OFFSET.store(
            std::mem::offset_of!(RecoveryContext, scratch_rcx) as u64,
            Ordering::Release,
        );
        KICK_RESTORE_RCX_OFFSET.store(
            std::mem::offset_of!(RecoveryContext, active) as u64,
            Ordering::Release,
        );

        unsafe {
            native_kick_handler(
                0,
                std::ptr::null_mut(),
                std::ptr::addr_of_mut!(ucontext).cast(),
            )
        };

        assert_eq!(ucontext.uc_mcontext.mc_rcx as u64, context.scratch_rcx);
        assert_eq!(ucontext.uc_mcontext.mc_rip as u64, 0x2000);
        assert_eq!(context.active, 0);

        CODE_BASE.store(0, Ordering::Release);
        CODE_LEN.store(0, Ordering::Release);
        KICK_STUB.store(0, Ordering::Release);
        KICK_SCRATCH_RCX_OFFSET.store(0, Ordering::Release);
        KICK_RESTORE_RCX_OFFSET.store(0, Ordering::Release);
    }
}
