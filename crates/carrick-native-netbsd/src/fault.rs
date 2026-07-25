//! The NetBSD/amd64 guest-fault shim: turns host signals raised by translated
//! guest code into typed gateway exits.
//!
//! Structurally identical to `carrick-native-freebsd::fault`; the ONE porting
//! difference is how a signal handler reads the trap state. NetBSD amd64
//! exposes the register file as an INDEXED ARRAY `mcontext_t.__gregs[_REG_*]`
//! (`/usr/include/amd64/mcontext.h`), not FreeBSD's named `mc_rip`/`mc_r15`
//! struct fields. The Task-0 grounding
//! (docs/superpowers/specs/2026-07-25-netbsd-primitives-grounding.md §2) and a
//! Task-2 grounding-review round-trip probe both confirm the indices this shim
//! uses — `_REG_RIP=21`, `_REG_R15=11`, `_REG_RCX=3` — round-trip a signal
//! handler's reads AND writes on NetBSD 10.1 (the RIP-rewrite→`sigreturn`
//! resume the shim depends on was proven end-to-end, not just readable).
//!
//! When SIGSEGV/SIGBUS/SIGFPE/SIGILL interrupts execution INSIDE the registered
//! code cache, the handler reads the amd64 `mcontext_t`, records the fault
//! (signal, `si_code`, `si_addr`, host RIP) through the gateway context still
//! pinned in `%r15` (`__gregs[_REG_R15]`), and rewrites `__gregs[_REG_RIP]` to
//! the lane's signal exit stub. `sigreturn` then "resumes" at the stub with the
//! guest's registers live, and the gateway's shared exit tail surfaces the
//! fault as a `Signal` exit to the run loop — a guest fault, not a host crash.
//! Faults OUTSIDE the code cache restore the pre-install disposition and
//! return, so the faulting instruction re-fires into the old handler (or the
//! default core dump): host bugs stay loud.
//!
//! ## Handler discipline (load-bearing)
//!
//! The handler can run while the GUEST fs base is installed (the gateway swaps
//! fsbase for the whole translated run), so host TLS is poison here: no
//! allocation, no panic paths, no `std` conveniences — only signal-async reads
//! of process globals and raw stores through the context pointer. The kernel's
//! `sigreturn` restores the interrupted register file (including the fsbase)
//! itself, and the signal exit stub restores the host base from the context
//! afterwards. NetBSD's async-signal-safety and TLS constraints are the same as
//! FreeBSD's, so the same lock-free registered-region lookup applies verbatim.
//!
//! This shim deliberately does not know the gateway context's layout: the lane
//! hands it the signal-stub address and the byte offset of the neutral
//! [`FaultRecord`](carrick_dsr::fault::FaultRecord) inside the context.

use std::io;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU64, Ordering};

use carrick_dsr::fault::FaultRecord;

/// The signals a translated guest instruction can raise synchronously.
const GUEST_FAULT_SIGNALS: [libc::c_int; 4] =
    [libc::SIGSEGV, libc::SIGBUS, libc::SIGFPE, libc::SIGILL];

// The NetBSD amd64 `mcontext_t.__gregs[_REG_*]` indices the handler reads. The
// libc crate re-exports these from the machine headers; naming them locally
// documents the load-bearing set and keeps the handler readable. Confirmed by
// the Task-2 grounding-review round-trip probe (all round-trip exactly).
const REG_RIP: usize = libc::_REG_RIP as usize; // 21
const REG_RSP: usize = libc::_REG_RSP as usize; // 24 (not read here; documented)
const REG_R15: usize = libc::_REG_R15 as usize; // 11 — pinned gateway context
const REG_RCX: usize = libc::_REG_RCX as usize; // 3 — kick RCX-spill recovery
const _: () = assert!(REG_RIP == 21 && REG_RSP == 24 && REG_R15 == 11 && REG_RCX == 3);

// Process-global shim state. Plain atomics — the handler must be able to read
// them without locks, TLS, or allocation. A zero code-cache base means
// "nothing registered": the handler treats every fault as a host fault.
static CODE_BASE: AtomicU64 = AtomicU64::new(0);
static CODE_LEN: AtomicU64 = AtomicU64::new(0);
static SIGNAL_STUB: AtomicU64 = AtomicU64::new(0);
static KICK_STUB: AtomicU64 = AtomicU64::new(0);
static KICK_RESTORE_RCX_OFFSET: AtomicU64 = AtomicU64::new(0);
static KICK_SCRATCH_RCX_OFFSET: AtomicU64 = AtomicU64::new(0);
static FAULT_RECORD_OFFSET: AtomicU64 = AtomicU64::new(0);

// The dispositions replaced at install time, restored when a fault is NOT ours.
// Written once by `install_fault_redirect` before any redirect can fire; the
// handler only reads.
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
/// the byte offset of the [`FaultRecord`] inside the object the pinned context
/// register (`%r15`) points at during translated execution (e.g.
/// `carrick_dsr_x86::gateway::CTX_FAULT_RECORD`).
pub fn install_fault_redirect(signal_stub: u64, fault_record_offset: u32) -> io::Result<()> {
    SIGNAL_STUB.store(signal_stub, Ordering::Release);
    FAULT_RECORD_OFFSET.store(u64::from(fault_record_offset), Ordering::Release);

    for (i, &signal) in GUEST_FAULT_SIGNALS.iter().enumerate() {
        // SAFETY: a well-formed sigaction installation; the handler obeys the
        // module's signal-async discipline.
        unsafe {
            let mut action: libc::sigaction = MaybeUninit::zeroed().assume_init();
            action.sa_sigaction = native_fault_handler as unsafe extern "C" fn(_, _, _) as usize;
            // SA_ONSTACK: honor a sigaltstack when the thread set one up (the
            // runtime's thread loop does — a guest stack overflow cannot run the
            // handler on the very stack that overflowed).
            action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
            libc::sigemptyset(&mut action.sa_mask);
            let mut old: libc::sigaction = MaybeUninit::zeroed().assume_init();
            if libc::sigaction(signal, &action, &mut old) != 0 {
                return Err(io::Error::last_os_error());
            }
            // Preserve the replaced disposition's handler for the not-ours path.
            // (Flags/mask are not round-tripped: the not-ours path reinstalls the
            // handler address with default flags, which is faithful for
            // SIG_DFL/SIG_IGN — the common pre-install states — and close enough
            // for a crash-reporting predecessor.)
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
///
/// `signal` is the lane's chosen kick signal — see
/// [`crate::NATIVE_EXIT_KICK_SIGNAL`] (NetBSD's SIGRTMIN, delivered per-thread
/// with `pthread_kill` by the run loop).
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
        let gregs = &mut (*uc).uc_mcontext.__gregs;
        let base = CODE_BASE.load(Ordering::Acquire);
        let len = CODE_LEN.load(Ordering::Acquire);
        let stub = KICK_STUB.load(Ordering::Acquire);
        let rip = gregs[REG_RIP];
        if base != 0 && stub != 0 && rip >= base && rip < base.saturating_add(len) {
            // A return-cache probe may be interrupted after spilling and then
            // borrowing guest RCX. Repair the kernel's saved register before
            // sigreturn reaches the ordinary kick stub. Volatile accesses are
            // required because emitted code, not Rust, owns these fields while
            // translated execution is live.
            let restore_offset = KICK_RESTORE_RCX_OFFSET.load(Ordering::Acquire);
            let scratch_offset = KICK_SCRATCH_RCX_OFFSET.load(Ordering::Acquire);
            if restore_offset != 0 && scratch_offset != 0 {
                let ctx = gregs[REG_R15];
                let active = (ctx + restore_offset) as *mut u32;
                if active.read_volatile() != 0 {
                    gregs[REG_RCX] = ((ctx + scratch_offset) as *const u64).read_volatile();
                    active.write_volatile(0);
                }
            }
            // Translated execution pins the gateway context in r15. Sigreturn
            // restores all guest registers, then the kick stub captures them
            // through the ordinary common exit path.
            gregs[REG_RIP] = stub;
        }
    }
}

/// The signal handler. Signal-async discipline: NO TLS (the guest fs base may
/// be live), no allocation, no panics — straight-line loads/stores only.
unsafe extern "C" fn native_fault_handler(
    signal: libc::c_int,
    info: *mut libc::siginfo_t,
    ucontext: *mut libc::c_void,
) {
    // SAFETY: the kernel hands a valid ucontext_t/siginfo_t to SA_SIGINFO
    // handlers; all global reads are atomic.
    unsafe {
        let uc = ucontext.cast::<libc::ucontext_t>();
        let gregs = &mut (*uc).uc_mcontext.__gregs;

        let base = CODE_BASE.load(Ordering::Acquire);
        let len = CODE_LEN.load(Ordering::Acquire);
        let stub = SIGNAL_STUB.load(Ordering::Acquire);
        let rip = gregs[REG_RIP];

        let in_translated_code =
            base != 0 && stub != 0 && rip >= base && rip < base.saturating_add(len);
        if in_translated_code {
            // Translated execution pins the gateway context in %r15; the fault
            // record lives at the lane-provided offset inside it.
            let ctx = gregs[REG_R15];
            let record = (ctx + FAULT_RECORD_OFFSET.load(Ordering::Acquire)) as *mut FaultRecord;
            (*record).signal = signal;
            (*record).code = (*info).si_code;
            (*record).addr = (*info).si_addr as u64;
            (*record).host_rip = rip;
            // Land in the signal exit stub on sigreturn; every guest register
            // (and the guest fsbase) is restored by the kernel, and the stub's
            // shared tail captures them into the snapshot.
            gregs[REG_RIP] = stub;
            return;
        }

        // Not ours: put back the replaced disposition and return. The faulting
        // instruction re-executes and the fault re-fires into the old handler /
        // default action (core dump) — host bugs stay loud.
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

    // Serializes tests that mutate the process-global shim state or the SIGSEGV
    // disposition (cargo runs tests concurrently). The fork-based genuine-signal
    // tests mutate only their child's copy of the globals, but they still take
    // the lock so a concurrent synthetic test cannot fork with half-written
    // globals visible to the child.
    static SHIM_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        SHIM_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[repr(C)]
    struct RecoveryContext {
        pad: u64,
        scratch_rcx: u64,
        active: u32,
    }

    /// Synthetic-ucontext proof (mirrors the FreeBSD peer): the kick handler
    /// repairs a live emitter RCX spill via `__gregs[_REG_RCX]` and lands the
    /// interrupted thread on the kick stub via `__gregs[_REG_RIP]`.
    #[test]
    fn kick_repairs_an_active_emitter_rcx_spill() {
        let _guard = lock();
        let mut context = RecoveryContext {
            pad: 0,
            scratch_rcx: 0x1122_3344_5566_7788,
            active: 1,
        };
        let mut ucontext: libc::ucontext_t = unsafe { std::mem::zeroed() };
        ucontext.uc_mcontext.__gregs[REG_RIP] = 0x1010;
        ucontext.uc_mcontext.__gregs[REG_R15] = std::ptr::addr_of_mut!(context) as u64;
        ucontext.uc_mcontext.__gregs[REG_RCX] = 0xDEAD;

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

        assert_eq!(ucontext.uc_mcontext.__gregs[REG_RCX], context.scratch_rcx);
        assert_eq!(ucontext.uc_mcontext.__gregs[REG_RIP], 0x2000);
        assert_eq!(context.active, 0);

        CODE_BASE.store(0, Ordering::Release);
        CODE_LEN.store(0, Ordering::Release);
        KICK_STUB.store(0, Ordering::Release);
        KICK_SCRATCH_RCX_OFFSET.store(0, Ordering::Release);
        KICK_RESTORE_RCX_OFFSET.store(0, Ordering::Release);
    }

    // ---- Genuine raised-SIGSEGV tests (real signals, real fork) --------------

    use carrick_dsr::host::NativeHostJit;

    /// A gateway-context stand-in whose only field the shim touches is a
    /// [`FaultRecord`] at offset 0 (matching `fault_record_offset = 0`). Lives in
    /// a MAP_SHARED page so the fork parent reads what the child's handler wrote.
    #[repr(C)]
    struct FaultCtx {
        record: FaultRecord,
    }

    /// Map one MAP_SHARED|MAP_ANON page so a fork parent and child share it.
    fn map_shared_page() -> *mut libc::c_void {
        // SAFETY: a fresh kernel-chosen shared anonymous page.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED, "map shared ctx page");
        p
    }

    /// A canonical user address that ALWAYS faults on read: a `PROT_NONE` page.
    /// Unlike an `mmap`+`munmap` hole, a `PROT_NONE` page stays mapped — no other
    /// thread's `mmap` can reuse the VA between here and the fault, and no
    /// fall-through can succeed — so the fault is deterministic. Leaked for the
    /// (short) test lifetime; `si_addr` is the returned address.
    fn guarded_fault_addr() -> u64 {
        // SAFETY: a fresh kernel-chosen page with no access; any load faults.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED, "map PROT_NONE probe page");
        p as u64
    }

    /// A genuine SIGSEGV raised INSIDE a registered code region must be REDIRECTED
    /// to the lane's signal stub (not fatal), and the handler must populate the
    /// FaultRecord in the `%r15` context. Proven with a real fork + real fault:
    ///
    /// - The parent writes two tiny machine-code fragments into the dual-map JIT
    ///   region: a faulting entry (`mov r15,ctx; mov rax,bad; mov eax,[rax]`) and
    ///   a signal stub (`exit(77)` — a raw NetBSD syscall, so reaching it proves
    ///   the redirect fired).
    /// - The child installs the redirect, registers the region, and jumps into
    ///   the entry. The fault routes to the stub → the child exits 77 (NOT killed
    ///   by SIGSEGV). The parent then reads the shared FaultRecord.
    #[test]
    fn raised_sigsegv_in_registered_region_routes_not_fatal() {
        let _guard = lock();
        let jit = crate::NetbsdHostJit;
        jit.supported().expect("jit supported");
        let region = jit.map_code_cache(64 * 1024).expect("map code cache");
        let exec = region.exec_base.as_ptr() as u64;
        let write = region
            .write_ptr_for(region.exec_base.as_ptr())
            .expect("write alias");

        let ctx_page = map_shared_page();
        let ctx_addr = ctx_page as u64;
        let bad = guarded_fault_addr();

        // Faulting entry at offset 0.
        let mut code = Vec::new();
        code.extend_from_slice(&[0x49, 0xBF]); // movabs r15, imm64
        code.extend_from_slice(&ctx_addr.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xB8]); // movabs rax, imm64
        code.extend_from_slice(&bad.to_le_bytes());
        code.extend_from_slice(&[0x8B, 0x00]); // mov eax, [rax]  -> #PF here
        // Signal stub at offset 64: exit(77) via raw NetBSD syscall.
        const STUB_OFF: usize = 64;
        assert!(code.len() <= STUB_OFF);
        // Pad with int3 (0xCC): if the load somehow does NOT fault, execution
        // hits int3 and the child dies with SIGTRAP — a fall-through into the
        // stub can never masquerade as a successful redirect.
        code.resize(STUB_OFF, 0xCC);
        code.extend_from_slice(&[0xBF, 77, 0x00, 0x00, 0x00]); // mov edi, 77
        code.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1 (SYS_exit)
        code.extend_from_slice(&[0x0F, 0x05]); // syscall

        // SAFETY: writing translated bytes through the RW alias of a region we own.
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), write, code.len()) };
        jit.flush_icache(region.exec_base.as_ptr(), code.len());

        // SAFETY: the child only touches async-signal-safe work + a raw syscall.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            install_fault_redirect(exec + STUB_OFF as u64, 0).expect("install redirect");
            register_code_region(exec, 64 * 1024);
            // Jump into the faulting entry; control never returns here (it either
            // routes to the exit(77) stub or the process dies).
            let entry: extern "C" fn() = unsafe { std::mem::transmute(exec as usize) };
            entry();
            // Unreachable if the redirect worked; distinct status if it didn't.
            unsafe { libc::_exit(66) };
        }

        let mut status: libc::c_int = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid, "reap child");
        assert!(
            libc::WIFEXITED(status),
            "in-region fault must NOT be fatal (child not signaled): raw status {status:#x}"
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            77,
            "child must reach the signal stub (exit 77), proving the redirect fired"
        );

        // The handler populated the FaultRecord in the shared %r15 context.
        // `FaultRecord` is `Copy`, so read just that field through the pointer
        // (the enclosing `FaultCtx` is not `Copy`).
        let record = unsafe { (*(ctx_page as *const FaultCtx)).record };
        assert_eq!(record.signal, libc::SIGSEGV, "recorded signal");
        assert_eq!(
            record.addr, bad,
            "recorded fault address is the unmapped VA"
        );
        assert!(
            record.host_rip >= exec && record.host_rip < exec + 64 * 1024,
            "recorded host RIP is inside the code cache (0x{:x})",
            record.host_rip
        );

        unsafe {
            libc::munmap(ctx_page, 4096);
            jit.unmap(&region);
        }
    }

    /// A SIGSEGV raised OUTSIDE any registered region must stay FATAL: the shim
    /// restores the prior disposition and the fault re-fires to the default
    /// action. Proven by forking a child that installs the redirect, registers a
    /// region that does NOT cover host code, then dereferences a bad pointer from
    /// ordinary Rust code — the child must die of SIGSEGV, not be swallowed.
    #[test]
    fn raised_sigsegv_outside_region_stays_fatal() {
        let _guard = lock();
        let jit = crate::NetbsdHostJit;
        let region = jit.map_code_cache(64 * 1024).expect("map code cache");
        let exec = region.exec_base.as_ptr() as u64;
        let bad = guarded_fault_addr();

        // SAFETY: child does only async-signal-safe work before it faults/dies.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            // Register the JIT region (far from this Rust code) as the ONLY guest
            // region; a fault in host code is therefore out-of-region.
            install_fault_redirect(exec, 0).expect("install redirect");
            register_code_region(exec, 64 * 1024);
            // Fault from ordinary host code (RIP is in libc/Rust text, not the
            // JIT region): the shim must let it stay fatal.
            let p = bad as *const u8;
            let _ = unsafe { std::ptr::read_volatile(p) };
            // If we somehow returned, exit with a sentinel so the parent's
            // assertion fails loudly rather than silently passing.
            unsafe { libc::_exit(55) };
        }

        let mut status: libc::c_int = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid, "reap child");
        assert!(
            libc::WIFSIGNALED(status),
            "out-of-region fault must stay fatal (child killed by a signal), raw status {status:#x}"
        );
        assert_eq!(
            libc::WTERMSIG(status),
            libc::SIGSEGV,
            "out-of-region fault must terminate with SIGSEGV"
        );

        unsafe { jit.unmap(&region) };
    }
}
