//! The lane-neutral guest-fault record.
//!
//! When a translated guest instruction faults (SIGSEGV/SIGBUS/SIGFPE/SIGILL
//! on the host), the host-OS seam's signal shim captures WHERE and WHY into a
//! [`FaultRecord`] embedded in the lane's gateway context, then redirects
//! execution to the lane's signal exit stub so the fault surfaces as a typed
//! gateway exit instead of a host crash. The record speaks only neutral
//! vocabulary — host signal number, `si_code`, faulting address, and the
//! host code-cache RIP (the lane's translator maps that back to a guest VA);
//! nothing ISA-specific.
//!
//! `#[repr(C)]` with asserted offsets: the shim writes this THROUGH A RAW
//! POINTER computed from the gateway context address plus a lane-provided
//! offset — it runs inside a signal handler where the guest's fs base may
//! still be installed, so it cannot touch host TLS, allocate, or panic, and
//! it deliberately does not know the lane context's full layout.

/// One captured guest fault. All fields are written by the host-OS seam's
/// signal shim and read by the lane's run loop after a `Signal` exit.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FaultRecord {
    /// Host signal number (SIGSEGV/SIGBUS/SIGFPE/SIGILL).
    pub signal: i32,
    /// The host `siginfo_t::si_code` (e.g. SEGV_MAPERR vs SEGV_ACCERR) —
    /// needed to synthesize the matching Linux `siginfo`.
    pub code: i32,
    /// The faulting data address (`si_addr`), a guest VA in the native
    /// mapping model.
    pub addr: u64,
    /// The HOST code-cache RIP of the faulting instruction. Not a guest VA:
    /// the lane's block records map it back to one.
    pub host_rip: u64,
}

impl FaultRecord {
    pub const fn new() -> Self {
        Self {
            signal: 0,
            code: 0,
            addr: 0,
            host_rip: 0,
        }
    }
}

// The signal shim addresses these fields by raw offset; drift is a compile
// error here rather than corruption there.
const _: () = assert!(std::mem::offset_of!(FaultRecord, signal) == 0);
const _: () = assert!(std::mem::offset_of!(FaultRecord, code) == 4);
const _: () = assert!(std::mem::offset_of!(FaultRecord, addr) == 8);
const _: () = assert!(std::mem::offset_of!(FaultRecord, host_rip) == 16);
const _: () = assert!(std::mem::size_of::<FaultRecord>() == 24);
