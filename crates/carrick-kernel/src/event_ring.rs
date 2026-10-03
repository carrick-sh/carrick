//! Lock-free, low-perturbation in-memory event ring for diagnosing timing-
//! sensitive (Heisenbug) deadlocks — specifically the nested-forkserver
//! `test_parent_process` hang where a server forked+exec'd from a forkserver
//! worker fails to function, and ANY `eprintln`/dtrace instrumentation perturbs
//! the race enough to change the manifestation (see
//! `docs/archive/forkserver-parent-process-deadlock.md`).
//!
//! Recording is hot-path-cheap and ALWAYS ON: an atomic reservation plus one
//! odd/even slot-generation claim, two payload stores, and one release publish
//! into a fixed array — no lock, no syscall, and no allocation.
//! It is unconditional on purpose, so the ring is present in a core file or a
//! live process from ANY run with nothing pre-armed — an intermittent Heisenbug
//! you can't predict still leaves its history behind. Read it post-mortem with
//! the lldb plugin: `lldb -c <core> target/release/carrick` then
//! `carrick eventring` (works on a live `lldb -p <pid>` too).
//!
//! There are two fixed rings with the same slot protocol. [`is_high_rate`]
//! kinds (per-dispatch scheduler, per-poll `EP*`/eventfd/futex) go to the
//! high-rate ring, read with `carrick eventring --high-rate`; every other kind
//! goes to the lifecycle ring. A spinning guest therefore cannot evict fork,
//! exec, fd, wait, fault or grant history (the `gbhang4` capture of a hung
//! `go build` held 8192 scheduler and `EPWAIT` records and nothing else).
//!
//! Only the perturbing, autonomous FILE dump is opt-in: build with the
//! `event-ring-dump` feature and set `CARRICK_EVENTRING` to a directory; a 1 Hz
//! watchdog thread (OFF the vCPU thread, so guest syscall timing is intact)
//! writes `<dir>/carrick-ring.<pid>`. Without the feature, only the in-memory
//! ring (above) exists — read it from a core or a live process via lldb.
//!
//! The ring is per HOST process. Legacy native/VMM execution normally places
//! one guest process in it; HvPatch deliberately multiplexes many Linux guest
//! processes in one host process, so its lifecycle/wait records carry explicit
//! guest PID/TID correlation. On a legacy host fork the child inherits the
//! parent's ring memory but only the forking thread survives, so
//! [`reinit_after_fork`] resets the index + re-arms the watchdog for the child.

#[cfg(feature = "event-ring-dump")]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

const N: usize = 8192;

// Generation is odd while a writer owns the slot and even only after both
// payload cells are complete. It also encodes the global logical index, so a
// delayed writer cannot publish over a newer wrap of the same physical slot.
#[repr(C)]
struct Slot {
    generation: AtomicU64,
    lo: AtomicU64,
    hi: AtomicU64,
}

#[allow(clippy::declare_interior_mutable_const)]
const EMPTY: Slot = Slot {
    generation: AtomicU64::new(0),
    lo: AtomicU64::new(0),
    hi: AtomicU64::new(0),
};

/// The lifecycle ring: fork/exec/fd/wait/signal/fault/grant history.
static RING: [Slot; N] = [EMPTY; N];
static IDX: AtomicU64 = AtomicU64::new(0);
/// The high-rate ring: per-dispatch scheduler and per-poll `EP*`/eventfd/futex
/// records (see [`is_high_rate`]). A spinning guest fills THIS ring, so a
/// scheduler spin can no longer evict the lifecycle history above. Same
/// geometry and slot protocol, so one reader serves both.
static SCHED_RING: [Slot; N] = [EMPTY; N];
static SCHED_IDX: AtomicU64 = AtomicU64::new(0);
static WATCHDOG: AtomicBool = AtomicBool::new(false);
static NEXT_HVPWAIT_ID: AtomicU32 = AtomicU32::new(1);

// Alias coordinator lifecycle: a:b is the full coordinator address, c is
// guest TID (0 when no guest identity is available). Holder state additionally
// records the acquiring Rust host thread ID for offline core inspection.
pub const ALIAS_MUTATION: u8 = 90;
pub const ALIAS_DISPATCH: u8 = 91;
pub const ALIAS_INSTALL: u8 = 92;
pub const ALIAS_END: u8 = 93;

// Event kinds.
pub const BIND: u8 = 1;
pub const LISTEN: u8 = 2;
pub const CONNECT: u8 = 3;
pub const ACCEPT: u8 = 4;
pub const EPADD: u8 = 5;
pub const EPWAIT: u8 = 6;
pub const FORK: u8 = 7;
pub const EXEC: u8 = 8;
pub const FDOPEN: u8 = 9;
pub const FDCLOSE: u8 = 10;
pub const ACCEPTERR: u8 = 11;
pub const EPWFD: u8 = 12;
pub const EPMASK: u8 = 13;
pub const EPMASKFD: u8 = 14;
pub const EPEDGE: u8 = 15;
pub const DSRFAULT_PC: u8 = 16;
pub const DSRFAULT_ADDR: u8 = 17;
pub const DSRFAULT_SP: u8 = 18;
pub const DSRFAULT_LR: u8 = 19;
/// A socket-namespace record was refused for claiming to belong to a different
/// key or a different instance. The guest-facing paths map that to
/// `ECONNREFUSED` and say nothing, so this ring entry is the only per-occurrence
/// record of a cross-instance mis-publication.
pub const NSREJECT: u8 = 20;
/// Eventfd counter transition after a successful guest write. `a` is the host
/// readiness-pipe read fd; `b` and `c` are the low 32 bits before and after.
pub const EFDWRITE: u8 = 21;
/// Eventfd counter transition after a successful guest read/copyout.
pub const EFDREAD: u8 = 22;
/// A process-private futex wait is about to park. `a:b` is the full guest VA;
/// `c` is the guest tid.
pub const FUTEXWAIT: u8 = 23;
/// A process-private FUTEX_WAKE completed. `a:b` is the full guest VA; `c` is
/// the number of waiters actually removed from the parking-lot queue.
pub const FUTEXWAKE: u8 = 24;
/// A process-private futex wait returned. `a:b` is the full guest VA; `c` is
/// 0=woken, 1=interrupted, 2=timed out.
pub const FUTEXEND: u8 = 25;
/// HvPatch process-thread teardown checkpoint. `a` is guest PID, `b` guest
/// TID, and `c` is the cleanup phase decoded by the LLDB plugin.
pub const HVPTHREAD: u8 = 26;
/// HvPatch blocking-fd wait lifecycle. `a` is guest PID, `b` guest TID, and
/// `c` packs wait class in bits 0..7, phase in 8..15, and fd count in 16..31.
pub const HVPWAIT: u8 = 27;
/// Correlation record for an HvPatch wait. `a` is guest PID, `b` guest TID,
/// and `c` packs a 24-bit wait ID plus 4-bit class and phase fields.
pub const HVPWAITX: u8 = 28;
/// Full-width guest resume PC at an HvPatch wait begin; `c` is the wait ID.
pub const HVPWAIT_PC: u8 = 29;
/// Full-width guest stack pointer at an HvPatch wait begin; `c` is the wait ID.
pub const HVPWAIT_SP: u8 = 30;
/// Full-width guest link register at an HvPatch wait begin; `c` is the wait ID.
pub const HVPWAIT_LR: u8 = 31;
/// Primary host fd/events for an HvPatch wait; `a` is wait ID, `b` fd, `c`
/// poll events. The existing HVPWAIT record retains the total fd count.
pub const HVPWAITFD: u8 = 32;
/// HvPatch process-exit publication is about to enter the shared process table.
pub const HVPPEXIT_BEGIN: u8 = 33;
/// HvPatch process-exit publication completed and waiters were notified.
pub const HVPPEXIT_END: u8 = 34;
/// Target guest process for a correlated HvPatch child wait. `a` is the wait
/// ID and `b` is the guest PID (`-1` means any child).
pub const HVPWAIT_TARGET: u8 = 35;
/// One guest-fd event actually copied into an epoll_wait result. `a` is the
/// guest epoll fd, `b` the originating guest fd, and `c` the returned mask.
/// This is deliberately distinct from [`EPEDGE`]: a multiplexer edge can be
/// observed but deferred by `maxevents`, while only EPREADY proves delivery to
/// the guest runtime.
pub const EPREADY: u8 = 36;
/// A drained multiplexer edge rejected by the guest-fd generation guard. `a`
/// is the guest fd, `b` the generation carried by the host event, and `c` the
/// live generation (`-1` when the guest fd no longer has an interest entry).
pub const EPSTALE: u8 = 37;
/// Process-qualified fd close companion. `a` is guest PID, `b` guest TID, and
/// `c` the guest fd removed from that process's private table. This record is
/// intentionally separate from [`FDCLOSE`], which preserves the historical
/// guest-fd/host-fd view used by socket and epoll investigations.
pub const FDOWNER: u8 = 38;
/// Logical open-description ownership at close. `a` is guest PID, `b` guest
/// fd, and `c` the logical reference count immediately before removal. It lets
/// a core/live LLDB session find the process clone that retained a pipe writer.
pub const FDREF: u8 = 39;
/// A file write whose payload begins at an `ar` archive boundary. `a` is the
/// host fd, `b` the file offset the write starts at (`-1` when the fd is not
/// seekable), and `c` the payload length.
///
/// Deliberately narrow. An `ar` archive is magic (`!<arch>\n`) followed by
/// member headers, so a payload starting with a member header is correct at a
/// nonzero offset and CORRUPT at offset 0 — `b == 0` with a member-header
/// payload is the defect, recorded at the moment it happens. The predicate is
/// a byte compare on the payload head, and only a match pays the `lseek` that
/// resolves the offset, so the hot write path is untouched. That cost matters:
/// paying it per write via the `trace-io` log perturbed the intermittent Go
/// build-cache corruption out of existence (0 of 4 reproductions against a
/// 3-in-4 base rate), which is why this lives in the always-on lock-free ring
/// instead.
pub const ARWRITE: u8 = 40;
/// A file write whose payload begins with the `ar` archive MAGIC — the correct
/// start of an archive. `a` is the host fd, `b` the starting offset (`-1` when
/// not seekable), `c` the payload length.
///
/// Normal traffic, recorded so the magic write can be correlated with the
/// member write that should follow it on the same description. Note host fd
/// numbers are recycled heavily within one build, so correlate by adjacency in
/// the ring rather than by fd number alone.
pub const ARMAGIC: u8 = 41;
/// Thread or process clone spawn outcome. `a` is parent PID, `b` child TID, `c` errno (0 = success).
pub const CLONESPAWN: u8 = 42;
/// HVPatch scheduler claim. `a` is guest PID, `b` guest TID, and `c` the
/// persistent executor id. This fires before backend load so an uninstrumented
/// core can distinguish a row that was never claimed from one stuck in load.
pub const HVPEXEC_CLAIM: u8 = 43;
/// HVPatch backend load and hardware audit completed for the exact claimed
/// guest PID/TID on executor `c`.
pub const HVPEXEC_LOAD: u8 = 44;
/// HVPatch process-leader quantum boundary. `c` is the exact non-syscall
/// boundary code decoded below. Paired with settlement, this distinguishes a
/// task still executing from one handed back to the scheduler.
pub const HVPEXEC_BOUNDARY: u8 = 45;
/// HVPatch process-leader state after successful scheduler settlement. `c` is
/// the authoritative `ThreadExecutionState` class, not merely the requested
/// boundary disposition.
pub const HVPEXEC_SETTLEMENT: u8 = 46;
/// HVPatch process-leader blocking-continuation construction. `a` is guest
/// PID, `b` guest TID, and `c` packs the guest-native syscall number in
/// bits 0..23 and the stable continuation-family code in bits 24..31.
pub const HVPBLOCK: u8 = 47;
pub const HVPBLOCK_NR_OVERFLOW: u32 = 0x00ff_ffff;
/// Full-width raw syscall argument 0 for an immediately preceding HVPBLOCK.
/// `a:b` is the u64 value and `c` is the guest TID join key.
pub const HVPBLOCK_ARG0: u8 = 48;
/// Raw low 32 bits of syscall arguments 1 and 2 for HVPBLOCK. `a` is arg1,
/// `b` is arg2, and `c` is the guest TID join key.
pub const HVPBLOCK_ARGS: u8 = 49;
/// HVPatch scheduler settlement sub-step for one exact thread claim. `a` is
/// the guest TID, `b` the `ExecutionGeneration` the claim was taken at, and
/// `c` the sub-step code decoded below. Steps 5..=7 are the binding's
/// publication gate, which has no thread identity: there `a` is 0 and `b` is
/// the binding's `MmId`.
///
/// This exists because a stranded terminal settlement is invisible in the
/// boundary/settlement pair: `HVPEXEC_BOUNDARY` says the quantum ended and
/// `HVPEXEC_SETTLEMENT` is only written when a settlement SUCCEEDED, so a
/// claim that is released without ever settling leaves no record at all. Code
/// Codes 10..=17 (`claim-dropped-unsettled/<state>`) are that missing record:
/// `RunnableThread`'s `Drop` released a live claim, which leaves the thread in
/// whatever state `begin_switch_out` last published and its process job
/// unpublished forever. The trailing state names the exact
pub const HVPSETTLE: u8 = 50;
/// Multiplex owner registration established. `a` is owner description ID, `b` target description ID, `c` registration fd.
pub const EPOWNER: u8 = 51;
/// Multiplex wake published across description hierarchy. `a` is owner description ID, `b` source description ID, `c` propagation depth.
pub const EPWAKE: u8 = 52;
/// Multiplex / IO edge consumption. `a` is guest fd, `b` io generation, `c` cleared readiness bits.
pub const EPCMSUM: u8 = 53;
/// Multiplex registration retired / unlinked. `a` is owner fd / desc ID, `b` guest fd, `c` registration generation.
pub const EPRETIRE: u8 = 54;
/// Linux syslog(2) operation recorded for diagnostics. `a` is action type and owner,
/// `b` is requested buffer length, and `c` is the return value / errno / seq.
pub const SYSLOG_OP: u8 = 55;
/// Linux syslog(2) record publication. `a` is owner, `b` sequence number,
/// and `c` is the ring total stored bytes.
pub const SYSLOG_RECORD: u8 = 56;
/// Linux syslog(2) reader cursor and state. `a` is owner, `b` encodes read and clear seq,
/// and `c` is unread bytes remaining.
pub const SYSLOG_STATE: u8 = 57;
/// Linux syslog(2) readiness notification and wait events. `a` is owner, `b` encodes
/// event class and wake count, and `c` is the raw host poll descriptor.
pub const SYSLOG_WAKE: u8 = 58;
/// Caught-signal restart decision. `a` is guest TID, `b` is Linux signal,
/// and `c` is the same four-bit predicate mask published by the USDT probe.
pub const SIGNAL_RESTART: u8 = 59;
/// Companion for `SIGNAL_RESTART`. `a:b` is the signed 64-bit syscall number
/// and `c` is guest TID.
pub const SIGNAL_SYSCALL: u8 = 60;
/// Companion for `SIGNAL_RESTART`. `a:b` is the signed 64-bit syscall return
/// value and `c` is guest TID.
pub const SIGNAL_RETVAL: u8 = 61;
/// Optional companion for `SIGNAL_RESTART`; `a:b` is the interrupted EL0 PC
/// and `c` is guest TID. Absence means delivery was at a syscall boundary.
pub const SIGNAL_PC: u8 = 62;
/// Successful caught-signal frame injection. `a` is guest TID, `b` is Linux
/// signal, and `c` is the final restart decision.
pub const SIGNAL_INJECT: u8 = 63;
/// Task dispatched to executor. `a` is guest TID, `b` is executor id, `c` is CPU index.
pub const SCHED_DISPATCH: u8 = 64;
/// Preemption request delivered to executor. `a` is guest TID, `b` is executor id, `c` is PreemptionReasons bits.
pub const SCHED_PREEMPT: u8 = 65;
/// Quantum budget assigned at dispatch. `a` is executor id, `b` is budget quantum in ms, `c` is execution generation.
pub const SCHED_BUDGET: u8 = 66;
/// Deadline scheduled for executor under contention. `a` is executor id, `b` is deadline delta in ms, `c` is demand ticket.
pub const SCHED_DEADLINE: u8 = 67;
/// Host claim of an EL1 frame-grant request on the forwarded-fault path.
/// `a` is Linux TID, `b` is the low 32 bits of the zone MM key, `c` packs the
/// claim outcome (bits 1:0, [`FrameGrantClaimOutcome`]), the faulting access
/// (bits 3:2, [`RingAccess`]) and the low 28 bits of the claimed request
/// generation (bits 31:4; zero unless the request was accepted). A
/// [`FAULT_VA`] companion carries the full fault address.
pub const EL1GRANT_CLAIM: u8 = 68;
/// Full-width fault address companion of [`EL1GRANT_CLAIM`] and
/// [`FIRST_TOUCH`]: `a:b` is the address, `c` the Linux TID.
pub const FAULT_VA: u8 = 69;
/// Host frame-grant decision. `a` is Linux TID, `b` is the low 32 bits of the
/// request generation, `c` packs the [`FrameGrantDecision`] (bits 3:0), the
/// Linux protection (bits 7:4) and the span in 4 KiB pages (bits 31:8,
/// saturating). Plan and Ready decisions are followed by [`EL1GRANT_BASE`];
/// Ready also by [`EL1GRANT_IPA`].
pub const EL1GRANT_DECISION: u8 = 70;
/// Semantic base of a granted/planned span: `a:b` is the VA, `c` the TID.
pub const EL1GRANT_BASE: u8 = 71;
/// Physical IPA of a published Ready grant: `a:b` is the IPA, `c` the TID.
pub const EL1GRANT_IPA: u8 = 72;
/// Host first-touch path result. `a` is Linux TID, `b` is the low 32 bits of
/// the MM key, `c` packs the resident plan result (bits 2:0,
/// [`FirstTouchResident`]), the grow-down result (bits 4:3,
/// [`FirstTouchGrowdown`]), the stale-stage-1 result (bits 6:5,
/// [`FirstTouchStale`]) and the access (bits 8:7, [`RingAccess`]). A
/// [`FAULT_VA`] companion carries the address.
pub const FIRST_TOUCH: u8 = 73;
/// Synchronous fault signal about to be delivered to an EL0 thread. `a` is
/// Linux TID, `b` the low 32 bits of the zone MM key (0 when none), `c` packs
/// signal (bits 7:0), si_code (bits 15:8), `fault_requires_mm_mutation` (bit
/// 16), live stage-1 walk available (bit 17), terminal descriptor valid (bit
/// 18), terminal descriptor permits the access (bit 19), terminal level
/// (bits 21:20), access (bits 23:22, [`RingAccess`]) and `from_el0_direct`
/// (bit 24). Followed by [`FAULTSIG_ADDR`], [`FAULTSIG_PC`],
/// [`FAULTSIG_LEAF`] and [`FAULTSIG_MBOXES`] (+ up to
/// [`FAULTSIG_MBOX_RECORDS`] [`FAULTSIG_MBOX`]).
pub const FAULTSIG: u8 = 74;
/// `a:b` is the fault address (FAR), `c` the low 32 bits of ESR_EL1.
pub const FAULTSIG_ADDR: u8 = 75;
/// `a:b` is the faulting PC (ELR), `c` the Linux TID.
pub const FAULTSIG_PC: u8 = 76;
/// `a:b` is the terminal descriptor of the live stage-1 walk (0 when the walk
/// was unavailable), `c` the Linux TID.
pub const FAULTSIG_LEAF: u8 = 77;
/// Frame-grant mailbox census at fault-signal time. `a` is Linux TID, `b`
/// packs the number of non-idle mailboxes (bits 15:0) and the faulting vCPU's
/// own mailbox slot plus one (bits 31:16; 0 = none), `c` is the non-idle
/// bitmask of slots 0..=31.
pub const FAULTSIG_MBOXES: u8 = 78;
/// One non-idle frame-grant mailbox: `a` is Linux TID, `b` the slot, `c` the
/// mailbox state (`FRAME_GRANT_MAILBOX_*`).
pub const FAULTSIG_MBOX: u8 = 79;
/// A vCPU slot refused an MM occupancy install. `a` is the execution slot,
/// `b` the low 32 bits of the MM already running there, `c` the low 32 bits
/// of the MM that asked to install.
pub const MMOCC_REFUSE: u8 = 80;

/// Host thread-clone errno 11 producer. `a` and `b` identify the canonical
/// caller's kernel task/thread IDs (not namespace projections); `c` is the
/// typed producer below. This is diagnostic history, not identity authority.
pub const CLONE_REFUSAL: u8 = 81;

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloneRefusalProducer {
    AdmissionRefused,
    Cancelled,
    Nproc,
    RuntimeReservation,
}

/// A stable cold-path breakpoint at the actual errno producer, unlike a
/// source-line breakpoint that optimized code can bind to an admitted path.
#[inline(never)]
pub fn rec_clone_refusal(context: &crate::kernel::KernelContext, producer: CloneRefusalProducer) {
    rec(
        CLONE_REFUSAL,
        context.task().key().id.raw(),
        context.thread().key().tid.raw(),
        producer as i32,
    );
}

#[cfg(any(test, feature = "event-ring-dump"))]
fn clone_refusal_label(producer: i32) -> &'static str {
    match producer {
        0 => "admission_refused",
        1 => "cancelled",
        2 => "nproc",
        3 => "runtime_reservation",
        _ => "unknown",
    }
}

/// Highest event kind a reader accepts.
const LAST_KIND: u8 = CLONE_REFUSAL;

/// At most this many [`FAULTSIG_MBOX`] records follow one fault signal, so a
/// census of all mailboxes never floods the ring.
pub const FAULTSIG_MBOX_RECORDS: usize = 8;

const HVPWAIT_ID_MASK: u32 = 0x00ff_ffff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HvpatchWaitRegisters {
    pub pc: u64,
    pub sp: u64,
    pub lr: u64,
}

#[cfg(feature = "event-ring-dump")]
fn dir() -> Option<&'static str> {
    static DIR: OnceLock<Option<String>> = OnceLock::new();
    DIR.get_or_init(|| std::env::var("CARRICK_EVENTRING").ok())
        .as_deref()
}

const fn busy_generation(logical_index: u64) -> u64 {
    // Encode the physical-slot lap, not twice the global index. The quotient is
    // at most u64::MAX / 8192, so both odd and even generations remain strictly
    // monotonic for the full non-wrapping IDX domain.
    (logical_index / N as u64) * 2 + 1
}

const fn complete_generation(logical_index: u64) -> u64 {
    busy_generation(logical_index) + 1
}

#[inline]
fn claim_slot(slot: &Slot, busy: u64) -> bool {
    let mut observed = slot.generation.load(Ordering::Acquire);
    loop {
        // Never supersede an in-flight writer: it may still store payload after
        // losing ownership, which could corrupt a newer completed generation.
        // The newer logical record becomes an explicit reader-visible gap.
        if observed & 1 == 1 || observed >= busy {
            return false;
        }
        match slot.generation.compare_exchange_weak(
            observed,
            busy,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(actual) => observed = actual,
        }
    }
}

#[inline]
fn write_reserved(slot: &Slot, logical_index: u64, lo: u64, hi: u64) -> bool {
    let busy = busy_generation(logical_index);
    if !claim_slot(slot, busy) {
        return false;
    }
    slot.lo.store(lo, Ordering::Relaxed);
    slot.hi.store(hi, Ordering::Relaxed);
    slot.generation
        .compare_exchange(
            busy,
            complete_generation(logical_index),
            Ordering::Release,
            Ordering::Relaxed,
        )
        .is_ok()
}

/// Append one event. ALWAYS records with no lock, syscall, or allocation so a
/// core/live LLDB read has trustworthy history without pre-arming diagnostics.
#[inline]
/// True when `payload` begins with an `ar` MEMBER header rather than the
/// archive magic.
///
/// An `ar` member header is a 16-byte name, then decimal mtime/uid/gid/mode,
/// a 10-byte decimal size, and the two-byte terminator `` `\n `` at offset 58.
/// Keying on that terminator plus a plausible name byte is a cheap, specific
/// test: it does not fire on the magic (`!<arch>\n`), and it does not fire on
/// ordinary data, so the caller's `lseek` stays off the hot path.
///
/// This is the write-side half of the archive-corruption detector: a member
/// header is correct at a nonzero file offset and corrupt at offset 0.
/// True when `payload` begins with the `ar` archive magic — the CORRECT start
/// of an archive. Paired with [`payload_starts_at_ar_member_header`] so a
/// caller can correlate the two writes that build one archive.
pub fn payload_starts_at_ar_magic(payload: &[u8]) -> bool {
    payload.starts_with(b"!<arch>\n")
}

pub fn payload_starts_at_ar_member_header(payload: &[u8]) -> bool {
    const AR_MEMBER_HEADER_LEN: usize = 60;
    const TERMINATOR_OFFSET: usize = 58;
    const AR_MAGIC: &[u8] = b"!<arch>\n";

    if payload.len() < AR_MEMBER_HEADER_LEN || payload.starts_with(AR_MAGIC) {
        return false;
    }
    // The fixed terminator is what makes this specific.
    if &payload[TERMINATOR_OFFSET..AR_MEMBER_HEADER_LEN] != b"`\n" {
        return false;
    }
    // A member name starts with a printable, non-space byte.
    payload[0].is_ascii_graphic()
}

/// Which ring a record kind is published into.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingSelect {
    /// Lifecycle, fault, grant, fd, wait and signal history.
    Lifecycle,
    /// Per-dispatch scheduler and per-poll `EP*`/eventfd/futex records.
    HighRate,
}

/// Kinds a spinning guest can emit once per dispatch or per poll. They go to
/// the separate high-rate ring so a spin cannot overwrite lifecycle records.
pub const fn is_high_rate(kind: u8) -> bool {
    matches!(
        kind,
        EPWAIT
            | EPWFD
            | EPMASK
            | EPMASKFD
            | EPEDGE
            | EFDWRITE
            | EFDREAD
            | FUTEXWAIT
            | FUTEXWAKE
            | FUTEXEND
            | EPREADY
            | EPWAKE
            | EPCMSUM
            | SCHED_DISPATCH
            | SCHED_PREEMPT
            | SCHED_BUDGET
            | SCHED_DEADLINE
    )
}

/// The ring `kind` is published into.
pub const fn ring_for_kind(kind: u8) -> RingSelect {
    if is_high_rate(kind) {
        RingSelect::HighRate
    } else {
        RingSelect::Lifecycle
    }
}

#[inline]
fn ring_storage(ring: RingSelect) -> (&'static [Slot; N], &'static AtomicU64) {
    match ring {
        RingSelect::Lifecycle => (&RING, &IDX),
        RingSelect::HighRate => (&SCHED_RING, &SCHED_IDX),
    }
}

pub fn rec(kind: u8, a: i32, b: i32, c: i32) {
    let (ring, idx) = ring_storage(ring_for_kind(kind));
    publish(ring, idx, kind, a, b, c);
    #[cfg(feature = "event-ring-dump")]
    maybe_start_watchdog();
}

/// Reserve the next logical index of one ring and publish into its slot.
#[inline]
fn publish(ring: &[Slot; N], idx: &AtomicU64, kind: u8, a: i32, b: i32, c: i32) {
    let lo = (a as u32 as u64) | ((b as u32 as u64) << 32);
    let hi = (c as u32 as u64) | ((kind as u64) << 32);
    let Ok(logical_index) = idx.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
        next.checked_add(1)
    }) else {
        return;
    };
    let slot = &ring[(logical_index % N as u64) as usize];
    let _published = write_reserved(slot, logical_index, lo, hi);
}

#[inline]
fn rec_futex(kind: u8, address: u64, detail: i32) {
    rec(
        kind,
        address as u32 as i32,
        (address >> 32) as u32 as i32,
        detail,
    );
}

/// Record entry into a process-private futex wait without allocation or a
/// syscall. The guest tid lets LLDB join the address to a sleeping host thread.
#[inline]
pub fn rec_futex_wait(address: u64, tid: i32) {
    rec_futex(FUTEXWAIT, address, tid);
}

/// Record the actual number of process-private waiters removed by FUTEX_WAKE.
#[inline]
pub fn rec_futex_wake(address: u64, woken: u32) {
    rec_futex(FUTEXWAKE, address, woken.min(i32::MAX as u32) as i32);
}

/// Record how a process-private futex wait ended: 0=woken, 1=interrupted,
/// 2=timed out.
#[inline]
pub fn rec_futex_end(address: u64, outcome: i32) {
    rec_futex(FUTEXEND, address, outcome);
}

/// Record one cold-path HvPatch thread teardown checkpoint.
#[inline]
pub fn rec_hvpatch_thread_teardown(pid: i32, tid: i32, phase: i32) {
    rec(HVPTHREAD, pid, tid, phase);
}

/// Record a process-aware HvPatch fd-wait checkpoint without allocation.
#[inline]
pub fn rec_hvpatch_wait(pid: i32, tid: i32, wait_class: u8, phase: u8, fd_count: usize) {
    let packed = u32::from(wait_class)
        | (u32::from(phase) << 8)
        | ((fd_count.min(u16::MAX as usize) as u32) << 16);
    rec(HVPWAIT, pid, tid, packed as i32);
}

#[inline]
fn encode_hvpatch_wait_correlation(id: u32, wait_class: u8, phase: u8) -> u32 {
    (id & HVPWAIT_ID_MASK)
        | ((u32::from(wait_class) & 0x0f) << 24)
        | ((u32::from(phase) & 0x0f) << 28)
}

#[inline]
fn rec_hvpatch_wait_value(kind: u8, value: u64, id: u32) {
    rec(
        kind,
        value as u32 as i32,
        (value >> 32) as u32 as i32,
        (id & HVPWAIT_ID_MASK) as i32,
    );
}

/// Begin a process-aware HvPatch wait trace before vCPU reclaim destroys the
/// live register file. The returned ID must be supplied to
/// [`rec_hvpatch_wait_end`] so concurrent waits can be joined without relying
/// on event adjacency.
#[inline]
pub fn rec_hvpatch_wait_begin(
    pid: i32,
    tid: i32,
    wait_class: u8,
    fd_count: usize,
    primary_fd: Option<(i32, i16)>,
    registers: HvpatchWaitRegisters,
) -> u32 {
    let mut id = NEXT_HVPWAIT_ID.fetch_add(1, Ordering::Relaxed) & HVPWAIT_ID_MASK;
    if id == 0 {
        id = 1;
    }
    rec_hvpatch_wait(pid, tid, wait_class, 1, fd_count);
    rec(
        HVPWAITX,
        pid,
        tid,
        encode_hvpatch_wait_correlation(id, wait_class, 1) as i32,
    );
    rec_hvpatch_wait_value(HVPWAIT_PC, registers.pc, id);
    rec_hvpatch_wait_value(HVPWAIT_SP, registers.sp, id);
    rec_hvpatch_wait_value(HVPWAIT_LR, registers.lr, id);
    if let Some((fd, events)) = primary_fd {
        rec(HVPWAITFD, id as i32, fd, i32::from(events));
    }
    id
}

/// Finish a correlated HvPatch wait trace. `phase` uses the HVPWAIT lifecycle
/// values (2 ready, 3 timeout, 4 interrupted, 5 errno).
#[inline]
pub fn rec_hvpatch_wait_end(
    pid: i32,
    tid: i32,
    wait_class: u8,
    phase: u8,
    fd_count: usize,
    id: u32,
) {
    rec_hvpatch_wait(pid, tid, wait_class, phase, fd_count);
    rec(
        HVPWAITX,
        pid,
        tid,
        encode_hvpatch_wait_correlation(id, wait_class, phase) as i32,
    );
}

/// Join an in-process guest child selector to a correlated wait snapshot.
#[inline]
pub fn rec_hvpatch_wait_target(id: u32, target_pid: Option<i32>) {
    rec(
        HVPWAIT_TARGET,
        (id & HVPWAIT_ID_MASK) as i32,
        target_pid.unwrap_or(-1),
        0,
    );
}

#[inline]
pub fn rec_hvpatch_process_exit_begin(pid: i32, tid: i32, exit_code: i32) {
    rec(HVPPEXIT_BEGIN, pid, tid, exit_code);
}

#[inline]
pub fn rec_hvpatch_process_exit_end(pid: i32, tid: i32, exit_code: i32) {
    rec(HVPPEXIT_END, pid, tid, exit_code);
}

#[inline]
pub fn rec_hvpatch_executor_claim(pid: i32, tid: i32, executor: u32) {
    rec(
        HVPEXEC_CLAIM,
        pid,
        tid,
        executor.min(i32::MAX as u32) as i32,
    );
}

#[inline]
pub fn rec_hvpatch_executor_load(pid: i32, tid: i32, executor: u32) {
    rec(HVPEXEC_LOAD, pid, tid, executor.min(i32::MAX as u32) as i32);
}

#[inline]
pub fn rec_hvpatch_executor_boundary(pid: i32, tid: i32, boundary: i32) {
    rec(HVPEXEC_BOUNDARY, pid, tid, boundary);
}

#[inline]
pub fn rec_hvpatch_executor_settlement(pid: i32, tid: i32, state: i32) {
    rec(HVPEXEC_SETTLEMENT, pid, tid, state);
}

#[inline]
pub fn rec_hvpatch_settle_step(tid: i32, generation: u64, step: i32) {
    rec(HVPSETTLE, tid, generation.min(i32::MAX as u64) as i32, step);
}

/// The `HVPSETTLE` variant whose `a:b` pair is a 64-bit object address rather
/// than a thread identity: steps 18 and 19 name the exact
/// `HvpatchLoopResultState` a job result was published into and the one a
/// container wait gave up on, which is the only way to tell "nobody published
/// this job" apart from "someone published a DIFFERENT job".
#[inline]
pub fn rec_hvpatch_settle_object(address: usize, step: i32) {
    let address = address as u64;
    rec(
        HVPSETTLE,
        (address & 0xffff_ffff) as u32 as i32,
        (address >> 32) as u32 as i32,
        step,
    );
}

#[inline]
pub fn rec_sched_dispatch(tid: i32, executor: u32, cpu: usize) {
    rec(SCHED_DISPATCH, tid, executor as i32, cpu as i32);
}

#[inline]
pub fn rec_sched_preempt(tid: i32, executor: u32, reasons: u32) {
    rec(SCHED_PREEMPT, tid, executor as i32, reasons as i32);
}

#[inline]
pub fn rec_sched_budget(executor: u32, budget_ms: u32, generation: u64) {
    rec(
        SCHED_BUDGET,
        executor as i32,
        budget_ms as i32,
        generation.min(i32::MAX as u64) as i32,
    );
}

#[inline]
pub fn rec_sched_deadline(executor: u32, deadline_ms: u32, ticket: u64) {
    rec(
        SCHED_DEADLINE,
        executor as i32,
        deadline_ms as i32,
        ticket.min(i32::MAX as u64) as i32,
    );
}

#[inline]
pub fn rec_hvpatch_blocked_continuation(
    pid: i32,
    tid: i32,
    syscall_number: u64,
    family: u8,
    args: [u64; 4],
) {
    let syscall = u32::try_from(syscall_number)
        .ok()
        .filter(|number| *number < HVPBLOCK_NR_OVERFLOW)
        .unwrap_or(HVPBLOCK_NR_OVERFLOW);
    let packed = syscall | (u32::from(family) << 24);
    rec(HVPBLOCK, pid, tid, packed as i32);
    rec(
        HVPBLOCK_ARG0,
        args[0] as u32 as i32,
        (args[0] >> 32) as u32 as i32,
        tid,
    );
    rec(
        HVPBLOCK_ARGS,
        args[1] as u32 as i32,
        args[2] as u32 as i32,
        tid,
    );
}

/// The faulting access as recorded in fault records (2 bits).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RingAccess {
    Unknown = 0,
    Read = 1,
    Write = 2,
    Execute = 3,
}

/// Outcome of the host's claim of an EL1 frame-grant request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameGrantClaimOutcome {
    /// No request for this exact fault (or no decodable access).
    None = 0,
    /// A response for this fault is already published; the fault retries.
    ResponsePending = 1,
    /// The host claimed the request and will answer it.
    Accepted = 2,
}

/// Host decision for a claimed frame-grant request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameGrantDecision {
    /// A resident plan names the span (base/len/prot follow).
    PlanFound = 0,
    /// Refused: no resident plan covers the fault.
    NoPlan = 1,
    /// Refused: the plan's protection denies the faulting access.
    FirstTouchDenied = 2,
    /// Refused: the backend could not prepare the grant.
    PrepareRefused = 3,
    /// Ready published to EL1 (base/len/IPA follow).
    Ready = 4,
}

/// Host first-touch resident-plan result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FirstTouchResident {
    NotReached = 0,
    Committed = 1,
    NoPlan = 2,
    ArmingDenied = 3,
    BackendRefused = 4,
}

/// Host grow-down stack extension result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FirstTouchGrowdown {
    NotReached = 0,
    Committed = 1,
    NoPlan = 2,
    ProtectFailed = 3,
}

/// Host stale-stage-1 leaf retry result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FirstTouchStale {
    NotReached = 0,
    Retried = 1,
    NotRetried = 2,
    AccessUnknown = 3,
}

#[inline]
fn rec_u64(kind: u8, value: u64, detail: i32) {
    rec(
        kind,
        value as u32 as i32,
        (value >> 32) as u32 as i32,
        detail,
    );
}

#[inline]
fn low32(value: u64) -> i32 {
    value as u32 as i32
}

#[inline]
fn encode_frame_grant_claim(
    outcome: FrameGrantClaimOutcome,
    access: RingAccess,
    request_generation: u64,
) -> i32 {
    ((outcome as u32 & 0x3)
        | ((access as u32 & 0x3) << 2)
        | (((request_generation & 0x0fff_ffff) as u32) << 4)) as i32
}

/// Record the host's claim of an EL1 frame-grant request for one forwarded
/// fault. `request_generation` is 0 unless the request was accepted.
#[inline]
pub fn rec_el1_frame_grant_claim(
    tid: i32,
    mm_key: u64,
    fault_va: u64,
    access: RingAccess,
    outcome: FrameGrantClaimOutcome,
    request_generation: u64,
) {
    rec(
        EL1GRANT_CLAIM,
        tid,
        low32(mm_key),
        encode_frame_grant_claim(outcome, access, request_generation),
    );
    rec_u64(FAULT_VA, fault_va, tid);
}

#[inline]
fn encode_frame_grant_decision(decision: FrameGrantDecision, prot: u64, len: u64) -> i32 {
    let pages = (len >> 12).min(0x00ff_ffff) as u32;
    ((decision as u32 & 0xf) | (((prot & 0xf) as u32) << 4) | (pages << 8)) as i32
}

/// Record the host's decision for a claimed frame-grant request. `base` is
/// the planned/granted semantic base (recorded for PlanFound and Ready);
/// `physical_ipa` is recorded for Ready only. `len` is the planned/granted
/// span, or the requested span for a NoPlan refusal.
#[inline]
pub fn rec_el1_frame_grant_decision(
    tid: i32,
    request_generation: u64,
    decision: FrameGrantDecision,
    prot: u64,
    len: u64,
    base: Option<u64>,
    physical_ipa: Option<u64>,
) {
    rec(
        EL1GRANT_DECISION,
        tid,
        low32(request_generation),
        encode_frame_grant_decision(decision, prot, len),
    );
    if let Some(base) = base {
        rec_u64(EL1GRANT_BASE, base, tid);
    }
    if let Some(ipa) = physical_ipa {
        rec_u64(EL1GRANT_IPA, ipa, tid);
    }
}

#[inline]
fn encode_first_touch(
    resident: FirstTouchResident,
    growdown: FirstTouchGrowdown,
    stale: FirstTouchStale,
    access: RingAccess,
) -> i32 {
    ((resident as u32 & 0x7)
        | ((growdown as u32 & 0x3) << 3)
        | ((stale as u32 & 0x3) << 5)
        | ((access as u32 & 0x3) << 7)) as i32
}

/// The host first-touch path result for one mutating fault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirstTouchRecord {
    pub tid: i32,
    pub mm_key: u64,
    pub fault_va: u64,
    pub access: RingAccess,
    pub resident: FirstTouchResident,
    pub growdown: FirstTouchGrowdown,
    pub stale: FirstTouchStale,
}

/// Record the host first-touch path result for one mutating fault.
#[inline]
pub fn rec_first_touch(record: &FirstTouchRecord) {
    rec(
        FIRST_TOUCH,
        record.tid,
        low32(record.mm_key),
        encode_first_touch(
            record.resident,
            record.growdown,
            record.stale,
            record.access,
        ),
    );
    rec_u64(FAULT_VA, record.fault_va, record.tid);
}

/// The live stage-1 walk of a fault address, summarized for the ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingStage1Walk {
    /// Level (0..=3) of the descriptor that terminated the walk.
    pub terminal_level: u8,
    /// The terminating descriptor.
    pub terminal_descriptor: u64,
    /// Whether the terminating descriptor is valid.
    pub terminal_valid: bool,
    /// Whether it permits the faulting EL0 access.
    pub permits_access: bool,
}

/// Everything a fault-signal delivery decision records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultSignalRecord {
    pub tid: i32,
    pub mm_key: Option<u64>,
    pub signum: i32,
    pub si_code: i32,
    pub fault_address: u64,
    pub esr: u64,
    pub pc: u64,
    pub requires_mm_mutation: bool,
    pub from_el0_direct: bool,
    pub access: RingAccess,
    /// `None` when the live walk was unavailable.
    pub walk: Option<RingStage1Walk>,
}

#[inline]
fn encode_fault_signal(record: &FaultSignalRecord) -> i32 {
    let mut packed = (record.signum as u32 & 0xff) | ((record.si_code as u32 & 0xff) << 8);
    packed |= u32::from(record.requires_mm_mutation) << 16;
    if let Some(walk) = record.walk {
        packed |= 1 << 17;
        packed |= u32::from(walk.terminal_valid) << 18;
        packed |= u32::from(walk.permits_access) << 19;
        packed |= (u32::from(walk.terminal_level) & 0x3) << 20;
    }
    packed |= (record.access as u32 & 0x3) << 22;
    packed |= u32::from(record.from_el0_direct) << 24;
    packed as i32
}

/// Record a fault-signal delivery decision and its live stage-1 walk, then a
/// bounded census of non-idle frame-grant mailboxes. `mailboxes` yields every
/// `(slot, state)` whose state is not idle; the census consumes it without
/// allocating and records at most [`FAULTSIG_MBOX_RECORDS`] slots.
pub fn rec_fault_signal(
    record: &FaultSignalRecord,
    own_mailbox_slot: Option<usize>,
    mailboxes: impl IntoIterator<Item = (usize, u32)>,
) {
    let tid = record.tid;
    rec(
        FAULTSIG,
        tid,
        record.mm_key.map_or(0, low32),
        encode_fault_signal(record),
    );
    rec_u64(FAULTSIG_ADDR, record.fault_address, low32(record.esr));
    rec_u64(FAULTSIG_PC, record.pc, tid);
    rec_u64(
        FAULTSIG_LEAF,
        record.walk.map_or(0, |walk| walk.terminal_descriptor),
        tid,
    );
    let mut listed = [(0_u32, 0_u32); FAULTSIG_MBOX_RECORDS];
    let mut count = 0_usize;
    let mut low_mask = 0_u32;
    for (slot, state) in mailboxes {
        if slot < 32 {
            low_mask |= 1 << slot;
        }
        if let Some(entry) = listed.get_mut(count) {
            *entry = (slot.min(i32::MAX as usize) as u32, state);
        }
        count += 1;
    }
    let own = own_mailbox_slot.map_or(0, |slot| (slot.min(0xfffe) + 1) as u32);
    rec(
        FAULTSIG_MBOXES,
        tid,
        ((count.min(0xffff) as u32) | (own << 16)) as i32,
        low_mask as i32,
    );
    for &(slot, state) in listed.iter().take(count) {
        rec(FAULTSIG_MBOX, tid, slot as i32, state as i32);
    }
}

/// Record a refused MM occupancy install of `slot`.
#[inline]
pub fn rec_mm_occupancy_refused(slot: usize, running_mm: u64, requested_mm: u64) {
    rec(
        MMOCC_REFUSE,
        slot.min(i32::MAX as usize) as i32,
        low32(running_mm),
        low32(requested_mm),
    );
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventRecord {
    pub logical_index: u64,
    pub kind: u8,
    pub a: i32,
    pub b: i32,
    pub c: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RingReadError {
    #[error("event-ring slot {logical_index} is busy at generation {generation}")]
    Busy { logical_index: u64, generation: u64 },
    #[error(
        "event-ring slot {logical_index} is missing: expected generation {expected}, observed {observed}"
    )]
    Gap {
        logical_index: u64,
        expected: u64,
        observed: u64,
    },
    #[error(
        "event-ring slot {logical_index} was overwritten: expected generation {expected}, observed {observed}"
    )]
    Overwritten {
        logical_index: u64,
        expected: u64,
        observed: u64,
    },
    #[error(
        "event-ring slot {logical_index} changed during read: generation {before} became {after}"
    )]
    Torn {
        logical_index: u64,
        before: u64,
        after: u64,
    },
    #[error("event-ring slot {logical_index} has unknown event kind {kind}")]
    UnknownKind { logical_index: u64, kind: u8 },
}

const fn known_kind(kind: u8) -> bool {
    (kind >= BIND && kind <= LAST_KIND) || (kind >= ALIAS_MUTATION && kind <= ALIAS_END)
}

fn read_slot_after(
    slot: &Slot,
    logical_index: u64,
    after_payload: impl FnOnce(),
) -> Result<EventRecord, RingReadError> {
    let expected = complete_generation(logical_index);
    let before = slot.generation.load(Ordering::Acquire);
    if before != expected {
        return Err(if before > expected {
            RingReadError::Overwritten {
                logical_index,
                expected,
                observed: before,
            }
        } else if before == busy_generation(logical_index) {
            RingReadError::Busy {
                logical_index,
                generation: before,
            }
        } else {
            RingReadError::Gap {
                logical_index,
                expected,
                observed: before,
            }
        });
    }
    let lo = slot.lo.load(Ordering::Relaxed);
    let hi = slot.hi.load(Ordering::Relaxed);
    after_payload();
    // Seqlock trailing read barrier: keep both payload loads before generation
    // validation. The first Acquire pairs with writer publication; this fence
    // prevents the final generation read from moving ahead of the payload.
    std::sync::atomic::fence(Ordering::Acquire);
    let after = slot.generation.load(Ordering::Acquire);
    if after != before {
        return Err(RingReadError::Torn {
            logical_index,
            before,
            after,
        });
    }
    let kind = (hi >> 32) as u8;
    if !known_kind(kind) {
        return Err(RingReadError::UnknownKind {
            logical_index,
            kind,
        });
    }
    Ok(EventRecord {
        logical_index,
        kind,
        a: (lo & 0xffff_ffff) as u32 as i32,
        b: (lo >> 32) as u32 as i32,
        c: (hi & 0xffff_ffff) as u32 as i32,
    })
}

fn read_slot(slot: &Slot, logical_index: u64) -> Result<EventRecord, RingReadError> {
    read_slot_after(slot, logical_index, || {})
}

/// Drain the ring oldest-to-newest for a post-mortem capture, up to `max`
/// records.
///
/// Every slot is reported: a slot the reader could not decode becomes an
/// `Err` row rather than a silent omission, because "the ring had nothing
/// there" and "the reader lost that slot" call for opposite conclusions and a
/// capture that cannot tell them apart is not evidence. Lock-free and
/// allocation-bounded; safe to call from a frozen carrier.
pub fn drain_recent(max: usize) -> Vec<Result<EventRecord, RingReadError>> {
    drain_ring(RingSelect::Lifecycle, max)
}

/// [`drain_recent`] for the high-rate ring.
pub fn drain_recent_high_rate(max: usize) -> Vec<Result<EventRecord, RingReadError>> {
    drain_ring(RingSelect::HighRate, max)
}

fn drain_ring(ring: RingSelect, max: usize) -> Vec<Result<EventRecord, RingReadError>> {
    let (slots, idx) = ring_storage(ring);
    let total = idx.load(Ordering::Acquire);
    let window = max.min(N) as u64;
    let start = total.saturating_sub(window);
    (start..total)
        .map(|logical_index| read_slot(&slots[(logical_index % N as u64) as usize], logical_index))
        .collect()
}

/// Whether the ring `kind` routes to still holds `(kind, a, b, c)`.
#[cfg(test)]
pub(crate) fn contains_event(kind: u8, a: i32, b: i32, c: i32) -> bool {
    ring_contains(ring_for_kind(kind), kind, a, b, c)
}

#[cfg(test)]
pub(crate) fn ring_contains(ring: RingSelect, kind: u8, a: i32, b: i32, c: i32) -> bool {
    drain_ring(ring, N)
        .into_iter()
        .filter_map(Result::ok)
        .any(|event| event.kind == kind && event.a == a && event.b == b && event.c == c)
}

#[inline]
fn encode_dsr_fault(
    pc: u64,
    address: u64,
    signal: i32,
    esr: u64,
    sp: u64,
    lr: u64,
) -> [(u8, i32, i32, i32); 4] {
    [
        (
            DSRFAULT_PC,
            pc as u32 as i32,
            (pc >> 32) as u32 as i32,
            signal,
        ),
        (
            DSRFAULT_ADDR,
            address as u32 as i32,
            (address >> 32) as u32 as i32,
            esr as u32 as i32,
        ),
        (DSRFAULT_SP, sp as u32 as i32, (sp >> 32) as u32 as i32, 0),
        (DSRFAULT_LR, lr as u32 as i32, (lr >> 32) as u32 as i32, 0),
    ]
}

/// Record a full-width DSR guest PC and fault address without allocation or
/// syscalls. The adjacent records are paired by order in the per-process ring.
#[inline]
pub fn rec_dsr_fault(pc: u64, address: u64, signal: i32, esr: u64, sp: u64, lr: u64) {
    for (kind, a, b, c) in encode_dsr_fault(pc, address, signal, esr, sp, lr) {
        rec(kind, a, b, c);
    }
}

/// Cheap, stable 32-bit hash of an AF_UNIX path, so a `connect` can be matched
/// to the `bind` of the same socket without storing the string.
pub fn path_hash(path: &[u8]) -> i32 {
    // FNV-1a.
    let mut h: u32 = 0x811c_9dc5;
    for &byte in path {
        h ^= byte as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h as i32
}

/// Reset the ring + re-arm the watchdog for a freshly forked child (its
/// inherited watchdog thread did not survive the fork). The child keeps its OWN
/// event history from here, so a per-process core shows that process's events.
pub fn reinit_after_fork() {
    // Only the forking thread survives, so no writer can race this reset.
    for (slots, idx) in [(&RING, &IDX), (&SCHED_RING, &SCHED_IDX)] {
        for slot in slots {
            slot.generation.store(0, Ordering::SeqCst);
        }
        idx.store(0, Ordering::SeqCst);
    }
    NEXT_HVPWAIT_ID.store(1, Ordering::SeqCst);
    WATCHDOG.store(false, Ordering::SeqCst);
}

/// Spawn the 1 Hz file-dump watchdog once per process (only compiled in under
/// the `event-ring-dump` feature). Cheap no-op on the hot path: a relaxed load,
/// and — unless `CARRICK_EVENTRING` names a dir — never spawns anything. The
/// recording itself is unconditional (see `rec`).
#[cfg(feature = "event-ring-dump")]
fn maybe_start_watchdog() {
    if WATCHDOG.load(Ordering::Relaxed) {
        return;
    }
    let Some(d) = dir() else {
        // No file dump requested; mark "started" so we don't re-check the env
        // every event. The ring is still recorded for lldb/core post-mortem.
        WATCHDOG.store(true, Ordering::Relaxed);
        return;
    };
    if WATCHDOG.swap(true, Ordering::SeqCst) {
        return; // another thread won the race
    }
    let path = format!("{d}/carrick-ring.{}", std::process::id());
    let _ = std::thread::Builder::new()
        .name("carrick-eventring".to_owned())
        .spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(1000));
                dump(&path);
            }
        });
}

#[cfg(any(test, feature = "event-ring-dump"))]
fn join_u64(a: i32, b: i32) -> u64 {
    (a as u32 as u64) | ((b as u32 as u64) << 32)
}

#[cfg(any(test, feature = "event-ring-dump"))]
fn ring_access_name(code: u32) -> &'static str {
    match code {
        1 => "read",
        2 => "write",
        3 => "exec",
        _ => "unknown",
    }
}

#[cfg(any(test, feature = "event-ring-dump"))]
fn ring_claim_outcome_name(code: u32) -> &'static str {
    match code {
        0 => "none",
        1 => "response-pending",
        2 => "accepted",
        _ => "unknown",
    }
}

#[cfg(any(test, feature = "event-ring-dump"))]
fn ring_grant_decision_name(code: u32) -> &'static str {
    match code {
        0 => "plan",
        1 => "refused/no-plan",
        2 => "refused/first-touch",
        3 => "refused/prepare",
        4 => "ready",
        _ => "unknown",
    }
}

#[cfg(any(test, feature = "event-ring-dump"))]
fn ring_first_touch_resident_name(code: u32) -> &'static str {
    match code {
        0 => "not-reached",
        1 => "committed",
        2 => "no-plan",
        3 => "arming-denied",
        4 => "backend-refused",
        _ => "unknown",
    }
}

#[cfg(any(test, feature = "event-ring-dump"))]
fn ring_first_touch_growdown_name(code: u32) -> &'static str {
    match code {
        0 => "not-reached",
        1 => "committed",
        2 => "no-plan",
        3 => "protect-failed",
        _ => "unknown",
    }
}

#[cfg(any(test, feature = "event-ring-dump"))]
fn ring_first_touch_stale_name(code: u32) -> &'static str {
    match code {
        0 => "not-reached",
        1 => "retried",
        2 => "not-retried",
        3 => "access-unknown",
        _ => "unknown",
    }
}

#[cfg(any(test, feature = "event-ring-dump"))]
fn ring_mailbox_state_name(state: u32) -> &'static str {
    match state {
        carrick_el1_abi::FRAME_GRANT_MAILBOX_IDLE => "idle",
        carrick_el1_abi::FRAME_GRANT_MAILBOX_GUEST_WRITING => "guest-writing",
        carrick_el1_abi::FRAME_GRANT_MAILBOX_REQUESTED => "requested",
        carrick_el1_abi::FRAME_GRANT_MAILBOX_HOST_WORKING => "host-working",
        carrick_el1_abi::FRAME_GRANT_MAILBOX_RESPONSE => "response",
        carrick_el1_abi::FRAME_GRANT_MAILBOX_GUEST_CONSUMING => "guest-consuming",
        _ => "unknown",
    }
}
#[cfg(any(test, feature = "event-ring-dump"))]
fn decode(kind: u8, a: i32, b: i32, c: i32) -> String {
    match kind {
        BIND => format!("BIND     gfd={a} hfd={b} pathhash={c:#010x}"),
        LISTEN => format!("LISTEN   hfd={a}"),
        CONNECT => format!("CONNECT  hfd={a} rc={b} pathhash={c:#010x}"),
        ACCEPT => format!("ACCEPT   listener_hfd={a} ret={b}"),
        EPADD => format!("EPADD    kq={a} hfd={b} events={c:#x}"),
        EPWAIT => format!("EPWAIT   kq={a} ready={b} timeout={c}"),
        FORK => format!("FORK     child_pid={a}"),
        EXEC => format!("EXEC     path_present={a}"),
        FDOPEN => format!("FDOPEN   gfd={a} hfd={b} minfd={c}"),
        ARMAGIC => format!("ARMAGIC  hfd={a} off={b} n={c}"),
        ARWRITE => format!(
            "ARWRITE  hfd={a} off={b} n={c}{}",
            if b == 0 {
                "  <-- ar member header at offset 0: CORRUPT"
            } else {
                ""
            }
        ),
        FDCLOSE => format!("FDCLOSE  gfd={a} hfd={b}"),
        ACCEPTERR => format!("ACCEPTER listener_hfd={a} accepted_hfd={b} errno={c}"),
        EPWFD => format!("EPWFD    fd={a} events={b:#x} timeout={c}"),
        EPMASK => format!("EPMASK   origin={a} raw={b:#x} last={c:#x}"),
        EPMASKFD => format!("EPMASKFD origin={a} gfd={b} hfd={c}"),
        EPEDGE => format!("EPEDGE   gfd={a} edge={b:#x} count={c}"),
        DSRFAULT_PC => format!(
            "DSRFAULT pc={:#018x} signal={c}",
            (a as u32 as u64) | ((b as u32 as u64) << 32)
        ),
        DSRFAULT_ADDR => format!(
            "DSRFAULT address={:#018x} esr={:#010x}",
            (a as u32 as u64) | ((b as u32 as u64) << 32),
            c as u32
        ),
        DSRFAULT_SP => format!(
            "DSRFAULT sp={:#018x}",
            (a as u32 as u64) | ((b as u32 as u64) << 32)
        ),
        DSRFAULT_LR => format!(
            "DSRFAULT lr={:#018x}",
            (a as u32 as u64) | ((b as u32 as u64) << 32)
        ),
        NSREJECT => format!("NSREJECT pathhash={a:#010x} reasonhash={b:#010x} pid={c}"),
        EFDWRITE => format!("EFDWRITE hfd={a} before={} after={}", b as u32, c as u32),
        EFDREAD => format!("EFDREAD  hfd={a} before={} after={}", b as u32, c as u32),
        FUTEXWAIT => format!(
            "FUTEXWAIT addr={:#018x} tid={c}",
            (a as u32 as u64) | ((b as u32 as u64) << 32)
        ),
        FUTEXWAKE => format!(
            "FUTEXWAKE addr={:#018x} woken={c}",
            (a as u32 as u64) | ((b as u32 as u64) << 32)
        ),
        FUTEXEND => format!(
            "FUTEXEND addr={:#018x} outcome={}",
            (a as u32 as u64) | ((b as u32 as u64) << 32),
            match c {
                0 => "woken",
                1 => "interrupted",
                2 => "timed-out",
                _ => "unknown",
            }
        ),
        HVPTHREAD => format!(
            "HVPTHREAD pid={a} tid={b} phase={}",
            match c {
                1 => "cleanup-start",
                2 => "registry-removed",
                3 => "kicker-unregistered",
                4 => "signal-forgotten",
                5 => "dispatcher-forgotten",
                6 => "vcpu-destroyed",
                7 => "loop-return",
                _ => "unknown",
            }
        ),
        HVPWAIT => {
            let packed = c as u32;
            let wait_class = match packed & 0xff {
                1 => "fds",
                2 => "select",
                3 => "poll",
                4 => "proc-exit",
                5 => "proc-state",
                6 => "child",
                7 => "futex",
                _ => "unknown",
            };
            let phase = match (packed >> 8) & 0xff {
                1 => "begin",
                2 => "ready",
                3 => "timed-out",
                4 => "interrupted",
                5 => "errno",
                _ => "unknown",
            };
            format!(
                "HVPWAIT  pid={a} tid={b} wait={wait_class} phase={phase} fds={}",
                packed >> 16
            )
        }
        HVPWAITX => {
            let packed = c as u32;
            let wait_class = match (packed >> 24) & 0x0f {
                1 => "fds",
                2 => "select",
                3 => "poll",
                4 => "proc-exit",
                5 => "proc-state",
                6 => "child",
                7 => "futex",
                _ => "unknown",
            };
            let phase = match (packed >> 28) & 0x0f {
                1 => "begin",
                2 => "ready",
                3 => "timed-out",
                4 => "interrupted",
                5 => "errno",
                _ => "unknown",
            };
            format!(
                "HVPWAITX pid={a} tid={b} id={:#08x} wait={wait_class} phase={phase}",
                packed & HVPWAIT_ID_MASK
            )
        }
        HVPWAIT_PC => format!(
            "HVPWAITPC id={:#08x} pc={:#018x}",
            c as u32 & HVPWAIT_ID_MASK,
            (a as u32 as u64) | ((b as u32 as u64) << 32)
        ),
        HVPWAIT_SP => format!(
            "HVPWAITSP id={:#08x} sp={:#018x}",
            c as u32 & HVPWAIT_ID_MASK,
            (a as u32 as u64) | ((b as u32 as u64) << 32)
        ),
        HVPWAIT_LR => format!(
            "HVPWAITLR id={:#08x} lr={:#018x}",
            c as u32 & HVPWAIT_ID_MASK,
            (a as u32 as u64) | ((b as u32 as u64) << 32)
        ),
        HVPWAITFD => format!(
            "HVPWAITFD id={:#08x} fd={b} events={:#x}",
            a as u32 & HVPWAIT_ID_MASK,
            c as u32
        ),
        HVPPEXIT_BEGIN => {
            format!("HVPPEXIT pid={a} tid={b} exit={c} publication=begin")
        }
        HVPPEXIT_END => {
            format!("HVPPEXIT pid={a} tid={b} exit={c} publication=complete")
        }
        HVPWAIT_TARGET => format!(
            "HVPWAITTARGET id={:#08x} target_pid={b}",
            a as u32 & HVPWAIT_ID_MASK
        ),
        EPREADY => format!("EPREADY  epfd={a} gfd={b} events={:#x}", c as u32),
        EPSTALE => format!(
            "EPSTALE  gfd={a} observed_gen={} live_gen={}",
            b as u32,
            if c < 0 {
                "none".to_owned()
            } else {
                (c as u32).to_string()
            }
        ),
        FDOWNER => format!("FDOWNER pid={a} tid={b} gfd={c}"),
        FDREF => format!("FDREF    pid={a} gfd={b} refs_before={c}"),
        CLONESPAWN => format!("CLONESPAWN parent_pid={a} child_tid={b} errno={c}"),
        CLONE_REFUSAL => format!(
            "CLONEREFUSE task_id={a} tid={b} errno=11 producer={}",
            clone_refusal_label(c)
        ),
        HVPEXEC_CLAIM => format!("HVPEXEC  pid={a} tid={b} executor={c} phase=claim"),
        HVPEXEC_LOAD => format!("HVPEXEC  pid={a} tid={b} executor={c} phase=load"),
        HVPEXEC_BOUNDARY => format!(
            "HVPEXEC  pid={a} tid={b} phase=boundary reason={}",
            match c {
                1 => "blocked-child",
                2 => "blocked-host",
                3 => "blocked-continuation",
                4 => "yielded",
                5 => "preempted",
                6 => "quiesced",
                7 => "exited",
                8 => "invalid-state",
                _ => "unknown",
            }
        ),
        HVPEXEC_SETTLEMENT => format!(
            "HVPEXEC  pid={a} tid={b} phase=settlement state={}",
            match c {
                1 => "runnable",
                2 => "blocked-child",
                3 => "blocked-host",
                4 => "exited",
                5 => "failed",
                6 => "running",
                7 => "switching-out",
                8 => "uninitialized",
                _ => "unknown",
            }
        ),
        HVPSETTLE => format!(
            "HVPSETTLE tid={a} generation={b} step={}",
            match c {
                1 => "settle-exited-enter",
                2 => "settle-exited-state-published",
                3 => "settle-exited-unbound",
                4 => "settle-exited-claim-finished",
                5 => "publish-terminal-active",
                6 => "publish-terminal-exec-transferred",
                7 => "publish-terminal-already-settled",
                8 => "claim-dropped-settled",
                10 => "claim-dropped-unsettled/runnable",
                11 => "claim-dropped-unsettled/blocked-child",
                12 => "claim-dropped-unsettled/blocked-host",
                13 => "claim-dropped-unsettled/exited",
                14 => "claim-dropped-unsettled/failed",
                15 => "claim-dropped-unsettled/running",
                16 => "claim-dropped-unsettled/switching-out",
                17 => "claim-dropped-unsettled/uninitialized",
                18 => "job-result-published",
                19 => "job-result-wait-abandoned",
                _ => "unknown",
            }
        ),
        HVPBLOCK => {
            let packed = c as u32;
            let native_nr = packed & 0x00ff_ffff;
            let number = if native_nr == HVPBLOCK_NR_OVERFLOW {
                "overflow".to_owned()
            } else {
                native_nr.to_string()
            };
            let family = match packed >> 24 {
                1 => "futex-wait",
                2 => "futex-waitv",
                3 => "shared-futex-wait",
                4 => "shared-futex-waitv",
                5 => "shared-word",
                6 => "fds",
                7 => "select",
                8 => "poll",
                9 => "host-write",
                10 => "timerfd-read",
                11 => "record-lock",
                12 => "proc-exit",
                13 => "proc-state",
                14 => "child",
                15 => "signals",
                16 => "sleep",
                17 => "vfork-parent",
                18 => "fd-wait",
                19 => "semop",
                20 => "mqueue",
                _ => "unknown",
            };
            format!("HVPBLOCK pid={a} tid={b} native_nr={number} family={family}")
        }
        HVPBLOCK_ARG0 => format!(
            "HVPBLOCKARG0 tid={c} arg0={:#018x}",
            (a as u32 as u64) | ((b as u32 as u64) << 32)
        ),
        HVPBLOCK_ARGS => format!(
            "HVPBLOCKARGS tid={c} arg1={:#x} arg2={}",
            a as u32, b as u32
        ),
        EPOWNER => format!("EPOWNER  owner={a} target={b} reg_fd={c}"),
        EPWAKE => format!("EPWAKE   owner={a} source={b} depth={c}"),
        EPCMSUM => format!("EPCMSUM  gfd={a} io_gen={b} cleared={:#x}", c as u32),
        EPRETIRE => format!("EPRETIRE epfd={a} gfd={b} reg_gen={}", c as u32),
        SYSLOG_OP => format!(
            "SYSLOG owner={} action={} len={} retval={}",
            (a as u32) >> 16,
            (a as u32) & 0xffff,
            b,
            c
        ),
        SYSLOG_RECORD => format!("SYSLOG_RECORD owner={a} seq={b} total_bytes={c}"),
        SYSLOG_STATE => format!(
            "SYSLOG_STATE owner={a} read_seq={} clear_seq={} unread={c}",
            (b as u32) >> 16,
            (b as u32) & 0xffff
        ),
        SYSLOG_WAKE => format!(
            "SYSLOG_WAKE owner={a} type={} wake_count={} poll_fd={c}",
            (b as u32) >> 16,
            (b as u32) & 0xffff
        ),
        SIGNAL_RESTART => format!(
            "SIGNAL_RESTART tid={a} signal={b} predicates={:#x}",
            c as u32
        ),
        SIGNAL_SYSCALL => format!(
            "SIGNAL_SYSCALL tid={c} nr={}",
            ((a as u32 as u64) | ((b as u32 as u64) << 32)) as i64
        ),
        SIGNAL_RETVAL => format!(
            "SIGNAL_RETVAL tid={c} retval={}",
            ((a as u32 as u64) | ((b as u32 as u64) << 32)) as i64
        ),
        SIGNAL_PC => format!(
            "SIGNAL_PC tid={c} pc={:#018x}",
            (a as u32 as u64) | ((b as u32 as u64) << 32)
        ),
        SIGNAL_INJECT => format!("SIGNAL_INJECT tid={a} signal={b} restart={}", c != 0),
        SCHED_DISPATCH => format!("SCHED_DISPATCH tid={a} executor={b} cpu={c}"),
        SCHED_PREEMPT => format!("SCHED_PREEMPT tid={a} executor={b} reasons={:#x}", c as u32),
        SCHED_BUDGET => format!("SCHED_BUDGET executor={a} budget_ms={b} generation={c}"),
        SCHED_DEADLINE => format!("SCHED_DEADLINE executor={a} deadline_ms={b} ticket={c}"),
        EL1GRANT_CLAIM => {
            let packed = c as u32;
            format!(
                "EL1GRANT_CLAIM tid={a} mm={} outcome={} access={} generation={}",
                b as u32,
                ring_claim_outcome_name(packed & 0x3),
                ring_access_name((packed >> 2) & 0x3),
                packed >> 4
            )
        }
        FAULT_VA => format!("FAULT_VA tid={c} va={:#018x}", join_u64(a, b)),
        EL1GRANT_DECISION => {
            let packed = c as u32;
            format!(
                "EL1GRANT_DECISION tid={a} generation={} decision={} prot={:#x} pages={}",
                b as u32,
                ring_grant_decision_name(packed & 0xf),
                (packed >> 4) & 0xf,
                packed >> 8
            )
        }
        EL1GRANT_BASE => format!("EL1GRANT_BASE tid={c} base={:#018x}", join_u64(a, b)),
        EL1GRANT_IPA => format!("EL1GRANT_IPA tid={c} ipa={:#018x}", join_u64(a, b)),
        FIRST_TOUCH => {
            let packed = c as u32;
            format!(
                "FIRST_TOUCH tid={a} mm={} resident={} growdown={} stale={} access={}",
                b as u32,
                ring_first_touch_resident_name(packed & 0x7),
                ring_first_touch_growdown_name((packed >> 3) & 0x3),
                ring_first_touch_stale_name((packed >> 5) & 0x3),
                ring_access_name((packed >> 7) & 0x3)
            )
        }
        FAULTSIG => {
            let packed = c as u32;
            let walk = if packed & (1 << 17) == 0 {
                "unavailable".to_owned()
            } else {
                format!(
                    "L{}-{}-{}",
                    (packed >> 20) & 0x3,
                    if packed & (1 << 18) != 0 {
                        "valid"
                    } else {
                        "invalid"
                    },
                    if packed & (1 << 19) != 0 {
                        "permits"
                    } else {
                        "denies"
                    }
                )
            };
            format!(
                "FAULTSIG tid={a} mm={} signal={} si_code={} mutating={} walk={walk} access={} direct={}",
                b as u32,
                packed & 0xff,
                (packed >> 8) & 0xff,
                packed & (1 << 16) != 0,
                ring_access_name((packed >> 22) & 0x3),
                packed & (1 << 24) != 0
            )
        }
        FAULTSIG_ADDR => format!(
            "FAULTSIG_ADDR far={:#018x} esr={:#010x}",
            join_u64(a, b),
            c as u32
        ),
        FAULTSIG_PC => format!("FAULTSIG_PC tid={c} pc={:#018x}", join_u64(a, b)),
        FAULTSIG_LEAF => format!("FAULTSIG_LEAF tid={c} leaf={:#018x}", join_u64(a, b)),
        FAULTSIG_MBOXES => {
            let packed = b as u32;
            let own = packed >> 16;
            format!(
                "FAULTSIG_MBOXES tid={a} busy={} own_slot={} mask0_31={:#010x}",
                packed & 0xffff,
                if own == 0 {
                    "none".to_owned()
                } else {
                    (own - 1).to_string()
                },
                c as u32
            )
        }
        FAULTSIG_MBOX => format!(
            "FAULTSIG_MBOX tid={a} slot={b} state={}",
            ring_mailbox_state_name(c as u32)
        ),
        MMOCC_REFUSE => format!(
            "MMOCC_REFUSE slot={a} running_mm={} requested_mm={}",
            b as u32, c as u32
        ),
        ALIAS_MUTATION => format!(
            "ALIAS    coordinator={:#x} tid={c} begin=mutation",
            ((a as u32 as u64) << 32) | (b as u32 as u64)
        ),
        ALIAS_DISPATCH => format!(
            "ALIAS    coordinator={:#x} tid={c} begin=dispatch",
            ((a as u32 as u64) << 32) | (b as u32 as u64)
        ),
        ALIAS_INSTALL => format!(
            "ALIAS    coordinator={:#x} tid={c} begin=install",
            ((a as u32 as u64) << 32) | (b as u32 as u64)
        ),
        ALIAS_END => format!(
            "ALIAS    coordinator={:#x} tid={c} end",
            ((a as u32 as u64) << 32) | (b as u32 as u64)
        ),
        _ => String::new(),
    }
}

/// Record the sparse, fully-qualified caught-signal decision. Companion
/// records immediately follow the decision; TID identifies the optional PC
/// record if events from another executor interleave.
pub fn rec_signal_restart_decision(
    tid: i32,
    signum: i32,
    syscall_nr: i64,
    retval: i64,
    predicates: i32,
    interrupted_pc: Option<u64>,
) {
    rec(SIGNAL_RESTART, tid, signum, predicates);
    rec(
        SIGNAL_SYSCALL,
        syscall_nr as u64 as u32 as i32,
        ((syscall_nr as u64) >> 32) as u32 as i32,
        tid,
    );
    rec(
        SIGNAL_RETVAL,
        retval as u64 as u32 as i32,
        ((retval as u64) >> 32) as u32 as i32,
        tid,
    );
    if let Some(pc) = interrupted_pc {
        rec(SIGNAL_PC, pc as u32 as i32, (pc >> 32) as u32 as i32, tid);
    }
}

pub fn rec_signal_inject(tid: i32, signum: i32, restart: bool) {
    rec(SIGNAL_INJECT, tid, signum, i32::from(restart));
}

pub fn rec_syslog(owner_id: u32, action: i32, len: i32, retval: i32) {
    let a = (((owner_id as u16 as u32) << 16) | (action as u16 as u32)) as i32;
    rec(SYSLOG_OP, a, len, retval);
}

pub fn rec_syslog_record(owner_id: u32, seq: u64, len: usize, total_bytes: usize) {
    let _ = len;
    rec(
        SYSLOG_RECORD,
        owner_id as i32,
        seq as i32,
        total_bytes as i32,
    );
}

pub fn rec_syslog_state(owner_id: u32, read_seq: u64, clear_seq: u64, unread: usize) {
    let b = (((read_seq as u16 as u32) << 16) | (clear_seq as u16 as u32)) as i32;
    rec(SYSLOG_STATE, owner_id as i32, b, unread as i32);
}

pub fn rec_syslog_wake(owner_id: u32, event_type: i32, wake_count: u64, poll_fd: i32) {
    let b = (((event_type as u16 as u32) << 16) | (wake_count as u16 as u32)) as i32;
    rec(SYSLOG_WAKE, owner_id as i32, b, poll_fd);
}

#[cfg(feature = "event-ring-dump")]
fn dump(path: &str) {
    use std::io::Write;
    let mut out = String::new();
    for (label, ring) in [
        ("lifecycle", RingSelect::Lifecycle),
        ("high-rate", RingSelect::HighRate),
    ] {
        dump_ring(&mut out, label, ring);
    }
    if let Ok(mut f) = std::fs::File::create(path) {
        let _ = f.write_all(out.as_bytes());
    }
}

#[cfg(feature = "event-ring-dump")]
fn dump_ring(out: &mut String, label: &str, ring: RingSelect) {
    let (slots, idx) = ring_storage(ring);
    let total = idx.load(Ordering::Acquire);
    let count = total.min(N as u64);
    let start = total.saturating_sub(count);
    out.push_str(&format!(
        "# carrick event ring ({label}) pid={} events={}\n",
        std::process::id(),
        total
    ));
    for logical_index in start..total {
        match read_slot(&slots[(logical_index % N as u64) as usize], logical_index) {
            Ok(event) => {
                let line = decode(event.kind, event.a, event.b, event.c);
                if line.is_empty() {
                    out.push_str(&format!(
                        "{logical_index:6} ERROR unknown-kind={}\n",
                        event.kind
                    ));
                } else {
                    out.push_str(&format!("{logical_index:6} {line}\n"));
                }
            }
            Err(error) => out.push_str(&format!("{logical_index:6} ERROR {error}\n")),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// A 60-byte `ar` member header for `name`, as `ar(5)` lays it out.
    fn ar_member_header(name: &str, size: usize) -> Vec<u8> {
        let mut header = vec![b' '; 60];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let size = size.to_string();
        header[48..48 + size.len()].copy_from_slice(size.as_bytes());
        header[58..60].copy_from_slice(b"`\n");
        header
    }

    #[test]
    fn ar_member_header_payload_is_detected() {
        let header = ar_member_header("cpu.o", 262);
        assert!(payload_starts_at_ar_member_header(&header));
    }

    /// The magic is the CORRECT start of an archive, so it must not fire —
    /// otherwise every well-formed archive write would be reported.
    #[test]
    fn archive_magic_payload_is_not_a_member_header() {
        let mut payload = b"!<arch>\n".to_vec();
        payload.extend_from_slice(&ar_member_header("cpu.o", 262));
        assert!(!payload_starts_at_ar_member_header(&payload));
    }

    #[test]
    fn ordinary_and_short_payloads_do_not_fire() {
        assert!(!payload_starts_at_ar_member_header(b""));
        assert!(!payload_starts_at_ar_member_header(b"cpu.o"));
        assert!(!payload_starts_at_ar_member_header(&[0_u8; 64]));
        assert!(!payload_starts_at_ar_member_header(&[b'x'; 64]));
    }

    /// The terminator is what makes the predicate specific: a 60-byte buffer
    /// that merely starts with a plausible name must not fire.
    #[test]
    fn a_plausible_name_without_the_terminator_does_not_fire() {
        let mut header = ar_member_header("cpu.o", 262);
        header[58] = b' ';
        assert!(!payload_starts_at_ar_member_header(&header));
    }

    /// The decoder only exists under the dump feature, which is also the only
    /// configuration that renders records to text.
    #[cfg(feature = "event-ring-dump")]
    #[test]
    fn the_arwrite_record_flags_offset_zero_as_corrupt() {
        assert!(decode(ARWRITE, 92, 0, 32768).contains("CORRUPT"));
        assert!(!decode(ARWRITE, 92, 68, 32768).contains("CORRUPT"));
    }

    fn empty_slot() -> Slot {
        Slot {
            generation: AtomicU64::new(0),
            lo: AtomicU64::new(0),
            hi: AtomicU64::new(0),
        }
    }

    #[test]
    fn clone_refusal_producer_decodes_each_typed_stage() {
        for (stage, label) in [
            "admission_refused",
            "cancelled",
            "nproc",
            "runtime_reservation",
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                decode(CLONE_REFUSAL, 56172, 56099, stage as i32),
                format!("CLONEREFUSE task_id=56172 tid=56099 errno=11 producer={label}")
            );
        }
        assert_eq!(
            decode(CLONE_REFUSAL, 56172, 56099, 99),
            "CLONEREFUSE task_id=56172 tid=56099 errno=11 producer=unknown"
        );
    }

    fn payload(kind: u8, a: i32, b: i32, c: i32) -> (u64, u64) {
        (
            (a as u32 as u64) | ((b as u32 as u64) << 32),
            (c as u32 as u64) | ((kind as u64) << 32),
        )
    }

    #[test]
    fn slot_layout_matches_lldb_wire_reader() {
        assert_eq!(std::mem::size_of::<Slot>(), 24);
        assert_eq!(std::mem::align_of::<Slot>(), 8);
    }

    #[test]
    fn generation_protocol_accepts_only_matching_complete_slot() {
        let slot = empty_slot();
        let logical_index = 41;
        let (lo, hi) = payload(FORK, 123, 0, 0);
        assert!(write_reserved(&slot, logical_index, lo, hi));
        assert_eq!(
            read_slot(&slot, logical_index),
            Ok(EventRecord {
                logical_index,
                kind: FORK,
                a: 123,
                b: 0,
                c: 0,
            })
        );
    }

    #[test]
    fn generation_protocol_reports_busy_gap_overwrite_torn_and_unknown_kind() {
        let logical_index = 51;

        let busy = empty_slot();
        assert!(claim_slot(&busy, busy_generation(logical_index)));
        assert!(matches!(
            read_slot(&busy, logical_index),
            Err(RingReadError::Busy {
                logical_index: 51,
                ..
            })
        ));

        let gap = empty_slot();
        assert!(matches!(
            read_slot(&gap, logical_index),
            Err(RingReadError::Gap {
                logical_index: 51,
                ..
            })
        ));

        let overwritten = empty_slot();
        let (lo, hi) = payload(EXEC, 1, 0, 0);
        assert!(write_reserved(
            &overwritten,
            logical_index + N as u64,
            lo,
            hi
        ));
        assert!(matches!(
            read_slot(&overwritten, logical_index),
            Err(RingReadError::Overwritten {
                logical_index: 51,
                ..
            })
        ));

        let torn = empty_slot();
        assert!(write_reserved(&torn, logical_index, lo, hi));
        assert!(matches!(
            read_slot_after(&torn, logical_index, || {
                torn.generation.store(
                    complete_generation(logical_index + N as u64),
                    Ordering::Release,
                );
            }),
            Err(RingReadError::Torn {
                logical_index: 51,
                ..
            })
        ));

        let unknown = empty_slot();
        let (lo, hi) = payload(0xff, 0, 0, 0);
        assert!(write_reserved(&unknown, logical_index, lo, hi));
        assert_eq!(
            read_slot(&unknown, logical_index),
            Err(RingReadError::UnknownKind {
                logical_index,
                kind: 0xff,
            })
        );
    }

    #[test]
    fn in_flight_writer_is_not_superseded_after_ring_wrap() {
        let slot = empty_slot();
        let old = 7;
        let newer = old + N as u64;
        let old_busy = busy_generation(old);
        assert!(claim_slot(&slot, old_busy));
        assert!(!claim_slot(&slot, busy_generation(newer)));
        let (lo, hi) = payload(BIND, 4, 9, 12);
        slot.lo.store(lo, Ordering::Relaxed);
        slot.hi.store(hi, Ordering::Relaxed);
        assert!(
            slot.generation
                .compare_exchange(
                    old_busy,
                    complete_generation(old),
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
        );
        assert!(matches!(
            read_slot(&slot, newer),
            Err(RingReadError::Gap { logical_index, .. }) if logical_index == newer
        ));
    }

    #[test]
    fn generations_remain_ordered_across_the_old_high_bit_boundary() {
        let slot = empty_slot();
        let high = 1_u64 << 63;
        let predecessor = high - N as u64;
        let (lo, hi) = payload(EXEC, 1, 0, 0);
        assert!(write_reserved(&slot, predecessor, lo, hi));
        assert!(write_reserved(&slot, high, lo, hi));
        assert!(read_slot(&slot, high).is_ok());
        assert!(complete_generation(u64::MAX) > complete_generation(high));
    }

    #[test]
    fn concurrent_wrap_never_accepts_payload_from_another_generation() {
        const LOCAL_N: usize = N;
        let slots = Arc::new(std::array::from_fn::<_, LOCAL_N, _>(|_| empty_slot()));
        let index = Arc::new(AtomicU64::new(0));
        let mut writers = Vec::new();
        for writer in 0..8_i32 {
            let slots = Arc::clone(&slots);
            let index = Arc::clone(&index);
            writers.push(std::thread::spawn(move || {
                for _ in 0..2_000 {
                    let logical = index.fetch_add(1, Ordering::Relaxed);
                    let (lo, hi) = payload(
                        FORK,
                        logical as u32 as i32,
                        (logical >> 32) as u32 as i32,
                        writer,
                    );
                    let _ = write_reserved(
                        &slots[(logical % LOCAL_N as u64) as usize],
                        logical,
                        lo,
                        hi,
                    );
                }
            }));
        }
        for writer in writers {
            assert!(writer.join().is_ok(), "event-ring writer panicked");
        }

        let total = index.load(Ordering::Acquire);
        for logical in total - LOCAL_N as u64..total {
            match read_slot(&slots[(logical % LOCAL_N as u64) as usize], logical) {
                Ok(event) => {
                    let payload_logical = event.a as u32 as u64 | ((event.b as u32 as u64) << 32);
                    assert_eq!(payload_logical, logical);
                }
                Err(RingReadError::Gap { .. } | RingReadError::Overwritten { .. }) => {}
                Err(other) => panic!("completed writers left invalid slot state: {other}"),
            }
        }
    }

    #[test]
    fn concurrent_reader_never_accepts_a_mixed_generation() {
        let slots = Arc::new(std::array::from_fn::<_, N, _>(|_| empty_slot()));
        let index = Arc::new(AtomicU64::new(0));
        let done = Arc::new(AtomicBool::new(false));
        let writer_slots = Arc::clone(&slots);
        let writer_index = Arc::clone(&index);
        let writer_done = Arc::clone(&done);
        let writer = std::thread::spawn(move || {
            for _ in 0..50_000 {
                let logical = writer_index.fetch_add(1, Ordering::Relaxed);
                let (lo, hi) = payload(
                    FORK,
                    logical as u32 as i32,
                    (logical >> 32) as u32 as i32,
                    0,
                );
                let _ = write_reserved(
                    &writer_slots[(logical % N as u64) as usize],
                    logical,
                    lo,
                    hi,
                );
            }
            writer_done.store(true, Ordering::Release);
        });

        while !done.load(Ordering::Acquire) {
            let total = index.load(Ordering::Acquire);
            let Some(logical) = total.checked_sub(1) else {
                std::hint::spin_loop();
                continue;
            };
            match read_slot(&slots[(logical % N as u64) as usize], logical) {
                Ok(event) => {
                    let payload_logical = event.a as u32 as u64 | ((event.b as u32 as u64) << 32);
                    assert_eq!(payload_logical, logical);
                }
                Err(
                    RingReadError::Busy { .. }
                    | RingReadError::Gap { .. }
                    | RingReadError::Overwritten { .. }
                    | RingReadError::Torn { .. },
                ) => {}
                Err(RingReadError::UnknownKind { .. }) => {
                    panic!("reader accepted an unknown mixed payload")
                }
            }
        }
        assert!(writer.join().is_ok(), "event-ring writer panicked");
    }

    #[test]
    fn futex_events_preserve_full_width_address_and_lifecycle_detail() {
        let address = 0x0000_0137_89ab_cdef;

        rec_futex_wait(address, 53_664);
        rec_futex_wake(address, 3);
        rec_futex_end(address, 2);

        let low = address as u32 as i32;
        let high = (address >> 32) as u32 as i32;
        assert!(contains_event(FUTEXWAIT, low, high, 53_664));
        assert!(contains_event(FUTEXWAKE, low, high, 3));
        assert!(contains_event(FUTEXEND, low, high, 2));
    }

    #[test]
    fn hvpatch_thread_teardown_event_carries_guest_process_thread_and_phase() {
        rec_hvpatch_thread_teardown(56_172, 56_099, 3);
        assert!(contains_event(HVPTHREAD, 56_172, 56_099, 3));
    }

    #[test]
    fn hvpatch_wait_event_carries_guest_identity_class_phase_and_fd_count() {
        rec_hvpatch_wait(57_499, 57_520, 3, 1, 2);
        assert!(contains_event(
            HVPWAIT,
            57_499,
            57_520,
            3 | (1 << 8) | (2 << 16)
        ));
    }

    #[test]
    fn hvpatch_wait_snapshot_correlates_identity_registers_and_primary_fd() {
        let id = rec_hvpatch_wait_begin(
            57_499,
            57_520,
            3,
            2,
            Some((16408, libc::POLLIN)),
            HvpatchWaitRegisters {
                pc: 0x0000_0040_1234_5678,
                sp: 0x0000_007f_89ab_cdef,
                lr: 0x0000_0040_dead_beef,
            },
        );
        rec_hvpatch_wait_end(57_499, 57_520, 3, 2, 2, id);

        let begin = encode_hvpatch_wait_correlation(id, 3, 1);
        let ready = encode_hvpatch_wait_correlation(id, 3, 2);
        assert!(contains_event(HVPWAITX, 57_499, 57_520, begin as i32));
        assert!(contains_event(HVPWAITX, 57_499, 57_520, ready as i32));
        assert!(contains_event(HVPWAIT_PC, 0x1234_5678, 0x40, id as i32));
        assert!(contains_event(
            HVPWAIT_SP,
            0x89ab_cdef_u32 as i32,
            0x7f,
            id as i32
        ));
        assert!(contains_event(
            HVPWAIT_LR,
            0xdead_beef_u32 as i32,
            0x40,
            id as i32
        ));
        assert!(contains_event(
            HVPWAITFD,
            id as i32,
            16408,
            i32::from(libc::POLLIN)
        ));
    }

    #[test]
    fn hvpatch_process_exit_records_publication_boundary() {
        rec_hvpatch_process_exit_begin(62_809, 62_809, 0);
        rec_hvpatch_process_exit_end(62_809, 62_809, 0);
        assert!(contains_event(HVPPEXIT_BEGIN, 62_809, 62_809, 0));
        assert!(contains_event(HVPPEXIT_END, 62_809, 62_809, 0));
    }

    #[test]
    fn hvpatch_executor_records_exact_guest_claim_and_load_boundaries() {
        rec_hvpatch_executor_claim(62_809, 62_809, 7);
        rec_hvpatch_executor_load(62_809, 62_809, 7);
        assert!(contains_event(HVPEXEC_CLAIM, 62_809, 62_809, 7));
        assert!(contains_event(HVPEXEC_LOAD, 62_809, 62_809, 7));
    }

    #[test]
    fn hvpatch_executor_records_process_leader_boundary_and_settlement() {
        rec_hvpatch_executor_boundary(62_809, 62_809, 5);
        rec_hvpatch_executor_settlement(62_809, 62_809, 2);
        assert!(contains_event(HVPEXEC_BOUNDARY, 62_809, 62_809, 5));
        assert!(contains_event(HVPEXEC_SETTLEMENT, 62_809, 62_809, 2));
    }

    #[test]
    fn hvpatch_blocked_continuation_preserves_syscall_and_family() {
        rec_hvpatch_blocked_continuation(
            62_809,
            62_809,
            202,
            3,
            [
                0x0000_0088_0006_0a70,
                0x0000_0001_0000_0081,
                0x0000_0002_0000_0002,
                0,
            ],
        );
        assert!(contains_event(
            HVPBLOCK,
            62_809,
            62_809,
            (3_i32 << 24) | 202
        ));
        assert!(contains_event(HVPBLOCK_ARG0, 0x0006_0a70, 0x88, 62_809));
        assert!(contains_event(HVPBLOCK_ARGS, 0x81, 2, 62_809));
        assert_eq!(
            decode(HVPBLOCK, 62_809, 62_809, (3_i32 << 24) | 202),
            "HVPBLOCK pid=62809 tid=62809 native_nr=202 family=shared-futex-wait"
        );
        assert_eq!(
            decode(HVPBLOCK_ARG0, 0x0006_0a70, 0x88, 62_809),
            "HVPBLOCKARG0 tid=62809 arg0=0x0000008800060a70"
        );
        assert_eq!(
            decode(HVPBLOCK_ARGS, 0x81, 2, 62_809),
            "HVPBLOCKARGS tid=62809 arg1=0x81 arg2=2"
        );

        rec_hvpatch_blocked_continuation(62_809, 62_809, u64::MAX, 4, [0; 4]);
        assert!(contains_event(
            HVPBLOCK,
            62_809,
            62_809,
            ((4_u32 << 24) | HVPBLOCK_NR_OVERFLOW) as i32
        ));
    }

    #[test]
    fn hvpatch_wait_target_joins_guest_child_pid_to_wait_id() {
        rec_hvpatch_wait_target(0x12_3456, Some(62_809));
        assert!(contains_event(HVPWAIT_TARGET, 0x12_3456, 62_809, 0));
    }

    #[test]
    fn dsr_fault_events_preserve_full_width_pc_address_signal_and_esr() {
        let pc = 0x0000_00a0_1234_5678;
        let address = 0xffff_00a0_9abc_def0;
        let signal = 11;
        let esr = 0x9600_0045;

        assert_eq!(
            encode_dsr_fault(
                pc,
                address,
                signal,
                esr,
                0x0000_00ff_1234_5678,
                0x400f_64380
            ),
            [
                (
                    DSRFAULT_PC,
                    pc as u32 as i32,
                    (pc >> 32) as u32 as i32,
                    signal,
                ),
                (
                    DSRFAULT_ADDR,
                    address as u32 as i32,
                    (address >> 32) as u32 as i32,
                    esr as i32,
                ),
                (DSRFAULT_SP, 0x1234_5678, 0x0000_00ff, 0),
                (DSRFAULT_LR, 0x00f6_4380, 0x0000_0004, 0),
            ]
        );
    }

    #[test]
    fn syslog_event_ring_encoding_and_decoding() {
        assert_eq!(SYSLOG_OP, 55);
        assert_eq!(SYSLOG_RECORD, 56);
        assert_eq!(SYSLOG_STATE, 57);
        assert_eq!(SYSLOG_WAKE, 58);
        let kinds = [SYSLOG_OP, SYSLOG_RECORD, SYSLOG_STATE, SYSLOG_WAKE];
        let unique: std::collections::BTreeSet<_> = kinds.iter().copied().collect();
        assert_eq!(unique.len(), kinds.len());

        let a = (((7u16 as u32) << 16) | (10u16 as u32)) as i32;
        assert_eq!(
            decode(SYSLOG_OP, a, 1024, 65536),
            "SYSLOG owner=7 action=10 len=1024 retval=65536"
        );
        assert_eq!(
            decode(SYSLOG_RECORD, 7, 42, 100),
            "SYSLOG_RECORD owner=7 seq=42 total_bytes=100"
        );
        let b_state = (((3u16 as u32) << 16) | (2u16 as u32)) as i32;
        assert_eq!(
            decode(SYSLOG_STATE, 7, b_state, 50),
            "SYSLOG_STATE owner=7 read_seq=3 clear_seq=2 unread=50"
        );
        let b_wake = (((1u16 as u32) << 16) | (5u16 as u32)) as i32;
        assert_eq!(
            decode(SYSLOG_WAKE, 7, b_wake, 12),
            "SYSLOG_WAKE owner=7 type=1 wake_count=5 poll_fd=12"
        );
    }

    #[test]
    fn signal_restart_event_ring_preserves_full_width_values() {
        assert_eq!(SIGNAL_RESTART, 59);
        assert_eq!(SIGNAL_SYSCALL, 60);
        assert_eq!(SIGNAL_RETVAL, 61);
        assert_eq!(SIGNAL_PC, 62);
        assert_eq!(SIGNAL_INJECT, 63);
        assert_eq!(
            decode(SIGNAL_RESTART, 41, 2, 0b1011),
            "SIGNAL_RESTART tid=41 signal=2 predicates=0xb"
        );
        let syscall_nr = 115i64;
        assert_eq!(
            decode(
                SIGNAL_SYSCALL,
                syscall_nr as u64 as u32 as i32,
                ((syscall_nr as u64) >> 32) as u32 as i32,
                41,
            ),
            "SIGNAL_SYSCALL tid=41 nr=115"
        );
        let retval = -0x1234_5678_7654_321i64;
        assert_eq!(
            decode(
                SIGNAL_RETVAL,
                retval as u64 as u32 as i32,
                ((retval as u64) >> 32) as u32 as i32,
                41,
            ),
            format!("SIGNAL_RETVAL tid=41 retval={retval}")
        );
        assert_eq!(
            decode(SIGNAL_PC, 0x7654_3210u32 as i32, 0x0000_ffff, 41),
            "SIGNAL_PC tid=41 pc=0x0000ffff76543210"
        );
        // Another executor may publish between companions. Every companion
        // carries its own TID, so a debugger does not infer ownership from
        // physical adjacency in the ring.
        assert_eq!(
            decode(SIGNAL_RETVAL, 7, 0, 99),
            "SIGNAL_RETVAL tid=99 retval=7"
        );
        assert_eq!(
            decode(SIGNAL_INJECT, 41, 2, 1),
            "SIGNAL_INJECT tid=41 signal=2 restart=true"
        );
        assert_eq!(
            decode(HVPBLOCK, 98, 4, (16_i32 << 24) | 115),
            "HVPBLOCK pid=98 tid=4 native_nr=115 family=sleep"
        );
        assert_eq!(
            decode(HVPBLOCK, 98, 4, (10_i32 << 24) | 85),
            "HVPBLOCK pid=98 tid=4 native_nr=85 family=timerfd-read"
        );
        assert_eq!(
            decode(HVPBLOCK, 98, 4, (18_i32 << 24) | 23),
            "HVPBLOCK pid=98 tid=4 native_nr=23 family=fd-wait"
        );
        assert_eq!(
            decode(HVPBLOCK, 98, 4, (19_i32 << 24) | 65),
            "HVPBLOCK pid=98 tid=4 native_nr=65 family=semop"
        );
        assert_eq!(
            decode(SCHED_DISPATCH, 42, 3, 1),
            "SCHED_DISPATCH tid=42 executor=3 cpu=1"
        );
        assert_eq!(
            decode(SCHED_PREEMPT, 42, 3, 0x13),
            "SCHED_PREEMPT tid=42 executor=3 reasons=0x13"
        );
        assert_eq!(
            decode(SCHED_BUDGET, 3, 4, 100),
            "SCHED_BUDGET executor=3 budget_ms=4 generation=100"
        );
        assert_eq!(
            decode(SCHED_DEADLINE, 3, 4, 1),
            "SCHED_DEADLINE executor=3 deadline_ms=4 ticket=1"
        );
    }

    #[test]
    fn event_ring_records_preemption_lifecycle_events() {
        rec_sched_dispatch(101, 5, 2);
        rec_sched_budget(5, 4, 12);
        rec_sched_deadline(5, 3, 42);
        rec_sched_preempt(101, 5, 0x01);

        assert!(contains_event(SCHED_DISPATCH, 101, 5, 2));
        assert!(contains_event(SCHED_BUDGET, 5, 4, 12));
        assert!(contains_event(SCHED_DEADLINE, 5, 3, 42));
        assert!(contains_event(SCHED_PREEMPT, 101, 5, 0x01));
    }

    /// The next record after the most recent `(kind, a)` match, oldest first:
    /// lets a test read back the packed words a helper actually published.
    fn latest_event(kind: u8, a: i32) -> Option<EventRecord> {
        drain_recent(N)
            .into_iter()
            .rev()
            .filter_map(Result::ok)
            .find(|event| event.kind == kind && event.a == a)
    }

    fn latest_companion(kind: u8, c: i32) -> Option<EventRecord> {
        drain_recent(N)
            .into_iter()
            .rev()
            .filter_map(Result::ok)
            .find(|event| event.kind == kind && event.c == c)
    }

    fn decoded(event: EventRecord) -> String {
        decode(event.kind, event.a, event.b, event.c)
    }

    #[test]
    fn fault_forensics_kinds_are_contiguous_and_readable() {
        assert_eq!(EL1GRANT_CLAIM, SCHED_DEADLINE + 1);
        assert_eq!(MMOCC_REFUSE, 80);
        for kind in EL1GRANT_CLAIM..=MMOCC_REFUSE {
            assert!(known_kind(kind), "kind {kind} must be readable");
            assert!(!decode(kind, 0, 0, 0).is_empty(), "kind {kind} decodes");
        }
        assert_eq!(CLONE_REFUSAL, MMOCC_REFUSE + 1);
        assert!(known_kind(CLONE_REFUSAL));
        assert!(!known_kind(LAST_KIND + 1));
    }

    #[test]
    fn el1_frame_grant_claim_round_trips() {
        let tid = 71_001;
        rec_el1_frame_grant_claim(
            tid,
            0x1_0000_0007,
            0x0000_ffff_8000_1234,
            RingAccess::Write,
            FrameGrantClaimOutcome::Accepted,
            0x1234_5678_9,
        );
        let claim = latest_event(EL1GRANT_CLAIM, tid).expect("claim record");
        assert_eq!(
            decoded(claim),
            // The low 28 bits of 0x1_2345_6789.
            "EL1GRANT_CLAIM tid=71001 mm=7 outcome=accepted access=write generation=54880137"
        );
        let va = latest_companion(FAULT_VA, tid).expect("fault va companion");
        assert_eq!(decoded(va), "FAULT_VA tid=71001 va=0x0000ffff80001234");

        rec_el1_frame_grant_claim(
            tid + 1,
            3,
            0x4000,
            RingAccess::Unknown,
            FrameGrantClaimOutcome::ResponsePending,
            0,
        );
        assert_eq!(
            decoded(latest_event(EL1GRANT_CLAIM, tid + 1).expect("pending claim")),
            "EL1GRANT_CLAIM tid=71002 mm=3 outcome=response-pending access=unknown generation=0"
        );
    }

    #[test]
    fn el1_frame_grant_decision_round_trips() {
        let tid = 72_001;
        rec_el1_frame_grant_decision(
            tid,
            41,
            FrameGrantDecision::Ready,
            0x3,
            0x10_000,
            Some(0x0000_aaaa_0000_0000),
            Some(0x0000_0040_1234_5000),
        );
        assert_eq!(
            decoded(latest_event(EL1GRANT_DECISION, tid).expect("decision")),
            "EL1GRANT_DECISION tid=72001 generation=41 decision=ready prot=0x3 pages=16"
        );
        assert_eq!(
            decoded(latest_companion(EL1GRANT_BASE, tid).expect("base")),
            "EL1GRANT_BASE tid=72001 base=0x0000aaaa00000000"
        );
        assert_eq!(
            decoded(latest_companion(EL1GRANT_IPA, tid).expect("ipa")),
            "EL1GRANT_IPA tid=72001 ipa=0x0000004012345000"
        );

        rec_el1_frame_grant_decision(
            tid + 1,
            42,
            FrameGrantDecision::NoPlan,
            0,
            u64::MAX,
            None,
            None,
        );
        assert_eq!(
            decoded(latest_event(EL1GRANT_DECISION, tid + 1).expect("refusal")),
            "EL1GRANT_DECISION tid=72002 generation=42 decision=refused/no-plan prot=0x0 pages=16777215"
        );
        assert!(latest_companion(EL1GRANT_BASE, tid + 1).is_none());
    }

    #[test]
    fn first_touch_round_trips() {
        let tid = 73_001;
        rec_first_touch(&FirstTouchRecord {
            tid,
            mm_key: 9,
            fault_va: 0xffff_0000,
            access: RingAccess::Execute,
            resident: FirstTouchResident::BackendRefused,
            growdown: FirstTouchGrowdown::ProtectFailed,
            stale: FirstTouchStale::NotRetried,
        });
        assert_eq!(
            decoded(latest_event(FIRST_TOUCH, tid).expect("first touch")),
            "FIRST_TOUCH tid=73001 mm=9 resident=backend-refused growdown=protect-failed stale=not-retried access=exec"
        );
        assert_eq!(
            decoded(latest_companion(FAULT_VA, tid).expect("va")),
            "FAULT_VA tid=73001 va=0x00000000ffff0000"
        );
    }

    #[test]
    fn fault_signal_round_trips_with_bounded_mailbox_census() {
        let tid = 74_001;
        let record = FaultSignalRecord {
            tid,
            mm_key: Some(0x5_0000_0011),
            signum: 11,
            si_code: 2,
            fault_address: 0x0000_ffff_dead_b000,
            esr: 0x9200_004f,
            pc: 0x0000_aaaa_0000_1000,
            requires_mm_mutation: true,
            from_el0_direct: true,
            access: RingAccess::Write,
            walk: Some(RingStage1Walk {
                terminal_level: 3,
                terminal_descriptor: 0x0060_0000_1234_5f43,
                terminal_valid: true,
                permits_access: false,
            }),
        };
        // Twelve busy mailboxes: the census counts all of them but lists
        // only FAULTSIG_MBOX_RECORDS.
        let busy = (0..12_usize).map(|index| (index * 3, 3_u32));
        rec_fault_signal(&record, Some(2), busy);

        assert_eq!(
            decoded(latest_event(FAULTSIG, tid).expect("fault signal")),
            "FAULTSIG tid=74001 mm=17 signal=11 si_code=2 mutating=true walk=L3-valid-denies access=write direct=true"
        );
        let addr = drain_recent(N)
            .into_iter()
            .rev()
            .filter_map(Result::ok)
            .find(|event| event.kind == FAULTSIG_ADDR && event.c == 0x9200_004f_u32 as i32)
            .expect("address record");
        assert_eq!(
            decoded(addr),
            "FAULTSIG_ADDR far=0x0000ffffdeadb000 esr=0x9200004f"
        );
        assert_eq!(
            decoded(latest_companion(FAULTSIG_PC, tid).expect("pc")),
            "FAULTSIG_PC tid=74001 pc=0x0000aaaa00001000"
        );
        assert_eq!(
            decoded(latest_companion(FAULTSIG_LEAF, tid).expect("leaf")),
            "FAULTSIG_LEAF tid=74001 leaf=0x0060000012345f43"
        );
        let mask = (0..11_u32)
            .map(|index| index * 3)
            .filter(|slot| *slot < 32)
            .fold(0_u32, |mask, slot| mask | (1 << slot));
        assert_eq!(
            decoded(latest_event(FAULTSIG_MBOXES, tid).expect("census")),
            format!("FAULTSIG_MBOXES tid=74001 busy=12 own_slot=2 mask0_31={mask:#010x}")
        );
        let listed = drain_recent(N)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|event| event.kind == FAULTSIG_MBOX && event.a == tid)
            .count();
        assert_eq!(listed, FAULTSIG_MBOX_RECORDS);
        assert!(contains_event(FAULTSIG_MBOX, tid, 21, 3));
        assert!(!contains_event(FAULTSIG_MBOX, tid, 24, 3));
        assert_eq!(
            decode(FAULTSIG_MBOX, tid, 21, 3),
            "FAULTSIG_MBOX tid=74001 slot=21 state=host-working"
        );

        let unavailable = FaultSignalRecord {
            tid: tid + 1,
            mm_key: None,
            walk: None,
            requires_mm_mutation: false,
            from_el0_direct: false,
            access: RingAccess::Unknown,
            ..record
        };
        rec_fault_signal(&unavailable, None, std::iter::empty());
        assert_eq!(
            decoded(latest_event(FAULTSIG, tid + 1).expect("no-walk signal")),
            "FAULTSIG tid=74002 mm=0 signal=11 si_code=2 mutating=false walk=unavailable access=unknown direct=false"
        );
        assert_eq!(
            decoded(latest_event(FAULTSIG_MBOXES, tid + 1).expect("empty census")),
            "FAULTSIG_MBOXES tid=74002 busy=0 own_slot=none mask0_31=0x00000000"
        );
    }

    #[test]
    fn mm_occupancy_refusal_round_trips() {
        rec_mm_occupancy_refused(75, 0x1_0000_0004, 9);
        assert!(contains_event(MMOCC_REFUSE, 75, 4, 9));
        assert_eq!(
            decode(MMOCC_REFUSE, 75, 4, 9),
            "MMOCC_REFUSE slot=75 running_mm=4 requested_mm=9"
        );
    }

    /// A private copy of the two-ring geometry, so a flood cannot evict the
    /// records other tests in this binary publish into the global rings.
    struct LocalRings {
        lifecycle: Box<[Slot; N]>,
        lifecycle_idx: AtomicU64,
        high_rate: Box<[Slot; N]>,
        high_rate_idx: AtomicU64,
    }

    impl LocalRings {
        fn new() -> Self {
            Self {
                lifecycle: Box::new(std::array::from_fn(|_| empty_slot())),
                lifecycle_idx: AtomicU64::new(0),
                high_rate: Box::new(std::array::from_fn(|_| empty_slot())),
                high_rate_idx: AtomicU64::new(0),
            }
        }

        /// Exactly `rec`'s routing, into the private rings.
        fn rec(&self, kind: u8, a: i32, b: i32, c: i32) {
            match ring_for_kind(kind) {
                RingSelect::Lifecycle => {
                    publish(&self.lifecycle, &self.lifecycle_idx, kind, a, b, c)
                }
                RingSelect::HighRate => {
                    publish(&self.high_rate, &self.high_rate_idx, kind, a, b, c)
                }
            }
        }

        fn lifecycle_contains(&self, kind: u8, a: i32, b: i32, c: i32) -> bool {
            let total = self.lifecycle_idx.load(Ordering::Acquire);
            (total.saturating_sub(N as u64)..total).any(|logical_index| {
                read_slot(
                    &self.lifecycle[(logical_index % N as u64) as usize],
                    logical_index,
                )
                .is_ok_and(|event| {
                    event.kind == kind && event.a == a && event.b == b && event.c == c
                })
            })
        }
    }

    /// A spinning scheduler must not evict lifecycle history. The `go build`
    /// hang capture (gbhang4) held 8192 SCHED_DISPATCH/SCHED_BUDGET/EPWAIT
    /// records from one tid and nothing else.
    #[test]
    fn a_scheduler_spin_does_not_evict_lifecycle_records() {
        let rings = LocalRings::new();
        let marker = 0x5eed_0001;
        rings.rec(FORK, marker, 0, 0);
        for index in 0..(N as i32 + 64) {
            rings.rec(SCHED_DISPATCH, 0x5eed_0002, 1, index);
            rings.rec(SCHED_BUDGET, 0x5eed_0002, 4, index);
            rings.rec(EPWAIT, 0x5eed_0002, 0, index);
        }
        assert!(
            rings.lifecycle_contains(FORK, marker, 0, 0),
            "a lifecycle record was overwritten by high-rate scheduler records"
        );
        assert_eq!(rings.lifecycle_idx.load(Ordering::Acquire), 1);
    }

    #[test]
    fn each_kind_lands_in_exactly_its_ring() {
        let high_rate = [
            EPWAIT,
            EPWFD,
            EPMASK,
            EPMASKFD,
            EPEDGE,
            EFDWRITE,
            EFDREAD,
            FUTEXWAIT,
            FUTEXWAKE,
            FUTEXEND,
            EPREADY,
            EPWAKE,
            EPCMSUM,
            SCHED_DISPATCH,
            SCHED_PREEMPT,
            SCHED_BUDGET,
            SCHED_DEADLINE,
        ];
        for kind in (BIND..=LAST_KIND).chain(ALIAS_MUTATION..=ALIAS_END) {
            let expected = if high_rate.contains(&kind) {
                RingSelect::HighRate
            } else {
                RingSelect::Lifecycle
            };
            assert_eq!(ring_for_kind(kind), expected, "kind {kind}");
            let other = match expected {
                RingSelect::Lifecycle => RingSelect::HighRate,
                RingSelect::HighRate => RingSelect::Lifecycle,
            };
            let marker = 0x7a00_0000 | i32::from(kind);
            rec(kind, marker, -1, 0x7a7a);
            assert!(
                ring_contains(expected, kind, marker, -1, 0x7a7a),
                "kind {kind} missing from {expected:?}"
            );
            assert!(
                !ring_contains(other, kind, marker, -1, 0x7a7a),
                "kind {kind} leaked into {other:?}"
            );
        }
        // The fault/grant/fd forensics this ring split exists to protect.
        for kind in [
            FORK,
            EXEC,
            FDOPEN,
            FDCLOSE,
            HVPWAIT,
            FAULTSIG,
            EL1GRANT_CLAIM,
            ALIAS_MUTATION,
        ] {
            assert_eq!(ring_for_kind(kind), RingSelect::Lifecycle);
        }
        assert!(
            drain_recent_high_rate(N)
                .into_iter()
                .filter_map(Result::ok)
                .all(|event| is_high_rate(event.kind))
        );
    }
}
