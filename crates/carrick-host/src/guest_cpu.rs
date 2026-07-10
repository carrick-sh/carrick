//! Guest CPU-time accounting via the Darwin hypervisor's per-vCPU execution
//! clock (`hv_vcpu_get_exec_time`).
//!
//! HVF guest execution does NOT accrue to the host thread's
//! rusage/`thread_info` — `proc_pid_rusage` drastically under-reports a guest's
//! CPU burn (measured: a loop that costs 275 ms on real Linux shows ~6 ms of
//! host CPU under carrick, because the cycles run in the hypervisor, not the
//! carrick thread). The hypervisor exposes the *true* cumulative per-vCPU run
//! time instead, which is the source of truth for the guest's user-mode CPU
//! time (`getrusage`/`times`/`/proc/<pid>/stat`).
//!
//! Each vCPU run accumulates the wall time it spent inside `hv_vcpu_run` (where
//! the vCPU thread is on-CPU executing guest code — blocking guest syscalls
//! trap OUT of `run` and wait in carrick host code, so `run` time tracks actual
//! guest execution, not idle waiting). `hv_vcpu_get_exec_time` was measured to
//! under-report this ~40×, so it is not used. Readers take the process-wide sum
//! across vCPUs. State is per-process — a forked guest is a separate host
//! process with its own table (`reset` clears the inherited parent entries in
//! the child) — so each process reports only its own guest threads, matching
//! Linux's per-process CPU accounting.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use carrick_kernel::arena::{ArenaError, KernelArena};
use carrick_kernel::domains::{HostPid, ProcessGeneration};
use carrick_kernel::process::{
    FLAG_ADOPTED, FLAG_ALIVE, ProcessRecord, ProcessRecordRef, ProcessSection, REGISTERING,
    VirtualPtraceControl, VirtualPtraceState,
};

/// Per-vCPU accumulated guest execution nanoseconds, one atomic slot per vCPU
/// thread. `add` is called on EVERY vCPU run (every guest syscall), so it must
/// be lock-free — a global lock here serialized all vCPU threads on every
/// syscall and throttled multi-threaded guests (e.g. Go's netpoller +
/// goroutine M's). Each thread claims a slot once and `fetch_add`s into it;
/// readers sum the array. Slots are intentionally not recycled: the value in a
/// departed thread's slot remains part of process-total CPU time, and recycling
/// through TLS destructors would complicate fork reset semantics. 512 slots
/// covers realistic active-lifetime vCPU thread counts; overflow shares the
/// last slot, which preserves total accounting because updates are atomic.
const MAX_VCPUS: usize = 512;
#[allow(clippy::declare_interior_mutable_const)]
static EXEC_SLOTS: [AtomicU64; MAX_VCPUS] = [const { AtomicU64::new(0) }; MAX_VCPUS];
static ACTIVE_START_NS: [AtomicU64; MAX_VCPUS] = [const { AtomicU64::new(0) }; MAX_VCPUS];
static NEXT_SLOT: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// This vCPU thread's slot index, claimed once. Capped at the last slot if
    /// somehow exceeded (degrades to shared accounting rather than UB).
    static MY_SLOT: usize = NEXT_SLOT.fetch_add(1, Ordering::Relaxed).min(MAX_VCPUS - 1);
}

fn monotonic_ns() -> u64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now)
        .elapsed()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}

/// Mark this vCPU thread as actively executing guest code. Called immediately
/// before `hv_vcpu_run` so readers can include the in-flight run before it traps
/// back and is committed to `EXEC_SLOTS`.
pub fn begin_active() {
    MY_SLOT.with(|&slot| {
        ACTIVE_START_NS[slot].store(monotonic_ns().max(1), Ordering::Release);
    });
}

/// Add `delta_ns` of guest execution to this vCPU's running total. Called from
/// the trap engine after each `hv_vcpu_run`; lock-free (a thread-local read +
/// one relaxed `fetch_add`).
pub fn add(delta_ns: u64) {
    if delta_ns == 0 {
        return;
    }
    MY_SLOT.with(|&slot| {
        EXEC_SLOTS[slot].fetch_add(delta_ns, Ordering::Relaxed);
    });
}

/// Commit a completed `hv_vcpu_run` and clear this thread's in-flight marker.
pub fn finish_active(delta_ns: u64) {
    add(delta_ns);
    MY_SLOT.with(|&slot| {
        ACTIVE_START_NS[slot].store(0, Ordering::Release);
    });
}

/// Time one vCPU run: mark this thread active, invoke `run`, and commit the
/// elapsed guest-CPU nanoseconds. The per-backend run-loop CPU-accounting wrapper
/// single-sourced — every aarch64/x86 trap loop (`hv_vcpu_run`, `KVM_RUN`, the
/// shared x86 engine) wraps its run the same way, so a new backend gets correct
/// `getrusage`/`times`/`/proc` guest CPU time by calling this instead of copying
/// the `Instant::now()` / `begin_active` / `finish_active` dance. Returns `run`'s
/// value unchanged.
pub fn timed_run<T>(run: impl FnOnce() -> T) -> T {
    let start = std::time::Instant::now();
    begin_active();
    let result = run();
    finish_active(start.elapsed().as_nanos().min(u64::MAX as u128) as u64);
    result
}

/// Process-wide guest CPU time (nanoseconds): the sum across all vCPU slots.
pub fn total_ns() -> u64 {
    EXEC_SLOTS.iter().map(|s| s.load(Ordering::Relaxed)).sum()
}

/// Process-wide guest CPU time including active `hv_vcpu_run` calls that have
/// not trapped back to the runtime yet.
pub fn total_ns_including_active() -> u64 {
    let now = monotonic_ns();
    EXEC_SLOTS
        .iter()
        .zip(ACTIVE_START_NS.iter())
        .map(|(total, active_start)| {
            let committed = total.load(Ordering::Relaxed);
            let start = active_start.load(Ordering::Acquire);
            if start == 0 {
                committed
            } else {
                committed.saturating_add(now.saturating_sub(start))
            }
        })
        .sum()
}

/// Number of vCPU threads currently inside `hv_vcpu_run`.
pub fn active_count() -> usize {
    ACTIVE_START_NS
        .iter()
        .filter(|start| start.load(Ordering::Acquire) != 0)
        .count()
}

/// Process-wide guest CPU time in microseconds (the unit accounting surfaces
/// use), including in-flight vCPU runs. Saturating.
pub fn total_us() -> u64 {
    total_ns_including_active() / 1000
}

/// THIS vCPU thread's own accumulated guest CPU time in microseconds (including
/// an in-flight run). For getrusage(RUSAGE_THREAD): the guest's getrusage traps
/// out and runs the dispatch ON its own vCPU thread, so this thread's slot is the
/// calling guest thread's CPU. Saturating.
pub fn this_thread_us() -> u64 {
    MY_SLOT.with(|&slot| {
        let committed = EXEC_SLOTS[slot].load(Ordering::Relaxed);
        let start = ACTIVE_START_NS[slot].load(Ordering::Acquire);
        let ns = if start == 0 {
            committed
        } else {
            committed.saturating_add(monotonic_ns().saturating_sub(start))
        };
        ns / 1000
    })
}

/// Clear per-process state in a freshly `fork`ed child: its vCPU starts a new
/// exec clock at zero and it has not waited any children of its own. (The
/// shared child-exit table is process-shared and intentionally NOT cleared.)
pub fn reset() {
    for slot in &EXEC_SLOTS {
        slot.store(0, Ordering::Relaxed);
    }
    for slot in &ACTIVE_START_NS {
        slot.store(0, Ordering::Relaxed);
    }
    CHILD_USER_US.store(0, Ordering::Relaxed);
    CHILD_SYS_US.store(0, Ordering::Relaxed);
}

// ---- Child metadata and CPU accounting (getrusage RUSAGE_CHILDREN, times cutime) ----
//
// A guest's child runs as a separate host process, so its guest CPU time lives
// in the child's own `EXEC_NS` table and dies with it. Linux rolls a reaped
// child's CPU into the parent's child-time totals; to match, an exiting child
// publishes its guest CPU into a process-SHARED table (created before any fork
// so the MAP_SHARED region is inherited), and the parent drains it at `wait4`
// into its per-process child accumulators below. The same live-child row also
// carries low-volume wait metadata that the parent must observe before terminal
// reap, such as pending ptrace signal-delivery stops. The host-side child CPU
// comes from Darwin's own `wait4` rusage out-param (added by the caller).

/// Per-process accumulated child CPU (microseconds), summed over reaped
/// children. NOT shared across fork — each process tracks the children IT
/// reaped, and `reset()` zeroes them in a forked child.
static CHILD_USER_US: AtomicU64 = AtomicU64::new(0);
static CHILD_SYS_US: AtomicU64 = AtomicU64::new(0);

const RUN_STATE_KIND_TID: u64 = 1 << 40;
const REF_NONE: u64 = u64::MAX;
const REF_INDEX_MASK: u64 = 0xffff_ffff;

static PENDING_CHILD_RECORD: AtomicU64 = AtomicU64::new(REF_NONE);

/// Ensure the arena exists before any `fork`, so every descendant inherits the
/// same process section. Idempotent.
pub fn init_child_table() {
    let _ = KernelArena::init_global();
}

fn process_section() -> &'static ProcessSection {
    &KernelArena::global().layout().processes
}

fn process_records() -> &'static [ProcessRecord] {
    &process_section().records
}

fn pack_ref(r: ProcessRecordRef) -> u64 {
    (u64::from(r.generation.raw()) << 32) | (r.index as u64)
}

fn unpack_ref(raw: u64) -> Option<ProcessRecordRef> {
    if raw == REF_NONE {
        return None;
    }
    let index = (raw & REF_INDEX_MASK) as usize;
    let generation = (raw >> 32) as u32;
    if generation == 0 {
        return None;
    }
    Some(ProcessRecordRef {
        index,
        generation: ProcessGeneration::new(generation),
    })
}

fn record_pid(record: &ProcessRecord) -> u32 {
    record.host_pid.load(Ordering::Acquire)
}

fn record_is_tid_entry(record: &ProcessRecord) -> bool {
    record.run_state.load(Ordering::Acquire) & RUN_STATE_KIND_TID != 0
}

fn record_generation(record: &ProcessRecord) -> Option<ProcessGeneration> {
    let generation = record.generation.load(Ordering::Acquire);
    (generation != 0).then(|| ProcessGeneration::new(generation))
}

fn find_child_record(pid: u32) -> Option<ProcessRecordRef> {
    for (index, record) in process_records().iter().enumerate() {
        if record_pid(record) != pid || record_is_tid_entry(record) {
            continue;
        }
        if let Some(generation) = record_generation(record) {
            return Some(ProcessRecordRef { index, generation });
        }
    }
    None
}

fn record_for_ref(r: ProcessRecordRef) -> Option<&'static ProcessRecord> {
    let record = process_records().get(r.index)?;
    let generation = record_generation(record)?;
    (generation == r.generation).then_some(record)
}

fn child_record(pid: u32) -> Option<&'static ProcessRecord> {
    find_child_record(pid).and_then(record_for_ref)
}

fn claim_child_record(pid: u32, fill: impl FnOnce(&ProcessRecord)) -> ProcessRecordRef {
    if let Some(r) = find_child_record(pid) {
        let Some(record) = record_for_ref(r) else {
            abort_on_arena_error(ArenaError::Exhausted {
                section: "processes",
                capacity: process_records().len(),
            });
        };
        fill(record);
        return r;
    }

    let generation = KernelArena::global().allocate_generation();
    match process_section().claim(Some(HostPid::new(pid)), generation, fill) {
        Ok(r) => r,
        Err(err) => abort_on_arena_error(err),
    }
}

fn abort_on_arena_error(err: ArenaError) -> ! {
    eprintln!("carrick: child metadata arena publication failed: {err:?}");
    std::process::abort();
}

/// Claim and fill a child process record before `fork(2)` publishes the child's
/// host pid. The pending ref is inherited by the fork child; both parent and
/// child publish the same host pid after fork, which is intentionally idempotent.
///
/// Exhaustion is an `Err`, NOT an abort: a guest that forks children nobody
/// reaps (SIGCHLD ignored, parent exited without a subreaper) can legitimately
/// fill the section, and `fork(2)` must then fail with Linux `EAGAIN` (spec
/// "Failure model") while the rest of the guest keeps running. On `Err`,
/// nothing was claimed and the pending-child stash is untouched.
pub fn prepare_child_record_pre_fork(
    parent_pid: u32,
    subreaper_pid: u32,
    ns_pid: u32,
    adopted: bool,
    ptrace_stop_signal: u64,
) -> Result<ProcessRecordRef, ArenaError> {
    init_child_table();
    let r = prepare_child_record_in(
        KernelArena::global(),
        parent_pid,
        subreaper_pid,
        ns_pid,
        adopted,
        ptrace_stop_signal,
    )?;
    PENDING_CHILD_RECORD.store(pack_ref(r), Ordering::Release);
    Ok(r)
}

fn prepare_child_record_in(
    arena: &KernelArena,
    parent_pid: u32,
    subreaper_pid: u32,
    ns_pid: u32,
    adopted: bool,
    ptrace_stop_signal: u64,
) -> Result<ProcessRecordRef, ArenaError> {
    let generation = arena.allocate_generation();
    arena.layout().processes.claim(None, generation, |record| {
        record.parent_host_pid.store(parent_pid, Ordering::Release);
        record.subreaper_pid.store(subreaper_pid, Ordering::Release);
        record.ns_pid.store(ns_pid, Ordering::Release);
        record
            .ptrace_stop_signal
            .store(ptrace_stop_signal, Ordering::Release);
        record.flags.fetch_or(FLAG_ALIVE, Ordering::AcqRel);
        set_adopted(record, adopted);
    })
}

/// Parent-side publish by the ref `prepare_child_record_pre_fork` returned.
///
/// The parent publishes AFTER `end_fork` releases fork serialization, so the
/// process-global stash may already hold a DIFFERENT thread's prepared record
/// (back-to-back forks from two threads). Publishing by ref stamps the record
/// this fork prepared; the stash stays the fork CHILD's channel (its memory
/// snapshot at `fork(2)` is taken inside the serialized window, so the
/// inherited stash is always this fork's ref).
pub fn publish_prepared_child_record_parent_ref(r: ProcessRecordRef, child_pid: u32) {
    process_section().publish_host_pid(r, HostPid::new(child_pid));
}

pub fn complete_child_record_post_fork_child() {
    let Some(r) = unpack_ref(PENDING_CHILD_RECORD.swap(REF_NONE, Ordering::AcqRel)) else {
        return;
    };
    process_section().publish_host_pid(r, HostPid::new(std::process::id()));
    if let Some(record) = record_for_ref(r) {
        let recorded_parent = record_parent_pid(record);
        let host_parent = unsafe { libc::getppid() };
        if recorded_parent != 0 && recorded_parent != host_parent as u32 {
            set_adopted(record, true);
        }
    }
}

pub fn abort_prepared_child_record() {
    let Some(r) = unpack_ref(PENDING_CHILD_RECORD.swap(REF_NONE, Ordering::AcqRel)) else {
        return;
    };
    process_section().release(r);
}

fn adopted_flag(record: &ProcessRecord) -> bool {
    record.flags.load(Ordering::Acquire) & FLAG_ADOPTED != 0
}

fn set_adopted(record: &ProcessRecord, adopted: bool) {
    if adopted {
        record.flags.fetch_or(FLAG_ADOPTED, Ordering::AcqRel);
    } else {
        record.flags.fetch_and(!FLAG_ADOPTED, Ordering::AcqRel);
    }
}

fn release_child_record(r: ProcessRecordRef) {
    process_section().release(r);
}

fn release_child_pid(pid: u32) {
    if let Some(r) = find_child_record(pid) {
        release_child_record(r);
    }
}

fn iter_child_records() -> impl Iterator<Item = &'static ProcessRecord> {
    process_records().iter().filter(|record| {
        let pid = record_pid(record);
        pid != 0 && pid != REGISTERING && !record_is_tid_entry(record)
    })
}

fn record_host_pid(record: &ProcessRecord) -> u32 {
    record.host_pid.load(Ordering::Acquire)
}

fn record_parent_pid(record: &ProcessRecord) -> u32 {
    record.parent_host_pid.load(Ordering::Acquire)
}

fn record_subreaper_pid(record: &ProcessRecord) -> u32 {
    record.subreaper_pid.load(Ordering::Acquire)
}

fn record_exit_ready(record: &ProcessRecord) -> bool {
    record.exit_ready.load(Ordering::Acquire) != 0
}

const PTRACE_STOP_SIGNAL_MASK: u64 = u32::MAX as u64;

fn ptrace_stop_word(sequence: u32, signum: u32) -> u64 {
    (u64::from(sequence) << 32) | u64::from(signum)
}

fn ptrace_stop_word_sequence(word: u64) -> u32 {
    (word >> 32) as u32
}

fn ptrace_stop_word_signal(word: u64) -> u64 {
    word & PTRACE_STOP_SIGNAL_MASK
}

fn record_ptrace_stop_word(record: &ProcessRecord) -> u64 {
    record.ptrace_stop_signal.load(Ordering::Acquire)
}

#[cfg(test)]
fn record_ptrace_stop_signal(record: &ProcessRecord) -> u64 {
    ptrace_stop_word_signal(record_ptrace_stop_word(record))
}

fn record_virtual_ptrace_control(record: &ProcessRecord) -> Option<VirtualPtraceControl> {
    VirtualPtraceControl::decode_shared(record.ptrace_control.load(Ordering::Acquire))
}

fn transition_virtual_ptrace_control(
    record: &ProcessRecord,
    from: VirtualPtraceControl,
    to: VirtualPtraceControl,
) -> bool {
    record
        .ptrace_control
        .compare_exchange(from.raw(), to.raw(), Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

fn clear_virtual_ptrace(record: &ProcessRecord) {
    record
        .ptrace_control
        .store(VirtualPtraceControl::untraced().raw(), Ordering::Release);
    let mut current = record_ptrace_stop_word(record);
    loop {
        let cleared = current & !PTRACE_STOP_SIGNAL_MASK;
        match record.ptrace_stop_signal.compare_exchange_weak(
            current,
            cleared,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

fn record_guest_ns(record: &ProcessRecord) -> u64 {
    record.guest_ns.load(Ordering::Acquire)
}

fn record_ns_pid(record: &ProcessRecord) -> u32 {
    record.ns_pid.load(Ordering::Acquire)
}

fn record_exit_status(record: &ProcessRecord) -> i32 {
    record.exit_status.load(Ordering::Acquire) as u32 as i32
}

fn ref_for_record(record: &ProcessRecord) -> Option<ProcessRecordRef> {
    let base = process_records().as_ptr() as usize;
    let ptr = std::ptr::from_ref(record) as usize;
    let index = (ptr.checked_sub(base)?) / std::mem::size_of::<ProcessRecord>();
    record_generation(record).map(|generation| ProcessRecordRef { index, generation })
}

fn release_record(record: &ProcessRecord) {
    if let Some(r) = ref_for_record(record) {
        release_child_record(r);
    }
}

fn store_exit_status(record: &ProcessRecord, status: i32) {
    record
        .exit_status
        .store(status as u32 as u64, Ordering::Release);
}

fn store_exit_ready(record: &ProcessRecord, ready: bool) {
    record.exit_ready.store(u32::from(ready), Ordering::Release);
}

/// Reparent every live child of `parent_pid` to its recorded nearest subreaper.
pub fn adopt_children_of(parent_pid: u32) {
    for record in iter_child_records() {
        if record_parent_pid(record) == parent_pid {
            let subreaper = record_subreaper_pid(record);
            if subreaper != 0 {
                record.parent_host_pid.store(subreaper, Ordering::Release);
                set_adopted(record, true);
            }
        }
    }
}

/// If the current process has been adopted by a subreaper, return that ppid.
pub fn adopted_parent_for_self() -> Option<u32> {
    adopted_parent_for(std::process::id())
}

/// Adopted parent to notify when `pid` exits, if any.
pub fn adopted_parent_for(pid: u32) -> Option<u32> {
    let record = child_record(pid)?;
    adopted_flag(record)
        .then(|| record_parent_pid(record))
        .filter(|p| *p != 0)
}

/// Mark the current process as having an unreported ptrace signal stop.
pub fn mark_self_ptrace_stop_pending(signum: i32) {
    let pid = std::process::id();
    claim_child_record(pid, |record| {
        record
            .ptrace_stop_signal
            .store(signum.max(0) as u64, Ordering::Release);
    });
}

/// Register the current process as a Darwin-native virtual ptrace tracee.
/// The tracer must be the parent recorded before `fork(2)` published this slot.
pub fn register_self_virtual_ptrace(tracer_pid: u32) -> bool {
    if tracer_pid == 0 {
        return false;
    }
    let pid = std::process::id();
    let Some(r) = find_child_record(pid) else {
        return false;
    };
    let Some(record) = record_for_ref(r) else {
        return false;
    };
    let untraced = VirtualPtraceControl::untraced();
    let Some(running) =
        VirtualPtraceControl::traced(tracer_pid, r.generation, VirtualPtraceState::Running)
    else {
        return false;
    };
    if record_parent_pid(record) != tracer_pid
        || record_virtual_ptrace_control(record) != Some(untraced)
    {
        return false;
    }
    transition_virtual_ptrace_control(record, untraced, running)
}

fn virtual_ptrace_record(
    pid: u32,
    tracer_pid: u32,
) -> Option<(
    ProcessRecordRef,
    &'static ProcessRecord,
    VirtualPtraceControl,
)> {
    let r = find_child_record(pid)?;
    let record = record_for_ref(r)?;
    let control = record_virtual_ptrace_control(record)?;
    (record_pid(record) == pid
        && record_parent_pid(record) == tracer_pid
        && control.tracer_pid() == tracer_pid
        && control.generation() == r.generation)
        .then_some((r, record, control))
}

/// Capability for one exact, reported Linux ptrace stop.
///
/// The record generation and stop sequence keep a stale tracer operation from
/// controlling a later process or a later stop that reused the same numeric PID.
/// The tracer runtime must also retain this token as an exclusive wait lease
/// until control finishes: Darwin signals by numeric PID and exposes no
/// signal-capable process descriptor, so a competing terminal `wait4` must not
/// reap the stopped child between the final record check and `kill(2)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtualPtraceStop {
    record: ProcessRecordRef,
    tracee_pid: u32,
    tracer_pid: u32,
    sequence: u32,
    linux_signum: i32,
}

impl VirtualPtraceStop {
    pub const fn linux_signum(self) -> i32 {
        self.linux_signum
    }
}

fn virtual_ptrace_record_for_stop(
    stop: VirtualPtraceStop,
    state: VirtualPtraceState,
) -> Option<&'static ProcessRecord> {
    if std::process::id() != stop.tracer_pid {
        return None;
    }
    let record = record_for_ref(stop.record)?;
    let expected = VirtualPtraceControl::traced(stop.tracer_pid, stop.record.generation, state)?;
    let stop_word = record_ptrace_stop_word(record);
    (record_pid(record) == stop.tracee_pid
        && record_parent_pid(record) == stop.tracer_pid
        && ptrace_stop_word_sequence(stop_word) == stop.sequence
        && ptrace_stop_word_signal(stop_word) == stop.linux_signum as u64
        && record_virtual_ptrace_control(record) == Some(expected))
    .then_some(record)
}

/// Whether the current process still has an active virtual ptrace owner.
pub fn self_is_virtual_ptrace_tracee() -> bool {
    let pid = std::process::id();
    let Some(r) = find_child_record(pid) else {
        return false;
    };
    let Some(record) = record_for_ref(r) else {
        return false;
    };
    let Some(control) = record_virtual_ptrace_control(record) else {
        return false;
    };
    let tracer_pid = control.tracer_pid();
    tracer_pid != 0
        && !matches!(
            control.state(),
            VirtualPtraceState::Untraced | VirtualPtraceState::DetachRequested
        )
        && record_parent_pid(record) == tracer_pid
        && control.generation() == r.generation
}

/// Publish a Linux signal-delivery stop before the tracee raises host SIGSTOP.
pub fn request_self_virtual_ptrace_stop(signum: i32) -> bool {
    let Ok(signum) = u32::try_from(signum) else {
        return false;
    };
    if signum == 0 {
        return false;
    }
    let pid = std::process::id();
    let Some(r) = find_child_record(pid) else {
        return false;
    };
    let Some(record) = record_for_ref(r) else {
        return false;
    };
    let Some(control) = record_virtual_ptrace_control(record) else {
        return false;
    };
    let tracer_pid = control.tracer_pid();
    let Some((r, record, control)) = virtual_ptrace_record(pid, tracer_pid) else {
        return false;
    };
    if control.state() != VirtualPtraceState::Running {
        return false;
    }
    let Some(preparing) =
        VirtualPtraceControl::traced(tracer_pid, r.generation, VirtualPtraceState::StopPreparing)
    else {
        return false;
    };
    let Some(requested) =
        VirtualPtraceControl::traced(tracer_pid, r.generation, VirtualPtraceState::StopRequested)
    else {
        return false;
    };
    if !transition_virtual_ptrace_control(record, control, preparing) {
        return false;
    }
    let previous_word = record_ptrace_stop_word(record);
    let previous_sequence = ptrace_stop_word_sequence(previous_word);
    let wrapped = previous_sequence.wrapping_add(1);
    let sequence = if wrapped == 0 { 1 } else { wrapped };
    let published_word = ptrace_stop_word(sequence, signum);
    record
        .ptrace_stop_signal
        .store(published_word, Ordering::Release);
    if transition_virtual_ptrace_control(record, preparing, requested) {
        return true;
    }
    let _ = record.ptrace_stop_signal.compare_exchange(
        published_word,
        previous_word,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    false
}

/// Whether `pid` has requested a virtual ptrace stop for `tracer_pid`.
pub fn child_virtual_ptrace_stop_requested(pid: u32) -> bool {
    let tracer_pid = std::process::id();
    virtual_ptrace_record(pid, tracer_pid)
        .is_some_and(|(_, _, control)| control.state() == VirtualPtraceState::StopRequested)
}

/// Convert one confirmed host SIGSTOP into exactly one Linux ptrace stop.
pub fn report_child_virtual_ptrace_stop(pid: u32) -> Option<VirtualPtraceStop> {
    let tracer_pid = std::process::id();
    let (r, record, requested) = virtual_ptrace_record(pid, tracer_pid)?;
    if requested.state() != VirtualPtraceState::StopRequested {
        return None;
    }
    let stop_word = record_ptrace_stop_word(record);
    let linux_signum = i32::try_from(ptrace_stop_word_signal(stop_word))
        .ok()
        .filter(|signum| *signum != 0)?;
    let sequence = ptrace_stop_word_sequence(stop_word);
    if sequence == 0 {
        return None;
    }
    let reported =
        VirtualPtraceControl::traced(tracer_pid, r.generation, VirtualPtraceState::StopReported)?;
    if !transition_virtual_ptrace_control(record, requested, reported) {
        return None;
    }
    Some(VirtualPtraceStop {
        record: r,
        tracee_pid: pid,
        tracer_pid,
        sequence,
        linux_signum,
    })
}

fn begin_virtual_ptrace_control(stop: VirtualPtraceStop, state: VirtualPtraceState) -> Option<()> {
    let record = virtual_ptrace_record_for_stop(stop, VirtualPtraceState::StopReported)?;
    let reported = VirtualPtraceControl::traced(
        stop.tracer_pid,
        stop.record.generation,
        VirtualPtraceState::StopReported,
    )?;
    let requested = VirtualPtraceControl::traced(stop.tracer_pid, stop.record.generation, state)?;
    if !transition_virtual_ptrace_control(record, reported, requested) {
        return None;
    }
    Some(())
}

fn rollback_virtual_ptrace_control(stop: VirtualPtraceStop, state: VirtualPtraceState) -> bool {
    let Some(record) = virtual_ptrace_record_for_stop(stop, state) else {
        return false;
    };
    let Some(from) = VirtualPtraceControl::traced(stop.tracer_pid, stop.record.generation, state)
    else {
        return false;
    };
    let Some(reported) = VirtualPtraceControl::traced(
        stop.tracer_pid,
        stop.record.generation,
        VirtualPtraceState::StopReported,
    ) else {
        return false;
    };
    transition_virtual_ptrace_control(record, from, reported)
}

/// Resume a reported virtual ptrace stop using host SIGCONT.
pub fn resume_child_virtual_ptrace(stop: VirtualPtraceStop) -> bool {
    if begin_virtual_ptrace_control(stop, VirtualPtraceState::ResumeRequested).is_none() {
        return false;
    }
    let Some(record) = virtual_ptrace_record_for_stop(stop, VirtualPtraceState::ResumeRequested)
    else {
        let _ = rollback_virtual_ptrace_control(stop, VirtualPtraceState::ResumeRequested);
        return false;
    };
    let Some(resume_requested) = VirtualPtraceControl::traced(
        stop.tracer_pid,
        stop.record.generation,
        VirtualPtraceState::ResumeRequested,
    ) else {
        let _ = rollback_virtual_ptrace_control(stop, VirtualPtraceState::ResumeRequested);
        return false;
    };
    let Some(running) = VirtualPtraceControl::traced(
        stop.tracer_pid,
        stop.record.generation,
        VirtualPtraceState::Running,
    ) else {
        let _ = rollback_virtual_ptrace_control(stop, VirtualPtraceState::ResumeRequested);
        return false;
    };
    if !transition_virtual_ptrace_control(record, resume_requested, running) {
        let _ = rollback_virtual_ptrace_control(stop, VirtualPtraceState::ResumeRequested);
        return false;
    }
    if virtual_ptrace_record_for_stop(stop, VirtualPtraceState::Running).is_none() {
        let _ = rollback_virtual_ptrace_control(stop, VirtualPtraceState::Running);
        return false;
    }
    if unsafe { libc::kill(stop.tracee_pid as i32, libc::SIGCONT) } == 0 {
        return true;
    }
    let _ = rollback_virtual_ptrace_control(stop, VirtualPtraceState::Running);
    false
}

/// Kill a reported virtual ptrace tracee using host SIGKILL.
pub fn kill_child_virtual_ptrace(stop: VirtualPtraceStop) -> bool {
    if begin_virtual_ptrace_control(stop, VirtualPtraceState::KillRequested).is_none() {
        return false;
    }
    if virtual_ptrace_record_for_stop(stop, VirtualPtraceState::KillRequested).is_none() {
        let _ = rollback_virtual_ptrace_control(stop, VirtualPtraceState::KillRequested);
        return false;
    }
    if unsafe { libc::kill(stop.tracee_pid as i32, libc::SIGKILL) } == 0 {
        return true;
    }
    let _ = rollback_virtual_ptrace_control(stop, VirtualPtraceState::KillRequested);
    false
}

/// Detach a reported virtual ptrace tracee and resume it with host SIGCONT.
pub fn detach_child_virtual_ptrace(stop: VirtualPtraceStop) -> bool {
    if begin_virtual_ptrace_control(stop, VirtualPtraceState::DetachRequested).is_none() {
        return false;
    }
    if virtual_ptrace_record_for_stop(stop, VirtualPtraceState::DetachRequested).is_none() {
        let _ = rollback_virtual_ptrace_control(stop, VirtualPtraceState::DetachRequested);
        return false;
    }
    if unsafe { libc::kill(stop.tracee_pid as i32, libc::SIGCONT) } != 0 {
        let _ = rollback_virtual_ptrace_control(stop, VirtualPtraceState::DetachRequested);
        return false;
    }
    let Some(record) = virtual_ptrace_record_for_stop(stop, VirtualPtraceState::DetachRequested)
    else {
        // The carrier was delivered and terminal cleanup won the race.
        return true;
    };
    let Some(detach_requested) = VirtualPtraceControl::traced(
        stop.tracer_pid,
        stop.record.generation,
        VirtualPtraceState::DetachRequested,
    ) else {
        return false;
    };
    if !transition_virtual_ptrace_control(
        record,
        detach_requested,
        VirtualPtraceControl::untraced(),
    ) {
        return record_virtual_ptrace_control(record) == Some(VirtualPtraceControl::untraced());
    }
    true
}

/// Clear and return the pending ptrace signal-stop marker once wait4 reports it.
pub fn take_child_ptrace_stop_signal(pid: u32) -> Option<i32> {
    let record = child_record(pid)?;
    let mut current = record_ptrace_stop_word(record);
    loop {
        if ptrace_stop_word_sequence(current) != 0 {
            // Virtual stops are immutable capabilities consumed through
            // `report_child_virtual_ptrace_stop`, never through this legacy
            // host-ptrace marker API.
            return None;
        }
        let signum = i32::try_from(ptrace_stop_word_signal(current))
            .ok()
            .filter(|signum| *signum != 0)?;
        match record.ptrace_stop_signal.compare_exchange_weak(
            current,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(signum),
            Err(actual) => current = actual,
        }
    }
}

/// Clear the pending ptrace signal-stop marker once wait4 reports it.
pub fn clear_child_ptrace_stop_pending(pid: u32) {
    let _ = take_child_ptrace_stop_signal(pid);
}

/// Whether `pid` has an unreported ptrace signal-delivery stop.
pub fn child_has_ptrace_stop_pending(pid: u32) -> bool {
    child_record(pid).is_some_and(record_has_ptrace_stop_pending)
}

fn record_has_ptrace_stop_pending(record: &ProcessRecord) -> bool {
    let stop_word = record_ptrace_stop_word(record);
    if ptrace_stop_word_signal(stop_word) == 0 {
        return false;
    }
    if ptrace_stop_word_sequence(stop_word) == 0 {
        return true;
    }
    record_virtual_ptrace_control(record)
        .is_some_and(|control| control.state() == VirtualPtraceState::StopRequested)
}

/// Whether any direct, non-adopted child of `waiter_pid` has an unreported
/// ptrace signal-delivery stop.
pub fn direct_child_ptrace_stop_pending(waiter_pid: u32) -> bool {
    for record in iter_child_records() {
        if adopted_flag(record) {
            continue;
        }
        if record_parent_pid(record) != waiter_pid {
            continue;
        }
        if record_has_ptrace_stop_pending(record) {
            return true;
        }
    }
    false
}

/// Publish an exiting child's total guest CPU (nanoseconds) for its parent to
/// reap. Called from the forked-child exit path.
pub fn record_child_exit(pid: u32, guest_ns: u64) {
    record_child_exit_status(pid, guest_ns, 0, false);
}

/// Publish an exiting child's guest CPU and, for adopted children, a wait status
/// the subreaper can consume even though the host kernel cannot wait it.
pub fn record_child_exit_status(pid: u32, guest_ns: u64, status: i32, status_ready: bool) {
    if let Some(record) = child_record(pid) {
        let status_ready = status_ready || adopted_flag(record);
        record.guest_ns.store(guest_ns, Ordering::Release);
        clear_virtual_ptrace(record);
        if status_ready {
            store_exit_status(record, status);
            store_exit_ready(record, true);
        }
        return;
    }

    claim_child_record(pid, |record| {
        record.guest_ns.store(guest_ns, Ordering::Release);
        clear_virtual_ptrace(record);
        if status_ready {
            store_exit_status(record, status);
            store_exit_ready(record, true);
        } else {
            store_exit_status(record, 0);
            store_exit_ready(record, false);
        }
    });
}

pub fn reap_adopted_child(waiter_pid: u32, target_pid: i32) -> Option<(u32, i32, u64)> {
    for record in iter_child_records() {
        let pid = record_host_pid(record);
        if !adopted_flag(record) {
            continue;
        }
        if record_parent_pid(record) != waiter_pid {
            continue;
        }
        if target_pid > 0 && pid != target_pid as u32 {
            continue;
        }
        if !record_exit_ready(record) {
            continue;
        }
        let status = record_exit_status(record);
        let ns = record_guest_ns(record);
        if record_ns_pid(record) == 0 {
            release_record(record);
        } else {
            record.guest_ns.store(0, Ordering::Release);
            clear_virtual_ptrace(record);
            store_exit_ready(record, false);
        }
        return Some((pid, status, ns));
    }
    None
}

/// Return an adopted child that this waiter should block on until it publishes
/// an exit status. `target_pid <= 0` means any adopted child, matching wait4's
/// any-child/process-group sentinel handling at this layer.
pub fn pending_adopted_child(waiter_pid: u32, target_pid: i32) -> Option<u32> {
    for record in iter_child_records() {
        let pid = record_host_pid(record);
        if !adopted_flag(record) {
            continue;
        }
        if record_parent_pid(record) != waiter_pid {
            continue;
        }
        if target_pid > 0 && pid != target_pid as u32 {
            continue;
        }
        if record_exit_ready(record) {
            continue;
        }
        return Some(pid);
    }
    None
}

/// Park target for a blocking `wait4(-1)`.
///
/// Returns `-1` whenever ANY direct child exists — the io_wait `-1` branch
/// (`wait_proc_exit_any_kqueue`) arms one `NOTE_EXIT` watch PER direct child.
/// Never substitutes a single child pid for `-1`: the single-pid slice loop
/// re-polls `child_status_ready` for ONLY the watched pid, so parking on the
/// first-listed child misses a sibling's exit (Linux returns the sibling
/// immediately; a first-child park blocks until the watched child dies).
/// With no direct children, an adopted child that is not yet exit-ready is a
/// concrete watchable pid (`EVFILT_PROC` watches non-children). With neither,
/// `None`: the caller reports `ECHILD` instead of parking forever.
pub fn wait_any_park_pid(waiter_pid: u32) -> Option<i32> {
    if !direct_children_for_wait(waiter_pid).is_empty() {
        return Some(-1);
    }
    pending_adopted_child(waiter_pid, -1).map(|pid| pid as i32)
}

/// Snapshot direct, non-adopted children of `waiter_pid` that can be watched
/// with host `EVFILT_PROC`/`NOTE_EXIT`.
///
/// Adopted children are deliberately excluded: their guest parent is no longer
/// the host parent, so the host kernel cannot deliver their exit to this waiter.
/// Those stay on the adopted-child table path.
pub fn direct_children_for_wait(waiter_pid: u32) -> Vec<u32> {
    let mut children = Vec::new();
    for record in iter_child_records() {
        if adopted_flag(record) {
            continue;
        }
        if record_parent_pid(record) != waiter_pid {
            continue;
        }
        children.push(record_host_pid(record));
    }
    children
}

/// Drain a child's published guest CPU nanoseconds (0 if none).
///
/// Namespace-member records also carry pid translation state, so they stay
/// published until the terminal namespace reap releases them. Non-namespace
/// child metadata remains owned by this table and is freed here.
pub fn reap_child_guest_ns(pid: u32) -> u64 {
    if let Some(record) = child_record(pid) {
        let ns = record_guest_ns(record);
        record.guest_ns.store(0, Ordering::Release);
        clear_virtual_ptrace(record);
        if record_ns_pid(record) == 0 {
            release_child_pid(pid);
        }
        return ns;
    }
    0
}

/// Accumulate a reaped child's CPU (microseconds) into this process's
/// child-time totals.
pub fn add_reaped_child(user_us: u64, system_us: u64) {
    CHILD_USER_US.fetch_add(user_us, Ordering::Relaxed);
    CHILD_SYS_US.fetch_add(system_us, Ordering::Relaxed);
}

/// This process's accumulated reaped-child user / system CPU (microseconds).
pub fn child_user_us() -> u64 {
    CHILD_USER_US.load(Ordering::Relaxed)
}
pub fn child_system_us() -> u64 {
    CHILD_SYS_US.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Register a (test) child through the production pre-fork path: claim +
    /// fill by the parent, then publish the child pid by ref. The legacy
    /// post-fork registration fns are deleted; every registration goes this
    /// way now.
    fn register_for_test(child: u32, parent: u32, subreaper: u32, adopted: bool) {
        let r = prepare_child_record_pre_fork(parent, subreaper, 0, adopted, 0)
            .expect("prepare child record");
        publish_prepared_child_record_parent_ref(r, child);
    }

    #[test]
    fn add_then_sum_accumulates() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        reset();
        add(1_000_000); // +1 ms
        add(2_000_000); // +2 ms (same test thread → same slot, accumulates)
        assert_eq!(total_ns(), 3_000_000);
        assert_eq!(total_us(), 3000);
        reset();
        assert_eq!(total_ns(), 0);
    }

    #[test]
    fn active_run_is_visible_before_commit() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        reset();
        begin_active();
        assert_eq!(active_count(), 1);
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(total_ns_including_active() > total_ns());
        assert!(total_us() > 0);
        finish_active(1_000_000);
        assert_eq!(active_count(), 0);
        assert_eq!(total_ns(), 1_000_000);
        reset();
    }

    #[test]
    fn child_ptrace_stop_marker_lives_until_report_or_reap() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let pid = 424_242;

        let _ = reap_child_guest_ns(pid);
        register_for_test(pid, 0, 0, false);
        assert!(!child_has_ptrace_stop_pending(pid));

        mark_ptrace_stop_pending_for_test(pid, 16);
        assert!(child_has_ptrace_stop_pending(pid));
        assert_eq!(take_child_ptrace_stop_signal(pid), Some(16));
        assert!(!child_has_ptrace_stop_pending(pid));

        clear_child_ptrace_stop_pending(pid);
        assert!(!child_has_ptrace_stop_pending(pid));

        mark_ptrace_stop_pending_for_test(pid, 30);

        record_child_exit(pid, 1234);
        assert!(!child_has_ptrace_stop_pending(pid));
        assert_eq!(reap_child_guest_ns(pid), 1234);
        assert!(!child_has_ptrace_stop_pending(pid));
    }

    #[test]
    fn virtual_ptrace_stop_is_reported_once_then_resumed() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let tracer_pid = std::process::id();
        let mut resumed_pipe = [-1; 2];
        let mut release_pipe = [-1; 2];
        assert_eq!(unsafe { libc::pipe(resumed_pipe.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { libc::pipe(release_pipe.as_mut_ptr()) }, 0);
        let prepared =
            prepare_child_record_pre_fork(tracer_pid, 0, 0, false, 0).expect("prepare child");

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            unsafe {
                libc::close(resumed_pipe[0]);
                libc::close(release_pipe[1]);
            }
            complete_child_record_post_fork_child();
            if !register_self_virtual_ptrace(tracer_pid)
                || !request_self_virtual_ptrace_stop(libc::SIGUSR2)
            {
                unsafe { libc::_exit(70) };
            }
            unsafe {
                libc::raise(libc::SIGSTOP);
                let byte = [1u8];
                libc::write(resumed_pipe[1], byte.as_ptr().cast(), byte.len());
                let mut release = [0u8];
                libc::read(release_pipe[0], release.as_mut_ptr().cast(), release.len());
                libc::_exit(42);
            }
        }

        unsafe {
            libc::close(resumed_pipe[1]);
            libc::close(release_pipe[0]);
        }
        publish_prepared_child_record_parent_ref(prepared, child as u32);
        let mut stop_status = 0;
        let stopped = unsafe { libc::waitpid(child, &mut stop_status, libc::WUNTRACED) };
        assert_eq!(stopped, child);
        assert!(libc::WIFSTOPPED(stop_status));
        assert_eq!(libc::WSTOPSIG(stop_status), libc::SIGSTOP);
        let reported =
            report_child_virtual_ptrace_stop(child as u32).expect("reported virtual stop");
        assert_eq!(reported.linux_signum(), libc::SIGUSR2);
        assert_eq!(
            report_child_virtual_ptrace_stop(child as u32),
            None,
            "one host stop must produce exactly one guest report"
        );
        let forged = VirtualPtraceStop {
            tracer_pid: tracer_pid.saturating_add(1),
            ..reported
        };
        assert!(!resume_child_virtual_ptrace(forged));
        assert!(resume_child_virtual_ptrace(reported));

        let mut resumed = [0u8];
        assert_eq!(
            unsafe { libc::read(resumed_pipe[0], resumed.as_mut_ptr().cast(), resumed.len(),) },
            1
        );
        let stop_identity_preserved = find_child_record(child as u32)
            .and_then(record_for_ref)
            .is_some_and(|record| record_ptrace_stop_signal(record) == libc::SIGUSR2 as u64);
        let release = [1u8];
        assert_eq!(
            unsafe { libc::write(release_pipe[1], release.as_ptr().cast(), release.len()) },
            1
        );
        unsafe {
            libc::close(resumed_pipe[0]);
            libc::close(release_pipe[1]);
        }

        let mut exit_status = 0;
        let reaped = unsafe { libc::waitpid(child, &mut exit_status, 0) };
        assert_eq!(reaped, child);
        assert!(libc::WIFEXITED(exit_status));
        assert_eq!(libc::WEXITSTATUS(exit_status), 42);
        let _ = reap_child_guest_ns(child as u32);
        assert!(
            stop_identity_preserved,
            "continue must not mutate the generation-scoped stop identity"
        );
    }

    #[test]
    fn virtual_ptrace_stop_token_expires_after_resume() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let tracer_pid = std::process::id();
        let prepared =
            prepare_child_record_pre_fork(tracer_pid, 0, 0, false, 0).expect("prepare child");

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            complete_child_record_post_fork_child();
            if !register_self_virtual_ptrace(tracer_pid)
                || !request_self_virtual_ptrace_stop(libc::SIGUSR1)
            {
                unsafe { libc::_exit(70) };
            }
            unsafe { libc::raise(libc::SIGSTOP) };
            if !request_self_virtual_ptrace_stop(libc::SIGUSR2) {
                unsafe { libc::_exit(71) };
            }
            unsafe {
                libc::raise(libc::SIGSTOP);
                libc::_exit(44);
            }
        }

        publish_prepared_child_record_parent_ref(prepared, child as u32);
        let mut stop_status = 0;
        assert_eq!(
            unsafe { libc::waitpid(child, &mut stop_status, libc::WUNTRACED) },
            child
        );
        let first = report_child_virtual_ptrace_stop(child as u32).expect("first stop");
        assert_eq!(first.linux_signum(), libc::SIGUSR1);
        assert!(resume_child_virtual_ptrace(first));

        assert_eq!(
            unsafe { libc::waitpid(child, &mut stop_status, libc::WUNTRACED) },
            child
        );
        let second = report_child_virtual_ptrace_stop(child as u32).expect("second stop");
        assert_eq!(second.linux_signum(), libc::SIGUSR2);
        assert_ne!(first, second);
        assert!(!resume_child_virtual_ptrace(first));
        assert!(resume_child_virtual_ptrace(second));

        let mut exit_status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut exit_status, 0) }, child);
        assert!(libc::WIFEXITED(exit_status));
        assert_eq!(libc::WEXITSTATUS(exit_status), 44);
        let _ = reap_child_guest_ns(child as u32);
    }

    #[test]
    fn virtual_ptrace_kill_is_terminal() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let tracer_pid = std::process::id();
        let prepared =
            prepare_child_record_pre_fork(tracer_pid, 0, 0, false, 0).expect("prepare child");

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            complete_child_record_post_fork_child();
            if !register_self_virtual_ptrace(tracer_pid)
                || !request_self_virtual_ptrace_stop(libc::SIGUSR1)
            {
                unsafe { libc::_exit(70) };
            }
            unsafe {
                libc::raise(libc::SIGSTOP);
                libc::_exit(71);
            }
        }

        publish_prepared_child_record_parent_ref(prepared, child as u32);
        let mut stop_status = 0;
        assert_eq!(
            unsafe { libc::waitpid(child, &mut stop_status, libc::WUNTRACED) },
            child
        );
        let reported =
            report_child_virtual_ptrace_stop(child as u32).expect("reported virtual stop");
        assert_eq!(reported.linux_signum(), libc::SIGUSR1);
        assert!(kill_child_virtual_ptrace(reported));

        let mut exit_status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut exit_status, 0) }, child);
        assert!(libc::WIFSIGNALED(exit_status));
        assert_eq!(libc::WTERMSIG(exit_status), libc::SIGKILL);
        let _ = reap_child_guest_ns(child as u32);
    }

    #[test]
    fn virtual_ptrace_detach_clears_ownership_before_resume() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let tracer_pid = std::process::id();
        let prepared =
            prepare_child_record_pre_fork(tracer_pid, 0, 0, false, 0).expect("prepare child");

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            complete_child_record_post_fork_child();
            if !register_self_virtual_ptrace(tracer_pid)
                || !request_self_virtual_ptrace_stop(libc::SIGHUP)
            {
                unsafe { libc::_exit(70) };
            }
            unsafe { libc::raise(libc::SIGSTOP) };
            if self_is_virtual_ptrace_tracee() || request_self_virtual_ptrace_stop(libc::SIGUSR2) {
                unsafe { libc::_exit(71) };
            }
            unsafe { libc::_exit(43) };
        }

        publish_prepared_child_record_parent_ref(prepared, child as u32);
        let mut stop_status = 0;
        assert_eq!(
            unsafe { libc::waitpid(child, &mut stop_status, libc::WUNTRACED) },
            child
        );
        let reported =
            report_child_virtual_ptrace_stop(child as u32).expect("reported virtual stop");
        assert_eq!(reported.linux_signum(), libc::SIGHUP);
        assert!(detach_child_virtual_ptrace(reported));

        let mut exit_status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut exit_status, 0) }, child);
        assert!(libc::WIFEXITED(exit_status));
        assert_eq!(libc::WEXITSTATUS(exit_status), 43);
        let _ = reap_child_guest_ns(child as u32);
    }

    #[test]
    fn virtual_ptrace_rollback_cannot_resurrect_terminal_or_reused_record() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let tracer = 424_260;
        let child = 424_261;

        let _ = reap_child_guest_ns(child);
        register_for_test(child, tracer, 0, false);
        let old_ref = find_child_record(child).expect("registered tracee");
        let old_record = record_for_ref(old_ref).expect("tracee record");
        let running =
            VirtualPtraceControl::traced(tracer, old_ref.generation, VirtualPtraceState::Running)
                .expect("valid traced control");
        old_record
            .ptrace_control
            .store(running.raw(), Ordering::Release);
        old_record
            .ptrace_stop_signal
            .store(ptrace_stop_word(7, libc::SIGUSR2 as u32), Ordering::Release);
        let old_stop = VirtualPtraceStop {
            record: old_ref,
            tracee_pid: child,
            tracer_pid: tracer,
            sequence: 7,
            linux_signum: libc::SIGUSR2,
        };

        record_child_exit(child, 0);
        assert!(!rollback_virtual_ptrace_control(
            old_stop,
            VirtualPtraceState::Running,
        ));
        assert_eq!(
            record_virtual_ptrace_control(old_record),
            Some(VirtualPtraceControl::untraced())
        );
        assert_eq!(record_ptrace_stop_signal(old_record), 0);
        assert_eq!(
            ptrace_stop_word_sequence(record_ptrace_stop_word(old_record)),
            7
        );

        release_child_record(old_ref);
        register_for_test(child, tracer, 0, false);
        let new_ref = find_child_record(child).expect("reused tracee pid");
        assert_ne!(new_ref.generation, old_ref.generation);
        assert!(!rollback_virtual_ptrace_control(
            old_stop,
            VirtualPtraceState::Running,
        ));
        let new_record = record_for_ref(new_ref).expect("new tracee record");
        assert_eq!(
            record_virtual_ptrace_control(new_record),
            Some(VirtualPtraceControl::untraced())
        );
        assert_eq!(record_ptrace_stop_signal(new_record), 0);
        release_child_record(new_ref);
    }

    #[test]
    fn virtual_ptrace_token_cannot_control_reused_pid() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let tracer = std::process::id();
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            loop {
                unsafe { libc::pause() };
            }
        }
        let child_pid = child as u32;

        register_for_test(child_pid, tracer, 0, false);
        let old_ref = find_child_record(child_pid).expect("old tracee record");
        let old_record = record_for_ref(old_ref).expect("old tracee");
        old_record
            .ptrace_stop_signal
            .store(ptrace_stop_word(9, libc::SIGUSR1 as u32), Ordering::Release);
        old_record.ptrace_control.store(
            VirtualPtraceControl::traced(
                tracer,
                old_ref.generation,
                VirtualPtraceState::StopRequested,
            )
            .expect("valid requested control")
            .raw(),
            Ordering::Release,
        );
        let stale_stop =
            report_child_virtual_ptrace_stop(child_pid).expect("reported stop for old record");

        release_child_record(old_ref);
        register_for_test(child_pid, tracer, 0, false);
        let new_ref = find_child_record(child_pid).expect("reused tracee record");
        assert_ne!(new_ref.generation, old_ref.generation);
        let new_record = record_for_ref(new_ref).expect("new tracee");
        let new_control = VirtualPtraceControl::traced(
            tracer,
            new_ref.generation,
            VirtualPtraceState::StopReported,
        )
        .expect("valid reported control");
        new_record
            .ptrace_stop_signal
            .store(ptrace_stop_word(9, libc::SIGUSR1 as u32), Ordering::Release);
        new_record
            .ptrace_control
            .store(new_control.raw(), Ordering::Release);

        let rejected = !kill_child_virtual_ptrace(stale_stop);
        let preserved = record_virtual_ptrace_control(new_record) == Some(new_control)
            && record_ptrace_stop_word(new_record) == ptrace_stop_word(9, libc::SIGUSR1 as u32);

        let _ = unsafe { libc::kill(child, libc::SIGKILL) };
        let mut status = 0;
        let _ = unsafe { libc::waitpid(child, &mut status, 0) };
        release_child_record(new_ref);

        assert!(rejected, "a stale stop token must be rejected");
        assert!(preserved, "a stale token must not mutate the reused record");
    }

    #[test]
    fn clone_parent_registration_is_adopted_immediately() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let child = 525_252;
        let parent = 424_242;

        let _ = reap_child_guest_ns(child);
        register_for_test(child, parent, 0, true);

        assert_eq!(adopted_parent_for(child), Some(parent));
        assert_eq!(pending_adopted_child(parent, child as i32), Some(child));

        record_child_exit_status(child, 9876, 0x2a00, true);
        assert_eq!(
            reap_adopted_child(parent, child as i32),
            Some((child, 0x2a00, 9876))
        );
    }

    #[test]
    fn adopted_record_exit_is_waitable_even_when_caller_did_not_preclassify_it() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let child = 525_262;
        let parent = 424_252;

        let _ = reap_child_guest_ns(child);
        register_for_test(child, parent, 0, true);

        record_child_exit_status(child, 6789, 0x2b00, false);
        assert_eq!(
            reap_adopted_child(parent, child as i32),
            Some((child, 0x2b00, 6789))
        );
    }

    #[test]
    fn adopted_reap_keeps_namespace_member_record_for_pid_translation() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let child = 525_272;
        let parent = 424_262;
        let ns_pid = 45_104;

        let _ = reap_child_guest_ns(child);
        let generation = KernelArena::global().allocate_generation();
        let r = process_section()
            .claim(Some(HostPid::new(child)), generation, |record| {
                record.parent_host_pid.store(parent, Ordering::Release);
                record.ns_pid.store(ns_pid, Ordering::Release);
                record.guest_ns.store(2345, Ordering::Release);
                set_adopted(record, true);
                store_exit_status(record, 0x2c00);
                store_exit_ready(record, true);
            })
            .expect("claim adopted namespace child record");

        assert_eq!(
            reap_adopted_child(parent, child as i32),
            Some((child, 0x2c00, 2345))
        );
        let record = child_record(child).expect("namespace record remains for translation");
        assert_eq!(record_ns_pid(record), ns_pid);
        assert_eq!(record_guest_ns(record), 0);
        assert!(!record_exit_ready(record));

        release_child_record(r);
    }

    #[test]
    fn direct_children_for_wait_excludes_adopted_children() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let parent = 616_161;
        let direct = 616_162;
        let adopted = 616_163;

        let _ = reap_child_guest_ns(direct);
        let _ = reap_child_guest_ns(adopted);
        register_for_test(direct, parent, 0, false);
        register_for_test(adopted, parent, 0, true);

        let children = direct_children_for_wait(parent);
        assert!(children.contains(&direct));
        assert!(!children.contains(&adopted));

        let _ = reap_child_guest_ns(direct);
        record_child_exit_status(adopted, 0, 0, true);
        let _ = reap_adopted_child(parent, adopted as i32);
    }

    #[test]
    fn direct_child_ptrace_stop_pending_excludes_adopted_children() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let parent = 717_171;
        let direct = 717_172;
        let adopted = 717_173;

        let _ = reap_child_guest_ns(direct);
        let _ = reap_child_guest_ns(adopted);
        register_for_test(direct, parent, 0, false);
        register_for_test(adopted, parent, 0, true);

        mark_ptrace_stop_pending_for_test(adopted, 5);
        assert!(!direct_child_ptrace_stop_pending(parent));

        mark_ptrace_stop_pending_for_test(direct, 5);
        assert!(direct_child_ptrace_stop_pending(parent));

        let _ = reap_child_guest_ns(direct);
        record_child_exit_status(adopted, 0, 0, true);
        let _ = reap_adopted_child(parent, adopted as i32);
    }

    #[test]
    fn ptrace_stop_marker_persists_on_prefork_record() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let parent = 717_181;
        let child = 717_182;

        // New invariant: the record is COMPLETE at publish (pre-fork fill), so
        // a ptrace-stop marker lands on an already-complete record and is
        // visible through the direct-child wait scan.
        let _ = reap_child_guest_ns(child);
        register_for_test(child, parent, 0, false);
        mark_ptrace_stop_pending_for_test(child, 19);

        assert!(direct_child_ptrace_stop_pending(parent));
        assert_eq!(take_child_ptrace_stop_signal(child), Some(19));

        let _ = reap_child_guest_ns(child);
    }

    #[test]
    fn wait_any_park_target_is_any_child_never_the_first() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let waiter = 818_181;
        let first = 818_182;
        let second = 818_183;

        // Two direct children registered through the pre-fork path. A blocking
        // wait4(-1) park must go to the any-child kqueue path (-1): parking on
        // the FIRST child's pid misses the second child's exit (the single-pid
        // slice loop re-polls only the watched pid).
        let prep1 =
            prepare_child_record_pre_fork(waiter, 0, 0, false, 0).expect("prepare child record");
        publish_prepared_child_record_parent_ref(prep1, first);
        let prep2 =
            prepare_child_record_pre_fork(waiter, 0, 0, false, 0).expect("prepare child record");
        publish_prepared_child_record_parent_ref(prep2, second);

        assert_eq!(wait_any_park_pid(waiter), Some(-1));

        let r1 = find_child_record(first).unwrap_or_else(|| panic!("first record"));
        release_child_record(r1);
        // With only one direct child left the park target is STILL -1: the
        // any-child path handles a single watch fine, and pid-order guessing
        // is exactly the bug this guards against.
        assert_eq!(wait_any_park_pid(waiter), Some(-1));
        let r2 = find_child_record(second).unwrap_or_else(|| panic!("second record"));
        release_child_record(r2);

        // No direct children, one adopted child not yet exit-ready: park on the
        // adopted child's concrete host pid (EVFILT_PROC watches non-children).
        let adopted = 818_184;
        let prep3 =
            prepare_child_record_pre_fork(waiter, 0, 0, true, 0).expect("prepare child record");
        publish_prepared_child_record_parent_ref(prep3, adopted);
        assert_eq!(wait_any_park_pid(waiter), Some(adopted as i32));
        let r3 = find_child_record(adopted).unwrap_or_else(|| panic!("adopted record"));
        release_child_record(r3);

        // No children at all: no park target (the caller reports ECHILD).
        assert_eq!(wait_any_park_pid(waiter), None);
    }

    #[test]
    fn parent_publish_by_ref_survives_a_second_prepare() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let parent_a = 828_181;
        let parent_b = 828_182;
        let child_a = 828_183;
        let child_b = 828_184;

        // Fork serialization releases (end_fork) before the parent publishes,
        // so another thread's prepare can overwrite the process-global stash
        // in that window. The parent must therefore publish the record IT
        // prepared, by ref — not whatever the stash currently holds.
        let r1 = prepare_child_record_pre_fork(parent_a, 0, 111, false, 0)
            .expect("prepare child record");
        let r2 = prepare_child_record_pre_fork(parent_b, 0, 222, false, 0)
            .expect("prepare child record");
        publish_prepared_child_record_parent_ref(r1, child_a);
        publish_prepared_child_record_parent_ref(r2, child_b);

        let rec_a = child_record(child_a).unwrap_or_else(|| panic!("child_a record"));
        assert_eq!(record_parent_pid(rec_a), parent_a);
        assert_eq!(rec_a.ns_pid.load(Ordering::Acquire), 111);
        let rec_b = child_record(child_b).unwrap_or_else(|| panic!("child_b record"));
        assert_eq!(record_parent_pid(rec_b), parent_b);
        assert_eq!(rec_b.ns_pid.load(Ordering::Acquire), 222);

        release_child_record(r1);
        release_child_record(r2);
    }

    #[test]
    fn fork_time_claim_exhaustion_is_an_error_not_an_abort() {
        // A guest that forks children nobody ever reaps (SIGCHLD set to
        // SIG_IGN, or the parent exits with no subreaper) eventually fills the
        // process section. The pre-fork claim must surface that as an error
        // the fork dispatch can turn into Linux EAGAIN (spec "Failure model":
        // section exhaustion fails the specific operation with a Linux errno)
        // — never an abort of the whole guest.
        let arena = KernelArena::create().expect("create private arena");
        let section = &arena.layout().processes;
        for i in 0..carrick_kernel::process::PROCESS_RECORDS {
            section
                .claim(
                    Some(HostPid::new(0x0600_0000 + i as u32)),
                    arena.allocate_generation(),
                    |_| {},
                )
                .expect("fill section");
        }
        let claimed = prepare_child_record_in(&arena, 4242, 0, 77, false, 0);
        assert!(
            matches!(
                claimed,
                Err(ArenaError::Exhausted {
                    section: "processes",
                    ..
                })
            ),
            "expected recoverable exhaustion, got {claimed:?}"
        );
    }

    #[test]
    fn prefork_record_is_complete_when_child_publishes_host_pid() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let parent_pid = std::process::id();
        let ns_pid = 45_002;
        let stop_signal = libc::SIGTRAP;

        let prepared =
            prepare_child_record_pre_fork(parent_pid, 0, ns_pid, false, stop_signal as u64)
                .expect("prepare child record");
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            complete_child_record_post_fork_child();
            let me = std::process::id();
            let ok = child_record(me).is_some_and(|record| {
                record_parent_pid(record) == parent_pid
                    && record.ns_pid.load(Ordering::Acquire) == ns_pid
                    && record.ptrace_stop_signal.load(Ordering::Acquire) == stop_signal as u64
            });
            unsafe { libc::_exit(if ok { 0 } else { 71 }) };
        }

        publish_prepared_child_record_parent_ref(prepared, child as u32);
        let mut status = 0;
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        assert_eq!(waited, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);

        let record = child_record(child as u32).expect("child record remains published");
        assert_eq!(record_parent_pid(record), parent_pid);
        assert_eq!(record.ns_pid.load(Ordering::Acquire), ns_pid);
        assert_eq!(
            record.ptrace_stop_signal.load(Ordering::Acquire),
            stop_signal as u64
        );
        let Some(r) = find_child_record(child as u32) else {
            panic!("child record should remain published");
        };
        release_child_record(r);
    }

    #[test]
    fn prefork_child_marks_adopted_when_recorded_parent_differs_from_host_parent() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let recorded_parent = std::process::id().saturating_add(10_000);

        let prepared = prepare_child_record_pre_fork(recorded_parent, 0, 45_052, false, 0)
            .expect("prepare child record");
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            complete_child_record_post_fork_child();
            let ok = adopted_parent_for_self() == Some(recorded_parent);
            unsafe { libc::_exit(if ok { 0 } else { 72 }) };
        }

        publish_prepared_child_record_parent_ref(prepared, child as u32);
        let mut status = 0;
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        assert_eq!(waited, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);

        let Some(r) = find_child_record(child as u32) else {
            panic!("child record should remain published");
        };
        release_child_record(r);
    }

    #[test]
    fn guest_cpu_drain_keeps_namespace_member_record_published() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let parent = 45_101;
        let child = 45_102;
        let ns_pid = 45_103;

        let _ = reap_child_guest_ns(child);
        let generation = KernelArena::global().allocate_generation();
        let r = process_section()
            .claim(Some(HostPid::new(child)), generation, |record| {
                record.parent_host_pid.store(parent, Ordering::Release);
                record.ns_pid.store(ns_pid, Ordering::Release);
                record.guest_ns.store(12_345, Ordering::Release);
                record
                    .ptrace_stop_signal
                    .store(libc::SIGSTOP as u64, Ordering::Release);
            })
            .expect("claim namespace child record");

        assert_eq!(reap_child_guest_ns(child), 12_345);
        let record = child_record(child).expect("namespace record remains published");
        assert_eq!(record_ns_pid(record), ns_pid);
        assert_eq!(record_guest_ns(record), 0);
        assert_eq!(record_ptrace_stop_signal(record), 0);

        release_child_record(r);
    }

    fn mark_ptrace_stop_pending_for_test(pid: u32, signum: i32) {
        if let Some(record) = child_record(pid) {
            record
                .ptrace_stop_signal
                .store(signum.max(0) as u64, Ordering::Release);
        }
    }
}
