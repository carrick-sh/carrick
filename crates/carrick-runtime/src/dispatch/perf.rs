//! `perf_event_open(2)` — minimal, honest software-event counters.
//!
//! # What carrick can honestly measure
//!
//! carrick has no guest PMU, so every `PERF_TYPE_HARDWARE` / hw-cache / raw /
//! tracepoint request answers **ENOENT** ("generic event not supported") — the
//! exact answer the native arm64 Docker oracle gives inside its VM, where the
//! LTP suites TCONF those cases. What carrick CAN measure honestly is a Linux
//! thread's guest CPU time, which the kernel graph already accounts per thread
//! for `getrusage`/`times` (`Thread::cpu_us`, backed by that thread's
//! `guest_cpu` slot). That ledger backs:
//!
//! - `PERF_COUNT_SW_CPU_CLOCK` and `PERF_COUNT_SW_TASK_CLOCK` — reported in
//!   nanoseconds like Linux (ledger granularity is 1 µs, scaled ×1000);
//! - `PERF_COUNT_SW_DUMMY` — a placeholder event that counts nothing by
//!   definition.
//!
//! Other software configs (page-faults, context-switches, migrations…) have no
//! honest carrick ledger and answer ENOENT rather than fabricating numbers.
//! Sampling (`sample_period`/`sample_freq != 0`) is refused with EOPNOTSUPP:
//! carrick delivers no overflow samples, and pretending to open a sampling
//! event that never fires would be a silent lie. Real Linux would accept it —
//! a documented, deliberate divergence until an honest delivery path exists.
//!
//! # Target resolution
//!
//! `pid == 0` (and the caller's own pid/tid aliases) measure the CALLING
//! thread. Another live Linux task is EOPNOTSUPP: the ledger could be read
//! (see the ownership model below), but resolving an arbitrary guest pid to
//! the exact `Thread` whose CPU perf should attribute needs a task→thread
//! selection rule this minimal implementation does not claim. A nonexistent
//! pid is ESRCH. `cpu >= 0` (per-CPU counters) is EOPNOTSUPP after Linux's own
//! EINVAL bound check, and `pid == -1 && cpu == -1` is EINVAL per the man page.
//!
//! # Ownership is kernel-graph identity, not a host pid
//!
//! A counter names its measured thread by a `Weak<`[`crate::kernel::Thread`]`>`
//! handle on the kernel-graph object itself, never by a host pid or bare tid.
//! Under HVPatch every logical Linux process is a thread of ONE VM carrier, so
//! a host-pid-keyed owner would be identical for every guest task — correct
//! only while exactly one Linux process exists. Because the owner is the
//! object, any thread's `read(2)` on a dup'd/inherited counter fd reports the
//! MEASURED thread's CPU rather than the reader's, and a counter whose thread
//! has been reaped simply stops advancing (still readable, as on Linux).
//!
//! # Errno shape (verified against the Docker arm64 oracle)
//!
//! Ordering and values were confirmed differentially: `attr.size` versioning
//! errors are E2BIG (with the supported size written back), and E2BIG wins
//! over ESRCH which wins over the cpu EINVAL; unknown `flags`/`read_format`/
//! reserved attr bits are EINVAL; short `read(2)` is ENOSPC; a repeated read
//! re-reports the counter (no drain); `lseek` is ESPIPE; `write` is EINVAL;
//! unknown ioctls are ENOTTY.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use super::*;

use carrick_abi::{
    LINUX_ENOSPC, LINUX_PERF_ATTR_SIZE_SUPPORTED, LINUX_PERF_ATTR_SIZE_VER0,
    LINUX_PERF_COUNT_SW_CPU_CLOCK, LINUX_PERF_COUNT_SW_DUMMY, LINUX_PERF_COUNT_SW_TASK_CLOCK,
    LINUX_PERF_EVENT_IOC_DISABLE, LINUX_PERF_EVENT_IOC_ENABLE, LINUX_PERF_EVENT_IOC_ID,
    LINUX_PERF_EVENT_IOC_PAUSE_OUTPUT, LINUX_PERF_EVENT_IOC_PERIOD, LINUX_PERF_EVENT_IOC_REFRESH,
    LINUX_PERF_EVENT_IOC_RESET, LINUX_PERF_EVENT_IOC_SET_BPF, LINUX_PERF_EVENT_IOC_SET_FILTER,
    LINUX_PERF_EVENT_IOC_SET_OUTPUT, LINUX_PERF_IOC_FLAG_GROUP, LINUX_PERF_TYPE_SOFTWARE,
    PerfEventAttrFlags, PerfEventOpenFlags, PerfEventReadFormat,
};

syscall_table! {
    /// Per-module syscall routing for perf events. `resolve_handler` in
    /// `dispatch/mod.rs` chains this with the other modules' tables.
    pub(crate) fn dispatch_perf;
    241 => perf_event_open,
}

/// The software events carrick backs with an honest measurement source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PerfSwEvent {
    /// `PERF_COUNT_SW_CPU_CLOCK` — the target thread's guest CPU nanoseconds.
    CpuClock,
    /// `PERF_COUNT_SW_TASK_CLOCK` — same ledger; Linux distinguishes the two
    /// clocks only in sub-µs bookkeeping carrick does not model.
    TaskClock,
    /// `PERF_COUNT_SW_DUMMY` — counts nothing, by definition.
    Dummy,
}

impl PerfSwEvent {
    fn from_config(config: u64) -> Option<Self> {
        match config {
            LINUX_PERF_COUNT_SW_CPU_CLOCK => Some(Self::CpuClock),
            LINUX_PERF_COUNT_SW_TASK_CLOCK => Some(Self::TaskClock),
            LINUX_PERF_COUNT_SW_DUMMY => Some(Self::Dummy),
            _ => None,
        }
    }
}

/// The Linux thread a perf event measures, held as kernel-graph identity.
///
/// This is deliberately NOT a host pid/tid pair. Under HVPatch every logical
/// Linux process is a THREAD of one VM carrier, so `std::process::id()` names
/// the carrier and is identical for every guest task — a host-pid-keyed owner
/// would be correct only while exactly one Linux process exists (the exact
/// scope-domain trap in `docs/identity-and-scope-domains.md`). The authority is
/// the kernel graph object itself.
///
/// A `Weak<Thread>` IS the exact generation: a recycled Linux tid gets a NEW
/// `Thread`, so this handle can never alias a later thread the way a bare tid
/// would — no separate `ThreadKey` guard is needed. Holding the object, rather
/// than reading a thread-local slot, is also what lets ANY caller sample the
/// measured thread: a sibling's `read(2)` on a dup'd counter fd reports the
/// MEASURED thread's CPU, not the reader's.
#[derive(Debug, Clone)]
struct PerfOwner {
    thread: std::sync::Weak<crate::kernel::Thread>,
}

impl PerfOwner {
    /// The measured thread's guest CPU in nanoseconds, or `Reaped` once the
    /// thread object is gone (its ledger no longer advances, so the counter
    /// freezes at its last materialized value — matching Linux, where a
    /// counter for an exited task stops counting but stays readable).
    fn sample(&self) -> PerfLedger {
        match self.thread.upgrade() {
            // `Thread::cpu_us` reads that thread's own `guest_cpu` slot, so it
            // is valid from any caller. µs granularity, scaled to Linux's ns.
            Some(thread) => PerfLedger::Live(thread.cpu_us().saturating_mul(1000)),
            None => PerfLedger::Reaped,
        }
    }
}

/// A ledger sample for one perf operation: `Live(ns)` is the measured thread's
/// current guest-CPU nanoseconds; `Reaped` means that thread is gone and the
/// counter can no longer advance.
#[derive(Debug, Clone, Copy)]
pub(super) enum PerfLedger {
    Live(u64),
    Reaped,
}

/// Monotonic wall-clock ns for `time_enabled`/`time_running` accounting.
fn wall_ns() -> u64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now)
        .elapsed()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}

/// Unique event ids for `PERF_EVENT_IOC_ID` / `PERF_FORMAT_ID`. Starts at 1 —
/// 0 never names an event, matching the kernel's non-zero ids.
fn next_event_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug)]
struct PerfCounterInner {
    enabled: bool,
    /// Accumulated counter value (ns for the clock events, always 0 for Dummy).
    value: u64,
    /// Ledger reading at the last enable/reset while enabled.
    ledger_base: u64,
    /// Accumulated enabled wall-time and its running base.
    time_enabled: u64,
    wall_base: u64,
}

/// One perf event: the fd-table variant holds `Arc<PerfEventState>`, so
/// `dup(2)` and fork share the counter the way an open file description is
/// shared.
#[derive(Debug)]
pub(super) struct PerfEventState {
    event: PerfSwEvent,
    id: u64,
    read_format: PerfEventReadFormat,
    owner: PerfOwner,
    /// Sibling events opened with `group_fd` naming this event as leader.
    /// Only the leader's list is populated; used for `PERF_IOC_FLAG_GROUP`
    /// fan-out and `PERF_FORMAT_GROUP` reads.
    members: Mutex<Vec<Arc<PerfEventState>>>,
    inner: Mutex<PerfCounterInner>,
}

impl PerfEventState {
    fn new(event: PerfSwEvent, read_format: PerfEventReadFormat, owner: PerfOwner) -> Self {
        Self {
            event,
            id: next_event_id(),
            read_format,
            owner,
            members: Mutex::new(Vec::new()),
            inner: Mutex::new(PerfCounterInner {
                enabled: false,
                value: 0,
                ledger_base: 0,
                time_enabled: 0,
                wall_base: 0,
            }),
        }
    }

    /// Sample this event's measurement source — the MEASURED thread's ledger,
    /// regardless of which thread is asking. Dummy events always read 0.
    fn ledger(&self) -> PerfLedger {
        if self.event == PerfSwEvent::Dummy {
            return PerfLedger::Live(0);
        }
        self.owner.sample()
    }

    fn enable(&self, ledger: PerfLedger) {
        let mut inner = self.inner.lock();
        if inner.enabled {
            return;
        }
        inner.enabled = true;
        inner.wall_base = wall_ns();
        if let PerfLedger::Live(now) = ledger {
            inner.ledger_base = now;
        }
        // A reaped measured thread keeps its previous base; its ledger no
        // longer advances, so the counter simply stops.
    }

    fn disable(&self, ledger: PerfLedger) {
        let mut inner = self.inner.lock();
        if !inner.enabled {
            return;
        }
        Self::materialize(&mut inner, ledger);
        inner.time_enabled = inner
            .time_enabled
            .saturating_add(wall_ns().saturating_sub(inner.wall_base));
        inner.enabled = false;
    }

    /// `PERF_EVENT_IOC_RESET`: zero the counter VALUE only — `time_enabled`/
    /// `time_running` keep accruing, per the man page.
    fn reset(&self, ledger: PerfLedger) {
        let mut inner = self.inner.lock();
        inner.value = 0;
        if inner.enabled
            && let PerfLedger::Live(now) = ledger
        {
            inner.ledger_base = now;
        }
    }

    /// Fold the delta since `ledger_base` into `value` and re-anchor the base.
    fn materialize(inner: &mut PerfCounterInner, ledger: PerfLedger) {
        if let PerfLedger::Live(now) = ledger {
            inner.value = inner
                .value
                .saturating_add(now.saturating_sub(inner.ledger_base));
            inner.ledger_base = now;
        }
    }

    /// Snapshot `(value, time_enabled, time_running)` without changing the
    /// running state. carrick never multiplexes (software events always
    /// schedule, as on Linux), so `time_running == time_enabled`.
    fn snapshot(&self, ledger: PerfLedger) -> (u64, u64, u64) {
        let mut inner = self.inner.lock();
        if inner.enabled {
            Self::materialize(&mut inner, ledger);
        }
        let enabled_ns = if inner.enabled {
            inner
                .time_enabled
                .saturating_add(wall_ns().saturating_sub(inner.wall_base))
        } else {
            inner.time_enabled
        };
        (inner.value, enabled_ns, enabled_ns)
    }
}

/// The parsed subset of `perf_event_attr` carrick interprets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ParsedPerfAttr {
    pub(super) type_: u32,
    pub(super) config: u64,
    pub(super) sample_period: u64,
    pub(super) read_format: PerfEventReadFormat,
    pub(super) flags: PerfEventAttrFlags,
}

/// Attr rejection: the errno plus whether the kernel writes its supported
/// size back into the guest's `attr.size` (the E2BIG contract).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PerfAttrError {
    /// `attr.size` versioning failure — write `LINUX_PERF_ATTR_SIZE_SUPPORTED`
    /// back to `attr.size`, then E2BIG.
    SizeMismatch,
    /// Reserved/unknown bits set — EINVAL.
    Invalid,
}

/// Validate and extract a `perf_event_attr` per the man page's size-versioning
/// contract. `bytes` is the guest struct clamped to the declared size (the
/// caller reads `min(size, guest bytes)`); a declared size beyond
/// [`LINUX_PERF_ATTR_SIZE_SUPPORTED`] is accepted iff the tail is all-zero.
pub(super) fn parse_perf_attr(
    bytes: &[u8],
    declared_size: u32,
) -> Result<ParsedPerfAttr, PerfAttrError> {
    let size = if declared_size == 0 {
        LINUX_PERF_ATTR_SIZE_VER0
    } else {
        declared_size
    };
    if size < LINUX_PERF_ATTR_SIZE_VER0 {
        return Err(PerfAttrError::SizeMismatch);
    }
    if bytes.len() < LINUX_PERF_ATTR_SIZE_VER0 as usize {
        return Err(PerfAttrError::SizeMismatch);
    }
    if size > LINUX_PERF_ATTR_SIZE_SUPPORTED {
        let known = LINUX_PERF_ATTR_SIZE_SUPPORTED as usize;
        let tail = bytes.get(known..).unwrap_or(&[]);
        if tail.iter().any(|b| *b != 0) {
            return Err(PerfAttrError::SizeMismatch);
        }
    }
    let u32_at = |off: usize| {
        let mut v = [0u8; 4];
        if let Some(src) = bytes.get(off..off + 4) {
            v.copy_from_slice(src);
        }
        u32::from_le_bytes(v)
    };
    let u64_at = |off: usize| {
        let mut v = [0u8; 8];
        if let Some(src) = bytes.get(off..off + 8) {
            v.copy_from_slice(src);
        }
        u64::from_le_bytes(v)
    };
    let type_ = u32_at(0);
    let config = u64_at(8);
    let sample_period = u64_at(16);
    let read_format_raw = u64_at(32);
    let flags_raw = u64_at(40);
    let Some(read_format) = PerfEventReadFormat::from_bits(read_format_raw) else {
        return Err(PerfAttrError::Invalid);
    };
    let Some(flags) = PerfEventAttrFlags::from_bits(flags_raw) else {
        // A bit above SIGTRAP is inside `__reserved_1` — EINVAL, like Linux.
        return Err(PerfAttrError::Invalid);
    };
    Ok(ParsedPerfAttr {
        type_,
        config,
        sample_period,
        read_format,
        flags,
    })
}

/// Byte length `read(2)` needs for `read_format` on a single (non-group)
/// event: value + the optional u64s.
pub(super) fn perf_read_size(read_format: PerfEventReadFormat, members: usize) -> usize {
    let opt = |flag: PerfEventReadFormat| usize::from(read_format.contains(flag)) * 8;
    if read_format.contains(PerfEventReadFormat::GROUP) {
        // nr, [time_enabled], [time_running], then per event: value [id] [lost]
        8 + opt(PerfEventReadFormat::TOTAL_TIME_ENABLED)
            + opt(PerfEventReadFormat::TOTAL_TIME_RUNNING)
            + members * (8 + opt(PerfEventReadFormat::ID) + opt(PerfEventReadFormat::LOST))
    } else {
        8 + opt(PerfEventReadFormat::TOTAL_TIME_ENABLED)
            + opt(PerfEventReadFormat::TOTAL_TIME_RUNNING)
            + opt(PerfEventReadFormat::ID)
            + opt(PerfEventReadFormat::LOST)
    }
}

/// Encode one event's counter in the `read_format` wire layout the man page
/// defines. `entries` carries `(value, id)` per event (the leader first for a
/// GROUP read); `times` is the leader's `(time_enabled, time_running)`.
pub(super) fn encode_perf_read(
    read_format: PerfEventReadFormat,
    times: (u64, u64),
    entries: &[(u64, u64)],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(perf_read_size(read_format, entries.len()));
    let push = |out: &mut Vec<u8>, v: u64| out.extend_from_slice(&v.to_le_bytes());
    if read_format.contains(PerfEventReadFormat::GROUP) {
        push(&mut out, entries.len() as u64);
        if read_format.contains(PerfEventReadFormat::TOTAL_TIME_ENABLED) {
            push(&mut out, times.0);
        }
        if read_format.contains(PerfEventReadFormat::TOTAL_TIME_RUNNING) {
            push(&mut out, times.1);
        }
        for (value, id) in entries {
            push(&mut out, *value);
            if read_format.contains(PerfEventReadFormat::ID) {
                push(&mut out, *id);
            }
            if read_format.contains(PerfEventReadFormat::LOST) {
                push(&mut out, 0);
            }
        }
    } else {
        let (value, id) = entries.first().copied().unwrap_or((0, 0));
        push(&mut out, value);
        if read_format.contains(PerfEventReadFormat::TOTAL_TIME_ENABLED) {
            push(&mut out, times.0);
        }
        if read_format.contains(PerfEventReadFormat::TOTAL_TIME_RUNNING) {
            push(&mut out, times.1);
        }
        if read_format.contains(PerfEventReadFormat::ID) {
            push(&mut out, id);
        }
        if read_format.contains(PerfEventReadFormat::LOST) {
            push(&mut out, 0);
        }
    }
    out
}

impl SyscallDispatcher {
    /// The `PerfEvent` state behind `fd`, if that is what `fd` is.
    pub(super) fn perf_event_state(&self, fd: i32) -> Option<Arc<PerfEventState>> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read();
        match &*open {
            OpenDescription::PerfEvent { state, .. } => Some(Arc::clone(state)),
            _ => None,
        }
    }

    /// The perf caller identity for owner checks: this host process plus the
    /// calling guest thread (`ThreadId::NONE` on the single-threaded path,
    /// where it is stable per process).
    fn perf_caller<M: GuestMemory>(cx: &SyscallCtx<M>) -> PerfOwner {
        PerfOwner {
            thread: Arc::downgrade(cx.kernel.thread()),
        }
    }

    /// `read(2)` on a perf event fd: report the counter in the `read_format`
    /// layout; a buffer smaller than the format needs is ENOSPC (verified
    /// against the oracle). Reads never drain — a counting fd re-reports.
    pub(super) fn read_perf_event<M: GuestMemory>(
        &self,
        memory: &mut M,
        address: u64,
        length: usize,
        state: &Arc<PerfEventState>,
    ) -> DispatchOutcome {
        let group = state.read_format.contains(PerfEventReadFormat::GROUP);
        let members: Vec<Arc<PerfEventState>> = if group {
            state.members.lock().clone()
        } else {
            Vec::new()
        };
        if length < perf_read_size(state.read_format, 1 + members.len()) {
            return DispatchOutcome::errno(LINUX_ENOSPC);
        }
        let (value, enabled, running) = state.snapshot(state.ledger());
        let mut entries = vec![(value, state.id)];
        for member in &members {
            let (value, _, _) = member.snapshot(member.ledger());
            entries.push((value, member.id));
        }
        let bytes = encode_perf_read(state.read_format, (enabled, running), &entries);
        if memory.write_bytes(address, &bytes).is_err() {
            return DispatchOutcome::errno(LINUX_EFAULT);
        }
        DispatchOutcome::Returned {
            value: bytes.len() as i64,
        }
    }

    /// perf event ioctls. Called from the `ioctl` handler once the fd is known
    /// to be a perf event; unknown requests report unhandled and ENOTTY like
    /// every other fd kind.
    pub(super) fn perf_event_ioctl<M: GuestMemory>(
        &self,
        cx: &mut SyscallCtx<M>,
        fd: i32,
        state: &Arc<PerfEventState>,
        request: u64,
        arg: u64,
    ) -> DispatchOutcome {
        let group_wide = arg & LINUX_PERF_IOC_FLAG_GROUP != 0;
        let fan_out = |op: &dyn Fn(&Arc<PerfEventState>)| {
            op(state);
            if group_wide {
                for member in state.members.lock().iter() {
                    op(member);
                }
            }
        };
        match request {
            LINUX_PERF_EVENT_IOC_ENABLE => {
                fan_out(&|target| target.enable(target.ledger()));
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_PERF_EVENT_IOC_DISABLE => {
                fan_out(&|target| target.disable(target.ledger()));
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_PERF_EVENT_IOC_RESET => {
                fan_out(&|target| target.reset(target.ledger()));
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_PERF_EVENT_IOC_ID => write_packed(&mut *cx.memory, arg, &state.id.to_le_bytes()),
            // Requests whose machinery carrick does not provide (overflow
            // delivery, sampling periods, ring-buffer redirection, filters,
            // BPF attachment). EINVAL — the kernel's own answer for an event
            // that does not support the operation — never a silent success.
            LINUX_PERF_EVENT_IOC_REFRESH
            | LINUX_PERF_EVENT_IOC_PERIOD
            | LINUX_PERF_EVENT_IOC_SET_OUTPUT
            | LINUX_PERF_EVENT_IOC_SET_FILTER
            | LINUX_PERF_EVENT_IOC_SET_BPF
            | LINUX_PERF_EVENT_IOC_PAUSE_OUTPUT => DispatchOutcome::errno(LINUX_EINVAL),
            _ => {
                cx.reporter
                    .record(CompatEvent::unhandled_ioctl(fd, request, arg));
                DispatchOutcome::errno(LINUX_ENOTTY)
            }
        }
    }

    define_syscall! {
        /// perf_event_open(attr, pid, cpu, group_fd, flags).
        fn perf_event_open(this, cx, attr: GuestPtr, pid_raw: u64, cpu_raw: u64, group_raw: u64, open_flags: u64) {
            let pid = pid_raw as u32 as i32;
            let cpu = cpu_raw as u32 as i32;
            let group_fd = group_raw as u32 as i32;
            let memory = &mut *cx.memory;

            // attr.size versioning first: E2BIG outranks every later check
            // (verified ordering: E2BIG > ESRCH > cpu EINVAL).
            let Ok(size_bytes) = memory.read_bytes(attr.0 + 4, 4) else {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            };
            let declared_size =
                u32::from_le_bytes([size_bytes[0], size_bytes[1], size_bytes[2], size_bytes[3]]);
            let read_len = declared_size.clamp(LINUX_PERF_ATTR_SIZE_VER0, 64 * 1024) as usize;
            let Ok(bytes) = memory.read_bytes(attr.0, read_len) else {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            };
            let parsed = match parse_perf_attr(&bytes, declared_size) {
                Ok(parsed) => parsed,
                Err(PerfAttrError::SizeMismatch) => {
                    // The kernel writes its supported size back into attr.size
                    // alongside E2BIG so the caller can retry.
                    let _ = memory
                        .write_bytes(attr.0 + 4, &LINUX_PERF_ATTR_SIZE_SUPPORTED.to_le_bytes());
                    return Ok(DispatchOutcome::errno(LINUX_E2BIG));
                }
                Err(PerfAttrError::Invalid) => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
            };

            // Syscall `flags` argument: unknown bits are EINVAL. Cgroup mode
            // (pid = cgroup fd) needs cgroup accounting carrick doesn't have.
            let Some(flags) = PerfEventOpenFlags::from_bits(open_flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            if flags.contains(PerfEventOpenFlags::PID_CGROUP) {
                return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
            }

            // Target task resolution (ESRCH before the cpu EINVAL, verified).
            // pid == -1 means "all tasks" (needs a cpu); anything below -1 is
            // not a valid target at all.
            if (pid == -1 && cpu == -1) || pid < -1 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let self_target = pid == 0 || sched_pid_is_self_for_perf(cx, pid as u64);
            if pid > 0 && !self_target {
                if !sched_pid_names_live_task(this, cx, pid as u64) {
                    return Ok(DispatchOutcome::errno(LINUX_ESRCH));
                }
                // A live task that is not the calling thread: carrick has no
                // honest way to read a foreign thread's CPU ledger.
                return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
            }
            if cpu >= 0 {
                if cpu as usize >= crate::host_facts::logical_cpu_count() {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                // Per-CPU counters have no honest carrick source.
                return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
            }

            // Group leader validation: EBADF for a closed fd OR a non-perf fd
            // (verified: /dev/null as group_fd is EBADF).
            let leader = if group_fd >= 0 && !flags.contains(PerfEventOpenFlags::FD_NO_GROUP) {
                match this.perf_event_state(group_fd) {
                    Some(leader) => Some(leader),
                    None => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                }
            } else if group_fd >= 0 {
                // FD_NO_GROUP: group_fd must still be a valid perf fd.
                if this.perf_event_state(group_fd).is_none() {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                None
            } else {
                None
            };

            // Event selection: everything carrick cannot measure is ENOENT —
            // the "generic event not supported" answer the oracle gives for
            // hardware events inside its VM. Never fabricate a counter.
            let event = if parsed.type_ == LINUX_PERF_TYPE_SOFTWARE {
                PerfSwEvent::from_config(parsed.config)
            } else {
                None
            };
            let Some(event) = event else {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            };

            // Sampling: carrick delivers no overflow samples; refuse rather
            // than return a sampling fd that never fires (see module docs).
            if parsed.sample_period != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
            }

            let state = Arc::new(PerfEventState::new(
                event,
                parsed.read_format,
                Self::perf_caller(cx),
            ));
            if !parsed.flags.contains(PerfEventAttrFlags::DISABLED) {
                state.enable(state.ledger());
            }
            if let Some(leader) = leader {
                leader.members.lock().push(Arc::clone(&state));
            }
            let fd_flags = if flags.contains(PerfEventOpenFlags::FD_CLOEXEC) {
                LINUX_FD_CLOEXEC
            } else {
                0
            };
            let description = OpenDescription::PerfEvent {
                base: OpenDescriptionBase::new(0),
                state,
            };
            Ok(this.install_fd(description, fd_flags))
        }
    }
}

/// Build the caller identity from the calling thread id.
/// Perf's notion of "the caller's own task": 0, the calling thread's tid, or
/// the caller's pid aliases. Mirrors `sched_pid_is_self` in `proc.rs`.
fn sched_pid_is_self_for_perf<M: GuestMemory>(cx: &SyscallCtx<'_, M>, pid: u64) -> bool {
    super::proc::sched_pid_is_self(cx, pid)
}

/// Whether `pid` names some other LIVE guest task (sibling thread or another
/// Linux process) — the ESRCH / EOPNOTSUPP split for foreign targets. Routed
/// through the same resolver every `sched_*` handler uses, so the HVPatch lane
/// (where a Linux process is a THREAD of the VM carrier and libproc knows
/// nothing about it) answers from carrick's kernel graph rather than the Darwin
/// ppid chain.
fn sched_pid_names_live_task<M: GuestMemory>(
    this: &SyscallDispatcher,
    cx: &SyscallCtx<'_, M>,
    pid: u64,
) -> bool {
    super::proc::sched_pid_is_live_guest_thread(cx, pid)
        || matches!(
            super::proc::resolve_sched_target(this, cx, pid),
            super::proc::SchedTarget::OtherGuest { .. }
        )
}

#[cfg(test)]
mod tests {
    //! Attr size-versioning, errno shape, and counter read-format tests.
    //! Every expectation here was captured differentially from the native
    //! arm64 Docker oracle (2026-08-18): E2BIG/ESRCH/EINVAL orderings, the
    //! attr.size write-back, ENOSPC short reads, ESPIPE lseek, EINVAL write,
    //! ENOTTY unknown ioctls, and the read_format wire sizes.
    use super::*;
    use crate::compat::CompatReporter;

    const MEM_BASE: u64 = 0x4000_0000;
    const ATTR: u64 = MEM_BASE + 0x100;
    const OUT: u64 = MEM_BASE + 0x800;

    /// Little-endian perf_event_attr image: type/size/config/sample_period/
    /// read_format/flags at the man page's offsets, zero elsewhere.
    fn attr_bytes(
        type_: u32,
        size: u32,
        config: u64,
        sample_period: u64,
        read_format: u64,
        flags: u64,
        total_len: usize,
    ) -> Vec<u8> {
        let mut bytes = vec![0u8; total_len.max(LINUX_PERF_ATTR_SIZE_VER0 as usize)];
        bytes[0..4].copy_from_slice(&type_.to_le_bytes());
        bytes[4..8].copy_from_slice(&size.to_le_bytes());
        bytes[8..16].copy_from_slice(&config.to_le_bytes());
        bytes[16..24].copy_from_slice(&sample_period.to_le_bytes());
        bytes[32..40].copy_from_slice(&read_format.to_le_bytes());
        bytes[40..48].copy_from_slice(&flags.to_le_bytes());
        bytes
    }

    const DISABLED_EXCLUDES: u64 = 1 | (1 << 5) | (1 << 6); // disabled|exclude_kernel|exclude_hv

    fn memory() -> LinearMemory {
        LinearMemory::new(MEM_BASE, vec![0u8; 16 * 1024])
    }

    fn dispatch(
        dispatcher: &mut SyscallDispatcher,
        memory: &mut LinearMemory,
        nr: u64,
        args: [u64; 6],
    ) -> DispatchOutcome {
        let reporter = CompatReporter::default();
        let kernel = dispatcher
            .capture_one_task_context()
            .expect("single-task kernel context");
        dispatcher
            .dispatch(
                &kernel,
                SyscallRequest::new(nr, SyscallArgs(args)),
                memory,
                &reporter,
            )
            .expect("dispatch")
    }

    /// perf_event_open(attr, pid, cpu, group_fd, flags) via the dispatcher.
    fn open_event(
        dispatcher: &mut SyscallDispatcher,
        memory: &mut LinearMemory,
        attr: &[u8],
        pid: i64,
        cpu: i64,
        group_fd: i64,
        flags: u64,
    ) -> DispatchOutcome {
        memory.write_bytes(ATTR, attr).expect("write attr");
        dispatch(
            dispatcher,
            memory,
            241,
            [ATTR, pid as u64, cpu as u64, group_fd as u64, flags, 0],
        )
    }

    fn open_sw_fd(
        dispatcher: &mut SyscallDispatcher,
        memory: &mut LinearMemory,
        config: u64,
    ) -> i32 {
        let attr = attr_bytes(
            LINUX_PERF_TYPE_SOFTWARE,
            LINUX_PERF_ATTR_SIZE_SUPPORTED,
            config,
            0,
            0,
            DISABLED_EXCLUDES,
            LINUX_PERF_ATTR_SIZE_SUPPORTED as usize,
        );
        match open_event(dispatcher, memory, &attr, 0, -1, -1, 0) {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("sw event must open: {other:?}"),
        }
    }

    // ── parse_perf_attr: size versioning + reserved bits ──

    #[test]
    fn attr_size_zero_reads_as_ver0() {
        let bytes = attr_bytes(LINUX_PERF_TYPE_SOFTWARE, 0, 0, 0, 0, 1, 64);
        let parsed = parse_perf_attr(&bytes, 0).expect("size 0 is VER0");
        assert_eq!(parsed.type_, LINUX_PERF_TYPE_SOFTWARE);
        assert!(parsed.flags.contains(PerfEventAttrFlags::DISABLED));
    }

    #[test]
    fn attr_size_below_ver0_is_size_mismatch() {
        for size in [1u32, 8, 63] {
            let bytes = attr_bytes(LINUX_PERF_TYPE_SOFTWARE, size, 0, 0, 0, 1, 64);
            assert_eq!(
                parse_perf_attr(&bytes, size),
                Err(PerfAttrError::SizeMismatch),
                "size {size} must be E2BIG"
            );
        }
    }

    #[test]
    fn attr_oversize_with_zero_tail_is_accepted() {
        let bytes = attr_bytes(LINUX_PERF_TYPE_SOFTWARE, 4096, 1, 0, 0, 1, 4096);
        let parsed = parse_perf_attr(&bytes, 4096).expect("zero tail accepted");
        assert_eq!(parsed.config, 1);
    }

    #[test]
    fn attr_oversize_with_dirty_tail_is_size_mismatch() {
        let mut bytes = attr_bytes(LINUX_PERF_TYPE_SOFTWARE, 4096, 1, 0, 0, 1, 4096);
        bytes[200] = 1;
        assert_eq!(
            parse_perf_attr(&bytes, 4096),
            Err(PerfAttrError::SizeMismatch)
        );
    }

    #[test]
    fn attr_reserved_flag_bit_is_invalid() {
        let bytes = attr_bytes(LINUX_PERF_TYPE_SOFTWARE, 128, 0, 0, 0, 1 | (1 << 63), 128);
        assert_eq!(parse_perf_attr(&bytes, 128), Err(PerfAttrError::Invalid));
    }

    #[test]
    fn attr_unknown_read_format_bit_is_invalid() {
        let bytes = attr_bytes(LINUX_PERF_TYPE_SOFTWARE, 128, 0, 0, 1 << 60, 1, 128);
        assert_eq!(parse_perf_attr(&bytes, 128), Err(PerfAttrError::Invalid));
    }

    // ── read-format wire layout ──

    #[test]
    fn read_sizes_match_the_format() {
        use PerfEventReadFormat as F;
        assert_eq!(perf_read_size(F::empty(), 1), 8);
        assert_eq!(perf_read_size(F::TOTAL_TIME_ENABLED, 1), 16);
        assert_eq!(
            perf_read_size(F::TOTAL_TIME_ENABLED | F::TOTAL_TIME_RUNNING | F::ID, 1),
            32
        );
        assert_eq!(perf_read_size(F::ID | F::LOST, 1), 24);
        // GROUP: nr + times + per-event {value,id,lost}
        assert_eq!(
            perf_read_size(
                F::GROUP | F::TOTAL_TIME_ENABLED | F::TOTAL_TIME_RUNNING | F::ID,
                2
            ),
            8 + 8 + 8 + 2 * (8 + 8)
        );
    }

    #[test]
    fn encode_matches_the_man_page_order() {
        use PerfEventReadFormat as F;
        let fmt = F::TOTAL_TIME_ENABLED | F::TOTAL_TIME_RUNNING | F::ID;
        let bytes = encode_perf_read(fmt, (7, 7), &[(42, 9)]);
        assert_eq!(bytes.len(), 32);
        let words: Vec<u64> = bytes
            .chunks(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();
        assert_eq!(words, vec![42, 7, 7, 9]);

        let group = F::GROUP | F::TOTAL_TIME_ENABLED | F::ID;
        let bytes = encode_perf_read(group, (5, 5), &[(1, 11), (2, 12)]);
        let words: Vec<u64> = bytes
            .chunks(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();
        assert_eq!(words, vec![2, 5, 1, 11, 2, 12]);
    }

    // ── dispatch-level errno shape (oracle-verified) ──

    #[test]
    fn open_size_mismatch_is_e2big_and_writes_supported_size_back() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = memory();
        let attr = attr_bytes(LINUX_PERF_TYPE_SOFTWARE, 8, 0, 0, 0, DISABLED_EXCLUDES, 64);
        assert_eq!(
            open_event(&mut dispatcher, &mut memory, &attr, 0, -1, -1, 0),
            DispatchOutcome::Errno { errno: LINUX_E2BIG }
        );
        let size_back = memory.read_bytes(ATTR + 4, 4).unwrap();
        assert_eq!(
            u32::from_le_bytes(size_back.try_into().unwrap()),
            LINUX_PERF_ATTR_SIZE_SUPPORTED,
            "E2BIG must write the supported attr.size back"
        );
        // Ordering: E2BIG outranks the bad-pid ESRCH and bad-cpu EINVAL.
        let attr = attr_bytes(LINUX_PERF_TYPE_SOFTWARE, 8, 0, 0, 0, DISABLED_EXCLUDES, 64);
        assert_eq!(
            open_event(&mut dispatcher, &mut memory, &attr, 999_999, 4096, -1, 0),
            DispatchOutcome::Errno { errno: LINUX_E2BIG }
        );
    }

    #[test]
    fn open_hardware_and_unknown_events_are_enoent() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = memory();
        // PERF_TYPE_HARDWARE (no guest PMU), an unknown type, and an unknown
        // software config all answer ENOENT — the oracle's VM answer.
        for (type_, config) in [
            (0u32, 0u64),
            (0xffff, 0),
            (LINUX_PERF_TYPE_SOFTWARE, 0xffff),
        ] {
            let attr = attr_bytes(type_, 128, config, 0, 0, DISABLED_EXCLUDES, 128);
            assert_eq!(
                open_event(&mut dispatcher, &mut memory, &attr, 0, -1, -1, 0),
                DispatchOutcome::Errno {
                    errno: LINUX_ENOENT
                },
                "type {type_} config {config} must be ENOENT"
            );
        }
    }

    #[test]
    fn open_rejects_bad_target_combinations() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = memory();
        let attr = || {
            attr_bytes(
                LINUX_PERF_TYPE_SOFTWARE,
                128,
                0,
                0,
                0,
                DISABLED_EXCLUDES,
                128,
            )
        };
        // pid=-1 cpu=-1 → EINVAL (man page).
        assert_eq!(
            open_event(&mut dispatcher, &mut memory, &attr(), -1, -1, -1, 0),
            DispatchOutcome::Errno {
                errno: LINUX_EINVAL
            }
        );
        // Nonexistent pid → ESRCH, and it outranks the bad-cpu EINVAL.
        assert_eq!(
            open_event(&mut dispatcher, &mut memory, &attr(), 999_999, -1, -1, 0),
            DispatchOutcome::Errno { errno: LINUX_ESRCH }
        );
        assert_eq!(
            open_event(&mut dispatcher, &mut memory, &attr(), 999_999, 4096, -1, 0),
            DispatchOutcome::Errno { errno: LINUX_ESRCH }
        );
        // cpu beyond the online range → EINVAL.
        assert_eq!(
            open_event(&mut dispatcher, &mut memory, &attr(), 0, 1 << 20, -1, 0),
            DispatchOutcome::Errno {
                errno: LINUX_EINVAL
            }
        );
        // Unknown open-flags bit → EINVAL.
        assert_eq!(
            open_event(&mut dispatcher, &mut memory, &attr(), 0, -1, -1, 0x1000),
            DispatchOutcome::Errno {
                errno: LINUX_EINVAL
            }
        );
        // group_fd that is not an open fd, or not a perf fd → EBADF.
        assert_eq!(
            open_event(&mut dispatcher, &mut memory, &attr(), 0, -1, 42, 0),
            DispatchOutcome::Errno { errno: LINUX_EBADF }
        );
    }

    #[test]
    fn open_sampling_event_is_refused_not_faked() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = memory();
        let attr = attr_bytes(
            LINUX_PERF_TYPE_SOFTWARE,
            128,
            0,
            1000,
            0,
            DISABLED_EXCLUDES,
            128,
        );
        assert_eq!(
            open_event(&mut dispatcher, &mut memory, &attr, 0, -1, -1, 0),
            DispatchOutcome::Errno {
                errno: LINUX_EOPNOTSUPP
            }
        );
    }

    #[test]
    fn counter_lifecycle_reset_enable_read_disable() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = memory();
        let fd = open_sw_fd(&mut dispatcher, &mut memory, LINUX_PERF_COUNT_SW_CPU_CLOCK);
        // RESET + ENABLE + DISABLE all return 0 (the LTP perf_event_open01
        // sequence).
        for request in [
            LINUX_PERF_EVENT_IOC_RESET,
            LINUX_PERF_EVENT_IOC_ENABLE,
            LINUX_PERF_EVENT_IOC_DISABLE,
        ] {
            assert_eq!(
                dispatch(
                    &mut dispatcher,
                    &mut memory,
                    29,
                    [fd as u64, request, 0, 0, 0, 0]
                ),
                DispatchOutcome::Returned { value: 0 },
                "ioctl {request:#x} must succeed"
            );
        }
        // read(2) of a u64 succeeds; a second read re-reports (no drain).
        for _ in 0..2 {
            assert_eq!(
                dispatch(
                    &mut dispatcher,
                    &mut memory,
                    63,
                    [fd as u64, OUT, 8, 0, 0, 0]
                ),
                DispatchOutcome::Returned { value: 8 }
            );
        }
        // Short read → ENOSPC (oracle-verified).
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &mut memory,
                63,
                [fd as u64, OUT, 4, 0, 0, 0]
            ),
            DispatchOutcome::Errno {
                errno: LINUX_ENOSPC
            }
        );
        // lseek → ESPIPE; write → EINVAL; unknown (tty) ioctl → ENOTTY.
        assert_eq!(
            dispatch(&mut dispatcher, &mut memory, 62, [fd as u64, 0, 0, 0, 0, 0]),
            DispatchOutcome::Errno {
                errno: LINUX_ESPIPE
            }
        );
        memory.write_bytes(OUT, &[0u8]).unwrap();
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &mut memory,
                64,
                [fd as u64, OUT, 1, 0, 0, 0]
            ),
            DispatchOutcome::Errno {
                errno: LINUX_EINVAL
            }
        );
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &mut memory,
                29,
                [fd as u64, 0x5401, 0, 0, 0, 0]
            ),
            DispatchOutcome::Errno {
                errno: LINUX_ENOTTY
            }
        );
    }

    #[test]
    fn time_enabled_accrues_and_id_ioctl_reports_the_event_id() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = memory();
        // TOTAL_TIME_ENABLED|TOTAL_TIME_RUNNING|ID → 32-byte reads.
        let attr = attr_bytes(
            LINUX_PERF_TYPE_SOFTWARE,
            128,
            LINUX_PERF_COUNT_SW_TASK_CLOCK,
            0,
            0x7,
            DISABLED_EXCLUDES,
            128,
        );
        let fd = match open_event(&mut dispatcher, &mut memory, &attr, 0, -1, -1, 0) {
            DispatchOutcome::Returned { value } => value,
            other => panic!("open: {other:?}"),
        };
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &mut memory,
                29,
                [fd as u64, LINUX_PERF_EVENT_IOC_ENABLE, 0, 0, 0, 0]
            ),
            DispatchOutcome::Returned { value: 0 }
        );
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &mut memory,
                29,
                [fd as u64, LINUX_PERF_EVENT_IOC_DISABLE, 0, 0, 0, 0]
            ),
            DispatchOutcome::Returned { value: 0 }
        );
        // A 24-byte buffer for a 32-byte format is ENOSPC.
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &mut memory,
                63,
                [fd as u64, OUT, 24, 0, 0, 0]
            ),
            DispatchOutcome::Errno {
                errno: LINUX_ENOSPC
            }
        );
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &mut memory,
                63,
                [fd as u64, OUT, 32, 0, 0, 0]
            ),
            DispatchOutcome::Returned { value: 32 }
        );
        let bytes = memory.read_bytes(OUT, 32).unwrap();
        let words: Vec<u64> = bytes
            .chunks(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();
        // words: [value, time_enabled, time_running, id]
        assert!(words[1] > 0, "time_enabled accrues wall time while enabled");
        assert_eq!(words[1], words[2], "no multiplexing: running == enabled");
        // PERF_EVENT_IOC_ID writes the same id read(2) reports.
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &mut memory,
                29,
                [fd as u64, LINUX_PERF_EVENT_IOC_ID, OUT + 0x100, 0, 0, 0]
            ),
            DispatchOutcome::Returned { value: 0 }
        );
        let id = u64::from_le_bytes(
            memory
                .read_bytes(OUT + 0x100, 8)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(id, words[3]);
        assert!(id > 0);
    }

    #[test]
    fn grouped_events_open_and_dummy_counts_zero() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = memory();
        let leader = open_sw_fd(&mut dispatcher, &mut memory, LINUX_PERF_COUNT_SW_CPU_CLOCK);
        // A software event groups under a software leader (tst 02's shape).
        let attr = attr_bytes(
            LINUX_PERF_TYPE_SOFTWARE,
            128,
            LINUX_PERF_COUNT_SW_TASK_CLOCK,
            0,
            0,
            0, // enabled at open (disabled=0)
            128,
        );
        let member = match open_event(&mut dispatcher, &mut memory, &attr, 0, -1, leader as i64, 0)
        {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("grouped open: {other:?}"),
        };
        assert!(member >= 0);
        // Dummy counts nothing.
        let dummy = open_sw_fd(&mut dispatcher, &mut memory, LINUX_PERF_COUNT_SW_DUMMY);
        for request in [LINUX_PERF_EVENT_IOC_ENABLE, LINUX_PERF_EVENT_IOC_DISABLE] {
            assert_eq!(
                dispatch(
                    &mut dispatcher,
                    &mut memory,
                    29,
                    [dummy as u64, request, 0, 0, 0, 0]
                ),
                DispatchOutcome::Returned { value: 0 }
            );
        }
        assert_eq!(
            dispatch(
                &mut dispatcher,
                &mut memory,
                63,
                [dummy as u64, OUT, 8, 0, 0, 0]
            ),
            DispatchOutcome::Returned { value: 8 }
        );
        let value = u64::from_le_bytes(memory.read_bytes(OUT, 8).unwrap().try_into().unwrap());
        assert_eq!(value, 0, "the dummy event never counts");
    }

    /// The counter's owner is the kernel-graph `Thread` object, NOT a host pid
    /// (which under HVPatch names the shared VM carrier and would be identical
    /// for every logical Linux process). Proven structurally: a counter reads
    /// through a `Weak<Thread>`, so once that thread object is dropped the
    /// sample reports `Reaped` and the value stops advancing instead of
    /// silently re-attributing to whoever calls `read(2)`.
    #[test]
    fn counter_measures_its_own_thread_not_the_calling_host_process() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = memory();
        let fd = open_sw_fd(&mut dispatcher, &mut memory, LINUX_PERF_COUNT_SW_CPU_CLOCK);
        let state = dispatcher.perf_event_state(fd).expect("perf fd");

        // A live owner samples that thread's ledger.
        assert!(
            matches!(state.ledger(), PerfLedger::Live(_)),
            "a live measured thread must sample its own ledger"
        );

        // Drop the measured thread: the counter must report Reaped rather than
        // fall back to the caller's CPU.
        let orphan = Arc::new(PerfEventState::new(
            PerfSwEvent::CpuClock,
            PerfEventReadFormat::empty(),
            PerfOwner {
                thread: std::sync::Weak::new(),
            },
        ));
        assert!(
            matches!(orphan.ledger(), PerfLedger::Reaped),
            "a counter whose thread is gone must stop advancing, not re-attribute"
        );
        // Still readable (Linux keeps an exited task's counter readable).
        orphan.enable(orphan.ledger());
        orphan.disable(orphan.ledger());
        let (value, _, _) = orphan.snapshot(orphan.ledger());
        assert_eq!(value, 0, "a reaped counter reports its frozen value");
    }
}
