use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use bitflags::bitflags;

use crate::arena::ArenaError;
use crate::domains::{HostPid, ProcessGeneration};

pub const PROCESS_RECORDS: usize = 4096;

bitflags! {
    /// Process lifecycle flags stored in [`ProcessRecord.flags`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ProcessFlags: u32 {
        const ALIVE = 1 << 0;
        const ORPHANED = 1 << 1;
        const DEAD = 1 << 2;
        const ADOPTED = 1 << 3;
        /// The owner is a CARRIER TASK, not a host process.
        ///
        /// Under HVPatch every Linux process is a task inside one Darwin
        /// process, so this record's `host_pid` field holds a GUEST pid. Any
        /// host-pid liveness probe against it (`kill(pid, 0)`) is meaningless:
        /// it names an unrelated host process or none at all. The flag lives on
        /// the RECORD rather than in a process-local static because the arena
        /// can also be attached by compatibility joiners such as transitional
        /// `carrick exec`; every arena reader must honor the carrier's owner
        /// domain rather than infer it from its own process-local state.
        const OWNER_GUEST_TASK = 1 << 4;
    }
}

pub const FLAG_ALIVE: u32 = ProcessFlags::ALIVE.bits();
pub const FLAG_ORPHANED: u32 = ProcessFlags::ORPHANED.bits();
pub const FLAG_DEAD: u32 = ProcessFlags::DEAD.bits();
pub const FLAG_ADOPTED: u32 = ProcessFlags::ADOPTED.bits();
pub const FLAG_OWNER_GUEST_TASK: u32 = ProcessFlags::OWNER_GUEST_TASK.bits();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Busy;

impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "process record transition busy")
    }
}

impl std::error::Error for Busy {}

impl From<Busy> for ProcessRecordTransitionError {
    fn from(_: Busy) -> Self {
        Self::Busy
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordState {
    Free,
    Registering,
    Live { host_pid: HostPid },
    Transitioning { host_pid: HostPid },
    Retiring,
}

impl RecordState {
    pub const fn host_pid(self) -> Option<HostPid> {
        match self {
            Self::Live { host_pid } | Self::Transitioning { host_pid } => Some(host_pid),
            Self::Free | Self::Registering | Self::Retiring => None,
        }
    }

    pub const fn is_free(self) -> bool {
        matches!(self, Self::Free)
    }

    pub const fn is_registering(self) -> bool {
        matches!(self, Self::Registering)
    }

    pub const fn is_live(self) -> bool {
        matches!(self, Self::Live { .. })
    }

    pub const fn is_transitioning(self) -> bool {
        matches!(self, Self::Transitioning { .. })
    }

    pub const fn is_retiring(self) -> bool {
        matches!(self, Self::Retiring)
    }
}

#[derive(Debug)]
pub struct RegisteringToken<'a> {
    cell: &'a RecordStateCell,
    disarmed: bool,
}

impl<'a> RegisteringToken<'a> {
    pub fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl<'a> Drop for RegisteringToken<'a> {
    fn drop(&mut self) {
        if !self.disarmed {
            let _ = self.cell.raw.compare_exchange(
                RecordStateCell::pack(RecordState::Registering),
                RecordStateCell::pack(RecordState::Free),
                Ordering::Release,
                Ordering::Relaxed,
            );
        }
    }
}

#[derive(Debug)]
pub struct TransitionGuard<'a> {
    cell: &'a RecordStateCell,
    host_pid: HostPid,
    disarmed: bool,
}

impl<'a> TransitionGuard<'a> {
    pub fn host_pid(&self) -> HostPid {
        self.host_pid
    }

    pub fn disarm(&mut self) {
        self.disarmed = true;
    }

    pub fn retire(mut self) {
        self.disarmed = true;
        self.cell.raw.store(
            RecordStateCell::pack(RecordState::Retiring),
            Ordering::Release,
        );
    }
}

impl<'a> Drop for TransitionGuard<'a> {
    fn drop(&mut self) {
        if !self.disarmed {
            let _ = self.cell.raw.compare_exchange(
                RecordStateCell::pack(RecordState::Transitioning {
                    host_pid: self.host_pid,
                }),
                RecordStateCell::pack(RecordState::Live {
                    host_pid: self.host_pid,
                }),
                Ordering::Release,
                Ordering::Relaxed,
            );
        }
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct RecordStateCell {
    raw: AtomicU64,
}

impl Default for RecordStateCell {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordStateCell {
    const TAG_FREE: u32 = 0;
    const TAG_REGISTERING: u32 = 1;
    const TAG_LIVE: u32 = 2;
    const TAG_TRANSITIONING: u32 = 3;
    const TAG_RETIRING: u32 = 4;

    pub const fn new() -> Self {
        Self {
            raw: AtomicU64::new(0),
        }
    }

    pub fn state(&self) -> RecordState {
        Self::unpack(self.raw.load(Ordering::Acquire))
    }

    pub fn claim(&self) -> Result<RegisteringToken<'_>, Busy> {
        match self.raw.compare_exchange(
            Self::pack(RecordState::Free),
            Self::pack(RecordState::Registering),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(RegisteringToken {
                cell: self,
                disarmed: false,
            }),
            Err(_) => Err(Busy),
        }
    }

    pub fn publish(&self, mut token: RegisteringToken<'_>, host_pid: HostPid) {
        token.disarm();
        let old = self.raw.swap(
            Self::pack(RecordState::Live { host_pid }),
            Ordering::Release,
        );
        debug_assert_eq!(
            (old >> 32) as u32,
            Self::TAG_REGISTERING,
            "publish must transition from Registering"
        );
    }

    pub fn publish_deferred(&self, host_pid: HostPid) -> bool {
        let expected = Self::pack(RecordState::Registering);
        let desired = Self::pack(RecordState::Live { host_pid });
        match self
            .raw
            .compare_exchange(expected, desired, Ordering::Release, Ordering::Acquire)
        {
            Ok(_) => true,
            Err(actual) => actual == desired,
        }
    }

    pub fn begin_transition(&self) -> Option<TransitionGuard<'_>> {
        let mut current = self.raw.load(Ordering::Acquire);
        loop {
            let state = Self::unpack(current);
            let RecordState::Live { host_pid } = state else {
                return None;
            };
            let desired = Self::pack(RecordState::Transitioning { host_pid });
            match self.raw.compare_exchange_weak(
                current,
                desired,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(TransitionGuard {
                        cell: self,
                        host_pid,
                        disarmed: false,
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }

    pub fn release_transition(&self) {
        let current = self.raw.load(Ordering::Acquire);
        let RecordState::Transitioning { host_pid } = Self::unpack(current) else {
            return;
        };
        let _ = self.raw.compare_exchange(
            current,
            Self::pack(RecordState::Live { host_pid }),
            Ordering::Release,
            Ordering::Relaxed,
        );
    }

    pub fn finish_retire(&self) {
        self.raw
            .store(Self::pack(RecordState::Free), Ordering::Release);
    }

    const fn pack(state: RecordState) -> u64 {
        match state {
            RecordState::Free => 0,
            RecordState::Registering => (Self::TAG_REGISTERING as u64) << 32,
            RecordState::Live { host_pid } => {
                ((Self::TAG_LIVE as u64) << 32) | (host_pid.raw() as u64)
            }
            RecordState::Transitioning { host_pid } => {
                ((Self::TAG_TRANSITIONING as u64) << 32) | (host_pid.raw() as u64)
            }
            RecordState::Retiring => (Self::TAG_RETIRING as u64) << 32,
        }
    }

    const fn unpack(raw: u64) -> RecordState {
        let tag = (raw >> 32) as u32;
        let pid = raw as u32;
        match tag {
            Self::TAG_FREE => RecordState::Free,
            Self::TAG_REGISTERING => RecordState::Registering,
            Self::TAG_LIVE => {
                if pid == 0 {
                    RecordState::Free
                } else {
                    RecordState::Live {
                        host_pid: HostPid::new(pid),
                    }
                }
            }
            Self::TAG_TRANSITIONING => {
                if pid == 0 {
                    RecordState::Free
                } else {
                    RecordState::Transitioning {
                        host_pid: HostPid::new(pid),
                    }
                }
            }
            Self::TAG_RETIRING => RecordState::Retiring,
            _ => RecordState::Free,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum VirtualPtraceState {
    Untraced = 0,
    Running = 1,
    StopRequested = 2,
    StopReported = 3,
    ResumeRequested = 4,
    KillRequested = 5,
    DetachRequested = 6,
    StopPreparing = 7,
}

impl VirtualPtraceState {
    pub const fn raw(self) -> u32 {
        self as u32
    }

    pub const fn decode_shared(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Untraced),
            1 => Some(Self::Running),
            2 => Some(Self::StopRequested),
            3 => Some(Self::StopReported),
            4 => Some(Self::ResumeRequested),
            5 => Some(Self::KillRequested),
            6 => Some(Self::DetachRequested),
            7 => Some(Self::StopPreparing),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtualPtraceControl {
    tracer_pid: u32,
    generation: ProcessGeneration,
    state: VirtualPtraceState,
}

impl VirtualPtraceControl {
    const STATE_BITS: u32 = 3;
    const STATE_MASK: u32 = (1 << Self::STATE_BITS) - 1;
    const MAX_TRACER_PID: u32 = u32::MAX >> Self::STATE_BITS;

    pub const fn untraced() -> Self {
        Self {
            tracer_pid: 0,
            generation: ProcessGeneration::NONE,
            state: VirtualPtraceState::Untraced,
        }
    }

    pub const fn traced(
        tracer_pid: u32,
        generation: ProcessGeneration,
        state: VirtualPtraceState,
    ) -> Option<Self> {
        if tracer_pid == 0
            || tracer_pid > Self::MAX_TRACER_PID
            || generation.raw() == ProcessGeneration::NONE.raw()
            || matches!(state, VirtualPtraceState::Untraced)
        {
            return None;
        }
        Some(Self {
            tracer_pid,
            generation,
            state,
        })
    }

    pub const fn decode_shared(raw: u64) -> Option<Self> {
        let encoded_control = raw as u32;
        let tracer_pid = encoded_control >> Self::STATE_BITS;
        let generation = ProcessGeneration::new((raw >> 32) as u32);
        let state = match VirtualPtraceState::decode_shared(encoded_control & Self::STATE_MASK) {
            Some(state) => state,
            None => return None,
        };
        if matches!(state, VirtualPtraceState::Untraced) {
            if tracer_pid != 0 || generation.raw() != ProcessGeneration::NONE.raw() {
                return None;
            }
        } else if tracer_pid == 0 || generation.raw() == ProcessGeneration::NONE.raw() {
            return None;
        }
        Some(Self {
            tracer_pid,
            generation,
            state,
        })
    }

    pub const fn raw(self) -> u64 {
        (self.generation.raw() as u64) << 32
            | ((self.tracer_pid << Self::STATE_BITS) | self.state.raw()) as u64
    }

    pub const fn tracer_pid(self) -> u32 {
        self.tracer_pid
    }

    pub const fn generation(self) -> ProcessGeneration {
        self.generation
    }

    pub const fn state(self) -> VirtualPtraceState {
        self.state
    }
}

/// The carrier's ONE process-record table. Namespace numbering words live per
/// namespace in `crate::pidns`; a record's `pid_ns` tag names its owner.
#[repr(C)]
pub struct ProcessSection {
    pub records: [ProcessRecord; PROCESS_RECORDS],
}

#[repr(C)]
pub struct ProcessRecord {
    pub state_cell: RecordStateCell,
    pub host_pid: AtomicU32,
    pub generation: AtomicU32,
    pub ns_pid: AtomicU32,
    pub parent_host_pid: AtomicU32,
    pub subreaper_pid: AtomicU32,
    pub flags: AtomicU32,
    pub exec_generation: AtomicU32,
    pub pgid: AtomicU32,
    pub sid: AtomicU32,
    pub ctty: AtomicU32,
    pub run_state: AtomicU64,
    pub ptrace_stop_signal: AtomicU64,
    pub exit_status: AtomicU64,
    pub ptrace_control: AtomicU64,
    pub exit_ready: AtomicU32,
    /// The PID namespace this record is a member of (`PidNamespaceRef::ns_id`),
    /// or 0 while it carries no namespace identity (run-state/guest-CPU only).
    pub pid_ns: AtomicU32,
    pub guest_ns: AtomicU64,
}

/// Index + generation pair so a stale ref cannot touch a reused slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessRecordRef {
    pub index: usize,
    pub generation: ProcessGeneration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessRecordTransitionAction {
    Preserve,
    Retire,
    RetireIfNamespaceUnowned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessRecordTransitionError {
    Busy,
    Stale,
}

impl ProcessSection {
    /// Claim a free record, fill via the closure, and publish `host_pid` last.
    pub fn claim(
        &self,
        host_pid: Option<HostPid>,
        generation: ProcessGeneration,
        fill: impl FnOnce(&ProcessRecord),
    ) -> Result<ProcessRecordRef, ArenaError> {
        for (index, record) in self.records.iter().enumerate() {
            let Ok(mut token) = record.state_cell.claim() else {
                continue;
            };

            record.clear_body_for_claim();
            record.generation.store(generation.raw(), Ordering::Release);
            fill(record);
            if let Some(pid) = host_pid {
                record.state_cell.publish(token, pid);
                record.host_pid.store(pid.raw(), Ordering::Release);
            } else {
                token.disarm();
            }
            return Ok(ProcessRecordRef { index, generation });
        }
        Err(ArenaError::Exhausted {
            section: "processes",
            capacity: PROCESS_RECORDS,
        })
    }

    pub fn find(&self, host_pid: HostPid) -> Option<ProcessRecordRef> {
        let wanted = host_pid.raw();
        if wanted == 0 {
            return None;
        }

        for (index, record) in self.records.iter().enumerate() {
            match record.state() {
                RecordState::Live { host_pid: p } | RecordState::Transitioning { host_pid: p }
                    if p == host_pid => {}
                _ => continue,
            }
            let generation = record.generation.load(Ordering::Acquire);
            if generation != 0 {
                return Some(ProcessRecordRef {
                    index,
                    generation: ProcessGeneration::new(generation),
                });
            }
        }
        None
    }

    pub fn publish_host_pid(&self, r: ProcessRecordRef, pid: HostPid) {
        if let Some(record) = self.record_for_ref(r) {
            record.state_cell.publish_deferred(pid);
            record.host_pid.store(pid.raw(), Ordering::Release);
        }
    }

    pub fn release(&self, r: ProcessRecordRef) -> bool {
        let Some(record) = self.record_for_ref(r) else {
            return false;
        };
        let Some(guard) = record.begin_transition() else {
            return false;
        };
        if record.generation.load(Ordering::Acquire) != r.generation.raw() {
            return false;
        }
        self.release_claimed(r, record, guard);
        true
    }

    /// Release a record only when no namespace member owns it.
    ///
    /// Namespace adoption and task retirement share the record, so checking
    /// `ns_pid == 0` and releasing later is racy. The transition bit makes the
    /// ownership verdict and release one critical section. A failed claim or a
    /// published/in-progress namespace owner leaves the record untouched.
    pub fn release_if_namespace_unowned(
        &self,
        r: ProcessRecordRef,
        expected_host_pid: HostPid,
    ) -> bool {
        let Some(record) = self.record_for_ref(r) else {
            return false;
        };
        let Some(guard) = record.begin_transition() else {
            return false;
        };
        let owns_record = record.generation.load(Ordering::Acquire) == r.generation.raw()
            && record.state().host_pid() == Some(expected_host_pid)
            && record.ns_pid.load(Ordering::Acquire) == 0;
        if !owns_record {
            return false;
        }
        self.release_claimed(r, record, guard);
        true
    }

    /// Inspect and update one exact record while holding its lifecycle claim.
    ///
    /// The closure may mutate record-local metadata. If it requests retirement,
    /// the slot is released only when namespace identity is still unpublished;
    /// otherwise the namespace-owned record is preserved and unlocked. This
    /// composes classification, cleanup, and release without a check-then-write
    /// window against reuse.
    pub fn with_record_transition<T>(
        &self,
        r: ProcessRecordRef,
        expected_host_pid: HostPid,
        update: impl FnOnce(&ProcessRecord) -> (T, ProcessRecordTransitionAction),
    ) -> Result<(T, bool), ProcessRecordTransitionError> {
        let Some(record) = self.record_for_ref(r) else {
            return Err(ProcessRecordTransitionError::Stale);
        };
        let Some(guard) = record.begin_transition() else {
            return Err(ProcessRecordTransitionError::Busy);
        };
        let owns_record = record.generation.load(Ordering::Acquire) == r.generation.raw()
            && record.state().host_pid() == Some(expected_host_pid);
        if !owns_record {
            return Err(ProcessRecordTransitionError::Stale);
        }

        let (value, action) = update(record);
        let released = action == ProcessRecordTransitionAction::Retire
            || (action == ProcessRecordTransitionAction::RetireIfNamespaceUnowned
                && record.ns_pid.load(Ordering::Acquire) == 0);
        if released {
            self.release_claimed(r, record, guard);
        }
        Ok((value, released))
    }

    fn release_claimed(
        &self,
        r: ProcessRecordRef,
        record: &ProcessRecord,
        guard: TransitionGuard<'_>,
    ) {
        if std::env::var_os("CARRICK_RUNSTATE_DEBUG").is_some() {
            eprintln!(
                "[RUNSTATE] release idx={} host_pid={:?} gen={}\n{}",
                r.index,
                record.state().host_pid(),
                record.generation.load(Ordering::Acquire),
                std::backtrace::Backtrace::force_capture(),
            );
        }
        // Unpublish the lookup key before clearing either namespace identity or
        // generation. A registrar that did not win the transition claim cannot
        // attach to a half-released record.
        guard.retire();
        record.host_pid.store(0, Ordering::Release);
        record.generation.store(0, Ordering::Release);
        record.clear_body_for_claim();
        record.state_cell.finish_retire();
    }

    fn record_for_ref(&self, r: ProcessRecordRef) -> Option<&ProcessRecord> {
        let record = self.records.get(r.index)?;
        let generation = record.generation.load(Ordering::Acquire);
        if generation == r.generation.raw() {
            Some(record)
        } else {
            None
        }
    }
}

impl ProcessRecord {
    pub fn state(&self) -> RecordState {
        self.state_cell.state()
    }

    pub fn host_pid(&self) -> Option<HostPid> {
        self.state_cell.state().host_pid()
    }

    pub fn begin_transition(&self) -> Option<TransitionGuard<'_>> {
        self.state_cell.begin_transition()
    }

    /// Try to become the sole lifecycle authority for this record.
    pub fn try_claim_transition(&self) -> bool {
        if let Some(mut guard) = self.state_cell.begin_transition() {
            guard.disarm();
            true
        } else {
            false
        }
    }

    /// Relinquish a lifecycle transition without releasing the record.
    pub fn release_transition(&self) {
        self.state_cell.release_transition();
    }

    pub fn transition_claimed(&self) -> bool {
        self.state_cell.state().is_transitioning()
    }

    fn clear_body_for_claim(&self) {
        self.host_pid.store(0, Ordering::Relaxed);
        self.ns_pid.store(0, Ordering::Relaxed);
        self.parent_host_pid.store(0, Ordering::Relaxed);
        self.subreaper_pid.store(0, Ordering::Relaxed);
        self.flags.store(0, Ordering::Relaxed);
        self.exec_generation.store(0, Ordering::Relaxed);
        self.pgid.store(0, Ordering::Relaxed);
        self.sid.store(0, Ordering::Relaxed);
        self.ctty.store(0, Ordering::Relaxed);
        self.run_state.store(0, Ordering::Relaxed);
        self.ptrace_stop_signal.store(0, Ordering::Relaxed);
        self.exit_status.store(0, Ordering::Relaxed);
        self.ptrace_control
            .store(VirtualPtraceControl::untraced().raw(), Ordering::Relaxed);
        self.exit_ready.store(0, Ordering::Relaxed);
        self.pid_ns.store(0, Ordering::Relaxed);
        self.guest_ns.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::arena::KernelArena;
    use crate::domains::HostPid;

    #[test]
    fn virtual_ptrace_control_round_trips_owner_and_state() {
        let generation = ProcessGeneration::new(7);
        let control =
            VirtualPtraceControl::traced(42, generation, VirtualPtraceState::StopReported)
                .expect("valid traced state");
        assert_eq!(
            VirtualPtraceControl::decode_shared(control.raw()),
            Some(control)
        );
        assert_eq!(control.tracer_pid(), 42);
        assert_eq!(control.generation(), generation);
        assert_eq!(control.state(), VirtualPtraceState::StopReported);
        assert_eq!(
            VirtualPtraceControl::decode_shared(VirtualPtraceControl::untraced().raw()),
            Some(VirtualPtraceControl::untraced())
        );
        assert_eq!(
            VirtualPtraceControl::decode_shared(42 << VirtualPtraceControl::STATE_BITS),
            None,
            "an untraced state cannot retain an owner"
        );
        assert_eq!(
            VirtualPtraceControl::decode_shared(
                (generation.raw() as u64) << 32 | VirtualPtraceState::Running.raw() as u64,
            ),
            None,
            "a traced state requires an owner"
        );
        assert_eq!(
            VirtualPtraceControl::decode_shared(
                (42 << VirtualPtraceControl::STATE_BITS | VirtualPtraceState::Running.raw()) as u64,
            ),
            None,
            "a traced state requires a record generation"
        );
    }

    #[test]
    fn claim_fill_publish_find_release_round_trip() {
        let arena = KernelArena::create().unwrap();
        let s = &arena.layout().processes;
        let generation = arena.allocate_generation();
        let r = s
            .claim(Some(HostPid::new(500)), generation, |rec| {
                rec.ns_pid.store(2, Ordering::Relaxed);
                rec.parent_host_pid.store(1, Ordering::Relaxed);
                rec.flags.store(FLAG_ALIVE, Ordering::Relaxed);
            })
            .unwrap();
        let found = s.find(HostPid::new(500)).unwrap();
        assert_eq!(found.index, r.index);
        assert_eq!(found.generation, generation);
        s.release(found);
        assert!(s.find(HostPid::new(500)).is_none());
    }

    #[test]
    fn registering_records_are_invisible_to_find() {
        let arena = KernelArena::create().unwrap();
        let s = &arena.layout().processes;
        let generation = arena.allocate_generation();
        let r = s.claim(None, generation, |_| {}).unwrap();
        assert_eq!(s.records[r.index].state(), RecordState::Registering);
        assert!(s.find(HostPid::new(600)).is_none());
        s.publish_host_pid(r, HostPid::new(600));
        assert_eq!(
            s.records[r.index].state(),
            RecordState::Live {
                host_pid: HostPid::new(600)
            }
        );
        assert!(s.find(HostPid::new(600)).is_some());
    }

    #[test]
    fn record_state_cell_transitions_and_refusals() {
        let cell = RecordStateCell::new();
        assert_eq!(cell.state(), RecordState::Free);
        assert!(cell.state().is_free());
        assert_eq!(cell.state().host_pid(), None);

        // Refusal: begin_transition / publish_deferred on Free
        assert!(cell.begin_transition().is_none());
        assert!(!cell.publish_deferred(HostPid::new(100)));

        // Transition: Free -> Registering
        let token = cell.claim().expect("claim on Free");
        assert_eq!(cell.state(), RecordState::Registering);
        assert!(cell.state().is_registering());
        assert_eq!(cell.state().host_pid(), None);

        // Refusal: claim / begin_transition on Registering
        assert!(matches!(cell.claim(), Err(Busy)));
        assert!(cell.begin_transition().is_none());

        // Drop token -> reverts to Free
        drop(token);
        assert_eq!(cell.state(), RecordState::Free);

        // Claim again and publish
        let token = cell.claim().expect("claim again");
        let pid = HostPid::new(555);
        cell.publish(token, pid);
        assert_eq!(cell.state(), RecordState::Live { host_pid: pid });
        assert!(cell.state().is_live());
        assert_eq!(cell.state().host_pid(), Some(pid));

        // Refusal: claim on Live
        assert!(matches!(cell.claim(), Err(Busy)));
        // Idempotent publish with same pid
        assert!(cell.publish_deferred(pid));
        // Refusal: publish with different pid
        assert!(!cell.publish_deferred(HostPid::new(999)));

        // Transition: Live -> Transitioning
        let guard = cell.begin_transition().expect("begin transition");
        assert_eq!(cell.state(), RecordState::Transitioning { host_pid: pid });
        assert!(cell.state().is_transitioning());

        // Refusal: concurrent begin_transition / claim
        assert!(cell.begin_transition().is_none());
        assert!(matches!(cell.claim(), Err(Busy)));
        assert!(!cell.publish_deferred(pid));

        // Drop guard -> reverts to Live
        drop(guard);
        assert_eq!(cell.state(), RecordState::Live { host_pid: pid });

        // Transition again and retire
        let guard = cell.begin_transition().expect("begin transition");
        guard.retire();
        assert_eq!(cell.state(), RecordState::Retiring);
        assert!(cell.state().is_retiring());
        assert_eq!(cell.state().host_pid(), None);

        // Refusal: operations on Retiring
        assert!(matches!(cell.claim(), Err(Busy)));
        assert!(cell.begin_transition().is_none());
        assert!(!cell.publish_deferred(pid));

        // Finish retire -> Free
        cell.finish_retire();
        assert_eq!(cell.state(), RecordState::Free);
    }

    #[test]
    fn namespace_owner_or_transition_blocks_conditional_release() {
        let arena = KernelArena::create().unwrap();
        let s = &arena.layout().processes;
        let generation = arena.allocate_generation();
        let r = s
            .claim(Some(HostPid::new(601)), generation, |_| {})
            .unwrap();
        let record = &s.records[r.index];

        assert!(record.try_claim_transition());
        assert!(!s.release_if_namespace_unowned(r, HostPid::new(601)));
        assert_eq!(record.generation.load(Ordering::Acquire), generation.raw());
        record.release_transition();

        record.ns_pid.store(2, Ordering::Release);
        assert!(!s.release_if_namespace_unowned(r, HostPid::new(601)));
        assert_eq!(record.host_pid.load(Ordering::Acquire), 601);

        record.ns_pid.store(0, Ordering::Release);
        assert!(s.release_if_namespace_unowned(r, HostPid::new(601)));
        assert!(s.find(HostPid::new(601)).is_none());
    }

    #[test]
    fn exhaustion_is_loud() {
        let arena = KernelArena::create().unwrap();
        let s = &arena.layout().processes;
        for i in 0..PROCESS_RECORDS {
            s.claim(
                Some(HostPid::new(1000 + i as u32)),
                arena.allocate_generation(),
                |_| {},
            )
            .unwrap();
        }
        assert!(matches!(
            s.claim(Some(HostPid::new(1)), arena.allocate_generation(), |_| {}),
            Err(ArenaError::Exhausted {
                section: "processes",
                capacity: PROCESS_RECORDS
            })
        ));
    }

    #[test]
    fn claim_clears_the_namespace_tag() {
        let arena = KernelArena::create().unwrap();
        let s = &arena.layout().processes;
        let r = s
            .claim(
                Some(HostPid::new(700)),
                arena.allocate_generation(),
                |rec| {
                    rec.pid_ns.store(9, Ordering::Relaxed);
                },
            )
            .unwrap();
        assert_eq!(s.records[r.index].pid_ns.load(Ordering::Acquire), 9);
        assert!(s.release(r));
        let again = s
            .claim(Some(HostPid::new(700)), arena.allocate_generation(), |_| {})
            .unwrap();
        assert_eq!(again.index, r.index);
        assert_eq!(
            s.records[again.index].pid_ns.load(Ordering::Acquire),
            0,
            "a reused record must not inherit a namespace tag"
        );
    }
}
