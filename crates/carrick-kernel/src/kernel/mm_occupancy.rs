//! Which vCPUs run which address space: the host's side of the one
//! authority (`carrick_sched_core::occupancy`) every "who may be executing
//! MM `Y`" question reads.
//!
//! A vCPU slot ([`ExecutionSlot`]: the zone slot of the vCPU's mailbox lease,
//! or a host-only slot for a vCPU without one) is occupied by an address
//! space for as long as an executor runs guest code of that MM on it, or is
//! stopped at an exit of such code: from admission of a task's quantum to
//! its suspension, less any blocking host wait (which vacates, as the thread
//! cannot run guest code meanwhile). The readers:
//!
//! - a stage-1 page-table pause raises the MM's fence (its
//!   [`carrick_thread::fork_quiesce::PtQuiesce`]), then kicks every occupied
//!   slot in guest and waits for each to leave ([`MmResidents`]); a sole
//!   editor is simply a pause whose drain found no other occupant;
//! - the frame-COW and foreign-MM editors take the same pause;
//! - process fork and crash capture kick every slot running the MM, whatever
//!   thread its executor loaded ([`kick_running`]);
//! - ASID retirement requires the MM to run nowhere ([`is_running_anywhere`]).
//!
//! None of them asks which thread or process an executor loaded, so a vCPU
//! whose address space changes without the host loading a task (EL1
//! switching between processes) keeps every reader true by changing its
//! slot's word.
//!
//! # Ordering
//!
//! Installer: [`MmOccupancy::install`] publishes the slot's word (under its
//! port lock, so a scanner that sees the word finds the port); later, before
//! each guest entry, the executor stores its in-guest flag and then reads the
//! MM's fence (`quiesce::enter_hvpatch_guest_or_service_invalidation`). A
//! pauser raises the fence, then [`residents`] scans the words and reads each
//! occupant's flag. All four accesses are `SeqCst`: if the installer read the
//! fence before it was raised, its word and flag stores precede the raise and
//! therefore the scan, which sees and drains it; otherwise it sees the fence
//! and does not enter. A slot is vacated only out of guest.
//!
//! The table is process-global, as the HVF VM and its mailbox slots are (one
//! VM per process). The word is the MM id; the port also names the MM's fence
//! object, and a scan matches both, so kernels of different tests in one
//! process never count each other's executors.

use std::cell::Cell;
use std::sync::Arc;

use carrick_fatal::carrick_fatal;
use carrick_sched_core::{AddressSpaceKey, EXECUTION_SLOTS, Occupancy};
pub use carrick_sched_core::{ExecutionSlot, SlotId as ZoneSlotId};
use parking_lot::Mutex;

use super::MmId;
use super::objects::{
    CrashSafePointParticipation, CrashSafePointParticipationError, ThreadKey, ThreadRef,
};

static TABLE: Occupancy = Occupancy::new();

static PORTS: [Mutex<Option<Port>>; EXECUTION_SLOTS] =
    [const { Mutex::new(None) }; EXECUTION_SLOTS];

fn key(mm: MmId) -> AddressSpaceKey {
    AddressSpaceKey::new(mm.nonzero())
}

/// How a pause reaches the executor on a slot: kick its vCPU, read and watch
/// its in-guest flag.
#[derive(Clone)]
pub(crate) enum PauseEndpoint {
    /// A vCPU registered in its process's registry under the loaded thread.
    Registered {
        registry: Arc<dyn carrick_hal::VcpuRegistry>,
        tid: carrick_hal::ThreadId,
    },
    /// A native (VM-free) executor's running flag.
    Native(Arc<crate::dispatch::native_execution::NativeExecutorState>),
}

impl PauseEndpoint {
    fn tid(&self) -> carrick_hal::ThreadId {
        match self {
            Self::Registered { tid, .. } => *tid,
            Self::Native(state) => state.tid(),
        }
    }

    fn is_in_guest(&self) -> bool {
        match self {
            Self::Registered { registry, tid } => registry.is_in_guest(*tid),
            Self::Native(state) => state.is_running(),
        }
    }

    fn watch_leave(&self, wake: &Arc<carrick_hal::GuestLeaveWake>) -> carrick_hal::GuestLeaveWatch {
        match self {
            Self::Registered { registry, tid } => registry.watch_leave_guest(*tid, wake),
            Self::Native(state) => state.watch_running(wake),
        }
    }

    fn kick_if_in_guest(&self) {
        match self {
            Self::Registered { registry, tid } => {
                let _ = registry.kick_if_in_guest(*tid);
            }
            Self::Native(state) => {
                if state.is_running() {
                    state.request_memory_pause();
                }
            }
        }
    }

    fn kick(&self) {
        match self {
            Self::Registered { registry, tid } => registry.kick(*tid),
            Self::Native(state) => state.request_memory_pause(),
        }
    }
}

impl std::fmt::Debug for PauseEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PauseEndpoint")
            .field("tid", &self.tid())
            .finish()
    }
}

/// The MM's fence: the page-table pause barrier its CLONE_VM dispatchers
/// share. It also scopes a scan to one kernel graph.
pub(crate) type MmFence = Arc<carrick_thread::fork_quiesce::PtQuiesce>;

struct Port {
    mm: MmId,
    fence: MmFence,
    endpoint: PauseEndpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MmOccupancyError {
    #[error("vCPU slot {slot:?} already runs address space {running}")]
    SlotBusy { slot: ExecutionSlot, running: u64 },
    #[error("every host-only execution slot is allocated")]
    HostSlotsExhausted,
    #[error("thread {thread:?} already owns crash safe-point participation")]
    CrashParticipationAlreadyActive { thread: ThreadKey },
    #[error("thread {thread:?} exhausted crash safe-point participation identities")]
    CrashParticipationIdentityExhausted { thread: ThreadKey },
}

/// A host-only execution slot, for a vCPU (or a native executor) without a
/// mailbox lease; freed on drop.
#[derive(Debug)]
pub struct HostExecutionSlot(ExecutionSlot);

impl HostExecutionSlot {
    pub fn allocate() -> Result<Self, MmOccupancyError> {
        TABLE
            .alloc_host_slot()
            .map(Self)
            .ok_or(MmOccupancyError::HostSlotsExhausted)
    }

    pub fn slot(&self) -> ExecutionSlot {
        self.0
    }

    /// Free the slot if it is vacant; otherwise give it back. For owners
    /// (test fixtures) that cannot order every occupancy before the slot.
    pub fn try_release(self) -> Result<(), Self> {
        if TABLE.running(self.0).is_some() {
            return Err(self);
        }
        drop(self);
        Ok(())
    }
}

impl Drop for HostExecutionSlot {
    fn drop(&mut self) {
        if !TABLE.free_host_slot(self.0) {
            carrick_fatal!(
                "kernel::mm_occupancy",
                "host execution slot {:?} freed while occupied",
                self.0
            );
        }
    }
}

/// A thread's own host-only slot. Freed at thread exit when vacant; one
/// still occupied then (an occupancy owned by an object that outlives the
/// thread's locals) stays allocated rather than being handed to another vCPU.
struct ThreadHostSlot(Option<HostExecutionSlot>);

impl Drop for ThreadHostSlot {
    fn drop(&mut self) {
        if let Some(slot) = self.0.take()
            && let Err(occupied) = slot.try_release()
        {
            std::mem::forget(occupied);
        }
    }
}

thread_local! {
    static THREAD_HOST_SLOT: std::cell::RefCell<ThreadHostSlot> =
        const { std::cell::RefCell::new(ThreadHostSlot(None)) };
}

/// The execution slot of the calling executor thread's vCPU: its zone slot
/// when it holds a mailbox lease, otherwise a host-only slot this thread
/// keeps for its life (a vCPU is bound to the thread that runs it).
pub fn execution_slot_for_current_thread(
    mailbox_slot: Option<usize>,
) -> Result<ExecutionSlot, MmOccupancyError> {
    if let Some(zone) = mailbox_slot.and_then(ZoneSlotId::from_index) {
        return Ok(ExecutionSlot::zone(zone));
    }
    THREAD_HOST_SLOT.with(|cell| {
        let mut cell = cell.borrow_mut();
        if let Some(slot) = cell.0.as_ref() {
            return Ok(slot.slot());
        }
        let slot = HostExecutionSlot::allocate()?;
        let id = slot.slot();
        cell.0 = Some(slot);
        Ok(id)
    })
}

/// One slot occupied by one MM, for as long as this lives. Vacated on every
/// exit path (suspension, host wait, error, unwind): an abandoned occupancy
/// would make every later pause of the MM wait for a vCPU that never runs it.
///
/// A thread's occupancy also carries its crash safe-point participation, so
/// "this thread takes part in guest execution" is one fact read by both the
/// pause and the crash quorum.
pub struct MmOccupancy {
    slot: ExecutionSlot,
    mm: MmId,
    crash_participation: Option<CrashSafePointParticipation>,
    _not_sync: std::marker::PhantomData<Cell<()>>,
}

impl MmOccupancy {
    /// Publish that `slot`'s vCPU runs `mm`. The slot must be vacant: a
    /// rejected install leaves the running occupant and its endpoint intact.
    pub(crate) fn install(
        slot: ExecutionSlot,
        mm: MmId,
        fence: &MmFence,
        thread: Option<ThreadRef>,
        endpoint: PauseEndpoint,
    ) -> Result<Self, MmOccupancyError> {
        {
            let mut port = PORTS[slot.index()].lock();
            if let Some(running) = port.as_ref() {
                return Err(MmOccupancyError::SlotBusy {
                    slot,
                    running: running.mm.raw(),
                });
            }
            TABLE
                .install(slot, key(mm))
                .map_err(|busy| MmOccupancyError::SlotBusy {
                    slot,
                    running: busy.running.raw(),
                })?;
            *port = Some(Port {
                mm,
                fence: Arc::clone(fence),
                endpoint,
            });
        }
        let mut occupancy = Self {
            slot,
            mm,
            crash_participation: None,
            _not_sync: std::marker::PhantomData,
        };
        if let Some(thread) = thread {
            // On error, `occupancy` drops and vacates the slot.
            occupancy.crash_participation =
                Some(thread.enter_crash_safe_point_participation().map_err(
                    |error| match error {
                        CrashSafePointParticipationError::AlreadyActive { thread } => {
                            MmOccupancyError::CrashParticipationAlreadyActive { thread }
                        }
                        CrashSafePointParticipationError::IdentityExhausted { thread } => {
                            MmOccupancyError::CrashParticipationIdentityExhausted { thread }
                        }
                    },
                )?);
        }
        Ok(occupancy)
    }

    pub fn slot(&self) -> ExecutionSlot {
        self.slot
    }

    pub fn mm(&self) -> MmId {
        self.mm
    }

    /// Switch this slot's vCPU to `mm` without the host loading a task, the
    /// way an in-guest address-space switch will. The caller follows `mm`'s
    /// fence exactly as an install does.
    #[cfg(any(test, feature = "test-support"))]
    pub fn switch_for_test(&mut self, mm: MmId, fence: &MmFence) {
        let mut port = PORTS[self.slot.index()].lock();
        let Some(port) = port.as_mut() else {
            carrick_fatal!("kernel::mm_occupancy", "switched a vacant slot");
        };
        if !TABLE.switch(self.slot, key(self.mm), key(mm)) {
            carrick_fatal!(
                "kernel::mm_occupancy",
                "switched a slot from an MM it did not run"
            );
        }
        port.mm = mm;
        port.fence = Arc::clone(fence);
        self.mm = mm;
    }

    /// Occupy `slot` for a test executor whose vCPU is registered in
    /// `registry` under `tid`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn install_registered_for_test(
        slot: ExecutionSlot,
        mm: MmId,
        fence: &MmFence,
        thread: Option<ThreadRef>,
        registry: Arc<dyn carrick_hal::VcpuRegistry>,
        tid: carrick_hal::ThreadId,
    ) -> Result<Self, MmOccupancyError> {
        Self::install(
            slot,
            mm,
            fence,
            thread,
            PauseEndpoint::Registered { registry, tid },
        )
    }
}

impl Drop for MmOccupancy {
    fn drop(&mut self) {
        drop(self.crash_participation.take());
        let mut port = PORTS[self.slot.index()].lock();
        if port.as_ref().is_none_or(|port| port.mm != self.mm)
            || !TABLE.vacate(self.slot, key(self.mm))
        {
            carrick_fatal!(
                "kernel::mm_occupancy",
                "vacated slot {:?} did not run MM {:?}",
                self.slot,
                self.mm
            );
        }
        *port = None;
    }
}

/// The occupants of one MM at one instant, excluding the caller's own slot.
/// Taken after the MM's fence is raised: an executor that installs later
/// sees the fence before it can enter the guest (module docs), so this set
/// is everything a drain must wait for.
pub(crate) struct MmResidents {
    members: Vec<(ExecutionSlot, PauseEndpoint)>,
}

/// Snapshot the occupants of `mm` under `fence`, except `except`.
pub(crate) fn residents(mm: MmId, fence: &MmFence, except: Option<ExecutionSlot>) -> MmResidents {
    let mut members = Vec::new();
    TABLE.for_each_running(key(mm), |slot| {
        if Some(slot) == except {
            return;
        }
        if let Some(port) = PORTS[slot.index()].lock().as_ref()
            && port.mm == mm
            && Arc::ptr_eq(&port.fence, fence)
        {
            members.push((slot, port.endpoint.clone()));
        }
    });
    MmResidents { members }
}

impl MmResidents {
    pub(crate) fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.members.len()
    }

    fn endpoints(&self) -> impl Iterator<Item = &PauseEndpoint> {
        self.members.iter().map(|(_, endpoint)| endpoint)
    }

    #[cfg(test)]
    pub(crate) fn tids(&self) -> Vec<carrick_hal::ThreadId> {
        self.endpoints().map(PauseEndpoint::tid).collect()
    }

    /// Endpoints that can acknowledge a hardware ASID invalidation phase.
    /// Native endpoints have no hardware translation cache.
    pub(crate) fn hardware_invalidation_tids(&self) -> Vec<carrick_hal::ThreadId> {
        self.endpoints()
            .filter_map(|endpoint| match endpoint {
                PauseEndpoint::Registered { tid, .. } => Some(*tid),
                PauseEndpoint::Native(_) => None,
            })
            .collect()
    }

    pub(crate) fn any_in_guest(&self) -> bool {
        self.endpoints().any(PauseEndpoint::is_in_guest)
    }

    pub(crate) fn first_in_guest_tid(&self) -> Option<carrick_hal::ThreadId> {
        self.endpoints()
            .find_map(|endpoint| endpoint.is_in_guest().then_some(endpoint.tid()))
    }

    pub(crate) fn in_guest_tids(&self) -> Vec<carrick_hal::ThreadId> {
        self.endpoints()
            .filter(|endpoint| endpoint.is_in_guest())
            .map(PauseEndpoint::tid)
            .collect()
    }

    /// Watch every member for its leave-guest acknowledgement. All members,
    /// not only those in guest now: a member can enter transiently, see the
    /// fence and withdraw, and that withdrawal must wake a drain that read
    /// it in guest. A member may also (re-)register its vCPU during the
    /// drain; its registry then wakes the drain, which takes fresh watches.
    pub(crate) fn watch_leaves(
        &self,
        wake: &Arc<carrick_hal::GuestLeaveWake>,
    ) -> Vec<carrick_hal::GuestLeaveWatch> {
        self.endpoints()
            .map(|endpoint| endpoint.watch_leave(wake))
            .collect()
    }

    pub(crate) fn kick_all_in_guest(&self) {
        for endpoint in self.endpoints() {
            endpoint.kick_if_in_guest();
        }
    }
}

/// Kick every vCPU running `mm` (under `fence`) except `except`, whatever
/// thread its executor loaded: a thread EL1 switched onto another process's
/// vCPU is reached through the vCPU it runs on. Returns how many were kicked.
pub fn kick_running(mm: MmId, fence: &MmFence, except: Option<ExecutionSlot>) -> usize {
    let residents = residents(mm, fence, except);
    for endpoint in residents.endpoints() {
        endpoint.kick();
    }
    residents.len()
}

/// Whether any vCPU runs `mm` (under `fence`).
pub fn is_running_anywhere(mm: MmId, fence: &MmFence) -> bool {
    !residents(mm, fence, None).is_empty()
}

/// Occupied slots of `mm` under `fence`, for the fixed-width probe ABI and
/// tests.
#[cfg(any(test, feature = "test-support"))]
pub fn occupant_count_for_probe(mm: MmId, fence: &MmFence) -> i32 {
    i32::try_from(residents(mm, fence, None).len()).unwrap_or(i32::MAX)
}

#[cfg(test)]
mod tests;
