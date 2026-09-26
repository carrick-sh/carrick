//! Which vCPUs run which address space: the host's side of the one
//! authority (`carrick_sched_core::occupancy`) every "who may be executing
//! MM `Y`" question reads.
//!
//! A vCPU slot ([`ExecutionSlot`]: the zone slot of the vCPU's mailbox lease,
//! or a host-only slot for a vCPU without one) is occupied by an address
//! space for as long as an executor has a task of that MM loaded on the vCPU
//! (running its guest code or stopped at an exit of it): from the start of
//! each resident stretch to the unload, less any blocking host wait (the
//! thread cannot run guest code meanwhile). The readers:
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
//! # Where the words live (EL1 increment 2, step 2)
//!
//! While the carrier schedules threads in the guest, a zone slot's word is in
//! the shared EL1 region (`ZoneTables::occupancy`): guest EL1 switches a vCPU
//! to another process's thread itself, publishing the new address space in
//! the word and then reading that space's gate, the copy of the MM's fence
//! the host raises in the region ([`AddressSpacePublication`]). A host-only
//! slot's word, and every word when the zone is off, is in a host table.
//!
//! A slot's port is how a pause reaches its vCPU: the loaded thread's
//! registration while an executor has a task loaded (EL1 switches address
//! spaces only on such a vCPU; one in the idle entry runs no thread). In the
//! host table a port also names the MM and fence it was installed with,
//! which scopes a scan to one kernel graph (VM-free tests run several
//! kernels in one process); the zone's table belongs to the one carrier,
//! whose MM ids are carrier-unique, so its words need no scope, and EL1 may
//! have changed them since the port was installed.
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
use carrick_sched_core::{AddressSpaceKey, AddressSpaces, EXECUTION_SLOTS, Occupancy, SpaceIndex};
pub use carrick_sched_core::{ExecutionSlot, SlotId as ZoneSlotId};
use parking_lot::Mutex;

use super::MmId;
use super::objects::ThreadKey;

/// Host-only slots, and every slot while the zone is off.
static HOST_TABLE: Occupancy = Occupancy::new();

static PORTS: [Mutex<Option<Port>>; EXECUTION_SLOTS] =
    [const { Mutex::new(None) }; EXECUTION_SLOTS];

fn key(mm: MmId) -> AddressSpaceKey {
    AddressSpaceKey::new(mm.nonzero())
}

/// The occupancy table in the shared EL1 region, while the carrier
/// schedules threads in the guest.
fn zone_table() -> Option<&'static Occupancy> {
    crate::el1_zone::zone().map(|zone| &zone.occupancy)
}

/// The table `slot`'s word lives in.
fn table_for(slot: ExecutionSlot) -> &'static Occupancy {
    match (slot.as_zone(), zone_table()) {
        (Some(_), Some(zone)) => zone,
        _ => &HOST_TABLE,
    }
}

fn is_host_table(table: &Occupancy) -> bool {
    std::ptr::eq(table, &HOST_TABLE)
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
    /// The MM and fence the loaded task installed. Scopes host-table scans;
    /// a zone word may have moved on (EL1 switched the vCPU).
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
        HOST_TABLE
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
        if HOST_TABLE.running(self.0).is_some() {
            return Err(self);
        }
        drop(self);
        Ok(())
    }
}

impl Drop for HostExecutionSlot {
    fn drop(&mut self) {
        if !HOST_TABLE.free_host_slot(self.0) {
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
/// exit path (unload, suspension, host wait, error, unwind): an abandoned
/// occupancy would make every later pause of the MM wait for a vCPU that
/// never runs it, and refuse the next task loaded on the vCPU.
pub struct MmOccupancy {
    slot: ExecutionSlot,
    mm: MmId,
    table: &'static Occupancy,
    _not_sync: std::marker::PhantomData<Cell<()>>,
}

impl MmOccupancy {
    /// Publish that `slot`'s vCPU runs `mm`. The slot must be vacant: a
    /// rejected install leaves the running occupant and its endpoint intact.
    pub(crate) fn install(
        slot: ExecutionSlot,
        mm: MmId,
        fence: &MmFence,
        endpoint: PauseEndpoint,
    ) -> Result<Self, MmOccupancyError> {
        let table = table_for(slot);
        let mut port = PORTS[slot.index()].lock();
        if let Some(running) = port.as_ref() {
            return Err(MmOccupancyError::SlotBusy {
                slot,
                running: running.mm.raw(),
            });
        }
        table
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
        Ok(Self {
            slot,
            mm,
            table,
            _not_sync: std::marker::PhantomData,
        })
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
        if !self.table.switch(self.slot, key(self.mm), key(mm)) {
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
        registry: Arc<dyn carrick_hal::VcpuRegistry>,
        tid: carrick_hal::ThreadId,
    ) -> Result<Self, MmOccupancyError> {
        Self::install(slot, mm, fence, PauseEndpoint::Registered { registry, tid })
    }
}

impl Drop for MmOccupancy {
    fn drop(&mut self) {
        let mut port = PORTS[self.slot.index()].lock();
        let own_port = port.as_ref().is_some_and(|port| port.mm == self.mm);
        // The vCPU is out of the guest. In the zone's table EL1 may have
        // switched the word to another address space, or emptied it, since
        // the task was loaded; whatever it holds now ends with this stretch.
        let vacated = if is_host_table(self.table) {
            self.table.vacate(self.slot, key(self.mm))
        } else {
            self.table.vacate_any(self.slot);
            true
        };
        if !own_port || !vacated {
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
    members: Vec<Resident>,
}

/// One vCPU a pause found running the MM.
struct Resident {
    endpoint: PauseEndpoint,
    /// For a zone slot: its shared word and the MM's key. Guest EL1 may move
    /// the vCPU off the MM without leaving the guest (to the maintenance
    /// root, or another space), and the executor behind the port may enter
    /// the guest again for other work (an idle wait, another task); with the
    /// MM's gate raised EL1 cannot put the MM back, so the vCPU runs the MM
    /// only while it is in the guest AND its word still names the MM.
    zone_word: Option<(&'static Occupancy, ExecutionSlot, u64)>,
}

impl Resident {
    fn host(endpoint: PauseEndpoint) -> Self {
        Self {
            endpoint,
            zone_word: None,
        }
    }

    fn zone(
        table: &'static Occupancy,
        slot: ExecutionSlot,
        mm: MmId,
        endpoint: PauseEndpoint,
    ) -> Self {
        Self {
            endpoint,
            zone_word: Some((table, slot, mm.raw())),
        }
    }

    fn runs_mm_in_guest(&self) -> bool {
        self.endpoint.is_in_guest()
            && self
                .zone_word
                .is_none_or(|(table, slot, mm)| table.running_raw(slot) == mm)
    }
}

/// Snapshot the occupants of `mm` under `fence`, except `except`: every
/// zone slot whose shared word names `mm` (whatever its executor loaded, or
/// none), and every host-table slot installed with exactly this MM and
/// fence.
pub(crate) fn residents(mm: MmId, fence: &MmFence, except: Option<ExecutionSlot>) -> MmResidents {
    let mut members = Vec::new();
    if let Some(zone) = zone_table() {
        zone.for_each_running(key(mm), |slot| {
            if Some(slot) == except {
                return;
            }
            if let Some(port) = PORTS[slot.index()].lock().as_ref() {
                members.push(Resident::zone(zone, slot, mm, port.endpoint.clone()));
            }
        });
    }
    HOST_TABLE.for_each_running(key(mm), |slot| {
        if Some(slot) == except {
            return;
        }
        if let Some(port) = PORTS[slot.index()].lock().as_ref()
            && port.mm == mm
            && Arc::ptr_eq(&port.fence, fence)
        {
            members.push(Resident::host(port.endpoint.clone()));
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
        self.members.iter().map(|resident| &resident.endpoint)
    }

    fn running_in_guest(&self) -> impl Iterator<Item = &PauseEndpoint> {
        self.members
            .iter()
            .filter(|resident| resident.runs_mm_in_guest())
            .map(|resident| &resident.endpoint)
    }

    #[cfg(test)]
    pub(crate) fn tids(&self) -> Vec<carrick_hal::ThreadId> {
        self.endpoints().map(PauseEndpoint::tid).collect()
    }

    pub(crate) fn any_in_guest(&self) -> bool {
        self.running_in_guest().next().is_some()
    }

    pub(crate) fn first_in_guest_tid(&self) -> Option<carrick_hal::ThreadId> {
        self.running_in_guest().next().map(PauseEndpoint::tid)
    }

    pub(crate) fn in_guest_tids(&self) -> Vec<carrick_hal::ThreadId> {
        self.running_in_guest().map(PauseEndpoint::tid).collect()
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
        for endpoint in self.running_in_guest() {
            endpoint.kick_if_in_guest();
        }
    }
}

/// EL1 switches vCPUs between published address spaces itself; with
/// `CARRICK_EL1_MM_SWITCH=0` nothing is published, so a thread of another
/// process reaches a vCPU through that vCPU's executor, as in plan 1d.
fn switching_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("CARRICK_EL1_MM_SWITCH").map_or(true, |value| value.trim() != "0")
    })
}

/// Serializes publication and freeing of address-space entries (the only
/// mutations of the table; EL1 only reads it).
static SPACES_LOCK: Mutex<()> = Mutex::new(());

/// The tables a publication lives in: the zone's, or (VM-free tests) a
/// private pair.
#[derive(Clone, Copy)]
struct SpaceTables {
    spaces: &'static AddressSpaces,
    occupancy: &'static Occupancy,
    zone: bool,
}

impl SpaceTables {
    /// Whether the tables are still there: a publication can outlive the VM
    /// whose EL1 region held the zone.
    fn live(&self) -> bool {
        !self.zone
            || crate::el1_zone::zone().is_some_and(|zone| std::ptr::eq(&zone.spaces, self.spaces))
    }
}

/// An MM's fence copied into its published address space's gate.
struct SpaceGate {
    tables: SpaceTables,
    index: SpaceIndex,
}

impl carrick_thread::fork_quiesce::FenceMirror for SpaceGate {
    fn raise(&self) {
        if self.tables.live() {
            self.tables.spaces.raise(self.index);
        }
    }

    fn lower(&self) {
        if self.tables.live() {
            self.tables.spaces.lower(self.index);
        }
    }
}

/// An address space guest EL1 may install on a vCPU itself (EL1 increment
/// 2, step 2), for as long as this lives and is not closed. Its gate in the
/// shared region follows the MM's fence ([`carrick_thread::fork_quiesce::PtQuiesce::bind_mirror`]),
/// so a page-table pause of the MM keeps EL1 from installing it exactly as
/// it keeps the MM's executors from entering, and the pause's occupancy scan
/// drains every vCPU EL1 installed it on before.
///
/// Dropping it (the MM's ASID retires) closes the gate for good, waits until
/// no vCPU in the guest has the space installed, and frees the entry: only
/// then may the ASID be invalidated for reuse, or a vCPU could still walk
/// the space's tables and cache translations under that ASID.
pub struct AddressSpacePublication {
    tables: SpaceTables,
    index: SpaceIndex,
    mm: MmId,
    fence: MmFence,
}

impl std::fmt::Debug for AddressSpacePublication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AddressSpacePublication")
            .field("mm", &self.mm)
            .field("index", &self.index)
            .finish()
    }
}

/// Publish `mm`, whose translation roots are `ttbr0`/`ttbr1`, for guest EL1
/// to install. `None`: the carrier does not schedule in the guest, the hatch
/// is set, the table is full, or `mm` is already published.
pub fn publish_address_space(
    mm: MmId,
    fence: &MmFence,
    ttbr0: u64,
    ttbr1: u64,
) -> Option<AddressSpacePublication> {
    if !switching_enabled() {
        return None;
    }
    let zone = crate::el1_zone::zone()?;
    publish_in(
        SpaceTables {
            spaces: &zone.spaces,
            occupancy: &zone.occupancy,
            zone: true,
        },
        mm,
        fence,
        ttbr0,
        ttbr1,
    )
}

fn publish_in(
    tables: SpaceTables,
    mm: MmId,
    fence: &MmFence,
    ttbr0: u64,
    ttbr1: u64,
) -> Option<AddressSpacePublication> {
    let spaces = tables.spaces;
    let _serial = SPACES_LOCK.lock();
    if spaces.find(mm.raw()).is_some() {
        return None;
    }
    let index = spaces.publish_closed(mm.raw(), ttbr0, ttbr1)?;
    // Bound while closed: a pause in force now raises the gate before it
    // opens, and every later pause raises it before its occupancy scan.
    if !fence.bind_mirror(Arc::new(SpaceGate { tables, index })) {
        spaces.free(index);
        return None;
    }
    spaces.open(index);
    Some(AddressSpacePublication {
        tables,
        index,
        mm,
        fence: Arc::clone(fence),
    })
}

impl AddressSpacePublication {
    /// No EL1 install of the space from now on (its ASID starts retiring).
    pub fn close(&self) {
        if self.tables.live() {
            self.tables.spaces.close(self.index);
        }
    }

    pub fn mm(&self) -> MmId {
        self.mm
    }
}

/// [`publish_address_space`] into private tables (VM-free tests).
#[cfg(test)]
fn publish_for_test(
    spaces: &'static AddressSpaces,
    occupancy: &'static Occupancy,
    mm: MmId,
    fence: &MmFence,
    ttbr: u64,
) -> Option<AddressSpacePublication> {
    publish_in(
        SpaceTables {
            spaces,
            occupancy,
            zone: false,
        },
        mm,
        fence,
        ttbr,
        ttbr,
    )
}

impl Drop for AddressSpacePublication {
    fn drop(&mut self) {
        let _ = self.fence.unbind_mirror();
        if !self.tables.live() {
            return;
        }
        self.tables.spaces.close(self.index);
        drain_space(self.tables.occupancy, self.mm);
        let _serial = SPACES_LOCK.lock();
        self.tables.spaces.free(self.index);
    }
}

/// After closing `mm`'s gate: wait until no vCPU in the guest has `mm`
/// installed in the zone's table, kicking each that does. A vCPU EL1 put on
/// `mm` before the close is in the scan (it published its word before it
/// read the gate); one out of the guest installs another root before it
/// runs again.
fn drain_space(occupancy: &'static Occupancy, mm: MmId) {
    loop {
        let mut members = Vec::new();
        occupancy.for_each_running(key(mm), |slot| {
            if let Some(port) = PORTS[slot.index()].lock().as_ref() {
                members.push(Resident::zone(occupancy, slot, mm, port.endpoint.clone()));
            }
        });
        let residents = MmResidents { members };
        if !residents.any_in_guest() {
            return;
        }
        let wake = carrick_hal::GuestLeaveWake::new();
        let seen = wake.generation();
        let _watches = residents.watch_leaves(&wake);
        if !residents.any_in_guest() {
            return;
        }
        residents.kick_all_in_guest();
        wake.wait_past(seen);
    }
}

/// A foreign COW changed `mm`'s translations while it was paused: the next
/// EL1 install of its address space invalidates its ASID first (the host's
/// own entries service the publication separately).
pub fn note_foreign_cow(mm: MmId) {
    if let Some(zone) = crate::el1_zone::zone()
        && let Some(index) = zone.spaces.find(mm.raw())
    {
        zone.spaces.note_cow(index);
    }
}

/// Publish the carrier's maintenance root, the translation root a vCPU runs
/// with no address space installed; EL1 switches between address spaces
/// through it.
pub fn publish_idle_root(ttbr: u64) {
    if let Some(zone) = crate::el1_zone::zone()
        && zone.spaces.idle_ttbr() != ttbr
    {
        zone.spaces.set_idle_ttbr(ttbr);
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
