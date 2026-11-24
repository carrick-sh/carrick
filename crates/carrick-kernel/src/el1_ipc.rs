//! Kernel-owned storage for the shared host/EL1 IPC authority.

mod table;
pub use table::{HostSlotReservation, HostTable};

use std::collections::BTreeMap;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use carrick_el1_abi::ipc::{
    HostResourceToken, IPC_DIRECTORY_BYTES, IPC_MAX_OBJECTS, IPC_MAX_OFDS, IPC_PIPE_PAGE_SIZE,
    IPC_POOL_ALIGN, IPC_POOL_AREAS, IPC_STOCK_RING_BYTES, IpcDirectory, IpcError, IpcObjectHandle,
    IpcPipeStorage, IpcRegion, IpcReleased, IpcWake, fd, pipe,
};
use parking_lot::Mutex;

use crate::el1_zone::HostLockWait;

static NEXT_REGION: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
static INJECT_OBJECT_WAIT_KEY_OUT_OF_RANGE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
pub(crate) fn inject_object_wait_key_out_of_range_once() {
    INJECT_OBJECT_WAIT_KEY_OUT_OF_RANGE.store(true, Ordering::Release);
}

/// Admission failure, before any descriptor or host reservation is published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    NoMemory,
    ObjectWaitKeyOutOfRange,
    ObjectWaitInvariant(carrick_sched_core::object_wait::ObjectWaitError),
    ObjectRollbackInvariant(IpcError),
    Shared(IpcError),
}
impl From<IpcError> for AdmissionError {
    fn from(error: IpcError) -> Self {
        Self::Shared(error)
    }
}
impl From<fd::Error> for AdmissionError {
    fn from(error: fd::Error) -> Self {
        Self::Shared(IpcError::Fd(error))
    }
}

/// Why creating a pipe or eventfd was refused. Only Linux-visible limits
/// exist here: an exhausted internal store is grown, never reported, so no
/// fixed table can surface as ENOMEM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateError {
    /// The zone-wide file table is full (ENFILE, `fs.file-max`).
    FileTableFull,
}
impl CreateError {
    /// Classify an admission refusal. The zone ceiling is ENFILE; any other
    /// refusal is an authority invariant violation (a store that could not
    /// grow without reaching its ceiling, a stale identity, bad backing)
    /// and fails closed rather than inventing an errno.
    pub fn from_admission(error: AdmissionError) -> Self {
        match error {
            AdmissionError::Shared(IpcError::ZoneLimit) => Self::FileTableFull,
            error @ (AdmissionError::ObjectWaitKeyOutOfRange
            | AdmissionError::NoMemory
            | AdmissionError::ObjectWaitInvariant(_)
            | AdmissionError::ObjectRollbackInvariant(_)
            | AdmissionError::Shared(_)) => {
                carrick_fatal::carrick_fatal!(
                    "ipc::admission",
                    "object creation or wait-binding invariant failed: {error:?}"
                )
            }
        }
    }
    pub fn errno(self) -> carrick_abi::LinuxErrno {
        match self {
            Self::FileTableFull => carrick_abi::LINUX_ENFILE,
        }
    }
}

/// The readiness lanes every pipe, eventfd and epoll object binds, in order.
const PIPE_LANES: [pipe::WaitFor; 2] = [pipe::WaitFor::Readable, pipe::WaitFor::Writable];

/// An admitted object's readiness wait key. Every object index has both
/// keys, so a missing one is an authority invariant, never an errno.
fn pipe_lane_key(
    object: IpcObjectHandle,
    direction: pipe::WaitFor,
) -> carrick_sched_core::object_wait::ObjectWaitKey {
    #[cfg(test)]
    let key = if INJECT_OBJECT_WAIT_KEY_OUT_OF_RANGE.swap(false, Ordering::AcqRel) {
        None
    } else {
        carrick_el1_abi::ipc::object_wait_key(object, direction)
    };
    #[cfg(not(test))]
    let key = carrick_el1_abi::ipc::object_wait_key(object, direction);
    let Some(key) = key else {
        carrick_fatal::carrick_fatal!(
            "ipc::admission",
            "admitted object has no readiness wait key: {object:?}"
        );
    };
    key
}

/// The IPC create path's lock policy: a held lock is refused at once,
/// never spun on. The caller retains its owned operation and parks on the
/// holder's release ([`PendingPipeCreate`]). Unlike the short-section
/// [`HostLockWait`], this never pins a host executor behind another party's
/// critical section (#1845). Used only by operations that can retain their
/// progress across that park; x86/CPL0 venues keep their own policy (#1059).
pub struct IpcCreateLockWait;

impl carrick_el1_abi::LockWait<carrick_el1_abi::Aarch64ParkedContext> for IpcCreateLockWait {
    fn wait(&self, _attempt: u32) -> bool {
        false
    }

    fn complete_object_wake(
        &self,
        zone: &carrick_el1_abi::ZoneTables,
        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_el1_abi::Aarch64ParkedContext,
        >,
    ) {
        crate::el1_zone::complete_object_wake(zone, owned);
    }
}

/// How [`HostIpc::begin_pipe`] (or a resumed [`PendingPipeCreate`]) ended.
#[derive(Debug)]
pub enum PipeCreation {
    /// The unpublished pipe with every readiness lane bound; the caller owns
    /// it exactly as a handle from a completed create.
    Created(IpcObjectHandle),
    /// A lane lock is held by another party: the create's progress is
    /// retained, not refused. It parks on that lock's physical custody
    /// ([`PendingPipeCreate::readiness_custody`]), not a refusal ticket.
    Retained(PendingPipeCreate),
}

/// An unpublished pipe whose readiness binding met a held lane lock: the
/// object, and the lanes already bound to its incarnation, owned until the
/// create completes or is dropped. It owns no descriptor, guest output
/// permit or execution lease, so it can wait across a park. Dropping it
/// unbinds the owned lanes, then frees the object.
#[must_use = "park on the held lane and resume, or drop to roll the create back"]
pub struct PendingPipeCreate {
    owner: std::sync::Arc<HostIpc>,
    zone: &'static carrick_el1_abi::ZoneTables,
    /// `None` once ownership passed to [`PipeCreation::Created`].
    object: Option<IpcObjectHandle>,
    /// Lanes `PIPE_LANES[..bound]` are bound to this incarnation.
    bound: usize,
}

impl std::fmt::Debug for PendingPipeCreate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingPipeCreate")
            .field("object", &self.object)
            .field("bound", &self.bound)
            .finish_non_exhaustive()
    }
}

impl PendingPipeCreate {
    fn bind(mut self) -> Result<PipeCreation, AdmissionError> {
        let Some(object) = self.object else {
            return Err(AdmissionError::Shared(IpcError::Stale));
        };
        match HostIpc::bind_pipe_lanes(self.zone, object, &mut self.bound) {
            Ok(true) => {
                self.object = None;
                Ok(PipeCreation::Created(object))
            }
            Ok(false) => Ok(PipeCreation::Retained(self)),
            Err(error) => {
                self.object = None;
                self.owner
                    .rollback_unpublished_pipe(Some(self.zone), object, self.bound)?;
                Err(HostIpc::wait_bind_error(error))
            }
        }
    }

    /// Run the create again after the held lane lock was released. It
    /// continues at the first unbound lane; nothing already bound is redone.
    pub fn resume(self) -> Result<PipeCreation, AdmissionError> {
        self.bind()
    }

    /// The owner this create belongs to.
    pub fn owner(&self) -> &std::sync::Arc<HostIpc> {
        &self.owner
    }

    /// The unpublished object this create owns.
    pub fn object(&self) -> Option<IpcObjectHandle> {
        self.object
    }

    /// How many readiness lanes are already bound to this incarnation.
    pub fn bound_lanes(&self) -> usize {
        self.bound
    }

    /// The physical readiness lock this create waits for, with its zone.
    /// Its release hands an enrolled operation back
    /// ([`carrick_sched_core::object_wait::ReadinessLockCustody::defer`]).
    pub fn readiness_custody(
        &self,
    ) -> Result<
        carrick_sched_core::object_wait::ReadinessLockCustody<
            'static,
            carrick_el1_abi::Aarch64ParkedContext,
        >,
        carrick_sched_core::object_wait::ObjectWaitError,
    > {
        let (Some(object), Some(lane)) = (self.object, PIPE_LANES.get(self.bound)) else {
            return Err(carrick_sched_core::object_wait::ObjectWaitError::Stale);
        };
        self.zone
            .readiness_lock_custody(pipe_lane_key(object, *lane))
    }

    /// The zone whose lane lock this create waits for.
    pub fn zone(&self) -> &'static carrick_el1_abi::ZoneTables {
        self.zone
    }
}

impl Drop for PendingPipeCreate {
    fn drop(&mut self) {
        let Some(object) = self.object.take() else {
            return;
        };
        if let Err(error) =
            self.owner
                .rollback_unpublished_pipe(Some(self.zone), object, self.bound)
        {
            // A failed rollback is an authority invariant: the one
            // admission classifier fails closed (never an errno).
            let _ = CreateError::from_admission(error);
        }
    }
}

/// An owned, zero-filled, shared mapping. Only the synchronized IPC views
/// access its contents; no slice of mutable shared memory escapes.
struct Mapping {
    ptr: NonNull<u8>,
    len: usize,
}
// SAFETY: contents are accessed through IpcRegion's table/object locks only.
unsafe impl Send for Mapping {}
unsafe impl Sync for Mapping {}
impl Mapping {
    fn new(len: usize) -> Result<Self, AdmissionError> {
        // SAFETY: anonymous mapping; no borrowed storage or fixed address.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(AdmissionError::NoMemory);
        }
        let Some(ptr) = NonNull::new(ptr.cast()) else {
            // SAFETY: a successful mapping at address zero still needs release.
            unsafe {
                libc::munmap(ptr, len);
            }
            return Err(AdmissionError::NoMemory);
        };
        Ok(Self { ptr, len })
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this owner outlives every region view and owns the mapping.
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }
    }
}

pub use carrick_el1_abi::ipc::IpcLimits;

/// Records the authority has published by growing its stores (never
/// shrinks): the elastic-store work receipt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpcGrowth {
    pub object_records: usize,
    pub description_records: usize,
}

/// One retained host object behind an `IpcBacking::Host` token. Shared so a
/// carrier service can use it without holding the resource table lock.
pub type HostResource = std::sync::Arc<dyn std::any::Any + Send + Sync>;

struct HostResources {
    next: u64,
    live: BTreeMap<u64, HostResource>,
}

/// Why a newly opened host resource could not be installed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallHostDescriptionError {
    /// The caller's descriptor limit (EMFILE).
    TooManyFiles,
    /// The zone-wide file table (ENFILE).
    FileTableFull,
    /// Host storage could not be provided (ENOMEM).
    NoMemory,
    /// The table is contended or inconsistent: never guess an errno.
    Unavailable,
}

/// Why a native host-file service could not reach a host resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinnedHostResourceError {
    /// No open descriptor with this number in the table.
    BadFd,
    /// The descriptor names an in-zone object, which the ring owns.
    InZone,
    /// The table or description is contended or inconsistent.
    Unavailable,
}

#[derive(Debug)]
pub(crate) struct HostSubscription {
    owner: std::sync::Arc<HostIpc>,
    object: IpcObjectHandle,
}
impl Drop for HostSubscription {
    fn drop(&mut self) {
        // A final close can retire the object before its observation enrollments.
        // Generation authentication prevents touching a recycled incarnation.
        let _ = self
            .owner
            .region()
            .unsubscribe_host(self.object, &self.owner.wait());
    }
}

enum HostWakeTarget {
    Queue(std::sync::Weak<crate::kernel::WaitQueue>),
    Publisher {
        wake: std::sync::Weak<dyn Fn() + Send + Sync>,
        prime: std::sync::Weak<dyn Fn() + Send + Sync>,
    },
}
/// A resolved, live [`HostWakeTarget`]: owning it is what licenses consuming
/// an owed host wake.
enum HostWakeDelivery {
    Queue(std::sync::Arc<crate::kernel::WaitQueue>),
    Publisher(std::sync::Arc<dyn Fn() + Send + Sync>),
}
struct HostWakeEntry {
    object: IpcObjectHandle,
    target: HostWakeTarget,
}

/// Host ownership of one description in the shared fd core. Numeric tables
/// and in-flight guest operations retain this same OFD, rather than creating
/// additional owners of its backing. Dropping the host pin releases backing
/// only if no descriptor or operation in either venue still holds it.
#[derive(Debug)]
pub struct HostDescription {
    flags: std::sync::Arc<HostDescriptionFlags>,
}

/// Non-owning observation of a host description's shared mutable flags.
/// Holding this view never retains an OFD pin. After host retirement it reads
/// a terminal snapshot, without touching a potentially recycled shared slot.
#[derive(Debug)]
pub struct HostDescriptionFlags {
    owner: std::sync::Arc<HostIpc>,
    state: Mutex<HostDescriptionState>,
}
#[derive(Debug)]
enum HostDescriptionState {
    Live(fd::OfdPin),
    Retired(fd::Description),
}

impl HostDescriptionFlags {
    pub(crate) fn belongs_to(&self, owner: &std::sync::Arc<HostIpc>) -> bool {
        std::sync::Arc::ptr_eq(&self.owner, owner)
    }

    pub(crate) const MUTABLE_MASK: u64 =
        carrick_abi::LINUX_O_APPEND | carrick_abi::LINUX_O_NONBLOCK | carrick_abi::LINUX_O_ASYNC;

    pub(crate) fn linux_flags(&self) -> u64 {
        let state = self.state.lock();
        let description = match &*state {
            HostDescriptionState::Live(pin) => self
                .owner
                .region()
                .fd(self.owner.wait())
                .pinned(pin)
                .unwrap_or_else(|_| {
                    carrick_fatal::carrick_fatal!("ipc::description", "invalid flag observation")
                }),
            HostDescriptionState::Retired(description) => *description,
        };
        let flags = description.flags;
        let access = match description.access {
            fd::AccessMode::ReadOnly => carrick_abi::LINUX_O_RDONLY,
            fd::AccessMode::WriteOnly => carrick_abi::LINUX_O_WRONLY,
            fd::AccessMode::ReadWrite => carrick_abi::LINUX_O_RDWR,
            fd::AccessMode::Path => carrick_abi::LINUX_O_PATH,
        };
        access
            | (u64::from(flags.append) * carrick_abi::LINUX_O_APPEND)
            | (u64::from(flags.nonblock) * carrick_abi::LINUX_O_NONBLOCK)
            | (u64::from(flags.asynchronous) * carrick_abi::LINUX_O_ASYNC)
    }

    /// The shared open file description's identity (index and generation,
    /// packed), the epoll item key of the open file this view describes.
    /// `None` once retired.
    pub(crate) fn ofd_key(&self) -> Option<u64> {
        match &*self.state.lock() {
            HostDescriptionState::Live(pin) => {
                let key = pin.key();
                Some((u64::from(key.index) << 32) | (key.generation & u64::from(u32::MAX)))
            }
            HostDescriptionState::Retired(_) => None,
        }
    }

    pub(crate) fn set_linux_flags(&self, value: Option<u64>, effects: fd::CloseEffects) {
        let state = self.state.lock();
        let HostDescriptionState::Live(pin) = &*state else {
            // A retired host observation has no mutation authority.
            return;
        };
        let region = self.owner.region();
        let authority = region.fd(self.owner.wait());
        let result = (|| {
            if let Some(value) = value {
                let mut flags = authority.pinned(pin)?.flags;
                flags.append = value & carrick_abi::LINUX_O_APPEND != 0;
                flags.nonblock = value & carrick_abi::LINUX_O_NONBLOCK != 0;
                flags.asynchronous = value & carrick_abi::LINUX_O_ASYNC != 0;
                authority.set_pinned_flags(pin, flags)?;
            }
            authority.require_pinned_close_effects(pin, effects)
        })();
        result.unwrap_or_else(|_| {
            carrick_fatal::carrick_fatal!(
                "ipc::description",
                "shared description mutation rejected"
            )
        });
    }

    pub(crate) fn require_close_effects(&self, effects: fd::CloseEffects) {
        if effects.is_empty() {
            return;
        }
        self.set_linux_flags(None, effects);
    }
}

impl HostDescription {
    pub(crate) fn flags(&self) -> std::sync::Arc<HostDescriptionFlags> {
        std::sync::Arc::clone(&self.flags)
    }

    /// Install the exact admitted description into a shared table. Caller
    /// supplies already-provisioned capacity and serializes slot admission.
    pub fn install(
        &self,
        table: fd::TableId,
        target: fd::Fd,
        cloexec: bool,
    ) -> Result<(), fd::Error> {
        let state = self.flags.state.lock();
        let HostDescriptionState::Live(pin) = &*state else {
            return Err(fd::Error::StalePin);
        };
        self.flags
            .owner
            .region()
            .fd(self.flags.owner.wait())
            .install_pin(table, target, pin, cloexec)
    }
}

impl Drop for HostDescription {
    fn drop(&mut self) {
        let description = {
            let mut state = self.flags.state.lock();
            let HostDescriptionState::Live(pin) = &*state else {
                return;
            };
            let owner = &self.flags.owner;
            let region = owner.region();
            let authority = region.fd(owner.wait());
            // A lock a stopped vCPU still holds quarantines this close (#2955):
            // the pin stays live and the description keeps its backing.
            let terminal = match authority.pinned(pin) {
                Ok(terminal) => terminal,
                Err(error) => {
                    if owner.quarantine_cut_off(error.into()).is_ok() {
                        return;
                    }
                    carrick_fatal::carrick_fatal!("ipc::description", "invalid closing description")
                }
            };
            let HostDescriptionState::Live(pin) =
                std::mem::replace(&mut *state, HostDescriptionState::Retired(terminal))
            else {
                carrick_fatal::carrick_fatal!("ipc::description", "description retired twice")
            };
            match authority.unpin(pin) {
                Ok(description) => description,
                Err(error) => {
                    if owner.quarantine_cut_off(error.into()).is_ok() {
                        return;
                    }
                    carrick_fatal::carrick_fatal!(
                        "ipc::description",
                        "invalid owned description pin"
                    )
                }
            }
        };
        // Backing release can call host readiness callbacks: leave the
        // description lock before delivering them.
        if let Some(description) = description {
            let owner = &self.flags.owner;
            if let Err(error) = owner.release(description.backing)
                && owner.quarantine_cut_off(error.into()).is_err()
            {
                carrick_fatal::carrick_fatal!(
                    "ipc::description",
                    "invalid final description backing"
                );
            }
        }
    }
}

/// One kernel's IPC authority and all memory needed by both venues.
/// Runtime mappings must retain an `Arc<HostIpc>` for their entire lifetime.
/// The pool reserves virtual address space; anonymous pages are committed by
/// the host on demand. Objects retain reusable storage after their final close.
pub struct HostIpc {
    directory: Mapping,
    bytes: Mapping,
    resources: Mutex<HostResources>,
    /// Host wake targets by object index, sized to the highest index used.
    host_wakes: Mutex<Vec<Option<HostWakeEntry>>>,
    limits: IpcLimits,
    /// Serializes host growth accounting; publication ownership is shared.
    growth: Mutex<IpcGrowth>,
    /// The carrier descriptor ceiling every host-side install raises first
    /// (the kernel's authority, which owns the carrier publisher; #1398).
    ceiling: std::sync::Arc<crate::kernel::FdCeilingAuthority>,
    /// The carrier-scoped zone host releases wake into when the
    /// process-global zone is absent (x86 CPL0, #2031). Bound once by the
    /// carrier that maps this region.
    carrier_zone: std::sync::OnceLock<crate::el1_zone::CarrierZone>,
    /// The deadlines of native members' poll waits (#231).
    poll_deadlines: crate::host_readiness::PollDeadlines,
    native_epolls: Mutex<Option<Arc<crate::dispatch::net::native_epoll::NativeSocketEpolls>>>,
    /// Whether an executor can still run the ring over this region (#2955).
    guest: GuestExecution,
}

/// Whether any vCPU can still run ring code over a region. A ring critical
/// section holds a lock in the shared region; its holder releases it only if
/// an executor resumes that vCPU. After the executor pool has joined every
/// worker (or a worker died), none will: a lock still held then belongs to
/// a section that was cut off and can never be released.
#[derive(Debug, Default)]
struct GuestExecution {
    stopped: std::sync::atomic::AtomicBool,
    /// Tables and extents left in place because a cut-off section held them.
    quarantined: AtomicU64,
}

/// The host's wait on its own region's locks. While guests can run it is
/// [`HostLockWait`]: the holder is a host thread or a vCPU that its executor
/// resumes. Once guest execution has stopped, the first contention refuses
/// (`Contended`), and the caller quarantines what the dead holder guards.
#[derive(Clone, Copy)]
pub struct RegionWait<'a>(&'a GuestExecution);

impl carrick_el1_abi::LockWait for RegionWait<'_> {
    fn complete_object_wake(
        &self,
        zone: &carrick_sched_core::ZoneTables,
        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>,
    ) {
        <HostLockWait as carrick_el1_abi::LockWait>::complete_object_wake(
            &HostLockWait,
            zone,
            owned,
        );
    }

    fn wait(&self, attempt: u32) -> bool {
        !self.0.stopped.load(Ordering::Acquire)
            && <HostLockWait as carrick_el1_abi::LockWait>::wait(&HostLockWait, attempt)
    }
}

/// The host carrier's only region wait (#2988): it refuses once guest
/// execution has stopped, where the carrier's zone wait would spin forever.
impl carrick_el1_abi::ipc::RegionLockWait for RegionWait<'_> {}

impl carrick_el1_abi::LockWait<carrick_el1_abi::Aarch64ParkedContext> for RegionWait<'_> {
    fn complete_object_wake(
        &self,
        zone: &carrick_sched_core::ZoneTables<carrick_el1_abi::Aarch64ParkedContext>,
        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_el1_abi::Aarch64ParkedContext,
        >,
    ) {
        <HostLockWait as carrick_el1_abi::LockWait<carrick_el1_abi::Aarch64ParkedContext>>::complete_object_wake(
            &HostLockWait,
            zone,
            owned,
        );
    }

    fn wait(&self, attempt: u32) -> bool {
        <Self as carrick_el1_abi::LockWait>::wait(self, attempt)
    }
}

struct SocketEpollLockWait<'a>(&'a crate::el1_zone::CarrierZone);

impl SocketEpollLockWait<'_> {
    fn complete(
        &self,
        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >,
    ) {
        let zone = self.0.zone();
        let (waker, effects) = owned.deliver_handbacks(&mut |record| {
            if let Some(handback) = zone.place_host_handback(record)
                && let carrick_sched_core::NativePlacement::Placed(placement) = handback.placement
            {
                self.0.resched(placement.slot);
            }
        });
        carrick_el1::substrate::sched::object_wait::deliver_effects_with(
            zone,
            None,
            waker,
            effects,
            false,
            |slot, _| self.0.resched(slot),
            (|slot| self.0.resched(slot), || {}),
        );
    }
}

impl carrick_sched_core::LockWait<carrick_sched_core::ParkedContextWords>
    for SocketEpollLockWait<'_>
{
    fn wait(&self, attempt: u32) -> bool {
        <HostLockWait as carrick_el1_abi::LockWait>::wait(&HostLockWait, attempt)
    }

    fn complete_object_wake(
        &self,
        _: &carrick_sched_core::ZoneTables<carrick_sched_core::ParkedContextWords>,
        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >,
    ) {
        self.complete(owned);
    }
}

impl carrick_sched_core::object_wait::ipc_release::IpcLockRelease for HostIpc {
    fn carrier(&self) -> std::num::NonZeroU64 {
        self.region().operation_slot_generation()
    }

    fn released(&self, index: carrick_sched_core::object_wait::ipc_release::IpcLockIndex) {
        let identity = self.carrier();
        if let Some(zone) = crate::el1_zone::zone() {
            if let Ok(source) = zone.ipc_lock_release_source(index, identity) {
                source
                    .reserve()
                    .publish(carrick_sched_core::Waker::Host, &|owned| {
                        crate::el1_zone::complete_object_wake(zone, owned);
                    });
            }
        } else if let Some(carrier) = self.carrier_zone.get()
            && let Ok(source) = carrier.zone().ipc_lock_release_source(index, identity)
        {
            let wait = SocketEpollLockWait(carrier);
            source
                .reserve()
                .publish(carrick_sched_core::Waker::Host, &|owned| {
                    wait.complete(owned)
                });
        }
    }
}

impl std::fmt::Debug for HostIpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostIpc")
            .field("pool_len", &self.bytes.len)
            .finish_non_exhaustive()
    }
}

impl carrick_el1_abi::IpcWindowBacking for HostIpc {
    fn directory_ptr(&self) -> *mut u8 {
        HostIpc::directory_ptr(self).cast()
    }

    fn directory_len(&self) -> usize {
        HostIpc::directory_len(self)
    }

    fn pool_ptr(&self) -> *mut u8 {
        HostIpc::pool_ptr(self)
    }

    fn pool_len(&self) -> usize {
        HostIpc::pool_len(self)
    }
}

impl HostIpc {
    pub const DEFAULT_POOL_BYTES: usize = carrick_el1_abi::EL1_IPC_POOL_SPAN as usize;

    pub fn new(pool_bytes: usize) -> Result<Self, AdmissionError> {
        Self::with_limits(pool_bytes, IpcLimits::ZONE)
    }

    /// An authority whose zone-wide file table stops at `limits` (clamped to
    /// the ABI's reservation). The directory reserves address space for every
    /// store's full span; pages are committed only as segments are published.
    pub fn with_limits(pool_bytes: usize, limits: IpcLimits) -> Result<Self, AdmissionError> {
        Self::with_ceiling(
            pool_bytes,
            limits,
            std::sync::Arc::new(crate::kernel::FdCeilingAuthority::new()),
        )
    }

    /// An authority whose host-side installs raise `ceiling`: a kernel passes
    /// its own [`crate::kernel::FdCeilingAuthority`], so a descriptor this
    /// authority installs from the carrier is covered by the same word the
    /// EL1 vector reads. [`HostIpc::new`]/[`HostIpc::with_limits`] own a
    /// private authority no carrier reads.
    pub fn with_ceiling(
        pool_bytes: usize,
        limits: IpcLimits,
        ceiling: std::sync::Arc<crate::kernel::FdCeilingAuthority>,
    ) -> Result<Self, AdmissionError> {
        if pool_bytes < (IPC_POOL_AREAS * IPC_POOL_ALIGN) as usize || !pool_bytes.is_power_of_two()
        {
            return Err(AdmissionError::NoMemory);
        }
        let limits = IpcLimits {
            objects: limits.objects.min(IPC_MAX_OBJECTS),
            descriptions: limits.descriptions.min(IPC_MAX_OFDS),
        };
        let owner = Self {
            directory: Mapping::new(IPC_DIRECTORY_BYTES)?,
            bytes: Mapping::new(pool_bytes)?,
            host_wakes: Mutex::new(Vec::new()),
            resources: Mutex::new(HostResources {
                next: 1,
                live: BTreeMap::new(),
            }),
            limits,
            growth: Mutex::new(IpcGrowth::default()),
            ceiling,
            carrier_zone: std::sync::OnceLock::new(),
            poll_deadlines: crate::host_readiness::PollDeadlines::default(),
            native_epolls: Mutex::new(None),
            guest: GuestExecution::default(),
        };
        let identity = NEXT_REGION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| AdmissionError::NoMemory)?;
        // SAFETY: newly owned zeroed mappings; no view exists before publication.
        unsafe {
            IpcRegion::initialize(
                owner.directory_ptr(),
                owner.directory_len(),
                owner.pool_ptr(),
                pool_bytes,
                identity,
                limits,
            )?;
        }
        Ok(owner)
    }

    /// The zone-wide ceilings this authority grows its stores to.
    pub fn limits(&self) -> IpcLimits {
        self.limits
    }

    /// Records published by store growth so far (the work receipt).
    pub fn growth(&self) -> IpcGrowth {
        *self.growth.lock()
    }

    /// Publish another object segment unless one was published since the
    /// caller observed `seen` records (then just retry). `ZoneLimit` at the
    /// configured ceiling. O(segment), under the growth lock only.
    fn grow_objects(&self, seen: usize) -> Result<(), AdmissionError> {
        let mut growth = self.growth.lock();
        growth.object_records += self.region().grow_objects(seen)?;
        Ok(())
    }

    /// As `grow_objects`, for the one shared OFD publication owner.
    fn grow_descriptions(&self, seen: usize) -> Result<(), AdmissionError> {
        let mut growth = self.growth.lock();
        growth.description_records += self.region().grow_ofds(seen)?;
        Ok(())
    }

    /// Run `create` until the object store has a free record: an exhausted
    /// store grows by one segment and the creation retries. Every retry
    /// follows growth (by this or another creator), so the loop is bounded
    /// by the zone's ceiling.
    fn with_object<T>(
        &self,
        mut create: impl FnMut(&IpcRegion<'_>) -> Result<T, IpcError>,
    ) -> Result<T, AdmissionError> {
        loop {
            let region = self.region();
            let seen = region.object_count();
            match create(&region) {
                Err(IpcError::NoObjects) => self.grow_objects(seen)?,
                result => return result.map_err(Into::into),
            }
        }
    }

    fn set_host_wake(&self, object: IpcObjectHandle, target: HostWakeTarget) {
        let mut wakes = self.host_wakes.lock();
        let index = object.index() as usize;
        if index >= wakes.len() {
            // Amortized: grows with the object store's highest used index.
            wakes.resize_with(index + 1, || None);
        }
        wakes[index] = Some(HostWakeEntry { object, target });
    }
    pub(crate) fn wait_queue(
        self: &std::sync::Arc<Self>,
        object: IpcObjectHandle,
    ) -> std::sync::Arc<crate::kernel::WaitQueue> {
        let owner = std::sync::Arc::clone(self);
        let queue = std::sync::Arc::new(crate::kernel::WaitQueue::with_subscription(move || {
            let subscription = owner.subscribe_host(object).ok()?;
            // Enrollment closes the gap after the dispatch readiness check.
            // Prime any proxy from the object after subscription publication,
            // before the reactor starts waiting on its level-triggered fd.
            let publisher = {
                let wakes = owner.host_wakes.lock();
                wakes
                    .get(object.index() as usize)
                    .and_then(Option::as_ref)
                    .filter(|entry| entry.object == object)
                    .and_then(|entry| match &entry.target {
                        HostWakeTarget::Publisher { prime, .. } => prime.upgrade(),
                        HostWakeTarget::Queue(_) => None,
                    })
            };
            if let Some(publisher) = publisher {
                publisher();
            }
            Some(Box::new(subscription))
        }));
        self.set_host_wake(
            object,
            HostWakeTarget::Queue(std::sync::Arc::downgrade(&queue)),
        );
        queue
    }

    #[cfg(feature = "test-support")]
    pub fn test_wait_queue(
        self: &std::sync::Arc<Self>,
        object: IpcObjectHandle,
    ) -> std::sync::Arc<crate::kernel::WaitQueue> {
        self.wait_queue(object)
    }
    pub(crate) fn subscribe_host(
        self: &std::sync::Arc<Self>,
        object: IpcObjectHandle,
    ) -> Result<std::sync::Arc<HostSubscription>, IpcError> {
        self.region().subscribe_host(object, &self.wait())?;
        Ok(std::sync::Arc::new(HostSubscription {
            owner: std::sync::Arc::clone(self),
            object,
        }))
    }
    pub(crate) fn register_host_waker(
        &self,
        object: IpcObjectHandle,
        publisher: &std::sync::Arc<dyn Fn() + Send + Sync>,
        primer: &std::sync::Arc<dyn Fn() + Send + Sync>,
    ) {
        self.set_host_wake(
            object,
            HostWakeTarget::Publisher {
                wake: std::sync::Arc::downgrade(publisher),
                prime: std::sync::Arc::downgrade(primer),
            },
        );
    }
    /// Deliver guest-produced readiness work by exact object incarnation.
    /// Runtime calls this after returning from EL1; it never scans the pool.
    ///
    /// The delivery target is resolved (and held alive) BEFORE the owed flag
    /// is consumed: a wake is only ever consumed by a delivery that happens.
    /// With no live target for this exact incarnation the wake stays owed
    /// and indexed, and the region counts it
    /// ([`IpcRegion::owed_host_wakes_without_target`], which must stay 0).
    pub fn service_host_wake(&self, object: IpcObjectHandle) -> bool {
        let target = self.host_wake_target(object);
        // Authenticate and consume under the object lock: a recycled slot
        // cannot lose its successor's wake between generation check and swap.
        let region = self.region();
        let Ok(mut guard) = region.lock(object, &self.wait()) else {
            return false;
        };
        let Some(target) = target else {
            guard.retain_undeliverable_host_wake();
            return false;
        };
        let owed = guard.take_host_wake();
        drop(guard);
        if !owed {
            return false;
        }
        match target {
            HostWakeDelivery::Queue(queue) => queue.wake_all(),
            HostWakeDelivery::Publisher(publisher) => publisher(),
        }
        true
    }

    /// Deliver every host wake a publication owed: the object's own (its
    /// host subscribers), and each zone epoll's it queued an item on (that
    /// epoll's host-side waiters). Each is consumed only where owed.
    pub fn service_wake(&self, wake: &IpcWake) {
        if !wake.host_owed {
            return;
        }
        self.service_host_wake(wake.object);
        for epoll in wake.epolls.iter() {
            self.service_host_wake(epoll);
        }
    }

    /// The live delivery target registered for exactly `object`'s
    /// incarnation, held strongly so it outlives the consumption it justifies.
    fn host_wake_target(&self, object: IpcObjectHandle) -> Option<HostWakeDelivery> {
        let wakes = self.host_wakes.lock();
        let entry = wakes
            .get(object.index() as usize)
            .and_then(Option::as_ref)
            .filter(|entry| entry.object == object)?;
        match &entry.target {
            HostWakeTarget::Queue(queue) => queue.upgrade().map(HostWakeDelivery::Queue),
            HostWakeTarget::Publisher { wake, .. } => {
                wake.upgrade().map(HostWakeDelivery::Publisher)
            }
        }
    }

    pub fn directory_ptr(&self) -> *mut IpcDirectory {
        self.directory.ptr.as_ptr().cast()
    }
    pub fn directory_len(&self) -> usize {
        self.directory.len
    }
    pub fn pool_ptr(&self) -> *mut u8 {
        self.bytes.ptr.as_ptr()
    }
    pub fn pool_len(&self) -> usize {
        self.bytes.len
    }

    /// This region's lock wait: [`HostLockWait`] until guest execution
    /// stops, then a refusal at the first contention.
    pub(crate) fn wait(&self) -> RegionWait<'_> {
        RegionWait(&self.guest)
    }

    /// No executor can run ring code over this region again: the executor
    /// pool has joined every worker. A ring section that still holds a lock
    /// was cut off, so host waits refuse from here on (#2955).
    pub fn stop_guest_execution(&self) {
        self.guest.stopped.store(true, Ordering::Release);
    }

    /// Settle a teardown step that was refused. After guest execution has
    /// stopped, a contended lock's holder can never release it: the step
    /// leaves what that lock guards in place (it may be mid-update), counts
    /// it, and teardown goes on. Any other refusal, or a contention while
    /// guests can still run, stays the caller's error.
    pub(crate) fn quarantine_cut_off(&self, error: AdmissionError) -> Result<(), AdmissionError> {
        let contended = matches!(
            error,
            AdmissionError::Shared(IpcError::Contended | IpcError::Fd(fd::Error::Contended))
        );
        if contended && self.guest.stopped.load(Ordering::Acquire) {
            self.guest.quarantined.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                ?error,
                "IPC teardown left state held by a stopped vCPU in quarantine"
            );
            return Ok(());
        }
        Err(error)
    }

    /// Teardown steps quarantined behind a lock a stopped vCPU held.
    pub fn quarantined_teardowns(&self) -> u64 {
        self.guest.quarantined.load(Ordering::Relaxed)
    }

    /// A view cannot outlive the mappings it borrows.
    pub fn region(&self) -> IpcRegion<'_> {
        // SAFETY: only new() constructs an owner; it initialized both mappings.
        unsafe {
            IpcRegion::attach(
                self.directory_ptr(),
                self.directory_len(),
                self.pool_ptr(),
                self.pool_len(),
            )
        }
        .unwrap_or_else(|_| carrick_fatal::carrick_fatal!("IPC", "corrupt owned IPC region"))
        .with_ceiling(&*self.ceiling)
    }

    /// The descriptor ceiling this authority's installs raise.
    pub fn fd_ceiling(&self) -> &std::sync::Arc<crate::kernel::FdCeilingAuthority> {
        &self.ceiling
    }

    fn bind_waits(
        &self,
        object: IpcObjectHandle,
    ) -> Result<(), carrick_sched_core::object_wait::ObjectWaitError> {
        if let Some(zone) = crate::el1_zone::zone() {
            let mut bound: [Option<carrick_sched_core::object_wait::ObjectWaitKey>; 2] =
                [None, None];
            let mut bound_count = 0;
            for direction in [pipe::WaitFor::Readable, pipe::WaitFor::Writable] {
                let key = pipe_lane_key(object, direction);
                let result = zone.bind_object_wait(key, &self.wait(), &|owned| {
                    crate::el1_zone::complete_object_wake(owned.zone(), owned)
                });
                if let Err(error) = result {
                    while bound_count > 0 {
                        bound_count -= 1;
                        let Some(key) = bound[bound_count] else {
                            continue;
                        };
                        zone.unbind_object_wait(key, &self.wait(), &|owned| {
                            crate::el1_zone::complete_object_wake(owned.zone(), owned)
                        })?;
                    }
                    return Err(error);
                }
                bound[bound_count] = Some(key);
                bound_count += 1;
            }
        }
        Ok(())
    }
    fn discard_unpublished_pipe(&self, object: IpcObjectHandle) -> Result<(), IpcError> {
        let region = self.region();
        for (index, end) in [pipe::End::Reader, pipe::End::Writer]
            .into_iter()
            .enumerate()
        {
            let backing = carrick_el1_abi::ipc::IpcBacking::Pipe { object, end }.encode();
            let released = region.release_backing(backing, &self.wait())?;
            if !matches!(released, carrick_el1_abi::ipc::IpcReleased::Object { freed, .. } if freed == (index == 1))
            {
                return Err(IpcError::Corrupt);
            }
        }
        Ok(())
    }
    fn wait_bind_error(error: carrick_sched_core::object_wait::ObjectWaitError) -> AdmissionError {
        match error {
            carrick_sched_core::object_wait::ObjectWaitError::Exhausted => {
                AdmissionError::ObjectWaitKeyOutOfRange
            }
            error => AdmissionError::ObjectWaitInvariant(error),
        }
    }
    fn discard_unpublished_eventfd(&self, object: IpcObjectHandle) -> Result<(), IpcError> {
        let backing = carrick_el1_abi::ipc::IpcBacking::EventFd { object }.encode();
        match self.region().release_backing(backing, &self.wait())? {
            carrick_el1_abi::ipc::IpcReleased::Object { freed: true, .. } => Ok(()),
            _ => Err(IpcError::Corrupt),
        }
    }
    fn provision_pipe(
        &self,
        ring_bytes: u64,
        pages: u64,
    ) -> Result<IpcPipeStorage, AdmissionError> {
        self.region()
            .provision_pipe_storage(ring_bytes, pages, &self.wait())
            .map_err(|error| match error {
                IpcError::Fd(fd::Error::NoMemory) => AdmissionError::NoMemory,
                error => error.into(),
            })
    }
    /// Bind `object`'s readiness lanes from `*bound` on, under the create
    /// path's refusing lock policy. `Ok(true)`: every lane is bound.
    /// `Ok(false)`: lane `*bound` is held by another party (a late holder of
    /// a recycled slot's previous incarnation); lanes before it stay bound
    /// and owned by the caller. Any other refusal is returned unchanged.
    fn bind_pipe_lanes(
        zone: &carrick_el1_abi::ZoneTables,
        object: IpcObjectHandle,
        bound: &mut usize,
    ) -> Result<bool, carrick_sched_core::object_wait::ObjectWaitError> {
        while *bound < PIPE_LANES.len() {
            let key = pipe_lane_key(object, PIPE_LANES[*bound]);
            match zone.bind_object_wait(key, &IpcCreateLockWait, &|owned| {
                crate::el1_zone::complete_object_wake(owned.zone(), owned)
            }) {
                Ok(()) => *bound += 1,
                Err(carrick_sched_core::object_wait::ObjectWaitError::Busy) => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        Ok(true)
    }

    /// Undo an unpublished pipe: unbind its owned lanes, newest first,
    /// BEFORE its record returns to the free list (a recycled index must
    /// never meet a lane still bound to this incarnation), then free it.
    ///
    /// Runs when the create fails, from the test helper, when a parked
    /// continuation is dropped (terminal cancellation), and on the resumed
    /// `pipe2` dispatcher when its `pipefd` output is owner-refused. In the
    /// last case the executor still runs it, but holds no output permit, no
    /// descriptor and no IPC lock: each lane bind released its lock before
    /// returning. It keeps the short-section [`HostLockWait`]: a lane or
    /// object lock holder is a host thread in a short section or an EL1 vCPU
    /// its executor resumes to completion, and a rollback that refused would
    /// leak the object (witness: `carrick-runtime`
    /// `serial_host_pipe2_lane_resume_output_refusal_rolls_back_and_reruns_once`).
    fn rollback_unpublished_pipe(
        &self,
        zone: Option<&carrick_el1_abi::ZoneTables>,
        object: IpcObjectHandle,
        bound: usize,
    ) -> Result<(), AdmissionError> {
        if let Some(zone) = zone {
            for lane in PIPE_LANES[..bound].iter().rev() {
                zone.unbind_object_wait(pipe_lane_key(object, *lane), &self.wait(), &|owned| {
                    crate::el1_zone::complete_object_wake(owned.zone(), owned)
                })
                .map_err(AdmissionError::ObjectWaitInvariant)?;
            }
        }
        self.discard_unpublished_pipe(object)
            .map_err(AdmissionError::ObjectRollbackInvariant)
    }

    /// Create an unpublished pipe for `pipe2`. A new pipe costs its object
    /// record only: its ring is provided at its first write
    /// ([`HostIpc::ensure_pipe_storage`]), as Linux allocates pipe pages on
    /// demand.
    ///
    /// Binding its readiness lanes never waits for a held lane lock: the
    /// partially bound object is returned as [`PipeCreation::Retained`] for
    /// its caller to park on that lock's release ([`PendingPipeCreate`]), so
    /// no host executor is pinned by another party's critical section (#1845).
    /// Contention is never an errno or an invariant failure.
    pub fn begin_pipe(
        self: &std::sync::Arc<Self>,
        capacity: usize,
    ) -> Result<PipeCreation, AdmissionError> {
        self.top_up_ring_stock()?;
        let object = self.with_object(|region| region.create_pipe(capacity, &self.wait()))?;
        let Some(zone) = crate::el1_zone::zone() else {
            return Ok(PipeCreation::Created(object));
        };
        PendingPipeCreate {
            owner: std::sync::Arc::clone(self),
            zone,
            object: Some(object),
            bound: 0,
        }
        .bind()
    }

    /// Test helper: create a pipe whose lanes no other party holds. A held
    /// lane rolls the object back and reports `Busy`; production `pipe2`
    /// retains it instead ([`HostIpc::begin_pipe`]).
    #[cfg(any(test, feature = "test-support"))]
    pub fn create_pipe(&self, capacity: usize) -> Result<IpcObjectHandle, AdmissionError> {
        self.top_up_ring_stock()?;
        let object = self.with_object(|region| region.create_pipe(capacity, &self.wait()))?;
        let Some(zone) = crate::el1_zone::zone() else {
            return Ok(object);
        };
        let mut bound = 0;
        let result = Self::bind_pipe_lanes(zone, object, &mut bound);
        match result {
            Ok(true) => Ok(object),
            Ok(false) => {
                self.rollback_unpublished_pipe(Some(zone), object, bound)?;
                Err(AdmissionError::ObjectWaitInvariant(
                    carrick_sched_core::object_wait::ObjectWaitError::Busy,
                ))
            }
            Err(error) => {
                self.rollback_unpublished_pipe(Some(zone), object, bound)?;
                Err(Self::wait_bind_error(error))
            }
        }
    }

    /// Add one default-capacity ring to the shared stock if it has room: one
    /// ring per pipe created keeps a fresh pipe's first write in EL1 (no host
    /// exit) for up to [`carrick_el1_abi::ipc::IPC_RING_STOCK`] pipes created between writes. The
    /// stock bounds the pool address space idle pipes can claim, so a zone
    /// of many idle pipes still costs records only. A refused provision
    /// only means later first writes allocate through the shared ring allocator.
    fn top_up_ring_stock(&self) -> Result<(), AdmissionError> {
        let region = self.region();
        if !region.ring_stock_has_room() {
            return Ok(());
        }
        let Ok(ring) = self.provision_pipe(
            IPC_STOCK_RING_BYTES,
            IPC_STOCK_RING_BYTES / IPC_PIPE_PAGE_SIZE as u64,
        ) else {
            return Ok(());
        };
        if let Err(mut ring) = region.stock_ring(ring) {
            region.reclaim_pipe_storage(&mut ring, &self.wait())?;
        }
        Ok(())
    }

    /// Give `object`'s pipe its ring before a host write: provisioned from
    /// the pool outside any lock, installed under the object lock unless
    /// another writer did so first (then reclaimed). A pipe that already has
    /// its ring costs one object lock. `NoMemory` only when the pool itself
    /// is exhausted (the write then fails like a failed page allocation).
    pub(crate) fn ensure_pipe_storage(
        &self,
        object: IpcObjectHandle,
    ) -> Result<(), AdmissionError> {
        self.top_up_ring_stock()?;
        let region = self.region();
        let mut guard = region.lock(object, &self.wait())?;
        guard
            .ensure_pipe_storage()
            .map(|_| ())
            .map_err(|error| match error {
                IpcError::Fd(fd::Error::NoMemory) => AdmissionError::NoMemory,
                error => error.into(),
            })
    }

    pub fn create_eventfd(
        &self,
        initial: u32,
        mode: pipe::EventMode,
    ) -> Result<IpcObjectHandle, AdmissionError> {
        let object =
            self.with_object(|region| region.create_eventfd(initial, mode, &self.wait()))?;
        if let Err(error) = self.bind_waits(object) {
            if let Err(rollback) = self.discard_unpublished_eventfd(object) {
                return Err(AdmissionError::ObjectRollbackInvariant(rollback));
            }
            return Err(Self::wait_bind_error(error));
        }
        Ok(object)
    }

    /// A zone epoll record ([`carrick_el1_abi::ipc::epoll`]) with an empty
    /// interest list. Its `Readable` wait key is bound like an object's.
    pub fn create_epoll(&self) -> Result<IpcObjectHandle, AdmissionError> {
        let object = self.with_object(|region| region.create_epoll(&self.wait()))?;
        if let Err(error) = self.bind_waits(object) {
            if let Err(rollback) = self.region().epoll_destroy(object, &self.wait()) {
                let error = AdmissionError::ObjectRollbackInvariant(rollback);
                let _ = CreateError::from_admission(error);
                return Err(error);
            }
            let error = Self::wait_bind_error(error);
            if matches!(
                error,
                AdmissionError::ObjectWaitInvariant(_) | AdmissionError::ObjectRollbackInvariant(_)
            ) {
                let _ = CreateError::from_admission(error);
            }
            return Err(error);
        }
        Ok(object)
    }

    pub(crate) fn resize_pipe(
        &self,
        object: IpcObjectHandle,
        requested: usize,
        limit: usize,
    ) -> Result<usize, AdmissionError> {
        self.region()
            .resize_pipe(object, requested, limit, &self.wait(), |wake| {
                let mut delivery = self.object_wake_delivery();
                delivery.collect(wake);
                delivery.deliver();
            })
            .map_err(Into::into)
    }

    fn provision_descriptors(&self, capacity: usize) -> Result<fd::Extent, AdmissionError> {
        self.region()
            .provision_descriptors(capacity, &self.wait())
            .map_err(|error| match error {
                fd::storage::StorageError::Exhausted | fd::storage::StorageError::Invalid => {
                    AdmissionError::NoMemory
                }
                fd::storage::StorageError::Contended => AdmissionError::Shared(IpcError::Contended),
            })
    }
    /// Admit an owned host description before installing any numeric fd.
    /// On refusal the caller still owns and must release the backing.
    pub fn admit_description(
        self: &std::sync::Arc<Self>,
        description: fd::Description,
    ) -> Result<HostDescription, AdmissionError> {
        // An exhausted description store grows by one segment and retries
        // (bounded by the zone's ceiling, as for objects).
        let pin = loop {
            let region = self.region();
            let seen = region.ofd_count();
            match region.fd(self.wait()).create_pinned(description) {
                Err(fd::Error::NeedsOfds) => self.grow_descriptions(seen)?,
                result => break result?,
            }
        };
        Ok(HostDescription {
            flags: std::sync::Arc::new(HostDescriptionFlags {
                owner: std::sync::Arc::clone(self),
                state: Mutex::new(HostDescriptionState::Live(pin)),
            }),
        })
    }

    /// Hold the exact description a shared table's slot names now: the
    /// returned [`HostDescription`] keeps that OFD (and so its backing) live
    /// until it drops, as an admitted one does.
    pub(crate) fn retain_description(
        self: &std::sync::Arc<Self>,
        table: fd::TableId,
        target: fd::Fd,
    ) -> Result<(HostDescription, fd::Description), fd::Error> {
        let (pin, description) = self.region().fd(self.wait()).pin(table, target)?;
        Ok((
            HostDescription {
                flags: std::sync::Arc::new(HostDescriptionFlags {
                    owner: std::sync::Arc::clone(self),
                    state: Mutex::new(HostDescriptionState::Live(pin)),
                }),
            },
            description,
        ))
    }

    pub fn create_table(
        &self,
        limit: usize,
        capacity: usize,
    ) -> Result<fd::TableId, AdmissionError> {
        let mut storage = self.provision_descriptors(capacity)?;
        let result = self
            .region()
            .fd(self.wait())
            .create_table(limit, &mut storage);
        if result.is_err() {
            self.reclaim_descriptors(storage)?;
        }
        result.map_err(Into::into)
    }
    /// Grow an admitted table before publishing any host slot reservation.
    /// Caller serializes host admission and supplies a nondecreasing capacity.
    pub fn ensure_capacity(
        &self,
        table: fd::TableId,
        capacity: usize,
    ) -> Result<(), AdmissionError> {
        let mut storage = self.provision_descriptors(capacity)?;
        let result = self
            .region()
            .fd(self.wait())
            .grow_table(table, &mut storage);
        self.reclaim_descriptors(storage)?;
        result.map_err(Into::into)
    }
    /// Reclaim only an extent returned by this region's destroy/grow operation.
    pub(crate) fn reclaim_descriptors(&self, mut extent: fd::Extent) -> Result<(), AdmissionError> {
        self.region()
            .reclaim_descriptors(&mut extent, &self.wait())
            .map_err(|error| {
                AdmissionError::Shared(match error {
                    fd::storage::StorageError::Contended => IpcError::Contended,
                    fd::storage::StorageError::Invalid | fd::storage::StorageError::Exhausted => {
                        IpcError::BadStorage
                    }
                })
            })
    }
    pub fn retain_host_resource(
        &self,
        resource: Box<dyn std::any::Any + Send + Sync>,
    ) -> Result<HostResourceToken, AdmissionError> {
        let mut resources = self.resources.lock();
        let token = HostResourceToken::new(resources.next).ok_or(AdmissionError::NoMemory)?;
        resources.next += 1;
        resources
            .live
            .insert(token.get(), HostResource::from(resource));
        Ok(token)
    }

    /// Install a newly opened host resource as the lowest free descriptor of
    /// ring table `table` (Linux open(2) numbering), growing the description
    /// store or the table's slots as fd-core requests. On refusal nothing is
    /// published and the resource is dropped.
    pub fn install_host_description(
        &self,
        table: fd::TableId,
        resource: Box<dyn std::any::Any + Send + Sync>,
        access: fd::AccessMode,
        flags: fd::StatusFlags,
        identity: Option<fd::record_lock::FileIdentity>,
        cloexec: bool,
    ) -> Result<fd::Fd, InstallHostDescriptionError> {
        let token = self
            .retain_host_resource(resource)
            .map_err(|_| InstallHostDescriptionError::NoMemory)?;
        let backing = carrick_el1_abi::ipc::IpcBacking::Host(token).encode();
        let forget = |error| {
            self.resources.lock().live.remove(&token.get());
            Err(error)
        };
        loop {
            let seen = self.region().ofd_count();
            // Stamped before any descriptor names it: every advisory lock
            // taken through the description finds its file.
            let opened = self.region().fd(self.wait()).open_identified(
                table,
                fd::Fd(0),
                fd::Description::new(backing, access, flags),
                identity,
                cloexec,
            );
            match opened {
                Ok(number) => return Ok(number),
                Err(fd::Error::NeedsOfds) => {
                    if let Err(error) = self.grow_descriptions(seen) {
                        return forget(match error {
                            AdmissionError::Shared(IpcError::ZoneLimit) => {
                                InstallHostDescriptionError::FileTableFull
                            }
                            _ => InstallHostDescriptionError::NoMemory,
                        });
                    }
                }
                Err(fd::Error::NeedsBacking { descriptors }) => {
                    if self.ensure_capacity(table, descriptors).is_err() {
                        return forget(InstallHostDescriptionError::NoMemory);
                    }
                }
                Err(fd::Error::TooManyFiles) => {
                    return forget(InstallHostDescriptionError::TooManyFiles);
                }
                Err(_) => return forget(InstallHostDescriptionError::Unavailable),
            }
        }
    }

    pub(crate) fn bind_socket_epoll_lock(&self, object: IpcObjectHandle) -> Result<(), IpcError> {
        use carrick_sched_core::object_wait::ipc_release::IpcLockIndex;
        let index = IpcLockIndex::object(object.index() as usize).ok_or(IpcError::Corrupt)?;
        let identity = self.region().operation_slot_generation();
        let result = if let Some(zone) = crate::el1_zone::zone() {
            zone.bind_ipc_lock_release(index, identity, &self.wait(), &|owned| {
                crate::el1_zone::complete_object_wake(zone, owned);
            })
        } else if let Some(carrier) = self.carrier_zone.get() {
            let wait = SocketEpollLockWait(carrier);
            carrier
                .zone()
                .bind_ipc_lock_release(index, identity, &wait, &|owned| wait.complete(owned))
        } else {
            Ok(())
        };
        result.map_err(|_| IpcError::Corrupt)
    }

    pub(crate) fn socket_epoll_region(&self) -> Result<IpcRegion<'_>, IpcError> {
        self.region().with_lock_release(self)
    }

    pub(crate) fn native_socket_epolls(
        self: &Arc<Self>,
        reactor: &Arc<crate::host_readiness::HostReadinessReactor>,
    ) -> Result<Arc<crate::dispatch::net::native_epoll::NativeSocketEpolls>, carrick_abi::LinuxErrno>
    {
        let mut epolls = self.native_epolls.lock();
        if let Some(held) = epolls.as_ref() {
            return Ok(held.clone());
        }
        let producer = crate::dispatch::net::native_epoll::NativeSocketEpolls::new(self, reactor)?;
        *epolls = Some(producer.clone());
        Ok(producer)
    }

    pub(crate) fn existing_native_socket_epolls(
        &self,
    ) -> Option<Arc<crate::dispatch::net::native_epoll::NativeSocketEpolls>> {
        self.native_epolls.lock().clone()
    }

    pub(crate) fn deliver_socket_epoll_wakes(&self, wakes: impl IntoIterator<Item = IpcWake>) {
        for wake in wakes {
            let mut delivery = self.object_wake_delivery();
            delivery.collect(wake);
            delivery.deliver();
            self.service_wake(&wake);
        }
    }

    pub(crate) fn host_resource(&self, token: HostResourceToken) -> Option<HostResource> {
        self.resources.lock().live.get(&token.get()).cloned()
    }

    pub(crate) fn with_pinned_ofd<R>(
        &self,
        table: fd::TableId,
        number: fd::Fd,
        serve: impl FnOnce(fd::OfdKey, fd::Description) -> R,
    ) -> Result<R, PinnedHostResourceError> {
        let region = self.region();
        let authority = region.fd(self.wait());
        let (pin, description) = authority.pin(table, number).map_err(|error| match error {
            fd::Error::BadFd => PinnedHostResourceError::BadFd,
            _ => PinnedHostResourceError::Unavailable,
        })?;
        let result = serve(pin.key(), description);
        match authority.unpin(pin) {
            Ok(Some(last)) => {
                self.release(last.backing)
                    .map_err(|_| PinnedHostResourceError::Unavailable)?;
            }
            Ok(None) => {}
            Err(_) => return Err(PinnedHostResourceError::Unavailable),
        }
        Ok(result)
    }

    /// Pin the exact open description `fd` names in ring table `table` and
    /// hand its host resource to `serve`. The pin lasts for the whole service,
    /// so a concurrent close cannot retire the resource underneath it; a
    /// final release found at unpin is performed here, after `serve`.
    pub fn with_pinned_host_resource<R>(
        &self,
        table: fd::TableId,
        number: fd::Fd,
        serve: impl FnOnce(&HostResource) -> R,
    ) -> Result<R, PinnedHostResourceError> {
        self.with_host_resource_pin(table, number, |resource, _, _| Ok(serve(resource)))
    }

    /// Give the callback the pinned description's shared status flags.
    pub(crate) fn with_pinned_host_description<R>(
        &self,
        table: fd::TableId,
        number: fd::Fd,
        serve: impl FnOnce(&HostResource, fd::StatusFlags) -> R,
    ) -> Result<R, PinnedHostResourceError> {
        self.with_host_resource_pin(table, number, |resource, _, flags| {
            Ok(serve(resource, flags))
        })
    }

    pub(crate) fn set_host_nonblock(
        &self,
        table: fd::TableId,
        number: fd::Fd,
        enable: bool,
    ) -> Result<(), PinnedHostResourceError> {
        self.with_host_resource_pin(table, number, |_, pin, _| {
            self.region()
                .fd(self.wait())
                .set_pinned_nonblock(pin, enable)
                .map_err(|error| match error {
                    fd::Error::BadFd => PinnedHostResourceError::BadFd,
                    _ => PinnedHostResourceError::Unavailable,
                })
        })
    }

    fn with_host_resource_pin<R>(
        &self,
        table: fd::TableId,
        number: fd::Fd,
        serve: impl FnOnce(
            &HostResource,
            &fd::OfdPin,
            fd::StatusFlags,
        ) -> Result<R, PinnedHostResourceError>,
    ) -> Result<R, PinnedHostResourceError> {
        let region = self.region();
        let authority = region.fd(self.wait());
        let (pin, description) = authority.pin(table, number).map_err(|error| match error {
            fd::Error::BadFd => PinnedHostResourceError::BadFd,
            _ => PinnedHostResourceError::Unavailable,
        })?;
        let resource = match carrick_el1_abi::ipc::IpcBacking::decode(description.backing) {
            Some(carrick_el1_abi::ipc::IpcBacking::Host(token)) => self
                .resources
                .lock()
                .live
                .get(&token.get())
                .cloned()
                .ok_or(PinnedHostResourceError::Unavailable),
            Some(_) => Err(PinnedHostResourceError::InZone),
            None => Err(PinnedHostResourceError::Unavailable),
        };
        let result = resource.and_then(|resource| serve(&resource, &pin, description.flags));
        match authority.unpin(pin) {
            Ok(Some(last)) => {
                self.release(last.backing)
                    .map_err(|_| PinnedHostResourceError::Unavailable)?;
            }
            Ok(None) => {}
            Err(_) => return Err(PinnedHostResourceError::Unavailable),
        }
        result
    }

    /// Sample `record`'s host-readiness queue before a non-blocking probe of
    /// a host object the member may wait on (#231). `None` when no zone
    /// serves the member.
    pub(crate) fn host_ready_revision(&self, record: carrick_el1_abi::RecordRef) -> Option<u64> {
        crate::el1_zone::host_ready_revision(self.carrier_zone.get(), record)
    }

    /// Replace `record`'s host-readiness wait with one on `interests`, and
    /// `deadline` if given, in `reactor`: the first to fire notifies its
    /// queue in this region's carrier zone. `false` when no reactor serves
    /// the kernel or a descriptor cannot be retained: the caller refuses the
    /// wait.
    pub(crate) fn watch_host_ready(
        &self,
        reactor: &crate::host_readiness::HostReadinessReactor,
        record: carrick_el1_abi::RecordRef,
        interests: &[crate::host_readiness::HostReadinessInterest<'_>],
        deadline: Option<std::time::Instant>,
    ) -> bool {
        reactor.watch(
            record,
            interests,
            deadline,
            self.carrier_zone.get().cloned(),
        )
    }

    /// [`Self::watch_host_ready`], with in-zone parts of the wait (#2867)
    /// and, for a socket timeout, the call's deadline (#2878).
    pub(crate) fn watch_host_ready_with_zone(
        &self,
        reactor: &crate::host_readiness::HostReadinessReactor,
        record: carrick_el1_abi::RecordRef,
        interests: &[crate::host_readiness::HostReadinessInterest<'_>],
        zone: Vec<crate::host_readiness::HostReadinessZoneInterest>,
        deadline: Option<std::time::Instant>,
    ) -> bool {
        reactor.watch_with_zone(
            record,
            interests,
            zone,
            deadline,
            self.carrier_zone.get().cloned(),
        )
    }

    /// The deadlines of native members' poll waits.
    pub(crate) fn poll_deadlines(&self) -> &crate::host_readiness::PollDeadlines {
        &self.poll_deadlines
    }

    #[cfg(feature = "test-support")]
    pub fn retained_host_resources(&self) -> usize {
        self.resources.lock().live.len()
    }
    /// Settle the completions the ring deferred to the bound carrier zone's
    /// chain (x86 CPL0, #2928); nothing when no carrier zone is bound.
    pub(crate) fn hand_back_carrier_completions(&self) {
        if let Some(carrier) = self.carrier_zone.get() {
            crate::el1_zone::hand_back_carrier_completions(carrier.as_ref());
        }
    }

    /// Bind the carrier-scoped zone this region's host releases wake into.
    /// A carrier binds once; a second binding is refused, never replaced.
    pub fn bind_carrier_zone(
        &self,
        zone: crate::el1_zone::CarrierZone,
    ) -> Result<(), crate::el1_zone::CarrierZone> {
        self.carrier_zone.set(zone)
    }

    /// Zone wake collection for a host-side object change: the
    /// process-global zone when it serves, else this region's carrier zone.
    fn object_wake_delivery(&self) -> crate::el1_zone::ObjectWakeDelivery {
        crate::el1_zone::ObjectWakeDelivery::for_carrier(self.carrier_zone.get().cloned())
    }

    /// Final-description release, after leaving the descriptor table lock.
    /// Delivers guest and host wakes after leaving object locks.
    pub fn release(&self, backing: fd::BackingToken) -> Result<IpcReleased, IpcError> {
        if let Some(carrick_el1_abi::ipc::IpcBacking::Epoll { object }) =
            carrick_el1_abi::ipc::IpcBacking::decode(backing)
            && self.region().epoll_needs_host_release(object)
            && let Some(epolls) = self.existing_native_socket_epolls()
        {
            epolls.forget_epoll(object);
        }
        let released = self.region().release_backing(backing, &self.wait())?;
        if let IpcReleased::Object { wake, freed: false } = released {
            let region = self.region();
            if let Ok(guard) = region.lock(wake.object, &self.wait()) {
                let mut delivery = self.object_wake_delivery();
                delivery.collect(wake);
                drop(guard);
                delivery.deliver();
                if self
                    .carrier_zone
                    .get()
                    .and_then(|carrier| carrier.take_undelivered())
                    .is_some()
                {
                    // The record stays queued, but a halted CPU never runs
                    // it: the release cannot claim the wake was delivered.
                    // Its callers fail closed on a corrupt release.
                    return Err(IpcError::Corrupt);
                }
            }
            self.service_wake(&wake);
        }
        if let IpcReleased::Host(token) = released {
            let resource = self
                .resources
                .lock()
                .live
                .remove(&token.get())
                .ok_or(IpcError::Stale)?;
            drop(resource);
        }
        Ok(released)
    }

    /// Drop the advisory locks whose owner no longer exists (a table the
    /// ring retired at exit, a description whose last reference the ring or
    /// this host released) and wake the ring waiters parked on the lock
    /// object: their calls rerun and probe once (#231).
    fn reap_file_locks(&self) -> Result<(), IpcError> {
        let region = self.region();
        let Some(mut locks) = region.existing_file_locks(&self.wait())? else {
            return Ok(());
        };
        if !locks.table().reap(&region.fd(self.wait())) {
            return Ok(());
        }
        let wake = locks.released();
        let mut delivery = self.object_wake_delivery();
        delivery.collect(wake);
        drop(locks);
        delivery.deliver();
        self.service_wake(&wake);
        Ok(())
    }

    /// Release a bounded batch of host-backed OFDs finalized in the ring
    /// (`close_filtered` / `dup2_filtered` / `dup3_filtered`).
    pub fn drain_retired_ofds(&self) -> Result<usize, AdmissionError> {
        let region = self.region();
        let authority = region.fd(self.wait());
        let mut count = 0;
        for _ in 0..region.ofd_count().max(1) {
            let Some(description) = authority.take_retired_ofd()? else {
                break;
            };
            self.release(description.backing)?;
            count += 1;
        }
        if count != 0 {
            self.reap_file_locks()?;
        }
        Ok(count)
    }

    /// Finish a bounded batch of ring-revoked tables. Receipts retain the
    /// table on refusal; resource destruction runs after all core locks.
    pub fn drain_retired_tables(&self) -> Result<usize, AdmissionError> {
        self.drain_retired_ofds()?;
        let region = self.region();
        let authority = region.fd(self.wait());
        let mut count = 0;
        for _ in 0..carrick_el1_abi::ipc::IPC_FD_TABLES {
            let Some(mut receipt) = authority.take_retired_table() else {
                break;
            };
            let mut releases = Vec::with_capacity(receipt.capacity().min(region.ofd_count()));
            let extent = receipt.finish(|description| releases.push(description));
            for description in releases {
                self.release(description.backing)?;
            }
            self.reclaim_descriptors(extent?)?;
            count += 1;
        }
        if count != 0 {
            self.reap_file_locks()?;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1_abi::ipc::{IpcBacking, fd, pipe};

    /// #2031: a carrier-scoped zone (x86 CPL0) for the host release path.
    mod carrier_zone_release {
        use super::*;
        use carrick_sched_core::object_wait::OperationToken;
        use carrick_sched_core::{
            CarrierZoneWake, ParkedContextWords, RecordId, ShortLockSpin, SlotId, ThreadIdentity,
            ZoneTables,
        };

        const MM: u64 = 0x2031;

        struct TestCarrier {
            zone: &'static ZoneTables<ParkedContextWords>,
            rescheds: Mutex<Vec<SlotId>>,
        }
        impl CarrierZoneWake<ParkedContextWords> for TestCarrier {
            fn zone(&self) -> &ZoneTables<ParkedContextWords> {
                self.zone
            }
            fn resched(&self, slot: SlotId) {
                self.rescheds.lock().push(slot);
            }
            fn take_undelivered(&self) -> Option<carrick_sched_core::WakeUndelivered> {
                None
            }
        }

        fn carrier() -> std::sync::Arc<TestCarrier> {
            let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
            // SAFETY: the shared zone ABI's empty state is all-zero; the
            // fixture leaks it for the 'static carrier binding.
            let zone = unsafe {
                &*std::alloc::alloc_zeroed(layout).cast::<ZoneTables<ParkedContextWords>>()
            };
            std::sync::Arc::new(TestCarrier {
                zone,
                rescheds: Mutex::new(Vec::new()),
            })
        }

        /// A native task parked on `object`'s readable lane, as the ring's
        /// zone poll leaves it (#2032), allowed on guest CPU 1 only.
        fn park_reader(carrier: &TestCarrier, object: IpcObjectHandle) -> RecordId {
            let zone = carrier.zone;
            let key = carrick_el1_abi::ipc::object_wait_key(object, pipe::WaitFor::Readable)
                .expect("lane key");
            let discard = |owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
                '_,
                ParkedContextWords,
            >| {
                let _ = owned.into_parts();
            };
            zone.bind_object_wait(key, &ShortLockSpin, &discard)
                .expect("ring binds the lane");
            let record = zone
                .alloc_record(ThreadIdentity {
                    tid: 77,
                    serial: 77,
                    mm: MM,
                    file_table: 77,
                    generation: 1,
                    affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                    affinity: 1 << 1,
                    lifecycle_page: 0,
                    control_slot: 0,
                })
                .expect("record");
            assert!(zone.mark_native_owned(record));
            let queue = zone
                .object_wait(key, &ShortLockSpin, &discard)
                .expect("lane");
            queue
                .park(
                    queue.snapshot(),
                    record,
                    OperationToken::new(77, 1).expect("token"),
                )
                .expect("park");
            record
        }

        fn release_last_writer(owner: &HostIpc, object: IpcObjectHandle) {
            let released = owner
                .release(
                    IpcBacking::Pipe {
                        object,
                        end: pipe::End::Writer,
                    }
                    .encode(),
                )
                .expect("release");
            assert!(
                matches!(released, IpcReleased::Object { wake, freed: false } if wake.readers),
                "{released:?}"
            );
        }

        fn queued_on(carrier: &TestCarrier, record: RecordId) -> Option<SlotId> {
            match carrier.zone.record(record).claim() {
                carrick_sched_core::Claim::Queued { slot, .. } => Some(slot),
                _ => None,
            }
        }

        /// The peer CPU idles in the guest: the drain places the parked
        /// reader there and reschedules exactly that CPU.
        #[test]
        fn release_places_parked_reader_on_idle_guest_cpu() {
            let carrier = carrier();
            let peer = SlotId::new(1);
            carrier.zone.drive(peer, 1);
            carrier.zone.publish_slot(peer, MM, Some(1), 1 << 1);
            let here = carrick_sched_core::ExecutionSlot::zone(peer);
            carrier.zone.occupancy.vacate_any(here);
            assert!(carrier.zone.occupancy.replace(here, 0, MM));
            carrier.zone.enter_guest(peer);
            let owner = HostIpc::new(1 << 20).expect("region");
            owner
                .bind_carrier_zone(carrier.clone())
                .unwrap_or_else(|_| panic!("first binding"));
            let object = owner.create_pipe(65536).expect("pipe");
            let record = park_reader(&carrier, object);
            release_last_writer(&owner, object);
            assert_eq!(queued_on(&carrier, record), Some(peer));
            assert_eq!(*carrier.rescheds.lock(), [peer]);
        }

        /// No allowed slot has a driver yet. Held custody retains the woken
        /// reader until CPU 1 publication places it exactly once.
        #[test]
        fn release_retains_reader_no_guest_cpu_can_take() {
            let carrier = carrier();
            let owner = HostIpc::new(1 << 20).expect("region");
            owner
                .bind_carrier_zone(carrier.clone())
                .unwrap_or_else(|_| panic!("first binding"));
            let object = owner.create_pipe(65536).expect("pipe");
            let record = park_reader(&carrier, object);
            release_last_writer(&owner, object);
            assert!(matches!(
                carrier.zone.record(record).claim(),
                carrick_sched_core::Claim::Held { .. }
            ));
            assert!(queued_on(&carrier, record).is_none());
            let slot = SlotId::new(1);
            carrier.zone.drive_and_publish(
                slot,
                1,
                MM,
                Some(1),
                carrick_sched_core::AffinitySource::UNBOUND,
            );
            assert_eq!(queued_on(&carrier, record), Some(slot));
            carrier.zone.publish_slot(slot, MM, Some(1), 1 << 1);
            assert_eq!(carrier.zone.slot(slot).queued(), 1);
        }

        /// Contention is "not now": a drain that finds the lane's queue
        /// held waits for the holder's release and then delivers (Busy
        /// once, then success), never dropping the wake.
        #[test]
        fn release_waits_out_a_held_lane_then_delivers() {
            let carrier = carrier();
            let owner = HostIpc::new(1 << 20).expect("region");
            owner
                .bind_carrier_zone(carrier.clone())
                .unwrap_or_else(|_| panic!("first binding"));
            let object = owner.create_pipe(65536).expect("pipe");
            let record = park_reader(&carrier, object);
            let key = carrick_el1_abi::ipc::object_wait_key(object, pipe::WaitFor::Readable)
                .expect("lane key");
            let (held_tx, held_rx) = std::sync::mpsc::channel();
            let zone = carrier.zone;
            let holder = std::thread::spawn(move || {
                let discard = |owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
                    '_,
                    ParkedContextWords,
                >| {
                    let _ = owned.into_parts();
                };
                let guard = zone
                    .object_wait(key, &ShortLockSpin, &discard)
                    .expect("hold lane");
                held_tx.send(()).expect("held");
                std::thread::sleep(std::time::Duration::from_millis(50));
                drop(guard);
            });
            held_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("holder took the lane");
            release_last_writer(&owner, object);
            holder.join().expect("holder");
            assert!(matches!(
                carrier.zone.record(record).claim(),
                carrick_sched_core::Claim::Held { .. }
            ));
            let slot = SlotId::new(1);
            carrier.zone.drive_and_publish(
                slot,
                1,
                MM,
                Some(1),
                carrick_sched_core::AffinitySource::UNBOUND,
            );
            assert_eq!(queued_on(&carrier, record), Some(slot));
            assert_eq!(carrier.zone.slot(slot).queued(), 1);
        }

        /// #2928: the x86 ring defers an object-wake completion it could not
        /// place (the waiter's affinity excludes the waker's CPU) to the
        /// carrier's completion chain and rings only the waker's doorbell, as
        /// `carrick_el1::substrate::sched::object_wait::deliver_completion`
        /// does. The host boundary that consumes that doorbell
        /// (`settle_host_work_boundary`, the x86 executor's `WORK_PORT` step)
        /// must settle the chain: the waiter goes to Held custody, and the
        /// CPU it may run on takes it when published. Left on the chain it
        /// stays `Transferring` while both CPUs idle.
        #[test]
        fn work_boundary_settles_the_carrier_completion_chain() {
            let carrier = carrier();
            let dispatcher = crate::dispatch::SyscallDispatcher::new();
            let kernel = std::sync::Arc::clone(dispatcher.kernel_binding.read().kernel());
            let owner = kernel.ipc().expect("kernel IPC owner");
            owner
                .bind_carrier_zone(carrier.clone())
                .unwrap_or_else(|_| panic!("first binding"));
            let object = owner.create_pipe(65536).expect("pipe");
            let record = park_reader(&carrier, object);
            let key = carrick_el1_abi::ipc::object_wait_key(object, pipe::WaitFor::Readable)
                .expect("lane key");
            // The waker is the ring on CPU 0, running another process; the
            // waiter's affinity excludes CPU 0 and no executor drives CPU 1.
            let here = SlotId::new(0);
            carrier.zone.drive(here, 1);
            carrier.zone.publish_slot(here, MM + 1, Some(0), 1);
            carrier.zone.enter_guest(here);
            let waker = carrick_el1_abi::CurrentTask::new();
            let deferred = std::cell::Cell::new(false);
            let completion = |owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
                '_,
                ParkedContextWords,
            >| {
                let (_, _, chained) = owned.defer_handbacks();
                if chained {
                    deferred.set(true);
                    waker.linux.mark_pending_host_work();
                }
            };
            let queue = carrier
                .zone
                .object_wait(key, &ShortLockSpin, &completion)
                .expect("lane");
            let mut effects = carrick_sched_core::WakeEffects::default();
            queue.notify_object(here, &mut effects).expect("notify");
            drop(queue);
            // As `deliver_effects_with` does for the ring: a waiter handed
            // to the host owes the waker's boundary, its only doorbell.
            if effects.owes_host_boundary() || deferred.get() {
                waker.linux.mark_pending_host_work();
            }
            assert!(effects.handed_to_host, "{effects:?}");
            assert!(matches!(
                carrier.zone.record(record).claim(),
                carrick_sched_core::Claim::Transferring { .. }
            ));
            let doorbell = waker.linux.take_host_work_doorbell();
            assert!(doorbell.is_some());
            crate::el1_delegation::settle_host_work_boundary(&kernel, false, doorbell);
            assert!(
                matches!(
                    carrier.zone.record(record).claim(),
                    carrick_sched_core::Claim::Held { .. }
                ),
                "the boundary left the waiter {:?}",
                carrier.zone.record(record).claim()
            );
            // Held custody places it exactly once when CPU 1 is published.
            let peer = SlotId::new(1);
            carrier.zone.drive_and_publish(
                peer,
                1,
                MM,
                Some(1),
                carrick_sched_core::AffinitySource::UNBOUND,
            );
            assert_eq!(queued_on(&carrier, record), Some(peer));
        }

        /// A carrier binds its zone once; a second binding is refused.
        #[test]
        fn carrier_zone_binds_once() {
            let owner = HostIpc::new(1 << 20).expect("region");
            assert!(owner.bind_carrier_zone(carrier()).is_ok());
            assert!(owner.bind_carrier_zone(carrier()).is_err());
        }
    }

    #[test]
    fn serial_host_el1_ipc_host_subscription_lifetime_is_exact() {
        let owner = std::sync::Arc::new(HostIpc::new(1 << 20).unwrap());
        let object = owner.create_eventfd(0, pipe::EventMode::Counter).unwrap();
        let queue = owner.wait_queue(object);
        let wait = crate::kernel::WaitSet::new();
        let region = owner.region();
        let count = || {
            region
                .lock(object, &crate::el1_zone::TestRegionWait)
                .unwrap()
                .host_subscribers()
        };
        assert_eq!(count(), 0);
        let first = queue.enroll(&wait);
        let callback = queue.enroll_callback(|_| {});
        assert_eq!(count(), 2);
        drop(first);
        assert_eq!(count(), 1);
        drop(callback);
        assert_eq!(count(), 0);
        let mut guard = region
            .lock(object, &crate::el1_zone::TestRegionWait)
            .unwrap();
        let step = guard.eventfd().unwrap().try_write(1);
        assert!(!guard.publish(step.wake).host_owed);
        drop(guard);
        assert!(!region.take_host_wake(object));
        owner
            .release(IpcBacking::EventFd { object }.encode())
            .unwrap();
    }

    /// Publish one owed host wake on `object` (a host subscriber exists).
    fn publish_owed(owner: &HostIpc, object: IpcObjectHandle) {
        let region = owner.region();
        let mut guard = region
            .lock(object, &crate::el1_zone::TestRegionWait)
            .unwrap();
        let step = guard.eventfd().unwrap().try_write(1);
        assert!(guard.publish(step.wake).host_owed);
    }

    fn indexed(owner: &HostIpc) -> Vec<IpcObjectHandle> {
        let mut candidates = Vec::new();
        owner
            .region()
            .drain_host_wake_candidates(|candidate| candidates.push(candidate));
        candidates
    }

    /// An owed host wake whose object has no live delivery target (none
    /// registered for this incarnation, or its queue is gone) is never
    /// consumed: it stays owed and indexed for the boundary after a target
    /// exists, and the region counts it (a count that must stay zero).
    #[test]
    fn serial_host_el1_ipc_owed_host_wake_survives_a_missing_target() {
        for dead_queue in [false, true] {
            let owner = std::sync::Arc::new(HostIpc::new(1 << 20).unwrap());
            let object = owner.create_eventfd(0, pipe::EventMode::Counter).unwrap();
            if dead_queue {
                drop(owner.wait_queue(object));
            }
            let subscription = owner.subscribe_host(object).unwrap();
            publish_owed(&owner, object);
            assert_eq!(indexed(&owner), [object]);
            assert!(!owner.service_host_wake(object), "no target to deliver to");
            assert_eq!(
                indexed(&owner),
                [object],
                "the undelivered wake stays indexed (dead_queue={dead_queue})"
            );
            assert_eq!(owner.region().owed_host_wakes_without_target(), 1);
            let mut census = String::new();
            owner.region().write_host_wake_census(&mut census).unwrap();
            assert!(
                census.starts_with("ipc host-wake index: owed_without_target=1 "),
                "{census}"
            );
            let queue = owner.wait_queue(object);
            let woken = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counted = std::sync::Arc::clone(&woken);
            let enrollment = queue.enroll_callback(move |_| {
                counted.fetch_add(1, Ordering::SeqCst);
            });
            assert!(owner.service_host_wake(object), "the target receives it");
            assert_eq!(woken.load(Ordering::SeqCst), 1);
            assert!(!owner.service_host_wake(object), "delivered exactly once");
            assert_eq!(owner.region().owed_host_wakes_without_target(), 1);
            drop(enrollment);
            drop(subscription);
            owner
                .release(IpcBacking::EventFd { object }.encode())
                .unwrap();
        }
    }

    #[test]
    fn serial_host_el1_ipc_pool_reuses_released_storage() {
        let owner = HostIpc::new(1 << 20).expect("region");
        for _ in 0..2048 {
            let object = owner.create_pipe(65536).expect("pipe");
            owner
                .ensure_pipe_storage(object)
                .expect("first write's ring");
            let region = owner.region();
            let mut guard = region
                .lock(object, &crate::el1_zone::TestRegionWait)
                .expect("object");
            assert_eq!(guard.pipe().unwrap().try_write(b"shared").result, Ok(6));
            drop(guard);
            let attached = unsafe {
                IpcRegion::attach(
                    owner.directory_ptr(),
                    owner.directory_len(),
                    owner.pool_ptr(),
                    owner.pool_len(),
                )
            }
            .expect("second venue");
            let mut bytes = [0; 6];
            let mut guard = attached
                .lock(object, &crate::el1_zone::TestRegionWait)
                .unwrap();
            assert_eq!(guard.pipe().unwrap().try_read(&mut bytes).result, Ok(6));
            assert_eq!(&bytes, b"shared");
            drop(guard);
            for end in [pipe::End::Reader, pipe::End::Writer] {
                owner
                    .release(IpcBacking::Pipe { object, end }.encode())
                    .unwrap();
            }
            assert!(matches!(
                region.lock(object, &crate::el1_zone::TestRegionWait),
                Err(IpcError::Stale)
            ));
        }
        // 2048 pipes ran in a ring area of four 128 KiB blocks: the freed
        // record's ring and the stock are reused, never one ring per pipe.
        assert!(owner.region().pipe_allocations() <= 4);
    }

    #[test]
    fn serial_host_el1_ipc_descriptor_admission_reclaims_extents() {
        let owner = HostIpc::new(1 << 20).unwrap();
        let table = owner.create_table(4096, 4).unwrap();
        owner.ensure_capacity(table, 2048).unwrap();
        let region = owner.region();
        let authority = region.fd(crate::el1_zone::TestRegionWait);
        let object = owner.create_eventfd(7, pipe::EventMode::Counter).unwrap();
        let desc = fd::Description::new(
            IpcBacking::EventFd { object }.encode(),
            fd::AccessMode::ReadWrite,
            fd::StatusFlags::default(),
        );
        let pin = authority.create_pinned(desc).unwrap();
        authority
            .install_pin(table, fd::Fd(2047), &pin, false)
            .unwrap();
        assert_eq!(authority.unpin(pin).unwrap(), None);
        let extent = authority
            .destroy_table(table, |description| {
                assert_eq!(description, desc);
            })
            .unwrap();
        owner.release(desc.backing).unwrap();
        owner.reclaim_descriptors(extent).unwrap();
        assert_eq!(owner.region().descriptor_allocations(), 0);
    }

    /// Creating a pipe takes no pool storage (Linux allocates pipe pages on
    /// demand): an exhausted pool refuses only the first write's ring, with
    /// nothing allocated and the pipe intact.
    #[test]
    fn serial_host_el1_ipc_pool_refusal_has_no_partial_admission() {
        let owner = HostIpc::new(8192).unwrap();
        let pipe = owner.create_pipe(65536).unwrap();
        assert_eq!(
            owner.ensure_pipe_storage(pipe),
            Err(AdmissionError::NoMemory)
        );
        assert!(owner.region().pipe_allocations() == 0);
        let region = owner.region();
        let mut guard = region.lock(pipe, &crate::el1_zone::TestRegionWait).unwrap();
        assert!(!guard.pipe().unwrap().is_backed());
        drop(guard);
        for end in [pipe::End::Reader, pipe::End::Writer] {
            owner
                .release(IpcBacking::Pipe { object: pipe, end }.encode())
                .unwrap();
        }
        let object = owner.create_eventfd(0, pipe::EventMode::Counter).unwrap();
        owner
            .release(IpcBacking::EventFd { object }.encode())
            .unwrap();
    }

    /// An idle pipe costs its record only: 4096 idle pipes claim no more
    /// pool than the bounded ring stock (one ring per creation until it is
    /// full). A first write takes a stocked ring (a second provision finds it
    /// and takes nothing; the stock is refilled by one), and F_SETPIPE_SZ on
    /// an unbacked pipe only records the capacity its first write then sizes.
    #[test]
    fn serial_host_el1_ipc_rings_are_provided_at_first_write() {
        use carrick_el1_abi::ipc::IPC_RING_STOCK;
        let owner = HostIpc::new(1 << 28).unwrap();
        let pipes: Vec<_> = (0..4096)
            .map(|_| owner.create_pipe(65536).unwrap())
            .collect();
        let allocated = || owner.region().pipe_allocations();
        assert_eq!(allocated(), IPC_RING_STOCK, "idle pipes: the stock only");
        let first = pipes[4000];
        owner.ensure_pipe_storage(first).unwrap();
        assert_eq!(allocated(), IPC_RING_STOCK, "taken from the stock");
        owner.ensure_pipe_storage(first).unwrap();
        assert_eq!(allocated(), IPC_RING_STOCK + 1, "stock refilled by one");
        let second = pipes[7];
        assert_eq!(owner.resize_pipe(second, 1 << 20, 1 << 20), Ok(1 << 20));
        assert_eq!(allocated(), IPC_RING_STOCK + 1, "resize takes no ring");
        owner.ensure_pipe_storage(second).unwrap();
        assert_eq!(allocated(), IPC_RING_STOCK + 2, "sized past a stock ring");
        let region = owner.region();
        let mut guard = region
            .lock(second, &crate::el1_zone::TestRegionWait)
            .unwrap();
        let mut ring = guard.pipe().unwrap();
        assert_eq!((ring.capacity(), ring.is_backed()), (1 << 20, true));
        assert_eq!(ring.try_write(&[7; 70_000]).result, Ok(70_000));
        drop(guard);
        for object in pipes {
            for end in [pipe::End::Reader, pipe::End::Writer] {
                owner
                    .release(IpcBacking::Pipe { object, end }.encode())
                    .unwrap();
            }
        }
    }

    /// Every pipe the host created since the last writes can take its first
    /// ring in EL1 (the `el1_ipc_pairs_blocking` shape: 128 pipes created,
    /// then each written from the guest): creation stocks one ring per pipe,
    /// so no first write needs a host exit while the stock covers them.
    #[test]
    fn serial_host_el1_ipc_each_created_pipe_can_take_a_stocked_ring() {
        let owner = HostIpc::new(1 << 27).unwrap();
        let pipes: Vec<_> = (0..128)
            .map(|_| owner.create_pipe(65536).unwrap())
            .collect();
        let region = owner.region();
        for object in &pipes {
            // What EL1's first write does under the object lock.
            let mut guard = region
                .lock(*object, &crate::el1_zone::TestRegionWait)
                .unwrap();
            assert_eq!(guard.provide_ring_from_stock(), Ok(true));
        }
        assert_eq!(owner.region().pipe_allocations(), 128, "one ring per pipe");
        for object in pipes {
            for end in [pipe::End::Reader, pipe::End::Writer] {
                owner
                    .release(IpcBacking::Pipe { object, end }.encode())
                    .unwrap();
            }
        }
    }
}
