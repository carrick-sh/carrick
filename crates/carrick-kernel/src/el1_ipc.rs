//! Kernel-owned storage for the shared host/EL1 IPC authority.

mod table;
pub use table::HostTable;

use std::collections::{BTreeMap, BTreeSet};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};

use carrick_el1_abi::ipc::{
    HostResourceToken, IPC_DIRECTORY_BYTES, IPC_MAX_OBJECTS, IPC_MAX_OFDS, IPC_OBJECT_SEGMENT,
    IPC_OFD_SEGMENT, IPC_PIPE_PAGE_SIZE, IPC_POOL_ALIGN, IPC_POOL_AREAS, IPC_STOCK_RING_BYTES,
    IpcDirectory, IpcError, IpcObjectHandle, IpcPipeStorage, IpcRegion, IpcReleased, IpcWake,
    descriptor_extent_bytes, fd, ipc_descriptor_area, ipc_ring_area, pipe,
};
use parking_lot::Mutex;

use crate::el1_zone::HostLockWait;

static NEXT_REGION: AtomicU64 = AtomicU64::new(1);

/// Admission failure, before any descriptor or host reservation is published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    NoMemory,
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
            error @ (AdmissionError::NoMemory | AdmissionError::Shared(_)) => {
                carrick_fatal::carrick_fatal!(
                    "ipc::admission",
                    "object creation refused outside the zone limit: {error:?}"
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

/// Buddy allocator for admission only, over one area of the pool: `bytes`
/// (a power of two) starting at `base` (a multiple of `bytes`). At most
/// log2(area pages) split/merge steps; transfer paths never enter it.
/// Allocated offsets authenticate frees.
struct Pool {
    free: Vec<BTreeSet<u64>>,
    allocated: BTreeMap<u64, usize>,
}
impl Pool {
    fn new(base: u64, bytes: usize) -> Self {
        let order = (bytes / IPC_POOL_ALIGN as usize).ilog2() as usize;
        let mut free = vec![BTreeSet::new(); order + 1];
        free[order].insert(base);
        Self {
            free,
            allocated: BTreeMap::new(),
        }
    }
    fn allocate(&mut self, bytes: u64) -> Result<u64, AdmissionError> {
        let pages = bytes.max(1).div_ceil(IPC_POOL_ALIGN);
        let size = pages
            .checked_next_power_of_two()
            .ok_or(AdmissionError::NoMemory)?;
        let order = size.ilog2() as usize;
        let available = (order..self.free.len())
            .find(|&i| !self.free[i].is_empty())
            .ok_or(AdmissionError::NoMemory)?;
        let offset = self.free[available]
            .pop_first()
            .ok_or(AdmissionError::NoMemory)?;
        for split in (order..available).rev() {
            self.free[split].insert(offset + (IPC_POOL_ALIGN << split));
        }
        self.allocated.insert(offset, order);
        Ok(offset)
    }
    fn release(&mut self, mut offset: u64) {
        let Some(mut order) = self.allocated.remove(&offset) else {
            return;
        };
        while order + 1 < self.free.len() {
            let buddy = offset ^ (IPC_POOL_ALIGN << order);
            if !self.free[order].remove(&buddy) {
                break;
            }
            offset = offset.min(buddy);
            order += 1;
        }
        self.free[order].insert(offset);
    }
}

/// Zone-wide ceilings of the authority's elastic stores: the zone's file
/// table limit (`fs.file-max`). Past them creation is ENFILE. Each store
/// grows a whole segment at a time, so a ceiling is effective rounded down
/// to its segment (never below the first segment, published at creation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpcLimits {
    /// Pipe and eventfd objects.
    pub objects: usize,
    /// Open file descriptions (pipe/eventfd ends and published host fds).
    pub descriptions: usize,
}
impl IpcLimits {
    /// The ABI's reservation: the largest zone the window can hold.
    pub const ZONE: Self = Self {
        objects: IPC_MAX_OBJECTS,
        descriptions: IPC_MAX_OFDS,
    };
}

/// Records the authority has published by growing its stores (never
/// shrinks): the elastic-store work receipt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpcGrowth {
    pub object_records: usize,
    pub description_records: usize,
}

struct HostResources {
    next: u64,
    live: BTreeMap<u64, Box<dyn Send + Sync>>,
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
            .unsubscribe_host(self.object, &HostLockWait);
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
                .fd(HostLockWait)
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

    pub(crate) fn set_linux_flags(&self, value: u64) {
        let state = self.state.lock();
        let HostDescriptionState::Live(pin) = &*state else {
            // A retired host observation has no mutation authority.
            return;
        };
        let region = self.owner.region();
        let authority = region.fd(HostLockWait);
        let mut flags = authority
            .pinned(pin)
            .unwrap_or_else(|_| {
                carrick_fatal::carrick_fatal!("ipc::description", "invalid flag mutation")
            })
            .flags;
        flags.append = value & carrick_abi::LINUX_O_APPEND != 0;
        flags.nonblock = value & carrick_abi::LINUX_O_NONBLOCK != 0;
        flags.asynchronous = value & carrick_abi::LINUX_O_ASYNC != 0;
        authority.set_pinned_flags(pin, flags).unwrap_or_else(|_| {
            carrick_fatal::carrick_fatal!("ipc::description", "shared flag mutation rejected")
        });
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
            .fd(HostLockWait)
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
            let region = self.flags.owner.region();
            let authority = region.fd(HostLockWait);
            let terminal = authority.pinned(pin).unwrap_or_else(|_| {
                carrick_fatal::carrick_fatal!("ipc::description", "invalid closing description")
            });
            let HostDescriptionState::Live(pin) =
                std::mem::replace(&mut *state, HostDescriptionState::Retired(terminal))
            else {
                carrick_fatal::carrick_fatal!("ipc::description", "description retired twice")
            };
            authority.unpin(pin).unwrap_or_else(|_| {
                carrick_fatal::carrick_fatal!("ipc::description", "invalid owned description pin")
            })
        };
        // Backing release can call host readiness callbacks: leave the
        // description lock before delivering them.
        if let Some(description) = description {
            self.flags
                .owner
                .release(description.backing)
                .unwrap_or_else(|_| {
                    carrick_fatal::carrick_fatal!(
                        "ipc::description",
                        "invalid final description backing"
                    )
                });
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
    /// The pool's two type-stable areas ([`ipc_ring_area`],
    /// [`ipc_descriptor_area`]), each allocated only for its own kind: a
    /// descriptor extent retired while a lock-free EL1 or host lookup still
    /// reads it is only ever reused as another extent (atomic words), never
    /// as ring bytes, and the pool memory lives as long as this owner (every
    /// view borrows it; the carrier retains the owner while it maps it).
    rings: Mutex<Pool>,
    descriptors: Mutex<Pool>,
    resources: Mutex<HostResources>,
    /// Host wake targets by object index, sized to the highest index used.
    host_wakes: Mutex<Vec<Option<HostWakeEntry>>>,
    limits: IpcLimits,
    /// Serializes store growth (the one growth venue) and counts its work.
    growth: Mutex<IpcGrowth>,
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
            rings: Mutex::new(Pool::new(
                ipc_ring_area(pool_bytes as u64).start,
                pool_bytes / IPC_POOL_AREAS as usize,
            )),
            descriptors: Mutex::new(Pool::new(
                ipc_descriptor_area(pool_bytes as u64).start,
                pool_bytes / IPC_POOL_AREAS as usize,
            )),
            host_wakes: Mutex::new(Vec::new()),
            resources: Mutex::new(HostResources {
                next: 1,
                live: BTreeMap::new(),
            }),
            limits,
            growth: Mutex::new(IpcGrowth::default()),
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
        let region = self.region();
        let count = region.object_count();
        if count != seen {
            return Ok(());
        }
        if count + IPC_OBJECT_SEGMENT > self.limits.objects {
            return Err(IpcError::ZoneLimit.into());
        }
        growth.object_records += region.grow_objects()?;
        Ok(())
    }

    /// As [`HostIpc::grow_objects`], for open file descriptions.
    fn grow_descriptions(&self, seen: usize) -> Result<(), AdmissionError> {
        let mut growth = self.growth.lock();
        let region = self.region();
        let count = region.ofd_count();
        if count != seen {
            return Ok(());
        }
        if count + IPC_OFD_SEGMENT > self.limits.descriptions {
            return Err(IpcError::ZoneLimit.into());
        }
        growth.description_records += region.grow_ofds()?;
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
    pub(crate) fn subscribe_host(
        self: &std::sync::Arc<Self>,
        object: IpcObjectHandle,
    ) -> Result<std::sync::Arc<HostSubscription>, IpcError> {
        self.region().subscribe_host(object, &HostLockWait)?;
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
        let Ok(mut guard) = region.lock(object, &HostLockWait) else {
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
    }

    fn bind_waits(&self, object: IpcObjectHandle) {
        if let Some(zone) = crate::el1_zone::zone() {
            for direction in [pipe::WaitFor::Readable, pipe::WaitFor::Writable] {
                if let Some(key) = carrick_el1_abi::ipc::object_wait_key(object, direction) {
                    zone.bind_object_wait(key, &HostLockWait)
                        .unwrap_or_else(|_| {
                            carrick_fatal::carrick_fatal!(
                                "ipc::admission",
                                "object wait generation collision"
                            )
                        });
                }
            }
        }
    }
    fn provision_pipe(
        &self,
        ring_bytes: u64,
        pages: u64,
    ) -> Result<IpcPipeStorage, AdmissionError> {
        let mut storage = IpcPipeStorage {
            offset: 0,
            ring_bytes,
            pages,
        };
        storage.offset = self.rings.lock().allocate(storage.footprint())?;
        Ok(storage)
    }
    /// A new pipe costs its object record only: its ring is provided at its
    /// first write ([`HostIpc::ensure_pipe_storage`]), as Linux allocates
    /// pipe pages on demand.
    pub fn create_pipe(&self, capacity: usize) -> Result<IpcObjectHandle, AdmissionError> {
        let mut retired = None;
        let object =
            self.with_object(|region| region.create_pipe(capacity, &mut retired, &HostLockWait));
        // A reused record's too-small ring, detached after the object lock.
        if let Some(retired) = retired {
            self.rings.lock().release(retired.offset);
        }
        let object = object?;
        self.bind_waits(object);
        self.top_up_ring_stock();
        Ok(object)
    }

    /// Add one default-capacity ring to the shared stock if it has room: one
    /// ring per pipe created keeps a fresh pipe's first write in EL1 (no host
    /// exit) for up to [`carrick_el1_abi::ipc::IPC_RING_STOCK`] pipes created between writes. The
    /// stock bounds the pool address space idle pipes can claim, so a zone
    /// of many idle pipes still costs records only. A refused provision
    /// only means later first writes take the host path.
    fn top_up_ring_stock(&self) {
        let region = self.region();
        if !region.ring_stock_has_room() {
            return;
        }
        let Ok(ring) = self.provision_pipe(
            IPC_STOCK_RING_BYTES,
            IPC_STOCK_RING_BYTES / IPC_PIPE_PAGE_SIZE as u64,
        ) else {
            return;
        };
        if let Err(ring) = region.stock_ring(ring) {
            self.rings.lock().release(ring.offset);
        }
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
        let region = self.region();
        loop {
            // The same stocked ring an EL1 first write takes; the stock is
            // refilled first. Only a pipe resized past the default capacity,
            // or an empty stock the pool cannot refill, is sized here.
            self.top_up_ring_stock();
            let capacity = {
                let mut guard = region.lock(object, &HostLockWait)?;
                if guard.provide_ring_from_stock()? {
                    return Ok(());
                }
                let pipe = guard.pipe()?;
                if pipe.is_backed() {
                    return Ok(());
                }
                pipe.capacity()
            };
            let mut storage =
                self.provision_pipe(capacity as u64, (capacity / IPC_PIPE_PAGE_SIZE) as u64)?;
            let installed = region
                .lock(object, &HostLockWait)
                .and_then(|mut guard| guard.provide_pipe_storage(&mut storage));
            if storage != IpcPipeStorage::default() {
                self.rings.lock().release(storage.offset);
            }
            match installed {
                Ok(_) => return Ok(()),
                // F_SETPIPE_SZ grew the capacity meanwhile: size it again.
                Err(IpcError::Object(pipe::Error::Storage)) => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }
    pub fn create_eventfd(
        &self,
        initial: u32,
        mode: pipe::EventMode,
    ) -> Result<IpcObjectHandle, AdmissionError> {
        let object =
            self.with_object(|region| region.create_eventfd(initial, mode, &HostLockWait))?;
        self.bind_waits(object);
        Ok(object)
    }

    /// A zone epoll record ([`carrick_el1_abi::ipc::epoll`]) with an empty
    /// interest list. Its `Readable` wait key is bound like an object's.
    pub fn create_epoll(&self) -> Result<IpcObjectHandle, AdmissionError> {
        let object = self.with_object(|region| region.create_epoll(&HostLockWait))?;
        self.bind_waits(object);
        Ok(object)
    }

    pub(crate) fn resize_pipe(
        &self,
        object: IpcObjectHandle,
        requested: usize,
        limit: usize,
    ) -> Result<usize, AdmissionError> {
        let region = self.region();
        loop {
            let (current, backed) = {
                let mut guard = region.lock(object, &HostLockWait)?;
                let pipe = guard.pipe()?;
                (pipe.capacity(), pipe.is_backed())
            };
            let rounded = pipe::Pipe::rounded_capacity(IPC_PIPE_PAGE_SIZE, requested)
                .map_err(IpcError::Object)?;
            if rounded > current && rounded > limit {
                return Err(IpcError::Object(pipe::Error::Permission).into());
            }
            // An unbacked pipe only records its capacity; its first write
            // sizes the ring.
            let mut replacement = if rounded > current && backed {
                Some(self.provision_pipe(rounded as u64, (rounded / IPC_PIPE_PAGE_SIZE) as u64)?)
            } else {
                None
            };
            let result = (|| {
                let mut guard = region.lock(object, &HostLockWait)?;
                if let Some(storage) = &mut replacement {
                    guard.replace_pipe_storage(storage)?;
                }
                let step = guard.pipe()?.set_capacity(requested, limit);
                let mut delivery = crate::el1_zone::ObjectWakeDelivery::new();
                delivery.collect(guard.publish(step.wake));
                drop(guard);
                delivery.deliver();
                step.result.map_err(IpcError::Object)
            })();
            let without_ring = replacement.is_none();
            if let Some(storage) = replacement {
                self.rings.lock().release(storage.offset);
            }
            match result {
                // A first write gave the pipe its ring (for the old capacity)
                // between the sample and the lock: size it again.
                Err(IpcError::Object(pipe::Error::Storage)) if without_ring => continue,
                result => return result.map_err(Into::into),
            }
        }
    }
    fn provision_descriptors(&self, capacity: usize) -> Result<fd::Extent, AdmissionError> {
        if capacity == 0 || capacity > i32::MAX as usize {
            return Err(AdmissionError::NoMemory);
        }
        let token = self
            .descriptors
            .lock()
            .allocate(descriptor_extent_bytes(capacity))?;
        Ok(fd::Extent {
            token,
            capacity: capacity as u64,
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
            match region.fd(HostLockWait).create_pinned(description) {
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

    pub fn create_table(
        &self,
        limit: usize,
        capacity: usize,
    ) -> Result<fd::TableId, AdmissionError> {
        let mut storage = self.provision_descriptors(capacity)?;
        let result = self
            .region()
            .fd(HostLockWait)
            .create_table(limit, &mut storage);
        if result.is_err() {
            self.reclaim_descriptors(storage);
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
            .fd(HostLockWait)
            .grow_table(table, &mut storage);
        self.reclaim_descriptors(storage);
        result.map_err(Into::into)
    }
    /// Reclaim only an extent returned by this region's destroy/grow operation.
    pub(crate) fn reclaim_descriptors(&self, extent: fd::Extent) {
        self.descriptors.lock().release(extent.token);
    }
    pub fn retain_host_resource(
        &self,
        resource: Box<dyn Send + Sync>,
    ) -> Result<HostResourceToken, AdmissionError> {
        let mut resources = self.resources.lock();
        let token = HostResourceToken::new(resources.next).ok_or(AdmissionError::NoMemory)?;
        resources.next += 1;
        resources.live.insert(token.get(), resource);
        Ok(token)
    }
    /// Final-description release, after leaving the descriptor table lock.
    /// Delivers guest and host wakes after leaving object locks.
    pub fn release(&self, backing: fd::BackingToken) -> Result<IpcReleased, IpcError> {
        let released = self.region().release_backing(backing, &HostLockWait)?;
        if let IpcReleased::Object { wake, freed: false } = released {
            let region = self.region();
            if let Ok(guard) = region.lock(wake.object, &HostLockWait) {
                let mut delivery = crate::el1_zone::ObjectWakeDelivery::new();
                delivery.collect(wake);
                drop(guard);
                delivery.deliver();
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1_abi::ipc::{IpcBacking, fd, pipe};

    #[test]
    fn serial_host_el1_ipc_host_subscription_lifetime_is_exact() {
        let owner = std::sync::Arc::new(HostIpc::new(1 << 20).unwrap());
        let object = owner.create_eventfd(0, pipe::EventMode::Counter).unwrap();
        let queue = owner.wait_queue(object);
        let wait = crate::kernel::WaitSet::new();
        let region = owner.region();
        let count = || {
            region
                .lock(object, &HostLockWait)
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
        let mut guard = region.lock(object, &HostLockWait).unwrap();
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
        let mut guard = region.lock(object, &HostLockWait).unwrap();
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
            let mut guard = region.lock(object, &HostLockWait).expect("object");
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
            let mut guard = attached.lock(object, &HostLockWait).unwrap();
            assert_eq!(guard.pipe().unwrap().try_read(&mut bytes).result, Ok(6));
            assert_eq!(&bytes, b"shared");
            drop(guard);
            for end in [pipe::End::Reader, pipe::End::Writer] {
                owner
                    .release(IpcBacking::Pipe { object, end }.encode())
                    .unwrap();
            }
            assert!(matches!(
                region.lock(object, &HostLockWait),
                Err(IpcError::Stale)
            ));
        }
        // 2048 pipes ran in a ring area of four 128 KiB blocks: the freed
        // record's ring and the stock are reused, never one ring per pipe.
        assert!(owner.rings.lock().allocated.len() <= 4);
    }

    #[test]
    fn serial_host_el1_ipc_descriptor_admission_reclaims_extents() {
        let owner = HostIpc::new(1 << 20).unwrap();
        let table = owner.create_table(4096, 4).unwrap();
        owner.ensure_capacity(table, 2048).unwrap();
        let region = owner.region();
        let authority = region.fd(HostLockWait);
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
        owner.reclaim_descriptors(extent);
        assert!(owner.descriptors.lock().allocated.is_empty());
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
        assert!(owner.rings.lock().allocated.is_empty());
        let region = owner.region();
        let mut guard = region.lock(pipe, &HostLockWait).unwrap();
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
        let allocated = || owner.rings.lock().allocated.len();
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
        let mut guard = region.lock(second, &HostLockWait).unwrap();
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
            let mut guard = region.lock(*object, &HostLockWait).unwrap();
            assert_eq!(guard.provide_ring_from_stock(), Ok(true));
        }
        assert_eq!(owner.rings.lock().allocated.len(), 128, "one ring per pipe");
        for object in pipes {
            for end in [pipe::End::Reader, pipe::End::Writer] {
                owner
                    .release(IpcBacking::Pipe { object, end }.encode())
                    .unwrap();
            }
        }
    }
}
