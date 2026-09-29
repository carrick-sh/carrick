//! Kernel-owned storage for the shared host/EL1 IPC authority.

mod table;
pub use table::HostTable;

use std::collections::{BTreeMap, BTreeSet};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};

use carrick_el1_abi::ipc::{
    HostResourceToken, IPC_POOL_ALIGN, IpcDirectory, IpcError, IpcObjectHandle, IpcPipeStorage,
    IpcRegion, IpcReleased, descriptor_extent_bytes, fd, pipe,
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

/// Buddy allocator for admission only. At most log2(pool pages) split/merge
/// steps; transfer paths never enter it. Allocated offsets authenticate frees.
struct Pool {
    free: Vec<BTreeSet<u64>>,
    allocated: BTreeMap<u64, usize>,
}
impl Pool {
    fn new(bytes: usize) -> Self {
        let order = (bytes / IPC_POOL_ALIGN as usize).ilog2() as usize;
        let mut free = vec![BTreeSet::new(); order + 1];
        free[order].insert(0);
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
    pool: Mutex<Pool>,
    resources: Mutex<HostResources>,
    host_wakes: Mutex<Vec<Option<HostWakeEntry>>>,
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
    pub const DEFAULT_POOL_BYTES: usize = 128 * 1024 * 1024;

    pub fn new(pool_bytes: usize) -> Result<Self, AdmissionError> {
        if pool_bytes < IPC_POOL_ALIGN as usize || !pool_bytes.is_power_of_two() {
            return Err(AdmissionError::NoMemory);
        }
        let owner = Self {
            directory: Mapping::new(std::mem::size_of::<IpcDirectory>())?,
            bytes: Mapping::new(pool_bytes)?,
            pool: Mutex::new(Pool::new(pool_bytes)),
            host_wakes: Mutex::new(
                (0..carrick_el1_abi::ipc::IPC_OBJECTS)
                    .map(|_| None)
                    .collect(),
            ),
            resources: Mutex::new(HostResources {
                next: 1,
                live: BTreeMap::new(),
            }),
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
                owner.pool_ptr(),
                pool_bytes,
                identity,
            )?;
        }
        Ok(owner)
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
        self.host_wakes.lock()[object.index() as usize] = Some(HostWakeEntry {
            object,
            target: HostWakeTarget::Queue(std::sync::Arc::downgrade(&queue)),
        });
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
        self.host_wakes.lock()[object.index() as usize] = Some(HostWakeEntry {
            object,
            target: HostWakeTarget::Publisher {
                wake: std::sync::Arc::downgrade(publisher),
                prime: std::sync::Arc::downgrade(primer),
            },
        });
    }
    /// Deliver guest-produced readiness work by exact object incarnation.
    /// Runtime calls this after returning from EL1; it never scans the pool.
    pub fn service_host_wake(&self, object: IpcObjectHandle) -> bool {
        // Authenticate and consume under the object lock: a recycled slot
        // cannot lose its successor's wake between generation check and swap.
        let region = self.region();
        let Ok(guard) = region.lock(object, &HostLockWait) else {
            return false;
        };
        let owed = region.take_host_wake(object);
        drop(guard);
        if !owed {
            return false;
        }
        let (queue, publisher) = {
            let wakes = self.host_wakes.lock();
            let Some(entry) = wakes
                .get(object.index() as usize)
                .and_then(Option::as_ref)
                .filter(|entry| entry.object == object)
            else {
                return false;
            };
            match &entry.target {
                HostWakeTarget::Queue(queue) => (queue.upgrade(), None),
                HostWakeTarget::Publisher { wake, .. } => (None, wake.upgrade()),
            }
        };
        if let Some(queue) = queue {
            queue.wake_all();
            return true;
        }
        if let Some(publisher) = publisher {
            publisher();
            return true;
        }
        false
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
        unsafe { IpcRegion::attach(self.directory_ptr(), self.pool_ptr(), self.pool_len()) }
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
        storage.offset = self.pool.lock().allocate(storage.footprint())?;
        Ok(storage)
    }
    pub fn create_pipe(&self, capacity: usize) -> Result<IpcObjectHandle, AdmissionError> {
        let region = self.region();
        let mut storage = None;
        match region.create_pipe(capacity, &mut storage, &HostLockWait) {
            Ok(object) => {
                self.bind_waits(object);
                return Ok(object);
            }
            Err(IpcError::NeedsStorage { ring_bytes, pages }) => {
                storage = Some(self.provision_pipe(ring_bytes, pages)?);
            }
            Err(error) => return Err(error.into()),
        }
        // Provisioning happens after create_pipe released its object lock.
        let result = region.create_pipe(capacity, &mut storage, &HostLockWait);
        if let Some(retired_or_unused) = storage {
            self.pool.lock().release(retired_or_unused.offset);
        }
        let object = result?;
        self.bind_waits(object);
        Ok(object)
    }
    pub fn create_eventfd(
        &self,
        initial: u32,
        mode: pipe::EventMode,
    ) -> Result<IpcObjectHandle, AdmissionError> {
        let object = self.region().create_eventfd(initial, mode, &HostLockWait)?;
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
        let current = region.lock(object, &HostLockWait)?.pipe()?.capacity();
        let rounded = pipe::Pipe::rounded_capacity(4096, requested).map_err(IpcError::Object)?;
        if rounded > current && rounded > limit {
            return Err(IpcError::Object(pipe::Error::Permission).into());
        }
        let mut replacement = if rounded > current {
            Some(self.provision_pipe(rounded as u64, (rounded / 4096) as u64)?)
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
        if let Some(storage) = replacement {
            self.pool.lock().release(storage.offset);
        }
        result.map_err(Into::into)
    }
    fn provision_descriptors(&self, capacity: usize) -> Result<fd::Extent, AdmissionError> {
        if capacity == 0 || capacity > i32::MAX as usize {
            return Err(AdmissionError::NoMemory);
        }
        let token = self
            .pool
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
    ) -> Result<HostDescription, fd::Error> {
        let pin = self.region().fd(HostLockWait).create_pinned(description)?;
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
        self.pool.lock().release(extent.token);
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
            if wake.host_owed {
                self.service_host_wake(wake.object);
            }
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

    #[test]
    fn serial_host_el1_ipc_pool_reuses_released_storage() {
        let owner = HostIpc::new(1 << 20).expect("region");
        for _ in 0..2048 {
            let object = owner.create_pipe(65536).expect("pipe");
            let region = owner.region();
            let mut guard = region.lock(object, &HostLockWait).expect("object");
            assert_eq!(guard.pipe().unwrap().try_write(b"shared").result, Ok(6));
            drop(guard);
            let attached = unsafe {
                IpcRegion::attach(owner.directory_ptr(), owner.pool_ptr(), owner.pool_len())
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
        assert_eq!(owner.pool.lock().allocated.len(), 1);
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
        assert!(owner.pool.lock().allocated.is_empty());
    }

    #[test]
    fn serial_host_el1_ipc_pool_refusal_has_no_partial_admission() {
        let owner = HostIpc::new(4096).unwrap();
        assert!(owner.create_pipe(65536).is_err());
        assert!(owner.pool.lock().allocated.is_empty());
        let object = owner.create_eventfd(0, pipe::EventMode::Counter).unwrap();
        owner
            .release(IpcBacking::EventFd { object }.encode())
            .unwrap();
    }
}
