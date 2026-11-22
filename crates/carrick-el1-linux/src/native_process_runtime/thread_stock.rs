//! Native graph adapter for the shared thread-birth stock owner.
use super::*;
use carrick_core::lifecycle::stock::{
    DEFAULT_THREAD_POOL_DEPTH, PoolControls, StockAdmission, StockEntries, ThreadStock,
};
use carrick_el1_abi::{THREAD_POOL_SEGMENT_ENTRIES, ThreadLifecycleSegment};

/// Consecutive segment allocations the metadata owner may miss before a
/// clone answers ENOMEM. A miss posts the grant request and the clone waits
/// one carrier round for it; a host that keeps refusing must not become an
/// endless wait.
const SEGMENT_GRANT_ROUNDS: u8 = 4;

/// Every pool entry's thread control: the loaned slab for the lifecycle
/// page's own entries, the segment's own controls past them.
#[derive(::core::clone::Clone, ::core::marker::Copy)]
pub(super) struct PoolSlots<'a> {
    page: &'a ThreadLifecyclePage,
    head: &'a [ThreadControlSlot],
}
impl PoolControls<ThreadControlSlot> for PoolSlots<'_> {
    fn pool_control(&self, index: usize) -> Option<&ThreadControlSlot> {
        self.page.pool_control(self.head, index)
    }
}

pub(super) struct NativeThreadStock<'a, C: ProcessContext> {
    controls: PoolSlots<'a>,
    identities: StockEntries<StockIdentity<'a>>,
    waiters: Vec<carrick_el1_abi::RecordRef>,
    release: Arc<ControlRelease<'a, C>>,
    namespace_exhausted: bool,
    /// The last refill needed a segment and the metadata owner had none.
    segment_missed: bool,
    segment_misses: u8,
}

#[cfg(test)]
std::thread_local! {
    /// Segment allocations to refuse, as a metadata capacity miss does.
    pub(crate) static INJECT_SEGMENT_MISSES: core::cell::Cell<u32> =
        const { core::cell::Cell::new(0) };
}

fn allocate_segment() -> Option<core::ptr::NonNull<ThreadLifecycleSegment>> {
    #[cfg(test)]
    if INJECT_SEGMENT_MISSES
        .try_with(|misses| {
            let left = misses.get();
            misses.set(left.saturating_sub(1));
            left != 0
        })
        .unwrap_or(false)
    {
        return None;
    }
    let segment = core::ptr::NonNull::new(segment_storage().cast::<ThreadLifecycleSegment>())?;
    // SAFETY: fresh, exclusively owned, correctly aligned storage.
    unsafe { ThreadLifecycleSegment::initialize_at(segment.as_ptr()) };
    Some(segment)
}

/// Ring metadata: the kernel's own allocator, whose capacity miss posts the
/// grant request the clone then waits a carrier round for.
#[cfg(not(test))]
fn segment_storage() -> *mut u8 {
    // SAFETY: the layout is a nonzero-sized, validly aligned type layout.
    unsafe { alloc::alloc::alloc(core::alloc::Layout::new::<ThreadLifecycleSegment>()) }
}
#[cfg(not(test))]
unsafe fn release_segment_storage(storage: *mut u8) {
    // SAFETY: the caller returns storage `segment_storage` allocated.
    unsafe {
        alloc::alloc::dealloc(
            storage,
            core::alloc::Layout::new::<ThreadLifecycleSegment>(),
        )
    }
}

/// Host tests run the ring at host addresses, where a thread's control is
/// admitted only inside the metadata window the fixtures map. Take the next
/// free chunk of that window, never replacing a mapping.
#[cfg(test)]
const TEST_SEGMENT_BYTES: usize =
    core::mem::size_of::<ThreadLifecycleSegment>().next_multiple_of(16384);
#[cfg(test)]
fn segment_storage() -> *mut u8 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut offset = 0x200_0000_u64;
        while offset + TEST_SEGMENT_BYTES as u64 <= carrick_el1_abi::EL1_DYNAMIC_METADATA_SIZE {
            let address = carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE + offset;
            // SAFETY: MAP_FIXED_NOREPLACE fails rather than replacing a mapping.
            let mapped = unsafe {
                libc::mmap(
                    address as *mut libc::c_void,
                    TEST_SEGMENT_BYTES,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                    -1,
                    0,
                )
            };
            if mapped != libc::MAP_FAILED && mapped as u64 == address {
                return mapped.cast();
            }
            if mapped != libc::MAP_FAILED {
                // SAFETY: unmaps only the misplaced mapping made above.
                unsafe { libc::munmap(mapped, TEST_SEGMENT_BYTES) };
            }
            offset += TEST_SEGMENT_BYTES as u64;
        }
    }
    core::ptr::null_mut()
}
#[cfg(test)]
unsafe fn release_segment_storage(storage: *mut u8) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: the caller returns one exact chunk `segment_storage` mapped.
    unsafe {
        libc::munmap(storage.cast(), TEST_SEGMENT_BYTES);
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = storage;
}

impl<C: ProcessContext> Drop for NativeThreadStock<'_, C> {
    fn drop(&mut self) {
        // SAFETY: the stock leaves with its process's resources, after every
        // member and control pin the page licensed; this owner allocated
        // each linked segment with this exact layout.
        unsafe {
            self.controls
                .page
                .detach_extension(|segment| release_segment_storage(segment.as_ptr().cast()));
        }
    }
}
/// One namespace reservation per stocked birth, held until its final pin drops.
struct StockIdentity<'a> {
    namespace: &'a NamespaceTable,
    number: InternalIdentity,
}

impl Drop for StockIdentity<'_> {
    fn drop(&mut self) {
        self.namespace
            .with_view(&carrick_sched_core::ShortLockSpin, |namespace| {
                namespace.release(self.number, ClaimKind::Thread);
            });
    }
}

struct ControlRelease<'a, C: ProcessContext> {
    zone: &'a ZoneTables<C>,
    source: carrick_sched_core::object_wait::ObjectNotificationSource<'a, C>,
}
impl<C: ProcessContext> carrick_core::lifecycle::MemberControlRelease for ControlRelease<'_, C> {
    fn released(&self) {
        self.source
            .reserve()
            .publish(carrick_sched_core::Waker::Host, &|owned| {
                crate::sched::object_wait::deliver_host_completion(self.zone, owned);
            });
    }
}
impl<'a, C: ProcessContext> NativeThreadStock<'a, C> {
    pub(super) fn new_root(
        page: &'a ThreadLifecyclePage,
        controls: &'a [ThreadControlSlot],
        zone: &'a ZoneTables<C>,
        record: RecordRef,
    ) -> Result<Self, NativeProcessError> {
        let identities =
            StockEntries::for_fresh_root(page).map_err(|_| NativeProcessError::Invalid)?;
        Self::new_with_wait(
            page,
            controls,
            zone,
            record,
            identities,
            &carrick_sched_core::ShortLockSpin,
        )
    }
    pub(super) fn new(
        page: &'a ThreadLifecyclePage,
        controls: &'a [ThreadControlSlot],
        zone: &'a ZoneTables<C>,
        record: carrick_el1_abi::RecordRef,
    ) -> Result<Self, NativeProcessError> {
        Self::new_with_wait(
            page,
            controls,
            zone,
            record,
            StockEntries::default(),
            &carrick_sched_core::ShortLockSpin,
        )
    }
    fn new_with_wait(
        page: &'a ThreadLifecyclePage,
        controls: &'a [ThreadControlSlot],
        zone: &'a ZoneTables<C>,
        record: carrick_el1_abi::RecordRef,
        mut identities: StockEntries<StockIdentity<'a>>,
        wait: &impl carrick_sched_core::LockWait<C>,
    ) -> Result<Self, NativeProcessError> {
        use carrick_sched_core::object_wait::{
            MemberReleaseGeneration, MemberReleaseIndex, ObjectWaitError, ObjectWaitKey,
        };
        // Every retained identity occupies one lifecycle slot. Reserve the
        // matching storage before any slot or namespace identity is published.
        let capacity = controls
            .len()
            .checked_sub(1)
            .ok_or(NativeProcessError::Invalid)?;
        identities
            .try_reserve_exact(capacity)
            .map_err(|_| NativeProcessError::Busy)?;
        let mut waiters = Vec::new();
        waiters
            .try_reserve_exact(controls.len())
            .map_err(|_| NativeProcessError::Busy)?;
        let start = record.id.raw() as usize;
        for index in (start..carrick_sched_core::ZONE_RECORDS).chain(0..start) {
            let index = MemberReleaseIndex::new(index).ok_or(NativeProcessError::Invalid)?;
            let generation = zone
                .serial_issuer()
                .allocate()
                .ok_or(NativeProcessError::Exhausted)?;
            let key = ObjectWaitKey::member_release(
                index,
                MemberReleaseGeneration::from_issued(generation),
            );
            match zone.bind_object_notification_source(key, wait, &|owned| {
                crate::sched::object_wait::deliver_host_completion(zone, owned)
            }) {
                Ok(ticket) => {
                    return Ok(Self {
                        controls: PoolSlots {
                            page,
                            head: controls,
                        },
                        identities,
                        namespace_exhausted: false,
                        segment_missed: false,
                        segment_misses: 0,
                        waiters,
                        release: Arc::new(ControlRelease {
                            zone,
                            source: ticket,
                        }),
                    });
                }
                Err(ObjectWaitError::Busy) => return Err(NativeProcessError::Busy),
                Err(ObjectWaitError::Occupied | ObjectWaitError::Stale) => {
                    continue;
                }
                Err(_) => return Err(NativeProcessError::Stale),
            }
        }
        Err(NativeProcessError::Exhausted)
    }
    fn drain_closed(&mut self, page: &ThreadLifecyclePage) -> Result<(), NativeFailure> {
        self.identities
            .drain_closed(page, &self.controls)
            .map_err(|_| NativeFailure::Stale)
    }
    fn settle(&mut self, page: &ThreadLifecyclePage) -> Result<(), NativeFailure> {
        self.identities
            .settle(page, &self.controls)
            .map_err(|_| NativeFailure::Stale)
    }
    /// Link one more segment of entries and controls to the page. Every
    /// fallible step, the retained-identity and waiter bookkeeping included,
    /// comes before the link, so a miss changes nothing.
    fn grow(&mut self) -> bool {
        let page = self.controls.page;
        let entries = carrick_el1_abi::Lifecycle::entry_count(page) + THREAD_POOL_SEGMENT_ENTRIES;
        if self.identities.try_reserve_total(entries).is_err()
            || self
                .waiters
                .try_reserve_exact((entries + 1).saturating_sub(self.waiters.len()))
                .is_err()
        {
            return false;
        }
        let Some(segment) = allocate_segment() else {
            return false;
        };
        // SAFETY: `allocate_segment` initialized it; this stock is the page's
        // one stock owner, serialized by the graph lock, and frees the
        // segment only in `drop`, after `detach_extension`.
        unsafe { page.publish_extension(segment) };
        true
    }
}

pub(super) fn drain_closed<M, C: ProcessContext>(
    resources: &mut NativeResources<'_, M, C>,
) -> Result<(), NativeFailure> {
    if let Some(stock) = resources.thread_stock.as_mut() {
        stock.drain_closed(resources.page)?;
    }
    Ok(())
}

pub(super) fn at_limit<M: Clone, C: ProcessContext>(
    graph: &Graph<'_, M, C>,
    key: TaskKey,
    caller: u32,
) -> Result<bool, NativeFailure> {
    use carrick_personality_linux::identity::LinuxCapabilitySet;
    let task = graph.owner.task(key).map_err(|_| NativeFailure::Stale)?;
    let credentials = task
        .credentials_for(caller)
        .map_err(|_| NativeFailure::Stale)?;
    let limit = task
        .rlimits
        .get(carrick_abi::LinuxResource::Nproc.index())
        .ok_or(NativeFailure::Invalid)?
        .rlim_cur;
    if credentials.ruid.is_root()
        || limit == u64::MAX
        || credentials
            .cap_effective
            .intersects(LinuxCapabilitySet::CAP_SYS_ADMIN | LinuxCapabilitySet::CAP_SYS_RESOURCE)
    {
        return Ok(false);
    }
    let count = graph
        .owner
        .tasks()
        .values()
        .map(|task| {
            task.threads
                .threads
                .iter()
                .filter(|thread| thread.credentials.ruid == credentials.ruid)
                .count()
        })
        .sum::<usize>();
    Ok(count as u64 >= limit)
}

/// Whether a refill may link a new segment. Only a clone that found the pool
/// with nothing standing and nothing on its way back grows it; the refills
/// after a birth or a retirement work within the entries the pool has.
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::cmp::Eq, ::core::cmp::PartialEq)]
pub(super) enum StockGrowth {
    Within,
    ForClone,
}

pub(super) fn replenish<'a, M: Clone, C: ProcessContext>(
    runtime: &NativeProcessRuntime<'a, M, C>,
    graph: &mut Graph<'a, M, C>,
    key: TaskKey,
    caller: u32,
    growth: StockGrowth,
) -> Result<(), NativeFailure> {
    let limit = at_limit(graph, key, caller)?;
    let namespace = graph.namespace;
    let visible_namespace = graph.visible_namespace;
    let task = graph
        .owner
        .task_mut(key)
        .map_err(|_| NativeFailure::Stale)?;
    let uid = task
        .credentials_for(caller)
        .map_err(|_| NativeFailure::Stale)?
        .ruid;
    let resources = task.native_mut().resources_mut();
    let Some(stock) = resources.thread_stock.as_mut() else {
        return Ok(());
    };
    if resources.page.gate() != carrick_el1_abi::GateState::Open {
        return stock.drain_closed(resources.page);
    }
    stock.settle(resources.page)?;
    stock.namespace_exhausted = false;
    stock.segment_missed = false;
    struct Stock<'s, 'a, C: ProcessContext> {
        stock: &'s mut NativeThreadStock<'a, C>,
        page: &'a ThreadLifecyclePage,
        zone: &'a ZoneTables<C>,
        namespace: &'a NamespaceTable,
        visible_namespace: VisibleNamespace,
        key: TaskKey,
        uid: carrick_personality_linux::identity::TaskUid,
        limit: bool,
        growth: StockGrowth,
    }
    impl<C: ProcessContext> ThreadStock for Stock<'_, '_, C> {
        fn page(&self) -> &dyn Lifecycle {
            self.page
        }
        fn standing(&self) -> usize {
            self.stock.identities.standing(self.page)
        }

        fn reserve_and_stock(&mut self) -> bool {
            if self.limit {
                return false;
            }
            let index = match self
                .stock
                .identities
                .recyclable(self.page, &self.stock.controls)
            {
                Some(index) => index,
                // Every entry is held: live threads, not a limit. Entries a
                // retiring thread is about to return are waited for instead.
                None if self.growth == StockGrowth::ForClone
                    && self.stock.identities.standing(self.page) == 0
                    && !self.stock.identities.retiring(self.page) =>
                {
                    if !self.stock.grow() {
                        self.stock.segment_missed = true;
                        return false;
                    }
                    self.stock.segment_misses = 0;
                    let Some(index) = self
                        .stock
                        .identities
                        .recyclable(self.page, &self.stock.controls)
                    else {
                        return false;
                    };
                    index
                }
                None => return false,
            };
            let Some(control) = self.stock.controls.pool_control(index) else {
                return false;
            };
            // Recycle only after the final graph/control pin is released.
            // The existing reset owner clears the predecessor visible TID.
            if control
                .reset_for_host_birth(carrick_personality_linux::abi::thread::BlockedMask(0))
                .is_err()
            {
                return false;
            }
            let Some(serial) = self.zone.serial_issuer().allocate() else {
                return false;
            };
            let Some((number, visible)) =
                self.namespace
                    .with_view(&carrick_sched_core::ShortLockSpin, |namespace| {
                        let number = namespace.reserve_next(ClaimKind::Thread).ok()?;
                        let Ok(visible) = namespace.assign_visible(number, self.visible_namespace)
                        else {
                            namespace.release(number, ClaimKind::Thread);
                            return None;
                        };
                        Some((number, visible))
                    })
            else {
                self.stock.namespace_exhausted = true;
                return false;
            };
            let claim = StockIdentity {
                namespace: self.namespace,
                number,
            };
            let Ok(entry) = self.page.stock_with_control(
                index,
                EntryIdentity {
                    tid: number.get() as u32,
                    visible_tid: visible.get(),
                    thread_serial: serial.get(),
                    birth: carrick_core_abi::entry::BirthSerial::of_task(self.key.serial),
                    uid_credit: u64::from(self.uid.raw()),
                },
                Some(carrick_guest_arch::KernelVa::new(
                    core::ptr::from_ref(control) as u64,
                )),
            ) else {
                return false;
            };
            self.stock.identities.insert(entry, claim);
            true
        }
    }
    carrick_core::lifecycle::stock::replenish(
        &mut Stock {
            stock,
            page: resources.page,
            zone: runtime.zone,
            namespace,
            visible_namespace,
            key,
            uid,
            limit,
            growth,
        },
        DEFAULT_THREAD_POOL_DEPTH,
    );
    Ok(())
}

/// Birth settlement owns the Claimed transition; notify only after its graph
/// and lifecycle publication have finished. Pin release uses this same source.
pub(super) fn admission_settled<M: Clone, C: ProcessContext>(
    runtime: &NativeProcessRuntime<'_, M, C>,
    key: TaskKey,
) {
    let release = {
        let graph = runtime.graph.lock();
        graph
            .owner
            .task(key)
            .ok()
            .and_then(|task| task.native().resources().thread_stock.as_ref())
            .filter(|stock| !stock.waiters.is_empty())
            .map(|stock| stock.release.clone())
    };
    if let Some(release) = release {
        carrick_core::lifecycle::MemberControlRelease::released(&*release);
    }
}

impl<'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>>
    NativeProcessEntry<'_, 'a, M, C, S>
{
    pub(super) fn prepare_native_thread_birth(
        &mut self,
    ) -> Result<carrick_personality_linux::lifecycle::ThreadBirthAdmission, NativeFailure> {
        use carrick_personality_linux::lifecycle::ThreadBirthAdmission;
        use carrick_sched_core::object_wait::{ObjectWaitError, OperationToken};
        let release = {
            let graph = self.runtime.graph.lock();
            let resources = graph
                .owner
                .task(self.key)
                .map_err(|_| NativeFailure::Stale)?
                .native()
                .resources();
            let Some(stock) = resources.thread_stock.as_ref() else {
                return Ok(ThreadBirthAdmission::Unmanaged);
            };
            stock.release.clone()
        };
        let key = release.source.key();
        let zone = self.source.zone;
        let record = self.record;
        loop {
            let mut limit = false;
            let mut segment_missed = None;
            let token = OperationToken::new(u64::from(key.index()), key.generation())
                .ok_or(NativeFailure::Stale)?;
            let parked = carrick_core::wait::park_object_record(
                zone,
                self.source.slot,
                carrick_core::wait::ObjectParkRequest::owner(
                    key,
                    token,
                    OwnerEntry::Syscall,
                    // SAFETY: the save_context closure below re-reads the
                    // stock's Reserved and recyclable identities and arms
                    // their release under this same object queue.
                    unsafe {
                        carrick_core::wait::OwnerProbeUnderQueueLock::for_save_context_probe()
                    },
                ),
                &|owned| crate::sched::object_wait::deliver_host_completion(zone, owned),
                || {
                    let mut graph = self.runtime.graph.lock();
                    if replenish(
                        self.runtime,
                        &mut graph,
                        self.key,
                        self.calling_tid,
                        StockGrowth::ForClone,
                    )
                    .is_err()
                    {
                        return Err(ObjectWaitError::Stale);
                    }
                    if at_limit(&graph, self.key, self.calling_tid)
                        .map_err(|_| ObjectWaitError::Stale)?
                    {
                        limit = true;
                        return Err(ObjectWaitError::Changed);
                    }
                    let task = graph
                        .owner
                        .task(self.key)
                        .map_err(|_| ObjectWaitError::Stale)?;
                    let resources = task.native().resources();
                    let stock = resources
                        .thread_stock
                        .as_ref()
                        .ok_or(ObjectWaitError::Stale)?;
                    if stock.namespace_exhausted && stock.identities.standing(resources.page) == 0 {
                        limit = true;
                        return Err(ObjectWaitError::Changed);
                    }
                    if stock.segment_missed && stock.identities.standing(resources.page) == 0 {
                        let stock = graph
                            .owner
                            .task_mut(self.key)
                            .map_err(|_| ObjectWaitError::Stale)?
                            .native_mut()
                            .resources_mut()
                            .thread_stock
                            .as_mut()
                            .ok_or(ObjectWaitError::Stale)?;
                        stock.segment_misses = stock.segment_misses.saturating_add(1);
                        let refused = stock.segment_misses > SEGMENT_GRANT_ROUNDS;
                        if refused {
                            stock.segment_misses = 0;
                        }
                        segment_missed = Some(refused);
                        return Err(ObjectWaitError::Changed);
                    }
                    // SAFETY: stock retains the source and control extent in
                    // the shared mapping until final-pin settlement. The queue
                    // is enrolled before this neutral admission decision.
                    match unsafe {
                        stock
                            .identities
                            .admission(resources.page, &stock.controls, release.clone())
                    } {
                        StockAdmission::Ready | StockAdmission::Changed => {
                            return Err(ObjectWaitError::Changed);
                        }
                        StockAdmission::Exhausted => {
                            limit = true;
                            return Err(ObjectWaitError::Changed);
                        }
                        StockAdmission::Waiting => {}
                    }
                    let stock = graph
                        .owner
                        .task_mut(self.key)
                        .map_err(|_| ObjectWaitError::Stale)?
                        .native_mut()
                        .resources_mut()
                        .thread_stock
                        .as_mut()
                        .ok_or(ObjectWaitError::Stale)?;
                    if stock.waiters.contains(&record)
                        || stock.waiters.len() == stock.waiters.capacity()
                    {
                        return Err(ObjectWaitError::Stale);
                    }
                    stock.waiters.push(record);
                    // The queue is enrolled before this final predicate probe.
                    // Only the final release notification, never a timer, wakes
                    // the preserved clone operation for another admission turn.
                    unsafe {
                        *zone.record(record.id).ctx_mut() = *self.words;
                    }
                    Ok((record.id, false))
                },
            );
            match parked {
                Ok(mut parked) => {
                    self.handoff = parked.take_receipt();
                    return Ok(ThreadBirthAdmission::Owned(LifecycleOutcome::Transferred {
                        progress: carrick_core::Served::Idle,
                        result: SyscallResult::new(0),
                    }));
                }
                Err((ObjectWaitError::Changed, _)) => {
                    self.clear_thread_stock_wait();
                    if limit {
                        return Ok(ThreadBirthAdmission::Owned(returned(-11)));
                    }
                    match segment_missed {
                        // The metadata owner keeps refusing the segment:
                        // memory, never a thread limit (`clone(2)`: ENOMEM).
                        Some(true) => return Ok(ThreadBirthAdmission::Owned(returned(-12))),
                        // Not now: the miss posted its grant request. Keep
                        // this clone, release the execution lease through the
                        // carrier-work retry, and rerun the exact SVC.
                        Some(false) => {
                            return self
                                .retry_guest_input(
                                    carrick_core_abi::service::ServiceOperation::CarrierWork {
                                        entry: OwnerEntry::Syscall,
                                        demand: carrick_core_abi::service::CarrierDemand::Work,
                                    },
                                    None,
                                    None,
                                )
                                .map(ThreadBirthAdmission::Owned)
                                .map_err(|error| {
                                    error.failure().unwrap_or(NativeFailure::Quarantined)
                                });
                        }
                        None => {}
                    }
                    // A ready pool never needed to park. If a release raced
                    // enrollment, rerun this same owned admission once notified.
                    let graph = self.runtime.graph.lock();
                    let resources = graph
                        .owner
                        .task(self.key)
                        .map_err(|_| NativeFailure::Stale)?
                        .native()
                        .resources();
                    if resources
                        .thread_stock
                        .as_ref()
                        .ok_or(NativeFailure::Stale)?
                        .identities
                        .standing(resources.page)
                        != 0
                    {
                        return Ok(ThreadBirthAdmission::Ready);
                    }
                }
                Err(_) => {
                    self.clear_thread_stock_wait();
                    return Err(NativeFailure::Stale);
                }
            }
        }
    }
    /// The shared clone policy found this unmanaged (host-stocked) pool
    /// empty: contention, not a host birth (#1974). The caller keeps its
    /// clone and releases its execution lease through the existing
    /// carrier-work retry (as an input preparation's `Busy` does). Its exact
    /// request carries [`CarrierDemand::ThreadStock`], so the carrier stocks
    /// this caller's process before it replies; the demand never rides a
    /// shared slot word another boundary could consume. The exact SVC then
    /// reruns and probes the pool again, so stock published at any point
    /// before the reply is never missed.
    ///
    /// The carrier's typed answer is retained for that rerun. `Stocked` and
    /// an empty pool mean a sibling took the stock: wait again. Only
    /// `Unstockable` (no standing depth, `RLIMIT_NPROC`, exhaustion, a
    /// closed gate) gives this call today's host answer (`None`), so a host
    /// with nothing to stock never becomes an endless wait.
    ///
    /// [`CarrierDemand::ThreadStock`]: carrick_core_abi::service::CarrierDemand::ThreadStock
    pub(super) fn await_unmanaged_thread_stock(
        &mut self,
    ) -> Result<Option<LifecycleOutcome>, NativeProcessError> {
        {
            let graph = self.runtime.graph.lock();
            // A managed pool's own stock owner waits in `prepare_thread_birth`.
            if graph
                .owner
                .task(self.key)
                .map_err(|_| NativeProcessError::Stale)?
                .native()
                .resources()
                .thread_stock
                .is_some()
            {
                return Err(NativeProcessError::Invalid);
            }
        }
        if self.thread_stock_reply.take()
            == Some(carrick_core_abi::service::CarrierWorkReply::Unstockable)
        {
            return Ok(None);
        }
        self.retry_guest_input(
            carrick_core_abi::service::ServiceOperation::CarrierWork {
                entry: OwnerEntry::Syscall,
                demand: carrick_core_abi::service::CarrierDemand::ThreadStock,
            },
            None,
            None,
        )
        .map(Some)
    }
    /// The carrier answered this member's thread-stock demand: retain the
    /// answer in the member row for the clone's rerun, the next syscall
    /// entry, which scopes it to itself (`scope_rerun_answers_to_entry`).
    pub(super) fn retain_thread_stock_reply(
        &mut self,
        reply: carrick_core_abi::service::CarrierWorkReply,
    ) {
        self.thread_stock_pending = true;
        self.runtime
            .graph
            .lock()
            .retain_thread_stock_reply(self.record, reply);
    }
    /// Move a retained thread-stock answer out of the member row. The
    /// admission snapshot keeps an entry without one off the graph lock.
    pub(super) fn take_retained_thread_stock_reply(
        &mut self,
    ) -> Option<carrick_core_abi::service::CarrierWorkReply> {
        if !core::mem::take(&mut self.thread_stock_pending) {
            return None;
        }
        self.runtime
            .graph
            .lock()
            .take_thread_stock_reply(&self.record)
    }
    pub(super) fn clear_thread_stock_wait(&self) {
        let mut graph = self.runtime.graph.lock();
        if let Ok(task) = graph.owner.task_mut(self.key)
            && let Some(stock) = task.native_mut().resources_mut().thread_stock.as_mut()
        {
            stock.waiters.retain(|record| *record != self.record);
        }
    }
    /// Resume a clone caller parked on the thread stock, or report no
    /// pending work. Out of line: the resume checkpoint frame is charged on
    /// the EL1 native backing-reply chain.
    #[inline(never)]
    pub(super) fn resume_thread_stock_wait(
        &mut self,
    ) -> Result<NativeResume, carrick_core_abi::NativeRunFailureReason> {
        self.take_thread_stock_wait()
            .map(|resumed| resumed.unwrap_or(NativeResume::NoPending))
            .map_err(NativeFailure::run_failure_reason)
    }
    fn take_thread_stock_wait(&mut self) -> Result<Option<NativeResume>, NativeFailure> {
        let key = {
            let graph = self.runtime.graph.lock();
            let task = graph
                .owner
                .task(self.key)
                .map_err(|_| NativeFailure::Stale)?;
            let Some(stock) = task.native().resources().thread_stock.as_ref() else {
                return Ok(None);
            };
            if !stock.waiters.contains(&self.record) {
                return Ok(None);
            }
            stock.release.source.key()
        };
        let token = carrick_core::wait::take_object_operation(
            self.source.zone,
            self.source.slot,
            self.source.zone.record(self.record.id).identity(),
        )
        .map_err(|_| NativeFailure::Stale)?
        .ok_or(NativeFailure::Stale)?;
        if token.index() != u64::from(key.index()) || token.generation() != key.generation() {
            return Err(NativeFailure::Stale);
        }
        self.clear_thread_stock_wait();
        // SAFETY: the selected record owns this exact Syscall continuation;
        // its token was consumed above and no guest instruction resumed.
        unsafe {
            self.source
                .zone
                .record(self.record.id)
                .consume_owner_continuation();
        }
        Ok(Some(NativeResume::RetrySyscall))
    }
}

#[cfg(test)]
pub(crate) fn claim_counts<M: Clone, C: ProcessContext>(
    runtime: &NativeProcessRuntime<'_, M, C>,
) -> carrick_sched_core::process::identity_allocator::IdRegistryCounts {
    runtime
        .graph
        .lock()
        .namespace
        .with_view(&carrick_sched_core::ShortLockSpin, |ns| ns.counts())
}
#[cfg(all(test, not(target_os = "macos")))]
pub(crate) fn retain_signal_snapshot<'a, M: Clone, C: ProcessContext>(
    runtime: &NativeProcessRuntime<'a, M, C>,
    record: carrick_el1_abi::RecordRef,
) -> Arc<
    crate::native_process_signals::NativeSignalProjection<
        'a,
        carrick_personality_linux::abi::signal::LinuxSiginfo,
    >,
> {
    let graph = runtime.graph.lock();
    graph
        .owner
        .tasks()
        .values()
        .flat_map(|task| task.native().resources().members.iter())
        .find(|member| member.record == record)
        .and_then(|member| member.signal_projection.clone())
        .expect("registered signal projection")
}
#[cfg(all(test, not(target_os = "macos")))]
pub(crate) fn retain_transient_control_pin<'a, M: Clone, C: ProcessContext>(
    runtime: &NativeProcessRuntime<'a, M, C>,
    record: carrick_el1_abi::RecordRef,
) -> carrick_core::lifecycle::MemberControlCustody<'a, ThreadControlSlot> {
    let graph = runtime.graph.lock();
    let control = graph
        .owner
        .tasks()
        .values()
        .flat_map(|task| task.native().resources().members.iter())
        .find(|member| member.record == record)
        .map(|member| member.control.control())
        .expect("registered member control");
    carrick_core::lifecycle::MemberControlCustody::retain(control).expect("transient control pin")
}

#[cfg(all(test, not(target_os = "macos")))]
pub(crate) fn claim_sibling_births<M: Clone, C: ProcessContext>(
    runtime: &NativeProcessRuntime<'_, M, C>,
    record: RecordRef,
) -> Vec<carrick_core::lifecycle::ClaimedEntry> {
    let mut graph = runtime.graph.lock();
    let task = graph
        .owner
        .tasks()
        .values()
        .find(|task| {
            task.native()
                .resources()
                .members
                .iter()
                .any(|member| member.record == record)
        })
        .unwrap();
    let key = task.key();
    let tid = runtime.zone.record(record.id).identity().tid as u32;
    let page = task.native().resources().page;
    let mut claims = Vec::new();
    for _ in 0..=page.entry_count() {
        replenish(runtime, &mut graph, key, tid, StockGrowth::Within).unwrap();
        match page.claim_any() {
            Ok(claim) => claims.push(claim),
            Err(carrick_core::lifecycle::TransitionError::PoolEmpty) => return claims,
            Err(error) => panic!("unexpected claim failure: {error:?}"),
        }
    }
    panic!("stock claims exceeded the lifecycle capacity")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn notification_source_busy_is_not_exhaustion_and_release_allows_admission() {
        let layout = std::alloc::Layout::new::<ZoneTables<carrick_el1_abi::Aarch64ParkedContext>>();
        // SAFETY: exact aligned, zero-valid scheduler allocation owned by Box.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout)
                .cast::<ZoneTables<carrick_el1_abi::Aarch64ParkedContext>>();
            assert!(!ptr.is_null());
            Box::from_raw(ptr)
        };
        let controls = core::array::from_fn::<_, 9, _>(|_| ThreadControlSlot::new());
        let page = Box::new(ThreadLifecyclePage::new());
        let id = zone.alloc_record(ThreadIdentity::default()).unwrap();
        let record = zone.record_ref(id);
        let first = NativeThreadStock::new(&page, &controls, &zone, record).unwrap();
        let key = first.release.source.key();
        let completion: &dyn Fn(
            carrick_sched_core::object_wait::OwnedObjectWakeEffects<
                '_,
                carrick_el1_abi::Aarch64ParkedContext,
            >,
        ) = &|owned| crate::sched::object_wait::deliver_host_completion(&zone, owned);
        let held = zone
            .object_wait_with_completion(key, &carrick_sched_core::ShortLockSpin, completion)
            .unwrap();
        assert!(matches!(
            NativeThreadStock::new_with_wait(
                &page,
                &controls,
                &zone,
                record,
                StockEntries::default(),
                &carrick_sched_core::BoundedSpin(0)
            ),
            Err(NativeProcessError::Busy)
        ));
        drop(held);
        drop(first);
        assert!(NativeThreadStock::new(&page, &controls, &zone, record).is_ok());
    }
}
