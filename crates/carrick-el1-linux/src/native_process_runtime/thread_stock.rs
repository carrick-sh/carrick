//! Native graph adapter for the shared thread-birth stock owner.
use super::*;
use carrick_core::lifecycle::stock::{DEFAULT_THREAD_POOL_DEPTH, ThreadStock};
use carrick_core::lifecycle::{EntryState, MemberControl};

pub(super) struct NativeThreadStock<'a, C: ProcessContext> {
    controls: &'a [ThreadControlSlot],
    identities: Vec<(EntryRef, NativeClaim)>,
    waiters: Vec<carrick_el1_abi::RecordRef>,
    release: Arc<ControlRelease<'a, C>>,
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
    pub(super) fn new(
        controls: &'a [ThreadControlSlot],
        zone: &'a ZoneTables<C>,
        record: carrick_el1_abi::RecordRef,
    ) -> Result<Self, NativeProcessError> {
        Self::new_with_wait(controls, zone, record, &carrick_sched_core::ShortLockSpin)
    }
    fn new_with_wait(
        controls: &'a [ThreadControlSlot],
        zone: &'a ZoneTables<C>,
        record: carrick_el1_abi::RecordRef,
        wait: &impl carrick_sched_core::LockWait<C>,
    ) -> Result<Self, NativeProcessError> {
        use carrick_sched_core::object_wait::{
            MemberReleaseGeneration, MemberReleaseIndex, ObjectWaitError, ObjectWaitKey,
        };
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
                        controls,
                        identities: Vec::new(),
                        waiters: Vec::with_capacity(carrick_el1_abi::THREAD_POOL_ENTRIES + 1),
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
    fn settle(&mut self, page: &ThreadLifecyclePage) -> Result<(), NativeProcessError> {
        let mut index = 0;
        while index < self.identities.len() {
            let entry = self.identities[index].0;
            match page.state(entry.index()) {
                Some((generation, EntryState::ExitedInZone))
                    if generation == entry.generation() =>
                {
                    let control = &self.controls[entry.index() + 1];
                    if control.exit_custody().referenced() {
                        index += 1;
                        continue;
                    }
                    page.reap(entry).map_err(|_| NativeProcessError::Stale)?;
                    self.identities.swap_remove(index);
                }
                Some((generation, EntryState::Reaped | EntryState::Revoked))
                    if generation == entry.generation() =>
                {
                    if self.controls[entry.index() + 1].exit_custody().referenced() {
                        index += 1;
                    } else {
                        self.identities.swap_remove(index);
                    }
                }
                Some((generation, _)) if generation == entry.generation() => index += 1,
                _ => return Err(NativeProcessError::Stale),
            }
        }
        Ok(())
    }
}

pub(super) fn at_limit<M: Clone, C: ProcessContext>(
    graph: &Graph<'_, M, C>,
    key: TaskKey,
    caller: u32,
) -> Result<bool, NativeProcessError> {
    use carrick_personality_linux::identity::LinuxCapabilitySet;
    let task = graph
        .owner
        .task(key)
        .map_err(|_| NativeProcessError::Stale)?;
    let credentials = task
        .credentials_for(caller)
        .map_err(|_| NativeProcessError::Stale)?;
    let limit = task
        .rlimits
        .get(carrick_abi::LinuxResource::Nproc.index())
        .ok_or(NativeProcessError::Invalid)?
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

pub(super) fn replenish<'a, M: Clone, C: ProcessContext>(
    runtime: &NativeProcessRuntime<'a, M, C>,
    graph: &mut Graph<'a, M, C>,
    key: TaskKey,
    caller: u32,
) -> Result<(), NativeProcessError> {
    let limit = at_limit(graph, key, caller)?;
    let namespace = graph.namespace.clone();
    let visible_namespace = graph.visible_namespace;
    let task = graph
        .owner
        .task_mut(key)
        .map_err(|_| NativeProcessError::Stale)?;
    let uid = task
        .credentials_for(caller)
        .map_err(|_| NativeProcessError::Stale)?
        .ruid;
    let resources = task.native_mut().resources_mut();
    let Some(stock) = resources.thread_stock.as_mut() else {
        return Ok(());
    };
    stock.settle(resources.page)?;
    struct Stock<'s, 'a, C: ProcessContext> {
        stock: &'s mut NativeThreadStock<'a, C>,
        page: &'a ThreadLifecyclePage,
        zone: &'a ZoneTables<C>,
        namespace: Arc<SpinLock<NamespaceState>>,
        visible_namespace: VisibleNamespace,
        key: TaskKey,
        uid: carrick_personality_linux::identity::TaskUid,
        limit: bool,
    }
    impl<C: ProcessContext> ThreadStock for Stock<'_, '_, C> {
        fn page(&self) -> &dyn Lifecycle {
            self.page
        }
        fn standing(&self) -> usize {
            self.stock
                .identities
                .iter()
                .filter(|(entry, _)| {
                    self.page.state(entry.index())
                        == Some((entry.generation(), EntryState::Reserved))
                })
                .count()
        }
        fn reserve_and_stock(&mut self) -> bool {
            if self.limit {
                return false;
            }
            let Some(index) = (0..self.page.entry_count()).find(|&i| {
                self.page.state(i).is_some_and(|(_, state)| {
                    matches!(
                        state,
                        EntryState::Vacant | EntryState::Reaped | EntryState::Revoked
                    )
                }) && !self.stock.controls[i + 1].exit_custody().referenced()
            }) else {
                return false;
            };
            // Recycle only after the final graph/control pin is released.
            // The existing reset owner clears the predecessor visible TID.
            if self.stock.controls[index + 1]
                .reset_for_host_birth(carrick_personality_linux::abi::thread::BlockedMask(0))
                .is_err()
            {
                return false;
            }
            let Some(serial) = self.zone.serial_issuer().allocate() else {
                return false;
            };
            let (number, visible) = {
                let mut namespace = self.namespace.lock();
                let Ok(number) = namespace.reserve_next(ClaimKind::Thread) else {
                    return false;
                };
                let Some(visible) = namespace.reserve_visible(self.visible_namespace) else {
                    namespace.release(number, ClaimKind::Thread);
                    return false;
                };
                (number, visible)
            };
            let claim = NativeClaim {
                namespace: self.namespace.clone(),
                claims: vec![(number, ClaimKind::Thread)],
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
                    &self.stock.controls[index + 1] as *const _ as u64,
                )),
            ) else {
                return false;
            };
            self.stock.identities.push((entry, claim));
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
    ) -> Result<carrick_personality_linux::lifecycle::ThreadBirthAdmission, NativeProcessError>
    {
        use carrick_personality_linux::lifecycle::ThreadBirthAdmission;
        use carrick_sched_core::object_wait::{ObjectWaitError, OperationToken};
        let release = {
            let graph = self.runtime.graph.lock();
            let resources = graph
                .owner
                .task(self.key)
                .map_err(|_| NativeProcessError::Stale)?
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
            let token = OperationToken::new(u64::from(key.index()), key.generation())
                .ok_or(NativeProcessError::Stale)?;
            let parked = carrick_core::wait::park_object_record(
                zone,
                self.source.slot,
                carrick_core::wait::ObjectParkRequest::owner(key, token, OwnerEntry::Syscall),
                &|owned| crate::sched::object_wait::deliver_host_completion(zone, owned),
                || {
                    let mut graph = self.runtime.graph.lock();
                    if replenish(self.runtime, &mut graph, self.key, self.calling_tid).is_err() {
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
                    if stock.identities.iter().any(|(entry, _)| {
                        resources.page.state(entry.index())
                            == Some((entry.generation(), EntryState::Reserved))
                    }) {
                        return Err(ObjectWaitError::Changed);
                    }
                    // Only native pool births have the admission-settled
                    // notifier. The process-close census also includes host
                    // claims and external work, which cannot release this stock.
                    let mut pending_release = (0..resources.page.entry_count()).any(|index| {
                        resources
                            .page
                            .state(index)
                            .is_some_and(|(_, state)| state == EntryState::Claimed)
                    });
                    for (entry, _) in &stock.identities {
                        if resources
                            .page
                            .state(entry.index())
                            .is_some_and(|(generation, state)| {
                                generation == entry.generation()
                                    && matches!(
                                        state,
                                        EntryState::ExitingBorn
                                            | EntryState::ExitingPublished
                                            | EntryState::ExitedInZone
                                            | EntryState::Reaped
                                            | EntryState::Revoked
                                    )
                            })
                        {
                            // SAFETY: the process stock owns this source and
                            // retains the control extent through final-pin
                            // settlement; its zone outlives these members.
                            // Fork-loan member/projection pins are dropped in
                            // the shared supervisor mapping, never by the host.
                            if !unsafe {
                                carrick_core::lifecycle::arm_member_release(
                                    &stock.controls[entry.index() + 1],
                                    release.clone(),
                                )
                            } {
                                return Err(ObjectWaitError::Changed);
                            }
                            pending_release = true;
                        }
                    }
                    if !pending_release {
                        limit = true;
                        return Err(ObjectWaitError::Changed);
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
                    // A ready pool never needed to park. If a release raced
                    // enrollment, rerun this same owned admission once notified.
                    let graph = self.runtime.graph.lock();
                    let resources = graph
                        .owner
                        .task(self.key)
                        .map_err(|_| NativeProcessError::Stale)?
                        .native()
                        .resources();
                    if (0..resources.page.entry_count()).any(|i| {
                        resources
                            .page
                            .state(i)
                            .is_some_and(|(_, state)| state == EntryState::Reserved)
                    }) {
                        return Ok(ThreadBirthAdmission::Ready);
                    }
                }
                Err(_) => {
                    self.clear_thread_stock_wait();
                    return Err(NativeProcessError::Stale);
                }
            }
        }
    }
    pub(super) fn clear_thread_stock_wait(&self) {
        let mut graph = self.runtime.graph.lock();
        if let Ok(task) = graph.owner.task_mut(self.key)
            && let Some(stock) = task.native_mut().resources_mut().thread_stock.as_mut()
        {
            stock.waiters.retain(|record| *record != self.record);
        }
    }
    pub(super) fn resume_thread_stock_wait(
        &mut self,
    ) -> Result<Option<NativeResume>, NativeProcessError> {
        let key = {
            let graph = self.runtime.graph.lock();
            let task = graph
                .owner
                .task(self.key)
                .map_err(|_| NativeProcessError::Stale)?;
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
        .map_err(|_| NativeProcessError::Stale)?
        .ok_or(NativeProcessError::Stale)?;
        if token.index() != u64::from(key.index()) || token.generation() != key.generation() {
            return Err(NativeProcessError::Stale);
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

#[cfg(all(test, not(target_os = "macos")))]
pub(crate) fn claim_counts<M: Clone, C: ProcessContext>(
    runtime: &NativeProcessRuntime<'_, M, C>,
) -> carrick_sched_core::process::identity_allocator::IdRegistryCounts {
    runtime.graph.lock().namespace.lock().counts()
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
        replenish(runtime, &mut graph, key, tid).unwrap();
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
        let id = zone.alloc_record(ThreadIdentity::default()).unwrap();
        let record = zone.record_ref(id);
        let first = NativeThreadStock::new(&controls, &zone, record).unwrap();
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
                &controls,
                &zone,
                record,
                &carrick_sched_core::BoundedSpin(0)
            ),
            Err(NativeProcessError::Busy)
        ));
        drop(held);
        drop(first);
        assert!(NativeThreadStock::new(&controls, &zone, record).is_ok());
    }
}
