//! Native Linux futex service over the existing typed scheduler and MM owners.
use super::*;
use carrick_core::user_copy::{CopyOutcome, UserCopy};
use carrick_guest_arch::CounterTick;
use carrick_personality_linux::sched::{
    FutexCall, FutexFrequency, FutexVenue, FutexWait, MmFutexKey, RelativeFutexWait,
};
use core::cell::{Cell, RefCell};

pub fn private_anonymous_futex_mapping<P, Policy, Geometry, Venue, B, C>(
    portal: &carrick_core::mm::transaction::MmPortal<'_, P, Policy, Geometry, Venue, B, C>,
    mm: MmGeneration,
    slot: u32,
    address: UserVa,
) -> Result<bool, NativeProcessError>
where
    P: carrick_core_abi::PinnedMetadataExtent,
    Policy: carrick_core::mm::reservation::ReservationPolicy,
    Geometry: carrick_core::mm::reservation::ReservationGeometry,
    Venue: carrick_core::mm::transaction::OwnerVenue<C>,
    B: carrick_mmu_core::owner_mmu::OwnerMmu,
    C: ProcessContext,
{
    let mut root = portal
        .root(
            carrick_el1_abi::ReservationMm::new(mm.raw().get()).ok_or(NativeProcessError::Stale)?,
            slot,
        )
        .map_err(|error| match error {
            carrick_core::mm::transaction::MmError::Wait(wait) => {
                NativeProcessError::OwnerWait(wait)
            }
            carrick_core::mm::transaction::MmError::Busy => NativeProcessError::Busy,
            _ => NativeProcessError::Stale,
        })?;
    Ok(root.mapping(address.raw()).is_some_and(|mapping| {
        mapping.anonymous
            && mapping
                .flags
                .contains(carrick_core_abi::ReservationNodeFlags::PRIVATE)
            && address
                .raw()
                .checked_add(4)
                .is_some_and(|end| end <= mapping.range.end())
    }))
}

struct Adapter<'e, 'r, 'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>> {
    entry: &'e mut NativeProcessEntry<'r, 'a, M, C, S>,
    copy: RefCell<&'e mut dyn UserCopy>,
    refusal: Cell<Option<CopyOutcome>>,
    shared: bool,
    mapping_refusal: Option<NativeProcessError>,
    now: CounterTick,
    frequency: FutexFrequency,
    retained: Option<RelativeFutexWait>,
}
impl<'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>>
    Adapter<'_, '_, 'a, M, C, S>
{
    fn authenticate_mapping(&mut self, address: UserVa) -> Option<bool> {
        if !self.shared {
            return Some(true);
        }
        let mm = self
            .entry
            .runtime
            .graph
            .lock()
            .owner
            .task(self.entry.key)
            .ok()?
            .native()
            .resources()
            .mm
            .clone();
        match self.entry.service.futex_shared_private(&mm, address) {
            Ok(admitted) => Some(admitted),
            Err(error) => {
                self.mapping_refusal = Some(error);
                None
            }
        }
    }
}
impl<'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>> FutexVenue
    for Adapter<'_, '_, 'a, M, C, S>
{
    type Served = LifecycleOutcome;
    fn mm(&self) -> Option<carrick_el1_abi::ReservationMm> {
        carrick_el1_abi::ReservationMm::new(self.entry.binding.mm.raw())
    }
    fn timed_wait_allowed(&self) -> bool {
        true
    }
    fn read_u64(&self, address: UserVa) -> Option<u64> {
        let mut bytes = [0; 8];
        match self.copy.borrow_mut().copy_in(&mut bytes, address) {
            CopyOutcome::Done => Some(u64::from_le_bytes(bytes)),
            CopyOutcome::Fault => {
                self.refusal.set(Some(CopyOutcome::Fault));
                None
            }
            CopyOutcome::NotYet(request) => {
                self.refusal.set(Some(CopyOutcome::NotYet(request)));
                None
            }
        }
    }
    fn frequency(&self) -> FutexFrequency {
        self.frequency
    }
    fn now(&self) -> CounterTick {
        self.now
    }
    fn retained_deadline(&self) -> Option<CounterTick> {
        self.retained.as_ref().map(|wait| wait.deadline)
    }
    fn invalid(&mut self, result: SyscallResult) -> Option<LifecycleOutcome> {
        Some(returned(result.raw()))
    }
    fn wake(
        &mut self,
        mm: carrick_el1_abi::ReservationMm,
        address: UserVa,
        bitset: u32,
        limit: u32,
    ) -> Option<LifecycleOutcome> {
        if !self.authenticate_mapping(address)? {
            return None;
        }
        let key = if self.shared {
            MmFutexKey::shared_private(address)?
        } else {
            MmFutexKey::private(address)?
        };
        let result = self.entry.wake_native_futex(mm, key, bitset, limit);
        match result {
            Ok(count) => Some(returned(i64::from(count))),
            Err(reason) => Some(self.entry.run_failed(reason)),
        }
    }
    fn wait(&mut self, wait: FutexWait) -> Option<LifecycleOutcome> {
        if let Some(deadline) = wait.deadline {
            self.retained = Some(RelativeFutexWait { deadline });
        }
        // Policy decoded the original relative expiry before mapping admission.
        // Both mapping and operand refusals now retain this same deadline.
        if !self.authenticate_mapping(wait.address)? {
            return None;
        }
        let key = if self.shared {
            MmFutexKey::shared_private(wait.address)?
        } else {
            MmFutexKey::private(wait.address)?
        };
        let zone = self.entry.source.zone;
        let slot = self.entry.source.slot;
        let record = self.entry.record.id;
        let guard = zone.short_lock(
            ZoneTables::<C>::bucket_of_with_context(wait.mm.raw(), key.scheduler_address()),
            &carrick_sched_core::ShortLockSpin,
        );
        let mut word = 0;
        match self
            .copy
            .borrow_mut()
            .atomic_load_u32(wait.address, &mut word)
        {
            CopyOutcome::Done => {}
            refusal => {
                drop(guard);
                self.refusal.set(Some(refusal));
                return None;
            }
        }
        if word != wait.expected {
            return Some(returned(wait.mismatch_result.raw()));
        }
        let start =
            carrick_core::entry::prepare_handoff(self.entry.binding, self.entry.source, record)?;
        // SAFETY: the exact current record remains exclusively OnCpu until
        // publication under this bucket transfers its saved context custody.
        unsafe {
            *zone.record(record).ctx_mut() = *self.entry.words;
        }
        let sequence = zone.next_seq(record);
        if wait.deadline.is_some() && zone.arm_timer(slot, record, sequence).is_err() {
            drop(guard);
            // Capacity is per record; this refusal means the same execution
            // already owns a timer, not contention with another task.
            return Some(
                self.entry
                    .run_failed(carrick_core_abi::NativeRunFailureReason::NativeStale),
            );
        }
        if zone
            .enqueue(
                &guard,
                record,
                sequence,
                wait.mm.raw(),
                key.scheduler_address(),
                wait.bitset,
                0,
            )
            .is_err()
        {
            zone.cancel_timer_admission(self.entry.record);
            drop(guard);
            return Some(
                self.entry
                    .run_failed(carrick_core_abi::NativeRunFailureReason::NativeStale),
            );
        }
        if self
            .entry
            .runtime
            .registry
            .lock()
            .is_some_and(|registry| registry.futex_signal_pending(zone, self.entry.record))
        {
            zone.withdraw_guest_park(&guard, record);
            return Some(returned(carrick_syscall_abi::LINUX_EINTR.guest_retval()));
        }
        zone.set_deadline(record, wait.deadline.map_or(0, CounterTick::raw));
        let receipt = carrick_core::entry::publish_handoff_park(
            start,
            &guard,
            carrick_core_abi::EntryRecordGeneration(sequence),
        );
        drop(guard);
        let Some(receipt) = receipt else {
            return Some(
                self.entry
                    .run_failed(carrick_core_abi::NativeRunFailureReason::NativeStale),
            );
        };
        self.entry.handoff = Some(receipt);
        zone.clear_current(slot);
        zone.counters.el1_parks.fetch_add(1, Ordering::Relaxed);
        Some(LifecycleOutcome::Transferred {
            progress: carrick_core::Served::Idle,
            result: SyscallResult::new(0),
        })
    }
}
impl<'a, M: Clone, C: ProcessContext, S: NativeProcessService<'a, C, Mm = M>>
    NativeProcessEntry<'_, 'a, M, C, S>
{
    /// One wake authority for native futex syscalls and clear-child-tid.
    /// Unplaceable claims no waiter: transfer the same key/mask/count through
    /// the scheduler's existing custody, then retain native placement after
    /// dropping the bucket lock. A returning eligible driver consumes it.
    pub(super) fn wake_native_futex(
        &mut self,
        mm: carrick_core_abi::ReservationMm,
        key: MmFutexKey,
        bitset: u32,
        limit: u32,
    ) -> Result<u32, carrick_core_abi::NativeRunFailureReason> {
        let zone = self.source.zone;
        let guard = zone.short_lock(
            ZoneTables::<C>::bucket_of_with_context(mm.raw(), key.scheduler_address()),
            &carrick_sched_core::ShortLockSpin,
        );
        let mut effects = WakeEffects::default();
        let result = zone.wake_placed(
            &guard,
            mm.raw(),
            key.scheduler_address(),
            bitset,
            limit,
            Waker::El1 {
                slot: self.source.slot,
            },
            &mut [],
            &mut effects,
        );
        let result = match result {
            Err(carrick_sched_core::WakeRefusal::Unplaceable) => {
                // The first pass changed no waiter. Claim the exact key/mask/
                // count through scheduler transfer custody, then place each
                // completed native wait after releasing the bucket lock.
                let mut pending = Vec::new();
                let count = zone.wake_host(
                    &guard,
                    mm.raw(),
                    key.scheduler_address(),
                    bitset,
                    limit,
                    true,
                    &mut |transfer| pending.push(transfer),
                    &mut |placement| {
                        if placement.resched {
                            effects.request_reschedule(placement.slot);
                        }
                    },
                );
                drop(guard);
                for transfer in pending {
                    if let Some(record) =
                        transfer.finish(&carrick_sched_core::ShortLockSpin, &|owned| {
                            crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                        })
                    {
                        let Some(placement) = zone.place_native_handback(record) else {
                            return Err(carrick_core_abi::NativeRunFailureReason::NativeStale);
                        };
                        if placement.resched {
                            effects.request_reschedule(placement.slot);
                        }
                        effects.queued_own |= placement.slot == self.source.slot;
                    }
                }
                Ok(count)
            }
            result => {
                drop(guard);
                result
            }
        };
        self.service.wake_effects(effects);
        result.map_err(|_| carrick_core_abi::NativeRunFailureReason::NativeStale)
    }

    pub(super) fn serve_native_futex(
        &mut self,
        mut call: FutexCall,
        copy: &mut dyn UserCopy,
    ) -> Option<LifecycleOutcome> {
        let shared = call.shared_private_candidate();
        if let Some(candidate) = shared {
            call = candidate;
        }
        if !call.admitted() {
            return None;
        }
        let (now, frequency) = if call.args[3] != 0
            && call.args[1] == carrick_personality_linux::sched::FUTEX_WAIT_PRIVATE
        {
            (
                self.service.signal_now().ok()?,
                self.service.counter_frequency().ok()?,
            )
        } else {
            (CounterTick::new(0), FutexFrequency::from_hz(1))
        };
        let retained = self.take_relative_futex_wait();
        let mut adapter = Adapter {
            entry: self,
            copy: RefCell::new(copy),
            refusal: Cell::new(None),
            shared: shared.is_some(),
            mapping_refusal: None,
            now,
            frequency,
            retained,
        };
        let result = carrick_personality_linux::sched::serve_futex(call, &mut adapter);
        if let Some(error) = adapter.mapping_refusal {
            return Some(match error {
                NativeProcessError::OwnerWait(_) | NativeProcessError::Busy => {
                    if let Some(retained) = adapter.retained {
                        adapter.entry.retain_relative_futex_wait(retained);
                    }
                    let wait = match error {
                        NativeProcessError::OwnerWait(wait) => Some(wait),
                        _ => None,
                    };
                    adapter
                        .entry
                        .retry_guest_input(
                            carrick_core_abi::service::ServiceOperation::CarrierWork {
                                entry: OwnerEntry::Syscall,
                            },
                            None,
                            wait,
                        )
                        .unwrap_or_else(|error| {
                            adapter.entry.run_failed(error.run_failure_reason())
                        })
                }
                error => adapter.entry.run_failed(error.run_failure_reason()),
            });
        }
        match adapter.refusal.get() {
            Some(CopyOutcome::Fault) => {
                Some(returned(carrick_syscall_abi::LINUX_EFAULT.guest_retval()))
            }
            Some(CopyOutcome::NotYet(request)) => {
                if let Some(retained) = adapter.retained {
                    adapter.entry.retain_relative_futex_wait(retained);
                }
                Some(adapter.entry.wait_guest_copy(request))
            }
            Some(CopyOutcome::Done) => Some(
                adapter
                    .entry
                    .run_failed(carrick_core_abi::NativeRunFailureReason::NativeStale),
            ),
            None => result,
        }
    }
}
