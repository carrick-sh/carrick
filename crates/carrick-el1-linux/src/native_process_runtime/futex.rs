//! Native Linux futex service over the existing typed scheduler and MM owners.
use super::*;
use carrick_core::user_copy::{CopyOutcome, GuestCopyRequest, UserCopy};
use carrick_guest_arch::{Access, CounterTick, GuestLen};
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
    now: CounterTick,
    frequency: FutexFrequency,
    retained: Option<RelativeFutexWait>,
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
            refusal => {
                self.refusal.set(Some(refusal));
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
        let key = if self.shared {
            MmFutexKey::shared_private(address)?
        } else {
            MmFutexKey::private(address)?
        };
        let zone = self.entry.source.zone;
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
                slot: self.entry.source.slot,
            },
            &mut [],
            &mut effects,
        );
        drop(guard);
        self.entry.service.wake_effects(effects);
        match result {
            Ok(count) => Some(returned(i64::from(count))),
            Err(_) => Some(
                self.entry
                    .run_failed(carrick_core_abi::NativeRunFailureReason::NativeStale),
            ),
        }
    }
    fn wait(&mut self, wait: FutexWait) -> Option<LifecycleOutcome> {
        if let Some(deadline) = wait.deadline {
            self.retained = Some(RelativeFutexWait { deadline });
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
            return Some(returned(-11));
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
    pub(super) fn serve_native_futex(
        &mut self,
        mut call: FutexCall,
        copy: &mut dyn UserCopy,
    ) -> Option<LifecycleOutcome> {
        let shared = call.shared_private_candidate();
        if let Some(candidate) = shared {
            let mm = self
                .runtime
                .graph
                .lock()
                .owner
                .task(self.key)
                .ok()?
                .native()
                .resources()
                .mm
                .clone();
            match self
                .service
                .futex_shared_private(&mm, UserVa::new(call.args[0]))
            {
                Ok(true) => call = candidate,
                Ok(false) => return None,
                Err(NativeProcessError::OwnerWait(_) | NativeProcessError::Busy) => {
                    return Some(self.wait_guest_copy(GuestCopyRequest {
                        address: UserVa::new(call.args[0]),
                        len: GuestLen::new(4),
                        access: Access::Read,
                    }));
                }
                Err(error) => return Some(self.run_failed(error.run_failure_reason())),
            }
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
            now,
            frequency,
            retained,
        };
        let result = carrick_personality_linux::sched::serve_futex(call, &mut adapter);
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
