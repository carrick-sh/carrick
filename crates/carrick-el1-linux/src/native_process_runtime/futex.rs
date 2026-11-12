//! Native Linux futex service over the existing typed scheduler and MM owners.
use super::*;
use carrick_core::user_copy::{CopyOutcome, UserCopy};
use carrick_guest_arch::CounterTick;
use carrick_personality_linux::sched::{
    FutexCall, FutexFrequency, FutexVenue, FutexWait, MmFutexKey, RelativeFutexWait,
};
use core::cell::{Cell, RefCell};

/// Whether `address` is a private anonymous mapping of the admitted MM.
///
/// The mapping root is acquired through the existing authenticated portal
/// protocol: the caller supplies the MM handle it already authenticated, and
/// the portal observes that handle's `Reservations` source before probing the
/// root lock. A held root therefore returns the holder's exact
/// [`carrick_core_abi::PortalOwnerWait`] for the caller to enrol on, never a
/// bare `Busy` that would send the syscall back through a checkpoint retry.
pub fn private_anonymous_futex_mapping<P, Policy, Geometry, Venue, B, C>(
    portal: &carrick_core::mm::transaction::MmPortal<'_, P, Policy, Geometry, Venue, B, C>,
    handle: carrick_core_abi::El1MmHandle,
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
    let mut root = portal.root_for(handle, slot).map_err(|error| match error {
        carrick_core::mm::transaction::MmError::Wait(wait) => NativeProcessError::OwnerWait(wait),
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
    mapping_refusal: Option<LifecycleOutcome>,
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
        let retained = self.retained.as_ref().map(|wait| RelativeFutexWait {
            deadline: wait.deadline,
        });
        match self.entry.authenticate_shared_futex(address, retained) {
            Ok(admitted) => Some(admitted),
            Err(outcome) => {
                self.mapping_refusal = Some(outcome);
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
    ) -> LifecycleOutcome {
        // `serve_native_futex` authenticated a shared candidate's mapping
        // before policy: an admitted wake always finishes here (#1941).
        // Admission requires an aligned word, so a key always exists.
        let key = if self.shared {
            MmFutexKey::shared_private(address)
        } else {
            MmFutexKey::private(address)
        };
        let Some(key) = key else {
            return returned(carrick_syscall_abi::LINUX_EINVAL.guest_retval());
        };
        returned(i64::from(
            self.entry.wake_native_futex(mm, key, bitset, limit),
        ))
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
    /// An EL1 wake always finishes in the ring (#1941): a waiter no guest
    /// slot may run now is queued on the slot that owns it, stopped,
    /// contended or busy (`ZoneTables::owner_candidates`), whose driver
    /// runs it when that slot is in the guest again; never on a waker whose
    /// CPU its affinity excludes, since no host boundary relocates the
    /// waker's queue: with no driven slot to own it, it goes to the host.
    pub(super) fn wake_native_futex(
        &mut self,
        mm: carrick_core_abi::ReservationMm,
        key: MmFutexKey,
        bitset: u32,
        limit: u32,
    ) -> u32 {
        let zone = self.source.zone;
        let guard = zone.short_lock(
            ZoneTables::<C>::bucket_of_with_context(mm.raw(), key.scheduler_address()),
            &carrick_sched_core::ShortLockSpin,
        );
        let mut effects = WakeEffects::default();
        let count = zone.wake_placed(
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
        drop(guard);
        self.service.wake_effects(effects);
        count
    }

    /// The one shared-private admission for both ISAs (#2124): a shared
    /// futex word keys as [`MmFutexKey::shared_private`] only after the
    /// memory owner authenticates private anonymous storage in this task's
    /// MM. Owner contention retains `retained` and retries the syscall on
    /// the holder's wait; any other refusal fails the run.
    pub(super) fn authenticate_shared_futex(
        &mut self,
        address: UserVa,
        retained: Option<RelativeFutexWait>,
    ) -> Result<bool, LifecycleOutcome> {
        let Ok(mm) = self
            .runtime
            .graph
            .lock()
            .owner
            .task(self.key)
            .map(|task| task.native().resources().mm.clone())
        else {
            return Ok(false);
        };
        match self.service.futex_shared_private(&mm, address) {
            Ok(admitted) => Ok(admitted),
            Err(NativeProcessError::OwnerWait(wait)) => {
                if let Some(retained) = retained {
                    self.retain_relative_futex_wait(retained);
                }
                Err(self
                    .retry_guest_input(
                        carrick_core_abi::service::ServiceOperation::CarrierWork {
                            entry: OwnerEntry::Syscall,
                            demand: carrick_core_abi::service::CarrierDemand::Work,
                        },
                        None,
                        Some(wait),
                    )
                    .unwrap_or_else(|error| self.run_failed(error.run_failure_reason())))
            }
            // A live portal always observes its Reservations source before
            // the root probe, so mapping contention cannot reach here as a
            // bare `Busy`. Treat it as the invariant break it is instead of
            // adding a waitless checkpoint-retry second path.
            Err(error) => Err(self.run_failed(error.run_failure_reason())),
        }
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
        let wake = call.args[1] == carrick_personality_linux::sched::FUTEX_WAKE_PRIVATE
            || call.args[1] == carrick_personality_linux::sched::FUTEX_WAKE_BITSET_PRIVATE;
        let result = if shared.is_some()
            && wake
            && adapter.authenticate_mapping(UserVa::new(call.args[0])) != Some(true)
        {
            None
        } else {
            carrick_personality_linux::sched::serve_futex(call, &mut adapter)
        };
        if let Some(outcome) = adapter.mapping_refusal {
            return Some(outcome);
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
