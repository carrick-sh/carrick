//! Ring-owned owed-return settlement on HVF (#1369 slice 3).
//!
//! A native (ring-owned) fork child retires a resident `munmap`/`brk` shrink
//! in place and journals it as an owed return. Its frames stay with the
//! child's physical grants until the MM retires (no per-range stage-2 return
//! exists for a native MM), so settling an extent here is: observe its
//! retired terminals from the child's exact root (fallible, no effect), then
//! clear them, and acknowledge. It runs at every exclusion of a native
//! child's editor ([`settle_native_exclusion`]: the carrier's COW settlement
//! hook, the native COW supply and the child retire) and on the
//! `GRANT_OP_RETURN_SETTLE` doorbell ([`service_return_settlement`]), each
//! time after the MM's outstanding COW completions (#1482 P0-3), through the
//! one neutral sequence
//! ([`carrick_hal::return_settlement::settle_cow_then_returns`]).
//! One exclusion settles at most one chunk
//! ([`carrick_el1_abi::SETTLEMENT_CHUNK_PAGES`] owed pages, #1482); the
//! doorbell lowers and re-raises it between chunks within its one crossing.
//!
//! The host-served root is not settled here: its host venue settles at its
//! boundaries (`reconcile_el1_deferred_returns`), and its ring never rings.
//!
//! Lock order: the exclusion, then the carrier's settlement lock, then the
//! fork stock (read for the child's root and loans, then released: no loan
//! begins while the exclusion holds the editor), then the root guard inside
//! each journal step.
use super::*;
use carrick_el1_abi::{
    OwedReturnRetirement, Refusal, ReturnJournal, ReturnSettlementRequest,
    SettlementDoorbellAnswer, SettlementDoorbellReply,
};
use carrick_hal::return_settlement::{
    CowSettled, DrainOutcome, ExclusionSettlement, HolderRevisions, OwedReturnDrain,
    PauseSettlement, ReturnJournalAccess, pause_settlement, settle_cow_then_returns,
    settle_in_bounded_pauses, settle_ring_owned_returns,
};
use carrick_sched_core::spaces::notification::{
    ExclusionRefusal, SpaceAccess, SpaceReleaseVenue, SpaceWaitCause, SpaceWakeDelivery,
};
use core::sync::atomic::{AtomicU64, Ordering};

type Zone = carrick_sched_core::ZoneTables<carrick_el1_abi::Aarch64ParkedContext>;

/// One native child's journal through its root, held for each step alone.
struct NativeRootJournal<'a> {
    table: &'a carrick_el1::memory::reservations::SharedReservations,
    release: SpaceReleaseVenue<'a, carrick_el1_abi::Aarch64ParkedContext>,
    index: usize,
    mm: carrick_el1_abi::ReservationMm,
}
impl ReturnJournalAccess for NativeRootJournal<'_> {
    type Error = Refusal;
    fn with_journal<R>(
        &self,
        step: impl FnOnce(&mut dyn ReturnJournal) -> Result<R, Refusal>,
    ) -> Result<R, Refusal> {
        let mut journal =
            carrick_el1::memory::reservations::RootReleaseVenue::new(self.table, self.release)?
                .lock_returns(self.index, self.mm)?;
        step(&mut journal)
    }
}

/// The native child's retirement of owed extents: its stage-1 words resolved
/// through the carrier's physical custody of the child's table pages.
struct NativeOwedReturns<'a> {
    custody: &'a crate::trap::CarrierVmCustody,
    root: u64,
    failed: bool,
}
impl NativeOwedReturns<'_> {
    fn word(&self, pa: u64) -> Option<&AtomicU64> {
        let pointer = crate::fork_stock::ForkStockHostCustody::physical_ptr::<AtomicU64>(
            self.custody,
            carrick_guest_arch::FrameGpa::new(pa),
        )
        .ok()?;
        // SAFETY: physical custody resolved a complete, aligned word of a
        // retained table page; descriptor words are only accessed atomically.
        Some(unsafe { &*pointer })
    }
}
impl OwedReturnRetirement for NativeOwedReturns<'_> {
    type Prepared = Vec<carrick_el1::memory::RetiredTerminal>;
    type Error = carrick_el1::memory::OwedTerminalRefusal;
    fn prepare(
        &mut self,
        request: &ReturnSettlementRequest,
    ) -> Result<Self::Prepared, Self::Error> {
        let mut terminals = Vec::new();
        for owed in request.iter() {
            carrick_el1::memory::owed_retired_terminals::<carrick_el1::memory::ArmAnonymousDecode>(
                &|pa| self.word(pa).map(|word| word.load(Ordering::Acquire)),
                self.root,
                owed.range.start(),
                owed.range.len(),
                &mut |terminal| terminals.push(terminal),
            )?;
        }
        Ok(terminals)
    }
    fn apply(&mut self, terminals: Self::Prepared) {
        // Retired terminals are invalid: no walker caches them, so clearing
        // them needs no TLB maintenance.
        self.failed = !carrick_el1::memory::clear_retired_terminals(
            &|pa, current, new| {
                self.word(pa).map(|word| {
                    word.compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                })
            },
            &terminals,
        );
    }
}

/// The release venue every settlement publishes through: the runtime's
/// retained zone wake.
fn with_release<R>(
    custody: &crate::trap::CarrierVmCustody,
    zone: &Zone,
    f: impl FnOnce(SpaceReleaseVenue<'_, carrick_el1_abi::Aarch64ParkedContext>) -> R,
) -> Option<R> {
    let wake = custody.native_wait_channel_wake.lock().clone()?;
    let deliver = |zone: &Zone,
                   _: carrick_sched_core::Waker,
                   effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
        '_,
        carrick_el1_abi::Aarch64ParkedContext,
    >| wake.complete_mm_wake(zone, effects);
    Some(f(SpaceReleaseVenue {
        zone,
        waker: carrick_sched_core::Waker::Host,
        deliver: SpaceWakeDelivery::Captured(&deliver),
    }))
}

/// The carrier's venue of the one exclusion sequence: the excluded MM's
/// COW completions through `pool`, then a native child's owed returns.
struct NativeExclusion<'a> {
    custody: &'a std::sync::Arc<crate::trap::CarrierVmCustody>,
    pool: Option<&'a carrick_el1_abi::CowGrantPool>,
}
impl ExclusionSettlement for NativeExclusion<'_> {
    type Error = TrapError;
    type Returns = Option<PauseSettlement>;
    fn settle_cow_completions(
        &mut self,
        excluded: &carrick_sched_core::ExcludedEditor<'_>,
    ) -> Result<(), TrapError> {
        // No retained pool: nothing was ever granted, so nothing completed.
        self.pool.map_or(Ok(()), |pool| {
            crate::trap::settle_cow_completions(self.custody, pool, excluded)
        })
    }
    fn settle_owed_returns(
        &mut self,
        excluded: &carrick_sched_core::ExcludedEditor<'_>,
        cow: &CowSettled<'_>,
    ) -> Result<Option<PauseSettlement>, TrapError> {
        settle_native_returns(self.custody, excluded, cow)
    }
}

/// Every exclusion of an MM's editor obtained for settlement (#1482 P0-3):
/// its outstanding COW completions, then a native child's owed returns.
/// `Ok(None)`: the MM is not a live native child (the host-served root's
/// host venue settles its returns).
pub(crate) fn settle_native_exclusion(
    custody: &std::sync::Arc<crate::trap::CarrierVmCustody>,
    excluded: &carrick_sched_core::ExcludedEditor<'_>,
) -> Result<Option<PauseSettlement>, TrapError> {
    settle_native_exclusion_in(custody, carrick_el1_abi::cow_grant_pool_host(), excluded)
}

/// [`settle_native_exclusion`] through the carrier's own COW pool.
pub(crate) fn settle_native_exclusion_in(
    custody: &std::sync::Arc<crate::trap::CarrierVmCustody>,
    pool: Option<&carrick_el1_abi::CowGrantPool>,
    excluded: &carrick_sched_core::ExcludedEditor<'_>,
) -> Result<Option<PauseSettlement>, TrapError> {
    settle_cow_then_returns(&mut NativeExclusion { custody, pool }, excluded)
}

/// Settle a native child's owed returns under an exclusion of its editor,
/// after its COW completions. `Ok(None)`: the MM is not a live native
/// child. A skipped or contended settlement leaves the returns owed for a
/// later exclusion and is never the caller's failure.
fn settle_native_returns(
    custody: &crate::trap::CarrierVmCustody,
    excluded: &carrick_sched_core::ExcludedEditor<'_>,
    cow: &CowSettled<'_>,
) -> Result<Option<PauseSettlement>, TrapError> {
    let Some(mm) = carrick_el1_abi::ReservationMm::new(excluded.key()) else {
        return Ok(None);
    };
    let (Some(region), Some(zone)) = (retained_abi_region(custody), carrick_el1_abi::zone_tables())
    else {
        return Ok(None);
    };
    let (Some(table), Some(index)) = (retained_reservations(region), zone.spaces.find(mm.raw()))
    else {
        return Ok(None);
    };
    let guard = custody.return_settlement.lock(excluded);
    let stock = custody.fork_stock.lock();
    let Some(root) = stock
        .owner
        .child_root(mm)
        .filter(|_| !stock.owner.is_quarantined(mm))
    else {
        return Ok(None);
    };
    let loan_pending = stock.owner.loan_names(mm);
    // No loan can begin while this exclusion holds the MM's editor; the
    // stock lock is not held across the root guard's wake delivery.
    drop(stock);
    with_release(custody, zone, |release| {
        let journal = NativeRootJournal {
            table,
            release,
            index: index.index(),
            mm,
        };
        let mut backend = NativeOwedReturns {
            custody,
            root: root.address().raw(),
            failed: false,
        };
        let outcome =
            settle_ring_owned_returns(excluded, cow, &guard, loan_pending, &journal, &mut backend);
        if backend.failed {
            return Err(TrapError::Hypervisor(format!(
                "native owed return of MM {} changed under exclusion",
                mm.raw()
            )));
        }
        pause_settlement(&outcome).map(Some).ok_or_else(|| {
            TrapError::Hypervisor(format!(
                "native owed return of MM {} holds a live terminal: {outcome:?}",
                mm.raw()
            ))
        })
    })
    .unwrap_or(Ok(None))
}

/// `GRANT_OP_RETURN_SETTLE`: a ring thread of the stopped native child
/// claimed the single flight and needs its MM's owed returns settled.
/// Exclude, settle, then, whatever happened, release the claim and publish
/// `Reservations` (the exit epilogue), and answer in x1 to x3.
pub(super) fn service_return_settlement(
    custody: &std::sync::Arc<crate::trap::CarrierVmCustody>,
    generation: Option<crate::trap::CarrierVmGeneration>,
    cpu: carrick_guest_arch::CpuId,
    args: [u64; 3],
    ttbr0: u64,
) -> [u64; 4] {
    use carrick_el1_abi::METADATA_GRANT_ERR_DENIED;
    let (Some(region), Some(zone)) = (retained_abi_region(custody), carrick_el1_abi::zone_tables())
    else {
        return [METADATA_GRANT_ERR_DENIED, 0, 0, 0];
    };
    let binding = stopped_records(region, cpu)
        .map(|(task, _)| carrick_core::entry::binding(&task.execution, &task.mm));
    let (Some(mm), Some(claim)) = (
        carrick_el1_abi::ReservationMm::new(args[0]),
        u32::try_from(args[2])
            .ok()
            .and_then(|slot| carrick_el1_abi::SettlementClaim::from_wire(slot, args[1])),
    ) else {
        return [METADATA_GRANT_ERR_DENIED, 0, 0, 0];
    };
    let child_root = custody.fork_stock.lock().owner.child_root(mm);
    let own = request_has_live_vm(custody, generation)
        && binding.is_some_and(|binding| binding.mm.raw() == mm.raw())
        && child_root.is_some_and(|root| {
            root.address().raw() == ttbr0 & carrick_sched_core::AARCH64_ROOT_ADDRESS_MASK
        });
    let answer = carrick_hal::return_settlement::service_settlement_doorbell(
        &mut NativeDoorbell {
            custody,
            region,
            zone,
        },
        mm,
        claim,
        own,
    );
    match answer {
        Ok(answer) => {
            let [word, holder, revision] = answer.to_words();
            [METADATA_GRANT_SUCCESS, word, holder, revision]
        }
        _ => [METADATA_GRANT_ERR_DENIED, 0, 0, 0],
    }
}

struct NativeDoorbell<'a> {
    custody: &'a std::sync::Arc<crate::trap::CarrierVmCustody>,
    region: RetainedAbiRegion<'a>,
    zone: &'a Zone,
}
impl carrick_hal::return_settlement::SettlementDoorbellService for NativeDoorbell<'_> {
    type Error = TrapError;
    fn settle(
        &mut self,
        mm: carrick_el1_abi::ReservationMm,
    ) -> Result<SettlementDoorbellAnswer, TrapError> {
        settle_at_doorbell(self.custody, self.zone, mm).and_then(|reply| {
            if reply == SettlementDoorbellReply::Settled {
                drain_owed_return_table(self.custody, self.region, self.zone, mm)
            } else {
                Ok(reply.into())
            }
        })
    }
    fn release(
        &mut self,
        mm: carrick_el1_abi::ReservationMm,
        claim: carrick_el1_abi::SettlementClaim,
    ) -> Result<(), TrapError> {
        if release_settlement_claim(self.custody, self.region, self.zone, mm, claim) {
            Ok(())
        } else {
            Err(TrapError::Hypervisor(
                "settlement claim release failed".into(),
            ))
        }
    }
}

fn settle_at_doorbell(
    custody: &std::sync::Arc<crate::trap::CarrierVmCustody>,
    zone: &Zone,
    mm: carrick_el1_abi::ReservationMm,
) -> Result<SettlementDoorbellReply, TrapError> {
    let Some(index) = zone.spaces.find(mm.raw()) else {
        return Ok(SettlementDoorbellReply::Stale);
    };
    with_release(custody, zone, |release| {
        // A live ring editor of the MM: the ring observed `Editor` before it
        // rang, so it parks at that revision and reruns on the release. No
        // exit spins on it. Each chunk takes its own exclusion, lowered
        // before the next is raised (#1482).
        settle_in_bounded_pauses::<TrapError>(|| {
            match SpaceAccess::notified(release).try_exclude_editor(index, mm.raw()) {
                Ok(exclusion) => {
                    let settled = settle_native_exclusion(custody, exclusion.proof())?;
                    drop(exclusion);
                    Ok(settled.unwrap_or(PauseSettlement::answer(SettlementDoorbellReply::Stale)))
                }
                Err(ExclusionRefusal::Busy) => {
                    Ok(PauseSettlement::answer(SettlementDoorbellReply::Editor))
                }
                Err(ExclusionRefusal::Stale) => {
                    Ok(PauseSettlement::answer(SettlementDoorbellReply::Stale))
                }
            }
        })
    })
    .unwrap_or(Ok(SettlementDoorbellReply::Stale))
}

/// The HVF venue of the one neutral drain: the shared table, each native
/// holder's live source in the zone, and the carrier's bounded doorbell
/// drive.
struct NativeDrain<'a> {
    custody: &'a std::sync::Arc<crate::trap::CarrierVmCustody>,
    table: &'a carrick_el1::memory::reservations::SharedReservations,
    zone: &'a Zone,
}
impl OwedReturnDrain for NativeDrain<'_> {
    type Error = TrapError;
    fn table_full(&self) -> bool {
        self.table.owed_return_table_full()
    }
    fn observe(&mut self, holder: carrick_el1_abi::ReservationMm) -> Option<HolderRevisions> {
        let source = self
            .zone
            .space_entry(core::num::NonZeroU64::new(holder.raw())?)?
            .live_notifications()
            .ok()?;
        Some(HolderRevisions {
            editor: source.observe(SpaceWaitCause::Editor).revision(),
            reservations: source.observe(SpaceWaitCause::Reservations).revision(),
            pending_edit: source.observe(SpaceWaitCause::PendingEdit).revision(),
        })
    }
    fn settle(
        &mut self,
        holder: carrick_el1_abi::ReservationMm,
    ) -> Result<SettlementDoorbellReply, TrapError> {
        settle_at_doorbell(self.custody, self.zone, holder)
    }
}

/// The shared owed-return table is full of other MMs' slots: the one
/// neutral drain ([`carrick_hal::return_settlement::drain_owed_return_table`])
/// settles the other native holders, oldest first, one MM's exclusions at a
/// time. When none could free a slot, the answer is the oldest refusing
/// holder's wait authority, so the caller waits on the holder that prevents
/// progress (#1482 P0-1). The host-served root's slots settle at its host
/// venue (it answers stale here); retired MMs' slots wait for their release
/// receipts.
fn drain_owed_return_table(
    custody: &std::sync::Arc<crate::trap::CarrierVmCustody>,
    region: RetainedAbiRegion<'_>,
    zone: &Zone,
    caller: carrick_el1_abi::ReservationMm,
) -> Result<SettlementDoorbellAnswer, TrapError> {
    let Some(table) = retained_reservations(region) else {
        return Ok(SettlementDoorbellReply::Settled.into());
    };
    if !table.owed_return_table_full() {
        return Ok(SettlementDoorbellReply::Settled.into());
    }
    let mut holders = Vec::new();
    table.owed_return_holders(caller, &mut |holder| holders.push(holder));
    let outcome = carrick_hal::return_settlement::drain_owed_return_table(
        &mut NativeDrain {
            custody,
            table,
            zone,
        },
        &holders,
    )?;
    Ok(match outcome {
        DrainOutcome::Wait(wait) => SettlementDoorbellAnswer::Holder(wait),
        // Room, or only retiring holders whose release receipts free their
        // slots: rerun.
        DrainOutcome::Room | DrainOutcome::Retiring => SettlementDoorbellReply::Settled.into(),
    })
}

/// The doorbell's exit epilogue: release the claim from its exact word and
/// publish the MM's `Reservations` release. A claim no longer held changes
/// nothing. `false` only when the release could not be published.
fn release_settlement_claim(
    custody: &crate::trap::CarrierVmCustody,
    region: RetainedAbiRegion<'_>,
    zone: &Zone,
    mm: carrick_el1_abi::ReservationMm,
    claim: carrick_el1_abi::SettlementClaim,
) -> bool {
    let Some(table) = retained_reservations(region) else {
        return false;
    };
    if !table.release_return_settlement(claim) {
        return true;
    }
    publish_space_release(custody, zone, mm, SpaceWaitCause::Reservations)
}

/// Publish one release cause on `mm`'s live notification source. An MM with
/// no live source has no waiter to wake.
pub(super) fn publish_space_release(
    custody: &crate::trap::CarrierVmCustody,
    zone: &Zone,
    mm: carrick_el1_abi::ReservationMm,
    cause: SpaceWaitCause,
) -> bool {
    let Some(source) = core::num::NonZeroU64::new(mm.raw())
        .and_then(|mm| zone.space_entry(mm))
        .and_then(|entry| entry.live_notifications().ok())
    else {
        return true;
    };
    with_release(custody, zone, |release| {
        release.publish(source.reserve(cause))
    })
    .is_some()
}
