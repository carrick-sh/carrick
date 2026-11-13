//! Ring-owned owed-return settlement on x86 CPL0 (#1369 slice 3).
//!
//! Every x86 MM is ring-owned: EL1 retires a resident `munmap`/`brk` shrink
//! in place and journals it as an owed return, and only this carrier can
//! settle it. Settlement runs at every exclusion of an MM's editor
//! ([`Cpl0HostCustody::settled_pause`] is the only way to obtain one), and a
//! ring thread that cannot proceed without it rings the owner-grant port's
//! settlement op ([`Cpl0HostCustody::service_return_settlement`]).
//!
//! The physical step: under the exclusion, observe each owed extent's retired
//! terminals from the MM's exact root, then clear them and drop the carrier's
//! alias edges for the span. Frames stay in their backing slots, admitted for
//! the MM, and return with its retirement, as on HVF. Lock order: exclusion,
//! then the settlement lock, then the fork stock (read under the custody
//! lock the caller holds), then the root guard, held only inside the journal
//! steps.
use super::*;
use carrick_el1::memory::{RetiredTerminal, X86AnonymousDecode, owed_retired_terminals};
use carrick_el1_abi::{
    OwedReturnRetirement, Refusal, ReturnJournal, ReturnSettlementDoorbell,
    ReturnSettlementRequest, SettlementDoorbellReply,
};
use carrick_hal::return_settlement::{
    ReturnJournalAccess, doorbell_reply, settle_ring_owned_returns,
};
use carrick_mmu_core::x86::descriptor_txn::LiveDescriptorWords;
use carrick_sched_core::spaces::notification::{ExclusionRefusal, SpaceWaitCause};

/// What this carrier's settlements did, for witnesses (deterministic counts).
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::default::Default,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct ReturnSettlementCounters {
    /// Settlement doorbells rung by ring threads.
    pub doorbells: u64,
    /// Exclusions that ran a settlement (doorbells included).
    pub exclusions: u64,
    /// Owed extents settled (slots freed or advanced).
    pub extents: u64,
    /// Settlements skipped for a pending fork loan.
    pub fork_loan_skips: u64,
    /// Doorbells refused because a ring editor of the MM was active.
    pub editor_contended: u64,
    /// Other MMs a full owed-return table's drain settled.
    pub drained_holders: u64,
}

/// One exclusion of an MM's EL1 editor that has settled the MM's owed
/// returns. Only [`Cpl0HostCustody::settled_pause`] builds one.
pub(super) struct CowPause<'a> {
    exclusion: carrick_sched_core::spaces::notification::SpaceExclusion<
        'a,
        carrick_sched_core::ParkedContextWords,
    >,
}
impl CowPause<'_> {
    pub(super) fn proof(&self) -> &carrick_el1_abi::ExcludedEditor<'_> {
        self.exclusion.proof()
    }
}

/// A raw exclusion before its settlement ran; private to this module.
fn exclude<'a>(
    access: SpaceAccess<'a, carrick_sched_core::ParkedContextWords>,
    mm: carrick_el1_abi::ReservationMm,
) -> Result<CowPause<'a>, ExclusionRefusal> {
    let index = access
        .table()
        .find(mm.raw())
        .ok_or(ExclusionRefusal::Stale)?;
    Ok(CowPause {
        exclusion: access.try_exclude_editor(index, mm.raw())?,
    })
}

/// A raw exclusion for VM-free custody tests of the gate itself.
#[cfg(test)]
pub(super) fn unsettled_pause_for_test(
    access: SpaceAccess<'_, carrick_sched_core::ParkedContextWords>,
    mm: u64,
) -> Result<CowPause<'_>, ExclusionRefusal> {
    exclude(
        access,
        carrick_el1_abi::ReservationMm::new(mm).ok_or(ExclusionRefusal::Stale)?,
    )
}

/// One MM's journal through its root, held for each step alone.
struct RingRootJournal<'a> {
    table: &'a X86Cpl0Reservations,
    release: SpaceReleaseVenue<'a, carrick_sched_core::ParkedContextWords>,
    index: usize,
    mm: carrick_el1_abi::ReservationMm,
}
impl ReturnJournalAccess for RingRootJournal<'_> {
    type Error = Refusal;
    fn with_journal<R>(
        &self,
        step: impl FnOnce(&mut dyn ReturnJournal) -> Result<R, Refusal>,
    ) -> Result<R, Refusal> {
        let mut journal = carrick_el1::memory::reservations::X86Cpl0RootReleaseVenue::new(
            self.table,
            self.release,
        )?
        .lock_returns(self.index, self.mm)?;
        step(&mut journal)
    }
}

/// The CPL0 venue's retirement of owed extents: observe every extent's
/// retired terminals (fallible, no effect), then clear them and drop their
/// alias edges (the one apply; a word changed under the exclusion
/// quarantines the carrier and is reported after the transaction).
struct Cpl0OwedReturns<'a, M: CarrierMemoryIo> {
    memory: &'a mut CarrierMemory<M>,
    mm: NonZeroU64,
    root: RootGpa,
    failed: Option<String>,
}
impl<M: CarrierMemoryIo> OwedReturnRetirement for Cpl0OwedReturns<'_, M> {
    type Prepared = Vec<(PageSpan, Vec<RetiredTerminal>)>;
    type Error = String;
    fn prepare(&mut self, request: &ReturnSettlementRequest) -> Result<Self::Prepared, String> {
        let words = self.memory.words();
        request
            .iter()
            .map(|owed| {
                let (start, len) = (owed.range.start(), owed.range.len());
                let mut terminals = Vec::new();
                owed_retired_terminals::<X86AnonymousDecode>(
                    &|pa| words.load(pa).ok(),
                    self.root.address().raw(),
                    start,
                    len,
                    &mut |terminal| terminals.push(terminal),
                )
                .map_err(|reason| {
                    format!("owed return [{start:#x}, +{len:#x}) holds a live terminal: {reason:?}")
                })?;
                Ok((PageSpan::new(start, len), terminals))
            })
            .collect()
    }
    fn apply(&mut self, prepared: Self::Prepared) {
        for (span, terminals) in prepared {
            if let Err(error) = self
                .memory
                .clear_settled_return(self.mm, self.root, span, &terminals)
            {
                self.failed.get_or_insert(error.to_string());
            }
        }
    }
}

impl<M: CarrierMemoryIo> Cpl0HostCustody<M> {
    /// Exclude `mm`'s EL1 editor and settle its owed returns under that
    /// exclusion: the only way this carrier obtains an exclusion, so every
    /// host operation on a ring-owned MM sees its owed returns settled
    /// (#1369 slice 3, item 1). The reply says what the settlement did; a
    /// skipped or contended settlement leaves the returns owed for a later
    /// exclusion and is never the caller's failure.
    pub(super) fn settled_pause<'a>(
        &mut self,
        release: SpaceReleaseVenue<'a, carrick_sched_core::ParkedContextWords>,
        mm: carrick_el1_abi::ReservationMm,
    ) -> Result<Result<(CowPause<'a>, SettlementDoorbellReply), ExclusionRefusal>, TrapError> {
        let pause = match exclude(SpaceAccess::notified(release), mm) {
            Ok(pause) => pause,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let reply = self.settle_excluded(release, pause.proof())?;
        Ok(Ok((pause, reply)))
    }

    /// [`Self::settled_pause`] for callers that treat a refused exclusion
    /// as a carrier fault.
    pub(super) fn settled_pause_or_fail<'a>(
        &mut self,
        release: SpaceReleaseVenue<'a, carrick_sched_core::ParkedContextWords>,
        mm: u64,
    ) -> Result<CowPause<'a>, TrapError> {
        let mm = carrick_el1_abi::ReservationMm::new(mm).ok_or_else(|| fail("owner COW MM"))?;
        self.settled_pause(release, mm)?
            .map(|(pause, _)| pause)
            .map_err(|reason| fail(format!("owner COW editor exclusion refused: {reason:?}")))
    }

    fn settle_excluded(
        &mut self,
        release: SpaceReleaseVenue<'_, carrick_sched_core::ParkedContextWords>,
        excluded: &carrick_el1_abi::ExcludedEditor<'_>,
    ) -> Result<SettlementDoorbellReply, TrapError> {
        let (Some(mm), Some(key)) = (
            carrick_el1_abi::ReservationMm::new(excluded.key()),
            NonZeroU64::new(excluded.key()),
        ) else {
            return Ok(SettlementDoorbellReply::Stale);
        };
        let ram = Arc::clone(&self.ram);
        let table = retained_reservations(&ram)?;
        let (Some(index), Some(context)) = (release.zone.spaces.find(mm.raw()), self._vm.root(key))
        else {
            return Ok(SettlementDoorbellReply::Stale);
        };
        if !table.admitted(index.index(), mm) {
            // No admitted root delegates this MM's memory: nothing is owed.
            return Ok(SettlementDoorbellReply::Settled);
        }
        self.return_settlement_counters.exclusions += 1;
        let guard = self.return_settlement.lock(excluded);
        let loan_pending = self.fork_stock.loan_names(mm);
        let journal = RingRootJournal {
            table,
            release,
            index: index.index(),
            mm,
        };
        let mut backend = Cpl0OwedReturns {
            memory: &mut self._vm,
            mm: key,
            root: context.root,
            failed: None,
        };
        let outcome =
            settle_ring_owned_returns(excluded, &guard, loan_pending, &journal, &mut backend);
        if let Some(error) = backend.failed {
            return Err(fail(format!("owed return settlement apply: {error}")));
        }
        match &outcome {
            Ok(carrick_el1_abi::SettlementOutcome::Settled(receipt)) => {
                self.return_settlement_counters.extents +=
                    (receipt.freed + receipt.advanced) as u64;
            }
            Ok(carrick_el1_abi::SettlementOutcome::Skipped(_)) => {
                self.return_settlement_counters.fork_loan_skips += 1;
            }
            _ => {}
        }
        doorbell_reply(&outcome).ok_or_else(|| match outcome {
            Err(carrick_hal::return_settlement::ReturnSettlementError::Backend(error)) => {
                fail(format!("owed return settlement: {error}"))
            }
            _ => fail("owed return settlement"),
        })
    }

    /// The owner-grant port's settlement op: a ring thread of the stopped
    /// execution's MM claimed the single flight and needs that MM's owed
    /// returns settled. Exclude, settle, then, whatever happened, release
    /// the claim and publish `Reservations` (the exit epilogue), and answer.
    pub(super) fn service_return_settlement<I: CarrierCpuIo>(
        &mut self,
        lease: &StoppedCpuLease<'_, I>,
        execution: GrantExecution,
    ) -> Result<(), TrapError> {
        let address = lease.io.get_gpr(X86Reg::Rsi)?;
        // SAFETY: the doorbell record is six fully initialized u64 words.
        let (physical, mut record) = unsafe {
            self.read_stack_record::<ReturnSettlementDoorbell, I>(lease, execution.context, address)
        }?;
        self.return_settlement_counters.doorbells += 1;
        let reply = match record.decode() {
            Some((mm, claim)) => {
                let settled = if mm.raw() == execution.context.mm.raw().get() {
                    self.ring_settlement(mm).and_then(|reply| {
                        if reply == SettlementDoorbellReply::Settled {
                            self.drain_owed_return_table(mm)?;
                        }
                        Ok(reply)
                    })
                } else {
                    // Not the stopped execution's MM: no effect.
                    Ok(SettlementDoorbellReply::Stale)
                };
                // The epilogue releases the claim the record names whatever
                // happened: an exact-word compare-and-swap, so a stale word
                // never releases a newer claim.
                let released = self.release_settlement_claim(mm, claim);
                let reply = settled?;
                released?;
                reply
            }
            None => SettlementDoorbellReply::Stale,
        };
        if reply == SettlementDoorbellReply::Editor {
            self.return_settlement_counters.editor_contended += 1;
        }
        record.answer(reply);
        // SAFETY: the record is a fully initialized array of six u64 words.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const record).cast::<u8>(),
                size_of::<ReturnSettlementDoorbell>(),
            )
        };
        self._vm
            .write(physical, bytes)
            .map_err(|e| fail(e.to_string()))
    }

    /// The shared owed-return table is full of other MMs' slots, so the
    /// caller's settled journal still cannot take a retirement: settle the
    /// other holders, one exclusion at a time (never holding one MM's
    /// exclusion while raising another's), until a slot is free. A holder
    /// whose ring editor is active is skipped: its editor section never
    /// blocks, and the caller's rerun rings again if the table is still
    /// full. Retired MMs' slots wait for their release receipts.
    fn drain_owed_return_table(
        &mut self,
        caller: carrick_el1_abi::ReservationMm,
    ) -> Result<(), TrapError> {
        let ram = Arc::clone(&self.ram);
        let table = retained_reservations(&ram)?;
        if !table.owed_return_table_full() {
            return Ok(());
        }
        let mut holders = Vec::new();
        table.owed_return_holders(caller, &mut |holder| holders.push(holder));
        for holder in holders {
            self.return_settlement_counters.drained_holders += 1;
            self.ring_settlement(holder)?;
            if !table.owed_return_table_full() {
                break;
            }
        }
        Ok(())
    }

    fn ring_settlement(
        &mut self,
        mm: carrick_el1_abi::ReservationMm,
    ) -> Result<SettlementDoorbellReply, TrapError> {
        let ram = Arc::clone(&self.ram);
        let zone = retained_cow_zone(&ram)?;
        let wake = HostCowWake::new(&ram, self._vm.clone_vm())?;
        let delivery = |zone: &X86Cpl0Zone,
                        waker: Waker,
                        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| wake.deliver(zone, waker, owned);
        let release = SpaceReleaseVenue {
            zone,
            waker: Waker::Host,
            deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                &delivery,
            ),
        };
        // A live ring editor of the MM: the ring observed `Editor` before it
        // rang, so it parks at that revision and reruns on the release. No
        // exit spins on it.
        let reply = match self.settled_pause(release, mm)? {
            Ok((pause, reply)) => {
                drop(pause);
                reply
            }
            Err(ExclusionRefusal::Busy) => SettlementDoorbellReply::Editor,
            Err(ExclusionRefusal::Stale) => SettlementDoorbellReply::Stale,
        };
        wake.finish()?;
        Ok(reply)
    }

    /// The doorbell's exit epilogue: release the claim from its exact word
    /// and publish the MM's `Reservations` release, so a sibling refuser
    /// that enrolled on the in-flight claim reruns. A claim no longer held
    /// (a stale record) changes nothing.
    fn release_settlement_claim(
        &mut self,
        mm: carrick_el1_abi::ReservationMm,
        claim: carrick_el1_abi::SettlementClaim,
    ) -> Result<(), TrapError> {
        let ram = Arc::clone(&self.ram);
        let table = retained_reservations(&ram)?;
        if !table.release_return_settlement(claim) {
            return Ok(());
        }
        self.publish_space_release(mm, SpaceWaitCause::Reservations)
    }

    /// Publish one release cause on `mm`'s live notification source through
    /// the host waker. An MM with no live source has no waiter to wake.
    pub(super) fn publish_space_release(
        &mut self,
        mm: carrick_el1_abi::ReservationMm,
        cause: SpaceWaitCause,
    ) -> Result<(), TrapError> {
        let ram = Arc::clone(&self.ram);
        let zone = retained_cow_zone(&ram)?;
        let Some(source) = NonZeroU64::new(mm.raw())
            .and_then(|mm| zone.space_entry(mm))
            .and_then(|entry| entry.live_notifications().ok())
        else {
            return Ok(());
        };
        let wake = HostCowWake::new(&ram, self._vm.clone_vm())?;
        let delivery = |zone: &X86Cpl0Zone,
                        waker: Waker,
                        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >| wake.deliver(zone, waker, owned);
        SpaceReleaseVenue {
            zone,
            waker: Waker::Host,
            deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Captured(
                &delivery,
            ),
        }
        .publish(source.reserve(cause));
        wake.finish()
    }
}
