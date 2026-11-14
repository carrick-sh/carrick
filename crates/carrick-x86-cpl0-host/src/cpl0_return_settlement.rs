//! Ring-owned owed-return settlement on x86 CPL0 (#1369 slice 3).
//!
//! Every x86 MM is ring-owned: EL1 retires a resident `munmap`/`brk` shrink
//! in place and journals it as an owed return, and only this carrier can
//! settle it. Settlement runs at every exclusion of an MM's editor
//! ([`Cpl0HostCustody::settled_pause`] is the only way to obtain one), and a
//! ring thread that cannot proceed without it rings the owner-grant port's
//! settlement op ([`Cpl0HostCustody::service_return_settlement`]). Every
//! such exclusion settles the MM's outstanding COW completions first and its
//! owed returns second, through the one neutral sequence
//! ([`carrick_hal::return_settlement::settle_cow_then_returns`], #1482 P0-3):
//! a sibling may have retired a replacement leaf whose completion is still
//! outstanding.
//!
//! The physical step: under the exclusion, observe each owed extent's retired
//! terminals from the MM's exact root, then clear them and drop the carrier's
//! alias edges for the span. One exclusion covers at most one chunk
//! ([`carrick_el1_abi::SETTLEMENT_CHUNK_PAGES`] owed pages, #1482); the
//! doorbell lowers and re-raises it between chunks. Frames stay in their
//! backing slots, admitted for the MM, and return with its retirement, as on
//! HVF. Lock order: exclusion,
//! then the settlement lock, then the fork stock (read under the custody
//! lock the caller holds), then the root guard, held only inside the journal
//! steps.
use super::*;
use carrick_el1::memory::{RetiredTerminal, X86AnonymousDecode, owed_retired_terminals};
use carrick_el1_abi::{
    OwedReturnRetirement, Refusal, ReturnJournal, ReturnSettlementDoorbell,
    ReturnSettlementRequest, SettlementDoorbellAnswer, SettlementDoorbellReply,
};
use carrick_hal::return_settlement::{
    CowSettled, DrainOutcome, ExclusionSettlement, HolderRevisions, OwedReturnDrain,
    PauseSettlement, ReturnJournalAccess, drain_owed_return_table, pause_settlement,
    settle_cow_then_returns, settle_in_bounded_pauses, settle_ring_owned_returns,
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
    /// Maximum owed pages walked while one editor exclusion stayed raised.
    pub max_pause_pages: u64,
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
    /// Doorbells answered with a foreign holder's wait authority: a full
    /// table no holder could drain (#1482 P0-1).
    pub holder_waits: u64,
    /// Drains that found only retiring holders (no live source to wait on).
    pub drain_retiring: u64,
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
    pages: u64,
}
impl<M: CarrierMemoryIo> OwedReturnRetirement for Cpl0OwedReturns<'_, M> {
    type Prepared = Vec<(PageSpan, Vec<RetiredTerminal>)>;
    type Error = String;
    fn prepare(&mut self, request: &ReturnSettlementRequest) -> Result<Self::Prepared, String> {
        self.pages = request.iter().map(|owed| owed.range.len() / 4096).sum();
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

/// The CPL0 venue of the one exclusion sequence: the excluded MM's COW
/// completions, then its owed returns, under one exclusion.
struct Cpl0Exclusion<'v, 'a, M: CarrierMemoryIo> {
    custody: &'v mut Cpl0HostCustody<M>,
    release: SpaceReleaseVenue<'a, carrick_sched_core::ParkedContextWords>,
}
impl<M: CarrierMemoryIo> ExclusionSettlement for Cpl0Exclusion<'_, '_, M> {
    type Error = TrapError;
    type Returns = PauseSettlement;
    fn settle_cow_completions(
        &mut self,
        excluded: &carrick_el1_abi::ExcludedEditor<'_>,
    ) -> Result<(), TrapError> {
        self.custody.settle_cow_completions(excluded)
    }
    fn reclaim_retired_holders(
        &mut self,
        excluded: &carrick_sched_core::ExcludedEditor<'_>,
    ) -> Result<(), TrapError> {
        let active = carrick_el1_abi::ReservationMm::new(excluded.key())
            .ok_or_else(|| fail("settlement quarantine active MM"))?;
        self.custody.drain_fork_quarantine_in(active.into())
    }
    fn settle_owed_returns(
        &mut self,
        excluded: &carrick_el1_abi::ExcludedEditor<'_>,
        cow: &CowSettled<'_>,
    ) -> Result<PauseSettlement, TrapError> {
        self.custody
            .settle_owed_returns(self.release, excluded, cow)
    }
}

/// The CPL0 venue of the one neutral drain: the shared table, each holder's
/// live source in the zone, and the carrier's bounded doorbell drive.
struct Cpl0Drain<'a, M: CarrierMemoryIo> {
    custody: &'a mut Cpl0HostCustody<M>,
    table: &'a X86Cpl0Reservations,
}
impl<M: CarrierMemoryIo> OwedReturnDrain for Cpl0Drain<'_, M> {
    type Error = TrapError;
    fn table_full(&self) -> bool {
        self.table.owed_return_table_full()
    }
    fn observe(&mut self, holder: carrick_el1_abi::ReservationMm) -> Option<HolderRevisions> {
        let ram = Arc::clone(&self.custody.ram);
        let zone = retained_cow_zone(&ram).ok()?;
        let source = zone
            .space_entry(NonZeroU64::new(holder.raw())?)?
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
        self.custody.return_settlement_counters.drained_holders += 1;
        self.custody.ring_settlement(holder)
    }
}

struct Cpl0Doorbell<'a, M: CarrierMemoryIo>(&'a mut Cpl0HostCustody<M>);
impl<M: CarrierMemoryIo> carrick_hal::return_settlement::SettlementDoorbellService
    for Cpl0Doorbell<'_, M>
{
    type Error = TrapError;
    fn settle(
        &mut self,
        mm: carrick_el1_abi::ReservationMm,
    ) -> Result<SettlementDoorbellAnswer, TrapError> {
        self.0.ring_settlement(mm).and_then(|reply| {
            if reply == SettlementDoorbellReply::Settled {
                self.0.drain_owed_return_table(mm)
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
        self.0.release_settlement_claim(mm, claim)
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
    ) -> Result<Result<(CowPause<'a>, PauseSettlement), ExclusionRefusal>, TrapError> {
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

    /// Every exclusion's settlement: COW completions, then owed returns.
    fn settle_excluded(
        &mut self,
        release: SpaceReleaseVenue<'_, carrick_sched_core::ParkedContextWords>,
        excluded: &carrick_el1_abi::ExcludedEditor<'_>,
    ) -> Result<PauseSettlement, TrapError> {
        settle_cow_then_returns(
            &mut Cpl0Exclusion {
                custody: self,
                release,
            },
            excluded,
        )
    }

    fn settle_owed_returns(
        &mut self,
        release: SpaceReleaseVenue<'_, carrick_sched_core::ParkedContextWords>,
        excluded: &carrick_el1_abi::ExcludedEditor<'_>,
        cow: &CowSettled<'_>,
    ) -> Result<PauseSettlement, TrapError> {
        let (Some(mm), Some(key)) = (
            carrick_el1_abi::ReservationMm::new(excluded.key()),
            NonZeroU64::new(excluded.key()),
        ) else {
            return Ok(PauseSettlement::answer(SettlementDoorbellReply::Stale));
        };
        let ram = Arc::clone(&self.ram);
        let table = retained_reservations(&ram)?;
        let (Some(index), Some(context)) = (release.zone.spaces.find(mm.raw()), self._vm.root(key))
        else {
            return Ok(PauseSettlement::answer(SettlementDoorbellReply::Stale));
        };
        if !table.admitted(index.index(), mm) {
            // A root already retired can still hold shared-table slots until
            // its fork-quarantine release. No native journal was settled.
            return Ok(PauseSettlement::answer(SettlementDoorbellReply::Stale));
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
            pages: 0,
        };
        let outcome =
            settle_ring_owned_returns(excluded, cow, &guard, loan_pending, &journal, &mut backend);
        self.return_settlement_counters.max_pause_pages = self
            .return_settlement_counters
            .max_pause_pages
            .max(backend.pages);
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
        pause_settlement(&outcome).ok_or_else(|| match outcome {
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
        let answer = match record.decode() {
            Some((mm, claim)) => carrick_hal::return_settlement::service_settlement_doorbell(
                &mut Cpl0Doorbell(self),
                mm,
                claim,
                mm.raw() == execution.context.mm.raw().get(),
            )?,
            None => SettlementDoorbellReply::Stale.into(),
        };
        match answer {
            SettlementDoorbellAnswer::Own(SettlementDoorbellReply::Editor) => {
                self.return_settlement_counters.editor_contended += 1;
            }
            SettlementDoorbellAnswer::Holder(_) => {
                self.return_settlement_counters.holder_waits += 1;
            }
            SettlementDoorbellAnswer::Own(_) => {}
        }
        #[cfg(feature = "test-support")]
        if let Some(hold) = &self.fixture_holder_hold {
            hold.count_doorbell();
        }
        record.answer(answer);
        // SAFETY: the record is a fully initialized array of eight u64 words.
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
    /// caller's settled journal still cannot take a retirement: the one
    /// neutral drain ([`carrick_hal::return_settlement::drain_owed_return_table`])
    /// settles the other holders, oldest first, one MM's exclusions at a
    /// time. When none could free a slot, the answer is the oldest refusing
    /// holder's wait authority, so the caller waits on the holder that
    /// prevents progress (#1482 P0-1). Retired MMs' slots wait for their
    /// release receipts.
    fn drain_owed_return_table(
        &mut self,
        caller: carrick_el1_abi::ReservationMm,
    ) -> Result<SettlementDoorbellAnswer, TrapError> {
        let ram = Arc::clone(&self.ram);
        let table = retained_reservations(&ram)?;
        if !table.owed_return_table_full() {
            return Ok(SettlementDoorbellReply::Settled.into());
        }
        let mut holders = Vec::new();
        table.owed_return_holders(caller, &mut |holder| holders.push(holder));
        #[cfg(feature = "test-support")]
        if let Some(hold) = self.fixture_holder_hold.clone() {
            hold.claim_once(retained_cow_zone(&ram)?, &holders);
        }
        let outcome = drain_owed_return_table(
            &mut Cpl0Drain {
                custody: self,
                table,
            },
            &holders,
        )?;
        Ok(match outcome {
            DrainOutcome::Room => SettlementDoorbellReply::Settled.into(),
            DrainOutcome::Wait(wait) => SettlementDoorbellAnswer::Holder(wait),
            DrainOutcome::Retiring => {
                // No live holder: retiring MMs' slots free with their release
                // receipts. The rerun is counted.
                self.return_settlement_counters.drain_retiring += 1;
                SettlementDoorbellReply::Settled.into()
            }
        })
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
        // exit spins on it. Each chunk takes its own exclusion, lowered
        // before the next is raised (#1482).
        let reply = settle_in_bounded_pauses::<TrapError>(|| {
            Ok(match self.settled_pause(release, mm)? {
                Ok((pause, settled)) => {
                    drop(pause);
                    settled
                }
                Err(ExclusionRefusal::Busy) => {
                    PauseSettlement::answer(SettlementDoorbellReply::Editor)
                }
                Err(ExclusionRefusal::Stale) => {
                    PauseSettlement::answer(SettlementDoorbellReply::Stale)
                }
            })
        });
        let finished = wake.finish();
        let reply = reply?;
        finished?;
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

/// The editor owner a fixture holder claims with: no vCPU slot owner
/// (`slot + 1`) reaches it.
#[cfg(feature = "test-support")]
const FIXTURE_HOLDER_EDITOR: NonZeroU64 = NonZeroU64::new(u64::MAX - 0x2250).unwrap();

/// Test-support witness of a full owed-return table whose holders are all
/// busy (#1482 P0-1): at the first drain that finds the table full, the
/// carrier claims each holder's real editor word, as an active ring editor
/// would, before the drain attempts it. [`OwedReturnHolderRelease`] gives
/// the words back and publishes each holder's exact `Editor` release.
#[cfg(feature = "test-support")]
#[derive(Debug, Default)]
pub struct OwedReturnHolderHold {
    state: std::sync::Mutex<HolderHoldState>,
    claimed: std::sync::Condvar,
    doorbells_while_held: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "test-support")]
#[derive(Debug, Default)]
struct HolderHoldState {
    armed: bool,
    held: Vec<(
        carrick_sched_core::spaces::SpaceIndex,
        carrick_el1_abi::ReservationMm,
    )>,
    released: bool,
}

#[cfg(feature = "test-support")]
impl OwedReturnHolderHold {
    pub(crate) fn armed() -> Arc<Self> {
        let hold = Self::default();
        hold.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .armed = true;
        Arc::new(hold)
    }

    /// The drain's hook: claim every holder's editor once.
    pub(super) fn claim_once(
        &self,
        zone: &X86Cpl0Zone,
        holders: &[carrick_el1_abi::ReservationMm],
    ) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !std::mem::take(&mut state.armed) {
            return;
        }
        for &mm in holders {
            if let Some(index) = zone.spaces.find(mm.raw())
                && zone
                    .spaces
                    .fixture_claim_editor(index, mm.raw(), FIXTURE_HOLDER_EDITOR)
            {
                state.held.push((index, mm));
            }
        }
        self.claimed.notify_all();
    }

    /// The doorbell's hook, after its answer: count doorbells answered while
    /// the editors are held.
    pub(super) fn count_doorbell(&self) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.held.is_empty() && !state.released {
            self.doorbells_while_held
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// The MMs whose editors the drain claimed.
    pub fn held(&self) -> Vec<carrick_el1_abi::ReservationMm> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.held.iter().map(|&(_, mm)| mm).collect()
    }

    /// Settlement doorbells rung while every holder's editor was held.
    pub fn doorbells_while_held(&self) -> u64 {
        self.doorbells_while_held
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Wait (bounded) until a drain claimed the holders' editors.
    pub fn wait_claimed(&self, bound: std::time::Duration) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (state, _) = self
            .claimed
            .wait_timeout_while(state, bound, |state| state.held.is_empty())
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !state.held.is_empty()
    }
}

/// The releasing side of an [`OwedReturnHolderHold`], for a host fixture
/// thread: it reads the held holders' `Editor` queues and releases.
#[cfg(feature = "test-support")]
pub struct OwedReturnHolderRelease<M: CarrierMemoryIo> {
    hold: Arc<OwedReturnHolderHold>,
    ram: Arc<GuestRam>,
    vm: Arc<M>,
}

#[cfg(feature = "test-support")]
impl<M: CarrierMemoryIo> OwedReturnHolderRelease<M> {
    pub(crate) fn new(hold: Arc<OwedReturnHolderHold>, ram: Arc<GuestRam>, vm: Arc<M>) -> Self {
        Self { hold, ram, vm }
    }

    pub fn hold(&self) -> &Arc<OwedReturnHolderHold> {
        &self.hold
    }

    /// Records parked on the held holders' `Editor` releases.
    pub fn enrolled(&self) -> Result<u32, TrapError> {
        let zone = retained_cow_zone(&self.ram)?;
        let state = self
            .hold
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(state
            .held
            .iter()
            .filter_map(|&(_, mm)| {
                let source = zone
                    .space_entry(NonZeroU64::new(mm.raw())?)?
                    .live_notifications()
                    .ok()?;
                zone.object_queue_census(source.key(SpaceWaitCause::Editor).index())
            })
            .map(|census| census.waiters)
            .sum())
    }

    /// Give every held editor word back, then publish each holder's exact
    /// `Editor` release through the carrier's host wake (unlock before the
    /// revision advances, as a ring editor's release does). Returns how
    /// many were released.
    pub fn release(&self) -> Result<usize, TrapError> {
        let zone = retained_cow_zone(&self.ram)?;
        let held = {
            let mut state = self
                .hold
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.released = true;
            state.held.clone()
        };
        for &(index, mm) in &held {
            if !zone
                .spaces
                .fixture_release_editor(index, FIXTURE_HOLDER_EDITOR)
            {
                return Err(fail(format!(
                    "fixture editor of MM {} was not held",
                    mm.raw()
                )));
            }
            let Some(source) = NonZeroU64::new(mm.raw())
                .and_then(|mm| zone.space_entry(mm))
                .and_then(|entry| entry.live_notifications().ok())
            else {
                continue;
            };
            let wake = HostCowWake::new(&self.ram, Arc::clone(&self.vm))?;
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
            .publish(source.reserve(SpaceWaitCause::Editor));
            wake.finish()?;
        }
        Ok(held.len())
    }
}
