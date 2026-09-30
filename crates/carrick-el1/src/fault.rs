//! In-guest EL1 fault handling and dispatch.

use carrick_el1_abi::{
    Action, Counters, CurrentTask, EL1_FRAME_GRANT_TARGET_SIZE, FrameGrantMailbox,
    FrameGrantMailboxes, FrameGrantRequest, TrapFrame,
};
use carrick_mmu_core::aarch64::descriptor_txn::{
    DescriptorOutcome, DescriptorReceipt, DescriptorTxnSlot,
};
use carrick_mmu_core::aarch64::{GuestPreparedCommit, GuestPreparedCommitError, LeafAccess};
use carrick_sched_core::AddressSpaces;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_FRAME_GRANT_GENERATION: AtomicU64 = AtomicU64::new(1);
/// The host now owns frame-grant publication; EL1 has no publication error.
pub fn panic_publication_detail() -> u64 {
    0
}

fn next_frame_grant_generation() -> u64 {
    loop {
        let generation = NEXT_FRAME_GRANT_GENERATION.fetch_add(1, Ordering::Relaxed);
        if generation != 0 {
            return generation;
        }
    }
}

/// Decode an EL0 translation fault that can be satisfied by publishing fresh
/// anonymous backing. Permission faults name an already-mapped page and must
/// follow the protection/COW path; requesting another frame for them adds a
/// host round trip and can never authorize the denied access.
fn frame_grant_access(esr: u64) -> Option<u64> {
    let ec = (esr >> 26) & 0x3f;
    let dfsc = esr & 0x3f;
    if !matches!(ec, 0x24 | 0x25) || !(0x04..=0x07).contains(&dfsc) {
        return None;
    }
    Some(if esr & (1 << 6) != 0 { 2 } else { 1 })
}

fn prepared_fault_access(esr: u64) -> Option<LeafAccess> {
    let ec = (esr >> 26) & 0x3f;
    let status = esr & 0x3f;
    if !(0x04..=0x07).contains(&status) {
        return None;
    }
    match ec {
        0x20 | 0x21 => Some(LeafAccess::Execute),
        0x24 | 0x25 if esr & (1 << 6) != 0 => Some(LeafAccess::Write),
        0x24 | 0x25 => Some(LeafAccess::Read),
        _ => None,
    }
}

/// Decode an EL0 write permission fault that can be satisfied by in-guest COW resolution.
pub fn is_write_permission_fault(esr: u64) -> bool {
    let ec = (esr >> 26) & 0x3f;
    let dfsc = esr & 0x3f;
    let is_write = (esr & (1 << 6)) != 0;
    matches!(ec, 0x24 | 0x25) && is_write && matches!(dfsc, 0x0c..=0x0f)
}

/// Operation needed to resolve a COW fault in EL1. The caller holds the
/// faulting MM's exact editor.
pub trait CowResolver {
    /// Resolve the write fault at `far` for `mm_key`, whose live root and
    /// ASID are in `ttbr0`. `true`: retry the faulting instruction.
    fn resolve_cow(&mut self, ttbr0: u64, mm_key: u64, far: u64) -> bool;
    /// The MM's editor could not be taken (another EL1 editor, or a host
    /// pause closed its gate): the fault goes to the host.
    fn editor_busy(&mut self) {}
}

#[derive(Default)]
pub struct NoopCowResolver;

impl CowResolver for NoopCowResolver {
    fn resolve_cow(&mut self, _ttbr0: u64, _mm_key: u64, _far: u64) -> bool {
        false
    }
}

pub trait PreparedPageResolver {
    fn commit_prepared(
        &mut self,
        ttbr0: u64,
        va: u64,
        expected_ipa: u64,
        access: LeafAccess,
    ) -> Result<GuestPreparedCommit, GuestPreparedCommitError>;
}

pub struct NoopPreparedResolver;

pub struct PreparedFaultPath<'a, P: PreparedPageResolver> {
    pub residency: &'a carrick_el1_abi::FrameGrantResidencyTable,
    pub resolver: &'a mut P,
}

impl PreparedPageResolver for NoopPreparedResolver {
    fn commit_prepared(
        &mut self,
        _ttbr0: u64,
        _va: u64,
        _expected_ipa: u64,
        _access: LeafAccess,
    ) -> Result<GuestPreparedCommit, GuestPreparedCommitError> {
        Err(GuestPreparedCommitError::NotPrepared)
    }
}

#[cfg(target_os = "none")]
pub struct HardwarePreparedResolver;

#[cfg(target_os = "none")]
impl PreparedPageResolver for HardwarePreparedResolver {
    fn commit_prepared(
        &mut self,
        ttbr0: u64,
        va: u64,
        expected_ipa: u64,
        access: LeafAccess,
    ) -> Result<GuestPreparedCommit, GuestPreparedCommitError> {
        let outcome = unsafe {
            carrick_mmu_core::aarch64::commit_existing_el1_prepared_page(
                carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE
                    as *mut core::sync::atomic::AtomicU64,
                ttbr0 & TTBR_BADDR_MASK,
                carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize,
                va,
                expected_ipa,
                access,
            )?
        };
        let mut cpu = crate::sched::HardwareCpu;
        crate::sched::ThreadCpu::invalidate_asid(&mut cpu, ttbr0);
        Ok(outcome)
    }
}

#[cfg(target_os = "none")]
pub struct HardwareCowResolver;

#[cfg(target_os = "none")]
impl CowResolver for HardwareCowResolver {
    fn resolve_cow(&mut self, ttbr0: u64, mm_key: u64, far: u64) -> bool {
        use carrick_mmu_core::aarch64::descriptor_txn::PrimaryTableWords;
        let maintenance = El1TableMaintenance { ttbr0 };
        // SAFETY: the alias maps exactly this MM's primary table arena and
        // the caller holds the MM's exact editor.
        let Ok(words) = (unsafe {
            PrimaryTableWords::new(
                carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE as *mut AtomicU64,
                ttbr0 & TTBR_BADDR_MASK,
                carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize,
                &maintenance,
            )
        }) else {
            return false;
        };
        let outcome = crate::cow::resolve_guest_cow(
            &crate::cow::GuestCowVenue {
                words: &words,
                root: carrick_mmu_core::aarch64::SubstrateGpa(ttbr0 & TTBR_BADDR_MASK),
                pool: carrick_el1_abi::cow_grant_pool_guest(),
                copy_base: carrick_el1_abi::EL1_COW_COPY_BASE,
            },
            mm_key,
            far,
            |source, destination| {
                // SAFETY: both aliases are mapped, distinct pages (source
                // EL1-RO, destination EL1-RW) until the window restores them.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        source as *const u8,
                        destination as *mut u8,
                        4096,
                    )
                }
            },
            || {
                let mut cpu = crate::sched::HardwareCpu;
                crate::sched::ThreadCpu::invalidate_asid(&mut cpu, ttbr0);
            },
        );
        !matches!(outcome, crate::cow::GuestCowOutcome::Declined(_))
    }

    fn editor_busy(&mut self) {
        carrick_el1_abi::cow_grant_pool_guest()
            .note_declined(carrick_el1_abi::CowDecline::EditorBusy);
    }
}

/// EL1 execution of host-submitted live descriptor transactions.
pub trait DescriptorTxnApplier {
    /// Claim and execute the submission in `slot` for `mm_key` against the
    /// live graph rooted at `ttbr0`'s table base, invalidating `ttbr0`'s ASID
    /// when the outcome stored anything, before the receipt is published
    /// (`ClaimedDescriptorTxn::complete`). The caller holds the exact editor.
    fn apply(
        &mut self,
        slot: &DescriptorTxnSlot,
        mm_key: u64,
        ttbr0: u64,
    ) -> Option<DescriptorReceipt>;
}

/// The descriptor-transaction slots EL1 serves, plus the executor.
pub struct DescriptorTxnPath<'a, X: DescriptorTxnApplier> {
    pub slots: &'a carrick_el1_abi::DescriptorTxnSlots,
    pub applier: &'a mut X,
}

#[cfg(target_os = "none")]
const TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

#[cfg(target_os = "none")]
struct El1TableMaintenance {
    ttbr0: u64,
}

#[cfg(target_os = "none")]
impl carrick_mmu_core::aarch64::descriptor_txn::TableMaintenance for El1TableMaintenance {
    fn publish_barrier(&self) {
        // The reviewed ASID maintenance sequence begins with `dsb ishst`,
        // which completes the unlinked table fills for every walker in the
        // Inner Shareable domain before the following link store. Links are
        // rare (hierarchy growth and splits), so the trailing TLBI is cheap.
        let mut cpu = crate::sched::HardwareCpu;
        crate::sched::ThreadCpu::invalidate_asid(&mut cpu, self.ttbr0);
    }

    fn invalidate_range(&self, _va: u64, _len: u64) {
        // Break-before-make needs the broken translation gone from every PE
        // before the replacement appears. The MM's whole ASID is a superset.
        let mut cpu = crate::sched::HardwareCpu;
        crate::sched::ThreadCpu::invalidate_asid(&mut cpu, self.ttbr0);
    }
}

#[cfg(target_os = "none")]
pub struct HardwareDescriptorTxnApplier;

#[cfg(target_os = "none")]
impl DescriptorTxnApplier for HardwareDescriptorTxnApplier {
    fn apply(
        &mut self,
        slot: &DescriptorTxnSlot,
        mm_key: u64,
        ttbr0: u64,
    ) -> Option<DescriptorReceipt> {
        use carrick_mmu_core::aarch64::descriptor_txn::{
            DescriptorOp, InlineJournal, PrimaryTableWords, execute_descriptor_txn,
            plan_descriptor_op,
        };
        let maintenance = El1TableMaintenance { ttbr0 };
        let words = unsafe {
            PrimaryTableWords::new(
                carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE as *mut AtomicU64,
                ttbr0 & TTBR_BADDR_MASK,
                carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize,
                &maintenance,
            )
        }
        .ok()?;
        let mut journal = InlineJournal::new();
        let root = carrick_mmu_core::aarch64::SubstrateGpa(ttbr0 & TTBR_BADDR_MASK);
        let claimed = slot.claim_for_mm(mm_key)?;
        let outcome = match claimed.txn() {
            Err(refusal) => DescriptorOutcome::Refused(refusal),
            Ok(txn) if txn.root != root => DescriptorOutcome::Refused(
                carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal::StaleRoot,
            ),
            Ok(txn) => {
                // COW's bytes and live repoint are one guest operation under
                // the caller's exact-MM editor. Host custody retains both
                // backing owners until this transaction's receipt settles.
                let copied = if let DescriptorOp::CowRepoint {
                    old_ipa,
                    new_ipa,
                    len,
                    ..
                } = txn.op
                {
                    plan_descriptor_op(&words, root, txn.op)
                        .map_err(DescriptorOutcome::Refused)
                        .and_then(|_| {
                            use carrick_mmu_core::aarch64::SubstrateGpa;
                            use carrick_mmu_core::aarch64::descriptor_txn::copy_window::with_cow_copy_aliases;
                            for offset in (0..len).step_by(4096) {
                                with_cow_copy_aliases(
                                    &words,
                                    root,
                                    carrick_el1_abi::EL1_COW_COPY_BASE,
                                    SubstrateGpa(old_ipa.raw() + offset),
                                    SubstrateGpa(new_ipa.raw() + offset),
                                    |source, destination| {
                                        // SAFETY: aliases expose pinned, distinct
                                        // pages: source RO, destination RW, both
                                        // kernel-only; revoked before returning.
                                        unsafe {
                                            core::ptr::copy_nonoverlapping(
                                                source as *const u8,
                                                destination as *mut u8,
                                                4096,
                                            );
                                        }
                                    },
                                )?;
                            }
                            Ok(())
                        })
                } else {
                    Ok(())
                };
                match copied {
                    Ok(()) => execute_descriptor_txn(&words, root, txn, &mut journal).outcome,
                    Err(outcome) => outcome,
                }
            }
        };
        let receipt = claimed.complete(outcome, || {
            let mut cpu = crate::sched::HardwareCpu;
            crate::sched::ThreadCpu::invalidate_asid(&mut cpu, ttbr0);
        });
        if let DescriptorOutcome::Indeterminate(refusal) = receipt.outcome {
            panic!("EL1 descriptor transaction rollback failed: {refusal:?}");
        }
        Some(receipt)
    }
}

/// Execute every host submission for the faulting MM under its exact
/// editor. A fault inside an applied submission's span retries (`Served`):
/// its descriptor now exists or was refused and the retry takes the normal
/// path. `None` leaves the fault to the ordinary dispatch.
pub fn serve_descriptor_txns<X: DescriptorTxnApplier>(
    frame: &TrapFrame,
    current_tasks: &[CurrentTask],
    spaces: &AddressSpaces,
    path: &mut DescriptorTxnPath<'_, X>,
) -> Option<Action> {
    let mm_key = current_tasks
        .get(frame.slot as usize)?
        .zone_mm
        .load(Ordering::Acquire);
    if mm_key == 0 || path.slots.submitted_for(mm_key).next().is_none() {
        return None;
    }
    let index = spaces.find(mm_key)?;
    let grant = spaces.grant(index, mm_key)?;
    let owner = NonZeroU64::new(frame.slot + 1)?;
    // A closed gate (host pause or retirement) leaves the submission for the
    // host boundary, which recognizes it as in flight.
    let _editor = spaces.try_begin_edit(index, mm_key, owner)?;
    let mut covered = false;
    for slot in path.slots.submitted_in_order(mm_key) {
        let covers = slot.pending_covering(mm_key, frame.far);
        if let Some(receipt) = path.applier.apply(slot, mm_key, grant.ttbr0) {
            covered |= covers && matches!(receipt.outcome, DescriptorOutcome::Applied(_));
        }
    }
    covered.then_some(Action::Served)
}

/// [`dispatch_fault_with_prepared`] after serving host descriptor
/// transactions for the faulting MM.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_fault_with_descriptor_txns<P, C, X>(
    frame: &mut TrapFrame,
    counters: &Counters,
    current_tasks: &[CurrentTask],
    spaces: &AddressSpaces,
    mut txns: Option<DescriptorTxnPath<'_, X>>,
    mailboxes: GrantMailboxes<'_>,
    prepared: Option<PreparedFaultPath<'_, P>>,
    cow_resolver: &mut C,
) -> Action
where
    P: PreparedPageResolver,
    C: CowResolver,
    X: DescriptorTxnApplier,
{
    if let Some(action) = txns
        .as_mut()
        .and_then(|path| serve_descriptor_txns(frame, current_tasks, spaces, path))
    {
        counters.fault_taken.fetch_add(1, Ordering::Relaxed);
        return action;
    }
    dispatch_fault_with_prepared(
        frame,
        counters,
        current_tasks,
        spaces,
        mailboxes,
        prepared,
        cow_resolver,
    )
}

/// Where EL1 reads the still-shared frame and writes its private
/// replacement for one COW grant (each exactly one page).
pub trait CowCopyWindow {
    fn frames(
        &mut self,
        grant: &carrick_mmu_core::aarch64::descriptor_txn::CowCopyGrant,
    ) -> Option<(&[u8], &mut [u8])>;
}

/// Guest COW copy: claim the grant MM's exact editor, check that the live
/// leaf still maps the shared frame COW-armed, copy it into the granted
/// replacement, and return the proof that authorizes exactly one repoint.
/// A closed gate or another editor refuses (`Contended`); nothing is copied.
pub fn copy_granted_cow_page<W, C>(
    words: &W,
    grant: carrick_mmu_core::aarch64::descriptor_txn::CowCopyGrant,
    spaces: &AddressSpaces,
    owner: NonZeroU64,
    window: &mut C,
) -> Result<
    carrick_mmu_core::aarch64::descriptor_txn::CowCopyComplete,
    carrick_mmu_core::aarch64::descriptor_txn::CowCopyError,
>
where
    W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + ?Sized,
    C: CowCopyWindow,
{
    use carrick_mmu_core::aarch64::descriptor_txn::{CowCopyError, DescriptorRefusal};
    let mm_key = grant.mm_key.get();
    let index = spaces
        .find(mm_key)
        .ok_or(CowCopyError::Refused(DescriptorRefusal::WrongMm))?;
    let space = spaces
        .grant(index, mm_key)
        .ok_or(CowCopyError::Refused(DescriptorRefusal::Contended))?;
    if space.ttbr0 & 0x0000_FFFF_FFFF_F000 != grant.root.raw() {
        return Err(CowCopyError::Refused(DescriptorRefusal::StaleRoot));
    }
    let _editor = spaces
        .try_begin_edit(index, mm_key, owner)
        .ok_or(CowCopyError::Refused(DescriptorRefusal::Contended))?;
    let (source, destination) = window.frames(&grant).ok_or(CowCopyError::BadWindow)?;
    carrick_mmu_core::aarch64::descriptor_txn::copy_granted_cow_page(
        words,
        grant,
        source,
        destination,
    )
}

/// Result of draining one MM's host descriptor submissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainOutcome {
    /// Nothing was submitted for the MM.
    Clean,
    /// This many submissions were applied (each answered with a receipt).
    Drained(u32),
    /// Submissions remain and this vCPU may not edit the MM now: the MM is
    /// unpublished, or a host pause closed its gate without delegating.
    Blocked,
}

/// Apply every submission for `mm_key` on the live graph `ttbr0` names.
///
/// With the MM's gate open, the exact editor is claimed first, waiting out
/// another EL1 editor (a bounded critical section: EL1 editors never block
/// on anything). `host_custody` is set only by the host-driven drain call:
/// the host holds this MM's pause, has excluded every EL1 editor, and
/// delegates the edit to this vCPU, so a closed gate is its custody rather
/// than a refusal.
///
/// Nothing is reported drained while any of the MM's submissions is still
/// submitted or being applied by another editor: its receipt, and the ASID
/// invalidation that precedes it, are still to come, and a caller that
/// settled or resumed EL0 on the report would run against stale
/// translations.
pub fn drain_mm_descriptor_txns<X: DescriptorTxnApplier>(
    spaces: &AddressSpaces,
    slots: &carrick_el1_abi::DescriptorTxnSlots,
    mm_key: u64,
    ttbr0: u64,
    owner: NonZeroU64,
    applier: &mut X,
    host_custody: bool,
) -> DrainOutcome {
    if mm_key == 0 || !slots.in_flight_for(mm_key) {
        return DrainOutcome::Clean;
    }
    loop {
        if let Some(outcome) =
            try_drain_mm_descriptor_txns(spaces, slots, mm_key, ttbr0, owner, applier, host_custody)
        {
            return outcome;
        }
        core::hint::spin_loop();
    }
}

/// One attempt of [`drain_mm_descriptor_txns`]. `None`: another EL1 editor
/// holds the MM while some of its submissions are still in flight; retry.
fn try_drain_mm_descriptor_txns<X: DescriptorTxnApplier>(
    spaces: &AddressSpaces,
    slots: &carrick_el1_abi::DescriptorTxnSlots,
    mm_key: u64,
    ttbr0: u64,
    owner: NonZeroU64,
    applier: &mut X,
    host_custody: bool,
) -> Option<DrainOutcome> {
    let Some(index) = spaces.find(mm_key) else {
        return Some(DrainOutcome::Blocked);
    };
    let apply_all = |applier: &mut X| {
        let mut applied = 0;
        for slot in slots.submitted_in_order(mm_key) {
            if applier.apply(slot, mm_key, ttbr0).is_some() {
                applied += 1;
            }
        }
        DrainOutcome::Drained(applied)
    };
    if spaces.grant(index, mm_key).is_none() {
        return Some(if host_custody {
            apply_all(applier)
        } else {
            DrainOutcome::Blocked
        });
    }
    if let Some(_editor) = spaces.try_begin_edit(index, mm_key, owner) {
        return Some(apply_all(applier));
    }
    // Another editor applied them and published every receipt, each after
    // its invalidation.
    (!slots.in_flight_for(mm_key)).then_some(DrainOutcome::Drained(0))
}

fn is_syscall(frame: &TrapFrame) -> bool {
    (frame.esr >> 26) & 0x3f == 0x15
}

/// The last EL1 step before a thread of an MM returns to EL0 (a served
/// syscall, fault or interrupt, including a thread the scheduler switched
/// in, whose record the slot's task now names), and before a kicked
/// interrupt leaves for the host: apply that MM's pending descriptor
/// submissions, so no instruction of the MM runs against a descriptor edit
/// the host already committed to (a fork-COW arm above all). When they
/// cannot be applied here, the thread leaves through the host instead:
/// a served syscall keeps its result (`ServedWithWork`), anything else
/// forwards.
pub fn drain_before_el0<X: DescriptorTxnApplier>(
    frame: &TrapFrame,
    action: Action,
    current_tasks: &[CurrentTask],
    spaces: &AddressSpaces,
    slots: &carrick_el1_abi::DescriptorTxnSlots,
    applier: &mut X,
) -> Action {
    let to_el0 = matches!(action, Action::Served | Action::ServedWithWork);
    let kicked = action == Action::Forward && frame.esr == 0;
    if !(to_el0 || kicked) {
        return action;
    }
    let Some(task) = current_tasks.get(frame.slot as usize) else {
        return action;
    };
    let mm_key = task.zone_mm.load(Ordering::Acquire);
    if mm_key == 0 || !slots.in_flight_for(mm_key) {
        return action;
    }
    let (Some(owner), Some(index)) = (NonZeroU64::new(frame.slot + 1), spaces.find(mm_key)) else {
        return action;
    };
    let outcome = match spaces.grant(index, mm_key) {
        Some(grant) => {
            drain_mm_descriptor_txns(spaces, slots, mm_key, grant.ttbr0, owner, applier, false)
        }
        None => DrainOutcome::Blocked,
    };
    match (outcome, action) {
        (DrainOutcome::Blocked, Action::Served | Action::ServedWithWork) if is_syscall(frame) => {
            task.leave_served_with_work()
        }
        (DrainOutcome::Blocked, Action::Served) => Action::Forward,
        _ => action,
    }
}

/// EL1 side of the host-driven drain call ([`carrick_el1_abi::DESCRIPTOR_DRAIN_ESR`]).
/// Answers in `frame.x[0]`: applied count, plus the blocked bit.
pub fn serve_host_drain<X: DescriptorTxnApplier>(
    frame: &mut TrapFrame,
    spaces: &AddressSpaces,
    slots: &carrick_el1_abi::DescriptorTxnSlots,
    applier: &mut X,
) {
    let mm_key = frame.x[carrick_el1_abi::DESCRIPTOR_DRAIN_MM];
    let ttbr0 = frame.x[carrick_el1_abi::DESCRIPTOR_DRAIN_TTBR0];
    let Some(owner) = NonZeroU64::new(frame.slot + 1) else {
        frame.x[0] = carrick_el1_abi::DESCRIPTOR_DRAIN_BLOCKED;
        return;
    };
    frame.x[0] = match drain_mm_descriptor_txns(spaces, slots, mm_key, ttbr0, owner, applier, true)
    {
        DrainOutcome::Clean => 0,
        DrainOutcome::Drained(applied) => u64::from(applied),
        DrainOutcome::Blocked => carrick_el1_abi::DESCRIPTOR_DRAIN_BLOCKED,
    };
}

/// Hardware entry of [`drain_before_el0`] (`carrick_el1_syscall`).
#[cfg(target_os = "none")]
pub fn drain_before_el0_hw(frame: &TrapFrame, action: Action) -> Action {
    let current_tasks = unsafe {
        &*(carrick_el1_abi::EL1_CURRENT_TASKS_BASE
            as *const [CurrentTask; carrick_el1_abi::EL1_STACK_SLOTS as usize])
    };
    let zone = unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
    drain_before_el0(
        frame,
        action,
        current_tasks,
        &zone.spaces,
        carrick_el1_abi::descriptor_txn_slots_guest(),
        &mut HardwareDescriptorTxnApplier,
    )
}

/// Hardware entry of [`serve_host_drain`] (`carrick_el1_syscall`).
#[cfg(target_os = "none")]
pub fn serve_host_drain_hw(frame: &mut TrapFrame) {
    let zone = unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
    serve_host_drain(
        frame,
        &zone.spaces,
        carrick_el1_abi::descriptor_txn_slots_guest(),
        &mut HardwareDescriptorTxnApplier,
    );
}

/// Dispatch an EL0 data abort at EL1.
///
/// Increments `counters.fault_taken`; at EL1, requests host-published bulk
/// frames, consumes refusals, or resolves in-guest COW faults.
/// Host builds retain the forward-only path.
pub fn dispatch_fault(frame: &mut TrapFrame, counters: &Counters) -> Action {
    #[cfg(target_os = "none")]
    {
        let current_tasks = unsafe {
            &*(carrick_el1_abi::EL1_CURRENT_TASKS_BASE
                as *const [CurrentTask; carrick_el1_abi::EL1_STACK_SLOTS as usize])
        };
        let zone =
            unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
        let Some(mailbox) =
            carrick_el1_abi::frame_grant_mailbox_guest_for_slot(frame.slot as usize)
        else {
            counters.fault_taken.fetch_add(1, Ordering::Relaxed);
            return Action::Forward;
        };
        dispatch_fault_with_descriptor_txns(
            frame,
            counters,
            current_tasks,
            &zone.spaces,
            Some(DescriptorTxnPath {
                slots: carrick_el1_abi::descriptor_txn_slots_guest(),
                applier: &mut HardwareDescriptorTxnApplier,
            }),
            GrantMailboxes {
                own: mailbox,
                peers: Some(carrick_el1_abi::frame_grant_mailboxes_guest()),
            },
            Some(PreparedFaultPath {
                residency: carrick_el1_abi::frame_grant_residency_guest(),
                resolver: &mut HardwarePreparedResolver,
            }),
            &mut HardwareCowResolver,
        )
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = frame;
        counters.fault_taken.fetch_add(1, Ordering::Relaxed);
        Action::Forward
    }
}

/// The faulting vCPU's frame-grant mailbox, plus every vCPU's mailbox so a
/// retry migrated by the EL1 scheduler can consume a refusal left elsewhere.
/// Successful grants leave no guest-owned response.
#[derive(Clone, Copy)]
pub struct GrantMailboxes<'a> {
    pub own: &'a FrameGrantMailbox,
    pub peers: Option<&'a FrameGrantMailboxes>,
}

impl<'a> GrantMailboxes<'a> {
    pub fn own(own: &'a FrameGrantMailbox) -> Self {
        Self { own, peers: None }
    }
}

/// Fault dispatch with explicitly supplied shared regions and COW resolver.
/// A refusal is consumed and forwarded once through the host fault path.
/// Successful publication and first-touch commit both happen on the host.
pub fn dispatch_fault_with_regions<C: CowResolver>(
    frame: &mut TrapFrame,
    counters: &Counters,
    current_tasks: &[CurrentTask],
    spaces: &AddressSpaces,
    mailboxes: GrantMailboxes<'_>,
    cow_resolver: &mut C,
) -> Action {
    dispatch_fault_with_prepared(
        frame,
        counters,
        current_tasks,
        spaces,
        mailboxes,
        None::<PreparedFaultPath<'_, NoopPreparedResolver>>,
        cow_resolver,
    )
}

pub fn dispatch_fault_with_prepared<P: PreparedPageResolver, C: CowResolver>(
    frame: &mut TrapFrame,
    counters: &Counters,
    current_tasks: &[CurrentTask],
    spaces: &AddressSpaces,
    mailboxes: GrantMailboxes<'_>,
    mut prepared: Option<PreparedFaultPath<'_, P>>,
    cow_resolver: &mut C,
) -> Action {
    let GrantMailboxes {
        own: mailbox,
        peers,
    } = mailboxes;
    counters.fault_taken.fetch_add(1, Ordering::Relaxed);
    if is_write_permission_fault(frame.esr) {
        let Some(task) = current_tasks.get(frame.slot as usize) else {
            return Action::Forward;
        };
        let mm_key = task.zone_mm.load(Ordering::Acquire);
        if mm_key == 0 {
            return Action::Forward;
        }
        let Some(index) = spaces.find(mm_key) else {
            return Action::Forward;
        };
        let Some(owner) = NonZeroU64::new(frame.slot + 1) else {
            return Action::Forward;
        };
        // A closed gate (host pause or retirement) or another EL1 editor:
        // the host resolves this fault.
        // Sibling threads fault on the same forked MM together; each COW
        // holds the editor only for one compound copy and repoint.
        let Some((grant, _editor)) = spaces.grant(index, mm_key).and_then(|grant| {
            Some((
                grant,
                spaces.try_begin_edit_bounded(
                    index,
                    mm_key,
                    owner,
                    carrick_el1_abi::EL1_GUEST_LOCK_SPINS,
                )?,
            ))
        }) else {
            cow_resolver.editor_busy();
            return Action::Forward;
        };
        if cow_resolver.resolve_cow(grant.ttbr0, mm_key, frame.far) {
            return Action::Served;
        }
        return Action::Forward;
    }

    let Some(prepared_access) = prepared_fault_access(frame.esr) else {
        return Action::Forward;
    };
    let Some(task) = current_tasks.get(frame.slot as usize) else {
        return Action::Forward;
    };
    let mm_key = task.zone_mm.load(Ordering::Acquire);
    if mm_key == 0 {
        return Action::Forward;
    }

    if let Some(page) = prepared
        .as_ref()
        .and_then(|path| path.residency.lookup(mm_key, frame.far))
    {
        let Some(index) = spaces.find(mm_key) else {
            return Action::Forward;
        };
        let Some(grant) = spaces.grant(index, mm_key) else {
            return Action::Forward;
        };
        let Some(owner) = NonZeroU64::new(frame.slot + 1) else {
            return Action::Forward;
        };
        let Some(_editor) = spaces.try_begin_edit(index, mm_key, owner) else {
            return Action::Forward;
        };
        let path = prepared.as_mut().expect("prepared grant path");
        match path.resolver.commit_prepared(
            grant.ttbr0,
            frame.far & !4095,
            page.expected_ipa,
            prepared_access,
        ) {
            Ok(GuestPreparedCommit::Committed) => {
                assert!(path.residency.record_commit(page));
                return Action::Served;
            }
            Ok(GuestPreparedCommit::AlreadyResident) => return Action::Served,
            Err(GuestPreparedCommitError::RollbackFailed) => {
                panic!("EL1 prepared-page commit rollback failed")
            }
            Err(_) => {}
        }
    }

    let Some(access) = frame_grant_access(frame.esr) else {
        return Action::Forward;
    };

    let found = mailbox
        .response_for_fault(mm_key, frame.far, access)
        .map(|response| (mailbox, response))
        .or_else(|| {
            peers?.iter().find_map(|peer| {
                peer.response_covering_fault(mm_key, frame.far, access)
                    .map(|response| (peer, response))
            })
        });
    if let Some((source, response)) = found {
        let generation = response.request.request_generation;
        // Only refusals cross back to EL1. Successful grants have already
        // published and released their slot on the host, even after migration.
        if source.claim_response(mm_key, generation).is_some() {
            assert!(source.finish_response(mm_key, generation));
        }
        return Action::Forward;
    }

    let _ = mailbox.try_publish_request(FrameGrantRequest {
        mm_key,
        request_generation: next_frame_grant_generation(),
        fault_va: frame.far,
        requested_len: EL1_FRAME_GRANT_TARGET_SIZE,
        access,
    });
    Action::Forward
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1_abi::CurrentTask;
    use carrick_el1_abi::{
        EL1_FRAME_GRANT_TARGET_SIZE, FRAME_GRANT_ERR_DENIED, FrameGrantMailbox, FrameGrantReady,
    };
    use carrick_sched_core::AddressSpaces;

    fn write_translation_fault(slot: u64, address: u64) -> TrapFrame {
        TrapFrame {
            esr: (0x24 << 26) | (1 << 6) | 0x07,
            far: address,
            slot,
            ..TrapFrame::default()
        }
    }

    fn write_permission_fault(slot: u64, address: u64) -> TrapFrame {
        TrapFrame {
            esr: (0x24 << 26) | (1 << 6) | 0x0f,
            far: address,
            slot,
            ..TrapFrame::default()
        }
    }

    fn published_space(mm: u64, ttbr0: u64) -> AddressSpaces {
        let spaces = AddressSpaces::new();
        let index = spaces.publish_closed(mm, ttbr0, ttbr0).unwrap();
        spaces.open(index);
        spaces
    }

    #[test]
    fn prepared_grant_fault_commits_in_guest_and_records_residency() {
        let mm = 77;
        let va = 0x4000_1000;
        let base = 0x4000_0000;
        let table = carrick_el1_abi::FrameGrantResidencyTable::new();
        let identity = carrick_el1_abi::FrameGrantResidencyIdentity {
            mm_key: mm,
            semantic_base: base,
            physical_ipa: 0x9000_0000,
            len: 3 * 4096,
            mapping_id: 11,
            frame_id: 12,
            owner_generation: 13,
            inventory_revision: 14,
        };
        let slot = table.publish(identity).unwrap();
        let task = CurrentTask::new();
        task.zone_mm.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(mm, 0x8800_0000);
        let mailbox = FrameGrantMailbox::new();
        let mut frame = write_translation_fault(0, va);
        let mut prepared = RecordingPreparedResolver::default();
        assert_eq!(
            dispatch_fault_with_prepared(
                &mut frame,
                &Counters::default(),
                &tasks,
                &spaces,
                GrantMailboxes::own(&mailbox),
                Some(PreparedFaultPath {
                    residency: &table,
                    resolver: &mut prepared,
                }),
                &mut NoopCowResolver,
            ),
            Action::Served
        );
        assert_eq!(prepared.calls, vec![(0x8800_0000, va, 0x9000_1000)]);
        assert_eq!(table.committed_words(slot, identity).unwrap()[0], 0b10);
        assert!(!mailbox.has_guest_work());
    }

    #[test]
    fn prepared_executable_leaf_commits_on_instruction_translation_fault() {
        let mm = 78;
        let va = 0x4000_0000;
        let table = carrick_el1_abi::FrameGrantResidencyTable::new();
        let identity = carrick_el1_abi::FrameGrantResidencyIdentity {
            mm_key: mm,
            semantic_base: va,
            physical_ipa: 0x9000_0000,
            len: 4096,
            mapping_id: 11,
            frame_id: 12,
            owner_generation: 13,
            inventory_revision: 14,
        };
        table.publish(identity).unwrap();
        let task = CurrentTask::new();
        task.zone_mm.store(mm, Ordering::Release);
        let mut frame = TrapFrame {
            esr: (0x20 << 26) | 0x07,
            far: va,
            ..TrapFrame::default()
        };
        assert_eq!(
            dispatch_fault_with_prepared(
                &mut frame,
                &Counters::default(),
                &[task],
                &published_space(mm, 0x8800_0000),
                GrantMailboxes::own(&FrameGrantMailbox::new()),
                Some(PreparedFaultPath {
                    residency: &table,
                    resolver: &mut RecordingPreparedResolver::default(),
                }),
                &mut NoopCowResolver,
            ),
            Action::Served
        );
        assert!(table.is_guest_committed(mm, va));
    }

    #[derive(Default)]
    struct RecordingCowResolver {
        succeeds: bool,
        calls: Vec<(u64, u64, u64)>,
    }

    impl CowResolver for RecordingCowResolver {
        fn resolve_cow(&mut self, ttbr0: u64, mm_key: u64, far: u64) -> bool {
            self.calls.push((ttbr0, mm_key, far));
            self.succeeds
        }
    }

    #[derive(Default)]
    struct RecordingPreparedResolver {
        calls: Vec<(u64, u64, u64)>,
    }

    impl PreparedPageResolver for RecordingPreparedResolver {
        fn commit_prepared(
            &mut self,
            ttbr0: u64,
            va: u64,
            expected_ipa: u64,
            _access: LeafAccess,
        ) -> Result<GuestPreparedCommit, GuestPreparedCommitError> {
            self.calls.push((ttbr0, va, expected_ipa));
            Ok(GuestPreparedCommit::Committed)
        }
    }

    /// Two slots can fault before either host boundary runs. Publication is
    /// scoped to the MM extent, not the slot that happened to request it.
    #[test]
    fn concurrent_and_migrated_faults_share_one_host_publication() {
        use core::cell::Cell;
        for pages in [1, 2, 512] {
            let mm = 9;
            let tasks = [CurrentTask::new(), CurrentTask::new()];
            for task in &tasks {
                task.zone_mm.store(mm, Ordering::Release);
            }
            let spaces = published_space(mm, 0x8800_0000);
            let boxes = FrameGrantMailboxes::new();
            let counters = Counters::default();
            let origin = boxes.slot(0).unwrap();
            let peer = boxes.slot(1).unwrap();
            let mut cow = NoopCowResolver;
            let base = 0x4000_0000;
            let mut first = write_translation_fault(0, base);
            let mut second = write_translation_fault(1, base + (pages - 1) * 4096);
            for (frame, own) in [(&mut first, origin), (&mut second, peer)] {
                assert_eq!(
                    dispatch_fault_with_regions(
                        frame,
                        &counters,
                        &tasks,
                        &spaces,
                        GrantMailboxes {
                            own,
                            peers: Some(&boxes)
                        },
                        &mut cow,
                    ),
                    Action::Forward
                );
            }
            let request = origin.claim_request().unwrap();
            let ready = FrameGrantReady {
                mm_key: mm,
                request_generation: request.request_generation,
                semantic_base: base,
                physical_ipa: 0x9000_0000,
                len: pages * 4096,
                permissions: 3,
                frame_id: 1,
                mapping_id: 2,
                owner_generation: 3,
                inventory_revision: 4,
            };
            let published = Cell::new(false);
            let armed = Cell::new(true);
            let publications = Cell::new(0);
            assert_eq!(
                origin.complete_grant(
                    ready,
                    |grant| {
                        assert!(armed.get());
                        assert_eq!(grant.len, pages * 4096);
                        // The second fault cannot consume unpublished frame authority.
                        assert!(
                            origin
                                .claim_response(mm, request.request_generation)
                                .is_none()
                        );
                        publications.set(publications.get() + 1);
                        published.set(true);
                        Ok::<_, ()>(true)
                    },
                    || {
                        assert!(published.get());
                        armed.set(false);
                    }
                ),
                Ok(true)
            );
            assert!(!armed.get());
            assert!(!origin.has_guest_work());
            // Slot 1's queued fault reaches the host after slot 0 committed.
            // The live-leaf path resolves it and cancels its unused request.
            assert!(published.get(), "stale fault must retry, not signal");
            assert!(peer.cancel_request_for_fault(mm, second.far, 2));
            // An already queued retry may migrate to the original slot. EL1
            // forwards; it never republishes stale frame metadata on that slot.
            second.slot = 0;
            assert_eq!(
                dispatch_fault_with_regions(
                    &mut second,
                    &counters,
                    &tasks,
                    &spaces,
                    GrantMailboxes {
                        own: origin,
                        peers: Some(&boxes)
                    },
                    &mut cow,
                ),
                Action::Forward
            );
            assert!(published.get());
            assert!(origin.cancel_request_for_fault(mm, second.far, 2));
            assert_eq!(publications.get(), 1, "one bulk publication for the extent");
            assert!(!peer.has_guest_work());
        }
    }

    #[test]
    fn missing_guest_table_is_handled_before_commit_without_guest_handback() {
        use core::cell::Cell;
        let task = CurrentTask::new();
        task.zone_mm.store(7, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(7, 0x8800_0000);
        let mailbox = FrameGrantMailbox::new();
        let mut frame = write_translation_fault(0, 0x4000_1000);
        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &Counters::default(),
                &tasks,
                &spaces,
                GrantMailboxes::own(&mailbox),
                &mut NoopCowResolver,
            ),
            Action::Forward
        );
        let request = mailbox.claim_request().unwrap();
        let tables = Cell::new(false);
        let leaves = Cell::new(false);
        assert_eq!(
            mailbox.complete_grant(
                FrameGrantReady {
                    mm_key: 7,
                    request_generation: request.request_generation,
                    semantic_base: 0x4000_0000,
                    physical_ipa: 0x9000_0000,
                    len: EL1_FRAME_GRANT_TARGET_SIZE,
                    permissions: 3,
                    frame_id: 1,
                    mapping_id: 2,
                    owner_generation: 3,
                    inventory_revision: 4,
                },
                |_| {
                    // This used to require GUEST_FAILED and another host exit. The
                    // host publisher allocates the missing table in this transaction.
                    tables.set(true);
                    leaves.set(true);
                    Ok::<_, ()>(true)
                },
                || {
                    assert!(tables.get() && leaves.get());
                }
            ),
            Ok(true)
        );
        assert!(!mailbox.has_guest_work());
        assert!(
            mailbox
                .claim_response(7, request.request_generation)
                .is_none()
        );
    }

    #[test]
    fn refused_frame_grant_falls_back_without_republishing_in_the_same_dispatch() {
        let mm = 8;
        let task = CurrentTask::new();
        task.zone_mm.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(mm, (32_u64 << 48) | 0x8900_0000_0000);
        let mailbox = FrameGrantMailbox::new();
        let counters = Counters::default();
        let mut cow_resolver = NoopCowResolver;
        let mut frame = write_translation_fault(0, 0x5000_1000);

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                GrantMailboxes::own(&mailbox),
                &mut cow_resolver,
            ),
            Action::Forward
        );
        let request = mailbox.claim_request().unwrap();
        assert!(mailbox.publish_refusal(FRAME_GRANT_ERR_DENIED));
        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                GrantMailboxes::own(&mailbox),
                &mut cow_resolver,
            ),
            Action::Forward
        );
        assert!(!mailbox.has_guest_work());
        assert_ne!(request.request_generation, 0);
    }

    #[test]
    fn permission_fault_never_requests_a_first_touch_frame_grant() {
        let mm = 82;
        let task = CurrentTask::new();
        task.zone_mm.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(mm, (35_u64 << 48) | 0x8c00_0000_0000);
        let mailbox = FrameGrantMailbox::new();
        let counters = Counters::default();
        let mut cow_resolver = NoopCowResolver;
        let mut frame = write_permission_fault(0, 0x5300_1000);

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                GrantMailboxes::own(&mailbox),
                &mut cow_resolver,
            ),
            Action::Forward
        );
        assert!(
            !mailbox.has_guest_work(),
            "a mapped-page permission denial must not request new physical backing"
        );
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn non_translation_or_permission_fault_never_requests_a_grant() {
        let task = CurrentTask::new();
        task.zone_mm.store(9, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(9, (33_u64 << 48) | 0x8a00_0000_0000);
        let mailbox = FrameGrantMailbox::new();
        let counters = Counters::default();
        let mut cow_resolver = NoopCowResolver;
        let mut frame = write_translation_fault(0, 0x6000_1000);
        frame.esr = (0x24 << 26) | 0x21;

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                GrantMailboxes::own(&mailbox),
                &mut cow_resolver,
            ),
            Action::Forward
        );
        assert!(!mailbox.has_guest_work());
    }

    #[test]
    fn cow_write_permission_fault_serves_in_guest_when_resolved() {
        let mm = 90;
        let ttbr0 = (36_u64 << 48) | 0x8d00_0000_0000;
        let fault = 0x4000_3000;
        let task = CurrentTask::new();
        task.zone_mm.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(mm, ttbr0);
        let mailbox = FrameGrantMailbox::new();
        let counters = Counters::default();
        let mut cow_resolver = RecordingCowResolver {
            succeeds: true,
            ..RecordingCowResolver::default()
        };
        let mut frame = write_permission_fault(0, fault);

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                GrantMailboxes::own(&mailbox),
                &mut cow_resolver,
            ),
            Action::Served
        );
        assert_eq!(cow_resolver.calls, vec![(ttbr0, mm, fault)]);
        assert!(!mailbox.has_guest_work());
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn cow_write_permission_fault_forwards_when_not_authorized() {
        let mm = 91;
        let ttbr0 = (37_u64 << 48) | 0x8e00_0000_0000;
        let fault = 0x4000_4000;
        let task = CurrentTask::new();
        task.zone_mm.store(mm, Ordering::Release);
        let tasks = [task];
        let spaces = published_space(mm, ttbr0);
        let mailbox = FrameGrantMailbox::new();
        let counters = Counters::default();
        let mut cow_resolver = RecordingCowResolver {
            succeeds: false,
            ..RecordingCowResolver::default()
        };
        let mut frame = write_permission_fault(0, fault);

        assert_eq!(
            dispatch_fault_with_regions(
                &mut frame,
                &counters,
                &tasks,
                &spaces,
                GrantMailboxes::own(&mailbox),
                &mut cow_resolver,
            ),
            Action::Forward
        );
        assert_eq!(cow_resolver.calls, vec![(ttbr0, mm, fault)]);
        assert!(!mailbox.has_guest_work());
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_dispatch_fault_increments_counter_and_forwards() {
        let mut frame = TrapFrame {
            esr: (0xFFFF_0000_u64 << 32) | (0x24 << 26) | (1 << 25) | 0x47,
            far: 0x1000_2000,
            x: {
                let mut x = [42; 31];
                x[8] = 172; // valid syscall nr (SYS_getpid) as canary
                x
            },
            ..TrapFrame::default()
        };
        let counters = Counters::default();
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 0);

        let action = dispatch_fault(&mut frame, &counters);
        assert_eq!(action, Action::Forward);
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
        // Ensure arbitrary x8 was not dispatched as a syscall and syscall counters were not touched
        assert_eq!(counters.forwarded[172].load(Ordering::Relaxed), 0);
        assert_eq!(counters.served[172].load(Ordering::Relaxed), 0);
        assert_eq!(counters.forwarded[42].load(Ordering::Relaxed), 0);
        assert_eq!(counters.served[42].load(Ordering::Relaxed), 0);
    }

    mod descriptor_txns {
        use super::*;
        use carrick_mmu_core::aarch64::descriptor_txn::{
            BackingIdentity, DescriptorOp, DescriptorRefusal, DescriptorTxn, DescriptorTxnId,
            InlineJournal, PageSpan, PrimaryTableWords, TableGrants, TableMaintenance,
            apply_submitted_descriptor_txn,
        };
        use carrick_mmu_core::aarch64::{
            El1PrivateLeafState, GuestLeafPublication, SubstrateGpa, el1_private_leaf_state,
            indices,
        };
        use core::cell::RefCell;

        const ROOT: u64 = 0x8800_0000_0000;
        const ASID: u64 = 5 << 48;
        const VA: u64 = 0x4000_0000;
        const IPA: u64 = 0x009b_4000_0000;

        struct Arena {
            words: Vec<AtomicU64>,
        }

        impl Arena {
            /// L0 -> L1 -> L2 -> L3 for `VA` in pages 0..=3 of a 16-page arena.
            fn new() -> Self {
                let words: Vec<AtomicU64> = (0..16 * 512).map(|_| AtomicU64::new(0)).collect();
                let idx = indices(VA);
                words[idx[0]].store((ROOT + 0x1000) | 0b11, Ordering::Relaxed);
                words[512 + idx[1]].store((ROOT + 0x2000) | 0b11, Ordering::Relaxed);
                words[1024 + idx[2]].store((ROOT + 0x3000) | 0b11, Ordering::Relaxed);
                Self { words }
            }
            fn leaf(&self, va: u64) -> u64 {
                self.words[1536 + indices(va)[3]].load(Ordering::Acquire)
            }
            fn image(&self) -> Vec<u64> {
                self.words
                    .iter()
                    .map(|w| w.load(Ordering::Relaxed))
                    .collect()
            }
        }

        struct NoBarrier;
        impl TableMaintenance for NoBarrier {
            fn publish_barrier(&self) {}
            fn invalidate_range(&self, _va: u64, _len: u64) {}
        }

        /// The EL1 applier over host memory, recording ASID invalidations
        /// and whether the host could already see the receipt when each ran.
        struct ArenaApplier<'a> {
            arena: &'a Arena,
            invalidated: RefCell<Vec<u64>>,
            receipt_visible_at_invalidation: RefCell<Vec<bool>>,
        }

        impl<'a> ArenaApplier<'a> {
            fn new(arena: &'a Arena) -> Self {
                Self {
                    arena,
                    invalidated: RefCell::new(Vec::new()),
                    receipt_visible_at_invalidation: RefCell::new(Vec::new()),
                }
            }
        }

        impl DescriptorTxnApplier for ArenaApplier<'_> {
            fn apply(
                &mut self,
                slot: &DescriptorTxnSlot,
                mm_key: u64,
                ttbr0: u64,
            ) -> Option<DescriptorReceipt> {
                let words = unsafe {
                    PrimaryTableWords::new(
                        self.arena.words.as_ptr().cast_mut(),
                        ROOT,
                        self.arena.words.len() * 8,
                        &NoBarrier,
                    )
                }
                .unwrap();
                let mut journal = InlineJournal::new();
                apply_submitted_descriptor_txn(
                    slot,
                    mm_key,
                    &words,
                    SubstrateGpa(ttbr0 & 0x0000_FFFF_FFFF_F000),
                    &mut journal,
                    || {
                        self.invalidated.borrow_mut().push(ttbr0);
                        self.receipt_visible_at_invalidation.borrow_mut().push(
                            slot.state()
                                == carrick_mmu_core::aarch64::descriptor_txn::DESCRIPTOR_TXN_RECEIPT,
                        );
                    },
                )
            }
        }

        fn nz(value: u64) -> NonZeroU64 {
            NonZeroU64::new(value).unwrap()
        }

        fn grant_txn(mm: u64, root: u64, fault: u64) -> DescriptorTxn {
            DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: nz(mm),
                    generation: nz(1),
                },
                root: SubstrateGpa(root),
                op: DescriptorOp::Prepare {
                    publication: GuestLeafPublication {
                        va: VA,
                        ipa: IPA,
                        len: 4 * 4096,
                        writable: true,
                        executable: false,
                    },
                    resident: PageSpan::new(fault, 4096),
                    backing: BackingIdentity {
                        frame_id: nz(1),
                        mapping_id: nz(2),
                        owner_generation: nz(3),
                        inventory_revision: nz(4),
                    },
                },
                tables: TableGrants::NONE,
            }
        }

        fn dispatch(
            mm: u64,
            spaces: &AddressSpaces,
            slots: &carrick_el1_abi::DescriptorTxnSlots,
            applier: &mut ArenaApplier<'_>,
            fault: u64,
            counters: &Counters,
        ) -> Action {
            let task = CurrentTask::new();
            task.zone_mm.store(mm, Ordering::Release);
            let mut frame = write_translation_fault(0, fault);
            dispatch_fault_with_descriptor_txns(
                &mut frame,
                counters,
                &[task],
                spaces,
                Some(DescriptorTxnPath { slots, applier }),
                GrantMailboxes::own(&FrameGrantMailbox::new()),
                None::<PreparedFaultPath<'_, NoopPreparedResolver>>,
                &mut NoopCowResolver,
            )
        }

        #[test]
        fn submitted_grant_is_applied_by_its_mm_and_serves_the_faulting_retry() {
            let mm = 77;
            let arena = Arena::new();
            let fault = VA + 2 * 4096;
            let txn = grant_txn(mm, ROOT, fault);
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(1, &txn));
            let spaces = published_space(mm, ROOT | ASID);
            let mut applier = ArenaApplier::new(&arena);
            let counters = Counters::default();
            assert_eq!(
                dispatch(mm, &spaces, &slots, &mut applier, fault, &counters),
                Action::Served
            );
            assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
            assert_eq!(*applier.invalidated.borrow(), vec![ROOT | ASID]);
            for page in 0..4 {
                let expected = if VA + page * 4096 == fault {
                    El1PrivateLeafState::Resident
                } else {
                    El1PrivateLeafState::Prepared
                };
                assert_eq!(
                    el1_private_leaf_state(arena.leaf(VA + page * 4096)),
                    expected
                );
            }
            let receipt = slots.take_receipt(1, txn.id).expect("receipt for the host");
            let verified = txn.verify_receipt(&receipt).expect("authentic");
            assert_eq!(verified.resident(), PageSpan::new(fault, 4096));
        }

        #[test]
        fn another_mm_or_a_closed_gate_never_applies_a_submission() {
            let arena = Arena::new();
            let before = arena.image();
            let txn = grant_txn(77, ROOT, VA);
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(0, &txn));
            let mut applier = ArenaApplier::new(&arena);
            // A different MM's fault takes the ordinary path.
            let other = published_space(78, ROOT | ASID);
            assert_eq!(
                dispatch(78, &other, &slots, &mut applier, VA, &Counters::default()),
                Action::Forward
            );
            // The right MM behind a closed (paused/retiring) gate leaves the
            // submission for the host boundary.
            let closed = AddressSpaces::new();
            closed.publish_closed(77, ROOT | ASID, ROOT | ASID).unwrap();
            assert_eq!(
                dispatch(77, &closed, &slots, &mut applier, VA, &Counters::default()),
                Action::Forward
            );
            assert_eq!(slots.submitted_for(77).count(), 1);
            assert_eq!(arena.image(), before);
            assert!(applier.invalidated.borrow().is_empty());
        }

        #[test]
        fn a_stale_root_submission_is_refused_without_a_store() {
            let mm = 77;
            let arena = Arena::new();
            let before = arena.image();
            // Built against a root this MM no longer publishes.
            let txn = grant_txn(mm, ROOT + 0x4000, VA);
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(0, &txn));
            let mut applier = ArenaApplier::new(&arena);
            let spaces = published_space(mm, ROOT | ASID);
            assert_eq!(
                dispatch(mm, &spaces, &slots, &mut applier, VA, &Counters::default()),
                Action::Forward,
                "a refused transaction does not serve the fault"
            );
            assert_eq!(arena.image(), before);
            let receipt = slots.take_receipt(0, txn.id).unwrap();
            assert_eq!(
                receipt.outcome,
                DescriptorOutcome::Refused(DescriptorRefusal::StaleRoot)
            );
            assert!(applier.invalidated.borrow().is_empty());
        }

        /// A resident writable page at `VA` and a fork arm for it.
        fn armable() -> (Arena, DescriptorTxn) {
            use carrick_mmu_core::aarch64::descriptor_txn::TerminalEdit;
            let arena = Arena::new();
            let idx = indices(VA);
            // Resident, writable, nG, EL1-private leaf.
            let leaf = (IPA & 0x0000_FFFF_FFFF_F000)
                | 0b11
                | (1 << 10)
                | (0b11 << 8)
                | (0b01 << 6)
                | (1 << 11)
                | (1 << 53)
                | (1 << 54)
                | (1 << 56)
                | (1 << 57);
            arena.words[1536 + idx[3]].store(leaf, Ordering::Relaxed);
            let txn = DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: nz(77),
                    generation: nz(9),
                },
                root: SubstrateGpa(ROOT),
                op: DescriptorOp::Terminal {
                    span: PageSpan::new(VA, 4096),
                    edit: TerminalEdit::fork_arm(false, false, true, 0, 0),
                },
                tables: TableGrants::NONE,
            };
            (arena, txn)
        }

        fn writable(arena: &Arena) -> bool {
            carrick_mmu_core::aarch64::terminal_descriptor_permits_el0(
                arena.leaf(VA),
                LeafAccess::Write,
            )
        }

        fn task(mm: u64) -> CurrentTask {
            let task = CurrentTask::new();
            task.zone_mm.store(mm, Ordering::Release);
            task
        }

        fn frame(esr: u64) -> TrapFrame {
            TrapFrame {
                esr,
                slot: 0,
                ..TrapFrame::default()
            }
        }

        const SVC: u64 = 0x15 << 26;

        #[test]
        fn a_served_syscall_drains_its_mms_arm_before_returning_to_el0() {
            let (arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(3, &txn));
            let spaces = published_space(77, ROOT | ASID);
            let mut applier = ArenaApplier::new(&arena);
            assert!(writable(&arena));
            assert_eq!(
                drain_before_el0(
                    &frame(SVC),
                    Action::Served,
                    &[task(77)],
                    &spaces,
                    &slots,
                    &mut applier
                ),
                Action::Served
            );
            assert!(!writable(&arena), "the arm landed before EL0 resumes");
            assert_eq!(*applier.invalidated.borrow(), vec![ROOT | ASID]);
            assert!(slots.take_receipt(3, txn.id).is_some());
        }

        #[test]
        fn a_kicked_sibling_cannot_resume_el0_before_the_arm_lands() {
            // Kick: the sibling leaves for the host, arm applied on the way.
            let (arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(0, &txn));
            let spaces = published_space(77, ROOT | ASID);
            let mut applier = ArenaApplier::new(&arena);
            assert_eq!(
                drain_before_el0(
                    &frame(0),
                    Action::Forward,
                    &[task(77)],
                    &spaces,
                    &slots,
                    &mut applier
                ),
                Action::Forward
            );
            assert!(!writable(&arena));
            // Reschedule/timer interrupt served in EL1: drained before eret.
            let (arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(0, &txn));
            let mut applier = ArenaApplier::new(&arena);
            assert_eq!(
                drain_before_el0(
                    &frame(0),
                    Action::Served,
                    &[task(77)],
                    &spaces,
                    &slots,
                    &mut applier
                ),
                Action::Served
            );
            assert!(!writable(&arena));
            // A parked thread's idle exit is not a return to EL0.
            let (arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(0, &txn));
            let mut applier = ArenaApplier::new(&arena);
            assert_eq!(
                drain_before_el0(
                    &frame(SVC),
                    Action::Idle,
                    &[task(77)],
                    &spaces,
                    &slots,
                    &mut applier
                ),
                Action::Idle
            );
            assert!(writable(&arena));
        }

        /// A syscall EL1 already served (its effect taken: bytes read,
        /// written or consumed) that must leave through the host because
        /// the drain is blocked keeps its result only if the host is told
        /// it was served. Without `served_with_work` the host dispatches
        /// the call again from the frame, whose `x0` is now the result:
        /// the read's bytes are lost and the result is read as an fd.
        #[test]
        fn a_blocked_drain_marks_a_served_syscall_served_for_the_host() {
            let (_arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(0, &txn));
            let closed = AddressSpaces::new();
            closed.publish_closed(77, ROOT | ASID, ROOT | ASID).unwrap();
            let mut applier = ArenaApplier::new(&_arena);
            let tasks = [task(77)];
            assert_eq!(
                drain_before_el0(
                    &frame(SVC),
                    Action::Served,
                    &tasks,
                    &closed,
                    &slots,
                    &mut applier
                ),
                Action::ServedWithWork
            );
            assert_eq!(
                tasks[0].served_with_work.load(Ordering::Acquire),
                1,
                "the host must complete, not re-dispatch, the served call"
            );
        }

        #[test]
        fn a_blocked_drain_never_returns_to_el0_unarmed() {
            let (arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(0, &txn));
            let closed = AddressSpaces::new();
            closed.publish_closed(77, ROOT | ASID, ROOT | ASID).unwrap();
            let mut applier = ArenaApplier::new(&arena);
            let tasks = [task(77)];
            assert_eq!(
                drain_before_el0(
                    &frame(SVC),
                    Action::Served,
                    &tasks,
                    &closed,
                    &slots,
                    &mut applier
                ),
                Action::ServedWithWork,
                "a served syscall keeps its result and leaves through the host"
            );
            assert_eq!(
                drain_before_el0(
                    &frame(0),
                    Action::Served,
                    &tasks,
                    &closed,
                    &slots,
                    &mut applier
                ),
                Action::Forward
            );
            let fault = (0x24 << 26) | 0x07;
            assert_eq!(
                drain_before_el0(
                    &frame(fault),
                    Action::Served,
                    &tasks,
                    &closed,
                    &slots,
                    &mut applier
                ),
                Action::Forward
            );
            assert!(writable(&arena), "nothing applied behind a closed gate");
        }

        #[test]
        fn a_switched_in_thread_drains_only_its_own_mm() {
            let (arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            let other = DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: nz(78),
                    generation: nz(1),
                },
                ..txn
            };
            assert!(slots.submit(1, &other));
            let spaces = AddressSpaces::new();
            for (mm, root) in [(77, ROOT), (78, ROOT)] {
                let index = spaces.publish_closed(mm, root | ASID, root | ASID).unwrap();
                spaces.open(index);
            }
            let mut applier = ArenaApplier::new(&arena);
            // The slot's task record names the switched-in thread (MM 77).
            assert_eq!(
                drain_before_el0(
                    &frame(SVC),
                    Action::Served,
                    &[task(77)],
                    &spaces,
                    &slots,
                    &mut applier
                ),
                Action::Served
            );
            assert_eq!(
                slots.submitted_for(78).count(),
                1,
                "MM 78 waits for its own thread"
            );
            assert!(writable(&arena));
        }

        #[test]
        fn the_host_drain_applies_under_delegated_custody_only_for_its_mm() {
            let (arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(5, &txn));
            // The host holds the MM's pause: the gate is closed.
            let closed = AddressSpaces::new();
            closed.publish_closed(77, ROOT | ASID, ROOT | ASID).unwrap();
            let mut applier = ArenaApplier::new(&arena);
            let mut call = TrapFrame {
                esr: carrick_el1_abi::DESCRIPTOR_DRAIN_ESR,
                slot: 5,
                ..TrapFrame::default()
            };
            call.x[carrick_el1_abi::DESCRIPTOR_DRAIN_MM] = 78;
            call.x[carrick_el1_abi::DESCRIPTOR_DRAIN_TTBR0] = ROOT | ASID;
            serve_host_drain(&mut call, &closed, &slots, &mut applier);
            assert_eq!(call.x[0], 0, "another MM's call applies nothing");
            assert!(writable(&arena));
            call.x[carrick_el1_abi::DESCRIPTOR_DRAIN_MM] = 77;
            serve_host_drain(&mut call, &closed, &slots, &mut applier);
            assert_eq!(call.x[0], 1);
            assert!(!writable(&arena));
            let receipt = slots.take_receipt(5, txn.id).unwrap();
            assert!(txn.verify_receipt(&receipt).is_ok());
        }

        /// The host settles a receipt and may then retire or reuse the
        /// backing and tables the edit removed. The receipt must therefore
        /// be observable only after the ASID invalidation that makes the
        /// applied edit exclusive, never before it.
        #[test]
        fn a_receipt_is_published_only_after_its_asid_invalidation() {
            let (arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(3, &txn));
            let spaces = published_space(77, ROOT | ASID);
            let mut applier = ArenaApplier::new(&arena);
            drain_before_el0(
                &frame(SVC),
                Action::Served,
                &[task(77)],
                &spaces,
                &slots,
                &mut applier,
            );
            assert_eq!(*applier.invalidated.borrow(), vec![ROOT | ASID]);
            assert_eq!(
                *applier.receipt_visible_at_invalidation.borrow(),
                vec![false],
                "the host could settle the arm before its TLBI ran"
            );
            assert!(slots.take_receipt(3, txn.id).is_some());
        }

        /// Another EL1 editor claimed the host's submission and is still
        /// applying it (its TLBI has not run). The drain must not report
        /// the MM drained: the host would settle before that invalidation.
        #[test]
        fn a_drain_never_reports_drained_while_another_editor_is_applying() {
            let (_arena, txn) = armable();
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            assert!(slots.submit(0, &txn));
            let spaces = published_space(77, ROOT | ASID);
            let index = spaces.find(77).unwrap();
            let other = spaces.try_begin_edit(index, 77, nz(9)).unwrap();
            let claimed = slots.slot(0).unwrap().claim_for_mm(77).unwrap();
            let mut applier = ArenaApplier::new(&_arena);
            let mut step = || {
                try_drain_mm_descriptor_txns(
                    &spaces,
                    &slots,
                    77,
                    ROOT | ASID,
                    nz(1),
                    &mut applier,
                    false,
                )
            };
            assert_eq!(
                step(),
                None,
                "reported drained while the claim is unfinished"
            );
            // The other editor finishes: invalidation, then the receipt.
            let invalidated = core::cell::Cell::new(false);
            claimed.complete(
                DescriptorOutcome::RolledBack(DescriptorRefusal::Contended),
                || invalidated.set(true),
            );
            assert!(invalidated.get());
            assert_eq!(step(), Some(DrainOutcome::Drained(0)));
            drop(other);
            assert_eq!(
                drain_mm_descriptor_txns(
                    &spaces,
                    &slots,
                    77,
                    ROOT | ASID,
                    nz(1),
                    &mut applier,
                    false
                ),
                DrainOutcome::Clean,
                "a published receipt is not in flight"
            );
        }

        /// The host prepares and submits one MM's transactions in
        /// generation order under that MM's mutation guard, but they sit in
        /// whichever vCPU slot was free. An async frame-grant `Prepare`
        /// left in a higher slot must still land before a later munmap
        /// retirement of the same range in a lower slot; applied in slot
        /// order, the grant would re-expose backing the host has retired.
        #[test]
        fn a_drain_applies_one_mms_submissions_in_generation_order() {
            use carrick_mmu_core::aarch64::descriptor_txn::TerminalEdit;
            use carrick_mmu_core::aarch64::{PtOp, TerminalRule};
            let mm = 77;
            let arena = Arena::new();
            let mut grant = grant_txn(mm, ROOT, VA);
            grant.id.generation = nz(4);
            let retire = DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: nz(mm),
                    generation: nz(5),
                },
                root: SubstrateGpa(ROOT),
                op: DescriptorOp::Terminal {
                    span: PageSpan::new(VA, 4 * 4096),
                    edit: TerminalEdit {
                        rule: TerminalRule::pt(PtOp::Retire),
                        asid_scoped: true,
                        excluded_ipa: 0,
                        excluded_len: 0,
                        reclaim_budget: 0,
                    },
                },
                tables: TableGrants::NONE,
            };
            let slots = carrick_el1_abi::DescriptorTxnSlots::new();
            // The faulting vCPU's slot is above the munmap caller's.
            assert!(slots.submit(6, &grant));
            assert!(slots.submit(2, &retire));
            let spaces = published_space(mm, ROOT | ASID);
            let mut applier = ArenaApplier::new(&arena);
            assert_eq!(
                drain_mm_descriptor_txns(
                    &spaces,
                    &slots,
                    mm,
                    ROOT | ASID,
                    nz(1),
                    &mut applier,
                    false
                ),
                DrainOutcome::Drained(2)
            );
            for page in 0..4 {
                let state = el1_private_leaf_state(arena.leaf(VA + page * 4096));
                assert!(
                    !matches!(
                        state,
                        El1PrivateLeafState::Prepared | El1PrivateLeafState::Resident
                    ),
                    "page {page} still names the granted backing after its retirement: {state:?}"
                );
            }
            let grant_receipt = slots.take_receipt(6, grant.id).unwrap();
            assert!(matches!(
                grant_receipt.outcome,
                DescriptorOutcome::Applied(_)
            ));
            assert!(slots.take_receipt(2, retire.id).is_some());
        }

        struct Frames {
            source: Vec<u8>,
            destination: Vec<u8>,
        }

        impl CowCopyWindow for Frames {
            fn frames(
                &mut self,
                _grant: &carrick_mmu_core::aarch64::descriptor_txn::CowCopyGrant,
            ) -> Option<(&[u8], &mut [u8])> {
                Some((&self.source, &mut self.destination))
            }
        }

        #[test]
        fn the_guest_cow_copy_runs_only_under_the_grant_mms_open_editor() {
            use carrick_mmu_core::aarch64::descriptor_txn::{CowCopyError, CowCopyGrant};
            let (arena, _) = armable();
            let byte_len = arena.words.len() * 8;
            unsafe {
                carrick_mmu_core::aarch64::arm_existing_el1_fork_pages(
                    arena.words.as_ptr().cast_mut(),
                    ROOT,
                    byte_len,
                    VA,
                    4096,
                )
            }
            .unwrap();
            let words = unsafe {
                PrimaryTableWords::new(arena.words.as_ptr().cast_mut(), ROOT, byte_len, &NoBarrier)
            }
            .unwrap();
            let grant = CowCopyGrant {
                mm_key: nz(77),
                root: SubstrateGpa(ROOT),
                va: VA,
                old_ipa: SubstrateGpa(IPA),
                new_ipa: SubstrateGpa(0x009d_0000_0000),
                old_backing: BackingIdentity {
                    frame_id: nz(1),
                    mapping_id: nz(2),
                    owner_generation: nz(3),
                    inventory_revision: nz(4),
                },
                new_backing: BackingIdentity {
                    frame_id: nz(5),
                    mapping_id: nz(6),
                    owner_generation: nz(7),
                    inventory_revision: nz(8),
                },
            };
            let mut frames = Frames {
                source: (0..4096).map(|i| (i % 253) as u8).collect(),
                destination: vec![0; 4096],
            };
            // Behind a closed gate (host pause) nothing is copied.
            let closed = AddressSpaces::new();
            closed.publish_closed(77, ROOT | ASID, ROOT | ASID).unwrap();
            assert!(matches!(
                copy_granted_cow_page(&words, grant, &closed, nz(1), &mut frames),
                Err(CowCopyError::Refused(DescriptorRefusal::Contended))
            ));
            assert!(frames.destination.iter().all(|&b| b == 0));
            let spaces = published_space(77, ROOT | ASID);
            let copy = copy_granted_cow_page(&words, grant, &spaces, nz(1), &mut frames).unwrap();
            assert_eq!(frames.destination, frames.source);
            assert_eq!(copy.grant(), grant);
        }
    }
}
