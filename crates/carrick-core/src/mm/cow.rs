//! Guest fork-COW resolution with host-provisioned replacement frames.

use carrick_core_abi::{CowDecline, CowGrantCompletion, CowGrantVenue, FrameGrantResidencyTable};
use carrick_mmu_core::aarch64::SubstrateGpa;
use carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords;

const PAGE: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CowError {
    Indeterminate,
    Corrupt,
    Internal,
    Refused,
}

/// What one guest COW attempt did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestCowOutcome {
    /// The run was copied, repointed and invalidated; the completion is the
    /// host's to settle. Retry the faulting instruction.
    Resolved(CowGrantCompletion),
    /// The leaf already permits the write; the ASID was invalidated. Retry.
    AlreadyWritable,
    /// Left to the host (counted in the pool by reason).
    Declined(CowDecline),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestCowRun {
    pub va: u64,
    pub len: u64,
    pub old_ipa: u64,
    pub compound_offset: u64,
    pub executable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CowClassifyOutcome {
    Armed(GuestCowRun),
    AlreadyWritable,
    Declined(CowDecline),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CowRepointOp {
    pub mm_key: u64,
    pub grant_epoch: u64,
    pub va: u64,
    pub len: u64,
    pub old_ipa: u64,
    pub new_ipa: u64,
    pub backing: carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CowRepointOutcome {
    Applied { flush_required: bool },
    Refused,
    RolledBack,
    Indeterminate,
}

pub trait OwnerCowMmu {
    const CARRIER_MAINT_ROOT_BASE: u64;
    const DEFAULT_COW_COPY_BASE: u64;

    fn classify_cow_write<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: u64,
        far: u64,
        publish_executable: bool,
    ) -> CowClassifyOutcome;

    fn plan_cow_repoint<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: u64,
        op: CowRepointOp,
    ) -> bool;

    fn with_copy_aliases<W: LiveDescriptorWords + ?Sized, F: FnMut(u64, u64)>(
        words: &W,
        root: u64,
        copy_base: u64,
        source_ipa: u64,
        destination_ipa: u64,
        effect: &mut F,
    ) -> Result<(), CowRepointOutcome>;

    fn execute_cow_repoint<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: u64,
        op: CowRepointOp,
    ) -> CowRepointOutcome;
}

/// Where one MM's guest COW runs: its live table words and authenticated
/// root, the shared grant pool, and the MM's copy-window base.
pub struct CowCopyWindow<'a, B: OwnerCowMmu> {
    pub words: &'a dyn LiveDescriptorWords,
    pub root: SubstrateGpa,
    pub slot: Option<&'a dyn carrick_core_abi::ServiceCopyWindowLease>,
    pub default_base: u64,
    _arch: core::marker::PhantomData<B>,
}

impl<'a, B: OwnerCowMmu> Clone for CowCopyWindow<'a, B> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, B: OwnerCowMmu> Copy for CowCopyWindow<'a, B> {}

impl<'a, B: OwnerCowMmu> CowCopyWindow<'a, B> {
    /// The faulting target's fixed, preprovisioned alias pair. The caller
    /// holds that MM's editor and executes under its translation root.
    pub fn target(words: &'a dyn LiveDescriptorWords, root: SubstrateGpa) -> Self {
        Self {
            words,
            root,
            slot: None,
            default_base: B::DEFAULT_COW_COPY_BASE,
            _arch: core::marker::PhantomData,
        }
    }

    /// The service's current translation root and exclusive scheduler slot
    /// jointly authorize its pair. Borrowing the lease prevents reuse until
    /// the entire owner operation has restored the aliases.
    pub fn maintenance(
        words: &'a dyn LiveDescriptorWords,
        live_root: u64,
        slot: &'a dyn carrick_core_abi::ServiceCopyWindowLease,
    ) -> Option<Self> {
        (live_root == B::CARRIER_MAINT_ROOT_BASE).then_some(Self {
            words,
            root: SubstrateGpa(B::CARRIER_MAINT_ROOT_BASE),
            slot: Some(slot),
            default_base: B::DEFAULT_COW_COPY_BASE,
            _arch: core::marker::PhantomData,
        })
    }

    pub fn with_page(
        &self,
        source: u64,
        destination: u64,
        effect: &mut impl FnMut(u64, u64),
    ) -> Result<(), CowRepointOutcome> {
        B::with_copy_aliases(
            self.words,
            self.root.raw(),
            self.base(),
            source,
            destination,
            effect,
        )
    }

    pub fn base(&self) -> u64 {
        self.slot.map_or(self.default_base, |slot| slot.base())
    }
}

pub struct GuestCowVenue<'a, B: OwnerCowMmu, W: ?Sized> {
    pub words: &'a W,
    pub root: SubstrateGpa,
    pub pool: &'a dyn CowGrantVenue,
    pub residency: &'a FrameGrantResidencyTable,
    pub copy_window: CowCopyWindow<'a, B>,
    pub publish_executable: Option<&'a dyn Fn(carrick_core_abi::CowGrant, u64, u64) -> bool>,
}

/// Resolve one EL0 write permission fault at `far` for `mm_key` in `venue`.
/// `copy_page(source, destination)` copies one page between the two
/// copy-window aliases while both are mapped; `invalidate_asid` invalidates
/// the MM's ASID on every PE.
pub fn resolve_guest_cow<B, W, C, I>(
    venue: &GuestCowVenue<'_, B, W>,
    mm_key: u64,
    far: u64,
    mut copy_page: C,
    mut invalidate_asid: I,
) -> Result<GuestCowOutcome, CowError>
where
    B: OwnerCowMmu,
    W: LiveDescriptorWords + ?Sized,
    C: FnMut(u64, u64),
    I: FnMut(),
{
    let GuestCowVenue {
        words,
        root,
        pool,
        residency,
        copy_window,
        publish_executable,
    } = *venue;

    let run = match B::classify_cow_write(words, root.raw(), far, publish_executable.is_some()) {
        CowClassifyOutcome::Armed(run) => run,
        CowClassifyOutcome::AlreadyWritable => {
            invalidate_asid();
            return Ok(GuestCowOutcome::AlreadyWritable);
        }
        CowClassifyOutcome::Declined(reason) => {
            pool.note_declined(reason);
            return Ok(GuestCowOutcome::Declined(reason));
        }
    };

    let Some(grant) = pool.claim(mm_key) else {
        pool.note_declined(CowDecline::PoolEmpty);
        return Ok(GuestCowOutcome::Declined(CowDecline::PoolEmpty));
    };

    let decline = |pool: &dyn CowGrantVenue| -> Result<GuestCowOutcome, CowError> {
        if !pool.abandon(&grant) {
            return Err(CowError::Internal);
        }
        pool.note_declined(CowDecline::Refused);
        Ok(GuestCowOutcome::Declined(CowDecline::Refused))
    };

    let new_ipa = grant.physical_ipa + run.compound_offset;
    let op = CowRepointOp {
        mm_key,
        grant_epoch: grant.epoch,
        va: run.va,
        len: run.len,
        old_ipa: run.old_ipa,
        new_ipa,
        backing: grant.backing,
    };

    if !B::plan_cow_repoint(words, root.raw(), op) {
        return decline(pool);
    }

    if !residency.retire_small_span(mm_key, run.va, run.len) {
        return decline(pool);
    }

    for offset in (0..run.len).step_by(PAGE as usize) {
        let copied = copy_window.with_page(run.old_ipa + offset, new_ipa + offset, &mut copy_page);
        match copied {
            Ok(()) => {}
            Err(CowRepointOutcome::Indeterminate) => return Err(CowError::Indeterminate),
            Err(_) => return decline(pool),
        }
    }

    if run.executable && !publish_executable.is_some_and(|publish| publish(grant, new_ipa, run.len))
    {
        return decline(pool);
    }

    match B::execute_cow_repoint(words, root.raw(), op) {
        CowRepointOutcome::Applied { flush_required } => {
            if flush_required {
                invalidate_asid();
            }
            let replacement = carrick_core_abi::FrameGrantResidencyIdentity {
                mm_key,
                semantic_base: run.va,
                physical_ipa: new_ipa,
                len: run.len,
                mapping_id: grant.backing.mapping_id.get(),
                frame_id: grant.backing.frame_id.get(),
                owner_generation: grant.backing.owner_generation.get(),
                inventory_revision: grant.backing.inventory_revision.get(),
            };
            if residency.publish(replacement).is_some() {
                for offset in (0..run.len).step_by(PAGE as usize) {
                    let page = residency
                        .lookup(mm_key, run.va + offset)
                        .ok_or(CowError::Corrupt)?;
                    if !residency.record_commit(page) {
                        return Err(CowError::Corrupt);
                    }
                }
            }
            let completion = CowGrantCompletion {
                purpose: carrick_core_abi::CowGrantPurpose::UserWrite,
                grant,
                span_va: run.va,
                span_len: run.len,
                old_ipa: run.old_ipa,
                new_ipa,
            };
            if !pool.complete(&completion) {
                return Err(CowError::Internal);
            }
            Ok(GuestCowOutcome::Resolved(completion))
        }
        CowRepointOutcome::Refused => decline(pool),
        CowRepointOutcome::RolledBack => {
            invalidate_asid();
            decline(pool)
        }
        CowRepointOutcome::Indeterminate => Err(CowError::Indeterminate),
    }
}
