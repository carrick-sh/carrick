//! Guest fork-COW resolution with host-provisioned replacement frames.

use carrick_el1_abi::{CowDecline, CowGrantCompletion, CowGrantPool, FrameGrantResidencyTable};
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

impl OwnerCowMmu for carrick_mmu_core::owner_mmu::Aarch64Mmu {
    const CARRIER_MAINT_ROOT_BASE: u64 = carrick_el1_abi::EL1_CARRIER_MAINT_ROOT_BASE;
    const DEFAULT_COW_COPY_BASE: u64 = carrick_el1_abi::EL1_COW_COPY_BASE;

    fn classify_cow_write<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: u64,
        far: u64,
        publish_executable: bool,
    ) -> CowClassifyOutcome {
        use carrick_mmu_core::aarch64::descriptor_txn::guest_cow::{
            GuestCowClass, GuestCowNotArmed, classify_guest_cow_write,
        };
        match classify_guest_cow_write(words, SubstrateGpa(root), far, publish_executable) {
            Ok(run) => CowClassifyOutcome::Armed(GuestCowRun {
                va: run.va,
                len: run.len,
                old_ipa: run.old_ipa.raw(),
                compound_offset: run.compound_offset(),
                executable: run.executable,
            }),
            Err(GuestCowClass::AlreadyWritable) => CowClassifyOutcome::AlreadyWritable,
            Err(class @ (GuestCowClass::NotArmed(_) | GuestCowClass::Unreachable(_))) => {
                let reason = match class {
                    GuestCowClass::NotArmed(GuestCowNotArmed::Unmapped) => CowDecline::Unmapped,
                    GuestCowClass::NotArmed(GuestCowNotArmed::NotCowArmed) => {
                        CowDecline::NotCowArmed
                    }
                    GuestCowClass::NotArmed(GuestCowNotArmed::NotEl1Private) => {
                        CowDecline::NotEl1Private
                    }
                    GuestCowClass::NotArmed(GuestCowNotArmed::NoWriteIntent) => {
                        CowDecline::NoWriteIntent
                    }
                    GuestCowClass::NotArmed(GuestCowNotArmed::Executable) => CowDecline::Executable,
                    _ => CowDecline::Unreachable,
                };
                CowClassifyOutcome::Declined(reason)
            }
        }
    }

    fn plan_cow_repoint<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: u64,
        op: CowRepointOp,
    ) -> bool {
        use carrick_mmu_core::aarch64::descriptor_txn::{
            CowRepointAccess, DescriptorOp, plan_descriptor_op,
        };
        let desc_op = DescriptorOp::CowRepoint {
            access: CowRepointAccess::RecordedPrivate,
            va: op.va,
            len: op.len,
            old_ipa: SubstrateGpa(op.old_ipa),
            new_ipa: SubstrateGpa(op.new_ipa),
            backing: op.backing,
        };
        match plan_descriptor_op(words, SubstrateGpa(root), desc_op) {
            Ok(plan) => plan.table_grants == 0,
            _ => false,
        }
    }

    fn with_copy_aliases<W: LiveDescriptorWords + ?Sized, F: FnMut(u64, u64)>(
        words: &W,
        root: u64,
        copy_base: u64,
        source_ipa: u64,
        destination_ipa: u64,
        effect: &mut F,
    ) -> Result<(), CowRepointOutcome> {
        use carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome;
        carrick_mmu_core::aarch64::descriptor_txn::copy_window::with_cow_copy_aliases(
            words,
            SubstrateGpa(root),
            copy_base,
            SubstrateGpa(source_ipa),
            SubstrateGpa(destination_ipa),
            effect,
        )
        .map_err(|e| match e {
            DescriptorOutcome::Indeterminate(_) => CowRepointOutcome::Indeterminate,
            DescriptorOutcome::RolledBack(_) => CowRepointOutcome::RolledBack,
            _ => CowRepointOutcome::Refused,
        })
    }

    fn execute_cow_repoint<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: u64,
        op: CowRepointOp,
    ) -> CowRepointOutcome {
        use carrick_mmu_core::aarch64::descriptor_txn::{
            CowRepointAccess, DescriptorOp, DescriptorOutcome, InlineJournal, TableGrants,
            execute_descriptor_op,
        };
        let desc_op = DescriptorOp::CowRepoint {
            access: CowRepointAccess::RecordedPrivate,
            va: op.va,
            len: op.len,
            old_ipa: SubstrateGpa(op.old_ipa),
            new_ipa: SubstrateGpa(op.new_ipa),
            backing: op.backing,
        };
        let mut journal = InlineJournal::new();
        match execute_descriptor_op(
            words,
            SubstrateGpa(root),
            desc_op,
            &TableGrants::NONE,
            &mut journal,
        ) {
            DescriptorOutcome::Applied(applied) => CowRepointOutcome::Applied {
                flush_required: applied.flush_required,
            },
            DescriptorOutcome::Refused(_) => CowRepointOutcome::Refused,
            DescriptorOutcome::RolledBack(_) => CowRepointOutcome::RolledBack,
            DescriptorOutcome::Indeterminate(_) => CowRepointOutcome::Indeterminate,
        }
    }
}

impl OwnerCowMmu for carrick_mmu_core::x86::owner_mmu::X86Mmu {
    const CARRIER_MAINT_ROOT_BASE: u64 = 0;
    const DEFAULT_COW_COPY_BASE: u64 = 0;

    fn classify_cow_write<W: LiveDescriptorWords + ?Sized>(
        _words: &W,
        _root: u64,
        _far: u64,
        _publish_executable: bool,
    ) -> CowClassifyOutcome {
        CowClassifyOutcome::Declined(CowDecline::Unreachable)
    }

    fn plan_cow_repoint<W: LiveDescriptorWords + ?Sized>(
        _words: &W,
        _root: u64,
        _op: CowRepointOp,
    ) -> bool {
        false
    }

    fn with_copy_aliases<W: LiveDescriptorWords + ?Sized, F: FnMut(u64, u64)>(
        _words: &W,
        _root: u64,
        _copy_base: u64,
        _source_ipa: u64,
        _destination_ipa: u64,
        _effect: &mut F,
    ) -> Result<(), CowRepointOutcome> {
        Err(CowRepointOutcome::Refused)
    }

    fn execute_cow_repoint<W: LiveDescriptorWords + ?Sized>(
        _words: &W,
        _root: u64,
        _op: CowRepointOp,
    ) -> CowRepointOutcome {
        CowRepointOutcome::Refused
    }
}

/// Where one MM's guest COW runs: its live table words and authenticated
/// root, the shared grant pool, and the MM's copy-window base.
#[derive(Clone, Copy)]
pub struct CowCopyWindow<'a> {
    pub words: &'a dyn LiveDescriptorWords,
    pub root: SubstrateGpa,
    pub slot: Option<&'a carrick_el1_abi::ServiceCopyLease<'a>>,
    pub default_base: u64,
}

impl<'a> CowCopyWindow<'a> {
    /// The faulting target's fixed, preprovisioned alias pair. The caller
    /// holds that MM's editor and executes under its translation root.
    pub fn target(words: &'a dyn LiveDescriptorWords, root: SubstrateGpa) -> Self {
        Self::target_arch::<carrick_mmu_core::owner_mmu::Aarch64Mmu>(words, root)
    }

    pub fn target_arch<B: OwnerCowMmu>(
        words: &'a dyn LiveDescriptorWords,
        root: SubstrateGpa,
    ) -> Self {
        Self {
            words,
            root,
            slot: None,
            default_base: B::DEFAULT_COW_COPY_BASE,
        }
    }

    /// The service's current translation root and exclusive scheduler slot
    /// jointly authorize its pair. Borrowing the lease prevents reuse until
    /// the entire owner operation has restored the aliases.
    pub fn maintenance(
        words: &'a dyn LiveDescriptorWords,
        live_root: u64,
        slot: &'a carrick_el1_abi::ServiceCopyLease<'a>,
    ) -> Option<Self> {
        Self::maintenance_arch::<carrick_mmu_core::owner_mmu::Aarch64Mmu>(words, live_root, slot)
    }

    pub fn maintenance_arch<B: OwnerCowMmu>(
        words: &'a dyn LiveDescriptorWords,
        live_root: u64,
        slot: &'a carrick_el1_abi::ServiceCopyLease<'a>,
    ) -> Option<Self> {
        (live_root == B::CARRIER_MAINT_ROOT_BASE).then_some(Self {
            words,
            root: SubstrateGpa(B::CARRIER_MAINT_ROOT_BASE),
            slot: Some(slot),
            default_base: B::DEFAULT_COW_COPY_BASE,
        })
    }

    pub fn with_page(
        &self,
        source: u64,
        destination: u64,
        effect: &mut impl FnMut(u64, u64),
    ) -> Result<(), carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome> {
        carrick_mmu_core::aarch64::descriptor_txn::copy_window::with_cow_copy_aliases(
            self.words,
            self.root,
            self.base(),
            SubstrateGpa(source),
            SubstrateGpa(destination),
            effect,
        )
    }

    pub fn base(&self) -> u64 {
        self.slot.map_or(self.default_base, |slot| slot.base())
    }
}

pub struct GuestCowVenue<'a, W: ?Sized> {
    pub words: &'a W,
    pub root: SubstrateGpa,
    pub pool: &'a CowGrantPool,
    pub residency: &'a FrameGrantResidencyTable,
    pub copy_window: CowCopyWindow<'a>,
    pub publish_executable: Option<&'a dyn Fn(carrick_el1_abi::CowGrant, u64, u64) -> bool>,
}

/// Resolve one EL0 write permission fault at `far` for `mm_key` in `venue`.
/// `copy_page(source, destination)` copies one page between the two
/// copy-window aliases while both are mapped; `invalidate_asid` invalidates
/// the MM's ASID on every PE.
pub fn resolve_guest_cow<B, W, C, I>(
    venue: &GuestCowVenue<'_, W>,
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

    let decline = |pool: &CowGrantPool| -> Result<GuestCowOutcome, CowError> {
        if !pool.abandon(&grant) {
            return Err(CowError::Internal);
        }
        pool.note_declined(CowDecline::Refused);
        Ok(GuestCowOutcome::Declined(CowDecline::Refused))
    };

    let new_ipa = grant.physical_ipa + run.compound_offset;
    let op = CowRepointOp {
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
        let copied = B::with_copy_aliases(
            copy_window.words,
            copy_window.root.raw(),
            copy_window.base(),
            run.old_ipa + offset,
            new_ipa + offset,
            &mut copy_page,
        );
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
            let replacement = carrick_el1_abi::FrameGrantResidencyIdentity {
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
                purpose: carrick_el1_abi::CowGrantPurpose::UserWrite,
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
