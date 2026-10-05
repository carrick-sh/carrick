//! Guest fork-COW resolution with host-provisioned replacement frames.

use carrick_el1_abi::{CowDecline, CowGrantCompletion, CowGrantPool, FrameGrantResidencyTable};
use carrick_mmu_core::aarch64::SubstrateGpa;
use carrick_mmu_core::aarch64::descriptor_txn::copy_window::with_cow_copy_aliases;
use carrick_mmu_core::aarch64::descriptor_txn::guest_cow::{
    GuestCowClass, GuestCowNotArmed, classify_guest_cow_write,
};
use carrick_mmu_core::aarch64::descriptor_txn::{
    CowRepointAccess, DescriptorOp, DescriptorOutcome, InlineJournal, LiveDescriptorWords,
    TableGrants, execute_descriptor_op, plan_descriptor_op,
};

const PAGE: u64 = 4096;

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

/// Where one MM's guest COW runs: its live table words and authenticated
/// root, the shared grant pool, and the MM's copy-window base.
#[derive(Clone, Copy)]
pub struct CowCopyWindow<'a> {
    words: &'a dyn LiveDescriptorWords,
    root: SubstrateGpa,
    slot: Option<&'a carrick_el1_abi::ServiceCopyLease<'a>>,
}

impl<'a> CowCopyWindow<'a> {
    /// The faulting target's fixed, preprovisioned alias pair. The caller
    /// holds that MM's editor and executes under its translation root.
    pub fn target(words: &'a dyn LiveDescriptorWords, root: SubstrateGpa) -> Self {
        Self {
            words,
            root,
            slot: None,
        }
    }

    /// The service's current translation root and exclusive scheduler slot
    /// jointly authorize its pair. Borrowing the lease prevents reuse until
    /// the entire owner operation has restored the aliases.
    pub fn maintenance(
        words: &'a dyn LiveDescriptorWords,
        live_ttbr: u64,
        slot: &'a carrick_el1_abi::ServiceCopyLease<'a>,
    ) -> Option<Self> {
        (live_ttbr == carrick_el1_abi::EL1_CARRIER_MAINT_ROOT_BASE).then_some(Self {
            words,
            root: SubstrateGpa(carrick_el1_abi::EL1_CARRIER_MAINT_ROOT_BASE),
            slot: Some(slot),
        })
    }

    pub fn with_page(
        &self,
        source: u64,
        destination: u64,
        effect: &mut impl FnMut(u64, u64),
    ) -> Result<(), DescriptorOutcome> {
        with_cow_copy_aliases(
            self.words,
            self.root,
            self.base(),
            SubstrateGpa(source),
            SubstrateGpa(destination),
            effect,
        )
    }

    fn base(&self) -> u64 {
        self.slot
            .map_or(carrick_el1_abi::EL1_COW_COPY_BASE, |slot| slot.base())
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
///
/// # Panics
///
/// When a store sequence can neither complete nor roll back (the live graph
/// is no longer the one this editor validated): continuing would run the MM
/// on unknown translations.
pub fn resolve_guest_cow<W, C, I>(
    venue: &GuestCowVenue<'_, W>,
    mm_key: u64,
    far: u64,
    mut copy_page: C,
    mut invalidate_asid: I,
) -> GuestCowOutcome
where
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
    let run = match classify_guest_cow_write(words, root, far, publish_executable.is_some()) {
        Ok(run) => run,
        Err(GuestCowClass::AlreadyWritable) => {
            invalidate_asid();
            return GuestCowOutcome::AlreadyWritable;
        }
        Err(class @ (GuestCowClass::NotArmed(_) | GuestCowClass::Unreachable(_))) => {
            let reason = match class {
                GuestCowClass::NotArmed(GuestCowNotArmed::Unmapped) => CowDecline::Unmapped,
                GuestCowClass::NotArmed(GuestCowNotArmed::NotCowArmed) => CowDecline::NotCowArmed,
                GuestCowClass::NotArmed(GuestCowNotArmed::NotEl1Private) => {
                    CowDecline::NotEl1Private
                }
                GuestCowClass::NotArmed(GuestCowNotArmed::NoWriteIntent) => {
                    CowDecline::NoWriteIntent
                }
                GuestCowClass::NotArmed(GuestCowNotArmed::Executable) => CowDecline::Executable,
                _ => CowDecline::Unreachable,
            };
            pool.note_declined(reason);
            return GuestCowOutcome::Declined(reason);
        }
    };
    let Some(grant) = pool.claim(mm_key) else {
        pool.note_declined(CowDecline::PoolEmpty);
        return GuestCowOutcome::Declined(CowDecline::PoolEmpty);
    };
    let decline = |pool: &CowGrantPool| {
        let abandoned = pool.abandon(&grant);
        assert!(abandoned, "EL1 lost its claimed COW grant");
        pool.note_declined(CowDecline::Refused);
        GuestCowOutcome::Declined(CowDecline::Refused)
    };
    let new_ipa = grant.physical_ipa + run.compound_offset();
    let op = DescriptorOp::CowRepoint {
        access: CowRepointAccess::RecordedPrivate,
        va: run.va,
        len: run.len,
        old_ipa: run.old_ipa,
        new_ipa: SubstrateGpa(new_ipa),
        backing: grant.backing,
    };
    // Validate the whole repoint (no table split, every leaf still the
    // classified one) before copying a byte.
    match plan_descriptor_op(words, root, op) {
        Ok(plan) if plan.table_grants == 0 => {}
        _ => return decline(pool),
    }
    // Revoke old grant-window tokens before changing their translation. A
    // failed copy may lose residency acceleration, but cannot leave an old
    // token authorizing a replacement frame. Physical custody stays on host.
    if !residency.retire_small_span(mm_key, run.va, run.len) {
        return decline(pool);
    }
    for offset in (0..run.len).step_by(PAGE as usize) {
        let copied = with_cow_copy_aliases(
            copy_window.words,
            copy_window.root,
            copy_window.base(),
            SubstrateGpa(run.old_ipa.raw() + offset),
            SubstrateGpa(new_ipa + offset),
            &mut copy_page,
        );
        match copied {
            Ok(()) => {}
            Err(DescriptorOutcome::Indeterminate(refusal)) => {
                panic!("EL1 COW copy window could not be restored: {refusal:?}")
            }
            Err(_) => return decline(pool),
        }
    }
    if run.executable && !publish_executable.is_some_and(|publish| publish(grant, new_ipa, run.len))
    {
        return decline(pool);
    }
    let mut journal = InlineJournal::new();
    match execute_descriptor_op(words, root, op, &TableGrants::NONE, &mut journal) {
        DescriptorOutcome::Applied(applied) => {
            if applied.flush_required {
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
            // Saturation only declines acceleration; the descriptor and COW
            // completion retain their existing production authority.
            if residency.publish(replacement).is_some() {
                for offset in (0..run.len).step_by(PAGE as usize) {
                    let page = residency
                        .lookup(mm_key, run.va + offset)
                        .expect("published COW grant window disappeared under its editor");
                    assert!(residency.record_commit(page));
                }
            }
            let completion = CowGrantCompletion {
                purpose: carrick_el1_abi::CowGrantPurpose::UserWrite,
                grant,
                span_va: run.va,
                span_len: run.len,
                old_ipa: run.old_ipa.raw(),
                new_ipa,
            };
            let recorded = pool.complete(&completion);
            assert!(recorded, "EL1 COW completion was not recordable");
            GuestCowOutcome::Resolved(completion)
        }
        DescriptorOutcome::Refused(_) => decline(pool),
        DescriptorOutcome::RolledBack(_) => {
            invalidate_asid();
            decline(pool)
        }
        DescriptorOutcome::Indeterminate(refusal) => {
            panic!("EL1 COW repoint rollback failed: {refusal:?}")
        }
    }
}
