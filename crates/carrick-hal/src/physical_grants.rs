//! Shared staging of exact-MM physical grants. Backends retain bytes and
//! apply the owner's publication receipts; this module owns no VMA policy.
use crate::{
    FrameCowAuthority, FrameEventCapacity, FrameInventoryEvent, FrameLength, GuestFrameOwner,
    MappingGeneration, MemPerms, PhysicalFrameInventory, TrapError, UnpublishedFrameInventoryApply,
};
use carrick_guest_arch::FrameGpa;
use carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity;
use std::{num::NonZeroU64, sync::Arc};

/// COW stock must also support a later executable publication. Stage-1
/// descriptors retain access policy; physical supply cannot narrow it.
pub const COW_GRANT_PERMISSIONS: MemPerms = MemPerms {
    read: true,
    write: true,
    exec: true,
};

/// Failed unpublished rollback remains in carrier custody. Explicit abort
/// callers propagate the invariant failure before reopening admission;
/// destructors only retain custody, never decide terminal policy or discard
/// the issuing authority on refusal.
#[derive(Default)]
pub struct PhysicalGrantRollback {
    receipts: parking_lot::Mutex<Vec<FailedPhysicalGrant>>,
}
struct FailedPhysicalGrant {
    _receipt: UnpublishedFrameInventoryApply<dyn FrameCowAuthority>,
    _backing: Option<Box<dyn Send>>,
}
impl PhysicalGrantRollback {
    pub fn failed(&self) -> bool {
        !self.receipts.lock().is_empty()
    }
    pub fn retain(&self, receipt: UnpublishedFrameInventoryApply<dyn FrameCowAuthority>) {
        self.receipts.lock().push(FailedPhysicalGrant {
            _receipt: receipt,
            _backing: None,
        });
    }
    fn retain_backed<R: Send + 'static>(
        &self,
        receipt: UnpublishedFrameInventoryApply<dyn FrameCowAuthority>,
        backing: Option<R>,
    ) {
        self.receipts.lock().push(FailedPhysicalGrant {
            _receipt: receipt,
            _backing: backing.map(|backing| Box::new(backing) as Box<dyn Send>),
        });
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PhysicalFrameGrant {
    pub gpa: FrameGpa,
    pub identity: BackingIdentity,
}

/// An unapplied-to-descriptors inventory transaction. The receipt remains
/// bound to the authority that issued it through rollback or publication.
#[must_use = "retain rollback custody until the publication owner accepts these grants"]
pub struct StagedPhysicalGrants {
    owner: GuestFrameOwner,
    rollback: Arc<PhysicalGrantRollback>,
    authority: Arc<dyn FrameCowAuthority>,
    receipt: Option<UnpublishedFrameInventoryApply<dyn FrameCowAuthority>>,
    frames: Vec<(FrameGpa, BackingIdentity)>,
    length: FrameLength,
    permissions: MemPerms,
    grants: Vec<PhysicalFrameGrant>,
}
/// Publication owner custody, transferred before any descriptor can expose a
/// grant. The recipient must retain the exact receipt through commit/rollback.
pub struct PhysicalGrantCustody {
    pub authority: Arc<dyn FrameCowAuthority>,
    pub receipt: UnpublishedFrameInventoryApply<dyn FrameCowAuthority>,
    pub frames: Vec<(FrameGpa, BackingIdentity)>,
    pub length: FrameLength,
    pub grants: Vec<PhysicalFrameGrant>,
}
impl StagedPhysicalGrants {
    /// Couple allocation custody to an unpublished inventory apply. Keep this
    /// value until the publication owner accepts both obligations. It must
    /// never be used to undo a reply the ring could already have consumed.
    pub fn with_backing<R: Send + 'static>(self, backing: R) -> UnpublishedPhysicalGrant<R> {
        UnpublishedPhysicalGrant {
            staged: self,
            backing: Some(backing),
        }
    }
    pub fn authority(&self) -> &Arc<dyn FrameCowAuthority> {
        &self.authority
    }
    pub fn grants(&self) -> &[PhysicalFrameGrant] {
        &self.grants
    }
    /// Move the rollback obligation into the caller's publication transaction.
    pub fn handoff(mut self) -> Result<PhysicalGrantCustody, TrapError> {
        self.take_custody()
    }
    fn take_custody(&mut self) -> Result<PhysicalGrantCustody, TrapError> {
        let receipt = self
            .receipt
            .take()
            .ok_or_else(|| TrapError::Hypervisor("physical staging receipt absent".into()))?;
        Ok(PhysicalGrantCustody {
            authority: Arc::clone(&self.authority),
            receipt,
            frames: std::mem::take(&mut self.frames),
            length: self.length,
            grants: std::mem::take(&mut self.grants),
        })
    }
    pub fn stage(
        rollback: Arc<PhysicalGrantRollback>,
        source: Arc<dyn PhysicalFrameInventory>,
        gpas: impl IntoIterator<Item = FrameGpa>,
        table_grants: usize,
        frame_len: u64,
        owner: GuestFrameOwner,
    ) -> Result<Self, TrapError> {
        Self::stage_with_permissions(
            rollback,
            source,
            gpas,
            table_grants,
            frame_len,
            owner,
            MemPerms {
                read: true,
                write: true,
                exec: false,
            },
        )
    }
    pub fn stage_with_permissions(
        rollback: Arc<PhysicalGrantRollback>,
        source: Arc<dyn PhysicalFrameInventory>,
        gpas: impl IntoIterator<Item = FrameGpa>,
        table_grants: usize,
        frame_len: u64,
        owner: GuestFrameOwner,
        permissions: MemPerms,
    ) -> Result<Self, TrapError> {
        let fail = TrapError::Hypervisor;
        let authority = source.bind(owner);
        let gpas: Vec<_> = gpas.into_iter().collect();
        if table_grants >= gpas.len() {
            return Err(fail("initial inventory grant partition".into()));
        }
        let capacity = FrameEventCapacity::for_event_count(
            gpas.len()
                .checked_mul(2)
                .ok_or_else(|| fail("initial inventory capacity".into()))?,
        )
        .map_err(|error| fail(format!("initial inventory capacity: {error}")))?;
        let mut reservation = authority
            .reserve(gpas.len(), gpas.len(), capacity.get())
            .map_err(|error| fail(format!("initial inventory reserve: {error}")))?;
        let transaction = reservation.transaction();
        // These mapping IDs were just reserved. Their inventory generation
        // starts here, independently of the retained carrier extent's owner
        // generation. Backends cannot supply that other domain as this one.
        let owner_generation = NonZeroU64::MIN;
        let generation = MappingGeneration::from_backend_counter(owner_generation);
        let length = FrameLength::from_mapping_extent(
            NonZeroU64::new(frame_len).ok_or_else(|| fail("initial frame length".into()))?,
        );
        let mut rows = Vec::with_capacity(gpas.len());
        for (index, gpa) in gpas.into_iter().enumerate() {
            let frame = reservation
                .claim_frame()
                .map_err(|error| fail(format!("initial frame candidate: {error}")))?;
            let mapping = reservation
                .claim_mapping()
                .map_err(|error| fail(format!("initial mapping candidate: {error}")))?;
            if index >= table_grants {
                reservation
                    .push(FrameInventoryEvent::PrepareMapping {
                        transaction,
                        frame,
                        mapping,
                        generation,
                        gpa: carrick_guest_mem::Gpa::new(gpa.raw()),
                        length,
                        permissions,
                    })
                    .map_err(|error| fail(format!("initial inventory prepare: {error}")))?;
                reservation
                    .push(FrameInventoryEvent::PublishMapping {
                        transaction,
                        mapping,
                        generation,
                    })
                    .map_err(|error| fail(format!("initial inventory publish: {error}")))?;
            }
            rows.push((gpa, frame, mapping, index >= table_grants));
        }
        let receipt =
            UnpublishedFrameInventoryApply::apply(Arc::clone(&authority), reservation.commit(()))
                .map_err(|error| fail(format!("initial inventory apply: {error}")))?;
        let mut staged = Self {
            owner,
            rollback,
            authority,
            receipt: Some(receipt),
            frames: Vec::with_capacity(rows.len() - table_grants),
            length,
            permissions,
            grants: Vec::with_capacity(rows.len()),
        };
        let receipt = staged
            .receipt
            .as_ref()
            .ok_or_else(|| fail("physical staging receipt absent".into()))?;
        for (gpa, frame, mapping, is_data) in rows {
            if is_data && !receipt.authorizes(mapping, frame) {
                return Err(fail("initial inventory missing mapping".into()));
            }
            let identity = BackingIdentity {
                frame_id: NonZeroU64::new(frame.raw())
                    .ok_or_else(|| fail("initial frame identity".into()))?,
                mapping_id: NonZeroU64::new(mapping.raw())
                    .ok_or_else(|| fail("initial mapping identity".into()))?,
                owner_generation,
                inventory_revision: NonZeroU64::new(receipt.revision())
                    .ok_or_else(|| fail("initial inventory revision".into()))?,
            };
            if is_data {
                staged.frames.push((gpa, identity));
            }
            staged.grants.push(PhysicalFrameGrant { gpa, identity });
        }
        staged.frames.sort_unstable_by_key(|(gpa, _)| gpa.raw());
        Ok(staged)
    }
}

impl Drop for StagedPhysicalGrants {
    fn drop(&mut self) {
        if let Some(mut receipt) = self.receipt.take()
            && receipt.rollback().is_err()
        {
            self.rollback.retain(receipt);
        }
    }
}

/// Pre-offer custody only: an allocation lease survives a failed inventory
/// undo together with its issuing receipt. No descriptor has been offered or
/// published while this value owns rollback authority. Full reply settlement
/// additionally needs descriptor, residency, table and stage-2 journals.
#[must_use = "transfer to the publication owner or explicitly abort before offering a reply"]
pub struct UnpublishedPhysicalGrant<R: Send + 'static> {
    staged: StagedPhysicalGrants,
    backing: Option<R>,
}
impl<R: Send + 'static> UnpublishedPhysicalGrant<R> {
    pub fn grants(&self) -> &[PhysicalFrameGrant] {
        self.staged.grants()
    }
    /// Undo inventory before allocation retirement is requested by releasing
    /// its lease. An indeterminate undo retains the receipt AND lease in the
    /// issuing MM's failure custody. The caller must fail the carrier on Err;
    /// it must not report an ordinary supply refusal or reopen admission.
    pub fn abort_inventory(mut self) -> Result<(), TrapError> {
        self.rollback_inventory()
    }
    fn rollback_inventory(&mut self) -> Result<(), TrapError> {
        if let Some(mut receipt) = self.staged.receipt.take()
            && receipt.rollback().is_err()
        {
            self.staged
                .rollback
                .retain_backed(receipt, self.backing.take());
            return Err(TrapError::Hypervisor(
                "unpublished physical grant inventory rollback indeterminate".into(),
            ));
        }
        Ok(())
    }
    fn handoff(mut self) -> Result<(PhysicalGrantCustody, R), TrapError> {
        let custody = self.staged.take_custody()?;
        let backing = self.backing.take().ok_or_else(|| {
            TrapError::Hypervisor("unpublished physical grant backing absent".into())
        })?;
        Ok((custody, backing))
    }
}
impl<R: Send + 'static> Drop for UnpublishedPhysicalGrant<R> {
    fn drop(&mut self) {
        // Drop retains failure custody, but never chooses terminal policy.
        // Native refusal paths use abort_inventory and propagate its result.
        let _ = self.rollback_inventory();
    }
}

/// Physical publications retained by one native MM. The neutral fork owner
/// drops this custody only after MM inventory retirement and slot absence.
pub struct NativePhysicalGrants<R> {
    owner: GuestFrameOwner,
    grants: std::collections::BTreeMap<u64, NativeGrant<R>>,
}
struct NativeGrant<R> {
    custody: PhysicalGrantCustody,
    _retained: R,
    published: Option<carrick_el1_abi::CowGrant>,
}
impl<R> core::fmt::Debug for NativePhysicalGrants<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativePhysicalGrants")
            .field("owner", &self.owner)
            .field("grants", &self.grants.len())
            .finish()
    }
}
impl<R> NativePhysicalGrants<R> {
    pub const REFILL_GRANTS: usize = 2;
    pub fn new(owner: GuestFrameOwner) -> Self {
        Self {
            owner,
            grants: Default::default(),
        }
    }
    pub fn owner(&self) -> GuestFrameOwner {
        self.owner
    }
    /// Retain the inventory receipt and backing before publishing READY. The
    /// exclusion keeps the ring from observing a partly admitted batch.
    pub fn publish_cow(
        &mut self,
        unpublished: UnpublishedPhysicalGrant<R>,
        pool: &carrick_el1_abi::CowGrantPool,
        excluded: &carrick_sched_core::ExcludedEditor<'_>,
    ) -> Result<(), TrapError>
    where
        R: Send + 'static,
    {
        let fail = || TrapError::Hypervisor("native physical grant admission mismatch".into());
        let staged = &unpublished.staged;
        if excluded.key() != self.owner.native_mm.raw().get()
            || staged.owner != self.owner
            || staged.grants.len() != 1
            || staged.length.raw() != carrick_el1_abi::COW_GRANT_SIZE
            || staged.permissions != COW_GRANT_PERMISSIONS
            || pool.ready(excluded.key()).count() >= Self::REFILL_GRANTS
        {
            unpublished.abort_inventory()?;
            return Err(fail());
        }
        let grant = staged.grants[0];
        if self.grants.contains_key(&grant.gpa.raw()) {
            unpublished.abort_inventory()?;
            return Err(fail());
        }
        let (custody, retained) = unpublished.handoff()?;
        let entry = self.grants.entry(grant.gpa.raw()).or_insert(NativeGrant {
            custody,
            _retained: retained,
            published: None,
        });
        let published = pool
            .publish(excluded.key(), grant.gpa.raw(), grant.identity)
            .ok_or_else(fail)?;
        entry.published = Some(published);
        Ok(())
    }
    /// Retain an isolated backing/table publication before its reply is visible.
    pub fn retain_backing(
        &mut self,
        unpublished: UnpublishedPhysicalGrant<R>,
    ) -> Result<Vec<PhysicalFrameGrant>, TrapError>
    where
        R: Send + 'static,
    {
        let staged = &unpublished.staged;
        if staged.owner != self.owner
            || staged.frames.len() != 1
            || staged.length.raw() > carrick_el1_abi::EL1_FRAME_GRANT_TARGET_SIZE
            || self.grants.contains_key(&staged.frames[0].0.raw())
        {
            unpublished.abort_inventory()?;
            return Err(TrapError::Hypervisor(
                "native backing publication mismatch".into(),
            ));
        }
        let key = staged.frames[0].0.raw();
        let grants = staged.grants.clone();
        let (custody, retained) = unpublished.handoff()?;
        self.grants.insert(
            key,
            NativeGrant {
                custody,
                _retained: retained,
                published: None,
            },
        );
        Ok(grants)
    }
    /// Settle exact USED receipts while the MM editor is excluded.
    ///
    /// USED authenticates a completed ring-owned publication, not the current
    /// descriptor: a later MAP_FIXED or unmap may already have replaced it.
    /// This owner authenticates retained physical custody and completes the
    /// pool record exactly once; no backend descriptor verdict is accepted.
    pub fn settle(
        &mut self,
        pool: &carrick_el1_abi::CowGrantPool,
        excluded: &carrick_sched_core::ExcludedEditor<'_>,
    ) -> Result<usize, TrapError> {
        let fail = || TrapError::Hypervisor("native USED physical receipt mismatch".into());
        if excluded.key() != self.owner.native_mm.raw().get() || pool.claimed_by(excluded) {
            return Err(fail());
        }
        let mut count = 0;
        for completion in pool.completions(excluded) {
            if !completion.is_well_formed() {
                return Err(fail());
            }
            let grant = completion.grant;
            let entry = self.grants.get_mut(&grant.physical_ipa).ok_or_else(fail)?;
            let identity = grant.backing;
            if entry.published != Some(grant)
                || !entry.custody.authority.mapping_is_live_exact_generation(
                    crate::MappingId::from_kernel_allocation(identity.mapping_id),
                    crate::FrameId::from_kernel_allocation(identity.frame_id),
                    MappingGeneration::from_backend_counter(identity.owner_generation),
                    carrick_guest_mem::Gpa::new(grant.physical_ipa),
                    entry.custody.length,
                )
                || !pool.finish(excluded, &grant)
            {
                return Err(fail());
            }
            entry.published = None;
            count += 1;
        }
        Ok(count)
    }
}
