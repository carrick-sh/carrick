//! Shared staging of exact-MM physical grants. Backends retain bytes and
//! apply the owner's publication receipts; this module owns no VMA policy.
use crate::{
    FrameCowAuthority, FrameEventCapacity, FrameInventoryEvent, FrameLength, GuestFrameOwner,
    MappingGeneration, MemPerms, PhysicalFrameInventory, TrapError, UnpublishedFrameInventoryApply,
};
use carrick_guest_arch::FrameGpa;
use carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity;
use std::{num::NonZeroU64, sync::Arc};

#[derive(Clone, Copy, Debug)]
pub struct PhysicalFrameGrant {
    pub gpa: FrameGpa,
    pub identity: BackingIdentity,
}

/// An unapplied-to-descriptors inventory transaction. The receipt remains
/// bound to the authority that issued it through rollback or publication.
#[must_use = "retain rollback custody until the publication owner accepts these grants"]
pub struct StagedPhysicalGrants {
    authority: Arc<dyn FrameCowAuthority>,
    receipt: Option<UnpublishedFrameInventoryApply<dyn FrameCowAuthority>>,
    frames: Vec<(FrameGpa, BackingIdentity)>,
    length: FrameLength,
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
    pub fn authority(&self) -> &Arc<dyn FrameCowAuthority> {
        &self.authority
    }
    pub fn grants(&self) -> &[PhysicalFrameGrant] {
        &self.grants
    }
    /// Move the rollback obligation into the caller's publication transaction.
    pub fn handoff(mut self) -> Result<PhysicalGrantCustody, TrapError> {
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
        source: Arc<dyn PhysicalFrameInventory>,
        gpas: impl IntoIterator<Item = FrameGpa>,
        table_grants: usize,
        frame_len: u64,
        owner_generation: NonZeroU64,
        owner: GuestFrameOwner,
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
                        permissions: MemPerms {
                            read: true,
                            write: true,
                            exec: false,
                        },
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
            authority,
            receipt: Some(receipt),
            frames: Vec::with_capacity(rows.len() - table_grants),
            length,
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
        if let Some(receipt) = &mut self.receipt
            && let Err(error) = receipt.rollback()
        {
            carrick_fatal::carrick_fatal!(
                "hal::physical_grants",
                "unexposed physical staging rollback failed: {error}"
            );
        }
    }
}
