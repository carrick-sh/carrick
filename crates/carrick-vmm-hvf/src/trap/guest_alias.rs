//! Guest-owned-lane alias publication.
//!
//! On a guest-owned MM the host never stores a live stage-1 descriptor; a
//! VA range that must name an existing stage-2 extent is published as EL1
//! `DescriptorOp::MapAlias` transactions. Every such writer (MAP_FIXED
//! repoint, shared-aperture identity restore, a new host alias) needs the
//! same two things, defined once here:
//!
//! * the backing identity EL1 carries: read from the live inventory extent
//!   that contains the target IPA and authenticated by the kernel authority
//!   at its current revision, with the physical owner pinned;
//! * the `MapAlias` publisher: GIC-window refusal before any submission
//!   (EL1 does not check the excluded output window; the host editor's
//!   `map_aliased` does), and chunking that stays inside the fixed
//!   table-grant capacity of one transaction.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use super::*;
use carrick_aarch64::vmm::{GuestAliasRefusal, Stage1Services};
use carrick_fatal::carrick_fatal;
use carrick_mmu_core::aarch64::descriptor_txn::{
    AliasAccess, BackingIdentity, DescriptorOp, PageSpan,
};
use carrick_mmu_core::aarch64::{LiveDescriptorOwner, PtOp, SubstrateGpa, TerminalRule};
use std::num::NonZeroU64;

const TWO_MIB: u64 = 1 << 21;
const ONE_GIB: u64 = 1 << 30;

/// One authenticated piece of an alias target: a logical inventory extent
/// clipped to the target range, its EL1 backing identity, and the pinned
/// physical owner. Holding it keeps the owner live through publication.
pub(super) struct RetainedAliasTarget {
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) physical_base: u64,
    pub(super) backing: BackingIdentity,
    pub(super) pin: GlobalFrameOwnerPin,
}

/// How a `MapAlias` publication stopped. The variants are the facts a caller
/// needs to choose between refusal, rollback and fail-stop.
#[derive(Debug)]
pub(super) enum AliasPublishFailure {
    /// Nothing from this publication is live: nothing was submitted (GIC
    /// window, or the first chunk's plan), or EL1 cleanly refused the first
    /// chunk (`GuestPublishError::NotApplied`).
    Unsubmitted(TrapError),
    /// A later chunk failed to prepare after earlier chunks were published.
    PartiallyPublished(TrapError),
    /// A chunk was submitted but no verified completion came back: its leaf
    /// state is unknown until something else authoritatively rewrites it.
    Unverified(TrapError),
    /// The verified receipt names another transaction.
    CrossedReceipt,
}

impl AliasPublishFailure {
    fn into_error(self) -> TrapError {
        match self {
            Self::Unsubmitted(error)
            | Self::PartiallyPublished(error)
            | Self::Unverified(error) => error,
            Self::CrossedReceipt => {
                TrapError::Hypervisor("alias receipt names another transaction".to_owned())
            }
        }
    }
}

/// `[offset, offset + count)` pieces of an alias publication, each within
/// one transaction's table-grant capacity. When VA and IPA are congruent mod
/// 2 MiB a piece may cover a whole 1 GiB-aligned VA span (at most an L1 and
/// an L2 table plus two edge L3 tables); otherwise every 2 MiB needs its own
/// L3 table, so pieces stop at 2 MiB VA boundaries.
pub(super) fn map_alias_chunks(va: u64, ipa: u64, len: u64) -> Vec<(u64, u64)> {
    let granule = if (va ^ ipa) & (TWO_MIB - 1) == 0 {
        ONE_GIB
    } else {
        TWO_MIB
    };
    let mut chunks = Vec::new();
    let mut offset = 0;
    while offset < len {
        let cursor = va + offset;
        let boundary = (cursor & !(granule - 1)) + granule;
        let count = (boundary - cursor).min(len - offset);
        chunks.push((offset, count));
        offset += count;
    }
    chunks
}

/// The inputs every guest-lane alias writer shares, borrowed from one MM.
pub(super) struct GuestAliasContext<'a> {
    pub(super) custody: &'a CarrierVmCustody,
    pub(super) ledger: &'a parking_lot::Mutex<HvpatchFrameInventory>,
    pub(super) authority: &'a dyn carrick_hal::FrameCowAuthority,
    pub(super) tables: &'a carrick_aarch64::Stage1Authority,
    pub(super) mm: NonZeroU64,
}

impl GuestAliasContext<'_> {
    fn error(message: impl Into<String>) -> TrapError {
        TrapError::Hypervisor(message.into())
    }

    pub(super) fn require_lane(&self, services: &dyn Stage1Services) -> Result<(), TrapError> {
        if self.tables.live_descriptor_owner() != LiveDescriptorOwner::Guest
            || !services.guest_publication_available()
        {
            return Err(Self::error(
                "guest alias requires its driving vCPU and descriptor owner",
            ));
        }
        Ok(())
    }

    /// EL1's `MapAlias` stores its output unchecked, so the host refuses an
    /// output overlapping the excluded (GIC) IPA window exactly where the
    /// host editor's `map_aliased` would.
    fn require_output_outside_excluded_window(&self, ipa: u64, len: u64) -> Result<(), TrapError> {
        match self
            .tables
            .with_manager(|manager| manager.layout().ipa_overlaps_excluded(ipa, len))
        {
            Some(false) => Ok(()),
            Some(true) => Err(Self::error(format!(
                "alias output 0x{ipa:x}+0x{len:x} overlaps the excluded IPA window"
            ))),
            None => Err(Self::error("guest alias has no stage-1 image")),
        }
    }

    /// Authenticate the complete target range before anything is copied or
    /// published. The logical inventory extent and its containing physical
    /// owner can differ after COW; both exact identities are retained.
    pub(super) fn authenticate(
        &self,
        target_ipa: u64,
        len: u64,
    ) -> Result<Vec<RetainedAliasTarget>, TrapError> {
        let end = target_ipa
            .checked_add(len)
            .ok_or_else(|| Self::error("alias IPA overflow"))?;
        let mut retained = Vec::new();
        let mut current = target_ipa;
        while current < end {
            let (key, extent) = self
                .ledger
                .lock()
                .extents
                .containing(current)
                .map(|(key, extent)| (*key, *extent))
                .ok_or_else(|| Self::error("alias target has no live inventory mapping"))?;
            let limit = key
                .0
                .checked_add(key.1)
                .ok_or_else(|| Self::error("alias inventory overflow"))?
                .min(end);
            let pin = pin_exact_live_global_frame_owner_in(
                self.custody,
                extent.stage2_base,
                extent.stage2_length,
                extent.stage2_owner.host_addr,
                extent.stage2_owner.generation,
            )
            .ok_or_else(|| Self::error("alias physical owner is not current"))?;
            let length = |raw| {
                NonZeroU64::new(raw)
                    .map(carrick_hal::FrameLength::from_mapping_extent)
                    .ok_or_else(|| Self::error("empty alias backing extent"))
            };
            let (authenticated_mm, backing) = self
                .authority
                .authenticate_frame_backing(carrick_hal::FrameBackingAuthentication {
                    mapping: extent.mapping,
                    frame: extent.frame,
                    gpa: carrick_guest_mem::Gpa(key.0),
                    length: length(key.1)?,
                    owner_gpa: carrick_guest_mem::Gpa(extent.stage2_base),
                    owner_length: length(extent.stage2_length)?,
                })
                .map_err(|e| Self::error(format!("authenticate alias backing: {e}")))?;
            if authenticated_mm != self.mm
                || backing.mapping_id.get() != extent.mapping.raw()
                || backing.frame_id.get() != extent.frame.raw()
                || backing.owner_generation.get() != extent.stage2_owner.generation
            {
                return Err(Self::error("alias backing identity mismatch"));
            }
            retained.push(RetainedAliasTarget {
                start: current,
                end: limit,
                physical_base: extent.stage2_base,
                backing,
                pin,
            });
            current = limit;
        }
        Ok(retained)
    }

    /// Publish `va -> target_ipa` over the authenticated `retained` pieces
    /// as user-accessible leaves carrying exactly `access` (the host editor's
    /// `map_aliased` flags for the same access).
    pub(super) fn publish(
        &self,
        va: u64,
        target_ipa: u64,
        access: carrick_mmu_core::aarch64::UserLeafAccess,
        retained: &[RetainedAliasTarget],
        services: &mut dyn Stage1Services,
    ) -> Result<(), AliasPublishFailure> {
        let len = retained
            .last()
            .map_or(0, |last| last.end.saturating_sub(target_ipa));
        self.require_output_outside_excluded_window(target_ipa, len)
            .map_err(AliasPublishFailure::Unsubmitted)?;
        let access = AliasAccess::User {
            writable: access.writable,
            executable: access.executable,
        };
        let mut published = false;
        for region in retained {
            let region_va = va + (region.start - target_ipa);
            for (offset, count) in
                map_alias_chunks(region_va, region.start, region.end - region.start)
            {
                let op = DescriptorOp::MapAlias {
                    access,
                    span: PageSpan::new(region_va + offset, count),
                    target_ipa: SubstrateGpa(region.start + offset),
                    backing: region.backing,
                };
                let txn = match self.tables.prepare_guest_descriptor_txn(self.mm, op) {
                    Ok(txn) => txn,
                    Err(e) => {
                        let error = Self::error(format!("prepare alias: {e:?}"));
                        return Err(if published {
                            AliasPublishFailure::PartiallyPublished(error)
                        } else {
                            AliasPublishFailure::Unsubmitted(error)
                        });
                    }
                };
                let receipt =
                    services
                        .publish(&txn)
                        .map_err(|error| match error.into_clean_refusal() {
                            Ok(refusal) if published => {
                                AliasPublishFailure::PartiallyPublished(refusal)
                            }
                            Ok(refusal) => AliasPublishFailure::Unsubmitted(refusal),
                            Err(error) => AliasPublishFailure::Unverified(error),
                        })?;
                if *receipt.txn() != txn {
                    return Err(AliasPublishFailure::CrossedReceipt);
                }
                published = true;
            }
        }
        Ok(())
    }

    /// Retire every leaf of `[va, va+len)` through EL1 — the guest-lane
    /// counterpart of the host `unmap_aliased` the host alias cleanup runs.
    /// Whatever a refused or unverified `MapAlias` left, a verified retire
    /// makes the span's state known.
    pub(super) fn retire(
        &self,
        va: u64,
        len: u64,
        services: &mut dyn Stage1Services,
    ) -> Result<(), TrapError> {
        let op = self
            .tables
            .with_manager(|manager| manager.terminal_op(va, len, TerminalRule::pt(PtOp::Retire)))
            .ok_or_else(|| Self::error("guest alias retire has no stage-1 image"))?;
        let txn = self
            .tables
            .prepare_guest_descriptor_txn(self.mm, op)
            .map_err(|e| Self::error(format!("prepare alias retire: {e:?}")))?;
        let receipt = services.publish(&txn).map_err(TrapError::from)?;
        if *receipt.txn() != txn {
            return Err(Self::error(
                "alias retire receipt names another transaction",
            ));
        }
        Ok(())
    }

    /// Republish shared-aperture identity: `va -> va`, named by the live
    /// aperture inventory extent that contains it. Stage-1 only.
    pub(super) fn restore_identity(
        &self,
        va: u64,
        len: u64,
        services: &mut dyn Stage1Services,
    ) -> Result<(), TrapError> {
        self.require_lane(services)?;
        if len == 0 {
            return Ok(());
        }
        let retained = self.authenticate(va, len)?;
        // Read/write and non-executable; the caller publishes the mapping's
        // protection next, exactly as on the host lane.
        self.publish(
            va,
            va,
            carrick_mmu_core::aarch64::UserLeafAccess::READ_WRITE,
            &retained,
            services,
        )
        .map_err(AliasPublishFailure::into_error)?;
        drop(retained);
        Ok(())
    }

    /// Guest-lane host alias publication after `add_alias` staged its
    /// inventory: apply the staged commit, authenticate the now-live mapping
    /// at its real revision, then publish `MapAlias`. After the apply, every
    /// refusal retires the VA span through EL1 BEFORE the grant is rolled
    /// back, so no leaf outlives the mapping it names.
    pub(super) fn publish_host_alias(
        &self,
        va: u64,
        gpa: u64,
        len: u64,
        writable: bool,
        services: &mut dyn Stage1Services,
    ) -> Result<(), GuestAliasRefusal> {
        use GuestAliasRefusal::BeforeInventory;
        self.require_lane(services).map_err(BeforeInventory)?;
        if len == 0 || !PageSpan::new(va, len).is_well_formed() || !gpa.is_multiple_of(4096) {
            return Err(BeforeInventory(Self::error(
                "invalid alias publication span",
            )));
        }
        self.require_output_outside_excluded_window(gpa, len)
            .map_err(BeforeInventory)?;
        let (commit, staged) = {
            let mut inventory = self.ledger.lock();
            let Some(commit) = inventory.alias_commit.take() else {
                return Err(BeforeInventory(Self::error(
                    "guest alias has no staged inventory commit",
                )));
            };
            (commit, std::mem::take(&mut inventory.alias_staged))
        };
        let challenge = commit.receipt_challenge();
        // The kernel refusing a staged alias batch is the publication-order
        // invariant the host lane's install arm aborts the carrier on; the
        // guest lane keeps that fail-stop rather than lowering it to ENOMEM.
        let receipt = self
            .authority
            .apply_with_receipt(commit)
            .unwrap_or_else(|error| {
                carrick_fatal!(
                    "hvpatch::alias",
                    "kernel refused the staged guest alias inventory: {error}"
                )
            });
        if !challenge.authenticate_apply(&receipt, self.mm)
            || !staged
                .iter()
                .all(|(_, extent)| receipt.authorizes(extent.mapping, extent.frame))
        {
            return Err(self.roll_back_host_alias(
                va,
                len,
                &receipt,
                &staged,
                services,
                Self::error("guest alias inventory receipt does not name the staged mapping"),
            ));
        }
        let retained = match self.authenticate(gpa, len) {
            Ok(retained) => retained,
            Err(error) => {
                return Err(self.roll_back_host_alias(va, len, &receipt, &staged, services, error));
            }
        };
        // Never executable here: a PROT_EXEC alias is published by the
        // caller's `protect_range`, exactly as on the host lane.
        let access = carrick_mmu_core::aarch64::UserLeafAccess {
            writable,
            executable: false,
        };
        if let Err(failure) = self.publish(va, gpa, access, &retained, services) {
            drop(retained);
            return Err(self.roll_back_host_alias(
                va,
                len,
                &receipt,
                &staged,
                services,
                failure.into_error(),
            ));
        }
        drop(retained);
        Ok(())
    }

    /// Undo an applied guest alias whose publication refused: retire the
    /// VA span through EL1 first, then roll the kernel grant back, then the
    /// backend's staged extents. Each step failing leaves the ledger and
    /// the authority diverged, so it fail-stops.
    fn roll_back_host_alias(
        &self,
        va: u64,
        len: u64,
        receipt: &carrick_hal::FrameInventoryApplyReceipt,
        staged: &[((u64, u64), InventoryExtent)],
        services: &mut dyn Stage1Services,
        error: TrapError,
    ) -> GuestAliasRefusal {
        if let Err(retire) = self.retire(va, len, services) {
            carrick_fatal!(
                "hvpatch::alias",
                "retire refused guest alias span 0x{va:x}+0x{len:x}: {retire}"
            );
        }
        if let Err(rollback) = self.authority.rollback_frame_grant(receipt) {
            carrick_fatal!(
                "hvpatch::alias",
                "kernel guest alias grant rollback: {rollback}"
            );
        }
        if let Err(rollback) =
            HvfVmState::rollback_unpublished_mappings(&mut self.ledger.lock(), staged)
        {
            carrick_fatal!(
                "hvpatch::alias",
                "backend guest alias staging rollback: {rollback}"
            );
        }
        GuestAliasRefusal::RolledBack(error)
    }
}

#[cfg(test)]
mod tests;
