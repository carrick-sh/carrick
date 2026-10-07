//! Host-visible completion of one guest-owned MMU edit.
//!
//! The exact-MM editor and its handoff provide ordering. This plain record
//! carries no descriptor write authority and is never an inventory grant.

/// An applied descriptor edit, handed to the host after the guest has drained
/// its local translation and before the exact-MM editor reopens admission.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestMmuPublication {
    pub revision: u32,
    pub outcome: u32,
    pub mm_key: u64,
    pub root_gpa: u64,
    pub generation: u64,
    pub edit_identity: u64,
    pub span_va: u64,
    pub span_len: u64,
    pub live_stores: u32,
    pub tables_linked: u32,
}

impl GuestMmuPublication {
    pub const REVISION: u32 = 1;
    pub const APPLIED: u32 = 1;

    /// Report the shared fork owner's applied parent journal and published
    /// child table extent. This record carries no descriptor authority.
    pub fn from_x86_fork(
        parent_root: u64,
        completion: crate::PortalForkCompletion,
        parent_stores: usize,
    ) -> Option<Self> {
        let request = completion.request;
        if parent_root == 0
            || parent_root & 4095 != 0
            || !request.valid()
            || completion.child_tables_used == 0
            || !completion.child_tables_used.is_multiple_of(4096)
            || completion.child_tables_used > request.child_tables.len
            || !completion.parent_tables_used.is_multiple_of(4096)
            || completion.parent_tables_used > request.parent_tables.len
            || completion.child.mm() != request.child_mm
            || completion.child.carrier() != request.operation.carrier
        {
            return None;
        }
        Some(Self {
            revision: Self::REVISION,
            outcome: Self::APPLIED,
            mm_key: request.operation.mm.raw(),
            root_gpa: parent_root,
            generation: completion.parent_generation.raw(),
            edit_identity: request.operation.sequence.get(),
            span_va: 0,
            span_len: 1 << 47,
            live_stores: u32::try_from(parent_stores).ok()?,
            tables_linked: u32::try_from(completion.child_tables_used / 4096).ok()?,
        })
    }

    /// Authenticate a fork publication against the exact neutral completion
    /// before the host accepts physical custody of the child root.
    pub fn matches_x86_fork(
        self,
        parent_root: u64,
        completion: crate::PortalForkCompletion,
    ) -> bool {
        Self::from_x86_fork(parent_root, completion, self.live_stores as usize)
            .is_some_and(|expected| expected == self)
    }

    /// Serialize one successful native receipt after the guest edit and
    /// local drain, while its exact-MM editor is still held.
    pub fn from_x86_receipt(
        txn: &carrick_mmu_core::x86::descriptor_txn::DescriptorTxn<'_>,
        receipt: &carrick_mmu_core::x86::descriptor_txn::DescriptorReceipt,
    ) -> Option<Self> {
        use carrick_mmu_core::x86::descriptor_txn::DescriptorOutcome;
        txn.verify_receipt(receipt).ok()?;
        let DescriptorOutcome::Applied {
            stores,
            tables_linked,
        } = receipt.outcome
        else {
            return None;
        };
        let span = txn.op.span();
        Some(Self {
            revision: Self::REVISION,
            outcome: Self::APPLIED,
            mm_key: txn.id.mm_key.get(),
            root_gpa: txn.root.address().raw(),
            generation: txn.id.generation.get(),
            edit_identity: receipt.edit_identity(),
            span_va: span.va,
            span_len: span.len,
            live_stores: u32::try_from(stores).ok()?,
            tables_linked: u32::try_from(tables_linked).ok()?,
        })
    }

    /// Authenticate the isolated owner-grant wire receipt, then project its
    /// native identity through the same ISA binding that executed the edit.
    pub fn from_x86_owner_grant(
        txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
        receipt: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt,
    ) -> Option<Self> {
        use carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome;
        txn.verify_receipt(receipt).ok()?;
        let DescriptorOutcome::Applied(applied) = receipt.outcome else {
            return None;
        };
        carrick_mmu_core::x86::owner_mmu::X86Mmu::project_grant(txn.root.raw(), txn, |native| {
            Some(Self {
                revision: Self::REVISION,
                outcome: Self::APPLIED,
                mm_key: native.id.mm_key.get(),
                root_gpa: native.root.address().raw(),
                generation: native.id.generation.get(),
                edit_identity: native.edit_identity(),
                span_va: native.op.span().va,
                span_len: native.op.span().len,
                live_stores: applied.live_stores,
                tables_linked: u32::from(applied.tables_linked),
            })
        })
        .ok()?
    }

    /// Match a host-held expected edit without interpreting descriptor words.
    /// A separate read-only postcondition check confirms the live guest graph.
    pub fn matches_x86_txn(
        self,
        txn: &carrick_mmu_core::x86::descriptor_txn::DescriptorTxn<'_>,
    ) -> bool {
        let span = txn.op.span();
        self.revision == Self::REVISION
            && self.outcome == Self::APPLIED
            && self.mm_key == txn.id.mm_key.get()
            && self.root_gpa == txn.root.address().raw()
            && self.generation == txn.id.generation.get()
            && self.edit_identity == txn.edit_identity()
            && self.span_va == span.va
            && self.span_len == span.len
            && self.tables_linked as usize <= txn.tables.len()
    }
}

const _: () = {
    assert!(core::mem::size_of::<GuestMmuPublication>() == 64);
    assert!(core::mem::align_of::<GuestMmuPublication>() == 8);
    assert!(core::mem::offset_of!(GuestMmuPublication, revision) == 0);
    assert!(core::mem::offset_of!(GuestMmuPublication, outcome) == 4);
    assert!(core::mem::offset_of!(GuestMmuPublication, mm_key) == 8);
    assert!(core::mem::offset_of!(GuestMmuPublication, root_gpa) == 16);
    assert!(core::mem::offset_of!(GuestMmuPublication, generation) == 24);
    assert!(core::mem::offset_of!(GuestMmuPublication, edit_identity) == 32);
    assert!(core::mem::offset_of!(GuestMmuPublication, span_va) == 40);
    assert!(core::mem::offset_of!(GuestMmuPublication, span_len) == 48);
    assert!(core::mem::offset_of!(GuestMmuPublication, live_stores) == 56);
    assert!(core::mem::offset_of!(GuestMmuPublication, tables_linked) == 60);
};

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{
        El1MmHandle, PortalForkRequest, PortalForkTableArena, PortalOperation,
        ReservationGeneration, ReservationMm,
    };
    use core::num::NonZeroU64;

    #[test]
    fn x86_fork_publication_binds_child_root_and_parent_journal() {
        let one = NonZeroU64::MIN;
        let child_mm = ReservationMm::new(78).unwrap();
        let request = PortalForkRequest {
            operation: PortalOperation {
                carrier: one,
                mm: ReservationMm::new(77).unwrap(),
                incarnation: one,
                sequence: one,
            },
            parent_generation: ReservationGeneration::INITIAL,
            child_mm,
            child_tables: PortalForkTableArena::new(0x81_0000, 0x4_0000).unwrap(),
            parent_tables: PortalForkTableArena::new(0x85_0000, 0x1_0000).unwrap(),
            kernel_control_ipa: 0xa0_0000,
        };
        // SAFETY: the test models the exact admitted child owner that the
        // neutral fork completion will publish; no live root is exposed.
        let child = unsafe { El1MmHandle::from_admitted_owner(one, child_mm, one) };
        let completion = crate::PortalForkCompletion {
            request,
            child,
            parent_generation: ReservationGeneration::INITIAL,
            child_tables_used: 0x5000,
            parent_tables_used: 0,
        };
        let record = GuestMmuPublication::from_x86_fork(0x80_0000, completion, 1).unwrap();
        assert_eq!(
            (record.root_gpa, record.mm_key, record.span_len),
            (0x80_0000, 77, 1 << 47)
        );
        assert_eq!((record.live_stores, record.tables_linked), (1, 5));
        assert!(record.matches_x86_fork(0x80_0000, completion));
        assert!(!record.matches_x86_fork(0x81_0000, completion));
        // SAFETY: this wrong test identity is never admitted to a real MM.
        let wrong_child =
            unsafe { El1MmHandle::from_admitted_owner(one, ReservationMm::new(79).unwrap(), one) };
        assert!(
            GuestMmuPublication::from_x86_fork(
                0x80_0000,
                crate::PortalForkCompletion {
                    child: wrong_child,
                    ..completion
                },
                1,
            )
            .is_none()
        );
    }
}
