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
