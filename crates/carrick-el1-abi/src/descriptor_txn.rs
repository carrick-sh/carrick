//! Placement of the host-to-EL1 live descriptor transaction slots.
//!
//! One [`DescriptorTxnSlot`] per persistent vCPU slot. The protocol, the
//! transaction/receipt types and the executor live in
//! `carrick_mmu_core::aarch64::descriptor_txn`; this module only fixes where
//! both venues find the slots inside the shared EL1 region, and folds their
//! layout and protocol revision into [`crate::EL1_ABI_LAYOUT_HASH`] so a host
//! and an EL1 image that disagree refuse each other at image load.
//!
//! The slots sit in the unused tail of the counters area, after
//! [`crate::Counters`]. Both accessors fail closed: the host gets `None`
//! until an EL1 region is installed, and an out-of-range slot is `None`.

pub use carrick_mmu_core::aarch64::descriptor_txn::{
    DESCRIPTOR_TXN_PROTOCOL_VERSION, DescriptorTxnSlot,
};
use carrick_mmu_core::aarch64::descriptor_txn::{
    DescriptorReceipt, DescriptorTxn, DescriptorTxnId,
};

use crate::{
    AtomicU64, Counters, EL1_COUNTERS_OFFSET, EL1_COUNTERS_SIZE, EL1_REGION_BASE, EL1_STACK_SLOTS,
    Ordering, get_el1_region_host_ptr,
};

/// Every persistent vCPU slot's descriptor transaction slot, plus a summary
/// of which slots the host has submitted into, so the EL1 fault path checks
/// four words rather than every slot. A stale summary bit costs one slot
/// check; the slot state remains the authority.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct DescriptorTxnSlots {
    submitted: [AtomicU64; SUMMARY_WORDS],
    slots: [DescriptorTxnSlot; EL1_STACK_SLOTS as usize],
}

const SUMMARY_WORDS: usize = (EL1_STACK_SLOTS as usize).div_ceil(64);

impl DescriptorTxnSlots {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            submitted: [const { AtomicU64::new(0) }; SUMMARY_WORDS],
            slots: [const { DescriptorTxnSlot::new() }; EL1_STACK_SLOTS as usize],
        }
    }

    #[must_use]
    pub fn slot(&self, slot: usize) -> Option<&DescriptorTxnSlot> {
        self.slots.get(slot)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[DescriptorTxnSlot] {
        &self.slots
    }

    /// Host: submit `txn` into `slot` and mark it in the summary.
    pub fn submit(&self, slot: usize, txn: &DescriptorTxn) -> bool {
        let Some(target) = self.slots.get(slot) else {
            return false;
        };
        if !target.submit(txn) {
            return false;
        }
        self.submitted[slot / 64].fetch_or(1 << (slot % 64), Ordering::Release);
        true
    }

    /// Host: withdraw an unclaimed submission and clear its summary bit.
    pub fn withdraw(&self, slot: usize, id: DescriptorTxnId) -> bool {
        let withdrawn = self
            .slots
            .get(slot)
            .is_some_and(|target| target.withdraw(id));
        if withdrawn {
            self.submitted[slot / 64].fetch_and(!(1 << (slot % 64)), Ordering::Release);
        }
        withdrawn
    }

    /// Host: consume the receipt for `id` from `slot` and clear its bit.
    pub fn take_receipt(&self, slot: usize, id: DescriptorTxnId) -> Option<DescriptorReceipt> {
        let receipt = self.slots.get(slot)?.take_receipt(id)?;
        self.submitted[slot / 64].fetch_and(!(1 << (slot % 64)), Ordering::Release);
        Some(receipt)
    }

    /// EL1: every slot holding a submission for `mm_key`.
    pub fn submitted_for(&self, mm_key: u64) -> impl Iterator<Item = &DescriptorTxnSlot> + '_ {
        self.submitted
            .iter()
            .enumerate()
            .flat_map(|(word, bits)| {
                let mut bits = bits.load(Ordering::Acquire);
                core::iter::from_fn(move || {
                    if bits == 0 {
                        return None;
                    }
                    let bit = bits.trailing_zeros() as usize;
                    bits &= bits - 1;
                    Some(word * 64 + bit)
                })
            })
            .filter_map(|index| self.slots.get(index))
            .filter(move |slot| slot.submitted_for(mm_key))
    }

    /// Either venue: an in-flight transaction for `mm_key` covers `va`.
    #[must_use]
    pub fn pending_covering(&self, mm_key: u64, va: u64) -> bool {
        self.submitted
            .iter()
            .any(|bits| bits.load(Ordering::Acquire) != 0)
            && self
                .slots
                .iter()
                .any(|slot| slot.pending_covering(mm_key, va))
    }
}

impl Default for DescriptorTxnSlots {
    fn default() -> Self {
        Self::new()
    }
}

/// Offset of [`DescriptorTxnSlots`] in the EL1 region: its assigned
/// `[0x180000, 0x1A0000)` window of the counters area.
pub const EL1_DESCRIPTOR_TXN_OFFSET: u64 = EL1_COUNTERS_OFFSET + 0x8_0000;
pub const EL1_DESCRIPTOR_TXN_BASE: u64 = EL1_REGION_BASE + EL1_DESCRIPTOR_TXN_OFFSET;

/// Two temporary kernel-only aliases for one exact-MM COW copy. The MM's
/// single editor owns both slots; they are invalid outside that copy. These
/// are virtual aliases, not another frame pool or persistent backing owner.
/// The window's VA is owned by `carrick-mmu-core`, whose stage-1 editors
/// provision it and refuse to edit it; these names are that same window.
pub const EL1_COW_COPY_OFFSET: u64 = 0x1A_0000;
pub const EL1_COW_COPY_BASE: u64 =
    carrick_mmu_core::aarch64::descriptor_txn::copy_window::COW_COPY_WINDOW_BASE;
pub const EL1_COW_COPY_SIZE: u64 =
    carrick_mmu_core::aarch64::descriptor_txn::copy_window::COW_COPY_WINDOW_LEN;
const _: () = assert!(EL1_COW_COPY_BASE == EL1_REGION_BASE + EL1_COW_COPY_OFFSET);
const _: () = assert!(EL1_COW_COPY_SIZE == 2 * 4096);
const _: () = assert!(EL1_COW_COPY_OFFSET + EL1_COW_COPY_SIZE <= crate::EL1_STACKS_OFFSET);

const _: () = assert!(core::mem::size_of::<Counters>() as u64 <= 0x8_0000);
const _: () = assert!(
    EL1_DESCRIPTOR_TXN_OFFSET.is_multiple_of(core::mem::align_of::<DescriptorTxnSlots>() as u64)
);
const _: () = assert!(
    EL1_DESCRIPTOR_TXN_OFFSET + core::mem::size_of::<DescriptorTxnSlots>() as u64
        <= EL1_COUNTERS_OFFSET + EL1_COUNTERS_SIZE
);
// Counters-area assignment: counters [0x100000, 0x120000), shared
// reservations [0x120000, 0x180000), descriptor-txn slots [0x180000, 0x1A0000).
const _: () = assert!(EL1_DESCRIPTOR_TXN_OFFSET >= EL1_COUNTERS_OFFSET + 0x8_0000);
const _: () = assert!(
    EL1_DESCRIPTOR_TXN_OFFSET + core::mem::size_of::<DescriptorTxnSlots>() as u64
        <= EL1_COUNTERS_OFFSET + 0xA_0000
);

/// Layout facts folded into [`crate::EL1_ABI_LAYOUT_HASH`].
pub const DESCRIPTOR_TXN_LAYOUT_FACTS: [u64; 8] = [
    EL1_COW_COPY_OFFSET,
    EL1_COW_COPY_SIZE,
    EL1_DESCRIPTOR_TXN_OFFSET,
    DESCRIPTOR_TXN_PROTOCOL_VERSION,
    core::mem::size_of::<DescriptorTxnSlot>() as u64,
    core::mem::align_of::<DescriptorTxnSlot>() as u64,
    core::mem::size_of::<DescriptorTxnSlots>() as u64,
    core::mem::offset_of!(DescriptorTxnSlots, slots) as u64,
];

/// `TrapFrame::esr` of a host-driven descriptor drain call: EC 0x3F is
/// architecturally unallocated, so no exception taken from EL0 carries it.
/// The host runs `carrick_el1_syscall` on a vCPU whose TTBR0 is the MM's
/// root, with a frame naming that MM, and EL1 applies every submission for
/// the MM before returning to the maintenance `hvc #1`.
pub const DESCRIPTOR_DRAIN_ESR: u64 = 0x3F << 26;

/// Drain frame words: `x[1]` = MM key, `x[2]` = the vCPU's full TTBR0 (root
/// and ASID) the host read and authenticated. EL1 answers in `x[0]`.
pub const DESCRIPTOR_DRAIN_MM: usize = 1;
pub const DESCRIPTOR_DRAIN_TTBR0: usize = 2;
/// `x[0]` answer bits: the low 32 bits count applied submissions; this bit
/// reports submissions EL1 could not apply (another EL1 editor holds the MM).
pub const DESCRIPTOR_DRAIN_BLOCKED: u64 = 1 << 32;

/// Offset in the EL1 region of the drain frame for vCPU `slot`: below the
/// vector's own trap frame at the top of that slot's EL1 stack, 16-aligned,
/// leaving the rest of the stack for the call.
#[must_use]
pub fn descriptor_drain_frame_offset(slot: usize) -> Option<u64> {
    if slot >= EL1_STACK_SLOTS as usize {
        return None;
    }
    let top = crate::EL1_STACKS_OFFSET + (slot as u64 + 1) * crate::EL1_STACK_SIZE;
    Some((top - 0x120 - 0x200) & !0xF)
}

/// Host view of every descriptor transaction slot, if an EL1 region is
/// installed.
pub fn descriptor_txn_slots_host() -> Option<&'static DescriptorTxnSlots> {
    let ptr = get_el1_region_host_ptr();
    if ptr == 0 {
        return None;
    }
    // SAFETY: the EL1 region owner keeps this mapping alive until it first
    // clears the region pointer; the slots contain only atomics, the region is
    // zero-initialized (the IDLE encoding) and the offset preserves alignment.
    Some(unsafe { &*((ptr + EL1_DESCRIPTOR_TXN_OFFSET as usize) as *const DescriptorTxnSlots) })
}

/// Host view of one vCPU slot's descriptor transaction slot.
pub fn descriptor_txn_slot_host(slot: usize) -> Option<&'static DescriptorTxnSlot> {
    descriptor_txn_slots_host()?.slot(slot)
}

/// Guest view of every descriptor transaction slot. Call only while
/// executing in the installed Carrick EL1 image.
#[cfg(target_os = "none")]
pub fn descriptor_txn_slots_guest() -> &'static DescriptorTxnSlots {
    // SAFETY: EL1_DESCRIPTOR_TXN_BASE is inside the mapped kernel-only EL1
    // region and the layout is included in EL1_ABI_LAYOUT_HASH.
    unsafe { &*(EL1_DESCRIPTOR_TXN_BASE as *const DescriptorTxnSlots) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_fit_the_counters_tail_and_start_idle() {
        let slots = DescriptorTxnSlots::new();
        assert_eq!(slots.as_slice().len(), EL1_STACK_SLOTS as usize);
        assert!(slots.slot(EL1_STACK_SLOTS as usize).is_none());
        assert!(slots.as_slice().iter().all(|slot| slot.state() == 0));
        assert!(!slots.pending_covering(1, 0x4000_0000));
        // The lazily zero-filled region is a valid all-IDLE slot array.
        assert_eq!(
            carrick_mmu_core::aarch64::descriptor_txn::DESCRIPTOR_TXN_IDLE,
            0
        );
    }

    #[test]
    fn the_summary_tracks_exactly_the_host_submissions() {
        use carrick_mmu_core::aarch64::SubstrateGpa;
        use carrick_mmu_core::aarch64::descriptor_txn::{
            DescriptorOp, DescriptorOutcome, DescriptorRefusal, PageSpan, TableGrants,
        };
        use core::num::NonZeroU64;
        let nz = |v| NonZeroU64::new(v).unwrap();
        let txn = |mm, generation| DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: nz(mm),
                generation: nz(generation),
            },
            root: SubstrateGpa(0x8800_0000_0000),
            op: DescriptorOp::Retire(PageSpan::new(0x4000_0000, 0x2000)),
            tables: TableGrants::NONE,
        };
        let slots = DescriptorTxnSlots::new();
        let a = txn(7, 1);
        let b = txn(8, 1);
        assert!(slots.submit(3, &a));
        assert!(slots.submit(200, &b));
        assert!(!slots.submit(3, &b), "single flight per slot");
        assert!(!slots.submit(EL1_STACK_SLOTS as usize, &b));
        assert_eq!(slots.submitted_for(7).count(), 1);
        assert_eq!(slots.submitted_for(8).count(), 1);
        assert_eq!(slots.submitted_for(9).count(), 0);
        assert!(slots.pending_covering(7, 0x4000_1abc));
        assert!(!slots.pending_covering(7, 0x4000_2000));
        let claimed = slots.slot(3).unwrap().claim_for_mm(7).unwrap();
        let _ = claimed.complete(DescriptorOutcome::Refused(DescriptorRefusal::StaleRoot));
        assert_eq!(
            slots.submitted_for(7).count(),
            0,
            "claimed, no longer submitted"
        );
        assert!(slots.take_receipt(3, a.id).is_some());
        assert!(slots.withdraw(200, b.id));
        assert!(
            slots
                .submitted
                .iter()
                .all(|w| w.load(Ordering::Relaxed) == 0)
        );
    }
}
