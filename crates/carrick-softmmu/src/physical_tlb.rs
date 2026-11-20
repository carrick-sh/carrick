//! Stage-1 page translations for a soft engine that serves guest physical
//! accesses through its memory provider. A hit grants no host pointer or
//! backing lifetime. The provider still checks and serves the physical access.

use alloc::{boxed::Box, vec};
use carrick_guest_arch::{Gpa, GuestVa};
use carrick_mmu_core::stage1::LeafAccess;

use crate::domains::{PAGE_BASE_MASK_4K, PAGE_OFFSET_MASK_4K};
use crate::tlb::{SOFT_TLB_ENTRIES, SoftTlb};

#[derive(Clone, Copy)]
struct Entry<Mode> {
    guest_page: GuestVa,
    physical_page: Gpa,
    mode: Mode,
}

/// A 4 KiB, direct-mapped stage-1 cache for a single translation regime.
/// The caller supplies the whole regime identity and the permission mode.
/// Separate access planes ensure a successful read cannot authorize a write
/// or a fetch.
pub struct PhysicalTlb<Regime, Mode> {
    regime: Option<Regime>,
    entries: Box<[Option<Entry<Mode>>]>,
}

impl<Regime: Eq, Mode: Copy + Eq> Default for PhysicalTlb<Regime, Mode> {
    fn default() -> Self {
        Self {
            regime: None,
            entries: vec![None; SOFT_TLB_ENTRIES * LeafAccess::ALL.len()].into_boxed_slice(),
        }
    }
}

impl<Regime: Eq, Mode: Copy + Eq> PhysicalTlb<Regime, Mode> {
    fn index(va: GuestVa, access: LeafAccess) -> usize {
        let plane = match access {
            LeafAccess::Read => 0,
            LeafAccess::Write => 1,
            LeafAccess::Execute => 2,
        };
        plane * SOFT_TLB_ENTRIES + SoftTlb::index_for(va)
    }

    pub fn invalidate(&mut self) {
        self.entries.fill(None);
    }

    /// Install the regime for this access and probe its page and permission.
    pub fn probe(
        &mut self,
        regime: Regime,
        va: GuestVa,
        access: LeafAccess,
        mode: Mode,
    ) -> Option<Gpa> {
        if self.regime.as_ref() != Some(&regime) {
            if self.regime.is_some() {
                self.invalidate();
            }
            self.regime = Some(regime);
        }
        let entry = self.entries[Self::index(va, access)]?;
        let guest_page = GuestVa::new(va.raw() & PAGE_BASE_MASK_4K);
        if entry.guest_page == guest_page && entry.mode == mode {
            Some(Gpa::new(
                entry.physical_page.raw() | (va.raw() & PAGE_OFFSET_MASK_4K),
            ))
        } else {
            None
        }
    }

    /// Fill the regime installed by the preceding probe, after its walk
    /// succeeded for this permission mode and access plane.
    pub fn fill(&mut self, va: GuestVa, access: LeafAccess, mode: Mode, output: Gpa) {
        debug_assert_eq!(
            va.raw() & PAGE_OFFSET_MASK_4K,
            output.raw() & PAGE_OFFSET_MASK_4K
        );
        self.entries[Self::index(va, access)] = Some(Entry {
            guest_page: GuestVa::new(va.raw() & PAGE_BASE_MASK_4K),
            physical_page: Gpa::new(output.raw() & PAGE_BASE_MASK_4K),
            mode,
        });
    }
}
