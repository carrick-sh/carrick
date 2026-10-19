//! Host fixtures for the guest COW path: the real descriptor executor and
//! copy window over a host table arena at `ROOT` and a page-granular model
//! of guest-physical memory. Shared by this crate's COW tests and by the
//! Linux portal's tests in `carrick-el1-linux`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
extern crate std;
use carrick_el1_abi::{EL1_COW_COPY_BASE, FrameGrantResidencyTable};
use carrick_mmu_core::aarch64::descriptor_txn::{
    BackingIdentity, PrimaryTableWords, TableMaintenance,
};
use carrick_mmu_core::aarch64::indices;
use core::cell::RefCell;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};
use std::collections::BTreeMap;
use std::vec;
use std::vec::Vec;

pub const ROOT: u64 = 0x8800_0000_0000;
pub const ASID: u64 = 5 << 48;
pub const MM: u64 = 77;
pub const VA: u64 = 0x4000_0000;
pub const OLD: u64 = 0x009b_4000_0000;
pub const GRANT: u64 = 0x009d_0000_4000;
pub const PA: u64 = 0x0000_FFFF_FFFF_F000;
pub const AF: u64 = 1 << 10;
pub const SH: u64 = 0b11 << 8;
pub const AP_RO_EL0: u64 = 0b11 << 6;
pub const AP_RW_EL0: u64 = 0b01 << 6;
pub const NG: u64 = 1 << 11;
pub const XN: u64 = (1 << 53) | (1 << 54);
pub const COW: u64 = 1 << 55;
pub const PRIVATE: u64 = 1 << 56;
pub const MAY_WRITE: u64 = 1 << 57;

pub struct Arena {
    words: Vec<AtomicU64>,
}

impl Arena {
    /// Tables for `VA` (L3 at +0x3000) and for the EL1 copy window
    /// (L2 at +0x4000, L3 at +0x5000) with its two idle leaves.
    pub fn new(window: bool) -> Self {
        let arena = Self {
            words: (0..8 * 512).map(|_| AtomicU64::new(0)).collect(),
        };
        let va = indices(VA);
        arena.set(ROOT + va[0] as u64 * 8, (ROOT + 0x1000) | 3);
        arena.set(ROOT + 0x1000 + va[1] as u64 * 8, (ROOT + 0x2000) | 3);
        arena.set(ROOT + 0x2000 + va[2] as u64 * 8, (ROOT + 0x3000) | 3);
        if window {
            let win = indices(EL1_COW_COPY_BASE);
            assert_eq!(win[0], va[0], "one L0 entry covers both");
            arena.set(ROOT + 0x1000 + win[1] as u64 * 8, (ROOT + 0x4000) | 3);
            arena.set(ROOT + 0x4000 + win[2] as u64 * 8, (ROOT + 0x5000) | 3);
            for page in 0..2 {
                let alias = EL1_COW_COPY_BASE + page * 4096;
                arena.set(ROOT + 0x5000 + indices(alias)[3] as u64 * 8, alias);
            }
        }
        arena
    }
    pub fn set(&self, pa: u64, value: u64) {
        self.words[((pa - ROOT) / 8) as usize].store(value, Ordering::Relaxed);
    }
    pub fn get(&self, pa: u64) -> u64 {
        self.words[((pa - ROOT) / 8) as usize].load(Ordering::Relaxed)
    }
    pub fn leaf_pa(va: u64) -> u64 {
        let l3 = if va >> 30 == EL1_COW_COPY_BASE >> 30 {
            ROOT + 0x5000
        } else {
            ROOT + 0x3000
        };
        l3 + indices(va)[3] as u64 * 8
    }
    pub fn leaf(&self, va: u64) -> u64 {
        self.get(Self::leaf_pa(va))
    }
    pub fn set_leaf(&self, va: u64, value: u64) {
        self.set(Self::leaf_pa(va), value);
    }
    pub fn words(&self) -> PrimaryTableWords<'_, Maintenance> {
        unsafe {
            PrimaryTableWords::new(
                self.words.as_ptr().cast_mut(),
                ROOT,
                self.words.len() * 8,
                &MAINTENANCE,
            )
        }
        .unwrap()
    }
    pub fn image(&self) -> Vec<u64> {
        self.words
            .iter()
            .map(|w| w.load(Ordering::Relaxed))
            .collect()
    }
}

pub struct Maintenance;
pub static MAINTENANCE: Maintenance = Maintenance;
impl TableMaintenance for Maintenance {
    fn publish_barrier(&self) {}
    fn invalidate_range(&self, _va: u64, _len: u64) {}
}

/// Guest-physical pages. Copies read the copy window's live leaves, so
/// a copy through an unmapped or wrong alias fails the test.
pub struct Memory(pub RefCell<BTreeMap<u64, Vec<u8>>>);

impl Memory {
    pub fn page(&self, ipa: u64) -> Vec<u8> {
        self.0.borrow().get(&ipa).cloned().unwrap_or(vec![0; 4096])
    }
    pub fn copy_through(&self, arena: &Arena, source: u64, destination: u64) {
        let (from, to) = (arena.leaf(source), arena.leaf(destination));
        assert_ne!(from & 1, 0, "source alias not mapped during the copy");
        assert_ne!(to & 1, 0, "destination alias not mapped during the copy");
        assert_eq!(
            from & (0b11 << 6),
            0b10 << 6,
            "source alias is EL1 read-only"
        );
        assert_eq!(to & (0b11 << 6), 0, "destination alias is EL1 read-write");
        let bytes = self.page(from & PA);
        self.0.borrow_mut().insert(to & PA, bytes);
    }
}

pub fn nz(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).unwrap()
}

pub fn backing() -> BackingIdentity {
    BackingIdentity {
        frame_id: nz(11),
        mapping_id: nz(12),
        owner_generation: nz(13),
        inventory_revision: nz(14),
    }
}

pub fn armed(ipa: u64, may_write: bool) -> u64 {
    ipa | 3 | AF | SH | AP_RO_EL0 | NG | XN | COW | PRIVATE | if may_write { MAY_WRITE } else { 0 }
}

pub fn residency_table() -> std::boxed::Box<FrameGrantResidencyTable> {
    let layout = std::alloc::Layout::new::<FrameGrantResidencyTable>();
    // SAFETY: the production shared index supports zero initialization;
    // the allocation has its exact size/alignment and one Box owner.
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) }.cast::<FrameGrantResidencyTable>();
    if ptr.is_null() {
        std::alloc::handle_alloc_error(layout);
    }
    unsafe { std::boxed::Box::from_raw(ptr) }
}

/// A forked private compound: four armed pages, lane 3 read-only in
/// Linux, each page holding distinct bytes.
pub fn forked(window: bool) -> (Arena, Memory) {
    let arena = Arena::new(window);
    let pages = Memory(RefCell::new(BTreeMap::new()));
    for lane in 0..4 {
        arena.set_leaf(VA + lane * 4096, armed(OLD + lane * 4096, lane != 3));
        pages.0.borrow_mut().insert(
            OLD + lane * 4096,
            (0..4096).map(|i| (i as u64 * 7 + lane) as u8).collect(),
        );
    }
    (arena, pages)
}
