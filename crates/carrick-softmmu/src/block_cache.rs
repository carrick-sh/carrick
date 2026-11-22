//! Bounded storage for decoded blocks and their executable owners.
//! The engine supplies keys and validates the mapping and code identity on
//! entry. The cache holds no guest memory or translation authority.
//!
//! Each owner (a soft CPU) supplies a [`ResidencyBudget`]: a block count and
//! a code-byte budget. Eviction is CLOCK (second chance): a lookup that hits
//! sets the entry's reference bit, and the hand evicts the first entry it
//! finds without one, clearing bits as it passes. Code hit since the hand
//! last passed survives, so a hot loop outlives any number of cold blocks
//! that run once. An evicted value is dropped at once, so executable memory
//! it owns is released in step with eviction.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::Cell;
use core::num::NonZeroUsize;

/// Host bytes a resident value keeps: for emitted code, the executable
/// mapping that holds it, page rounding included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct CodeBytes(usize);

impl CodeBytes {
    pub const ZERO: Self = Self(0);
    /// No byte budget: only the block count binds.
    pub const UNBOUNDED: Self = Self(usize::MAX);

    pub const fn new(bytes: usize) -> Self {
        Self(bytes)
    }

    pub const fn get(self) -> usize {
        self.0
    }
}

/// The host footprint of an owner's prepared code.
pub trait CodeFootprint {
    fn code_bytes(&self) -> CodeBytes;
}

/// Code with no host footprint (a dispatcher test double).
impl CodeFootprint for () {
    fn code_bytes(&self) -> CodeBytes {
        CodeBytes::ZERO
    }
}

/// The most blocks an owner keeps resident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResidentBlocks(NonZeroUsize);

impl ResidentBlocks {
    pub const fn new(blocks: NonZeroUsize) -> Self {
        Self(blocks)
    }

    pub const fn get(self) -> usize {
        self.0.get()
    }
}

/// How the hand chooses a victim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replacement {
    /// Second chance: hits set a reference bit the hand clears once.
    UseAware,
    /// No reference bits: the hand evicts in insertion order (FIFO). Only
    /// [`ResidencyBudget::OPT_OUT`] selects it.
    InsertionOrder,
}

/// An owner's resident-code bound. Both limits hold after every insert,
/// except that one value larger than the byte budget is kept alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResidencyBudget {
    pub blocks: ResidentBlocks,
    pub code_bytes: CodeBytes,
    pub replacement: Replacement,
}

impl ResidencyBudget {
    /// The pre-#2717 cache, kept only behind an owner's exact `=0` opt-out:
    /// 1,024 blocks in insertion order, with no byte budget.
    pub const OPT_OUT: Self = Self {
        blocks: ResidentBlocks::new(NonZeroUsize::new(1024).unwrap()),
        code_bytes: CodeBytes::UNBOUNDED,
        replacement: Replacement::InsertionOrder,
    };

    /// Use-aware residency within `blocks` and `code_bytes`.
    pub const fn use_aware(blocks: ResidentBlocks, code_bytes: CodeBytes) -> Self {
        Self {
            blocks,
            code_bytes,
            replacement: Replacement::UseAware,
        }
    }

    /// The owner's budget, or [`Self::OPT_OUT`] under exactly
    /// `CARRICK_SOFT_CODE_RESIDENCY=0`. Every soft CPU reads it here.
    #[cfg(feature = "std")]
    pub fn for_owner(owner: Self) -> Self {
        if std::env::var_os("CARRICK_SOFT_CODE_RESIDENCY").as_deref()
            == Some(std::ffi::OsStr::new("0"))
        {
            Self::OPT_OUT
        } else {
            owner
        }
    }
}

/// What the cache holds now and the most it has held since it was created.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ResidencyCensus {
    pub blocks: usize,
    pub code_bytes: CodeBytes,
    pub peak_blocks: usize,
    pub peak_code_bytes: CodeBytes,
    pub evictions: u64,
}

struct Slot<K, V> {
    key: K,
    value: V,
    bytes: CodeBytes,
    referenced: Cell<bool>,
}

pub struct BlockCache<K, V> {
    budget: ResidencyBudget,
    index: BTreeMap<K, usize>,
    slots: Vec<Option<Slot<K, V>>>,
    vacant: Vec<usize>,
    hand: usize,
    census: ResidencyCensus,
}

impl<K, V> BlockCache<K, V> {
    pub fn new(budget: ResidencyBudget) -> Self {
        Self {
            budget,
            index: BTreeMap::new(),
            slots: Vec::new(),
            vacant: Vec::new(),
            hand: 0,
            census: ResidencyCensus::default(),
        }
    }

    pub fn budget(&self) -> ResidencyBudget {
        self.budget
    }

    pub fn census(&self) -> ResidencyCensus {
        self.census
    }
}

impl<K: Copy + Ord, V> BlockCache<K, V> {
    /// A hit marks the entry used.
    pub fn get(&self, key: &K) -> Option<&V> {
        let slot = self.slots[*self.index.get(key)?].as_ref()?;
        if self.budget.replacement == Replacement::UseAware {
            slot.referenced.set(true);
        }
        Some(&slot.value)
    }

    /// Insert or replace `key`. A replacement keeps its slot, so repeated
    /// changes to one block do not evict its peers. The new value is never
    /// the victim of its own insert.
    pub fn insert(&mut self, key: K, value: V, bytes: CodeBytes) -> &V {
        let slot = match self.index.get(&key) {
            Some(&at) => {
                let Some(old) = self.slots[at].as_mut() else {
                    unreachable!("an indexed slot is occupied");
                };
                self.census.code_bytes = CodeBytes(self.census.code_bytes.0 - old.bytes.0);
                old.value = value;
                old.bytes = bytes;
                at
            }
            None => {
                while self.index.len() >= self.budget.blocks.get() && self.evict(None) {}
                let at = self.vacant.pop().unwrap_or_else(|| {
                    self.slots.push(None);
                    self.slots.len() - 1
                });
                self.slots[at] = Some(Slot {
                    key,
                    value,
                    bytes,
                    referenced: Cell::new(false),
                });
                self.index.insert(key, at);
                at
            }
        };
        while self.census.code_bytes.0.saturating_add(bytes.0) > self.budget.code_bytes.0
            && self.evict(Some(slot))
        {}
        self.census.code_bytes = CodeBytes(self.census.code_bytes.0.saturating_add(bytes.0));
        self.census.blocks = self.index.len();
        self.census.peak_blocks = self.census.peak_blocks.max(self.census.blocks);
        self.census.peak_code_bytes = self.census.peak_code_bytes.max(self.census.code_bytes);
        let Some(slot) = self.slots[slot].as_ref() else {
            unreachable!("the inserted slot is occupied");
        };
        &slot.value
    }

    /// Evict the next unreferenced entry other than `keep`, clearing the
    /// reference bits the hand passes. False when nothing else is resident.
    fn evict(&mut self, keep: Option<usize>) -> bool {
        if self.index.len() <= usize::from(keep.is_some()) {
            return false;
        }
        loop {
            if self.hand >= self.slots.len() {
                self.hand = 0;
            }
            let at = self.hand;
            self.hand += 1;
            if Some(at) == keep {
                continue;
            }
            let Some(slot) = self.slots[at].as_ref() else {
                continue;
            };
            if slot.referenced.replace(false) {
                continue;
            }
            if let Some(victim) = self.slots[at].take() {
                self.index.remove(&victim.key);
                self.census.code_bytes = CodeBytes(self.census.code_bytes.0 - victim.bytes.0);
                self.census.evictions += 1;
            }
            self.vacant.push(at);
            return true;
        }
    }

    pub fn clear(&mut self) {
        self.index.clear();
        self.slots.clear();
        self.vacant.clear();
        self.hand = 0;
        self.census.blocks = 0;
        self.census.code_bytes = CodeBytes::ZERO;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(blocks: usize, bytes: usize) -> ResidencyBudget {
        ResidencyBudget::use_aware(
            ResidentBlocks::new(NonZeroUsize::new(blocks).unwrap()),
            CodeBytes::new(bytes),
        )
    }

    fn resident(cache: &BlockCache<u32, u32>) -> Vec<u32> {
        (0..64).filter(|k| cache.index.contains_key(k)).collect()
    }

    #[test]
    fn a_referenced_entry_survives_a_scan_of_unreferenced_ones() {
        let mut cache = BlockCache::new(budget(4, usize::MAX));
        for key in 0..4 {
            cache.insert(key, key, CodeBytes::ZERO);
        }
        for cold in 10..40 {
            assert_eq!(cache.get(&0), Some(&0));
            cache.insert(cold, cold, CodeBytes::ZERO);
        }
        let kept = resident(&cache);
        assert!(kept.contains(&0), "hot key evicted: {kept:?}");
        assert_eq!(kept.len(), 4);
        assert_eq!(cache.census().evictions, 30);
    }

    #[test]
    fn insertion_order_without_reference_bits_is_fifo() {
        let mut cache = BlockCache::new(ResidencyBudget {
            blocks: ResidentBlocks::new(NonZeroUsize::new(3).unwrap()),
            ..ResidencyBudget::OPT_OUT
        });
        for key in 0..3 {
            cache.insert(key, key, CodeBytes::ZERO);
        }
        assert_eq!(cache.get(&0), Some(&0));
        cache.insert(3, 3, CodeBytes::ZERO);
        assert_eq!(resident(&cache), [1, 2, 3]);
        // A replacement keeps its place in the order.
        cache.insert(1, 11, CodeBytes::ZERO);
        cache.insert(4, 4, CodeBytes::ZERO);
        assert_eq!(resident(&cache), [2, 3, 4]);
        cache.insert(5, 5, CodeBytes::ZERO);
        assert_eq!(resident(&cache), [3, 4, 5]);
    }

    #[test]
    fn the_byte_budget_binds_and_evicted_values_drop_at_once() {
        use alloc::rc::Rc;
        let live = Rc::new(());
        let mut cache = BlockCache::new(budget(64, 4096 * 3));
        for key in 0..20 {
            cache.insert(key, Rc::clone(&live), CodeBytes::new(4096));
            let census = cache.census();
            assert!(census.code_bytes.get() <= 4096 * 3);
            assert_eq!(Rc::strong_count(&live), 1 + census.blocks);
        }
        assert_eq!(cache.census().blocks, 3);
        assert_eq!(cache.census().peak_code_bytes, CodeBytes::new(4096 * 3));
        // A larger replacement evicts peers, never itself.
        cache.insert(19, Rc::clone(&live), CodeBytes::new(4096 * 2));
        assert_eq!(cache.census().blocks, 2);
        assert!(cache.get(&19).is_some());
        // One value over the whole budget is kept alone.
        cache.insert(30, Rc::clone(&live), CodeBytes::new(4096 * 4));
        assert_eq!(cache.census().blocks, 1);
        assert_eq!(Rc::strong_count(&live), 2);
        cache.clear();
        assert_eq!(Rc::strong_count(&live), 1);
        assert_eq!(cache.census().code_bytes, CodeBytes::ZERO);
    }

    #[test]
    fn the_hand_bounds_a_sweep_when_every_entry_is_referenced() {
        let mut cache = BlockCache::new(budget(8, usize::MAX));
        for key in 0..8 {
            cache.insert(key, key, CodeBytes::ZERO);
            cache.get(&key);
        }
        cache.insert(8, 8, CodeBytes::ZERO);
        assert_eq!(cache.census().blocks, 8);
        assert_eq!(cache.census().evictions, 1);
    }
}
