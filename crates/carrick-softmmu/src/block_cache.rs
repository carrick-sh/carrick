//! Bounded storage for decoded blocks and their executable owners.
//! The engine supplies keys and validates the mapping and code identity on
//! entry. The cache holds no guest memory or translation authority.

use alloc::collections::{BTreeMap, VecDeque};

const CAPACITY: usize = 1024;

/// MEASUREMENT ONLY (#2717, do not land): capacity override; 0 keeps
/// `CAPACITY`.
pub static MEASURE_CAPACITY: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

fn capacity() -> usize {
    match MEASURE_CAPACITY.load(core::sync::atomic::Ordering::Relaxed) {
        0 => CAPACITY,
        n => n,
    }
}

/// FIFO eviction bounds resident entries. Replacing an entry keeps its place
/// in the queue, so repeated changes to one block do not evict its peers.
pub struct BlockCache<K, V> {
    blocks: BTreeMap<K, V>,
    order: VecDeque<K>,
}

impl<K, V> Default for BlockCache<K, V> {
    fn default() -> Self {
        Self {
            blocks: BTreeMap::new(),
            order: VecDeque::new(),
        }
    }
}

impl<K: Copy + Ord, V> BlockCache<K, V> {
    pub fn get(&self, key: &K) -> Option<&V> {
        self.blocks.get(key)
    }

    pub fn insert(&mut self, key: K, value: V) -> &V {
        if !self.blocks.contains_key(&key) {
            if self.blocks.len() >= capacity()
                && let Some(oldest) = self.order.pop_front()
            {
                self.blocks.remove(&oldest);
            }
            self.order.push_back(key);
        }
        self.blocks.entry(key).insert_entry(value).into_mut()
    }

    /// MEASUREMENT ONLY (#2717, do not land): `insert` that reports the
    /// key it evicted.
    pub fn insert_reporting(&mut self, key: K, value: V) -> (Option<K>, &V) {
        let mut evicted = None;
        if !self.blocks.contains_key(&key) {
            if self.blocks.len() >= capacity()
                && let Some(oldest) = self.order.pop_front()
            {
                self.blocks.remove(&oldest);
                evicted = Some(oldest);
            }
            self.order.push_back(key);
        }
        (
            evicted,
            self.blocks.entry(key).insert_entry(value).into_mut(),
        )
    }

    /// MEASUREMENT ONLY (#2717, do not land).
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.blocks.keys()
    }

    /// MEASUREMENT ONLY (#2717, do not land).
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// MEASUREMENT ONLY (#2717, do not land).
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub fn clear(&mut self) {
        self.blocks.clear();
        self.order.clear();
    }
}
