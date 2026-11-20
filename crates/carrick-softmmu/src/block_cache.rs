//! Bounded storage for decoded blocks and their executable owners.
//! The engine supplies keys and validates the mapping and code identity on
//! entry. The cache holds no guest memory or translation authority.

use alloc::collections::{BTreeMap, VecDeque};

pub const DEFAULT_BLOCK_CACHE_CAPACITY: usize = 1024;

/// FIFO eviction bounds resident entries. Replacing an entry keeps its place
/// in the queue, so repeated changes to one block do not evict its peers.
pub struct BlockCache<K, V> {
    blocks: BTreeMap<K, V>,
    order: VecDeque<K>,
    capacity: usize,
}

impl<K, V> Default for BlockCache<K, V> {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_BLOCK_CACHE_CAPACITY)
    }
}

impl<K, V> BlockCache<K, V> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            blocks: BTreeMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }
}

impl<K: Copy + Ord, V> BlockCache<K, V> {
    pub fn get(&self, key: &K) -> Option<&V> {
        self.blocks.get(key)
    }

    pub fn insert(&mut self, key: K, value: V) -> &V {
        if !self.blocks.contains_key(&key) {
            if self.blocks.len() == self.capacity
                && let Some(oldest) = self.order.pop_front()
            {
                self.blocks.remove(&oldest);
            }
            self.order.push_back(key);
        }
        self.blocks.entry(key).insert_entry(value).into_mut()
    }

    pub fn clear(&mut self) {
        self.blocks.clear();
        self.order.clear();
    }
}
