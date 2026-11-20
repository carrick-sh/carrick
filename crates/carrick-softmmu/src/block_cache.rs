//! Bounded storage for decoded blocks and their executable owners.
//! The engine supplies keys and validates the mapping and code identity on
//! entry. The cache holds no guest memory or translation authority.

use alloc::collections::{BTreeMap, VecDeque};

const CAPACITY: usize = 1024;

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
        let _ = key;
        None
    }

    pub fn insert(&mut self, key: K, value: V) -> &V {
        if !self.blocks.contains_key(&key) {
            if self.blocks.len() == CAPACITY
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
