//! Pointer-free extent allocation for descriptor backing shared by venues.
//!
//! A buddy tree records the largest free order below each node. Allocation
//! and release visit at most twice the tree height under one short lock.
//! Only offsets cross the venue boundary; backing remains caller-owned.

use crate::{AtomicU32, LockWait, Ordering};

const ALLOCATED: u32 = 1 << 31;
const SPLIT: u32 = 1 << 30;
const ORDER: u32 = !(ALLOCATED | SPLIT);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    Invalid,
    Exhausted,
    Contended,
}

/// Owned allocation receipt. The venue transfers its ownership into the
/// descriptor table's extent and reconstructs it only from a retired extent.
#[derive(Debug)]
pub struct Allocation {
    pub offset: u64,
    pub bytes: u64,
}

/// Zero-initializable shared metadata. `N` is twice the maximum page count;
/// smaller pools use a prefix of the tree. No allocation touches data pages.
#[repr(C)]
pub struct Storage<const N: usize> {
    lock: AtomicU32,
    pages: AtomicU32,
    live: AtomicU32,
    nodes: [AtomicU32; N],
}

struct Guard<'a>(&'a AtomicU32);
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.0.store(0, Ordering::Release);
    }
}

impl<const N: usize> Storage<N> {
    /// Initialize once before publication, over power-of-two 4 KiB pages.
    pub fn initialize(&self, bytes: u64) -> Result<(), StorageError> {
        let _guard = self.acquire(&crate::BoundedSpin(0))?;
        let pages = bytes / 4096;
        if !bytes.is_multiple_of(4096)
            || !pages.is_power_of_two()
            || pages > (N / 2) as u64
            || pages > u64::from(u32::MAX)
            || self.pages.load(Ordering::Relaxed) != 0
        {
            return Err(StorageError::Invalid);
        }
        self.nodes[1].store(pages.ilog2() + 1, Ordering::Relaxed);
        self.pages.store(pages as u32, Ordering::Release);
        Ok(())
    }

    fn acquire(&self, wait: &impl LockWait) -> Result<Guard<'_>, StorageError> {
        let mut attempt = 0u32;
        while self
            .lock
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            attempt = attempt.saturating_add(1);
            if !wait.wait(attempt) {
                return Err(StorageError::Contended);
            }
        }
        Ok(Guard(&self.lock))
    }

    fn order(bytes: u64) -> Result<u32, StorageError> {
        let pages = bytes.max(1).div_ceil(4096);
        pages
            .checked_next_power_of_two()
            .map(|pages| pages.ilog2() + 1)
            .ok_or(StorageError::Exhausted)
    }

    pub fn allocate(&self, bytes: u64, wait: &impl LockWait) -> Result<Allocation, StorageError> {
        let wanted = Self::order(bytes)?;
        let _guard = self.acquire(wait)?;
        let pages = self.pages.load(Ordering::Relaxed);
        if pages == 0 {
            return Err(StorageError::Invalid);
        }
        if self.nodes[1].load(Ordering::Relaxed) & ORDER < wanted {
            return Err(StorageError::Exhausted);
        }
        let mut index = 1;
        let mut order = pages.ilog2() + 1;
        let mut offset = 0;
        while order > wanted {
            if self.nodes[index].load(Ordering::Relaxed) & SPLIT == 0 {
                self.nodes[index * 2].store(order - 1, Ordering::Relaxed);
                self.nodes[index * 2 + 1].store(order - 1, Ordering::Relaxed);
            }
            order -= 1;
            index *= 2;
            if self.nodes[index].load(Ordering::Relaxed) & ORDER < wanted {
                index += 1;
                offset += 4096u64 << (order - 1);
            }
        }
        self.nodes[index].store(ALLOCATED, Ordering::Relaxed);
        while index > 1 {
            index /= 2;
            let maximum = (self.nodes[index * 2].load(Ordering::Relaxed) & ORDER)
                .max(self.nodes[index * 2 + 1].load(Ordering::Relaxed) & ORDER);
            self.nodes[index].store(SPLIT | maximum, Ordering::Relaxed);
        }
        self.live.fetch_add(1, Ordering::Relaxed);
        Ok(Allocation {
            offset,
            bytes: 4096u64 << (wanted - 1),
        })
    }

    /// Return an exact owned receipt after the table stops using its storage.
    /// Wrong sizes, interior pointers and duplicate returns before reuse change
    /// nothing. A receipt must never be reconstructed from an already returned
    /// extent: it carries allocation custody, not an independently usable ID.
    pub fn release(
        &self,
        allocation: Allocation,
        wait: &impl LockWait,
    ) -> Result<(), StorageError> {
        let _guard = self.acquire(wait)?;
        let pages = u64::from(self.pages.load(Ordering::Relaxed));
        let bytes = allocation.bytes;
        if bytes < 4096
            || !bytes.is_power_of_two()
            || !allocation.offset.is_multiple_of(bytes)
            || allocation
                .offset
                .checked_add(bytes)
                .is_none_or(|end| end > pages * 4096)
        {
            return Err(StorageError::Invalid);
        }
        let mut order = pages.ilog2() + 1;
        let wanted = Self::order(bytes)?;
        let mut index = 1;
        let mut offset = allocation.offset;
        while order > wanted {
            if self.nodes[index].load(Ordering::Relaxed) & SPLIT == 0 {
                return Err(StorageError::Invalid);
            }
            order -= 1;
            let half = 4096u64 << (order - 1);
            index = index * 2 + usize::from(offset >= half);
            offset %= half;
        }
        if self.nodes[index].load(Ordering::Relaxed) != ALLOCATED {
            return Err(StorageError::Invalid);
        }
        self.nodes[index].store(wanted, Ordering::Relaxed);
        while index > 1 {
            index /= 2;
            order += 1;
            let left = self.nodes[index * 2].load(Ordering::Relaxed);
            let right = self.nodes[index * 2 + 1].load(Ordering::Relaxed);
            let value = if left == order - 1 && right == order - 1 {
                order
            } else {
                SPLIT | (left & ORDER).max(right & ORDER)
            };
            self.nodes[index].store(value, Ordering::Relaxed);
        }
        self.live.fetch_sub(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn live_allocations(&self) -> u32 {
        self.live.load(Ordering::Acquire)
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_models {
    use super::*;
    use crate::{AtomicU64, BoundedSpin};
    use loom::{sync::Arc, thread};

    #[test]
    fn two_venues_never_own_the_same_extent() {
        let mut model = loom::model::Builder::new();
        model.preemption_bound = Some(2);
        model.max_branches = 10_000;
        model.check(|| {
            let storage = Arc::new(Storage::<8> {
                lock: AtomicU32::new(0),
                pages: AtomicU32::new(0),
                live: AtomicU32::new(0),
                nodes: core::array::from_fn(|_| AtomicU32::new(0)),
            });
            storage.initialize(4 * 4096).unwrap();
            let active = Arc::new(AtomicU64::new(0));
            let actors: [_; 2] = core::array::from_fn(|_| {
                let storage = Arc::clone(&storage);
                let active = Arc::clone(&active);
                thread::spawn(move || {
                    if let Ok(allocation) = storage.allocate(4096, &BoundedSpin(0)) {
                        let bit = 1 << (allocation.offset / 4096);
                        assert_eq!(active.fetch_or(bit, Ordering::AcqRel) & bit, 0);
                        thread::yield_now();
                        assert_ne!(active.fetch_and(!bit, Ordering::AcqRel) & bit, 0);
                        struct Wait;
                        impl LockWait for Wait {
                            fn wait(&self, _: u32) -> bool {
                                thread::yield_now();
                                true
                            }
                        }
                        storage.release(allocation, &Wait).unwrap();
                    }
                })
            });
            for actor in actors {
                actor.join().unwrap();
            }
            assert_eq!(active.load(Ordering::Acquire), 0);
            assert_eq!(storage.live_allocations(), 0);
            let entire = storage.allocate(4 * 4096, &BoundedSpin(0)).unwrap();
            assert_eq!(entire.bytes, 4 * 4096);
            storage.release(entire, &BoundedSpin(0)).unwrap();
        });
    }
}

#[cfg(all(test, not(feature = "loom")))]
mod tests {
    use super::*;
    use crate::BoundedSpin;
    use std::boxed::Box;

    #[test]
    fn live_extents_are_disjoint_and_retirement_restores_the_whole_pool() {
        // SAFETY: this record contains only zero-initializable atomics.
        let storage = unsafe { Box::<Storage<128>>::new_zeroed().assume_init() };
        storage.initialize(64 * 4096).unwrap();
        let wait = BoundedSpin(0);
        let mut live = std::vec::Vec::new();
        for bytes in [1, 4096, 16384, 4097, 32768, 8192, 65536] {
            let allocation = storage.allocate(bytes, &wait).unwrap();
            for prior in &live {
                let prior: &Allocation = prior;
                assert!(
                    allocation.offset + allocation.bytes <= prior.offset
                        || prior.offset + prior.bytes <= allocation.offset
                );
            }
            live.push(allocation);
        }
        assert_eq!(storage.live_allocations(), 7);
        assert!(matches!(
            storage.allocate(64 * 4096, &wait),
            Err(StorageError::Exhausted)
        ));
        for allocation in live.into_iter().rev() {
            storage.release(allocation, &wait).unwrap();
        }
        let entire = storage.allocate(64 * 4096, &wait).unwrap();
        assert_eq!((entire.offset, entire.bytes), (0, 64 * 4096));
        storage.release(entire, &wait).unwrap();
        assert_eq!(storage.live_allocations(), 0);
    }

    #[test]
    fn invalid_returns_cannot_release_a_live_neighbor_or_split_allocation() {
        // SAFETY: this record contains only zero-initializable atomics.
        let storage = unsafe { Box::<Storage<16>>::new_zeroed().assume_init() };
        let wait = BoundedSpin(0);
        storage.initialize(8 * 4096).unwrap();
        let first = storage.allocate(8192, &wait).unwrap();
        let peer = storage.allocate(8192, &wait).unwrap();
        for allocation in [
            Allocation {
                offset: first.offset,
                bytes: 4096,
            },
            Allocation {
                offset: first.offset + 4096,
                bytes: 4096,
            },
            Allocation {
                offset: first.offset,
                bytes: 16384,
            },
        ] {
            assert_eq!(
                storage.release(allocation, &wait),
                Err(StorageError::Invalid)
            );
            assert_eq!(storage.live_allocations(), 2);
        }
        let duplicate = Allocation {
            offset: first.offset,
            bytes: first.bytes,
        };
        storage.release(first, &wait).unwrap();
        assert_eq!(
            storage.release(duplicate, &wait),
            Err(StorageError::Invalid)
        );
        storage.release(peer, &wait).unwrap();
        assert_eq!(storage.live_allocations(), 0);
    }
}
