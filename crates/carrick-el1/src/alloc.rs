//! Bump allocator over the EL1 heap region.

use carrick_el1_abi::{EL1_HEAP_BASE, EL1_HEAP_SIZE};
use core::sync::atomic::{AtomicUsize, Ordering};

pub struct BumpAllocator {
    offset: AtomicUsize,
}

impl BumpAllocator {
    pub const fn new() -> Self {
        Self {
            offset: AtomicUsize::new(0),
        }
    }

    pub fn allocate(&self, size: usize, align: usize) -> Option<*mut u8> {
        let align_mask = align.checked_sub(1)?;
        let mut current = self.offset.load(Ordering::Relaxed);
        loop {
            let aligned = (current.checked_add(align_mask)?) & !align_mask;
            let next = aligned.checked_add(size)?;
            if next > EL1_HEAP_SIZE as usize {
                return None;
            }
            match self.offset.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some((EL1_HEAP_BASE as usize + aligned) as *mut u8),
                Err(prev) => current = prev,
            }
        }
    }
}

impl Default for BumpAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bump_allocator() {
        let alloc = BumpAllocator::new();
        let p1 = alloc.allocate(64, 8).expect("alloc p1");
        assert_eq!(p1 as usize % 8, 0);
        let p2 = alloc.allocate(128, 16).expect("alloc p2");
        assert_eq!(p2 as usize % 16, 0);
        assert!(p2 as usize >= p1 as usize + 64);
    }
}
