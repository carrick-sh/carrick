//! Guest side of giving back a granted fork-stock loan that the fork never
//! committed, shared by every guest ISA's native process service.
//!
//! Once the stock crossing granted a loan, the carrier holds it as this
//! CPU's pending loan until a settlement arrives. Every error after the
//! crossing must therefore send an abort settlement, or each later fork on
//! the CPU is refused for capacity. The abort is accepted only when every
//! loaned table page is zero again, so a fork whose publish stored into
//! those pages first scrubs them here.

use carrick_el1_abi::{ForkStockLoan, THREAD_POOL_ENTRIES, ThreadControlSlot, ThreadLifecyclePage};
use carrick_mmu_core::live_descriptor_words::LiveDescriptorWords;

/// Zero the lifecycle page and thread controls the guest initialized for
/// `loan`.
///
/// # Safety
///
/// The caller exclusively owns the never-committed loan: no birth was
/// published from its record, so nothing else reads or writes it.
pub unsafe fn clear_lifecycle(loan: &ForkStockLoan) {
    // SAFETY: the caller's exclusive custody of the loaned record; both
    // extents are the exact sizes the carrier loaned.
    unsafe {
        core::ptr::write_bytes(
            loan.lifecycle.page.raw() as *mut u8,
            0,
            core::mem::size_of::<ThreadLifecyclePage>(),
        );
        core::ptr::write_bytes(
            loan.lifecycle.controls.raw() as *mut u8,
            0,
            core::mem::size_of::<ThreadControlSlot>() * (THREAD_POOL_ENTRIES + 1),
        );
    }
}

/// Zero every nonzero word of the loan's child and parent table arenas.
///
/// Valid only once no walker can reach those pages: the fork's publish
/// refused and rolled back its parent edits, so the loaned tables are
/// unlinked. False when a word could not be read or replaced; the loan then
/// stays pending rather than returning dirty pages to the stock.
pub fn scrub_tables<W: LiveDescriptorWords + ?Sized>(words: &W, loan: &ForkStockLoan) -> bool {
    for arena in [loan.request.child_tables, loan.request.parent_tables] {
        let Some(end) = arena.base.checked_add(arena.len) else {
            return false;
        };
        for pa in (arena.base..end).step_by(8) {
            match words.load(pa) {
                Ok(0) => {}
                Ok(word) => {
                    if words.compare_exchange(pa, word, 0) != Ok(true) {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
    }
    words.publish_barrier();
    true
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// Descriptor words over a sparse map; `fail` refuses one address.
    struct Words {
        words: Mutex<BTreeMap<u64, u64>>,
        fail: Option<u64>,
    }

    impl LiveDescriptorWords for Words {
        fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
            if self.fail == Some(pa) {
                return Err(DescriptorRefusal::MissingTable);
            }
            Ok(self.words.lock().unwrap().get(&pa).copied().unwrap_or(0))
        }
        fn compare_exchange(
            &self,
            pa: u64,
            current: u64,
            new: u64,
        ) -> Result<bool, DescriptorRefusal> {
            let mut words = self.words.lock().unwrap();
            let word = words.entry(pa).or_insert(0);
            if *word != current {
                return Ok(false);
            }
            *word = new;
            Ok(true)
        }
        fn store_unlinked(&self, _: u64, _: u64) -> Result<(), DescriptorRefusal> {
            Err(DescriptorRefusal::Contended)
        }
        fn publish_barrier(&self) {}
        fn invalidate_range(&self, _: u64, _: u64) {}
    }

    fn loan() -> ForkStockLoan {
        let request = carrick_el1_abi::PortalForkRequest {
            operation: carrick_el1_abi::PortalOperation {
                carrier: core::num::NonZeroU64::MIN,
                mm: carrick_el1_abi::ReservationMm::new(1).unwrap(),
                incarnation: core::num::NonZeroU64::MIN,
                sequence: core::num::NonZeroU64::MIN,
            },
            parent_generation: carrick_el1_abi::ReservationGeneration::new(1).unwrap(),
            child_mm: carrick_el1_abi::ReservationMm::new(2).unwrap(),
            child_tables: carrick_el1_abi::PortalForkTableArena::new(0x10000, 0x2000).unwrap(),
            parent_tables: carrick_el1_abi::PortalForkTableArena::new(0x20000, 0x1000).unwrap(),
            kernel_control_ipa: 0x30000,
        };
        ForkStockLoan {
            id: core::num::NonZeroU64::MIN,
            request,
            lifecycle: carrick_el1_abi::ForkLifecycleLoan::new(
                carrick_guest_arch::KernelVa::new(0x40000),
                carrick_guest_arch::KernelVa::new(0x41000),
            )
            .unwrap(),
            asid: None,
        }
    }

    #[test]
    fn scrub_zeroes_every_stored_word_of_both_arenas_and_nothing_else() {
        let stored = [
            (0x10000, 0x8000_0003),
            (0x11ff8, 7),
            (0x20010, 9),
            (0x50000, 11),
        ];
        let words = Words {
            words: Mutex::new(stored.into_iter().collect()),
            fail: None,
        };
        assert!(scrub_tables(&words, &loan()));
        let left = words.words.lock().unwrap();
        assert!(left.range(0x10000..0x12000).all(|(_, word)| *word == 0));
        assert!(left.range(0x20000..0x21000).all(|(_, word)| *word == 0));
        // A word outside the loaned arenas is never touched.
        assert_eq!(left.get(&0x50000), Some(&11));
    }

    #[test]
    fn scrub_refuses_when_a_loaned_word_cannot_be_read() {
        let words = Words {
            words: Mutex::new(BTreeMap::from([(0x10000, 3)])),
            fail: Some(0x20008),
        };
        assert!(!scrub_tables(&words, &loan()));
    }
}
