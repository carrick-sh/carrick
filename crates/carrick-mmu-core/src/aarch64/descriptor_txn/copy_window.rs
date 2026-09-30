//! Temporary, exact-MM kernel aliases for guest COW copying.
use super::{DescriptorOutcome, DescriptorRefusal, LiveDescriptorWords};
use crate::aarch64::SubstrateGpa;

const PAGE: u64 = 4096;
const MASK: u64 = 0x0000_FFFF_FFFF_F000;
const AP: u64 = 3 << 6;

fn leaf<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: SubstrateGpa,
    va: u64,
) -> Result<(u64, u64), DescriptorRefusal> {
    let mut table = root.raw();
    for shift in [39, 30, 21] {
        let descriptor = words.load(table + ((va >> shift) & 511) * 8)?;
        if descriptor & 3 != 3 {
            return Err(DescriptorRefusal::CopyWindowAbsent);
        }
        table = descriptor & MASK;
    }
    let address = table + ((va >> 12) & 511) * 8;
    Ok((address, words.load(address)?))
}

/// Map two preallocated, idle kernel-only page leaves while the caller owns
/// the exact-MM editor. Invoke `copy` only after both aliases are visible;
/// restore and invalidate both before returning its result. No tables or
/// backing are allocated. The caller retains both exact stage-2 owner pins.
///
/// `base` is a trusted layout constant, never a guest-supplied address. Its
/// two idle leaves must retain their original identity outputs and deny EL0.
/// An indeterminate cleanup is fatal for the MM, never permission to resume.
pub fn with_cow_copy_aliases<W, R>(
    words: &W,
    root: SubstrateGpa,
    base: u64,
    source: SubstrateGpa,
    destination: SubstrateGpa,
    copy: impl FnOnce(u64, u64) -> R,
) -> Result<R, DescriptorOutcome>
where
    W: LiveDescriptorWords + ?Sized,
{
    let refused = DescriptorOutcome::Refused;
    if base.checked_add(2 * PAGE).is_none()
        || !base.is_multiple_of(PAGE)
        || source == destination
        || [source.raw(), destination.raw()]
            .iter()
            .any(|ipa| *ipa == 0 || *ipa & !MASK != 0)
    {
        return Err(refused(DescriptorRefusal::WrongBacking));
    }
    let mut edits = [(0, 0, 0); 2];
    for (index, ipa) in [source.raw(), destination.raw()].into_iter().enumerate() {
        let va = base + index as u64 * PAGE;
        let (address, before) = leaf(words, root, va).map_err(refused)?;
        if before & 1 != 0 || before & AP != 0 || before & MASK != va {
            return Err(refused(DescriptorRefusal::WrongBacking));
        }
        // Normal inner-shareable memory; source EL1-RO, destination EL1-RW;
        // never executable or EL0-accessible, and scoped to this MM's ASID.
        let after = ipa
            | 3
            | (1 << 10)
            | (3 << 8)
            | (1 << 11)
            | (1 << 53)
            | (1 << 54)
            | if index == 0 { 2 << 6 } else { 0 };
        edits[index] = (address, before, after);
    }
    for index in 0..2 {
        let (address, before, after) = edits[index];
        if words.compare_exchange(address, before, after) != Ok(true) {
            return if restore(words, base, &edits[..index]) {
                Err(refused(DescriptorRefusal::Contended))
            } else {
                Err(DescriptorOutcome::Indeterminate(
                    DescriptorRefusal::Contended,
                ))
            };
        }
    }
    words.publish_barrier();
    words.invalidate_range(base, 2 * PAGE);
    let result = copy(base, base + PAGE);
    if !restore(words, base, &edits) {
        return Err(DescriptorOutcome::Indeterminate(
            DescriptorRefusal::Contended,
        ));
    }
    Ok(result)
}

fn restore<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    base: u64,
    edits: &[(u64, u64, u64)],
) -> bool {
    let mut restored = true;
    for &(address, before, after) in edits.iter().rev() {
        restored &= words.compare_exchange(address, after, before) == Ok(true);
    }
    if !edits.is_empty() {
        words.publish_barrier();
        words.invalidate_range(base, 2 * PAGE);
    }
    restored
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::cell::Cell;

    const BASE: u64 = 0x1_0000;
    const ROOT: SubstrateGpa = SubstrateGpa(0x1000);
    const FIRST: u64 = 0x4000 + 16 * 8;
    struct Words {
        words: Vec<Cell<u64>>,
        fail: Cell<Option<u64>>,
        invalidations: Cell<usize>,
    }
    impl Words {
        fn new() -> Self {
            let words = Self {
                words: (0..0x5000 / 8).map(|_| Cell::new(0)).collect(),
                fail: Cell::new(None),
                invalidations: Cell::new(0),
            };
            words.words[0x1000 / 8].set(0x2003);
            words.words[0x2000 / 8].set(0x3003);
            words.words[0x3000 / 8].set(0x4003);
            words.words[FIRST as usize / 8].set(BASE | 2);
            words.words[FIRST as usize / 8 + 1].set((BASE + PAGE) | 2);
            words
        }
    }
    impl LiveDescriptorWords for Words {
        fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
            self.words
                .get(pa as usize / 8)
                .map(Cell::get)
                .ok_or(DescriptorRefusal::TableOutsidePrimary)
        }
        fn compare_exchange(
            &self,
            pa: u64,
            before: u64,
            after: u64,
        ) -> Result<bool, DescriptorRefusal> {
            if self.fail.get() == Some(pa) {
                return Ok(false);
            }
            if self.load(pa)? != before {
                return Ok(false);
            }
            self.words[pa as usize / 8].set(after);
            Ok(true)
        }
        fn store_unlinked(&self, _: u64, _: u64) -> Result<(), DescriptorRefusal> {
            panic!("window must never allocate tables")
        }
        fn publish_barrier(&self) {}
        fn invalidate_range(&self, va: u64, len: u64) {
            assert_eq!((va, len), (BASE, 2 * PAGE));
            self.invalidations.set(self.invalidations.get() + 1);
        }
    }
    #[test]
    fn cow_copy_aliases_are_scoped_kernel_only_and_removed_before_completion() {
        let words = Words::new();
        assert_eq!(
            with_cow_copy_aliases(
                &words,
                ROOT,
                BASE,
                SubstrateGpa(0x8000),
                SubstrateGpa(0x9000),
                |source, dest| {
                    assert_eq!((source, dest), (BASE, BASE + PAGE));
                    assert_eq!(
                        words.load(FIRST).unwrap() & (MASK | AP | 3),
                        0x8000 | (2 << 6) | 3
                    );
                    assert_eq!(words.load(FIRST + 8).unwrap() & (MASK | AP | 3), 0x9000 | 3);
                    for address in [FIRST, FIRST + 8] {
                        assert_eq!(
                            words.load(address).unwrap() & ((1 << 53) | (1 << 54) | (1 << 11)),
                            (1 << 53) | (1 << 54) | (1 << 11)
                        );
                    }
                    17
                }
            ),
            Ok(17)
        );
        assert_eq!(words.load(FIRST).unwrap(), BASE | 2);
        assert_eq!(words.load(FIRST + 8).unwrap(), (BASE + PAGE) | 2);
        assert_eq!(words.invalidations.get(), 2);
    }
    #[test]
    fn cow_copy_aliases_refuse_busy_slots_and_roll_back_partial_mapping() {
        for busy in [true, false] {
            let words = Words::new();
            if busy {
                words.words[(FIRST + 8) as usize / 8].set(0x9003);
            } else {
                words.fail.set(Some(FIRST + 8));
            }
            assert!(
                with_cow_copy_aliases(
                    &words,
                    ROOT,
                    BASE,
                    SubstrateGpa(0x8000),
                    SubstrateGpa(0x9000),
                    |_, _| panic!("refusal must precede copying")
                )
                .is_err()
            );
            assert_eq!(words.load(FIRST).unwrap(), BASE | 2);
        }
    }
    #[test]
    fn cow_copy_aliases_at_the_same_va_are_private_to_each_mm_root() {
        let mut words = Words::new();
        words.words.resize_with(0x9000 / 8, || Cell::new(0));
        let second_root = SubstrateGpa(0x5000);
        let second_leaf = 0x8000 + 16 * 8;
        for (address, value) in [
            (0x5000, 0x6003),
            (0x6000, 0x7003),
            (0x7000, 0x8003),
            (second_leaf, BASE | 2),
            (second_leaf + 8, (BASE + PAGE) | 2),
        ] {
            words.words[address as usize / 8].set(value);
        }
        with_cow_copy_aliases(
            &words,
            ROOT,
            BASE,
            SubstrateGpa(0xA000),
            SubstrateGpa(0xB000),
            |_, _| {
                assert_eq!(words.load(second_leaf).unwrap(), BASE | 2);
                with_cow_copy_aliases(
                    &words,
                    second_root,
                    BASE,
                    SubstrateGpa(0xC000),
                    SubstrateGpa(0xD000),
                    |_, _| {
                        assert_eq!(words.load(FIRST).unwrap() & MASK, 0xA000);
                        assert_eq!(words.load(second_leaf).unwrap() & MASK, 0xC000);
                    },
                )
                .unwrap();
                assert_eq!(words.load(FIRST).unwrap() & MASK, 0xA000);
                assert_eq!(words.load(second_leaf).unwrap(), BASE | 2);
            },
        )
        .unwrap();
        assert_eq!(words.load(FIRST).unwrap(), BASE | 2);
    }

    #[test]
    fn cow_copy_aliases_report_failed_revocation_as_indeterminate() {
        let words = Words::new();
        assert_eq!(
            with_cow_copy_aliases(
                &words,
                ROOT,
                BASE,
                SubstrateGpa(0x8000),
                SubstrateGpa(0x9000),
                |_, _| words.fail.set(Some(FIRST))
            ),
            Err(DescriptorOutcome::Indeterminate(
                DescriptorRefusal::Contended
            ))
        );
        assert_eq!(
            words.load(FIRST + 8).unwrap(),
            (BASE + PAGE) | 2,
            "still revoke the other alias"
        );
    }
}
