//! Exact-MM temporary supervisor aliases for COW copying. Fork clones this
//! private root branch; all other retained supervisor branches stay shared.
use super::descriptor_txn::{ADDRESS, HUGE, NX, PRESENT, USER, WRITE};
use crate::descriptor_refusal::DescriptorRefusal;
use crate::x86::descriptor_txn::{DescriptorOutcome, LiveDescriptorWords};
use carrick_guest_arch::{FrameGpa, RootGpa};

pub const COW_COPY_WINDOW_BASE: u64 = 0xffff_fe00_0000_0000;
pub const COW_COPY_WINDOW_LEN: u64 = 8192;
pub const COW_COPY_TABLE_PAGES: usize = 3;
const ACCESSED: u64 = 1 << 5;
const DIRTY: u64 = 1 << 6;
const _: () =
    assert!(((COW_COPY_WINDOW_BASE >> 39) & 511) as usize == super::owner_mmu::COW_COPY_ROOT_INDEX);

fn frame_valid(frame: FrameGpa) -> bool {
    frame.raw() != 0 && frame.raw() & !ADDRESS == 0
}

struct Pair {
    addresses: [u64; 2],
    tables: [u64; 4],
}

fn pair<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: RootGpa,
) -> Result<Pair, DescriptorRefusal> {
    let mut tables = [root.address().raw(), 0, 0, 0];
    if !frame_valid(root.address()) {
        return Err(DescriptorRefusal::WrongBacking);
    }
    for (level, shift) in [39, 30, 21].into_iter().enumerate() {
        let word = words.load(tables[level] + ((COW_COPY_WINDOW_BASE >> shift) & 511) * 8)?;
        if word & (PRESENT | WRITE | USER | HUGE) != PRESENT | WRITE {
            return Err(DescriptorRefusal::CopyWindowAbsent);
        }
        let next = word & ADDRESS;
        if !frame_valid(FrameGpa::new(next)) || tables[..=level].contains(&next) {
            return Err(DescriptorRefusal::WrongBacking);
        }
        tables[level + 1] = next;
    }
    let first = tables[3] + ((COW_COPY_WINDOW_BASE >> 12) & 511) * 8;
    let addresses = [first, first + 8];
    for address in addresses {
        if words.load(address)? != 0 {
            return Err(DescriptorRefusal::Contended);
        }
    }
    Ok(Pair { addresses, tables })
}

/// Validate the fixed idle pair without publishing any descriptor.
pub fn validate_cow_copy_window<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: RootGpa,
) -> Result<(), DescriptorRefusal> {
    pair(words, root).map(|_| ())
}

/// Return the authenticated private branch frames of the fixed idle pair.
pub fn cow_copy_table_frames<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: RootGpa,
) -> Result<[RootGpa; COW_COPY_TABLE_PAGES], DescriptorRefusal> {
    let pair = pair(words, root)?;
    let mut frames = [root; COW_COPY_TABLE_PAGES];
    for (frame, address) in frames.iter_mut().zip(pair.tables[1..].iter()) {
        *frame = RootGpa::page_aligned(FrameGpa::new(*address))
            .ok_or(DescriptorRefusal::WrongBacking)?;
    }
    Ok(frames)
}

fn restore<W: LiveDescriptorWords + ?Sized>(words: &W, edits: &[(u64, u64)]) -> bool {
    let mut clean = true;
    for &(address, installed) in edits.iter().rev() {
        clean &= words.compare_exchange(address, installed, 0) == Ok(true);
    }
    if !edits.is_empty() {
        words.publish_barrier();
        words.invalidate_range(COW_COPY_WINDOW_BASE, COW_COPY_WINDOW_LEN);
    }
    clean
}

/// Provision an unopened MM's private branch from three exclusive zero table
/// grants. The caller retains the root and grants through refusal/rollback;
/// an indeterminate outcome forbids their reuse. No physical resources are
/// selected or allocated here.
pub fn provision_cow_copy_window<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: RootGpa,
    tables: [RootGpa; COW_COPY_TABLE_PAGES],
) -> Result<(), DescriptorOutcome> {
    let refused = DescriptorOutcome::Refused;
    if !frame_valid(root.address()) {
        return Err(refused(DescriptorRefusal::WrongBacking));
    }
    let root_word = root.address().raw() + super::owner_mmu::COW_COPY_ROOT_INDEX as u64 * 8;
    if words.load(root_word).map_err(refused)? != 0 {
        return Err(refused(DescriptorRefusal::Contended));
    }
    for (index, table) in tables.iter().enumerate() {
        if !frame_valid(table.address()) || *table == root || tables[..index].contains(table) {
            return Err(refused(DescriptorRefusal::WrongBacking));
        }
        for offset in (0..4096).step_by(8) {
            if words
                .load(table.address().raw() + offset)
                .map_err(refused)?
                != 0
            {
                return Err(refused(DescriptorRefusal::Contended));
            }
        }
    }
    let flags = PRESENT | WRITE | NX | ACCESSED;
    let edits = [
        (tables[0].address().raw(), tables[1].address().raw() | flags),
        (tables[1].address().raw(), tables[2].address().raw() | flags),
        (root_word, tables[0].address().raw() | flags),
    ];
    for (index, &(address, after)) in edits.iter().enumerate() {
        if index == 2 {
            words.publish_barrier();
        }
        if words.compare_exchange(address, 0, after) != Ok(true) {
            return Err(if restore(words, &edits[..index]) {
                refused(DescriptorRefusal::Contended)
            } else {
                DescriptorOutcome::Indeterminate(DescriptorRefusal::Contended)
            });
        }
    }
    words.publish_barrier();
    words.invalidate_range(COW_COPY_WINDOW_BASE, COW_COPY_WINDOW_LEN);
    Ok(())
}

/// Map the two idle leaves under the exact-MM editor, copy, then restore and
/// drain before returning. Source and destination stage-2 custody is retained
/// by the shared COW grant owner. The caller must quarantine an indeterminate
/// cleanup. Hardware A/D bits are pre-set so cleanup remains exact.
pub fn with_cow_copy_aliases<W, R>(
    words: &W,
    root: RootGpa,
    source: FrameGpa,
    destination: FrameGpa,
    copy: impl FnOnce(u64, u64) -> R,
) -> Result<R, DescriptorOutcome>
where
    W: LiveDescriptorWords + ?Sized,
{
    let refused = DescriptorOutcome::Refused;
    let pair = pair(words, root).map_err(refused)?;
    if !frame_valid(source)
        || !frame_valid(destination)
        || source == destination
        || pair.tables.contains(&source.raw())
        || pair.tables.contains(&destination.raw())
    {
        return Err(refused(DescriptorRefusal::WrongBacking));
    }
    let edits = [
        (pair.addresses[0], source.raw() | PRESENT | NX | ACCESSED),
        (
            pair.addresses[1],
            destination.raw() | PRESENT | WRITE | NX | ACCESSED | DIRTY,
        ),
    ];
    for (index, &(address, after)) in edits.iter().enumerate() {
        if words.compare_exchange(address, 0, after) != Ok(true) {
            return Err(if restore(words, &edits[..index]) {
                refused(DescriptorRefusal::Contended)
            } else {
                DescriptorOutcome::Indeterminate(DescriptorRefusal::Contended)
            });
        }
    }
    words.publish_barrier();
    words.invalidate_range(COW_COPY_WINDOW_BASE, COW_COPY_WINDOW_LEN);
    let result = copy(COW_COPY_WINDOW_BASE, COW_COPY_WINDOW_BASE + 4096);
    if !restore(words, &edits) {
        return Err(DescriptorOutcome::Indeterminate(
            DescriptorRefusal::Contended,
        ));
    }
    Ok(result)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::cell::Cell;

    struct Words {
        image: Vec<Cell<u64>>,
        loads: Cell<usize>,
        exchanges: Cell<usize>,
        fail_at: Cell<Option<usize>>,
        drains: Cell<usize>,
    }
    impl Words {
        fn new() -> Self {
            Self {
                image: (0..0x5000 / 8).map(|_| Cell::new(0)).collect(),
                loads: Cell::new(0),
                exchanges: Cell::new(0),
                fail_at: Cell::new(None),
                drains: Cell::new(0),
            }
        }
        fn read(&self, pa: u64) -> u64 {
            self.image[pa as usize / 8].get()
        }
    }
    impl LiveDescriptorWords for Words {
        fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
            self.loads.set(self.loads.get() + 1);
            self.image
                .get(pa as usize / 8)
                .map(Cell::get)
                .ok_or(DescriptorRefusal::TableOutsidePrimary)
        }
        fn compare_exchange(&self, pa: u64, old: u64, new: u64) -> Result<bool, DescriptorRefusal> {
            let count = self.exchanges.get() + 1;
            self.exchanges.set(count);
            if self.fail_at.get() == Some(count) {
                return Ok(false);
            }
            let cell = self
                .image
                .get(pa as usize / 8)
                .ok_or(DescriptorRefusal::TableOutsidePrimary)?;
            if cell.get() != old {
                return Ok(false);
            }
            cell.set(new);
            Ok(true)
        }
        fn store_unlinked(&self, _: u64, _: u64) -> Result<(), DescriptorRefusal> {
            Err(DescriptorRefusal::TableOutsidePrimary)
        }
        fn publish_barrier(&self) {}
        fn invalidate_range(&self, va: u64, len: u64) {
            assert_eq!((va, len), (COW_COPY_WINDOW_BASE, COW_COPY_WINDOW_LEN));
            self.drains.set(self.drains.get() + 1);
        }
    }
    fn root(pa: u64) -> RootGpa {
        RootGpa::page_aligned(FrameGpa::new(pa)).unwrap()
    }
    fn tables() -> [RootGpa; 3] {
        [root(0x2000), root(0x3000), root(0x4000)]
    }

    #[test]
    fn private_copy_pair_has_bounded_work_and_restores_before_completion() {
        let words = Words::new();
        provision_cow_copy_window(&words, root(0x1000), tables()).unwrap();
        assert_eq!(words.loads.get(), 1 + 3 * 512);
        assert_eq!(words.exchanges.get(), 3);
        assert_eq!(
            cow_copy_table_frames(&words, root(0x1000)).unwrap(),
            tables()
        );
        words.loads.set(0);
        words.exchanges.set(0);
        words.drains.set(0);
        with_cow_copy_aliases(
            &words,
            root(0x1000),
            FrameGpa::new(0x100000),
            FrameGpa::new(0x2_0000_0000),
            |from, to| {
                assert_eq!(
                    (from, to),
                    (COW_COPY_WINDOW_BASE, COW_COPY_WINDOW_BASE + 4096)
                );
                assert_eq!(words.read(0x4000), 0x100000 | PRESENT | NX | ACCESSED);
                assert_eq!(
                    words.read(0x4008),
                    0x2_0000_0000 | PRESENT | WRITE | NX | ACCESSED | DIRTY
                );
                assert_eq!(words.drains.get(), 1);
            },
        )
        .unwrap();
        assert_eq!((words.read(0x4000), words.read(0x4008)), (0, 0));
        assert_eq!(words.loads.get(), 5);
        assert_eq!(words.exchanges.get(), 4);
        assert_eq!(words.drains.get(), 2);
    }

    #[test]
    fn private_copy_pair_refuses_dirty_or_aliased_grants_before_publication() {
        for candidates in [
            [root(0x1000), root(0x3000), root(0x4000)],
            [root(0x2000), root(0x2000), root(0x4000)],
        ] {
            let words = Words::new();
            assert!(provision_cow_copy_window(&words, root(0x1000), candidates).is_err());
            assert_eq!(words.exchanges.get(), 0);
        }
        let words = Words::new();
        words.image[0x4008 / 8].set(1);
        assert!(provision_cow_copy_window(&words, root(0x1000), tables()).is_err());
        assert_eq!(words.exchanges.get(), 0);
    }

    #[test]
    fn private_copy_pair_restores_partial_admission_and_reports_failed_cleanup() {
        for fail_at in [1, 2, 3] {
            let words = Words::new();
            words.fail_at.set(Some(fail_at));
            assert!(matches!(
                provision_cow_copy_window(&words, root(0x1000), tables()),
                Err(DescriptorOutcome::Refused(_))
            ));
            assert!(words.image.iter().all(|word| word.get() == 0));
        }
        for (fail_at, indeterminate) in [(2, false), (3, true)] {
            let words = Words::new();
            provision_cow_copy_window(&words, root(0x1000), tables()).unwrap();
            words.exchanges.set(0);
            words.fail_at.set(Some(fail_at));
            let mut copied = false;
            let result = with_cow_copy_aliases(
                &words,
                root(0x1000),
                FrameGpa::new(0x100000),
                FrameGpa::new(0x2_0000_0000),
                |_, _| copied = true,
            );
            assert_eq!(copied, indeterminate);
            assert_eq!(
                matches!(result, Err(DescriptorOutcome::Indeterminate(_))),
                indeterminate
            );
            if !indeterminate {
                assert_eq!((words.read(0x4000), words.read(0x4008)), (0, 0));
            }
        }
    }
}
