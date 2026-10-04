#![allow(clippy::unwrap_used)]
use super::*;
use alloc::vec;
use core::num::NonZeroU64;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

struct Words {
    words: RefCell<BTreeMap<u64, u64>>,
    writes: Cell<usize>,
    fail: Cell<usize>,
}
impl Words {
    fn new() -> Self {
        Self {
            words: RefCell::new((0x1000..0x20000).step_by(8).map(|pa| (pa, 0)).collect()),
            writes: Cell::new(0),
            fail: Cell::new(usize::MAX),
        }
    }
}
impl LiveDescriptorWords for Words {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        self.words
            .borrow()
            .get(&pa)
            .copied()
            .ok_or(DescriptorRefusal::MissingTable)
    }
    fn compare_exchange(
        &self,
        pa: u64,
        before: u64,
        after: u64,
    ) -> Result<bool, DescriptorRefusal> {
        let n = self.writes.get();
        self.writes.set(n + 1);
        if n == self.fail.get() {
            return Err(DescriptorRefusal::Contended);
        }
        let mut words = self.words.borrow_mut();
        let entry = words.get_mut(&pa).ok_or(DescriptorRefusal::MissingTable)?;
        if *entry != before {
            return Ok(false);
        }
        *entry = after;
        Ok(true)
    }
    fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
        self.words.borrow_mut().insert(pa, value);
        Ok(())
    }
    fn publish_barrier(&self) {}
    fn invalidate_range(&self, _: u64, _: u64) {}
}
fn root(pa: u64) -> RootGpa {
    RootGpa::page_aligned(FrameGpa::new(pa)).unwrap()
}
fn backing() -> BackingIdentity {
    let n = NonZeroU64::new(1).unwrap();
    BackingIdentity {
        frame_id: n,
        mapping_id: n,
        owner_generation: n,
        inventory_revision: n,
    }
}
fn txn<'a>(op: DescriptorOp, tables: &'a [RootGpa]) -> DescriptorTxn<'a> {
    let n = NonZeroU64::new(1).unwrap();
    DescriptorTxn {
        id: DescriptorTxnId {
            mm_key: n,
            generation: n,
        },
        root: root(0x1000),
        op,
        tables,
    }
}
fn map(va: u64, output: u64, len: u64, size: LeafSize) -> DescriptorOp {
    DescriptorOp::Map {
        span: PageSpan::new(va, len),
        output: FrameGpa::new(output),
        permissions: Permissions {
            writable: true,
            executable: false,
            user: true,
        },
        size,
        resident: true,
        backing: backing(),
    }
}
fn apply(words: &Words, op: DescriptorOp, tables: &[RootGpa]) -> DescriptorOutcome {
    execute_descriptor_txn(
        words,
        &txn(op, tables),
        root(0x1000),
        &mut InlineJournal::new(),
    )
    .outcome
}
#[test]
fn builds_all_four_levels_and_nonidentity_output() {
    let words = Words::new();
    assert!(matches!(
        apply(
            &words,
            map(0x4000, 0x800000, PAGE, LeafSize::Page),
            &[root(0x2000), root(0x3000), root(0x4000)]
        ),
        DescriptorOutcome::Applied {
            tables_linked: 3,
            ..
        }
    ));
    assert_eq!(words.load(0x1000).unwrap() & ADDRESS, 0x2000);
    assert_eq!(words.load(0x3000).unwrap() & ADDRESS, 0x4000);
    assert_eq!(words.load(0x4000 + 4 * 8).unwrap() & ADDRESS, 0x800000);
}
#[test]
fn every_publication_failure_restores_all_levels_and_grants() {
    for failure in 0..4 {
        let words = Words::new();
        let before = words.words.borrow().clone();
        words.fail.set(failure);
        assert_eq!(
            apply(
                &words,
                map(0x4000, 0x800000, PAGE, LeafSize::Page),
                &[root(0x2000), root(0x3000), root(0x4000)]
            ),
            DescriptorOutcome::RolledBack(DescriptorRefusal::Contended)
        );
        assert_eq!(*words.words.borrow(), before);
    }
}
#[test]
fn contiguous_unaligned_outputs_must_not_coalesce() {
    let words = Words::new();
    assert!(matches!(
        apply(
            &words,
            map(0x200000, 0x401000, 1 << 21, LeafSize::Page),
            &[root(0x2000), root(0x3000), root(0x4000)]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    let before = words.words.borrow().clone();
    assert!(matches!(
        apply(
            &words,
            DescriptorOp::Coalesce {
                span: PageSpan::new(0x200000, 1 << 21),
                size: LeafSize::Block2M
            },
            &[]
        ),
        DescriptorOutcome::Refused(_)
    ));
    assert_eq!(*words.words.borrow(), before);
}
#[test]
fn first_touch_cow_nx_and_protection_have_distinct_classes() {
    let words = Words::new();
    let span = PageSpan::new(0x4000, PAGE);
    let mut op = map(span.va, 0x800000, span.len, LeafSize::Page);
    if let DescriptorOp::Map { resident, .. } = &mut op {
        *resident = false;
    }
    assert!(matches!(
        apply(&words, op, &[root(0x2000), root(0x3000), root(0x4000)]),
        DescriptorOutcome::Applied { .. }
    ));
    let walk = |access| {
        translate(
            &words,
            root(0x1000),
            UserVa::new(span.va + 19),
            access,
            true,
        )
    };
    assert_eq!(walk(Access::Read), Err(FaultClass::NotPresent));
    assert!(matches!(
        apply(
            &words,
            DescriptorOp::Publish {
                span,
                expected: FrameGpa::new(0x800000)
            },
            &[]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    assert_eq!(walk(Access::Read), Ok(FrameGpa::new(0x800000 + 19)));
    assert_eq!(walk(Access::Execute), Err(FaultClass::Nx));
    apply(&words, DescriptorOp::ArmCow(span), &[]);
    assert_eq!(walk(Access::Write), Err(FaultClass::CowWrite));
    assert!(matches!(
        apply(
            &words,
            DescriptorOp::CowRepoint {
                span,
                old: FrameGpa::new(0x800000),
                new: FrameGpa::new(0x900000),
                backing: backing()
            },
            &[]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    assert_eq!(walk(Access::Write), Ok(FrameGpa::new(0x900000 + 19)));
    apply(
        &words,
        DescriptorOp::Protect {
            span,
            permissions: Permissions {
                writable: false,
                executable: true,
                user: true,
            },
        },
        &[],
    );
    assert_eq!(walk(Access::Write), Err(FaultClass::Protection));
    assert_eq!(walk(Access::Execute), Ok(FrameGpa::new(0x900000 + 19)));
}
#[test]
fn split_and_coalesce_preserve_pat_output_and_neighbors() {
    for size in [LeafSize::Block2M, LeafSize::Block1G] {
        let words = Words::new();
        let len = size.bytes();
        let initial_grants = if size == LeafSize::Block1G {
            vec![root(0x2000)]
        } else {
            vec![root(0x2000), root(0x3000)]
        };
        apply(&words, map(len, len * 2, len, size), &initial_grants);
        // Set large-page PAT, which moves from bit 12 to bit 7 at 4 KiB.
        let parent_slot = if size == LeafSize::Block1G {
            0x2008
        } else {
            0x3008
        };
        *words.words.borrow_mut().get_mut(&parent_slot).unwrap() |= PAT_LARGE;
        let first_grant = if size == LeafSize::Block1G {
            0x3000
        } else {
            0x4000
        };
        let grants = if size == LeafSize::Block1G {
            vec![root(first_grant), root(first_grant + PAGE)]
        } else {
            vec![root(first_grant)]
        };
        let span = PageSpan::new(len + PAGE, PAGE);
        let permissions = Permissions {
            writable: false,
            executable: false,
            user: true,
        };
        assert!(matches!(
            apply(&words, DescriptorOp::Protect { span, permissions }, &grants),
            DescriptorOutcome::Applied { .. }
        ));
        assert_eq!(
            translate(&words, root(0x1000), UserVa::new(len), Access::Write, true),
            Ok(FrameGpa::new(len * 2))
        );
        assert_eq!(
            translate(
                &words,
                root(0x1000),
                UserVa::new(len + PAGE),
                Access::Write,
                true
            ),
            Err(FaultClass::Protection)
        );
        apply(
            &words,
            DescriptorOp::Protect {
                span,
                permissions: Permissions {
                    writable: true,
                    ..permissions
                },
            },
            &[],
        );
        let page_span = PageSpan::new(len, 1 << 21);
        assert!(matches!(
            apply(
                &words,
                DescriptorOp::Coalesce {
                    span: page_span,
                    size: LeafSize::Block2M
                },
                &[]
            ),
            DescriptorOutcome::Applied { .. }
        ));
        if size == LeafSize::Block1G {
            assert!(matches!(
                apply(
                    &words,
                    DescriptorOp::Coalesce {
                        span: PageSpan::new(len, len),
                        size
                    },
                    &[]
                ),
                DescriptorOutcome::Applied { .. }
            ));
        }
        assert_eq!(
            words.load(parent_slot).unwrap() & (ADDRESS | HUGE),
            (len * 2) | PAT_LARGE | HUGE
        );
    }
}
#[test]
fn failed_split_restores_all_512_children_and_parent() {
    for failure in [0, 1, 127, 511, 512, 513] {
        let words = Words::new();
        apply(
            &words,
            map(1 << 21, 1 << 22, 1 << 21, LeafSize::Block2M),
            &[root(0x2000), root(0x3000)],
        );
        let before = words.words.borrow().clone();
        words.fail.set(words.writes.get() + failure);
        assert_eq!(
            apply(
                &words,
                DescriptorOp::Protect {
                    span: PageSpan::new((1 << 21) + PAGE, PAGE),
                    permissions: Permissions {
                        writable: false,
                        executable: false,
                        user: true
                    }
                },
                &[root(0x4000)]
            ),
            DescriptorOutcome::RolledBack(DescriptorRefusal::Contended)
        );
        assert_eq!(*words.words.borrow(), before);
    }
}
#[test]
fn touched_work_scales_with_range_not_unrelated_population() {
    for n in [16, 64, 256] {
        let words = Words::new();
        let op = map(0x200000, 0x400000, n * PAGE, LeafSize::Page);
        let tables = [root(0x2000), root(0x3000), root(0x4000)];
        let plan = plan_descriptor_txn(&words, &txn(op, &tables), root(0x1000)).unwrap();
        assert_eq!(plan.tables_linked, 3);
        assert_eq!(plan.live_stores(), n as usize + 3);
        assert!(plan.words_read <= 3 * 512 + 6 * n as usize + 3);
        // Unrelated populated PML4 branches are never scanned.
        for i in 1..512 {
            words
                .words
                .borrow_mut()
                .insert(0x1000 + i * 8, 0x10000 | PRESENT | WRITE | USER);
        }
        let populated = plan_descriptor_txn(&words, &txn(op, &tables), root(0x1000)).unwrap();
        assert_eq!(populated.words_read, plan.words_read);
        assert_eq!(populated.live_stores(), plan.live_stores());
    }
}
#[test]
fn stale_root_grants_receipt_and_journal_capacity_refuse_without_writes() {
    let words = Words::new();
    let tables = [root(0x2000), root(0x3000), root(0x4000)];
    let mut txn = txn(map(0x4000, 0x800000, PAGE, LeafSize::Page), &tables);
    let mut journal = InlineJournal::new();
    assert_eq!(
        execute_descriptor_txn(&words, &txn, root(0x5000), &mut journal).outcome,
        DescriptorOutcome::Refused(DescriptorRefusal::StaleRoot)
    );
    let mut storage = [JournalEntry::default(); 3];
    let mut small = crate::aarch64::descriptor_txn::SliceJournal::new(&mut storage);
    assert_eq!(
        execute_descriptor_txn(&words, &txn, txn.root, &mut small).outcome,
        DescriptorOutcome::Refused(DescriptorRefusal::JournalCapacity)
    );
    assert_eq!(words.writes.get(), 0);
    let plan = plan_descriptor_txn(&words, &txn, txn.root).unwrap();
    let receipt = apply_descriptor_plan(&words, &plan, &mut journal);
    txn.verify_receipt(&receipt).unwrap();
    txn.op = map(0x4000, 0x900000, PAGE, LeafSize::Page);
    assert!(txn.verify_receipt(&receipt).is_err());
    assert!(matches!(
        rollback_descriptor_plan(&words, &plan),
        DescriptorOutcome::RolledBack(_)
    ));
    assert_eq!(words.load(0x1000).unwrap(), 0);
}
#[test]
fn whole_block_protection_edits_one_terminal_without_split_grants() {
    let words = Words::new();
    let span = PageSpan::new(1 << 30, 1 << 30);
    apply(
        &words,
        map(span.va, 1 << 31, span.len, LeafSize::Block1G),
        &[root(0x2000)],
    );
    let txn = txn(
        DescriptorOp::Protect {
            span,
            permissions: Permissions {
                writable: false,
                executable: false,
                user: true,
            },
        },
        &[],
    );
    let plan = plan_descriptor_txn(&words, &txn, txn.root).unwrap();
    assert_eq!(plan.tables_linked, 0);
    assert_eq!(plan.live_stores(), 1);
    assert!(plan.words_read <= 3);
    let outcome = apply_descriptor_plan(&words, &plan, &mut InlineJournal::new()).outcome;
    assert!(matches!(
        outcome,
        DescriptorOutcome::Applied {
            stores: 1,
            tables_linked: 0
        }
    ));
    assert_eq!(
        translate(
            &words,
            txn.root,
            UserVa::new(span.va + PAGE),
            Access::Write,
            true
        ),
        Err(FaultClass::Protection)
    );
}
#[test]
fn unable_to_restore_a_published_word_is_indeterminate() {
    let words = Words::new();
    let tables = [root(0x2000), root(0x3000), root(0x4000)];
    let txn = txn(map(0x4000, 0x800000, PAGE, LeafSize::Page), &tables);
    let plan = plan_descriptor_txn(&words, &txn, txn.root).unwrap();
    apply_descriptor_plan(&words, &plan, &mut InlineJournal::new());
    words.fail.set(words.writes.get());
    assert_eq!(
        rollback_descriptor_plan(&words, &plan),
        DescriptorOutcome::Indeterminate(DescriptorRefusal::Contended)
    );
}
