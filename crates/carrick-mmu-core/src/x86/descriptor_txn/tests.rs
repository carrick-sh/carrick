#![allow(clippy::unwrap_used)]
use super::*;
use alloc::vec;
use core::num::NonZeroU64;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

#[test]
fn owner_grant_projection_preserves_prepared_neighbors_and_refuses_exhaustion() {
    use crate::aarch64::descriptor_txn::{
        DescriptorOp as WireOp, DescriptorOutcome as WireOutcome, DescriptorTxn as WireTxn,
        TableGrants,
    };
    use crate::aarch64::{GuestLeafPublication, SubstrateGpa};
    use crate::owner_mmu::OwnerGrantMmu;
    use crate::x86::owner_mmu::X86Mmu;
    let grant = |tables: &[SubstrateGpa]| WireTxn {
        id: txn(DescriptorOp::Unmap(PageSpan::new(0x4000, PAGE)), &[]).id,
        root: SubstrateGpa(0x1000),
        op: WireOp::Prepare {
            publication: GuestLeafPublication {
                va: 0x4000,
                ipa: 0x100000,
                len: 3 * PAGE,
                writable: true,
                executable: false,
            },
            resident: PageSpan::new(0x5000, PAGE),
            backing: backing(),
        },
        tables: TableGrants::new(tables).unwrap(),
    };
    let words = Words::new();
    let before = words.words.borrow().clone();
    assert_eq!(
        X86Mmu::execute_grant(&words, 0x1000, &grant(&[])),
        WireOutcome::Refused(DescriptorRefusal::TablesExhausted)
    );
    assert_eq!(*words.words.borrow(), before);
    let tables = [
        SubstrateGpa(0x2000),
        SubstrateGpa(0x3000),
        SubstrateGpa(0x4000),
    ];
    assert_eq!(
        X86Mmu::execute_grant(&words, 0x8000, &grant(&tables)),
        WireOutcome::Refused(DescriptorRefusal::StaleRoot)
    );
    assert_eq!(*words.words.borrow(), before);
    assert!(matches!(
        X86Mmu::execute_grant(&words, 0x1000, &grant(&tables)),
        WireOutcome::Applied(_)
    ));
    for (va, output, resident) in [
        (0x4000, 0x100000, false),
        (0x5000, 0x101000, true),
        (0x6000, 0x102000, false),
    ] {
        let leaf = read_terminal_descriptor(&words, root(0x1000), UserVa::new(va)).unwrap();
        assert_eq!(leaf.0 & ADDRESS, output);
        assert_ne!(leaf.0 & PRIVATE, 0);
        assert_eq!(leaf.0 & PRESENT != 0, resident);
        assert_eq!(leaf.0 & PREPARED != 0, !resident);
    }
    let middle = read_terminal_descriptor(&words, root(0x1000), UserVa::new(0x5000))
        .unwrap()
        .0;
    assert!(matches!(
        apply(
            &words,
            DescriptorOp::Publish {
                span: PageSpan::new(0x6000, PAGE),
                expected: FrameGpa::new(0x102000),
                access: Access::Write
            },
            &[]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    assert_eq!(
        read_terminal_descriptor(&words, root(0x1000), UserVa::new(0x5000))
            .unwrap()
            .0,
        middle
    );
    assert_ne!(
        read_terminal_descriptor(&words, root(0x1000), UserVa::new(0x4000))
            .unwrap()
            .0
            & PREPARED,
        0
    );
}

/// #1338: an owner grant for a shared file window page projects to one
/// resident host `Map` leaf on the window slot: writable as the mapping is,
/// never `PRIVATE` (so it is never retired into a private lease or COW
/// copied), and the projection both the guest and the host settlement use
/// names the exact page.
#[test]
fn owner_grant_projects_a_shared_file_window_page_as_a_host_map_leaf() {
    use crate::aarch64::SubstrateGpa;
    use crate::aarch64::descriptor_txn::{
        AliasAccess, DescriptorOp as WireOp, DescriptorOutcome as WireOutcome,
        DescriptorTxn as WireTxn, TableGrants,
    };
    use crate::owner_mmu::OwnerGrantMmu;
    use crate::x86::owner_mmu::X86Mmu;
    let tables = [
        SubstrateGpa(0x2000),
        SubstrateGpa(0x3000),
        SubstrateGpa(0x4000),
    ];
    let grant = |access| WireTxn {
        id: txn(DescriptorOp::Unmap(PageSpan::new(0x4000, PAGE)), &[]).id,
        root: SubstrateGpa(0x1000),
        op: WireOp::MapAlias {
            access,
            span: crate::aarch64::descriptor_txn::PageSpan::new(0x5000, PAGE),
            target_ipa: SubstrateGpa(0x4000_0000 + 3 * PAGE),
            backing: backing(),
        },
        tables: TableGrants::new(&tables).unwrap(),
    };
    let words = Words::new();
    let before = words.words.borrow().clone();
    // A deferred alias has no user leaf to give a window page.
    assert_eq!(
        X86Mmu::execute_grant(&words, 0x1000, &grant(AliasAccess::Deferred)),
        WireOutcome::Refused(DescriptorRefusal::BadEncoding)
    );
    assert_eq!(*words.words.borrow(), before);
    let writable = grant(AliasAccess::User {
        writable: true,
        executable: false,
    });
    let WireOutcome::Applied(applied) = X86Mmu::execute_grant(&words, 0x1000, &writable) else {
        panic!("window page grant applies");
    };
    assert_eq!(applied.pages, 1);
    // The shared receipt rule (`DescriptorTxn::verify_receipt`): an alias
    // names no resident span, so the host settlement accepts this receipt.
    assert_eq!(applied.resident, PageSpan::EMPTY);
    let leaf = read_terminal_descriptor(&words, root(0x1000), UserVa::new(0x5000))
        .unwrap()
        .0;
    assert_eq!(leaf & ADDRESS, 0x4000_0000 + 3 * PAGE);
    assert_eq!(leaf & PRIVATE, 0);
    assert_ne!(leaf & PRESENT, 0);
    assert_ne!(leaf & WRITE, 0);
    assert_ne!(leaf & NX, 0);
    // The page beside it is untouched.
    assert!(matches!(
        translate_leaf(
            &words,
            root(0x1000),
            UserVa::new(0x6000),
            Access::Read,
            true
        ),
        Err(FaultClass::NotPresent)
    ));
    // A second grant over the live leaf is refused, not stacked.
    assert!(matches!(
        X86Mmu::execute_grant(&words, 0x1000, &writable),
        WireOutcome::Refused(_)
    ));
}

#[test]
fn neutral_prepare_intent_publishes_one_native_page() {
    use carrick_guest_arch::{
        EditBacking, EditIntent, EditOperation, EditOwner, EditPermissions, GuestLen, UserRange,
    };
    let words = Words::new();
    let one = NonZeroU64::MIN;
    // SAFETY: the fixture owns the sole synthetic MM editor and live root.
    let owner = unsafe { EditOwner::issue(root(0x1000), one, one) };
    let range = UserRange::checked(UserVa::new(0x4000), GuestLen::new(8192)).unwrap();
    let resident = UserRange::checked(UserVa::new(0x4000), GuestLen::new(PAGE)).unwrap();
    let grants = [root(0x2000), root(0x3000), root(0x4000)];
    let intent = EditIntent::checked(
        owner,
        range,
        EditOperation::Prepare {
            output: FrameGpa::new(0x8000),
            permissions: EditPermissions {
                readable: true,
                writable: true,
                executable: false,
                user: true,
            },
            resident,
            backing: EditBacking {
                frame_id: one,
                mapping_id: one,
                owner_generation: one,
                inventory_revision: one,
            },
        },
        &grants,
    )
    .unwrap();
    let txn = DescriptorTxn::from_intent(&intent).unwrap();
    let receipt = execute_descriptor_txn(&words, &txn, root(0x1000), &mut InlineJournal::new());
    assert!(matches!(receipt.outcome, DescriptorOutcome::Applied { .. }));
    let live = translate_leaf(
        &words,
        root(0x1000),
        UserVa::new(0x4000),
        Access::Write,
        true,
    )
    .unwrap();
    assert_eq!(live.output, FrameGpa::new(0x8000));
    assert!(matches!(
        translate_leaf(
            &words,
            root(0x1000),
            UserVa::new(0x5000),
            Access::Read,
            true
        ),
        Err(FaultClass::NotPresent)
    ));
    assert!(words.stores.get() > 0);
}

#[test]
fn retired_x86_leaf_retains_backing_and_repoints_without_publication() {
    use carrick_guest_arch::{EditIntent, EditOperation, EditOwner, GuestLen, UserRange};
    let words = Words::new();
    let span = PageSpan::new(0x4000, PAGE);
    assert!(matches!(
        apply(
            &words,
            private_prepare(
                span,
                0x800000,
                Permissions {
                    writable: true,
                    executable: false,
                    user: true
                }
            ),
            &[root(0x2000), root(0x3000), root(0x4000)]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    // SAFETY: the fixture holds the sole editor for this synthetic root.
    let owner = unsafe { EditOwner::issue(root(0x1000), NonZeroU64::MIN, NonZeroU64::MIN) };
    let range = UserRange::checked(UserVa::new(span.va), GuestLen::new(span.len)).unwrap();
    let intent = EditIntent::checked(owner, range, EditOperation::Unmap, &[]).unwrap();
    let retirement = DescriptorTxn::from_intent(&intent).unwrap();
    assert!(matches!(retirement.op, DescriptorOp::Retire(_)));
    assert!(matches!(
        execute_descriptor_txn(&words, &retirement, root(0x1000), &mut InlineJournal::new())
            .outcome,
        DescriptorOutcome::Applied { .. }
    ));
    let (retired, _) =
        read_terminal_descriptor(&words, root(0x1000), UserVa::new(span.va)).unwrap();
    assert_eq!(retired & ADDRESS, 0x800000);
    assert_eq!(retired & (PRESENT | PREPARED), 0);
    assert_eq!(
        translate(
            &words,
            root(0x1000),
            UserVa::new(span.va),
            Access::Read,
            true
        ),
        Err(FaultClass::NotPresent)
    );
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
    let (repointed, _) =
        read_terminal_descriptor(&words, root(0x1000), UserVa::new(span.va)).unwrap();
    assert_eq!(repointed & ADDRESS, 0x900000);
    assert_eq!(repointed & (PRESENT | PREPARED), 0);
}

struct Words {
    words: RefCell<BTreeMap<u64, u64>>,
    reads: Cell<usize>,
    stores: Cell<usize>,
    writes: Cell<usize>,
    fail: Cell<usize>,
}
impl Words {
    fn new() -> Self {
        Self {
            words: RefCell::new((0x1000..0x20000).step_by(8).map(|pa| (pa, 0)).collect()),
            reads: Cell::new(0),
            stores: Cell::new(0),
            writes: Cell::new(0),
            fail: Cell::new(usize::MAX),
        }
    }
}
impl LiveDescriptorWords for Words {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        self.reads.set(self.reads.get() + 1);
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
        self.stores.set(self.stores.get() + 1);
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
        self.stores.set(self.stores.get() + 1);
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

fn private_prepare(span: PageSpan, output: u64, permissions: Permissions) -> DescriptorOp {
    DescriptorOp::Prepare {
        span,
        output: FrameGpa::new(output),
        permissions,
        resident: span,
        backing: backing(),
    }
}

#[test]
fn guest_protect_refuses_host_map_leaf() {
    let words = Words::new();
    let span = PageSpan::new(0x4000, PAGE);
    assert!(matches!(
        apply(
            &words,
            map(span.va, 0x800000, PAGE, LeafSize::Page),
            &[root(0x2000), root(0x3000), root(0x4000)]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    let before = words.words.borrow().clone();
    assert_eq!(
        apply(
            &words,
            DescriptorOp::Protect {
                span,
                permissions: Permissions {
                    writable: false,
                    executable: false,
                    user: true
                },
                exec: ExecAuthority::Leaf,
            },
            &[]
        ),
        DescriptorOutcome::Refused(DescriptorRefusal::NotPrivateAnonymous)
    );
    assert_eq!(*words.words.borrow(), before);
}

#[test]
fn guest_protect_refuses_write_and_execute_widening_past_grant() {
    let words = Words::new();
    let span = PageSpan::new(0x4000, PAGE);
    let readonly = Permissions {
        writable: false,
        executable: false,
        user: true,
    };
    assert!(matches!(
        apply(
            &words,
            private_prepare(span, 0x800000, readonly),
            &[root(0x2000), root(0x3000), root(0x4000)]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    let before = words.words.borrow().clone();
    for permissions in [
        Permissions {
            writable: true,
            ..readonly
        },
        Permissions {
            executable: true,
            ..readonly
        },
    ] {
        assert_eq!(
            apply(
                &words,
                DescriptorOp::Protect {
                    span,
                    permissions,
                    exec: ExecAuthority::Leaf
                },
                &[]
            ),
            DescriptorOutcome::Refused(DescriptorRefusal::PermissionWidening)
        );
        assert_eq!(*words.words.borrow(), before);
    }
}

/// #2874: a private page granted read-write may become executable when the
/// mapping's ceiling allows execute (V8's code range), and keeps `MAY_EXEC`
/// for a later grant; write stays a leaf fact the ceiling cannot widen.
#[test]
fn guest_protect_grants_execute_within_the_mapping_ceiling() {
    let words = Words::new();
    let span = PageSpan::new(0x4000, PAGE);
    let read_write = Permissions {
        writable: true,
        executable: false,
        user: true,
    };
    let read_only = Permissions {
        writable: false,
        ..read_write
    };
    assert!(matches!(
        apply(
            &words,
            private_prepare(span, 0x800000, read_only),
            &[root(0x2000), root(0x3000), root(0x4000)]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    let before = words.words.borrow().clone();
    assert_eq!(
        apply(
            &words,
            DescriptorOp::Protect {
                span,
                permissions: read_write,
                exec: ExecAuthority::Mapping,
            },
            &[]
        ),
        DescriptorOutcome::Refused(DescriptorRefusal::PermissionWidening)
    );
    assert_eq!(*words.words.borrow(), before);
    let read_exec = Permissions {
        executable: true,
        ..read_only
    };
    assert!(matches!(
        apply(
            &words,
            DescriptorOp::Protect {
                span,
                permissions: read_exec,
                exec: ExecAuthority::Mapping,
            },
            &[]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    let (protected, _) =
        read_terminal_descriptor(&words, root(0x1000), UserVa::new(span.va)).unwrap();
    assert_eq!(protected & (NX | WRITE), 0);
    assert_ne!(protected & MAY_EXEC, 0);
    for permissions in [read_only, read_exec] {
        assert!(matches!(
            apply(
                &words,
                DescriptorOp::Protect {
                    span,
                    permissions,
                    exec: ExecAuthority::Leaf,
                },
                &[]
            ),
            DescriptorOutcome::Applied { .. }
        ));
    }
}

#[test]
fn guest_protect_can_restore_write_within_private_grant_ceiling() {
    let words = Words::new();
    let span = PageSpan::new(0x4000, PAGE);
    let writable = Permissions {
        writable: true,
        executable: false,
        user: true,
    };
    assert!(matches!(
        apply(
            &words,
            private_prepare(span, 0x800000, writable),
            &[root(0x2000), root(0x3000), root(0x4000)]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    let readonly = Permissions {
        writable: false,
        ..writable
    };
    assert!(matches!(
        apply(
            &words,
            DescriptorOp::Protect {
                span,
                permissions: readonly,
                exec: ExecAuthority::Leaf,
            },
            &[]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    let (protected, _) =
        read_terminal_descriptor(&words, root(0x1000), UserVa::new(span.va)).unwrap();
    assert_eq!(protected & WRITE, 0);
    assert_ne!(protected & MAY_WRITE, 0);
    assert!(matches!(
        apply(
            &words,
            DescriptorOp::Protect {
                span,
                permissions: writable,
                exec: ExecAuthority::Leaf,
            },
            &[]
        ),
        DescriptorOutcome::Applied { .. }
    ));
}

#[test]
fn guest_retire_refuses_host_map_leaf() {
    let words = Words::new();
    let span = PageSpan::new(0x4000, PAGE);
    assert!(matches!(
        apply(
            &words,
            map(span.va, 0x800000, PAGE, LeafSize::Page),
            &[root(0x2000), root(0x3000), root(0x4000)]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    let before = words.words.borrow().clone();
    assert_eq!(
        apply(&words, DescriptorOp::Retire(span), &[]),
        DescriptorOutcome::Refused(DescriptorRefusal::NotPrivateAnonymous)
    );
    assert_eq!(*words.words.borrow(), before);
}

/// #1338: the unlink a shared file window munmap takes clears a host-mapped
/// leaf and refuses a private one, which only ever retires.
#[test]
fn guest_unlink_clears_host_map_leaf_and_refuses_private_leaf() {
    let words = Words::new();
    let tables = [root(0x2000), root(0x3000), root(0x4000)];
    let host = PageSpan::new(0x4000, PAGE);
    let private = PageSpan::new(0x5000, PAGE);
    assert!(matches!(
        apply(
            &words,
            map(host.va, 0x800000, PAGE, LeafSize::Page),
            &tables
        ),
        DescriptorOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply(
            &words,
            private_prepare(
                private,
                0x900000,
                Permissions {
                    writable: true,
                    executable: false,
                    user: true,
                },
            ),
            &[]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    let before = words.words.borrow().clone();
    assert_eq!(
        apply(&words, DescriptorOp::UnmapWindow(private), &[]),
        DescriptorOutcome::Refused(DescriptorRefusal::WrongBacking)
    );
    assert_eq!(*words.words.borrow(), before);
    assert!(matches!(
        apply(&words, DescriptorOp::UnmapWindow(host), &[]),
        DescriptorOutcome::Applied { .. }
    ));
    assert_eq!(
        read_terminal_descriptor(&words, root(0x1000), UserVa::new(host.va))
            .unwrap()
            .0,
        0
    );
    assert_ne!(
        read_terminal_descriptor(&words, root(0x1000), UserVa::new(private.va))
            .unwrap()
            .0,
        0
    );
}

/// #1338: an mprotect over shared file window pages re-permissions the
/// host-mapped leaves in place (read-only, then writable again), skips a
/// hole, and refuses a private leaf, which takes `Protect`.
#[test]
fn window_protect_edits_host_map_leaves_and_refuses_private_leaf() {
    let words = Words::new();
    let tables = [root(0x2000), root(0x3000), root(0x4000)];
    let host = PageSpan::new(0x4000, PAGE);
    let private = PageSpan::new(0x6000, PAGE);
    assert!(matches!(
        apply(
            &words,
            map(host.va, 0x800000, PAGE, LeafSize::Page),
            &tables
        ),
        DescriptorOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply(
            &words,
            private_prepare(
                private,
                0x900000,
                Permissions {
                    writable: true,
                    executable: false,
                    user: true,
                },
            ),
            &[]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    let protect = |span, writable| DescriptorOp::ProtectWindow {
        span,
        permissions: Permissions {
            writable,
            executable: false,
            user: true,
        },
    };
    let leaf = |va| {
        read_terminal_descriptor(&words, root(0x1000), UserVa::new(va))
            .unwrap()
            .0
    };
    let mapped = leaf(host.va);
    // The window page and the hole after it.
    assert!(matches!(
        apply(
            &words,
            protect(PageSpan::new(host.va, 2 * PAGE), false),
            &[]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    assert_eq!(leaf(host.va), mapped & !WRITE);
    assert_eq!(leaf(host.va + PAGE), 0);
    assert!(matches!(
        apply(&words, protect(host, true), &[]),
        DescriptorOutcome::Applied { .. }
    ));
    assert_eq!(leaf(host.va), mapped);
    let before = words.words.borrow().clone();
    assert_eq!(
        apply(&words, protect(private, false), &[]),
        DescriptorOutcome::Refused(DescriptorRefusal::WrongBacking)
    );
    assert_eq!(*words.words.borrow(), before);
}

#[test]
fn cow_classifier_names_only_the_faulting_armed_user_page() {
    let words = Words::new();
    assert!(matches!(
        apply(
            &words,
            map(0x4000, 0x8000, PAGE, LeafSize::Page),
            &[root(0x2000), root(0x3000), root(0x4000)]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply(
            &words,
            DescriptorOp::ArmCow(PageSpan::new(0x4000, PAGE)),
            &[]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    let run = classify_guest_cow_write(&words, root(0x1000), UserVa::new(0x4008), false)
        .expect("armed user write");
    assert_eq!(run.va, 0x4000);
    assert_eq!(run.old_ipa, FrameGpa::new(0x8000));
    assert_eq!(run.len, PAGE);
    assert_eq!(run.compound_offset, 0);
    assert_eq!(
        classify_guest_cow_write(&words, root(0x1000), UserVa::new(0x5000), false),
        Err(CowClass::Unmapped)
    );
}

#[test]
fn cow_classifiers_agree_on_non_writable_ancestor_refusal() {
    use crate::owner_mmu::{OwnerMmu, OwnerMmuRefusal};
    use crate::x86::owner_mmu::X86Mmu;

    for ancestor_pa in [0x1000, 0x2000, 0x3000] {
        let words = Words::new();
        assert!(matches!(
            apply(
                &words,
                map(0x4000, 0x8000, PAGE, LeafSize::Page),
                &[root(0x2000), root(0x3000), root(0x4000)]
            ),
            DescriptorOutcome::Applied { .. }
        ));
        assert!(matches!(
            apply(
                &words,
                DescriptorOp::ArmCow(PageSpan::new(0x4000, PAGE)),
                &[]
            ),
            DescriptorOutcome::Applied { .. }
        ));

        // Clear WRITE on the ancestor entry so the ancestor table is non-writable.
        let original = words.words.borrow()[&ancestor_pa];
        words
            .words
            .borrow_mut()
            .insert(ancestor_pa, original & !WRITE);

        // X86Mmu::classify_cow already refuses because !leaf.ancestors_writable.
        assert_eq!(
            X86Mmu::classify_cow(&words, root(0x1000), UserVa::new(0x4008), false),
            Err(OwnerMmuRefusal::Protection),
            "X86Mmu::classify_cow must refuse non-writable ancestor at pa {ancestor_pa:#x}"
        );

        // classify_guest_cow_write must also refuse when an ancestor is non-writable.
        assert_eq!(
            classify_guest_cow_write(&words, root(0x1000), UserVa::new(0x4008), false),
            Err(CowClass::AncestorNotWritable),
            "classify_guest_cow_write must refuse non-writable ancestor at pa {ancestor_pa:#x}"
        );
    }
}

#[test]
fn already_writable_large_leaf_recognized_without_cow() {
    use crate::owner_mmu::OwnerMmu;
    use crate::x86::owner_mmu::X86Mmu;

    for size in [LeafSize::Block2M, LeafSize::Block1G] {
        let (words, va, _, _) = raw_translation(size);

        // Witness (a): An already-writable 2 MiB or 1 GiB leaf needs no COW work.
        // X86Mmu::classify_cow succeeds (Ok(())), and classify_guest_cow_write
        // returns Err(CowClass::AlreadyWritable).
        assert_eq!(
            X86Mmu::classify_cow(&words, root(0x1000), UserVa::new(va + 0x1000), false),
            Ok(())
        );
        assert_eq!(
            classify_guest_cow_write(&words, root(0x1000), UserVa::new(va + 0x1000), false),
            Err(CowClass::AlreadyWritable)
        );
    }
}

#[test]
fn non_writable_ancestor_large_leaf_is_refused() {
    use crate::owner_mmu::{OwnerMmu, OwnerMmuRefusal};
    use crate::x86::owner_mmu::X86Mmu;

    for size in [LeafSize::Block2M, LeafSize::Block1G] {
        let (words, va, _, path) = raw_translation(size);

        // Clear WRITE on the PML4 ancestor entry.
        let ancestor_pa = path[0];
        let original = words.words.borrow()[&ancestor_pa];
        words
            .words
            .borrow_mut()
            .insert(ancestor_pa, original & !WRITE);

        // Witness (b): Both classifiers refuse a large leaf when an ancestor is non-writable.
        assert_eq!(
            X86Mmu::classify_cow(&words, root(0x1000), UserVa::new(va + 0x1000), false),
            Err(OwnerMmuRefusal::Protection)
        );
        assert_eq!(
            classify_guest_cow_write(&words, root(0x1000), UserVa::new(va + 0x1000), false),
            Err(CowClass::AncestorNotWritable)
        );
    }
}

#[test]
fn non_user_intermediate_entry_through_owner_classify_cow_returns_protection() {
    use crate::owner_mmu::{OwnerMmu, OwnerMmuRefusal};
    use crate::x86::owner_mmu::X86Mmu;

    let words = Words::new();
    assert!(matches!(
        apply(
            &words,
            map(0x4000, 0x8000, PAGE, LeafSize::Page),
            &[root(0x2000), root(0x3000), root(0x4000)]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply(
            &words,
            DescriptorOp::ArmCow(PageSpan::new(0x4000, PAGE)),
            &[]
        ),
        DescriptorOutcome::Applied { .. }
    ));

    // Clear USER on intermediate PDPT entry at 0x2000.
    let orig = words.words.borrow()[&0x2000];
    words.words.borrow_mut().insert(0x2000, orig & !USER);

    // Intermediate entry without USER causes FaultClass::Protection, which
    // must map to CowClass::Unmapped and OwnerMmuRefusal::Protection (not Unreachable).
    assert_eq!(
        classify_guest_cow_write(&words, root(0x1000), UserVa::new(0x4008), false),
        Err(CowClass::Unmapped)
    );
    assert_eq!(
        X86Mmu::classify_cow(&words, root(0x1000), UserVa::new(0x4008), false),
        Err(OwnerMmuRefusal::Protection)
    );
}

#[test]
fn writable_4k_leaf_under_non_writable_ancestor_refused_instead_of_already_writable() {
    use crate::owner_mmu::{OwnerMmu, OwnerMmuRefusal};
    use crate::x86::owner_mmu::X86Mmu;

    for ancestor_pa in [0x1000, 0x2000, 0x3000] {
        let words = Words::new();
        // Leaf is writable (map creates WRITE without ArmCow).
        assert!(matches!(
            apply(
                &words,
                map(0x4000, 0x8000, PAGE, LeafSize::Page),
                &[root(0x2000), root(0x3000), root(0x4000)]
            ),
            DescriptorOutcome::Applied { .. }
        ));

        // Clear WRITE on the ancestor entry.
        let original = words.words.borrow()[&ancestor_pa];
        words
            .words
            .borrow_mut()
            .insert(ancestor_pa, original & !WRITE);

        // Prior to the unified ancestor rule, classify_guest_cow_write checked leaf
        // WRITE first and returned AlreadyWritable, causing an infinite fault/return livelock.
        // With ancestor checking first, it returns AncestorNotWritable.
        assert_eq!(
            classify_guest_cow_write(&words, root(0x1000), UserVa::new(0x4008), false),
            Err(CowClass::AncestorNotWritable),
            "classify_guest_cow_write must refuse non-writable ancestor at pa {ancestor_pa:#x}"
        );
        assert_eq!(
            X86Mmu::classify_cow(&words, root(0x1000), UserVa::new(0x4008), false),
            Err(OwnerMmuRefusal::Protection),
            "X86Mmu::classify_cow must refuse non-writable ancestor at pa {ancestor_pa:#x}"
        );
    }
}

#[test]
fn lower_half_supervisor_and_upper_half_user_leaves_are_refused_before_stores() {
    for (va, user) in [(0x4000, false), (0xffff_8000_0000_4000, true)] {
        let words = Words::new();
        let op = DescriptorOp::Map {
            span: PageSpan::new(va, PAGE),
            output: FrameGpa::new(0x800000),
            permissions: Permissions {
                writable: true,
                executable: false,
                user,
            },
            size: LeafSize::Page,
            resident: true,
            backing: backing(),
        };
        assert_eq!(
            apply(&words, op, &[root(0x2000), root(0x3000), root(0x4000)]),
            DescriptorOutcome::Refused(DescriptorRefusal::PermissionDenied)
        );
        assert_eq!(words.stores.get(), 0);
    }
}
#[test]
fn lower_half_user_and_upper_half_supervisor_leaves_are_accepted() {
    for (va, user) in [(0x4000, true), (0xffff_8000_0000_4000, false)] {
        let words = Words::new();
        let op = DescriptorOp::Map {
            span: PageSpan::new(va, PAGE),
            output: FrameGpa::new(0x800000),
            permissions: Permissions {
                writable: true,
                executable: false,
                user,
            },
            size: LeafSize::Page,
            resident: true,
            backing: backing(),
        };
        assert!(matches!(
            apply(&words, op, &[root(0x2000), root(0x3000), root(0x4000)]),
            DescriptorOutcome::Applied { .. }
        ));
        let leaf_index = (va >> 12) & 511;
        assert_eq!(
            words.load(0x4000 + leaf_index * 8).unwrap() & USER != 0,
            user
        );
    }
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

// Independent descriptor words: no transaction planner or VMA permission model.
// Bind kernel.el1.stage1-publication and kernel.mm.address-space-occupancy only
// for hardware interpretation (Intel SDM Vol. 3A, four-level paging).
fn raw_translation(size: LeafSize) -> (Words, u64, u64, Vec<u64>) {
    let (bytes, terminal, output) = match size {
        LeafSize::Page => (4096, 3, 0x1234_5000),
        LeafSize::Block2M => (1 << 21, 2, 0x4560_0000),
        LeafSize::Block1G => (1 << 30, 1, 0x1_c000_0000),
    };
    let va = ((3 << 39) | (5 << 30) | (7 << 21) | (11 << 12)) & !(bytes - 1);
    let words = Words::new();
    let tables = [0x1000, 0x2000, 0x3000, 0x4000];
    let mut path = Vec::new();
    for level in 0..=terminal {
        let pa = tables[level] + ((va >> (39 - level * 9)) & 511) * 8;
        let entry = if level == terminal {
            output | PRESENT | WRITE | USER | if terminal < 3 { HUGE } else { 0 }
        } else {
            tables[level + 1] | PRESENT | WRITE | USER
        };
        words.words.borrow_mut().insert(pa, entry);
        path.push(pa);
    }
    (words, va, output, path)
}

fn ancestor_permission_matrix(
    clear: u64,
    set: u64,
    denied_access: Option<Access>,
    fault: FaultClass,
) {
    let mut mismatches = Vec::new();
    for size in [LeafSize::Page, LeafSize::Block2M, LeafSize::Block1G] {
        let (words, va, output, path) = raw_translation(size);
        for (level, &pa) in path[..path.len() - 1].iter().enumerate() {
            let original = words.words.borrow()[&pa];
            words
                .words
                .borrow_mut()
                .insert(pa, (original & !clear) | set);
            for user in [false, true] {
                for access in [Access::Read, Access::Write, Access::Execute] {
                    let denied = denied_access.map_or(user, |denied| access == denied);
                    let expected = if denied {
                        Err(fault)
                    } else {
                        Ok(FrameGpa::new(output + 19))
                    };
                    let actual =
                        translate(&words, root(0x1000), UserVa::new(va + 19), access, user);
                    if actual != expected {
                        mismatches.push((size, level, access, user, actual, expected));
                    }
                }
            }
            words.words.borrow_mut().insert(pa, original);
        }
    }
    // Collect all rows so the injected terminal-only defect witnesses every
    // ancestor, rather than stopping at the first PML4 denial.
    assert!(
        mismatches.is_empty(),
        "ancestor permission mismatches: {mismatches:?}"
    );
}

#[test]
fn supervisor_ancestors_deny_user_access_beneath_permissive_terminals() {
    ancestor_permission_matrix(USER, 0, None, FaultClass::Protection);
}

#[test]
fn readonly_ancestors_deny_writes_beneath_permissive_terminals() {
    ancestor_permission_matrix(WRITE, 0, Some(Access::Write), FaultClass::Protection);
}

#[test]
fn nx_ancestors_deny_execution_beneath_permissive_terminals() {
    ancestor_permission_matrix(0, NX, Some(Access::Execute), FaultClass::Nx);
}

#[test]
fn nonidentity_terminal_offsets_cover_4k_2m_and_1g() {
    let mut mismatches = Vec::new();
    for (size, bytes) in [
        (LeafSize::Page, 4096),
        (LeafSize::Block2M, 1 << 21),
        (LeafSize::Block1G, 1 << 30),
    ] {
        let (words, va, output, _) = raw_translation(size);
        for offset in [0, 19, bytes / 2 + 37, bytes - 1] {
            for access in [Access::Read, Access::Write, Access::Execute] {
                let expected = Ok(FrameGpa::new(output + offset));
                let actual =
                    translate(&words, root(0x1000), UserVa::new(va + offset), access, true);
                if actual != expected {
                    mismatches.push((size, offset, access, actual, expected));
                }
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "terminal offset mismatches: {mismatches:?}"
    );
}

#[test]
fn translation_load_budget_is_independent_of_unrelated_branches() {
    let mut mismatches = Vec::new();
    for branches in [16, 64, 256] {
        for (size, depth) in [
            (LeafSize::Page, 4),
            (LeafSize::Block2M, 3),
            (LeafSize::Block1G, 2),
        ] {
            let (words, va, output, _) = raw_translation(size);
            // Distinct populated, unrelated PML4 branches, each with a PDPT
            // and a 1 GiB terminal. None aliases the queried PML4 index 3.
            for i in 0..branches {
                let table = 0x20_0000 + i * PAGE;
                let mut entries = words.words.borrow_mut();
                entries.insert(0x1000 + (32 + i) * 8, table | PRESENT | WRITE | USER);
                entries.insert(table, 0x2_0000_0000 | PRESENT | WRITE | USER | HUGE);
            }
            for access in [Access::Read, Access::Write, Access::Execute] {
                words.reads.set(0);
                assert_eq!(
                    translate(&words, root(0x1000), UserVa::new(va + 19), access, true),
                    Ok(FrameGpa::new(output + 19))
                );
                let loads = words.reads.get();
                if loads != depth || loads > 4 {
                    mismatches.push((branches, size, access, loads, depth));
                }
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "translation load budget exceeded: {mismatches:?}"
    );
}

#[test]
fn translation_performs_zero_stores_even_when_ancestors_deny_access() {
    let mut mismatches = Vec::new();
    for branches in [16, 64, 256] {
        for size in [LeafSize::Page, LeafSize::Block2M, LeafSize::Block1G] {
            let (words, va, _, path) = raw_translation(size);
            for i in 0..branches {
                words.words.borrow_mut().insert(
                    0x1000 + (32 + i) * 8,
                    (0x20_0000 + i * PAGE) | PRESENT | WRITE | USER,
                );
            }
            for restriction in [0, USER, WRITE, NX] {
                let pa = path[0];
                let original = words.words.borrow()[&pa];
                let entry = if restriction == NX {
                    original | NX
                } else {
                    original & !restriction
                };
                words.words.borrow_mut().insert(pa, entry);
                let before = words.words.borrow().clone();
                words.stores.set(0);
                for access in [Access::Read, Access::Write, Access::Execute] {
                    let _ = translate(&words, root(0x1000), UserVa::new(va + 19), access, true);
                }
                if words.stores.get() != 0 || *words.words.borrow() != before {
                    mismatches.push((branches, size, restriction, words.stores.get()));
                }
                words.words.borrow_mut().insert(pa, original);
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "translation performed stores: {mismatches:?}"
    );
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
    let op = DescriptorOp::Prepare {
        span: PageSpan::new(span.va, 2 * PAGE),
        output: FrameGpa::new(0x800000),
        permissions: Permissions {
            writable: true,
            executable: true,
            user: true,
        },
        resident: PageSpan::new(span.va + PAGE, PAGE),
        backing: backing(),
    };
    assert!(matches!(
        apply(&words, op, &[root(0x2000), root(0x3000), root(0x4000)]),
        DescriptorOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply(
            &words,
            DescriptorOp::Protect {
                span,
                permissions: Permissions {
                    writable: true,
                    executable: false,
                    user: true
                },
                exec: ExecAuthority::Leaf,
            },
            &[]
        ),
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
                expected: FrameGpa::new(0x800000),
                access: Access::Read,
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
            exec: ExecAuthority::Leaf,
        },
        &[],
    );
    assert_eq!(walk(Access::Write), Err(FaultClass::Protection));
    assert_eq!(walk(Access::Execute), Ok(FrameGpa::new(0x900000 + 19)));
}

#[test]
fn prepared_readonly_leaf_refuses_write_publication_without_a_store() {
    let words = Words::new();
    let span = PageSpan::new(0x4000, PAGE);
    let op = DescriptorOp::Map {
        span,
        output: FrameGpa::new(0x800000),
        permissions: Permissions {
            writable: false,
            executable: false,
            user: true,
        },
        size: LeafSize::Page,
        resident: false,
        backing: backing(),
    };
    assert!(matches!(
        apply(&words, op, &[root(0x2000), root(0x3000), root(0x4000)]),
        DescriptorOutcome::Applied { .. }
    ));
    let before = words.words.borrow().clone();
    assert_eq!(
        apply(
            &words,
            DescriptorOp::Publish {
                span,
                expected: FrameGpa::new(0x800000),
                access: Access::Write,
            },
            &[]
        ),
        DescriptorOutcome::Refused(DescriptorRefusal::PermissionDenied),
    );
    assert_eq!(*words.words.borrow(), before);
    assert!(matches!(
        apply(
            &words,
            DescriptorOp::Publish {
                span,
                expected: FrameGpa::new(0x800000),
                access: Access::Read,
            },
            &[]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    let resident = |access| {
        resident_satisfies_publication(
            &words,
            root(0x1000),
            UserVa::new(span.va),
            FrameGpa::new(0x800000),
            access,
        )
    };
    assert!(resident(Access::Read));
    assert!(!resident(Access::Write));
}
/// A fork arms a not-yet-present writable leaf for COW. The child's first
/// write publishes it resident and still COW-armed, so the retried store
/// takes the COW copy, as ARM's deferred fork COW does (#2226).
#[test]
fn fork_armed_prepared_leaf_publishes_for_write_and_stays_cow_armed() {
    let words = Words::new();
    let span = PageSpan::new(0x4000, PAGE);
    let op = DescriptorOp::Map {
        span,
        output: FrameGpa::new(0x800000),
        permissions: Permissions {
            writable: true,
            executable: false,
            user: true,
        },
        size: LeafSize::Page,
        resident: false,
        backing: backing(),
    };
    assert!(matches!(
        apply(&words, op, &[root(0x2000), root(0x3000), root(0x4000)]),
        DescriptorOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply(&words, DescriptorOp::ArmCow(span), &[]),
        DescriptorOutcome::Applied { .. }
    ));
    assert!(matches!(
        apply(
            &words,
            DescriptorOp::Publish {
                span,
                expected: FrameGpa::new(0x800000),
                access: Access::Write,
            },
            &[]
        ),
        DescriptorOutcome::Applied { .. }
    ));
    let leaf = read_terminal_descriptor(&words, root(0x1000), UserVa::new(span.va))
        .unwrap()
        .0;
    assert_eq!(leaf & (PRESENT | PREPARED | WRITE | COW), PRESENT | COW);
    // A second CPU's racing write fault finds the leaf already resident:
    // its publication is satisfied and its retry takes the COW copy.
    assert_eq!(
        apply(
            &words,
            DescriptorOp::Publish {
                span,
                expected: FrameGpa::new(0x800000),
                access: Access::Write,
            },
            &[]
        ),
        DescriptorOutcome::Refused(DescriptorRefusal::NotPrepared),
    );
    assert!(resident_satisfies_publication(
        &words,
        root(0x1000),
        UserVa::new(span.va),
        FrameGpa::new(0x800000),
        Access::Write,
    ));
    let walk = |access| translate(&words, root(0x1000), UserVa::new(span.va), access, true);
    assert_eq!(walk(Access::Read), Ok(FrameGpa::new(0x800000)));
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
    assert_eq!(walk(Access::Write), Ok(FrameGpa::new(0x900000)));
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
        // Model an owner-granted huge leaf while retaining the Map topology fixture.
        *words.words.borrow_mut().get_mut(&parent_slot).unwrap() |= PAT_LARGE | PRIVATE;
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
            apply(
                &words,
                DescriptorOp::Protect {
                    span,
                    permissions,
                    exec: ExecAuthority::Leaf
                },
                &grants
            ),
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
                exec: ExecAuthority::Leaf,
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
        // The split fixture starts from an owner-granted huge terminal.
        *words.words.borrow_mut().get_mut(&0x3008).unwrap() |= PRIVATE;
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
                    },
                    exec: ExecAuthority::Leaf,
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
    let diagnostic = Cell::new(None);
    let observe = |event| diagnostic.set(Some(event));
    let observed = crate::live_descriptor_words::ObservedDescriptorWords {
        words: &words,
        observe: Some(&observe),
    };
    let mut storage = [JournalEntry::default(); 3];
    let mut small = crate::aarch64::descriptor_txn::SliceJournal::new(&mut storage);
    assert_eq!(
        execute_descriptor_txn(&observed, &txn, txn.root, &mut small).outcome,
        DescriptorOutcome::Refused(DescriptorRefusal::JournalCapacity)
    );
    assert_eq!(
        diagnostic.get(),
        Some(DescriptorDiagnostic::PlanRefused {
            site: DescriptorPlanRefusalSite::JournalReserve,
            reason: DescriptorRefusal::JournalCapacity,
            op_kind: 1,
            live_stores: 4,
            table_grants: 3,
        })
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
    *words.words.borrow_mut().get_mut(&0x2008).unwrap() |= PRIVATE;
    let txn = txn(
        DescriptorOp::Protect {
            span,
            permissions: Permissions {
                writable: false,
                executable: false,
                user: true,
            },
            exec: ExecAuthority::Leaf,
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

#[test]
fn hardware_walk_ignores_nonleaf_bits_8_to_11_and_leaf_bits_52_to_62_and_sets_ad() {
    let (words, va, output, path) = raw_translation(LeafSize::Page);
    let mut map = words.words.borrow_mut();
    for (pa, bit) in [
        (path[0], PREPARED),
        (path[1], COW),
        (path[2], MAY_WRITE),
        (path[3], 1u64 << 55),
    ] {
        let prev = map[&pa];
        map.insert(pa, prev | bit);
    }
    drop(map);

    let u_va = UserVa::new(va + 8);
    assert_eq!(
        translate_leaf(&words, root(0x1000), u_va, Access::Read, true),
        Err(FaultClass::Reserved)
    );

    words.reads.set(0);
    let cfg = HardwareWalkConfig::new();
    let r = translate_leaf_hardware(&words, root(0x1000), u_va, Access::Read, true, &cfg).unwrap();
    assert_eq!(
        (words.reads.get(), r.output),
        (4, FrameGpa::new(output + 8))
    );
    assert!(r.effective_user && r.effective_writable);
    assert_eq!(
        r.descriptor & ((1u64 << 55) | ACCESSED | DIRTY),
        (1u64 << 55) | ACCESSED
    );
    for &pa in &path {
        assert_ne!(words.words.borrow()[&pa] & ACCESSED, 0);
    }
    assert_eq!(words.words.borrow()[&path[3]] & DIRTY, 0);

    words.reads.set(0);
    words.stores.set(0);
    let w = translate_leaf_hardware(&words, root(0x1000), u_va, Access::Write, true, &cfg).unwrap();
    assert_eq!((words.reads.get(), words.stores.get()), (4, 1));
    assert_eq!(w.descriptor & (ACCESSED | DIRTY), ACCESSED | DIRTY);
    assert_ne!(words.words.borrow()[&path[3]] & DIRTY, 0);
}

#[test]
fn hardware_walk_enforces_cr0_wp_cr4_smep_cr4_smap_and_nxe() {
    let (words, va, output, path) = raw_translation(LeafSize::Page);
    let leaf_pa = path[3];
    let base_leaf = words.words.borrow()[&leaf_pa];
    words.words.borrow_mut().insert(leaf_pa, base_leaf & !WRITE);
    let hw = |acc, c: &HardwareWalkConfig| {
        translate_leaf_hardware(&words, root(0x1000), UserVa::new(va), acc, false, c)
    };

    let mut cfg = HardwareWalkConfig::new();
    cfg.cr4_smap = false;
    assert_eq!(hw(Access::Write, &cfg), Err(HardwareFaultClass::Protection));
    cfg.cr0_wp = false;
    let wp0_leaf = hw(Access::Write, &cfg).unwrap();
    assert_eq!(
        (wp0_leaf.output, wp0_leaf.effective_writable),
        (FrameGpa::new(output), false)
    );
    assert_ne!(words.words.borrow()[&leaf_pa] & (ACCESSED | DIRTY), 0);

    cfg.cr0_wp = true;
    cfg.cr4_smep = true;
    assert_eq!(hw(Access::Execute, &cfg), Err(HardwareFaultClass::Smep));
    cfg.cr4_smep = false;
    assert!(hw(Access::Execute, &cfg).is_ok());

    cfg.cr4_smap = true;
    cfg.rflags_ac = false;
    assert_eq!(hw(Access::Read, &cfg), Err(HardwareFaultClass::Smap));
    cfg.cr4_smap = false;
    assert!(hw(Access::Read, &cfg).is_ok());
}

// #2480 N1: the Stage1Walker facade is exactly translate_leaf_hardware on the
// same descriptor words (same result, same loads, same A/D writes), with the
// descriptor refusal split out of the guest fault classes.
#[test]
fn hardware_walker_is_translate_leaf_hardware_with_refusal_split() {
    use crate::stage1::{LeafSpan, Stage1Leaf, Stage1Walker, WalkError};
    let configs = {
        let base = HardwareWalkConfig::new();
        let mut no_ad = base;
        no_ad.update_ad = false;
        let mut no_nxe = base;
        no_nxe.nxe = false;
        let mut permissive = base;
        (permissive.cr0_wp, permissive.cr4_smep, permissive.cr4_smap) = (false, false, false);
        [base, no_ad, no_nxe, permissive]
    };
    // (path index or None, clear, set): terminal edits and a refused table.
    let edits: [(Option<usize>, u64, u64); 6] = [
        (None, 0, 0),
        (Some(usize::MAX), PRESENT, 0),
        (Some(usize::MAX), WRITE, 0),
        (Some(usize::MAX), USER, 0),
        (Some(usize::MAX), 0, NX),
        (Some(0), ADDRESS, 0x00ff_0000_0000),
    ];
    let mut rows = 0;
    let mut seen = BTreeMap::new();
    for size in [LeafSize::Page, LeafSize::Block2M, LeafSize::Block1G] {
        for &(at, clear, set) in &edits {
            for config in configs {
                for user in [false, true] {
                    for access in Access::ALL {
                        for offset in [19, 0x0000_8000_0000_0000] {
                            let fixture = || {
                                let (words, va, _, path) = raw_translation(size);
                                if let Some(at) = at {
                                    let pa = path[at.min(path.len() - 1)];
                                    let mut map = words.words.borrow_mut();
                                    let entry = map[&pa];
                                    map.insert(pa, (entry & !clear) | set);
                                }
                                (words, va)
                            };
                            let (direct_words, va) = fixture();
                            let (seam_words, _) = fixture();
                            let direct = translate_leaf_hardware(
                                &direct_words,
                                root(0x1000),
                                UserVa::new(va + offset),
                                access,
                                user,
                                &config,
                            );
                            let context = HardwareWalkContext {
                                root: root(0x1000),
                                user,
                                config,
                            };
                            let seam = HardwareWalker.walk(
                                &seam_words,
                                &context,
                                GuestVa::new(va + offset),
                                access,
                            );
                            let expected = direct.map_err(|fault| match fault {
                                HardwareFaultClass::DescriptorLoad(refusal) => {
                                    WalkError::Refusal(refusal)
                                }
                                fault => WalkError::Fault(fault),
                            });
                            assert_eq!(seam, expected, "{size:?} {at:?} {access:?} {user}");
                            let class = match seam {
                                Ok(_) => "leaf",
                                Err(WalkError::Refusal(_)) => "refusal",
                                Err(WalkError::Fault(HardwareFaultClass::NonCanonical)) => {
                                    "non-canonical"
                                }
                                Err(WalkError::Fault(HardwareFaultClass::NotPresent)) => {
                                    "not-present"
                                }
                                Err(WalkError::Fault(HardwareFaultClass::Protection)) => {
                                    "protection"
                                }
                                Err(WalkError::Fault(HardwareFaultClass::Nx)) => "nx",
                                Err(WalkError::Fault(HardwareFaultClass::Reserved)) => "reserved",
                                Err(WalkError::Fault(HardwareFaultClass::Smep)) => "smep",
                                Err(WalkError::Fault(HardwareFaultClass::Smap)) => "smap",
                                Err(WalkError::Fault(_)) => "other",
                            };
                            *seen.entry(class).or_insert(0) += 1;
                            if let Ok(leaf) = seam {
                                assert_eq!(leaf.output(), leaf.output);
                                assert_eq!(
                                    Some(leaf.span()),
                                    LeafSpan::new(
                                        FrameGpa::new(leaf.output.raw() & !(size.bytes() - 1)),
                                        size.bytes()
                                    )
                                );
                            }
                            assert_eq!(
                                (seam_words.reads.get(), seam_words.stores.get()),
                                (direct_words.reads.get(), direct_words.stores.get())
                            );
                            assert_eq!(*seam_words.words.borrow(), *direct_words.words.borrow());
                            rows += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(rows, 3 * 6 * 4 * 2 * 3 * 2);
    // The matrix reaches every outcome the seam distinguishes.
    for class in [
        "leaf",
        "refusal",
        "non-canonical",
        "not-present",
        "protection",
        "nx",
        "reserved",
        "smep",
        "smap",
    ] {
        assert!(seen.contains_key(class), "{class} not reached: {seen:?}");
    }
}
