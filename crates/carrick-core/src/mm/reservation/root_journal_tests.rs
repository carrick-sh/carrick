// The physical release itself is represented by the VM-free release authority;
// production custody wiring and retention of retired-owed slots land in 2b.
fn journal_release<'a>(identity: JournalIdentity<'a>, revision: u64, origin: &FrameInventoryOrigin) -> JournalRelease<'a> {
    let id = |raw| core::num::NonZeroU64::new(raw).unwrap();
    let owner = FrameInventoryReceiptOwner::GuestMm {
        native_mm: carrick_guest_arch::MmGeneration::new(id(identity.mm().raw())),
        root_generation: carrick_guest_arch::ContextGeneration::new(id(identity
            .incarnation()
            .raw())),
    };
    let retirement = FrameInventoryRetirementReceipt::from_kernel_authority(
        FrameInventoryApplyReceipt::from_kernel_authority(
            origin.clone(),
            FrameInventoryProvenance::from_kernel_entropy([4; 32]),
            KernelTransactionId::from_kernel_allocation(id(1)),
            owner,
            revision,
            Vec::new(),
        ),
        true,
    );
    JournalRelease::from_mm_release(
        identity,
        MmReleaseReceipt::from_retirement(retirement).unwrap(),
    )
    .unwrap()
}

fn journal_owed(root: &mut Reservations<'_>) {
    let span = range(0x200000, 0x201000);
    let d = root
        .mmap(
            Placement::Fixed(span.start()),
            span.len(),
            ReservationProtection::READ_WRITE,
        )
        .unwrap();
    complete(root, d);
    let Decision::Work(request) = root.munmap(span).unwrap() else {
        panic!("retirement")
    };
    let slot = root.reserve_return(span).unwrap();
    // SAFETY: this VM-free fixture models completed stage-1 retirement.
    let receipt = unsafe {
        ReservationCompletion::after_descriptor_and_backing_commit(
            request,
            ReservationBackingReceipt {
                receipt: request.sequence.raw(),
                granted_bytes: 0,
                returned_bytes: 0,
            },
        )
    }
    .unwrap();
    root.complete_deferring_return(receipt, slot).unwrap();
}

#[test]
fn retired_journal_release_before_borrowed_root_retirement_joins_once() {
    let origin = FrameInventoryOrigin::default();
    let table = table();
    let mut root = admitted(&table, 0, 41);
    journal_owed(&mut root);
    let identity = root.journal_identity();
    let mut join = RetiredJournalJoin::new(identity, origin.clone());
    // Models the authenticated whole-MM physical release arriving
    // while the reservation root is still borrowed by this guard.
    join.record_release(journal_release(identity, 17, &origin)).unwrap();
    assert_eq!(join.acknowledge(&table), None);
    assert_eq!(root.deferred().count(), 1);
    let journal = root.retire_final().unwrap();
    assert_eq!(journal.released_count(), 1);
    join.record_journal(journal).unwrap();
    // 2a intentionally preserves the old eager-clear behavior; the join has
    // no remaining slots to clear. 2b retains these exact token identities.
    assert_eq!(join.acknowledge(&table), Some(0));
    assert_eq!(join.acknowledge(&table), None);
}

#[test]
fn retired_journal_recycled_slots_and_same_raw_mm_do_not_touch_successor() {
    let origin = FrameInventoryOrigin::default();
    let table = table();
    let mut root = admitted(&table, 0, 41);
    journal_owed(&mut root);
    let old_identity = root.journal_identity();
    let journal = root.retire_final().unwrap();
    let old_slot = journal.slots[0].unwrap();
    let mut successor = admitted(&table, 0, 41);
    journal_owed(&mut successor);
    let new_identity = successor.journal_identity();
    assert_ne!(old_identity, new_identity);
    let next = &table.deferred[old_slot.index];
    assert_ne!(next.epoch.load(Ordering::Relaxed), old_slot.epoch);
    let mut join = RetiredJournalJoin::new(old_identity, origin.clone());
    join.record_journal(journal).unwrap();
    assert_eq!(join.acknowledge(&table), None);
    // Models a late release of the predecessor, not the successor.
    join.record_release(journal_release(old_identity, 18, &origin))
        .unwrap();
    assert_eq!(join.acknowledge(&table), Some(0));
    assert_eq!(successor.deferred().count(), 1);
    let other = admitted(&table, 1, 41);
    assert_ne!(
        other.journal_identity().incarnation(),
        new_identity.incarnation(),
        "incarnations are unique even across root indices"
    );
    let mut mismatched = RetiredJournalJoin::new(new_identity, origin.clone());
    // Models a real release proof belonging to the old root only.
    assert_eq!(
        mismatched.record_release(journal_release(old_identity, 19, &origin)),
        Err(Refusal::Stale)
    );
    assert_eq!(successor.deferred().count(), 1);
}

#[test]
fn return_slot_cannot_release_reused_raw_mm_incarnation() {
    let table = table();
    let mut root = admitted(&table, 0, 41);
    let span = range(0x200000, 0x201000);
    let old = root.reserve_return(span).unwrap();
    let index = old.index;
    assert_eq!(
        root.retire_final().unwrap().released_count(),
        0,
        "uncommitted slot is not an owed extent"
    );
    let mut successor = admitted(&table, 0, 41);
    let fresh = successor.reserve_return(span).unwrap();
    assert_eq!(fresh.index, index);
    successor.release_return(old);
    assert!(successor.owns_deferred_slot(&table.deferred[index]));
    successor.release_return(fresh);
    assert_eq!(table.deferred[index].mm.load(Ordering::Acquire), 0);
}

#[test]
fn journal_receipt_cannot_cross_same_mm_roots_at_equal_local_epochs() {
    let origin = FrameInventoryOrigin::default();
    let table = table();
    let first = admitted(&table, 0, 41);
    let second = admitted(&table, 1, 41);
    let first_identity = first.journal_identity();
    let second_identity = second.journal_identity();
    assert_ne!(first_identity.incarnation(), second_identity.incarnation());
    let release = journal_release(first_identity, 23, &origin);
    assert!(matches!(
        JournalRelease::from_mm_release(second_identity, release.receipt),
        Err(Refusal::Stale)
    ));
}

#[test]
fn journal_incarnation_exhaustion_does_not_publish_a_root() {
    let table = table();
    table.journal_incarnation.store(u64::MAX, Ordering::Relaxed);
    let mm = ReservationMm::new(41).unwrap();
    assert_eq!(table.publish(0, mm, layout()), Err(Refusal::Stale));
    assert_eq!(table.lock(0, mm).err(), Some(Refusal::Stale));
    assert_eq!(table.roots[0].key.load(Ordering::Acquire), 0);
}

#[test]
fn return_tokens_cannot_cross_tables_with_identical_numeric_ids() {
    let first = table();
    let second = table();
    let mut a = admitted(&first, 0, 41);
    let mut b = admitted(&second, 0, 41);
    let span = range(0x200000, 0x201000);
    let foreign = a.reserve_return(span).unwrap();
    let local = b.reserve_return(span).unwrap();
    b.release_return(foreign);
    assert!(b.authenticates_return_slot(&local));
    b.release_return(local);
}

#[test]
fn journal_join_preserves_proofs_when_given_another_table() {
    let origin = FrameInventoryOrigin::default();
    let first = table();
    let second = table();
    let mut a = admitted(&first, 0, 41);
    let mut b = admitted(&second, 0, 41);
    journal_owed(&mut a);
    journal_owed(&mut b);
    let identity = a.journal_identity();
    let mut join = RetiredJournalJoin::new(identity, origin.clone());
    join.record_journal(a.retire_final().unwrap()).unwrap();
    join.record_release(journal_release(identity, 29, &origin)).unwrap();
    assert_eq!(join.acknowledge(&second), None);
    assert_eq!(b.deferred().count(), 1);
    // 2a keeps eager clearing; the matching join consumes its proofs once.
    assert_eq!(join.acknowledge(&first), Some(0));
    assert_eq!(join.acknowledge(&first), None);
}

#[test]
fn journal_join_rejects_foreign_inventory_with_same_numeric_owner() {
    let origin = FrameInventoryOrigin::default();
    let table = table();
    let mut root = admitted(&table, 0, 41);
    journal_owed(&mut root);
    let identity = root.journal_identity();
    let mut join = RetiredJournalJoin::new(identity, origin.clone());
    join.record_journal(root.retire_final().unwrap()).unwrap();
    assert_eq!(
        join.record_release(journal_release(identity, 29, &FrameInventoryOrigin::default())),
        Err(Refusal::Stale)
    );
    assert_eq!(join.acknowledge(&table), None);
    join.record_release(journal_release(identity, 29, &origin)).unwrap();
    assert_eq!(join.acknowledge(&table), Some(0));
}
