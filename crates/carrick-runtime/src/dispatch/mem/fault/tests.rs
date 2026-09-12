use super::super::tests::{CountingMmapMemory, Stage1MmapMemory, threaded_memory_call};
use super::*;
use crate::linux_abi::{LINUX_PAGE_SIZE, LINUX_PROT_READ};
use crate::memory::LINUX_MMAP_BASE;

#[test]
fn growdown_metadata_is_trimmed_with_mapping_teardown() {
    let dispatcher = SyscallDispatcher::new();
    let page = dispatcher.linux_page_size();
    let start = 0x10_000;
    dispatcher.record_dynamic_mapping(
        start,
        page * 4,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Private,
        "stack".to_owned(),
    );
    dispatcher.record_growdown_mapping(start, page * 4);
    dispatcher
        .with_mmap_growdown_fault_plan_for_test(start - page, |plan| {
            dispatcher.commit_mmap_growdown(plan);
        })
        .expect("grow-down plan");

    dispatcher.with_vma_dispatch_for_test(|_vma_dispatch| {
        dispatcher.remove_mapping_metadata(start + page, page);
    });
    let split = dispatcher
        .vma_snapshot_source()
        .snapshot(std::time::Instant::now() + std::time::Duration::from_secs(1))
        .expect("split grow-down snapshot");
    assert_eq!(
        split.vmas,
        vec![
            crate::kernel::VmaSummary {
                start: GuestVa(start - page),
                end: GuestVa(start + page),
                access: crate::kernel::VmaAccess {
                    readable: true,
                    writable: true,
                    executable: false,
                    kernel_visible: true,
                },
            },
            crate::kernel::VmaSummary {
                start: GuestVa(start + page * 2),
                end: GuestVa(start + page * 4),
                access: crate::kernel::VmaAccess {
                    readable: true,
                    writable: true,
                    executable: false,
                    kernel_visible: true,
                },
            },
        ]
    );

    dispatcher.with_vma_dispatch_for_test(|_vma_dispatch| {
        dispatcher.remove_mapping_metadata(start - page, page * 2);
    });
    assert!(
        dispatcher
            .with_mmap_growdown_fault_plan_for_test(start - page * 2, |plan| drop(plan))
            .is_none()
    );
    let retired = dispatcher
        .vma_snapshot_source()
        .snapshot(std::time::Instant::now() + std::time::Duration::from_secs(1))
        .expect("retired grow-down snapshot");
    assert_eq!(
        retired.vmas,
        vec![crate::kernel::VmaSummary {
            start: GuestVa(start + page * 2),
            end: GuestVa(start + page * 4),
            access: crate::kernel::VmaAccess {
                readable: true,
                writable: true,
                executable: false,
                kernel_visible: true,
            },
        }]
    );
}

/// Two guest threads first-touch the same armed page. The winner commits the
/// page under MM mutation authority and retires its fault range; the loser's
/// fault was already taken against the invalid leaf, so its read-only
/// classification runs AFTER the commit. It must still route to the mutation
/// authority (where the live leaf is authenticated and the access retried),
/// never straight to `SIGSEGV` (go-crypto_md5 under 4-way load: 3/12 SEGV).
#[test]
fn committed_first_touch_page_still_routes_to_mutation_authority() {
    let dispatcher = SyscallDispatcher::new();
    let page = dispatcher.linux_page_size();
    let base = LINUX_MMAP_BASE;
    dispatcher.record_dynamic_mapping(
        base,
        page * 2,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Private,
        String::new(),
    );
    dispatcher.track_resident_fault_range(
        base,
        page * 2,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
    );
    assert!(dispatcher.fault_requires_mm_mutation(base + 16));

    dispatcher
        .with_resident_fault_plan_for_test(base + 16, |plan| {
            assert_eq!(plan.page(), base);
            dispatcher.commit_resident_fault(plan);
        })
        .expect("first-touch plan");
    assert!(
        dispatcher
            .with_resident_fault_plan_for_test(base + 16, |plan| drop(plan))
            .is_none(),
        "a committed page has no pending stage-1 edit"
    );

    assert!(
        dispatcher.fault_requires_mm_mutation(base + 16),
        "the losing sibling's fault on the committed page must reach the authority"
    );
    assert!(dispatcher.fault_requires_mm_mutation(base + page));

    dispatcher.with_vma_dispatch_for_test(|_vma_dispatch| {
        dispatcher.remove_mapping_metadata(base, page * 2);
    });
    assert!(
        !dispatcher.fault_requires_mm_mutation(base + 16),
        "unmapping retires the tracked extent"
    );
}

/// `mprotect` over an armed first-touch range must not silently make the
/// pending pages accessible: the leaf stays invalid (so the first touch is
/// still observed for `mincore`) and the recorded protection follows the new
/// VMA permission, so the eventual fault installs what the guest asked for
/// last -- never the stale arming-time protection.
#[test]
fn mprotect_over_armed_first_touch_page_keeps_the_leaf_invalid_with_new_prot() {
    const SYS_MPROTECT: u64 = 226;
    let dispatcher = SyscallDispatcher::new();
    let page = dispatcher.linux_page_size();
    let base = LINUX_MMAP_BASE;
    let rw = LinuxProtFlags::READ | LinuxProtFlags::WRITE;
    dispatcher.record_dynamic_mapping(base, page * 2, rw, ProcMapSharing::Private, String::new());
    dispatcher.track_resident_fault_range(base, page * 2, rw);
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1171));
    let reporter = CompatReporter::default();
    let mut memory = CountingMmapMemory::new(base, (page * 2) as usize);

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MPROTECT,
            SyscallArgs([base, page, LINUX_PROT_READ, 0, 0, 0]),
        ),
    );
    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });

    let prot = dispatcher
        .with_resident_fault_plan_for_test(base + 16, |plan| plan.prot())
        .expect("the untouched page stays armed");
    assert_eq!(
        prot, LINUX_PROT_READ,
        "the pending edit carries the NEW protection"
    );
    let sibling = dispatcher
        .with_resident_fault_plan_for_test(base + page + 16, |plan| plan.prot())
        .expect("the page outside the mprotect range stays armed");
    assert_eq!(sibling, rw.bits());
    let log = memory.protect_log.borrow();
    assert_eq!(
        log.last().copied(),
        Some((base, page as usize, 0)),
        "the armed page must be re-protected to an invalid leaf after the VMA edit: {log:?}"
    );
}

/// `MADV_DONTNEED` turns a private-anonymous page back into a first-touch
/// fault. The protection restored by that fault is the VMA's complete live
/// R/W/X permission, not a reconstruction from only its writable bit. V8 uses
/// this exact RWX reserve/discard/publish sequence for generated code.
#[test]
fn dontneed_first_touch_restores_an_executable_leaf() {
    const SYS_MADVISE: u64 = 233;
    let dispatcher = SyscallDispatcher::new();
    let page = dispatcher.linux_page_size();
    let base = LINUX_MMAP_BASE;
    let rwx = LinuxProtFlags::READ | LinuxProtFlags::WRITE | LinuxProtFlags::EXEC;
    dispatcher.record_dynamic_mapping(base, page, rwx, ProcMapSharing::Private, String::new());

    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1174));
    let reporter = CompatReporter::default();
    let mut memory = Stage1MmapMemory::new(base, page as usize);
    memory
        .protect_range(base, page as usize, rwx.bits())
        .expect("publish the live RWX VMA");

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MADVISE,
            SyscallArgs([base, page, carrick_abi::LINUX_MADV_DONTNEED, 0, 0, 0]),
        ),
    );
    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });

    let restored_prot = dispatcher
        .with_resident_fault_plan_for_test(base + 16, |plan| {
            let prot = plan.prot();
            memory
                .protect_range(plan.page(), page as usize, prot)
                .expect("publish first-touch leaf");
            prot
        })
        .expect("MADV_DONTNEED re-arms the discarded page");
    let leaf = memory.terminal_descriptor(base);
    assert_eq!(
        restored_prot,
        rwx.bits(),
        "the pending edit preserves PROT_EXEC"
    );
    assert!(
        carrick_mem::page_table::terminal_descriptor_permits_el0(
            leaf,
            carrick_mem::page_table::LeafAccess::Execute,
        ),
        "the exact first-touch leaf must remain executable: {leaf:#x}"
    );
}

/// `mprotect(PROT_NONE)` over an armed page retires its pending edit: a later
/// fault must be delivered as SIGSEGV, not resolved by installing the
/// arming-time RW leaf. The extent stays routed to the authority so a fault
/// there still asks the live stage-1 leaf before delivery, and a later
/// accessible `mprotect` re-arms the still-untouched page.
#[test]
fn mprotect_none_over_armed_first_touch_page_retires_and_rearms_the_pending_edit() {
    const SYS_MPROTECT: u64 = 226;
    let dispatcher = SyscallDispatcher::new();
    let page = dispatcher.linux_page_size();
    let base = LINUX_MMAP_BASE;
    let rw = LinuxProtFlags::READ | LinuxProtFlags::WRITE;
    dispatcher.record_dynamic_mapping(base, page * 2, rw, ProcMapSharing::Private, String::new());
    dispatcher.track_resident_fault_range(base, page * 2, rw);
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1172));
    let reporter = CompatReporter::default();
    let mut memory = CountingMmapMemory::new(base, (page * 2) as usize);

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(SYS_MPROTECT, SyscallArgs([base, page, 0, 0, 0, 0])),
    );
    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    assert!(
        dispatcher
            .with_resident_fault_plan_for_test(base + 16, |plan| drop(plan))
            .is_none(),
        "a PROT_NONE page has no pending accessible edit to install"
    );
    assert!(
        dispatcher.fault_requires_mm_mutation(base + 16),
        "the tracked extent still routes to the authority"
    );
    assert!(
        dispatcher
            .with_resident_fault_plan_for_test(base + page + 16, |plan| drop(plan))
            .is_some(),
        "the neighbouring page keeps its pending edit"
    );

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MPROTECT,
            SyscallArgs([base, page, LINUX_PROT_READ, 0, 0, 0]),
        ),
    );
    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    let prot = dispatcher
        .with_resident_fault_plan_for_test(base + 16, |plan| plan.prot())
        .expect("an accessible mprotect re-arms the still-untouched page");
    assert_eq!(prot, LINUX_PROT_READ);
    let log = memory.protect_log.borrow();
    assert_eq!(
        log.last().copied(),
        Some((base, page as usize, 0)),
        "{log:?}"
    );
}

/// A page the guest has already touched is resident; `mprotect` over it must
/// publish the new leaf and leave it valid -- only the untouched remainder
/// of the tracked extent is re-armed.
#[test]
fn mprotect_over_committed_first_touch_page_does_not_rearm_it() {
    const SYS_MPROTECT: u64 = 226;
    let dispatcher = SyscallDispatcher::new();
    let page = dispatcher.linux_page_size();
    let base = LINUX_MMAP_BASE;
    let rw = LinuxProtFlags::READ | LinuxProtFlags::WRITE;
    dispatcher.record_dynamic_mapping(base, page * 2, rw, ProcMapSharing::Private, String::new());
    dispatcher.track_resident_fault_range(base, page * 2, rw);
    dispatcher
        .with_resident_fault_plan_for_test(base + 16, |plan| dispatcher.commit_resident_fault(plan))
        .expect("first-touch plan");
    let registry =
        crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1173));
    let reporter = CompatReporter::default();
    let mut memory = CountingMmapMemory::new(base, (page * 2) as usize);

    let outcome = threaded_memory_call(
        &dispatcher,
        &mut memory,
        &registry,
        &reporter,
        SyscallRequest::new(
            SYS_MPROTECT,
            SyscallArgs([base, page * 2, LINUX_PROT_READ, 0, 0, 0]),
        ),
    );
    assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    assert!(
        dispatcher
            .with_resident_fault_plan_for_test(base + 16, |plan| drop(plan))
            .is_none(),
        "a resident page is never re-armed"
    );
    let prot = dispatcher
        .with_resident_fault_plan_for_test(base + page + 16, |plan| plan.prot())
        .expect("the untouched page stays armed");
    assert_eq!(prot, LINUX_PROT_READ);
    let log = memory.protect_log.borrow().clone();
    assert_eq!(
        log,
        vec![
            (base, (page * 2) as usize, LINUX_PROT_READ),
            (base + page, page as usize, 0),
        ],
        "only the untouched page returns to an invalid leaf"
    );
}

/// Same race on the grow-down stack: the winner lowers `current` to its page,
/// so the loser's page no longer satisfies `page < current`. The whole
/// grow-down extent stays routed to the authority.
#[test]
fn committed_growdown_page_still_routes_to_mutation_authority() {
    let dispatcher = SyscallDispatcher::new();
    let page = dispatcher.linux_page_size();
    let start = 0x10_000;
    dispatcher.record_dynamic_mapping(
        start,
        page * 4,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
        ProcMapSharing::Private,
        "stack".to_owned(),
    );
    dispatcher.record_growdown_mapping(start, page * 4);
    assert!(dispatcher.fault_requires_mm_mutation(start - page * 2 + 8));
    dispatcher
        .with_mmap_growdown_fault_plan_for_test(start - page * 2, |plan| {
            dispatcher.commit_mmap_growdown(plan);
        })
        .expect("grow-down plan");
    assert!(
        dispatcher
            .with_mmap_growdown_fault_plan_for_test(start - page, |plan| drop(plan))
            .is_none(),
        "the committed extent has no pending grow-down edit"
    );
    assert!(
        dispatcher.fault_requires_mm_mutation(start - page + 8),
        "the losing sibling's fault inside the committed extent must reach the authority"
    );
    assert!(dispatcher.fault_requires_mm_mutation(start + page * 3));
    assert!(!dispatcher.fault_requires_mm_mutation(start + page * 4));
}

/// The first-touch arming set is what `resident_fault_plan` asks and what
/// `commit_resident_fault` edits on every anonymous first touch. It replaced an
/// unsorted `Vec` that was scanned linearly and rebuilt whole per committed
/// page; these cases pin the answers that migration must not change — the
/// boundary conditions of the "last extent at or below the page" lookup and the
/// prefix/suffix split a one-page commit leaves behind.
#[test]
fn first_touch_arming_answers_and_splits_exactly_like_a_scan() {
    let page = LINUX_PAGE_SIZE;
    let base = crate::memory::LINUX_HIGH_VA_THRESHOLD;
    let range = |start: u64, end: u64| {
        crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(end)).expect("range")
    };
    let mut arming = FirstTouchArming::default();
    arming.arm(range(base, base + 4 * page), LinuxProtFlags::READ);
    arming.arm(
        range(base + 8 * page, base + 10 * page),
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
    );

    // Lookup is exact at both edges of both extents, and the gap between them
    // is unarmed — the case a "last entry at or below" search gets wrong if it
    // forgets to check the end.
    assert_eq!(arming.prot_for_page(base), Some(LinuxProtFlags::READ));
    assert_eq!(
        arming.prot_for_page(base + 3 * page),
        Some(LinuxProtFlags::READ)
    );
    assert_eq!(arming.prot_for_page(base + 4 * page), None);
    assert_eq!(arming.prot_for_page(base + 7 * page), None);
    assert_eq!(
        arming.prot_for_page(base + 9 * page),
        Some(LinuxProtFlags::READ | LinuxProtFlags::WRITE)
    );
    assert_eq!(arming.prot_for_page(base - page), None);

    // Committing one page in the middle leaves the prefix and the suffix armed
    // at the same protection, and disarms exactly that page.
    arming.disarm(range(base + 2 * page, base + 3 * page));
    assert_eq!(
        arming.prot_for_page(base + page),
        Some(LinuxProtFlags::READ)
    );
    assert_eq!(arming.prot_for_page(base + 2 * page), None);
    assert_eq!(
        arming.prot_for_page(base + 3 * page),
        Some(LinuxProtFlags::READ)
    );
    assert_eq!(
        arming
            .iter()
            .map(|fault| (fault.range.start().raw(), fault.range.end().raw()))
            .collect::<Vec<_>>(),
        vec![
            (base, base + 2 * page),
            (base + 3 * page, base + 4 * page),
            (base + 8 * page, base + 10 * page),
        ]
    );

    // `intersections` clips to the populated range and reports an extent that
    // merely OVERLAPS its start, not only extents that begin inside it.
    let populate = range(base + 3 * page + 8, base + 9 * page);
    assert_eq!(
        arming
            .intersections(populate)
            .into_iter()
            .map(|fault| (
                fault.range.start().raw(),
                fault.range.end().raw(),
                fault.prot
            ))
            .collect::<Vec<_>>(),
        vec![
            (base + 3 * page + 8, base + 4 * page, LinuxProtFlags::READ),
            (
                base + 8 * page,
                base + 9 * page,
                LinuxProtFlags::READ | LinuxProtFlags::WRITE
            ),
        ]
    );

    // A disarm spanning several extents removes every covered one and keeps
    // only the uncovered tail.
    arming.disarm(range(base + page, base + 9 * page));
    assert_eq!(
        arming
            .iter()
            .map(|fault| (fault.range.start().raw(), fault.range.end().raw()))
            .collect::<Vec<_>>(),
        vec![(base, base + page), (base + 9 * page, base + 10 * page)]
    );

    // Re-arming a range replaces what covered it rather than shadowing it, so
    // the newest VMA over those pages owns their protection.
    arming.arm(range(base, base + 2 * page), LinuxProtFlags::WRITE);
    assert_eq!(arming.prot_for_page(base), Some(LinuxProtFlags::WRITE));
    assert_eq!(
        arming.prot_for_page(base + page),
        Some(LinuxProtFlags::WRITE)
    );
    assert_eq!(arming.len(), 2);
    assert!(arming.overlaps(base, base + page));
    assert!(!arming.overlaps(base + 2 * page, base + 9 * page));
}
