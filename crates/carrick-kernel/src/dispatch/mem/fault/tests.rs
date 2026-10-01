use super::super::tests::{CountingMmapMemory, Stage1MmapMemory, threaded_memory_call};
use super::*;
use crate::linux_abi::{LINUX_PAGE_SIZE, LINUX_PROT_READ};
use crate::memory::LINUX_MMAP_BASE;

#[test]
fn growdown_cannot_claim_raw_clock_transport() {
    let dispatcher = SyscallDispatcher::new();
    let page = dispatcher.linux_page_size();
    let stub_base = carrick_mem::memory::LINUX_EL0_CLOCK_STUB_BASE;
    let stub_limit = stub_base + carrick_mem::memory::LINUX_EL0_CLOCK_STUB_SIZE;

    dispatcher.record_growdown_mapping(stub_limit, page * 4);
    assert!(
        dispatcher
            .with_mmap_growdown_fault_plan_for_test(stub_base, |plan| drop(plan))
            .is_none(),
        "grow-down expansion must not mint writable stage-1 permissions over the clock stub"
    );

    let ordinary_start = stub_limit + page * 512;
    dispatcher.record_growdown_mapping(ordinary_start, page * 4);
    assert!(
        dispatcher
            .with_mmap_growdown_fault_plan_for_test(ordinary_start - page, |plan| drop(plan))
            .is_some(),
        "adjacent ordinary grow-down behavior must remain available"
    );
}

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

#[test]
fn host_sigframe_copyout_commits_prepared_altstack_after_stage1_publish() {
    let dispatcher = SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().expect("task context");
    let mm = context.shared().mm().id();
    let page = dispatcher.linux_page_size();
    let altstack_page = LINUX_MMAP_BASE + 4 * page;
    dispatcher.track_resident_fault_range(
        altstack_page,
        page,
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
    );
    let mut guard = super::super::super::mm_quiesce::acquire_host_write_mutation_quiesce(
        &dispatcher.pt_quiesce(),
        mm,
        dispatcher.mm_mutation_coordinator(),
        crate::thread::ThreadId::synthetic_for_tests(context.thread().key().tid.raw()),
        super::super::super::mm_quiesce::PtPauseBudget::DEFAULT,
    )
    .expect("exact-MM host-write authority");
    let mut stage1_published = false;
    assert!(
        dispatcher
            .commit_host_first_touch(&mut guard, altstack_page + 8, &mut |address, prot| {
                assert_eq!(address, altstack_page);
                assert_eq!(prot, (LinuxProtFlags::READ | LinuxProtFlags::WRITE).bits());
                Err("stage-1 publication refused".to_owned())
            })
            .is_err()
    );
    assert!(
        dispatcher
            .with_resident_fault_plan_for_test(altstack_page, |_| ())
            .is_some()
    );
    assert_eq!(
        dispatcher.commit_host_first_touch(&mut guard, altstack_page + 8, &mut |address, prot| {
            assert_eq!(address, altstack_page);
            assert_eq!(prot, (LinuxProtFlags::READ | LinuxProtFlags::WRITE).bits());
            stage1_published = true;
            Ok(())
        }),
        Ok(true)
    );
    assert!(stage1_published);
    assert!(
        dispatcher
            .with_resident_fault_plan_for_test(altstack_page, |_| ())
            .is_none()
    );

    let read_only_page = altstack_page + page;
    dispatcher.track_resident_fault_range(read_only_page, page, LinuxProtFlags::READ);
    let mut protection_called = false;
    assert!(
        dispatcher
            .commit_host_first_touch(&mut guard, read_only_page, &mut |_, _| {
                protection_called = true;
                Ok(())
            })
            .is_err()
    );
    assert!(
        !protection_called,
        "PROT_READ must refuse before stage-1 edit"
    );
    assert!(
        dispatcher
            .with_resident_fault_plan_for_test(read_only_page, |_| ())
            .is_some()
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
        carrick_mmu_core::aarch64::terminal_descriptor_permits_el0(
            leaf,
            carrick_mmu_core::aarch64::LeafAccess::Execute,
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
        carrick_vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(end)).expect("range")
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

#[test]
fn frame_grant_plan_clips_backing_window_and_commits_only_the_fault_page() {
    const GRANT: u64 = 2 * 1024 * 1024;
    let dispatcher = SyscallDispatcher::new();
    let page = dispatcher.linux_page_size();
    let base = LINUX_MMAP_BASE + 3 * page;
    let end = base + GRANT + 5 * page;
    let fault = base + 8 * page + 17;
    let prot = LinuxProtFlags::READ | LinuxProtFlags::WRITE;
    dispatcher.track_resident_fault_range(base, end - base, prot);

    let window_start = fault / GRANT * GRANT;
    let expected_start = base.max(window_start);
    let expected_end = end.min(window_start + GRANT);
    dispatcher
        .with_resident_frame_grant_plan_for_test(fault, GRANT, |plan| {
            assert_eq!(plan.start(), expected_start);
            assert_eq!(plan.len(), expected_end - expected_start);
            assert_eq!(plan.prot(), prot.bits());
            dispatcher.commit_resident_frame_grant(plan);
        })
        .expect("bulk first-touch grant plan");

    assert!(
        dispatcher
            .with_resident_fault_plan_for_test(fault, |plan| drop(plan))
            .is_none(),
        "the faulting page must leave the arming set"
    );
    assert!(
        dispatcher
            .with_resident_fault_plan_for_test(expected_start, |plan| drop(plan))
            .is_some(),
        "untouched prefix inside the grant must remain armed"
    );
    if base < expected_start {
        assert!(
            dispatcher
                .with_resident_fault_plan_for_test(base, |plan| drop(plan))
                .is_some(),
            "prefix outside the bulk window must remain armed"
        );
    }
    if expected_end < end {
        assert!(
            dispatcher
                .with_resident_fault_plan_for_test(expected_end, |plan| drop(plan))
                .is_some(),
            "suffix outside the bulk window must remain armed"
        );
    }
}

#[test]
fn first_touch_arming_coalesces_adjacent_equal_protections() {
    let page = LINUX_PAGE_SIZE;
    let base = crate::memory::LINUX_HIGH_VA_THRESHOLD;
    let range = |start: u64, end: u64| {
        carrick_vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(end)).expect("range")
    };
    let mut arming = FirstTouchArming::default();

    arming.arm(
        range(base, base + 3 * page),
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
    );
    arming.arm(
        range(base + 3 * page, base + 8 * page),
        LinuxProtFlags::READ | LinuxProtFlags::WRITE,
    );
    arming.arm(
        range(base + 8 * page, base + 9 * page),
        LinuxProtFlags::READ,
    );

    assert_eq!(
        arming
            .iter()
            .map(|fault| (
                fault.range.start().raw(),
                fault.range.end().raw(),
                fault.prot
            ))
            .collect::<Vec<_>>(),
        vec![
            (
                base,
                base + 8 * page,
                LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ),
            (base + 8 * page, base + 9 * page, LinuxProtFlags::READ),
        ]
    );
}

// Grant allocation is not Linux residency: the untouched middle page must
// remain observable even when its physical backing was prepared in bulk.
#[test]
fn frame_grant_sparse_mincore_tracks_only_faulting_pages() {
    let dispatcher = SyscallDispatcher::new();
    let base = LINUX_MMAP_BASE;
    let page = dispatcher.linux_page_size();
    let prot = LinuxProtFlags::READ | LinuxProtFlags::WRITE;
    dispatcher.record_dynamic_mapping(base, 3 * page, prot, ProcMapSharing::Private, String::new());
    dispatcher.track_resident_fault_range(base, 3 * page, prot);
    let memory = LinearMemory::new(base, vec![0; 3 * page as usize]);
    dispatcher
        .with_resident_frame_grant_plan_for_test(base, 2 * 1024 * 1024, |plan| {
            assert_eq!(plan.len(), 3 * page, "retain bulk backing preparation");
            dispatcher.commit_resident_frame_grant(plan);
        })
        .unwrap();
    assert_eq!(
        dispatcher.mincore_residency_vector(&memory, base, 3, page),
        Some(vec![1, 0, 0])
    );
    dispatcher
        .with_resident_fault_plan_for_test(base + 2 * page, |plan| {
            dispatcher.commit_resident_fault(plan);
        })
        .expect("prepared pages still require first-touch publication");
    assert_eq!(
        dispatcher.mincore_residency_vector(&memory, base, 3, page),
        Some(vec![1, 0, 1])
    );
}

// EL1 executes a first-touch grant after the host planned it. A sibling
// thread's adjacent mmap can merge into the armed extent in between, so the
// settlement-time plan is wider than the published one; the published span
// is still armed and must settle. A span that lost its arming must not.
#[test]
fn published_frame_grant_settles_while_its_fault_page_stays_armed() {
    let dispatcher = SyscallDispatcher::new();
    let base = LINUX_MMAP_BASE;
    let page = dispatcher.linux_page_size();
    let prot = LinuxProtFlags::READ | LinuxProtFlags::WRITE;
    const WINDOW: u64 = 2 * 1024 * 1024;
    dispatcher.record_dynamic_mapping(base, 4 * page, prot, ProcMapSharing::Private, String::new());
    dispatcher.track_resident_fault_range(base, 4 * page, prot);
    let published = dispatcher
        .with_resident_frame_grant_plan_for_test(base + 3 * page, WINDOW, |plan| {
            (plan.start(), plan.len(), plan.prot())
        })
        .unwrap();
    assert_eq!(published, (base, 4 * page, prot.bits()));

    // The adjacent mapping arrives before settlement and merges.
    dispatcher.record_dynamic_mapping(
        base + 4 * page,
        4 * page,
        prot,
        ProcMapSharing::Private,
        String::new(),
    );
    dispatcher.track_resident_fault_range(base + 4 * page, 4 * page, prot);
    let memory = LinearMemory::new(base, vec![0; 8 * page as usize]);
    dispatcher
        .with_resident_frame_grant_plan_for_test(base + 3 * page, WINDOW, |plan| {
            assert_eq!(
                (plan.start(), plan.len()),
                (base, 8 * page),
                "the settlement-time plan grew past the published span"
            );
            assert!(plan.covers_published(published));
            dispatcher.commit_resident_frame_grant(plan);
        })
        .unwrap();
    assert_eq!(
        dispatcher.mincore_residency_vector(&memory, base, 8, page),
        Some(vec![0, 0, 0, 1, 0, 0, 0, 0]),
        "only the faulting page commits; the merged pages stay armed"
    );

    // A sibling's first touch committed page 3 of a span another grant
    // published for fault page 1: the settlement-time plan shrank, but the
    // faulting page is still armed and still commits (windowcoherence:
    // published (0x6000a22000, 0x10000), now (0x6000a25000, 0xd000)).
    dispatcher
        .with_resident_frame_grant_plan_for_test(base + page, WINDOW, |plan| {
            assert_eq!(
                (plan.start(), plan.len()),
                (base, 3 * page),
                "the settlement-time plan shrank inside the published span"
            );
            assert!(plan.covers_published((base, 4 * page, prot.bits())));
            // Reprotected arming, or a span that never held this fault page,
            // does not settle.
            assert!(!plan.covers_published((base, 4 * page, LinuxProtFlags::READ.bits())));
            assert!(!plan.covers_published((base + 2 * page, 2 * page, prot.bits())));
        })
        .unwrap();
    // A fault page that lost its own arming has no plan at all.
    assert!(
        dispatcher
            .with_resident_frame_grant_plan_for_test(base + 3 * page, WINDOW, |_| ())
            .is_none()
    );
}

#[test]
fn reconciled_el1_commit_joins_host_residency_and_disarms_first_touch() {
    let dispatcher = SyscallDispatcher::new();
    let base = LINUX_MMAP_BASE;
    let page = dispatcher.linux_page_size();
    let prot = LinuxProtFlags::READ | LinuxProtFlags::WRITE;
    dispatcher.record_dynamic_mapping(base, 3 * page, prot, ProcMapSharing::Private, String::new());
    dispatcher.track_resident_fault_range(base, 3 * page, prot);
    let memory = LinearMemory::new(base, vec![0; 3 * page as usize]);
    dispatcher
        .with_resident_frame_grant_plan_for_test(base, 3 * page, |plan| {
            dispatcher.commit_resident_frame_grant(plan);
        })
        .unwrap();
    let mut executor = dispatcher.enter_mm_executor().unwrap();
    let guard = crate::dispatch::mm_mutation::from_executor(&mut executor).unwrap();
    assert!(dispatcher.reconcile_el1_resident_page(&guard, base + page));
    assert_eq!(
        dispatcher.mincore_residency_vector(&memory, base, 3, page),
        Some(vec![1, 1, 0])
    );
    assert!(
        dispatcher
            .with_resident_fault_plan_for_test(base + page, |_| ())
            .is_none()
    );
    drop(guard);
    drop(executor);
    let child = dispatcher.fork_clone_in_process(
        crate::thread::ThreadId::synthetic_for_tests(783),
        crate::thread::ThreadId::synthetic_for_tests(784),
        783,
        784,
    );
    assert_eq!(
        child.mincore_residency_vector(&memory, base, 3, page),
        Some(vec![1, 1, 0])
    );
    dispatcher
        .mem_view()
        .mark_range_nonresident(base + page, page);
    assert_eq!(
        dispatcher.mincore_residency_vector(&memory, base, 3, page),
        Some(vec![1, 0, 0])
    );
}

#[test]
fn forked_private_file_grant_excludes_wholly_beyond_eof_page() {
    let parent = SyscallDispatcher::new();
    let base = LINUX_MMAP_BASE;
    let page = parent.linux_page_size();
    let prot = LinuxProtFlags::READ | LinuxProtFlags::WRITE;
    parent.record_dynamic_mapping(base, 4 * page, prot, ProcMapSharing::Private, String::new());
    // Model a bulk-armed snapshot whose final page is wholly beyond EOF.
    parent.track_resident_fault_range(base, 4 * page, prot);
    parent
        .mem()
        .lock()
        .bus_fault_ranges
        .push((base + 3 * page, page));
    let child = parent.fork_clone_in_process(
        crate::thread::ThreadId::synthetic_for_tests(781),
        crate::thread::ThreadId::synthetic_for_tests(782),
        781,
        782,
    );
    assert!(child.mmap_fault_is_sigbus(base + 3 * page + 8));
    child
        .with_resident_frame_grant_plan_for_test(base + page, 2 * 1024 * 1024, |plan| {
            assert_eq!(plan.start(), base);
            assert_eq!(plan.len(), 3 * page);
        })
        .expect("backed pages remain grantable in the child");
    assert!(
        child
            .with_resident_frame_grant_plan_for_test(base + 3 * page + 8, 2 * 1024 * 1024, |_| ())
            .is_none(),
        "the BUS page cannot receive EL1-private prepared backing"
    );
    assert!(
        child
            .with_resident_fault_plan_for_test(base + 3 * page + 8, |_| ())
            .is_none(),
        "host first-touch must not validate the BUS page either"
    );
}

#[test]
fn frame_grant_core_omits_speculative_zero_pages_without_losing_host_writes() {
    let page = LINUX_PAGE_SIZE as usize;
    let mut backing = vec![0; 512 * page];
    backing[0] = 17;
    backing[511 * page] = 29;
    assert_eq!(
        core_data_runs(&backing),
        vec![0..page, 511 * page..512 * page]
    );
    // A host copyout can write without a guest first-touch trap. Its bytes
    // must survive even when residency metadata has not observed that page.
    backing[128 * page + 13] = 91;
    assert_eq!(
        core_data_runs(&backing),
        vec![0..page, 128 * page..129 * page, 511 * page..512 * page]
    );
    assert!(core_data_runs(&vec![0; 512 * page]).is_empty());
    assert!(core_data_runs(&[]).is_empty());
}
