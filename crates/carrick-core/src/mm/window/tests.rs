use super::*;
use carrick_core_abi::{MmIncarnation, PublicationMm};

const PAGE: u64 = 0x1000;

fn nz(raw: u64) -> NonZeroU64 {
    NonZeroU64::new(raw).unwrap()
}
fn mm(raw: u64) -> MmIncarnationKey {
    MmIncarnationKey {
        mm: PublicationMm::new(nz(raw)),
        incarnation: MmIncarnation::new(nz(1)),
    }
}
fn file(inode: u64) -> WindowIdentity {
    WindowIdentity {
        device: 7,
        inode,
        generation: nz(3),
    }
}
const C0: WindowChunk = WindowChunk::of_offset(0);
const C1: WindowChunk = WindowChunk::of_offset(WINDOW_CHUNK_BYTES);

fn attach(
    registry: &mut WindowRegistry,
    chunk: WindowChunk,
    who: MmIncarnationKey,
    access: WindowAccess,
    eof: u64,
) -> EdgeGeneration {
    // SAFETY: the test is the mapping path that admitted each mapping.
    unsafe { registry.attach(file(1), chunk, who, access, eof) }.unwrap()
}

fn plan(admission: SizeAdmission) -> RevokePlan {
    match admission {
        SizeAdmission::NeedsRevoke(plan) => plan,
        other => panic!("expected a revoke plan, got {other:?}"),
    }
}

#[test]
fn chunks_are_fixed_two_mib_spans_of_the_file() {
    assert_eq!(WindowChunk::of_offset(WINDOW_CHUNK_BYTES - 1), C0);
    assert_eq!(C1.index(), 1);
    assert_eq!(
        (C1.start(), C1.end()),
        (WINDOW_CHUNK_BYTES, 2 * WINDOW_CHUNK_BYTES)
    );
}

/// C3: one MM maps a chunk twice; unmapping one leaves the other its edge.
#[test]
fn a_chunk_mapped_twice_keeps_its_edge_until_both_are_unmapped() {
    let mut registry = WindowRegistry::new();
    let first = attach(&mut registry, C0, mm(1), WindowAccess::Writable, PAGE);
    let second = attach(&mut registry, C0, mm(1), WindowAccess::Writable, PAGE);
    assert_eq!(first, second, "one edge per MM, counted per mapping");
    assert_eq!(registry.writable_maps(file(1)), 2);

    assert_eq!(
        registry.detach(file(1), C0, mm(1), WindowAccess::Writable),
        Ok(Detached::StillMapped)
    );
    assert_eq!(
        registry.fault(file(1), mm(1), 7),
        Ok(FaultAdmission::Publish)
    );
    assert_eq!(registry.writable_maps(file(1)), 1);

    let Ok(Detached::EdgeRevoked {
        edge,
        chunk_dropped: true,
    }) = registry.detach(file(1), C0, mm(1), WindowAccess::Writable)
    else {
        panic!("the last mapping revokes the edge and drops the chunk");
    };
    assert_eq!(edge.generation, first);
    assert_eq!(
        registry.state(file(1)),
        None,
        "the file drops with its last chunk"
    );
    assert_eq!(
        registry.fault(file(1), mm(1), 7),
        Err(WindowRefusal::Unknown)
    );
}

#[test]
fn each_mm_holds_its_own_edge_and_a_foreign_mm_none() {
    let mut registry = WindowRegistry::new();
    let a = attach(&mut registry, C0, mm(1), WindowAccess::Writable, PAGE);
    let b = attach(&mut registry, C0, mm(2), WindowAccess::ReadOnly, PAGE);
    assert_ne!(a, b);
    assert_eq!(registry.writable_maps(file(1)), 1);
    assert_eq!(
        registry.fault(file(1), mm(3), 0),
        Err(WindowRefusal::Foreign)
    );
    assert!(matches!(
        registry.detach(file(1), C0, mm(1), WindowAccess::Writable),
        Ok(Detached::EdgeRevoked {
            chunk_dropped: false,
            ..
        })
    ));
    assert_eq!(registry.edges(file(1), C0), [mm(2)]);
    assert_eq!(
        registry.fault(file(1), mm(2), 0),
        Ok(FaultAdmission::Publish)
    );
    assert_eq!(
        registry.fault(file(1), mm(1), 0),
        Err(WindowRefusal::Foreign)
    );
}

#[test]
fn a_fault_past_the_end_is_sigbus_until_the_file_grows() {
    let mut registry = WindowRegistry::new();
    attach(&mut registry, C0, mm(1), WindowAccess::Writable, PAGE);
    assert_eq!(
        registry.fault(file(1), mm(1), PAGE),
        Ok(FaultAdmission::Bus)
    );
    assert_eq!(
        registry.begin_size_change(file(1), 3 * PAGE),
        SizeAdmission::Admit
    );
    registry.observe_eof(file(1), 3 * PAGE);
    assert_eq!(
        registry.fault(file(1), mm(1), PAGE),
        Ok(FaultAdmission::Publish)
    );
    // A smaller observation in Live is not a shrink: only an admitted one is.
    registry.observe_eof(file(1), PAGE);
    assert_eq!(registry.believed_eof(file(1)), Some(3 * PAGE));
}

#[test]
fn a_size_change_of_an_unmapped_file_is_admitted() {
    let mut registry = WindowRegistry::new();
    assert_eq!(registry.begin_size_change(file(9), 0), SizeAdmission::Admit);
}

/// C2: a shrink revokes first; meanwhile faults past it park, a second size
/// change is Busy, and the applied size is SIGBUS after.
#[test]
fn a_shrink_parks_faults_past_it_until_the_host_applies_it() {
    let mut registry = WindowRegistry::new();
    let eof = WINDOW_CHUNK_BYTES + 5 * PAGE;
    attach(&mut registry, C0, mm(1), WindowAccess::Writable, eof);
    attach(&mut registry, C1, mm(1), WindowAccess::Writable, eof);
    attach(&mut registry, C1, mm(2), WindowAccess::ReadOnly, eof);

    let new_len = WINDOW_CHUNK_BYTES + PAGE;
    let plan = plan(registry.begin_size_change(file(1), new_len));
    assert_eq!(plan.from, new_len);
    assert_eq!(
        plan.edges,
        [(C1, mm(1)), (C1, mm(2))],
        "only chunks reaching past the new size, every MM mapping them"
    );
    assert_eq!(
        registry.state(file(1)),
        Some(WindowState::Shrinking {
            new_len,
            epoch: plan.epoch
        })
    );
    assert_eq!(
        registry.fault(file(1), mm(2), new_len - 1),
        Ok(FaultAdmission::Publish)
    );
    assert_eq!(
        registry.fault(file(1), mm(2), new_len),
        Ok(FaultAdmission::Park)
    );
    assert_eq!(
        registry.fault(file(1), mm(1), eof - 1),
        Ok(FaultAdmission::Park)
    );
    assert_eq!(
        registry.begin_size_change(file(1), PAGE),
        SizeAdmission::Busy,
        "a second size change waits for Live; it never takes the shrink over"
    );
    // Growth observed mid-shrink can't republish past the new size.
    registry.observe_eof(file(1), 2 * WINDOW_CHUNK_BYTES);
    assert_eq!(
        registry.fault(file(1), mm(1), eof - 1),
        Ok(FaultAdmission::Park)
    );

    assert_eq!(
        registry.finish_size_change(file(1), plan.epoch, SizeChangeOutcome::Applied),
        Ok(())
    );
    assert_eq!(registry.state(file(1)), Some(WindowState::Live));
    assert_eq!(registry.believed_eof(file(1)), Some(new_len));
    assert_eq!(
        registry.fault(file(1), mm(2), new_len),
        Ok(FaultAdmission::Bus)
    );
    assert_eq!(
        registry.fault(file(1), mm(2), new_len - 1),
        Ok(FaultAdmission::Publish)
    );
}

/// C2: a failed host shrink returns the file to Live at its old size.
#[test]
fn a_failed_shrink_keeps_the_old_size() {
    let mut registry = WindowRegistry::new();
    attach(&mut registry, C0, mm(1), WindowAccess::Writable, 4 * PAGE);
    let plan = plan(registry.begin_size_change(file(1), PAGE));
    assert_eq!(
        registry.fault(file(1), mm(1), 2 * PAGE),
        Ok(FaultAdmission::Park)
    );
    assert_eq!(
        registry.finish_size_change(file(1), plan.epoch, SizeChangeOutcome::Failed),
        Ok(())
    );
    assert_eq!(registry.state(file(1)), Some(WindowState::Live));
    assert_eq!(registry.believed_eof(file(1)), Some(4 * PAGE));
    assert_eq!(
        registry.fault(file(1), mm(1), 2 * PAGE),
        Ok(FaultAdmission::Publish)
    );
}

/// C2: a mapping made while the file shrinks (a fork, a new mmap) parks
/// like any other past the new size, and never publishes there.
#[test]
fn a_mapping_made_while_the_file_shrinks_parks_past_the_new_size() {
    let mut registry = WindowRegistry::new();
    attach(&mut registry, C0, mm(1), WindowAccess::Writable, 4 * PAGE);
    let plan = plan(registry.begin_size_change(file(1), PAGE));
    assert_eq!(plan.edges, [(C0, mm(1))]);
    // The new mapping names the old size; the record keeps its own.
    attach(&mut registry, C0, mm(2), WindowAccess::Writable, 4 * PAGE);
    assert_eq!(
        registry.fault(file(1), mm(2), PAGE),
        Ok(FaultAdmission::Park)
    );
    assert_eq!(
        registry.fault(file(1), mm(2), 0),
        Ok(FaultAdmission::Publish)
    );
    registry
        .finish_size_change(file(1), plan.epoch, SizeChangeOutcome::Applied)
        .unwrap();
    assert_eq!(
        registry.fault(file(1), mm(2), PAGE),
        Ok(FaultAdmission::Bus)
    );
}

#[test]
fn a_stale_or_missing_shrink_result_is_refused() {
    let mut registry = WindowRegistry::new();
    attach(&mut registry, C0, mm(1), WindowAccess::Writable, 4 * PAGE);
    let first = plan(registry.begin_size_change(file(1), 2 * PAGE));
    registry
        .finish_size_change(file(1), first.epoch, SizeChangeOutcome::Applied)
        .unwrap();
    assert_eq!(
        registry.finish_size_change(file(1), first.epoch, SizeChangeOutcome::Applied),
        Err(WindowRefusal::StaleEpoch),
        "no shrink is under way"
    );
    let second = plan(registry.begin_size_change(file(1), PAGE));
    assert_ne!(second.epoch, first.epoch);
    assert_eq!(
        registry.finish_size_change(file(1), first.epoch, SizeChangeOutcome::Applied),
        Err(WindowRefusal::StaleEpoch)
    );
    assert_eq!(registry.believed_eof(file(1)), Some(2 * PAGE));
}

/// The file record outlives its last mapping while a shrink is under way,
/// so the host result still finds it; then it drops.
#[test]
fn a_file_unmapped_mid_shrink_drops_when_the_shrink_finishes() {
    let mut registry = WindowRegistry::new();
    attach(&mut registry, C0, mm(1), WindowAccess::Writable, 4 * PAGE);
    let plan = plan(registry.begin_size_change(file(1), PAGE));
    assert!(matches!(
        registry.detach(file(1), C0, mm(1), WindowAccess::Writable),
        Ok(Detached::EdgeRevoked {
            chunk_dropped: true,
            ..
        })
    ));
    assert!(registry.state(file(1)).is_some());
    registry
        .finish_size_change(file(1), plan.epoch, SizeChangeOutcome::Applied)
        .unwrap();
    assert_eq!(registry.state(file(1)), None);
}

#[test]
fn detaching_what_was_never_attached_is_refused() {
    let mut registry = WindowRegistry::new();
    assert_eq!(
        registry.detach(file(1), C0, mm(1), WindowAccess::ReadOnly),
        Err(WindowRefusal::Unknown)
    );
    attach(&mut registry, C0, mm(1), WindowAccess::ReadOnly, PAGE);
    assert_eq!(
        registry.detach(file(1), C0, mm(2), WindowAccess::ReadOnly),
        Err(WindowRefusal::Foreign)
    );
    assert_eq!(
        registry.detach(file(1), C0, mm(1), WindowAccess::Writable),
        Err(WindowRefusal::Foreign),
        "a read-only mapping can't retire a writable count"
    );
}
