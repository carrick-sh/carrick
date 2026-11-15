#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::fork_stock::UntaggedRoots;
use carrick_core_abi::service::ServiceBirth;
use carrick_el1_abi::{
    EL1_DYNAMIC_METADATA_BASE, El1MmHandle, EntryMmKey, EntryTaskKey, EntryThreadGeneration,
    ForkLifecycleLoan, SnapshotGeneration,
};
use carrick_guest_arch::{
    AddressContext, ContextGeneration, CpuId, FrameGpa, KernelVa, MmGeneration, RootGpa,
};
use carrick_sched_core::process::{TaskId, TaskKey, TaskSerial};
use carrick_sched_core::{RecordId, RecordRef};
use core::num::NonZeroI32;

const CARRIER: NonZeroU64 = NonZeroU64::new(7).unwrap();
const PREDECESSOR: u64 = 301;
const INCARNATION: u64 = 5;

fn mm(raw: u64) -> ReservationMm {
    ReservationMm::new(raw).unwrap()
}

fn identity(origin: ServiceOrigin, task: i32) -> ServiceIdentity {
    ServiceIdentity {
        birth: ServiceBirth {
            origin,
            process: TaskKey {
                id: TaskId::from_registry_allocation(NonZeroI32::new(task).unwrap()),
                serial: TaskSerial::from_registry_allocation(NonZeroU64::new(3).unwrap()),
            },
            thread: EntryThreadGeneration::from_raw(9),
            record: RecordRef {
                id: RecordId::from_raw(1).unwrap(),
                incarnation: 1,
            },
            // SAFETY: a synthetic, never-reused MM identity for this fixture;
            // it authorizes no memory operation.
            mm: unsafe {
                El1MmHandle::from_admitted_owner(
                    CARRIER,
                    mm(PREDECESSOR),
                    NonZeroU64::new(INCARNATION).unwrap(),
                )
            },
        },
        execution: SnapshotGeneration::from_raw(11),
        sequence: NonZeroU64::new(1).unwrap(),
    }
}

fn execution(task: u64, mm_key: u64, incarnation: u64) -> GrantExecution {
    GrantExecution::new(
        CpuId::new(0),
        carrick_el1_abi::ExecutionBinding {
            task: EntryTaskKey::from_raw(task),
            generation: SnapshotGeneration::from_raw(11),
            mm: EntryMmKey::from_raw(mm_key),
            thread_generation: EntryThreadGeneration::from_raw(9),
        },
        AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(0x10_0000)).unwrap(),
            mm: MmGeneration::new(NonZeroU64::new(mm_key).unwrap()),
            generation: ContextGeneration::new(NonZeroU64::new(incarnation).unwrap()),
        },
    )
}

fn generation() -> NonZeroU64 {
    NonZeroU64::new(4).unwrap()
}

type Owner = ExecPreparations<&'static str, &'static str, u32>;

fn stock(tables: u64) -> ForkStock<UntaggedRoots> {
    let mut stock = ForkStock::new(CARRIER, None, UntaggedRoots);
    let pages = (0..tables)
        .map(|n| RootGpa::page_aligned(FrameGpa::new(0x20_0000 + n * 4096)).unwrap())
        .collect();
    let lifecycles = vec![
        ForkLifecycleLoan::new_for_base(
            EL1_DYNAMIC_METADATA_BASE,
            KernelVa::new(EL1_DYNAMIC_METADATA_BASE + 0x4000),
            KernelVa::new(EL1_DYNAMIC_METADATA_BASE + 0x5000),
        )
        .unwrap(),
    ];
    stock.install(pages, lifecycles).unwrap();
    stock
}

/// One allocator, reserving at claim: the receipt exists before anything is
/// staged or sealed, the seal reuses it, and receipts are never reused.
#[test]
fn the_receipt_is_reserved_at_claim_and_the_seal_reuses_it() {
    let mut owner = Owner::default();
    let first = owner
        .claim(identity(ServiceOrigin::Initial, 1), mm(900), generation())
        .unwrap();
    let second = owner
        .claim(
            identity(ServiceOrigin::Descendant, 2),
            mm(901),
            generation(),
        )
        .unwrap();
    assert_ne!(first.receipt(), second.receipt());
    assert_eq!(first.origin(), ServiceOrigin::Initial);
    assert_eq!(owner.census().reserved, 2);
    assert_eq!(owner.census().sealed, 0);
    assert_eq!(owner.seal(first.receipt()), Err(ExecOwnerError::WrongPhase));
    owner.stage(first.receipt(), "staged").unwrap();
    assert_eq!(owner.seal(first.receipt()), Ok(first));
    assert_eq!(owner.census().reserved, 2, "the seal reserves nothing");
    // A retired receipt is never issued again.
    let retired = owner
        .retire(second.receipt(), ExecRetireReason::Refused)
        .unwrap();
    assert!(matches!(retired.held, ExecRetained::Claimed));
    let third = owner
        .claim(
            identity(ServiceOrigin::Descendant, 3),
            mm(902),
            generation(),
        )
        .unwrap();
    assert!(third.receipt().raw() > second.receipt().raw());
}

/// The attachment slot: set once before the seal, returned by value with
/// the adoption, dropped with any other retirement.
#[test]
fn the_attachment_returns_with_the_adoption_and_drops_with_a_retirement() {
    let mut owner = Owner::default();
    let root = owner
        .claim(identity(ServiceOrigin::Initial, 1), mm(900), generation())
        .unwrap();
    assert_eq!(owner.attach(root.receipt(), 7), Ok(()));
    assert_eq!(owner.attach(root.receipt(), 8), Err(8), "once");
    owner.stage(root.receipt(), "staged").unwrap();
    owner.seal(root.receipt()).unwrap();
    assert_eq!(
        owner.attach(root.receipt(), 9),
        Err(9),
        "not after the seal"
    );
    let adopted = owner.adopt(root.receipt(), mm(PREDECESSOR)).unwrap();
    assert_eq!(adopted.attachment, Some(7));
    assert_eq!(adopted.data, "staged");

    let refused = owner
        .claim(identity(ServiceOrigin::Initial, 1), mm(901), generation())
        .unwrap();
    owner.attach(refused.receipt(), 3).unwrap();
    let retired = owner
        .retire(refused.receipt(), ExecRetireReason::Refused)
        .unwrap();
    assert_eq!(retired.attachment, Some(3));
}

/// The retirement report: every reserved receipt retires exactly once, with
/// its origin and whether the ring ever learned it.
#[test]
fn every_receipt_retires_once_with_its_origin_and_seal() {
    let mut owner = Owner::default();
    let stock = stock(4);
    let adopted = owner
        .claim(
            identity(ServiceOrigin::Descendant, 2),
            mm(900),
            generation(),
        )
        .unwrap();
    owner.stage(adopted.receipt(), "a").unwrap();
    owner.seal(adopted.receipt()).unwrap();
    let report = owner
        .adopt(adopted.receipt(), mm(PREDECESSOR))
        .unwrap()
        .retirement;
    assert_eq!(
        report,
        ExecRetirement {
            receipt: adopted.receipt(),
            origin: ServiceOrigin::Descendant,
            reason: ExecRetireReason::Adopted,
            sealed: true,
        }
    );

    let cancelled = owner
        .claim(
            identity(ServiceOrigin::Descendant, 2),
            mm(901),
            generation(),
        )
        .unwrap();
    owner.stage(cancelled.receipt(), "c").unwrap();
    owner.seal(cancelled.receipt()).unwrap();
    let (data, _, report) = owner.cancel(cancelled.receipt()).unwrap();
    assert_eq!(
        (data, report.reason, report.sealed),
        ("c", ExecRetireReason::Cancelled, true)
    );

    let published = owner
        .claim(
            identity(ServiceOrigin::Descendant, 2),
            mm(902),
            generation(),
        )
        .unwrap();
    owner.stage(published.receipt(), "p").unwrap();
    assert!(
        owner
            .retire(published.receipt(), ExecRetireReason::PublishCancelled)
            .is_err(),
        "only a sealed row's publication is cancelled"
    );
    owner.seal(published.receipt()).unwrap();
    assert!(
        owner
            .retire(published.receipt(), ExecRetireReason::Refused)
            .is_err(),
        "a sealed row is past refusal"
    );
    let retired = owner
        .retire(published.receipt(), ExecRetireReason::PublishCancelled)
        .unwrap();
    assert!(matches!(retired.held, ExecRetained::Staged("p")));

    let parked = owner
        .claim(identity(ServiceOrigin::Initial, 1), mm(903), generation())
        .unwrap();
    let (wake, _) = ExecParkWake::new();
    owner
        .park(
            parked.receipt(),
            StockParked::new("ticket", stock.table_release()),
            wake,
        )
        .unwrap();
    let ParkedProbe::Cancelled(continuation, report) = owner
        .probe_parked::<_, _, ()>(parked.receipt(), &stock, |_| Ok(true))
        .unwrap()
    else {
        panic!("a cancelled parked row retires");
    };
    assert_eq!(continuation, "ticket");
    assert_eq!(
        report,
        ExecRetirement {
            receipt: parked.receipt(),
            origin: ServiceOrigin::Initial,
            reason: ExecRetireReason::ParkCancelled,
            sealed: false,
        }
    );

    let census = owner.census();
    assert_eq!(census.reserved, 4);
    assert_eq!(census.retired(), 4);
    assert_eq!(
        (
            census.adopted,
            census.cancelled,
            census.publish_cancelled,
            census.park_cancelled
        ),
        (1, 1, 1, 1)
    );
    assert!(owner.is_empty());
}

/// Contention is "not now": a parked row keeps its receipt, reruns only once
/// its wake has landed and a table has returned, and then seals with the
/// receipt reserved at claim.
#[test]
fn a_parked_row_reruns_after_the_stock_release_and_seals_its_claimed_receipt() {
    let mut owner = Owner::default();
    let mut stock = stock(4);
    let claim = owner
        .claim(identity(ServiceOrigin::Initial, 1), mm(900), generation())
        .unwrap();
    let held = stock.reserve_successor_tables(4).unwrap();
    let observed = stock.table_release();
    let (wake, stock_wake) = ExecParkWake::new();
    assert!(!stock.enrol_release(observed, stock_wake));
    owner
        .park(claim.receipt(), StockParked::new("ticket", observed), wake)
        .unwrap();
    assert_eq!(owner.parked(), vec![claim.receipt()]);
    assert!(matches!(
        owner
            .probe_parked::<_, _, ()>(claim.receipt(), &stock, |_| Ok(false))
            .unwrap(),
        ParkedProbe::Still
    ));
    stock.return_successor_tables(held);
    let ParkedProbe::Rerun(rerun, continuation) = owner
        .probe_parked::<_, _, ()>(claim.receipt(), &stock, |_| Ok(false))
        .unwrap()
    else {
        panic!("the release reruns the parked row");
    };
    assert_eq!((rerun, continuation), (claim, "ticket"));
    assert!(owner.stageable(claim.receipt(), mm(900)));
    owner.stage(claim.receipt(), "staged").unwrap();
    assert_eq!(
        owner.seal(claim.receipt()).unwrap().receipt(),
        claim.receipt()
    );
    let census = owner.census();
    assert_eq!(
        (census.reserved, census.parked, census.reruns, census.sealed),
        (1, 1, 1, 1)
    );
}

/// One successor is staged by one row.
#[test]
fn a_successor_stages_once() {
    let mut owner = Owner::default();
    let first = owner
        .claim(
            identity(ServiceOrigin::Descendant, 2),
            mm(900),
            generation(),
        )
        .unwrap();
    let second = owner
        .claim(
            identity(ServiceOrigin::Descendant, 2),
            mm(900),
            generation(),
        )
        .unwrap();
    owner.stage(first.receipt(), "a").unwrap();
    assert!(!owner.stageable(second.receipt(), mm(900)));
    assert_eq!(
        owner.stage(second.receipt(), "b"),
        Err((ExecOwnerError::SuccessorStaged, "b"))
    );
    assert!(
        !owner.stageable(first.receipt(), mm(901)),
        "its own successor"
    );
}

/// The adoption yields the ring-issued successor MM the sealed receipt
/// authenticated, exactly once.
#[test]
fn the_adoption_names_the_ring_issued_successor_once() {
    let mut owner = Owner::default();
    let claim = owner
        .claim(identity(ServiceOrigin::Initial, 1), mm(900), generation())
        .unwrap();
    owner.stage(claim.receipt(), "s").unwrap();
    assert_eq!(
        owner.adopt(claim.receipt(), mm(PREDECESSOR)).err(),
        Some(ExecOwnerError::WrongPhase),
        "only a sealed row adopts"
    );
    owner.seal(claim.receipt()).unwrap();
    let adopted = owner.adopt(claim.receipt(), mm(PREDECESSOR)).unwrap();
    assert_eq!(adopted.mm.successor(), mm(900));
    assert_eq!(adopted.mm.root_generation(), generation());
    assert_eq!(adopted.mm.receipt(), claim.receipt());
    assert_eq!(adopted.mm.origin(), ServiceOrigin::Initial);
    assert_eq!(
        owner.adopt(claim.receipt(), mm(PREDECESSOR)).err(),
        Some(ExecOwnerError::UnknownReceipt)
    );
}

/// The claim authenticates the predecessor execution it was made for.
#[test]
fn the_claim_names_its_exact_predecessor_execution() {
    let mut owner = Owner::default();
    let claim = owner
        .claim(
            identity(ServiceOrigin::Descendant, 2),
            mm(900),
            generation(),
        )
        .unwrap();
    assert!(claim.names_execution(CARRIER, execution(2, PREDECESSOR, INCARNATION)));
    assert!(claim.predecessor_is(CARRIER, execution(2, PREDECESSOR, INCARNATION)));
    assert!(!claim.names_execution(CARRIER, execution(3, PREDECESSOR, INCARNATION)));
    assert!(claim.predecessor_is(CARRIER, execution(3, PREDECESSOR, INCARNATION)));
    assert!(!claim.predecessor_is(CARRIER, execution(2, PREDECESSOR + 1, INCARNATION)));
    assert!(!claim.predecessor_is(CARRIER, execution(2, PREDECESSOR, INCARNATION + 1)));
    assert!(!claim.predecessor_is(
        NonZeroU64::new(8).unwrap(),
        execution(2, PREDECESSOR, INCARNATION)
    ));
}

fn adopted(owner: &mut Owner, origin: ServiceOrigin, successor: u64) {
    let claim = owner
        .claim(identity(origin, 1), mm(successor), generation())
        .unwrap();
    owner.stage(claim.receipt(), "s").unwrap();
    owner.seal(claim.receipt()).unwrap();
    let _ = owner.adopt(claim.receipt(), mm(PREDECESSOR)).unwrap();
}

/// A root settlement on a lane without the root's custody is handed back
/// before any change; the lane holding it then settles it as the root's.
/// A descendant settles on any lane.
#[test]
fn a_root_settlement_on_the_peer_is_handed_back_unchanged() {
    let mut owner = Owner::default();
    adopted(&mut owner, ServiceOrigin::Initial, 900);
    let before = owner.settling();
    assert_eq!(
        owner.settle(
            mm(PREDECESSOR),
            mm(900),
            ExecCommitEffects::COMPLETE,
            ExecSettleLane::Peer
        ),
        Ok(ExecSettlement::NotHere)
    );
    assert_eq!(owner.settling(), before, "nothing changed");
    assert_eq!(owner.census().settled, 0);
    assert_eq!(owner.census().signal_resets_discharged, 0);
    let Ok(ExecSettlement::Root(root)) = owner.settle(
        mm(PREDECESSOR),
        mm(900),
        ExecCommitEffects::COMPLETE,
        ExecSettleLane::RootCustody,
    ) else {
        panic!("the root's lane settles it");
    };
    assert_eq!(root.consume().successor, mm(900));

    adopted(&mut owner, ServiceOrigin::Descendant, 901);
    assert!(matches!(
        owner.settle(
            mm(PREDECESSOR),
            mm(901),
            ExecCommitEffects::COMPLETE,
            ExecSettleLane::Peer
        ),
        Ok(ExecSettlement::Child(SettledExec { .. }))
    ));
    let census = owner.census();
    assert_eq!(
        (census.settled, census.handed_back, owner.settling()),
        (2, 1, 0)
    );
    assert_eq!(
        owner.settle(
            mm(PREDECESSOR),
            mm(901),
            ExecCommitEffects::COMPLETE,
            ExecSettleLane::RootCustody
        ),
        Err(ExecSettleRefusal::Unknown),
        "settled once"
    );
}

/// The signal reset owed since adoption is discharged only by the ring's
/// complete commit effects, for either origin; a short word is refused.
#[test]
fn a_short_commit_effects_word_is_refused_for_either_origin() {
    for origin in [ServiceOrigin::Initial, ServiceOrigin::Descendant] {
        for missing in [
            ExecCommitEffects::SIGNALS_RESET,
            ExecCommitEffects::DELIVERIES_CLEARED,
            ExecCommitEffects::ALTSTACK_DISABLED,
            ExecCommitEffects::ROBUST_CLEARED,
            ExecCommitEffects::LEADER_PROMOTED,
        ] {
            let mut owner = Owner::default();
            adopted(&mut owner, origin, 900);
            let short = ExecCommitEffects::COMPLETE.without(missing);
            assert_eq!(
                owner.settle(mm(PREDECESSOR), mm(900), short, ExecSettleLane::RootCustody),
                Err(ExecSettleRefusal::ShortEffects(short)),
                "{origin:?} without {missing:?}"
            );
            let census = owner.census();
            assert_eq!(
                (
                    census.short_effects,
                    census.signal_resets_discharged,
                    owner.settling()
                ),
                (1, 0, 0)
            );
        }
    }
}

/// A successor that retires before its settlement leaves settling.
#[test]
fn an_unsettled_successor_is_abandoned_on_retirement() {
    let mut owner = Owner::default();
    adopted(&mut owner, ServiceOrigin::Descendant, 900);
    assert!(owner.abandon_settling(mm(900)));
    assert!(!owner.abandon_settling(mm(900)));
    assert_eq!(owner.settling(), 0);
}
