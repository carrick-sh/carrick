//! Both ISA projections obey the same reservation and live-leaf supply rule.
#![allow(clippy::unwrap_used, clippy::panic)]
use carrick_core::mm::transaction::{MmPortal, SelectionVenues, TransferStep};
use carrick_core::mm::transfer::{GuestVa, resolver::*};
use carrick_core_abi::PortalTransferIntent;
use carrick_el1::personality::mm_portal::NativeOwnerVenue;
use carrick_el1::personality::mm_portal::test_support::*;
use carrick_mmu_core::aarch64::descriptor_txn::CallerInvalidatesAsid;
use carrick_mmu_core::owner_mmu::{Aarch64Mmu, OwnerForkMmu};
use carrick_mmu_core::x86::owner_mmu::X86Mmu;
use carrick_sched_core::AddressSpaces;
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

fn first_touch_window<B: OwnerForkMmu + Copy>(
    backend: B,
    table_flags: u64,
    resident: u64,
    prepared: u64,
    neighbors: bool,
) {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mm = admit(&region, &spaces, 78, ROOT, 4, 0);
    let parent = admit(&region, &spaces, 77, ROOT + 0x100000, 4, 0);
    let view = nodes(&region);
    let portal = MmPortal::<_, _, _, NativeOwnerVenue>::new(
        NonZeroU64::new(1).unwrap(),
        region.table(),
        &spaces,
        &view,
    )
    .with_mmu(backend);
    let tables = Tables::new(ROOT, 0, 0);
    for (entry, offset) in [(0, 4096), (513, 8192), (1024, 12288)] {
        tables.words[entry].store((ROOT + offset) | table_flags, Ordering::Release);
    }
    if neighbors {
        tables.words[1536].store(IPA | resident, Ordering::Release);
        tables.words[1538].store((IPA + 8192) | prepared, Ordering::Release);
    }
    let inherited: Vec<_> = tables
        .words
        .iter()
        .map(|word| word.load(Ordering::Acquire))
        .collect();
    let identity = |mm: carrick_core_abi::ReservationMm| {
        let mut root = region
            .table()
            .lock_el1_resolved(spaces.find(mm.raw()).unwrap().index(), mm, &view, 0)
            .unwrap();
        (
            root.incarnation(),
            root.generation(),
            root.mapping(VA).unwrap(),
        )
    };
    let parent_identity = identity(parent);
    let owner_identity = identity(mm);
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            GuestVa::new(VA + 4096),
            1,
            PortalTransferIntent::UserRead,
            0,
        )
        .unwrap();
    let maintenance = CallerInvalidatesAsid;
    let live = tables.live(&maintenance);
    let words = CountWords {
        words: &live,
        loads: core::cell::Cell::new(0),
    };
    let TransferStep::Supply(window) = portal
        .select(
            &transfer,
            &words,
            SelectionVenues {
                prepared: &mut NoopPreparedResolver,
                cow: &mut NoopCowResolver,
                residency: &residency(),
                slot: 0,
            },
        )
        .unwrap()
    else {
        panic!("untouched owner page must select supply")
    };
    assert_eq!(
        window.range.start(),
        if neighbors { VA + 4096 } else { VA },
        "owner supply must exclude the inherited resident predecessor"
    );
    assert_eq!(
        window.range.end(),
        if neighbors { VA + 8192 } else { VA + 16384 },
        "owner supply must exclude the inherited prepared successor"
    );
    assert_eq!(window.operation.mm, mm);
    assert_eq!(window.generation, owner_identity.2.generation);
    assert_eq!(window.host_backing, None);
    let slots = Box::new(carrick_el1_abi::MmPortalSlots::new());
    assert!(slots.bind_carrier(NonZeroU64::new(1).unwrap()));
    let mailbox = carrick_core_abi::FrameGrantMailbox::new();
    let grant_residency = residency();
    let venue = carrick_core::mm::fault::OwnerFaultVenue {
        roots: region.table(),
        spaces: carrick_sched_core::spaces::notification::SpaceAccess::source_free(&spaces),
        slots: &*slots,
        residency: &grant_residency,
        worker: 0,
        mailbox: &mailbox,
    };
    assert!(venue.publish(backend, &words, mm.raw(), VA + 4096, 1));
    let request = mailbox.claim_request().unwrap();
    let fault_window = slots
        .grant(0)
        .unwrap()
        .fault_selection(mm.raw(), request.request_generation)
        .unwrap();
    assert_eq!(fault_window.range, window.range);
    assert_eq!(fault_window.generation, window.generation);
    assert_eq!(fault_window.operation.mm, mm);
    assert_eq!(
        fault_window.operation.incarnation,
        window.operation.incarnation
    );
    assert_ne!(fault_window.operation.sequence, window.operation.sequence);
    assert_eq!(fault_window.host_backing, None);
    assert_eq!(request.requested_len, window.range.len());
    assert!(
        slots
            .grant(0)
            .unwrap()
            .cancel_fault_selection(fault_window, request.request_generation)
    );
    assert_eq!(
        identity(parent),
        parent_identity,
        "peer descriptor authority must retain exact incarnation and generations"
    );
    assert_eq!(identity(mm), owner_identity);
    assert_eq!(
        tables
            .words
            .iter()
            .map(|word| word.load(Ordering::Acquire))
            .collect::<Vec<_>>(),
        inherited
    );
    assert!(
        words.loads.get() <= 4 * (2 * 4 + 1),
        "selection work must be bounded by the reservation window"
    );
}

#[test]
fn aarch64_owner_fault_window_excludes_inherited_backing() {
    first_touch_window(
        Aarch64Mmu,
        3,
        RW | (1 << 56) | (1 << 57),
        (RW | (1 << 56) | (1 << 57)) & !1,
        true,
    );
}

#[test]
fn x86_owner_fault_window_excludes_inherited_backing() {
    use carrick_mmu_core::x86::descriptor_txn::{MAY_WRITE, NX, PREPARED, PRESENT, USER, WRITE};
    first_touch_window(
        X86Mmu,
        PRESENT | USER | WRITE,
        PRESENT | USER | WRITE | NX | MAY_WRITE,
        PREPARED | USER | WRITE | NX | MAY_WRITE,
        true,
    );
}

#[test]
fn aarch64_owner_fault_batches_unbacked_reservation() {
    first_touch_window(Aarch64Mmu, 3, 0, 0, false);
}

#[test]
fn x86_owner_fault_batches_unbacked_reservation() {
    use carrick_mmu_core::x86::descriptor_txn::{PRESENT, USER, WRITE};
    first_touch_window(X86Mmu, PRESENT | USER | WRITE, 0, 0, false);
}
