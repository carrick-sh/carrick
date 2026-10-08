//! The transaction owner borrows the scheduler's actual parked context ABI.
use carrick_core::mm::fork::{ForkChildRoot, ForkParentRoot};
use carrick_core::mm::transaction::*;
use carrick_core::mm::transfer::GuestVa;
use carrick_core::mm::transfer::resolver::{CowResolution, CowResolver, NoopPreparedResolver};
use carrick_core_abi::*;
use carrick_el1::memory::reservations::{
    LinuxReservationLayout, NoRootWait, X86Cpl0ReservationGeometry, X86Cpl0Reservations,
    X86Cpl0RootReleaseVenue,
};
use carrick_el1::personality::mm_portal::test_support::{IPA, NoPin, Region, Tables, VA};
use carrick_mmu_core::aarch64::descriptor_txn::CallerInvalidatesAsid;
use carrick_mmu_core::x86::descriptor_txn::{COW, MAY_WRITE, NX, PRESENT, PRIVATE, USER, WRITE};
use carrick_mmu_core::x86::owner_mmu::X86Mmu;
use carrick_personality_linux::mm::LinuxReservationPolicy;
use carrick_sched_core::object_wait::OwnedObjectWakeEffects;
use carrick_sched_core::spaces::notification::{SpaceAccess, SpaceReleaseVenue};
use carrick_sched_core::{ParkedContextWords, SlotId, Waker, ZoneTables};
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

struct CompactVenue;
fn deliver(
    _zone: &ZoneTables<ParkedContextWords>,
    _waker: Waker,
    effects: OwnedObjectWakeEffects<'_, ParkedContextWords>,
) {
    let _ = effects.deliver_handbacks(&mut |_| {});
}
impl OwnerVenue<ParkedContextWords> for CompactVenue {
    fn space_access(
        zone: &ZoneTables<ParkedContextWords>,
        slot: SlotId,
    ) -> SpaceAccess<'_, ParkedContextWords> {
        carrick_core::wait::space_access(zone, slot, deliver)
    }
    fn deliver_completion(
        zone: &ZoneTables<ParkedContextWords>,
        slot: SlotId,
        effects: OwnedObjectWakeEffects<'_, ParkedContextWords>,
    ) {
        deliver(zone, Waker::El1 { slot }, effects);
    }
    fn encode_error(_: MmError) -> u32 {
        1
    }
    fn cancelled_copy_code() -> u32 {
        1
    }
}
struct NeedPhysicalSupply;
impl CowResolver for NeedPhysicalSupply {
    fn resolve_cow(&mut self, _: u64, _: u64, _: u64) -> bool {
        false
    }
    fn resolve_cow_outcome(&mut self, _: u64, _: u64, _: u64) -> CowResolution {
        CowResolution::NeedsSupply
    }
}

#[test]
fn compact_parked_context_owner_clones_two_roots_and_selects_exact_cow_supply() {
    type Portal<'a> = MmPortal<
        'a,
        NoPin,
        LinuxReservationPolicy,
        X86Cpl0ReservationGeometry,
        CompactVenue,
        X86Mmu,
        ParkedContextWords,
    >;
    const _: () = {
        assert!(core::mem::align_of::<X86Cpl0Reservations>() <= 64);
        assert!(core::mem::align_of::<ZoneTables<ParkedContextWords>>() <= 64);
    };
    let region = Region::new();
    // SAFETY: the retained aligned fixture region owns both zero-valid ABI
    // records at their real CPL0 offsets until every borrowed guard drops.
    let (roots, zone) = unsafe {
        (
            &*region
                .ptr
                .as_ptr()
                .add(carrick_el1_abi::X86_CPL0_RESERVATIONS_OFFSET as usize)
                .cast::<X86Cpl0Reservations>(),
            &*region
                .ptr
                .as_ptr()
                .add(carrick_el1_abi::X86_CPL0_ZONE_OFFSET as usize)
                .cast::<ZoneTables<ParkedContextWords>>(),
        )
    };
    let mms = [
        ReservationMm::new(11).unwrap(),
        ReservationMm::new(12).unwrap(),
    ];
    let indices = mms.map(|mm| {
        zone.spaces
            .publish_closed(mm.raw(), 0x6000 + (mm.raw() - 11) * 0x10000, 0)
            .unwrap()
    });
    let layout = LinuxReservationLayout {
        heap: ReservationRange::new(0x200000, 0x300000).unwrap(),
        arena: ReservationRange::new(VA, VA + 0x400000).unwrap(),
        brk: 0x200000,
        address_limit: u64::MAX,
        data_limit: u64::MAX,
        external_address_bytes: 0,
        external_data_bytes: 0,
    };
    for (index, mm) in indices.into_iter().zip(mms) {
        roots.publish(index.index(), mm, layout).unwrap();
    }
    let release = X86Cpl0RootReleaseVenue::new(
        roots,
        SpaceReleaseVenue {
            zone,
            waker: Waker::Host,
            deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Function(deliver),
        },
    )
    .unwrap();
    {
        let mut parent = release
            .lock(indices[0].index(), mms[0], &NoRootWait)
            .unwrap();
        parent
            .import(
                ReservationRange::new(VA, VA + 4096).unwrap(),
                ReservationProtection::READ_WRITE,
                true,
            )
            .unwrap();
        parent.finish_import().unwrap();
        let mut child = release
            .lock(indices[1].index(), mms[1], &NoRootWait)
            .unwrap();
        let request = PortalForkRequest {
            operation: PortalOperation {
                carrier: NonZeroU64::MIN,
                mm: mms[0],
                incarnation: NonZeroU64::new(parent.incarnation().raw()).unwrap(),
                sequence: parent.next_transfer_sequence().unwrap(),
            },
            parent_generation: parent.generation(),
            child_mm: mms[1],
            child_tables: PortalForkTableArena::new(0x200000, 4096).unwrap(),
            parent_tables: PortalForkTableArena::new(0x300000, 4096).unwrap(),
            kernel_control_ipa: 0xa00000,
        };
        ForkParentRoot::reserve_fork_certificate(&mut parent, request).unwrap();
        ForkChildRoot::set_fork_origin(&mut child, request).unwrap();
        ForkParentRoot::clone_into(&mut parent, &mut child).unwrap();
    }
    let portal = Portal {
        backend: core::marker::PhantomData,
        carrier: NonZeroU64::MIN,
        roots,
        spaces: &zone.spaces,
        nodes: None,
        zone: None,
        vma_visits: core::sync::atomic::AtomicUsize::new(0),
    }
    .with_zone(zone)
    .unwrap();
    fn accepts_native_fork<
        T: carrick_el1::personality::mm_portal::NativeForkPortal<NoPin, X86Mmu>,
    >(
        _: &T,
    ) {
    }
    accepts_native_fork(&portal);
    for (index, mm) in indices.into_iter().zip(mms) {
        let handle = portal.admitted_handle(mm, 0).unwrap();
        // Root admission already published this exact notification source.
        let entry = zone
            .space_entry(NonZeroU64::new(mm.raw()).unwrap())
            .unwrap();
        let _source = entry.notifications(handle.incarnation()).unwrap();
        SpaceAccess::notified(SpaceReleaseVenue {
            zone,
            waker: Waker::Host,
            deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Function(deliver),
        })
        .open(index);
    }
    let residency = FrameGrantResidencyTable::new();
    for (index, mm) in mms.into_iter().enumerate() {
        let root = 0x6000 + index as u64 * 0x10000;
        let tables = Tables::new(root, IPA, 1);
        for (entry, offset) in [(0, 4096), (513, 8192), (1024, 12288)] {
            tables.words[entry].store((root + offset) | PRESENT | WRITE | USER, Ordering::Relaxed);
        }
        tables.words[1536].store(
            IPA | PRESENT | USER | PRIVATE | COW | MAY_WRITE | NX,
            Ordering::Relaxed,
        );
        let handle = portal.admitted_handle(mm, 0).unwrap();
        let transfer = portal
            .begin(
                handle,
                GuestVa::new(VA),
                4,
                PortalTransferIntent::UserWrite,
                0,
            )
            .unwrap();
        let step = portal
            .select(
                &transfer,
                &tables.live(&CallerInvalidatesAsid),
                SelectionVenues {
                    prepared: &mut NoopPreparedResolver,
                    cow: &mut NeedPhysicalSupply,
                    residency: &residency,
                    slot: 0,
                },
            )
            .unwrap();
        let TransferStep::CowSupply(window) = step else {
            panic!("private inherited write requires physical supply");
        };
        assert_eq!(window.operation.mm, mm);
        assert_eq!(window.operation.incarnation, handle.incarnation());
        assert_eq!(window.range, ReservationRange::new(VA, VA + 4096).unwrap());
    }
}

#[test]
fn compact_native_portal_prepares_and_publishes_initial_private_ranges() {
    type Portal<'a> = MmPortal<
        'a,
        NoPin,
        LinuxReservationPolicy,
        X86Cpl0ReservationGeometry,
        CompactVenue,
        X86Mmu,
        ParkedContextWords,
    >;
    const _: () = {
        assert!(core::mem::align_of::<X86Cpl0Reservations>() <= 64);
        assert!(core::mem::align_of::<ZoneTables<ParkedContextWords>>() <= 64);
    };
    let region = Region::new();
    // SAFETY: the retained aligned fixture region owns both zero-valid ABI
    // records at their real CPL0 offsets until every borrowed guard drops.
    let (roots, zone) = unsafe {
        (
            &*region
                .ptr
                .as_ptr()
                .add(carrick_el1_abi::X86_CPL0_RESERVATIONS_OFFSET as usize)
                .cast::<X86Cpl0Reservations>(),
            &*region
                .ptr
                .as_ptr()
                .add(carrick_el1_abi::X86_CPL0_ZONE_OFFSET as usize)
                .cast::<ZoneTables<ParkedContextWords>>(),
        )
    };
    let mms = [
        ReservationMm::new(11).unwrap(),
        ReservationMm::new(12).unwrap(),
    ];
    let indices = mms.map(|mm| {
        zone.spaces
            .publish_closed(mm.raw(), if mm.raw() == 11 { 0x6000 } else { 0x200000 }, 0)
            .unwrap()
    });
    let layout = LinuxReservationLayout {
        heap: ReservationRange::new(0x200000, 0x300000).unwrap(),
        arena: ReservationRange::new(VA, VA + 0x400000).unwrap(),
        brk: 0x200000,
        address_limit: u64::MAX,
        data_limit: u64::MAX,
        external_address_bytes: 8192,
        external_data_bytes: 0,
    };
    for (index, mm) in indices.into_iter().zip(mms) {
        roots.publish(index.index(), mm, layout).unwrap();
    }
    let release = X86Cpl0RootReleaseVenue::new(
        roots,
        SpaceReleaseVenue {
            zone,
            waker: Waker::Host,
            deliver: carrick_sched_core::spaces::notification::SpaceWakeDelivery::Function(deliver),
        },
    )
    .unwrap();

    let request = {
        let mut parent = release
            .lock(indices[0].index(), mms[0], &NoRootWait)
            .unwrap();
        parent
            .import(
                ReservationRange::new(VA, VA + 4096).unwrap(),
                ReservationProtection::READ,
                true,
            )
            .unwrap();
        parent
            .import(
                ReservationRange::new(VA + 4096, VA + 8192).unwrap(),
                ReservationProtection::READ_WRITE,
                true,
            )
            .unwrap();
        parent.finish_import().unwrap();
        PortalForkRequest {
            operation: PortalOperation {
                carrier: NonZeroU64::MIN,
                mm: mms[0],
                incarnation: NonZeroU64::new(parent.incarnation().raw()).unwrap(),
                sequence: parent.next_transfer_sequence().unwrap(),
            },
            parent_generation: parent.generation(),
            child_mm: mms[1],
            child_tables: PortalForkTableArena::new(0x200000, 6 * 4096).unwrap(),
            parent_tables: PortalForkTableArena::new(0x300000, 4096).unwrap(),
            kernel_control_ipa: 0xa00000,
        }
    };
    let portal = Portal {
        backend: core::marker::PhantomData,
        carrier: NonZeroU64::MIN,
        roots,
        spaces: &zone.spaces,
        nodes: None,
        zone: Some(zone),
        vma_visits: core::sync::atomic::AtomicUsize::new(0),
    };
    CompactVenue::space_access(zone, SlotId::new(0)).open(indices[0]);
    let parent = Tables::new(0x6000, IPA, 2);
    for (entry, offset) in [(0, 4096), (513, 8192), (1024, 12288)] {
        parent.words[entry].store(
            (parent.base + offset) | PRESENT | WRITE | USER,
            Ordering::Relaxed,
        );
    }
    parent.words[1536].store(IPA | PRESENT | USER | PRIVATE, Ordering::Relaxed);
    parent.words[1537].store(
        (IPA + 4096) | PRESENT | USER | PRIVATE | WRITE | NX,
        Ordering::Relaxed,
    );
    let child = Tables::new(0x200000, 0, 0);
    let supply = Tables::new(0x300000, 0, 0);
    for table in [&child, &supply] {
        for word in table.words.iter() {
            word.store(0, Ordering::Relaxed);
        }
    }
    struct Words<'a>([&'a Tables; 3]);
    impl Words<'_> {
        fn word(
            &self,
            pa: u64,
        ) -> Result<
            &core::sync::atomic::AtomicU64,
            carrick_mmu_core::descriptor_refusal::DescriptorRefusal,
        > {
            self.0
                .iter()
                .find_map(|table| {
                    pa.checked_sub(table.base)
                        .filter(|offset| offset.is_multiple_of(8))
                        .and_then(|offset| table.words.get(offset as usize / 8))
                })
                .ok_or(carrick_mmu_core::descriptor_refusal::DescriptorRefusal::TableOutsidePrimary)
        }
    }
    impl carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords for Words<'_> {
        fn load(
            &self,
            pa: u64,
        ) -> Result<u64, carrick_mmu_core::descriptor_refusal::DescriptorRefusal> {
            Ok(self.word(pa)?.load(Ordering::Acquire))
        }
        fn compare_exchange(
            &self,
            pa: u64,
            before: u64,
            after: u64,
        ) -> Result<bool, carrick_mmu_core::descriptor_refusal::DescriptorRefusal> {
            Ok(self
                .word(pa)?
                .compare_exchange(before, after, Ordering::AcqRel, Ordering::Acquire)
                .is_ok())
        }
        fn store_unlinked(
            &self,
            pa: u64,
            value: u64,
        ) -> Result<(), carrick_mmu_core::descriptor_refusal::DescriptorRefusal> {
            self.word(pa)?.store(value, Ordering::Release);
            Ok(())
        }
        fn publish_barrier(&self) {}
        fn invalidate_range(&self, _: u64, _: u64) {}
    }
    use carrick_el1::personality::mm_portal::NativeForkPortal;
    let words = Words([&parent, &child, &supply]);
    let scratch = portal.census_fork(request, &words, 0).unwrap();
    let plan = portal.prepare_fork(request, scratch, &words, 0).unwrap();
    assert_eq!(plan.custody().len(), 2);
    assert!(plan.custody().iter().all(|row| matches!(
        row,
        PortalForkCustody::Frame {
            shared: false,
            len: 4096,
            ..
        }
    )));
    let mut pending = portal.publish_fork(plan, &words, 0).unwrap();
    pending.commit(&portal, 0).unwrap();
    assert_eq!(parent.words[1537].load(Ordering::Acquire) & WRITE, 0);
    assert_eq!(portal.admitted_handle(mms[1], 0).unwrap().mm(), mms[1]);
}
