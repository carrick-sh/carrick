//! x86 custody of a native exec successor: publication of its closed space,
//! the consuming adoption/cancellation crossings, and the switch of the
//! executing slot onto it. The sequencing and every refusal live here, away
//! from the freestanding image's statics, so VM-free fixtures drive it;
//! `native_process::Service` supplies the machine effects.
//!
//! The ISA-neutral publication, adoption and cancellation protocol is
//! `carrick_el1_linux::exec_successor`, shared with the AArch64 owner. This
//! module holds only what x86 decides differently: the sealed identity (no
//! PCID, so the manifest carries `Asid::x86_untagged()`), the entry state, and
//! the space switch.
extern crate alloc;

use alloc::boxed::Box;
use carrick_core::mm::transaction::{MmPortal, OwnerVenue};
use carrick_core_abi::service::{
    ExecAdoptionReceipt, ExecSuccessorManifest, ExecSuccessorManifestView, ServiceIdentity,
};
use carrick_core_abi::{PinnedMetadataExtent, ReservationMm};
use carrick_el1::memory::reservations::{X86Cpl0ReservationGeometry, X86Cpl0Reservations};
use carrick_el1_linux::exec_successor::{
    PrepareCross, adopt_closed_exec_successor, cancel_prepared_exec,
    prepare_closed_exec_successor_slot,
};
use carrick_el1_linux::native_process_runtime::{
    ExecSuccessorSlot, NativeExecSuccessor, NativeFailure, NativeProcessError,
};
use carrick_el1_linux::retired_spaces::{RetiredSpace, RetiredSpaces};
use carrick_guest_arch::{AddressContext, RootGpa, SlotId};
use carrick_mmu_core::x86::owner_mmu::X86Mmu;
use carrick_personality_linux::mm::LinuxReservationPolicy;
use carrick_sched_core::{ParkedContextWords, ZoneTables};
use core::num::NonZeroU64;

pub(crate) type Mm = AddressContext<RootGpa>;

/// What only the machine can do. Crossings are the stopped host's consuming
/// answers; the rest is CPU and live-context state outside the zone tables.
pub(crate) trait X86ExecMachine {
    fn cross_adopt(&self, record: u64) -> Result<(), NativeProcessError>;
    fn cross_cancel(&self, record: u64) -> Result<(), NativeProcessError>;
    fn cross_settle(
        &self,
        predecessor: ReservationMm,
        successor: ReservationMm,
    ) -> Result<(), NativeProcessError>;
    /// CR3 onto the carrier's maintenance root, so no process root is live
    /// while the slot's occupancy changes. False: the carrier has none.
    fn park_on_maintenance_root(&self) -> bool;
    /// The live-context census a first syscall capture authenticates against.
    fn admit_context(&self, address: Mm) -> bool;
    fn retire_context(&self, address: Mm) -> bool;
}

/// The successor build x86 runs inside `prepare_cross`, after the arm and
/// before the consuming crossing: the boot editor over the reserved
/// fork-stock tables and inventory data grants, sourcing the shared
/// supervisor entries from the predecessor's live root
/// (`carrick_x86_carrier::initial_boot::build_x86_successor`).
pub(crate) trait X86SuccessorBuild {
    /// Build the sealed `successor` and return the root it built. `Busy`
    /// means stock or inventory ran out: not now, with nothing consumed.
    fn build(
        &mut self,
        successor: &ExecSuccessorManifestView,
    ) -> Result<RootGpa, NativeProcessError>;
}

/// x86's pre-crossing step. No PCID: the only identity this adopter accepts
/// is the one `Asid::x86_untagged()` names, and the generation the manifest
/// seals beside it is the root's. Any other value is a manifest built for
/// another ISA's translation identity. With a build attached, the build runs
/// last and must produce the sealed root. The closed space carries the root
/// alone.
pub(crate) struct X86PrepareCross<'b> {
    pub(crate) build: Option<&'b mut dyn X86SuccessorBuild>,
}

impl PrepareCross for X86PrepareCross<'_> {
    fn prepare_cross(
        &mut self,
        successor: &ExecSuccessorManifestView,
    ) -> Result<u64, NativeProcessError> {
        let untagged = successor.asid.is_x86_untagged()
            && successor.asid_generation == successor.root_generation;
        let enterable = ParkedContextWords::valid_user_entry(
            successor.entry.raw(),
            successor.stack_pointer.raw(),
        );
        if !(untagged && enterable) {
            return Err(NativeProcessError::Stale);
        }
        if let Some(build) = self.build.as_deref_mut()
            && build.build(successor)? != successor.root
        {
            return Err(NativeProcessError::Stale);
        }
        Ok(successor.root.address().raw())
    }
}

/// One execution slot's exec custody over the CPL0 zone and reservations.
pub(crate) struct X86ExecSuccessor<'a, Pin, Venue, M> {
    pub(crate) zone: &'a ZoneTables<ParkedContextWords>,
    pub(crate) roots: &'a X86Cpl0Reservations,
    pub(crate) retired: &'a RetiredSpaces,
    pub(crate) carrier: NonZeroU64,
    pub(crate) slot: SlotId,
    /// The zone's CPU count: slots whose installed space keeps a retired MM
    /// queued.
    pub(crate) cpus: usize,
    pub(crate) machine: M,
    pub(crate) marker: core::marker::PhantomData<fn() -> (Pin, Venue)>,
}

impl<'a, Pin, Venue, M> X86ExecSuccessor<'a, Pin, Venue, M>
where
    Pin: PinnedMetadataExtent + 'a,
    Venue: OwnerVenue<ParkedContextWords> + 'a,
    M: X86ExecMachine,
{
    fn worker(&self) -> u32 {
        u32::from(self.slot.raw())
    }

    fn portal(
        &self,
    ) -> MmPortal<
        '_,
        Pin,
        LinuxReservationPolicy,
        X86Cpl0ReservationGeometry,
        Venue,
        X86Mmu,
        ParkedContextWords,
    > {
        MmPortal::for_zone(self.carrier, self.roots, self.zone).with_mmu(X86Mmu)
    }

    pub(crate) fn prepare_slot(
        &self,
        mm: ReservationMm,
    ) -> Result<Box<dyn ExecSuccessorSlot + 'a>, NativeProcessError> {
        prepare_closed_exec_successor_slot::<
            Pin,
            LinuxReservationPolicy,
            X86Cpl0ReservationGeometry,
            Venue,
            X86Mmu,
            ParkedContextWords,
        >(
            self.zone,
            self.roots,
            self.carrier,
            self.worker(),
            mm,
            X86Mmu,
        )
    }

    pub(crate) fn cancel(&self, receipt: ExecAdoptionReceipt) -> Result<(), NativeFailure> {
        cancel_prepared_exec(receipt, |record| self.machine.cross_cancel(record))
    }

    /// Adopt the sealed successor, running `build` (when the successor's
    /// tables are built here rather than by the host) before the crossing.
    /// Everything x86 can refuse is refused before the consuming crossing,
    /// so a refusal leaves the receipt unconsumed, the predecessor installed
    /// and the successor unbound.
    pub(crate) fn adopt(
        &self,
        identity: ServiceIdentity,
        receipt: ExecAdoptionReceipt,
        manifest: &ExecSuccessorManifest,
        build: Option<&mut dyn X86SuccessorBuild>,
    ) -> Result<NativeExecSuccessor<Mm, ParkedContextWords>, NativeProcessError> {
        let adopted = adopt_closed_exec_successor(
            self.zone,
            identity,
            receipt,
            manifest,
            &mut X86PrepareCross { build },
            |record| self.machine.cross_adopt(record),
        )?;
        let address = adopted.address;
        Ok(NativeExecSuccessor {
            mm: address,
            address,
            words: Box::new(ParkedContextWords::user_entry(
                address,
                adopted.view.entry.raw(),
                adopted.view.stack_pointer.raw(),
            )),
        })
    }

    /// Move the executing slot from the predecessor's space to the adopted
    /// successor's. The consuming adoption was the point of no return, so a
    /// refusal here is terminal (`Quarantined`). CR3 stays on the maintenance
    /// root across the switch; the settling crossing loads the successor's.
    pub(crate) fn finish(&self, predecessor: Mm, successor: Mm) -> Result<(), NativeProcessError> {
        let predecessor_mm = ReservationMm::new(predecessor.mm.raw().get())
            .ok_or(NativeProcessError::Quarantined)?;
        let successor_mm =
            ReservationMm::new(successor.mm.raw().get()).ok_or(NativeProcessError::Quarantined)?;
        let predecessor_index = self
            .zone
            .spaces
            .find(predecessor_mm.raw())
            .ok_or(NativeProcessError::Quarantined)?;
        let successor_index = self
            .zone
            .spaces
            .find(successor_mm.raw())
            .ok_or(NativeProcessError::Quarantined)?;
        // The first syscall capture of the successor authenticates against
        // this census; admit it before anything can no longer be undone.
        if !self.machine.admit_context(successor) {
            return Err(NativeProcessError::Quarantined);
        }
        // Nothing installs the predecessor again.
        self.zone.spaces.close(predecessor_index);
        self.machine.park_on_maintenance_root();
        self.zone.release_space(self.slot);
        Venue::space_access(self.zone, self.slot).open(successor_index);
        self.zone
            .install_space(self.slot, successor_mm.raw())
            .ok_or(NativeProcessError::Quarantined)?;
        if !self.machine.retire_context(predecessor) {
            return Err(NativeProcessError::Quarantined);
        }
        self.retired.push(RetiredSpace {
            carrier: self.carrier,
            zone: core::ptr::from_ref(self.zone).addr(),
            roots: core::ptr::from_ref(self.roots).addr(),
            mm: predecessor_mm,
        });
        // A refused drain keeps the entry queued for the next drain; the
        // switch itself is complete.
        let _ = self
            .retired
            .drain_portal(&self.portal(), self.zone, self.cpus, self.worker());
        self.machine.cross_settle(predecessor_mm, successor_mm)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use carrick_core_abi::service::{
        ExecSuccessorBacking, ExecSuccessorEntry, ServiceBirth, ServiceOrigin,
    };
    use carrick_core_abi::{
        El1MmHandle, EntryThreadGeneration, ReservationRange, SnapshotGeneration,
    };
    use carrick_el1_abi::NativeExecAdoption;
    use carrick_el1_linux::mm_portal::test_support::{NoPin, Region};
    use carrick_guest_arch::{Asid, FrameGpa, UserVa};
    use carrick_sched_core::object_wait::OwnedObjectWakeEffects;
    use carrick_sched_core::process::{TaskId, TaskKey, TaskSerial};
    use carrick_sched_core::{RecordId, RecordRef, Waker};
    use core::cell::Cell;
    use core::num::NonZeroI32;

    struct TestVenue;
    fn deliver(
        _zone: &ZoneTables<ParkedContextWords>,
        _waker: Waker,
        effects: OwnedObjectWakeEffects<'_, ParkedContextWords>,
    ) {
        let _ = effects.deliver_handbacks(&mut |_| {});
    }
    impl OwnerVenue<ParkedContextWords> for TestVenue {
        fn space_access(
            zone: &ZoneTables<ParkedContextWords>,
            slot: SlotId,
        ) -> carrick_sched_core::spaces::notification::SpaceAccess<'_, ParkedContextWords> {
            carrick_core::wait::space_access(zone, slot, deliver)
        }
        fn deliver_completion(
            zone: &ZoneTables<ParkedContextWords>,
            slot: SlotId,
            effects: OwnedObjectWakeEffects<'_, ParkedContextWords>,
        ) {
            deliver(zone, Waker::El1 { slot }, effects);
        }
        fn encode_error(_: carrick_core::mm::transaction::MmError) -> u32 {
            1
        }
        fn cancelled_copy_code() -> u32 {
            1
        }
    }

    /// The stopped host's answers. `accept` mirrors the carrier: on an
    /// accepted adoption it binds the successor's root into its closed space
    /// (the BIND service) before replying.
    struct Machine<'a> {
        zone: &'a ZoneTables<ParkedContextWords>,
        accept: Cell<bool>,
        adopt_crossings: Cell<u32>,
        cancel_crossings: Cell<u32>,
        settles: Cell<u32>,
        parked: Cell<u32>,
        admitted: Cell<Option<Mm>>,
        retired_context: Cell<Option<Mm>>,
        bind: Cell<Option<(u64, u64)>>,
    }
    impl X86ExecMachine for Machine<'_> {
        fn cross_adopt(&self, record: u64) -> Result<(), NativeProcessError> {
            self.adopt_crossings.set(self.adopt_crossings.get() + 1);
            // SAFETY: the adopter's record lives on its stack for the whole
            // synchronous crossing.
            let record = unsafe { &mut *(record as *mut NativeExecAdoption) };
            let request = record.claim().ok_or(NativeProcessError::Invalid)?;
            if let (true, Some((mm, root))) = (self.accept.get(), self.bind.get()) {
                let index = self.zone.spaces.find(mm).unwrap();
                assert!(self.zone.spaces.bind_initial_root(index, mm, root, root));
                request.accept();
            } else {
                request.refuse();
            }
            Ok(())
        }
        fn cross_cancel(&self, record: u64) -> Result<(), NativeProcessError> {
            self.cancel_crossings.set(self.cancel_crossings.get() + 1);
            // SAFETY: as for `cross_adopt`.
            let record = unsafe { &mut *(record as *mut carrick_el1_abi::NativeExecCancellation) };
            if self.accept.get() {
                assert!(record.accept());
            } else {
                assert!(record.refuse());
            }
            Ok(())
        }
        fn cross_settle(
            &self,
            _: ReservationMm,
            _: ReservationMm,
        ) -> Result<(), NativeProcessError> {
            self.settles.set(self.settles.get() + 1);
            Ok(())
        }
        fn park_on_maintenance_root(&self) -> bool {
            self.parked.set(self.parked.get() + 1);
            true
        }
        fn admit_context(&self, address: Mm) -> bool {
            self.admitted.set(Some(address));
            true
        }
        fn retire_context(&self, address: Mm) -> bool {
            self.retired_context.set(Some(address));
            true
        }
    }

    const PREDECESSOR: u64 = 11;
    const SUCCESSOR: u64 = 12;
    const ROOT: u64 = 0x90_0000;

    struct Fixture {
        region: Region,
        retired: RetiredSpaces,
        slot: SlotId,
    }
    impl Fixture {
        fn zone(&self) -> &ZoneTables<ParkedContextWords> {
            // SAFETY: the retained aligned region owns the zero-valid zone at
            // its real CPL0 offset for the fixture's life.
            unsafe {
                &*self
                    .region
                    .ptr
                    .as_ptr()
                    .add(carrick_core_abi::X86_CPL0_ZONE_OFFSET as usize)
                    .cast()
            }
        }
        fn roots(&self) -> &X86Cpl0Reservations {
            // SAFETY: as for `zone`.
            unsafe {
                &*self
                    .region
                    .ptr
                    .as_ptr()
                    .add(carrick_core_abi::X86_CPL0_RESERVATIONS_OFFSET as usize)
                    .cast()
            }
        }
        fn new() -> Self {
            let fixture = Self {
                region: Region::new(),
                retired: RetiredSpaces::new(),
                slot: SlotId::new(0),
            };
            // The installed predecessor: a published, admitted, open space
            // running on the slot.
            let mm = ReservationMm::new(PREDECESSOR).unwrap();
            let index = fixture
                .zone()
                .spaces
                .publish_closed(PREDECESSOR, 0x6000, 0)
                .unwrap();
            fixture
                .roots()
                .publish(index.index(), mm, layout())
                .unwrap();
            let portal: MmPortal<'_, NoPin, _, _, TestVenue, X86Mmu, ParkedContextWords> =
                MmPortal::for_zone(NonZeroU64::MIN, fixture.roots(), fixture.zone())
                    .with_mmu(X86Mmu);
            portal.root_any(mm, 0).unwrap().finish_import().unwrap();
            TestVenue::space_access(fixture.zone(), fixture.slot).open(index);
            assert!(
                fixture
                    .zone()
                    .install_space(fixture.slot, PREDECESSOR)
                    .is_some()
            );
            fixture
        }
        fn machine(&self, accept: bool) -> Machine<'_> {
            Machine {
                zone: self.zone(),
                accept: Cell::new(accept),
                adopt_crossings: Cell::new(0),
                cancel_crossings: Cell::new(0),
                settles: Cell::new(0),
                parked: Cell::new(0),
                admitted: Cell::new(None),
                retired_context: Cell::new(None),
                bind: Cell::new(Some((SUCCESSOR, ROOT))),
            }
        }
        fn exec<'a>(
            &'a self,
            machine: Machine<'a>,
        ) -> X86ExecSuccessor<'a, NoPin, TestVenue, Machine<'a>> {
            X86ExecSuccessor {
                zone: self.zone(),
                roots: self.roots(),
                retired: &self.retired,
                carrier: NonZeroU64::MIN,
                slot: self.slot,
                cpus: 1,
                machine,
                marker: core::marker::PhantomData,
            }
        }
        fn predecessor_intact(&self) {
            assert_eq!(self.zone().installed_space(self.slot), PREDECESSOR);
            assert!(self.zone().spaces.is_open(PREDECESSOR));
            assert!(self.retired.is_empty());
        }
    }

    fn layout() -> carrick_el1::memory::reservations::Layout {
        carrick_el1::memory::reservations::Layout {
            heap: ReservationRange::new(0x20_0000, 0x30_0000).unwrap(),
            arena: ReservationRange::new(0x4000_0000, 0x4400_0000).unwrap(),
            brk: 0x20_0000,
            address_limit: u64::MAX,
            data_limit: u64::MAX,
            external_address_bytes: 0,
            external_data_bytes: 0,
        }
    }

    fn identity() -> ServiceIdentity {
        ServiceIdentity {
            birth: ServiceBirth {
                origin: ServiceOrigin::Initial,
                process: TaskKey {
                    id: TaskId::from_registry_allocation(NonZeroI32::new(7).unwrap()),
                    serial: TaskSerial::from_registry_allocation(NonZeroU64::new(11).unwrap()),
                },
                thread: EntryThreadGeneration::from_raw(13),
                record: RecordRef {
                    id: RecordId::from_raw(7).unwrap(),
                    incarnation: 17,
                },
                // SAFETY: a synthetic handle for a VM-free fixture.
                mm: unsafe {
                    El1MmHandle::from_admitted_owner(
                        NonZeroU64::MIN,
                        ReservationMm::new(PREDECESSOR).unwrap(),
                        NonZeroU64::new(23).unwrap(),
                    )
                },
            },
            execution: SnapshotGeneration::from_raw(29),
            sequence: NonZeroU64::new(31).unwrap(),
        }
    }

    fn receipt() -> ExecAdoptionReceipt {
        ExecAdoptionReceipt::checked(NonZeroU64::new(41).unwrap()).unwrap()
    }

    fn manifest(
        generation: NonZeroU64,
        asid: Asid,
        asid_generation: NonZeroU64,
        entry: u64,
    ) -> ExecSuccessorManifest {
        ExecSuccessorManifest::propose(
            identity(),
            ReservationMm::new(SUCCESSOR).unwrap(),
            generation,
        )
        .seal(
            identity(),
            receipt(),
            ExecSuccessorBacking {
                root: RootGpa::page_aligned(FrameGpa::new(ROOT)).unwrap(),
                asid,
                asid_generation,
            },
            ExecSuccessorEntry {
                entry: UserVa::new(entry),
                stack_pointer: UserVa::new(0x7fff_f000),
            },
        )
        .unwrap()
    }

    fn sealed(generation: NonZeroU64) -> ExecSuccessorManifest {
        manifest(generation, Asid::x86_untagged(), generation, 0x40_1000)
    }

    #[test]
    fn adopts_a_sealed_successor_and_switches_the_slot_at_finish() {
        let fixture = Fixture::new();
        let exec = fixture.exec(fixture.machine(true));
        let slot = exec
            .prepare_slot(ReservationMm::new(SUCCESSOR).unwrap())
            .unwrap();
        let manifest = sealed(slot.root_generation());
        slot.prepare_adoption().unwrap();

        let adopted = exec.adopt(identity(), receipt(), &manifest, None).unwrap();
        slot.commit();
        assert_eq!(exec.machine.adopt_crossings.get(), 1);
        // Entry state is the sealed rip/rsp under the successor's cr3.
        assert_eq!(adopted.words.user_rip(), 0x40_1000);
        assert_eq!(adopted.words.user_rsp(), 0x7fff_f000);
        assert!(adopted.words.authenticates(adopted.address));
        assert_eq!(adopted.address.root.address().raw(), ROOT);
        // The predecessor keeps running until the graph publishes the
        // successor; adoption alone installs nothing.
        fixture.predecessor_intact();

        let predecessor = AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(0x6000)).unwrap(),
            mm: carrick_guest_arch::MmGeneration::new(NonZeroU64::new(PREDECESSOR).unwrap()),
            generation: carrick_guest_arch::ContextGeneration::new(NonZeroU64::MIN),
        };
        exec.finish(predecessor, adopted.address).unwrap();
        assert_eq!(fixture.zone().installed_space(fixture.slot), SUCCESSOR);
        assert!(fixture.zone().spaces.is_open(SUCCESSOR));
        assert!(!fixture.zone().spaces.is_open(PREDECESSOR));
        assert_eq!(exec.machine.settles.get(), 1);
        assert_eq!(exec.machine.parked.get(), 1);
        assert_eq!(exec.machine.admitted.get(), Some(adopted.address));
        assert_eq!(exec.machine.retired_context.get(), Some(predecessor));
    }

    #[test]
    fn refuses_every_asid_but_the_untagged_one_before_the_crossing() {
        for (asid, asid_generation) in [
            // Another ISA's tag, with a matching generation.
            (Asid::first(), None),
            (
                Asid::from_registry_allocation(core::num::NonZeroU16::new(47).unwrap()),
                None,
            ),
            // The untagged value with a generation that is not the root's.
            (Asid::x86_untagged(), Some(NonZeroU64::new(0x1234).unwrap())),
        ] {
            let fixture = Fixture::new();
            let exec = fixture.exec(fixture.machine(true));
            let slot = exec
                .prepare_slot(ReservationMm::new(SUCCESSOR).unwrap())
                .unwrap();
            let generation = slot.root_generation();
            let manifest = manifest(
                generation,
                asid,
                asid_generation.unwrap_or(generation),
                0x40_1000,
            );
            slot.prepare_adoption().unwrap();

            assert!(matches!(
                exec.adopt(identity(), receipt(), &manifest, None),
                Err(NativeProcessError::Stale)
            ));
            // Refused before the consuming crossing: the receipt is unspent,
            // the old image is untouched and the successor is still unbound.
            assert_eq!(exec.machine.adopt_crossings.get(), 0);
            fixture.predecessor_intact();
            let index = fixture.zone().spaces.find(SUCCESSOR).unwrap();
            assert_eq!(
                fixture.zone().spaces.closed_root_identity(index, SUCCESSOR),
                None
            );
            // The rolled-back slot retires the successor's space.
            drop(slot);
            assert!(fixture.zone().spaces.find(SUCCESSOR).is_none());
            fixture.predecessor_intact();
        }
    }

    #[test]
    fn refuses_an_entry_state_no_user_return_can_enter() {
        let fixture = Fixture::new();
        let exec = fixture.exec(fixture.machine(true));
        let slot = exec
            .prepare_slot(ReservationMm::new(SUCCESSOR).unwrap())
            .unwrap();
        let generation = slot.root_generation();
        let manifest = manifest(generation, Asid::x86_untagged(), generation, 1 << 47);
        assert!(matches!(
            exec.adopt(identity(), receipt(), &manifest, None),
            Err(NativeProcessError::Stale)
        ));
        assert_eq!(exec.machine.adopt_crossings.get(), 0);
        fixture.predecessor_intact();
    }

    /// A test build: records that it ran before any adoption crossing and
    /// answers with `result`.
    struct RecordedBuild<'m> {
        crossings: &'m Cell<u32>,
        result: Result<u64, NativeProcessError>,
        builds: u32,
        crossed_before_build: bool,
    }
    impl<'m> RecordedBuild<'m> {
        fn new(crossings: &'m Cell<u32>, result: Result<u64, NativeProcessError>) -> Self {
            Self {
                crossings,
                result,
                builds: 0,
                crossed_before_build: false,
            }
        }
    }
    impl X86SuccessorBuild for RecordedBuild<'_> {
        fn build(
            &mut self,
            successor: &ExecSuccessorManifestView,
        ) -> Result<RootGpa, NativeProcessError> {
            assert_eq!(successor.successor_mm.raw(), SUCCESSOR);
            self.builds += 1;
            self.crossed_before_build |= self.crossings.get() != 0;
            let root = self.result?;
            RootGpa::page_aligned(FrameGpa::new(root)).ok_or(NativeProcessError::Invalid)
        }
    }

    #[test]
    fn the_successor_build_runs_before_the_consuming_crossing() {
        let fixture = Fixture::new();
        let exec = fixture.exec(fixture.machine(true));
        let slot = exec
            .prepare_slot(ReservationMm::new(SUCCESSOR).unwrap())
            .unwrap();
        let manifest = sealed(slot.root_generation());
        slot.prepare_adoption().unwrap();
        let mut build = RecordedBuild::new(&exec.machine.adopt_crossings, Ok(ROOT));

        let adopted = exec
            .adopt(identity(), receipt(), &manifest, Some(&mut build))
            .unwrap();
        slot.commit();
        assert_eq!(build.builds, 1);
        assert!(!build.crossed_before_build);
        assert_eq!(exec.machine.adopt_crossings.get(), 1);
        assert_eq!(adopted.address.root.address().raw(), ROOT);
    }

    #[test]
    fn a_busy_build_refuses_before_the_crossing_then_succeeds_on_rerun() {
        let fixture = Fixture::new();
        let exec = fixture.exec(fixture.machine(true));
        let slot = exec
            .prepare_slot(ReservationMm::new(SUCCESSOR).unwrap())
            .unwrap();
        let manifest = sealed(slot.root_generation());
        slot.prepare_adoption().unwrap();

        let mut busy =
            RecordedBuild::new(&exec.machine.adopt_crossings, Err(NativeProcessError::Busy));
        assert!(matches!(
            exec.adopt(identity(), receipt(), &manifest, Some(&mut busy)),
            Err(NativeProcessError::Busy)
        ));
        assert_eq!(busy.builds, 1);
        // Not now: the receipt is unspent and the predecessor still runs.
        assert_eq!(exec.machine.adopt_crossings.get(), 0);
        fixture.predecessor_intact();

        let mut ready = RecordedBuild::new(&exec.machine.adopt_crossings, Ok(ROOT));
        exec.adopt(identity(), receipt(), &manifest, Some(&mut ready))
            .unwrap();
        slot.commit();
        assert_eq!(exec.machine.adopt_crossings.get(), 1);
    }

    #[test]
    fn a_build_of_another_root_is_refused_before_the_crossing() {
        let fixture = Fixture::new();
        let exec = fixture.exec(fixture.machine(true));
        let slot = exec
            .prepare_slot(ReservationMm::new(SUCCESSOR).unwrap())
            .unwrap();
        let manifest = sealed(slot.root_generation());
        slot.prepare_adoption().unwrap();
        let mut build = RecordedBuild::new(&exec.machine.adopt_crossings, Ok(ROOT + 0x1000));

        assert!(matches!(
            exec.adopt(identity(), receipt(), &manifest, Some(&mut build)),
            Err(NativeProcessError::Stale)
        ));
        assert_eq!(build.builds, 1);
        assert_eq!(exec.machine.adopt_crossings.get(), 0);
        fixture.predecessor_intact();
        drop(slot);
        assert!(fixture.zone().spaces.find(SUCCESSOR).is_none());
    }

    #[test]
    fn a_host_refusal_rolls_back_leaving_the_old_image_installed() {
        let fixture = Fixture::new();
        let exec = fixture.exec(fixture.machine(false));
        let slot = exec
            .prepare_slot(ReservationMm::new(SUCCESSOR).unwrap())
            .unwrap();
        let manifest = sealed(slot.root_generation());
        assert!(matches!(
            exec.adopt(identity(), receipt(), &manifest, None),
            Err(NativeProcessError::Stale)
        ));
        assert_eq!(exec.machine.adopt_crossings.get(), 1);
        fixture.predecessor_intact();
        drop(slot);
        assert!(fixture.zone().spaces.find(SUCCESSOR).is_none());
        fixture.predecessor_intact();
    }

    #[test]
    fn cancel_spends_the_receipt_and_the_dropped_slot_frees_the_successor() {
        let fixture = Fixture::new();
        let exec = fixture.exec(fixture.machine(true));
        let slot = exec
            .prepare_slot(ReservationMm::new(SUCCESSOR).unwrap())
            .unwrap();
        assert!(fixture.zone().spaces.find(SUCCESSOR).is_some());
        exec.cancel(receipt()).unwrap();
        assert_eq!(exec.machine.cancel_crossings.get(), 1);
        drop(slot);
        assert!(fixture.zone().spaces.find(SUCCESSOR).is_none());
        fixture.predecessor_intact();

        // A refused cancellation is reported, never swallowed.
        let exec = fixture.exec(fixture.machine(false));
        assert!(matches!(exec.cancel(receipt()), Err(NativeFailure::Stale)));
        fixture.predecessor_intact();
    }
}
