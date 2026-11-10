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
use carrick_core_abi::service::{ExecAdoptionReceipt, ExecSuccessorManifest, ServiceIdentity};
use carrick_core_abi::{PinnedMetadataExtent, ReservationMm};
use carrick_el1::memory::reservations::{X86Cpl0ReservationGeometry, X86Cpl0Reservations};
use carrick_el1_linux::exec_successor::{
    adopt_closed_exec_successor, cancel_prepared_exec, prepare_closed_exec_successor_slot,
};
use carrick_el1_linux::native_process_runtime::{
    ExecSuccessorSlot, NativeExecSuccessor, NativeProcessError,
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

    pub(crate) fn cancel(&self, receipt: ExecAdoptionReceipt) -> Result<(), NativeProcessError> {
        cancel_prepared_exec(receipt, |record| self.machine.cross_cancel(record))
    }

    /// Adopt the sealed successor. Everything x86 can refuse is refused
    /// before the consuming crossing, so a refusal leaves the receipt
    /// unconsumed, the predecessor installed and the successor unbound.
    pub(crate) fn adopt(
        &self,
        identity: ServiceIdentity,
        receipt: ExecAdoptionReceipt,
        manifest: &ExecSuccessorManifest,
    ) -> Result<NativeExecSuccessor<Mm, ParkedContextWords>, NativeProcessError> {
        let adopted = adopt_closed_exec_successor(
            self.zone,
            identity,
            receipt,
            manifest,
            |successor| {
                // No PCID: the only identity this adopter accepts is the one
                // `Asid::x86_untagged()` names, and the generation the manifest
                // seals beside it is the root's. Any other value is a manifest
                // built for another ISA's translation identity.
                let untagged = successor.asid.is_x86_untagged()
                    && successor.asid_generation == successor.root_generation;
                let enterable = ParkedContextWords::valid_user_entry(
                    successor.entry.raw(),
                    successor.stack_pointer.raw(),
                );
                (untagged && enterable).then(|| successor.root.address().raw())
            },
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
