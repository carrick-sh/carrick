//! Native process user-copy mechanics.
use super::*;
use carrick_core::mm::transaction::{
    SelectionVenues, UserWriteError, UserWriteRequest, UserWriteVenue, VenueRefusal,
};
use carrick_el1_abi::KernelFaultVenues;

/// Physical crossings and ISA byte access for the shared native-write protocol.
struct NativeWriteVenue<'a> {
    /// Only a preparation may select a page for the fault service: its
    /// caller begins that service with the selection. A copy that selected
    /// one would leave it published with no service to take it, and the
    /// CPU's next selection (the caller's own preparation, or a later COW
    /// fault) would find the slot taken.
    allow_backing: bool,
    task: &'a CurrentTask,
    address: UserVa,
    slot: SlotId,
    pool: &'a carrick_el1_abi::CowGrantPool,
    slots: &'a MmPortalSlots,
    prepared: carrick_el1::fault::X86PreparedResolver<'a, InitialWords>,
    cow: carrick_el1_linux::cow_resolver::X86CowResolver<'a, InitialWords>,
}
impl NativeWriteVenue<'_> {
    /// Ring the settlement of this MM's copy-on-write completions. A
    /// completion is the MM's, in its pool, and the carrier settles every
    /// one of the MM under one exclusion: whichever member sees one rings,
    /// from either CPU, a sibling's completion included (#2749). One still
    /// in the pool after the crossing means the carrier met the MM's editor
    /// held on the other CPU: the copy is contended, and its retry rings
    /// again.
    fn settle_cow_grants(
        &mut self,
        handle: carrick_el1_abi::El1MmHandle,
    ) -> Result<(), VenueRefusal<NativeProcessError>> {
        let mm = handle.mm().raw();
        if !self.pool.has_completions_for(mm) {
            return Ok(());
        }
        #[cfg(feature = "test-support")]
        crate::test_support::hold_editor_for_copy_cow_settle(
            carrick_x86_carrier::native_execution::source(self.slot).zone,
            u32::from(self.slot.raw()),
            handle,
        );
        carrick_x86_carrier::entry::cross_owner_grant(
            carrick_guest_arch::CpuId::new(u32::from(self.slot.raw())),
            self.address,
        );
        if self.pool.has_completions_for(mm) {
            #[cfg(feature = "test-support")]
            crate::test_support::record_copy_cow_editor_held();
            return Err(VenueRefusal::EditorHeld);
        }
        Ok(())
    }
}
impl<'a> UserWriteVenue<ParkedContextWords> for NativeWriteVenue<'a> {
    type Prepared = carrick_el1::fault::X86PreparedResolver<'a, InitialWords>;
    type Cow = carrick_el1_linux::cow_resolver::X86CowResolver<'a, InitialWords>;
    type Error = NativeProcessError;

    fn selection_venues(&mut self) -> SelectionVenues<'_, Self::Prepared, Self::Cow> {
        let residency = self.cow.residency;
        SelectionVenues {
            prepared: &mut self.prepared,
            cow: &mut self.cow,
            residency,
            slot: u32::from(self.slot.raw()),
        }
    }
    fn settle_completions(
        &mut self,
        request: &UserWriteRequest<'_>,
    ) -> Result<(), VenueRefusal<Self::Error>> {
        self.settle_cow_grants(request.handle)
    }
    /// A preparation resolves the same COW grants as a write (#2716): it
    /// rings the same settlement before it returns.
    fn settle_preparation(
        &mut self,
        target: &carrick_core::mm::transaction::UserWriteTarget,
    ) -> Result<(), VenueRefusal<Self::Error>> {
        self.settle_cow_grants(target.handle)
    }
    fn supply_cow(
        &mut self,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<(), VenueRefusal<Self::Error>> {
        let cpu = carrick_guest_arch::CpuId::new(u32::from(self.slot.raw()));
        self.slots
            .grant(usize::from(self.slot.raw()))
            .ok_or(NativeProcessError::Stale)?
            .supply_cow_selection(window, || {
                // The crossing names the selected page: a copy that spans
                // pages may need its grant for a later page than the one it
                // starts on.
                carrick_x86_carrier::entry::cross_owner_grant(cpu, UserVa::new(window.fault_page));
                Ok::<(), NativeProcessError>(())
            })
            // The carrier met this MM's editor held on the other CPU and
            // supplied nothing; the lane withdrew its selection. The copy is
            // contended, not failed: it waits for the editor's release.
            .map_err(NativeProcessError::venue_cow_supply)
    }
    fn supply_backing(
        &mut self,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Option<Result<(), VenueRefusal<Self::Error>>> {
        if !self.allow_backing {
            return None;
        }
        Some((|| {
            let slot = self
                .slots
                .grant(usize::from(self.slot.raw()))
                .ok_or(NativeProcessError::Stale)?;
            if !slot.publish_fault_selection(window.operation.sequence.get(), window) {
                return Err(NativeProcessError::Busy.into());
            }
            // The shared service owner retains its reply across MM waits and
            // CPU migration; a per-CPU physical reply cannot survive that park.
            Err(NativeProcessError::SupplySelected.into())
        })())
    }
    fn copy(
        &mut self,
        fence: &carrick_core::mm::transfer::ValidatedChunk<'_, ParkedContextWords>,
        bytes: &[u8],
    ) -> bool {
        let selected = fence.selected();
        // SAFETY: the shared exact-MM fence retains this user-write span;
        // the protocol supplies exactly its bounded source bytes.
        unsafe {
            carrick_el1::isa::x86::user_access::copy(
                self.task,
                selected.va.raw() as *mut u8,
                bytes.as_ptr(),
                bytes.len(),
                selected.va.raw(),
                true,
            )
        }
    }
}

impl Service {
    pub(super) fn copy_user_bytes(
        &mut self,
        mm: &Mm,
        address: UserVa,
        bytes: &[u8],
    ) -> Result<(), NativeProcessError> {
        self.access_user_target(
            mm,
            address,
            carrick_guest_arch::GuestLen::new(bytes.len() as u64),
            Some(bytes),
            carrick_guest_arch::Access::Write,
        )
    }

    pub(super) fn access_user_target(
        &mut self,
        mm: &Mm,
        address: UserVa,
        len: carrick_guest_arch::GuestLen,
        bytes: Option<&[u8]>,
        access: carrick_guest_arch::Access,
    ) -> Result<(), NativeProcessError> {
        // Reading the live root is a CPU fact, not owner contention.
        let live = carrick_el1::isa::x86::hardware_live_root()
            .map_err(|_: carrick_el1::isa::ArchError| NativeProcessError::Fault)?;
        if live != mm.root {
            return Err(NativeProcessError::Stale);
        }
        let owner = portal()?;
        let mm_key = ReservationMm::new(mm.mm.raw().get()).ok_or(NativeProcessError::Stale)?;
        let words = anonymous::live_words(mm_key).ok_or(NativeProcessError::Stale)?;
        let handle = owner
            .admitted_handle(mm_key, self.worker())
            .map_err(|error| NativeProcessError::from_user_write(UserWriteError::Owner(error)))?;
        let venues = KernelFaultVenues::derive(carrick_el1::isa::x86_kernel_layout())
            .and_then(KernelFaultVenues::require_upper_half)
            .ok_or(NativeProcessError::Stale)?;
        // SAFETY: boot retains the actual residency and physical replacement
        // pool; the Core owner authenticates each exact source before using it.
        let (residency, pool, slots) = unsafe {
            (
                &*(venues.residency.raw() as *const carrick_el1_abi::FrameGrantResidencyTable),
                &*(venues.cow_pool.raw() as *const carrick_el1_abi::CowGrantPool),
                &*(carrick_el1::isa::x86_kernel_layout().portal.raw() as *const MmPortalSlots),
            )
        };
        // SAFETY: the shared protocol acquires this MM's exact editor for
        // every selection before invoking the prepared resolver.
        let prepared =
            unsafe { carrick_el1::fault::X86PreparedResolver::under_editor(mm.mm.raw(), &words) };
        let mut venue = NativeWriteVenue {
            allow_backing: bytes.is_none(),
            task: self.task,
            address,
            slot: self.slot,
            pool,
            slots,
            prepared,
            cow: carrick_el1_linux::cow_resolver::X86CowResolver {
                words: &words,
                pool,
                residency,
                completion: None,
            },
        };
        #[cfg(feature = "test-support")]
        let held = crate::test_support::hold_editor_for_early_release(self.task);
        let result = if let Some(bytes) = bytes {
            owner.write_user_bytes(
                UserWriteRequest {
                    handle,
                    address,
                    bytes,
                    slot: self.slot,
                },
                &words,
                &mut venue,
            )
        } else if access == carrick_guest_arch::Access::Read {
            owner.prepare_user_read(
                carrick_core::mm::transaction::UserWriteTarget {
                    handle,
                    address,
                    len,
                    slot: self.slot,
                },
                &words,
                &mut venue,
            )
        } else {
            owner.prepare_user_write(
                carrick_core::mm::transaction::UserWriteTarget {
                    handle,
                    address,
                    len,
                    slot: self.slot,
                },
                &words,
                &mut venue,
            )
        };
        #[cfg(feature = "test-support")]
        crate::test_support::release_editor_before_park(
            held,
            matches!(
                result,
                Err(UserWriteError::Owner(
                    carrick_core::mm::transaction::MmError::Wait(_)
                ))
            ),
            carrick_x86_carrier::native_execution::source(self.slot),
            self.task,
        );
        result.map_err(NativeProcessError::from_user_write)
    }
}
