//! Native process user-copy mechanics.
use super::*;
use carrick_core::mm::transaction::{
    SelectionVenues, UserWriteError, UserWriteRequest, UserWriteVenue,
};
use carrick_el1_abi::KernelFaultVenues;

/// Physical crossings and ISA byte access for the shared native-write protocol.
struct NativeWriteVenue<'a> {
    task: &'a CurrentTask,
    address: UserVa,
    slot: SlotId,
    pool: &'a carrick_el1_abi::CowGrantPool,
    slots: &'a MmPortalSlots,
    prepared: carrick_el1::fault::X86PreparedResolver<'a, InitialWords>,
    cow: carrick_el1_linux::cow_resolver::X86CowResolver<'a, InitialWords>,
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
    fn settle_completions(&mut self, request: &UserWriteRequest<'_>) -> Result<(), Self::Error> {
        if self.pool.has_completions_for(request.handle.mm().raw()) {
            carrick_x86_carrier::entry::cross_owner_grant(
                carrick_guest_arch::CpuId::new(u32::from(self.slot.raw())),
                self.address,
            );
        }
        Ok(())
    }
    fn supply_cow(
        &mut self,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<(), Self::Error> {
        if !self
            .slots
            .grant(usize::from(self.slot.raw()))
            .ok_or(NativeProcessError::Stale)?
            .publish_cow_fault_selection(window.operation.sequence.get(), window)
        {
            return Err(NativeProcessError::Busy);
        }
        carrick_x86_carrier::entry::cross_owner_grant(
            carrick_guest_arch::CpuId::new(u32::from(self.slot.raw())),
            self.address,
        );
        Ok(())
    }
    fn supply_backing(
        &mut self,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Option<Result<(), Self::Error>> {
        Some((|| {
            let slot = self
                .slots
                .grant(usize::from(self.slot.raw()))
                .ok_or(NativeProcessError::Stale)?;
            if !slot.publish_fault_selection(window.operation.sequence.get(), window) {
                return Err(NativeProcessError::Busy);
            }
            // The shared service owner retains its reply across MM waits and
            // CPU migration; a per-CPU physical reply cannot survive that park.
            Err(NativeProcessError::Unsupported)
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
        if carrick_el1::isa::x86::hardware_live_root().map_err(error)? != mm.root {
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
        result.map_err(NativeProcessError::from_user_write)
    }
}
