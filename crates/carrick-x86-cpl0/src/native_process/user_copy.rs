//! Native process copy mechanics, moved verbatim from the process adapter.
use super::*;
use carrick_core::mm::transaction::{SelectionVenues, TransferStep};
use carrick_el1_abi::KernelFaultVenues;

impl Service {
    pub(super) fn copy_user_bytes(
        &mut self,
        mm: &Mm,
        address: UserVa,
        bytes: &[u8],
    ) -> Result<(), NativeProcessError> {
        if carrick_el1::isa::x86::hardware_live_root().map_err(error)? != mm.root {
            return Err(NativeProcessError::Stale);
        }
        let owner = portal()?;
        let mm_key = ReservationMm::new(mm.mm.raw().get()).ok_or(NativeProcessError::Stale)?;
        let words = anonymous::live_words(mm_key).ok_or(NativeProcessError::Stale)?;
        let handle = owner
            .admitted_handle(mm_key, self.worker())
            .map_err(error)?;
        let mut continuation = owner
            .begin(
                handle,
                carrick_core::mm::transfer::GuestVa::new(address.raw()),
                bytes.len() as u64,
                carrick_el1_abi::PortalTransferIntent::UserWrite,
                self.worker(),
            )
            .map_err(error)?;
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
        while !continuation.is_complete() {
            // SAFETY: select acquires the exact editor before using this leaf.
            let mut prepared = unsafe {
                carrick_el1::fault::X86PreparedResolver::under_editor(mm.mm.raw(), &words)
            };
            let mut cow = carrick_el1::fault::X86CowResolver {
                words: &words,
                pool,
                residency,
                completion: None,
            };
            let step = owner
                .select(
                    &continuation,
                    &words,
                    SelectionVenues {
                        prepared: &mut prepared,
                        cow: &mut cow,
                        residency,
                        slot: self.worker(),
                    },
                )
                .map_err(error)?;
            if pool.has_completions_for(mm.mm.raw().get()) {
                carrick_x86_carrier::entry::cross_owner_grant(
                    carrick_guest_arch::CpuId::new(self.worker()),
                    address,
                );
            }
            match step {
                TransferStep::CowSupply(window) => {
                    if !slots
                        .grant(usize::from(self.slot.raw()))
                        .ok_or(NativeProcessError::Stale)?
                        .publish_cow_fault_selection(window.operation.sequence.get(), window)
                    {
                        return Err(NativeProcessError::Busy);
                    }
                    carrick_x86_carrier::entry::cross_owner_grant(
                        carrick_guest_arch::CpuId::new(self.worker()),
                        address,
                    );
                }
                TransferStep::Selected(selected) => {
                    let fence = owner
                        .revalidate(&continuation, selected, &words, self.worker())
                        .map_err(error)?
                        .ok_or(NativeProcessError::Busy)?;
                    let offset = usize::try_from(continuation.offset())
                        .map_err(|_| NativeProcessError::Invalid)?;
                    let count =
                        usize::try_from(selected.len).map_err(|_| NativeProcessError::Invalid)?;
                    // SAFETY: shared exact-MM fence retains the authorized
                    // user-write span; kernel bytes are live for this call.
                    let copied = unsafe {
                        carrick_el1::isa::x86::user_access::copy(
                            self.task,
                            selected.va.raw() as *mut u8,
                            bytes.as_ptr().add(offset),
                            count,
                            selected.va.raw(),
                            true,
                        )
                    };
                    if !copied {
                        return Err(NativeProcessError::Fault);
                    }
                    fence.complete(&mut continuation).map_err(error)?;
                }
                TransferStep::Supply(_) => return Err(NativeProcessError::Unsupported),
                TransferStep::Suspended => return Err(NativeProcessError::Busy),
                TransferStep::Complete => break,
            }
        }
        Ok(())
    }
}
