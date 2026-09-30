//! Shared host-to-EL1 descriptor drain, used by fork and host copyout.

use carrick_hal::{ThreadedEngine, TrapError};

/// The venue a synchronous guest descriptor drain runs on: the exact vCPU
/// (slot, TTBR0) of the MM, the host-driven EL1 call, and receipt settlement.
pub trait GuestDrainVenue {
    fn slot(&self) -> Option<usize>;
    fn live_ttbr0(&mut self) -> Result<u64, TrapError>;
    /// Run the EL1 drain call with `frame` on this vCPU; return the frame
    /// EL1 answered.
    fn drain_call(
        &mut self,
        frame: carrick_el1_abi::TrapFrame,
    ) -> Result<carrick_el1_abi::TrapFrame, TrapError>;
    fn settle(
        &mut self,
        txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
        receipt: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt,
    ) -> Result<carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt, TrapError>;
}

/// The production venue: the engine's own vCPU and the shared EL1 region.
pub struct EngineDrainVenue<'a, E>(pub &'a mut E);

impl<E: ThreadedEngine> GuestDrainVenue for EngineDrainVenue<'_, E> {
    fn slot(&self) -> Option<usize> {
        self.0.mailbox_slot()
    }

    fn live_ttbr0(&mut self) -> Result<u64, TrapError> {
        self.0.live_ttbr0()
    }

    fn drain_call(
        &mut self,
        frame: carrick_el1_abi::TrapFrame,
    ) -> Result<carrick_el1_abi::TrapFrame, TrapError> {
        let unavailable = |what: &str| TrapError::Hypervisor(format!("guest drain call: {what}"));
        let region = carrick_el1_abi::get_el1_region_host_ptr();
        if region == 0 {
            return Err(unavailable("no EL1 region"));
        }
        let offset = carrick_el1_abi::descriptor_drain_frame_offset(frame.slot as usize)
            .ok_or_else(|| unavailable("slot out of range"))?;
        // SAFETY: the EL1 region owner keeps the region alive while it is
        // installed; the header is its first 32 bytes.
        let header = carrick_el1_abi::ImageHeader::read_from_prefix(unsafe {
            std::slice::from_raw_parts(
                region as *const u8,
                std::mem::size_of::<carrick_el1_abi::ImageHeader>(),
            )
        })
        .ok_or_else(|| unavailable("no EL1 image header"))?;
        let host_frame = (region + offset as usize) as *mut carrick_el1_abi::TrapFrame;
        // SAFETY: the offset lies in this vCPU slot's own EL1 stack, below the
        // vector's trap frame, 16-aligned; this host thread owns the vCPU.
        unsafe { host_frame.write_volatile(frame) };
        self.0.run_el1_service_call(
            carrick_el1_abi::EL1_REGION_BASE + header.entry_offset,
            carrick_el1_abi::EL1_REGION_BASE + offset,
        )?;
        // SAFETY: as above; EL1 answered in place before `hvc #1`.
        Ok(unsafe { host_frame.read_volatile() })
    }

    fn settle(
        &mut self,
        txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
        receipt: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt,
    ) -> Result<carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt, TrapError>
    {
        self.0.settle_el1_descriptor_receipt(txn, receipt)
    }
}

/// Apply `txns` for one MM synchronously, in order, on the venue's vCPU while
/// the host holds that MM: each is submitted into a free slot, EL1 applies it
/// through the host-driven drain call under the host's delegated custody, and
/// its exact receipt is settled before the next one is submitted. Any
/// refusal, blocked drain or unauthenticated receipt is an error; the caller
/// decides whether that is fatal.
pub fn apply_guest_descriptor_txns_now<V: GuestDrainVenue>(
    venue: &mut V,
    slots: &carrick_el1_abi::DescriptorTxnSlots,
    txns: &[carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn],
) -> Result<Vec<carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt>, TrapError> {
    let fail = |what: String| TrapError::Hypervisor(format!("guest descriptor drain: {what}"));
    let own = venue
        .slot()
        .ok_or_else(|| fail("vCPU has no slot".to_owned()))?;
    let mut verified = Vec::with_capacity(txns.len());
    for txn in txns {
        let ttbr0 = venue.live_ttbr0()?;
        if ttbr0 & 0x0000_FFFF_FFFF_F000 != txn.root.raw() {
            return Err(fail(format!(
                "vCPU TTBR0 0x{ttbr0:x} is not the transaction root 0x{:x}",
                txn.root.raw()
            )));
        }
        let used = (0..slots.as_slice().len())
            .map(|offset| (own + offset) % slots.as_slice().len())
            .find(|&slot| slots.submit(slot, txn))
            .ok_or_else(|| fail("every descriptor slot is busy".to_owned()))?;
        let mut frame = carrick_el1_abi::TrapFrame {
            esr: carrick_el1_abi::DESCRIPTOR_DRAIN_ESR,
            slot: own as u64,
            ..carrick_el1_abi::TrapFrame::default()
        };
        frame.x[carrick_el1_abi::DESCRIPTOR_DRAIN_MM] = txn.id.mm_key.get();
        frame.x[carrick_el1_abi::DESCRIPTOR_DRAIN_TTBR0] = ttbr0;
        let answered = match venue.drain_call(frame) {
            Ok(answered) => answered,
            Err(error) => {
                let _ = slots.withdraw(used, txn.id);
                return Err(error);
            }
        };
        if answered.x[0] & carrick_el1_abi::DESCRIPTOR_DRAIN_BLOCKED != 0 {
            let _ = slots.withdraw(used, txn.id);
            return Err(fail("EL1 could not claim the MM".to_owned()));
        }
        let receipt = slots
            .take_receipt(used, txn.id)
            .ok_or_else(|| fail(format!("no receipt for {:?}", txn.id)))?;
        verified.push(venue.settle(txn, &receipt)?);
    }
    Ok(verified)
}

/// Publish one prepared copyout page through the existing guest executor.
pub fn publish_copyout<V: GuestDrainVenue>(
    venue: &mut V,
    authority: &crate::stage1_authority::Stage1Authority,
    slots: &carrick_el1_abi::DescriptorTxnSlots,
    mm: std::num::NonZeroU64,
    page: u64,
    ipa: u64,
) -> Result<carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt, TrapError> {
    use carrick_mmu_core::aarch64::descriptor_txn::{DescriptorOp, PageSpan};
    use carrick_mmu_core::aarch64::{LeafAccess, SubstrateGpa};
    let txn = authority
        .prepare_guest_descriptor_txn(
            mm,
            DescriptorOp::Publish {
                span: PageSpan::new(page, 4096),
                expected_ipa: SubstrateGpa(ipa),
                access: LeafAccess::Write,
            },
        )
        .map_err(|error| TrapError::Hypervisor(format!("prepare guest copyout: {error:?}")))?;
    let mut receipts = apply_guest_descriptor_txns_now(venue, slots, &[txn])?;
    receipts
        .pop()
        .ok_or_else(|| TrapError::Hypervisor("guest copyout has no verified receipt".to_owned()))
}
