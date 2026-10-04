//! Exact-target descriptor publication before exclusive MM-owner admission.
//!
//! When guest EL1 owns a target MM's live descriptors, the host may not edit
//! them; a foreign writer (process_vm_writev, ptrace POKE) instead submits an
//! owned descriptor transaction and has EL1 apply it. The target is paused,
//! so none of its own threads can pass EL1 to drain it: the runtime lends the
//! CALLER's vCPU for this mutation scope, and the host-driven drain call runs
//! on it with the target's TTBR0 installed for exactly the call (EL1's COW
//! copy window and ASID maintenance address the live graph that TTBR0 names).
//! EL1 still claims only a published MM (`AddressSpaces::find(mm_key)`), and
//! refuses a transaction whose root is not the drained root; the host
//! authenticates the target's binding against its own `Stage1Authority`
//! before submitting, and settles every receipt against that authority.

use super::*;
use carrick_aarch64::descriptor_drain::GuestPublishError;
use carrick_mmu_core::aarch64::descriptor_txn::{
    DescriptorReceipt, DescriptorTxn, VerifiedDescriptorReceipt,
};

const TTBR_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// A lent caller vCPU bound to one authenticated target MM.
pub(crate) struct ForeignEl1Publisher<'a> {
    _legacy: carrick_guest_mem::LegacyProtectionRead<'a>,
    caller: &'a mut dyn carrick_guest_mem::CallerEl1Call,
    /// The target ASID generation's admission for the borrowed-TTBR0
    /// windows: it lives until this publisher drops, so the target cannot
    /// finish retiring (or recycle its ASID) while a window may be open.
    admission: Box<dyn carrick_guest_mem::BorrowedTtbr0Admission>,
    tables: carrick_aarch64::Stage1Authority,
    slots: Option<&'static carrick_el1_abi::DescriptorTxnSlots>,
    mm_key: std::num::NonZeroU64,
    root: u64,
    ttbr0: u64,
}

impl<'a> ForeignEl1Publisher<'a> {
    /// Bind the lent caller vCPU to the exact target before any mutation:
    /// the target is guest-owned, a vCPU with an EL1 slot was lent, and the
    /// requested binding's root is the target authority's own live root.
    pub(crate) fn authenticate(
        invalidator: &'a mut dyn carrick_hal::ForeignMmInvalidator,
        target: &'a MmAccessState,
        mm: carrick_hal::ForeignMmId,
        binding: CarrierForeignMmBinding,
    ) -> Result<Self, carrick_hal::ForeignMmTransportError> {
        use carrick_hal::ForeignMmTransportError as Error;
        // Descriptor ownership alone does not admit host plans against an
        // exclusive MM owner. This borrow excludes owner selection until the
        // legacy publication has settled, including failure/Drop paths.
        let legacy = target
            .protections
            .legacy()
            .ok_or(Error::AuthorityUnavailable)?;
        let tables = target.page_tables_authority();
        if tables.live_descriptor_owner() != carrick_mmu_core::aarch64::LiveDescriptorOwner::Guest {
            return Err(Error::AuthorityUnavailable);
        }
        let mm_key = std::num::NonZeroU64::new(mm.raw_for_probe()).ok_or(Error::MissingBinding)?;
        let root = binding.stage1_root.raw();
        let live_root = tables
            .with_manager(|manager| manager.base())
            .ok_or(Error::AuthorityUnavailable)?;
        if root & !TTBR_BADDR_MASK != 0 || live_root != root {
            return Err(Error::MissingBinding);
        }
        // Refused (no mutation yet) when the target generation is retiring.
        let admission = invalidator.admit_borrowed_ttbr0(
            carrick_hal::ForeignMmBinding::for_aarch64(binding.asid, binding.stage1_root),
        )?;
        let caller = invalidator
            .caller_el1_call()
            .ok_or(Error::AuthorityUnavailable)?;
        if caller.slot().is_none() {
            return Err(Error::AuthorityUnavailable);
        }
        let ttbr0 = root | (u64::from(binding.asid.raw_for_probe()) << 48);
        Ok(Self {
            _legacy: legacy,
            caller,
            admission,
            tables,
            slots: target.descriptor_txn_slots(),
            mm_key,
            root,
            ttbr0,
        })
    }

    /// Apply one prepared transaction of the bound target through EL1 and
    /// return its verified receipt. A transaction of another MM or root is
    /// refused before submission.
    pub(crate) fn publish(
        &mut self,
        txn: &DescriptorTxn,
    ) -> Result<VerifiedDescriptorReceipt, GuestPublishError> {
        if txn.id.mm_key != self.mm_key || txn.root.raw() != self.root {
            return Err(TrapError::Hypervisor(
                "foreign descriptor transaction names another target".to_owned(),
            )
            .into());
        }
        let slots = self
            .slots
            .ok_or_else(|| TrapError::Hypervisor("foreign descriptor slots absent".to_owned()))?;
        carrick_aarch64::descriptor_drain::apply_guest_descriptor_txns_now(self, slots, &[*txn])?
            .pop()
            .ok_or_else(|| {
                TrapError::Hypervisor("foreign descriptor receipt absent".to_owned()).into()
            })
    }
}

impl carrick_aarch64::descriptor_drain::GuestDrainVenue for ForeignEl1Publisher<'_> {
    fn slot(&self) -> Option<usize> {
        self.caller.slot()
    }

    /// The TTBR0 the drain installs: the authenticated target's, never the
    /// caller vCPU's own.
    fn live_ttbr0(&mut self) -> Result<u64, TrapError> {
        Ok(self.ttbr0)
    }

    fn drain_call(
        &mut self,
        frame: carrick_el1_abi::TrapFrame,
    ) -> Result<carrick_el1_abi::TrapFrame, TrapError> {
        if frame.x[carrick_el1_abi::DESCRIPTOR_DRAIN_MM] != self.mm_key.get()
            || frame.x[carrick_el1_abi::DESCRIPTOR_DRAIN_TTBR0] != self.ttbr0
        {
            return Err(TrapError::Hypervisor(
                "foreign drain frame names another target".to_owned(),
            ));
        }
        let answer = self
            .caller
            .drain_foreign(self.mm_key.get(), self.ttbr0, &mut *self.admission)
            .map_err(|error| TrapError::Hypervisor(format!("foreign EL1 drain: {error}")))?;
        let mut answered = frame;
        answered.x[0] = answer;
        Ok(answered)
    }

    fn settle(
        &mut self,
        txn: &DescriptorTxn,
        receipt: &DescriptorReceipt,
    ) -> Result<VerifiedDescriptorReceipt, GuestPublishError> {
        self.tables
            .settle_guest_descriptor_receipt(txn, receipt)
            .map_err(|error| GuestPublishError::from_settle(error, "settle foreign descriptor"))
    }
}

/// Stage-1 services for a foreign sparse publication: host edits flushed by
/// the exact-target invalidator, or EL1 publication through the lent vCPU.
pub(crate) enum ForeignStage1Services<'a> {
    Host {
        _legacy: carrick_guest_mem::LegacyProtectionRead<'a>,
        invalidator: &'a mut dyn carrick_hal::ForeignMmInvalidator,
        binding: carrick_hal::ForeignMmBinding,
        deadline: std::time::Instant,
    },
    Guest(ForeignEl1Publisher<'a>),
}

impl<'a> ForeignStage1Services<'a> {
    /// Select the target's lane; a guest-owned target without a lent vCPU
    /// (or with a binding that is not its own) refuses before any mutation.
    pub(crate) fn for_target(
        invalidator: &'a mut dyn carrick_hal::ForeignMmInvalidator,
        target: &'a MmAccessState,
        requested: &CarrierForeignMmSnapshot,
        deadline: std::time::Instant,
    ) -> Result<Self, carrick_hal::ForeignMmTransportError> {
        // An admitted target requires UserTransfer, not either descriptor
        // editor. Refusal does not select the host arm.
        let legacy = target
            .protections
            .legacy()
            .ok_or(carrick_hal::ForeignMmTransportError::AuthorityUnavailable)?;
        if target.page_tables_authority().live_descriptor_owner()
            == carrick_mmu_core::aarch64::LiveDescriptorOwner::Guest
        {
            return ForeignEl1Publisher::authenticate(
                invalidator,
                target,
                requested.mm,
                requested.binding,
            )
            .map(Self::Guest);
        }
        Ok(Self::Host {
            _legacy: legacy,
            invalidator,
            binding: carrick_hal::ForeignMmSnapshot::binding(requested),
            deadline,
        })
    }
}

impl carrick_aarch64::vmm::Stage1Services for ForeignStage1Services<'_> {
    fn flush(&mut self) -> Result<(), TrapError> {
        match self {
            Self::Host {
                invalidator,
                binding,
                deadline,
                ..
            } => invalidator
                .invalidate_exact_asid(*binding, *deadline)
                .map_err(|error| TrapError::Hypervisor(format!("foreign sparse TLBI: {error:?}"))),
            Self::Guest(_) => Err(TrapError::Hypervisor(
                "guest-owned foreign publication has no host flush".to_owned(),
            )),
        }
    }

    fn guest_publication_available(&self) -> bool {
        matches!(self, Self::Guest(_))
    }

    fn publish(
        &mut self,
        txn: &DescriptorTxn,
    ) -> Result<VerifiedDescriptorReceipt, GuestPublishError> {
        match self {
            Self::Guest(publisher) => publisher.publish(txn),
            Self::Host { .. } => Err(TrapError::Hypervisor(
                "host-owned foreign MM has no guest publication".to_owned(),
            )
            .into()),
        }
    }
}
