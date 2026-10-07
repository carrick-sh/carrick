//! Physical custody service for CPL0-selected anonymous windows. No host VMA
//! selection or live descriptor store occurs at this boundary.
use super::*;
use carrick_el1_abi::{MmPortalSlots, PortalGrantWindow};
use carrick_mmu_core::aarch64::descriptor_txn::{
    DescriptorOp as WireOp, DescriptorTxn as WireTxn, TableGrants,
};
use carrick_mmu_core::aarch64::{GuestLeafPublication, SubstrateGpa};
use carrick_mmu_core::x86::owner_mmu::X86Mmu;

pub(super) struct PendingGrant {
    window: PortalGrantWindow,
    txn: WireTxn,
    inventory: InitialInventory,
    handle: BackingHandle,
}

impl Cpl0Carrier {
    fn grant_portal(&self) -> Result<&MmPortalSlots, TrapError> {
        // SAFETY: the boot owner zero-initializes this atomic-only record in
        // the retained supervisor kernel region before either vCPU runs.
        unsafe {
            self._vm.retained_record(FrameGpa::new(
                KERNEL_REGION_GPA + carrick_el1_abi::EL1_MM_PORTAL_OFFSET,
            ))
        }
        .map_err(|error| fail(error.to_string()))
    }

    pub(super) fn bind_grant_portal(&self) -> Result<(), TrapError> {
        static CARRIERS: AtomicU64 = AtomicU64::new(1);
        let carrier = CARRIERS
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| fail("carrier identity exhausted"))?;
        let carrier = NonZeroU64::new(carrier).ok_or_else(|| fail("zero carrier identity"))?;
        if !self.grant_portal()?.bind_carrier(carrier) {
            return Err(fail("carrier portal already bound"));
        }
        Ok(())
    }

    pub(super) fn service_anonymous_grant(&mut self) -> Result<(), TrapError> {
        if self.cpus[0].get_gpr(X86Reg::Rax)? != 0 {
            return Err(fail("owner grant CPU slot"));
        }
        let mm = NonZeroU64::new(INITIAL_MM_KEY).ok_or_else(|| fail("owner grant MM"))?;
        if let Some(mut pending) = self.anonymous_pending.take() {
            let receipt = self
                .grant_portal()?
                .grant(0)
                .ok_or_else(|| fail("owner grant slot"))?
                .take_receipt(pending.window, &pending.txn)
                .ok_or_else(|| fail("owner grant receipt absent"))?;
            let publication = GuestMmuPublication::from_x86_owner_grant(&pending.txn, &receipt)
                .ok_or_else(|| fail(format!("owner grant refused: {:?}", receipt.outcome)))?;
            X86Mmu::project_grant(pending.txn.root.raw(), &pending.txn, |native| {
                self._vm
                    .publish(native, publication, &mut pending.inventory)
            })
            .map_err(|error| fail(format!("owner grant projection: {error:?}")))?
            .map_err(|error| fail(error.to_string()))?;
            pending.inventory.finish()?;
            self.anonymous_private_pages = self
                .anonymous_private_pages
                .checked_add(pending.window.range.len() / 4096)
                .ok_or_else(|| fail("owner grant witness overflow"))?;
            let used = publication.tables_linked as usize;
            if used > pending.txn.tables.len() {
                return Err(fail("owner grant table receipt"));
            }
            self.grant_tables.drain(..used);
            // Retained stage-2 custody now belongs to the live guest graph.
            let _retained = pending.handle;
            return Ok(());
        }
        let far = self.cpus[0].get_gpr(X86Reg::Cr2)?;
        let (_, window) = self
            .grant_portal()?
            .grant(0)
            .ok_or_else(|| fail("owner grant slot"))?
            .pending_fault_selection(mm.get(), far)
            .ok_or_else(|| fail("owner fault selection absent"))?;
        if self.grant_portal()?.carrier() != Some(window.operation.carrier)
            || window.host_backing.is_some()
            || window.range.len() > carrick_el1_abi::EL1_FRAME_GRANT_TARGET_SIZE
        {
            return Err(fail("owner grant selection identity"));
        }
        let root = self
            ._vm
            .root(mm)
            .ok_or_else(|| fail("owner grant root"))?
            .root;
        if self.cpus[0].get_gpr(X86Reg::Cr3)? != root.address().raw() {
            return Err(fail("owner grant inactive root"));
        }
        let gpa = FrameGpa::new(self.anonymous_next_gpa);
        let len = window.range.len();
        self.anonymous_next_gpa = gpa
            .raw()
            .checked_add(len)
            .ok_or_else(|| fail("owner grant GPA exhausted"))?;
        let (mut inventory, grants) = InitialInventory::stage(
            Arc::clone(&self.frame_inventory),
            &self.object_ids,
            [gpa],
            0,
            len,
            // A newly allocated physical mapping starts at generation one;
            // the guest operation sequence belongs to the descriptor txn.
            NonZeroU64::MIN,
        )?;
        let identity = inventory
            .frames
            .first()
            .ok_or_else(|| fail("owner grant backing identity"))?
            .1;
        let extent =
            BackingExtent::private(gpa, len as usize).map_err(|error| fail(error.to_string()))?;
        let handles = self
            ._vm
            .prepare(
                &[PreparedBacking {
                    extent: Arc::new(extent),
                    identity,
                }],
                &mut inventory,
            )
            .map_err(|error| fail(error.to_string()))?;
        let handle = handles[0];
        let grant = grants[0];
        let tables: Vec<_> = self
            .grant_tables
            .iter()
            .take(carrick_mmu_core::aarch64::descriptor_txn::MAX_TABLE_GRANTS)
            .map(|table| SubstrateGpa(table.address().raw()))
            .collect();
        let txn = WireTxn {
            id: DescriptorTxnId {
                mm_key: mm,
                generation: window.operation.sequence,
            },
            root: SubstrateGpa(root.address().raw()),
            op: WireOp::Prepare {
                publication: GuestLeafPublication {
                    va: window.range.start(),
                    ipa: grant.gpa,
                    len,
                    writable: window.protection.bits() & 2 != 0,
                    executable: window.protection.bits() & 4 != 0,
                },
                resident: PageSpan::new(window.fault_page, 4096),
                backing: identity,
            },
            tables: TableGrants::new(&tables).ok_or_else(|| fail("owner table grant encoding"))?,
        };
        let admission = X86Mmu::project_grant(root.address().raw(), &txn, |native| {
            self._vm.admit_guest_edit(native)
        })
        .map_err(|error| fail(format!("owner grant projection: {error:?}")))?;
        if admission.is_err()
            || !self
                .grant_portal()?
                .grant(0)
                .ok_or_else(|| fail("owner grant slot"))?
                .submit(window, &txn)
        {
            // SAFETY: the vCPU is stopped, and no descriptor submission was
            // admitted. The fresh extent has never been guest-visible.
            unsafe { self._vm.cancel_prepared(&[handle], &mut inventory) }
                .map_err(|error| fail(error.to_string()))?;
            return Err(fail("owner grant admission refused"));
        }
        inventory.expected = 1;
        // Once submitted, guest descriptor publication may have happened even
        // if the carrier never receives a verifiable completion. Keep physical
        // custody through carrier teardown rather than rolling inventory back.
        inventory.guest_exposed = true;
        self.anonymous_pending = Some(PendingGrant {
            window,
            txn,
            inventory,
            handle,
        });
        Ok(())
    }
}
