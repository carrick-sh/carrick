//! Physical custody service for CPL0-selected anonymous windows. No host VMA
//! selection or live descriptor store occurs at this boundary.
use super::*;
use carrick_el1_abi::{MmPortalSlots, PortalGrantWindow};
use carrick_mmu_core::aarch64::descriptor_txn::{
    DescriptorOp as WireOp, DescriptorTxn as WireTxn, TableGrants,
};
use carrick_mmu_core::aarch64::{GuestLeafPublication, SubstrateGpa};
use carrick_mmu_core::x86::owner_mmu::X86Mmu;

#[derive(Clone, Copy)]
struct GrantExecution {
    cpu: carrick_guest_arch::CpuId,
    binding: carrick_el1_abi::ExecutionBinding,
    context: AddressContext<RootGpa>,
}
impl GrantExecution {
    fn matches(self, current: Self) -> bool {
        self.cpu == current.cpu
            && self.binding == current.binding
            && self.context == current.context
    }
}

fn reserve_table_stock(stock: &mut Vec<RootGpa>) -> Vec<RootGpa> {
    let count = stock
        .len()
        .min(carrick_mmu_core::aarch64::descriptor_txn::MAX_TABLE_GRANTS);
    stock.drain(..count).collect()
}

pub(super) struct PendingGrant {
    window: PortalGrantWindow,
    txn: WireTxn,
    inventory: InitialInventory,
    handle: BackingHandle,
    execution: GrantExecution,
    tables: Vec<RootGpa>,
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
        let carrier = self._vm.identity().nonzero();
        if !self.grant_portal()?.bind_carrier(carrier) {
            return Err(fail("carrier portal already bound"));
        }
        Ok(())
    }

    pub(super) fn service_anonymous_grant(
        &mut self,
        cpu: carrick_guest_arch::CpuId,
    ) -> Result<(), TrapError> {
        let index = cpu.raw() as usize;
        let lane = self
            .cpus
            .get(index)
            .ok_or_else(|| fail("owner grant CPU slot"))?;
        if lane.get_gpr(X86Reg::Rax)? != u64::from(cpu.raw()) {
            return Err(fail("owner grant CPU identity"));
        }
        let task = self.task(index);
        let binding = carrick_core::entry::binding(&task.execution, &task.mm);
        let mm = NonZeroU64::new(binding.mm.raw()).ok_or_else(|| fail("owner grant MM"))?;
        let context = self._vm.root(mm).ok_or_else(|| fail("owner grant root"))?;
        if !binding.issued()
            || binding.thread_generation.raw() == 0
            || context.mm.raw() != mm
            || lane.get_gpr(X86Reg::Cr3)? != context.root.address().raw()
        {
            return Err(fail("owner grant inactive execution/root"));
        }
        let execution = GrantExecution {
            cpu,
            binding,
            context,
        };
        if let Some(pending) = &self.anonymous_pending[index]
            && !pending.execution.matches(execution)
        {
            return Err(fail("owner grant stale execution/root"));
        }
        if let Some(mut pending) = self.anonymous_pending[index].take() {
            let receipt = self
                .grant_portal()?
                .grant(index)
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
            self.grant_tables.extend(pending.tables.drain(used..));
            // Retained stage-2 custody now belongs to the live guest graph.
            let _retained = pending.handle;
            return Ok(());
        }
        let far = self.cpus[index].get_gpr(X86Reg::Cr2)?;
        let (_, window) = self
            .grant_portal()?
            .grant(index)
            .ok_or_else(|| fail("owner grant slot"))?
            .pending_fault_selection(mm.get(), far)
            .ok_or_else(|| fail("owner fault selection absent"))?;
        if self.grant_portal()?.carrier() != Some(window.operation.carrier)
            || window.host_backing.is_some()
            || window.range.len() > carrick_el1_abi::EL1_FRAME_GRANT_TARGET_SIZE
        {
            return Err(fail("owner grant selection identity"));
        }
        let root = context.root;
        let gpa = self.anonymous_next_gpa;
        let len = window.range.len();
        self.anonymous_next_gpa = FrameGpa::new(
            gpa.raw()
                .checked_add(len)
                .ok_or_else(|| fail("owner grant GPA exhausted"))?,
        );
        let (mut inventory, grants) = InitialInventory::stage(
            Arc::clone(&self.frame_inventory),
            &self.object_ids,
            [gpa],
            0,
            len,
            // A newly allocated physical mapping starts at generation one;
            // the guest operation sequence belongs to the descriptor txn.
            NonZeroU64::MIN,
            MmId::from_raw_u64(mm.get()).ok_or_else(|| fail("owner inventory MM"))?,
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
        let owned_tables = reserve_table_stock(&mut self.grant_tables);
        let tables: Vec<_> = owned_tables
            .iter()
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
                    writable: window
                        .protection
                        .permits(carrick_el1_abi::ReservationProtection::WRITE),
                    executable: window
                        .protection
                        .permits(carrick_el1_abi::ReservationProtection::EXECUTE),
                },
                resident: PageSpan::new(window.fault_page, 4096),
                backing: identity,
            },
            tables: TableGrants::new(&tables).ok_or_else(|| fail("owner table grant encoding"))?,
        };
        let admission = X86Mmu::project_grant(root.address().raw(), &txn, |native| {
            self._vm.admit_guest_edit(native)
        });
        if !matches!(admission, Ok(Ok(())))
            || !self
                .grant_portal()?
                .grant(index)
                .ok_or_else(|| fail("owner grant slot"))?
                .submit(window, &txn)
        {
            // SAFETY: the vCPU is stopped, and no descriptor submission was
            // admitted. The fresh extent has never been guest-visible.
            unsafe { self._vm.cancel_prepared(&[handle], &mut inventory) }
                .map_err(|error| fail(error.to_string()))?;
            self.grant_tables.extend(owned_tables);
            return Err(fail("owner grant admission refused"));
        }
        inventory.expected = 1;
        // Once submitted, guest descriptor publication may have happened even
        // if the carrier never receives a verifiable completion. Keep physical
        // custody through carrier teardown rather than rolling inventory back.
        inventory.guest_exposed = true;
        self.anonymous_pending[index] = Some(PendingGrant {
            window,
            txn,
            inventory,
            handle,
            execution,
            tables: owned_tables,
        });
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod custody_tests {
    use super::*;
    use carrick_el1_abi::{
        EntryGeneration, EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding,
    };
    fn execution() -> GrantExecution {
        GrantExecution {
            cpu: carrick_guest_arch::CpuId::new(1),
            binding: ExecutionBinding {
                task: EntryTaskKey::from_raw(42),
                generation: EntryGeneration::from_raw(12),
                mm: EntryMmKey::from_raw(302),
                thread_generation: EntryThreadGeneration::from_raw(102),
            },
            context: AddressContext {
                root: RootGpa::page_aligned(FrameGpa::new(0x7000)).unwrap(),
                mm: MmGeneration::new(NonZeroU64::new(302).unwrap()),
                generation: ContextGeneration::new(NonZeroU64::new(17).unwrap()),
            },
        }
    }
    #[test]
    fn owner_grant_receipt_refuses_recycled_execution_or_root() {
        let admitted = execution();
        assert!(admitted.matches(admitted));
        let mut foreign = admitted;
        foreign.binding.task = EntryTaskKey::from_raw(43);
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.binding.generation = EntryGeneration::from_raw(13);
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.binding.mm = EntryMmKey::from_raw(303);
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.binding.thread_generation = EntryThreadGeneration::from_raw(103);
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.cpu = carrick_guest_arch::CpuId::new(0);
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.context.root = RootGpa::page_aligned(FrameGpa::new(0x8000)).unwrap();
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.context.generation = ContextGeneration::new(NonZeroU64::new(18).unwrap());
        assert!(!admitted.matches(foreign));
        let mut foreign = admitted;
        foreign.context.mm = MmGeneration::new(NonZeroU64::new(303).unwrap());
        assert!(!admitted.matches(foreign));
    }
    #[test]
    fn owner_grants_reserve_disjoint_table_stock_before_receipt() {
        let mut stock: Vec<_> = (1..=32)
            .map(|n| RootGpa::page_aligned(FrameGpa::new(n * 4096)).unwrap())
            .collect();
        let first = reserve_table_stock(&mut stock);
        let second = reserve_table_stock(&mut stock);
        assert!(!first.is_empty());
        assert!(first.iter().all(|frame| !second.contains(frame)));
    }
}
