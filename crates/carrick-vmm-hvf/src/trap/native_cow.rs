//! Physical stock and completion custody for native guest MM COW.
//! Guest descriptor edits stay in the shared CowGrantPool protocol.

use super::CarrierVmCustody;
use super::TrapError;
use super::carrier_custody::CarrierStage2Pin;
use carrick_guest_arch::{FrameGpa, UserVa};
use core::ops::Deref;
use core::ptr::NonNull;
use std::sync::Arc;

/// Only initialized atomic ABI records in the retained kernel region can be
/// borrowed through this aperture. The physical address belongs to the type.
trait ControlRecord {
    const GPA: FrameGpa;
}
impl ControlRecord for carrick_el1_abi::CowGrantPool {
    const GPA: FrameGpa = FrameGpa::new(carrick_el1_abi::EL1_COW_GRANT_POOL_BASE);
}
impl ControlRecord for carrick_el1_abi::FrameGrantResidencyTable {
    const GPA: FrameGpa = FrameGpa::new(carrick_el1_abi::EL1_FRAME_GRANT_RESIDENCY_BASE);
}
impl ControlRecord for carrick_el1_abi::MmPortalSlots {
    const GPA: FrameGpa = FrameGpa::new(carrick_el1_abi::EL1_MM_PORTAL_BASE);
}
impl ControlRecord for carrick_el1_abi::ZoneTables {
    const GPA: FrameGpa = FrameGpa::new(carrick_el1_abi::EL1_ZONE_BASE);
}

struct RetainedControl<T: ControlRecord> {
    pointer: NonNull<T>,
    _pin: CarrierStage2Pin,
}
impl<T: ControlRecord> RetainedControl<T> {
    fn new(custody: &Arc<CarrierVmCustody>) -> Result<Self, TrapError> {
        let fail = || TrapError::Hypervisor("native COW control record lacks live custody".into());
        let identity = custody
            .stage2_record_covering(T::GPA.raw(), core::mem::size_of::<T>())
            .ok_or_else(fail)?;
        let pin = custody.pin_stage2_record(identity).map_err(|_| fail())?;
        let snapshot = custody
            .stage2_record_snapshot(identity.record_id)
            .filter(|snapshot| {
                snapshot.mapped
                    && snapshot.vm_generation == identity.vm_generation
                    && snapshot.logical_owner == identity.logical_owner
            })
            .ok_or_else(fail)?;
        let offset = usize::try_from(T::GPA.raw().checked_sub(snapshot.ipa).ok_or_else(fail)?)
            .map_err(|_| fail())?;
        let host = snapshot
            .host_addr
            .checked_add(offset)
            .filter(|host| *host != 0 && host.is_multiple_of(core::mem::align_of::<T>()))
            .ok_or_else(fail)?;
        let pointer = NonNull::new(host as *mut T).ok_or_else(fail)?;
        Ok(Self { pointer, _pin: pin })
    }
}
impl<T: ControlRecord> Deref for RetainedControl<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the type names a fixed initialized atomic kernel ABI record.
        // Construction checked full physical coverage and alignment. The exact
        // pin remains owned by this borrow, excluding backing retirement.
        unsafe { self.pointer.as_ref() }
    }
}

/// Authenticate a selected native COW source without a host MM row.
pub(crate) fn selected_source(
    custody: &Arc<CarrierVmCustody>,
    execution: crate::fork_stock::GrantExecution,
    fault: UserVa,
) -> Result<carrick_hal::PhysicalMappingRow, TrapError> {
    use super::native_frame_custody::{NativeRootWords, selected_row};
    let fail = || TrapError::Hypervisor("native COW source custody mismatch".into());
    let source = custody.admit_native_frame_execution(execution)?;
    let run = carrick_mmu_core::aarch64::descriptor_txn::guest_cow::classify_guest_cow_write(
        &NativeRootWords { custody },
        carrick_mmu_core::aarch64::SubstrateGpa(execution.context.root.address().raw()),
        fault.raw(),
        false,
    )
    .map_err(|_| fail())?;
    let row = {
        let stock = custody.fork_stock.lock();
        let frames = stock.root_frames(execution.context).ok_or_else(fail)?;
        selected_row(
            frames,
            carrick_guest_arch::FrameGpa::new(run.old_ipa.0),
            run.len,
        )
        .map_err(|_| fail())?
    };
    if source
        .bind(execution.context.into())
        .live_mapping_row(row.mapping)
        != Some(row)
    {
        return Err(fail());
    }
    let residency = RetainedControl::<carrick_el1_abi::FrameGrantResidencyTable>::new(custody)?;
    for offset in (0..run.len).step_by(4096) {
        let physical = run.old_ipa.0 + offset;
        let identity = custody
            .stage2_record_covering(physical, 4096)
            .ok_or_else(fail)?;
        let owner = identity
            .logical_owner
            .filter(|owner| owner.generation != 0)
            .ok_or_else(fail)?;
        let page = residency
            .lookup(execution.context.mm.raw().get(), run.va + offset)
            .ok_or_else(fail)?;
        if page.expected_ipa != physical
            || page.identity.frame_id != row.frame.raw()
            || page.identity.mapping_id != row.mapping.raw()
            || page.identity.owner_generation != owner.generation
            || !residency.is_guest_committed(execution.context.mm.raw().get(), run.va + offset)
        {
            return Err(fail());
        }
    }
    Ok(row)
}

/// The physical stock exposed to one stopped CPU. Completion retains this
/// receipt until the guest projection and exact source removal are verified.
pub(crate) struct PendingNativeCow {
    execution: crate::fork_stock::GrantExecution,
    window: carrick_el1_abi::PortalGrantWindow,
    source: carrick_hal::PhysicalMappingRow,
    run: carrick_mmu_core::aarch64::descriptor_txn::guest_cow::GuestCowRun,
    source_records: Vec<super::CarrierStage2RecordIdentity>,
    grant: carrick_el1_abi::CowGrant,
    replacement: carrick_hal::PhysicalMappingRow,
    receipt: carrick_hal::UnpublishedFrameInventoryApply<dyn carrick_hal::FrameCowAuthority>,
}
impl core::fmt::Debug for PendingNativeCow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingNativeCow")
            .field("execution", &self.execution)
            .field("grant", &self.grant)
            .finish_non_exhaustive()
    }
}

fn failure(reason: &str) -> TrapError {
    TrapError::Hypervisor(format!("native COW: {reason}"))
}

pub(crate) fn supply(
    custody: &Arc<CarrierVmCustody>,
    execution: crate::fork_stock::GrantExecution,
    fault: UserVa,
) -> Result<(), TrapError> {
    use carrick_sched_core::spaces::notification::{
        SpaceAccess, SpaceReleaseVenue, SpaceWakeDelivery,
    };
    use core::num::NonZeroU64;
    let scope = carrick_el1_abi::CowGrantScope::checked(execution.binding, execution.context)
        .ok_or_else(|| failure("execution scope"))?;
    let index = execution.cpu.raw() as usize;
    if index >= carrick_el1_abi::EL1_STACK_SLOTS as usize {
        return Err(failure("CPU index"));
    }
    let mut pending = custody.native_cow_pending[index].lock();
    if pending.is_some() {
        return Err(failure("pending stock already exposed"));
    }
    let portal = RetainedControl::<carrick_el1_abi::MmPortalSlots>::new(custody)?;
    let slot = portal.grant(index).ok_or_else(|| failure("portal slot"))?;
    let (_, window) = slot
        .pending_cow_fault_selection(execution.context.mm.raw().get(), fault.raw())
        .ok_or_else(|| failure("COW selection absent"))?;
    if !window.valid()
        || portal.carrier() != Some(window.operation.carrier)
        || window.operation.mm.raw() != execution.context.mm.raw().get()
        || window.range.len() != 4096
        || window.range.start() != window.fault_page
        || window.host_backing.is_some()
    {
        return Err(failure("selection identity"));
    }
    let zone = RetainedControl::<carrick_el1_abi::ZoneTables>::new(custody)?;
    let wake = custody
        .native_space_completion
        .lock()
        .clone()
        .ok_or_else(|| failure("space completion venue absent"))?;
    let deliver = |zone: &carrick_el1_abi::ZoneTables,
                   _: carrick_sched_core::Waker,
                   effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
        '_,
        carrick_el1_abi::ZoneContext,
    >| wake.complete(zone, effects);
    let access = SpaceAccess::notified(SpaceReleaseVenue {
        zone: &zone,
        waker: carrick_sched_core::Waker::Host,
        deliver: SpaceWakeDelivery::Captured(&deliver),
    });
    let mm = execution.context.mm.raw().get();
    let space = access
        .table()
        .find(mm)
        .ok_or_else(|| failure("space absent"))?;
    let _pause = access
        .try_exclude_editor(space, mm)
        .map_err(|_| failure("editor exclusion"))?;
    let source_row = selected_source(custody, execution, fault)?;
    let run = carrick_mmu_core::aarch64::descriptor_txn::guest_cow::classify_guest_cow_write(
        &super::native_frame_custody::NativeRootWords { custody },
        carrick_mmu_core::aarch64::SubstrateGpa(execution.context.root.address().raw()),
        fault.raw(),
        false,
    )
    .map_err(|_| failure("source changed under editor exclusion"))?;
    let source_records = (0..run.len)
        .step_by(4096)
        .map(|offset| {
            custody
                .stage2_record_covering(run.old_ipa.0 + offset, 4096)
                .ok_or_else(|| failure("source physical custody"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let source = custody.admit_native_frame_execution(execution)?;
    let authority = source.bind(execution.context.into());
    let pool = RetainedControl::<carrick_el1_abi::CowGrantPool>::new(custody)?;
    let (_, physical, owner_generation) = super::guest_cow::allocate_grant_compound(
        custody,
        applevisor::memory::MemPerms::ReadWriteExec,
    )?;
    let mut physical_rollback =
        super::execve_rebuild::GlobalFrameOwnerRollback::new(Arc::clone(custody));
    physical_rollback.record((physical, carrick_el1_abi::COW_GRANT_SIZE));
    let mut reservation = authority
        .reserve(1, 1, 2)
        .map_err(|_| failure("inventory reservation"))?;
    let frame = reservation
        .claim_frame()
        .map_err(|_| failure("frame identity"))?;
    let mapping = reservation
        .claim_mapping()
        .map_err(|_| failure("mapping identity"))?;
    let generation = carrick_hal::MappingGeneration::from_backend_counter(NonZeroU64::MIN);
    let transaction = reservation.transaction();
    reservation
        .push(carrick_hal::FrameInventoryEvent::PrepareMapping {
            transaction,
            frame,
            mapping,
            generation,
            gpa: carrick_guest_mem::Gpa(physical),
            length: carrick_hal::FrameLength::from_mapping_extent(
                NonZeroU64::new(carrick_el1_abi::COW_GRANT_SIZE)
                    .ok_or_else(|| failure("extent"))?,
            ),
            permissions: carrick_hal::MemPerms {
                read: true,
                write: true,
                exec: true,
            },
        })
        .map_err(|_| failure("prepare inventory row"))?;
    reservation
        .push(carrick_hal::FrameInventoryEvent::PublishMapping {
            transaction,
            mapping,
            generation,
        })
        .map_err(|_| failure("publish inventory row"))?;
    let mut receipt =
        carrick_hal::UnpublishedFrameInventoryApply::apply(authority, reservation.commit(()))
            .map_err(|_| failure("inventory publication"))?;
    let backing = carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity {
        frame_id: NonZeroU64::new(frame.raw()).ok_or_else(|| failure("frame identity"))?,
        mapping_id: NonZeroU64::new(mapping.raw()).ok_or_else(|| failure("mapping identity"))?,
        owner_generation: NonZeroU64::new(owner_generation)
            .ok_or_else(|| failure("physical owner"))?,
        inventory_revision: NonZeroU64::new(receipt.revision())
            .ok_or_else(|| failure("inventory revision"))?,
    };
    let Some(grant) = pool.publish(scope, physical, backing) else {
        if receipt.rollback().is_err() {
            physical_rollback.commit();
            return Err(failure("unexposed inventory rollback"));
        }
        return Err(failure("COW pool capacity"));
    };
    // Publication permits guest consumption: all subsequent failures retain
    // the stock in the pending slot and carrier inventory, never free it.
    physical_rollback.commit();
    custody.host_cow_ledger.record_guest_cow_provisioned(1);
    *pending = Some(PendingNativeCow {
        execution,
        window,
        source: source_row,
        run,
        source_records,
        grant,
        receipt,
        replacement: carrick_hal::PhysicalMappingRow {
            frame,
            mapping,
            generation,
            gpa: carrick_guest_mem::Gpa(physical),
            length: carrick_hal::FrameLength::from_mapping_extent(
                NonZeroU64::new(carrick_el1_abi::COW_GRANT_SIZE)
                    .ok_or_else(|| failure("extent"))?,
            ),
            permissions: carrick_hal::MemPerms {
                read: true,
                write: true,
                exec: true,
            },
        },
    });
    if !slot.take_cow_fault_selection(window) {
        return Err(failure("selection changed after stock publication"));
    }
    Ok(())
}

pub(crate) fn settle(
    custody: &Arc<CarrierVmCustody>,
    execution: crate::fork_stock::GrantExecution,
    fault: UserVa,
) -> Result<(), TrapError> {
    use carrick_mmu_core::aarch64::descriptor_txn::{
        CowRepointAccess, DescriptorOp, DescriptorTxn, DescriptorTxnId, TableGrants,
    };
    use carrick_mmu_core::aarch64::{LeafAccess, SubstrateGpa, terminal_descriptor_permits_el0};
    use carrick_sched_core::spaces::notification::{
        SpaceAccess, SpaceReleaseVenue, SpaceWakeDelivery,
    };
    use core::num::NonZeroU64;
    let slot = custody
        .native_cow_pending
        .get(execution.cpu.raw() as usize)
        .ok_or_else(|| failure("CPU index"))?;
    let mut pending_slot = slot.lock();
    let pending = pending_slot
        .as_ref()
        .filter(|pending| {
            pending.execution.matches(execution) && pending.window.fault_page == fault.raw() & !4095
        })
        .ok_or_else(|| failure("pending execution/root mismatch"))?;
    let source = custody.admit_native_frame_execution(execution)?;
    let authority = source.bind(execution.context.into());
    if authority.live_mapping_row(pending.source.mapping) != Some(pending.source)
        || authority.live_mapping_row(pending.replacement.mapping) != Some(pending.replacement)
        || !pending
            .receipt
            .authorizes(pending.replacement.mapping, pending.replacement.frame)
    {
        return Err(failure("pending canonical custody changed"));
    }
    let zone = RetainedControl::<carrick_el1_abi::ZoneTables>::new(custody)?;
    let wake = custody
        .native_space_completion
        .lock()
        .clone()
        .ok_or_else(|| failure("space completion venue absent"))?;
    let deliver = |zone: &carrick_el1_abi::ZoneTables,
                   _: carrick_sched_core::Waker,
                   effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
        '_,
        carrick_el1_abi::ZoneContext,
    >| wake.complete(zone, effects);
    let access = SpaceAccess::notified(SpaceReleaseVenue {
        zone: &zone,
        waker: carrick_sched_core::Waker::Host,
        deliver: SpaceWakeDelivery::Captured(&deliver),
    });
    let mm = execution.context.mm.raw().get();
    let space = access
        .table()
        .find(mm)
        .ok_or_else(|| failure("space absent"))?;
    let pause = access
        .try_exclude_editor(space, mm)
        .map_err(|_| failure("editor exclusion"))?;
    let pool = RetainedControl::<carrick_el1_abi::CowGrantPool>::new(custody)?;
    let scope = carrick_el1_abi::CowGrantScope::checked(execution.binding, execution.context)
        .ok_or_else(|| failure("completion scope"))?;
    if !pool.authenticates_scope(&pending.grant, scope) {
        return Err(failure("original stock audience changed"));
    }
    for (offset, expected) in (0..pending.run.len)
        .step_by(4096)
        .zip(&pending.source_records)
    {
        if custody.stage2_record_covering(pending.run.old_ipa.0 + offset, 4096) != Some(*expected) {
            return Err(failure("source physical owner changed"));
        }
    }
    let completion = pool
        .completions(pause.proof())
        .find(|completion| completion.grant == pending.grant)
        .filter(|completion| {
            completion.is_well_formed()
                && completion.purpose == carrick_el1_abi::CowGrantPurpose::UserWrite
                && completion.span_va == pending.run.va
                && completion.span_len == pending.run.len
                && completion.old_ipa == pending.run.old_ipa.0
                && completion.span_va <= pending.window.fault_page
                && pending.window.fault_page < completion.span_va + completion.span_len
                && completion.new_ipa
                    == pending.grant.physical_ipa
                        + (pending.run.old_ipa.0 & (carrick_el1_abi::COW_GRANT_SIZE - 1))
        })
        .ok_or_else(|| failure("exact completion absent"))?;
    let replacement_owner = custody
        .stage2_record_covering(
            pending.grant.physical_ipa,
            carrick_el1_abi::COW_GRANT_SIZE as usize,
        )
        .and_then(|record| record.logical_owner)
        .filter(|owner| owner.generation == pending.grant.backing.owner_generation.get())
        .ok_or_else(|| failure("replacement physical owner changed"))?;
    let residency = RetainedControl::<carrick_el1_abi::FrameGrantResidencyTable>::new(custody)?;
    let words = super::native_frame_custody::NativeRootWords { custody };
    for offset in (0..completion.span_len).step_by(4096) {
        let va = completion.span_va + offset;
        let (output, leaf) =
            super::native_frame_custody::retained_leaf(&words, execution.context.root, va)
                .map_err(|_| failure("live replacement leaf"))?;
        let page = residency
            .lookup(mm, va)
            .ok_or_else(|| failure("replacement residency absent"))?;
        if output.raw() != completion.new_ipa + offset
            || !terminal_descriptor_permits_el0(leaf, LeafAccess::Write)
            || carrick_mmu_core::aarch64::terminal_descriptor_is_fork_cow(leaf)
            || carrick_mmu_core::aarch64::el1_private_leaf_state(leaf)
                != carrick_mmu_core::aarch64::El1PrivateLeafState::Resident
            || page.expected_ipa != output.raw()
            || page.identity.frame_id != pending.replacement.frame.raw()
            || page.identity.mapping_id != pending.replacement.mapping.raw()
            || page.identity.owner_generation != replacement_owner.generation
            || page.identity.inventory_revision != pending.receipt.revision()
            || !residency.is_guest_committed(mm, va)
        {
            return Err(failure("live replacement projection mismatch"));
        }
    }
    let txn = DescriptorTxn {
        id: DescriptorTxnId {
            mm_key: execution.context.mm.raw(),
            generation: NonZeroU64::new(pending.grant.epoch)
                .ok_or_else(|| failure("grant epoch"))?,
        },
        root: SubstrateGpa(execution.context.root.address().raw()),
        op: DescriptorOp::CowRepoint {
            access: CowRepointAccess::RecordedPrivate,
            va: completion.span_va,
            len: completion.span_len,
            old_ipa: SubstrateGpa(completion.old_ipa),
            new_ipa: SubstrateGpa(completion.new_ipa),
            backing: completion.grant.backing,
        },
        tables: TableGrants::NONE,
    };
    let _publication = carrick_el1_abi::GuestMmuPublication::from_aarch64_cow_completion(
        &txn,
        &completion,
        (completion.span_len / 4096) as u32,
    )
    .ok_or_else(|| failure("COW publication identity"))?;
    // Mirror InitialInventory::finish on x86: a successful guest projection
    // commits the exposed replacement receipt. Keep the containing source
    // row in MM custody until shared retirement; unchanged pages still name
    // it and their residency identities must not be rewritten speculatively.
    custody
        .fork_stock
        .lock()
        .publish_native_cow_frame(
            execution.context,
            pending.source,
            pending.replacement,
            NonZeroU64::new(pending.receipt.revision())
                .ok_or_else(|| failure("inventory revision"))?,
        )
        .map_err(|_| failure("root projection publication"))?;
    if !pool.finish(pause.proof(), &pending.grant) {
        return Err(failure("completion changed after inventory settlement"));
    }
    custody.host_cow_ledger.record_guest_cow_settled();
    *pending_slot = None;
    Ok(())
}
