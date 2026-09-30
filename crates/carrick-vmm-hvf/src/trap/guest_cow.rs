//! Host side of guest EL1 fork COW: grant provisioning and settlement.
//!
//! On the guest-owned descriptor lane EL1 resolves a fork-COW write itself
//! with a *grant* from the carrier's [`CowGrantPool`]: a 16 KiB replacement
//! compound whose stage-2 owner, backend inventory extent and kernel
//! mapping this module made live for exactly one MM beforehand
//! ([`provision_guest_cow_grants`]). A provisioned grant is an ordinary
//! extent of the MM's inventory that no VA maps yet, so the MM's retirement
//! retires it with every other mapping and nothing ever has to roll it back.
//!
//! EL1 then copies and repoints without a host exit and records what moved.
//! Until the host *settles* that completion, the MM's inventory still says
//! the span maps the old compound. [`settle_guest_cow_completions`] folds
//! each completion into the host authorities exactly as the host COW path
//! would have after a verified `CowRepoint` receipt: the inventory split of
//! the old compound (its frame references, retained fragments, and stage-2
//! retirement when this MM held the last reference), the replacement alias,
//! and the disarm of the span.
//!
//! Ordering is a type property: settlement, like every other free of a
//! pool record, requires an [`ExcludedEditor`] for the MM, which only the
//! shared address-space table mints when the host raises (or closes) the
//! MM's gate and no EL1 editor remains. The carrier installs
//! [`CarrierGuestCowSettlement`] into that exclusion, so every host pause of
//! the MM, and every host mutation guard, settles before the host reads or
//! edits the MM's translations or frames. Other MMs sharing the old
//! compound need no settlement of this one: this MM's unsettled mapping
//! keeps the old frame referenced (never retired under a peer), and EL1
//! never wrote it.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use super::*;
use carrick_el1_abi::{CowGrantCompletion, CowGrantPool, CowGrantSettlement, ExcludedEditor};
use carrick_fatal::carrick_fatal;

/// Grants a fresh MM receives at its first empty-pool COW exit.
pub(crate) const GUEST_COW_FIRST_BATCH: usize = 2;
/// The most grants one refill provisions (and so the most an MM leaves
/// unused when it retires): 1 MiB of compounds.
pub(crate) const GUEST_COW_MAX_BATCH: usize = 64;

/// The next refill size after one of `batch`: doubling while an MM keeps
/// emptying its pool, so the exits a workload pays grow with the log of the
/// COW faults it takes, not with their number.
pub(crate) fn next_guest_cow_batch(batch: usize) -> usize {
    batch
        .saturating_mul(2)
        .clamp(GUEST_COW_FIRST_BATCH, GUEST_COW_MAX_BATCH)
}

/// Provision up to `count` grants for the MM of `state` and publish them in
/// `pool`. Returns how many were published; a full probe chain stops early
/// (the unpublished grant is rolled back). The MM must be bound to its COW
/// runtime and own the guest descriptor lane.
pub(crate) fn provision_guest_cow_grants(
    state: &MmAccessState,
    custody: &std::sync::Arc<CarrierVmCustody>,
    pool: &CowGrantPool,
    count: usize,
) -> Result<usize, TrapError> {
    let runtime =
        state.cow_runtime.read().clone().ok_or_else(|| {
            TrapError::Hypervisor("guest COW grant has no COW runtime".to_owned())
        })?;
    let mm = std::num::NonZeroU64::new(runtime.identity.mm)
        .ok_or_else(|| TrapError::Hypervisor("guest COW grant has no MM".to_owned()))?;
    if state.page_tables_authority().live_descriptor_owner()
        != carrick_mmu_core::aarch64::LiveDescriptorOwner::Guest
    {
        return Err(TrapError::Hypervisor(
            "guest COW grants serve only a guest-owned MM".to_owned(),
        ));
    }
    let stage2_perms = applevisor::memory::MemPerms::ReadWriteExec;
    let mut published = 0;
    while published < count {
        let (new_host_ptr, new_physical_ipa, owner_generation) =
            allocate_grant_compound(custody, stage2_perms)?;
        let mut owner_rollback = GlobalFrameOwnerRollback::new(std::sync::Arc::clone(custody));
        owner_rollback.record((new_physical_ipa, CowArmedRanges::COMPOUND_SIZE));
        let reservation = runtime
            .authority
            .reserve(1, 1, 2)
            .map_err(|error| TrapError::Hypervisor(format!("reserve guest COW grant: {error}")))?;
        let mut grant = super::cow_engine::GuestPreparedBacking::prepare_owned(
            std::sync::Arc::clone(custody),
            std::sync::Arc::clone(&runtime.authority),
            std::sync::Arc::clone(&state.frame_inventory.ledger),
            reservation,
            mm,
            InventoryMappingStage {
                gpa: new_physical_ipa,
                length: CowArmedRanges::COMPOUND_SIZE,
                permissions: carrick_hal::MemPerms {
                    read: true,
                    write: true,
                    exec: true,
                },
                backing: HvfVmState::private_backing_identity(),
                inherited_frame: None,
                stage2_lease: Some((new_physical_ipa, CowArmedRanges::COMPOUND_SIZE)),
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr: new_host_ptr as usize,
                    generation: owner_generation,
                },
            },
            owner_rollback,
        )?;
        let backing = grant.backing()?;
        if pool.publish(mm.get(), new_physical_ipa, backing).is_none() {
            // Dropping the armed grant rolls back the kernel mapping, the
            // inventory extent and the new owner.
            drop(grant);
            break;
        }
        // Published: the grant is now one of the MM's inventory extents.
        grant.commit();
        published += 1;
    }
    state
        .host_cow_stats
        .record_guest_cow_provisioned(published as u64);
    Ok(published)
}

impl HvfTaskState {
    /// A guest COW write fault reached the host: see [`refill_guest_cow_pool`].
    pub(crate) fn refill_guest_cow_pool(
        &self,
        custody: &std::sync::Arc<CarrierVmCustody>,
        fault_va: u64,
    ) -> Result<bool, TrapError> {
        let Some(pool) = carrick_el1_abi::cow_grant_pool_host() else {
            return Ok(false);
        };
        refill_guest_cow_pool(&self.mm_access, custody, pool, fault_va, |mm| {
            carrick_el1_abi::zone_tables().is_some_and(|zone| zone.spaces.find(mm).is_some())
        })
    }
}

/// A guest COW write fault at `fault_va` reached the host. When EL1 could
/// have taken it but found no grant for this MM (the MM is guest-owned and
/// `published` for EL1, the leaf is an armed EL1-private Linux-writable
/// page, and the pool holds none of the MM's grants), provision the MM's
/// next elastic batch and report `true`: retrying the instruction lets EL1
/// resolve it. Otherwise (`false`) the host resolves the fault itself.
pub(crate) fn refill_guest_cow_pool(
    state: &MmAccessState,
    custody: &std::sync::Arc<CarrierVmCustody>,
    pool: &CowGrantPool,
    fault_va: u64,
    published: impl FnOnce(u64) -> bool,
) -> Result<bool, TrapError> {
    let tables = state.page_tables_authority();
    if tables.live_descriptor_owner() != carrick_mmu_core::aarch64::LiveDescriptorOwner::Guest {
        return Ok(false);
    }
    let Some(mm) = state
        .cow_runtime
        .read()
        .as_ref()
        .map(|runtime| runtime.identity.mm)
    else {
        return Ok(false);
    };
    let armed = tables
        .with_manager(|manager| {
            let (level, leaf) =
                carrick_mmu_core::aarch64::terminal_entry(manager.debug_walk(fault_va));
            carrick_mmu_core::aarch64::descriptor_txn::guest_cow::is_guest_cow_write_leaf(
                level, leaf,
            )
        })
        .unwrap_or(false);
    if !armed || pool.ready(mm).next().is_some() || !published(mm) {
        return Ok(false);
    }
    let batch = state
        .guest_cow_batch
        .load(std::sync::atomic::Ordering::Relaxed);
    // A grant that cannot be made (no frame, a full kernel reservation)
    // leaves this fault to the host COW path; grants already published stay.
    let provisioned = match provision_guest_cow_grants(state, custody, pool, batch) {
        Ok(provisioned) => provisioned,
        Err(error) => {
            tracing::debug!(target: "carrick::guest_cow", %error, "guest COW refill failed");
            0
        }
    };
    state.guest_cow_batch.store(
        next_guest_cow_batch(batch),
        std::sync::atomic::Ordering::Relaxed,
    );
    Ok(provisioned > 0)
}

/// One replacement compound, stage-2 mapped and registered as a live global
/// frame owner: its host pointer, IPA and owner generation.
fn allocate_grant_compound(
    custody: &std::sync::Arc<CarrierVmCustody>,
    stage2_perms: applevisor::memory::MemPerms,
) -> Result<(*mut u8, u64, u64), TrapError> {
    if let Some(handle) = custody
        .frame_pool()
        .and_then(|pool| pool.allocate_compound())
    {
        let host_ptr = handle.as_mut_ptr();
        let physical_ipa = handle.ipa();
        let generation =
            register_pooled_global_frame_host_owner_in(custody, handle, u64::from(stage2_perms))?;
        return Ok((host_ptr, physical_ipa, generation));
    }
    let new_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        CowArmedRanges::COMPOUND_SIZE as usize,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .map_err(|error| TrapError::Hypervisor(format!("allocate guest COW grant: {error}")))?;
    let host_ptr = new_host.as_ptr();
    #[allow(unused_mut)]
    let mut lease = GlobalFrameStage2Lease::reserve(
        CowArmedRanges::COMPOUND_SIZE,
        CowArmedRanges::COMPOUND_SIZE,
    )?;
    let physical_ipa = lease.base;
    #[cfg(not(any(test, feature = "foreign-cow-test-support")))]
    {
        // SAFETY: the host mapping outlives its stage-2 record, which the
        // owner registration below transfers into carrier custody.
        let rc = unsafe {
            inventory_hv_vm_map(
                host_ptr.cast(),
                physical_ipa,
                CowArmedRanges::COMPOUND_SIZE as usize,
                u64::from(stage2_perms),
            )
        };
        if rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "map guest COW grant IPA 0x{physical_ipa:x}: 0x{rc:x}"
            )));
        }
        lease.mark_mapped();
    }
    #[cfg(any(test, feature = "foreign-cow-test-support"))]
    lease.mark_test_mapped_without_backend();
    let generation =
        register_global_frame_host_owner_in(custody, lease, new_host, u64::from(stage2_perms))?;
    Ok((host_ptr, physical_ipa, generation))
}

/// Settle every guest COW completion of the excluded MM. Returns how many
/// were settled. An inconsistency between EL1's completion and the host
/// authorities is fatal: EL1 already runs the MM on the repointed leaves.
pub(crate) fn settle_guest_cow_completions(
    state: &MmAccessState,
    custody: &std::sync::Arc<CarrierVmCustody>,
    pool: &CowGrantPool,
    excluded: &ExcludedEditor<'_>,
) -> usize {
    if !pool.any_completed() {
        return 0;
    }
    let _serial = state.guest_cow_settlement.lock();
    if pool.claimed_by(excluded) {
        carrick_fatal!(
            "hvpatch::guest_cow",
            "an EL1 COW grant is still claimed while its MM's editor is excluded"
        );
    }
    let completions: Vec<CowGrantCompletion> = pool.completions(excluded).collect();
    if completions.is_empty() {
        return 0;
    }
    let runtime = state.cow_runtime.read().clone().unwrap_or_else(|| {
        carrick_fatal!(
            "hvpatch::guest_cow",
            "guest COW completions for an MM with no COW runtime"
        )
    });
    if runtime.identity.mm != excluded.key() {
        carrick_fatal!(
            "hvpatch::guest_cow",
            "guest COW settlement for MM {} ran on the state of MM {}",
            excluded.key(),
            runtime.identity.mm
        );
    }
    for completion in &completions {
        settle_one(state, custody, &runtime, completion).unwrap_or_else(|error| {
            carrick_fatal!(
                "hvpatch::guest_cow",
                "settle EL1 COW of span 0x{:x}+0x{:x} (grant 0x{:x}): {error}",
                completion.span_va,
                completion.span_len,
                completion.grant.physical_ipa
            )
        });
        if !pool.finish(excluded, &completion.grant) {
            carrick_fatal!(
                "hvpatch::guest_cow",
                "settled EL1 COW grant could not be freed"
            );
        }
        state.host_cow_stats.record_guest_cow_settled();
    }
    completions.len()
}

fn settle_one(
    state: &MmAccessState,
    custody: &std::sync::Arc<CarrierVmCustody>,
    runtime: &MmCowRuntimeBinding,
    completion: &CowGrantCompletion,
) -> Result<(), TrapError> {
    const PAGE: u64 = 0x1000;
    let refuse = |what: &str| Err(TrapError::Hypervisor(what.to_owned()));
    if !completion.is_well_formed() || completion.grant.mm_key != runtime.identity.mm {
        return refuse("malformed completion");
    }
    let span_len = usize::try_from(completion.span_len)
        .map_err(|_| TrapError::Hypervisor("span length".to_owned()))?;
    let span_end = completion.span_va + completion.span_len;
    let new_physical_ipa = completion.grant.physical_ipa;
    let new_key = (new_physical_ipa, CowArmedRanges::COMPOUND_SIZE);
    let old_ipa = completion.old_ipa;
    let old_physical_ipa = align_down(old_ipa, CowArmedRanges::COMPOUND_SIZE);
    let old_offset = old_ipa - old_physical_ipa;

    // The grant is the MM's exact extent and live owner EL1 claimed.
    let grant_extent = state
        .frame_inventory
        .ledger
        .lock()
        .extents
        .get(&new_key)
        .copied()
        .filter(|extent| {
            extent.mapping.raw() == completion.grant.backing.mapping_id.get()
                && extent.frame.raw() == completion.grant.backing.frame_id.get()
                && extent.stage2_owner.generation == completion.grant.backing.owner_generation.get()
        })
        .ok_or_else(|| TrapError::Hypervisor("grant is not this MM's extent".to_owned()))?;
    let (new_host_addr, owner_generation) =
        global_frame_host_owner_identity_in(custody, new_key.0, new_key.1)
            .filter(|(host, generation)| {
                *host == grant_extent.stage2_owner.host_addr
                    && *generation == grant_extent.stage2_owner.generation
            })
            .ok_or_else(|| TrapError::Hypervisor("grant owner is not live".to_owned()))?;

    // EL1's repoint is what the live graph holds for every page of the span.
    let tables = state.page_tables_authority();
    tables
        .with_manager(|manager| {
            (0..completion.span_len / PAGE).all(|index| {
                manager.translate_retained_output(completion.span_va + index * PAGE)
                    == Some(completion.new_ipa + index * PAGE)
            })
        })
        .filter(|live| *live)
        .ok_or_else(|| TrapError::Hypervisor("live leaves do not name the grant".to_owned()))?;

    // Every page of the span was fork-armed; EL1 moves only armed leaves.
    let armed = {
        let cow_armed = state.cow_armed.lock();
        let first = cow_armed.span_for(completion.span_va);
        let covered = (0..completion.span_len / PAGE).all(|index| {
            cow_armed
                .span_for(completion.span_va + index * PAGE)
                .is_some()
        });
        first.filter(|_| covered)
    }
    .ok_or_else(|| TrapError::Hypervisor("span is not COW-armed".to_owned()))?;
    let span = CowArmedSpan {
        va: completion.span_va,
        len: span_len,
        executable: armed.executable,
        kernel_only: false,
    };

    // The source alias: the VMA's Linux write permission rides on the
    // replacement's alias, exactly as on the host COW path.
    let source_guest_writable = alias_registry()
        .lock()
        .newest_matching_for_process(runtime.mm_root_slot, runtime.container_root, |alias| {
            let Some(offset) = span.va.checked_sub(alias.start) else {
                return false;
            };
            offset < alias.size as u64
                && alias
                    .start
                    .checked_add(alias.size as u64)
                    .is_some_and(|end| span_end <= end)
                && alias.ipa.checked_add(offset) == Some(old_ipa)
                && alias.physical_ipa <= old_physical_ipa
                && old_physical_ipa < alias.physical_ipa + alias.physical_size as u64
        })
        .map(|alias| alias.guest_writable)
        .ok_or_else(|| TrapError::Hypervisor("no source alias for the span".to_owned()))?;

    let retention_aliases = authenticated_cow_retention_aliases_in(
        custody,
        runtime.mm_root_slot,
        runtime.container_root,
        old_physical_ipa,
    );
    let retain_old_compound = tables
        .with_manager(|manager| {
            cow_source_has_retained_projection(
                span,
                old_ipa,
                old_physical_ipa,
                &retention_aliases,
                |va| manager.translate_retained_output(va),
            )
        })
        .ok_or_else(|| TrapError::Hypervisor("page tables are absent".to_owned()))?;
    let CowInventorySplitShape {
        old_key,
        old,
        fragments,
        retirement,
    } = HvfVmState::cow_inventory_split_shape(
        &state.frame_inventory.ledger.lock(),
        old_physical_ipa,
        retain_old_compound,
        |frame| {
            runtime
                .authority
                .frame_mapping_count(frame)
                .map_err(|error| TrapError::Hypervisor(format!("frame mapping count: {error}")))
        },
    )?;
    let mapping_candidates = fragments.len().saturating_add(1);
    let event_count = 1usize
        .saturating_add(mapping_candidates.saturating_mul(2))
        .saturating_add(usize::from(retirement.retire_old_frame));
    let mut reservation = runtime
        .authority
        .reserve(1, mapping_candidates, event_count)
        .map_err(|error| TrapError::Hypervisor(format!("reserve settlement: {error}")))?;
    let split = HvfVmState::stage_cow_inventory_split(
        &mut reservation,
        old_key,
        old,
        &fragments,
        retirement,
        CowInventoryReplacementStage {
            existing: Some(grant_extent),
            gpa: new_physical_ipa,
            backing: grant_extent.backing,
            stage2_owner: grant_extent.stage2_owner,
        },
    )?;
    let registry = crate::fork_quiesce::FrameRegistryGuard::acquire(
        carrick_observability::probes::HvpatchTopologyOperation::FrameCow,
        runtime.identity.linux_pid,
        runtime.identity.linux_tid,
    );
    runtime
        .authority
        .apply(reservation.commit(()))
        .map_err(|error| TrapError::Hypervisor(format!("settlement inventory: {error}")))?;
    let retired_old_stage2 = HvfVmState::commit_cow_inventory_split(
        &mut state.frame_inventory.ledger.lock(),
        &split,
        || {
            HvfVmState::retire_stage2_extent_from_mappings_in(
                custody,
                &mut TaskMappingIndex::new(),
                split.old.stage2_base,
                split.old.stage2_length,
            )
        },
    )?;
    drop(registry);
    if retired_old_stage2 {
        let retired = [RetiredStage2Projection::from(split.old)];
        let _ = mutate_known_external_alias_state(
            |aliases| retired_projection_mutation_keys(aliases, &retired, &[]),
            |aliases| remove_rows_for_retired_stage2_projections(aliases, &retired),
        );
    }
    register_shared_alias(AliasBacking {
        start: span.va,
        ipa: completion.new_ipa,
        host_addr: new_host_addr + old_offset as usize,
        size: span_len,
        physical_ipa: new_physical_ipa,
        physical_host_addr: new_host_addr,
        physical_size: CowArmedRanges::COMPOUND_SIZE as usize,
        perms: u64::from(applevisor::memory::MemPerms::ReadWriteExec),
        guest_writable: source_guest_writable,
        sharing: GuestMappingSharing::Private,
        ownership_scope: alias_ownership_scope(
            GuestMappingSharing::Private,
            runtime.mm_root_slot,
            runtime.container_root,
        ),
        inventory_backing: grant_extent.backing,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation,
    });
    let cow_length = carrick_hal::FrameLength::from_mapping_extent(
        std::num::NonZeroU64::new(CowArmedRanges::COMPOUND_SIZE)
            .ok_or_else(|| TrapError::Hypervisor("zero compound".to_owned()))?,
    );
    if runtime
        .authority
        .mapping_is_live(
            split.new_extent.mapping,
            split.new_extent.frame,
            carrick_guest_mem::Gpa(new_physical_ipa),
            cow_length,
        )
        .ok()
        != Some(true)
    {
        return refuse("replacement mapping is not live after settlement");
    }
    state.supersede_cow_receipts(span.va, span.len as u64);
    state.cow_armed.lock().disarm(span);
    Ok(())
}

/// The carrier's settlement, run by every host exclusion of an MM's EL1
/// editor: the MM's backend state is found by its exact key in the
/// carrier's MM directory.
pub struct CarrierGuestCowSettlement {
    transport: std::sync::Weak<CarrierForeignMmTransport>,
    #[cfg(test)]
    pool: Option<&'static CowGrantPool>,
}

impl CarrierGuestCowSettlement {
    pub(crate) fn new(transport: &std::sync::Arc<CarrierForeignMmTransport>) -> Self {
        Self {
            transport: std::sync::Arc::downgrade(transport),
            #[cfg(test)]
            pool: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_pool(mut self, pool: &'static CowGrantPool) -> Self {
        self.pool = Some(pool);
        self
    }

    fn pool(&self) -> Option<&'static CowGrantPool> {
        #[cfg(test)]
        if let Some(pool) = self.pool {
            return Some(pool);
        }
        carrick_el1_abi::cow_grant_pool_host()
    }

    fn state_for(
        &self,
        mm: u64,
    ) -> Option<(
        std::sync::Arc<MmAccessState>,
        std::sync::Arc<CarrierVmCustody>,
    )> {
        let transport = self.transport.upgrade()?;
        let state = transport
            .states
            .read()
            .values()
            .filter_map(std::sync::Weak::upgrade)
            .find(|state| {
                state
                    .identity
                    .read()
                    .is_some_and(|(id, _)| id.raw_for_probe() == mm)
            })?;
        Some((state, std::sync::Arc::clone(&transport.custody)))
    }
}

impl CowGrantSettlement for CarrierGuestCowSettlement {
    fn settle(&self, excluded: &ExcludedEditor<'_>) {
        let Some(pool) = self.pool() else {
            return;
        };
        if !pool.any_completed() {
            return;
        }
        // No backend state: the MM is retiring. Its inventory retires the
        // grants EL1 used with every other mapping, and its publication's
        // retirement releases the records.
        let Some((state, custody)) = self.state_for(excluded.key()) else {
            return;
        };
        settle_guest_cow_completions(&state, &custody, pool, excluded);
    }

    fn release(&self, excluded: &ExcludedEditor<'_>) {
        if let Some(pool) = self.pool() {
            pool.release_mm(excluded);
        }
    }
}
