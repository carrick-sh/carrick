use super::*;

/// Stage-2 custody and MM authority that move with a logical HVPatch task.
pub(crate) struct Stage2State {
    pub(super) custody: std::sync::Arc<CarrierVmCustody>,
    pub(crate) mappings: TaskMappingIndex,
    /// Per-mm stage-1 root-table slot. It contains page-table/control backing
    /// only; guest data frames live at stable global IPAs outside the slot.
    /// Ordinary VMM engines leave this unset.
    pub(crate) mm_root_slot: Option<(u64, u64)>,
    /// Monotonic token identifying the container root this task belongs to,
    /// used to scope private aliases across containers sharing the carrier.
    pub(crate) container_root: ContainerRootToken,
    pub(super) pending_exec_mm_root_slot: Option<(u64, u64)>,
    pub(super) pending_exec_asid: Option<u16>,
    pub(super) pending_exec_predecessor_identity: Option<carrick_hal::ExecPredecessorIdentity>,
    pub(super) pending_exec_stage2_cleanup: Option<PendingExecStage2Cleanup>,
    /// A distinct Linux process edge onto another process's live CLONE_VM MM.
    /// Exit/exec drops this projection without retiring shared stage-2 state.
    pub(super) shared_process_mm: bool,
    /// Exact MM-owned access authority. This is the only movable MM state:
    /// sibling/CLONE_VM tasks clone this Arc, while copied forks allocate a
    /// distinct value.
    pub(super) mm_access: std::sync::Arc<MmAccessState>,
    /// HvPatch owns one process-wide HVF VM across guest exec/fork lifecycle;
    /// ordinary VMM preserves the mature destroy/recreate behavior.
    pub(crate) persistent_vm_lifecycle: bool,
    /// HVPatch-only exact sparse-extent inventory. Sibling vCPUs share this
    /// ledger; VM/vCPU recreation reuses it and therefore emits no logical
    /// mapping events.
    /// Per-engine runtime authority. Sibling vCPUs bind their own Linux TID;
    /// the underlying mm/frame inventory remains shared.
    pub(crate) cow_authority: Option<std::sync::Arc<dyn carrick_hal::FrameCowAuthority>>,
    pub(crate) cow_identity: Option<carrick_hal::FrameCowIdentity>,
    pub(crate) pending_fork_frame_receipts: Vec<PendingForkFrameReceipt>,
    /// Child aliases withheld until fresh-vCPU register restoration succeeds.
    pub(super) pending_process_aliases: Vec<AliasBacking>,
    /// Test-only diagnostic arm owned by this executor projection. It must not
    /// move into the shared MM access state or a sibling can consume it.
    pub(super) fail_next_begin_exec_inventory: bool,
    /// Recycled buffer for the frame-COW rollback pre-image.
    ///
    /// `perform_frame_cow` snapshots the whole stage-1 manager before it edits,
    /// so a failed publication can restore the exact pre-transaction image. That
    /// snapshot is unchanged; only its allocation is reused. A fresh
    /// `PageTableManager::clone()` costs an `mmap` of 1.75 MiB, a zero-fill
    /// fault per page as the copy touches it, and a `munmap`/`madvise` on drop
    /// — measured at ~6 COW faults per guest fork+wait round trip, which put
    /// that whole host-VM churn on the COW path. Taken for the duration of one
    /// COW and returned on success; a rollback consumes it (it becomes the live
    /// manager) and the next COW allocates one again.
    pub(super) cow_rollback_scratch: Option<carrick_mmu_core::aarch64::PageTableManager>,
}

impl Stage2State {
    pub(crate) fn custody(&self) -> &CarrierVmCustody {
        &self.custody
    }

    pub(super) fn custody_arc(&self) -> std::sync::Arc<CarrierVmCustody> {
        std::sync::Arc::clone(&self.custody)
    }

    pub(crate) fn mm_access_authority(&self) -> std::sync::Arc<MmAccessState> {
        std::sync::Arc::clone(&self.mm_access)
    }

    pub(crate) fn runtime_authorities_match(
        &self,
        mm_access: &std::sync::Arc<MmAccessState>,
        page_tables: &carrick_aarch64::Stage1Authority,
        protections: &carrick_guest_mem::UserMemoryAuthority,
    ) -> bool {
        std::sync::Arc::ptr_eq(&self.mm_access, mm_access)
            && carrick_aarch64::Aarch64TaskRuntimeProjection {
                page_tables: page_tables.clone(),
                protections: protections.clone(),
                process_asid: None,
            }
            .shares_exact_mm_authority(
                &self.mm_access.page_tables_authority(),
                &self.mm_access.protections,
            )
    }

    pub(super) fn publish_pending_fork_frame_receipts_with(
        &mut self,
        publish: &mut dyn FnMut(carrick_observability::probes::HvpatchForkFrameShare),
    ) {
        // This task-local vector is the observation copy made by
        // `runtime_task_state`. The MM authority retains its original receipts
        // for exact retirement authentication, so draining here is publication
        // exactly once without discharging the Kernel obligation.
        if self.pending_fork_frame_receipts.is_empty() {
            return;
        }
        let authority = self.cow_authority.as_ref().unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::cow_token",
                "pending fork-frame receipt has no COW authority"
            )
        });
        let identity = self.cow_identity.unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::cow_token",
                "pending fork-frame receipt has no COW identity"
            )
        });
        for receipt in std::mem::take(&mut self.pending_fork_frame_receipts) {
            let length = carrick_hal::FrameLength::from_mapping_extent(
                std::num::NonZeroU64::new(receipt.length).unwrap_or_else(|| {
                    carrick_fatal!(
                        "hvpatch::fork_publication",
                        "pending fork-frame receipt has zero length"
                    )
                }),
            );
            match authority.mapping_is_live(
                receipt.child_mapping,
                receipt.frame,
                carrick_guest_mem::Gpa::new(receipt.ipa),
                length,
            ) {
                Ok(true) => {}
                Ok(false) => {
                    carrick_fatal!(
                        "hvpatch::fork_publication",
                        "fork-frame receipt child mapping {:?} is not live",
                        receipt.child_mapping
                    );
                }
                Err(error) => {
                    carrick_fatal!(
                        "hvpatch::cow_token",
                        "authenticate fork-frame receipt mapping {:?}: {error}",
                        receipt.child_mapping
                    );
                }
            }
            let event = carrick_observability::probes::HvpatchForkFrameShare::new(
                carrick_observability::probes::HvpatchForkFrameShareArgs {
                    pid: identity.linux_pid,
                    tid: identity.linux_tid,
                    mm: identity.mm,
                    asid: u32::from(identity.asid),
                    kind: receipt.kind,
                    parent_mapping: receipt.parent_mapping.raw(),
                    child_mapping: receipt.child_mapping.raw(),
                    frame: receipt.frame.raw(),
                    ipa: receipt.ipa,
                    length: receipt.length,
                },
            )
            .unwrap_or_else(|error| {
                carrick_fatal!(
                    "hvpatch::fork_publication",
                    "construct authenticated fork-frame receipt failed: {error}"
                )
            });
            publish(event);
        }
    }

    pub(crate) fn publish_pending_fork_frame_receipts(&mut self) {
        self.publish_pending_fork_frame_receipts_with(&mut |event| {
            crate::probes::hvpatch_fork_frame_share(event);
        });
    }

    /// Whether an execve on this task retires the old mm's extents.
    ///
    /// A vfork / `CLONE_VM` child shares its mm with a live sharer that keeps
    /// every mapping, so its exec retires nothing: the replacement gets a fresh
    /// ledger and the old one stays whole. Callers must arm no retirement
    /// transaction in that case — a reservation filled with zero events is
    /// rejected by the Kernel authority, and the exec is already past its point
    /// of no return by the time the commit is applied.
    pub(crate) fn exec_retires_old_mm(&self) -> bool {
        !self.shared_process_mm
    }

    /// Extents this task's execve will retire from the old mm: none when a
    /// live sharer still owns it.
    pub(crate) fn exec_retired_extent_count(&self) -> usize {
        if self.exec_retires_old_mm() {
            self.mm_access.frame_inventory.lock().extents.len()
        } else {
            0
        }
    }

    pub(super) fn begin_exec_inventory(
        &mut self,
        retired: Option<carrick_hal::FrameInventoryReservation>,
        replacement: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        if std::mem::take(&mut self.fail_next_begin_exec_inventory) {
            return Err(TrapError::Hypervisor(
                "injected HVPatch begin_exec_inventory failure".to_owned(),
            ));
        }
        if self.shared_process_mm {
            // The parent still owns this ledger. Exec starts a fresh backend
            // ledger for the replacement MM so it cannot remove the parent's
            // mappings. Nothing is retired, so `retired` is `None` here:
            // reserving a retirement would stage zero events against the fresh
            // ledger, and the Kernel authority rejects a zero-event commit.
            let frames = self.mm_access.frame_inventory.lock().frames.clone();
            self.mm_access = MmAccessState::new_unbound(
                self.mm_access.page_tables_authority(),
                self.mm_access.protections.clone(),
                std::sync::Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::with_frames(
                    frames,
                ))),
                std::sync::Arc::clone(&self.mm_access.cow_armed),
                std::sync::Arc::clone(&self.mm_access.cow_deferred_publications),
                self.custody().host_cow_ledger.admit_mm(),
            );
            // This provisional state only separates the replacement inventory.
            // Its table authority still belongs to the live parent: installing
            // a child resolver here would redirect every parent table read to
            // the child's empty ledger. Exec rebuild binds a new resolver only
            // after creating the successor's independent table authority.
        }
        self.mm_access
            .frame_inventory
            .begin_exec_inventory(retired, replacement)
    }

    pub(crate) fn set_persistent_vm_lifecycle(&mut self, enabled: bool) {
        self.persistent_vm_lifecycle = enabled;
    }

    pub(crate) fn sparse_mmap_arena_enabled(&self) -> bool {
        self.persistent_vm_lifecycle
    }

    /// Retire the generic boot loader's hidden 32 GiB mmap backing after the
    /// runtime selects HVPatch, but before initial frame inventory publication.
    /// Mature VMM never enables the persistent lifecycle and keeps its existing
    /// eager identity mapping unchanged.
    ///
    /// **Once per carrier VM, not once per container.** The unmap below is
    /// `inventory_stage2_unmap` over the WHOLE arena extent, which is VM-wide
    /// state, while this runs during each container's root bring-up. With one
    /// VM per container that distinction did not exist. With a carrier VM
    /// shared by several containers it is the difference between retiring an
    /// eager mapping nobody is using yet and tearing out the sparse per-page
    /// backing a SIBLING container has already faulted in inside that same
    /// range — the sibling's next access then takes a level-1 translation
    /// fault on an address it was legitimately handed, and its guest dies of
    /// SIGSEGV within a few traps.
    ///
    /// The carrier's root boot gate serializes VM ownership and the first root
    /// publishes the carrier bundle before any guest instruction runs, so the
    /// first caller retires while no guest can yet hold sparse pages, and
    /// every later container skips it. Absence remains tolerated for the same
    /// reason it always was: a later container's plan omits the eager mapping.
    /// What is NOT tolerated is a second unmap.
    pub(crate) fn retire_initial_mmap_arena(&mut self) -> Result<(), TrapError> {
        if !self.persistent_vm_lifecycle {
            return Ok(());
        }
        if carrier_initial_arena_retired().swap(true, std::sync::atomic::Ordering::AcqRel) {
            return Ok(());
        }
        let Some(mapping) = self
            .mappings
            .get(&GuestVa::new(crate::memory::LINUX_MMAP_BASE))
        else {
            return Ok(());
        };
        if mapping.end
            != crate::memory::LINUX_MMAP_BASE.saturating_add(crate::memory::mmap_arena_size())
            || mapping.physical_ipa != crate::memory::LINUX_MMAP_BASE
            || mapping.physical_size as u64 != crate::memory::mmap_arena_size()
            || mapping.is_dynamic_alias
            || mapping.stage2_lease.is_some()
            || mapping.host_mapping.is_none()
        {
            return Err(TrapError::Hypervisor(
                "HVPatch initial mmap arena backing has unexpected shape or ownership".to_owned(),
            ));
        }
        let rc = unsafe {
            inventory_stage2_unmap(
                self.custody().stage2_backend(),
                mapping.physical_ipa,
                mapping.physical_size,
            )
        };
        if rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "unmap HVPatch initial sparse mmap arena: 0x{rc:x}"
            )));
        }
        self.mappings.remove_range(
            GuestVa::new(crate::memory::LINUX_MMAP_BASE),
            crate::memory::mmap_arena_size() as usize,
        );
        Ok(())
    }

    pub(crate) fn bind_deferred_anonymous_state(
        &mut self,
        state: std::sync::Arc<carrick_guest_mem::DeferredAnonymousState>,
    ) {
        let mm = carrick_hal::ForeignMmId::from_kernel_allocation(
            self.cow_identity
                .and_then(|identity| std::num::NonZeroU64::new(identity.mm))
                .unwrap_or_else(|| {
                    carrick_fatal!(
                        "hvpatch::deferred_materialization_binding",
                        "local HVF state has no nonzero COW MM identity while binding deferred-memory authority"
                    )
                }),
        );
        let mut binding = self.mm_access.deferred_anonymous.write();
        if let Some((bound_mm, bound_state)) = binding.as_ref()
            && (*bound_mm != mm || !std::sync::Arc::ptr_eq(bound_state, &state))
        {
            carrick_fatal!(
                "hvpatch::deferred_materialization_binding",
                "local HVF state already holds a different MM or deferred-memory authority"
            );
        }
        *binding = Some((mm, state));
    }

    pub(crate) fn deferred_anonymous_state(
        &self,
    ) -> Option<std::sync::Arc<carrick_guest_mem::DeferredAnonymousState>> {
        let mm = carrick_hal::ForeignMmId::from_kernel_allocation(std::num::NonZeroU64::new(
            self.cow_identity?.mm,
        )?);
        self.mm_access
            .deferred_anonymous
            .read()
            .as_ref()
            .filter(|(bound_mm, _)| *bound_mm == mm)
            .map(|(_, state)| std::sync::Arc::clone(state))
    }

    pub(crate) fn prepare_exec_address_space(
        &mut self,
        root_slot_base: u64,
        root_slot_size: u64,
        asid: u16,
    ) -> Result<(), TrapError> {
        if !root_slot_base.is_multiple_of(HVF_PAGE_SIZE) || root_slot_size == 0 || asid == 0 {
            return Err(TrapError::Hypervisor(
                "invalid exact HVPatch exec MM lease".to_owned(),
            ));
        }
        if self.pending_exec_mm_root_slot.is_some() || self.pending_exec_asid.is_some() {
            return Err(TrapError::Hypervisor(
                "duplicate exact HVPatch exec MM lease".to_owned(),
            ));
        }
        self.pending_exec_mm_root_slot = Some((root_slot_base, root_slot_size));
        self.pending_exec_asid = Some(asid);
        Ok(())
    }

    pub(crate) fn bind_exec_predecessor_identity(
        &mut self,
        identity: carrick_hal::ExecPredecessorIdentity,
    ) -> Result<(), TrapError> {
        bind_exec_predecessor_identity_slot(&mut self.pending_exec_predecessor_identity, identity)
    }

    /// See `carrick_hal::ThreadedEngine::mark_exec_predecessor_shared`. The
    /// flag drives `exec_retires_old_mm`, the fresh-ledger split in
    /// `begin_exec_inventory`, and `execve_rebuild`'s `shared_projection`;
    /// `execve_rebuild` clears it after capturing the projection.
    pub(crate) fn mark_exec_predecessor_shared(&mut self, shared: bool) {
        self.shared_process_mm = shared;
    }

    /// The process-wide PROT_NONE bookkeeping (the engine's EFAULT gate).
    pub(crate) fn protections_ref(&self) -> Option<carrick_guest_mem::LegacyProtectionRead<'_>> {
        self.mm_access.protections.legacy()
    }
}
