//! Memory, page-table mutation, identity page, and COW authority for the vCPU loop.

use carrick_fatal::carrick_fatal;
use carrick_guest_mem::CurrentMmMemory;
use carrick_hal::{ThreadedEngine, TrapError};
use carrick_mem::memory::AddressSpace;
use std::sync::Arc;

use super::Kernel;
use super::quiesce;
use crate::dispatch::{DispatchError, ProcMapSharing, ProcMapsEntry, SyscallDispatcher};
use crate::run_result::RuntimeError;

/// Whether this syscall must take the process-wide page-table pause BEFORE the
/// dispatcher runs — see the call site in `service_threaded_syscall` for the
/// lock-order argument. `arg2` is the third syscall argument (madvise's
/// `advice`); it is ignored for every other number.
pub(crate) fn syscall_takes_pre_dispatch_pt_pause(
    number: u64,
    arg2: u64,
    multi_vcpu: bool,
) -> bool {
    if !multi_vcpu {
        return false;
    }
    syscall_edits_stage1(number, arg2)
}

/// Whether this syscall edits stage-1 descriptors at all, independent of how
/// many threads exist. Split out from the pause predicate because the two
/// answers are used for different things: a peer executor decides whether a
/// PAUSE is needed, while editing stage-1 at all decides whether this thread
/// should claim stage-1 EXCLUSIVITY for the dispatch — which it holds either
/// way, since with no peer executor there is nobody to be exclusive against.
pub(crate) fn syscall_edits_stage1(number: u64, arg2: u64) -> bool {
    crate::dispatch::syscall_requires_mm_mutation(
        number,
        crate::compat::SyscallArgs::from([0, 0, arg2, 0, 0, 0]),
    )
}

/// Restores the guest-visible `Running` state when a guest-blocking wait ends.
///
/// Deliberately owns no borrow of the run state: the blocking arms it wraps
/// need `&mut self` for `complete_errno`/`complete_returned`, so a guard
/// holding `&self` could not coexist with them. It carries the identity it
/// publishes under instead, which is fixed for the life of the thread.
pub(crate) fn apply_alias_frame_inventory(
    context: &crate::kernel::KernelContext,
    commit: carrick_hal::FrameInventoryCommit<()>,
) -> Result<(), crate::kernel::FrameInventoryError> {
    context
        .kernel()
        .frame_inventory()
        .apply(context.shared().mm().id(), commit)
        .map(|_| ())
}

/// The alias-install arm's (the guest map-file syscall) fail-closed sink.
///
/// Every step after `map_host_alias` has succeeded runs with the alias already
/// committed to stage-2, so none of them can be lowered to a guest errno: a
/// refusal there is a carrier invariant violation. Until 2026-09-08 each was a
/// bare `abort()` with no log line, and the go-build reducer died rc=134 with
/// empty stderr. This names the site through lane B's `KernelAbort` sink —
/// the run ends in `kernel aborted: hvpatch alias install …` with a
/// post-mortem — and, for a refused inventory publication, asks the authority
/// whether the frame the batch names is still a candidate of some other
/// reserved, unapplied transaction, which is the publication-order signature.
///
/// Returns the carrier-terminal error the arm completes with; every later job
/// wait in this carrier is answered by the same recorded abort.
#[allow(clippy::too_many_arguments)]
pub(crate) fn refuse_alias_install(
    kernel: &Kernel,
    context: &crate::kernel::KernelContext,
    site: crate::kernel::debug::HvpatchAliasInstallSite,
    guest_pid: i32,
    guest_tid: i32,
    va: u64,
    len: u64,
    prot: u64,
    shared: bool,
    prot_none: bool,
    error: String,
    frame: Option<carrick_hal::FrameId>,
) -> RuntimeError {
    let pending_reservation = frame
        .and_then(|frame| {
            context
                .kernel()
                .frame_inventory()
                .pending_reservation_for_frame(frame)
        })
        .map(|transaction| transaction.raw());
    let reason = crate::kernel::debug::AbortReason::HvpatchAliasInstall {
        site,
        guest_pid,
        guest_tid,
        executor: std::thread::current().name().map(str::to_owned),
        mm: context.shared().mm().id().raw(),
        va,
        len,
        prot,
        shared,
        prot_none,
        error,
        frame: frame.map(|frame| frame.raw()),
        pending_reservation,
    };
    tracing::error!(
        reason = %reason.summary(),
        "HVPatch alias install refused; aborting the carrier"
    );
    match kernel.hvpatch_runtime.as_ref() {
        Some(directory) => directory.process_graph_liveness().abort(reason),
        // The arm is reached only with an HVPatch process context, which is
        // always paired with a runtime directory; a carrier without one cannot
        // capture, so the summary is the whole evidence.
        None => RuntimeError::Configuration(reason.summary()),
    }
}

pub(crate) struct KernelFrameCowAuthority {
    pub(crate) deferred_anonymous: Option<Arc<carrick_guest_mem::DeferredAnonymousState>>,
    pub(crate) kernel: Arc<crate::kernel::Kernel>,
    pub(crate) mm: crate::kernel::MmId,
    pub(crate) owner_inventory: Arc<dyn carrick_hal::FrameCowOwnerInventory>,
    /// Exact-MM admission plus every participant's opaque pause endpoint.
    pub(crate) guest_executors: Arc<crate::kernel::GuestExecutorCensus>,
    pub(crate) tid: carrick_hal::ThreadId,
    pub(crate) identity: carrick_hal::FrameCowIdentity,
    pub(crate) pt_quiesce: Arc<carrick_thread::fork_quiesce::PtQuiesce>,
}

/// Runtime-private payload carried opaquely through the HAL receipt. A
/// transport can return only a proof that this exact Kernel authority minted;
/// an internally consistent transport-owned tuple has the wrong `TypeId` and
/// cannot authorize `CowBroken`.
#[derive(Clone, Debug)]
pub(crate) struct KernelForeignCowProof {
    kernel: Arc<crate::kernel::Kernel>,
    mm: crate::kernel::MmId,
    semantic_start: carrick_guest_mem::GuestVa,
    semantic_len: std::num::NonZeroUsize,
    inventory_revision: u64,
    mapping: carrick_hal::MappingId,
    frame: carrick_hal::FrameId,
    physical_base: carrick_guest_mem::Gpa,
    physical_len: carrick_hal::FrameLength,
    owner_generation: carrick_hal::ForeignOwnerGeneration,
}

impl KernelForeignCowProof {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        kernel: Arc<crate::kernel::Kernel>,
        mm: crate::kernel::MmId,
        semantic_start: carrick_guest_mem::GuestVa,
        semantic_len: std::num::NonZeroUsize,
        inventory_revision: u64,
        mapping: carrick_hal::MappingId,
        frame: carrick_hal::FrameId,
        physical_base: carrick_guest_mem::Gpa,
        physical_len: carrick_hal::FrameLength,
        owner_generation: carrick_hal::ForeignOwnerGeneration,
    ) -> Self {
        Self {
            kernel,
            mm,
            semantic_start,
            semantic_len,
            inventory_revision,
            mapping,
            frame,
            physical_base,
            physical_len,
            owner_generation,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authenticates(
        &self,
        kernel: &Arc<crate::kernel::Kernel>,
        mm: crate::kernel::MmId,
        semantic_start: carrick_guest_mem::GuestVa,
        semantic_len: usize,
        inventory_revision: u64,
        mapping: carrick_hal::MappingId,
        frame: carrick_hal::FrameId,
        physical_base: carrick_guest_mem::Gpa,
        physical_len: u64,
        owner_generation: carrick_hal::ForeignOwnerGeneration,
    ) -> bool {
        let Some(semantic_len) = std::num::NonZeroUsize::new(semantic_len) else {
            return false;
        };
        let Some(physical_len) = std::num::NonZeroU64::new(physical_len)
            .map(carrick_hal::FrameLength::from_mapping_extent)
        else {
            return false;
        };
        Arc::ptr_eq(&self.kernel, kernel)
            && self.mm == mm
            && self.semantic_start == semantic_start
            && self.semantic_len == semantic_len
            && self.inventory_revision == inventory_revision
            && self.mapping == mapping
            && self.frame == frame
            && self.physical_base == physical_base
            && self.physical_len == physical_len
            && self.owner_generation == owner_generation
            && kernel.frame_inventory().mapping_is_live_exact_at_revision(
                mm,
                inventory_revision,
                mapping,
                frame,
                physical_base,
                physical_len,
            )
    }
}

impl KernelFrameCowAuthority {
    #[allow(dead_code)] // consumed by the HVPatch child publication slice
    pub(crate) fn issue_hvpatch_child_token(
        self: Arc<Self>,
        context: &crate::kernel::KernelContext,
    ) -> Result<carrick_hal::HvpatchChildKernelToken, String> {
        if self.identity.linux_tid != self.tid.raw()
            || self.identity.mm != self.mm.raw()
            || self.identity.asid == 0
        {
            return Err("child token identity does not match Kernel COW authority".to_owned());
        }
        static NEXT_AUTHORITY_ID: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(1);
        let raw = NEXT_AUTHORITY_ID
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |current| current.checked_add(1),
            )
            .map_err(|_| "child COW authority identity exhausted".to_owned())?;
        let authority_identity = std::num::NonZeroU64::new(raw)
            .ok_or_else(|| "child COW authority identity is zero".to_owned())?;
        let identity = self.identity;
        let authority: Arc<dyn carrick_hal::FrameCowAuthority> = self;
        context
            .issue_hvpatch_child_token(authority, identity, authority_identity)
            .map_err(|error| format!("issue exact HVPatch child token: {error}"))
    }
}

#[cfg(test)]
#[derive(Debug)]
struct FixedFrameCowOwnerLease {
    generation: carrick_hal::ForeignOwnerGeneration,
}

#[cfg(test)]
impl carrick_hal::FrameCowOwnerLease for FixedFrameCowOwnerLease {
    fn generation(&self) -> carrick_hal::ForeignOwnerGeneration {
        self.generation
    }

    fn is_current(&self) -> bool {
        true
    }
}

#[cfg(test)]
#[derive(Debug)]
struct FixedFrameCowOwnerInventory {
    generation: carrick_hal::ForeignOwnerGeneration,
}

#[cfg(test)]
impl carrick_hal::FrameCowOwnerInventory for FixedFrameCowOwnerInventory {
    fn retain_current(
        &self,
        _gpa: carrick_guest_mem::Gpa,
        _length: carrick_hal::FrameLength,
    ) -> Result<Box<dyn carrick_hal::FrameCowOwnerLease>, Box<dyn std::error::Error + Send + Sync>>
    {
        Ok(Box::new(FixedFrameCowOwnerLease {
            generation: self.generation,
        }))
    }
}

#[cfg(test)]
pub(crate) fn fixed_frame_cow_owner_inventory_for_test(
    generation: carrick_hal::ForeignOwnerGeneration,
) -> Arc<dyn carrick_hal::FrameCowOwnerInventory> {
    Arc::new(FixedFrameCowOwnerInventory { generation })
}

#[cfg(test)]
pub(crate) fn kernel_frame_cow_authority_for_test(
    kernel: Arc<crate::kernel::Kernel>,
    mm: crate::kernel::MmId,
    guest_executors: Arc<crate::kernel::GuestExecutorCensus>,
    tid: carrick_hal::ThreadId,
    asid: u16,
    owner_inventory: Arc<dyn carrick_hal::FrameCowOwnerInventory>,
) -> Arc<dyn carrick_hal::FrameCowAuthority> {
    Arc::new(KernelFrameCowAuthority {
        deferred_anonymous: None,
        kernel,
        mm,
        owner_inventory,
        guest_executors,
        tid,
        identity: carrick_hal::FrameCowIdentity {
            linux_pid: tid.raw(),
            linux_tid: tid.raw(),
            mm: mm.raw(),
            asid,
        },
        pt_quiesce: Arc::new(carrick_thread::fork_quiesce::PtQuiesce::new()),
    })
}

impl carrick_hal::FrameCowAuthority for KernelFrameCowAuthority {
    fn deferred_anonymous_state(&self) -> Option<Arc<carrick_guest_mem::DeferredAnonymousState>> {
        self.deferred_anonymous.clone()
    }

    fn quiesce(
        &self,
    ) -> Result<Box<dyn carrick_hal::FrameCowQuiesce>, Box<dyn std::error::Error + Send + Sync>>
    {
        quiesce::acquire_frame_cow_quiesce(
            &self.pt_quiesce,
            self.mm,
            &self.guest_executors,
            self.tid,
            quiesce::PtPauseBudget::DEFAULT,
        )
        .map(|guard| Box::new(guard) as Box<dyn carrick_hal::FrameCowQuiesce>)
        .map_err(|error| {
            Box::new(std::io::Error::other(format!(
                "HVPatch frame-COW vCPU quiesce failed: {error:?}"
            ))) as Box<dyn std::error::Error + Send + Sync>
        })
    }

    fn reserve(
        &self,
        frame_candidates: usize,
        mapping_candidates: usize,
        event_count: usize,
    ) -> Result<carrick_hal::FrameInventoryReservation, Box<dyn std::error::Error + Send + Sync>>
    {
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(event_count)?;
        self.kernel
            .reserve_frame_inventory(frame_candidates, mapping_candidates, capacity)
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
    }

    fn apply(
        &self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.kernel
            .frame_inventory()
            .apply(self.mm, commit)
            .map(|_| ())
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
    }

    fn apply_with_receipt(
        &self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<carrick_hal::FrameInventoryApplyReceipt, Box<dyn std::error::Error + Send + Sync>>
    {
        self.kernel
            .frame_inventory()
            .apply_with_receipt(self.mm, commit)
            .map(|(_, receipt)| receipt)
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
    }

    fn apply_foreign_cow(
        &self,
        commit: carrick_hal::FrameInventoryCommit<()>,
        semantic_start: carrick_guest_mem::GuestVa,
        semantic_len: std::num::NonZeroUsize,
        mapping: carrick_hal::MappingId,
        frame: carrick_hal::FrameId,
        gpa: carrick_guest_mem::Gpa,
        length: carrick_hal::FrameLength,
    ) -> Result<
        (
            carrick_hal::FrameInventoryApplyReceipt,
            carrick_hal::ForeignCowKernelProof,
            carrick_hal::ForeignOwnerGeneration,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        // This endpoint is bound from the concrete owner engine when the
        // Kernel COW authority is constructed. It seals the transport's exact
        // semantic and physical publication tuple while independently choosing
        // the retained owner incarnation and generation that will be signed.
        let owner = self.owner_inventory.retain_current(gpa, length)?;
        let owner_generation = owner.generation();
        let ((), receipt) = self
            .kernel
            .frame_inventory()
            .apply_with_receipt(self.mm, commit)
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
        let expected_mm = std::num::NonZeroU64::new(self.mm.raw()).unwrap_or_else(|| {
            carrick_fatal!(
                "kernel::mm_identity",
                "KernelFrameCowAuthority target MmId is zero"
            )
        });
        if receipt.mm() != expected_mm
            || !receipt.authorizes(mapping, frame)
            || !self
                .kernel
                .frame_inventory()
                .mapping_is_live_exact_at_revision(
                    self.mm,
                    receipt.revision(),
                    mapping,
                    frame,
                    gpa,
                    length,
                )
            || !owner.is_current()
        {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "Applied foreign COW frame inventory receipt failed authorization, revision, or owner generation verification"
            );
        }
        let proof = KernelForeignCowProof::new(
            Arc::clone(&self.kernel),
            self.mm,
            semantic_start,
            semantic_len,
            receipt.revision(),
            mapping,
            frame,
            gpa,
            length,
            owner_generation,
        );
        Ok((
            receipt,
            carrick_hal::ForeignCowKernelProof::from_runtime_authority(Box::new(proof)),
            owner_generation,
        ))
    }

    fn attest_foreign_identity_write(
        &self,
        semantic_start: carrick_guest_mem::GuestVa,
        semantic_len: std::num::NonZeroUsize,
        inventory_revision: u64,
        mapping: carrick_hal::MappingId,
        frame: carrick_hal::FrameId,
        gpa: carrick_guest_mem::Gpa,
        length: carrick_hal::FrameLength,
    ) -> Result<
        (
            carrick_hal::ForeignCowKernelProof,
            carrick_hal::ForeignOwnerGeneration,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        // No inventory mutation happens for an identity write, so the proof
        // binds the revision the CALLER's snapshot captured; the mapping must
        // be live at exactly that revision or the snapshot is stale and the
        // transport retries. The owner retention pins the current host
        // incarnation for the duration of the mint, and its generation is the
        // one the prepared write will re-verify against the extent ledger.
        let owner = self.owner_inventory.retain_current(gpa, length)?;
        let owner_generation = owner.generation();
        if !self
            .kernel
            .frame_inventory()
            .mapping_is_live_exact_at_revision(
                self.mm,
                inventory_revision,
                mapping,
                frame,
                gpa,
                length,
            )
            || !owner.is_current()
        {
            return Err(Box::new(std::io::Error::other(
                "identity write attestation: mapping not live at snapshot revision",
            )));
        }
        let proof = KernelForeignCowProof::new(
            Arc::clone(&self.kernel),
            self.mm,
            semantic_start,
            semantic_len,
            inventory_revision,
            mapping,
            frame,
            gpa,
            length,
            owner_generation,
        );
        Ok((
            carrick_hal::ForeignCowKernelProof::from_runtime_authority(Box::new(proof)),
            owner_generation,
        ))
    }

    fn mapping_is_live(
        &self,
        mapping: carrick_hal::MappingId,
        frame: carrick_hal::FrameId,
        gpa: carrick_guest_mem::Gpa,
        length: carrick_hal::FrameLength,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let inventory = self.kernel.frame_inventory();
        if inventory.mapping_is_live_exact(self.mm, mapping, frame, gpa, length) {
            return Ok(true);
        }
        let candidates: Vec<_> = inventory
            .snapshot()
            .mappings
            .into_iter()
            .filter(|row| {
                row.mapping == mapping
                    || row.frame == frame
                    || (row.gpa == gpa && row.length == length)
            })
            .take(16)
            .collect();
        Err(Box::new(std::io::Error::other(format!(
            "frame mapping is not exact-live: expected mm={:?} mapping={mapping:?} frame={frame:?} gpa={gpa:?} length={} candidates={candidates:?}",
            self.mm,
            length.raw(),
        ))))
    }

    fn frame_mapping_count(
        &self,
        frame: carrick_hal::FrameId,
    ) -> Result<Option<usize>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.kernel.frame_inventory().frame_mapping_count(frame))
    }

    #[allow(clippy::type_complexity)]
    fn retirement_batch_query(
        &self,
        candidate_extents: &[(
            carrick_hal::MappingId,
            carrick_hal::FrameId,
            carrick_guest_mem::Gpa,
            carrick_hal::FrameLength,
        )],
        candidate_frames: &[carrick_hal::FrameId],
    ) -> Result<(Vec<bool>, Vec<Option<usize>>), Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.kernel.frame_inventory().retirement_batch_query(
            self.mm,
            candidate_extents,
            candidate_frames,
        ))
    }
}

/// HVPatch multiplexes every Linux process inside one carrier, so no guest exit
/// is ever a host-process exit: the terminal owner always unwinds. This was
/// true only for the retired host-fork lanes, where a forked child had to
/// `_exit` without running Drop over its parent's inherited fd table.
pub(crate) fn requires_no_unwind_host_exit(kernel: &Kernel, engine_is_forked_child: bool) -> bool {
    let _ = (kernel, engine_is_forked_child);
    false
}

/// Enter sole-executor stage-1 authority only from an exact-MM census token.
/// Normalized handlers receive no such token.
pub(crate) fn with_sole_mm_stage1<T>(
    participation: &mut crate::dispatch::MmExecutorParticipation,
    run: impl FnOnce(&mut quiesce::SoleMmStage1<'_>) -> T,
) -> Option<T> {
    let mut authority = quiesce::SoleMmStage1::claim(participation)?;
    Some(run(&mut authority))
}

#[cfg(test)]
pub(crate) fn with_real_pt_pause_for_test<T>(
    coordinator: Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>,
    run: impl FnOnce(&mut quiesce::PtPauseGuard<'_>) -> T,
) -> T {
    quiesce::with_real_mutation_pause_for_test(coordinator, run)
}

#[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
pub(crate) fn with_foreign_mm_mutation_guard<T>(
    barrier: &Arc<crate::fork_quiesce::PtQuiesce>,
    mm: crate::kernel::MmId,
    coordinator: Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>,
    census: &crate::kernel::GuestExecutorCensus,
    stage1: Arc<crate::hvpatch::Stage1MmLease>,
    tid: carrick_hal::ThreadId,
    run: impl FnOnce(&mut crate::dispatch::mm_mutation::MmMutationGuard<'_>) -> T,
) -> Result<T, crate::dispatch::mm_mutation::ForeignMmMutationError> {
    let mut authority = quiesce::acquire_foreign_mm_mutation_quiesce(
        barrier,
        mm,
        census,
        coordinator,
        stage1,
        tid,
        quiesce::PtPauseBudget::DEFAULT,
    )
    .map_err(|error| match error {
        quiesce::PtPauseError::TimedOut => {
            crate::dispatch::mm_mutation::ForeignMmMutationError::TimedOut
        }
        quiesce::PtPauseError::UnkickableExecutor => {
            crate::dispatch::mm_mutation::ForeignMmMutationError::UnkickableExecutor
        }
    })?;
    let mut mutation = crate::dispatch::mm_mutation::from_frame_cow(&mut authority);
    Ok(run(&mut mutation))
}

/// Hand the dispatcher the loaded image's region list + auxv so /proc/self/maps
/// and /proc/self/auxv reflect it (refreshed on each execve).
pub(crate) fn apply_image_proc_state(
    dispatcher: &mut SyscallDispatcher,
    image: &AddressSpace,
) -> Result<(), DispatchError> {
    dispatcher.publish_initial_image_state(
        proc_maps_from_address_space(image),
        image.linux_auxv_image().to_vec(),
        core_file_mappings_from_address_space(image),
        crate::dispatch::boot_private_file_backings(image),
    )
}

/// Publish a successful exec image as one dispatcher VMA generation.
pub(crate) fn apply_exec_image_proc_state(
    dispatcher: &SyscallDispatcher,
    replacement_mm_id: crate::kernel::MmId,
    image: &AddressSpace,
) -> crate::dispatch::PreparedDispatchMmExec {
    dispatcher.publish_exec_image_state(
        replacement_mm_id,
        proc_maps_from_address_space(image),
        image.linux_auxv_image().to_vec(),
        core_file_mappings_from_address_space(image),
        crate::dispatch::boot_private_file_backings(image),
    )
}

pub(crate) fn core_file_mappings_from_address_space(
    image: &AddressSpace,
) -> Vec<crate::core_dump::FileMapping> {
    image
        .file_mappings()
        .iter()
        .filter(|mapping| !mapping.path.is_empty())
        .map(|mapping| crate::core_dump::FileMapping {
            start: mapping.start,
            end: mapping.end,
            file_page_offset: mapping.file_page_offset,
            path: mapping.path.clone(),
        })
        .collect()
}

/// Stamp the per-process identity page the EL1 syscall shim reads (no-op unless
/// the shim is enabled). Must run before the guest issues any intercepted
/// syscall: at boot, and again in a forked child / after execve, since the
/// child's pid and the new image's identity differ.
pub(crate) fn stamp_identity_page<M: CurrentMmMemory>(
    memory: &mut M,
    dispatcher: &SyscallDispatcher,
    kernel_context: &crate::kernel::KernelContext,
) -> Result<(), carrick_guest_mem::MemoryError> {
    stamp_identity_page_at(
        memory,
        dispatcher,
        kernel_context,
        crate::memory::LINUX_IDENTITY_PAGE_BASE,
    )
}

pub(crate) fn stamp_identity_page_at<M: CurrentMmMemory>(
    memory: &mut M,
    dispatcher: &SyscallDispatcher,
    kernel_context: &crate::kernel::KernelContext,
    base: u64,
) -> Result<(), carrick_guest_mem::MemoryError> {
    if !crate::syscall_shim_enabled() {
        return Ok(());
    }
    let id = dispatcher.identity_snapshot(kernel_context);
    // FAIL CLOSED on an unpublishable identity.
    //
    // `getpid()` never returns 0 on Linux, so a zero here means the identity
    // is not knowable yet rather than that it is zero — a pid-namespace
    // translation that has not been registered resolves to 0 through the
    // `unwrap_or(0)` in `identity_pid`. Opening the fast-path gate over that
    // publishes a pid no Linux process has, and the guest reads it in
    // userspace with NO vm exit, so nothing ever re-checks it. Observed as a
    // container's init reporting `getpid=0`.
    //
    // Leaving the gate SHUT costs only speed: the guest traps and the
    // dispatcher answers correctly. A later stamp re-opens it once the
    // identity is real.
    let shim_enabled = identity_gate_word(dispatcher.identity_fast_path_enabled(), id.pid);
    stamp_identity_values(memory, base, id.pid, shim_enabled)
}

/// The value to publish in the identity page's shim gate.
///
/// Non-zero opens the userspace fast path, so it must only ever be opened over
/// a pid a guest could legitimately observe. `getpid()` never returns 0 on
/// Linux: a zero here means the identity is not knowable YET — an unregistered
/// pid-namespace translation resolves to 0 through the `unwrap_or(0)` in
/// `identity_pid` — not that the pid is zero. Publishing it would let a guest
/// read a pid no process has, with no vm exit and nothing to re-check it.
///
/// Shutting the gate costs only speed: the guest traps and the dispatcher
/// answers correctly, and a later stamp opens it once the identity is real.
pub(crate) fn identity_gate_word(fast_path_enabled: bool, pid: u32) -> u32 {
    u32::from(fast_path_enabled && pid != 0)
}

pub(crate) fn stamp_identity_values<M: CurrentMmMemory>(
    memory: &mut M,
    base: u64,
    pid: u32,
    shim_enabled: u32,
) -> Result<(), carrick_guest_mem::MemoryError> {
    // Disable the fast path FIRST, then publish the identity, then re-enable.
    //
    // The shim word is the gate: while it is non-zero the guest answers
    // getpid/gettid from this page in userspace with NO vm exit, so nothing
    // re-checks the value it reads. Writing the pid before the gate is only
    // safe if the gate is known to be closed, and on a carrier VM it is not —
    // the identity page's backing is recycled between containers, so a
    // container can begin life with a predecessor's `1` still in the gate
    // while its own pid slot reads zero. The guest then reports pid 0, which
    // no Linux process ever sees. It is rare because the window is short, and
    // it widens under load, which is precisely why it must be closed rather
    // than tolerated.
    //
    // Closing the gate first costs nothing: a guest that reads it mid-stamp
    // takes the trap path and gets the correct answer from the dispatcher.
    memory.write_bytes(
        base + crate::memory::IDENTITY_OFF_SHIM_ENABLED,
        &0_u32.to_le_bytes(),
    )?;
    // Pair for the release below: the CLOSE must be observable before the
    // identity it protects starts changing, or a guest can see the old gate
    // open over a half-written pid.
    std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
    memory.write_bytes(base + crate::memory::IDENTITY_OFF_PID, &pid.to_le_bytes())?;
    // A fresh stamp starts a fresh serviced-syscall ledger: a forked child
    // COWs its parent's identity page and must not inherit the parent's
    // counter (Linux children start rusage at zero), and an exec'd image
    // keeps its task ledger but not the page. (The exec re-stamp drops any
    // pre-exec counted-but-unfolded syscalls — a µs-scale undercount.)
    memory.write_bytes(
        base + crate::memory::IDENTITY_OFF_SHIM_SYSCALLS,
        &0_u64.to_le_bytes(),
    )?;
    // RELEASE the identity before opening the gate.
    //
    // Ordering the stores in program order is necessary but NOT sufficient.
    // The guest reads this page from another vCPU, and AArch64 lets plain
    // stores be observed out of order: without a barrier a guest can see the
    // gate word already non-zero while the pid store is not yet visible, and
    // report pid 0 through a fast path that never traps. That is the whole
    // failure — intermittent, wider under load, and closed by anything that
    // slows the writer down (which is why logging or a debug build hides it).
    //
    // The gate is a publication flag, so it needs release semantics: every
    // store above must be observable before the store that opens it.
    std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
    memory.write_bytes(
        base + crate::memory::IDENTITY_OFF_SHIM_ENABLED,
        &shim_enabled.to_le_bytes(),
    )?;
    Ok(())
}

/// The tid the guest must observe for this thread, in its OWN pid namespace.
///
/// `getpid` is namespace-translated (the identity page publishes
/// `ns_self_pid_for`), so `gettid` has to be too, or a thread-group leader
/// observes `gettid() != getpid()` -- which no Linux process can, because a
/// leader's tid IS its tgid. Inside a container the two numbering spaces are
/// offset, so every containerized guest saw it.
///
/// Every task and secondary thread owns an exact namespace identity. A missing
/// mapping is an invariant failure; returning zero would publish a TID Linux
/// can never assign and could be mistaken for a successful fast-path stamp.
pub(crate) fn ns_visible_guest_tid(
    _dispatcher: &SyscallDispatcher,
    context: &crate::kernel::KernelContext,
) -> Option<u32> {
    u32::try_from(context.thread().key().tid.raw())
        .ok()
        .and_then(|tid| crate::namespace::pid::kernel_to_ns_for(context, tid))
}

/// Stamp the EL1 `gettid` fast-path register with the NAMESPACE-visible tid.
///
/// The guest reads this register in userspace with no vm exit and compares it
/// against a namespace-translated `getpid`, so publishing the raw kernel-graph
/// tid here is what let a leader observe `gettid() != getpid()`. See
/// [`ns_visible_guest_tid`].
pub(crate) fn stamp_ns_visible_guest_tid<E: ThreadedEngine>(
    engine: &E,
    dispatcher: &SyscallDispatcher,
    context: &crate::kernel::KernelContext,
) -> Result<(), TrapError> {
    stamp_ns_visible_guest_tid_with(crate::syscall_shim_enabled(), dispatcher, context, |tid| {
        engine.set_guest_thread_id(tid)
    })
}

/// The injectable seam under [`stamp_ns_visible_guest_tid`]: a failed stamp is
/// mandatory to propagate, because a guest whose fast-path register was not
/// published answers `gettid` from whatever the previous lease left there.
pub(crate) fn stamp_ns_visible_guest_tid_with(
    shim_enabled: bool,
    dispatcher: &SyscallDispatcher,
    context: &crate::kernel::KernelContext,
    set: impl FnOnce(u64) -> Result<(), TrapError>,
) -> Result<(), TrapError> {
    if !shim_enabled {
        return Ok(());
    }
    let tid = ns_visible_guest_tid(dispatcher, context).ok_or_else(|| {
        TrapError::Hypervisor(format!(
            "live thread {} is missing its container-visible TID",
            context.thread().key().tid.raw()
        ))
    })?;
    set(u64::from(tid))
}

pub(crate) fn proc_maps_from_address_space(image: &AddressSpace) -> Vec<ProcMapsEntry> {
    // Linux reserves RLIMIT_STACK as the maximum grow-down extent, but the
    // initial [stack] VMA covers only the argument/environment tail plus the
    // kernel's 128 KiB pre-expansion. Musl's pthread_getattr_np reads that VMA;
    // projecting the full Carrick backing falsely reports an already-grown
    // 8 MiB mapping. The backing remains the full RLIMIT-sized region so deep
    // recursion still has the same capacity as Linux.
    const INITIAL_STACK_VMA_EXPANSION: u64 = 128 * 1024;
    let stack_backing_start = crate::memory::LINUX_STACK_TOP - crate::memory::LINUX_STACK_SIZE;
    let initial_stack_vma_start = image.initial_stack_pointer().map(|stack_pointer| {
        stack_pointer
            .saturating_sub(INITIAL_STACK_VMA_EXPANSION)
            .max(stack_backing_start)
            & !(crate::linux_abi::LINUX_PAGE_SIZE - 1)
    });
    image
        .regions()
        .iter()
        .map(|region| {
            let is_initial_stack =
                region.start == stack_backing_start && region.end == crate::memory::LINUX_STACK_TOP;
            ProcMapsEntry {
                start: if is_initial_stack {
                    initial_stack_vma_start.unwrap_or(region.start)
                } else {
                    region.start
                },
                end: region.end,
                read: region.perms.read,
                write: region.perms.write,
                execute: region.perms.execute,
                sharing: ProcMapSharing::Private,
                path: if is_initial_stack {
                    "[stack]".to_owned()
                } else {
                    String::new()
                },
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_maps_projects_linux_initial_stack_vma_not_full_rlimit_backing() {
        let image = crate::memory::AddressSpace::from_regions(0x1_0000, Vec::new())
            .expect("empty image")
            .with_linux_initial_stack([b"tool".as_slice()], [b"KEY=value".as_slice()])
            .expect("initial stack");
        let initial_sp = image.initial_stack_pointer().expect("initial SP");
        let maps = proc_maps_from_address_space(&image);
        let stack = maps
            .iter()
            .find(|mapping| mapping.path == "[stack]")
            .expect("Linux-visible stack VMA");
        let expected_start =
            initial_sp.saturating_sub(128 * 1024) & !(crate::linux_abi::LINUX_PAGE_SIZE - 1);

        assert_eq!(stack.start, expected_start);
        assert_eq!(stack.end, crate::memory::LINUX_STACK_TOP);
        assert!(
            stack.start > crate::memory::LINUX_STACK_TOP - crate::memory::LINUX_STACK_SIZE,
            "the full RLIMIT-sized backing is not the initially grown Linux VMA"
        );
    }

    #[test]
    fn identity_gate_stays_shut_over_an_unpublishable_pid() {
        // `getpid()` never returns 0 on Linux, so a zero identity means "not
        // knowable yet", not "zero" — an unregistered pid-namespace
        // translation resolves to 0 via `unwrap_or(0)` in `identity_pid`.
        // Opening the fast path over it publishes a pid no process has, and
        // the guest reads it with NO vm exit, so nothing re-checks it. Seen as
        // a container's init reporting `getpid=0`.
        //
        // Drop the `pid != 0` term and the first assertion fails.
        assert_eq!(
            identity_gate_word(true, 0),
            0,
            "an unpublishable identity must leave the fast path SHUT"
        );
        assert_eq!(
            identity_gate_word(true, 1),
            1,
            "a real pid still opens the fast path"
        );
        assert_eq!(
            identity_gate_word(false, 1),
            0,
            "a caller that disabled the fast path still wins"
        );
    }

    #[test]
    fn identity_stamp_closes_the_shim_gate_before_publishing_a_new_pid() {
        // The shim word gates a userspace read with NO vm exit, so the guest
        // may look at this page at any instant. Starting from a page that a
        // previous container left ENABLED with a stale pid, the stamp must
        // never leave the gate open over a pid it has not written yet —
        // otherwise the guest reads a pid that belongs to no one (observed as
        // `getpid=0` from a container's init, which no Linux process reports).
        //
        // Records the exact write order and asserts the gate is shut before the
        // pid moves and reopened only after. Under the old order (pid, then
        // gate) the first recorded write is the pid, and this fails.
        #[derive(Default)]
        struct RecordingMemory {
            base: u64,
            page: Vec<u8>,
            order: Vec<(u64, u64)>,
        }
        impl carrick_guest_mem::GuestMemory for RecordingMemory {
            fn read_bytes_raw(
                &self,
                addr: u64,
                len: usize,
            ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
                let off = (addr - self.base) as usize;
                Ok(self.page[off..off + len].to_vec())
            }
            fn write_bytes_raw(
                &mut self,
                addr: u64,
                bytes: &[u8],
            ) -> Result<(), carrick_guest_mem::MemoryError> {
                let off = (addr - self.base) as usize;
                self.page[off..off + bytes.len()].copy_from_slice(bytes);
                let mut word = [0u8; 8];
                let n = bytes.len().min(8);
                word[..n].copy_from_slice(&bytes[..n]);
                self.order
                    .push((addr - self.base, u64::from_le_bytes(word)));
                Ok(())
            }
        }
        impl carrick_guest_mem::CurrentMmMemory for RecordingMemory {}

        let base = crate::memory::LINUX_IDENTITY_PAGE_BASE;
        let mut memory = RecordingMemory {
            base,
            page: vec![0; 4096],
            order: Vec::new(),
        };
        // The predecessor's residue: gate open, someone else's pid.
        memory.page[crate::memory::IDENTITY_OFF_SHIM_ENABLED as usize] = 1;
        memory.page[crate::memory::IDENTITY_OFF_PID as usize] = 7;

        stamp_identity_values(&mut memory, base, 1, 1).expect("stamp");

        let gate = crate::memory::IDENTITY_OFF_SHIM_ENABLED;
        let pid_off = crate::memory::IDENTITY_OFF_PID;
        let first_gate_write = memory
            .order
            .iter()
            .position(|(off, _)| *off == gate)
            .expect("the gate must be written");
        let pid_write = memory
            .order
            .iter()
            .position(|(off, _)| *off == pid_off)
            .expect("the pid must be written");
        assert!(
            first_gate_write < pid_write,
            "the shim gate must be CLOSED before the pid moves; write order was {:?}",
            memory.order
        );
        assert_eq!(
            memory.order[first_gate_write].1, 0,
            "the first gate write must shut it, not re-open it"
        );
        assert_eq!(
            memory.order.last().map(|(off, val)| (*off, *val)),
            Some((gate, 1)),
            "the gate must be re-opened LAST, after pid and ledger are published"
        );
    }

    #[test]
    fn identity_page_stamp_surfaces_guest_memory_write_failure() {
        let base = crate::memory::LINUX_IDENTITY_PAGE_BASE;
        let mut memory = crate::dispatch::LinearMemory::new(base, vec![0; 4]);
        let error = stamp_identity_values(&mut memory, base, 123, 1)
            .expect_err("second identity word is outside the backing");
        assert!(matches!(
            error,
            carrick_guest_mem::MemoryError::OutOfBounds { .. }
        ));
    }

    #[test]
    fn mandatory_child_contextidr_stamp_propagates_injected_failure() {
        let (_, context) = crate::hvpatch::process_context_for_tests(70_200);
        let dispatcher = crate::dispatch::SyscallDispatcher::new();
        let error = stamp_ns_visible_guest_tid_with(true, &dispatcher, &context, |_| {
            Err(TrapError::Hypervisor(
                "injected CONTEXTIDR failure".to_owned(),
            ))
        })
        .unwrap_err();
        assert!(error.to_string().contains("CONTEXTIDR"));
    }

    /// Editing stage-1 and NEEDING A PAUSE are different questions, and the
    /// page-table manager keys table reclaim on the first. A sole guest
    /// executor takes no pause precisely because it is already exclusive, so if
    /// exclusivity were derived from pause ownership it would read as "shared"
    /// there — which is the shape that leaked one stage-1 table per
    /// `mmap(MAP_SHARED, fd)` until the pool hit `OutOfTables`.
    #[test]
    fn stage1_editors_are_claimed_regardless_of_peers() {
        for &editor in crate::dispatch::MM_MUTATION_SYSCALLS {
            assert!(
                syscall_edits_stage1(editor, 0),
                "{editor} edits stage-1 whether or not a peer exists"
            );
            assert_eq!(
                syscall_takes_pre_dispatch_pt_pause(editor, 0, true),
                syscall_edits_stage1(editor, 0)
            );
        }
        assert!(!syscall_edits_stage1(63, 0), "read edits no descriptors");
    }

    /// The pre-dispatch page-table pause exists to keep ONE global lock order
    /// (pause, then the dispatcher's host-alias phase). `MADV_DONTNEED` is in
    /// the set because it is the one host-alias-taking syscall that reaches the
    /// backend's self-quiescing `zero_backing` path; without it the two orders
    /// crossed and deadlocked a whole guest at ~0% CPU.
    #[test]
    fn pre_dispatch_pt_pause_covers_madvise_dontneed() {
        for &editor in crate::dispatch::MM_MUTATION_SYSCALLS {
            assert!(syscall_takes_pre_dispatch_pt_pause(editor, 0, true));
            assert!(
                !syscall_takes_pre_dispatch_pt_pause(editor, 0, false),
                "a single-vCPU process has no sibling to pause"
            );
        }
        assert!(!syscall_takes_pre_dispatch_pt_pause(63, 0, true));
    }
}
