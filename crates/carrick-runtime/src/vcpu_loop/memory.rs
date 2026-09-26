//! Memory, page-table mutation, identity page, and COW authority for the vCPU loop.

use carrick_fatal::carrick_fatal;
use carrick_hal::{ThreadedEngine, TrapError};
use carrick_mem::memory::AddressSpace;
use std::sync::Arc;

use super::Kernel;
use carrick_kernel::dispatch::{DispatchError, SyscallDispatcher};
use carrick_kernel::kernel::KernelForeignCowProof;
use carrick_kernel::run_result::RuntimeError;
use carrick_vfs::{ProcMapSharing, ProcMapsEntry};

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
    carrick_kernel::dispatch::syscall_requires_mm_mutation(
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
    context: &carrick_kernel::kernel::KernelContext,
    commit: carrick_hal::FrameInventoryCommit<()>,
) -> Result<(), carrick_kernel::kernel::FrameInventoryError> {
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
pub(crate) struct RefuseAliasInstallSpec {
    pub(crate) site: carrick_kernel::kernel::debug::HvpatchAliasInstallSite,
    pub(crate) guest_pid: i32,
    pub(crate) guest_tid: i32,
    pub(crate) va: u64,
    pub(crate) len: u64,
    pub(crate) prot: u64,
    pub(crate) shared: bool,
    pub(crate) prot_none: bool,
    pub(crate) error: String,
    pub(crate) frame: Option<carrick_hal::FrameId>,
}

pub(crate) fn refuse_alias_install(
    kernel: &Kernel,
    context: &carrick_kernel::kernel::KernelContext,
    spec: RefuseAliasInstallSpec,
) -> RuntimeError {
    let RefuseAliasInstallSpec {
        site,
        guest_pid,
        guest_tid,
        va,
        len,
        prot,
        shared,
        prot_none,
        error,
        frame,
    } = spec;
    let pending_reservation = frame
        .and_then(|frame| {
            context
                .kernel()
                .frame_inventory()
                .pending_reservation_for_frame(frame)
        })
        .map(|transaction| transaction.raw());
    let reason = carrick_kernel::kernel::debug::AbortReason::HvpatchAliasInstall {
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
    pub(crate) kernel: Arc<carrick_kernel::kernel::Kernel>,
    pub(crate) mm: carrick_kernel::kernel::MmId,
    pub(crate) owner_inventory: Arc<dyn carrick_hal::FrameCowOwnerInventory>,
    pub(crate) tid: carrick_hal::ThreadId,
    pub(crate) identity: carrick_hal::FrameCowIdentity,
    pub(crate) pt_quiesce: Arc<carrick_thread::fork_quiesce::PtQuiesce>,
}

impl KernelFrameCowAuthority {
    #[allow(dead_code)] // consumed by the HVPatch child publication slice
    pub(crate) fn issue_hvpatch_child_token(
        self: Arc<Self>,
        context: &carrick_kernel::kernel::KernelContext,
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
    kernel: Arc<carrick_kernel::kernel::Kernel>,
    mm: carrick_kernel::kernel::MmId,
    tid: carrick_hal::ThreadId,
    asid: u16,
    owner_inventory: Arc<dyn carrick_hal::FrameCowOwnerInventory>,
) -> Arc<dyn carrick_hal::FrameCowAuthority> {
    Arc::new(KernelFrameCowAuthority {
        deferred_anonymous: None,
        kernel,
        mm,
        owner_inventory,
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
        carrick_kernel::dispatch::mm_quiesce::acquire_frame_cow_quiesce(
            &self.pt_quiesce,
            self.mm,
            self.tid,
            carrick_kernel::dispatch::mm_quiesce::PtPauseBudget::DEFAULT,
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
        carrick_kernel::dispatch::boot_private_file_backings(image),
    )
}

/// Publish a successful exec image as one dispatcher VMA generation.
pub(crate) fn apply_exec_image_proc_state(
    dispatcher: &SyscallDispatcher,
    replacement_mm_id: carrick_kernel::kernel::MmId,
    image: &AddressSpace,
) -> carrick_kernel::dispatch::PreparedDispatchMmExec {
    dispatcher.publish_exec_image_state(
        replacement_mm_id,
        proc_maps_from_address_space(image),
        image.linux_auxv_image().to_vec(),
        core_file_mappings_from_address_space(image),
        carrick_kernel::dispatch::boot_private_file_backings(image),
    )
}

pub(crate) fn core_file_mappings_from_address_space(
    image: &AddressSpace,
) -> Vec<carrick_kernel::core_dump::FileMapping> {
    image
        .file_mappings()
        .iter()
        .filter(|mapping| !mapping.path.is_empty())
        .map(|mapping| carrick_kernel::core_dump::FileMapping {
            start: mapping.start,
            end: mapping.end,
            file_page_offset: mapping.file_page_offset,
            path: mapping.path.clone(),
        })
        .collect()
}

/// Stamp the EL1 `gettid` fast-path register with the NAMESPACE-visible tid.
///
/// The guest reads this register in userspace with no vm exit and compares it
/// against a namespace-translated `getpid`, so publishing the raw kernel-graph
/// tid here is what let a leader observe `gettid() != getpid()`. See
/// [`carrick_kernel::namespace::pid::ns_visible_guest_tid`].
pub(crate) fn stamp_ns_visible_guest_tid<E: ThreadedEngine>(
    engine: &E,
    context: &carrick_kernel::kernel::KernelContext,
) -> Result<(), TrapError> {
    stamp_ns_visible_guest_tid_with(carrick_kernel::syscall_shim_enabled(), context, |tid| {
        engine.set_guest_thread_id(tid)
    })
}

/// The injectable seam under [`stamp_ns_visible_guest_tid`]: a failed stamp is
/// mandatory to propagate, because a guest whose fast-path register was not
/// published answers `gettid` from whatever the previous lease left there.
pub(crate) fn stamp_ns_visible_guest_tid_with(
    shim_enabled: bool,
    context: &carrick_kernel::kernel::KernelContext,
    set: impl FnOnce(u64) -> Result<(), TrapError>,
) -> Result<(), TrapError> {
    if !shim_enabled {
        return Ok(());
    }
    let tid = carrick_kernel::namespace::pid::ns_visible_guest_tid(context).ok_or_else(|| {
        TrapError::Hypervisor(format!(
            "live thread {} is missing its container-visible TID",
            context.thread().key().tid.raw()
        ))
    })?;
    let task_id = u32::try_from(context.task().key().id.raw()).unwrap_or(0);
    let pid = carrick_kernel::namespace::pid::ns_self_pid_for(context, task_id);
    let packed = (u64::from(pid) << 32) | u64::from(tid);
    set(packed)
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
    mod native_buffers;
    mod native_floor;
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
    fn mandatory_child_contextidr_stamp_propagates_injected_failure() {
        let (_, context) = crate::hvpatch::process_context_for_tests(70_200);
        let error = stamp_ns_visible_guest_tid_with(true, &context, |_| {
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
        for &editor in carrick_kernel::dispatch::MM_MUTATION_SYSCALLS {
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
        for &editor in carrick_kernel::dispatch::MM_MUTATION_SYSCALLS {
            assert!(syscall_takes_pre_dispatch_pt_pause(editor, 0, true));
            assert!(
                !syscall_takes_pre_dispatch_pt_pause(editor, 0, false),
                "a single-vCPU process has no sibling to pause"
            );
        }
        assert!(!syscall_takes_pre_dispatch_pt_pause(63, 0, true));
    }

    #[test]
    fn remap_file_pages_does_not_pause_stage1() {
        assert!(
            !syscall_edits_stage1(carrick_abi::syscall::nr::REMAP_FILE_PAGES.raw(), 0),
            "remap_file_pages only updates attachment metadata or copies bytes"
        );
        assert!(!syscall_takes_pre_dispatch_pt_pause(
            carrick_abi::syscall::nr::REMAP_FILE_PAGES.raw(),
            0,
            true,
        ));
    }

    #[test]
    fn shmdt_validates_before_pausing_stage1() {
        assert!(
            !syscall_edits_stage1(carrick_abi::syscall::nr::SHMDT.raw(), 0),
            "shmdt must reject invalid or remapped attachments before acquiring mutation authority"
        );
        assert!(!syscall_takes_pre_dispatch_pt_pause(
            carrick_abi::syscall::nr::SHMDT.raw(),
            0,
            true,
        ));
    }

    // ------------------------------------------------------------------
    // Carrier foreign-COW projection tests. These exercise the production
    // HVF carrier harness, the stage-1 composition and `KernelFrameCowAuthority`
    // (the carrier's projection of the kernel COW authority); they build on
    // the kernel's `mm_access` test fixtures and mocks, imported below.
    // ------------------------------------------------------------------
    use std::num::NonZeroU64;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use carrick_abi::LinuxCloneFlags;
    use carrick_guest_mem::{Gpa, GuestVa};
    use carrick_hal::{
        ForeignCowReceipt, ForeignMmReadLease, ForeignMmReadReceipt, ForeignMmSnapshot,
        ForeignMmTransport, ForeignMmTransportError, ThreadId, VcpuKickDyn, VcpuRegistry,
    };

    use carrick_kernel::kernel::mm_access::ProjectedForeignMmSnapshot;
    use carrick_kernel::kernel::mm_access::test_support::{
        MockCowCounters, MockCowFault, MockCowReceipt, MockCowTransport, bootstrap, cow_fixture,
        execution_lease, fixture_backend, foreign_mm, fork_with_backend, publish_cow_mapping,
        with_foreign_mutation,
    };
    use carrick_kernel::kernel::objects::ExecutorId;
    use carrick_kernel::kernel::{
        ClonePlan, Kernel, KernelContext, LinuxWaitStatus, MmAccessError, MmBackend, MmId,
        MmRelation, SnapshotError, VmaAccess,
    };

    struct LeaveGuestOnKick(Arc<carrick_hal::InGuestFlag>);

    impl VcpuKickDyn for LeaveGuestOnKick {
        fn kick(&self) {
            self.0.leave_guest();
        }
    }

    struct OwnerSigningOracleTransport {
        lease: Arc<OwnerSigningOracleLease>,
    }

    impl std::fmt::Debug for OwnerSigningOracleTransport {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("OwnerSigningOracleTransport")
                .finish_non_exhaustive()
        }
    }

    struct OwnerSigningOracleLease {
        authority: Arc<dyn carrick_hal::FrameCowAuthority>,
        commit: parking_lot::Mutex<Option<carrick_hal::FrameInventoryCommit<()>>>,
        mapping: carrick_hal::MappingId,
        frame: carrick_hal::FrameId,
        physical_base: Gpa,
        physical_len: carrick_hal::FrameLength,
        transport_chosen_owner: carrick_hal::ForeignOwnerGeneration,
    }

    impl std::fmt::Debug for OwnerSigningOracleLease {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("OwnerSigningOracleLease")
                .field("mapping", &self.mapping)
                .field("frame", &self.frame)
                .field("physical_base", &self.physical_base)
                .field("physical_len", &self.physical_len)
                .field("transport_chosen_owner", &self.transport_chosen_owner)
                .finish_non_exhaustive()
        }
    }

    impl ForeignMmReadLease for OwnerSigningOracleLease {
        fn read(
            &self,
            _invocation: &carrick_hal::ForeignMmInvocation,
            _authority: &dyn carrick_hal::ForeignMmLiveAuthority,
            _snapshot: &dyn ForeignMmSnapshot,
            _va: GuestVa,
            _dst: &mut [u8],
            _deadline: Instant,
        ) -> Result<Box<dyn ForeignMmReadReceipt>, ForeignMmTransportError> {
            Err(ForeignMmTransportError::AuthorityUnavailable)
        }

        fn break_cow(
            &self,
            _invocation: &carrick_hal::ForeignMmInvocation,
            _invalidator: &mut dyn carrick_hal::ForeignMmInvalidator,
            snapshot: &dyn ForeignMmSnapshot,
            va: GuestVa,
            len: usize,
            _executable: Option<&carrick_hal::ForeignPtraceTextCowPlan>,
            _deadline: Instant,
        ) -> Result<Box<dyn ForeignCowReceipt>, ForeignMmTransportError> {
            let commit = self
                .commit
                .lock()
                .take()
                .ok_or(ForeignMmTransportError::MutationFailed)?;
            let (apply, kernel_proof, _independent_owner) = self
                .authority
                .apply_foreign_cow(
                    commit,
                    va,
                    std::num::NonZeroUsize::new(len)
                        .ok_or(ForeignMmTransportError::MutationFailed)?,
                    self.mapping,
                    self.frame,
                    self.physical_base,
                    self.physical_len,
                )
                .map_err(|_| ForeignMmTransportError::MutationFailed)?;
            Ok(Box::new(MockCowReceipt {
                mm: snapshot.mm(),
                start: va,
                len,
                backend: snapshot.backend_revision(),
                vma: snapshot.vma_revision(),
                inventory: carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(
                    apply.revision(),
                ),
                mapping: self.mapping,
                frame: self.frame,
                physical_base: self.physical_base,
                physical_len: self.physical_len.raw(),
                owner: self.transport_chosen_owner,
                kernel_proof,
            }))
        }
    }

    impl ForeignMmTransport for OwnerSigningOracleTransport {
        fn retain(
            &self,
            _invocation: &carrick_hal::ForeignMmInvocation,
            _snapshot: &dyn ForeignMmSnapshot,
            _deadline: Instant,
        ) -> Result<Arc<dyn ForeignMmReadLease>, ForeignMmTransportError> {
            Ok(self.lease.clone())
        }
    }

    fn production_composition_cow_fixture(
        kernel: &Arc<Kernel>,
        parent: &KernelContext,
        registry_id: i32,
    ) -> KernelContext {
        let (_stage1_pool, stage1) = crate::hvpatch::Stage1MmPool::new_root_for_tests(
            0x20_0000 + (registry_id as u64 & 0xff) * 0x1000,
            4,
        )
        .expect("production composition stage-1 lease");
        let backend = stage1.backend();
        let child = fork_with_backend(
            kernel,
            parent,
            registry_id,
            "production foreign COW composition",
            Arc::clone(&backend) as Arc<dyn MmBackend>,
        );
        let mm = child.shared().mm().id();
        let (dispatch_mm, mutation) =
            carrick_kernel::dispatch::DispatchMmAuthority::foreign_cow_composition_for_test(
                mm,
                Arc::clone(&stage1) as Arc<dyn carrick_hal::stage1_mm::Stage1MmProjection>,
                0x3000,
                0x4000,
            );
        backend.bind_inventory(kernel, mm);
        backend.bind_vma_source(dispatch_mm);
        let physical_base = Gpa(0xb000);
        let physical_len = 0x4000;
        let (mapping, frame, inventory_revision) =
            publish_cow_mapping(kernel, mm, physical_base, physical_len);
        let owner =
            carrick_hal::ForeignOwnerGeneration::from_backend_counter(NonZeroU64::new(61).unwrap());
        let proof = carrick_kernel::kernel::KernelForeignCowProof::new(
            Arc::clone(kernel),
            mm,
            GuestVa(0x3000),
            std::num::NonZeroUsize::new(physical_len as usize).unwrap(),
            inventory_revision,
            mapping,
            frame,
            physical_base,
            carrick_hal::FrameLength::from_mapping_extent(NonZeroU64::new(physical_len).unwrap()),
            owner,
        );
        child.shared().mm().install_foreign_mm_endpoint_for_test(
            carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(MockCowTransport {
                owner_generation: Arc::new(AtomicU64::new(61)),
                bytes: Arc::new(parking_lot::Mutex::new(b"same".to_vec())),
                counters: MockCowCounters::default(),
                fault: MockCowFault::ReacquireSnapshot,
                proof,
                ptrace_proof: None,
                mapping,
                frame,
                physical_base,
                physical_len,
                post_write_backend_revision: None,
            })),
        );
        child
            .shared()
            .mm()
            .install_foreign_mm_mutation_authority_for_test(mutation);
        child
    }

    struct RealProductionCowFixture {
        child: KernelContext,
        stage1: Arc<crate::hvpatch::Stage1MmLease>,
        dispatch_mm: Arc<carrick_kernel::dispatch::DispatchMmAuthority>,
        carrier:
            carrick_vmm_hvf::trap::foreign_cow_test_support::ProductionCarrierForeignCowHarness,
    }

    fn real_production_cow_fixture(
        kernel: &Arc<Kernel>,
        parent: &KernelContext,
        registry_id: i32,
        stage1_root: u64,
        data_ipa: u64,
        caller_tid: ThreadId,
    ) -> RealProductionCowFixture {
        use carrick_vmm_hvf::trap::foreign_cow_test_support::{FixtureShape, TEST_VA};
        let shape = FixtureShape::new(Gpa(stage1_root), Gpa(data_ipa)).unwrap();
        production_cow_fixture_with_shape(
            kernel,
            parent,
            registry_id,
            caller_tid,
            shape,
            TEST_VA..TEST_VA + shape.data_len,
        )
    }

    fn production_cow_fixture_with_shape(
        kernel: &Arc<Kernel>,
        parent: &KernelContext,
        registry_id: i32,
        caller_tid: ThreadId,
        shape: carrick_vmm_hvf::trap::foreign_cow_test_support::FixtureShape,
        semantic_data: std::ops::Range<u64>,
    ) -> RealProductionCowFixture {
        use carrick_vmm_hvf::trap::foreign_cow_test_support::{
            InitialInventoryIdentity, ProductionCarrierForeignCowCustody,
            ProductionCarrierForeignCowHarness, ProductionCarrierForeignCowInstallArgs,
        };
        let stage1_root = shape.stage1_root.0;

        let (_stage1_pool, stage1) =
            crate::hvpatch::Stage1MmPool::new_root_for_tests(stage1_root, 4)
                .expect("real production foreign COW stage-1 lease");
        let backend = stage1.backend();
        let child = fork_with_backend(
            kernel,
            parent,
            registry_id,
            "real production carrier foreign COW",
            Arc::clone(&backend) as Arc<dyn MmBackend>,
        );
        let mm = child.shared().mm().id();
        let (dispatch_mm, mutation) =
            carrick_kernel::dispatch::DispatchMmAuthority::foreign_cow_composition_for_test(
                mm,
                Arc::clone(&stage1) as Arc<dyn carrick_hal::stage1_mm::Stage1MmProjection>,
                semantic_data.start,
                semantic_data.end,
            );
        backend.bind_inventory(kernel, mm);
        let vma_source: carrick_kernel::kernel::SharedVmaSnapshotSource = dispatch_mm.clone();
        backend.bind_vma_source(vma_source);
        let (root_mapping, root_frame, _) =
            publish_cow_mapping(kernel, mm, shape.stage1_root, shape.page_table_len);
        let (data_mapping, data_frame, _) =
            publish_cow_mapping(kernel, mm, shape.data_ipa, shape.data_len);
        let backend_snapshot = backend
            .snapshot(Instant::now() + std::time::Duration::from_secs(1))
            .expect("real production carrier snapshot");
        let projected = ProjectedForeignMmSnapshot::from_backend(mm, &backend_snapshot)
            .expect("typed real production carrier snapshot");
        let carrier_custody = ProductionCarrierForeignCowCustody::new();
        let authority = crate::vcpu_loop::kernel_frame_cow_authority_for_test(
            Arc::clone(kernel),
            mm,
            caller_tid,
            projected.binding.asid().raw_for_probe(),
            carrier_custody.owner_inventory(),
        );
        let identity = carrick_hal::FrameCowIdentity {
            linux_pid: caller_tid.raw(),
            linux_tid: caller_tid.raw(),
            mm: mm.raw(),
            asid: projected.binding.asid().raw_for_probe(),
        };
        let carrier = ProductionCarrierForeignCowHarness::install(
            carrier_custody,
            &projected,
            ProductionCarrierForeignCowInstallArgs {
                shape,
                inventory: InitialInventoryIdentity {
                    root_mapping,
                    root_frame,
                    data_mapping,
                    data_frame,
                },
                authority,
                identity,
                ordinal: registry_id as u64,
                initial_bytes: *b"same",
            },
        )
        .expect("install production carrier foreign COW transport");
        child
            .shared()
            .mm()
            .install_foreign_mm_endpoint_for_test(carrier.endpoint());
        child
            .shared()
            .mm()
            .install_foreign_mm_mutation_authority_for_test(mutation);
        RealProductionCowFixture {
            child,
            stage1,
            dispatch_mm,
            carrier,
        }
    }

    fn with_mm_mutation<T>(
        mm: MmId,
        run: impl FnOnce(&mut carrick_kernel::dispatch::mm_mutation::MmMutationGuard<'_>) -> T,
    ) -> T {
        let coordinator =
            Arc::new(carrick_kernel::dispatch::mm_mutation::MmMutationCoordinator::new(mm));
        carrick_kernel::dispatch::mm_quiesce::with_real_pt_pause_for_test(coordinator, |pause| {
            let mut mutation = carrick_kernel::dispatch::mm_mutation::from_pt_pause(pause);
            run(&mut mutation)
        })
    }

    #[test]
    fn production_composition_foreign_cow_does_not_reacquire_snapshot_under_alias() {
        let (kernel, root) = bootstrap(31_075);
        let execution = execution_lease(&root, 75);
        let child = production_composition_cow_fixture(&kernel, &root, 31_076);
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();

        let result = with_foreign_mutation(&foreign, |mutation| {
            carrick_kernel::kernel::MmAccessAuthority::new()
                .break_foreign_cow(mutation, &foreign, range)
                .map(|_| ())
        });

        assert!(result.is_ok(), "production composition failed: {result:?}");
    }

    #[test]
    fn production_composition_committed_cow_ignores_final_snapshot_contention() {
        let (kernel, root) = bootstrap(31_077);
        let execution = execution_lease(&root, 77);
        let child = production_composition_cow_fixture(&kernel, &root, 31_078);
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();

        let result = with_foreign_mutation(&foreign, |mutation| {
            carrick_kernel::kernel::MmAccessAuthority::new()
                .break_foreign_cow_with_final_snapshot_contended_for_test(mutation, &foreign, range)
                .map(|_| ())
        });

        assert!(
            result.is_ok(),
            "post-commit receipt validation reacquired a contended snapshot: {result:?}"
        );
    }

    #[cfg(feature = "conformance-metrics")]
    #[test]
    fn native_instruction_content_scope_contract() {
        use carrick_conformance_contract::{
            Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
            SemanticAssertion, WorkMetric, WorkSnapshot, evaluate,
        };
        use carrick_kernel::dispatch::SyscallDispatcher;
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;
        let (kernel, root) = bootstrap(41_100);
        let fixture = real_production_cow_fixture(
            &kernel,
            &root,
            41_101,
            0x9a00_f500_0000,
            0x9b00_f500_0000,
            ThreadId::synthetic_for_tests(41_101),
        );
        fixture
            .dispatch_mm
            .set_foreign_cow_vma_access_for_test(VmaAccess {
                readable: true,
                writable: false,
                executable: true,
                kernel_visible: true,
            });
        let other = real_production_cow_fixture(
            &kernel,
            &root,
            41_102,
            0x9a00_f600_0000,
            0x9b00_f600_0000,
            ThreadId::synthetic_for_tests(41_102),
        );
        let mut execution = execution_lease(&fixture.child, 41101);
        let mut content = fixture
            .child
            .fetch_instruction_bytes(&execution, GuestVa(TEST_VA), 4)
            .unwrap()
            .prepare_tracked_content()
            .unwrap();
        assert_eq!(content.bytes(), b"same");
        let dispatcher = SyscallDispatcher::with_native_mm_for_test(fixture.dispatch_mm.clone());
        let mut executor = dispatcher
            .admit_native_executor(&fixture.child, &execution)
            .unwrap();
        // A different live execution cannot adopt the receipt, even in one kernel.
        let mut wrong_execution = execution_lease(&other.child, 41102);
        let wrong_dispatcher =
            SyscallDispatcher::with_native_mm_for_test(other.dispatch_mm.clone());
        let mut wrong_executor = wrong_dispatcher
            .admit_native_executor(&other.child, &wrong_execution)
            .unwrap();
        {
            let scope = wrong_dispatcher
                .enter_native_execution(&mut wrong_executor, &other.child, &mut wrong_execution)
                .unwrap();
            assert!(matches!(
                content.activate(&scope),
                Err(MmAccessError::ForeignRangeAuthorityMismatch)
            ));
        }
        activation_allocator::ALLOCATIONS.set(Some(0));
        let control = std::hint::black_box(vec![std::hint::black_box(42u8); 64]);
        assert!(activation_allocator::ALLOCATIONS.replace(None).unwrap() > 0);
        drop(control);
        {
            let scope = dispatcher
                .enter_native_execution(&mut executor, &fixture.child, &mut execution)
                .unwrap();
            let active = content.activate(&scope).unwrap();
            assert!(!active.stop_requested());
        }
        // The content scope must expose the real execution control signal.
        let interrupt = executor.interrupt_handle();
        {
            let scope = dispatcher
                .enter_native_execution(&mut executor, &fixture.child, &mut execution)
                .unwrap();
            let active = content.activate(&scope).unwrap();
            interrupt.request_stop();
            assert!(active.stop_requested());
        }
        assert!(executor.take_stop_request());
        let mut observations = Vec::new();
        for scale in [1, 8, 32, 128] {
            activation_allocator::ALLOCATIONS.set(Some(0));
            for _ in 0..scale {
                let scope = dispatcher
                    .enter_native_execution(&mut executor, &fixture.child, &mut execution)
                    .unwrap();
                let active = content.activate(&scope).unwrap();
                assert!(!active.stop_requested());
            }
            let allocations = activation_allocator::ALLOCATIONS.replace(None).unwrap();
            assert_eq!(allocations, 0);
            let mut work = WorkSnapshot::new();
            work.insert(WorkMetric::HostHeapAllocations, allocations)
                .unwrap();
            observations.push(ContractObservation {
                contract_id: ContractId::new("kernel.mm.native-code-drain").unwrap(),
                layer: ExecutionLayer::VmFree,
                implementation_revision: format!(
                    "sha256:{:x}",
                    <sha2::Sha256 as sha2::Digest>::digest(include_bytes!(
                        "../../../carrick-kernel/src/kernel/mm_access/instruction_content.rs"
                    ))
                ),
                fixture_identity: "unit:native-code-drain".into(),
                scale,
                semantic_assertions: vec![SemanticAssertion::pass(
                    "exact_carrier_content_scope_reuses_without_allocation",
                )],
                work: Some(work),
                timing: None,
                completeness: Completeness::Complete,
            });
        }
        let root_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let registry = ContractRegistry::load(root_path).unwrap();
        println!(
            "native_code_drain_observations {}",
            serde_json::to_string(&observations).unwrap()
        );
        evaluate(
            registry.require("kernel.mm.native-code-drain").unwrap(),
            &observations,
        )
        .unwrap();
        // A participating physical write makes the old preparation unusable.
        let original = fixture.carrier.pin_original_data_for_test().unwrap();
        original.write_prefix_for_test(*b"new!").unwrap();
        {
            let scope = dispatcher
                .enter_native_execution(&mut executor, &fixture.child, &mut execution)
                .unwrap();
            assert!(content.activate(&scope).is_err());
        }
        let mut fresh = fixture
            .child
            .fetch_instruction_bytes(&execution, GuestVa(TEST_VA), 4)
            .unwrap()
            .prepare_tracked_content()
            .unwrap();
        assert_eq!(fresh.bytes(), b"new!");
        {
            let scope = dispatcher
                .enter_native_execution(&mut executor, &fixture.child, &mut execution)
                .unwrap();
            let active = fresh.activate(&scope).unwrap();
            assert!(!active.stop_requested());
        }
        fixture
            .dispatch_mm
            .set_foreign_cow_vma_access_for_test(VmaAccess {
                readable: true,
                writable: true,
                executable: false,
                kernel_visible: true,
            });
        {
            let scope = dispatcher
                .enter_native_execution(&mut executor, &fixture.child, &mut execution)
                .unwrap();
            assert!(matches!(
                fresh.activate(&scope),
                Err(MmAccessError::StaleInstructionRead)
            ));
        }
        drop((content, fresh, executor, wrong_executor));
        fixture
            .child
            .thread()
            .yield_from_executor(execution)
            .unwrap();
        other
            .child
            .thread()
            .yield_from_executor(wrong_execution)
            .unwrap();
    }

    #[test]
    fn instruction_fetch_composes_kernel_lease_and_production_carrier() {
        use carrick_vmm_hvf::trap::foreign_cow_test_support::{OWNER_LEN, TEST_VA};
        let (kernel, root) = bootstrap(31_170);
        let fixture = real_production_cow_fixture(
            &kernel,
            &root,
            31_171,
            0x9a00_3a00_0000,
            0x9b00_3a00_0000,
            ThreadId::synthetic_for_tests(31_171),
        );
        let execution = execution_lease(&fixture.child, 171);
        // Existing fixture starts writable and NX. Fetch must refuse before
        // the same production VMA authority grants execution permission.
        assert!(matches!(
            fixture
                .child
                .fetch_instruction_bytes(&execution, GuestVa(TEST_VA), 4),
            Err(MmAccessError::ExecuteDenied { .. })
        ));
        fixture
            .dispatch_mm
            .set_foreign_cow_vma_access_for_test(VmaAccess {
                readable: false,
                writable: false,
                executable: true,
                kernel_visible: true,
            });
        let read = fixture
            .child
            .fetch_instruction_bytes(&execution, GuestVa(TEST_VA), 4)
            .expect("kernel-authorized execute-only fetch through production carrier");
        assert_eq!(read.bytes(), b"same");
        read.validate_mapping().unwrap();
        read.validate_tracked_content().unwrap();
        // Data-read authority must not inherit the instruction permission.
        let current = fixture.child.current_mm(&execution).unwrap();
        use carrick_kernel::kernel::mm_access::MmAccessTarget;
        assert!(matches!(
            current.access_token().read_range(GuestVa(TEST_VA), 4),
            Err(MmAccessError::ReadDenied { .. })
        ));
        assert!(matches!(
            fixture
                .child
                .fetch_instruction_bytes(&execution, GuestVa(TEST_VA + OWNER_LEN - 2), 4),
            Err(MmAccessError::Unmapped { .. })
        ));
        let wrong = execution_lease(&root, 170);
        assert!(matches!(
            fixture
                .child
                .fetch_instruction_bytes(&wrong, GuestVa(TEST_VA), 4),
            Err(MmAccessError::ExecutionAuthority(_))
        ));
        fixture
            .dispatch_mm
            .set_foreign_cow_vma_access_for_test(VmaAccess {
                readable: true,
                writable: false,
                executable: false,
                kernel_visible: true,
            });
        assert!(matches!(
            read.validate_mapping(),
            Err(MmAccessError::StaleInstructionRead)
        ));
        assert!(matches!(
            fixture
                .child
                .fetch_instruction_bytes(&execution, GuestVa(TEST_VA), 4),
            Err(MmAccessError::ExecuteDenied { .. })
        ));
    }

    fn native_carrier_elf(words: &[u32], data_va: u64) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x3000];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, v) in [(16, 2u16), (18, 183), (52, 64), (54, 56), (56, 2)] {
            bytes[at..at + 2].copy_from_slice(&v.to_le_bytes());
        }
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        for (at, v) in [(24, 0x400000u64), (32, 64)] {
            bytes[at..at + 8].copy_from_slice(&v.to_le_bytes());
        }
        for (i, base, len, flags) in [(0, 0x400000u64, words.len() * 4, 5u32), (1, data_va, 8, 6)] {
            let h = 64 + i * 56;
            bytes[h..h + 4].copy_from_slice(&1u32.to_le_bytes());
            bytes[h + 4..h + 8].copy_from_slice(&flags.to_le_bytes());
            for (offset, value) in [
                (8, 0x1000u64 * (i as u64 + 1)),
                (16, base),
                (32, len as u64),
                (40, len as u64),
                (48, 4096),
            ] {
                bytes[h + offset..h + offset + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        for (i, w) in words.iter().enumerate() {
            bytes[0x1000 + i * 4..0x1004 + i * 4].copy_from_slice(&w.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn native_carrier_elf_memory_control_round_trip() {
        use carrick_kernel::{
            compat::{CompatReporter, SyscallArgs},
            dispatch::{
                DispatchOutcome, SyscallRequest, ThreadCtx,
                mm_quiesce::{PtPauseBudget, PtPauseTryError, try_acquire_mutation_pause_for_test},
            },
            kernel::mm_access::MmAccessTarget,
            thread::{FutexTable, ThreadRegistry},
        };
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;
        use native_syscall_slice::{
            Memory,
            native::{Code, State},
        };
        let (kernel, root) = bootstrap(37_000);
        let root_execution = execution_lease(&root, 37000);
        let tid = ThreadId::synthetic_for_tests(37_001);
        let fixture = real_production_cow_fixture(
            &kernel,
            &root,
            37_001,
            0x9a00_c000_0000,
            0x9b00_c000_0000,
            tid,
        );
        let original = fixture.carrier.pin_original_data_for_test().unwrap();
        let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::with_native_mm_for_test(
            fixture.dispatch_mm.clone(),
        );
        let mut execution = execution_lease(&fixture.child, 37001);
        let mut executor = dispatcher
            .admit_native_executor(&fixture.child, &execution)
            .unwrap();
        let authority = carrick_kernel::kernel::MmAccessAuthority::new();
        let current = fixture.child.current_mm(&execution).unwrap();
        let range = current
            .access_token()
            .write_range(GuestVa(TEST_VA), 8)
            .unwrap()
            .unwrap();
        let mut prepared = authority
            .with_current_mutation(&current, tid, |mutation| {
                let mut cow = authority.break_foreign_cow(mutation, &current, range)?;
                Ok(fixture
                    .child
                    .borrow_current_native_data(&execution, &mut cow)?
                    .prepare_for_execution())
            })
            .unwrap();
        drop(current);
        // ldr w9,[x2]; add w9,w9,#1; str w9,[x2]; svc #0.
        // Text remains a private, immutable research publication. Only this
        // declared data segment uses carrier backing; close(-1) has no buffer.
        let elf = native_carrier_elf(&[0xb9400049, 0x11000529, 0xb9000049, 0xd4000001], TEST_VA);
        if let Some(dir) = std::env::var_os("CARRICK_NATIVE_SCOPE_RECEIPT_DIR") {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(std::path::Path::new(&dir).join("native-carrier.elf"), &elf).unwrap();
        }
        let (mut memory, image) = Memory::load_elf(&elf).unwrap();
        let code = Code::publish(&image, &memory).unwrap();
        let mut state = State::new(image.entry());
        let registry = ThreadRegistry::new(tid);
        let futex = FutexTable::new();
        let reporter = CompatReporter::default();
        let mut completed = 0;
        for scale in [1, 8, 32, 128] {
            for _ in 0..scale {
                state.pc = image.entry();
                state.x[2] = TEST_VA;
                state.x[0] = u64::MAX;
                state.x[8] = 57;
                let scope = dispatcher
                    .enter_native_execution(&mut executor, &fixture.child, &mut execution)
                    .unwrap();
                {
                    let mut active = prepared.activate(&scope).unwrap();
                    // Request a real memory drain while code owns the grant. It
                    // must refuse until the code reaches its checkpoint and exits.
                    let refusal = try_acquire_mutation_pause_for_test(
                        fixture.dispatch_mm.pt_quiesce(),
                        ThreadId::synthetic_for_tests(37002),
                        fixture.child.shared().mm().id(),
                        dispatcher.mm_mutation_coordinator(),
                        PtPauseBudget {
                            election: std::time::Duration::ZERO,
                        },
                    );
                    assert!(matches!(refusal, Err(PtPauseTryError::SiblingInGuest)));
                    drop(refusal);
                    assert!(scope.stop_requested());
                    code.run_carrier_until_checkpoint(&image, &memory, &mut active, &mut state)
                        .unwrap();
                }
                drop(scope);
                assert_eq!(state.pc, image.entry() + 12);
                assert!(executor.memory_pause_pending());
                dispatcher
                    .service_native_memory_control(&mut executor, &fixture.child, &execution)
                    .unwrap();
                assert!(!executor.take_stop_request());
                let outcome = dispatcher
                    .dispatch_threaded_with_mm_executor(
                        executor.dispatch_participation(),
                        &fixture.child,
                        SyscallRequest::new(
                            state.x[8],
                            SyscallArgs::from([state.x[0], 0, 0, 0, 0, 0]),
                        ),
                        &mut memory,
                        &reporter,
                        ThreadCtx::new(tid, &registry, &futex),
                    )
                    .unwrap();
                assert!(
                    matches!(outcome, DispatchOutcome::Errno { errno } if errno == carrick_abi::LINUX_EBADF)
                );
                completed += 1;
                let current = fixture.child.current_mm(&execution).unwrap();
                let foreign =
                    foreign_mm(&kernel, &root, &root_execution, fixture.child.task().key());
                let read = foreign
                    .access_token()
                    .read_range(GuestVa(TEST_VA), 4)
                    .unwrap()
                    .unwrap();
                let mut actual = [0; 4];
                authority.read_foreign(&foreign, read, &mut actual).unwrap();
                drop(foreign);
                assert_eq!(
                    u32::from_le_bytes(actual),
                    u32::from_le_bytes(*b"same") + completed,
                    "ELF store did not reach carrier backing"
                );
                authority
                    .with_current_mutation(&current, tid, |_mutation| {
                        fixture
                            .carrier
                            .deny_native_data_for_test(TEST_VA, 6)
                            .unwrap();
                        Ok(())
                    })
                    .unwrap();
            }
            println!(
                "native_carrier_elf scale={scale} completed_total={completed} close_errno=9 pause_requests_serviced={scale}"
            );
        }
        assert_eq!(completed, 169);
        assert_eq!(original.prefix(), *b"same");
        // The private ELF data segment is a decoy: carrier writes must never
        // fall back into it, even when the translated access misses its grant.
        let mut private_bytes = [0u8; 8];
        carrick_guest_mem::GuestMemory::read_into(&memory, TEST_VA, &mut private_bytes).unwrap();
        assert_eq!(private_bytes, [0; 8]);
        let (other_memory, _) = Memory::load_elf(&elf).unwrap();
        {
            let scope = dispatcher
                .enter_native_execution(&mut executor, &fixture.child, &mut execution)
                .unwrap();
            let mut active = prepared.activate(&scope).unwrap();
            for address in [TEST_VA + 5, TEST_VA + 8, u64::MAX] {
                state.pc = image.entry();
                state.x[2] = address;
                state.x[9] = 0x12345678;
                code.run_carrier_until_checkpoint(&image, &memory, &mut active, &mut state)
                    .unwrap();
                assert_eq!(
                    state.pc,
                    image.entry(),
                    "out-of-grant load did not checkpoint"
                );
                assert_eq!(
                    state.x[9], 0x12345678,
                    "out-of-grant load changed destination"
                );
            }
            assert!(
                code.run_carrier_until_checkpoint(&image, &other_memory, &mut active, &mut state)
                    .is_err()
            );
            memory.protect(image.base(), 4).unwrap();
            assert!(
                code.run_carrier_until_checkpoint(&image, &memory, &mut active, &mut state)
                    .is_err()
            );
        }
        let current = fixture.child.current_mm(&execution).unwrap();
        authority
            .with_current_mutation(&current, tid, |_mutation| {
                fixture
                    .carrier
                    .deny_native_data_for_test(TEST_VA, 0)
                    .unwrap();
                Ok(())
            })
            .unwrap();
        drop(current);
        let scope = dispatcher
            .enter_native_execution(&mut executor, &fixture.child, &mut execution)
            .unwrap();
        assert!(
            prepared.activate(&scope).is_err(),
            "revoked carrier data was executable"
        );
        drop(scope);
        drop(executor);
        fixture
            .child
            .thread()
            .yield_from_executor(execution)
            .unwrap();
        assert_eq!(dispatcher.mm_occupancy_probe()(), 0);
        root.thread().yield_from_executor(root_execution).unwrap();
    }

    /// Native membership must drain, but cannot acknowledge a hardware ASID.
    /// Historical hardware residency on the same executor stays pending until
    /// the actual hardware entry path services it.
    #[test]
    fn native_admission_allows_carrier_cow_without_hardware_ack() {
        use carrick_kernel::kernel::mm_access::MmAccessTarget;
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;
        for scale in [1, 8, 32, 128] {
            let (kernel, root) = bootstrap(35_000 + scale);
            let fixture = real_production_cow_fixture(
                &kernel,
                &root,
                35_200 + scale,
                0x9a00_b000_0000,
                0x9b00_b000_0000,
                ThreadId::synthetic_for_tests(35_200 + scale),
            );
            let original = fixture.carrier.pin_original_data_for_test().unwrap();
            let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::with_native_mm_for_test(
                fixture.dispatch_mm.clone(),
            );
            let mut peers = Vec::new();
            for index in 1..scale {
                let plan = carrick_kernel::kernel::ClonePlan::from_flags(
                    carrick_abi::LinuxCloneFlags::THREAD
                        | carrick_abi::LinuxCloneFlags::VM
                        | carrick_abi::LinuxCloneFlags::SIGHAND,
                )
                .unwrap();
                peers.push(
                    kernel
                        .reserve_thread_clone(&fixture.child, plan, None)
                        .unwrap()
                        .prepare(ThreadId::synthetic_for_tests(36_000 + index))
                        .unwrap()
                        .commit()
                        .unwrap()
                        .into_context()
                        .unwrap(),
                );
            }
            let contexts: Vec<_> = std::iter::once(&fixture.child)
                .chain(peers.iter())
                .collect();
            let mut leases: Vec<_> = contexts
                .iter()
                .enumerate()
                .map(|(i, c)| execution_lease(c, 36000 + i as u64))
                .collect();
            let mut executors: Vec<_> = contexts
                .iter()
                .zip(&leases)
                .map(|(c, e)| dispatcher.admit_native_executor(c, e).unwrap())
                .collect();
            // Model a previous hardware quantum on the current executor. Native
            // execution must neither load this ASID nor consume its ticket.
            let resident = leases[0].executor();
            fixture
                .stage1
                .begin_asid_load(resident)
                .unwrap()
                .mark_resident()
                .unwrap();
            let authority = carrick_kernel::kernel::MmAccessAuthority::new();
            let current = fixture.child.current_mm(&leases[0]).unwrap();
            let range = current
                .access_token()
                .write_range(GuestVa(TEST_VA), 8)
                .unwrap()
                .unwrap();
            let result = authority.with_current_mutation(
                &current,
                fixture.child.thread().registry_id(),
                |mutation| {
                    let mut cow = authority.break_foreign_cow(mutation, &current, range)?;
                    Ok(fixture
                        .child
                        .borrow_current_native_data(&leases[0], &mut cow)?
                        .prepare_for_execution())
                },
            );
            assert!(
                result.is_ok(),
                "native census scale {scale} blocked real carrier COW: {:?}",
                result.as_ref().err()
            );
            let mut prepared = result.unwrap();
            drop(current);
            assert!(fixture.stage1.pending_cow_invalidation(resident).is_some());
            for ((executor, context), lease) in executors.iter_mut().zip(&contexts).zip(&mut leases)
            {
                let scope = dispatcher
                    .enter_native_execution(executor, context, lease)
                    .unwrap();
                {
                    let mut data = prepared.activate(&scope).unwrap();
                    // SAFETY: one exclusive activated carrier span, eight valid
                    // bytes, and no Rust alias or dispatch while native code runs.
                    unsafe {
                        let ptr = data.as_mut_ptr();
                        crate::vcpu_loop::native_probe::increment_u32(ptr);
                    }
                }
                drop(scope);
                assert!(fixture.stage1.pending_cow_invalidation(resident).is_some());
            }
            assert_eq!(original.prefix(), *b"same");
            for ((context, executor), lease) in contexts.iter().zip(executors).zip(leases) {
                drop(executor);
                context.thread().yield_from_executor(lease).unwrap();
            }
            assert_eq!(dispatcher.mm_occupancy_probe()(), 0);
            println!(
                "native_carrier_cow scale={scale} completed={scale} hardware_ticket_retained=true"
            );
        }
    }

    #[test]
    fn native_data_activation_outlives_mutation_but_not_execution() {
        use carrick_kernel::kernel::mm_access::MmAccessTarget;
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;
        let (kernel, root) = bootstrap(32_180);
        let fixture = real_production_cow_fixture(
            &kernel,
            &root,
            32_181,
            0x9a00_6b00_0000,
            0x9b00_6b00_0000,
            ThreadId::synthetic_for_tests(32_181),
        );
        let original = fixture.carrier.pin_original_data_for_test().unwrap();
        let mut execution = execution_lease(&fixture.child, 32181);
        let authority = carrick_kernel::kernel::MmAccessAuthority::new();
        let current = fixture.child.current_mm(&execution).unwrap();
        let range = current
            .access_token()
            .write_range(GuestVa(TEST_VA), 4)
            .unwrap()
            .unwrap();
        let mut prepared = authority
            .with_current_mutation(
                &current,
                ThreadId::synthetic_for_tests(32_181),
                |mutation| {
                    let mut cow = authority
                        .break_foreign_cow(mutation, &current, range)
                        .unwrap();
                    Ok(fixture
                        .child
                        .borrow_current_native_data(&execution, &mut cow)
                        .unwrap()
                        .prepare_for_execution())
                },
            )
            .unwrap();
        drop(current);
        assert!(!fixture.dispatch_mm.pt_quiesce().is_quiescing());
        let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::with_native_mm_for_test(
            fixture.dispatch_mm.clone(),
        );
        let mut executor = dispatcher
            .admit_native_executor(&fixture.child, &execution)
            .unwrap();
        let mut completed = 0u32;
        for scale in [1, 8, 32, 128] {
            for _ in 0..scale {
                let scope = dispatcher
                    .enter_native_execution(&mut executor, &fixture.child, &mut execution)
                    .unwrap();
                {
                    let mut active = prepared.activate(&scope).unwrap();
                    assert_eq!(active.start(), GuestVa(TEST_VA));
                    assert_eq!(active.len(), 4);
                    // Bounded CPU access to the actual pinned carrier bytes, after mutation
                    // exclusion has ended. No syscall/dispatcher reentry or Rust aliases.
                    unsafe {
                        let ptr = active.as_mut_ptr();
                        crate::vcpu_loop::native_probe::increment_u32(ptr);
                    }
                }
                drop(scope);
                completed += 1;
            }
        }
        assert_eq!(completed, 169);
        // The prepared window is still retained, but every active pointer
        // grant has ended. Making these fixture bytes executable must allow a
        // fresh tracked read; a writer leaked past ActiveNativeData::drop would
        // refuse it even though no native code is running.
        fixture.dispatch_mm.set_foreign_cow_vma_access_for_test(
            carrick_kernel::kernel::VmaAccess {
                readable: false,
                writable: false,
                executable: true,
                kernel_visible: true,
            },
        );
        let captured = fixture
            .child
            .fetch_instruction_bytes(&execution, GuestVa(TEST_VA), 4)
            .unwrap();
        captured.validate_tracked_content().unwrap();
        assert_eq!(
            captured.bytes(),
            &(u32::from_le_bytes(*b"same") + completed).to_le_bytes()
        );
        drop(captured);
        // The final foreign data read retains its original readable-VMA check.
        fixture.dispatch_mm.set_foreign_cow_vma_access_for_test(
            carrick_kernel::kernel::VmaAccess {
                readable: true,
                writable: true,
                executable: false,
                kernel_visible: true,
            },
        );
        drop(executor);
        fixture
            .child
            .thread()
            .yield_from_executor(execution)
            .unwrap();
        assert_eq!(original.prefix(), *b"same");
        let root_execution = execution_lease(&root, 32180);
        let current = foreign_mm(&kernel, &root, &root_execution, fixture.child.task().key());
        let read = current
            .access_token()
            .read_range(GuestVa(TEST_VA), 4)
            .unwrap()
            .unwrap();
        let mut bytes = [0; 4];
        authority.read_foreign(&current, read, &mut bytes).unwrap();
        assert_eq!(
            u32::from_le_bytes(bytes),
            u32::from_le_bytes(*b"same") + completed
        );
        root.thread().yield_from_executor(root_execution).unwrap();
    }

    #[cfg(feature = "conformance-metrics")]
    mod activation_allocator {
        use std::{
            alloc::{GlobalAlloc, Layout, System},
            cell::Cell,
        };
        thread_local! { pub(super) static ALLOCATIONS: Cell<Option<u64>> = const { Cell::new(None) }; }
        struct CountingAllocator;
        #[global_allocator]
        static ALLOCATOR: CountingAllocator = CountingAllocator;
        fn allocated() {
            let _ = ALLOCATIONS.try_with(|count| {
                if let Some(n) = count.get() {
                    count.set(Some(n.checked_add(1).unwrap()));
                }
            });
        }
        // SAFETY: every allocator argument is forwarded unchanged to System.
        // The const TLS counter allocates nothing and observes only this thread.
        unsafe impl GlobalAlloc for CountingAllocator {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                allocated();
                unsafe { System.alloc(layout) }
            }
            unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
                allocated();
                unsafe { System.alloc_zeroed(layout) }
            }
            unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
                allocated();
                unsafe { System.realloc(ptr, layout, size) }
            }
            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                unsafe { System.dealloc(ptr, layout) }
            }
        }
    }

    #[cfg(feature = "conformance-metrics")]
    #[test]
    fn native_data_activation_cost_contract() {
        use carrick_kernel::kernel::mm_access::MmAccessTarget;
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;
        let (kernel, root) = bootstrap(34_180);
        let fixture = real_production_cow_fixture(
            &kernel,
            &root,
            34_181,
            0x9a00_cb00_0000,
            0x9b00_cb00_0000,
            ThreadId::synthetic_for_tests(34_181),
        );
        let original = fixture.carrier.pin_original_data_for_test().unwrap();
        let mut execution = execution_lease(&fixture.child, 34181);
        let authority = carrick_kernel::kernel::MmAccessAuthority::new();
        let current = fixture.child.current_mm(&execution).unwrap();
        let range = current
            .access_token()
            .write_range(GuestVa(TEST_VA), 4)
            .unwrap()
            .unwrap();
        let mut prepared = authority
            .with_current_mutation(
                &current,
                ThreadId::synthetic_for_tests(34_181),
                |mutation| {
                    let mut cow = authority
                        .break_foreign_cow(mutation, &current, range)
                        .unwrap();
                    Ok(fixture
                        .child
                        .borrow_current_native_data(&execution, &mut cow)
                        .unwrap()
                        .prepare_for_execution())
                },
            )
            .unwrap();
        drop(current);
        assert!(!fixture.dispatch_mm.pt_quiesce().is_quiescing());
        let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::with_native_mm_for_test(
            fixture.dispatch_mm.clone(),
        );
        let mut executor = dispatcher
            .admit_native_executor(&fixture.child, &execution)
            .unwrap();
        use carrick_conformance_contract::{
            Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
            SemanticAssertion, WorkMetric, WorkSnapshot, evaluate,
        };
        // Qualify both instruments outside the measured reuse windows.
        activation_allocator::ALLOCATIONS.set(Some(0));
        let allocation = std::hint::black_box(vec![std::hint::black_box(42u8); 64]);
        assert!(activation_allocator::ALLOCATIONS.replace(None).unwrap() > 0);
        drop(allocation);
        let leaves_before = fixture.carrier.native_activation_leaf_checks_for_test();
        {
            let scope = dispatcher
                .enter_native_execution(&mut executor, &fixture.child, &mut execution)
                .unwrap();
            let _active = prepared.activate(&scope).unwrap();
        }
        assert!(fixture.carrier.native_activation_leaf_checks_for_test() > leaves_before);
        let mut observations = Vec::new();
        let mut completed = 0u32;
        for scale in [1, 8, 32, 128] {
            let before = fixture.carrier.native_activation_leaf_checks_for_test();
            let completed_before = completed;
            activation_allocator::ALLOCATIONS.set(Some(0));
            for _ in 0..scale {
                let scope = dispatcher
                    .enter_native_execution(&mut executor, &fixture.child, &mut execution)
                    .unwrap();
                {
                    let mut active = prepared.activate(&scope).unwrap();
                    assert_eq!(active.start(), GuestVa(TEST_VA));
                    assert_eq!(active.len(), 4);
                    // Bounded CPU access to the actual pinned carrier bytes, after mutation
                    // exclusion has ended. No syscall/dispatcher reentry or Rust aliases.
                    unsafe {
                        let ptr = active.as_mut_ptr();
                        crate::vcpu_loop::native_probe::increment_u32(ptr);
                    }
                }
                drop(scope);
                completed += 1;
            }
            let allocations = activation_allocator::ALLOCATIONS.replace(None).unwrap();
            let leaves = fixture.carrier.native_activation_leaf_checks_for_test() - before;
            let mut work = WorkSnapshot::new();
            work.insert(WorkMetric::HostHeapAllocations, allocations)
                .unwrap();
            work.insert(WorkMetric::NativeActivationLeafChecks, leaves)
                .unwrap();
            observations.push(ContractObservation {
                contract_id: ContractId::new("kernel.mm.native-data-activation").unwrap(),
                layer: ExecutionLayer::VmFree,
                implementation_revision: std::env::var("CARRICK_NATIVE_SCOPE_REVISION")
                    .unwrap_or_else(|_| "unarchived-working-tree".into()),
                fixture_identity: "unit:native-data-activation".into(),
                scale: scale as u64,
                semantic_assertions: vec![
                    SemanticAssertion {
                        name: "exact_completed_native_stores".into(),
                        passed: completed - completed_before == scale,
                        detail: None,
                    },
                    SemanticAssertion::pass("allocator_and_leaf_positive_controls_fired"),
                ],
                work: Some(work),
                timing: None,
                completeness: Completeness::Complete,
            });
        }
        assert_eq!(completed, 169);
        drop(executor);
        fixture
            .child
            .thread()
            .yield_from_executor(execution)
            .unwrap();
        assert_eq!(original.prefix(), *b"same");
        let root_execution = execution_lease(&root, 34180);
        let current = foreign_mm(&kernel, &root, &root_execution, fixture.child.task().key());
        let read = current
            .access_token()
            .read_range(GuestVa(TEST_VA), 4)
            .unwrap()
            .unwrap();
        let mut bytes = [0; 4];
        authority.read_foreign(&current, read, &mut bytes).unwrap();
        assert_eq!(
            u32::from_le_bytes(bytes),
            u32::from_le_bytes(*b"same") + completed
        );
        root.thread().yield_from_executor(root_execution).unwrap();
        println!(
            "native_activation_observations {}",
            serde_json::to_string(&observations).unwrap()
        );
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let registry = ContractRegistry::load(root).unwrap();
        evaluate(
            registry
                .require("kernel.mm.native-data-activation")
                .unwrap(),
            &observations,
        )
        .unwrap();
    }

    #[test]
    fn native_data_activation_rejects_changes_after_preparation() {
        use carrick_kernel::kernel::mm_access::MmAccessTarget;
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;
        // Each case starts with a successfully activated real COW span, then
        // changes only one authority under the actual mutation/drain protocol.
        for mode in 0..11 {
            let id = 32_200 + mode;
            let (kernel, root) = bootstrap(id);
            let fixture = real_production_cow_fixture(
                &kernel,
                &root,
                id + 100,
                0x9a00_7000_0000 + mode as u64 * 0x100_0000,
                0x9b00_7000_0000 + mode as u64 * 0x100_0000,
                ThreadId::synthetic_for_tests(id + 100),
            );
            let mut execution = execution_lease(&fixture.child, id as u64);
            let authority = carrick_kernel::kernel::MmAccessAuthority::new();
            let current = fixture.child.current_mm(&execution).unwrap();
            let range = current
                .access_token()
                .write_range(GuestVa(TEST_VA), 8192)
                .unwrap()
                .unwrap();
            let mut prepared = authority
                .with_current_mutation(
                    &current,
                    ThreadId::synthetic_for_tests(id + 100),
                    |mutation| {
                        let mut cow = authority
                            .break_foreign_cow(mutation, &current, range)
                            .unwrap();
                        Ok(fixture
                            .child
                            .borrow_current_native_data(&execution, &mut cow)
                            .unwrap()
                            .prepare_for_execution())
                    },
                )
                .unwrap();
            drop(current);
            let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::with_native_mm_for_test(
                fixture.dispatch_mm.clone(),
            );
            let mut executor = dispatcher
                .admit_native_executor(&fixture.child, &execution)
                .unwrap();
            {
                let scope = dispatcher
                    .enter_native_execution(&mut executor, &fixture.child, &mut execution)
                    .unwrap();
                let _active = prepared.activate(&scope).unwrap();
            }
            let current = fixture.child.current_mm(&execution).unwrap();
            authority
                .with_current_mutation(
                    &current,
                    ThreadId::synthetic_for_tests(id + 100),
                    |_mutation| {
                        match mode {
                            // The second page alone loses leaf write permission, tracker
                            // permission, mapping, or exact owner generation. These do
                            // not change kernel VMA revisions in this fixture.
                            0..=3 => fixture
                                .carrier
                                .deny_native_data_for_test(TEST_VA + 4096, mode as u8)
                                .unwrap(),
                            4 | 5 => {
                                fixture.dispatch_mm.set_foreign_cow_vma_access_for_test(
                                    carrick_kernel::kernel::VmaAccess {
                                        readable: true,
                                        writable: false,
                                        executable: false,
                                        kernel_visible: true,
                                    },
                                );
                                if mode == 5 {
                                    fixture.dispatch_mm.set_foreign_cow_vma_access_for_test(
                                        carrick_kernel::kernel::VmaAccess {
                                            readable: true,
                                            writable: true,
                                            executable: false,
                                            kernel_visible: true,
                                        },
                                    );
                                }
                            }
                            6 => fixture.dispatch_mm.set_foreign_cow_vma_access_for_test(
                                carrick_kernel::kernel::VmaAccess {
                                    readable: true,
                                    writable: true,
                                    executable: true,
                                    kernel_visible: true,
                                },
                            ),
                            7 | 8 => fixture
                                .carrier
                                .deny_native_data_for_test(TEST_VA + 4096, (mode - 3) as u8)
                                .unwrap(),
                            // Equal binding values cannot revive an older backend revision.
                            9 => {
                                let backend = fixture.stage1.backend();
                                backend.publish_binding(backend.binding());
                            }
                            10 => fixture
                                .carrier
                                .deny_native_data_for_test(TEST_VA + 4096, 6)
                                .unwrap(),
                            _ => unreachable!(),
                        }
                        Ok(())
                    },
                )
                .unwrap();
            drop(current);
            let scope = dispatcher
                .enter_native_execution(&mut executor, &fixture.child, &mut execution)
                .unwrap();
            if mode == 10 {
                let before = fixture.carrier.native_activation_leaf_checks_for_test();
                {
                    let _active = prepared.activate(&scope).unwrap();
                }
                assert_eq!(
                    fixture.carrier.native_activation_leaf_checks_for_test() - before,
                    2,
                    "a restored image must revalidate both leaves"
                );
                {
                    let _active = prepared.activate(&scope).unwrap();
                }
                assert_eq!(
                    fixture.carrier.native_activation_leaf_checks_for_test() - before,
                    2,
                    "the new validation may now be reused"
                );
            } else {
                assert!(
                    prepared.activate(&scope).is_err(),
                    "stale preparation accepted mode {mode}"
                );
            }
            drop(scope);
            drop(executor);
            fixture
                .child
                .thread()
                .yield_from_executor(execution)
                .unwrap();
        }
    }

    #[test]
    fn native_data_activation_requires_exact_authority_and_real_drain() {
        use carrick_kernel::{
            dispatch::mm_quiesce::{
                PtPauseBudget, PtPauseTryError, acquire_mutation_pause_for_test,
                try_acquire_mutation_pause_for_test,
            },
            kernel::mm_access::{MmAccessError, MmAccessTarget},
        };
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;
        let (kernel, root) = bootstrap(32_400);
        let fixture = real_production_cow_fixture(
            &kernel,
            &root,
            32_401,
            0x9a00_8000_0000,
            0x9b00_8000_0000,
            ThreadId::synthetic_for_tests(32_401),
        );
        let mut execution = execution_lease(&fixture.child, 32401);
        let authority = carrick_kernel::kernel::MmAccessAuthority::new();
        let current = fixture.child.current_mm(&execution).unwrap();
        let range = current
            .access_token()
            .write_range(GuestVa(TEST_VA), 4)
            .unwrap()
            .unwrap();
        let mut prepared = authority
            .with_current_mutation(
                &current,
                ThreadId::synthetic_for_tests(32_401),
                |mutation| {
                    let mut cow = authority
                        .break_foreign_cow(mutation, &current, range)
                        .unwrap();
                    Ok(fixture
                        .child
                        .borrow_current_native_data(&execution, &mut cow)
                        .unwrap()
                        .prepare_for_execution())
                },
            )
            .unwrap();
        drop(current);
        let mm = fixture.child.shared().mm().id();
        // Equal MM number and stage-1 projection, different real census/barrier.
        let (impostor, _) =
            carrick_kernel::dispatch::DispatchMmAuthority::foreign_cow_composition_for_test(
                mm,
                fixture.stage1.clone(),
                TEST_VA,
                TEST_VA + 8192,
            );
        let wrong = carrick_kernel::dispatch::SyscallDispatcher::with_native_mm_for_test(impostor);
        let mut wrong_executor = wrong
            .admit_native_executor(&fixture.child, &execution)
            .unwrap();
        let wrong_scope = wrong
            .enter_native_execution(&mut wrong_executor, &fixture.child, &mut execution)
            .unwrap();
        assert!(matches!(
            prepared.activate(&wrong_scope),
            Err(MmAccessError::ForeignMutationAuthorityMismatch)
        ));
        drop(wrong_scope);
        drop(wrong_executor);

        let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::with_native_mm_for_test(
            fixture.dispatch_mm.clone(),
        );
        let mut executor = dispatcher
            .admit_native_executor(&fixture.child, &execution)
            .unwrap();
        let mutator_tid = ThreadId::synthetic_for_tests(32_402);
        let barrier = fixture.dispatch_mm.pt_quiesce();
        let scope = dispatcher
            .enter_native_execution(&mut executor, &fixture.child, &mut execution)
            .unwrap();
        {
            let active = prepared.activate(&scope).unwrap();
            let result = try_acquire_mutation_pause_for_test(
                barrier,
                mutator_tid,
                mm,
                dispatcher.mm_mutation_coordinator(),
                PtPauseBudget {
                    election: std::time::Duration::ZERO,
                },
            );
            assert!(matches!(result, Err(PtPauseTryError::SiblingInGuest)));
            drop(result);
            assert!(scope.stop_requested());
            assert_eq!(active.len(), 4);
        }
        assert!(matches!(
            prepared.activate(&scope),
            Err(MmAccessError::NativeDataControlPending)
        ));
        drop(scope);
        let pause = acquire_mutation_pause_for_test(
            barrier,
            mutator_tid,
            mm,
            dispatcher.mm_mutation_coordinator(),
            PtPauseBudget::DEFAULT,
        )
        .unwrap();
        assert!(barrier.is_quiescing());
        drop(pause);
        assert!(executor.take_stop_request());
        // A new exact execution lease can activate the retained pin again; the
        // prior scope/lease themselves cannot survive scheduler migration.
        drop(executor);
        fixture
            .child
            .thread()
            .yield_from_executor(execution)
            .unwrap();
        let mut successor = fixture
            .child
            .thread()
            .claim_runnable(
                carrick_kernel::kernel::objects::ExecutorId::for_transitional_thread(
                    ThreadId::synthetic_for_tests(32403),
                )
                .unwrap(),
            )
            .unwrap();
        let mut executor = dispatcher
            .admit_native_executor(&fixture.child, &successor)
            .unwrap();
        let scope = dispatcher
            .enter_native_execution(&mut executor, &fixture.child, &mut successor)
            .unwrap();
        {
            let _active = prepared.activate(&scope).unwrap();
        }
        drop(scope);
        drop(executor);
        assert_eq!(dispatcher.mm_occupancy_probe()(), 0);
        fixture
            .child
            .thread()
            .yield_from_executor(successor)
            .unwrap();
    }

    /// Same-binary diagnostic for the incremental cost of activating a retained
    /// data pin at entry. No Linux ratio, guest ELF or workload speedup claim.
    #[test]
    #[ignore = "release-only native activation cost diagnostic"]
    #[expect(
        clippy::assertions_on_constants,
        reason = "The ignored diagnostic must compile in debug and refuse only when run; a const assertion would break unrelated debug tests"
    )]
    fn native_data_activation_entry_cost() {
        use carrick_kernel::kernel::mm_access::MmAccessTarget;
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;
        assert!(
            !cfg!(debug_assertions),
            "run this diagnostic with --release"
        );
        // A resident COW grant is bounded to one 16 KiB compound. Keep one
        // valid page fixed and scale actual activation count, not an invalid
        // synthetic range extending beyond the fixture's mapping.
        const ITERATIONS: u32 = 4096;
        for scale in [1u32, 8, 32, 128] {
            let id = 33_000 + scale as i32;
            let (kernel, root) = bootstrap(id);
            let fixture = real_production_cow_fixture(
                &kernel,
                &root,
                id + 200,
                0x9a00_a000_0000 + scale as u64 * 0x100_0000,
                0x9b00_a000_0000 + scale as u64 * 0x100_0000,
                ThreadId::synthetic_for_tests(id + 200),
            );
            let mut execution = execution_lease(&fixture.child, id as u64);
            let authority = carrick_kernel::kernel::MmAccessAuthority::new();
            let current = fixture.child.current_mm(&execution).unwrap();
            let range = current
                .access_token()
                .write_range(GuestVa(TEST_VA), 4096)
                .unwrap()
                .unwrap();
            let mut prepared = authority
                .with_current_mutation(
                    &current,
                    ThreadId::synthetic_for_tests(id + 200),
                    |mutation| {
                        let mut cow = authority
                            .break_foreign_cow(mutation, &current, range)
                            .unwrap();
                        Ok(fixture
                            .child
                            .borrow_current_native_data(&execution, &mut cow)
                            .unwrap()
                            .prepare_for_execution())
                    },
                )
                .unwrap();
            drop(current);
            let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::with_native_mm_for_test(
                fixture.dispatch_mm.clone(),
            );
            let mut executor = dispatcher
                .admit_native_executor(&fixture.child, &execution)
                .unwrap();
            // Alternate paired arms. Preparation, COW and output stay outside
            // both timed windows. Every requested activation must succeed.
            let mut run = |activate: bool, count: u32| {
                let start = std::time::Instant::now();
                for _ in 0..count {
                    let scope = dispatcher
                        .enter_native_execution(&mut executor, &fixture.child, &mut execution)
                        .unwrap();
                    if activate {
                        let active = prepared.activate(&scope).unwrap();
                        std::hint::black_box(active.len());
                    } else {
                        std::hint::black_box(&scope);
                    }
                }
                start.elapsed().as_nanos() as f64 / f64::from(count)
            };
            run(false, 128);
            run(true, 128);
            for sample in 0..9 {
                let (scope_ns, activated_ns) = if sample % 2 == 0 {
                    let base = run(false, ITERATIONS * scale);
                    (base, run(true, ITERATIONS * scale))
                } else {
                    let active = run(true, ITERATIONS * scale);
                    (run(false, ITERATIONS * scale), active)
                };
                println!(
                    "native_activation_cost {}",
                    serde_json::json!({
                        "scale": scale, "pages": 1, "sample": sample, "iterations": ITERATIONS * scale,
                        "scope_ns": scope_ns, "activated_ns": activated_ns,
                        "activation_delta_ns": activated_ns - scope_ns,
                        "runtime_conformance_metrics": cfg!(feature = "conformance-metrics"),
                        "workload_timing_eligible": false,
                    })
                );
            }
            drop(executor);
            fixture
                .child
                .thread()
                .yield_from_executor(execution)
                .unwrap();
        }
    }

    #[test]
    fn native_data_borrow_composes_execution_lease_and_production_cow() {
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;
        let (kernel, root) = bootstrap(31_180);
        let fixture = real_production_cow_fixture(
            &kernel,
            &root,
            31_181,
            0x9a00_3b00_0000,
            0x9b00_3b00_0000,
            ThreadId::synthetic_for_tests(31_181),
        );
        let original = fixture.carrier.pin_original_data_for_test().unwrap();
        let execution = execution_lease(&fixture.child, 181);
        let wrong = execution_lease(&root, 180);
        let current = fixture.child.current_mm(&execution).unwrap();
        use carrick_kernel::kernel::mm_access::MmAccessTarget;
        let range = current
            .access_token()
            .write_range(GuestVa(TEST_VA), 4)
            .unwrap()
            .unwrap();
        let authority = carrick_kernel::kernel::MmAccessAuthority::new();
        authority
            .with_current_mutation(
                &current,
                ThreadId::synthetic_for_tests(31_181),
                |mutation| {
                    let mut cow = authority
                        .break_foreign_cow(mutation, &current, range)
                        .unwrap();
                    assert!(
                        fixture
                            .child
                            .borrow_current_native_data(&wrong, &mut cow)
                            .is_err()
                    );
                    let mut data = fixture
                        .child
                        .borrow_current_native_data(&execution, &mut cow)
                        .expect("authenticated resident native data span after production COW");
                    assert_eq!(data.start(), GuestVa(TEST_VA));
                    assert_eq!(data.len(), 4);
                    // This bounded native CPU operation qualifies the data grant only.
                    // It does not publish translated code or call the syscall dispatcher.
                    unsafe {
                        let ptr = data.as_mut_ptr();
                        crate::vcpu_loop::native_probe::increment_u32(ptr);
                    }
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(
            original.prefix(),
            *b"same",
            "COW must preserve original backing"
        );
        let current = foreign_mm(&kernel, &root, &wrong, fixture.child.task().key());
        let read = current
            .access_token()
            .read_range(GuestVa(TEST_VA), 4)
            .unwrap()
            .unwrap();
        let mut bytes = [0; 4];
        authority.read_foreign(&current, read, &mut bytes).unwrap();
        assert_eq!(u32::from_le_bytes(bytes), u32::from_le_bytes(*b"same") + 1);
    }

    #[test]
    fn native_data_borrow_rechecks_all_vma_permissions_and_revision() {
        use carrick_kernel::kernel::mm_access::MmAccessTarget;
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;
        for mode in 0..7 {
            let id = 31_200 + mode;
            let (kernel, root) = bootstrap(id);
            let fixture = real_production_cow_fixture(
                &kernel,
                &root,
                id + 100,
                0x9a00_4000_0000 + mode as u64 * 0x100_0000,
                0x9b00_4000_0000 + mode as u64 * 0x100_0000,
                ThreadId::synthetic_for_tests(id + 100),
            );
            let execution = execution_lease(&fixture.child, id as u64);
            let current = fixture.child.current_mm(&execution).unwrap();
            let range = current
                .access_token()
                .write_range(GuestVa(TEST_VA), 4)
                .unwrap()
                .unwrap();
            let authority = carrick_kernel::kernel::MmAccessAuthority::new();
            authority
                .with_current_mutation(
                    &current,
                    ThreadId::synthetic_for_tests(id + 100),
                    |mutation| {
                        let mut cow = authority
                            .break_foreign_cow(mutation, &current, range)
                            .unwrap();
                        fixture
                            .dispatch_mm
                            .set_foreign_cow_vma_access_for_test(VmaAccess {
                                readable: mode != 0 && mode != 4,
                                writable: mode == 2 || mode == 3,
                                executable: mode <= 2,
                                kernel_visible: true,
                            });
                        // mode 5 restores RW after an intervening protection change.
                        if mode == 5 {
                            fixture
                                .dispatch_mm
                                .set_foreign_cow_vma_access_for_test(VmaAccess {
                                    readable: true,
                                    writable: true,
                                    executable: false,
                                    kernel_visible: true,
                                });
                        }
                        let result = fixture
                            .child
                            .borrow_current_native_data(&execution, &mut cow);
                        let expected = match mode {
                            0 | 4 => matches!(result, Err(MmAccessError::ReadDenied { .. })),
                            1 | 6 => matches!(result, Err(MmAccessError::WriteDenied { .. })),
                            2 => matches!(result, Err(MmAccessError::NativeDataExecutable { .. })),
                            3 | 5 => matches!(result, Err(MmAccessError::StaleCowBroken)),
                            _ => unreachable!(),
                        };
                        assert!(expected, "wrong refusal for permission mode {mode}");
                        Ok(())
                    },
                )
                .unwrap();
        }
    }

    #[test]
    fn native_data_borrow_refuses_denied_second_leaf_and_stale_owner() {
        use carrick_kernel::kernel::mm_access::MmAccessTarget;
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;
        for kind in 0..4u8 {
            let id = 31_400 + i32::from(kind);
            let (kernel, root) = bootstrap(id);
            let fixture = real_production_cow_fixture(
                &kernel,
                &root,
                id + 100,
                0x9a00_5000_0000 + u64::from(kind) * 0x100_0000,
                0x9b00_5000_0000 + u64::from(kind) * 0x100_0000,
                ThreadId::synthetic_for_tests(id + 100),
            );
            let execution = execution_lease(&fixture.child, id as u64);
            let current = fixture.child.current_mm(&execution).unwrap();
            let range = current
                .access_token()
                .write_range(GuestVa(TEST_VA + 4092), 8)
                .unwrap()
                .unwrap();
            let authority = carrick_kernel::kernel::MmAccessAuthority::new();
            authority
                .with_current_mutation(
                    &current,
                    ThreadId::synthetic_for_tests(id + 100),
                    |mutation| {
                        let mut cow = authority
                            .break_foreign_cow(mutation, &current, range)
                            .unwrap();
                        // Both pages initially qualify. Deny only the second, keeping
                        // the semantic VMA unchanged so the carrier must reject it.
                        drop(
                            fixture
                                .child
                                .borrow_current_native_data(&execution, &mut cow)
                                .unwrap(),
                        );
                        fixture
                            .carrier
                            .deny_native_data_for_test(TEST_VA + 4096, kind)
                            .unwrap();
                        assert!(
                            fixture
                                .child
                                .borrow_current_native_data(&execution, &mut cow)
                                .is_err(),
                            "kind {kind}"
                        );
                        Ok(())
                    },
                )
                .unwrap();
        }
    }

    #[test]
    fn native_data_borrow_isolates_same_va_and_accepts_private_identity() {
        use carrick_kernel::kernel::mm_access::MmAccessTarget;
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;
        let (kernel, root) = bootstrap(31_600);
        let a = real_production_cow_fixture(
            &kernel,
            &root,
            31_601,
            0x9a00_6000_0000,
            0x9b00_6000_0000,
            ThreadId::synthetic_for_tests(31_601),
        );
        let b = real_production_cow_fixture(
            &kernel,
            &root,
            31_602,
            0x9a00_6100_0000,
            0x9b00_6100_0000,
            ThreadId::synthetic_for_tests(31_602),
        );
        let ae = execution_lease(&a.child, 601);
        let be = execution_lease(&b.child, 602);
        let (_other_kernel, other_root) = bootstrap(31_600);
        let other_execution = execution_lease(&other_root, 600);
        let authority = carrick_kernel::kernel::MmAccessAuthority::new();
        for (fixture, execution, value) in [(&a, &ae, 11u32), (&b, &be, 22)] {
            for round in 0..2 {
                // copy-COW first, already-private identity next
                let current = fixture.child.current_mm(execution).unwrap();
                let range = current
                    .access_token()
                    .write_range(GuestVa(TEST_VA), 4)
                    .unwrap()
                    .unwrap();
                authority
                    .with_current_mutation(
                        &current,
                        ThreadId::synthetic_for_tests(if value == 11 { 31_601 } else { 31_602 }),
                        |mutation| {
                            let mut cow = authority
                                .break_foreign_cow(mutation, &current, range)
                                .unwrap();
                            assert!(
                                root.borrow_current_native_data(&other_execution, &mut cow)
                                    .is_err()
                            );
                            assert!(a.child.borrow_current_native_data(&be, &mut cow).is_err());
                            let (other_context, valid_other_execution) = if value == 11 {
                                (&b.child, &be)
                            } else {
                                (&a.child, &ae)
                            };
                            assert!(
                                other_context
                                    .borrow_current_native_data(valid_other_execution, &mut cow)
                                    .is_err()
                            );
                            let mut data = fixture
                                .child
                                .borrow_current_native_data(execution, &mut cow)
                                .unwrap();
                            // SAFETY: exact four-byte grant; no callback/escape; native
                            // scalar memory access stays within the mutation scope.
                            unsafe {
                                if round == 1 {
                                    assert_eq!(
                                        std::ptr::read_unaligned(data.as_mut_ptr().cast::<u32>()),
                                        value
                                    );
                                }
                                std::ptr::write_unaligned(data.as_mut_ptr().cast::<u32>(), value);
                            }
                            Ok(())
                        },
                    )
                    .unwrap();
            }
        }
        // Revisit A after changing B: equal semantic VA never shares backing.
        let current = a.child.current_mm(&ae).unwrap();
        let range = current
            .access_token()
            .write_range(GuestVa(TEST_VA), 4)
            .unwrap()
            .unwrap();
        authority
            .with_current_mutation(
                &current,
                ThreadId::synthetic_for_tests(31_601),
                |mutation| {
                    let mut cow = authority
                        .break_foreign_cow(mutation, &current, range)
                        .unwrap();
                    let mut data = a.child.borrow_current_native_data(&ae, &mut cow).unwrap();
                    assert_eq!(
                        unsafe { std::ptr::read_unaligned(data.as_mut_ptr().cast::<u32>()) },
                        11
                    );
                    Ok(())
                },
            )
            .unwrap();
    }

    #[test]
    fn production_carrier_foreign_cow_runs_end_to_end_through_runtime_facade() {
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;

        let (kernel, root) = bootstrap(31_110);
        let execution = execution_lease(&root, 110);
        let fixture = real_production_cow_fixture(
            &kernel,
            &root,
            31_111,
            0x9a00_3000_0000,
            0x9b00_3000_0000,
            ThreadId::synthetic_for_tests(31_079),
        );
        let foreign = foreign_mm(&kernel, &root, &execution, fixture.child.task().key());
        let range = foreign.write_range(GuestVa(TEST_VA), 4).unwrap().unwrap();

        let write = with_foreign_mutation(&foreign, |mutation| {
            let mut cow = carrick_kernel::kernel::MmAccessAuthority::new()
                .break_foreign_cow(mutation, &foreign, range)
                .expect("production carrier COW transaction");
            let prepared = carrick_kernel::kernel::MmAccessAuthority::new()
                .prepare_foreign_write(&mut cow, b"edit")
                .expect("production carrier authenticated write");
            carrick_kernel::kernel::MmAccessAuthority::new().commit_foreign_write(prepared)
        });

        assert_eq!(write.bytes_written(), 4);
        assert_eq!(
            fixture.stage1.binding().stage1_root.gpa(),
            Gpa(0x9a00_3000_0000)
        );
        assert_ne!(fixture.dispatch_mm.vma_revision().raw(), 0);
        let _keep_carrier_live = &fixture.carrier;
    }

    #[test]
    fn production_rx_ptrace_text_commit_accepts_post_cow_inventory_revision() {
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;

        let (kernel, root) = bootstrap(31_114);
        let execution = execution_lease(&root, 114);
        let fixture = real_production_cow_fixture(
            &kernel,
            &root,
            31_115,
            0x9a00_3100_0000,
            0x9b00_3100_0000,
            ThreadId::synthetic_for_tests(31_080),
        );
        fixture
            .dispatch_mm
            .set_foreign_cow_vma_access_for_test(VmaAccess {
                readable: true,
                writable: false,
                executable: true,
                kernel_visible: true,
            });
        assert!(kernel.claim_ptrace_traceme(&fixture.child));
        let stop = carrick_kernel::kernel::LinuxSignal::for_signal_number(12).unwrap();
        assert!(kernel.stop_task_for_ptrace(fixture.child.task().key().id, stop));
        assert_eq!(
            kernel.settle_task_ptrace_stop(fixture.child.task().key().id),
            carrick_kernel::kernel::objects::PtraceStopSettlement::Stopped,
        );
        let witness = fixture
            .child
            .task()
            .begin_ptrace_memory_access(root.task().key())
            .expect("settled ptrace text witness");
        let foreign = foreign_mm(&kernel, &root, &execution, fixture.child.task().key());

        let write = with_foreign_mutation(&foreign, |mutation| {
            witness
                .with_revalidated_text(foreign.mm_id(), |access| {
                    carrick_kernel::kernel::MmAccessAuthority::new()
                        .write_ptrace_text_under_witness(
                            mutation,
                            &foreign,
                            &access,
                            GuestVa(TEST_VA),
                            b"edit",
                        )
                })
                .expect("revalidate exact ptrace text stop")
        });

        assert!(
            write.is_ok(),
            "post-COW executable prepare failed: {write:?}"
        );
        assert_eq!(write.unwrap().bytes_written(), 4);
        let _keep_carrier_live = &fixture.carrier;
    }

    #[test]
    fn production_ptrace_text_carries_executable_authority_when_snapshot_is_writable_but_source_is_rx()
     {
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;

        let (kernel, root) = bootstrap(31_116);
        let execution = execution_lease(&root, 116);
        let fixture = real_production_cow_fixture(
            &kernel,
            &root,
            31_117,
            0x9a00_3200_0000,
            0x9b00_3200_0000,
            ThreadId::synthetic_for_tests(31_081),
        );
        fixture
            .dispatch_mm
            .set_foreign_cow_vma_access_for_test(VmaAccess {
                readable: true,
                writable: true,
                executable: true,
                kernel_visible: true,
            });
        fixture
            .carrier
            .set_source_guest_writable_for_test(false)
            .expect("make production carrier source alias read-execute");
        fixture
            .carrier
            .set_source_stage1_writable_for_test()
            .expect("make production carrier source stage-1 leaf writable");
        assert!(
            !fixture
                .carrier
                .source_direct_store_would_fault_for_test()
                .expect("read production carrier source stage-1 leaf"),
            "fixture must model the live writable preimage / exact RX alias disagreement"
        );
        assert!(kernel.claim_ptrace_traceme(&fixture.child));
        let stop = carrick_kernel::kernel::LinuxSignal::for_signal_number(12).unwrap();
        assert!(kernel.stop_task_for_ptrace(fixture.child.task().key().id, stop));
        assert_eq!(
            kernel.settle_task_ptrace_stop(fixture.child.task().key().id),
            carrick_kernel::kernel::objects::PtraceStopSettlement::Stopped,
        );
        let witness = fixture
            .child
            .task()
            .begin_ptrace_memory_access(root.task().key())
            .expect("settled ptrace text witness");
        let foreign = foreign_mm(&kernel, &root, &execution, fixture.child.task().key());

        let write = with_foreign_mutation(&foreign, |mutation| {
            witness
                .with_revalidated_text(foreign.mm_id(), |access| {
                    carrick_kernel::kernel::MmAccessAuthority::new()
                        .write_ptrace_text_under_witness(
                            mutation,
                            &foreign,
                            &access,
                            GuestVa(TEST_VA),
                            b"edit",
                        )
                })
                .expect("revalidate exact ptrace text stop")
        });

        assert!(
            write.is_ok(),
            "executable POKETEXT lost its authenticated transport plan: {write:?}"
        );
        assert_eq!(write.unwrap().bytes_written(), 4);
        assert!(
            !fixture
                .carrier
                .source_guest_writable_for_test()
                .expect("read production carrier source alias permissions"),
            "ptrace executable authority must not widen the source RX protection"
        );
        assert!(
            fixture
                .carrier
                .source_direct_store_would_fault_for_test()
                .expect("read production carrier post-COW stage-1 leaf"),
            "exact RX alias authority must force the post-COW stage-1 leaf nonwritable"
        );
        let _keep_carrier_live = &fixture.carrier;
    }

    #[test]
    fn production_carrier_budget_one_full_occupancy_defers_caller_self_ack_to_entry() {
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;

        const ISOLATED_ENV: &str = "CARRICK_TASK7_BUDGET_ONE_CHILD";
        if std::env::var_os(ISOLATED_ENV).is_none() {
            let status = std::process::Command::new(
                std::env::current_exe().expect("locate runtime unit-test executable"),
            )
            .arg("--exact")
            .arg(
                "vcpu_loop::memory::tests::production_carrier_budget_one_full_occupancy_defers_caller_self_ack_to_entry",
            )
            .arg("--nocapture")
            .env(ISOLATED_ENV, "1")
            .status()
            .expect("run isolated production vCPU-budget test");
            assert!(
                status.success(),
                "isolated production vCPU-budget test failed"
            );
            return;
        }
        let _handshake = crate::vcpu_loop::quiesce::foreign_cow_handshake_test_lock();
        let (kernel, root) = bootstrap(31_112);
        let execution = execution_lease(&root, 112);
        let caller_tid = ThreadId::synthetic_for_tests(31_079);
        let fixture = real_production_cow_fixture(
            &kernel,
            &root,
            31_113,
            0x9a00_3100_0000,
            0x9b00_3100_0000,
            caller_tid,
        );
        let mm = fixture.child.shared().mm().id();
        let caller_executor = ExecutorId::for_transitional_thread(caller_tid)
            .expect("production caller executor identity");
        fixture
            .stage1
            .begin_asid_load(caller_executor)
            .expect("publish caller target-MM load")
            .mark_resident()
            .expect("publish caller target-MM residency");
        let binding = crate::vcpu_loop::quiesce::foreign_cow_task_binding_for_test(
            Arc::clone(&fixture.stage1),
            mm,
        )
        .expect("construct caller foreign-COW task binding");
        let observer = binding.cow_invalidation_observer(caller_executor);
        carrick_hal::vcpu_sched::install_for_budget(1);
        let scheduler = carrick_hal::vcpu_sched::global();
        let occupied = scheduler.acquire(caller_tid.raw() as u64);
        assert!(
            !scheduler.has_spare_capacity(),
            "the caller owns the sole vCPU"
        );
        let foreign = foreign_mm(&kernel, &root, &execution, fixture.child.task().key());
        let range = foreign.write_range(GuestVa(TEST_VA), 4).unwrap().unwrap();

        with_foreign_mutation(&foreign, |mutation| {
            carrick_kernel::kernel::MmAccessAuthority::new()
                .break_foreign_cow(mutation, &foreign, range)
                .expect("full-occupancy carrier COW must not acquire a maintenance vCPU");
        });
        assert!(
            fixture
                .stage1
                .pending_cow_invalidation(caller_executor)
                .is_some(),
            "foreign caller resident must not be awaited as its own command"
        );
        assert!(
            !scheduler.has_waiters(),
            "COW attempted a second vCPU acquisition"
        );

        let in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let hardware_calls = AtomicUsize::new(0);
        let entered =
            crate::vcpu_loop::quiesce::enter_hvpatch_guest_or_service_invalidation_for_test(
                &in_guest,
                fixture.dispatch_mm.pt_quiesce().as_ref(),
                caller_tid,
                caller_executor,
                &binding,
                &observer,
                |_| {
                    hardware_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )
            .expect("mandatory production pre-entry invalidation service");
        assert!(
            entered,
            "inactive resident should continue into guest after service"
        );
        in_guest.leave_guest();
        assert_eq!(hardware_calls.load(Ordering::SeqCst), 1);
        assert!(
            fixture
                .stage1
                .pending_cow_invalidation(caller_executor)
                .is_none()
        );
        scheduler.release(occupied, carrick_hal::vcpu_sched::Yield::Exited);
    }

    #[test]
    fn production_carrier_active_target_services_publication_on_owner_entry_path() {
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;

        let _handshake = crate::vcpu_loop::quiesce::foreign_cow_handshake_test_lock();
        let (kernel, root) = bootstrap(31_114);
        let execution = execution_lease(&root, 114);
        let caller_tid = ThreadId::synthetic_for_tests(31_079);
        let fixture = real_production_cow_fixture(
            &kernel,
            &root,
            31_115,
            0x9a00_3200_0000,
            0x9b00_3200_0000,
            caller_tid,
        );
        // Mixed execution modes share the drain, but only the hardware owner
        // below services this phase's ASID invalidation.
        let native_dispatcher =
            carrick_kernel::dispatch::SyscallDispatcher::with_native_mm_for_test(
                fixture.dispatch_mm.clone(),
            );
        let native_lease = execution_lease(&fixture.child, 31115);
        let native_executor = native_dispatcher
            .admit_native_executor(&fixture.child, &native_lease)
            .unwrap();
        let mm = fixture.child.shared().mm().id();
        let active_tid = ThreadId::synthetic_for_tests(31_116);
        let active_executor = ExecutorId::for_transitional_thread(active_tid)
            .expect("production active executor identity");
        fixture
            .stage1
            .begin_asid_load(active_executor)
            .expect("publish active target-MM load")
            .mark_resident()
            .expect("publish active target-MM residency");
        let binding = crate::vcpu_loop::quiesce::foreign_cow_task_binding_for_test(
            Arc::clone(&fixture.stage1),
            mm,
        )
        .expect("construct active foreign-COW task binding");
        let observer = binding.cow_invalidation_observer(active_executor);
        let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let in_guest = Arc::new(carrick_hal::InGuestFlag::for_guest_thread());
        assert!(matches!(
            registry.subscribe_register(
                active_tid,
                Box::new(LeaveGuestOnKick(Arc::clone(&in_guest))),
                &in_guest,
                Arc::new(|| {}),
            ),
            carrick_hal::VcpuRegistrationEnrollment::Registered
        ));
        let target_mm = Arc::clone(&fixture.dispatch_mm);
        let endpoint: Arc<dyn VcpuRegistry> = registry.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
        let hardware_calls = Arc::new(AtomicUsize::new(0));
        let worker_calls = Arc::clone(&hardware_calls);
        let target_quiesce = Arc::clone(fixture.dispatch_mm.pt_quiesce());
        let worker_quiesce = Arc::clone(&target_quiesce);
        let worker = std::thread::spawn(move || {
            let slot = carrick_kernel::kernel::HostExecutionSlot::allocate()
                .expect("active target host slot");
            let _participation = target_mm
                .occupy_for_test(slot.slot(), endpoint, active_tid)
                .expect("production active target occupancy");
            in_guest.enter_guest();
            ready_tx.send(()).expect("publish active target entry");
            let deadline = Instant::now() + Duration::from_secs(1);
            while !worker_quiesce.is_quiescing() {
                assert!(
                    Instant::now() < deadline,
                    "production target pause was never raised"
                );
                std::thread::yield_now();
            }
            let entered =
                crate::vcpu_loop::quiesce::enter_hvpatch_guest_or_service_invalidation_for_test(
                    &in_guest,
                    &worker_quiesce,
                    active_tid,
                    active_executor,
                    &binding,
                    &observer,
                    |_| {
                        worker_calls.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                )
                .expect("active target production entry service");
            assert!(
                !entered,
                "paused target returns to the outer execution loop"
            );
        });
        ready_rx.recv().expect("active target is in guest");
        let foreign = foreign_mm(&kernel, &root, &execution, fixture.child.task().key());
        let range = foreign.write_range(GuestVa(TEST_VA), 4).unwrap().unwrap();

        let result = with_foreign_mutation(&foreign, |mutation| {
            carrick_kernel::kernel::MmAccessAuthority::new()
                .break_foreign_cow(mutation, &foreign, range)
                .map(|_| ())
        });
        worker
            .join()
            .expect("active target resumes after COW commit");

        assert!(
            result.is_ok(),
            "active target carrier COW failed: {result:?}"
        );
        assert_eq!(hardware_calls.load(Ordering::SeqCst), 1);
        assert!(
            fixture
                .stage1
                .pending_cow_invalidation(active_executor)
                .is_none()
        );
        registry.unregister(active_tid);
        drop(native_executor);
        fixture
            .child
            .thread()
            .yield_from_executor(native_lease)
            .unwrap();
        assert_eq!(native_dispatcher.mm_occupancy_probe()(), 0);
    }

    #[test]
    fn production_carrier_clone_vm_target_reuses_exact_cow_authority() {
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;

        let (kernel, root) = bootstrap(31_079);
        let execution = execution_lease(&root, 79);
        let target = real_production_cow_fixture(
            &kernel,
            &root,
            31_080,
            0x9a00_3300_0000,
            0x9b00_3300_0000,
            ThreadId::synthetic_for_tests(31_079),
        );
        let shared = kernel
            .reserve_fork(
                &target.child,
                ClonePlan::from_flags(LinuxCloneFlags::VM).expect("CLONE_VM plan"),
                "production foreign COW CLONE_VM peer".to_owned(),
                None,
            )
            .expect("reserve CLONE_VM peer")
            .prepare_shared_mm(ThreadId::synthetic_for_tests(31_081))
            .expect("prepare shared target MM")
            .commit()
            .expect("publish CLONE_VM peer")
            .into_parts()
            .expect("start CLONE_VM peer")
            .0;
        assert!(Arc::ptr_eq(
            &target.child.shared().mm(),
            &shared.shared().mm()
        ));
        let foreign = foreign_mm(&kernel, &root, &execution, shared.task().key());
        let range = foreign.write_range(GuestVa(TEST_VA), 4).unwrap().unwrap();

        let result = with_foreign_mutation(&foreign, |mutation| {
            carrick_kernel::kernel::MmAccessAuthority::new()
                .break_foreign_cow(mutation, &foreign, range)
                .map(|_| ())
        });

        assert!(
            result.is_ok(),
            "CLONE_VM lost exact COW authority: {result:?}"
        );
    }

    #[test]
    fn production_carrier_target_exec_and_retirement_race_foreign_acquisition() {
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;

        fn finish_acquisition(acquired: Result<MmRelation<'_>, MmAccessError>, expected_mm: MmId) {
            match acquired {
                Ok(MmRelation::Foreign(foreign)) => {
                    assert_eq!(foreign.mm_id(), expected_mm, "race selected the wrong MM");
                    let range = foreign
                        .write_range(GuestVa(TEST_VA), 4)
                        .expect("race target range validation")
                        .expect("race target has writable production VMA");
                    let result = carrick_kernel::kernel::MmAccessAuthority::new()
                        .with_foreign_mutation(
                            &foreign,
                            ThreadId::synthetic_for_tests(31_079),
                            |mutation| {
                                carrick_kernel::kernel::MmAccessAuthority::new()
                                    .break_foreign_cow(mutation, &foreign, range)
                                    .map(|_| ())
                            },
                        );
                    assert!(
                        result.is_ok(),
                        "retained race winner failed COW: {result:?}"
                    );
                }
                Err(
                    MmAccessError::UnknownTask(_)
                    | MmAccessError::StaleContext(_)
                    | MmAccessError::MissingForeignTransport(_),
                ) => {}
                Err(MmAccessError::Snapshot(SnapshotError::TimedOut)) => {}
                Ok(MmRelation::Current(_)) => panic!("foreign race selected caller MM"),
                Err(error) => panic!("unexpected foreign acquisition race outcome: {error:?}"),
            }
        }

        {
            let (kernel, root) = bootstrap(31_117);
            let execution = execution_lease(&root, 117);
            let target = real_production_cow_fixture(
                &kernel,
                &root,
                31_118,
                0x9a00_3400_0000,
                0x9b00_3400_0000,
                ThreadId::synthetic_for_tests(31_079),
            );
            let target_key = target.child.task().key();
            let expected_mm = target.child.shared().mm().id();
            let start = Arc::new(std::sync::Barrier::new(2));
            let (acquired, replacement) = std::thread::scope(|scope| {
                let worker_start = Arc::clone(&start);
                let worker_kernel = &kernel;
                let worker_target = &target.child;
                let worker = scope.spawn(move || {
                    worker_start.wait();
                    worker_kernel
                        .commit_exec(
                            worker_kernel
                                .prepare_exec_with_mm_backend(
                                    worker_target,
                                    fixture_backend(),
                                    None,
                                )
                                .expect("prepare racing target exec"),
                            None,
                        )
                        .expect("commit racing target exec")
                });
                start.wait();
                let acquired = kernel.foreign_mm(&root, &execution, target_key);
                let replacement = worker.join().expect("racing exec worker");
                (acquired, replacement)
            });
            finish_acquisition(acquired, expected_mm);
            assert_ne!(replacement.shared().mm().id(), expected_mm);
        }

        {
            let (kernel, root) = bootstrap(31_119);
            let execution = execution_lease(&root, 119);
            let target = real_production_cow_fixture(
                &kernel,
                &root,
                31_120,
                0x9a00_3500_0000,
                0x9b00_3500_0000,
                ThreadId::synthetic_for_tests(31_079),
            );
            let target_key = target.child.task().key();
            let expected_mm = target.child.shared().mm().id();
            let start = Arc::new(std::sync::Barrier::new(2));
            let acquired = std::thread::scope(|scope| {
                let worker_start = Arc::clone(&start);
                let worker_kernel = &kernel;
                let worker = scope.spawn(move || {
                    worker_start.wait();
                    worker_kernel
                        .exit_task_key_eventually(
                            target_key,
                            LinuxWaitStatus::from_wait_encoding(0),
                        )
                        .expect("racing target retirement")
                });
                start.wait();
                let acquired = kernel.foreign_mm(&root, &execution, target_key);
                worker.join().expect("racing retirement worker");
                acquired
            });
            finish_acquisition(acquired, expected_mm);
        }
    }

    #[test]
    fn foreign_cow_rejects_wrong_mm_guard_range_and_backend_receipt_identity() {
        let (kernel, root) = bootstrap(31_082);
        let execution = execution_lease(&root, 82);
        let (child, _backend, _owner, _bytes, _counters) =
            cow_fixture(&kernel, &root, 31_083, MockCowFault::None);
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();
        let wrong_mm =
            MmId::from_registry_allocation(NonZeroU64::new(foreign.mm_id().raw() + 1).unwrap());
        with_mm_mutation(wrong_mm, |mutation| {
            assert!(matches!(
                carrick_kernel::kernel::MmAccessAuthority::new()
                    .break_foreign_cow(mutation, &foreign, range),
                Err(MmAccessError::ForeignMutationAuthorityMismatch)
            ));
        });

        let (other, _backend, _owner, _bytes, _counters) =
            cow_fixture(&kernel, &root, 31_084, MockCowFault::None);
        let other_foreign = foreign_mm(&kernel, &root, &execution, other.task().key());
        let other_range = other_foreign
            .write_range(GuestVa(0x3000), 4)
            .unwrap()
            .unwrap();
        with_foreign_mutation(&foreign, |mutation| {
            assert!(matches!(
                carrick_kernel::kernel::MmAccessAuthority::new().break_foreign_cow(
                    mutation,
                    &foreign,
                    other_range,
                ),
                Err(MmAccessError::ForeignRangeAuthorityMismatch)
            ));
        });

        for fault in [MockCowFault::WrongMm, MockCowFault::WrongRange] {
            let (target, _backend, _owner, _bytes, _counters) =
                cow_fixture(&kernel, &root, 31_085 + fault as i32, fault);
            let target = foreign_mm(&kernel, &root, &execution, target.task().key());
            let target_range = target.write_range(GuestVa(0x3000), 4).unwrap().unwrap();
            with_foreign_mutation(&target, |mutation| {
                assert!(matches!(
                    carrick_kernel::kernel::MmAccessAuthority::new().break_foreign_cow(
                        mutation,
                        &target,
                        target_range,
                    ),
                    Err(MmAccessError::ForeignCowReceiptMismatch)
                ));
            });
        }
    }

    #[test]
    fn foreign_cow_proof_issuer_does_not_sign_transport_chosen_owner_generation() {
        let (kernel, root) = bootstrap(31_128);
        let mm = root.shared().mm().id();
        let tid = ThreadId::synthetic_for_tests(31_128);
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(2).unwrap();
        let mut reservation = kernel.reserve_frame_inventory(1, 1, capacity).unwrap();
        let transaction = reservation.transaction();
        let frame = reservation.claim_frame().unwrap();
        let mapping = reservation.claim_mapping().unwrap();
        let generation =
            carrick_hal::MappingGeneration::from_backend_counter(NonZeroU64::new(1).unwrap());
        let gpa = Gpa(0xd000);
        let length =
            carrick_hal::FrameLength::from_mapping_extent(NonZeroU64::new(0x4000).unwrap());
        reservation
            .push(carrick_hal::FrameInventoryEvent::PrepareMapping {
                transaction,
                frame,
                mapping,
                generation,
                gpa,
                length,
                permissions: carrick_hal::MemPerms {
                    read: true,
                    write: true,
                    exec: false,
                },
            })
            .unwrap();
        reservation
            .push(carrick_hal::FrameInventoryEvent::PublishMapping {
                transaction,
                mapping,
                generation,
            })
            .unwrap();
        let current_owner =
            carrick_hal::ForeignOwnerGeneration::from_backend_counter(NonZeroU64::new(61).unwrap());
        let transport_chosen_owner =
            carrick_hal::ForeignOwnerGeneration::from_backend_counter(NonZeroU64::new(62).unwrap());
        let authority = crate::vcpu_loop::kernel_frame_cow_authority_for_test(
            Arc::clone(&kernel),
            mm,
            tid,
            7,
            crate::vcpu_loop::fixed_frame_cow_owner_inventory_for_test(current_owner),
        );

        let (receipt, proof, authenticated_owner) = authority
            .apply_foreign_cow(
                reservation.commit(()),
                GuestVa(0x3000),
                std::num::NonZeroUsize::new(0x4000).unwrap(),
                mapping,
                frame,
                gpa,
                length,
            )
            .expect("apply foreign COW inventory transaction");
        let proof = proof
            .downcast_ref::<carrick_kernel::kernel::KernelForeignCowProof>()
            .expect("runtime-private kernel proof");

        assert!(
            authenticated_owner == current_owner,
            "proof issuer returned a transport-selected owner generation"
        );
        assert!(
            proof.authenticates(
                &kernel,
                mm,
                GuestVa(0x3000),
                0x4000,
                receipt.revision(),
                mapping,
                frame,
                gpa,
                length.raw(),
                current_owner,
            ),
            "proof issuer signed a transport-chosen owner instead of the independent current owner"
        );
        assert!(
            !proof.authenticates(
                &kernel,
                mm,
                GuestVa(0x3000),
                0x4000,
                receipt.revision(),
                mapping,
                frame,
                gpa,
                length.raw(),
                transport_chosen_owner,
            ),
            "transport-selected owner generation was accepted by the kernel proof issuer"
        );
    }

    #[test]
    fn foreign_cow_runtime_rejects_transport_owner_after_independent_proof_issuance() {
        let (kernel, root) = bootstrap(31_129);
        let execution = execution_lease(&root, 129);
        let (child, _backend, owner_generation, _bytes, _counters) =
            cow_fixture(&kernel, &root, 31_130, MockCowFault::None);
        let mm = child.shared().mm().id();
        let current_owner = carrick_hal::ForeignOwnerGeneration::from_backend_counter(
            NonZeroU64::new(owner_generation.load(Ordering::Acquire)).unwrap(),
        );
        let transport_chosen_owner = carrick_hal::ForeignOwnerGeneration::from_backend_counter(
            NonZeroU64::new(current_owner.raw_for_probe().checked_add(1).unwrap()).unwrap(),
        );
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(2).unwrap();
        let mut reservation = kernel.reserve_frame_inventory(1, 1, capacity).unwrap();
        let transaction = reservation.transaction();
        let frame = reservation.claim_frame().unwrap();
        let mapping = reservation.claim_mapping().unwrap();
        let generation =
            carrick_hal::MappingGeneration::from_backend_counter(NonZeroU64::new(1).unwrap());
        let physical_base = Gpa(0x20_000);
        let physical_len =
            carrick_hal::FrameLength::from_mapping_extent(NonZeroU64::new(0x4000).unwrap());
        reservation
            .push(carrick_hal::FrameInventoryEvent::PrepareMapping {
                transaction,
                frame,
                mapping,
                generation,
                gpa: physical_base,
                length: physical_len,
                permissions: carrick_hal::MemPerms {
                    read: true,
                    write: true,
                    exec: false,
                },
            })
            .unwrap();
        reservation
            .push(carrick_hal::FrameInventoryEvent::PublishMapping {
                transaction,
                mapping,
                generation,
            })
            .unwrap();
        let proof_issuer = crate::vcpu_loop::kernel_frame_cow_authority_for_test(
            Arc::clone(&kernel),
            mm,
            ThreadId::synthetic_for_tests(31_130),
            9,
            crate::vcpu_loop::fixed_frame_cow_owner_inventory_for_test(current_owner),
        );
        child.shared().mm().install_foreign_mm_endpoint_for_test(
            carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(OwnerSigningOracleTransport {
                lease: Arc::new(OwnerSigningOracleLease {
                    authority: proof_issuer,
                    commit: parking_lot::Mutex::new(Some(reservation.commit(()))),
                    mapping,
                    frame,
                    physical_base,
                    physical_len,
                    transport_chosen_owner,
                }),
            })),
        );
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();

        with_foreign_mutation(&foreign, |mutation| {
            assert!(matches!(
                carrick_kernel::kernel::MmAccessAuthority::new()
                    .break_foreign_cow(mutation, &foreign, range,),
                Err(MmAccessError::ForeignCowReceiptMismatch)
            ));
        });
    }
}
