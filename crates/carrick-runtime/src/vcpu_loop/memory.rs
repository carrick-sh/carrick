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
    /// Exact-MM admission plus every participant's opaque pause endpoint.
    pub(crate) guest_executors: Arc<carrick_kernel::kernel::GuestExecutorCensus>,
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
    guest_executors: Arc<carrick_kernel::kernel::GuestExecutorCensus>,
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
        carrick_kernel::dispatch::mm_quiesce::acquire_frame_cow_quiesce(
            &self.pt_quiesce,
            self.mm,
            &self.guest_executors,
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
        use carrick_vmm_hvf::trap::foreign_cow_test_support::{
            FixtureShape, InitialInventoryIdentity, ProductionCarrierForeignCowCustody,
            ProductionCarrierForeignCowHarness, ProductionCarrierForeignCowInstallArgs, TEST_VA,
        };

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
        let shape = FixtureShape::new(Gpa(stage1_root), Gpa(data_ipa))
            .expect("real production carrier fixture shape");
        let (dispatch_mm, mutation) =
            carrick_kernel::dispatch::DispatchMmAuthority::foreign_cow_composition_for_test(
                mm,
                Arc::clone(&stage1) as Arc<dyn carrick_hal::stage1_mm::Stage1MmProjection>,
                TEST_VA,
                TEST_VA + shape.data_len,
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
        let census = dispatch_mm.foreign_cow_executor_census_for_test();
        let carrier_custody = ProductionCarrierForeignCowCustody::new();
        let authority = crate::vcpu_loop::kernel_frame_cow_authority_for_test(
            Arc::clone(kernel),
            mm,
            census,
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
        let census = fixture.dispatch_mm.foreign_cow_executor_census_for_test();
        let endpoint: Arc<dyn VcpuRegistry> = registry.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
        let hardware_calls = Arc::new(AtomicUsize::new(0));
        let worker_calls = Arc::clone(&hardware_calls);
        let target_quiesce = Arc::clone(fixture.dispatch_mm.pt_quiesce());
        let worker_quiesce = Arc::clone(&target_quiesce);
        let worker = std::thread::spawn(move || {
            let _participation = census
                .enter_with_pause_endpoint(None, endpoint, active_tid)
                .expect("production active target census participation");
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
            Arc::new(carrick_kernel::kernel::GuestExecutorCensus::default()),
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
            Arc::new(carrick_kernel::kernel::GuestExecutorCensus::default()),
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
