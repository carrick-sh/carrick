//! What a backend implements for ONE Linux process, with no VM behind it.
//!
//! The kernel reaches a process through three seams, and this file is the
//! smallest honest implementation of each:
//!
//! - [`ExampleProcess`] is the [`CarrierProcess`]: the process's exact task
//!   binding, its kernel graph, per-Linux-tid contexts, and the two
//!   mm-authority bindings the dispatcher makes when it is bound to the
//!   process.
//! - [`ExampleMmBackend`] is the [`MmBackend`]: the address-space snapshot a
//!   `RootBootstrap` boots on. Guest memory here is a `Vec<u8>` the task owns
//!   (`carrick_kernel::dispatch::LinearMemory`), so the snapshot carries only
//!   what the dispatcher publishes into it (its VMA source) and no frame
//!   inventory.
//! - [`ExampleStage1Projection`] is the [`Stage1MmProjection`]: the ASID and
//!   stage-1 root a foreign-COW invalidation is addressed to. There are no
//!   page tables behind it. The ASID is a label this backend allocates so the
//!   kernel can tell two address spaces apart, and the "root" is derived from
//!   it.
//!
//! Everything here is built from `pub` items of `carrick-kernel`,
//! `carrick-hal` and `carrick-guest-mem`; nothing names the HVPatch carrier.

use std::num::{NonZeroU16, NonZeroU64};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::time::Instant;

use carrick_guest_mem::Gpa;
use carrick_hal::stage1_mm::{ForeignMmInstaller, Stage1MmProjection};
use carrick_hal::{
    ForeignAsid, ForeignAsidGeneration, ForeignCowInvalidationGeneration, ForeignMmBinding,
    ForeignMmId, ForeignStage1Identity, HostSignalBridge,
};
use carrick_kernel::dispatch::mm_mutation::ForeignMmMutationAuthority;
use carrick_kernel::kernel::{
    Asid, CarrierProcess, Kernel, KernelContext, KernelError, KernelTaskBinding, LinuxTid,
    MmAccessAuthority, MmBackend, MmBackendSnapshot, MmBinding, RootBootstrap,
    SharedVmaSnapshotSource, SnapshotError, Stage1Root, Stage1RootError, TaskKey, VmaRevision,
};
use carrick_kernel::run_result::RuntimeError;
use carrick_kernel::thread::ThreadId;
use parking_lot::{Mutex, RwLock};

/// Hands out the ASID labels this backend's address spaces are told apart
/// by. One per backend run: a VM owns its hardware ASID pool the same way,
/// and an ASID is never recycled here, so every ASID has exactly one
/// lifetime (generation 1 in [`ExampleStage1Projection`]).
#[derive(Debug)]
pub struct AsidAllocator {
    next: AtomicU16,
}

impl AsidAllocator {
    /// An allocator whose first label is ASID 1 (0 is never a valid ASID).
    pub const fn new() -> Self {
        Self {
            next: AtomicU16::new(1),
        }
    }

    fn allocate(&self) -> Option<NonZeroU16> {
        NonZeroU16::new(self.next.fetch_add(1, Ordering::AcqRel))
    }
}

impl Default for AsidAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Why an address space could not be allocated.
#[derive(Debug, thiserror::Error)]
pub enum AddressSpaceError {
    #[error("this backend's ASID labels are exhausted")]
    AsidExhausted,
    #[error("stage-1 root: {0}")]
    Stage1Root(#[from] Stage1RootError),
}

/// One address space of this backend: the mm backend the kernel snapshots
/// through and the stage-1 projection it addresses invalidations to, both
/// over the same `(ASID, root)` binding. Allocated before the kernel fork
/// that will own it (`ForkReservation::prepare_with_mm_backend` takes the
/// backend), then moved into the [`ExampleProcess`] of the published task.
#[derive(Debug)]
pub struct AddressSpace {
    backend: Arc<ExampleMmBackend>,
    stage1: Arc<ExampleStage1Projection>,
}

impl AddressSpace {
    /// A fresh address space under the next ASID label.
    pub fn allocate(asids: &AsidAllocator) -> Result<Self, AddressSpaceError> {
        let asid = asids.allocate().ok_or(AddressSpaceError::AsidExhausted)?;
        let stage1 = ExampleStage1Projection::new(asid)?;
        let backend = Arc::new(ExampleMmBackend::new(stage1.binding()));
        Ok(Self {
            backend,
            stage1: Arc::new(stage1),
        })
    }

    /// The backend as the kernel's `RootBootstrap::with_mm_backend` and
    /// `ForkReservation::prepare_with_mm_backend` take it.
    pub fn mm_backend(&self) -> Arc<dyn MmBackend> {
        Arc::clone(&self.backend) as Arc<dyn MmBackend>
    }
}

/// The stage-1 identity of one address space, with no page tables behind it.
///
/// The kernel asks a projection three things: the binding it publishes, the
/// exact identity a foreign-COW invalidation is addressed to, and a fresh
/// invalidation generation. A VM-less backend answers all three from one
/// fixed label: this backend never recycles an ASID, so its lifetime is
/// generation 1, and the "stage-1 root" is `asid << 12` (4 KiB aligned) so
/// two address spaces never publish the same root.
#[derive(Debug)]
pub struct ExampleStage1Projection {
    asid: NonZeroU16,
    binding: MmBinding,
    cow_invalidations: AtomicU64,
}

impl ExampleStage1Projection {
    /// The projection for ASID `asid`.
    pub fn new(asid: NonZeroU16) -> Result<Self, Stage1RootError> {
        let root = Stage1Root::for_aarch64_4k(Gpa(u64::from(asid.get()) << 12))?;
        let binding = MmBinding::for_aarch64(Asid::from_registry_allocation(asid), root);
        Ok(Self {
            asid,
            binding,
            cow_invalidations: AtomicU64::new(0),
        })
    }

    /// The `(ASID, root)` binding this projection publishes; the mm backend
    /// of the same address space snapshots under it.
    pub const fn binding(&self) -> MmBinding {
        self.binding
    }

    fn foreign_asid(&self) -> ForeignAsid {
        ForeignAsid::from_kernel_allocation(self.asid)
    }
}

impl Stage1MmProjection for ExampleStage1Projection {
    fn foreign_mm_binding(&self) -> ForeignMmBinding {
        ForeignMmBinding::for_aarch64(self.foreign_asid(), self.binding.stage1_root.gpa())
    }

    // `ForeignStage1Identity::new` refuses a binding and a generation that
    // name different ASIDs. Both halves come from `self.foreign_asid()`, so
    // the refusal is unreachable, and there is no other constructor to fall
    // back to.
    #[allow(clippy::expect_used)]
    fn foreign_stage1_identity(&self, mm: ForeignMmId) -> ForeignStage1Identity {
        let binding = self.foreign_mm_binding();
        let generation =
            ForeignAsidGeneration::from_runtime_binding(self.foreign_asid(), NonZeroU64::MIN);
        ForeignStage1Identity::new(mm, binding, generation)
            .expect("the binding and the generation were built from the same ASID")
    }

    fn publish_foreign_cow_invalidation(&self) -> ForeignCowInvalidationGeneration {
        let previous = self.cow_invalidations.fetch_add(1, Ordering::AcqRel);
        ForeignCowInvalidationGeneration::from_runtime_publication(
            NonZeroU64::MIN.saturating_add(previous),
        )
    }
}

/// The capability that installs foreign-mm state on one of this backend's
/// kernel mms. Only this module can mint one, which is the point of the
/// `ForeignMmInstaller` seam: a syscall handler holding a type-erased
/// `dyn Stage1MmProjection` cannot replace what the backend installed.
pub struct ExampleInstallPermit(());

impl ForeignMmInstaller for ExampleStage1Projection {
    type InstallPermit = ExampleInstallPermit;
}

/// The kernel's address-space snapshot seam over `Vec`-backed guest memory.
///
/// The dispatcher publishes a VMA source into the backend when it is bound
/// to the process ([`CarrierProcess::bind_vma_source`]); the snapshot reports
/// that source's VMAs and revision. There is no frame inventory: guest
/// memory is one `Vec<u8>` per task and no frame is ever shared, mapped or
/// COW-tracked, so `mapping_ids` is empty and `frame_inventory_revision`
/// absent.
pub struct ExampleMmBackend {
    binding: MmBinding,
    vma_source: RwLock<Option<SharedVmaSnapshotSource>>,
    revision: AtomicU64,
}

impl ExampleMmBackend {
    /// An unbound backend over `binding`: an empty address space at
    /// revision 1.
    pub fn new(binding: MmBinding) -> Self {
        Self {
            binding,
            vma_source: RwLock::new(None),
            revision: AtomicU64::new(1),
        }
    }

    /// Attach the VMA source the dispatcher publishes at bind time.
    pub fn bind_vma_source(&self, source: SharedVmaSnapshotSource) {
        *self.vma_source.write() = Some(source);
        self.revision.fetch_add(1, Ordering::AcqRel);
    }
}

impl std::fmt::Debug for ExampleMmBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExampleMmBackend")
            .field("binding", &self.binding)
            .field("vma_source_bound", &self.vma_source.read().is_some())
            .field("revision", &self.revision.load(Ordering::Acquire))
            .finish()
    }
}

impl MmBackend for ExampleMmBackend {
    fn snapshot(&self, deadline: Instant) -> Result<MmBackendSnapshot, SnapshotError> {
        let before = self.revision.load(Ordering::Acquire);
        let source = self.vma_source.read().clone();
        let (vmas, vma_revision) = match &source {
            Some(source) => {
                let snapshot = source.snapshot(deadline)?;
                (snapshot.vmas, Some(snapshot.revision))
            }
            None => (Vec::new(), None),
        };
        let after = self.revision.load(Ordering::Acquire);
        let source_moved = match (&source, vma_revision) {
            (Some(source), Some(revision)) => source.revision() != revision,
            _ => false,
        };
        if before != after || source_moved {
            return Err(SnapshotError::ChangedDuringObservation);
        }
        Ok(MmBackendSnapshot {
            revision: after,
            binding: self.binding,
            vmas,
            vma_revision,
            mapping_ids: Vec::new(),
            frame_inventory_revision: None,
        })
    }

    fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    fn vma_revision(&self, _deadline: Instant) -> Result<Option<VmaRevision>, SnapshotError> {
        Ok(self
            .vma_source
            .read()
            .as_ref()
            .map(|source| source.revision()))
    }
}

/// This backend's handle on one Linux process: the shape a backend
/// implements for the dispatcher to reach "the process it is bound to".
///
/// It is the process's exact `KernelTaskBinding` plus the address space it
/// runs in. Every derived operation the kernel needs (child waits, pidfd
/// watches, thread exit, ptrace stops) is a provided method of
/// [`CarrierProcess`] and is answered from the kernel graph, so this type
/// supplies only the carrier's own facts.
pub struct ExampleProcess {
    binding: KernelTaskBinding,
    space: AddressSpace,
    bind_failure: Mutex<Option<KernelError>>,
}

impl ExampleProcess {
    /// Boot the root Linux task of a fresh kernel graph in `space`, exactly
    /// as the carrier boots its root: `RootBootstrap::with_mm_backend` over
    /// the backend's own `MmBackend`, then `Kernel::bootstrap_root`. The
    /// root's leader tid is its pid, as Linux numbers a thread-group leader.
    pub fn boot_root(
        pid: i32,
        diagnostic_name: &str,
        host_signal: Arc<dyn HostSignalBridge>,
        space: AddressSpace,
    ) -> Result<(Self, KernelContext), KernelError> {
        let bootstrap = RootBootstrap::with_mm_backend(
            pid,
            ThreadId::from_guest_supplied_tid(pid),
            space.mm_backend(),
            diagnostic_name.to_owned(),
            host_signal,
        )?;
        let (_kernel, root) = Kernel::bootstrap_root(bootstrap)?;
        Ok((Self::new(&root, space), root))
    }

    /// The handle on an already-published task (a forked child), in the
    /// address space its fork was prepared with.
    pub fn new(context: &KernelContext, space: AddressSpace) -> Self {
        Self {
            binding: context.task_binding(),
            space,
            bind_failure: Mutex::new(None),
        }
    }

    /// A dispatcher bind that could not resolve this process's own leader
    /// context is a broken process, not a condition the bind callback can
    /// report (it returns `()`); it is recorded here for the backend to
    /// surface right after `SyscallDispatcher::bind_hvpatch_process`.
    pub fn take_bind_failure(&self) -> Option<KernelError> {
        self.bind_failure.lock().take()
    }
}

impl CarrierProcess for ExampleProcess {
    fn kernel_graph(&self) -> &Arc<Kernel> {
        self.binding.kernel()
    }

    fn task_key(&self) -> TaskKey {
        self.binding.task_key()
    }

    fn task_binding(&self) -> KernelTaskBinding {
        self.binding.clone()
    }

    fn context_for_linux_tid(&self, tid: LinuxTid) -> Result<KernelContext, KernelError> {
        self.binding.capture(tid)
    }

    /// No foreign-mm access: a task's memory is a `Vec` only its own thread
    /// holds, so `process_vm_readv`-class syscalls have no endpoint here.
    fn mm_access_authority(&self) -> Option<&MmAccessAuthority> {
        None
    }

    fn stage1_mm_projection(&self) -> Result<Arc<dyn Stage1MmProjection>, RuntimeError> {
        Ok(Arc::clone(&self.space.stage1) as Arc<dyn Stage1MmProjection>)
    }

    fn bind_vma_source(&self, source: SharedVmaSnapshotSource) {
        self.space.backend.bind_vma_source(source);
    }

    fn bind_mm_mutation_authority(&self, authority: ForeignMmMutationAuthority) {
        match self.context_for_linux_tid(LinuxTid::for_task_leader(self.task_id())) {
            Ok(context) => context
                .shared()
                .mm()
                .install_foreign_mm_mutation_authority::<ExampleStage1Projection>(
                    authority,
                    &ExampleInstallPermit(()),
                ),
            Err(error) => *self.bind_failure.lock() = Some(error),
        }
    }
}
