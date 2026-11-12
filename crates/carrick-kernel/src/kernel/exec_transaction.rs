//! The root exec transaction: one ISA-neutral order for replacing a process
//! image, generic over the venue that owns the vCPU and its memory (#2142).
//!
//! The driver walks one typestate path, `Drained` -> `Prepared` -> `Armed` ->
//! `Installed` -> `Replaced` -> `Committed` -> published, and owns the neutral
//! steps between the venue hooks: the executable identity and binfmt argv, the
//! per-thread signal-state reset, the `/proc/self/{maps,auxv}` generation, SysV shm
//! detach, close-on-exec, the `/proc/self/exe` exec mark and the ptrace exec
//! stop. Everything that touches a register frame, a page-table format, a
//! stage-2 or ring MM, or venue-held thread state is a [`RootExecVenue`] hook.
//! The credential commit happens inside the venue's [`RootExecVenue::commit`],
//! through [`crate::kernel::Kernel::commit_exec_transition`].
//!
//! The order here is the HVF/HVPatch order it was moved from
//! (`carrick-runtime` `drive_execve`), unchanged: the signal reset and the
//! `/proc` generation precede the MM transaction, and every step after
//! [`ImageReplacement::arm_no_return`] that fails kills the process instead of
//! returning an errno.
//!
//! Lock order, for every venue: clone admission closed, the MM-generation
//! reservation, the sibling drain (nothing held across it), the registry write
//! inside [`RootExecVenue::prepare_mm`], the frame registry, then the MM
//! transaction of [`RootExecVenue::replace_image`], which takes the frame
//! registry again only after releasing the MM transaction. The two are never
//! nested.

use std::sync::Arc;
use std::time::Instant;

use carrick_observability::probes::HvpatchExecRuntimeStagePhase;
pub use carrick_signal_core::policy::ExecPastNoReturn;
use carrick_vfs::{ProcMapSharing, ProcMapsEntry};

use crate::dispatch::executable_authority::ExecSource;
use crate::dispatch::{PreparedDispatchMmExec, SyscallDispatcher};
use crate::kernel::{FileTable, KernelContext, MmId};
use crate::memory::AddressSpace;
use crate::run_result::RuntimeError;

/// The exec syscall's final answer when the driver stops early: `Ok(None)`
/// leaves the caller running, `Ok(Some(_))` terminates the process (a kill
/// after the point of no return), and `Err` is a runtime fault.
pub struct ExecExit<O>(Result<Option<O>, RuntimeError>);

impl<O> ExecExit<O> {
    pub const fn new(result: Result<Option<O>, RuntimeError>) -> Self {
        Self(result)
    }

    pub fn into_result(self) -> Result<Option<O>, RuntimeError> {
        self.0
    }
}

impl<O> From<RuntimeError> for ExecExit<O> {
    fn from(error: RuntimeError) -> Self {
        Self(Err(error))
    }
}

/// One driver step: continue with `T`, or stop with the syscall's answer.
pub type ExecStep<T, O> = Result<T, ExecExit<O>>;

/// Proof that the caller's siblings are gone and clone admission is closed.
/// The driver starts here; nothing is held across the drain.
pub struct Drained {
    started: Instant,
}

impl Drained {
    /// `started` is when the sibling drain began, for its runtime stage.
    pub const fn new(started: Instant) -> Self {
        Self { started }
    }
}

/// What the new image says about itself: `/proc/self/{exe,cmdline,environ}`
/// and the binfmt argv, published before the image is replaced.
pub struct ExecImageIdentity {
    pub path: String,
    pub argv: Vec<String>,
    pub env: Vec<Vec<u8>>,
    pub source: ExecSource,
    pub binfmt_argv: Option<Vec<Vec<u8>>>,
    pub command_line: String,
}

/// The Kernel preparation a venue returns from [`RootExecVenue::prepare_mm`].
pub trait PreparedRootExec {
    fn replacement_mm_id(&self) -> MmId;

    /// The caller's file table, closed by close-on-exec once committed.
    fn old_file_table(&self) -> Arc<FileTable>;

    /// Accept the `/proc` VMA generation the driver staged for the
    /// replacement MM. A failure kills the process.
    fn acknowledge_staged_vma_revision(&mut self) -> Result<(), String>;
}

impl PreparedRootExec for crate::kernel::PreparedExec {
    fn replacement_mm_id(&self) -> MmId {
        Self::replacement_mm_id(self)
    }

    fn old_file_table(&self) -> Arc<FileTable> {
        Self::old_file_table(self)
    }

    fn acknowledge_staged_vma_revision(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// The hooks that run inside the venue's MM transaction, between the
/// no-return arm and MM publication.
pub trait ImageReplacement<V: RootExecVenue + ?Sized> {
    /// Cross the point of no return: from here, failure kills the process.
    fn arm_no_return(
        &mut self,
        prepared: V::Prepared,
        dispatch_mm: Option<&PreparedDispatchMmExec>,
    ) -> ExecStep<V::Armed, V::Outcome>;

    /// Destroy the old image and install the new one.
    fn install_image(&mut self, armed: V::Armed) -> ExecStep<V::Installed, V::Outcome>;

    /// Publish the replacement MM to the Kernel graph.
    fn publish_mm(&mut self, installed: V::Installed) -> ExecStep<V::Replaced, V::Outcome>;
}

/// The per-ISA, per-host half of a root exec. The driver owns the order; a
/// venue owns its registers, page tables, MM leases and thread state.
pub trait RootExecVenue {
    /// The terminal outcome a kill past the point of no return produces.
    type Outcome;
    type Prepared: PreparedRootExec;
    /// Pre-replacement custody (frame-inventory reservations) the driver
    /// holds until the transaction ends. Dropped before `Prepared` rolls back.
    type Envelope;
    type Armed;
    type Installed;
    type Replaced;
    type Committed;
    /// The successor MM as this execution lane loaded it.
    type Resident;
    /// The successor's entry state.
    type Entry;

    fn dispatcher(&self) -> &SyscallDispatcher;

    /// The loaded replacement image.
    fn image(&self) -> &AddressSpace;

    /// The caller's exact pre-commit context.
    fn exec_context(&self) -> &KernelContext;

    /// Whether this exec may rename the host process.
    fn renames_host_process(&self) -> bool;

    fn record_stage(&self, phase: HvpatchExecRuntimeStagePhase, started: Instant);

    /// Kill the process after the point of no return with `verdict`.
    fn fail_past_no_return(
        &mut self,
        verdict: ExecPastNoReturn,
        cause: &str,
    ) -> ExecExit<Self::Outcome>;

    /// `Drained` -> `Prepared`: prepare the Kernel exec and reserve the
    /// replacement MM's custody.
    fn prepare_mm(&mut self) -> ExecStep<(Self::Prepared, Self::Envelope), Self::Outcome>;

    /// Hold the venue's MM transaction across `replace`, then settle the
    /// replaced image's frame custody after releasing it.
    fn replace_image<R>(
        &mut self,
        prepared: Self::Prepared,
        topology_lock_started: Instant,
        replace: impl FnOnce(
            &mut dyn ImageReplacement<Self>,
            Self::Prepared,
        ) -> ExecStep<R, Self::Outcome>,
    ) -> ExecStep<R, Self::Outcome>;

    /// `Replaced` -> `Committed`: commit the Kernel successor (credentials,
    /// task graph) and the staged `/proc` generation in `dispatch_mm`.
    fn commit(
        &mut self,
        replaced: Self::Replaced,
        dispatch_mm: &mut Option<PreparedDispatchMmExec>,
    ) -> ExecStep<(KernelContext, Self::Committed), Self::Outcome>;

    /// Make the committed successor the terminal context: every later
    /// failure carries it.
    fn adopt_successor_context(
        &mut self,
        committed_context: &KernelContext,
    ) -> ExecStep<(), Self::Outcome>;

    /// Make the replacement MM resident on this execution lane.
    fn load_successor_mm(
        &mut self,
        committed_context: &KernelContext,
        committed: &mut Self::Committed,
    ) -> ExecStep<Self::Resident, Self::Outcome>;

    /// Capture the successor's entry register frame over its resident MM.
    fn entry_state(
        &mut self,
        committed_context: &KernelContext,
        resident: Self::Resident,
    ) -> ExecStep<Self::Entry, Self::Outcome>;

    /// Rebind fault-time memory authority (COW, anonymous backing, table
    /// arenas, frame inventory) to the successor MM.
    fn bind_successor_memory(
        &mut self,
        committed_context: &KernelContext,
    ) -> ExecStep<(), Self::Outcome>;

    /// Rebind the venue's thread identity to the successor generation.
    fn rebind_identity(&mut self, committed_context: &KernelContext);

    /// Optional check that the published image is the prepared one.
    fn verify_image(&mut self) -> ExecStep<(), Self::Outcome>;

    /// Publish the successor's identity to the vCPU port (identity page,
    /// vvar, guest thread id) and its fatal-signal image generation.
    fn stamp_port(&mut self, committed_context: &KernelContext) -> ExecStep<(), Self::Outcome>;

    /// Publish the runnable successor and hand its replacement custody to the
    /// executor.
    fn publish_replacement(
        &mut self,
        committed_context: &KernelContext,
        committed: Self::Committed,
        entry: Self::Entry,
    ) -> ExecStep<(), Self::Outcome>;
}

/// Run one root exec from `Drained` to a published successor. `Ok(None)` is a
/// replaced image; `Ok(Some(_))` is a process killed past the point of no
/// return. Callers box-pin this future.
pub async fn drive_root_exec<V: RootExecVenue>(
    venue: &mut V,
    drained: Drained,
    identity: ExecImageIdentity,
) -> Result<Option<V::Outcome>, RuntimeError> {
    match run(venue, drained, identity) {
        Ok(()) => Ok(None),
        Err(exit) => exit.into_result(),
    }
}

fn run<V: RootExecVenue>(
    venue: &mut V,
    drained: Drained,
    identity: ExecImageIdentity,
) -> ExecStep<(), V::Outcome> {
    venue.record_stage(HvpatchExecRuntimeStagePhase::SiblingDrain, drained.started);
    // Kernel preparation follows the sibling drain but precedes every
    // destructive image, CLOEXEC and proc-state mutation. Dropping
    // `_envelope` abandons the reserved frame custody before dropping
    // `prepared` rolls the Kernel preparation back.
    let (mut prepared, _envelope) = venue.prepare_mm()?;
    let replacement_mm_id = prepared.replacement_mm_id();
    let proc_state_started = Instant::now();
    let ExecImageIdentity {
        path,
        argv,
        env,
        source,
        binfmt_argv,
        command_line,
    } = identity;
    if venue.renames_host_process() {
        crate::dispatch::set_host_process_name(command_line.as_bytes());
    }
    venue
        .dispatcher()
        .set_executable_identity_with_source(path, argv, env, source);
    if let Some(argv) = binfmt_argv {
        venue.dispatcher().enter_binfmt(&argv);
    }
    venue
        .dispatcher()
        .reset_signal_handlers_on_execve(venue.exec_context());
    // Reset + refresh /proc/self/maps and /proc/self/auxv under one
    // dispatcher memory-authority generation. The historical MM retains the
    // pre-staging snapshot, but records this deliberate source revision so
    // commit can reject any later mutation.
    let mut dispatch_mm = Some(apply_exec_image_proc_state(
        venue.dispatcher(),
        replacement_mm_id,
        venue.image(),
    ));
    if let Err(error) = prepared.acknowledge_staged_vma_revision() {
        return Err(venue.fail_past_no_return(
            ExecPastNoReturn,
            &format!("acknowledge staged exec VMA revision: {error}"),
        ));
    }
    venue.record_stage(HvpatchExecRuntimeStagePhase::ProcState, proc_state_started);

    let old_files = prepared.old_file_table();
    let topology_lock_started = Instant::now();
    let (replaced, engine_replace_started) =
        venue.replace_image(prepared, topology_lock_started, |transaction, prepared| {
            let engine_replace_started = Instant::now();
            let armed = transaction.arm_no_return(prepared, dispatch_mm.as_ref())?;
            let installed = transaction.install_image(armed)?;
            let replaced = transaction.publish_mm(installed)?;
            Ok((replaced, engine_replace_started))
        })?;
    let (committed_context, mut committed) = venue.commit(replaced, &mut dispatch_mm)?;
    venue.adopt_successor_context(&committed_context)?;
    // Linux detaches every SysV shared-memory mapping only after exec has
    // crossed its no-return boundary. Preparation failures above preserve
    // the old image and its attachment set; a committed replacement owns
    // neither the old VMAs nor their `shm_nattch` charges.
    venue
        .dispatcher()
        .cleanup_sysv_shm_attachments_on_process_exit();
    let resident = venue.load_successor_mm(&committed_context, &mut committed)?;
    let entry = venue.entry_state(&committed_context, resident)?;
    venue.bind_successor_memory(&committed_context)?;
    venue.record_stage(
        HvpatchExecRuntimeStagePhase::EngineReplace,
        engine_replace_started,
    );
    let close_cloexec_started = Instant::now();
    venue.dispatcher().close_draining_file_table(
        committed_context.kernel(),
        &old_files,
        Some(committed_context.task().key()),
        Some(&committed_context.resources().files()),
    );
    venue.record_stage(
        HvpatchExecRuntimeStagePhase::CloseCloexec,
        close_cloexec_started,
    );
    venue.rebind_identity(&committed_context);
    let publication_started = Instant::now();
    venue.verify_image()?;
    crate::namespace::pid::mark_self_execed_for(&committed_context);
    venue.stamp_port(&committed_context)?;
    venue.record_stage(
        HvpatchExecRuntimeStagePhase::Publication,
        publication_started,
    );
    venue.publish_replacement(&committed_context, committed, entry)?;
    crate::exec_helpers::stop_after_traced_exec(venue.dispatcher());
    Ok(())
}

/// Publish a successful exec image as one dispatcher VMA generation.
pub fn apply_exec_image_proc_state(
    dispatcher: &SyscallDispatcher,
    replacement_mm_id: MmId,
    image: &AddressSpace,
) -> PreparedDispatchMmExec {
    dispatcher.publish_exec_image_state(
        replacement_mm_id,
        proc_maps_from_address_space(image),
        image.linux_auxv_image().to_vec(),
        core_file_mappings_from_address_space(image),
        crate::dispatch::boot_private_file_backings(image),
    )
}

pub fn core_file_mappings_from_address_space(
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

pub fn proc_maps_from_address_space(image: &AddressSpace) -> Vec<ProcMapsEntry> {
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
mod tests;
