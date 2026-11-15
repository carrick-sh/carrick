//! The root exec transaction: one ISA-neutral order for replacing a process
//! image, generic over the venue that owns the vCPU and its memory (#2142).
//!
//! The transaction runs in four phases, each a free function over a
//! [`RootExecVenue`]:
//!
//! - [`begin`]: `Drained` -> [`ExecBegun`], the Kernel preparation and the
//!   venue's reserved replacement custody;
//! - [`stage`]: [`ExecBegun`] -> [`ExecStaged`], the executable identity and
//!   binfmt argv, the signal reset ([`SignalReset`]) and the
//!   `/proc/self/{maps,auxv}` generation;
//! - [`arm`]: [`ExecStaged`] -> [`ExecArmed`], the venue's MM transaction
//!   across the no-return arm, the image install and MM publication;
//! - [`settle`]: [`ExecArmed`] -> published, the credential and task-graph
//!   commit, SysV shm detach, close-on-exec, the `/proc/self/exe` exec mark
//!   and the ptrace exec stop.
//!
//! [`drive_root_exec`] composes all four in one call (HVF). The phase values
//! are generic over the venue's associated types, so a venue whose types own
//! their custody can hold an [`ExecArmed`] between two crossings (x86: from
//! the adopt crossing to the settle crossing) while HVF keeps borrowing its
//! frame-inventory envelope. Everything that touches a register frame, a
//! page-table format, a stage-2 or ring MM, or venue-held thread state is a
//! [`RootExecVenue`] hook. The credential commit happens inside the venue's
//! [`RootExecVenue::commit`], through
//! [`crate::kernel::Kernel::commit_exec_transition`].
//!
//! The order here is the HVF/HVPatch order it was moved from
//! (`carrick-runtime` `drive_execve`), unchanged: the signal reset and the
//! `/proc` generation precede the MM transaction.
//!
//! Once [`begin`] starts, the process either becomes the successor or dies
//! past the point of no return: no phase returns an errno to the caller
//! ([`ExecTerminal`]). Every recoverable exec errno (ENOENT, ENOEXEC, EACCES
//! and E2BIG from the loader, ENOMEM from a carrier's stock) is decided
//! before a venue enters [`begin`]. Dropping a phase value on the terminal
//! path releases resources (the exec reservation, the drained siblings, the
//! staged MM authority) and restores nothing of the predecessor: the
//! identity, binfmt, signal reset and `/proc` generation that [`stage`]
//! wrote stay written.
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

/// A phase's stop: `Ok(_)` is the process killed past the point of no
/// return with the venue's outcome, `Err` a runtime fault. There is no
/// errno: a stopped phase never leaves the caller running.
pub struct ExecTerminal<O>(Result<O, RuntimeError>);

impl<O> ExecTerminal<O> {
    pub const fn new(result: Result<O, RuntimeError>) -> Self {
        Self(result)
    }

    pub fn into_result(self) -> Result<O, RuntimeError> {
        self.0
    }
}

impl<O> From<RuntimeError> for ExecTerminal<O> {
    fn from(error: RuntimeError) -> Self {
        Self(Err(error))
    }
}

/// One phase step: continue with `T`, or stop the process.
pub type ExecStep<T, O> = Result<T, ExecTerminal<O>>;

/// Who resets the caller's signal state for the successor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalReset {
    /// The venue reset it during [`stage`].
    Done,
    /// The ring resets it in its own exec commit, after [`arm`] returns. The
    /// obligation rides in [`ExecArmed`] until a ring commit receipt
    /// discharges it; [`settle`] refuses an undischarged one.
    RingOwed,
}

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
    /// Cross the venue's no-return cut: from here the predecessor image is
    /// gone, not merely unreachable.
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
    ) -> ExecTerminal<Self::Outcome>;

    /// Reset the caller's per-thread signal state for the successor, or say
    /// that the ring owes that reset.
    fn reset_exec_signals(&mut self) -> SignalReset;

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

/// [`begin`]'s value: the Kernel preparation and the venue's reserved
/// replacement custody.
#[must_use = "dropping a begun exec releases its reservations and frame custody (a `PreparedExec` also resumes the drained siblings) and kills nothing; the caller owes the terminal path"]
pub struct ExecBegun<P, Envelope> {
    // Field order is drop order: the envelope abandons the reserved frame
    // custody before the Kernel preparation rolls back.
    envelope: Envelope,
    prepared: P,
}

impl<P: PreparedRootExec, Envelope> ExecBegun<P, Envelope> {
    pub fn replacement_mm_id(&self) -> MmId {
        self.prepared.replacement_mm_id()
    }
}

/// [`stage`]'s value: the begun exec with the successor's identity, signal
/// reset and `/proc` generation written.
#[must_use = "dropping a staged exec releases its reservations and frame custody (a `PreparedExec` also resumes the drained siblings) and kills nothing; the caller owes the terminal path"]
pub struct ExecStaged<P, Envelope> {
    dispatch_mm: PreparedDispatchMmExec,
    signal_reset: SignalReset,
    envelope: Envelope,
    prepared: P,
}

/// [`arm`]'s value: the successor image installed and its MM published,
/// awaiting [`settle`]. When the venue's `Replaced` and `Envelope` own their
/// custody, this owns the whole continuation.
#[must_use = "dropping an armed exec releases its replacement custody and kills nothing; the caller owes the terminal path"]
pub struct ExecArmed<Replaced, Envelope> {
    old_files: Arc<FileTable>,
    dispatch_mm: PreparedDispatchMmExec,
    signal_reset: SignalReset,
    engine_replace_started: Instant,
    replaced: Replaced,
    envelope: Envelope,
}

impl<Replaced, Envelope> ExecArmed<Replaced, Envelope> {
    pub const fn signal_reset(&self) -> SignalReset {
        self.signal_reset
    }
}

/// Run one root exec from `Drained` to a published successor, all four
/// phases in one call. `Ok(None)` is a replaced image; `Ok(Some(_))` is a
/// process killed past the point of no return. Callers box-pin this future.
pub async fn drive_root_exec<V: RootExecVenue>(
    venue: &mut V,
    drained: Drained,
    identity: ExecImageIdentity,
) -> Result<Option<V::Outcome>, RuntimeError> {
    match run(venue, drained, identity) {
        Ok(()) => Ok(None),
        Err(terminal) => terminal.into_result().map(Some),
    }
}

fn run<V: RootExecVenue>(
    venue: &mut V,
    drained: Drained,
    identity: ExecImageIdentity,
) -> ExecStep<(), V::Outcome> {
    let begun = begin(venue, drained)?;
    let staged = stage(venue, begun, identity)?;
    let armed = arm(venue, staged)?;
    settle(venue, armed)
}

/// `Drained` -> [`ExecBegun`]: prepare the Kernel exec and reserve the
/// replacement MM's custody. Kernel preparation follows the sibling drain
/// but precedes every destructive image, CLOEXEC and proc-state mutation.
pub fn begin<V: RootExecVenue>(
    venue: &mut V,
    drained: Drained,
) -> ExecStep<ExecBegun<V::Prepared, V::Envelope>, V::Outcome> {
    venue.record_stage(HvpatchExecRuntimeStagePhase::SiblingDrain, drained.started);
    let (prepared, envelope) = venue.prepare_mm()?;
    Ok(ExecBegun { envelope, prepared })
}

/// [`ExecBegun`] -> [`ExecStaged`]: publish the successor's identity and
/// binfmt argv, reset its signal state, and stage its `/proc` generation.
pub fn stage<V: RootExecVenue>(
    venue: &mut V,
    begun: ExecBegun<V::Prepared, V::Envelope>,
    identity: ExecImageIdentity,
) -> ExecStep<ExecStaged<V::Prepared, V::Envelope>, V::Outcome> {
    // Held whole, so a stop below drops it in field order.
    let mut begun = begun;
    let replacement_mm_id = begun.replacement_mm_id();
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
    let signal_reset = venue.reset_exec_signals();
    // Reset + refresh /proc/self/maps and /proc/self/auxv under one
    // dispatcher memory-authority generation. The historical MM retains the
    // pre-staging snapshot, but records this deliberate source revision so
    // commit can reject any later mutation.
    let dispatch_mm =
        apply_exec_image_proc_state(venue.dispatcher(), replacement_mm_id, venue.image());
    if let Err(error) = begun.prepared.acknowledge_staged_vma_revision() {
        return Err(venue.fail_past_no_return(
            ExecPastNoReturn,
            &format!("acknowledge staged exec VMA revision: {error}"),
        ));
    }
    venue.record_stage(HvpatchExecRuntimeStagePhase::ProcState, proc_state_started);
    Ok(ExecStaged {
        dispatch_mm,
        signal_reset,
        envelope: begun.envelope,
        prepared: begun.prepared,
    })
}

/// [`ExecStaged`] -> [`ExecArmed`]: inside the venue's MM transaction, cross
/// the no-return arm, install the successor image and publish its MM.
pub fn arm<V: RootExecVenue>(
    venue: &mut V,
    staged: ExecStaged<V::Prepared, V::Envelope>,
) -> ExecStep<ExecArmed<V::Replaced, V::Envelope>, V::Outcome> {
    let ExecStaged {
        envelope,
        dispatch_mm,
        signal_reset,
        prepared,
    } = staged;
    let old_files = prepared.old_file_table();
    let topology_lock_started = Instant::now();
    let (replaced, engine_replace_started) =
        venue.replace_image(prepared, topology_lock_started, |transaction, prepared| {
            let engine_replace_started = Instant::now();
            let armed = transaction.arm_no_return(prepared, Some(&dispatch_mm))?;
            let installed = transaction.install_image(armed)?;
            let replaced = transaction.publish_mm(installed)?;
            Ok((replaced, engine_replace_started))
        })?;
    Ok(ExecArmed {
        old_files,
        dispatch_mm,
        signal_reset,
        engine_replace_started,
        replaced,
        envelope,
    })
}

/// [`ExecArmed`] -> published: commit the Kernel successor, close the old
/// image's descriptors, and publish the runnable successor.
pub fn settle<V: RootExecVenue>(
    venue: &mut V,
    armed: ExecArmed<V::Replaced, V::Envelope>,
) -> ExecStep<(), V::Outcome> {
    let ExecArmed {
        envelope: _envelope,
        replaced,
        engine_replace_started,
        signal_reset,
        dispatch_mm,
        old_files,
    } = armed;
    if signal_reset == SignalReset::RingOwed {
        // Only a ring commit receipt discharges a ring-owed reset (#2142
        // R3). Without one, the successor would run with the predecessor's
        // caught handlers.
        return Err(venue.fail_past_no_return(
            ExecPastNoReturn,
            "exec settle without a ring commit receipt for the owed signal reset",
        ));
    }
    let mut dispatch_mm = Some(dispatch_mm);
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
