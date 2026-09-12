//! PROC concern: execve of the vCPU run loop.
//!
//! Split out of `vcpu_loop/mod.rs` (Task A2). Pure relocation — no logic
//! changes; only `mod`/`use`/visibility wiring differs.

use super::*;

use carrick_fatal::carrick_fatal;

#[expect(
    clippy::large_enum_variant,
    reason = "guest completion stays inline so the ordinary trapped-syscall path does not allocate"
)]
pub(crate) enum SyscallCompletionOwnership {
    Idle,
    Guest(SyscallCompletionToken),
    InternalControlExec,
}

/// Non-copyable completion authority transferred into a pending exec phase.
///
/// Once this owner exists, `ThreadRuntimeState::syscall_completion` is Idle.
/// Dropping a pending phase therefore retires a guest exec without fabricating
/// a return, and cannot strand live completion authority in shared runtime
/// state. Extracting guest ownership consumes and destroys the completion
/// token without publication, then carries this non-copyable provenance marker
/// across the pending exec phase.
pub(crate) enum PendingExecCompletionOwnership {
    Guest,
    InternalControlExec,
}

// Keep the explicit consumption points in the exec state machine meaningful:
// this linear marker is retired where the formerly boxed token was retired,
// even though guest-token destruction now happens before the pending phase.
impl Drop for PendingExecCompletionOwnership {
    fn drop(&mut self) {}
}

impl SyscallCompletionOwnership {
    pub(crate) const fn is_idle(&self) -> bool {
        matches!(self, Self::Idle)
    }

    pub(crate) fn guest(
        &self,
        missing: &'static str,
    ) -> Result<&SyscallCompletionToken, RuntimeError> {
        match self {
            Self::Guest(completion) => Ok(completion),
            Self::Idle | Self::InternalControlExec => {
                Err(RuntimeError::Configuration(missing.to_owned()))
            }
        }
    }
}

pub(crate) struct PendingExecTerminal {
    pub(crate) context: crate::kernel::KernelContext,
    pub(crate) handoff: ExecTerminalHandoff,
}

pub(crate) struct PendingExecTerminalError {
    pub(crate) error: RuntimeError,
    pub(crate) pending: PendingExecTerminal,
}

pub(crate) enum ProductionHvpatchPollError {
    Runtime(RuntimeError),
    Exec(Box<PendingExecTerminalError>),
}

impl ProductionHvpatchPollError {
    pub(super) fn from_exec_failure(failure: ExecTerminalFailure) -> Self {
        Self::Exec(failure.into_pending())
    }

    pub(crate) fn from_exec_error(
        error: RuntimeError,
        context: crate::kernel::KernelContext,
        handoff: ExecTerminalHandoff,
    ) -> Self {
        Self::Exec(Box::new(PendingExecTerminalError {
            error,
            pending: PendingExecTerminal { context, handoff },
        }))
    }

    #[cfg(test)]
    pub(crate) fn into_runtime_error(self) -> RuntimeError {
        match self {
            Self::Runtime(error) => error,
            Self::Exec(pending) => pending.error,
        }
    }
}

impl From<RuntimeError> for ProductionHvpatchPollError {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<TrapError> for ProductionHvpatchPollError {
    fn from(error: TrapError) -> Self {
        Self::Runtime(RuntimeError::Trap(error))
    }
}

impl std::fmt::Debug for ProductionHvpatchPollError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Runtime(error) => formatter.debug_tuple("Runtime").field(error).finish(),
            Self::Exec(pending) => formatter.debug_tuple("Exec").field(&pending.error).finish(),
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExecCompletionOrigin {
    GuestSyscall,
    InternalControl,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedExecCompletionOrigin(pub(crate) ExecCompletionOrigin);

impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>
where
    E::SiblingSpec: 'static,
{
    pub(crate) fn begin_internal_control_exec(&mut self) -> Result<(), RuntimeError> {
        if !self.syscall_completion.is_idle() {
            return Err(RuntimeError::Configuration(
                "internal control exec collided with live syscall ownership".to_owned(),
            ));
        }
        self.syscall_completion = SyscallCompletionOwnership::InternalControlExec;
        Ok(())
    }

    pub(crate) fn authenticate_exec_completion_origin(
        &self,
        origin: ExecCompletionOrigin,
    ) -> Result<AuthenticatedExecCompletionOrigin, RuntimeError> {
        match (&self.syscall_completion, origin) {
            (SyscallCompletionOwnership::Guest(_), ExecCompletionOrigin::GuestSyscall)
            | (
                SyscallCompletionOwnership::InternalControlExec,
                ExecCompletionOrigin::InternalControl,
            ) => Ok(AuthenticatedExecCompletionOrigin(origin)),
            (SyscallCompletionOwnership::Idle, ExecCompletionOrigin::GuestSyscall) => Err(
                RuntimeError::Configuration("guest exec missing completion token".to_owned()),
            ),
            (SyscallCompletionOwnership::Idle, ExecCompletionOrigin::InternalControl) => {
                Err(RuntimeError::Configuration(
                    "internal control exec missing typed ownership".to_owned(),
                ))
            }
            (SyscallCompletionOwnership::Guest(_), ExecCompletionOrigin::InternalControl)
            | (
                SyscallCompletionOwnership::InternalControlExec,
                ExecCompletionOrigin::GuestSyscall,
            ) => Err(RuntimeError::Configuration(
                "exec completion origin mismatched live typed ownership".to_owned(),
            )),
        }
    }

    #[cfg(test)]
    pub(crate) fn finish_authenticated_exec_completion(
        &mut self,
        origin: AuthenticatedExecCompletionOrigin,
    ) -> Result<(), RuntimeError> {
        match origin.0 {
            ExecCompletionOrigin::GuestSyscall => self.retire_syscall(),
            ExecCompletionOrigin::InternalControl => self.finish_internal_control_exec(),
        }
    }

    pub(crate) fn take_authenticated_exec_completion_ownership(
        &mut self,
        origin: AuthenticatedExecCompletionOrigin,
    ) -> Result<PendingExecCompletionOwnership, RuntimeError> {
        let ownership = std::mem::replace(
            &mut self.syscall_completion,
            SyscallCompletionOwnership::Idle,
        );
        match (origin.0, ownership) {
            (ExecCompletionOrigin::GuestSyscall, SyscallCompletionOwnership::Guest(completion)) => {
                drop(completion);
                Ok(PendingExecCompletionOwnership::Guest)
            }
            (
                ExecCompletionOrigin::InternalControl,
                SyscallCompletionOwnership::InternalControlExec,
            ) => Ok(PendingExecCompletionOwnership::InternalControlExec),
            (ExecCompletionOrigin::GuestSyscall, other) => {
                self.syscall_completion = other;
                Err(RuntimeError::Configuration(
                    "threaded syscall retired without guest completion ownership".to_owned(),
                ))
            }
            (ExecCompletionOrigin::InternalControl, other) => {
                self.syscall_completion = other;
                Err(RuntimeError::Configuration(
                    "internal control exec lost typed ownership".to_owned(),
                ))
            }
        }
    }

    pub(crate) fn finish_internal_control_exec(&mut self) -> Result<(), RuntimeError> {
        match std::mem::replace(
            &mut self.syscall_completion,
            SyscallCompletionOwnership::Idle,
        ) {
            SyscallCompletionOwnership::InternalControlExec => Ok(()),
            other => {
                self.syscall_completion = other;
                Err(RuntimeError::Configuration(
                    "internal control exec lost typed ownership".to_owned(),
                ))
            }
        }
    }
}

fn first_byte_mismatch(expected: &[u8], observed: &[u8]) -> Option<usize> {
    expected
        .iter()
        .zip(observed)
        .position(|(expected, observed)| expected != observed)
        .or_else(|| (expected.len() != observed.len()).then(|| expected.len().min(observed.len())))
}

fn word_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fn exec_regions_to_verify_with_mappings<'a>(
    image: &'a AddressSpace,
    file_mappings: &'a [crate::memory::AddressSpaceFileMapping],
) -> impl Iterator<Item = &'a crate::memory::MemoryRegion> {
    image.regions().iter().filter(move |region| {
        region.perms.execute
            || file_mappings
                .iter()
                .any(|mapping| mapping.start < region.end && mapping.end > region.start)
    })
}

fn exec_regions_to_verify(
    image: &AddressSpace,
) -> impl Iterator<Item = &crate::memory::MemoryRegion> {
    exec_regions_to_verify_with_mappings(image, image.file_mappings())
}

/// Route the exec's two independent commits to their own `MmId`s.
///
/// `retired` is `None` when a live sharer still owns the old mm (a vfork /
/// `CLONE_VM` child's execve): the exec retires nothing from it, so there is no
/// retirement transaction to apply. Its reservation is released by the caller's
/// `InventoryAbandon` guard. An absent retirement is not the same as an empty
/// one — the authority rejects a zero-event commit outright.
#[cfg_attr(not(test), allow(dead_code))]
fn apply_exec_inventory<E>(
    old_mm: crate::kernel::MmId,
    replacement_mm: crate::kernel::MmId,
    retired: Option<carrick_hal::FrameInventoryCommit<()>>,
    replacement: carrick_hal::FrameInventoryCommit<()>,
    mut apply: impl FnMut(crate::kernel::MmId, carrick_hal::FrameInventoryCommit<()>) -> Result<(), E>,
) -> Result<(), E> {
    if let Some(retired) = retired {
        apply(old_mm, retired)?;
    }
    apply(replacement_mm, replacement)
}

#[derive(Default)]
struct ExecBackendPublicationGate {
    engine_replaced: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecDispositionRouting {
    predecessor_shared: bool,
    retirement_inventory: bool,
}

fn route_exec_disposition(
    disposition: crate::hvpatch::ExecMmDispositionKind,
) -> ExecDispositionRouting {
    match disposition {
        crate::hvpatch::ExecMmDispositionKind::RetainOldMm => ExecDispositionRouting {
            predecessor_shared: true,
            retirement_inventory: false,
        },
        crate::hvpatch::ExecMmDispositionKind::RetireOldMm => ExecDispositionRouting {
            predecessor_shared: false,
            retirement_inventory: true,
        },
    }
}

impl ExecBackendPublicationGate {
    fn record_engine_replaced(&mut self) {
        self.engine_replaced = true;
    }

    fn take_after_replace<T>(&self, take: impl FnOnce() -> Option<T>) -> Option<T> {
        self.engine_replaced.then(take).flatten()
    }
}

enum RuntimePreparedExec {
    Hvpatch(Box<crate::hvpatch::PreparedProcessExec>),
    Other(Box<crate::kernel::PreparedExec>),
}

enum RuntimePublishedExec {
    Hvpatch(crate::hvpatch::PublishedProcessExec),
    Other(crate::kernel::PreparedExec),
}

pub(super) struct PreparedExecve {
    origin: Option<super::AuthenticatedExecCompletionOrigin>,
    image: AddressSpace,
    path: String,
    proc_argv: Vec<String>,
    proc_env: Vec<Vec<u8>>,
    command_line: String,
    inventory_failure_injection: Option<HvpatchExecInventoryFailureInjection>,
    hvpatch_mm_reservation: Option<crate::hvpatch::ExecMmReservation>,
    /// Exact terminal context paired with `clone_admission`. The pair moves
    /// together until the destructive suffix either commits a Kernel successor
    /// or reaches the exec-specific terminal entry.
    terminal_context: Option<crate::kernel::KernelContext>,
    clone_admission: Option<ExecCloneAdmission>,
    runtime_region_count: u64,
    runtime_mapped_bytes: u64,
    sibling_drain_started: std::time::Instant,
}

impl PreparedExecve {
    fn take_terminal_authority(
        &mut self,
    ) -> (crate::kernel::KernelContext, super::ExecTerminalHandoff) {
        let context = self.terminal_context.take().unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::exec_terminal",
                "prepared exec terminal context was consumed before paired clone-admission handoff"
            );
        });
        let clone_admission = self.clone_admission.take().unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::exec_terminal",
                "prepared exec clone-admission token was consumed before paired terminal context"
            );
        });
        (context, super::ExecTerminalHandoff { clone_admission })
    }

    fn into_terminal_authority(
        mut self,
    ) -> (crate::kernel::KernelContext, super::ExecTerminalHandoff) {
        self.take_terminal_authority()
    }

    fn take_origin(&mut self) -> Result<super::AuthenticatedExecCompletionOrigin, RuntimeError> {
        self.origin.take().ok_or_else(|| {
            RuntimeError::Configuration(
                "prepared exec authenticated completion origin consumed twice".to_owned(),
            )
        })
    }
}

/// A post-close failure paired with the exact, non-reconstructible admission
/// token that must become terminal ownership before the original error can be
/// published.
pub(super) struct ExecTerminalFailure(Box<PendingExecTerminalError>);

impl ExecTerminalFailure {
    fn from_prepared(error: RuntimeError, prepared: PreparedExecve) -> Self {
        let (context, handoff) = prepared.into_terminal_authority();
        Self(Box::new(PendingExecTerminalError {
            error,
            pending: PendingExecTerminal { context, handoff },
        }))
    }

    fn from_admission(
        error: RuntimeError,
        context: crate::kernel::KernelContext,
        clone_admission: ExecCloneAdmission,
    ) -> Self {
        Self(Box::new(PendingExecTerminalError {
            error,
            pending: PendingExecTerminal {
                context,
                handoff: ExecTerminalHandoff { clone_admission },
            },
        }))
    }

    pub(super) fn into_pending(self) -> Box<PendingExecTerminalError> {
        self.0
    }
}

impl std::fmt::Debug for ExecTerminalFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecTerminalFailure")
            .field("error", &self.0.error)
            .finish_non_exhaustive()
    }
}

/// A completed destructive suffix still retains exec admission until its
/// caller has either published the replacement or routed a terminal outcome.
pub(super) struct FinishedPreparedExecve {
    outcome: Option<VcpuLoopOutcome>,
    context: crate::kernel::KernelContext,
    handoff: super::ExecTerminalHandoff,
}

impl FinishedPreparedExecve {
    pub(super) fn into_parts(
        self,
    ) -> (
        Option<VcpuLoopOutcome>,
        crate::kernel::KernelContext,
        super::ExecTerminalHandoff,
    ) {
        (self.outcome, self.context, self.handoff)
    }
}

/// The single non-copyable owner retained from sibling-drain admission through
/// delayed drain completion and the destructive exec suffix.  Keeping the
/// prepared image and transferred completion authority inside this envelope
/// makes phase replacement, terminal drain/suffix errors, and unwind retire
/// without publishing a fabricated guest return.
pub(super) struct PreparedExecveDrain {
    prepared: PreparedExecve,
    drain: super::continuation::ProcessDrain,
    completion_ownership: super::PendingExecCompletionOwnership,
}

impl PreparedExecveDrain {
    pub(super) fn is_ready(&self) -> bool {
        self.drain.is_ready()
    }

    pub(super) fn into_terminal_authority(
        self,
    ) -> (crate::kernel::KernelContext, super::ExecTerminalHandoff) {
        let Self {
            prepared,
            drain,
            completion_ownership,
        } = self;
        drop(drain);
        drop(completion_ownership);
        prepared.into_terminal_authority()
    }
}

fn close_clone_admission_then<T>(
    close: impl FnOnce() -> Result<ExecCloneAdmission, RuntimeError>,
    after_close: impl FnOnce() -> T,
) -> Result<(ExecCloneAdmission, T), RuntimeError> {
    let admission = close()?;
    Ok((admission, after_close()))
}

pub(super) enum ExecvePreparation {
    Complete(Option<VcpuLoopOutcome>),
    Prepared(Box<PreparedExecve>),
    TerminalFailure(ExecTerminalFailure),
}

impl RuntimePreparedExec {
    fn old_mm_id(&self) -> crate::kernel::MmId {
        match self {
            Self::Hvpatch(prepared) => prepared.old_mm_id(),
            Self::Other(prepared) => prepared.old_mm_id(),
        }
    }

    fn old_file_table(&self) -> std::sync::Arc<crate::kernel::FileTable> {
        match self {
            Self::Hvpatch(prepared) => prepared.old_file_table(),
            Self::Other(prepared) => prepared.old_file_table(),
        }
    }

    fn replacement_mm_id(&self) -> crate::kernel::MmId {
        match self {
            Self::Hvpatch(prepared) => prepared.replacement_mm_id(),
            Self::Other(prepared) => prepared.replacement_mm_id(),
        }
    }

    fn hvpatch_disposition(&self) -> Option<crate::hvpatch::ExecMmDispositionKind> {
        match self {
            Self::Hvpatch(prepared) => Some(prepared.disposition()),
            Self::Other(_) => None,
        }
    }

    fn acknowledge_staged_vma_revision(&mut self) -> Result<(), String> {
        match self {
            Self::Hvpatch(prepared) => prepared.acknowledge_staged_vma_revision(),
            Self::Other(_) => Ok(()),
        }
    }

    fn prepare_hvpatch_address_space<E: ThreadedEngine>(
        &self,
        engine: &mut E,
        executor: crate::kernel::objects::ExecutorId,
    ) -> Result<Option<crate::hvpatch::AsidLoad>, String> {
        let Self::Hvpatch(prepared) = self else {
            return Ok(None);
        };
        let root_slot = prepared
            .replacement_root_slot()
            .ok_or_else(|| "HVPatch exec replacement has no root slot".to_owned())?;
        let generation = prepared.replacement_asid_generation();
        let mut load = prepared.begin_replacement_load(executor)?;
        load.arm_hardware_dirty()
            .map_err(|error| error.to_string())?;
        engine
            .prepare_exec_address_space(root_slot.base(), root_slot.size(), generation.raw())
            .map_err(|error| error.to_string())?;
        Ok(Some(load))
    }
}

fn should_update_host_process_title(is_hvpatch: bool) -> bool {
    // HvPatch multiplexes many Linux processes inside one host process. A
    // per-guest exec cannot truthfully rename that shared process, and the
    // macOS helper also overwrites the executing host thread's stable
    // `guest-pid-*` name used by LLDB. Legacy one-process backends retain the
    // useful process-title update.
    !is_hvpatch
}

fn retire_execution_authority_for_exec(
    thread: &std::sync::Arc<crate::kernel::Thread>,
    lease_slot: &super::ExecutionLeaseCell,
) -> Result<(), crate::kernel::objects::ThreadExecutionError> {
    let lease = lease_slot.lock().take().ok_or_else(|| {
        crate::kernel::objects::ThreadExecutionError::InvalidTransition {
            operation: "retire_execution_authority_for_exec_without_lease",
            state: thread.execution_state(),
        }
    })?;
    thread
        .exit_from_executor(lease)
        .map_err(|(error, _lease)| error)
}

fn publish_execution_authority_after_exec(
    replacement: &std::sync::Arc<crate::kernel::Thread>,
    executor: crate::kernel::objects::ExecutorId,
    state: crate::kernel::objects::MigratableTaskState,
    lease_slot: &super::ExecutionLeaseCell,
) -> Result<(), crate::kernel::objects::ThreadExecutionError> {
    replacement.publish_initial_task_state(state)?;
    let lease = replacement.claim_runnable(executor)?;
    debug_assert!(lease_slot.lock().is_none());
    *lease_slot.lock() = Some(lease);
    Ok(())
}

/// Diagnostic-only deterministic failures for fallible operations that follow
/// HVPatch sibling teardown. A nonempty absolute `@PATH` suffix is mandatory,
/// so a container launcher can reach the probe before its selected child
/// crosses the failure point without arming unrelated execs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HvpatchExecInventoryFailureInjection {
    OldCapacity,
    ReplacementReservation,
    BeginInventory,
    IdentityPage,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ExecTerminalContextFailpoint {
    BeforeKernelCommit,
    TaskLoadPublication,
    SnapshotPublication,
    FrameCowBinding,
    InventoryActivation,
    IdentityPublication,
    VvarPublication,
}

fn parse_hvpatch_exec_inventory_failure_injection(
    configured: &str,
    path: &str,
) -> Option<HvpatchExecInventoryFailureInjection> {
    let (name, target) = configured.split_once('@')?;
    if target.is_empty() || !std::path::Path::new(target).is_absolute() || target != path {
        return None;
    }
    match name {
        "old-capacity" => Some(HvpatchExecInventoryFailureInjection::OldCapacity),
        "replacement-reservation" => {
            Some(HvpatchExecInventoryFailureInjection::ReplacementReservation)
        }
        "begin-inventory" => Some(HvpatchExecInventoryFailureInjection::BeginInventory),
        "identity-page" => Some(HvpatchExecInventoryFailureInjection::IdentityPage),
        _ => None,
    }
}

fn hvpatch_exec_inventory_failure_injection(
    path: &str,
) -> Option<HvpatchExecInventoryFailureInjection> {
    let configured = std::env::var("CARRICK_HVPATCH_EXEC_INVENTORY_FAILURE").ok()?;
    parse_hvpatch_exec_inventory_failure_injection(&configured, path)
}

/// Fail-closed, opt-in proof that the immutable program image Carrick prepared
/// for `execve` is the image its freshly rebuilt engine exposes before the vCPU
/// re-enters the guest. This deliberately reads through
/// `ThreadedEngine::read_bytes`, the same mapping-ledger path used by the
/// fatal-fault recorder. It therefore distinguishes an already-wrong exec
/// publication from corruption that only appears after another process reuses
/// the stage-2 bank. Mutable runtime regions (page tables, vvar, identity page,
/// and syscall mailboxes) are deliberately excluded; executable runtime code
/// and every ELF file-backed segment remain covered.
fn verify_published_exec_image<E: ThreadedEngine>(
    engine: &E,
    image: &AddressSpace,
    path: &str,
) -> Result<(), RuntimeError> {
    const CHUNK_SIZE: usize = 64 * 1024;

    for region in exec_regions_to_verify(image) {
        let expected = region.bytes();
        for offset in (0..expected.len()).step_by(CHUNK_SIZE) {
            let end = offset.saturating_add(CHUNK_SIZE).min(expected.len());
            let guest_address = region.start.checked_add(offset as u64).ok_or_else(|| {
                RuntimeError::Configuration(format!(
                    "hvpatch exec verifier address overflow for {path:?}"
                ))
            })?;
            let observed = engine.read_bytes(guest_address, end - offset).map_err(|error| {
                RuntimeError::Configuration(format!(
                    "hvpatch exec verifier could not read {path:?} at {guest_address:#x}: {error}"
                ))
            })?;
            if let Some(delta) = first_byte_mismatch(&expected[offset..end], &observed) {
                let mismatch_offset = offset + delta;
                let mismatch_address = region.start + mismatch_offset as u64;
                return Err(RuntimeError::Configuration(format!(
                    "hvpatch exec publication mismatch for {path:?} at VA {mismatch_address:#x}: expected_word={:?} observed_word={:?} region={:#x}..{:#x}",
                    word_at(expected, mismatch_offset),
                    word_at(&observed, delta),
                    region.start,
                    region.end,
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod exec_image_verification_tests {
    use super::{
        ExecBackendPublicationGate, ExecDispositionRouting, HvpatchExecInventoryFailureInjection,
        apply_exec_inventory, close_clone_admission_then, exec_regions_to_verify_with_mappings,
        first_byte_mismatch, parse_hvpatch_exec_inventory_failure_injection,
        publish_execution_authority_after_exec, retire_execution_authority_for_exec,
        route_exec_disposition, should_update_host_process_title,
    };

    fn cpu_state_for_exec_test(mm_generation: u64) -> carrick_hal::threaded::Aarch64TaskCpuStateV1 {
        carrick_hal::threaded::Aarch64TaskCpuStateV1 {
            gprs: [0; 31],
            pc: 0,
            pstate: 0,
            trap_pc: 0,
            trap_pstate: 0,
            sp_el0: 0,
            elr_el1: 0,
            spsr_el1: 0,
            ttbr0: 0,
            ttbr1: 0,
            tcr: 0,
            sctlr_el1: 0,
            mair_el1: 0,
            vbar_el1: 0,
            cpacr_el1: 0,
            cntkctl_el1: 0,
            tpidr_el1: 0,
            actlr_el1: 0,
            tpidr_el0: 0,
            tpidrro_el0: 0,
            contextidr_el1: 0,
            vregs: [0; 32],
            fpsr: 0,
            fpcr: 0,
            pending_resume_pc: None,
            last_syscall_nr: None,
            last_syscall_orig_x0: 0,
            last_fault_esr: 0,
            last_exit_class: 0,
            is_forked_child: false,
            syscall_continuation: None,
            mm_generation,
            asid_generation: mm_generation,
        }
    }

    #[test]
    fn persistent_exec_never_fabricates_a_transitional_executor() {
        let source = include_str!("exec.rs");
        let production = source
            .split(concat!("async fn drive_", "execve"))
            .nth(1)
            .and_then(|tail| {
                tail.split(concat!("pub(super) async fn handle_", "execve"))
                    .next()
            })
            .expect("production exec suffix");
        assert!(!production.contains(concat!("ExecutorId::for_transitional_", "thread")));
    }

    #[test]
    fn exec_mm_admission_runs_only_after_in_flight_process_fork_drains() {
        let gate = std::sync::Arc::new(super::super::CloneAdmissionGate::default());
        let owner = carrick_hal::ThreadId::synthetic_for_tests(19_100);
        let process_fork = gate
            .enroll_process_fork(owner)
            .admitted()
            .expect("process fork admission");
        let (after_close_tx, after_close_rx) = std::sync::mpsc::channel();

        std::thread::scope(|scope| {
            let close_gate = std::sync::Arc::clone(&gate);
            let exec = scope.spawn(move || {
                close_clone_admission_then(
                    || close_gate.close_for_exec(owner),
                    || after_close_tx.send(()).unwrap(),
                )
            });

            while !process_fork.is_cancelled() {
                std::thread::yield_now();
            }
            assert!(
                after_close_rx
                    .recv_timeout(std::time::Duration::from_millis(50))
                    .is_err(),
                "post-close MM admission ran while a process fork was still admitted",
            );

            drop(process_fork);
            after_close_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("post-close MM admission did not run after fork settlement");
            let (admission, ()) = exec
                .join()
                .expect("exec admission worker")
                .expect("clone-admission drain");
            drop(admission);
        });
    }

    #[test]
    fn reclaim_exec_reclaim_replaces_the_exact_kernel_execution_lease() {
        use std::sync::Arc;

        use carrick_hal::ThreadId;
        use carrick_hal::threaded::GuestCpuState;

        use crate::kernel::objects::{
            BlockedReason, ExecutorId, MigratableTaskState, ThreadExecutionState,
        };
        use crate::kernel::{Kernel, RootBootstrap};

        let input = RootBootstrap::for_reference_model(
            19_101,
            ThreadId::synthetic_for_tests(19_101),
            "reclaim exec reclaim".to_owned(),
        )
        .unwrap();
        let (kernel, context) = Kernel::bootstrap_root(input).unwrap();
        let old_thread = Arc::clone(context.thread());
        let executor =
            ExecutorId::for_transitional_thread(ThreadId::synthetic_for_tests(19_101)).unwrap();
        let old_mm = context.shared().mm().id();
        let cpu = GuestCpuState::from_aarch64_v1(cpu_state_for_exec_test(old_mm.raw()));
        let old_state = MigratableTaskState {
            cpu,
            mm: old_mm,
            asid_generation: old_mm.raw(),
        };
        old_thread
            .publish_initial_task_state(old_state.clone())
            .unwrap();
        let mut lease = old_thread.claim_runnable(executor).unwrap();
        lease.replace_task_state(old_state).unwrap();
        old_thread.begin_switch_out(&lease).unwrap();
        old_thread
            .park_from_executor(lease, BlockedReason::HostWait)
            .unwrap();
        let active = old_thread
            .claim_blocked_for_transitional_executor(executor)
            .unwrap();
        let lease_slot = crate::vcpu_loop::ExecutionLeaseCell::owned();
        *lease_slot.lock() = Some(active);

        retire_execution_authority_for_exec(&old_thread, &lease_slot).unwrap();
        let prepared = kernel.prepare_exec(&context, None).unwrap();
        let committed = kernel.commit_exec(prepared, None).unwrap();
        let replacement = Arc::clone(committed.thread());
        let replacement_mm = committed.shared().mm().id();
        let replacement_state = MigratableTaskState {
            cpu: GuestCpuState::from_aarch64_v1(cpu_state_for_exec_test(replacement_mm.raw())),
            mm: replacement_mm,
            asid_generation: replacement_mm.raw(),
        };
        publish_execution_authority_after_exec(
            &replacement,
            executor,
            replacement_state.clone(),
            &lease_slot,
        )
        .unwrap();

        let mut replacement_lease = lease_slot.lock().take().unwrap();
        replacement_lease
            .replace_task_state(replacement_state.clone())
            .unwrap();
        replacement.begin_switch_out(&replacement_lease).unwrap();
        replacement
            .park_from_executor(replacement_lease, BlockedReason::HostWait)
            .unwrap();
        let resumed = replacement
            .claim_blocked_for_transitional_executor(executor)
            .unwrap();
        assert_eq!(
            resumed
                .task_state_for_restore(
                    carrick_abi::LinuxGuestAbi::Aarch64,
                    1,
                    replacement_mm,
                    replacement_mm.raw(),
                )
                .unwrap(),
            &replacement_state
        );
        assert!(matches!(
            old_thread.execution_state(),
            ThreadExecutionState::Exited { .. }
        ));
        replacement.exit_from_executor(resumed).unwrap();
    }

    #[test]
    fn predecessor_authority_is_validated_before_destructive_exec_replacement() {
        let source = include_str!("exec.rs");
        let retire = source
            .find(concat!(
                "retire_execution_authority_for_",
                "exec(&retiring_thread"
            ))
            .expect("predecessor lease validation");
        let replace = source
            .rfind("engine.execve_into(&img)")
            .expect("destructive backend replacement");
        assert!(
            retire < replace,
            "stale or wrong predecessor authority must reject before execve_into destroys the old image"
        );

        let input = crate::kernel::RootBootstrap::for_reference_model(
            19_104,
            carrick_hal::ThreadId::synthetic_for_tests(19_104),
            "missing exec authority".to_owned(),
        )
        .unwrap();
        let (_kernel, missing_context) = crate::kernel::Kernel::bootstrap_root(input).unwrap();
        let missing_slot = crate::vcpu_loop::ExecutionLeaseCell::owned();
        let missing_destructive_calls = std::cell::Cell::new(0);
        let missing_authorized =
            retire_execution_authority_for_exec(missing_context.thread(), &missing_slot);
        if missing_authorized.is_ok() {
            missing_destructive_calls.set(missing_destructive_calls.get() + 1);
        }
        assert!(missing_authorized.is_err());
        assert_eq!(missing_destructive_calls.get(), 0);

        use crate::kernel::objects::{ExecutorId, MigratableTaskState};
        use crate::kernel::{Kernel, RootBootstrap};
        use carrick_hal::ThreadId;
        use carrick_hal::threaded::GuestCpuState;
        use std::sync::Arc;

        let input = RootBootstrap::for_reference_model(
            19_103,
            ThreadId::synthetic_for_tests(19_103),
            "stale exec authority".to_owned(),
        )
        .unwrap();
        let (kernel, context) = Kernel::bootstrap_root(input).unwrap();
        let thread = Arc::clone(context.thread());
        let mm = context.shared().mm().id();
        let mut cpu = cpu_state_for_exec_test(mm.raw());
        cpu.mm_generation = mm.raw();
        cpu.asid_generation = mm.raw();
        thread
            .publish_initial_task_state(MigratableTaskState {
                cpu: GuestCpuState::from_aarch64_v1(cpu),
                mm,
                asid_generation: mm.raw(),
            })
            .unwrap();
        let lease = thread
            .claim_runnable(
                ExecutorId::for_transitional_thread(ThreadId::synthetic_for_tests(19_103)).unwrap(),
            )
            .unwrap();
        let slot = crate::vcpu_loop::ExecutionLeaseCell::owned();
        *slot.lock() = Some(lease);
        let prepared = kernel.prepare_exec(&context, None).unwrap();
        let _replacement = kernel.commit_exec(prepared, None).unwrap();
        let destructive_calls = std::cell::Cell::new(0);
        let authorized = retire_execution_authority_for_exec(&thread, &slot);
        if authorized.is_ok() {
            destructive_calls.set(destructive_calls.get() + 1);
        }
        assert!(authorized.is_err());
        assert_eq!(destructive_calls.get(), 0);
    }

    #[test]
    fn hvpatch_exec_verifier_covers_initialized_data_as_well_as_code() {
        let image = crate::memory::AddressSpace::from_segments(
            0x1_0000,
            [
                (
                    0x1_0000,
                    crate::elf::SegmentPerms {
                        read: true,
                        write: false,
                        execute: true,
                    },
                    vec![0xaa],
                    0x1000,
                ),
                (
                    0x2_0000,
                    crate::elf::SegmentPerms {
                        read: true,
                        write: true,
                        execute: false,
                    },
                    vec![0xbb],
                    0x1000,
                ),
            ],
        )
        .unwrap();
        let data_mapping = crate::memory::AddressSpaceFileMapping {
            start: 0x2_0000,
            end: 0x2_1000,
            file_page_offset: 0,
            path: "/bin/static".to_owned(),
        };

        assert_eq!(
            exec_regions_to_verify_with_mappings(&image, &[data_mapping])
                .map(|region| region.start)
                .collect::<Vec<_>>(),
            vec![0x1_0000, 0x2_0000]
        );
    }

    #[test]
    fn hvpatch_exec_failure_injection_requires_known_point_and_absolute_target() {
        let target = "/bin/execfatalstatus";
        for (configured, expected) in [
            (
                "old-capacity@/bin/execfatalstatus",
                Some(HvpatchExecInventoryFailureInjection::OldCapacity),
            ),
            (
                "replacement-reservation@/bin/execfatalstatus",
                Some(HvpatchExecInventoryFailureInjection::ReplacementReservation),
            ),
            (
                "begin-inventory@/bin/execfatalstatus",
                Some(HvpatchExecInventoryFailureInjection::BeginInventory),
            ),
            (
                "identity-page@/bin/execfatalstatus",
                Some(HvpatchExecInventoryFailureInjection::IdentityPage),
            ),
        ] {
            assert_eq!(
                parse_hvpatch_exec_inventory_failure_injection(configured, target),
                expected
            );
        }

        for configured in [
            "old-capacity",
            "old-capacity@",
            "old-capacity@bin/execfatalstatus",
            "old-capacity@/bin/other",
            "unknown@/bin/execfatalstatus",
            "@/bin/execfatalstatus",
        ] {
            assert_eq!(
                parse_hvpatch_exec_inventory_failure_injection(configured, target),
                None,
                "malformed injection armed: {configured}"
            );
        }
    }

    #[test]
    fn reports_the_first_divergent_exec_byte() {
        assert_eq!(first_byte_mismatch(b"same", b"same"), None);
        assert_eq!(first_byte_mismatch(b"abXd", b"abYd"), Some(2));
        assert_eq!(first_byte_mismatch(b"short", b"shorter"), Some(5));
    }

    #[test]
    fn shared_vm_exec_preserves_process_aware_host_thread_identity() {
        assert!(!should_update_host_process_title(true));
        assert!(should_update_host_process_title(false));
    }

    #[test]
    fn exec_inventory_routes_retirement_before_replacement_to_prepared_mms() {
        let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
            1_540,
            carrick_hal::ThreadId::synthetic_for_tests(1_540),
            "exec-inventory-routing".to_owned(),
        )
        .unwrap();
        let (kernel, context) = crate::kernel::Kernel::bootstrap_root(bootstrap).unwrap();
        let prepared = kernel.prepare_exec(&context, None).unwrap();
        let old_mm = prepared.old_mm_id();
        let replacement_mm = prepared.replacement_mm_id();
        assert_ne!(old_mm, replacement_mm);

        let capacity = carrick_hal::FrameEventCapacity::for_event_count(1).unwrap();
        let retired = kernel
            .reserve_frame_inventory(0, 0, capacity)
            .unwrap()
            .commit(());
        let replacement = kernel
            .reserve_frame_inventory(0, 0, capacity)
            .unwrap()
            .commit(());
        let mut routed = Vec::new();
        apply_exec_inventory(
            old_mm,
            replacement_mm,
            Some(retired),
            replacement,
            |mm, _| {
                routed.push(mm);
                Ok::<(), ()>(())
            },
        )
        .unwrap();

        assert_eq!(routed, [old_mm, replacement_mm]);
        drop(prepared);
    }

    /// A vfork/`CLONE_VM` child's execve leaves the old mm owned by the still
    /// live sharer, so the exec retires nothing from it. The retirement half is
    /// then absent rather than an empty batch: `FrameEventCapacity` is
    /// non-zero by construction, and the authority rejects a zero-event commit.
    #[test]
    fn exec_inventory_applies_only_replacement_when_old_mm_is_retained() {
        let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
            1_541,
            carrick_hal::ThreadId::synthetic_for_tests(1_541),
            "exec-inventory-retained-old-mm".to_owned(),
        )
        .unwrap();
        let (kernel, context) = crate::kernel::Kernel::bootstrap_root(bootstrap).unwrap();
        let prepared = kernel.prepare_exec(&context, None).unwrap();
        let old_mm = prepared.old_mm_id();
        let replacement_mm = prepared.replacement_mm_id();

        let capacity = carrick_hal::FrameEventCapacity::for_event_count(1).unwrap();
        let replacement = kernel
            .reserve_frame_inventory(0, 0, capacity)
            .unwrap()
            .commit(());
        let mut routed = Vec::new();
        apply_exec_inventory(old_mm, replacement_mm, None, replacement, |mm, _| {
            routed.push(mm);
            Ok::<(), ()>(())
        })
        .unwrap();

        assert_eq!(routed, [replacement_mm]);
        drop(prepared);
    }

    #[test]
    fn exec_inventory_cannot_be_taken_before_engine_replacement_succeeds() {
        let mut gate = ExecBackendPublicationGate::default();
        let calls = std::cell::Cell::new(0);
        assert_eq!(
            gate.take_after_replace(|| {
                calls.set(calls.get() + 1);
                Some(7)
            }),
            None
        );
        assert_eq!(calls.get(), 0);

        gate.record_engine_replaced();
        assert_eq!(
            gate.take_after_replace(|| {
                calls.set(calls.get() + 1);
                Some(7)
            }),
            Some(7)
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn pinned_exec_disposition_drives_engine_sharing_and_inventory_presence() {
        assert_eq!(
            route_exec_disposition(crate::hvpatch::ExecMmDispositionKind::RetainOldMm),
            ExecDispositionRouting {
                predecessor_shared: true,
                retirement_inventory: false,
            },
        );
        assert_eq!(
            route_exec_disposition(crate::hvpatch::ExecMmDispositionKind::RetireOldMm),
            ExecDispositionRouting {
                predecessor_shared: false,
                retirement_inventory: true,
            },
        );

        let source = include_str!("exec.rs");
        let runtime_path = source
            .rsplit("impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>")
            .next()
            .expect("runtime exec implementation");
        assert!(
            !runtime_path.contains(".observe_exec_owners("),
            "production exec must never recount owners after reservation",
        );
    }

    #[test]
    fn mm_publication_is_the_no_return_cut_and_precedes_destructive_work() {
        let source = include_str!("exec.rs");
        let publish = source
            .rfind("process.publish_exec_mm(*prepared")
            .expect("MM publication cut");
        let retire = source
            .rfind("retire_execution_authority_for_exec(&retiring_thread")
            .expect("predecessor retirement");
        let replace = source
            .rfind("engine.execve_into(&img)")
            .expect("destructive engine replacement");
        assert!(publish < retire && retire < replace);
        assert!(
            !source[publish..].contains("get_sys_reg(carrick_hal::SysReg::Ttbr0)"),
            "post-publication engine TTBR reads must not select MM authority",
        );
        let retirement_failure = &source[retire..replace];
        assert!(
            retirement_failure.contains("Self::exec_failed_past_no_return("),
            "every failure after MM publication must be terminal",
        );
    }
}

impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>
where
    E::SiblingSpec: 'static,
{
    /// Kill THIS guest process after an exec failure past the point of no
    /// return, the way Linux's `force_sigsegv` does: WIFSIGNALED by SIGSEGV.
    ///
    /// Never `exit(127)`. 127 is WIFEXITED, so `wait(2)` reports a *normal*
    /// exit and the parent cannot tell an internal carrick failure from a
    /// program that chose to exit 127 — and 127 is precisely what a shell
    /// reports for "command not found", so an exec that died inside carrick
    /// was indistinguishable from a missing binary. Every caller here has
    /// already destroyed the thread group, so returning to the guest is not an
    /// option; dying with the right *shape* is.
    ///
    /// Kills only this Linux process, never the whole runtime: on the kernel
    /// lane a host `abort()` would take down every other guest sharing the host
    /// process.
    fn exec_failed_past_no_return(
        kernel: &Kernel,
        engine: &mut E,
        cause: &str,
    ) -> Result<VcpuLoopOutcome, RuntimeError> {
        tracing::error!(
            cause,
            "execve failed after the point of no return; killing the guest process by SIGSEGV"
        );
        let sigsegv = crate::linux_abi::LINUX_SIGSEGV;
        if super::requires_no_unwind_host_exit(kernel, engine.is_forked_child()) {
            if let Err(error) = engine.process_exit_cleanup() {
                tracing::error!(
                    %error,
                    "post-exec-failure engine cleanup failed; preserving SIGSEGV terminal shape"
                );
            }
            let out = kernel.dispatcher.stdout();
            let err = kernel.dispatcher.stderr();
            crate::exec_helpers::forked_child_die_by_signal(sigsegv, &out, &err);
        }
        let result = super::assemble_run_result(kernel, 128 + sigsegv, Some(sigsegv), 0, false);
        Ok(VcpuLoopOutcome::ProcessExit(Box::new(result)))
    }

    /// Fail the `execve` syscall itself, leaving the caller running its old
    /// image. Only correct BEFORE the point of no return.
    fn exec_failed_with_errno(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        errno: crate::linux_abi::LinuxErrno,
        origin: super::AuthenticatedExecCompletionOrigin,
    ) -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
        match origin.0 {
            super::ExecCompletionOrigin::GuestSyscall => {
                self.complete_errno(engine, &kernel.reporter, errno)?;
            }
            super::ExecCompletionOrigin::InternalControl => {
                self.finish_internal_control_exec()?;
            }
        }
        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_execve(
        &mut self,
        kernel: &Kernel,
        kernel_context: &crate::kernel::KernelContext,
        engine: &mut E,
        path: String,
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
        origin: super::ExecCompletionOrigin,
    ) -> Result<ExecvePreparation, RuntimeError> {
        let origin = self.authenticate_exec_completion_origin(origin)?;
        if let Some(process) = kernel.hvpatch_process.as_ref() {
            process.trace_lifecycle(
                carrick_observability::probes::HvpatchGuestLifecyclePhase::ExecBegin,
                self.this_tid,
                0,
            );
        }
        crate::probes::execve_argv(&path, &argv);
        if let Some(chain) = kernel.dispatcher.observers() {
            let p = crate::observe::ProcessInfo::new(kernel_context);
            let argv_slices: Vec<&[u8]> = argv.iter().map(|arg| arg.as_slice()).collect();
            match chain.on_exec(&p, path.as_bytes(), &argv_slices) {
                crate::observe::SyscallAction::Allow => {}
                crate::observe::SyscallAction::Deny(errno) => {
                    return self
                        .exec_failed_with_errno(kernel, engine, errno, origin)
                        .map(ExecvePreparation::Complete);
                }
                crate::observe::SyscallAction::Kill(_sig) => {
                    return self
                        .exec_failed_with_errno(
                            kernel,
                            engine,
                            crate::linux_abi::LINUX_EACCES,
                            origin,
                        )
                        .map(ExecvePreparation::Complete);
                }
                crate::observe::SyscallAction::Short(_) => {}
            }
        }
        let proc_argv: Vec<String> = argv
            .iter()
            .map(|argument| String::from_utf8_lossy(argument).into_owned())
            .collect();
        let command_line = proc_argv.join(" ");
        let proc_env = env.clone();
        let requires_syscall_traps = kernel.dispatcher.requires_syscall_traps();
        let image = match kernel.dispatcher.with_kernel_resources(kernel_context, || {
            load_execve_image(&kernel.dispatcher, &path, argv, env, requires_syscall_traps)
        }) {
            Ok(image) => image,
            Err(errno) => {
                return self
                    .exec_failed_with_errno(kernel, engine, errno, origin)
                    .map(ExecvePreparation::Complete);
            }
        };
        let inventory_failure_injection = kernel
            .hvpatch_process
            .as_ref()
            .and_then(|_| hvpatch_exec_inventory_failure_injection(&path));
        // First close clone admission and wait for every already-admitted fork
        // to publish or cancel. Only then may this exec mark the shared MM
        // generation reserved: an in-flight fork publishes a shared-child edge
        // under the same authority and must never collide with that marker.
        // The exact, non-cloneable reservation then crosses the persistent-
        // executor handoff before sibling drain/no-return work begins.
        let admissions = close_clone_admission_then(
            || kernel.close_clone_admission_for_exec(self.this_tid),
            || {
                kernel
                    .hvpatch_process
                    .as_ref()
                    .map(|process| process.reserve_exec_mm_eventual())
            },
        );
        let (clone_admission, hvpatch_mm_reservation) = match admissions {
            Ok((admission, Some(Ok(reservation)))) => (admission, Some(reservation)),
            Ok((admission, None)) => (admission, None),
            Ok((admission, Some(Err(error)))) => {
                tracing::error!(
                    %error,
                    "execve MM-generation admission failed before the point of no return"
                );
                return match self.exec_failed_with_errno(
                    kernel,
                    engine,
                    crate::linux_abi::LINUX_EAGAIN,
                    origin,
                ) {
                    Ok(outcome) => Ok(ExecvePreparation::Complete(outcome)),
                    Err(completion_error) => Ok(ExecvePreparation::TerminalFailure(
                        ExecTerminalFailure::from_admission(
                            completion_error,
                            kernel_context.retain_exact(),
                            admission,
                        ),
                    )),
                };
            }
            Err(error) => {
                tracing::error!(
                    %error,
                    "execve clone-admission drain failed before the point of no return"
                );
                return self
                    .exec_failed_with_errno(kernel, engine, crate::linux_abi::LINUX_EAGAIN, origin)
                    .map(ExecvePreparation::Complete);
            }
        };
        crate::probes::execve_loaded(
            &path,
            image.entry(),
            image.initial_stack_pointer().unwrap_or(0),
            image.regions().len() as u64,
        );
        let runtime_region_count = image.regions().len() as u64;
        let runtime_mapped_bytes = image.regions().iter().map(|region| region.len()).sum();
        Ok(ExecvePreparation::Prepared(Box::new(PreparedExecve {
            origin: Some(origin),
            image,
            path,
            proc_argv,
            proc_env,
            command_line,
            inventory_failure_injection,
            hvpatch_mm_reservation,
            terminal_context: Some(kernel_context.retain_exact()),
            clone_admission: Some(clone_admission),
            runtime_region_count,
            runtime_mapped_bytes,
            sibling_drain_started: std::time::Instant::now(),
        })))
    }

    /// `Ok(None)` means the syscall finished — the image was replaced, or the
    /// exec failed with an errno and the caller is still running its old
    /// image. `Ok(Some(outcome))` means the process is terminating.
    async fn drive_execve(
        &mut self,
        kernel: &Kernel,
        kernel_context: &mut crate::kernel::KernelContext,
        engine: &mut E,
        prepared: PreparedExecve,
    ) -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
        let PreparedExecve {
            origin: _,
            image: img,
            path,
            proc_argv,
            proc_env,
            command_line: cmdline,
            inventory_failure_injection,
            mut hvpatch_mm_reservation,
            terminal_context,
            clone_admission,
            runtime_region_count,
            runtime_mapped_bytes,
            sibling_drain_started,
        } = prepared;
        if terminal_context.is_some() || clone_admission.is_some() {
            carrick_fatal!(
                "hvpatch::exec_terminal",
                "destructive exec suffix retained duplicate terminal authority: terminal_context_is_some={}, clone_admission_is_some={}",
                terminal_context.is_some(),
                clone_admission.is_some()
            );
        }
        let emit_runtime_stage =
            |phase: carrick_observability::probes::HvpatchExecRuntimeStagePhase,
             started: std::time::Instant| {
                if kernel.hvpatch_process.is_some() {
                    let elapsed_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
                    crate::probes::hvpatch_exec_runtime_stage(
                        carrick_observability::probes::HvpatchExecRuntimeStage::new(
                            phase,
                            elapsed_ns,
                            runtime_region_count,
                            runtime_mapped_bytes,
                        ),
                    );
                }
            };
        emit_runtime_stage(
            carrick_observability::probes::HvpatchExecRuntimeStagePhase::SiblingDrain,
            sibling_drain_started,
        );
        // Kernel preparation follows the runtime sibling drain (whose
        // exiting host loops retire their own old Kernel threads) but
        // precedes every destructive image, CLOEXEC, and proc-state
        // mutation. HVPatch selects the survivor and installs the exec
        // reservation under one registry write lock, so a late loser
        // retirement cannot invalidate a separately captured revision.
        // From here, the prepared exec transaction is the sole owner of
        // nonleader promotion and replacement Mm state.
        let prepared_kernel_exec = match kernel.hvpatch_process.as_ref() {
            Some(process) => {
                let reservation = hvpatch_mm_reservation.take().unwrap_or_else(|| {
                    carrick_fatal!(
                        "hvpatch::mm_authority",
                        "prepared HVPatch exec lost MM-generation admission for tid={:?}",
                        self.linux_tid
                    );
                });
                process
                    .prepare_exec_for_linux_tid_with_mm_reservation(self.linux_tid, reservation)
                    .map(|(prepared, context)| {
                        (
                            RuntimePreparedExec::Hvpatch(Box::new(prepared)),
                            Some(context),
                        )
                    })
            }
            None => kernel
                .dispatcher
                .prepare_one_task_kernel_exec(kernel_context)
                .map(|prepared| (RuntimePreparedExec::Other(Box::new(prepared)), None))
                .map_err(|error| error.to_string()),
        };
        let (mut prepared_kernel_exec, refreshed_hvpatch_context) = match prepared_kernel_exec {
            Ok(prepared) => prepared,
            Err(error) => {
                return Self::exec_failed_past_no_return(
                    kernel,
                    engine,
                    &format!("prepare authoritative Kernel exec: {error}"),
                )
                .map(Some);
            }
        };
        let exec_kernel_context = refreshed_hvpatch_context.as_ref().unwrap_or(kernel_context);
        let old_mm_id = prepared_kernel_exec.old_mm_id();
        let replacement_mm_id = prepared_kernel_exec.replacement_mm_id();
        let mut exec_predecessor_identity = None;
        // Allocate both complete transaction envelopes before proc-state
        // mutation or topology/backend locking. Dropping the guard on
        // any pre-replacement failure abandons both runtime records and
        // dropping `prepared_kernel_exec` rolls back Kernel preparation.
        let _inventory_abandon = if let Some(process) = kernel.hvpatch_process.as_ref() {
            // The reservation pinned this topology decision under MM-resource
            // authority before any later topology mutation. Never recount it.
            let disposition = prepared_kernel_exec
                .hvpatch_disposition()
                .unwrap_or_else(|| {
                    carrick_fatal!(
                        "hvpatch::exec_topology",
                        "HVPatch prepared exec missing disposition metadata during transaction routing"
                    );
                });
            let routing = route_exec_disposition(disposition);
            let retires_old_mm = routing.retirement_inventory;
            let predecessor_shared = routing.predecessor_shared;
            let predecessor_binding = process.mm_binding().ok_or_else(|| {
                RuntimeError::Configuration(
                    "HVPatch exec predecessor has no exact MM binding".to_owned(),
                )
            })?;
            if exec_kernel_context.task().key() != process.task_key()
                || exec_kernel_context.shared().mm().id() != old_mm_id
            {
                return Err(RuntimeError::Configuration(
                    "HVPatch exec predecessor ProcessContext/MM binding drifted".to_owned(),
                ));
            }
            let predecessor_identity = carrick_hal::ExecPredecessorIdentity {
                task_serial: exec_kernel_context.task().key().serial.raw(),
                thread_serial: exec_kernel_context.thread().key().serial.raw(),
                linux_pid: exec_kernel_context.task().key().id.raw(),
                linux_tid: exec_kernel_context.thread().key().tid.raw(),
                mm: old_mm_id.raw(),
                asid: predecessor_binding.asid.raw(),
            };
            let predecessor_classification =
                carrick_observability::probes::HvpatchExecPredecessorClassification::new(
                    carrick_observability::probes::HvpatchExecPredecessorClassificationPhase::AuthorityComputed,
                    carrick_observability::probes::HvpatchExecPredecessorIdentity::new(
                        predecessor_identity.task_serial,
                        predecessor_identity.thread_serial,
                        predecessor_identity.linux_pid,
                        predecessor_identity.linux_tid,
                        predecessor_identity.mm,
                        u32::from(predecessor_identity.asid),
                    )
                    .map_err(|error| {
                        RuntimeError::Configuration(format!(
                            "construct authoritative HVPatch exec predecessor identity: {error}"
                        ))
                    })?,
                    predecessor_shared,
                )
                .map_err(|error| {
                    RuntimeError::Configuration(format!(
                        "construct authoritative HVPatch exec predecessor classification: {error}"
                    ))
                })?;
            crate::probes::hvpatch_exec_predecessor_classification(predecessor_classification);
            exec_predecessor_identity = Some(predecessor_identity);
            engine.mark_exec_predecessor_shared(predecessor_shared);
            let (mut old_extent_count, replacement_extent_count) =
                engine.frame_inventory_exec_extent_counts(&img);
            if inventory_failure_injection
                == Some(HvpatchExecInventoryFailureInjection::OldCapacity)
            {
                old_extent_count = carrick_hal::MAX_FRAME_INVENTORY_EVENTS_PER_BATCH / 2 + 1;
            }
            // `old_extent_count == 0` silently skips the retirement of the OLD
            // mm's inventory, which is correct only when a live sharer still
            // owns that ledger. Getting it wrong leaves the kernel graph with
            // mappings naming an mm that no longer exists, and nothing else
            // reports it. Name the numbers.
            tracing::debug!(
                target: "carrick::exec",
                old_mm = ?old_mm_id,
                replacement_mm = ?replacement_mm_id,
                old_extent_count,
                replacement_extent_count,
                retires_old_mm,
                "HVPatch exec inventory sizing",
            );
            // A retained pinned disposition has no retirement reservation at
            // all; an observed zero is not allowed to redefine ownership.
            let old_capacity = if !retires_old_mm {
                None
            } else {
                match carrick_hal::FrameEventCapacity::for_event_count(
                    carrick_hal::MAX_FRAME_INVENTORY_EVENTS_PER_BATCH,
                ) {
                    Ok(capacity) => Some(capacity),
                    Err(error) => {
                        return Self::exec_failed_past_no_return(
                            kernel,
                            engine,
                            &format!("size HVPatch exec retirement inventory: {error}"),
                        )
                        .map(Some);
                    }
                }
            };
            let replacement_capacity = match carrick_hal::FrameEventCapacity::for_event_count(
                carrick_hal::MAX_FRAME_INVENTORY_EVENTS_PER_BATCH,
            ) {
                Ok(capacity) => capacity,
                Err(error) => {
                    return Self::exec_failed_past_no_return(
                        kernel,
                        engine,
                        &format!("size HVPatch exec replacement inventory: {error}"),
                    )
                    .map(Some);
                }
            };
            let registry = crate::fork_quiesce::FrameRegistryGuard::new(
                crate::fork_quiesce::frame_registry_lock().lock(),
            );
            let retired = match old_capacity {
                None => None,
                Some(old_capacity) => {
                    match process
                        .kernel_graph()
                        .reserve_frame_inventory(0, 0, old_capacity)
                    {
                        Ok(reservation) => Some(reservation),
                        Err(error) => {
                            return Self::exec_failed_past_no_return(
                                kernel,
                                engine,
                                &format!("reserve HVPatch exec retirement inventory: {error}"),
                            )
                            .map(Some);
                        }
                    }
                }
            };
            let retired_transaction = retired.as_ref().map(|retired| retired.transaction());
            let replacement_candidate_count = if inventory_failure_injection
                == Some(HvpatchExecInventoryFailureInjection::ReplacementReservation)
            {
                replacement_capacity.get() + 1
            } else {
                replacement_extent_count
            };
            let replacement = match process.kernel_graph().reserve_frame_inventory(
                replacement_candidate_count,
                replacement_candidate_count,
                replacement_capacity,
            ) {
                Ok(reservation) => reservation,
                Err(error) => {
                    if let Some(retired_transaction) = retired_transaction {
                        process
                            .kernel_graph()
                            .frame_inventory()
                            .abandon(retired_transaction);
                    }
                    return Self::exec_failed_past_no_return(
                        kernel,
                        engine,
                        &format!("reserve HVPatch exec replacement inventory: {error}"),
                    )
                    .map(Some);
                }
            };
            let replacement_transaction = replacement.transaction();
            let abandon = super::quiesce::InventoryAbandon::new(
                process.kernel_graph().frame_inventory(),
                [retired_transaction, Some(replacement_transaction)],
            );
            if inventory_failure_injection
                == Some(HvpatchExecInventoryFailureInjection::BeginInventory)
            {
                engine.inject_next_begin_exec_inventory_failure();
            }
            if let Err(error) = engine.begin_exec_inventory(retired, replacement) {
                return Self::exec_failed_past_no_return(
                    kernel,
                    engine,
                    &format!("arm HVPatch exec frame inventory: {error}"),
                )
                .map(Some);
            }
            drop(registry);
            Some(abandon)
        } else {
            None
        };
        let proc_state_started = std::time::Instant::now();
        if should_update_host_process_title(kernel.hvpatch_process.is_some()) {
            crate::dispatch::set_host_process_name(cmdline.as_bytes());
        }
        kernel
            .dispatcher
            .set_executable_identity(path.clone(), proc_argv, proc_env);
        kernel
            .dispatcher
            .reset_signal_handlers_on_execve(exec_kernel_context);
        // Reset + refresh /proc/self/maps and /proc/self/auxv under one
        // dispatcher memory-authority generation. The historical MM
        // retains the pre-staging snapshot, but records this deliberate
        // source revision so commit can reject any later mutation.
        let mut prepared_dispatch_mm_exec = Some(apply_exec_image_proc_state(
            &kernel.dispatcher,
            replacement_mm_id,
            &img,
        ));
        if let Err(error) = prepared_kernel_exec.acknowledge_staged_vma_revision() {
            return Self::exec_failed_past_no_return(
                kernel,
                engine,
                &format!("acknowledge staged exec VMA revision: {error}"),
            )
            .map(Some);
        }
        emit_runtime_stage(
            carrick_observability::probes::HvpatchExecRuntimeStagePhase::ProcState,
            proc_state_started,
        );

        // Stage-2 edits for distinct MMs touch distinct IPA ranges owned by
        // distinct MMs, so the exclusion is the MM's transaction guard rather
        // than the carrier topology lock.
        // Task 4: replaced acquire_topology_lock with mutation.begin_transaction().
        let topology_lock_started = std::time::Instant::now();
        let mut admitted_mm_executor = None;
        let mut mm_authority = if kernel.hvpatch_process.is_some() {
            let mm_executor: &mut crate::dispatch::MmExecutorParticipation = match self
                .guest_execution
                .as_mut()
                .filter(|p| p.mm_id() == old_mm_id)
            {
                Some(participation) => participation,
                None => match kernel.dispatcher.enter_mm_executor() {
                    Ok(p) => admitted_mm_executor.insert(p),
                    Err(error) => {
                        return Self::exec_failed_past_no_return(
                            kernel,
                            engine,
                            &format!("admit exact-MM exec authority: {error}"),
                        )
                        .map(Some);
                    }
                },
            };
            let coordinator = kernel.dispatcher.mm_mutation_coordinator();
            let authority = match super::quiesce::acquire_mm_stage1_authority(
                mm_executor,
                self.this_tid,
                super::quiesce::PtPauseBudget::DEFAULT,
            ) {
                Ok(auth) => auth,
                Err(error) => {
                    return Self::exec_failed_past_no_return(
                        kernel,
                        engine,
                        &format!("acquire exact-MM exec authority: {error:?}"),
                    )
                    .map(Some);
                }
            };
            Some((authority, coordinator, old_mm_id))
        } else {
            None
        };
        let mutation =
            mm_authority
                .as_mut()
                .map(|(authority, coordinator, mm_id)| match authority {
                    super::quiesce::MmStage1Authority::Sole(sole) => {
                        crate::dispatch::mm_mutation::from_sole_executor(
                            sole,
                            std::sync::Arc::clone(coordinator),
                            *mm_id,
                        )
                    }
                    super::quiesce::MmStage1Authority::Paused(pause) => {
                        crate::dispatch::mm_mutation::from_pt_pause(pause)
                    }
                });
        let _hvpatch_topology = mutation.as_ref().map(|m| m.begin_transaction());
        emit_runtime_stage(
            carrick_observability::probes::HvpatchExecRuntimeStagePhase::TopologyLock,
            topology_lock_started,
        );
        let engine_replace_started = std::time::Instant::now();
        let mut backend_publication_gate = ExecBackendPublicationGate::default();
        let retiring_thread = self.kernel_thread.as_ref().cloned().ok_or_else(|| {
            RuntimeError::Configuration(
                "committed exec lost predecessor Kernel thread authority".to_owned(),
            )
        })?;
        let worker_executor = self
            .execution_lease
            .lock()
            .as_ref()
            .map(crate::kernel::objects::ThreadExecutionLease::executor)
            .ok_or_else(|| {
                RuntimeError::Configuration(
                    "exec replacement lost worker-authenticated execution lease".to_owned(),
                )
            })?;
        let replacement_asid_load =
            match prepared_kernel_exec.prepare_hvpatch_address_space(engine, worker_executor) {
                Ok(load) => load,
                Err(error) => {
                    return Self::exec_failed_past_no_return(
                        kernel,
                        engine,
                        &format!("bind fresh HVPatch exec MM/ASID lease: {error}"),
                    )
                    .map(Some);
                }
            };
        let old_files = prepared_kernel_exec.old_file_table();
        let published_kernel_exec = match (kernel.hvpatch_process.as_ref(), prepared_kernel_exec) {
            (Some(process), RuntimePreparedExec::Hvpatch(prepared)) => {
                let replacement_vma_source = prepared_dispatch_mm_exec.as_ref().map_or_else(
                    || kernel.dispatcher.vma_snapshot_source(),
                    crate::dispatch::PreparedDispatchMmExec::vma_snapshot_source,
                );
                match process.publish_exec_mm(*prepared, replacement_vma_source) {
                    Ok(published) => RuntimePublishedExec::Hvpatch(published),
                    Err(error) => {
                        return Err(RuntimeError::Configuration(format!(
                            "reject exec before MM publication: {error}"
                        )));
                    }
                }
            }
            (None, RuntimePreparedExec::Other(prepared)) => RuntimePublishedExec::Other(*prepared),
            _ => {
                carrick_fatal!(
                    "hvpatch::exec_backend",
                    "prepared Kernel exec variant disagrees with configured HVPatch backend before destructive image replacement"
                );
            }
        };
        if let Err(error) =
            retire_execution_authority_for_exec(&retiring_thread, &self.execution_lease)
        {
            return Self::exec_failed_past_no_return(
                kernel,
                engine,
                &format!("retire predecessor after MM publication: {error}"),
            )
            .map(Some);
        }
        if let Some(identity) = exec_predecessor_identity
            && let Err(error) = engine.bind_exec_predecessor_identity(identity)
        {
            return Self::exec_failed_past_no_return(
                kernel,
                engine,
                &format!("bind exact HVPatch exec predecessor identity: {error}"),
            )
            .map(Some);
        }
        if let Err(error) = engine.execve_into(&img) {
            return Self::exec_failed_past_no_return(
                kernel,
                engine,
                &format!("replace guest image: {error}"),
            )
            .map(Some);
        }
        if let (Some(process), RuntimePublishedExec::Hvpatch(published)) =
            (kernel.hvpatch_process.as_ref(), &published_kernel_exec)
        {
            let source = process.table_arena_source_for_lease(published.replacement_lease());
            tracing::debug!(target: "carrick::stage1_arena", "install replacement-lease arena source after execve_into");
            if let Err(error) = engine.install_stage1_table_arena_source(source) {
                return Self::exec_failed_past_no_return(
                    kernel,
                    engine,
                    &format!("install replacement HVPatch table arena source: {error}"),
                )
                .map(Some);
            }
        }
        backend_publication_gate.record_engine_replaced();
        // `execve_into` has released every stage-2/frame lock. Topology
        // serialization must also be released before runtime takes its
        // frame-inventory authority lock.
        drop(_hvpatch_topology);
        drop(mutation);
        drop(mm_authority);
        drop(admitted_mm_executor);
        if let Some(process) = kernel.hvpatch_process.as_ref() {
            let registry = crate::fork_quiesce::FrameRegistryGuard::new(
                crate::fork_quiesce::frame_registry_lock().lock(),
            );
            let Some((retired_commit, fallback_replacement_commit)) =
                backend_publication_gate.take_after_replace(|| engine.take_exec_inventory())
            else {
                return Self::exec_failed_past_no_return(
                    kernel,
                    engine,
                    "HVPatch destructive exec produced no frame inventory commits",
                )
                .map(Some);
            };
            if let Some(retired_commit) = retired_commit {
                if let Err(error) = process
                    .kernel_graph()
                    .frame_inventory()
                    .apply(old_mm_id, retired_commit)
                {
                    return Self::exec_failed_past_no_return(
                        kernel,
                        engine,
                        &format!(
                            "apply HVPatch exec retirement frame inventory for old mm {old_mm_id:?}: {error}"
                        ),
                    )
                    .map(Some);
                }
            }
            let mut applied_by_authority = false;
            if let Err(error) =
                engine.apply_exec_inventory(replacement_mm_id.raw(), &mut |commit| {
                    applied_by_authority = true;
                    process
                        .kernel_graph()
                        .frame_inventory()
                        .apply_with_receipt(replacement_mm_id, commit)
                        .map(|(_, receipt)| receipt)
                        .map_err(|error| crate::trap::TrapError::Hypervisor(error.to_string()))
                })
            {
                return Self::exec_failed_past_no_return(
                    kernel,
                    engine,
                    &format!(
                        "apply HVPatch exec replacement authority for replacement mm {replacement_mm_id:?}: {error}"
                    ),
                )
                .map(Some);
            }
            if !applied_by_authority {
                let Some(replacement_commit) = fallback_replacement_commit else {
                    return Self::exec_failed_past_no_return(
                        kernel,
                        engine,
                        "HVPatch fallback replacement frame inventory commit missing",
                    )
                    .map(Some);
                };
                if let Err(error) = process
                    .kernel_graph()
                    .frame_inventory()
                    .apply(replacement_mm_id, replacement_commit)
                {
                    return Self::exec_failed_past_no_return(
                        kernel,
                        engine,
                        &format!(
                            "apply HVPatch exec replacement frame inventory for replacement mm {replacement_mm_id:?}: {error}"
                        ),
                    )
                    .map(Some);
                }
            }
            drop(registry);
        }
        #[cfg(test)]
        self.fail_exec_terminal_context_for_test(ExecTerminalContextFailpoint::BeforeKernelCommit)?;
        let committed = match (kernel.hvpatch_process.as_ref(), published_kernel_exec) {
            (Some(process), RuntimePublishedExec::Hvpatch(published)) => process
                .complete_exec(published, prepared_dispatch_mm_exec.take())
                .map(|committed| (committed.context().retain_exact(), Some(committed))),
            (None, RuntimePublishedExec::Other(prepared)) => {
                let committed = kernel.dispatcher.commit_one_task_kernel_exec(prepared);
                if committed.is_ok()
                    && let Some(prepared) = prepared_dispatch_mm_exec.take()
                {
                    prepared.commit();
                }
                committed
                    .map(|context| (context, None))
                    .map_err(crate::hvpatch::CompleteExecError::before_commit)
            }
            _ => {
                carrick_fatal!(
                    "hvpatch::exec_commit",
                    "published Kernel exec variant disagrees with configured HVPatch backend after destructive image replacement"
                );
            }
        };
        let (committed_context, committed_transition) = match committed {
            Ok(committed) => committed,
            Err(error) => {
                let (error, committed_context) = error.into_parts();
                if let Some(committed_context) = committed_context {
                    *kernel_context = committed_context;
                }
                // The engine now runs the replacement image. Returning a
                // guest-visible exec failure or resuming the old Kernel
                // graph would create split lifecycle authority.
                return Self::exec_failed_past_no_return(
                    kernel,
                    engine,
                    &format!("commit Kernel exec after image replacement: {error}"),
                )
                .map(Some);
            }
        };
        // This is the terminal-context authority boundary: every remaining
        // edge is post-commit and must carry the Kernel successor, including
        // errors before runtime state and replacement publication catch up.
        *kernel_context = committed_context.retain_exact();
        #[cfg(test)]
        {
            self.committed_exec_context_for_test = Some(committed_context.retain_exact());
            self.fail_exec_terminal_context_for_test(
                ExecTerminalContextFailpoint::TaskLoadPublication,
            )?;
        }
        // Linux detaches every SysV shared-memory mapping only after exec has
        // crossed its no-return boundary. Preparation failures above preserve
        // the old image and its attachment set; a committed replacement owns
        // neither the old VMAs nor their `shm_nattch` charges.
        kernel
            .dispatcher
            .cleanup_sysv_shm_attachments_on_process_exit();
        if replacement_asid_load.is_some()
            && let Err(error) = engine.complete_task_load_barrier()
        {
            return Self::exec_failed_past_no_return(
                kernel,
                engine,
                &format!("complete replacement task-load DSB/ISB barrier: {error}"),
            )
            .map(Some);
        }
        if let Some(load) = replacement_asid_load
            && let Err(error) = load.mark_resident()
        {
            return Self::exec_failed_past_no_return(
                kernel,
                engine,
                &format!("commit replacement ASID residence after exec: {error}"),
            )
            .map(Some);
        }
        let committed_mm = committed_context.shared().mm().id();
        let committed_asid_generation = kernel.hvpatch_process.as_ref().map_or(
            committed_mm.raw(),
            crate::hvpatch::ProcessContext::asid_generation,
        );
        engine.bind_task_snapshot_identity(committed_mm.raw(), committed_asid_generation);
        #[cfg(test)]
        self.fail_exec_terminal_context_for_test(
            ExecTerminalContextFailpoint::SnapshotPublication,
        )?;
        let replacement_cpu = match engine.snapshot_guest_state_for_publication() {
            Ok(state) => state,
            Err(error) => {
                committed_context.thread().fail_uninitialized_snapshot(
                    crate::kernel::objects::ExecutionFailure::SnapshotSaveFailed,
                );
                return Self::exec_failed_past_no_return(
                    kernel,
                    engine,
                    &format!("capture replacement execution state after exec: {error}"),
                )
                .map(Some);
            }
        };
        let replacement_state = crate::kernel::objects::MigratableTaskState {
            cpu: replacement_cpu,
            mm: committed_mm,
            asid_generation: committed_asid_generation,
        };
        if let Err(error) = publish_execution_authority_after_exec(
            committed_context.thread(),
            worker_executor,
            replacement_state,
            &self.execution_lease,
        ) {
            return Self::exec_failed_past_no_return(
                kernel,
                engine,
                &format!("publish replacement execution lease after exec: {error}"),
            )
            .map(Some);
        }
        if let Some(committed) = committed_transition {
            let (transition, replacement_mm, retired_mm) = committed.into_parts();
            let replacement = super::executor::PendingExecReplacement {
                transition,
                replacement_mm,
                retired_mm,
            };
            if self.pending_exec_replacement.replace(replacement).is_some() {
                carrick_fatal!(
                    "hvpatch::exec_replacement",
                    "duplicate pending exec replacement would overwrite Kernel transition and MM retirement authority"
                );
            }
        }
        // `exec` publishes a new Mm generation while keeping this host
        // engine/vCPU.  Frame-COW callbacks must therefore move from
        // the retired mm to the committed replacement before any
        // identity-page or guest write can fault.  Keeping the old
        // authority makes a structurally valid COW MappingId belong to
        // the retired mm and fail closed at replacement-mm teardown.
        if let Some(process) = kernel.hvpatch_process.as_ref() {
            #[cfg(test)]
            self.fail_exec_terminal_context_for_test(
                ExecTerminalContextFailpoint::FrameCowBinding,
            )?;
            let owner_inventory = engine.frame_cow_owner_inventory().ok_or_else(|| {
                RuntimeError::Configuration(
                    "committed HVPatch exec has no carrier host-owner inventory".to_owned(),
                )
            })?;
            let binding = process.mm_binding().ok_or_else(|| {
                RuntimeError::Configuration(
                    "committed HVPatch exec has no replacement mm binding".to_owned(),
                )
            })?;
            let authority: std::sync::Arc<dyn carrick_hal::FrameCowAuthority> =
                std::sync::Arc::new(super::KernelFrameCowAuthority {
                    deferred_anonymous: kernel.dispatcher.deferred_anonymous_state(committed_mm),
                    kernel: std::sync::Arc::clone(committed_context.kernel()),
                    mm: committed_mm,
                    owner_inventory,
                    guest_executors: kernel.dispatcher.mm_executor_census(),
                    tid: self.this_tid,
                    identity: carrick_hal::FrameCowIdentity {
                        linux_pid: process.pid(),
                        linux_tid: self.this_tid.raw(),
                        mm: committed_mm.raw(),
                        asid: binding.asid.raw(),
                    },
                    pt_quiesce: kernel.dispatcher.pt_quiesce(),
                });
            engine.bind_frame_cow(
                authority,
                carrick_hal::FrameCowIdentity {
                    linux_pid: process.pid(),
                    linux_tid: self.this_tid.raw(),
                    mm: committed_mm.raw(),
                    asid: binding.asid.raw(),
                },
            );
            if !kernel
                .dispatcher
                .bind_deferred_anonymous_state(engine, committed_mm)
            {
                return Err(RuntimeError::Configuration(
                    "exec anonymous authority MM mismatch".to_owned(),
                ));
            }
            // The exec rebuild starts a fresh stage-1 manager for the
            // replacement mm; its extension arenas must be leased against the
            // REPLACEMENT lease (the old source belongs to the retired mm and
            // would return live slots at that mm's teardown). Without this the
            // exec'd process could never grow past one arena — pagetablegrow
            // through `/bin/sh -c` died at 87 mappings, and CPython's
            // recursion-limit compile hit `OutOfTables (arenas=1)`.
            let arena_source = process
                .mm_resources()
                .table_arena_source(committed_context.task().key())
                .map_err(|error| {
                    RuntimeError::Configuration(format!(
                        "committed HVPatch exec has no replacement table arena lease: {error}"
                    ))
                })?;
            tracing::debug!(target: "carrick::stage1_arena", "install committed-task arena source at exec commit");
            engine
                .install_stage1_table_arena_source(arena_source)
                .map_err(|error| {
                    RuntimeError::Configuration(format!(
                        "install replacement HVPatch table arena source: {error}"
                    ))
                })?;
            #[cfg(test)]
            self.fail_exec_terminal_context_for_test(
                ExecTerminalContextFailpoint::InventoryActivation,
            )?;
            if let Err(error) = engine.activate_exec_inventory() {
                return Self::exec_failed_past_no_return(
                    kernel,
                    engine,
                    &format!("activate HVPatch exec authority: {error}"),
                )
                .map(Some);
            }
        }
        emit_runtime_stage(
            carrick_observability::probes::HvpatchExecRuntimeStagePhase::EngineReplace,
            engine_replace_started,
        );
        let close_cloexec_started = std::time::Instant::now();
        kernel.dispatcher.close_draining_file_table(
            committed_context.kernel(),
            &old_files,
            Some(committed_context.task().key()),
            Some(&committed_context.resources().files()),
        );
        emit_runtime_stage(
            carrick_observability::probes::HvpatchExecRuntimeStagePhase::CloseCloexec,
            close_cloexec_started,
        );
        self.linux_tid = committed_context.thread().key().tid;
        // Crash-register authority follows the replacement Kernel
        // Thread generation. Keeping the pre-exec Arc would publish a
        // later capture into a retired object, while the committed
        // task census correctly waits on the replacement object.
        self.kernel_thread = Some(std::sync::Arc::clone(committed_context.thread()));
        // The common run-loop signal boundary must consume the exact
        // replacement generation, never the pre-exec context retained
        // at syscall entry. A failed exec leaves that entry context in
        // place; only a committed image replacement publishes here.
        self.service_kernel_context = Some(committed_context.retain_exact());
        let publication_started = std::time::Instant::now();
        if kernel.hvpatch_process.is_some()
            && std::env::var_os("CARRICK_HVPATCH_VERIFY_EXEC_CODE").is_some()
        {
            if let Err(error) = verify_published_exec_image(engine, &img, &path) {
                return Self::exec_failed_past_no_return(
                    kernel,
                    engine,
                    &format!("verify published HVPatch exec image: {error}"),
                )
                .map(Some);
            }
        }
        crate::namespace::pid::mark_self_execed_for(&committed_context);
        // execve_into rebuilt a fresh vCPU: re-stamp the identity page
        // (zeroed) and TPIDR_EL1 (reset) for the same thread/tid.
        let identity_base = if inventory_failure_injection
            == Some(HvpatchExecInventoryFailureInjection::IdentityPage)
        {
            u64::MAX - 0x100
        } else {
            crate::memory::LINUX_IDENTITY_PAGE_BASE
        };
        #[cfg(test)]
        self.fail_exec_terminal_context_for_test(
            ExecTerminalContextFailpoint::IdentityPublication,
        )?;
        if let Err(error) = super::stamp_identity_page_at(
            engine,
            &kernel.dispatcher,
            &committed_context,
            identity_base,
        ) {
            return Self::exec_failed_past_no_return(
                kernel,
                engine,
                &format!("stamp HVPatch exec identity page: {error}"),
            )
            .map(Some);
        }
        // The new image's vvar was published with the host calibration only;
        // fold in the guest CLOCK_REALTIME delta before the image runs its
        // first instruction, so a vDSO read before any syscall already agrees
        // with the syscall path (`sync_vvar_realtime_offset`; probe
        // clocksettimevdso, `date -s` followed by an exec'd `date`).
        #[cfg(test)]
        self.fail_exec_terminal_context_for_test(ExecTerminalContextFailpoint::VvarPublication)?;
        if let Err(error) = kernel
            .dispatcher
            .sync_vvar_realtime_offset(committed_context.task().container().clock(), engine)
        {
            return Self::exec_failed_past_no_return(
                kernel,
                engine,
                &format!("stamp HVPatch exec vvar realtime word: {error}"),
            )
            .map(Some);
        }
        if let Err(error) =
            super::stamp_ns_visible_guest_tid(engine, &kernel.dispatcher, &committed_context)
        {
            return Self::exec_failed_past_no_return(
                kernel,
                engine,
                &format!("publish HVPatch guest thread identity: {error}"),
            )
            .map(Some);
        }
        self.fatal_image_generation = kernel
            .fatal_signal
            .rebind_after_exec(self.fatal_image_generation)
            .unwrap_or_else(|| {
                carrick_fatal!(
                    "kernel::fatal_signal_authority",
                    "fatal-signal image generation could not rebind to committed exec successor: fatal_image_generation={:?}",
                    self.fatal_image_generation
                );
            });
        emit_runtime_stage(
            carrick_observability::probes::HvpatchExecRuntimeStagePhase::Publication,
            publication_started,
        );
        if let Some(process) = kernel.hvpatch_process.as_ref() {
            process.trace_lifecycle(
                carrick_observability::probes::HvpatchGuestLifecyclePhase::Exec,
                self.this_tid,
                0,
            );
        }
        // vfork: the execve SUCCEEDED and we now have our own private VM.
        // Release the suspended parent by writing one byte to the
        // inherited pipe, then close it. A FAILED execve returns above via
        // a failure branch WITHOUT releasing — the child then `_exit`s
        // and the parent's `read()` gets EOF instead.
        if let Some(fd) = self.vfork_release_fd.take() {
            let _ = unsafe { libc::write(fd, [0u8; 1].as_ptr().cast(), 1) };
            unsafe { libc::close(fd) };
        }
        stop_after_traced_exec(&kernel.dispatcher);
        Ok(None)
    }

    /// Resume the destructive exec suffix after the persistent executor has
    /// loaded a fresh engine. `Prepared` bypasses the sole await arm in
    /// `drive_execve`; returning Pending is therefore a fail-closed state-machine
    /// bug, never an invitation to retain `&mut E`.
    pub(super) fn finish_prepared_execve(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        mut prepared: PreparedExecve,
    ) -> Result<FinishedPreparedExecve, ExecTerminalFailure> {
        let (mut terminal_context, handoff) = prepared.take_terminal_authority();
        let mut future =
            Box::pin(self.drive_execve(kernel, &mut terminal_context, engine, prepared));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        let result = match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(result) => result,
            std::task::Poll::Pending => Err(RuntimeError::Configuration(
                "prepared exec suffix attempted to suspend with an injected engine".to_owned(),
            )),
        };
        drop(future);
        match result {
            Ok(outcome) => Ok(FinishedPreparedExecve {
                outcome,
                context: terminal_context,
                handoff,
            }),
            Err(error) => Err(ExecTerminalFailure(Box::new(PendingExecTerminalError {
                error,
                pending: PendingExecTerminal {
                    context: terminal_context,
                    handoff,
                },
            }))),
        }
    }

    pub(super) fn begin_prepared_execve_drain(
        &mut self,
        kernel: &Kernel,
        current: super::continuation::JobId,
        mut prepared: PreparedExecve,
    ) -> Result<PreparedExecveDrain, ExecTerminalFailure> {
        let origin = match prepared.take_origin() {
            Ok(origin) => origin,
            Err(error) => return Err(ExecTerminalFailure::from_prepared(error, prepared)),
        };
        let completion_ownership = match self.take_authenticated_exec_completion_ownership(origin) {
            Ok(ownership) => ownership,
            Err(error) => return Err(ExecTerminalFailure::from_prepared(error, prepared)),
        };
        let drain = match self.begin_persistent_exec_sibling_drain(kernel, current) {
            Ok(drain) => drain,
            Err(error) => {
                drop(completion_ownership);
                return Err(ExecTerminalFailure::from_prepared(error, prepared));
            }
        };
        Ok(PreparedExecveDrain {
            prepared,
            drain,
            completion_ownership,
        })
    }

    #[cfg(test)]
    pub(super) fn prepared_execve_drain_for_test(
        &mut self,
        mut prepared: PreparedExecve,
        drain: super::continuation::ProcessDrain,
    ) -> Result<PreparedExecveDrain, ExecTerminalFailure> {
        let origin = match prepared.take_origin() {
            Ok(origin) => origin,
            Err(error) => return Err(ExecTerminalFailure::from_prepared(error, prepared)),
        };
        let completion_ownership = match self.take_authenticated_exec_completion_ownership(origin) {
            Ok(ownership) => ownership,
            Err(error) => return Err(ExecTerminalFailure::from_prepared(error, prepared)),
        };
        Ok(PreparedExecveDrain {
            prepared,
            drain,
            completion_ownership,
        })
    }

    pub(super) fn finish_prepared_execve_drain(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        current: &super::continuation::LogicalJobCompletion,
        owner: PreparedExecveDrain,
    ) -> Result<FinishedPreparedExecve, ExecTerminalFailure> {
        let PreparedExecveDrain {
            prepared,
            drain,
            completion_ownership,
        } = owner;
        let drain_result = self.finish_persistent_sibling_drain(current);
        drop(drain);
        if let Err(error) = drain_result {
            drop(completion_ownership);
            return Err(ExecTerminalFailure::from_prepared(error, prepared));
        }
        let result = self.finish_prepared_execve(kernel, engine, prepared);
        drop(completion_ownership);
        result
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super as exec;
    use super::super::tests::*;
    use super::super::*;
    use super::*;
    use crate::thread::{FutexTable, ThreadId, ThreadRegistry};
    use crate::vcpu_loop::executor::TaskBindingResolver;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use std::time::Instant;

    struct CompletionOrderObserver {
        events: Arc<Mutex<Vec<&'static str>>>,
        returns: Arc<Mutex<Vec<i64>>>,
    }

    impl crate::observe::SyscallObserver for CompletionOrderObserver {
        fn on_syscall_return(
            &self,
            _process: &crate::observe::ProcessInfo<'_>,
            _call: &crate::observe::SyscallInfo<'_>,
            outcome: &crate::observe::SyscallOutcome,
        ) {
            self.events.lock().push("observer");
            self.returns.lock().push(outcome.value);
        }
    }

    struct CountingEntryObserver {
        entries: Arc<std::sync::atomic::AtomicUsize>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl crate::observe::SyscallObserver for CountingEntryObserver {
        fn on_syscall(
            &self,
            _process: &crate::observe::ProcessInfo<'_>,
            _call: &crate::observe::SyscallInfo<'_>,
        ) -> crate::observe::SyscallAction {
            self.entries
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.events.lock().push("entry");
            crate::observe::SyscallAction::Allow
        }
    }

    struct CountingPreflightInterceptor {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl crate::observe::SyscallInterceptor for CountingPreflightInterceptor {
        fn intercept(
            &self,
            _process: &crate::observe::ProcessInfo<'_>,
            _call: &crate::observe::InterceptedSyscall<'_>,
        ) -> crate::observe::InterceptAction {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.events.lock().push("interceptor");
            crate::observe::InterceptAction::Continue
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ObservedCompletionIdentity {
        pid: i32,
        tid: i32,
        task: crate::kernel::TaskKey,
        container: crate::kernel::container::ContainerId,
        value: i64,
    }

    struct CompletionIdentityObserver(Arc<Mutex<Vec<ObservedCompletionIdentity>>>);

    impl crate::observe::SyscallObserver for CompletionIdentityObserver {
        fn on_syscall_return(
            &self,
            process: &crate::observe::ProcessInfo<'_>,
            _call: &crate::observe::SyscallInfo<'_>,
            outcome: &crate::observe::SyscallOutcome,
        ) {
            self.0.lock().push(ObservedCompletionIdentity {
                pid: process.pid(),
                tid: process.tid(),
                task: process.task_key(),
                container: process.container_id(),
                value: outcome.value,
            });
        }
    }

    struct ExecPreparationCounter(Arc<std::sync::atomic::AtomicUsize>);

    impl crate::observe::SyscallObserver for ExecPreparationCounter {
        fn on_exec(
            &self,
            _process: &crate::observe::ProcessInfo<'_>,
            _exe: &[u8],
            _argv: &[&[u8]],
        ) -> crate::observe::SyscallAction {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            crate::observe::SyscallAction::Allow
        }
    }

    fn typed_completion_fixture(
        pid: i32,
        dispatcher: SyscallDispatcher,
    ) -> (
        Arc<KernelState>,
        crate::kernel::KernelContext,
        ThreadRuntimeState<CrashCaptureTestEngine>,
    ) {
        let (process, root) = crate::hvpatch::process_context_for_tests(pid);
        dispatcher.bind_hvpatch_process(process.clone());
        let kernel = Arc::new(KernelState::new(
            dispatcher,
            Arc::new(EndpointTestSignalPump),
            Arc::new(EndpointTestSignalArrival),
            Some(process.clone()),
            None,
            None,
        ));
        let this_tid = ThreadId::synthetic_for_tests(pid);
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
            Arc::new(ThreadRegistry::new(this_tid)),
            Arc::new(FutexTable::new()),
            platform,
            platform_factory,
            kernel.process_fork_barrier.clone(),
            kernel.crash_capture.clone(),
            Some(Arc::clone(root.thread())),
            Some(process.pid()),
            root.thread().key().tid,
            kernel.fatal_signal.current_generation(),
            this_tid,
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(carrick_hal::GenericVcpuRegistry::new()),
            carrick_hal::InGuestFlag::for_guest_thread(),
            1_000,
        );
        state.service_kernel_context = Some(root.retain_exact());
        (kernel, root, state)
    }

    fn install_typed_guest_completion(
        kernel: &Kernel,
        context: &crate::kernel::KernelContext,
        state: &mut ThreadRuntimeState<CrashCaptureTestEngine>,
    ) -> PreparedSyscall {
        let prepared = kernel
            .dispatcher
            .prepare_syscall(
                context,
                SyscallRequest::new(92, crate::compat::SyscallArgs::from([0; 6])),
                &kernel.reporter,
            )
            .unwrap();
        let PreparedDispatch::Invoke(syscall) = prepared else {
            panic!("personality completion fixture must reach its handler")
        };
        state.syscall_completion = SyscallCompletionOwnership::Guest(SyscallCompletionToken::new(
            syscall,
            context.retain_exact(),
            kernel.dispatcher.observers().cloned(),
        ));
        syscall
    }

    #[test]
    fn guest_syscall_completion_owner_retains_token_inline() {
        assert!(
            std::mem::size_of::<SyscallCompletionOwnership>()
                >= std::mem::size_of::<SyscallCompletionToken>(),
            "the per-trap completion owner must retain its token inline rather than heap-allocate it"
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn interception_completion_dynamic_fork_and_clone_children_publish_once_at_bootstrap() {
        for (case, process_child) in [("fork", true), ("clone", false)] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let returns = Arc::new(Mutex::new(Vec::new()));
            let mut dispatcher = SyscallDispatcher::new();
            dispatcher.install_observer(Arc::new(CompletionOrderObserver {
                events: Arc::clone(&events),
                returns: Arc::clone(&returns),
            }));
            let pid = if process_child { 72_420 } else { 72_421 };
            let (kernel, context, mut state) = typed_completion_fixture(pid, dispatcher);
            install_typed_guest_completion(&kernel, &context, &mut state);
            let mut engine = CrashCaptureTestEngine::default();

            if process_child {
                bootstrap_hvpatch_process_child(
                    &kernel,
                    &mut state,
                    &mut engine,
                    ProcessChildBootstrap::GuestFork {
                        shares_mm: true,
                        child_settid: None,
                    },
                )
                .unwrap();
            } else {
                state
                    .complete_precompleted_child(&kernel.reporter, 0)
                    .unwrap();
            }

            assert!(state.syscall_completion.is_idle(), "{case}");
            assert!(engine.completed_syscalls.is_empty(), "{case}");
            assert_eq!(*returns.lock(), vec![0], "{case}");
            assert_eq!(kernel.reporter.snapshot().summary.syscall_invocations, 1);
            assert_eq!(kernel.reporter.snapshot().summary.syscall_returns_ok, 1);
            assert!(
                state
                    .complete_precompleted_child(&kernel.reporter, 0)
                    .is_err(),
                "{case} child bootstrap must consume exactly once"
            );
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn interception_completion_dynamic_fork_child_job_preserves_exact_observer_identity_once() {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let returns = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_observer(Arc::new(CompletionIdentityObserver(Arc::clone(&observed))));
        dispatcher.install_observer(Arc::new(CompletionOrderObserver {
            events: Arc::clone(&events),
            returns: Arc::clone(&returns),
        }));
        let (runtime, scheduler, kernel, root, process, root_generation) =
            test_carrier_graph_with_dispatcher!(72_425, dispatcher);
        let root_authority = runtime
            .persistent_bindings()
            .take_submission_authority(root.thread().key(), root_generation)
            .expect("root submission authority");
        let root_executor = scheduler
            .register_executor(Arc::new(RuntimeTestExecutorKick::default()))
            .expect("root executor");
        let mut root_running = scheduler.take(&root_executor).expect("take queued root");

        let this_tid = ThreadId::synthetic_for_tests(72_425);
        let registry = Arc::new(ThreadRegistry::new(this_tid));
        let kicker: Arc<dyn VcpuRegistry> = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
            registry,
            Arc::new(FutexTable::new()),
            platform,
            platform_factory,
            kernel.process_fork_barrier.clone(),
            kernel.crash_capture.clone(),
            Some(Arc::clone(root.thread())),
            Some(process.pid()),
            root.thread().key().tid,
            kernel.fatal_signal.current_generation(),
            this_tid,
            Arc::new(Mutex::new(Vec::new())),
            Arc::clone(&kicker),
            carrick_hal::InGuestFlag::for_guest_thread(),
            1_000,
        );
        *state.execution_lease.lock() = Some(root_running.take_lease());
        let mm_executor = kernel
            .dispatcher
            .enter_mm_executor_for_thread(Some(Arc::clone(root.thread())), kicker, this_tid)
            .expect("parent MM executor participation");
        state.guest_execution = Some(mm_executor);
        let frame = carrick_hal::RawSyscall {
            number: carrick_abi::CanonicalNr(220),
            args: [0; 6],
            guest_abi: carrick_abi::LinuxGuestAbi::Aarch64,
            native_number: carrick_abi::NativeNr(220),
        };
        let mut parent_engine = CrashCaptureTestEngine {
            completion_events: Some(Arc::clone(&events)),
            ..Default::default()
        };
        let outcome = state
            .service_threaded_syscall(&kernel, &mut parent_engine, frame)
            .expect("production parent fork dispatch");
        let DispatchOutcome::Fork {
            flags,
            pidfd_out,
            clone_parent,
            parent_tid_addr,
            child_tid_addr,
            exit_signal,
            child_stack,
            vfork,
        } = outcome
        else {
            panic!("clone syscall must route to process fork")
        };
        assert_eq!(kernel.reporter.snapshot().summary.syscall_invocations, 1);

        let need_resched = std::sync::atomic::AtomicBool::new(false);
        let mut parent_submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: Some(&root_authority),
            lease: None,
            exec_replacement: None,
        };
        let mut parent_control =
            executor::HvpatchQuantumControl::for_test(&need_resched, &mut parent_submission);
        let mut memory = Memory::default();
        let prepared = state
            .prepare_in_process_fork(
                &kernel,
                &root,
                &mut memory,
                &mut parent_control,
                &mut FakeBackendOps::default(),
                quiesce::ProcessForkAttempt {
                    request: quiesce::ForkRequest {
                        flags,
                        pidfd_out,
                        clone_parent,
                        parent_tid_addr,
                        child_tid_addr,
                        exit_signal,
                        child_stack,
                        vfork,
                    },
                    coordinator: None,
                    external_exec: None,
                },
            )
            .expect("actual guest fork publication");
        let child_pid = match &prepared {
            quiesce::PreparedInProcessFork::Complete(Some(child_pid)) => *child_pid,
            _ => panic!("guest fork must publish one child"),
        };
        let mut job =
            suffix_failure_test_job(&kernel, state, HvpatchProductionPhase::Resident, None);
        assert!(matches!(
            job.complete_persistent_process_fork(
                &mut parent_engine,
                &mut parent_control,
                Some(frame),
                None,
                prepared,
            )
            .expect("production parent fork completion"),
            executor::ExecutorExit::Syscall
        ));
        assert_eq!(parent_engine.completed_syscalls, vec![child_pid]);
        assert_eq!(*events.lock(), vec!["engine", "observer"]);
        assert_eq!(*returns.lock(), vec![child_pid]);
        assert!(job.state.syscall_completion.is_idle());

        let child_id =
            crate::kernel::TaskId::for_root_bootstrap(child_pid as i32).expect("child task id");
        let child_context = root
            .kernel()
            .context(child_id, crate::kernel::LinuxTid::for_task_leader(child_id))
            .expect("published child context");
        let child_generation = child_context
            .thread()
            .execution_state()
            .generation()
            .expect("child execution generation");
        let child_binding = runtime
            .persistent_bindings()
            .resolve(child_context.thread().key(), child_generation)
            .expect("active child binding");
        let child_authority = runtime
            .persistent_bindings()
            .take_submission_authority(child_context.thread().key(), child_generation)
            .expect("child submission authority");
        let child_executor = scheduler
            .register_executor(Arc::new(RuntimeTestExecutorKick::default()))
            .expect("child executor");
        let mut child_running = scheduler.take(&child_executor).expect("take queued child");
        assert_eq!(child_running.thread_key(), child_context.thread().key());

        let mut child_engine = CrashCaptureTestEngine::default();
        let mut child_submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: Some(&child_authority),
            lease: Some(child_running.take_lease()),
            exec_replacement: None,
        };
        let (first, second) = {
            let mut child_control =
                executor::HvpatchQuantumControl::for_test(&need_resched, &mut child_submission);
            let first = child_binding
                .quantum()
                .poll_quantum_with_engine(&mut child_engine, &mut child_control);
            let second = child_binding
                .quantum()
                .poll_quantum_with_engine(&mut child_engine, &mut child_control);
            (first, second)
        };
        assert!(matches!(first, executor::ExecutorExit::Syscall));
        assert!(matches!(second, executor::ExecutorExit::Syscall));
        child_running
            .restore_lease(child_submission.lease.take().expect("returned child lease"))
            .expect("restore child lease");
        scheduler
            .settle_runnable(child_running)
            .expect("settle child after bootstrap");
        root_running
            .restore_lease(
                job.state
                    .execution_lease
                    .lock()
                    .take()
                    .expect("returned parent lease"),
            )
            .expect("restore parent lease");
        scheduler
            .settle_runnable(root_running)
            .expect("settle parent after fork");
        drop(child_authority);
        drop(root_authority);

        assert!(child_engine.completed_syscalls.is_empty());
        assert_eq!(*events.lock(), vec!["engine", "observer", "observer"]);
        assert_eq!(*returns.lock(), vec![child_pid, 0]);
        let completions = observed.lock();
        assert_eq!(
            completions.len(),
            2,
            "second quantum must not republish fork return"
        );
        assert_eq!(
            completions[0],
            ObservedCompletionIdentity {
                pid: process.pid(),
                tid: root.thread().key().tid.raw(),
                task: root.task().key(),
                container: root.task().container().id(),
                value: child_pid,
            }
        );
        assert_eq!(
            completions[1],
            ObservedCompletionIdentity {
                pid: child_pid as i32,
                tid: child_pid as i32,
                task: child_context.task().key(),
                container: child_context.task().container().id(),
                value: 0,
            }
        );
        assert_eq!(kernel.reporter.snapshot().summary.syscall_invocations, 1);
        assert_eq!(kernel.reporter.snapshot().summary.syscall_returns_ok, 1);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn interception_completion_dynamic_clone_child_job_preserves_exact_observer_identity_once() {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let returns = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_observer(Arc::new(CompletionIdentityObserver(Arc::clone(&observed))));
        dispatcher.install_observer(Arc::new(CompletionOrderObserver {
            events: Arc::clone(&events),
            returns: Arc::clone(&returns),
        }));
        let (runtime, scheduler, kernel, root, process, root_generation) =
            test_carrier_graph_with_dispatcher!(72_426, dispatcher);
        let root_authority = runtime
            .persistent_bindings()
            .take_submission_authority(root.thread().key(), root_generation)
            .expect("root submission authority");
        let root_executor = scheduler
            .register_executor(Arc::new(RuntimeTestExecutorKick::default()))
            .expect("root executor");
        let mut root_running = scheduler.take(&root_executor).expect("take queued root");

        let this_tid = ThreadId::synthetic_for_tests(72_426);
        let registry = Arc::new(ThreadRegistry::new(this_tid));
        let kicker: Arc<dyn VcpuRegistry> = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
            registry,
            Arc::new(FutexTable::new()),
            platform,
            platform_factory,
            kernel.process_fork_barrier.clone(),
            kernel.crash_capture.clone(),
            Some(Arc::clone(root.thread())),
            Some(process.pid()),
            root.thread().key().tid,
            kernel.fatal_signal.current_generation(),
            this_tid,
            Arc::new(Mutex::new(Vec::new())),
            Arc::clone(&kicker),
            carrick_hal::InGuestFlag::for_guest_thread(),
            1_000,
        );
        *state.execution_lease.lock() = Some(root_running.take_lease());
        state.guest_execution = Some(
            kernel
                .dispatcher
                .enter_mm_executor_for_thread(Some(Arc::clone(root.thread())), kicker, this_tid)
                .expect("parent MM executor participation"),
        );
        let flags = (carrick_abi::LinuxCloneFlags::THREAD
            | carrick_abi::LinuxCloneFlags::SIGHAND
            | carrick_abi::LinuxCloneFlags::VM)
            .bits();
        let frame = carrick_hal::RawSyscall {
            number: carrick_abi::CanonicalNr(220),
            args: [flags, 0x9000, 0, 0, 0, 0],
            guest_abi: carrick_abi::LinuxGuestAbi::Aarch64,
            native_number: carrick_abi::NativeNr(220),
        };
        let mut parent_engine = CrashCaptureTestEngine {
            completion_events: Some(Arc::clone(&events)),
            ..Default::default()
        };
        let outcome = state
            .service_threaded_syscall(&kernel, &mut parent_engine, frame)
            .expect("production parent clone dispatch");
        let DispatchOutcome::CloneThread {
            stack,
            tls,
            flags,
            parent_tid_addr,
            child_tid_addr,
            clear_child_tid_addr,
        } = outcome
        else {
            panic!("thread clone flags must route to persistent thread clone")
        };

        let job_result = HvpatchLoopResult::pending();
        let job_completion = continuation::LogicalJobCompletion::pending();
        let mut job = ProductionHvpatchLoopJob {
            kernel: Arc::clone(&kernel),
            state,
            phase: HvpatchProductionPhase::Resident,
            registration_wait: None,
            terminal_settlement: HvpatchExternalTerminalSettlement::new(
                job_result,
                job_completion.clone(),
            ),
            terminal_result: None,
            completion: job_completion,
            traps: 0,
            budget_floor: 0,
            seen_signal_progress: signal_progress_count(),
            last_signal_progress: Instant::now(),
            terminal_runtime: PersistentTerminalRuntimeState::Resident,
            pending_terminal_retirement: None,
            pending_terminal_inventory: None,
            external_exec: None,
        };
        let need_resched = std::sync::atomic::AtomicBool::new(false);
        let mut parent_submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: Some(&root_authority),
            lease: None,
            exec_replacement: None,
        };
        let mut parent_control =
            executor::HvpatchQuantumControl::for_test(&need_resched, &mut parent_submission);
        let mut memory = Memory::default();
        let spawned = job
            .spawn_persistent_hvpatch_clone_thread(
                &mut memory,
                &mut parent_control,
                &root,
                HvpatchCloneThreadRequest {
                    stack,
                    tls,
                    flags,
                    parent_tid_addr,
                    child_tid_addr,
                    clear_child_tid_addr,
                },
                None,
                &mut DynamicCloneBackendOps,
            )
            .expect("actual persistent clone publication");
        let PersistentHvpatchCloneAttempt::Complete(threads::CloneThreadSpawn::Started {
            internal: child_tid,
            visible: child_visible_tid,
        }) = spawned
        else {
            panic!("persistent clone must start one child thread")
        };
        assert!(matches!(
            job.complete_persistent_hvpatch_clone(
                &mut parent_engine,
                threads::CloneThreadSpawn::Started {
                    internal: child_tid,
                    visible: child_visible_tid,
                },
            )
            .expect("parent clone completion"),
            executor::ExecutorExit::Syscall
        ));

        let child_context = root
            .kernel()
            .context(root.task().key().id, child_tid)
            .expect("published clone context");
        let child_generation = child_context
            .thread()
            .execution_state()
            .generation()
            .expect("child execution generation");
        let child_binding = runtime
            .persistent_bindings()
            .resolve(child_context.thread().key(), child_generation)
            .expect("active child binding");
        let child_authority = runtime
            .persistent_bindings()
            .take_submission_authority(child_context.thread().key(), child_generation)
            .expect("child submission authority");
        let child_executor = scheduler
            .register_executor(Arc::new(RuntimeTestExecutorKick::default()))
            .expect("child executor");
        let mut child_running = scheduler.take(&child_executor).expect("take queued child");
        assert_eq!(child_running.thread_key(), child_context.thread().key());

        let mut child_engine = CrashCaptureTestEngine::default();
        let mut child_submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: Some(&child_authority),
            lease: Some(child_running.take_lease()),
            exec_replacement: None,
        };
        let (first, second) = {
            let mut child_control =
                executor::HvpatchQuantumControl::for_test(&need_resched, &mut child_submission);
            let first = child_binding
                .quantum()
                .poll_quantum_with_engine(&mut child_engine, &mut child_control);
            let second = child_binding
                .quantum()
                .poll_quantum_with_engine(&mut child_engine, &mut child_control);
            (first, second)
        };
        assert!(matches!(first, executor::ExecutorExit::Syscall));
        assert!(matches!(second, executor::ExecutorExit::Syscall));
        child_running
            .restore_lease(child_submission.lease.take().expect("returned child lease"))
            .expect("restore child lease");
        scheduler
            .settle_runnable(child_running)
            .expect("settle child after bootstrap");
        root_running
            .restore_lease(
                job.state
                    .execution_lease
                    .lock()
                    .take()
                    .expect("returned parent lease"),
            )
            .expect("restore parent lease");
        scheduler
            .settle_runnable(root_running)
            .expect("settle parent after clone");
        drop(child_authority);
        drop(root_authority);

        assert_eq!(
            parent_engine.completed_syscalls,
            vec![i64::from(child_visible_tid)]
        );
        assert!(child_engine.completed_syscalls.is_empty());
        assert_eq!(*events.lock(), vec!["engine", "observer", "observer"]);
        assert_eq!(*returns.lock(), vec![i64::from(child_visible_tid), 0]);
        let completions = observed.lock();
        assert_eq!(
            completions.len(),
            2,
            "second child quantum must not republish"
        );
        assert_eq!(
            completions[0],
            ObservedCompletionIdentity {
                pid: process.pid(),
                tid: root.thread().key().tid.raw(),
                task: root.task().key(),
                container: root.task().container().id(),
                value: i64::from(child_visible_tid),
            }
        );
        assert_eq!(
            completions[1],
            ObservedCompletionIdentity {
                pid: process.pid(),
                tid: child_tid.raw(),
                task: root.task().key(),
                container: root.task().container().id(),
                value: 0,
            }
        );
        assert_eq!(kernel.reporter.snapshot().summary.syscall_invocations, 1);
        assert_eq!(kernel.reporter.snapshot().summary.syscall_returns_ok, 2);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn interception_completion_dynamic_timeout_and_interruption_resume_through_scheduler_once() {
        for (case, interrupted, expected) in [
            ("timeout", false, 0),
            (
                "interruption",
                true,
                crate::linux_abi::LINUX_EINTR.guest_retval(),
            ),
        ] {
            let interceptor_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let events = Arc::new(Mutex::new(Vec::new()));
            let returns = Arc::new(Mutex::new(Vec::new()));
            let mut dispatcher = SyscallDispatcher::new();
            dispatcher.install_interceptor(Arc::new(CountingPreflightInterceptor {
                calls: Arc::clone(&interceptor_calls),
                events: Arc::clone(&events),
            }));
            dispatcher.install_observer(Arc::new(CompletionOrderObserver {
                events: Arc::clone(&events),
                returns: Arc::clone(&returns),
            }));
            let pid = if interrupted { 72_428 } else { 72_427 };
            let (runtime, scheduler, kernel, root, process, root_generation) =
                test_carrier_graph_with_dispatcher!(pid, dispatcher);
            let root_authority = runtime
                .persistent_bindings()
                .take_submission_authority(root.thread().key(), root_generation)
                .expect("root submission authority");
            let root_executor = scheduler
                .register_executor(Arc::new(RuntimeTestExecutorKick::default()))
                .expect("root executor");
            let mut root_running = scheduler.take(&root_executor).expect("take queued root");

            let this_tid = ThreadId::synthetic_for_tests(pid);
            let kicker: Arc<dyn VcpuRegistry> = Arc::new(carrick_hal::GenericVcpuRegistry::new());
            let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
            let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
            let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
                Arc::new(ThreadRegistry::new(this_tid)),
                Arc::new(FutexTable::new()),
                platform,
                platform_factory,
                kernel.process_fork_barrier.clone(),
                kernel.crash_capture.clone(),
                Some(Arc::clone(root.thread())),
                Some(process.pid()),
                root.thread().key().tid,
                kernel.fatal_signal.current_generation(),
                this_tid,
                Arc::new(Mutex::new(Vec::new())),
                Arc::clone(&kicker),
                carrick_hal::InGuestFlag::for_guest_thread(),
                1_000,
            );
            state.guest_execution = Some(
                kernel
                    .dispatcher
                    .enter_mm_executor_for_thread(Some(Arc::clone(root.thread())), kicker, this_tid)
                    .expect("root MM executor participation"),
            );
            let request_address = 0x20_000;
            let duration = if interrupted {
                Duration::from_secs(60)
            } else {
                Duration::from_millis(1)
            };
            let mut timespec = Vec::with_capacity(16);
            timespec.extend_from_slice(&(duration.as_secs() as i64).to_le_bytes());
            timespec.extend_from_slice(&(i64::from(duration.subsec_nanos())).to_le_bytes());
            let frame = carrick_hal::RawSyscall {
                number: carrick_abi::CanonicalNr(101),
                args: [request_address, 0, 0, 0, 0, 0],
                guest_abi: carrick_abi::LinuxGuestAbi::Aarch64,
                native_number: carrick_abi::NativeNr(101),
            };
            let mut engine = CrashCaptureTestEngine {
                completion_events: Some(Arc::clone(&events)),
                guest_memory: [(request_address, timespec)].into(),
                ..Default::default()
            };
            let outcome = state
                .service_threaded_syscall(&kernel, &mut engine, frame)
                .expect("production nanosleep dispatch");
            assert!(
                matches!(outcome, DispatchOutcome::WaitOnSleep { .. }),
                "{case}"
            );
            assert_eq!(kernel.reporter.snapshot().summary.syscall_invocations, 1);

            let job_result = HvpatchLoopResult::pending();
            let job_completion = continuation::LogicalJobCompletion::pending();
            let mut job = ProductionHvpatchLoopJob {
                kernel: Arc::clone(&kernel),
                state,
                phase: HvpatchProductionPhase::Resident,
                registration_wait: None,
                terminal_settlement: HvpatchExternalTerminalSettlement::new(
                    job_result,
                    job_completion.clone(),
                ),
                terminal_result: None,
                completion: job_completion,
                traps: 0,
                budget_floor: 0,
                seen_signal_progress: signal_progress_count(),
                last_signal_progress: Instant::now(),
                terminal_runtime: PersistentTerminalRuntimeState::Resident,
                pending_terminal_retirement: None,
                pending_terminal_inventory: None,
                external_exec: None,
            };
            let need_resched = std::sync::atomic::AtomicBool::new(false);
            let mut submission = executor::ExecutorSubmissionContext {
                scheduler: &scheduler,
                publish_test_descendant: &|_, _| unreachable!(),
                current: Some(&root_authority),
                lease: Some(root_running.take_lease()),
                exec_replacement: None,
            };
            let blocked_exit = {
                let mut control =
                    executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
                job.service_outcome(&mut engine, &mut control, frame, outcome)
                    .expect("production continuation capture")
            };
            let executor::ExecutorExit::BlockedContinuation {
                continuation,
                vfork_activation: None,
            } = blocked_exit
            else {
                panic!("{case} must suspend as a typed continuation")
            };
            let wait_service = runtime.continuation_services(root.kernel()).1;
            let mut registration = wait_service.prepare_registration(&continuation);
            wait_service
                .enroll(&mut registration)
                .expect("enroll real wait-service continuation");
            root_running
                .restore_lease(submission.lease.take().expect("returned blocked lease"))
                .expect("restore blocked lease");
            scheduler
                .settle_blocked_continuation(root_running, *continuation, registration)
                .expect("settle Kernel-owned continuation");

            if interrupted {
                let signal =
                    crate::kernel::LinuxSignal::for_signal_number(crate::linux_abi::LINUX_SIGUSR1)
                        .expect("SIGUSR1");
                let mut action = carrick_abi::LinuxSigaction::empty();
                action.sa_handler = 0x4000;
                root.signal_authority().install_action(signal, action);
                let ticket = match root.kernel().authorize_signal_target_exact(
                    &root,
                    root.task().key(),
                    Some(root.thread().key()),
                    Some(signal),
                ) {
                    crate::kernel::ExactSignalTargetAuthorization::Allowed(ticket) => ticket,
                    other => panic!("authorize exact continuation signal: {other:?}"),
                };
                assert_eq!(
                    root.kernel()
                        .post_guest_thread_signal_to_authorized_target(&ticket, signal, None),
                    crate::kernel::ExactThreadSignalPost::Posted(Some(root.thread().key()))
                );
            }

            let deadline = Instant::now() + Duration::from_secs(2);
            let mut resumed_running = loop {
                match scheduler.take(&root_executor) {
                    Ok(running) => break running,
                    Err(crate::kernel::scheduler::RunQueueError::QueueEmpty) => {}
                    Err(error) => panic!("{case} scheduler take: {error}"),
                }
                assert!(
                    Instant::now() < deadline,
                    "{case} continuation did not wake"
                );
                std::thread::yield_now();
            };
            let mut resumed_submission = executor::ExecutorSubmissionContext {
                scheduler: &scheduler,
                publish_test_descendant: &|_, _| unreachable!(),
                current: Some(&root_authority),
                lease: Some(resumed_running.take_lease()),
                exec_replacement: None,
            };
            let resumed = {
                let mut control = executor::HvpatchQuantumControl::for_test(
                    &need_resched,
                    &mut resumed_submission,
                );
                job.poll_with_engine(&mut engine, &mut control)
                    .expect("production ResumeBlocked completion")
            };
            assert!(matches!(resumed, executor::ExecutorExit::Syscall), "{case}");
            resumed_running
                .restore_lease(
                    resumed_submission
                        .lease
                        .take()
                        .expect("returned resumed lease"),
                )
                .expect("restore resumed lease");
            scheduler
                .settle_runnable(resumed_running)
                .expect("settle resumed syscall");
            drop(root_authority);

            assert_eq!(
                interceptor_calls.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "{case}"
            );
            assert_eq!(engine.completed_syscalls, vec![expected], "{case}");
            assert_eq!(
                *events.lock(),
                vec!["interceptor", "engine", "observer"],
                "{case}"
            );
            assert_eq!(*returns.lock(), vec![expected], "{case}");
            assert!(job.state.syscall_completion.is_idle(), "{case}");
            assert_eq!(kernel.reporter.snapshot().summary.syscall_invocations, 1);
            assert_eq!(
                kernel.reporter.snapshot().summary.syscall_returns_ok,
                usize::from(!interrupted) as u64,
                "{case}"
            );
            assert_eq!(
                kernel.reporter.snapshot().summary.syscall_returns_errno,
                usize::from(interrupted) as u64,
                "{case}"
            );
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn interception_completion_dynamic_readiness_once_and_twice_redispatches_handler_only() {
        for redispatches in [1, 2] {
            let interceptor_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let entry_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let events = Arc::new(Mutex::new(Vec::new()));
            let returns = Arc::new(Mutex::new(Vec::new()));
            let mut dispatcher = SyscallDispatcher::new();
            dispatcher.install_interceptor(Arc::new(CountingPreflightInterceptor {
                calls: Arc::clone(&interceptor_calls),
                events: Arc::clone(&events),
            }));
            dispatcher.install_observer(Arc::new(CountingEntryObserver {
                entries: Arc::clone(&entry_calls),
                events: Arc::clone(&events),
            }));
            dispatcher.install_observer(Arc::new(CompletionOrderObserver {
                events: Arc::clone(&events),
                returns: Arc::clone(&returns),
            }));
            let pid = 72_430 + redispatches;
            let (runtime, scheduler, kernel, root, process, root_generation) =
                test_carrier_graph_with_dispatcher!(pid, dispatcher);
            let root_authority = runtime
                .persistent_bindings()
                .take_submission_authority(root.thread().key(), root_generation)
                .expect("root submission authority");
            let root_executor = scheduler
                .register_executor(Arc::new(RuntimeTestExecutorKick::default()))
                .expect("root executor");
            let mut running = scheduler.take(&root_executor).expect("take queued root");

            let this_tid = ThreadId::synthetic_for_tests(pid);
            let kicker: Arc<dyn VcpuRegistry> = Arc::new(carrick_hal::GenericVcpuRegistry::new());
            let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
            let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
            let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
                Arc::new(ThreadRegistry::new(this_tid)),
                Arc::new(FutexTable::new()),
                platform,
                platform_factory,
                kernel.process_fork_barrier.clone(),
                kernel.crash_capture.clone(),
                Some(Arc::clone(root.thread())),
                Some(process.pid()),
                root.thread().key().tid,
                kernel.fatal_signal.current_generation(),
                this_tid,
                Arc::new(Mutex::new(Vec::new())),
                Arc::clone(&kicker),
                carrick_hal::InGuestFlag::for_guest_thread(),
                1_000,
            );
            state.guest_execution = Some(
                kernel
                    .dispatcher
                    .enter_mm_executor_for_thread(Some(Arc::clone(root.thread())), kicker, this_tid)
                    .expect("root MM executor participation"),
            );
            let request_address = 0x21_000;
            let duration = Duration::from_millis(250);
            let mut timespec = Vec::with_capacity(16);
            timespec.extend_from_slice(&(duration.as_secs() as i64).to_le_bytes());
            timespec.extend_from_slice(&(i64::from(duration.subsec_nanos())).to_le_bytes());
            let frame = carrick_hal::RawSyscall {
                number: carrick_abi::CanonicalNr(101),
                args: [request_address, 0, 0, 0, 0, 0],
                guest_abi: carrick_abi::LinuxGuestAbi::Aarch64,
                native_number: carrick_abi::NativeNr(101),
            };
            let mut engine = CrashCaptureTestEngine {
                completion_events: Some(Arc::clone(&events)),
                guest_memory: [(request_address, timespec)].into(),
                ..Default::default()
            };
            let outcome = state
                .service_threaded_syscall(&kernel, &mut engine, frame)
                .expect("production nanosleep dispatch");
            assert!(matches!(outcome, DispatchOutcome::WaitOnSleep { .. }));

            let job_result = HvpatchLoopResult::pending();
            let job_completion = continuation::LogicalJobCompletion::pending();
            let mut job = ProductionHvpatchLoopJob {
                kernel: Arc::clone(&kernel),
                state,
                phase: HvpatchProductionPhase::Resident,
                registration_wait: None,
                terminal_settlement: HvpatchExternalTerminalSettlement::new(
                    job_result,
                    job_completion.clone(),
                ),
                terminal_result: None,
                completion: job_completion,
                traps: 0,
                budget_floor: 0,
                seen_signal_progress: signal_progress_count(),
                last_signal_progress: Instant::now(),
                terminal_runtime: PersistentTerminalRuntimeState::Resident,
                pending_terminal_retirement: None,
                pending_terminal_inventory: None,
                external_exec: None,
            };
            let need_resched = std::sync::atomic::AtomicBool::new(false);
            let mut submission = executor::ExecutorSubmissionContext {
                scheduler: &scheduler,
                publish_test_descendant: &|_, _| unreachable!(),
                current: Some(&root_authority),
                lease: Some(running.take_lease()),
                exec_replacement: None,
            };
            let mut next_exit = {
                let mut control =
                    executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
                job.service_outcome(&mut engine, &mut control, frame, outcome)
                    .expect("initial production continuation")
            };
            let wait_service = runtime.continuation_services(root.kernel()).1;

            for readiness in 0..redispatches {
                let executor::ExecutorExit::BlockedContinuation {
                    continuation,
                    vfork_activation: None,
                } = next_exit
                else {
                    panic!("readiness {readiness} did not retain a typed continuation")
                };
                let mut registration = wait_service.prepare_registration(&continuation);
                let token = registration.wake_token();
                wait_service
                    .enroll(&mut registration)
                    .expect("enroll readiness continuation");
                running
                    .restore_lease(submission.lease.take().expect("returned blocked lease"))
                    .expect("restore blocked lease");
                scheduler
                    .settle_blocked_continuation(running, *continuation, registration)
                    .expect("settle readiness continuation");
                assert!(
                    wait_service.publish_ready(token).accepted(),
                    "readiness {readiness} must win exactly once"
                );
                let deadline = Instant::now() + Duration::from_secs(2);
                running = loop {
                    match scheduler.take(&root_executor) {
                        Ok(running) => break running,
                        Err(crate::kernel::scheduler::RunQueueError::QueueEmpty) => {}
                        Err(error) => panic!("readiness {readiness} scheduler take: {error}"),
                    }
                    assert!(
                        Instant::now() < deadline,
                        "readiness {readiness} did not wake"
                    );
                    std::thread::yield_now();
                };
                submission.lease = Some(running.take_lease());
                next_exit = {
                    let mut control =
                        executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
                    job.poll_with_engine(&mut engine, &mut control)
                        .expect("handler-only readiness redispatch")
                };
                assert!(
                    matches!(
                        next_exit,
                        executor::ExecutorExit::BlockedContinuation { .. }
                    ),
                    "readiness {readiness} must redispatch the nanosleep handler and re-park"
                );
                assert!(engine.completed_syscalls.is_empty());
                assert!(returns.lock().is_empty());
            }

            let executor::ExecutorExit::BlockedContinuation {
                continuation,
                vfork_activation: None,
            } = next_exit
            else {
                panic!("final timer continuation missing")
            };
            let mut registration = wait_service.prepare_registration(&continuation);
            wait_service
                .enroll(&mut registration)
                .expect("enroll final timer continuation");
            running
                .restore_lease(
                    submission
                        .lease
                        .take()
                        .expect("returned final blocked lease"),
                )
                .expect("restore final blocked lease");
            scheduler
                .settle_blocked_continuation(running, *continuation, registration)
                .expect("settle final timer continuation");
            let deadline = Instant::now() + Duration::from_secs(2);
            running = loop {
                match scheduler.take(&root_executor) {
                    Ok(running) => break running,
                    Err(crate::kernel::scheduler::RunQueueError::QueueEmpty) => {}
                    Err(error) => panic!("final timer scheduler take: {error}"),
                }
                assert!(Instant::now() < deadline, "final timer did not wake");
                std::thread::yield_now();
            };
            submission.lease = Some(running.take_lease());
            let final_exit = {
                let mut control =
                    executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
                job.poll_with_engine(&mut engine, &mut control)
                    .expect("final timer completion")
            };
            assert!(matches!(final_exit, executor::ExecutorExit::Syscall));
            running
                .restore_lease(submission.lease.take().expect("returned final lease"))
                .expect("restore final lease");
            scheduler
                .settle_runnable(running)
                .expect("settle completed nanosleep");
            drop(root_authority);

            assert_eq!(
                interceptor_calls.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "redispatch count {redispatches} reran the interceptor"
            );
            assert_eq!(
                entry_calls.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "redispatch count {redispatches} reran user entry observers"
            );
            assert_eq!(engine.completed_syscalls, vec![0]);
            assert_eq!(
                *events.lock(),
                vec!["interceptor", "entry", "engine", "observer"]
            );
            assert_eq!(*returns.lock(), vec![0]);
            assert!(job.state.syscall_completion.is_idle());
            assert_eq!(kernel.reporter.snapshot().summary.syscall_invocations, 1);
            assert_eq!(kernel.reporter.snapshot().summary.syscall_returns_ok, 1);
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn interception_completion_dynamic_blocking_partial_runs_driver_before_one_publication() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let returns = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_observer(Arc::new(CompletionOrderObserver {
            events: Arc::clone(&events),
            returns: Arc::clone(&returns),
        }));
        let (runtime, scheduler, kernel, root, process, root_generation) =
            test_carrier_graph_with_dispatcher!(72_433, dispatcher);
        let root_authority = runtime
            .persistent_bindings()
            .take_submission_authority(root.thread().key(), root_generation)
            .expect("root submission authority");
        let root_executor = scheduler
            .register_executor(Arc::new(RuntimeTestExecutorKick::default()))
            .expect("root executor");
        let mut running = scheduler.take(&root_executor).expect("take queued root");

        let this_tid = ThreadId::synthetic_for_tests(72_433);
        let kicker: Arc<dyn VcpuRegistry> = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
            Arc::new(ThreadRegistry::new(this_tid)),
            Arc::new(FutexTable::new()),
            platform,
            platform_factory,
            kernel.process_fork_barrier.clone(),
            kernel.crash_capture.clone(),
            Some(Arc::clone(root.thread())),
            Some(process.pid()),
            root.thread().key().tid,
            kernel.fatal_signal.current_generation(),
            this_tid,
            Arc::new(Mutex::new(Vec::new())),
            Arc::clone(&kicker),
            carrick_hal::InGuestFlag::for_guest_thread(),
            1_000,
        );
        state.guest_execution = Some(
            kernel
                .dispatcher
                .enter_mm_executor_for_thread(Some(Arc::clone(root.thread())), kicker, this_tid)
                .expect("root MM executor participation"),
        );
        let frame = carrick_hal::RawSyscall {
            number: carrick_abi::CanonicalNr(92),
            args: [0; 6],
            guest_abi: carrick_abi::LinuxGuestAbi::Aarch64,
            native_number: carrick_abi::NativeNr(92),
        };
        let mut engine = CrashCaptureTestEngine {
            completion_events: Some(Arc::clone(&events)),
            ..Default::default()
        };
        let handler_outcome = state
            .service_threaded_syscall(&kernel, &mut engine, frame)
            .expect("production preflight and handler");
        assert!(matches!(handler_outcome, DispatchOutcome::Returned { .. }));

        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let write = crate::dispatch::BlockingHostWrite::for_tests(
            fds[1],
            vec![1, 2, 3, 4],
            2,
            this_tid,
            true,
        )
        .expect("partial blocking write");
        assert_eq!(unsafe { libc::close(fds[0]) }, 0);
        assert_eq!(unsafe { libc::close(fds[1]) }, 0);

        let job_result = HvpatchLoopResult::pending();
        let job_completion = continuation::LogicalJobCompletion::pending();
        let mut job = ProductionHvpatchLoopJob {
            kernel: Arc::clone(&kernel),
            state,
            phase: HvpatchProductionPhase::Resident,
            registration_wait: None,
            terminal_settlement: HvpatchExternalTerminalSettlement::new(
                job_result,
                job_completion.clone(),
            ),
            terminal_result: None,
            completion: job_completion,
            traps: 0,
            budget_floor: 0,
            seen_signal_progress: signal_progress_count(),
            last_signal_progress: Instant::now(),
            terminal_runtime: PersistentTerminalRuntimeState::Resident,
            pending_terminal_retirement: None,
            pending_terminal_inventory: None,
            external_exec: None,
        };
        let need_resched = std::sync::atomic::AtomicBool::new(false);
        let mut submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: Some(&root_authority),
            lease: Some(running.take_lease()),
            exec_replacement: None,
        };
        let blocked_exit = {
            let mut control =
                executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
            job.service_outcome(
                &mut engine,
                &mut control,
                frame,
                DispatchOutcome::BlockingHostWrite(write),
            )
            .expect("production blocking-write continuation")
        };
        let executor::ExecutorExit::BlockedContinuation {
            continuation,
            vfork_activation: None,
        } = blocked_exit
        else {
            panic!("blocking partial must park in the production driver")
        };
        let wait_service = runtime.continuation_services(root.kernel()).1;
        let mut registration = wait_service.prepare_registration(&continuation);
        wait_service
            .enroll(&mut registration)
            .expect("enroll blocking-write driver");
        running
            .restore_lease(submission.lease.take().expect("returned blocked lease"))
            .expect("restore blocked lease");
        scheduler
            .settle_blocked_continuation(running, *continuation, registration)
            .expect("settle blocking-write continuation");

        let deadline = Instant::now() + Duration::from_secs(2);
        running = loop {
            match scheduler.take(&root_executor) {
                Ok(running) => break running,
                Err(crate::kernel::scheduler::RunQueueError::QueueEmpty) => {}
                Err(error) => panic!("blocking-write scheduler take: {error}"),
            }
            assert!(
                Instant::now() < deadline,
                "blocking-write driver did not wake"
            );
            std::thread::yield_now();
        };
        submission.lease = Some(running.take_lease());
        let final_exit = {
            let mut control =
                executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
            job.poll_with_engine(&mut engine, &mut control)
                .expect("production blocking-write completion")
        };
        assert!(matches!(final_exit, executor::ExecutorExit::Syscall));
        running
            .restore_lease(submission.lease.take().expect("returned final lease"))
            .expect("restore final lease");
        scheduler
            .settle_runnable(running)
            .expect("settle completed blocking write");
        drop(root_authority);

        assert_eq!(engine.completed_syscalls, vec![2]);
        assert_eq!(*events.lock(), vec!["engine", "observer"]);
        assert_eq!(*returns.lock(), vec![2]);
        assert!(job.state.syscall_completion.is_idle());
        assert_eq!(kernel.reporter.snapshot().summary.syscall_invocations, 1);
        assert_eq!(kernel.reporter.snapshot().summary.syscall_returns_ok, 1);
    }

    #[test]
    fn interception_completion_dynamic_signal_and_partial_return_publish_after_engine_once() {
        for (case, value, signal_path) in [("signal", 0, true), ("partial-write", 3, false)] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let returns = Arc::new(Mutex::new(Vec::new()));
            let mut dispatcher = SyscallDispatcher::new();
            dispatcher.install_observer(Arc::new(CompletionOrderObserver {
                events: Arc::clone(&events),
                returns: Arc::clone(&returns),
            }));
            let pid = if signal_path { 72_422 } else { 72_423 };
            let (kernel, context, mut state) = typed_completion_fixture(pid, dispatcher);
            install_typed_guest_completion(&kernel, &context, &mut state);
            let mut engine = CrashCaptureTestEngine {
                completion_events: Some(Arc::clone(&events)),
                ..Default::default()
            };

            let completed = if signal_path {
                let target = ThreadId::synthetic_for_tests(context.thread().key().tid.raw());
                state
                    .complete_signal_thread(
                        &kernel,
                        &mut engine,
                        target,
                        crate::linux_abi::LINUX_SIGUSR1,
                        Some(context.thread().key()),
                    )
                    .unwrap()
            } else {
                state
                    .complete_returned(&mut engine, &kernel.reporter, value)
                    .unwrap()
            };

            assert_eq!(completed, value, "{case}");
            assert_eq!(engine.completed_syscalls, vec![value], "{case}");
            assert_eq!(*events.lock(), vec!["engine", "observer"], "{case}");
            assert_eq!(*returns.lock(), vec![value], "{case}");
            assert_eq!(kernel.reporter.snapshot().summary.syscall_invocations, 1);
            assert_eq!(kernel.reporter.snapshot().summary.syscall_returns_ok, 1);
            assert!(
                state
                    .complete_returned(&mut engine, &kernel.reporter, value)
                    .is_err(),
                "{case} completion token must be single-use"
            );
            assert_eq!(engine.completed_syscalls, vec![value], "{case}");
        }
    }

    #[test]
    fn interception_completion_dynamic_guest_exec_failure_completes_errno_once() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let returns = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_observer(Arc::new(CompletionOrderObserver {
            events: Arc::clone(&events),
            returns: Arc::clone(&returns),
        }));
        let (kernel, context, mut state) = typed_completion_fixture(72_424, dispatcher);
        install_typed_guest_completion(&kernel, &context, &mut state);
        let mut engine = CrashCaptureTestEngine {
            completion_events: Some(Arc::clone(&events)),
            ..Default::default()
        };

        let preparation = state
            .prepare_execve(
                &kernel,
                &context,
                &mut engine,
                "/definitely/missing/guest-exec".to_owned(),
                vec![b"missing".to_vec()],
                Vec::new(),
                ExecCompletionOrigin::GuestSyscall,
            )
            .unwrap();

        assert!(matches!(
            preparation,
            exec::ExecvePreparation::Complete(None)
        ));
        let expected = crate::linux_abi::LINUX_ENOENT.guest_retval();
        assert_eq!(engine.completed_syscalls, vec![expected]);
        assert_eq!(*events.lock(), vec!["engine", "observer"]);
        assert_eq!(*returns.lock(), vec![expected]);
        assert!(state.syscall_completion.is_idle());
        assert_eq!(kernel.reporter.snapshot().summary.syscall_invocations, 1);
        assert_eq!(kernel.reporter.snapshot().summary.syscall_returns_errno, 1);
    }

    fn suffix_failure_test_executable() -> tempfile::NamedTempFile {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;

        let mut executable = tempfile::NamedTempFile::new().expect("synthetic executable");
        executable
            .write_all(&synthetic_elf(183))
            .expect("write synthetic ELF");
        let mut permissions = executable
            .as_file()
            .metadata()
            .expect("synthetic ELF metadata")
            .permissions();
        permissions.set_mode(0o700);
        executable
            .as_file()
            .set_permissions(permissions)
            .expect("mark synthetic ELF executable");
        executable
    }

    trait TestRuntimeError {
        fn into_runtime_error(self) -> RuntimeError;
    }

    impl TestRuntimeError for RuntimeError {
        fn into_runtime_error(self) -> RuntimeError {
            self
        }
    }

    impl TestRuntimeError for ProductionHvpatchPollError {
        fn into_runtime_error(self) -> RuntimeError {
            ProductionHvpatchPollError::into_runtime_error(self)
        }
    }

    fn assert_exact_configuration_error(error: impl TestRuntimeError, expected: &str) {
        match error.into_runtime_error() {
            RuntimeError::Configuration(actual) => assert_eq!(actual, expected),
            other => panic!("expected RuntimeError::Configuration({expected:?}), got {other:?}"),
        }
    }

    fn assert_no_exec_return_publication(
        kernel: &Kernel,
        engine: &CrashCaptureTestEngine,
        returns: &Arc<Mutex<Vec<i64>>>,
        events: &Arc<Mutex<Vec<&'static str>>>,
    ) {
        assert!(engine.completed_syscalls.is_empty());
        assert!(returns.lock().is_empty());
        assert!(events.lock().is_empty());
        let report = kernel.reporter.snapshot();
        assert_eq!(report.summary.syscall_returns_ok, 0);
        assert_eq!(report.summary.syscall_returns_errno, 0);
    }

    fn install_exec_terminal_handoff_contender(
        gate: &Arc<CloneAdmissionGate>,
        contender: ThreadId,
    ) -> std::thread::JoinHandle<Result<ExecCloneAdmission, RuntimeError>> {
        let (validated_tx, validated_rx) = std::sync::mpsc::channel();
        let (observation_tx, observation_rx) = std::sync::mpsc::channel::<bool>();
        gate.install_exec_terminal_handoff_hook(move || {
            validated_tx
                .send(())
                .expect("publish exact handoff validation");
            assert!(
                observation_rx
                    .recv()
                    .expect("receive contender mutex observation"),
                "production contender must encounter the held gate mutex"
            );
        });
        let contender_gate = Arc::clone(gate);
        std::thread::spawn(move || {
            validated_rx.recv().expect("wait for exact handoff");
            let encountered_held_mutex = contender_gate.state.try_lock().is_none();
            observation_tx
                .send(encountered_held_mutex)
                .expect("publish contender mutex observation");
            contender_gate.close_for_exec(contender)
        })
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn assert_production_exec_terminal_failure(
        job: &mut ProductionHvpatchLoopJob<CrashCaptureTestEngine>,
        engine: &mut CrashCaptureTestEngine,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        expected: &str,
        origin: ExecCompletionOrigin,
        contender: ThreadId,
    ) {
        let contender_thread =
            install_exec_terminal_handoff_contender(&job.kernel.clone_admission, contender);

        let exit = ProductionHvpatchLoopPoll::poll(job, engine, control);

        assert!(
            matches!(exit, executor::ExecutorExit::Exited),
            "exec terminal failure must exit, got {exit:?}"
        );
        assert_pending_exec_terminal_error(job, expected);
        assert!(
            contender_thread
                .join()
                .expect("join exec contender")
                .is_err(),
            "different exec must lose at the exact terminal handoff"
        );
        assert_eq!(
            job.kernel
                .clone_admission
                .try_claim_process_exit(job.state.this_tid)
                .expect("same-owner terminal retry")
                .claim,
            ProcessExitClaim::Owner,
        );
        assert_eq!(
            job.kernel
                .clone_admission
                .try_claim_process_exit(contender)
                .expect("different-owner terminal retry")
                .claim,
            ProcessExitClaim::AlreadyOwned,
        );
        assert!(job.state.syscall_completion.is_idle());
        assert!(
            job.state
                .finish_authenticated_exec_completion(AuthenticatedExecCompletionOrigin(origin))
                .is_err(),
            "terminal exec failure must not replay its completion origin"
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn assert_production_exec_terminal_trap_failure(
        job: &mut ProductionHvpatchLoopJob<CrashCaptureTestEngine>,
        engine: &mut CrashCaptureTestEngine,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        expected: &str,
        origin: ExecCompletionOrigin,
        contender: ThreadId,
    ) {
        let contender_thread =
            install_exec_terminal_handoff_contender(&job.kernel.clone_admission, contender);

        let exit = ProductionHvpatchLoopPoll::poll(job, engine, control);

        assert!(
            matches!(exit, executor::ExecutorExit::Exited),
            "exec terminal failure must exit, got {exit:?}"
        );
        match job.terminal_result.as_ref() {
            Some(Err(RuntimeError::Trap(TrapError::Hypervisor(actual)))) => {
                assert_eq!(actual, expected)
            }
            Some(Err(other)) => panic!("expected exact terminal trap {expected:?}, got {other:?}"),
            Some(Ok(_)) => panic!("expected exact terminal trap {expected:?}, got success"),
            None => panic!("expected exact terminal trap {expected:?}, got none"),
        }
        assert!(matches!(job.phase, HvpatchProductionPhase::Complete));
        assert!(
            contender_thread
                .join()
                .expect("join exec contender")
                .is_err(),
            "different exec must lose at the exact terminal handoff"
        );
        assert_eq!(
            job.kernel
                .clone_admission
                .try_claim_process_exit(job.state.this_tid)
                .expect("same-owner terminal retry")
                .claim,
            ProcessExitClaim::Owner,
        );
        assert_eq!(
            job.kernel
                .clone_admission
                .try_claim_process_exit(contender)
                .expect("different-owner terminal retry")
                .claim,
            ProcessExitClaim::AlreadyOwned,
        );
        assert!(job.state.syscall_completion.is_idle());
        assert!(
            job.state
                .finish_authenticated_exec_completion(AuthenticatedExecCompletionOrigin(origin))
                .is_err(),
            "terminal exec failure must not replay its completion origin"
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn external_exec_work_for_test(
        path: String,
        context: &crate::kernel::KernelContext,
    ) -> crate::kernel::control::ExecWork {
        use crate::kernel::control::{
            CarrierExecAdmission, ControlNonce, ExecAttach, ExecCapability, ExecRequest,
            ExecRuntime, ExecStatus,
        };

        let runtime = ExecRuntime::new(1);
        let capability = ExecCapability::from(ControlNonce::fresh().expect("control nonce"));
        let submit_runtime = runtime.clone();
        let submitter = std::thread::spawn(move || {
            submit_runtime.admit(
                capability,
                ExecRequest {
                    argv: vec![path],
                    env: Vec::new(),
                    workdir: None,
                    user: None,
                    tty: false,
                    attach: ExecAttach::Capture,
                },
            )
        });
        while runtime.query(capability) != ExecStatus::Pending {
            std::thread::yield_now();
        }
        let mut work = loop {
            if let Some(work) = runtime.try_take() {
                break work;
            }
            std::thread::yield_now();
        };
        assert!(work.begin_publication());
        assert!(work.admit(context.task().key().into()));
        assert_eq!(submitter.join().expect("exec submitter"), Ok(capability));
        work
    }

    fn process_owner_drain_failure(
        state: &ThreadRuntimeState<CrashCaptureTestEngine>,
    ) -> HvpatchExternalTerminalSettlement {
        let settlement = HvpatchExternalTerminalSettlement::new(
            HvpatchLoopResult::pending(),
            continuation::LogicalJobCompletion::pending(),
        );
        settlement.arm_process_owner().unwrap();
        enroll_persistent_process_member(&state.threads, &settlement);
        settlement
    }

    fn execve_test_frame() -> carrick_hal::RawSyscall {
        carrick_hal::RawSyscall {
            number: carrick_abi::CanonicalNr(221),
            args: [0; 6],
            guest_abi: carrick_abi::LinuxGuestAbi::Aarch64,
            native_number: carrick_abi::NativeNr(221),
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn scripted_guest_execve_engine(path: &str) -> CrashCaptureTestEngine {
        const PATH: u64 = 0x30_000;
        const ARGV: u64 = 0x31_000;
        let mut path_bytes = vec![0; 256];
        path_bytes[..path.len()].copy_from_slice(path.as_bytes());
        let guest_memory = [
            (PATH, path_bytes),
            (ARGV, PATH.to_le_bytes().to_vec()),
            (ARGV + 8, 0_u64.to_le_bytes().to_vec()),
        ]
        .into();
        CrashCaptureTestEngine {
            next_syscall: Some(carrick_hal::RawSyscall {
                number: carrick_abi::CanonicalNr(221),
                args: [PATH, ARGV, 0, 0, 0, 0],
                guest_abi: carrick_abi::LinuxGuestAbi::Aarch64,
                native_number: carrick_abi::NativeNr(221),
            }),
            guest_memory,
            ..Default::default()
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn enable_exec_support_for_test(
        engine: &mut CrashCaptureTestEngine,
        context: &crate::kernel::KernelContext,
        owner_generation: u64,
    ) {
        engine.exec_support = true;
        engine.snapshot_cpu = Some(executor::tests::task_state(context, 901).cpu);
        engine.frame_cow_owner_inventory = Some(fixed_frame_cow_owner_inventory_for_test(
            carrick_hal::ForeignOwnerGeneration::from_backend_counter(
                std::num::NonZeroU64::new(owner_generation).expect("nonzero exec owner generation"),
            ),
        ));
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    struct ImmediateProductionExecFailureCase {
        _executable: tempfile::NamedTempFile,
        kernel: Arc<KernelState>,
        context: crate::kernel::KernelContext,
        job: ProductionHvpatchLoopJob<CrashCaptureTestEngine>,
        engine: CrashCaptureTestEngine,
        preparations: Arc<std::sync::atomic::AtomicUsize>,
        returns: Arc<Mutex<Vec<i64>>>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn immediate_production_exec_failure_case(
        pid: i32,
        origin: ExecCompletionOrigin,
        fail_drain_begin: bool,
    ) -> ImmediateProductionExecFailureCase {
        let preparations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let returns = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_observer(Arc::new(ExecPreparationCounter(Arc::clone(&preparations))));
        dispatcher.install_observer(Arc::new(CompletionOrderObserver {
            events: Arc::clone(&events),
            returns: Arc::clone(&returns),
        }));
        let (kernel, context, mut state) = typed_completion_fixture(pid, dispatcher);
        state.guest_execution = Some(
            kernel
                .dispatcher
                .enter_mm_executor_for_thread(
                    state.kernel_thread.as_ref().map(Arc::clone),
                    Arc::clone(&state.kicker),
                    state.this_tid,
                )
                .expect("immediate production exec MM participation"),
        );
        let executable = suffix_failure_test_executable();
        let path = executable.path().to_string_lossy().into_owned();
        let (phase, engine) = match origin {
            ExecCompletionOrigin::GuestSyscall => (
                HvpatchProductionPhase::Resident,
                scripted_guest_execve_engine(&path),
            ),
            ExecCompletionOrigin::InternalControl => {
                state.begin_internal_control_exec().unwrap();
                kernel
                    .install_external_exec_work(external_exec_work_for_test(path.clone(), &context))
                    .expect("install production external exec work");
                (
                    HvpatchProductionPhase::BootstrapProcessChild(
                        ProcessChildBootstrap::ExternalControlExec { shares_mm: true },
                    ),
                    CrashCaptureTestEngine::default(),
                )
            }
        };
        if fail_drain_begin {
            state.kernel_thread = None;
        }
        let job = suffix_failure_test_job(&kernel, state, phase, None);
        ImmediateProductionExecFailureCase {
            _executable: executable,
            kernel,
            context,
            job,
            engine,
            preparations,
            returns,
            events,
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn context_boundary_production_exec_failure_case(
        pid: i32,
        origin: ExecCompletionOrigin,
        failpoint: Option<exec::ExecTerminalContextFailpoint>,
    ) -> ImmediateProductionExecFailureCase {
        let preparations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let returns = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_observer(Arc::new(ExecPreparationCounter(Arc::clone(&preparations))));
        dispatcher.install_observer(Arc::new(CompletionOrderObserver {
            events: Arc::clone(&events),
            returns: Arc::clone(&returns),
        }));
        let (_runtime, scheduler, kernel, context, process, _root_generation) =
            test_carrier_graph_with_dispatcher!(pid, dispatcher);
        let executor = scheduler
            .register_executor(Arc::new(RuntimeTestExecutorKick::default()))
            .expect("context-boundary executor");
        let mut running = scheduler
            .take(&executor)
            .expect("context-boundary runnable root");
        let this_tid = ThreadId::synthetic_for_tests(pid);
        let kicker: Arc<dyn VcpuRegistry> = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
            Arc::new(ThreadRegistry::new(this_tid)),
            Arc::new(FutexTable::new()),
            platform,
            platform_factory,
            kernel.process_fork_barrier.clone(),
            kernel.crash_capture.clone(),
            Some(Arc::clone(context.thread())),
            Some(process.pid()),
            context.thread().key().tid,
            kernel.fatal_signal.current_generation(),
            this_tid,
            Arc::new(Mutex::new(Vec::new())),
            Arc::clone(&kicker),
            carrick_hal::InGuestFlag::for_guest_thread(),
            1_000,
        );
        *state.execution_lease.lock() = Some(running.take_lease());
        state.service_kernel_context = Some(context.retain_exact());
        state.guest_execution = Some(
            kernel
                .dispatcher
                .enter_mm_executor_for_thread(Some(Arc::clone(context.thread())), kicker, this_tid)
                .expect("context-boundary MM participation"),
        );
        if let Some(failpoint) = failpoint {
            state.install_exec_terminal_context_failpoint_for_test(failpoint);
        }

        let executable = suffix_failure_test_executable();
        let path = executable.path().to_string_lossy().into_owned();
        let (phase, mut engine) = match origin {
            ExecCompletionOrigin::GuestSyscall => (
                HvpatchProductionPhase::Resident,
                scripted_guest_execve_engine(&path),
            ),
            ExecCompletionOrigin::InternalControl => {
                state.begin_internal_control_exec().unwrap();
                kernel
                    .install_external_exec_work(external_exec_work_for_test(path.clone(), &context))
                    .expect("install context-boundary external exec work");
                (
                    HvpatchProductionPhase::BootstrapProcessChild(
                        ProcessChildBootstrap::ExternalControlExec { shares_mm: true },
                    ),
                    CrashCaptureTestEngine::default(),
                )
            }
        };
        enable_exec_support_for_test(&mut engine, &context, pid as u64);
        let job = suffix_failure_test_job(&kernel, state, phase, None);
        ImmediateProductionExecFailureCase {
            _executable: executable,
            kernel,
            context,
            job,
            engine,
            preparations,
            returns,
            events,
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    struct PendingExecDrainTestCase {
        kernel: Kernel,
        context: crate::kernel::KernelContext,
        job: ProductionHvpatchLoopJob<CrashCaptureTestEngine>,
        engine: CrashCaptureTestEngine,
        sibling: HvpatchExternalTerminalSettlement,
        preparations: Arc<std::sync::atomic::AtomicUsize>,
        returns: Arc<Mutex<Vec<i64>>>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn pending_exec_drain_test_case(
        pid: i32,
        origin: ExecCompletionOrigin,
    ) -> PendingExecDrainTestCase {
        let preparations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let returns = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_observer(Arc::new(ExecPreparationCounter(Arc::clone(&preparations))));
        dispatcher.install_observer(Arc::new(CompletionOrderObserver {
            events: Arc::clone(&events),
            returns: Arc::clone(&returns),
        }));
        let (kernel, context, mut state) = typed_completion_fixture(pid, dispatcher);
        match origin {
            ExecCompletionOrigin::GuestSyscall => {
                install_typed_guest_completion(&kernel, &context, &mut state);
            }
            ExecCompletionOrigin::InternalControl => {
                state.begin_internal_control_exec().unwrap();
            }
        }
        state.guest_execution = Some(
            kernel
                .dispatcher
                .enter_mm_executor_for_thread(
                    state.kernel_thread.as_ref().map(Arc::clone),
                    Arc::clone(&state.kicker),
                    state.this_tid,
                )
                .expect("pending exec MM participation"),
        );
        let sibling = HvpatchExternalTerminalSettlement::new(
            HvpatchLoopResult::pending(),
            continuation::LogicalJobCompletion::pending(),
        );
        enroll_persistent_process_member(&state.threads, &sibling);
        let executable = suffix_failure_test_executable();
        let path = executable.path().to_string_lossy().into_owned();
        let external_exec = match origin {
            ExecCompletionOrigin::GuestSyscall => None,
            ExecCompletionOrigin::InternalControl => {
                Some(external_exec_work_for_test(path.clone(), &context))
            }
        };
        let scheduler = kernel
            .hvpatch_runtime
            .as_ref()
            .expect("HVPatch runtime")
            .continuation_services(context.kernel())
            .0;
        let mut job = suffix_failure_test_job(
            &kernel,
            state,
            HvpatchProductionPhase::Resident,
            external_exec,
        );
        let need_resched = std::sync::atomic::AtomicBool::new(false);
        let mut submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: None,
            lease: None,
            exec_replacement: None,
        };
        let mut control = executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
        let mut engine = CrashCaptureTestEngine::default();
        let first = match origin {
            ExecCompletionOrigin::GuestSyscall => job
                .service_outcome(
                    &mut engine,
                    &mut control,
                    execve_test_frame(),
                    DispatchOutcome::Execve {
                        path: path.clone(),
                        argv: vec![path.into_bytes()],
                        env: Vec::new(),
                    },
                )
                .expect("guest exec must suspend with its pending drain owner"),
            ExecCompletionOrigin::InternalControl => job
                .start_external_exec(&mut engine, &mut control)
                .expect("internal exec must suspend with its pending drain owner"),
        };
        assert!(matches!(
            first,
            executor::ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::ChildState)
        ));
        assert!(matches!(
            job.phase,
            HvpatchProductionPhase::ExecSiblingDrain { .. }
        ));
        assert!(
            job.state.syscall_completion.is_idle(),
            "pending exec phase must exclusively own completion authority"
        );
        assert_eq!(preparations.load(std::sync::atomic::Ordering::SeqCst), 1);
        PendingExecDrainTestCase {
            kernel,
            context,
            job,
            engine,
            sibling,
            preparations,
            returns,
            events,
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn assert_pending_exec_terminal_error(
        job: &ProductionHvpatchLoopJob<CrashCaptureTestEngine>,
        expected: &str,
    ) {
        match job.terminal_result.as_ref() {
            Some(Err(RuntimeError::Configuration(actual))) => assert_eq!(actual, expected),
            Some(Err(other)) => {
                panic!("expected exact pending-exec terminal error {expected:?}, got {other:?}")
            }
            Some(Ok(_)) => {
                panic!(
                    "expected exact pending-exec terminal error {expected:?}, got success (successor committed: {})",
                    job.state.committed_exec_context_for_test.is_some()
                )
            }
            None => panic!("expected exact pending-exec terminal error {expected:?}, got none"),
        }
        assert!(matches!(job.phase, HvpatchProductionPhase::Complete));
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn pending_exec_completion_ownership_survives_mm_readmission_failure_without_masking_error() {
        for (pid, origin) in [
            (72_429, ExecCompletionOrigin::GuestSyscall),
            (72_430, ExecCompletionOrigin::InternalControl),
        ] {
            let mut case = pending_exec_drain_test_case(pid, origin);
            case.sibling
                .publish_member(Ok(VcpuLoopOutcome::ThreadDone))
                .expect("settle the real pending sibling");
            let blocker = case
                .kernel
                .dispatcher
                .enter_mm_executor_for_thread(
                    case.job.state.kernel_thread.as_ref().map(Arc::clone),
                    Arc::clone(&case.job.state.kicker),
                    case.job.state.this_tid,
                )
                .expect("occupy the exact MM/thread admission");
            let expected = format!(
                "thread {:?} is already admitted as a guest executor",
                case.context.thread().key()
            );
            let scheduler = case
                .kernel
                .hvpatch_runtime
                .as_ref()
                .expect("HVPatch runtime")
                .continuation_services(case.context.kernel())
                .0;
            let need_resched = std::sync::atomic::AtomicBool::new(false);
            let mut submission = executor::ExecutorSubmissionContext {
                scheduler: &scheduler,
                publish_test_descendant: &|_, _| unreachable!(),
                current: None,
                lease: None,
                exec_replacement: None,
            };
            let mut control =
                executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);

            let exit =
                ProductionHvpatchLoopPoll::poll(&mut case.job, &mut case.engine, &mut control);

            drop(blocker);
            assert!(matches!(exit, executor::ExecutorExit::Exited));
            assert_pending_exec_terminal_error(&case.job, &expected);
            assert!(case.job.state.syscall_completion.is_idle());
            assert_eq!(
                case.preparations.load(std::sync::atomic::Ordering::SeqCst),
                1
            );
            assert_no_exec_return_publication(
                &case.kernel,
                &case.engine,
                &case.returns,
                &case.events,
            );
            assert_eq!(
                case.kernel
                    .clone_admission
                    .try_claim_process_exit(case.job.state.this_tid)
                    .expect("same-owner retry")
                    .claim,
                ProcessExitClaim::Owner,
            );
            assert!(
                case.kernel
                    .clone_admission
                    .close_for_exec(ThreadId::synthetic_for_tests(74_102))
                    .is_err(),
                "terminal ownership must keep exec admission closed"
            );
            assert!(
                case.job
                    .state
                    .finish_authenticated_exec_completion(
                        AuthenticatedExecCompletionOrigin(origin,)
                    )
                    .is_err(),
                "pending exec authority must reject replay after re-admission failure"
            );
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn pending_exec_owner_executor_failure_converts_exec_close_to_exit() {
        for (pid, origin) in [
            (72_445, ExecCompletionOrigin::GuestSyscall),
            (72_446, ExecCompletionOrigin::InternalControl),
        ] {
            let mut case = pending_exec_drain_test_case(pid, origin);

            assert_eq!(
                ProductionHvpatchLoopPoll::after_executor_failure_settlement(&mut case.job),
                continuation::ExecutorFailureSettlement::PublishCurrent,
                "the executor that owns the pending exec must settle itself"
            );
            assert!(
                !matches!(
                    case.job.phase,
                    HvpatchProductionPhase::ExecSiblingDrain { .. }
                ),
                "executor failure must consume the pending exec owner"
            );
            assert_eq!(
                case.kernel
                    .clone_admission
                    .try_claim_process_exit(case.job.state.this_tid)
                    .expect("same-owner exit retry")
                    .claim,
                ProcessExitClaim::Owner,
                "the exact exec handoff must become the process-exit owner"
            );
            assert!(
                case.sibling.is_published(),
                "self-owned exec failure must settle the sibling member"
            );
            assert_eq!(
                case.job
                    .state
                    .service_kernel_context
                    .as_ref()
                    .expect("restored exact terminal context")
                    .thread()
                    .key(),
                case.context.thread().key(),
            );
        }
    }

    /// An executor failure on a job that LOST the process-exit claim must still
    /// publish that job's own logical result.
    ///
    /// Deferring to the process terminal owner is only sound while this job's
    /// settlement is still enrolled in the owner's member list. An `execve`
    /// survivor is removed from that list by `finish_persistent_process_handles`
    /// and never re-enrolled, so the owner's drain never publishes it: the
    /// container's `wait_process_jobs` then waits on an `HvpatchLoopResult` that
    /// no one can ever publish, with an empty kernel graph and idle executors
    /// (the `go build` / `go_types` exit wedge).
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn executor_failure_after_a_lost_exit_claim_publishes_its_own_result() {
        let (kernel, _context, state) = typed_completion_fixture(72_461, SyscallDispatcher::new());
        let owner = ThreadId::synthetic_for_tests(72_462);
        assert_eq!(
            kernel
                .clone_admission
                .try_claim_process_exit(owner)
                .expect("sibling claims the process exit")
                .claim,
            ProcessExitClaim::Owner,
        );
        let mut job =
            suffix_failure_test_job(&kernel, state, HvpatchProductionPhase::Resident, None);
        let settlement = job.terminal_settlement.clone();
        let result = settlement.result.clone();
        let completion = settlement.completion();
        assert_ne!(
            kernel
                .clone_admission
                .try_claim_process_exit(job.state.this_tid)
                .expect("loser claim")
                .claim,
            ProcessExitClaim::Owner,
        );

        assert_eq!(
            ProductionHvpatchLoopPoll::after_executor_failure_settlement(&mut job),
            continuation::ExecutorFailureSettlement::PublishCurrent,
            "a job that cannot prove an owner will publish it must publish itself"
        );

        assert!(
            settlement.is_published(),
            "the lost-claim member left its container job result unpublished"
        );
        assert!(completion.is_finished());
        assert!(
            matches!(result.wait(), Ok(VcpuLoopOutcome::ThreadDone)),
            "Linux terminated this thread at the owner's exit_group: ThreadDone"
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn pending_exec_completion_ownership_survives_control_context_failure_without_abort() {
        const CHILD: &str = "CARRICK_PENDING_EXEC_CONTEXT_FAILURE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(
                std::env::current_exe().expect("runtime unit-test executable"),
            )
            .arg("--exact")
            .arg("vcpu_loop::tests::pending_exec_completion_ownership_survives_control_context_failure_without_abort")
            .arg("--nocapture")
            .env(CHILD, "1")
            .output()
            .expect("run isolated pending-exec context failure");
            assert!(
                output.status.success(),
                "isolated pending-exec context failure did not preserve the exact terminal error:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        for (pid, origin) in [
            (72_431, ExecCompletionOrigin::GuestSyscall),
            (72_432, ExecCompletionOrigin::InternalControl),
        ] {
            let mut case = pending_exec_drain_test_case(pid, origin);
            case.sibling
                .publish_member(Ok(VcpuLoopOutcome::ThreadDone))
                .expect("settle the real pending sibling");
            case.job.state.service_kernel_context = None;
            let scheduler = case
                .kernel
                .hvpatch_runtime
                .as_ref()
                .expect("HVPatch runtime")
                .continuation_services(case.context.kernel())
                .0;
            let need_resched = std::sync::atomic::AtomicBool::new(false);
            let mut submission = executor::ExecutorSubmissionContext {
                scheduler: &scheduler,
                publish_test_descendant: &|_, _| unreachable!(),
                current: None,
                lease: None,
                exec_replacement: None,
            };
            let mut control =
                executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);

            let exit =
                ProductionHvpatchLoopPoll::poll(&mut case.job, &mut case.engine, &mut control);

            assert!(matches!(exit, executor::ExecutorExit::Exited));
            assert_pending_exec_terminal_error(
                &case.job,
                "carrier logical exec lost exact root Kernel context",
            );
            assert!(case.job.state.syscall_completion.is_idle());
            assert_no_exec_return_publication(
                &case.kernel,
                &case.engine,
                &case.returns,
                &case.events,
            );
            assert_eq!(
                case.kernel
                    .clone_admission
                    .try_claim_process_exit(case.job.state.this_tid)
                    .expect("same-owner retry")
                    .claim,
                ProcessExitClaim::Owner,
            );
            assert!(
                case.kernel
                    .clone_admission
                    .close_for_exec(ThreadId::synthetic_for_tests(74_102))
                    .is_err(),
                "terminal ownership must keep exec admission closed"
            );
            assert!(
                case.job
                    .state
                    .finish_authenticated_exec_completion(
                        AuthenticatedExecCompletionOrigin(origin,)
                    )
                    .is_err(),
                "pending exec authority must reject replay after context failure"
            );
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn pending_exec_completion_ownership_is_drop_safe_for_external_settlement_and_unwind() {
        for (pid, origin) in [
            (72_433, ExecCompletionOrigin::GuestSyscall),
            (72_434, ExecCompletionOrigin::InternalControl),
        ] {
            let mut case = pending_exec_drain_test_case(pid, origin);
            case.job
                .terminal_settlement
                .publish_member(Ok(VcpuLoopOutcome::ThreadDone))
                .expect("externally settle the pending exec job");
            let scheduler = case
                .kernel
                .hvpatch_runtime
                .as_ref()
                .expect("HVPatch runtime")
                .continuation_services(case.context.kernel())
                .0;
            let need_resched = std::sync::atomic::AtomicBool::new(false);
            let mut submission = executor::ExecutorSubmissionContext {
                scheduler: &scheduler,
                publish_test_descendant: &|_, _| unreachable!(),
                current: None,
                lease: None,
                exec_replacement: None,
            };
            let mut control =
                executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);

            let exit = case
                .job
                .poll_with_engine(&mut case.engine, &mut control)
                .expect("external settlement must retire the pending exec owner");

            assert!(matches!(exit, executor::ExecutorExit::Exited));
            assert!(matches!(case.job.phase, HvpatchProductionPhase::Complete));
            assert!(case.job.state.syscall_completion.is_idle());
            assert_no_exec_return_publication(
                &case.kernel,
                &case.engine,
                &case.returns,
                &case.events,
            );
            assert!(
                case.job
                    .state
                    .finish_authenticated_exec_completion(
                        AuthenticatedExecCompletionOrigin(origin,)
                    )
                    .is_err(),
                "externally settled pending exec authority must reject replay"
            );
        }

        let case = pending_exec_drain_test_case(72_435, ExecCompletionOrigin::GuestSyscall);
        assert!(
            case.job.state.syscall_completion.is_idle(),
            "pending owner must remove live completion authority from droppable runtime state"
        );
        let kernel = Arc::clone(&case.kernel);
        let returns = Arc::clone(&case.returns);
        let events = Arc::clone(&case.events);
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _pending_owner = case.job;
            panic!("exercise pending exec owner unwind");
        }));
        assert!(unwind.is_err());
        let report = kernel.reporter.snapshot();
        assert_eq!(report.summary.syscall_returns_ok, 0);
        assert_eq!(report.summary.syscall_returns_errno, 0);
        assert!(returns.lock().is_empty());
        assert!(events.lock().is_empty());
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn production_poll_preserves_immediate_exec_drain_begin_errors_for_both_origins() {
        for (pid, origin, contender_pid) in [
            (72_436, ExecCompletionOrigin::GuestSyscall, 74_130),
            (72_437, ExecCompletionOrigin::InternalControl, 74_131),
        ] {
            let mut case = immediate_production_exec_failure_case(pid, origin, true);
            let scheduler = case
                .kernel
                .hvpatch_runtime
                .as_ref()
                .expect("HVPatch runtime")
                .continuation_services(case.context.kernel())
                .0;
            let need_resched = std::sync::atomic::AtomicBool::new(false);
            let mut submission = executor::ExecutorSubmissionContext {
                scheduler: &scheduler,
                publish_test_descendant: &|_, _| unreachable!(),
                current: None,
                lease: None,
                exec_replacement: None,
            };
            let mut control =
                executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);

            assert_production_exec_terminal_failure(
                &mut case.job,
                &mut case.engine,
                &mut control,
                "HVPatch persistent sibling drain lost exact Kernel thread",
                origin,
                ThreadId::synthetic_for_tests(contender_pid),
            );

            assert_eq!(
                case.job
                    .state
                    .service_kernel_context
                    .as_ref()
                    .expect("restored exact terminal context")
                    .thread()
                    .key(),
                case.context.thread().key(),
            );
            assert_eq!(
                case.preparations.load(std::sync::atomic::Ordering::SeqCst),
                1
            );
            assert_eq!(case.engine.exec_inventory_arms, 0);
            assert_eq!(case.engine.execve_installs, 0);
            assert_no_exec_return_publication(
                &case.kernel,
                &case.engine,
                &case.returns,
                &case.events,
            );
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn production_poll_preserves_immediate_exec_suffix_errors_for_both_origins() {
        for (pid, origin, contender_pid) in [
            (72_438, ExecCompletionOrigin::GuestSyscall, 74_132),
            (72_439, ExecCompletionOrigin::InternalControl, 74_133),
        ] {
            let mut case = immediate_production_exec_failure_case(pid, origin, false);
            let scheduler = case
                .kernel
                .hvpatch_runtime
                .as_ref()
                .expect("HVPatch runtime")
                .continuation_services(case.context.kernel())
                .0;
            let need_resched = std::sync::atomic::AtomicBool::new(false);
            let mut submission = executor::ExecutorSubmissionContext {
                scheduler: &scheduler,
                publish_test_descendant: &|_, _| unreachable!(),
                current: None,
                lease: None,
                exec_replacement: None,
            };
            let mut control =
                executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);

            assert_production_exec_terminal_failure(
                &mut case.job,
                &mut case.engine,
                &mut control,
                "exec replacement lost worker-authenticated execution lease",
                origin,
                ThreadId::synthetic_for_tests(contender_pid),
            );

            assert_eq!(
                case.preparations.load(std::sync::atomic::Ordering::SeqCst),
                1
            );
            assert_eq!(case.engine.exec_inventory_arms, 1);
            assert_eq!(case.engine.execve_installs, 0);
            assert_no_exec_return_publication(
                &case.kernel,
                &case.engine,
                &case.returns,
                &case.events,
            );
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn production_poll_exec_terminal_context_changes_only_at_kernel_successor_commit() {
        use exec::ExecTerminalContextFailpoint::{
            BeforeKernelCommit, FrameCowBinding, IdentityPublication, InventoryActivation,
            SnapshotPublication, TaskLoadPublication, VvarPublication,
        };

        let points = [
            BeforeKernelCommit,
            TaskLoadPublication,
            SnapshotPublication,
            FrameCowBinding,
            InventoryActivation,
            IdentityPublication,
            VvarPublication,
        ];
        for (case_index, point) in points.into_iter().enumerate() {
            for (origin_index, origin) in [
                ExecCompletionOrigin::GuestSyscall,
                ExecCompletionOrigin::InternalControl,
            ]
            .into_iter()
            .enumerate()
            {
                let pid = 74_200 + (case_index * 2 + origin_index) as i32;
                let mut case =
                    context_boundary_production_exec_failure_case(pid, origin, Some(point));
                let scheduler = case
                    .kernel
                    .hvpatch_runtime
                    .as_ref()
                    .expect("HVPatch runtime")
                    .continuation_services(case.context.kernel())
                    .0;
                let need_resched = std::sync::atomic::AtomicBool::new(false);
                let mut submission = executor::ExecutorSubmissionContext {
                    scheduler: &scheduler,
                    publish_test_descendant: &|_, _| unreachable!(),
                    current: None,
                    lease: None,
                    exec_replacement: None,
                };
                let mut control =
                    executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
                let expected = format!("injected exec terminal context failure at {point:?}");

                assert_production_exec_terminal_failure(
                    &mut case.job,
                    &mut case.engine,
                    &mut control,
                    &expected,
                    origin,
                    ThreadId::synthetic_for_tests(pid + 2_000),
                );

                let terminal_context = case
                    .job
                    .state
                    .service_kernel_context
                    .as_ref()
                    .expect("terminal path must retain an exact context");
                if point == BeforeKernelCommit {
                    assert_eq!(terminal_context.thread().key(), case.context.thread().key());
                    assert_eq!(
                        terminal_context.shared().mm().id(),
                        case.context.shared().mm().id()
                    );
                    assert!(case.job.state.committed_exec_context_for_test.is_none());
                } else {
                    let successor = case
                        .job
                        .state
                        .committed_exec_context_for_test
                        .as_ref()
                        .expect("post-commit failpoint must observe the Kernel successor");
                    assert_ne!(successor.thread().key(), case.context.thread().key());
                    assert_ne!(
                        successor.shared().mm().id(),
                        case.context.shared().mm().id()
                    );
                    assert_eq!(terminal_context.thread().key(), successor.thread().key());
                    assert_eq!(
                        terminal_context.shared().mm().id(),
                        successor.shared().mm().id()
                    );
                }
                assert_eq!(
                    case.preparations.load(std::sync::atomic::Ordering::SeqCst),
                    1
                );
                assert_no_exec_return_publication(
                    &case.kernel,
                    &case.engine,
                    &case.returns,
                    &case.events,
                );
            }
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn production_poll_preserves_successor_context_on_actual_duplicate_replacement_publication() {
        for (case_index, origin) in [
            ExecCompletionOrigin::GuestSyscall,
            ExecCompletionOrigin::InternalControl,
        ]
        .into_iter()
        .enumerate()
        {
            let pid = 74_230 + case_index as i32;
            let mut case = context_boundary_production_exec_failure_case(pid, origin, None);
            let scheduler = case
                .kernel
                .hvpatch_runtime
                .as_ref()
                .expect("HVPatch runtime")
                .continuation_services(case.context.kernel())
                .0;
            let need_resched = std::sync::atomic::AtomicBool::new(false);
            let mut submission = executor::ExecutorSubmissionContext {
                scheduler: &scheduler,
                publish_test_descendant: &|_, _| unreachable!(),
                current: None,
                lease: None,
                exec_replacement: None,
            };

            let first_exit = {
                let mut control =
                    executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
                ProductionHvpatchLoopPoll::poll(&mut case.job, &mut case.engine, &mut control)
            };
            assert!(matches!(first_exit, executor::ExecutorExit::Preempted));
            assert!(
                submission.exec_replacement.is_some(),
                "first real exec must occupy the quantum replacement slot"
            );
            assert!(case.job.terminal_result.is_none());
            let first_successor = case
                .job
                .state
                .service_kernel_context
                .as_ref()
                .expect("first exec successor context")
                .retain_exact();
            assert_ne!(first_successor.thread().key(), case.context.thread().key());

            let path = case._executable.path().to_string_lossy().into_owned();
            case.job.state.committed_exec_context_for_test = None;
            case.job.state.exec_terminal_context_failpoint = None;
            match origin {
                ExecCompletionOrigin::GuestSyscall => {
                    install_typed_guest_completion(
                        &case.kernel,
                        &first_successor,
                        &mut case.job.state,
                    );
                }
                ExecCompletionOrigin::InternalControl => {
                    case.job.state.begin_internal_control_exec().unwrap();
                }
            }
            case.job.state.guest_execution = Some(
                case.kernel
                    .dispatcher
                    .enter_mm_executor_for_thread(
                        case.job.state.kernel_thread.as_ref().map(Arc::clone),
                        Arc::clone(&case.job.state.kicker),
                        case.job.state.this_tid,
                    )
                    .expect("second exec MM participation"),
            );
            let mut second_engine = CrashCaptureTestEngine::default();
            enable_exec_support_for_test(&mut second_engine, &first_successor, (pid + 100) as u64);
            let exec::ExecvePreparation::Prepared(prepared) = case
                .job
                .state
                .prepare_execve(
                    &case.kernel,
                    &first_successor,
                    &mut second_engine,
                    path.clone(),
                    vec![path.into_bytes()],
                    Vec::new(),
                    origin,
                )
                .expect("second exec preparation")
            else {
                panic!("second exec must reach its destructive suffix")
            };
            let owner = case
                .job
                .state
                .prepared_execve_drain_for_test(
                    *prepared,
                    continuation::ProcessDrain::excluding(
                        continuation::LogicalJobCompletion::pending(),
                        Vec::new(),
                    ),
                )
                .expect("second exec delayed owner");
            case.job.phase = HvpatchProductionPhase::ExecSiblingDrain {
                context: first_successor.retain_exact(),
                owner,
            };
            case.engine = second_engine;

            let contender = ThreadId::synthetic_for_tests(pid + 2_000);
            {
                let mut control =
                    executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
                assert_production_exec_terminal_trap_failure(
                    &mut case.job,
                    &mut case.engine,
                    &mut control,
                    "quantum published more than one exec replacement",
                    origin,
                    contender,
                );
            }

            let successor = case
                .job
                .state
                .committed_exec_context_for_test
                .as_ref()
                .expect("duplicate publication follows the second Kernel successor");
            let terminal_context = case
                .job
                .state
                .service_kernel_context
                .as_ref()
                .expect("duplicate publication terminal context");
            assert_ne!(successor.thread().key(), first_successor.thread().key());
            assert_ne!(
                successor.shared().mm().id(),
                first_successor.shared().mm().id()
            );
            assert_eq!(terminal_context.thread().key(), successor.thread().key());
            assert_eq!(
                terminal_context.shared().mm().id(),
                successor.shared().mm().id()
            );
            assert_no_exec_return_publication(
                &case.kernel,
                &case.engine,
                &case.returns,
                &case.events,
            );
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn production_poll_terminal_outcome_after_successor_commit_keeps_successor_context() {
        for (case_index, origin) in [
            ExecCompletionOrigin::GuestSyscall,
            ExecCompletionOrigin::InternalControl,
        ]
        .into_iter()
        .enumerate()
        {
            let pid = 74_240 + case_index as i32;
            let mut case = context_boundary_production_exec_failure_case(pid, origin, None);
            case.engine.snapshot_cpu = None;
            let scheduler = case
                .kernel
                .hvpatch_runtime
                .as_ref()
                .expect("HVPatch runtime")
                .continuation_services(case.context.kernel())
                .0;
            let need_resched = std::sync::atomic::AtomicBool::new(false);
            let mut submission = executor::ExecutorSubmissionContext {
                scheduler: &scheduler,
                publish_test_descendant: &|_, _| unreachable!(),
                current: None,
                lease: None,
                exec_replacement: None,
            };
            let contender = ThreadId::synthetic_for_tests(pid + 2_000);
            let contender_thread =
                install_exec_terminal_handoff_contender(&case.kernel.clone_admission, contender);
            let exit = {
                let mut control =
                    executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
                ProductionHvpatchLoopPoll::poll(&mut case.job, &mut case.engine, &mut control)
            };

            assert!(matches!(exit, executor::ExecutorExit::Exited));
            match case.job.terminal_result.as_ref() {
                Some(Ok(VcpuLoopOutcome::ProcessExit(run))) => {
                    assert_eq!(
                        run.terminating_signal,
                        Some(crate::linux_abi::LINUX_SIGSEGV)
                    );
                }
                Some(Ok(_)) => panic!("post-commit exec failure fabricated a non-process exit"),
                Some(Err(error)) => panic!("post-commit terminal outcome was masked: {error:?}"),
                None => panic!("post-commit terminal outcome disappeared"),
            }
            assert!(
                contender_thread
                    .join()
                    .expect("join outcome contender")
                    .is_err()
            );
            assert_eq!(
                case.kernel
                    .clone_admission
                    .try_claim_process_exit(case.job.state.this_tid)
                    .expect("same-owner terminal outcome retry")
                    .claim,
                ProcessExitClaim::Owner
            );
            assert_eq!(
                case.kernel
                    .clone_admission
                    .try_claim_process_exit(contender)
                    .expect("different-owner terminal outcome retry")
                    .claim,
                ProcessExitClaim::AlreadyOwned
            );
            let successor = case
                .job
                .state
                .committed_exec_context_for_test
                .as_ref()
                .expect("snapshot failure follows Kernel successor commit");
            let terminal_context = case
                .job
                .state
                .service_kernel_context
                .as_ref()
                .expect("terminal outcome exact context");
            assert_ne!(successor.thread().key(), case.context.thread().key());
            assert_ne!(
                successor.shared().mm().id(),
                case.context.shared().mm().id()
            );
            assert_eq!(terminal_context.thread().key(), successor.thread().key());
            assert_eq!(
                terminal_context.shared().mm().id(),
                successor.shared().mm().id()
            );
            assert!(case.job.state.syscall_completion.is_idle());
            assert!(
                case.job
                    .state
                    .finish_authenticated_exec_completion(AuthenticatedExecCompletionOrigin(origin))
                    .is_err()
            );
            assert_no_exec_return_publication(
                &case.kernel,
                &case.engine,
                &case.returns,
                &case.events,
            );
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn typed_completion_ownership_immediate_guest_exec_drain_begin_error_consumes_origin() {
        let preparations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let returns = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_observer(Arc::new(ExecPreparationCounter(Arc::clone(&preparations))));
        dispatcher.install_observer(Arc::new(CompletionOrderObserver {
            events: Arc::clone(&events),
            returns: Arc::clone(&returns),
        }));
        let (kernel, context, mut state) = typed_completion_fixture(72_425, dispatcher);
        install_typed_guest_completion(&kernel, &context, &mut state);
        state.kernel_thread = None;
        let executable = suffix_failure_test_executable();
        let path = executable.path().to_string_lossy().into_owned();
        let scheduler = kernel
            .hvpatch_runtime
            .as_ref()
            .expect("HVPatch runtime")
            .continuation_services(context.kernel())
            .0;
        let mut job =
            suffix_failure_test_job(&kernel, state, HvpatchProductionPhase::Resident, None);
        let need_resched = std::sync::atomic::AtomicBool::new(false);
        let mut submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: None,
            lease: None,
            exec_replacement: None,
        };
        let mut control = executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
        let mut engine = CrashCaptureTestEngine::default();

        let error = job
            .service_outcome(
                &mut engine,
                &mut control,
                execve_test_frame(),
                DispatchOutcome::Execve {
                    path: path.clone(),
                    argv: vec![path.into_bytes()],
                    env: Vec::new(),
                },
            )
            .expect_err("missing Kernel thread must fail real drain begin");

        assert_exact_configuration_error(
            error,
            "HVPatch persistent sibling drain lost exact Kernel thread",
        );
        assert_eq!(preparations.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(engine.exec_inventory_arms, 0);
        assert_eq!(engine.execve_installs, 0);
        assert_no_exec_return_publication(&kernel, &engine, &returns, &events);
        assert!(job.state.syscall_completion.is_idle());
        assert_exact_configuration_error(
            job.state
                .finish_authenticated_exec_completion(AuthenticatedExecCompletionOrigin(
                    ExecCompletionOrigin::GuestSyscall,
                ))
                .expect_err("authenticated guest origin must be one-shot"),
            "threaded syscall retired without guest completion ownership",
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn typed_completion_ownership_immediate_internal_exec_drain_begin_error_consumes_origin() {
        let preparations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let returns = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_observer(Arc::new(ExecPreparationCounter(Arc::clone(&preparations))));
        dispatcher.install_observer(Arc::new(CompletionOrderObserver {
            events: Arc::clone(&events),
            returns: Arc::clone(&returns),
        }));
        let (kernel, context, mut state) = typed_completion_fixture(72_426, dispatcher);
        state.begin_internal_control_exec().unwrap();
        state.kernel_thread = None;
        let executable = suffix_failure_test_executable();
        let path = executable.path().to_string_lossy().into_owned();
        let work = external_exec_work_for_test(path, &context);
        let scheduler = kernel
            .hvpatch_runtime
            .as_ref()
            .expect("HVPatch runtime")
            .continuation_services(context.kernel())
            .0;
        let mut job =
            suffix_failure_test_job(&kernel, state, HvpatchProductionPhase::Resident, Some(work));
        let need_resched = std::sync::atomic::AtomicBool::new(false);
        let mut submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: None,
            lease: None,
            exec_replacement: None,
        };
        let mut control = executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
        let mut engine = CrashCaptureTestEngine::default();

        let error = job
            .start_external_exec(&mut engine, &mut control)
            .expect_err("missing Kernel thread must fail real internal drain begin");

        assert_exact_configuration_error(
            error,
            "HVPatch persistent sibling drain lost exact Kernel thread",
        );
        assert_eq!(preparations.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(engine.exec_inventory_arms, 0);
        assert_eq!(engine.execve_installs, 0);
        assert_no_exec_return_publication(&kernel, &engine, &returns, &events);
        assert!(job.state.syscall_completion.is_idle());
        assert_exact_configuration_error(
            job.state
                .finish_authenticated_exec_completion(AuthenticatedExecCompletionOrigin(
                    ExecCompletionOrigin::InternalControl,
                ))
                .expect_err("authenticated internal origin must be one-shot"),
            "internal control exec lost typed ownership",
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn typed_completion_ownership_delayed_guest_exec_drain_finish_error_consumes_origin() {
        let preparations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let returns = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_observer(Arc::new(ExecPreparationCounter(Arc::clone(&preparations))));
        dispatcher.install_observer(Arc::new(CompletionOrderObserver {
            events: Arc::clone(&events),
            returns: Arc::clone(&returns),
        }));
        let (kernel, context, mut state) = typed_completion_fixture(72_427, dispatcher);
        install_typed_guest_completion(&kernel, &context, &mut state);
        state.guest_execution = Some(
            kernel
                .dispatcher
                .enter_mm_executor_for_thread(
                    state.kernel_thread.as_ref().map(Arc::clone),
                    Arc::clone(&state.kicker),
                    state.this_tid,
                )
                .expect("delayed guest exec MM participation"),
        );
        let failing_sibling = process_owner_drain_failure(&state);
        let executable = suffix_failure_test_executable();
        let path = executable.path().to_string_lossy().into_owned();
        let scheduler = kernel
            .hvpatch_runtime
            .as_ref()
            .expect("HVPatch runtime")
            .continuation_services(context.kernel())
            .0;
        let mut job =
            suffix_failure_test_job(&kernel, state, HvpatchProductionPhase::Resident, None);
        let need_resched = std::sync::atomic::AtomicBool::new(false);
        let mut submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: None,
            lease: None,
            exec_replacement: None,
        };
        let mut control = executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
        let mut engine = CrashCaptureTestEngine::default();

        let first = job
            .service_outcome(
                &mut engine,
                &mut control,
                execve_test_frame(),
                DispatchOutcome::Execve {
                    path: path.clone(),
                    argv: vec![path.into_bytes()],
                    env: Vec::new(),
                },
            )
            .expect("guest exec must retain its prepared owner while drain is pending");
        assert!(matches!(
            first,
            executor::ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::ChildState)
        ));
        assert!(matches!(
            job.phase,
            HvpatchProductionPhase::ExecSiblingDrain { .. }
        ));
        failing_sibling.completion().publish();

        assert_production_exec_terminal_failure(
            &mut job,
            &mut engine,
            &mut control,
            "drained-member settlement attempted to replace process-owner outcome",
            ExecCompletionOrigin::GuestSyscall,
            ThreadId::synthetic_for_tests(74_134),
        );
        assert_eq!(preparations.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(engine.exec_inventory_arms, 0);
        assert_eq!(engine.execve_installs, 0);
        assert_no_exec_return_publication(&kernel, &engine, &returns, &events);
        assert!(job.state.syscall_completion.is_idle());
        assert_exact_configuration_error(
            job.state
                .finish_authenticated_exec_completion(AuthenticatedExecCompletionOrigin(
                    ExecCompletionOrigin::GuestSyscall,
                ))
                .expect_err("delayed guest origin must be one-shot"),
            "threaded syscall retired without guest completion ownership",
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn typed_completion_ownership_delayed_internal_exec_drain_finish_error_consumes_origin() {
        let preparations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let returns = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_observer(Arc::new(ExecPreparationCounter(Arc::clone(&preparations))));
        dispatcher.install_observer(Arc::new(CompletionOrderObserver {
            events: Arc::clone(&events),
            returns: Arc::clone(&returns),
        }));
        let (kernel, context, mut state) = typed_completion_fixture(72_428, dispatcher);
        state.begin_internal_control_exec().unwrap();
        state.guest_execution = Some(
            kernel
                .dispatcher
                .enter_mm_executor_for_thread(
                    state.kernel_thread.as_ref().map(Arc::clone),
                    Arc::clone(&state.kicker),
                    state.this_tid,
                )
                .expect("delayed internal exec MM participation"),
        );
        let failing_sibling = process_owner_drain_failure(&state);
        let executable = suffix_failure_test_executable();
        let path = executable.path().to_string_lossy().into_owned();
        let work = external_exec_work_for_test(path, &context);
        let scheduler = kernel
            .hvpatch_runtime
            .as_ref()
            .expect("HVPatch runtime")
            .continuation_services(context.kernel())
            .0;
        let mut job =
            suffix_failure_test_job(&kernel, state, HvpatchProductionPhase::Resident, Some(work));
        let need_resched = std::sync::atomic::AtomicBool::new(false);
        let mut submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: None,
            lease: None,
            exec_replacement: None,
        };
        let mut control = executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
        let mut engine = CrashCaptureTestEngine::default();

        let first = job
            .start_external_exec(&mut engine, &mut control)
            .expect("internal exec must retain its prepared owner while drain is pending");
        assert!(matches!(
            first,
            executor::ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::ChildState)
        ));
        assert!(matches!(
            job.phase,
            HvpatchProductionPhase::ExecSiblingDrain { .. }
        ));
        failing_sibling.completion().publish();

        assert_production_exec_terminal_failure(
            &mut job,
            &mut engine,
            &mut control,
            "drained-member settlement attempted to replace process-owner outcome",
            ExecCompletionOrigin::InternalControl,
            ThreadId::synthetic_for_tests(74_135),
        );
        assert_eq!(preparations.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(engine.exec_inventory_arms, 0);
        assert_eq!(engine.execve_installs, 0);
        assert_no_exec_return_publication(&kernel, &engine, &returns, &events);
        assert!(job.state.syscall_completion.is_idle());
        assert_exact_configuration_error(
            job.state
                .finish_authenticated_exec_completion(AuthenticatedExecCompletionOrigin(
                    ExecCompletionOrigin::InternalControl,
                ))
                .expect_err("delayed internal origin must be one-shot"),
            "internal control exec lost typed ownership",
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn typed_completion_ownership_immediate_guest_exec_suffix_error_consumes_origin() {
        let preparations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let returns = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_observer(Arc::new(ExecPreparationCounter(Arc::clone(&preparations))));
        dispatcher.install_observer(Arc::new(CompletionOrderObserver {
            events: Arc::clone(&events),
            returns: Arc::clone(&returns),
        }));
        let (kernel, context, mut state) = typed_completion_fixture(72_405, dispatcher);
        install_typed_guest_completion(&kernel, &context, &mut state);
        let executable = suffix_failure_test_executable();
        let path = executable.path().to_string_lossy().into_owned();
        let scheduler = kernel
            .hvpatch_runtime
            .as_ref()
            .expect("HVPatch runtime")
            .continuation_services(context.kernel())
            .0;
        let mut job =
            suffix_failure_test_job(&kernel, state, HvpatchProductionPhase::Resident, None);
        let need_resched = std::sync::atomic::AtomicBool::new(false);
        let mut submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: None,
            lease: None,
            exec_replacement: None,
        };
        let mut control = executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
        let frame = carrick_hal::RawSyscall {
            number: carrick_abi::CanonicalNr(221),
            args: [0; 6],
            guest_abi: carrick_abi::LinuxGuestAbi::Aarch64,
            native_number: carrick_abi::NativeNr(221),
        };
        let mut engine = CrashCaptureTestEngine::default();

        let error = job
            .service_outcome(
                &mut engine,
                &mut control,
                frame,
                DispatchOutcome::Execve {
                    path: path.clone(),
                    argv: vec![path.into_bytes()],
                    env: Vec::new(),
                },
            )
            .expect_err("missing execution lease must fail the prepared suffix");

        assert_exact_configuration_error(
            error,
            "exec replacement lost worker-authenticated execution lease",
        );
        assert_eq!(preparations.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(engine.exec_inventory_arms, 1);
        assert_eq!(engine.execve_installs, 0);
        assert_no_exec_return_publication(&kernel, &engine, &returns, &events);
        assert!(job.state.syscall_completion.is_idle());
        assert!(
            job.state
                .finish_authenticated_exec_completion(AuthenticatedExecCompletionOrigin(
                    ExecCompletionOrigin::GuestSyscall,
                ))
                .is_err(),
            "the suffix owner must consume the authenticated origin exactly once"
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn typed_completion_ownership_immediate_internal_exec_suffix_error_consumes_origin() {
        use crate::kernel::control::{
            CarrierExecAdmission, ControlNonce, ExecAttach, ExecCapability, ExecRequest,
            ExecRuntime, ExecStatus,
        };

        let preparations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let returns = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_observer(Arc::new(ExecPreparationCounter(Arc::clone(&preparations))));
        dispatcher.install_observer(Arc::new(CompletionOrderObserver {
            events: Arc::clone(&events),
            returns: Arc::clone(&returns),
        }));
        let (kernel, context, mut state) = typed_completion_fixture(72_406, dispatcher);
        state.begin_internal_control_exec().unwrap();
        let executable = suffix_failure_test_executable();
        let path = executable.path().to_string_lossy().into_owned();
        let runtime = ExecRuntime::new(1);
        let capability = ExecCapability::from(ControlNonce::fresh().expect("control nonce"));
        let submit_runtime = runtime.clone();
        let submitted_path = path.clone();
        let submitter = std::thread::spawn(move || {
            submit_runtime.admit(
                capability,
                ExecRequest {
                    argv: vec![submitted_path],
                    env: Vec::new(),
                    workdir: None,
                    user: None,
                    tty: false,
                    attach: ExecAttach::Capture,
                },
            )
        });
        while runtime.query(capability) != ExecStatus::Pending {
            std::thread::yield_now();
        }
        let mut work = loop {
            if let Some(work) = runtime.try_take() {
                break work;
            }
            std::thread::yield_now();
        };
        assert!(work.begin_publication());
        assert!(work.admit(context.task().key().into()));
        assert_eq!(submitter.join().expect("exec submitter"), Ok(capability));
        let scheduler = kernel
            .hvpatch_runtime
            .as_ref()
            .expect("HVPatch runtime")
            .continuation_services(context.kernel())
            .0;
        let mut job =
            suffix_failure_test_job(&kernel, state, HvpatchProductionPhase::Resident, Some(work));
        let need_resched = std::sync::atomic::AtomicBool::new(false);
        let mut submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: None,
            lease: None,
            exec_replacement: None,
        };
        let mut control = executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
        let mut engine = CrashCaptureTestEngine::default();

        let error = job
            .start_external_exec(&mut engine, &mut control)
            .expect_err("missing execution lease must fail internal prepared suffix");

        assert_exact_configuration_error(
            error,
            "exec replacement lost worker-authenticated execution lease",
        );
        assert_eq!(preparations.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(engine.exec_inventory_arms, 1);
        assert_eq!(engine.execve_installs, 0);
        assert_no_exec_return_publication(&kernel, &engine, &returns, &events);
        assert!(job.state.syscall_completion.is_idle());
        assert!(
            job.state
                .finish_authenticated_exec_completion(AuthenticatedExecCompletionOrigin(
                    ExecCompletionOrigin::InternalControl,
                ))
                .is_err(),
            "the internal origin must be single-use"
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn assert_delayed_exec_suffix_error_consumes_origin(pid: i32, origin: ExecCompletionOrigin) {
        let preparations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let returns = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_observer(Arc::new(ExecPreparationCounter(Arc::clone(&preparations))));
        dispatcher.install_observer(Arc::new(CompletionOrderObserver {
            events: Arc::clone(&events),
            returns: Arc::clone(&returns),
        }));
        let (kernel, context, mut state) = typed_completion_fixture(pid, dispatcher);
        match origin {
            ExecCompletionOrigin::GuestSyscall => {
                install_typed_guest_completion(&kernel, &context, &mut state);
            }
            ExecCompletionOrigin::InternalControl => {
                state.begin_internal_control_exec().unwrap();
            }
        }
        state.guest_execution = Some(
            kernel
                .dispatcher
                .enter_mm_executor_for_thread(
                    state.kernel_thread.as_ref().map(Arc::clone),
                    Arc::clone(&state.kicker),
                    state.this_tid,
                )
                .expect("delayed exec MM participation"),
        );
        let executable = suffix_failure_test_executable();
        let path = executable.path().to_string_lossy().into_owned();
        let mut engine = CrashCaptureTestEngine::default();
        let exec::ExecvePreparation::Prepared(prepared) = state
            .prepare_execve(
                &kernel,
                &context,
                &mut engine,
                path.clone(),
                vec![path.into_bytes()],
                Vec::new(),
                origin,
            )
            .expect("valid guest exec preparation")
        else {
            panic!("valid guest exec must reach the destructive suffix")
        };
        let completion = continuation::LogicalJobCompletion::pending();
        let owner = state
            .prepared_execve_drain_for_test(
                *prepared,
                continuation::ProcessDrain::excluding(completion.clone(), Vec::new()),
            )
            .expect("test sibling drain must transfer authenticated ownership");
        let phase = HvpatchProductionPhase::ExecSiblingDrain {
            context: context.retain_exact(),
            owner,
        };
        let scheduler = kernel
            .hvpatch_runtime
            .as_ref()
            .expect("HVPatch runtime")
            .continuation_services(context.kernel())
            .0;
        let mut job = suffix_failure_test_job(&kernel, state, phase, None);
        let need_resched = std::sync::atomic::AtomicBool::new(false);
        let mut submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: None,
            lease: None,
            exec_replacement: None,
        };
        let mut control = executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);

        assert_production_exec_terminal_failure(
            &mut job,
            &mut engine,
            &mut control,
            "exec replacement lost worker-authenticated execution lease",
            origin,
            ThreadId::synthetic_for_tests(pid + 2_000),
        );
        assert_eq!(preparations.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(engine.exec_inventory_arms, 1);
        assert_eq!(engine.execve_installs, 0);
        assert_no_exec_return_publication(&kernel, &engine, &returns, &events);
        assert!(job.state.syscall_completion.is_idle());
        assert!(
            job.state
                .finish_authenticated_exec_completion(AuthenticatedExecCompletionOrigin(origin))
                .is_err(),
            "the delayed suffix must consume its origin exactly once"
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn two_task_mm_thread_sibling_sharing_manager_does_not_error() {
        let (kernel, context, state1) = typed_completion_fixture(79_001, SyscallDispatcher::new());
        let mut job1 =
            suffix_failure_test_job(&kernel, state1, HvpatchProductionPhase::Resident, None);

        let mut engine = CrashCaptureTestEngine::default();
        let scheduler = kernel
            .hvpatch_runtime
            .as_ref()
            .expect("HVPatch runtime")
            .continuation_services(context.kernel())
            .0;
        let need_resched = std::sync::atomic::AtomicBool::new(false);
        let mut submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: None,
            lease: None,
            exec_replacement: None,
        };
        let mut control = executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);

        // Task 1 of the MM runs and polls.
        let _ = job1.poll_with_engine(&mut engine, &mut control);

        // Task 2 (thread sibling in the same MM) runs and polls with the same engine.
        // Under the old first-poll install, task 2 attempted a second install of the arena source
        // on the shared manager and panicked/errored with "stage-1 table arena source is already installed".
        // Now, arena sources are MM properties installed at MM creation, so sibling task polling does not error.
        let (_, _, state2) = typed_completion_fixture(79_002, SyscallDispatcher::new());
        let mut job2 =
            suffix_failure_test_job(&kernel, state2, HvpatchProductionPhase::Resident, None);
        let _ = job2.poll_with_engine(&mut engine, &mut control);

        // Neither task panicked or attempted a redundant arena source installation.
        assert_eq!(engine.installed_table_arena_sources, 0);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn typed_completion_ownership_delayed_guest_and_internal_suffix_errors_consume_origins() {
        for (pid, origin) in [
            (72_407, ExecCompletionOrigin::GuestSyscall),
            (72_408, ExecCompletionOrigin::InternalControl),
        ] {
            assert_delayed_exec_suffix_error_consumes_origin(pid, origin);
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn typed_completion_ownership_external_exec_bootstrap_is_tokenless_and_nonpublishing() {
        use crate::kernel::control::{
            CarrierExecAdmission, ControlNonce, ExecAttach, ExecCapability, ExecRequest,
            ExecRuntime, ExecStatus,
        };

        let preparation_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let returns = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_observer(Arc::new(ExecPreparationCounter(Arc::clone(
            &preparation_count,
        ))));
        dispatcher.install_observer(Arc::new(CompletionOrderObserver {
            events: Arc::clone(&events),
            returns: Arc::clone(&returns),
        }));
        let (runtime, scheduler, kernel, root, process, root_generation) =
            test_carrier_graph_with_dispatcher!(72_401, dispatcher);
        let root_authority = runtime
            .persistent_bindings()
            .take_submission_authority(root.thread().key(), root_generation)
            .expect("root submission authority");
        let this_tid = ThreadId::synthetic_for_tests(72_401);
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
            Arc::new(ThreadRegistry::new(this_tid)),
            Arc::new(FutexTable::new()),
            platform,
            platform_factory,
            kernel.process_fork_barrier.clone(),
            kernel.crash_capture.clone(),
            Some(Arc::clone(root.thread())),
            Some(process.pid()),
            root.thread().key().tid,
            kernel.fatal_signal.current_generation(),
            this_tid,
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(carrick_hal::GenericVcpuRegistry::new()),
            carrick_hal::InGuestFlag::for_guest_thread(),
            1_000,
        );
        state.service_kernel_context = Some(root.retain_exact());

        let exec_runtime = ExecRuntime::new(1);
        let capability = ExecCapability::from(ControlNonce::fresh().expect("control nonce"));
        let submit_runtime = exec_runtime.clone();
        let submitter = std::thread::spawn(move || {
            submit_runtime.admit(
                capability,
                ExecRequest {
                    argv: vec!["/definitely/missing/external-control-exec".to_owned()],
                    env: Vec::new(),
                    workdir: None,
                    user: None,
                    tty: false,
                    attach: ExecAttach::Capture,
                },
            )
        });
        while exec_runtime.query(capability) != ExecStatus::Pending {
            std::thread::yield_now();
        }
        let work = loop {
            if let Some(work) = exec_runtime.try_take() {
                break work;
            }
            std::thread::yield_now();
        };

        let need_resched = std::sync::atomic::AtomicBool::new(false);
        let mut parent_submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: Some(&root_authority),
            lease: None,
            exec_replacement: None,
        };
        let mut parent_control =
            executor::HvpatchQuantumControl::for_test(&need_resched, &mut parent_submission);
        let mut memory = Memory::default();
        let prepared = state
            .prepare_in_process_fork(
                &kernel,
                &root,
                &mut memory,
                &mut parent_control,
                &mut FakeBackendOps::default(),
                quiesce::ProcessForkAttempt {
                    request: quiesce::ForkRequest {
                        flags: 0,
                        pidfd_out: None,
                        clone_parent: false,
                        parent_tid_addr: None,
                        child_tid_addr: None,
                        exit_signal: 0,
                        child_stack: 0,
                        vfork: None,
                    },
                    coordinator: None,
                    external_exec: Some(work),
                },
            )
            .expect("actual external exec process-child publication");
        let quiesce::PreparedInProcessFork::Complete(Some(child_pid)) = prepared else {
            panic!("external exec fork must publish one runnable child")
        };
        assert_eq!(submitter.join().expect("exec submitter"), Ok(capability));

        let child_id =
            crate::kernel::TaskId::for_root_bootstrap(child_pid as i32).expect("child task id");
        let child_context = root
            .kernel()
            .context(child_id, crate::kernel::LinuxTid::for_task_leader(child_id))
            .expect("published child context");
        let child_generation = child_context
            .thread()
            .execution_state()
            .generation()
            .expect("published child execution generation");
        let child_binding = runtime
            .persistent_bindings()
            .resolve(child_context.thread().key(), child_generation)
            .expect("active external exec child binding");
        let child_authority = runtime
            .persistent_bindings()
            .take_submission_authority(child_context.thread().key(), child_generation)
            .expect("child submission authority");

        let root_executor = scheduler
            .register_executor(Arc::new(RuntimeTestExecutorKick::default()))
            .expect("root executor");
        let child_executor = scheduler
            .register_executor(Arc::new(RuntimeTestExecutorKick::default()))
            .expect("child executor");
        let root_running = scheduler.take(&root_executor).expect("take queued root");
        assert_eq!(root_running.thread_key(), root.thread().key());
        let mut child_running = scheduler.take(&child_executor).expect("take queued child");
        assert_eq!(child_running.thread_key(), child_context.thread().key());

        let mut engine = CrashCaptureTestEngine::default();
        let mut child_submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: Some(&child_authority),
            lease: Some(child_running.take_lease()),
            exec_replacement: None,
        };
        let exit = {
            let mut child_control =
                executor::HvpatchQuantumControl::for_test(&need_resched, &mut child_submission);
            child_binding
                .quantum()
                .poll_quantum_with_engine(&mut engine, &mut child_control)
        };
        child_running
            .restore_lease(child_submission.lease.take().expect("returned child lease"))
            .expect("restore child lease");
        match exit {
            executor::ExecutorExit::Blocked(reason) => {
                scheduler
                    .settle_blocked(child_running, reason)
                    .expect("settle blocked external exec child");
            }
            executor::ExecutorExit::Exited => scheduler
                .settle_exited(child_running)
                .expect("settle exited external exec child"),
            executor::ExecutorExit::Syscall
            | executor::ExecutorExit::Yielded
            | executor::ExecutorExit::Preempted => scheduler
                .settle_runnable(child_running)
                .expect("settle runnable external exec child"),
            other => panic!("unexpected external exec bootstrap exit: {other:?}"),
        }
        scheduler
            .settle_runnable(root_running)
            .expect("settle untouched root");
        drop(child_authority);
        drop(root_authority);

        assert_eq!(
            preparation_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "bootstrap must consume queued work through start_external_exec"
        );
        assert!(engine.completed_syscalls.is_empty());
        assert!(returns.lock().is_empty());
        assert!(events.lock().is_empty());
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn typed_completion_ownership_guest_exec_missing_token_is_rejected() {
        let dispatcher = SyscallDispatcher::new();
        let (_runtime, _scheduler, kernel, root, process, _generation) =
            test_carrier_graph_with_dispatcher!(72_402, dispatcher);
        let this_tid = ThreadId::synthetic_for_tests(72_402);
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
            Arc::new(ThreadRegistry::new(this_tid)),
            Arc::new(FutexTable::new()),
            platform,
            platform_factory,
            kernel.process_fork_barrier.clone(),
            kernel.crash_capture.clone(),
            Some(Arc::clone(root.thread())),
            Some(process.pid()),
            root.thread().key().tid,
            kernel.fatal_signal.current_generation(),
            this_tid,
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(carrick_hal::GenericVcpuRegistry::new()),
            carrick_hal::InGuestFlag::for_guest_thread(),
            1_000,
        );
        state.service_kernel_context = Some(root.retain_exact());
        let mut engine = CrashCaptureTestEngine::default();

        let error = match state.prepare_execve(
            &kernel,
            &root,
            &mut engine,
            "/definitely/missing/carrick-exec".to_owned(),
            vec![b"missing".to_vec()],
            Vec::new(),
            ExecCompletionOrigin::GuestSyscall,
        ) {
            Ok(_) => panic!("guest exec without its completion token must fail closed"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("guest exec missing completion token")
        );
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn typed_completion_ownership_guest_valid_exec_authenticates_before_preparation() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;

        let preparation_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_observer(Arc::new(ExecPreparationCounter(Arc::clone(
            &preparation_count,
        ))));
        let (kernel, context, mut state) = typed_completion_fixture(72_404, dispatcher);
        let mut executable = tempfile::NamedTempFile::new().expect("synthetic executable");
        executable
            .write_all(&synthetic_elf(183))
            .expect("write synthetic ELF");
        let mut permissions = executable
            .as_file()
            .metadata()
            .expect("synthetic ELF metadata")
            .permissions();
        permissions.set_mode(0o700);
        executable
            .as_file()
            .set_permissions(permissions)
            .expect("mark synthetic ELF executable");
        let path = executable.path().to_string_lossy().into_owned();
        let mut engine = CrashCaptureTestEngine::default();

        let error = match state.prepare_execve(
            &kernel,
            &context,
            &mut engine,
            path.clone(),
            vec![path.into_bytes()],
            Vec::new(),
            ExecCompletionOrigin::GuestSyscall,
        ) {
            Ok(_) => panic!("guest exec without its completion token must fail before preparation"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("guest exec missing completion token")
        );
        assert_eq!(
            preparation_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "authentication must precede observer-visible exec preparation"
        );
        assert_eq!(engine.execve_installs, 0);
        assert!(engine.completed_syscalls.is_empty());
        assert_eq!(kernel.reporter.snapshot().summary.syscall_returns_ok, 0);
        assert_eq!(kernel.reporter.snapshot().summary.syscall_returns_errno, 0);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn typed_completion_ownership_internal_exec_failure_is_tokenless_and_nonpublishing() {
        let dispatcher = SyscallDispatcher::new();
        let (_runtime, _scheduler, kernel, root, process, _generation) =
            test_carrier_graph_with_dispatcher!(72_403, dispatcher);
        let this_tid = ThreadId::synthetic_for_tests(72_403);
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
            Arc::new(ThreadRegistry::new(this_tid)),
            Arc::new(FutexTable::new()),
            platform,
            platform_factory,
            kernel.process_fork_barrier.clone(),
            kernel.crash_capture.clone(),
            Some(Arc::clone(root.thread())),
            Some(process.pid()),
            root.thread().key().tid,
            kernel.fatal_signal.current_generation(),
            this_tid,
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(carrick_hal::GenericVcpuRegistry::new()),
            carrick_hal::InGuestFlag::for_guest_thread(),
            1_000,
        );
        state.service_kernel_context = Some(root.retain_exact());
        state.begin_internal_control_exec().unwrap();
        let mut engine = CrashCaptureTestEngine::default();

        let result = state
            .prepare_execve(
                &kernel,
                &root,
                &mut engine,
                "/definitely/missing/carrick-control-exec".to_owned(),
                vec![b"missing".to_vec()],
                Vec::new(),
                ExecCompletionOrigin::InternalControl,
            )
            .unwrap();
        assert!(matches!(result, exec::ExecvePreparation::Complete(None)));
        assert!(state.syscall_completion.is_idle());
        assert!(engine.completed_syscalls.is_empty());
        assert_eq!(kernel.reporter.snapshot().summary.syscall_returns_ok, 0);
        assert_eq!(kernel.reporter.snapshot().summary.syscall_returns_errno, 0);
    }
}
