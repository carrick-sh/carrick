//! PROC concern: execve of the vCPU run loop.
//!
//! Split out of `vcpu_loop/mod.rs` (Task A2). Pure relocation — no logic
//! changes; only `mod`/`use`/visibility wiring differs.

use super::*;

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

fn apply_exec_inventory<E>(
    old_mm: crate::kernel::MmId,
    replacement_mm: crate::kernel::MmId,
    retired: carrick_hal::FrameInventoryCommit<()>,
    replacement: carrick_hal::FrameInventoryCommit<()>,
    mut apply: impl FnMut(crate::kernel::MmId, carrick_hal::FrameInventoryCommit<()>) -> Result<(), E>,
) -> Result<(), E> {
    apply(old_mm, retired)?;
    apply(replacement_mm, replacement)
}

#[derive(Default)]
struct ExecBackendPublicationGate {
    engine_replaced: bool,
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
    Hvpatch(crate::hvpatch::PreparedProcessExec),
    Other(crate::kernel::PreparedExec),
}

pub(super) struct PreparedExecve {
    image: AddressSpace,
    path: String,
    proc_argv: Vec<String>,
    proc_env: Vec<Vec<u8>>,
    command_line: String,
    inventory_failure_injection: Option<HvpatchExecInventoryFailureInjection>,
    _clone_admission: ExecCloneAdmission,
    runtime_region_count: u64,
    runtime_mapped_bytes: u64,
    sibling_drain_started: std::time::Instant,
}

pub(super) enum ExecvePreparation {
    Complete(Option<VcpuLoopOutcome>),
    Prepared(Box<PreparedExecve>),
}

enum ExecveInput {
    Fresh {
        path: String,
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
    },
    Prepared(Box<PreparedExecve>),
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
        ExecBackendPublicationGate, HvpatchExecInventoryFailureInjection, apply_exec_inventory,
        exec_regions_to_verify_with_mappings, first_byte_mismatch,
        parse_hvpatch_exec_inventory_failure_injection, publish_execution_authority_after_exec,
        retire_execution_authority_for_exec, should_update_host_process_title,
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
        apply_exec_inventory(old_mm, replacement_mm, retired, replacement, |mm, _| {
            routed.push(mm);
            Ok::<(), ()>(())
        })
        .unwrap();

        assert_eq!(routed, [old_mm, replacement_mm]);
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
        engine: &mut E,
        errno: crate::linux_abi::LinuxErrno,
    ) -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
        engine.complete_syscall(errno.guest_retval())?;
        Ok(None)
    }

    pub(super) fn prepare_execve(
        &mut self,
        kernel: &Kernel,
        kernel_context: &crate::kernel::KernelContext,
        engine: &mut E,
        path: String,
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
    ) -> Result<ExecvePreparation, RuntimeError> {
        if let Some(process) = kernel.hvpatch_process.as_ref() {
            process.trace_lifecycle(
                carrick_observability::probes::HvpatchGuestLifecyclePhase::ExecBegin,
                self.this_tid,
                0,
            );
        }
        crate::probes::execve_argv(&path, &argv);
        let proc_argv: Vec<String> = argv
            .iter()
            .map(|argument| String::from_utf8_lossy(argument).into_owned())
            .collect();
        let command_line = proc_argv.join(" ");
        let proc_env = env.clone();
        let image = match kernel
            .dispatcher
            .with_kernel_credentials(kernel_context, || {
                load_execve_image(&kernel.dispatcher, &path, argv, env)
            }) {
            Ok(image) => image,
            Err(errno) => {
                if std::env::var_os("CARRICK_FAULT_DEBUG").is_some() {
                    eprintln!(
                        "[FAULTDBG tid={}] execve path={path:?} failed errno={}",
                        self.this_tid.raw(),
                        errno.get()
                    );
                }
                return Self::exec_failed_with_errno(engine, errno)
                    .map(ExecvePreparation::Complete);
            }
        };
        let inventory_failure_injection = kernel
            .hvpatch_process
            .as_ref()
            .and_then(|_| hvpatch_exec_inventory_failure_injection(&path));
        let clone_admission = match kernel.close_clone_admission_for_exec(self.this_tid) {
            Ok(admission) => admission,
            Err(error) => {
                tracing::error!(
                    %error,
                    "execve clone-admission drain failed before the point of no return"
                );
                return Self::exec_failed_with_errno(engine, crate::linux_abi::LINUX_EAGAIN)
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
            image,
            path,
            proc_argv,
            proc_env,
            command_line,
            inventory_failure_injection,
            _clone_admission: clone_admission,
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
        kernel_context: &crate::kernel::KernelContext,
        engine: &mut E,
        input: ExecveInput,
    ) -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
        let (prepared, needs_sibling_drain) = match input {
            ExecveInput::Fresh { path, argv, env } => {
                let prepared =
                    match self.prepare_execve(kernel, kernel_context, engine, path, argv, env)? {
                        ExecvePreparation::Complete(outcome) => return Ok(outcome),
                        ExecvePreparation::Prepared(prepared) => *prepared,
                    };
                (prepared, true)
            }
            ExecveInput::Prepared(prepared) => (*prepared, false),
        };
        let PreparedExecve {
            image: img,
            path,
            proc_argv,
            proc_env,
            command_line: cmdline,
            inventory_failure_injection,
            _clone_admission,
            runtime_region_count,
            runtime_mapped_bytes,
            sibling_drain_started,
        } = prepared;
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
        // THE POINT OF NO RETURN. Destroying the thread group cannot
        // be undone, so from here `execve` must never return to the
        // guest — the same place Linux puts it (`de_thread` inside
        // `begin_new_exec`, after which Linux uses `force_sigsegv`).
        // A partial drain leaves a half-dead thread group, so even this
        // step's OWN failure is past the line.
        if needs_sibling_drain
            && self.registry.live_count() > 1
            && let Err(error) = self.terminate_siblings_for_exec(kernel, engine).await
        {
            return Self::exec_failed_past_no_return(
                kernel,
                engine,
                &format!("terminate siblings for exec: {error}"),
            )
            .map(Some);
        }
        emit_runtime_stage(
            carrick_observability::probes::HvpatchExecRuntimeStagePhase::SiblingDrain,
            sibling_drain_started,
        );
        // Every HVPatch exec loser retires its exact authoritative
        // Kernel thread while the runtime drain waits above. That
        // advances the task revision, so the syscall-entry context is
        // deliberately stale by the time only the survivor remains.
        // Re-capture that survivor before preparing the Kernel exec;
        // using the pre-drain revision makes every multi-threaded exec
        // fail closed as a foreign context.
        let refreshed_hvpatch_context = match kernel.hvpatch_process.as_ref() {
            Some(process) => match process.context_for_linux_tid(self.linux_tid) {
                Ok(context) => Some(context),
                Err(error) => {
                    return Self::exec_failed_past_no_return(
                        kernel,
                        engine,
                        &format!("capture authoritative Kernel exec survivor: {error}"),
                    )
                    .map(Some);
                }
            },
            None => None,
        };
        let exec_kernel_context = refreshed_hvpatch_context.as_ref().unwrap_or(kernel_context);
        // Kernel preparation follows the runtime sibling drain (whose
        // exiting host loops retire their own old Kernel threads) but
        // precedes every destructive image, CLOEXEC, and proc-state
        // mutation. From here, the prepared exec transaction is the
        // sole owner of nonleader promotion and replacement Mm state.
        let prepared_kernel_exec = match kernel.hvpatch_process.as_ref() {
            Some(process) => process
                .prepare_exec(exec_kernel_context)
                .map(RuntimePreparedExec::Hvpatch),
            None => kernel
                .dispatcher
                .prepare_one_task_kernel_exec(exec_kernel_context)
                .map(RuntimePreparedExec::Other),
        };
        let mut prepared_kernel_exec = match prepared_kernel_exec {
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
        let old_mm_id = prepared_kernel_exec.old_mm_id();
        let replacement_mm_id = prepared_kernel_exec.replacement_mm_id();
        // Allocate both complete transaction envelopes before proc-state
        // mutation or topology/backend locking. Dropping the guard on
        // any pre-replacement failure abandons both runtime records and
        // dropping `prepared_kernel_exec` rolls back Kernel preparation.
        let _inventory_abandon = if let Some(process) = kernel.hvpatch_process.as_ref() {
            let (mut old_extent_count, replacement_extent_count) =
                engine.frame_inventory_exec_extent_counts(&img);
            if inventory_failure_injection
                == Some(HvpatchExecInventoryFailureInjection::OldCapacity)
            {
                old_extent_count = carrick_hal::MAX_FRAME_INVENTORY_EVENTS_PER_BATCH / 2 + 1;
            }
            let old_capacity =
                match super::quiesce::inventory_capacity_for_extents(old_extent_count) {
                    Ok(capacity) => capacity,
                    Err(error) => {
                        return Self::exec_failed_past_no_return(
                            kernel,
                            engine,
                            &format!("size HVPatch exec retirement inventory: {error}"),
                        )
                        .map(Some);
                    }
                };
            let replacement_capacity =
                match super::quiesce::inventory_capacity_for_extents(replacement_extent_count) {
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
            let retired = match process
                .kernel_graph()
                .reserve_frame_inventory(0, 0, old_capacity)
            {
                Ok(reservation) => reservation,
                Err(error) => {
                    return Self::exec_failed_past_no_return(
                        kernel,
                        engine,
                        &format!("reserve HVPatch exec retirement inventory: {error}"),
                    )
                    .map(Some);
                }
            };
            let retired_transaction = retired.transaction();
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
                    process
                        .kernel_graph()
                        .frame_inventory()
                        .abandon(retired_transaction);
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
                [retired_transaction, replacement_transaction],
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
        apply_exec_image_proc_state(&kernel.dispatcher, &img);
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

        // All hvpatch processes mutate stage-2 in one HVF VM. Keep
        // process-local thread-group drain separate, but serialize the
        // actual unmap/remap transaction across concurrent execs.
        let topology_lock_started = std::time::Instant::now();
        let _hvpatch_topology = kernel.hvpatch_process.as_ref().map(|process| {
            crate::fork_quiesce::acquire_topology_lock(
                carrick_observability::probes::HvpatchTopologyOperation::ExecReplace,
                process.pid(),
                self.this_tid.raw(),
            )
        });
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
        if let Err(error) =
            retire_execution_authority_for_exec(&retiring_thread, &self.execution_lease)
        {
            return Err(RuntimeError::Configuration(format!(
                "reject exec before backend replacement: {error}"
            )));
        }
        if let Err(error) = engine.execve_into(&img) {
            return Self::exec_failed_past_no_return(
                kernel,
                engine,
                &format!("replace guest image: {error}"),
            )
            .map(Some);
        }
        backend_publication_gate.record_engine_replaced();
        // `execve_into` has released every stage-2/frame lock. Topology
        // serialization must also be released before runtime takes its
        // frame-inventory authority lock.
        drop(_hvpatch_topology);
        if let Some(process) = kernel.hvpatch_process.as_ref() {
            let Some((retired_commit, replacement_commit)) =
                backend_publication_gate.take_after_replace(|| engine.take_exec_inventory())
            else {
                return Self::exec_failed_past_no_return(
                    kernel,
                    engine,
                    "HVPatch destructive exec produced no frame inventory commits",
                )
                .map(Some);
            };
            if let Err(error) = apply_exec_inventory(
                old_mm_id,
                replacement_mm_id,
                retired_commit,
                replacement_commit,
                |mm, commit| {
                    process
                        .kernel_graph()
                        .frame_inventory()
                        .apply(mm, commit)
                        .map(|_| ())
                },
            ) {
                return Self::exec_failed_past_no_return(
                            kernel,
                            engine,
                            &format!(
                                "apply HVPatch exec frame inventory for old mm {old_mm_id:?} and replacement mm {replacement_mm_id:?}: {error}"
                            ),
                        )
                        .map(Some);
            }
        }
        let old_files = prepared_kernel_exec.old_file_table();
        let committed = match (kernel.hvpatch_process.as_ref(), prepared_kernel_exec) {
            (Some(process), RuntimePreparedExec::Hvpatch(prepared)) => {
                const TTBR_ROOT_MASK: u64 = (1_u64 << 48) - 1;
                let stage1_root = match engine.get_sys_reg(carrick_hal::SysReg::Ttbr0) {
                    Ok(root) => root & TTBR_ROOT_MASK,
                    Err(error) => {
                        return Self::exec_failed_past_no_return(
                            kernel,
                            engine,
                            &format!("read HVPatch stage-1 root after destructive exec: {error}"),
                        )
                        .map(Some);
                    }
                };
                process
                    .commit_exec(
                        prepared,
                        stage1_root,
                        kernel.dispatcher.vma_snapshot_source(),
                    )
                    .map(|committed| (committed.context().retain_exact(), Some(committed)))
            }
            (None, RuntimePreparedExec::Other(prepared)) => kernel
                .dispatcher
                .commit_one_task_kernel_exec(prepared)
                .map(|context| (context, None)),
            _ => {
                tracing::error!("exec preparation/backend authority mismatch");
                std::process::abort();
            }
        };
        let (committed_context, committed_transition) = match committed {
            Ok(committed) => committed,
            Err(error) => {
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
                std::process::abort();
            }
        }
        // `exec` publishes a new Mm generation while keeping this host
        // engine/vCPU.  Frame-COW callbacks must therefore move from
        // the retired mm to the committed replacement before any
        // identity-page or guest write can fault.  Keeping the old
        // authority makes a structurally valid COW MappingId belong to
        // the retired mm and fail closed at replacement-mm teardown.
        if let Some(process) = kernel.hvpatch_process.as_ref() {
            let binding = process.mm_binding().ok_or_else(|| {
                RuntimeError::Configuration(
                    "committed HVPatch exec has no replacement mm binding".to_owned(),
                )
            })?;
            let authority: std::sync::Arc<dyn carrick_hal::FrameCowAuthority> =
                std::sync::Arc::new(super::KernelFrameCowAuthority {
                    kernel: std::sync::Arc::clone(committed_context.kernel()),
                    mm: committed_mm,
                    guest_executors: std::sync::Arc::clone(&kernel.guest_executors),
                    kicker: std::sync::Arc::clone(&self.kicker),
                    tid: self.this_tid,
                    identity: carrick_hal::FrameCowIdentity {
                        linux_pid: process.pid(),
                        linux_tid: self.this_tid.raw(),
                        mm: committed_mm.raw(),
                        asid: binding.asid.raw(),
                    },
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
        crate::namespace::pid::mark_self_execed();
        // execve_into rebuilt a fresh vCPU: re-stamp the identity page
        // (zeroed) and TPIDR_EL1 (reset) for the same thread/tid.
        let identity_base = if inventory_failure_injection
            == Some(HvpatchExecInventoryFailureInjection::IdentityPage)
        {
            u64::MAX - 0x100
        } else {
            crate::memory::LINUX_IDENTITY_PAGE_BASE
        };
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
        if let Err(error) = engine.set_guest_thread_id(self.linux_tid.raw() as u64) {
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
                tracing::error!("committed exec could not rebind fatal-signal image authority");
                std::process::abort();
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

    pub(super) async fn handle_execve(
        &mut self,
        kernel: &Kernel,
        kernel_context: &crate::kernel::KernelContext,
        engine: &mut E,
        path: String,
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
    ) -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
        self.drive_execve(
            kernel,
            kernel_context,
            engine,
            ExecveInput::Fresh { path, argv, env },
        )
        .await
    }

    /// Resume the destructive exec suffix after the persistent executor has
    /// loaded a fresh engine. `Prepared` bypasses the sole await arm in
    /// `drive_execve`; returning Pending is therefore a fail-closed state-machine
    /// bug, never an invitation to retain `&mut E`.
    pub(super) fn finish_prepared_execve(
        &mut self,
        kernel: &Kernel,
        kernel_context: &crate::kernel::KernelContext,
        engine: &mut E,
        prepared: PreparedExecve,
    ) -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
        let mut future = Box::pin(self.drive_execve(
            kernel,
            kernel_context,
            engine,
            ExecveInput::Prepared(Box::new(prepared)),
        ));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(result) => result,
            std::task::Poll::Pending => Err(RuntimeError::Configuration(
                "prepared exec suffix attempted to suspend with an injected engine".to_owned(),
            )),
        }
    }
}
