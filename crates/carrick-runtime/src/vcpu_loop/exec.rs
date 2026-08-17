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

enum RuntimePreparedExec {
    Hvpatch(crate::hvpatch::PreparedProcessExec),
    Other(crate::kernel::PreparedExec),
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
}

fn should_update_host_process_title(is_hvpatch: bool) -> bool {
    // HvPatch multiplexes many Linux processes inside one host process. A
    // per-guest exec cannot truthfully rename that shared process, and the
    // macOS helper also overwrites the executing host thread's stable
    // `guest-pid-*` name used by LLDB. Legacy one-process backends retain the
    // useful process-title update.
    !is_hvpatch
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
        HvpatchExecInventoryFailureInjection, apply_exec_inventory,
        exec_regions_to_verify_with_mappings, first_byte_mismatch,
        parse_hvpatch_exec_inventory_failure_injection, should_update_host_process_title,
    };

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

    /// `Ok(None)` means the syscall finished — the image was replaced, or the
    /// exec failed with an errno and the caller is still running its old
    /// image. `Ok(Some(outcome))` means the process is terminating.
    pub(super) fn handle_execve(
        &mut self,
        kernel: &Kernel,
        kernel_context: &crate::kernel::KernelContext,
        engine: &mut E,
        path: String,
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
    ) -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
        if let Some(process) = kernel.hvpatch_process.as_ref() {
            process.trace_lifecycle(
                carrick_observability::probes::HvpatchGuestLifecyclePhase::ExecBegin,
                self.this_tid,
                0,
            );
        }
        crate::probes::execve_argv(&path, &argv);
        // The proctitle / /proc/self/cmdline identity is display text; lossily
        // decode the byte argv (a genuinely non-UTF-8 argv is rare).
        let proc_argv: Vec<String> = argv
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        let cmdline = proc_argv.join(" ");
        let proc_env = env.clone();
        let loaded = kernel
            .dispatcher
            .with_kernel_credentials(kernel_context, || {
                load_execve_image(&kernel.dispatcher, &path, argv, env)
            });
        match loaded {
            Ok(img) => {
                let inventory_failure_injection = kernel
                    .hvpatch_process
                    .as_ref()
                    .and_then(|_| hvpatch_exec_inventory_failure_injection(&path));
                // Close thread-clone admission across the full destructive
                // exec transaction. Every pre-existing permit must either
                // publish a handle-visible started child or roll back before
                // sibling census and VM replacement; Drop reopens only if a
                // concurrent process exit did not promote the gate to Exit.
                let _clone_admission = match kernel.close_clone_admission_for_exec(self.this_tid) {
                    Ok(admission) => admission,
                    // BEFORE the point of no return: nothing has been destroyed
                    // yet, so this is a syscall failure, not a dead process.
                    // The drain is bounded by a wall-clock timeout, so this is
                    // reachable under load — and it used to kill the caller.
                    //
                    // DIVERGENCE, stated plainly: Linux has no such drain and
                    // would never fail `execve` here, so there is no faithful
                    // errno. EAGAIN is the honest approximation — "resource
                    // temporarily unavailable", which is retryable and which a
                    // caller can act on. A dead process is not.
                    Err(error) => {
                        tracing::error!(
                            %error,
                            "execve clone-admission drain failed before the point of no return"
                        );
                        return Self::exec_failed_with_errno(
                            engine,
                            crate::linux_abi::LINUX_EAGAIN,
                        );
                    }
                };
                crate::probes::execve_loaded(
                    &path,
                    img.entry(),
                    img.initial_stack_pointer().unwrap_or(0),
                    img.regions().len() as u64,
                );
                let runtime_region_count = img.regions().len() as u64;
                let runtime_mapped_bytes = img.regions().iter().map(|region| region.len()).sum();
                let emit_runtime_stage =
                    |phase: carrick_observability::probes::HvpatchExecRuntimeStagePhase,
                     started: std::time::Instant| {
                        if kernel.hvpatch_process.is_some() {
                            let elapsed_ns =
                                started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
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
                let sibling_drain_started = std::time::Instant::now();
                // THE POINT OF NO RETURN. Destroying the thread group cannot
                // be undone, so from here `execve` must never return to the
                // guest — the same place Linux puts it (`de_thread` inside
                // `begin_new_exec`, after which Linux uses `force_sigsegv`).
                // A partial drain leaves a half-dead thread group, so even this
                // step's OWN failure is past the line.
                if self.registry.live_count() > 1
                    && let Err(error) = self.terminate_siblings_for_exec(kernel, engine)
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
                let exec_kernel_context =
                    refreshed_hvpatch_context.as_ref().unwrap_or(kernel_context);
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
                        old_extent_count =
                            carrick_hal::MAX_FRAME_INVENTORY_EVENTS_PER_BATCH / 2 + 1;
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
                    let replacement_capacity = match super::quiesce::inventory_capacity_for_extents(
                        replacement_extent_count,
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
                    let retired =
                        match process
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
                if let Err(error) = engine.execve_into(&img) {
                    return Self::exec_failed_past_no_return(
                        kernel,
                        engine,
                        &format!("replace guest image: {error}"),
                    )
                    .map(Some);
                }
                // `execve_into` has released every stage-2/frame lock. Topology
                // serialization must also be released before runtime takes its
                // frame-inventory authority lock.
                drop(_hvpatch_topology);
                if let Some(process) = kernel.hvpatch_process.as_ref() {
                    let Some((retired_commit, replacement_commit)) = engine.take_exec_inventory()
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
                let committed_context =
                    match (kernel.hvpatch_process.as_ref(), prepared_kernel_exec) {
                        (Some(process), RuntimePreparedExec::Hvpatch(prepared)) => {
                            const TTBR_ROOT_MASK: u64 = (1_u64 << 48) - 1;
                            let stage1_root = match engine.get_sys_reg(carrick_hal::SysReg::Ttbr0) {
                                Ok(root) => root & TTBR_ROOT_MASK,
                                Err(error) => {
                                    return Self::exec_failed_past_no_return(
                                    kernel,
                                    engine,
                                    &format!(
                                        "read HVPatch stage-1 root after destructive exec: {error}"
                                    ),
                                )
                                .map(Some);
                                }
                            };
                            process.commit_exec(
                                prepared,
                                stage1_root,
                                kernel.dispatcher.vma_snapshot_source(),
                            )
                        }
                        (None, RuntimePreparedExec::Other(prepared)) => {
                            kernel.dispatcher.commit_one_task_kernel_exec(prepared)
                        }
                        _ => {
                            tracing::error!("exec preparation/backend authority mismatch");
                            std::process::abort();
                        }
                    };
                let committed_context = match committed_context {
                    Ok(context) => context,
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
                    let committed_mm = committed_context.shared().mm().id();
                    let authority: std::sync::Arc<dyn carrick_hal::FrameCowAuthority> =
                        std::sync::Arc::new(super::KernelFrameCowAuthority {
                            kernel: std::sync::Arc::clone(committed_context.kernel()),
                            mm: committed_mm,
                            guest_executors: std::sync::Arc::clone(&kernel.guest_executors),
                            kicker: std::sync::Arc::clone(&self.kicker),
                            tid: self.this_tid,
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
                        tracing::error!(
                            "committed exec could not rebind fatal-signal image authority"
                        );
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
            Err(errno) => {
                if std::env::var_os("CARRICK_FAULT_DEBUG").is_some() {
                    eprintln!(
                        "[FAULTDBG tid={}] execve path={path:?} failed errno={}",
                        self.this_tid.raw(),
                        errno.get()
                    );
                }
                Self::exec_failed_with_errno(engine, errno)
            }
        }
    }
}
