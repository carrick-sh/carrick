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

fn should_update_host_process_title(is_hvpatch: bool) -> bool {
    // HvPatch multiplexes many Linux processes inside one host process. A
    // per-guest exec cannot truthfully rename that shared process, and the
    // macOS helper also overwrites the executing host thread's stable
    // `guest-pid-*` name used by LLDB. Legacy one-process backends retain the
    // useful process-title update.
    !is_hvpatch
}

/// Fail-closed, opt-in proof that the image Carrick prepared for `execve` is
/// the image its freshly rebuilt engine exposes before the vCPU re-enters the
/// guest.  This deliberately reads through `ThreadedEngine::read_bytes`, the
/// same mapping-ledger path used by the fatal-fault recorder.  It therefore
/// distinguishes an already-wrong exec publication from corruption that only
/// appears after another process reuses the stage-2 bank.
fn verify_published_exec_image<E: ThreadedEngine>(
    engine: &E,
    image: &AddressSpace,
    path: &str,
) -> Result<(), RuntimeError> {
    const CHUNK_SIZE: usize = 64 * 1024;

    for region in image.regions().iter().filter(|region| region.perms.execute) {
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
    use super::{first_byte_mismatch, should_update_host_process_title};

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
}

impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>
where
    E::SiblingSpec: 'static,
{
    pub(super) fn handle_execve(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        path: String,
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
    ) -> Result<(), RuntimeError> {
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
        match load_execve_image(&kernel.dispatcher, &path, argv, env) {
            Ok(img) => {
                // Close thread-clone admission across the full destructive
                // exec transaction. Every pre-existing permit must either
                // publish a handle-visible started child or roll back before
                // sibling census and VM replacement; Drop reopens only if a
                // concurrent process exit did not promote the gate to Exit.
                let _clone_admission = kernel.close_clone_admission_for_exec(self.this_tid)?;
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
                if self.registry.live_count() > 1 {
                    self.terminate_siblings_for_exec(kernel, engine)?;
                }
                emit_runtime_stage(
                    carrick_observability::probes::HvpatchExecRuntimeStagePhase::SiblingDrain,
                    sibling_drain_started,
                );
                // Kernel preparation follows the runtime sibling drain (whose
                // exiting host loops retire their own old Kernel threads) but
                // precedes every destructive image, CLOEXEC, and proc-state
                // mutation. From here, the prepared exec transaction is the
                // sole owner of nonleader promotion and replacement Mm state.
                let prepared_kernel_exec = match kernel.hvpatch_process.as_ref() {
                    Some(process) => process.prepare_exec(self.linux_tid),
                    None => kernel
                        .dispatcher
                        .prepare_one_task_kernel_exec(self.linux_tid),
                }
                .map_err(|error| {
                    RuntimeError::Configuration(format!(
                        "prepare authoritative Kernel exec: {error}"
                    ))
                })?;
                let proc_state_started = std::time::Instant::now();
                if should_update_host_process_title(kernel.hvpatch_process.is_some()) {
                    crate::dispatch::set_host_process_name(cmdline.as_bytes());
                }
                kernel
                    .dispatcher
                    .set_executable_identity(path.clone(), proc_argv, proc_env);
                // Refresh /proc/self/maps + /proc/self/auxv for the new image.
                apply_image_proc_state(&kernel.dispatcher, &img);
                emit_runtime_stage(
                    carrick_observability::probes::HvpatchExecRuntimeStagePhase::ProcState,
                    proc_state_started,
                );
                let close_cloexec_started = std::time::Instant::now();
                kernel.dispatcher.close_cloexec_fds();
                emit_runtime_stage(
                    carrick_observability::probes::HvpatchExecRuntimeStagePhase::CloseCloexec,
                    close_cloexec_started,
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
                engine.execve_into(&img)?;
                let committed_context = match kernel.hvpatch_process.as_ref() {
                    Some(process) => {
                        const TTBR_ROOT_MASK: u64 = (1_u64 << 48) - 1;
                        let stage1_root = match engine.get_sys_reg(carrick_hal::SysReg::Ttbr0) {
                            Ok(root) => root & TTBR_ROOT_MASK,
                            Err(error) => {
                                tracing::error!(
                                    %error,
                                    "read HVPatch stage-1 root after destructive exec"
                                );
                                std::process::abort();
                            }
                        };
                        process.commit_exec(prepared_kernel_exec, stage1_root)
                    }
                    None => kernel
                        .dispatcher
                        .commit_one_task_kernel_exec(prepared_kernel_exec),
                };
                let committed_context = match committed_context {
                    Ok(context) => context,
                    Err(error) => {
                        // The engine now runs the replacement image. Returning a
                        // guest-visible exec failure or resuming the old Kernel
                        // graph would create split lifecycle authority.
                        tracing::error!(%error, "commit Kernel exec after image replacement");
                        std::process::abort();
                    }
                };
                self.linux_tid = committed_context.thread().key().tid;
                emit_runtime_stage(
                    carrick_observability::probes::HvpatchExecRuntimeStagePhase::EngineReplace,
                    engine_replace_started,
                );
                let publication_started = std::time::Instant::now();
                if kernel.hvpatch_process.is_some()
                    && std::env::var_os("CARRICK_HVPATCH_VERIFY_EXEC_CODE").is_some()
                {
                    verify_published_exec_image(engine, &img, &path)?;
                }
                crate::namespace::pid::mark_self_execed();
                // execve_into rebuilt a fresh vCPU: re-stamp the identity page
                // (zeroed) and TPIDR_EL1 (reset) for the same thread/tid.
                stamp_identity_page(engine, &kernel.dispatcher);
                engine
                    .set_guest_thread_id(self.linux_tid.raw() as u64)
                    .map_err(|error| {
                        RuntimeError::Trap(TrapError::Hypervisor(error.to_string()))
                    })?;
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
                // `?` WITHOUT releasing — the child then `_exit`s and the parent's
                // `read()` gets EOF instead.
                if let Some(fd) = self.vfork_release_fd.take() {
                    let _ = unsafe { libc::write(fd, [0u8; 1].as_ptr().cast(), 1) };
                    unsafe { libc::close(fd) };
                }
                stop_after_traced_exec(&kernel.dispatcher);
                Ok(())
            }
            Err(errno) => {
                if std::env::var_os("CARRICK_FAULT_DEBUG").is_some() {
                    eprintln!(
                        "[FAULTDBG tid={}] execve path={path:?} failed errno={}",
                        self.this_tid.raw(),
                        errno.get()
                    );
                }
                let retval = errno.guest_retval();
                engine.complete_syscall(retval)?;
                Ok(())
            }
        }
    }
}
