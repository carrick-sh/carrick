use anyhow::{Result, bail, ensure};
use carrick_hal::{NullGuestTimerBridge, NullHostSignalBridge};
use carrick_kernel::{
    compat::{CompatEvent, CompatReporter, SyscallArgs},
    dispatch::{CarrierBridges, DispatchOutcome, SyscallDispatcher, SyscallRequest, ThreadCtx},
    kernel::{CarrierProcess, objects::ExecutorId},
    thread::{FutexTable, ThreadId, ThreadRegistry},
};
use carrick_kernel_example::{
    driver::seed_initial_task_state,
    process::{AddressSpace, AsidAllocator, ExampleProcess},
};
use carrick_vfs::fs_backend::HostFsBackend;
use native_syscall_slice::{
    Instruction, Memory, classify, emulate,
    native::{Code, State},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
#[cfg(feature = "allocation-metrics")]
mod allocations;

fn main() -> Result<()> {
    #[cfg(feature = "allocation-metrics")]
    allocations::positive_control();
    let elf = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: native-syscall-slice ELF"))?;
    let (mut memory, image) = Memory::load_elf(&load_host_fixture(&elf)?)?;
    let code = Code::publish(&image, &memory)?;
    let scratch = tempfile::tempdir()?;
    let bridges = CarrierBridges {
        host_signal: Arc::new(NullHostSignalBridge::default()),
        timers: Arc::new(NullGuestTimerBridge::default()),
    };
    let tid = ThreadId::from_guest_supplied_tid(carrick_abi::LINUX_BOOTSTRAP_PID as i32);
    let (process, context) = ExampleProcess::boot_root(
        tid.raw(),
        "bounded-native-slice",
        bridges.host_signal.clone(),
        AddressSpace::allocate(&AsidAllocator::new())?,
    )?;
    let process = Arc::new(process);
    let mut dispatcher = SyscallDispatcher::with_bridges(bridges);
    dispatcher.set_fs_backend(Box::new(HostFsBackend::new_in(scratch.path())?));
    dispatcher.bind_hvpatch_process(process.clone() as Arc<dyn CarrierProcess>);
    if let Some(e) = process.take_bind_failure() {
        return Err(e.into());
    }
    dispatcher.activate_file_authority(context.resources().files())?;
    seed_initial_task_state(&context, process.asid_generation())?;
    let mut execution = context
        .thread()
        .claim_runnable(ExecutorId::for_transitional_thread(tid)?)?;
    let owner = context.validate_current_execution_mm(&execution)?;
    let mut executor = dispatcher.admit_native_executor(&context, &execution)?;
    let registry = ThreadRegistry::new(tid);
    let futex = FutexTable::new();
    let reporter = CompatReporter::default();
    let mut state = State::new(image.entry());
    let mut requests = 0u64;
    let mut completions = 0u64;
    let mut errors = 0u64;
    let mut transitions = 0u64;
    let mut by_number = std::collections::BTreeMap::<u64, u64>::new();
    let mut exited = None;
    #[cfg(feature = "allocation-metrics")]
    let mut windows = Vec::with_capacity(32);
    #[cfg(feature = "allocation-metrics")]
    let mut window = None;
    let started = Instant::now();
    let mut service =
        |state: &mut State,
         memory: &mut Memory,
         executor: &mut carrick_kernel::dispatch::native_execution::NativeExecutor,
         execution: &carrick_kernel::kernel::objects::ThreadExecutionLease|
         -> Result<bool> {
            transitions += 1;
            ensure!(
                transitions <= 100_000_000 && started.elapsed() < Duration::from_secs(40),
                "native diagnostic execution bound"
            );
            ensure!(
                context.validate_current_execution_mm(execution)? == owner,
                "current MM changed"
            );
            // A real pending signal is never silently bypassed. Guest handler and
            // host signal bridge support remain explicit unsatisfied capabilities.
            while let Some(pending) = dispatcher.take_deliverable_pending_from(&context, tid) {
                let action = dispatcher.signal_action(&context, pending.signum);
                match carrick_kernel::kernel::evaluate_signal_delivery_action(
                    pending.signum,
                    action,
                ) {
                    carrick_kernel::kernel::SignalDeliveryAction::Ignore => {}
                    other => bail!("native slice cannot deliver pending signal: {other:?}"),
                }
            }
            let index = state
                .pc
                .checked_sub(image.base())
                .filter(|n| n % 4 == 0)
                .and_then(|n| usize::try_from(n / 4).ok())
                .ok_or_else(|| anyhow::anyhow!("invalid semantic PC"))?;
            let w = *image
                .words()
                .get(index)
                .ok_or_else(|| anyhow::anyhow!("guest fell outside code"))?;
            if classify(w).map_err(anyhow::Error::msg)? != Instruction::Syscall {
                emulate(w, state, memory)?;
                return Ok(true);
            }
            let number = state.x[8];
            #[cfg(feature = "allocation-metrics")]
            let closing = number == 113 && window.is_some();
            #[cfg(feature = "allocation-metrics")]
            if closing {
                let count = allocations::end();
                let (r, c) = window.take().unwrap();
                windows.push((requests - r, completions - c, count));
            }
            // No mapping/exec/clone/handler syscall can claim unsupported semantics.
            ensure!(
                matches!(number, 26 | 27 | 28 | 29 | 56 | 57 | 63 | 64 | 93 | 113),
                "unsupported syscall {number}"
            );
            requests += 1;
            *by_number.entry(number).or_default() += 1;
            let request = SyscallRequest::new(
                number,
                SyscallArgs::from([
                    state.x[0], state.x[1], state.x[2], state.x[3], state.x[4], state.x[5],
                ]),
            );
            let outcome = dispatcher.dispatch_threaded_with_mm_executor(
                executor.dispatch_participation(),
                &context,
                request,
                memory,
                &reporter,
                ThreadCtx::new(tid, &registry, &futex),
            )?;
            let (value, errno) = match outcome {
                DispatchOutcome::Returned { value } => (value, None),
                DispatchOutcome::Errno { errno } => {
                    errors += 1;
                    let value = errno.guest_retval();
                    (value, Some((-value) as i32))
                }
                DispatchOutcome::Exit { code } => {
                    exited = Some(code);
                    return Ok(false);
                }
                other => bail!("unsupported synchronous outcome: {other:?}"),
            };
            completions += 1;
            let meta = carrick_abi::syscall::lookup_aarch64(number)
                .ok_or_else(|| anyhow::anyhow!("missing syscall metadata"))?;
            reporter.record(CompatEvent::SyscallReturn {
                number,
                name: meta.name.into(),
                retval: value,
                errno,
            });
            state.x[0] = value as u64;
            state.pc += 4;
            #[cfg(feature = "allocation-metrics")]
            if number == 113 && !closing {
                window = Some((requests, completions));
                allocations::begin();
            }
            Ok(true)
        };
    let result = (|| -> Result<()> {
        loop {
            // Return to Rust at the existing SVC/memory/backedge checkpoint.
            // The scope ends before semantic dispatch may mutate this MM.
            let scope =
                dispatcher.enter_native_execution(&mut executor, &context, &mut execution)?;
            let mut reached_checkpoint = false;
            let run = code.run(&image, &mut memory, &mut state, &mut |_, _| {
                reached_checkpoint = true;
                Ok(false)
            });
            drop(scope);
            run?;
            ensure!(
                reached_checkpoint,
                "native execution returned without a checkpoint"
            );
            if executor.memory_pause_pending() {
                dispatcher.service_native_memory_control(&mut executor, &context, &execution)?;
            }
            // Control requests cannot be silently acknowledged as delivered
            // signals/cancellation: this research runner has no such service.
            ensure!(
                !executor.take_stop_request(),
                "native execution requires signal/cancellation control service"
            );
            if !service(&mut state, &mut memory, &mut executor, &execution)? {
                break;
            }
        }
        Ok(())
    })();
    if let Err(e) = result {
        bail!(
            "guest pc={:#x} x0={} x8={}: {e:#}",
            state.pc,
            state.x[0],
            state.x[8]
        );
    }
    let report = reporter.snapshot();
    ensure!(
        report.summary.syscall_invocations == requests
            && report.summary.syscall_returns_ok == completions - errors
            && report.summary.syscall_returns_errno == errors,
        "observer counts diverged"
    );
    std::io::Write::write_all(&mut std::io::stdout().lock(), &dispatcher.stdout())?;
    eprintln!(
        "{}",
        serde_json::json!({"elf":elf,"exit":exited,"requests":requests,"completions":completions,
        "errno_returns":errors,"gateway_transitions":transitions,"syscalls":by_number,
        "elapsed_ms":started.elapsed().as_millis(),"backend":"bounded-native-research","host_signal_bridge":"null"})
    );
    #[cfg(feature = "allocation-metrics")]
    {
        ensure!(
            window.is_none() && windows.len() == 10,
            "incomplete allocation windows"
        );
        eprintln!(
            "{}",
            serde_json::json!({"allocation_windows":windows,"positive_control":true,"timing_eligible":false})
        );
        if errors > 0 {
            ensure!(
                windows.iter().skip(1).all(|(r, c, a)| r == c && *a == 0),
                "warmed invalid loop allocation budget failed"
            );
            if let Ok(path) = std::env::var("CARRICK_OBSERVATION_OUTPUT") {
                use carrick_conformance_contract::{
                    Completeness, ContractId, ContractObservation, ExecutionLayer,
                    SemanticAssertion, WorkMetric, WorkSnapshot,
                };
                let output = dispatcher.stdout();
                ensure!(output.len() == 560, "missing guest record population");
                let phase = u64::from_le_bytes(output[..8].try_into()?);
                let scale = u64::from_le_bytes(output[8..16].try_into()?);
                ensure!(
                    phase == 0
                        && windows
                            .iter()
                            .skip(1)
                            .all(|(r, c, a)| *r == 2 * scale && *c == 2 * scale && *a == 0),
                    "invalid structural population"
                );
                let mut work = WorkSnapshot::new();
                work.insert(WorkMetric::KernelDispatches, 2 * scale)?;
                work.insert(WorkMetric::HostHeapAllocations, 0)?;
                work.unknown_metrics.push(
                    "hvf_syscall_exits: no live HVF-exit instrument in this research binary".into(),
                );
                let observation=ContractObservation {
                    contract_id:ContractId::new("kernel.execution.native-synchronous-syscall")?,
                    layer:ExecutionLayer::EmbedStructural,
                    implementation_revision:std::env::var("CARRICK_OBSERVATION_SOURCE")?,
                    fixture_identity:format!("bounded-native watch-0-{scale}; nine post-warmup guest windows"),
                    scale,semantic_assertions:vec![SemanticAssertion::pass("actual_guest_syscalls_match_EBADF"),SemanticAssertion::pass("exactly_two_requests_and_completions_per_pair"),SemanticAssertion::pass("allocator_positive_control_fired")],
                    work:Some(work),timing:None,
                    completeness:Completeness::Incomplete {reasons:vec!["research executor is not a registered embed binding".into(),"unified-carrier MM, COW, signal/cancellation and foreign-write obligations remain unproved".into()]},
                };
                // Retain typed partial evidence, and prove the verifier rejects it.
                ensure!(
                    observation.validate().is_err(),
                    "partial research evidence unexpectedly qualified"
                );
                save_host_observation(&path, &serde_json::to_string_pretty(&observation)?)?;
            }
        }
    }
    ensure!(
        exited == Some(0),
        "guest did not exit successfully: {exited:?}"
    );
    Ok(())
}

#[expect(
    clippy::disallowed_methods,
    reason = "Non-product harness host input: the operator explicitly selects this ELF; guest paths use HostFsBackend"
)]
fn load_host_fixture(path: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(path)
}

#[cfg(feature = "allocation-metrics")]
#[expect(
    clippy::disallowed_methods,
    reason = "Non-product harness host output: the operator selects an evidence file; never a guest syscall path"
)]
fn save_host_observation(path: &str, bytes: &str) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}
