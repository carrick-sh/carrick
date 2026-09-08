//! `carrick debug` — operator tooling that pairs with the lldb plugin.
//!
//! # Theory of operation
//!
//! These subcommands exist to make a wedged or crashed guest legible without
//! re-running it. They pair with the Python lldb plugin at
//! `scripts/carrick_lldb.py` (the carrick-lldb workflow), and the contract
//! between the two is that *both decode the same way*:
//!
//! - `decode-esr` parses an AArch64 `ESR_EL1` syndrome into its exception class,
//!   IL bit, and ISS (with the DFSC data-abort fault detail) so an operator
//!   never hand-parses a syndrome mid-session. The field layout here
//!   deliberately mirrors the table in the lldb plugin, so the CLI and an lldb
//!   session give the *same* answer for a given syndrome — the test pins a real
//!   Tier-B `ldaxr` external-abort syndrome (`0x92000035`) to keep them in sync.
//! - `lldb-plugin` prints the on-disk path to `carrick_lldb.py` (resolved from
//!   `CARGO_MANIFEST_DIR`) so the operator can `command script import` it.
//! - `inspect-state` renders the `DebugStateSnapshot` JSON that
//!   `run --debug-state-path` dumps *before* starting the vCPU — the same dump
//!   the lldb plugin reads to translate guest addresses back to image / segment
//!   / file context. This gives a one-shot, lldb-free inspection of the guest
//!   address-space layout.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use carrick_runtime::runtime::DebugStateSnapshot;

use crate::args::DebugCommand;
use crate::debug_layout::native_x86_layout_json;

pub(crate) fn run_debug(
    command: DebugCommand,
    store: carrick_image::ImageStore,
) -> anyhow::Result<()> {
    match command {
        DebugCommand::Core { core } => {
            crate::debug_core::run_debug_core(&core).map_err(|error| anyhow::anyhow!("{error}"))?;
        }
        DebugCommand::HvpatchVmLedger {
            artifact,
            run_id,
            source_sha256,
            command_sha256,
        } => {
            let metadata = std::fs::metadata(&artifact)
                .with_context(|| format!("failed to inspect {}", artifact.display()))?;
            let observed = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
            if observed > carrick_runtime::vm_lifecycle::VM_LIFECYCLE_ARTIFACT_MAX_BYTES {
                bail!(
                    "HVPatch VM ledger {} is {observed} bytes; maximum is {}",
                    artifact.display(),
                    carrick_runtime::vm_lifecycle::VM_LIFECYCLE_ARTIFACT_MAX_BYTES
                );
            }
            let bytes = std::fs::read(&artifact)
                .with_context(|| format!("failed to read {}", artifact.display()))?;
            let executable = std::env::current_exe().context("resolve validator executable")?;
            let binary_sha256 = carrick_runtime::vm_lifecycle::sha256_file(&executable)
                .context("hash validator executable")?;
            let expected = carrick_runtime::vm_lifecycle::VmLifecycleArtifactExpectations::new(
                run_id.as_bytes(),
                source_sha256,
                binary_sha256,
                command_sha256,
            )
            .context("build trusted HVPatch VM ledger expectations")?;
            let summary =
                carrick_runtime::vm_lifecycle::validate_authenticated_artifact(&bytes, &expected)
                    .with_context(|| format!("invalid HVPatch VM ledger {}", artifact.display()))?;
            let terminal = match summary.terminal {
                carrick_runtime::vm_lifecycle::VmRunTerminalOutcome::Completed {
                    exit_code,
                    traps,
                    trap_limit_hit,
                } => serde_json::json!({
                    "kind": "completed",
                    "exit_code": exit_code,
                    "traps": traps,
                    "trap_limit_hit": trap_limit_hit,
                }),
                carrick_runtime::vm_lifecycle::VmRunTerminalOutcome::RuntimeError => {
                    serde_json::json!({ "kind": "runtime-error" })
                }
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema": carrick_runtime::vm_lifecycle::VM_LIFECYCLE_ARTIFACT_SCHEMA,
                    "serial": summary.serial.get(),
                    "terminal": terminal,
                    "program_sha256": summary.program_sha256,
                    "run_id_sha256": summary.run_id_sha256,
                    "source_sha256": summary.source_sha256,
                    "binary_sha256": summary.binary_sha256,
                    "command_sha256": summary.command_sha256,
                    "payload_sha256": summary.payload_sha256,
                }))?
            );
        }
        DebugCommand::HvpatchKernel {
            run_id,
            tables,
            list_tables,
        } => {
            run_hvpatch_kernel_snapshot(run_id.as_deref(), &tables, list_tables)?;
        }
        DebugCommand::Abort { run_id } => {
            let ack = carrick_runtime::kernel::kernel_debug_abort(&run_id)
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema": ack.schema,
                    "run_id": ack.run_id,
                    "post_mortem_dir": ack.post_mortem_dir,
                    "note": "the runtime performs one capture at its next runner boundary; \
                             the run itself fails with EmbedError::KernelAborted",
                }))?
            );
        }
        DebugCommand::NativeX86Layout => {
            println!(
                "{}",
                serde_json::to_string_pretty(&native_x86_layout_json())?
            );
        }
        DebugCommand::XlatCensus {
            dir,
            top,
            processes_observed,
        } => {
            crate::debug_census::run_xlat_census(&dir, top, processes_observed)?;
        }
        DebugCommand::AllocOwnerCensus {
            dir,
            native_perf,
            expected_process_epochs,
            expected_pids,
            normal_host_allocation_opportunity_share,
            qualification_share_of_total,
        } => {
            crate::debug_alloc_owner::run_alloc_owner_census(
                &crate::debug_alloc_owner::AllocOwnerCensusRequest {
                    dir,
                    native_perf,
                    expected_process_epochs,
                    expected_pids,
                    normal_host_allocation_opportunity_share,
                    qualification_share_of_total,
                },
            )?;
        }
        DebugCommand::AmplificationLedger { trace, output } => {
            crate::debug_amplification::run_amplification_ledger(&trace, output.as_deref())?;
        }
        DebugCommand::AmplificationCompare { a, b, output } => {
            crate::debug_amplification::run_amplification_compare(&a, &b, output.as_deref())?;
        }
        DebugCommand::NativeFaultPartition { raw, output } => {
            crate::native_fault_profile::run_native_fault_partition(&raw, output.as_deref())?;
        }
        DebugCommand::ExecStampCensus { input, workload_ns } => {
            crate::debug_exec_stamps::run_exec_stamp_census(&input, workload_ns)?;
        }
        DebugCommand::JitShapeCensus {
            trace,
            capture,
            snapshots,
            output,
        } => {
            crate::debug_jit_shape::run_jit_shape_census(
                &trace,
                &capture,
                &snapshots,
                output.as_deref(),
            )?;
        }
        DebugCommand::JitShapeCompare { a, b, output } => {
            crate::debug_jit_shape::run_jit_shape_compare(&a, &b, output.as_deref())?;
        }
        DebugCommand::DecodeEsr { syndrome } => {
            let stripped = syndrome.trim();
            let value = if let Some(hex) = stripped
                .strip_prefix("0x")
                .or_else(|| stripped.strip_prefix("0X"))
            {
                u64::from_str_radix(hex, 16)?
            } else {
                stripped.parse::<u64>()?
            };
            println!("{}", serde_json::to_string_pretty(&decode_esr_el1(value))?);
        }
        DebugCommand::LldbPlugin => {
            let manifest_dir = env!("CARGO_MANIFEST_DIR");
            let path = std::path::Path::new(manifest_dir)
                .join("scripts")
                .join("carrick_lldb.py");
            if !path.exists() {
                tracing::warn!(
                    "warning: lldb plugin not found at {} (CARGO_MANIFEST_DIR may not match runtime tree)",
                    path.display()
                );
            }
            println!("{}", path.display());
        }
        DebugCommand::InspectState { path } => {
            let bytes = std::fs::read(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let state: DebugStateSnapshot = serde_json::from_slice(&bytes)
                .with_context(|| format!("failed to parse {}", path.display()))?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        DebugCommand::LldbRun {
            deadline_seconds,
            out_dir,
            run_id,
            lldb_plugin,
            no_core,
            stop_on_signal,
            command,
        } => {
            let status = run_lldb_deadline(
                command,
                deadline_seconds,
                out_dir,
                run_id,
                lldb_plugin,
                no_core,
                stop_on_signal,
            )?;
            std::process::exit(status);
        }
        DebugCommand::LldbSnapshot {
            run_id,
            out_dir,
            lldb_plugin,
            no_core,
        } => {
            run_lldb_snapshot(run_id, out_dir, lldb_plugin, no_core)?;
        }
        DebugCommand::ContainerGate {
            image,
            probe,
            gate_dir,
            mode,
            output,
        } => {
            run_container_gate(store, &image, &probe, &gate_dir, mode, &output)?;
        }
    }
    Ok(())
}

fn run_lldb_snapshot(
    run_id: String,
    out_dir: PathBuf,
    lldb_plugin_arg: Option<PathBuf>,
    no_core: bool,
) -> anyhow::Result<()> {
    if run_id.is_empty() {
        bail!("debug lldb-snapshot requires a nonempty --run-id");
    }
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;
    let exe = std::env::current_exe().context("failed to resolve current carrick binary path")?;
    let lldb_plugin = lldb_plugin_arg.unwrap_or_else(default_lldb_plugin_path);
    let lldb_log = out_dir.join(format!("{run_id}.lldb.txt"));
    let ps_log = out_dir.join(format!("{run_id}.ps.txt"));
    let pids = dump_lldb(&LldbDumpContext {
        run_id: &run_id,
        why: "external-timeout-snapshot",
        exe: &exe,
        lldb_plugin: &lldb_plugin,
        out_dir: &out_dir,
        lldb_log: &lldb_log,
        ps_log: &ps_log,
        no_core,
    })?;
    if pids.is_empty() {
        bail!("no scoped Carrick processes matched run id `{run_id}`");
    }
    eprintln!(
        "carrick debug lldb-snapshot: run_id={run_id} processes={} lldb_log={} ps_log={}",
        pids.len(),
        lldb_log.display(),
        ps_log.display(),
    );
    Ok(())
}

fn run_lldb_deadline(
    mut run_args: Vec<String>,
    deadline_seconds: u64,
    out_dir: PathBuf,
    run_id_arg: Option<String>,
    lldb_plugin_arg: Option<PathBuf>,
    no_core: bool,
    stop_on_signal: Option<i32>,
) -> anyhow::Result<i32> {
    if run_args.is_empty() {
        bail!("debug lldb-run needs `-- <carrick run args>`");
    }
    if run_args.first().map(String::as_str) == Some("run") {
        bail!("debug lldb-run expects args for `carrick run`; omit the `run` word");
    }

    let name_arg = find_run_name(&run_args)?;
    let needs_injected_name = name_arg.is_none();
    let run_id = match (run_id_arg, name_arg) {
        (Some(explicit), Some(name)) if explicit != name => {
            bail!("--run-id `{explicit}` does not match forwarded --name `{name}`");
        }
        (Some(explicit), _) => explicit,
        (None, Some(name)) => name,
        (None, None) => generated_run_id(),
    };
    if needs_injected_name {
        run_args.splice(0..0, [String::from("--name"), run_id.clone()]);
    }

    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;
    let guest_log = out_dir.join(format!("{run_id}.guest.log"));
    let lldb_log = out_dir.join(format!("{run_id}.lldb.txt"));
    let ps_log = out_dir.join(format!("{run_id}.ps.txt"));
    let manifest = out_dir.join(format!("{run_id}.manifest.txt"));
    let exe = std::env::current_exe().context("failed to resolve current carrick binary path")?;
    let lldb_plugin = lldb_plugin_arg.unwrap_or_else(default_lldb_plugin_path);

    write_manifest(
        &manifest,
        &run_id,
        deadline_seconds,
        stop_on_signal,
        &exe,
        &lldb_plugin,
        &run_args,
    )?;

    let guest = File::create(&guest_log)
        .with_context(|| format!("failed to create {}", guest_log.display()))?;
    let guest_stderr = guest
        .try_clone()
        .with_context(|| format!("failed to clone {}", guest_log.display()))?;
    let mut command = Command::new(&exe);
    command
        .arg("run")
        .args(&run_args)
        .env("CARRICK_RUN_ID", &run_id)
        .stdout(Stdio::from(guest))
        .stderr(Stdio::from(guest_stderr));
    if let Some(signum) = stop_on_signal {
        command.env("CARRICK_DEBUG_STOP_ON_SIGNAL", signum.to_string());
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to spawn {} run", exe.display()))?;

    eprintln!(
        "carrick debug lldb-run: run_id={run_id} deadline={deadline_seconds}s guest_log={} lldb_log={}",
        guest_log.display(),
        lldb_log.display()
    );

    let deadline = Duration::from_secs(deadline_seconds);
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .context("failed to poll carrick run child")?
        {
            return Ok(exit_code(status));
        }
        if let Some(signum) = stop_on_signal {
            let pids = collect_scoped_processes(&run_id)?;
            if pids.iter().any(MatchedProcess::is_stopped) {
                write_ps_log(&ps_log, &pids)?;
                let why = format!("stopped-before-signal-{signum}");
                dump_lldb(&LldbDumpContext {
                    run_id: &run_id,
                    why: &why,
                    exe: &exe,
                    lldb_plugin: &lldb_plugin,
                    out_dir: &out_dir,
                    lldb_log: &lldb_log,
                    ps_log: &ps_log,
                    no_core,
                })?;
                terminate_scoped_run(&run_id, &mut child)?;
                return Ok(124);
            }
        }
        if started.elapsed() >= deadline {
            let why = format!("deadline-{deadline_seconds}s");
            dump_lldb(&LldbDumpContext {
                run_id: &run_id,
                why: &why,
                exe: &exe,
                lldb_plugin: &lldb_plugin,
                out_dir: &out_dir,
                lldb_log: &lldb_log,
                ps_log: &ps_log,
                no_core,
            })?;
            terminate_scoped_run(&run_id, &mut child)?;
            return Ok(124);
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn find_run_name(args: &[String]) -> anyhow::Result<Option<String>> {
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if let Some(value) = arg.strip_prefix("--name=") {
            if value.is_empty() {
                bail!("forwarded --name must not be empty");
            }
            return Ok(Some(value.to_owned()));
        }
        if arg == "--name" {
            let value = iter
                .next()
                .context("forwarded --name is missing its value")?;
            if value.is_empty() {
                bail!("forwarded --name must not be empty");
            }
            return Ok(Some(value.to_owned()));
        }
    }
    Ok(None)
}

fn generated_run_id() -> String {
    let epoch = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    };
    format!("lldb-run-{}-{epoch}", std::process::id())
}

fn write_manifest(
    path: &Path,
    run_id: &str,
    deadline_seconds: u64,
    stop_on_signal: Option<i32>,
    exe: &Path,
    lldb_plugin: &Path,
    run_args: &[String],
) -> anyhow::Result<()> {
    let mut file =
        File::create(path).with_context(|| format!("failed to create {}", path.display()))?;
    writeln!(file, "run_id={run_id}")?;
    writeln!(file, "deadline_seconds={deadline_seconds}")?;
    writeln!(
        file,
        "stop_on_signal={}",
        stop_on_signal.map_or_else(|| String::from("<none>"), |s| s.to_string())
    )?;
    writeln!(file, "exe={}", exe.display())?;
    writeln!(file, "lldb_plugin={}", lldb_plugin.display())?;
    writeln!(file, "run_args={}", run_args.join(" "))?;
    Ok(())
}

#[derive(Clone, Debug)]
struct MatchedProcess {
    pid: libc::pid_t,
    ppid: libc::pid_t,
    stat: String,
    command: String,
}

impl MatchedProcess {
    fn is_stopped(&self) -> bool {
        self.stat.contains('T')
    }
}

struct LldbDumpContext<'a> {
    run_id: &'a str,
    why: &'a str,
    exe: &'a Path,
    lldb_plugin: &'a Path,
    out_dir: &'a Path,
    lldb_log: &'a Path,
    ps_log: &'a Path,
    no_core: bool,
}

fn dump_lldb(ctx: &LldbDumpContext<'_>) -> anyhow::Result<Vec<MatchedProcess>> {
    // LLDB must perform the Mach task stop itself.  Pre-stopping a macOS
    // process with SIGSTOP makes `attach` fail after acquiring the task port
    // because LLDB cannot complete its own pause handshake.  The unified
    // HVPatch kernel has one carrier, so collecting the scoped target without
    // a host-process freeze is also the exact architecture we need to inspect.
    let pids = collect_scoped_processes(ctx.run_id)?;
    write_ps_log(ctx.ps_log, &pids)?;

    // The live debug server can project scheduler state and the exact executor
    // receipt ledger only while the carrier is running.  Capture it before
    // LLDB freezes the task; the backtraces/core remain the fallback when the
    // coherent snapshot itself reports a named busy/timeout failure.
    let kernel_capture = capture_hvpatch_kernel_snapshot(ctx);

    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(ctx.lldb_log)
        .with_context(|| format!("failed to open {}", ctx.lldb_log.display()))?;
    writeln!(log, "RUN_ID={} WHY={}", ctx.run_id, ctx.why)?;
    match kernel_capture {
        Ok(path) => writeln!(log, "KERNEL_SNAPSHOT={}", path.display())?,
        Err(error) => writeln!(log, "KERNEL_SNAPSHOT_ERROR={error:#}")?,
    }
    writeln!(log, "PS_MATCHES:")?;
    let mut attach_order = pids.clone();
    let parent_pids = pids
        .iter()
        .map(|process| process.ppid)
        .collect::<HashSet<_>>();
    attach_order.sort_by(|a, b| {
        parent_pids
            .contains(&a.pid)
            .cmp(&parent_pids.contains(&b.pid))
            .then_with(|| b.pid.cmp(&a.pid))
    });

    for process in &attach_order {
        writeln!(
            log,
            "{} {} {} {}",
            process.pid, process.ppid, process.stat, process.command
        )?;
    }

    for process in &attach_order {
        if process.pid == std::process::id() as libc::pid_t {
            continue;
        }
        if !scoped_process_still_matches(ctx.run_id, process)? {
            writeln!(
                log,
                "===== lldb skip pid={} reason=scoped-process-identity-changed =====",
                process.pid
            )?;
            continue;
        }
        writeln!(
            log,
            "===== lldb attach pid={} ppid={} stat={} =====",
            process.pid, process.ppid, process.stat
        )?;
        log.flush()?;
        let core_path = ctx
            .out_dir
            .join(format!("{}.{}.core", ctx.run_id, process.pid));
        let mut status = run_lldb_attach(ctx, &mut log, process.pid, &core_path)?;
        if !status.success() && process.is_stopped() {
            writeln!(
                log,
                "===== lldb retry pid={} after SIGCONT from stopped attach failure =====",
                process.pid
            )?;
            log.flush()?;
            // SAFETY: this is still the scoped process selected by run id.
            // lldb will attach to the now-running task and stop it itself.
            unsafe {
                libc::kill(process.pid, libc::SIGCONT);
            }
            thread::sleep(Duration::from_millis(50));
            status = run_lldb_attach(ctx, &mut log, process.pid, &core_path)?;
        }
        writeln!(
            log,
            "===== lldb status pid={} status={} =====",
            process.pid, status
        )?;
    }
    Ok(pids)
}

fn capture_hvpatch_kernel_snapshot(ctx: &LldbDumpContext<'_>) -> anyhow::Result<PathBuf> {
    let snapshot = carrick_runtime::kernel::kernel_debug_fetch(ctx.run_id, None)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let path = ctx
        .out_dir
        .join(format!("{}.kernel-debug.json", ctx.run_id));
    let bytes = serde_json::to_vec_pretty(&snapshot).context("serialize kernel debug snapshot")?;
    fs::write(&path, bytes)
        .with_context(|| format!("failed to write kernel snapshot {}", path.display()))?;
    Ok(path)
}

fn run_lldb_attach(
    ctx: &LldbDumpContext<'_>,
    log: &mut File,
    pid: libc::pid_t,
    core_path: &Path,
) -> anyhow::Result<std::process::ExitStatus> {
    let mut lldb = Command::new("lldb");
    lldb.arg("--batch")
        .arg("-o")
        .arg(format!(
            "command script import {}",
            lldb_quoted_path(ctx.lldb_plugin)
        ))
        .arg("-o")
        .arg(format!("attach {pid}"))
        .arg("-o")
        .arg("carrick guest-processes")
        .arg("-o")
        .arg("carrick guest-threads")
        .arg("-o")
        .arg(lldb_eventring_capture_command())
        .arg("-o")
        .arg("thread backtrace all");
    if !ctx.no_core {
        lldb.arg("-o").arg(modified_memory_core_command(core_path));
    }
    lldb.arg("-o").arg("detach").arg(ctx.exe);

    let stdout = log
        .try_clone()
        .with_context(|| format!("failed to clone {}", ctx.lldb_log.display()))?;
    let stderr = log
        .try_clone()
        .with_context(|| format!("failed to clone {}", ctx.lldb_log.display()))?;
    lldb.stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .status()
        .context("failed to run lldb")
}

fn collect_scoped_processes(run_id: &str) -> anyhow::Result<Vec<MatchedProcess>> {
    let output = Command::new("ps")
        .args(["-A", "-o", "pid=,ppid=,stat=,command="])
        .output()
        .context("failed to run ps")?;
    if !output.status.success() {
        bail!("ps failed with status {}", output.status);
    }
    let needle = format!("carrick:{run_id}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut processes = Vec::new();
    for line in stdout.lines() {
        if !line.contains(&needle) {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(pid_raw) = parts.next() else {
            continue;
        };
        let Some(ppid_raw) = parts.next() else {
            continue;
        };
        let Some(stat) = parts.next() else {
            continue;
        };
        let command = parts.collect::<Vec<_>>().join(" ");
        let pid = pid_raw
            .parse::<libc::pid_t>()
            .with_context(|| format!("failed to parse pid from `{line}`"))?;
        let ppid = ppid_raw
            .parse::<libc::pid_t>()
            .with_context(|| format!("failed to parse ppid from `{line}`"))?;
        processes.push(MatchedProcess {
            pid,
            ppid,
            stat: stat.to_owned(),
            command,
        });
    }
    Ok(processes)
}

fn write_ps_log(path: &Path, pids: &[MatchedProcess]) -> anyhow::Result<()> {
    let mut file =
        File::create(path).with_context(|| format!("failed to create {}", path.display()))?;
    for process in pids {
        writeln!(
            file,
            "{} {} {} {}",
            process.pid, process.ppid, process.stat, process.command
        )?;
    }
    Ok(())
}

fn scoped_process_still_matches(run_id: &str, expected: &MatchedProcess) -> anyhow::Result<bool> {
    Ok(collect_scoped_processes(run_id)?.iter().any(|current| {
        current.pid == expected.pid
            && current.ppid == expected.ppid
            && current.command == expected.command
    }))
}

fn terminate_scoped_run(run_id: &str, child: &mut Child) -> anyhow::Result<()> {
    let kill_script = Path::new("scripts").join("sudo").join("kill.sh");
    if kill_script.exists() {
        let _ = Command::new(&kill_script).arg(run_id).status();
    }

    // Never signal the snapshot captured before LLDB work: a process may have
    // exited and its numeric PID may have been reused while a core was being
    // written.  Re-resolve the run-id-qualified set immediately before each
    // signal phase instead.
    for process in collect_scoped_processes(run_id)? {
        // SAFETY: same scoped pid set as below; resume stopped diagnostic
        // targets so SIGTERM can run normal cleanup before the SIGKILL fallback.
        unsafe {
            libc::kill(process.pid, libc::SIGCONT);
        }
        // SAFETY: signal delivery is scoped to pids whose proctitle matched this
        // run id. Errors are best-effort here because the process may have exited.
        unsafe {
            libc::kill(process.pid, libc::SIGTERM);
        }
    }
    if wait_for_child(child, Duration::from_secs(2))?.is_none() {
        for process in collect_scoped_processes(run_id)? {
            // SAFETY: same scoped pid set as above; SIGKILL is the final cleanup
            // after the graceful deadline expires.
            unsafe {
                libc::kill(process.pid, libc::SIGKILL);
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    Ok(())
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> anyhow::Result<Option<i32>> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().context("failed to poll child")? {
            return Ok(Some(exit_code(status)));
        }
        if started.elapsed() >= timeout {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

fn default_lldb_plugin_path() -> PathBuf {
    let relative = Path::new("scripts").join("carrick_lldb.py");
    if relative.exists() {
        return relative;
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    for ancestor in manifest.ancestors() {
        let candidate = ancestor.join("scripts").join("carrick_lldb.py");
        if candidate.exists() {
            return candidate;
        }
    }
    manifest.join("scripts").join("carrick_lldb.py")
}

fn lldb_quoted_path(path: &Path) -> String {
    format!("\"{}\"", path.display())
}

fn modified_memory_core_command(path: &Path) -> String {
    format!(
        "process save-core --style modified-memory {}",
        lldb_quoted_path(path)
    )
}

fn lldb_eventring_capture_command() -> &'static str {
    // The interactive plugin defaults to a concise 128-event tail. Deadline
    // captures preserve the whole fixed ring so a high-rate workload cannot
    // hide the child's exit publication immediately before a parent wait.
    "carrick eventring 8192"
}

/// Decode an `ESR_EL1` value into a human-readable struct. Mirrors the
/// fields documented in the ARMv8-A ARM and the lldb plugin's table so
/// CLI and lldb give the same answer for a given syndrome.
fn decode_esr_el1(value: u64) -> serde_json::Value {
    let ec = ((value >> 26) & 0x3f) as u8;
    let il = (value >> 25) & 1;
    let iss = value & 0x01_FF_FF_FF;
    let ec_name = match ec {
        0x00 => "Unknown",
        0x01 => "WFI/WFE trap",
        0x07 => "Trapped access to SVE/SIMD/FP (CPACR_EL1.FPEN)",
        0x15 => "SVC instruction (AArch64)",
        0x16 => "HVC instruction (AArch64)",
        0x18 => "MSR/MRS trapped",
        0x20 => "Instruction Abort from a lower EL",
        0x21 => "Instruction Abort from current EL",
        0x22 => "PC alignment fault",
        0x24 => "Data Abort from a lower EL",
        0x25 => "Data Abort from current EL",
        0x26 => "SP alignment fault",
        0x2c => "Trapped floating-point exception",
        0x2f => "SError interrupt",
        _ => "(other)",
    };

    let mut iss_detail = serde_json::Map::new();
    if matches!(ec, 0x20 | 0x21 | 0x24 | 0x25) {
        let dfsc = iss & 0x3f;
        let wnr = (iss >> 6) & 1;
        let s1ptw = (iss >> 7) & 1;
        let cm = (iss >> 8) & 1;
        let ea = (iss >> 9) & 1;
        let sf = (iss >> 15) & 1;
        let srt = (iss >> 16) & 0x1f;
        let isv = (iss >> 24) & 1;
        let dfsc_name = match dfsc {
            0x00 => "Address size fault, level 0",
            0x01 => "Address size fault, level 1",
            0x02 => "Address size fault, level 2",
            0x03 => "Address size fault, level 3",
            0x04 => "Translation fault, level 0",
            0x05 => "Translation fault, level 1",
            0x06 => "Translation fault, level 2",
            0x07 => "Translation fault, level 3",
            0x09 => "Access flag fault, level 1",
            0x0a => "Access flag fault, level 2",
            0x0b => "Access flag fault, level 3",
            0x0d => "Permission fault, level 1",
            0x0e => "Permission fault, level 2",
            0x0f => "Permission fault, level 3",
            0x10 => "Synchronous External abort, not on TT walk",
            0x21 => "Alignment fault",
            0x30 => "TLB conflict abort",
            0x31 => "Unsupported atomic hardware update fault",
            0x34 => "IMPLEMENTATION DEFINED fault (Lockdown)",
            0x35 => "External abort on translation table walk, level 1",
            0x36 => "External abort on translation table walk, level 2",
            0x37 => "External abort on translation table walk, level 3",
            _ => "(other)",
        };
        iss_detail.insert("dfsc".into(), serde_json::Value::from(dfsc));
        iss_detail.insert("dfsc_name".into(), serde_json::Value::from(dfsc_name));
        iss_detail.insert("wnr".into(), serde_json::Value::from(wnr == 1));
        iss_detail.insert("s1ptw".into(), serde_json::Value::from(s1ptw == 1));
        iss_detail.insert("cm".into(), serde_json::Value::from(cm == 1));
        iss_detail.insert("ea_external_abort".into(), serde_json::Value::from(ea == 1));
        iss_detail.insert("sf_64bit_reg".into(), serde_json::Value::from(sf == 1));
        iss_detail.insert("srt_register".into(), serde_json::Value::from(srt));
        iss_detail.insert("isv".into(), serde_json::Value::from(isv == 1));
    }

    serde_json::json!({
        "esr_el1": format!("0x{:x}", value),
        "ec": ec,
        "ec_hex": format!("0x{:02x}", ec),
        "ec_name": ec_name,
        "il": il == 1,
        "iss": format!("0x{:x}", iss),
        "iss_detail": iss_detail,
    })
}

/// Read one coherent kernel snapshot from a live run and print it.
///
/// Every failure mode is named: an unknown table, a run that is not listening,
/// a wedged runtime (timeout), a refusal from the runtime, or a response that
/// fails schema/join/frame validation.
fn run_hvpatch_kernel_snapshot(
    run_id: Option<&str>,
    tables: &[String],
    list_tables: bool,
) -> anyhow::Result<()> {
    use carrick_runtime::kernel::KernelDebugTable;

    if list_tables {
        for table in KernelDebugTable::ALL {
            println!("{}", table.wire_name());
        }
        return Ok(());
    }
    let Some(run_id) = run_id else {
        bail!("--run-id is required unless --list-tables is given");
    };

    let selected = if tables.is_empty() {
        None
    } else {
        let mut parsed = Vec::with_capacity(tables.len());
        for name in tables {
            parsed.push(
                KernelDebugTable::parse(name)
                    .map_err(|error| anyhow::anyhow!("{error}; run with --list-tables"))?,
            );
        }
        Some(parsed)
    };

    let snapshot = carrick_runtime::kernel::kernel_debug_fetch(run_id, selected)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    println!("{}", serde_json::to_string_pretty(&snapshot)?);
    Ok(())
}

fn container_gate_request(
    image: &str,
    probe: &Path,
    gate_dir: &Path,
    role: &str,
    mode: &str,
) -> carrick_engine::RunRequest {
    use camino::Utf8PathBuf;
    carrick_engine::RunRequest {
        image_ref: image.to_owned(),
        platform: Some("linux/arm64".to_owned()),
        args: vec!["/tmp/p".to_owned(), role.to_owned(), mode.to_owned()],
        mounts: vec![
            carrick_engine::Mount {
                source: Utf8PathBuf::from_path_buf(probe.to_path_buf())
                    .unwrap_or_else(|p| Utf8PathBuf::from(p.to_string_lossy().into_owned())),
                target: Utf8PathBuf::from("/tmp/p"),
                readonly: true,
            },
            carrick_engine::Mount {
                source: Utf8PathBuf::from_path_buf(gate_dir.to_path_buf())
                    .unwrap_or_else(|p| Utf8PathBuf::from(p.to_string_lossy().into_owned())),
                target: Utf8PathBuf::from("/gate"),
                readonly: false,
            },
        ],
        hostname: Some(format!("gate-{role}")),
        entrypoint_override: Some(Vec::new()),
        fs: Some(carrick_spec::FsBackendKind::Host),
        exec_backend: carrick_spec::ExecBackendRequest::HvPatch,
        pid: carrick_spec::PidMode::Private,
        network: carrick_spec::NetworkMode::Host,
        ..carrick_engine::RunRequest::default()
    }
}

fn container_gate_outcome(
    run: &Result<carrick_runtime::runtime::RunResult, carrick_runtime::runtime::RuntimeError>,
) -> serde_json::Value {
    match run {
        Ok(result) => serde_json::json!({
            "exit_code": result.exit_code,
            "terminating_signal": result.terminating_signal,
            "trap_limit_hit": result.trap_limit_hit,
            "traps": result.traps,
        }),
        Err(error) => serde_json::json!({ "error": format!("{error:#}") }),
    }
}

/// Two containers, one carrier. Resolution runs under a short-lived tokio
/// runtime that is dropped before execution (the CLI's own pattern, see
/// `commands.rs`); execution is plain `Runtime::execute` — on this thread in
/// sequence, or on two host threads at once.
fn run_container_gate(
    store: carrick_image::ImageStore,
    image: &str,
    probe: &Path,
    gate_dir: &Path,
    mode: crate::args::ContainerGateMode,
    output: &Path,
) -> anyhow::Result<()> {
    use crate::args::ContainerGateMode;
    if !probe.is_file() {
        bail!("container_gate probe is not a file: {}", probe.display());
    }
    fs::create_dir_all(gate_dir)
        .with_context(|| format!("failed to create {}", gate_dir.display()))?;
    carrick_runtime::memory::init_alias_ipa_allocator();
    carrick_runtime::fs_resolve_cache::init();
    let engine = carrick_engine::Engine::new(store);
    let probe_mode = match mode {
        ContainerGateMode::Sequential => "solo",
        ContainerGateMode::Concurrent => "paired",
    };
    let alpha = crate::runtime_util::block_on_oci(engine.resolve(container_gate_request(
        image, probe, gate_dir, "alpha", probe_mode,
    )))
    .map_err(|error| anyhow::anyhow!("resolve alpha: {error:#}"))?;
    let beta = crate::runtime_util::block_on_oci(engine.resolve(container_gate_request(
        image, probe, gate_dir, "beta", probe_mode,
    )))
    .map_err(|error| anyhow::anyhow!("resolve beta: {error:#}"))?;
    let carrier = carrick_runtime::CarrierRuntime::new_explicit()
        .map_err(|error| anyhow::anyhow!("create container-gate carrier: {error:#}"))?;
    let started = Instant::now();
    let (alpha_run, beta_run) = match mode {
        ContainerGateMode::Sequential => (
            carrick_runtime::Runtime::execute_on(
                &carrier,
                &alpha.spec,
                carrick_runtime::kernel::LaunchContext::from_process_env()?,
            ),
            carrick_runtime::Runtime::execute_on(
                &carrier,
                &beta.spec,
                carrick_runtime::kernel::LaunchContext::from_process_env()?,
            ),
        ),
        ContainerGateMode::Concurrent => {
            let alpha_carrier = carrier.clone();
            let alpha_thread = thread::Builder::new()
                .name("gate-alpha".into())
                .spawn(move || {
                    let launch = carrick_runtime::kernel::LaunchContext::from_process_env()?;
                    carrick_runtime::Runtime::execute_on(&alpha_carrier, &alpha.spec, launch)
                })
                .context("spawn alpha container thread")?;
            let beta_carrier = carrier.clone();
            let beta_thread = thread::Builder::new()
                .name("gate-beta".into())
                .spawn(move || {
                    let launch = carrick_runtime::kernel::LaunchContext::from_process_env()?;
                    carrick_runtime::Runtime::execute_on(&beta_carrier, &beta.spec, launch)
                })
                .context("spawn beta container thread")?;
            let alpha_run = alpha_thread
                .join()
                .map_err(|_| anyhow::anyhow!("alpha container thread panicked"))?;
            let beta_run = beta_thread
                .join()
                .map_err(|_| anyhow::anyhow!("beta container thread panicked"))?;
            (alpha_run, beta_run)
        }
    };
    let elapsed_ms = started.elapsed().as_millis();
    let snapshot = carrier
        .snapshot()
        .map_err(|error| anyhow::anyhow!("snapshot container-gate carrier: {error:#}"))?;
    let receipt = serde_json::json!({
        "schema": "carrick.container-gate.v1",
        "mode": match mode {
            ContainerGateMode::Sequential => "sequential",
            ContainerGateMode::Concurrent => "concurrent",
        },
        "carrier_pid": std::process::id(),
        "image": image,
        "elapsed_ms": elapsed_ms,
        "vm_create_success_events": snapshot.vm_create_success_events,
        "live_containers_after": snapshot.live_containers,
        "alpha": container_gate_outcome(&alpha_run),
        "beta": container_gate_outcome(&beta_run),
    });
    fs::write(output, serde_json::to_vec_pretty(&receipt)?)
        .with_context(|| format!("failed to write {}", output.display()))?;
    carrier
        .shutdown_wait()
        .map_err(|error| anyhow::anyhow!("{error:#}"))?;
    alpha_run.map_err(|error| anyhow::anyhow!("alpha container: {error:#}"))?;
    beta_run.map_err(|error| anyhow::anyhow!("beta container: {error:#}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{decode_esr_el1, lldb_eventring_capture_command, modified_memory_core_command};
    use std::path::Path;

    #[test]
    fn lldb_core_capture_keeps_modified_guest_and_runtime_memory() {
        assert_eq!(
            modified_memory_core_command(Path::new("/tmp/hvpatch.core")),
            "process save-core --style modified-memory \"/tmp/hvpatch.core\""
        );
    }

    #[test]
    fn deadline_capture_keeps_enough_event_history_for_cross_thread_waits() {
        assert_eq!(lldb_eventring_capture_command(), "carrick eventring 8192");
    }

    #[test]
    fn deadline_capture_leaves_running_targets_for_lldb_to_stop() {
        let source = include_str!("debug.rs");
        let start = source.find("fn dump_lldb(").expect("dump_lldb");
        let end = source[start..]
            .find("fn run_lldb_attach(")
            .map(|offset| start + offset)
            .expect("run_lldb_attach");
        let body = &source[start..end];

        assert!(body.contains("collect_scoped_processes(ctx.run_id)?"));
        assert!(!body.contains("stop_scoped_processes(ctx.run_id)?"));
    }

    #[test]
    fn deadline_capture_collects_kernel_ledger_before_lldb_freezes_the_carrier() {
        let source = include_str!("debug.rs");
        let start = source.find("fn dump_lldb(").expect("dump_lldb");
        let end = source[start..]
            .find("fn run_lldb_attach(")
            .map(|offset| start + offset)
            .expect("run_lldb_attach");
        let body = &source[start..end];

        let kernel = body
            .find("capture_hvpatch_kernel_snapshot(ctx)")
            .expect("kernel snapshot capture");
        let lldb = body.find("run_lldb_attach(").expect("lldb attach");
        assert!(kernel < lldb, "kernel snapshot must precede LLDB attach");
    }

    #[test]
    fn deadline_capture_revalidates_scoped_identity_before_attach_and_signal() {
        let source = include_str!("debug.rs");
        let dump_start = source.find("fn dump_lldb(").expect("dump_lldb");
        let dump_end = source[dump_start..]
            .find("fn capture_hvpatch_kernel_snapshot(")
            .map(|offset| dump_start + offset)
            .expect("kernel snapshot helper");
        let dump = &source[dump_start..dump_end];
        assert!(dump.contains("scoped_process_still_matches(ctx.run_id, process)?"));

        let terminate_start = source
            .find("fn terminate_scoped_run(")
            .expect("terminate_scoped_run");
        let terminate_end = source[terminate_start..]
            .find("fn wait_for_child(")
            .map(|offset| terminate_start + offset)
            .expect("wait_for_child");
        let terminate = &source[terminate_start..terminate_end];
        assert_eq!(
            terminate
                .matches("collect_scoped_processes(run_id)?")
                .count(),
            2
        );
        assert!(!terminate.contains("for process in pids"));
    }

    #[test]
    fn decodes_tier_b_data_abort_syndrome() {
        // Real syndrome captured from musl `ldaxr` failing at the Tier B wall.
        let json = decode_esr_el1(0x92000035);
        assert_eq!(json["ec_hex"], "0x24");
        assert_eq!(json["ec_name"], "Data Abort from a lower EL");
        assert_eq!(json["il"], true);
        assert_eq!(json["iss_detail"]["dfsc"], 53);
        assert_eq!(
            json["iss_detail"]["dfsc_name"],
            "External abort on translation table walk, level 1"
        );
        assert_eq!(json["iss_detail"]["wnr"], false);
        assert_eq!(json["iss_detail"]["isv"], false);
    }
}
