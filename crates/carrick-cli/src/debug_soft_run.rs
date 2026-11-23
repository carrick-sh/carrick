//! `carrick debug soft-run`: one AArch64 Linux process on the soft AArch64
//! CPU (#1236), from a rootfs directory, through the production EL1 image and
//! the production kernel dispatcher
//! (`carrick_softcpu_aarch64_host::run_single_process`). Diagnostics only: it
//! is the soft-a64 provider of `carrick debug discover` (#1906), so a parity
//! row's first single-process command reaches ARM semantics on a Linux host.
//!
//! The command is looked up the way `execve` and a shell's `PATH` search do,
//! inside the rootfs (`carrick_softcpu_aarch64_host::rootfs_command`, shared
//! with the soft-CPU row witnesses). The guest's stdout and stderr are this
//! command's; the exit status is the guest's, or 128 plus the signal that
//! killed it. A command the lookup cannot run exits as a shell's would: 127
//! when it is not found, 126 when it is found but cannot be executed (no
//! execute bit, not an ELF or a script), 125 when the lookup can't run it.
//! With `CARRICK_EL1_CENSUS=<directory>` the run publishes the same terminal
//! census a hardware carrier does, cut from the EL1 image's counters.
//!
//! The soft CPU executes translated blocks natively, so a run needs a Linux
//! arm64 host; anywhere else the runner refuses it (`UnsupportedHost`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use carrick_softcpu_aarch64_host::rootfs_command::{env_path, resolve_command};

/// The exit status of a run the carrier could not finish (as `carrick run`).
const CARRIER_ERROR_STATUS: i32 = 125;

/// What `carrick debug soft-run` was asked to run.
pub(crate) struct SoftRunOptions<'a> {
    pub(crate) rootfs: &'a Path,
    /// The production EL1 ELF; default `CARRICK_A64_ELF`.
    pub(crate) el1_elf: Option<&'a Path>,
    /// `KEY=VALUE` guest environment entries.
    pub(crate) env: &'a [String],
    pub(crate) max_syscalls: usize,
    /// Write the run's summary here as JSON.
    pub(crate) summary_out: Option<&'a Path>,
    pub(crate) argv: &'a [String],
}

/// The run's summary line and `--summary-out` record.
#[derive(Debug, serde::Serialize)]
struct SoftRunSummary {
    executable: String,
    argv: Vec<String>,
    /// The guest's exit status; absent when the carrier failed.
    exit_code: Option<i32>,
    /// The signal of a terminating synchronous fault.
    signal: Option<i32>,
    fault_addr: Option<String>,
    fault_pc: Option<String>,
    carrier_error: Option<String>,
    syscalls_dispatched: u64,
    ring_completed: u64,
    kernel_dispatched: u64,
    runner_refused: u64,
    /// `(aarch64 nr, name, count)` answered with a counted ENOSYS.
    counted_enosys: Vec<(u64, String, u64)>,
    census_published: bool,
}

/// Run `carrick debug soft-run` and exit with the guest's status.
pub(crate) fn run(options: &SoftRunOptions<'_>) -> Result<()> {
    let status = run_to_status(options)?;
    use std::io::Write as _;
    std::io::stdout().flush()?;
    std::process::exit(status);
}

fn run_to_status(options: &SoftRunOptions<'_>) -> Result<i32> {
    ensure!(
        options.rootfs.is_dir(),
        "--rootfs {} is not a directory",
        options.rootfs.display()
    );
    for entry in options.env {
        ensure!(entry.contains('='), "--env {entry:?} is not KEY=VALUE");
    }
    let el1_path = match options.el1_elf {
        Some(path) => path.to_path_buf(),
        None => std::env::var_os("CARRICK_A64_ELF").map(PathBuf::from).context(
            "soft-run needs the production EL1 ELF: --el1-elf <path> or CARRICK_A64_ELF \
             (the carrick-el1-image build's el1-target/aarch64-unknown-none-softfloat/el1-image/carrick-el1)",
        )?,
    };
    let el1_elf =
        std::fs::read(&el1_path).with_context(|| format!("read {}", el1_path.display()))?;
    ensure!(
        el1_elf.starts_with(b"\x7fELF"),
        "{} is not an ELF (soft-run loads the linked EL1 ELF, not the flat image)",
        el1_path.display()
    );
    let command = match resolve_command(options.rootfs, options.argv, env_path(options.env)) {
        Ok(command) => command,
        Err(error) => {
            // As a shell reports it: 127 not found, 126 not executable.
            eprintln!("carrick: soft-run: {error}");
            return Ok(error.exit_status());
        }
    };
    let elf_bytes = std::fs::read(command.host_executable(options.rootfs))
        .with_context(|| format!("read {}", command.executable))?;
    let config = carrick_softcpu_aarch64_host::SoftSingleProcessConfig {
        elf_bytes: &elf_bytes,
        executable_path: &command.executable,
        argv: command
            .argv
            .iter()
            .map(|arg| arg.as_bytes().to_vec())
            .collect(),
        envp: options
            .env
            .iter()
            .map(|entry| entry.as_bytes().to_vec())
            .collect(),
        rootfs_dir: Some(options.rootfs),
        el1_elf_override: Some(&el1_elf),
        max_syscalls: options.max_syscalls,
    };
    let mut summary = SoftRunSummary {
        executable: command.executable.clone(),
        argv: command.argv.clone(),
        exit_code: None,
        signal: None,
        fault_addr: None,
        fault_pc: None,
        carrier_error: None,
        syscalls_dispatched: 0,
        ring_completed: 0,
        kernel_dispatched: 0,
        runner_refused: 0,
        counted_enosys: Vec::new(),
        census_published: false,
    };
    let status = match carrick_softcpu_aarch64_host::run_single_process(&config) {
        Ok(run) => {
            use std::io::Write as _;
            std::io::stdout().write_all(&run.stdout)?;
            std::io::stdout().flush()?;
            std::io::stderr().write_all(&run.stderr)?;
            summary.syscalls_dispatched = run.syscalls_dispatched;
            summary.ring_completed = run.reply_census.ring_completed;
            summary.kernel_dispatched = run.reply_census.kernel_dispatched;
            summary.runner_refused = run.reply_census.runner_refused;
            summary.counted_enosys = run
                .counted_enosys
                .iter()
                .map(|&(nr, name, count)| (nr, name.to_owned(), count))
                .collect();
            summary.census_published = publish_census(&run)?;
            match run.terminating_fault {
                Some(fault) => {
                    summary.signal = Some(fault.signum);
                    summary.fault_addr = Some(format!("{:#x}", fault.fault_addr));
                    summary.fault_pc = Some(format!("{:#x}", fault.elr));
                    128 + fault.signum
                }
                None => {
                    summary.exit_code = Some(run.exit_code);
                    run.exit_code & 0xff
                }
            }
        }
        Err(error) => {
            summary.carrier_error = Some(error);
            CARRIER_ERROR_STATUS
        }
    };
    eprintln!("{}", summary_line(&summary));
    if let Some(path) = options.summary_out {
        std::fs::write(path, serde_json::to_vec_pretty(&summary)?)
            .with_context(|| format!("write {}", path.display()))?;
    }
    Ok(status)
}

/// Publish the terminal census when `CARRICK_EL1_CENSUS` asks for one.
fn publish_census(run: &carrick_softcpu_aarch64_host::SoftProcessRun) -> Result<bool> {
    carrick_runtime::el1_census::init_from_env();
    if !carrick_runtime::el1_census::enabled() {
        return Ok(false);
    }
    let counters =
        el1_counters(&run.engine).context("the soft engine has no EL1 counters to publish")?;
    let scope = std::env::var("CARRICK_RUN_ID")
        .ok()
        .and_then(|id| carrick_kernel::kernel::CarrierScopeId::new(id).ok());
    carrick_runtime::el1_census::publish_counters_terminal(
        scope.as_ref(),
        counters,
        carrick_spec::syscall_census::CensusIsa::Aarch64,
    )
    .context("publish the soft run's terminal census")?;
    Ok(true)
}

/// The EL1 image's live counters in the engine's EL1 region, the record a
/// carrier's terminal census is cut from. `None` when nothing is mapped there.
fn el1_counters(
    engine: &carrick_softcpu_aarch64_host::SoftAarch64Engine<
        carrick_softcpu_aarch64_host::HostBlockRunner,
    >,
) -> Option<&carrick_el1_abi::Counters> {
    use carrick_el1_abi::{Counters, EL1_COUNTERS_BASE};
    let ptr = carrick_hal::GuestVmBackend::host_ptr(
        engine.backend(),
        EL1_COUNTERS_BASE,
        size_of::<Counters>(),
    )?;
    if ptr.align_offset(align_of::<Counters>()) != 0 {
        return None;
    }
    // SAFETY: the engine's stage 2 maps `size_of::<Counters>()` bytes at the
    // aligned `EL1_COUNTERS_BASE` for as long as `engine` lives, and every
    // field of `Counters` is an atomic, valid for any bit pattern.
    Some(unsafe { &*ptr.cast::<Counters>() })
}

fn summary_line(summary: &SoftRunSummary) -> String {
    let ending = match (&summary.carrier_error, summary.signal, summary.exit_code) {
        (Some(error), _, _) => format!("carrier error: {error}"),
        (None, Some(signal), _) => format!(
            "signal {signal} (fault at {}, pc {})",
            summary.fault_addr.as_deref().unwrap_or("?"),
            summary.fault_pc.as_deref().unwrap_or("?")
        ),
        (None, None, Some(code)) => format!("exit {code}"),
        (None, None, None) => "no ending".to_owned(),
    };
    let enosys: Vec<String> = summary
        .counted_enosys
        .iter()
        .map(|(nr, name, count)| format!("{nr}({name})x{count}"))
        .collect();
    format!(
        "carrick: soft-run {}: {ending}; syscalls {} (ring {}, kernel {}, refused {}); counted ENOSYS [{}]",
        summary.executable,
        summary.syscalls_dispatched,
        summary.ring_completed,
        summary.kernel_dispatched,
        summary.runner_refused,
        enosys.join(", ")
    )
}
