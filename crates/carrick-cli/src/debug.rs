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

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use carrick_runtime::runtime::DebugStateSnapshot;

use crate::args::DebugCommand;

pub(crate) fn run_debug(command: DebugCommand) -> anyhow::Result<()> {
    match command {
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
            command,
        } => {
            let status = run_lldb_deadline(
                command,
                deadline_seconds,
                out_dir,
                run_id,
                lldb_plugin,
                no_core,
            )?;
            std::process::exit(status);
        }
    }
    Ok(())
}

fn run_lldb_deadline(
    mut run_args: Vec<String>,
    deadline_seconds: u64,
    out_dir: PathBuf,
    run_id_arg: Option<String>,
    lldb_plugin_arg: Option<PathBuf>,
    no_core: bool,
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
        &exe,
        &lldb_plugin,
        &run_args,
    )?;

    let guest = File::create(&guest_log)
        .with_context(|| format!("failed to create {}", guest_log.display()))?;
    let guest_stderr = guest
        .try_clone()
        .with_context(|| format!("failed to clone {}", guest_log.display()))?;
    let mut child = Command::new(&exe)
        .arg("run")
        .args(&run_args)
        .env("CARRICK_RUN_ID", &run_id)
        .stdout(Stdio::from(guest))
        .stderr(Stdio::from(guest_stderr))
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
        if started.elapsed() >= deadline {
            let why = format!("deadline-{deadline_seconds}s");
            let pids = dump_lldb(&LldbDumpContext {
                run_id: &run_id,
                why: &why,
                exe: &exe,
                lldb_plugin: &lldb_plugin,
                out_dir: &out_dir,
                lldb_log: &lldb_log,
                ps_log: &ps_log,
                no_core,
            })?;
            terminate_scoped_run(&run_id, &pids, &mut child)?;
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
    exe: &Path,
    lldb_plugin: &Path,
    run_args: &[String],
) -> anyhow::Result<()> {
    let mut file =
        File::create(path).with_context(|| format!("failed to create {}", path.display()))?;
    writeln!(file, "run_id={run_id}")?;
    writeln!(file, "deadline_seconds={deadline_seconds}")?;
    writeln!(file, "exe={}", exe.display())?;
    writeln!(file, "lldb_plugin={}", lldb_plugin.display())?;
    writeln!(file, "run_args={}", run_args.join(" "))?;
    Ok(())
}

#[derive(Clone, Debug)]
struct MatchedProcess {
    pid: libc::pid_t,
    ppid: libc::pid_t,
    command: String,
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
    let pids = collect_scoped_processes(ctx.run_id)?;
    write_ps_log(ctx.ps_log, &pids)?;

    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(ctx.lldb_log)
        .with_context(|| format!("failed to open {}", ctx.lldb_log.display()))?;
    writeln!(log, "RUN_ID={} WHY={}", ctx.run_id, ctx.why)?;
    writeln!(log, "PS_MATCHES:")?;
    for process in &pids {
        writeln!(log, "{} {} {}", process.pid, process.ppid, process.command)?;
    }

    for process in &pids {
        if process.pid == std::process::id() as libc::pid_t {
            continue;
        }
        writeln!(
            log,
            "===== lldb attach pid={} ppid={} =====",
            process.pid, process.ppid
        )?;
        log.flush()?;
        let core_path = ctx
            .out_dir
            .join(format!("{}.{}.core", ctx.run_id, process.pid));
        let mut lldb = Command::new("lldb");
        lldb.arg("--batch")
            .arg("-o")
            .arg(format!(
                "command script import {}",
                lldb_quoted_path(ctx.lldb_plugin)
            ))
            .arg("-o")
            .arg(format!("attach {}", process.pid))
            .arg("-o")
            .arg("carrick eventring")
            .arg("-o")
            .arg("thread backtrace all");
        if !ctx.no_core {
            lldb.arg("-o").arg(format!(
                "process save-core {}",
                lldb_quoted_path(&core_path)
            ));
        }
        lldb.arg("-o").arg("detach").arg(ctx.exe);

        let stdout = log
            .try_clone()
            .with_context(|| format!("failed to clone {}", ctx.lldb_log.display()))?;
        let stderr = log
            .try_clone()
            .with_context(|| format!("failed to clone {}", ctx.lldb_log.display()))?;
        let status = lldb
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .status()
            .context("failed to run lldb")?;
        writeln!(
            log,
            "===== lldb status pid={} status={} =====",
            process.pid, status
        )?;
    }
    Ok(pids)
}

fn collect_scoped_processes(run_id: &str) -> anyhow::Result<Vec<MatchedProcess>> {
    let output = Command::new("ps")
        .args(["-A", "-o", "pid=,ppid=,command="])
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
        let command = parts.collect::<Vec<_>>().join(" ");
        let pid = pid_raw
            .parse::<libc::pid_t>()
            .with_context(|| format!("failed to parse pid from `{line}`"))?;
        let ppid = ppid_raw
            .parse::<libc::pid_t>()
            .with_context(|| format!("failed to parse ppid from `{line}`"))?;
        processes.push(MatchedProcess { pid, ppid, command });
    }
    Ok(processes)
}

fn write_ps_log(path: &Path, pids: &[MatchedProcess]) -> anyhow::Result<()> {
    let mut file =
        File::create(path).with_context(|| format!("failed to create {}", path.display()))?;
    for process in pids {
        writeln!(file, "{} {} {}", process.pid, process.ppid, process.command)?;
    }
    Ok(())
}

fn terminate_scoped_run(
    run_id: &str,
    pids: &[MatchedProcess],
    child: &mut Child,
) -> anyhow::Result<()> {
    let kill_script = Path::new("scripts").join("sudo").join("kill.sh");
    if kill_script.exists() {
        let _ = Command::new(&kill_script).arg(run_id).status();
    }

    for process in pids {
        // SAFETY: signal delivery is scoped to pids whose proctitle matched this
        // run id. Errors are best-effort here because the process may have exited.
        unsafe {
            libc::kill(process.pid, libc::SIGTERM);
        }
    }
    if wait_for_child(child, Duration::from_secs(2))?.is_none() {
        for process in pids {
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

#[cfg(test)]
mod tests {
    use super::decode_esr_el1;

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
