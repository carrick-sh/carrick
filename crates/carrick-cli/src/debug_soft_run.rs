//! `carrick debug soft-run`: one AArch64 Linux process on the soft AArch64
//! CPU (#1236), from a rootfs directory, through the production EL1 image and
//! the production kernel dispatcher
//! (`carrick_softcpu_aarch64_host::run_single_process`). Diagnostics only: it
//! is the soft-a64 provider of `carrick debug discover` (#1906), so a parity
//! row's first single-process command reaches ARM semantics on a Linux host.
//!
//! The command is looked up the way `execve` and a shell's `PATH` search do,
//! inside the rootfs: every symlink resolves against the rootfs root, and one
//! `#!` interpreter line is honoured. The guest's stdout and stderr are this
//! command's; the exit status is the guest's, or 128 plus the signal that
//! killed it. With `CARRICK_EL1_CENSUS=<directory>` the run publishes the same
//! terminal census a hardware carrier does, cut from the EL1 image's counters.
//!
//! The soft CPU executes translated blocks natively, so a run needs a Linux
//! arm64 host; anywhere else the runner refuses it (`UnsupportedHost`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};

/// A shell's `PATH` when the environment names none.
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// Symlinks one lookup may follow before it is a loop (Linux's `ELOOP` bound).
const MAX_SYMLINK_HOPS: usize = 40;
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

/// The program `execve` would load for an argv, inside a rootfs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedCommand {
    /// The ELF's guest path with every symlink resolved.
    pub(crate) executable: String,
    /// The guest argv: the caller's, or an interpreter's in front of it.
    pub(crate) argv: Vec<String>,
}

/// Resolve `guest` (absolute, or relative to `/`) inside `root`, following
/// every symlink against `root`. Returns the resolved guest path.
pub(crate) fn resolve_guest_path(root: &Path, guest: &str) -> Result<String> {
    let mut pending: Vec<String> = guest.split('/').rev().map(str::to_owned).collect();
    let mut resolved: Vec<String> = Vec::new();
    let mut hops = 0usize;
    while let Some(part) = pending.pop() {
        match part.as_str() {
            "" | "." => continue,
            ".." => {
                resolved.pop();
                continue;
            }
            _ => {}
        }
        let mut host = root.to_path_buf();
        host.extend(&resolved);
        host.push(&part);
        let metadata = std::fs::symlink_metadata(&host).with_context(|| {
            format!(
                "{guest}: /{} not in the rootfs",
                resolved_join(&resolved, &part)
            )
        })?;
        if metadata.file_type().is_symlink() {
            hops += 1;
            ensure!(
                hops <= MAX_SYMLINK_HOPS,
                "{guest}: more than {MAX_SYMLINK_HOPS} symlinks (ELOOP)"
            );
            let target = std::fs::read_link(&host)
                .with_context(|| format!("read symlink {}", host.display()))?;
            let target = target
                .to_str()
                .with_context(|| format!("{}: symlink target is not UTF-8", host.display()))?;
            if target.starts_with('/') {
                resolved.clear();
            }
            pending.extend(target.split('/').rev().map(str::to_owned));
        } else {
            resolved.push(part);
        }
    }
    Ok(format!("/{}", resolved.join("/")))
}

fn resolved_join(resolved: &[String], part: &str) -> String {
    let mut path = resolved.join("/");
    if !path.is_empty() {
        path.push('/');
    }
    path.push_str(part);
    path
}

/// The host path of a resolved guest path.
fn host_path(root: &Path, resolved: &str) -> PathBuf {
    root.join(resolved.trim_start_matches('/'))
}

/// Find `argv[0]` the way a shell does: a name with a `/` is a path (relative
/// to `/`, the guest's working directory); a bare name is searched in `path`.
/// Returns the guest path as found, before symlinks resolve.
pub(crate) fn find_command(root: &Path, name: &str, path: &str) -> Result<String> {
    ensure!(!name.is_empty(), "empty command");
    if name.contains('/') {
        return Ok(if name.starts_with('/') {
            name.to_owned()
        } else {
            format!("/{name}")
        });
    }
    for dir in path.split(':').filter(|dir| dir.starts_with('/')) {
        let candidate = format!("{}/{name}", dir.trim_end_matches('/'));
        let Ok(resolved) = resolve_guest_path(root, &candidate) else {
            continue;
        };
        if is_executable_file(&host_path(root, &resolved)) {
            return Ok(candidate);
        }
    }
    bail!("{name}: not found in the rootfs PATH {path}")
}

fn is_executable_file(host: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(host)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// Resolve the command for `argv` inside `root`: the PATH search, symlinks,
/// and one `#!` line (`#!interpreter [one argument]`, as Linux reads it).
pub(crate) fn resolve_command(root: &Path, argv: &[String], path: &str) -> Result<ResolvedCommand> {
    let name = argv.first().context("soft-run needs a command after --")?;
    let found = find_command(root, name, path)?;
    let executable = resolve_guest_path(root, &found)?;
    let head = read_head(&host_path(root, &executable))?;
    if let Some(line) = head.strip_prefix(b"#!") {
        let line = line.split(|byte| *byte == b'\n').next().unwrap_or_default();
        let line = std::str::from_utf8(line)
            .with_context(|| format!("{found}: #! line is not UTF-8"))?
            .trim();
        let (interpreter, argument) = match line.split_once([' ', '\t']) {
            Some((interpreter, argument)) => (interpreter, Some(argument.trim())),
            None => (line, None),
        };
        ensure!(
            interpreter.starts_with('/'),
            "{found}: #! interpreter {interpreter:?} is not an absolute path"
        );
        let interpreter_path = resolve_guest_path(root, interpreter)?;
        let interpreter_head = read_head(&host_path(root, &interpreter_path))?;
        ensure!(
            interpreter_head.starts_with(b"\x7fELF"),
            "{found}: #! interpreter {interpreter} is not an ELF (one #! level only)"
        );
        let mut script_argv = vec![interpreter.to_owned()];
        script_argv.extend(argument.filter(|arg| !arg.is_empty()).map(str::to_owned));
        script_argv.push(found);
        script_argv.extend(argv[1..].iter().cloned());
        return Ok(ResolvedCommand {
            executable: interpreter_path,
            argv: script_argv,
        });
    }
    ensure!(
        head.starts_with(b"\x7fELF"),
        "{found} ({executable}) is neither an ELF nor a #! script"
    );
    Ok(ResolvedCommand {
        executable,
        argv: argv.to_vec(),
    })
}

fn read_head(host: &Path) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let mut head = Vec::with_capacity(256);
    std::fs::File::open(host)
        .with_context(|| format!("open {}", host.display()))?
        .take(256)
        .read_to_end(&mut head)
        .with_context(|| format!("read {}", host.display()))?;
    Ok(head)
}

/// The `PATH` of a `KEY=VALUE` environment.
fn env_path(env: &[String]) -> &str {
    env.iter()
        .rev()
        .find_map(|entry| entry.strip_prefix("PATH="))
        .unwrap_or(DEFAULT_PATH)
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
    let command = resolve_command(options.rootfs, options.argv, env_path(options.env))?;
    let elf_bytes = std::fs::read(host_path(options.rootfs, &command.executable))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    fn rootfs() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for dir in ["usr/bin", "usr/local/go/bin", "bin", "etc"] {
            std::fs::create_dir_all(root.path().join(dir)).unwrap();
        }
        let elf = |path: &str| {
            let host = root.path().join(path);
            std::fs::write(&host, b"\x7fELF\x02\x01\x01").unwrap();
            std::fs::set_permissions(&host, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        elf("usr/local/go/bin/go");
        elf("usr/bin/dash");
        // An absolute symlink must resolve inside the rootfs, never the host.
        symlink("/usr/local/go/bin/go", root.path().join("usr/bin/go")).unwrap();
        symlink("../usr/bin/dash", root.path().join("bin/sh")).unwrap();
        symlink("loop-b", root.path().join("etc/loop-a")).unwrap();
        symlink("loop-a", root.path().join("etc/loop-b")).unwrap();
        std::fs::write(root.path().join("etc/readme"), b"text").unwrap();
        let script = root.path().join("usr/bin/hello");
        std::fs::write(&script, b"#!/bin/sh -e\necho hi\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        root
    }

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    }

    #[test]
    fn symlinks_resolve_against_the_rootfs_root() {
        let root = rootfs();
        assert_eq!(
            resolve_guest_path(root.path(), "/usr/bin/go").unwrap(),
            "/usr/local/go/bin/go"
        );
        assert_eq!(
            resolve_guest_path(root.path(), "/bin/sh").unwrap(),
            "/usr/bin/dash"
        );
        assert_eq!(
            resolve_guest_path(root.path(), "/../../bin/./sh").unwrap(),
            "/usr/bin/dash"
        );
        let error = resolve_guest_path(root.path(), "/etc/loop-a").unwrap_err();
        assert!(error.to_string().contains("ELOOP"), "{error}");
        assert!(resolve_guest_path(root.path(), "/usr/bin/missing").is_err());
    }

    #[test]
    fn a_bare_name_is_searched_in_path_and_keeps_its_argv() {
        let root = rootfs();
        let command =
            resolve_command(root.path(), &argv(&["go", "version"]), DEFAULT_PATH).unwrap();
        assert_eq!(
            command,
            ResolvedCommand {
                executable: "/usr/local/go/bin/go".to_owned(),
                argv: argv(&["go", "version"]),
            }
        );
        // A PATH entry that holds a non-executable file of the name is skipped.
        assert!(resolve_command(root.path(), &argv(&["readme"]), "/etc").is_err());
        assert!(resolve_command(root.path(), &argv(&["nope"]), DEFAULT_PATH).is_err());
        assert_eq!(
            env_path(&argv(&["HOME=/root", "PATH=/usr/local/go/bin"])),
            "/usr/local/go/bin"
        );
        assert_eq!(env_path(&[]), DEFAULT_PATH);
    }

    #[test]
    fn a_script_runs_under_its_interpreter_with_one_argument() {
        let root = rootfs();
        let command =
            resolve_command(root.path(), &argv(&["hello", "a", "b"]), "/usr/bin").unwrap();
        assert_eq!(
            command,
            ResolvedCommand {
                executable: "/usr/bin/dash".to_owned(),
                argv: argv(&["/bin/sh", "-e", "/usr/bin/hello", "a", "b"]),
            }
        );
        // A path that is neither an ELF nor a script is refused.
        let error =
            resolve_command(root.path(), &argv(&["/etc/readme"]), DEFAULT_PATH).unwrap_err();
        assert!(error.to_string().contains("neither an ELF"), "{error}");
    }
}
