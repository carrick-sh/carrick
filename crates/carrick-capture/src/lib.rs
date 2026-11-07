//! The one root-run capture command on agent-template clones (#1621; owner
//! decision on #231, 2026-11-04, scoped by the carrick-87 review).
//!
//! The worker account may run `sudo carrick-capture <name> [--seconds N]`
//! and nothing else that reaches bpftrace. `<name>` must be one of
//! [`SCRIPTS`], reviewed `.bt` files compiled into this binary and installed
//! root-owned under [`SCRIPT_DIR`]. There is no way to pass a program (`-e`),
//! a program file, an include path, an output file or any other bpftrace
//! option: root bpftrace with a free-form program can read any process's
//! memory and any file, which would erase the separation between the worker
//! account and the accounts that hold credentials.
//!
//! Before it runs anything, the front checks that the installed script is
//! byte-identical to the compiled-in copy and that it and every directory
//! above it are root-owned and writable by root alone. It then execs
//! `/usr/bin/timeout`, which runs `/usr/bin/bpftrace -B line <path> <N>` with
//! a hard deadline, from `/`, with stdin closed and a cleared environment.
//!
//! This crate is std only and holds no `unsafe`: agent templates build it
//! with the pinned rustc alone (`scripts/ci/build-template-debian.sh`), so no
//! xtask or CLI change ever becomes root-run code. The script rules (no
//! `cat()`, `system()`, `str()`, `buf()`, `kptr()`/`uptr()`, pointer
//! dereferences, includes or `config`) are enforced over the script
//! directory by `tests/capture.rs`.
#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Where templates install this binary; the sudoers rule names this path.
pub const FRONT_PATH: &str = "/usr/local/sbin/carrick-capture";
/// Where templates install [`SCRIPTS`], root-owned, mode 644, in a 755 directory.
pub const SCRIPT_DIR: &str = "/usr/local/lib/carrick-capture";
pub const BPFTRACE: &str = "/usr/bin/bpftrace";
pub const TIMEOUT: &str = "/usr/bin/timeout";
/// The capture length when `--seconds` is absent.
pub const DEFAULT_SECONDS: u32 = 60;
/// The longest capture `--seconds` admits.
pub const MAX_SECONDS: u32 = 3600;
/// The hard deadline is the capture length plus this much bpftrace startup
/// time; each script also exits on its own after `N` interval ticks.
pub const GRACE_SECONDS: u32 = 30;
/// Exit status for an argument shape outside the allowlist (`EX_USAGE`).
pub const REFUSED_SHAPE: i32 = 64;
/// Exit status when the installed script is not the reviewed one or is not
/// root-only (`EX_NOPERM`).
pub const REFUSED_INSTALL: i32 = 77;
/// Every refusal's stderr starts with this.
pub const REFUSAL: &str = "carrick-capture: refused";

/// A reviewed capture script: `<name>.bt` under `scripts/` in this crate.
#[derive(Debug, PartialEq, Eq)]
pub struct Script {
    pub name: &'static str,
    pub source: &'static str,
}

/// The allowlist. A new entry needs a reviewed `scripts/<name>.bt` that
/// passes the script rules in `tests/capture.rs`.
pub const SCRIPTS: &[Script] = &[Script {
    name: "signal-kill-sender",
    source: include_str!("../scripts/signal-kill-sender.bt"),
}];

/// An admitted invocation.
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub script: &'static Script,
    pub seconds: u32,
}

/// Admit exactly `<name>` or `<name> --seconds N`, with `<name>` compared
/// byte for byte against [`SCRIPTS`] and `N` plain decimal in
/// `1..=MAX_SECONDS`.
pub fn parse(args: &[OsString]) -> Result<Request, String> {
    let (name, seconds) = match args {
        [name] => (name, None),
        [name, flag, value] if flag.as_bytes() == b"--seconds" => (name, Some(value)),
        _ => return Err("expected `<name>` or `<name> --seconds N`".to_owned()),
    };
    let script = SCRIPTS
        .iter()
        .find(|script| script.name.as_bytes() == name.as_bytes())
        .ok_or_else(|| format!("{name:?} is not an allowlisted capture script"))?;
    let seconds = match seconds {
        None => DEFAULT_SECONDS,
        Some(value) => parse_seconds(value)?,
    };
    Ok(Request { script, seconds })
}

fn parse_seconds(value: &OsStr) -> Result<u32, String> {
    let refused =
        || format!("--seconds takes a plain number from 1 to {MAX_SECONDS}, not {value:?}");
    let digits = value.as_bytes();
    let plain = !digits.is_empty()
        && digits.len() <= 4
        && digits[0] != b'0'
        && digits.iter().all(u8::is_ascii_digit);
    if !plain {
        return Err(refused());
    }
    let seconds = digits
        .iter()
        .fold(0u32, |total, digit| total * 10 + u32::from(digit - b'0'));
    if seconds > MAX_SECONDS {
        return Err(refused());
    }
    Ok(seconds)
}

/// The two fields of an `lstat` result the directory walk reads. Callers
/// fill it without following a final symlink, so a symlink reports its own
/// type and never its target's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathMode {
    /// `st_mode`, file type bits included.
    pub mode: u32,
    pub uid: u32,
}

const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;

impl PathMode {
    fn of(meta: &Metadata) -> Self {
        Self {
            mode: meta.mode(),
            uid: meta.uid(),
        }
    }
}

/// The one root-trust path walk, for this binary's own script check and
/// for qualification's check of the installed front and script directory
/// (`carrick-xtask ci-scaler qualify-clone`). `dir` and each ancestor up to
/// and including `trusted_root` must be a real directory, never a symlink,
/// owned by `owner` and writable by nobody else. `lstat` reports one path
/// without following it; production passes `/` and uid 0.
pub fn verify_directory_chain(
    dir: &Path,
    trusted_root: &Path,
    owner: u32,
    mut lstat: impl FnMut(&Path) -> Result<PathMode, String>,
) -> Result<(), String> {
    let mut current = dir;
    loop {
        let meta = lstat(current)?;
        if meta.mode & S_IFMT == S_IFLNK {
            return Err(format!("{} is a symlink", current.display()));
        }
        if meta.mode & S_IFMT != S_IFDIR {
            return Err(format!("{} is not a directory", current.display()));
        }
        owner_only(current, meta, owner)?;
        if current == trusted_root {
            return Ok(());
        }
        current = current
            .parent()
            .ok_or_else(|| format!("{} is outside {}", dir.display(), trusted_root.display()))?;
    }
}

/// Check the installed copy of `script` under `dir` and return its path.
/// `dir` must pass [`verify_directory_chain`] up to `trusted_root`; the
/// script must be a regular file with the same owner and write rule,
/// byte-identical to the compiled-in source. Production passes
/// [`SCRIPT_DIR`], `/` and uid 0.
pub fn verify_installed(
    dir: &Path,
    trusted_root: &Path,
    owner: u32,
    script: &Script,
) -> Result<PathBuf, String> {
    verify_directory_chain(dir, trusted_root, owner, |path| {
        path.symlink_metadata()
            .map(|meta| PathMode::of(&meta))
            .map_err(|error| format!("{}: {error}", path.display()))
    })?;
    let path = dir.join(format!("{}.bt", script.name));
    let link = path
        .symlink_metadata()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let mut file = File::open(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if !link.file_type().is_file() || (link.dev(), link.ino()) != (meta.dev(), meta.ino()) {
        return Err(format!("{} is not a regular file", path.display()));
    }
    owner_only(&path, PathMode::of(&meta), owner)?;
    let limit = script.source.len() as u64 + 1;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if bytes != script.source.as_bytes() {
        return Err(format!(
            "{} differs from the reviewed copy built into carrick-capture",
            path.display()
        ));
    }
    Ok(path)
}

fn owner_only(path: &Path, meta: PathMode, owner: u32) -> Result<(), String> {
    if meta.uid != owner || meta.mode & 0o022 != 0 {
        return Err(format!(
            "{} must be owned by uid {owner} and writable by it alone",
            path.display()
        ));
    }
    Ok(())
}

/// The exec the front performs for an admitted request: a hard deadline of
/// `seconds + GRACE_SECONDS` (SIGINT, then SIGKILL 5 s later) around
/// bpftrace with line-buffered output, the fixed script path and the
/// capture length as `$1`. Nothing from the caller's environment, working
/// directory or stdin reaches it.
pub fn command(request: &Request, script: &Path) -> Command {
    let mut command = Command::new(TIMEOUT);
    command
        .args([
            "--foreground",
            "--signal=INT",
            "--kill-after=5",
            &(request.seconds + GRACE_SECONDS).to_string(),
            BPFTRACE,
            "-B",
            "line",
        ])
        .arg(script)
        .arg(request.seconds.to_string())
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .current_dir("/")
        .stdin(Stdio::null());
    command
}

fn usage() -> String {
    let names: Vec<&str> = SCRIPTS.iter().map(|script| script.name).collect();
    format!(
        "usage: sudo carrick-capture <name> [--seconds N]  (N from 1 to {MAX_SECONDS}, default {DEFAULT_SECONDS})\nscripts: {}",
        names.join(", ")
    )
}

/// The binary's whole behaviour. Returns an exit status when it does not exec.
pub fn run(args: &[OsString]) -> i32 {
    let request = match parse(args) {
        Ok(request) => request,
        Err(reason) => {
            eprintln!("{REFUSAL}: {reason}\n{}", usage());
            return REFUSED_SHAPE;
        }
    };
    let script = match verify_installed(Path::new(SCRIPT_DIR), Path::new("/"), 0, request.script) {
        Ok(script) => script,
        Err(reason) => {
            eprintln!("{REFUSAL}: {reason}");
            return REFUSED_INSTALL;
        }
    };
    let error = command(&request, &script).exec();
    eprintln!("carrick-capture: cannot run {TIMEOUT}: {error}");
    127
}
