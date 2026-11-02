//! Job-scoped tools and credentials for any Unix `carrick-agent` runner.
use crate::ci_scaler::mint::{AppToken, MintScope};
use crate::ci_scaler::{ScalerError, execute};
use crate::dispatch_mint::MintFailure;
use serde::Deserialize;
use sha2::{Digest, Sha512};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(clap::Args, Debug)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}
#[derive(clap::Subcommand, Debug)]
pub enum Action {
    /// Install checked-in, digest-pinned tools and the private launcher.
    Bootstrap,
    /// Materialize all available worker credentials and the separate loop credential.
    Auth {
        #[arg(long)]
        event: PathBuf,
    },
    /// Remove the entire job-scoped home, credentials and launcher state.
    Cleanup,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    director_repository: String,
    director_sha: String,
    /// The roster the launcher falls back to when `agy models` fails and it
    /// has no cache of its own (#1240): fresh clones start without one.
    /// Refresh it when the agy pin or the account's models change.
    agy_models_seed: Vec<String>,
    platforms: BTreeMap<String, Vec<Tool>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tool {
    name: String,
    url: String,
    sha256: Option<String>,
    sha512: Option<String>,
    member: String,
}

/// The launcher's fallback roster, inside the staged `director` tree.
pub(crate) const MODELS_SEED: &str = "agy-models-seed.json";

/// Model ids as `agy models` prints them: non-empty, lowercase, dotted or
/// hyphenated, no spaces.
fn valid_roster(models: &[String]) -> bool {
    !models.is_empty()
        && models.iter().all(|m| {
            !m.is_empty()
                && m.len() < 128
                && m.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b))
        })
}

const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
const BOOTSTRAP_BUDGET: std::time::Duration = std::time::Duration::from_secs(9 * 60);
const FETCH_ATTEMPTS: usize = 2;

struct BootstrapEnv<'a> {
    state: PathBuf,
    github_path: PathBuf,
    path_env: Option<&'a std::ffi::OsStr>,
    manifest: &'a str,
    fetch_timeout: std::time::Duration,
    deadline: std::time::Instant,
}

fn is_fetch_timeout(error: &ScalerError) -> bool {
    let ScalerError::CommandFailed(detail) = error else {
        return false;
    };
    let reason = detail.split("; stderr: ").next().unwrap_or(detail);
    reason.contains(" timed out after ") || reason == "curl exited with code 28"
}

fn fetch_limit(
    deadline: std::time::Instant,
    fetch_timeout: std::time::Duration,
) -> Result<std::time::Duration, ScalerError> {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        return Err(ScalerError::Guard(
            "host/infra: bootstrap fetch time budget exhausted",
        ));
    }
    Ok(fetch_timeout.min(remaining))
}

/// Run a bootstrap command. No inherited GitHub token reaches it; only the
/// launcher fetch gets the controller-minted `launcher` token (#1034).
fn run_command(
    dir: &Path,
    program: &str,
    args: &[&str],
    launcher: Option<&AppToken>,
    path_env: Option<&std::ffi::OsStr>,
    timeout: std::time::Duration,
) -> Result<(), ScalerError> {
    let mut command = if program == "git" {
        crate::dispatch_worker::git_invocation(dir, args)
    } else {
        let mut command = std::process::Command::new(program);
        command.args(args).current_dir(dir);
        command
    };
    if let Some(path) = path_env {
        command.env("PATH", path);
    }
    command.env_remove("GH_TOKEN").env_remove("GITHUB_TOKEN");
    if let Some(token) = launcher {
        command.env("GH_TOKEN", token.secret());
    }
    execute(&mut command, &[], timeout).map(|_| ())
}

fn invoke(
    dir: &Path,
    program: &str,
    args: &[&str],
    launcher: Option<&AppToken>,
    path_env: Option<&std::ffi::OsStr>,
    timeout: std::time::Duration,
) -> Result<(), ScalerError> {
    if let Err(error) = run_command(dir, program, args, launcher, path_env, timeout) {
        if let Some(token) = launcher {
            return Err(check_token(dir, token, path_env).err().unwrap_or(error));
        }
        return Err(error);
    }
    Ok(())
}

/// Retry a timed-out bootstrap network fetch once within `env.deadline` (#1457).
/// Non-timeout failures stop immediately; `check_token` runs only after the
/// final attempt fails.
fn retry_fetch(
    label: &str,
    env: &BootstrapEnv<'_>,
    check_dir: &Path,
    launcher: Option<&AppToken>,
    mut attempt_fn: impl FnMut(usize, std::time::Duration) -> Result<(), ScalerError>,
) -> Result<(), ScalerError> {
    for attempt in 0..FETCH_ATTEMPTS {
        let limit = fetch_limit(env.deadline, env.fetch_timeout)?;
        match attempt_fn(attempt, limit) {
            Ok(()) => return Ok(()),
            Err(error) => {
                let remaining = env
                    .deadline
                    .saturating_duration_since(std::time::Instant::now());
                let timed_out = is_fetch_timeout(&error);
                if attempt + 1 < FETCH_ATTEMPTS && timed_out && !remaining.is_zero() {
                    let _ = writeln!(
                        std::io::stderr(),
                        "bootstrap: {label} timed out; retrying once ({}s budget remaining)",
                        remaining.as_secs()
                    );
                    continue;
                }
                let error = match error {
                    ScalerError::CommandFailed(detail) if attempt > 0 => {
                        ScalerError::CommandFailed(format!("{detail} (after 1 retry)"))
                    }
                    ScalerError::CommandFailed(detail) if timed_out && remaining.is_zero() => {
                        ScalerError::CommandFailed(format!(
                            "{detail} (bootstrap fetch time budget exhausted before retry)"
                        ))
                    }
                    other => other,
                };
                if let Some(token) = launcher {
                    return Err(check_token(check_dir, token, env.path_env)
                        .err()
                        .unwrap_or(error));
                }
                return Err(error);
            }
        }
    }
    Err(ScalerError::Guard("bootstrap fetch attempts exhausted"))
}

/// The launcher token, minted by the ctb controller for this job. A refusal
/// or an unavailable controller fails bootstrap; no other token is tried.
fn launcher_token(
    mint: impl FnOnce() -> Result<AppToken, MintFailure>,
) -> Result<AppToken, ScalerError> {
    mint().map_err(|failure| {
        ScalerError::Usage(format!(
            "host/infra: no controller-minted bootstrap token ({}); bootstrap requires read access to the private launcher repository and uses no other token",
            failure.describe()
        ))
    })
}

fn check_token(
    root: &Path,
    token: &AppToken,
    path_env: Option<&std::ffi::OsStr>,
) -> Result<(), ScalerError> {
    let repository = "carrick-sh/agy-director";
    let message = "host/infra: controller-minted bootstrap token rejected or expired, or GitHub access unavailable; bootstrap requires read access to the private launcher repository";
    let mut command = std::process::Command::new("gh");
    command
        .args(["api", &format!("repos/{repository}")])
        .current_dir(root)
        .env_remove("GITHUB_TOKEN")
        .env("GH_TOKEN", token.secret());
    if let Some(path) = path_env {
        command.env("PATH", path);
    }
    execute(
        &mut command,
        &[],
        std::time::Duration::from_secs(30).min(job_remaining(39)?),
    )
    .map_err(|_| ScalerError::Guard(message))?;
    Ok(())
}

/// Bound a phase against job admission time, reserving time for reporting.
pub(crate) fn job_remaining(minutes: u64) -> Result<std::time::Duration, ScalerError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ScalerError::Guard("host/infra: invalid runner clock"))?
        .as_secs();
    let started = std::env::var("CARRICK_AGENT_JOB_STARTED_AT")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|_| ScalerError::Guard("host/infra: invalid dispatch job start time"))?
        .unwrap_or(now);
    let seconds = started.saturating_add(minutes * 60).saturating_sub(now);
    if started > now || seconds == 0 {
        return Err(ScalerError::Guard(
            "host/infra: dispatch job time budget exhausted; start a fresh job",
        ));
    }
    Ok(std::time::Duration::from_secs(seconds))
}

pub(crate) fn state() -> Result<PathBuf, ScalerError> {
    let temporary =
        std::env::var_os("RUNNER_TEMP").ok_or(ScalerError::Guard("RUNNER_TEMP is required"))?;
    let id = |key| -> Result<String, ScalerError> {
        std::env::var(key)
            .ok()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .ok_or(ScalerError::Guard("invalid Actions run identity"))
    };
    Ok(PathBuf::from(temporary).join(format!(
        "carrick-agent-{}-{}",
        id("GITHUB_RUN_ID")?,
        id("GITHUB_RUN_ATTEMPT")?
    )))
}

fn private_dir(path: &Path) -> Result<(), ScalerError> {
    std::fs::create_dir(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Give the agent writable Rust state without modifying the runner's cache homes.
pub(crate) fn isolate_rust_homes(
    command: &mut std::process::Command,
    state: &Path,
) -> Result<(), ScalerError> {
    let private = state.canonicalize()?.join("rust");
    private_dir(&private)?;
    let mut homes = Vec::new();
    for (key, directory) in [("CARGO_HOME", ".cargo"), ("RUSTUP_HOME", ".rustup")] {
        let configured = command
            .get_envs()
            .find(|(name, _)| *name == key)
            .and_then(|(_, value)| value.map(PathBuf::from));
        let source = configured
            .or_else(|| std::env::var_os(key).map(PathBuf::from))
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(directory)))
            .ok_or(ScalerError::Guard("Rust home is unavailable"))?
            .canonicalize()?;
        let destination = private.join(directory.trim_start_matches('.'));
        if key == "CARGO_HOME" {
            // Cargo config is executable policy, not a cache: [build] wrappers
            // and [env] can reconnect the agent to runner-owned services.
            // Drop both supported filenames wholesale, including symlinks.
            private_dir(&destination)?;
            for entry in std::fs::read_dir(&source)? {
                let entry = entry?;
                if matches!(
                    entry.file_name().to_str(),
                    Some("config" | "config.toml" | "credentials" | "credentials.toml")
                ) {
                    continue;
                }
                copy_rust_home(
                    &entry.path(),
                    &destination.join(entry.file_name()),
                    &mut Vec::new(),
                )?;
            }
        } else {
            copy_rust_home(&source, &destination, &mut Vec::new())?;
        }
        command.env(key, &destination);
        homes.push((source, destination));
    }
    let configured_path = command
        .get_envs()
        .find(|(key, _)| *key == "PATH")
        .and_then(|(_, value)| value.map(std::ffi::OsString::from));
    let original_path = configured_path
        .or_else(|| std::env::var_os("PATH"))
        .ok_or(ScalerError::Guard("runner PATH is unavailable"))?;
    let mut paths = vec![private.join("cargo/bin")];
    for path in std::env::split_paths(&original_path) {
        let mapped = homes
            .iter()
            .find_map(|(source, destination)| {
                path.strip_prefix(source)
                    .ok()
                    .map(|suffix| destination.join(suffix))
            })
            .unwrap_or(path);
        if !paths.contains(&mapped) {
            paths.push(mapped);
        }
    }
    command.env(
        "PATH",
        std::env::join_paths(paths).map_err(|_| ScalerError::Guard("invalid private Rust PATH"))?,
    );
    Ok(())
}

// Rustup proxies can be symlinks or hardlinks. Materialize each entry as a
// distinct writable file so neither the source home nor another proxy aliases
// writes from the agent. Directory links are traversed with cycle detection.
fn copy_rust_home(
    source: &Path,
    destination: &Path,
    ancestors: &mut Vec<PathBuf>,
) -> Result<(), ScalerError> {
    let source = source.canonicalize()?;
    if destination.starts_with(&source) {
        return Err(ScalerError::Guard("private Rust home is inside its source"));
    }
    let metadata = source.metadata()?;
    if metadata.is_dir() {
        if ancestors.contains(&source) {
            return Err(ScalerError::Guard("cyclic link in Rust home"));
        }
        private_dir(destination)?;
        ancestors.push(source.clone());
        for entry in std::fs::read_dir(&source)? {
            let entry = entry?;
            copy_rust_home(
                &entry.path(),
                &destination.join(entry.file_name()),
                ancestors,
            )?;
        }
        ancestors.pop();
    } else if metadata.is_file() {
        let mode = if metadata.permissions().mode() & 0o111 == 0 {
            0o600
        } else {
            0o700
        };
        let mut input = std::fs::File::open(source)?;
        let mut output = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(destination)?;
        std::io::copy(&mut input, &mut output)?;
    } else {
        return Err(ScalerError::Guard("unsupported entry in Rust home"));
    }
    Ok(())
}

pub(crate) fn secret_file(path: &Path, bytes: &[u8]) -> Result<(), ScalerError> {
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

fn verify(tool: &Tool, archive: &Path) -> Result<(), ScalerError> {
    let valid = match (&tool.sha256, &tool.sha512) {
        (Some(expected), None) => crate::provision::compute_sha256(archive)? == *expected,
        (None, Some(expected)) => {
            let mut input = std::fs::File::open(archive)?;
            let mut hash = Sha512::new();
            let mut buffer = [0; 16384];
            loop {
                let count = input.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hash.update(&buffer[..count]);
            }
            format!("{:x}", hash.finalize()) == *expected
        }
        _ => false,
    };
    if !valid {
        return Err(ScalerError::Guard("pinned agent tool checksum mismatch"));
    }
    Ok(())
}

fn extract(tool: &Tool, archive: &Path, bin: &Path) -> Result<(), ScalerError> {
    verify(tool, archive)?;
    let decoder = flate2::read::GzDecoder::new(std::fs::File::open(archive)?);
    let mut tar = tar::Archive::new(decoder);
    let mut found = false;
    for entry in tar.entries()? {
        let mut entry = entry?;
        if entry.path()?.as_ref() != Path::new(&tool.member) {
            continue;
        }
        if found || !entry.header().entry_type().is_file() {
            return Err(ScalerError::Guard("invalid pinned tool archive member"));
        }
        // Extract just the named regular binary; never unpack archive paths or links.
        let output = bin.join(&tool.name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(output)?;
        std::io::copy(&mut entry, &mut file)?;
        found = true;
    }
    if !found {
        return Err(ScalerError::Guard("pinned tool archive member absent"));
    }
    Ok(())
}

fn bootstrap(
    root: &Path,
    mint: impl FnOnce() -> Result<AppToken, MintFailure>,
) -> Result<(), ScalerError> {
    // Mint first, before any state or download, and before `remember` so the
    // token is in this job's redaction set.
    let launcher = launcher_token(mint)?;
    let env = BootstrapEnv {
        state: state()?,
        github_path: PathBuf::from(
            std::env::var_os("GITHUB_PATH").ok_or(ScalerError::Guard("missing GITHUB_PATH"))?,
        ),
        path_env: None,
        manifest: include_str!("../../../scripts/ci/inputs/agent-tools.json"),
        fetch_timeout: FETCH_TIMEOUT,
        deadline: std::time::Instant::now() + BOOTSTRAP_BUDGET.min(job_remaining(80)?),
    };
    bootstrap_with_env(root, &launcher, &env)
}

fn bootstrap_with_env(
    root: &Path,
    launcher: &AppToken,
    env: &BootstrapEnv<'_>,
) -> Result<(), ScalerError> {
    private_dir(&env.state)?;
    crate::dispatch_redaction::remember_in(&env.state)?;
    let bin = env.state.join("bin");
    private_dir(&bin)?;
    private_dir(&env.state.join("home"))?;
    let manifest: Manifest = serde_json::from_str(env.manifest)?;
    if manifest.director_repository != "carrick-sh/agy-director"
        || manifest.director_sha.len() != 40
        || !manifest.director_sha.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(ScalerError::Guard("invalid pinned director identity"));
    }
    if !valid_roster(&manifest.agy_models_seed) {
        return Err(ScalerError::Guard("invalid pinned model roster seed"));
    }
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let tools = manifest
        .platforms
        .get(&platform)
        .ok_or(ScalerError::Guard("unsupported agent runner platform"))?;
    for tool in tools {
        if !matches!(tool.name.as_str(), "agy" | "just") || !tool.url.starts_with("https://") {
            return Err(ScalerError::Guard("invalid pinned agent tool"));
        }
        let archive = env.state.join(format!("{}.tar.gz", tool.name));
        let label = format!("tool {}", tool.name);
        retry_fetch(&label, env, root, None, |attempt, limit| {
            if attempt > 0 {
                match std::fs::remove_file(&archive) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
            let max_time = limit.as_secs().saturating_sub(10).max(1).to_string();
            run_command(
                root,
                "curl",
                &[
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--location",
                    "--proto",
                    "=https",
                    "--tlsv1.2",
                    "--max-time",
                    &max_time,
                    "--output",
                    archive
                        .to_str()
                        .ok_or(ScalerError::Guard("non-UTF8 runner path"))?,
                    &tool.url,
                ],
                None,
                env.path_env,
                limit,
            )
        })?;
        extract(tool, &archive, &bin)?;
        std::fs::remove_file(archive)?;
    }
    // Cargo's repository toolchain selection installs rust-toolchain.toml before
    // this driver is built. The workflow caches tools, never the isolated home.
    invoke(
        root,
        "rustup",
        &["show", "active-toolchain"],
        None,
        env.path_env,
        fetch_limit(env.deadline, env.fetch_timeout)?,
    )?;
    let director = env.state.join("director");
    retry_fetch(
        "launcher repository",
        env,
        root,
        Some(launcher),
        |attempt, limit| {
            if attempt > 0 && director.exists() {
                std::fs::remove_dir_all(&director)?;
            }
            private_dir(&director)?;
            run_command(&director, "git", &["init"], None, env.path_env, limit)?;
            run_command(
                &director,
                "git",
                &[
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "core.fsmonitor=false",
                    "-c",
                    "credential.helper=!gh auth git-credential",
                    "fetch",
                    "--depth=1",
                    "https://github.com/carrick-sh/agy-director",
                    &manifest.director_sha,
                ],
                Some(launcher),
                env.path_env,
                limit,
            )
        },
    )?;
    invoke(
        &director,
        "git",
        &["checkout", "--detach", "FETCH_HEAD"],
        None,
        env.path_env,
        fetch_limit(env.deadline, env.fetch_timeout)?,
    )?;
    // Copied with the launcher into every model account (`AGY_MODELS_SEED`).
    std::fs::write(
        director.join(MODELS_SEED),
        serde_json::to_vec(&serde_json::json!({ "models": manifest.agy_models_seed }))?,
    )?;
    let mut paths = std::fs::OpenOptions::new()
        .append(true)
        .open(&env.github_path)?;
    writeln!(paths, "{}", bin.display())?;
    Ok(())
}

fn auth(_root: &Path, event: &Path) -> Result<(), ScalerError> {
    crate::dispatch_worker::read_admission(event)?;
    let home = state()?.join("home");
    if !home.is_dir() {
        return Err(ScalerError::Guard("bootstrap must precede auth"));
    }
    if let Ok(auth) = std::env::var("CODEX_AUTH_JSON")
        && !auth.is_empty()
    {
        if !serde_json::from_str::<serde_json::Value>(&auth).is_ok_and(|v| v.is_object()) {
            return Err(ScalerError::Guard("invalid CODEX_AUTH_JSON"));
        }
        let codex = home.join(".codex");
        private_dir(&codex)?;
        secret_file(&codex.join("auth.json"), auth.as_bytes())?;
        secret_file(
            &codex.join("config.toml"),
            b"cli_auth_credentials_store = \"file\"\n",
        )?;
    }
    let raw = std::env::var("AGY_OAUTH_TOKEN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or(ScalerError::Guard("missing AGY_OAUTH_TOKEN for loop"))?;
    agy_auth(&home, &raw)?;
    let loop_home = state()?.join("loop-home");
    private_dir(&loop_home)?;
    agy_auth(&loop_home, &raw)?;
    crate::dispatch_redaction::remember()?;
    Ok(())
}

fn agy_auth(home: &Path, raw: &str) -> Result<(), ScalerError> {
    let gemini = home.join(".gemini");
    private_dir(&gemini)?;
    let agy = gemini.join("antigravity-cli");
    private_dir(&agy)?;
    secret_file(&agy.join("antigravity-oauth-token"), raw.as_bytes())
}

pub fn run(root: &Path, args: Args) -> Result<(), ScalerError> {
    match args.action {
        Action::Bootstrap => bootstrap(root, || {
            crate::dispatch_mint::app_token(MintScope::Bootstrap)
        }),
        Action::Auth { event } => auth(root, &event),
        Action::Cleanup => {
            crate::dispatch_worker::cleanup_dispatch_users()?;
            let state = state()?;
            match std::fs::symlink_metadata(&state) {
                Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
                    std::fs::remove_dir_all(state)?
                }
                Ok(_) => return Err(ScalerError::Guard("refusing non-directory agent state")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    #[test]
    fn runner_wrapper_configuration_never_reaches_agent_cargo() {
        // Exercise Cargo's real config selection, without a daemon or uid switch.
        for filename in ["config", "config.toml"] {
            let temp =
                tempfile::tempdir_in(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"))
                    .unwrap();
            let cargo_home = temp.path().join("cargo");
            let rustup = temp.path().join("rustup");
            let state = temp.path().join("state");
            let project = temp.path().join("project");
            for directory in [&cargo_home, &rustup, &state, &project] {
                std::fs::create_dir(directory).unwrap();
            }
            let marker = temp.path().join("runner-work-executed");
            let wrapper = temp.path().join("sccache");
            crate::lock_file::tests::write_test_executable(
                &wrapper,
                format!("#!/bin/sh\ntouch '{}'\nexit 91\n", marker.display()),
                std::fs::Permissions::from_mode(0o700),
            );
            std::fs::write(cargo_home.join(filename), format!(
                "[build]\nrustc-wrapper = '{}'\n[env]\nSCCACHE_SERVER_UDS = '{}'\nRUSTC_WORKSPACE_WRAPPER = '{}'\n",
                wrapper.display(), temp.path().join("runner.sock").display(), wrapper.display()
            )).unwrap();
            std::fs::write(project.join("Cargo.toml"), "[package]\nname = 'isolation-witness'\nversion = '0.0.0'\nedition = '2021'\n[lib]\npath = 'lib.rs'\n[workspace]\n").unwrap();
            std::fs::write(project.join("lib.rs"), "pub fn witness() {}\n").unwrap();
            for name in ["credentials", "credentials.toml"] {
                std::fs::write(cargo_home.join(name), "runner-registry-secret").unwrap();
            }
            let cargo = PathBuf::from(env!("CARGO"));
            let mut command = std::process::Command::new(&cargo);
            super::super::dispatch_worker::private_environment(&mut command);
            command
                .args(["check", "--offline"])
                .current_dir(&project)
                .env("CARGO_BUILD_JOBS", "3")
                .env("RUSTC", cargo.parent().unwrap().join("rustc"))
                .env("CARGO_HOME", &cargo_home)
                .env("RUSTUP_HOME", &rustup);
            isolate_rust_homes(&mut command, &state).unwrap();
            let output = command.output().unwrap();
            assert!(
                !marker.exists(),
                "runner wrapper executed via {filename}: {output:?}"
            );
            assert!(output.status.success(), "{output:?}");
            for name in ["config", "config.toml", "credentials", "credentials.toml"] {
                assert!(
                    !state.join("rust/cargo").join(name).exists(),
                    "runner Cargo config crossed boundary"
                );
            }
            assert!(
                !command
                    .get_envs()
                    .any(|(key, _)| key.to_string_lossy().starts_with("SCCACHE_"))
            );
        }
    }
    #[test]
    fn rust_home_child_mutations_leave_original_caches_and_proxies_unchanged() {
        let temp = tempfile::tempdir().unwrap();
        let cargo = temp.path().join("cargo");
        let rustup = temp.path().join("rustup");
        let toolchain = temp.path().join("linked-toolchain");
        let state = temp.path().join("state");
        std::fs::create_dir_all(cargo.join("bin")).unwrap();
        std::fs::create_dir_all(cargo.join("registry/cache")).unwrap();
        std::fs::create_dir_all(rustup.join("toolchains")).unwrap();
        std::fs::create_dir_all(toolchain.join("bin")).unwrap();
        std::os::unix::fs::symlink(&toolchain, rustup.join("toolchains/stable")).unwrap();
        std::fs::create_dir(&state).unwrap();
        let state = state.canonicalize().unwrap();
        let proxy = b"#!/bin/sh\nprintf 'private proxy:%s\\n' \"$0\"\n";
        crate::lock_file::tests::write_test_executable(
            cargo.join("bin/rustup"),
            proxy,
            std::fs::Permissions::from_mode(0o500),
        );
        std::os::unix::fs::symlink("rustup", cargo.join("bin/cargo")).unwrap();
        std::fs::write(cargo.join("registry/cache/sample"), "original crate").unwrap();
        std::fs::write(
            rustup.join("toolchains/stable/bin/rustc"),
            "original compiler",
        )
        .unwrap();
        std::fs::set_permissions(
            cargo.join("registry/cache/sample"),
            std::fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        std::fs::set_permissions(
            toolchain.join("bin/rustc"),
            std::fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        let mut child = std::process::Command::new("/bin/sh");
        child
            .args([
                "-eu",
                "-c",
                r#"cargo
printf poisoned > "$CARGO_HOME/registry/cache/sample"
printf poisoned > "$RUSTUP_HOME/toolchains/stable/bin/rustc"
printf poisoned > "$CARGO_HOME/bin/cargo"
printf '%s\n%s\n' "$CARGO_HOME" "$RUSTUP_HOME"
"#,
            ])
            .env("CARGO_HOME", &cargo)
            .env("RUSTUP_HOME", &rustup)
            .env("PATH", cargo.join("bin"));
        isolate_rust_homes(&mut child, &state).unwrap();
        let output = child.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            std::fs::read_to_string(cargo.join("registry/cache/sample")).unwrap(),
            "original crate",
            "the child poisoned the shared Cargo cache"
        );
        assert_eq!(
            std::fs::read_to_string(rustup.join("toolchains/stable/bin/rustc")).unwrap(),
            "original compiler"
        );
        assert_eq!(std::fs::read(cargo.join("bin/rustup")).unwrap(), proxy);
        assert_eq!(
            std::fs::read(state.join("rust/cargo/bin/rustup")).unwrap(),
            proxy,
            "copied symlinks must not alias another proxy"
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!(
                "private proxy:{}\n{}\n{}\n",
                state.join("rust/cargo/bin/cargo").display(),
                state.join("rust/cargo").display(),
                state.join("rust/rustup").display()
            )
        );
        assert_eq!(
            state.join("rust").metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(!state.join("rust/cargo/bin/cargo").is_symlink());
        assert!(!state.join("rust/rustup/toolchains/stable").is_symlink());
        assert_eq!(
            state
                .join("rust/rustup/toolchains/stable/bin/rustc")
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    #[test]
    fn tool_digest_is_verified_before_extracting_the_named_binary() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("tool.tar.gz");
        let encoder = flate2::write::GzEncoder::new(
            std::fs::File::create(&archive).unwrap(),
            flate2::Compression::default(),
        );
        let mut tar = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o700);
        header.set_cksum();
        tar.append_data(&mut header, "tool", &b"tool"[..]).unwrap();
        tar.into_inner().unwrap().finish().unwrap();
        let mut tool = Tool {
            name: "just".into(),
            url: "https://fixture".into(),
            sha256: Some("bad".into()),
            sha512: None,
            member: "tool".into(),
        };
        assert!(extract(&tool, &archive, temp.path()).is_err());
        assert!(!temp.path().join("just").exists());
        tool.sha256 = Some(crate::provision::compute_sha256(&archive).unwrap());
        extract(&tool, &archive, temp.path()).unwrap();
        assert_eq!(std::fs::read(temp.path().join("just")).unwrap(), b"tool");
    }
    #[test]
    fn controller_refusal_fails_bootstrap_without_a_fallback() {
        use crate::ci_scaler::mint::MintRefusal;
        use crate::dispatch_mint::MintUnavailable;
        for failure in [
            MintFailure::Refused(MintRefusal::ScopeNotAllowed),
            MintFailure::Refused(MintRefusal::BudgetExhausted),
            MintFailure::Refused(MintRefusal::JobNotInProgress),
            MintFailure::Unavailable(MintUnavailable::NoChannel),
            MintFailure::Unavailable(MintUnavailable::Timeout),
        ] {
            // The mint is the first thing bootstrap does: a failure returns
            // before any state, download or other credential is touched.
            let error = bootstrap(Path::new("/nonexistent"), || Err(failure))
                .unwrap_err()
                .to_string();
            assert!(
                error.starts_with("host/infra: no controller-minted bootstrap token"),
                "{error}"
            );
            assert!(error.contains(failure.describe()), "{error}");
            assert!(error.contains("uses no other token"), "{error}");
        }
        let token = launcher_token(|| Ok(AppToken::for_test("ghs_launcherFixture0123")));
        assert_eq!(token.unwrap().secret(), "ghs_launcherFixture0123");
    }
    #[test]
    fn credentials_are_private_and_never_overwrite_an_existing_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("auth.json");
        secret_file(&path, b"opaque").unwrap();
        assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert!(secret_file(&path, b"replace").is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"opaque");
    }

    struct BootstrapFixture {
        temp: tempfile::TempDir,
        bin: PathBuf,
        manifest: String,
    }
    impl BootstrapFixture {
        fn new(curl_mode: &str, git_mode: &str) -> Self {
            let temp = tempfile::tempdir().unwrap();
            let bin = temp.path().join("fake-bin");
            std::fs::create_dir(&bin).unwrap();
            let archives = temp.path().join("archives");
            std::fs::create_dir(&archives).unwrap();
            let mut tools = Vec::new();
            for (name, member) in [("agy", "agy"), ("just", "just")] {
                let archive = archives.join(format!("{name}.tar.gz"));
                let encoder = flate2::write::GzEncoder::new(
                    std::fs::File::create(&archive).unwrap(),
                    flate2::Compression::default(),
                );
                let mut tar = tar::Builder::new(encoder);
                let payload = format!("pinned-{name}");
                let mut header = tar::Header::new_gnu();
                header.set_size(payload.len() as u64);
                header.set_mode(0o700);
                header.set_cksum();
                tar.append_data(&mut header, member, payload.as_bytes())
                    .unwrap();
                tar.into_inner().unwrap().finish().unwrap();
                let sha256 = crate::provision::compute_sha256(&archive).unwrap();
                tools.push(serde_json::json!({
                    "name": name,
                    "url": format!("https://fixture.invalid/{name}.tar.gz"),
                    "sha256": sha256,
                    "member": member,
                }));
            }
            let remote = temp.path().join("remote-director");
            std::fs::create_dir(&remote).unwrap();
            let run_git = |args: &[&str]| {
                let out = crate::safe_copy::git_command(&remote, args)
                    .current_dir(&remote)
                    .output()
                    .unwrap();
                assert!(out.status.success(), "{args:?}: {out:?}");
                String::from_utf8(out.stdout).unwrap().trim().to_owned()
            };
            run_git(&["init", "-q"]);
            std::fs::write(remote.join("agy_worker.py"), "#!/usr/bin/env python3\n").unwrap();
            run_git(&["add", "agy_worker.py"]);
            run_git(&["commit", "-q", "-m", "pin"]);
            let director_sha = run_git(&["rev-parse", "HEAD"]);
            let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
            let manifest = serde_json::json!({
                "director_repository": "carrick-sh/agy-director",
                "director_sha": director_sha,
                "agy_models_seed": ["gemini-4-argon-high"],
                "platforms": { platform: tools },
            })
            .to_string();
            crate::lock_file::tests::write_test_executable(
                bin.join("rustup"),
                b"#!/bin/sh\ntest \"$1 $2\" = 'show active-toolchain'\n",
                std::fs::Permissions::from_mode(0o700),
            );
            crate::lock_file::tests::write_test_executable(
                bin.join("gh"),
                format!(
                    "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nprintf '{{\"full_name\":\"carrick-sh/agy-director\"}}\\n'\n",
                    temp.path().join("gh.calls").display()
                ),
                std::fs::Permissions::from_mode(0o700),
            );
            crate::lock_file::tests::write_test_executable(
                bin.join("curl"),
                format!(
                    r#"#!/bin/sh
set -eu
out=''
url=''
prev=''
for arg do
  if [ "$prev" = --output ]; then out="$arg"; fi
  prev="$arg"
  url="$arg"
done
name=$(basename "$url" .tar.gz)
count_file='{root}/curl.'"$name"'.attempts'
n=0
if [ -f "$count_file" ]; then n=$(cat "$count_file"); fi
n=$((n + 1))
printf '%s' "$n" > "$count_file"
if [ "$name" = agy ]; then
  case '{curl_mode}' in
    exit28_once)
      if [ "$n" -eq 1 ]; then
        printf 'partial' > "$out"
        echo 'curl: (28) Operation timed out' >&2
        exit 28
      fi
      ;;
    hang_once)
      if [ "$n" -eq 1 ]; then
        printf 'partial' > "$out"
        sleep 5
      fi
      ;;
    http_fail)
      echo 'curl: (22) The requested URL returned error: 503' >&2
      exit 22
      ;;
  esac
fi
cp '{archives}/'"$name"'.tar.gz' "$out"
"#,
                    root = temp.path().display(),
                    archives = archives.display(),
                ),
                std::fs::Permissions::from_mode(0o700),
            );
            crate::lock_file::tests::write_test_executable(
                bin.join("git"),
                format!(
                    r#"#!/bin/sh
set -eu
is_fetch=0
for arg do
  if [ "$arg" = fetch ]; then is_fetch=1; fi
done
if [ "$is_fetch" -eq 0 ]; then
  exec /usr/bin/git "$@"
fi
if [ -e .git/shallow.lock ]; then
  echo 'fatal: shallow.lock left behind by killed fetch' >&2
  exit 95
fi
count_file='{root}/git-fetch.attempts'
n=0
if [ -f "$count_file" ]; then n=$(cat "$count_file"); fi
n=$((n + 1))
printf '%s' "$n" > "$count_file"
case '{git_mode}' in
  hang_once)
    if [ "$n" -eq 1 ]; then
      : > .git/shallow.lock
      sleep 5
    fi
    ;;
  hang_always)
    : > .git/shallow.lock
    sleep 5
    ;;
  fatal_once)
    echo 'fatal: remote error (timed out after 5ms in untrusted text)' >&2
    exit 128
    ;;
esac
exec /usr/bin/git -c protocol.file.allow=always fetch --depth=1 '{remote}' '{sha}'
"#,
                    root = temp.path().display(),
                    remote = remote.display(),
                    sha = director_sha,
                ),
                std::fs::Permissions::from_mode(0o700),
            );
            Self {
                temp,
                bin,
                manifest,
            }
        }
        fn run(
            &self,
            run_name: &str,
            fetch_timeout: std::time::Duration,
            budget: std::time::Duration,
        ) -> Result<PathBuf, ScalerError> {
            let state = self.temp.path().join(run_name);
            let github_path = self.temp.path().join(format!("{run_name}.path"));
            std::fs::write(&github_path, "").unwrap();
            let path = std::ffi::OsString::from(format!("{}:/usr/bin:/bin", self.bin.display()));
            let env = BootstrapEnv {
                state: state.clone(),
                github_path,
                path_env: Some(path.as_os_str()),
                manifest: &self.manifest,
                fetch_timeout,
                deadline: std::time::Instant::now() + budget,
            };
            let token = AppToken::for_test("ghs_launcherFixture0123");
            bootstrap_with_env(self.temp.path(), &token, &env)?;
            Ok(state)
        }
        fn count(&self, file: &str) -> usize {
            std::fs::read_to_string(self.temp.path().join(file))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0)
        }
    }

    #[test]
    fn bootstrap_retries_timed_out_fetches_once_within_budget() {
        use std::time::Duration;
        // 1. Timed-out git fetch (leaving .git/shallow.lock) and timed-out curl
        // each retry once, clean partial state, and install tools + launcher.
        let ok = BootstrapFixture::new("exit28_once", "hang_once");
        let state = ok
            .run(
                "retry-ok",
                Duration::from_millis(250),
                Duration::from_secs(5),
            )
            .expect("single timeout on curl and git fetch should recover on retry");
        assert_eq!(ok.count("curl.agy.attempts"), 2);
        assert_eq!(ok.count("curl.just.attempts"), 1);
        assert_eq!(ok.count("git-fetch.attempts"), 2);
        assert!(
            !ok.temp.path().join("gh.calls").exists(),
            "recoverable first-attempt timeout must not probe check_token before retry"
        );
        assert_eq!(std::fs::read(state.join("bin/agy")).unwrap(), b"pinned-agy");
        assert!(state.join("director/agy_worker.py").is_file());
        assert!(state.join("director").join(MODELS_SEED).is_file());

        // 2. Hanging curl killed by execute() also retries once and succeeds.
        let curl_hang = BootstrapFixture::new("hang_once", "ok");
        curl_hang
            .run(
                "curl-hang",
                Duration::from_millis(250),
                Duration::from_secs(5),
            )
            .expect("killed hanging curl should retry once");
        assert_eq!(curl_hang.count("curl.agy.attempts"), 2);

        // 3. Two consecutive git fetch timeouts stop after one retry (2 attempts).
        let twice = BootstrapFixture::new("ok", "hang_always");
        let err = twice
            .run(
                "hang-twice",
                Duration::from_millis(200),
                Duration::from_secs(5),
            )
            .unwrap_err()
            .to_string();
        assert_eq!(twice.count("git-fetch.attempts"), 2);
        assert!(err.contains("git timed out after"), "{err}");

        // 4. Non-timeout failures never retry, even if stderr mentions "timed out after".
        let git_fatal = BootstrapFixture::new("ok", "fatal_once");
        let err = git_fatal
            .run(
                "git-fatal",
                Duration::from_millis(250),
                Duration::from_secs(5),
            )
            .unwrap_err()
            .to_string();
        assert_eq!(git_fatal.count("git-fetch.attempts"), 1);
        assert!(err.contains("git exited with code 128"), "{err}");

        let curl_http = BootstrapFixture::new("http_fail", "ok");
        let err = curl_http
            .run(
                "curl-http",
                Duration::from_millis(250),
                Duration::from_secs(5),
            )
            .unwrap_err()
            .to_string();
        assert_eq!(curl_http.count("curl.agy.attempts"), 1);
        assert!(err.contains("curl exited with code 22"), "{err}");

        // 5. Overall bootstrap budget bounds retries: when attempt 1 consumes the
        // entire budget, no second attempt starts.
        let exhausted = BootstrapFixture::new("ok", "hang_once");
        let started = std::time::Instant::now();
        let err = exhausted
            .run(
                "budget-exhausted",
                Duration::from_millis(300),
                Duration::from_millis(220),
            )
            .unwrap_err()
            .to_string();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(exhausted.count("git-fetch.attempts"), 1, "{err}");
    }
}

#[cfg(test)]
mod roster_tests {
    #![allow(clippy::unwrap_used)]
    /// #1240: the pinned seed parses and is a usable roster.
    #[test]
    fn pinned_model_seed_is_a_valid_roster() {
        let manifest: super::Manifest =
            serde_json::from_str(include_str!("../../../scripts/ci/inputs/agent-tools.json"))
                .unwrap();
        assert!(super::valid_roster(&manifest.agy_models_seed));
        assert!(
            manifest
                .agy_models_seed
                .iter()
                .any(|m| m.starts_with("gemini-"))
        );
        assert!(!super::valid_roster(&[]));
        assert!(!super::valid_roster(&["Gemini High".into()]));
    }
}
