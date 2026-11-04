//! Job-scoped tools and credentials for any Unix `carrick-agent` runner.
use crate::ci_scaler::mint::{AppToken, MintScope};
use crate::ci_scaler::{ScalerError, execute};
use crate::dispatch_mint::MintFailure;
use serde::Deserialize;
use sha2::{Digest, Sha512};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
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

/// Run a bootstrap command. No inherited GitHub token reaches it; only the
/// launcher fetch gets the controller-minted `launcher` token (#1034).
fn invoke(
    dir: &Path,
    program: &str,
    args: &[&str],
    launcher: Option<&AppToken>,
) -> Result<(), ScalerError> {
    let mut command = if program == "git" {
        crate::dispatch_worker::git_invocation(dir, args)
    } else {
        let mut command = std::process::Command::new(program);
        command.args(args).current_dir(dir);
        command
    };
    command.env_remove("GH_TOKEN").env_remove("GITHUB_TOKEN");
    if let Some(token) = launcher {
        command.env("GH_TOKEN", token.secret());
    }
    let result = execute(&mut command, &[], std::time::Duration::from_secs(120));
    if let Err(error) = result {
        if let Some(token) = launcher {
            return Err(check_token(dir, token).err().unwrap_or(error));
        }
        return Err(error);
    }
    Ok(())
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

fn check_token(root: &Path, token: &AppToken) -> Result<(), ScalerError> {
    let repository = "carrick-sh/agy-director";
    let message = "host/infra: controller-minted bootstrap token rejected or expired, or GitHub access unavailable; bootstrap requires read access to the private launcher repository";
    let mut command = std::process::Command::new("gh");
    command
        .args(["api", &format!("repos/{repository}")])
        .current_dir(root)
        .env_remove("GITHUB_TOKEN")
        .env("GH_TOKEN", token.secret());
    execute(
        &mut command,
        &[],
        std::time::Duration::from_secs(30).min(job_remaining(39)?),
    )
    .map_err(|_| ScalerError::Guard(message))?;
    Ok(())
}

/// The dispatch loop step's `timeout-minutes` in
/// `.github/workflows/dispatch-worker.yml`. Owner decision 2026-11-03
/// (#231): strong-tier rounds run for about three hours. The workflow
/// repeats these numbers as literals; `tests/dispatch_workflow.rs` holds
/// the two in agreement.
pub const DISPATCH_LOOP_STEP_MINUTES: u64 = 180;
/// Checkout, driver build, bootstrap, credentials, retirement and upload
/// around the loop step.
pub const DISPATCH_JOB_OVERHEAD_MINUTES: u64 = 13;
/// The dispatch worker job's `timeout-minutes`.
pub const DISPATCH_JOB_MINUTES: u64 = DISPATCH_LOOP_STEP_MINUTES + DISPATCH_JOB_OVERHEAD_MINUTES;
/// The loop's final reserve, at the end of both the loop step and the job:
/// final capture, the outcome post and the artifact upload.
pub const DISPATCH_FINAL_RESERVE_MINUTES: u64 = 5;
/// The job minute by which the coordinator loop stops.
pub const DISPATCH_LOOP_JOB_MINUTES: u64 = DISPATCH_JOB_MINUTES - DISPATCH_FINAL_RESERVE_MINUTES;
/// The job minute by which a worker turn is cut off, leaving its harvest
/// and the loop's reporting inside the job.
pub const DISPATCH_WORKER_JOB_MINUTES: u64 = DISPATCH_JOB_MINUTES - 2;
const _: () = assert!(DISPATCH_FINAL_RESERVE_MINUTES < DISPATCH_LOOP_STEP_MINUTES);
const _: () = assert!(DISPATCH_LOOP_JOB_MINUTES < DISPATCH_WORKER_JOB_MINUTES);

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
    isolate_rust_homes_owned(command, state, 0)
}

fn isolate_rust_homes_owned(
    command: &mut std::process::Command,
    state: &Path,
    owner: u32,
) -> Result<(), ScalerError> {
    let private = state.canonicalize()?.join("rust");
    private_dir(&private)?;
    command.env(
        "CARGO_TARGET_DIR",
        state.canonicalize()?.join("work/target"),
    );
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
            verify_rustup_tree(&source, owner, &mut BTreeSet::new())?;
            command
                .env("RUSTUP_HOME", &source)
                .env("RUSTUP_AUTO_INSTALL", "0");
            continue;
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

// Provisioned toolchains contain regular files and directories. Refuse links
// rather than letting a writable link target redirect a compiler after validation.
// Verify metadata only; never read or copy toolchain file contents.
fn verify_rustup_tree(
    path: &Path,
    owner: u32,
    seen: &mut BTreeSet<PathBuf>,
) -> Result<(), ScalerError> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(ScalerError::Guard(
            "links are not admitted in the shared Rust toolchain",
        ));
    }
    let path = path.canonicalize()?;
    if seen.contains(&path) {
        return Ok(());
    }
    // Production also authenticates every ancestor. Fixture owners can validate
    // a tree beneath a temporary directory without owning the system root.
    for ancestor in path
        .ancestors()
        .take_while(|ancestor| owner == 0 || ancestor.starts_with(&path))
    {
        let metadata = ancestor.metadata()?;
        if metadata.uid() != owner || metadata.permissions().mode() & 0o022 != 0 {
            return Err(ScalerError::Guard(
                "Rust toolchain must be root-owned and not group/other writable",
            ));
        }
    }
    let metadata = path.metadata()?;
    if metadata.is_dir() {
        seen.insert(path.clone());
        for entry in std::fs::read_dir(path)? {
            verify_rustup_tree(&entry?.path(), owner, seen)?;
        }
    } else if !metadata.is_file() {
        return Err(ScalerError::Guard("unsupported Rust toolchain entry"));
    }
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
    let state = state()?;
    private_dir(&state)?;
    crate::dispatch_redaction::remember()?;
    let bin = state.join("bin");
    private_dir(&bin)?;
    private_dir(&state.join("home"))?;
    let manifest: Manifest =
        serde_json::from_str(include_str!("../../../scripts/ci/inputs/agent-tools.json"))?;
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
        let archive = state.join(format!("{}.tar.gz", tool.name));
        invoke(
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
                "110",
                "--output",
                archive
                    .to_str()
                    .ok_or(ScalerError::Guard("non-UTF8 runner path"))?,
                &tool.url,
            ],
            None,
        )?;
        extract(tool, &archive, &bin)?;
        std::fs::remove_file(archive)?;
    }
    // Cargo's repository toolchain selection installs rust-toolchain.toml before
    // this driver is built. The workflow caches tools, never the isolated home.
    invoke(root, "rustup", &["show", "active-toolchain"], None)?;
    let director = state.join("director");
    private_dir(&director)?;
    invoke(&director, "git", &["init"], None)?;
    invoke(
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
        Some(&launcher),
    )?;
    invoke(
        &director,
        "git",
        &["checkout", "--detach", "FETCH_HEAD"],
        None,
    )?;
    // Copied with the launcher into every model account (`AGY_MODELS_SEED`).
    std::fs::write(
        director.join(MODELS_SEED),
        serde_json::to_vec(&serde_json::json!({ "models": manifest.agy_models_seed }))?,
    )?;
    let mut paths = std::fs::OpenOptions::new()
        .append(true)
        .open(std::env::var_os("GITHUB_PATH").ok_or(ScalerError::Guard("missing GITHUB_PATH"))?)?;
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
    // The owner's Copilot PAT (#1474) goes only into the runner's agent
    // home, which capacity probes and a selected Copilot worker copy from;
    // never into the loop home. A refused token is left out, so Copilot
    // reads as not installed and the other backends are unaffected.
    if let Ok(token) = std::env::var("COPILOT_TOKEN")
        && !token.is_empty()
    {
        match copilot_token_refusal(token.trim(), copilot_scope_probe) {
            None => {
                let directory = home.join(".copilot-dispatch");
                private_dir(&directory)?;
                secret_file(
                    &home.join(crate::dispatch_worker::COPILOT_TOKEN_FILE),
                    token.trim().as_bytes(),
                )?;
            }
            Some(reason) => eprintln!("agent-runner: COPILOT_TOKEN refused: {reason}"),
        }
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

/// Why a Copilot token must not be used, or `None` to accept it (#1474).
/// The owner's decision: Copilot bills the owner, through a fine-grained
/// PAT whose only permission is "Copilot Requests". Classic (`ghp_`),
/// OAuth (`gho_`), user-to-server (`ghu_`), App (`ghs_`) and refresh
/// (`ghr_`) tokens are refused by shape; a fine-grained PAT is accepted only
/// when GitHub answers it and reports no OAuth scopes (`X-OAuth-Scopes` is
/// a classic-scope header). `probe` returns the response header block.
/// Reasons are fixed text and never contain the token.
pub(crate) fn copilot_token_refusal(
    token: &str,
    probe: impl FnOnce(&str) -> Result<String, ScalerError>,
) -> Option<&'static str> {
    if ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]
        .iter()
        .any(|prefix| token.starts_with(prefix))
    {
        return Some(
            "a classic, OAuth, App or refresh token; only a fine-grained PAT (github_pat_) is accepted",
        );
    }
    if !token.starts_with("github_pat_")
        || token.len() > 512
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Some("not a fine-grained personal access token (github_pat_)");
    }
    let Ok(headers) = probe(token) else {
        return Some("the scope check could not reach GitHub");
    };
    let mut lines = headers.lines().map(str::trim);
    let ok = lines.next().is_some_and(|status| {
        status.starts_with("HTTP/") && status.split_whitespace().nth(1) == Some("200")
    });
    if !ok {
        return Some("GitHub did not accept the token");
    }
    if lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("x-oauth-scopes") && !value.trim().is_empty()
        })
    }) {
        return Some("the token reports OAuth scopes");
    }
    None
}
/// One authenticated `GET /rate_limit` (any valid token may call it), with
/// the token in a curl config on stdin rather than on the command line.
fn copilot_scope_probe(token: &str) -> Result<String, ScalerError> {
    let mut command = std::process::Command::new("curl");
    command
        // `-q` first: ignore any ~/.curlrc. HTTPS only, redirects included.
        .args([
            "-q",
            "-sS",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-time",
            "20",
            "-o",
            "/dev/null",
            "-D",
            "-",
            "--config",
            "-",
        ])
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN");
    let config = format!(
        "url = \"https://api.github.com/rate_limit\"\nheader = \"Accept: application/vnd.github+json\"\nheader = {}\n",
        serde_json::to_string(&format!("Authorization: Bearer {token}"))?
    );
    let out = execute(
        &mut command,
        config.as_bytes(),
        std::time::Duration::from_secs(30),
    )?;
    // Keep the last response block: curl prints one per redirect.
    let text = String::from_utf8_lossy(&out).replace("\r\n", "\n");
    Ok(text
        .trim_end()
        .rsplit("\n\n")
        .next()
        .unwrap_or_default()
        .to_owned())
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
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn lock_fixture_tree(path: &Path) {
        let metadata = path.metadata().unwrap();
        std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(metadata.permissions().mode() & !0o022),
        )
        .unwrap();
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).unwrap() {
                lock_fixture_tree(&entry.unwrap().path());
            }
        }
    }
    /// #1474: only a fine-grained PAT with no OAuth scopes is used for
    /// Copilot. Fixtures are fake; no reason ever echoes the token.
    #[test]
    fn copilot_token_accepts_only_unscoped_fine_grained_pats() {
        let fine = "github_pat_11FIXTURE0123456789_abcdefFIXTURE";
        let ok = |_: &str| Ok("HTTP/2 200\nx-ratelimit-limit: 5000\n".to_owned());
        assert_eq!(copilot_token_refusal(fine, ok), None);
        let empty = |_: &str| Ok("HTTP/2 200\nX-OAuth-Scopes: \n".to_owned());
        assert_eq!(copilot_token_refusal(fine, empty), None);
        let unreachable = |_: &str| -> Result<String, ScalerError> {
            panic!("an over-broad token reached the network")
        };
        for broad in [
            "ghp_classicFixture0123",
            "gho_oauthFixture0123",
            "ghu_userFixture0123",
            "ghs_appFixture0123",
            "ghr_refreshFixture0123",
            "plain-text",
            "github_pat_has space",
        ] {
            let reason = copilot_token_refusal(broad, unreachable).unwrap();
            assert!(!reason.contains(broad), "{reason}");
        }
        let scoped = |_: &str| Ok("HTTP/2 200\nx-oauth-scopes: repo, workflow\n".to_owned());
        assert_eq!(
            copilot_token_refusal(fine, scoped),
            Some("the token reports OAuth scopes")
        );
        let rejected = |_: &str| Ok("HTTP/2 401\n".to_owned());
        assert_eq!(
            copilot_token_refusal(fine, rejected),
            Some("GitHub did not accept the token")
        );
        let down = |_: &str| Err(ScalerError::Guard("offline"));
        assert_eq!(
            copilot_token_refusal(fine, down),
            Some("the scope check could not reach GitHub")
        );
    }
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
            std::fs::write(
                project.join("Cargo.lock"),
                "version = 4\n[[package]]\nname = \"isolation-witness\"\nversion = \"0.0.0\"\n",
            )
            .unwrap();
            let cargo = PathBuf::from(env!("CARGO"));
            let mut command = std::process::Command::new(&cargo);
            super::super::dispatch_worker::private_environment(&mut command);
            command
                .args(["check", "--locked", "--offline"])
                .current_dir(&project)
                .env("CARGO_BUILD_JOBS", "3")
                .env("RUSTC", cargo.parent().unwrap().join("rustc"))
                .env("CARGO_HOME", &cargo_home)
                .env("RUSTUP_HOME", &rustup);
            lock_fixture_tree(&rustup);
            isolate_rust_homes_owned(&mut command, &state, unsafe { libc::geteuid() }).unwrap();
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
        let toolchain = rustup.join("toolchains/stable");
        let state = temp.path().join("state");
        std::fs::create_dir_all(cargo.join("bin")).unwrap();
        std::fs::create_dir_all(cargo.join("registry/cache")).unwrap();
        std::fs::create_dir_all(rustup.join("toolchains")).unwrap();
        std::fs::create_dir_all(toolchain.join("bin")).unwrap();
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
test ! -e "${CARGO_HOME}/../rustup"
printf poisoned > "$CARGO_HOME/bin/cargo"
printf '%s\n%s\n' "$CARGO_HOME" "$RUSTUP_HOME"
"#,
            ])
            .env("CARGO_HOME", &cargo)
            .env("RUSTUP_HOME", &rustup)
            .env("PATH", cargo.join("bin"));
        lock_fixture_tree(&rustup);
        isolate_rust_homes_owned(&mut child, &state, unsafe { libc::geteuid() }).unwrap();
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
                // The runner hands the child its canonical RUSTUP_HOME; on
                // macOS the fixture's `/var` tempdir resolves to `/private/var`.
                std::fs::canonicalize(&rustup).unwrap().display()
            )
        );
        assert_eq!(
            state.join("rust").metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(!state.join("rust/cargo/bin/cargo").is_symlink());
        assert!(!state.join("rust/rustup").exists());
    }
    #[test]
    fn worker_refuses_a_writable_toolchain_instead_of_copying_it() {
        let temp = tempfile::tempdir().unwrap();
        let cargo = temp.path().join("cargo");
        let rustup = temp.path().join("rustup");
        let state = temp.path().join("state");
        for path in [&cargo, &rustup, &state] {
            std::fs::create_dir(path).unwrap();
        }
        std::fs::set_permissions(&rustup, std::fs::Permissions::from_mode(0o777)).unwrap();
        let mut command = std::process::Command::new("/bin/true");
        command
            .env("CARGO_HOME", &cargo)
            .env("RUSTUP_HOME", &rustup);
        assert!(isolate_rust_homes(&mut command, &state).is_err());
        assert!(!state.join("rust/rustup").exists());
    }
    #[test]
    fn shared_toolchain_rejects_writable_entries_and_link_targets() {
        let temp = tempfile::tempdir().unwrap();
        let tree = temp.path().join("rustup");
        std::fs::create_dir(&tree).unwrap();
        let compiler = tree.join("rustc");
        std::fs::write(&compiler, "compiler").unwrap();
        let owner = unsafe { libc::geteuid() };
        lock_fixture_tree(&tree);
        verify_rustup_tree(&tree, owner, &mut BTreeSet::new()).unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(verify_rustup_tree(&tree, owner, &mut BTreeSet::new()).is_err());
        std::fs::remove_file(&compiler).unwrap();
        let external = temp.path().join("external");
        std::fs::write(&external, "writable compiler").unwrap();
        std::fs::set_permissions(&external, std::fs::Permissions::from_mode(0o666)).unwrap();
        std::os::unix::fs::symlink(&external, &compiler).unwrap();
        assert!(verify_rustup_tree(&tree, owner, &mut BTreeSet::new()).is_err());
        if owner != 0 {
            assert!(verify_rustup_tree(&tree, 0, &mut BTreeSet::new()).is_err());
        }
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
