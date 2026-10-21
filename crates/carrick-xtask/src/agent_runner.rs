//! Job-scoped tools and credentials for any Unix `carrick-agent` runner.
use crate::ci_scaler::{ScalerError, execute};
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
    /// Materialize only this dispatch tier's protected environment secrets.
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

fn invoke(dir: &Path, program: &str, args: &[&str]) -> Result<(), ScalerError> {
    let mut command = if program == "git" {
        crate::dispatch_worker::git_invocation(dir, args)
    } else {
        let mut command = std::process::Command::new(program);
        command.args(args).current_dir(dir);
        command
    };
    let result = execute(&mut command, &[], std::time::Duration::from_secs(120));
    if let Err(error) = result {
        if program == "git" && args.first() == Some(&"fetch") {
            return Err(check_token(dir).err().unwrap_or(error));
        }
        return Err(error);
    }
    Ok(())
}

fn check_token(root: &Path) -> Result<(), ScalerError> {
    let repository = "carrick-sh/agy-director";
    let message = "host/infra: AGENT_DIRECTOR_TOKEN rejected or expired, or GitHub access unavailable; bootstrap requires read access to the private launcher repository";
    if !std::env::var("GH_TOKEN").is_ok_and(|token| !token.is_empty()) {
        return Err(ScalerError::Guard(message));
    }
    execute(
        std::process::Command::new("gh")
            .args(["api", &format!("repos/{repository}")])
            .current_dir(root),
        &[],
        std::time::Duration::from_secs(30).min(job_remaining(39)?),
    )
    .map_err(|_| ScalerError::Guard(message))?;
    Ok(())
}

/// Leave time for workflow reporting before the job's 40-minute cap.
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
                if entry.file_name() == "config" || entry.file_name() == "config.toml" {
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

fn secret_file(path: &Path, bytes: &[u8]) -> Result<(), ScalerError> {
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

fn bootstrap(root: &Path) -> Result<(), ScalerError> {
    check_token(root)?;
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
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let tools = manifest
        .platforms
        .get(&platform)
        .ok_or(ScalerError::Guard("unsupported agent runner platform"))?;
    for tool in tools {
        if !matches!(tool.name.as_str(), "codex" | "agy" | "just")
            || !tool.url.starts_with("https://")
        {
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
        )?;
        extract(tool, &archive, &bin)?;
        std::fs::remove_file(archive)?;
    }
    // Cargo's repository toolchain selection installs rust-toolchain.toml before
    // this driver is built. The workflow caches tools, never the isolated home.
    invoke(root, "rustup", &["show", "active-toolchain"])?;
    let director = state.join("director");
    private_dir(&director)?;
    invoke(&director, "git", &["init"])?;
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
    )?;
    invoke(&director, "git", &["checkout", "--detach", "FETCH_HEAD"])?;
    let mut paths = std::fs::OpenOptions::new()
        .append(true)
        .open(std::env::var_os("GITHUB_PATH").ok_or(ScalerError::Guard("missing GITHUB_PATH"))?)?;
    writeln!(paths, "{}", bin.display())?;
    Ok(())
}

fn auth(event: &Path) -> Result<(), ScalerError> {
    let event: serde_json::Value = serde_json::from_slice(&std::fs::read(event)?)?;
    let dispatch = crate::dispatch_worker::validate_event(
        &event,
        include_str!("../../../.github/dispatch-tiers.toml"),
        &std::env::var("GITHUB_TRIGGERING_ACTOR").unwrap_or_default(),
    )?;
    let home = state()?.join("home");
    if !home.is_dir() {
        return Err(ScalerError::Guard("bootstrap must precede auth"));
    }
    if dispatch.tier.backend == "codex" {
        let auth = std::env::var("CODEX_AUTH_JSON")
            .map_err(|_| ScalerError::Guard("missing CODEX_AUTH_JSON"))?;
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
    } else {
        let raw = std::env::var("AGY_OAUTH_TOKEN")
            .ok()
            .filter(|token| !token.is_empty())
            .ok_or(ScalerError::Guard("missing AGY_OAUTH_TOKEN"))?;
        let gemini = home.join(".gemini");
        private_dir(&gemini)?;
        let agy = gemini.join("antigravity-cli");
        private_dir(&agy)?;
        secret_file(&agy.join("antigravity-oauth-token"), raw.as_bytes())?;
    }
    crate::dispatch_redaction::remember()?;
    Ok(())
}

pub fn run(root: &Path, args: Args) -> Result<(), ScalerError> {
    match args.action {
        Action::Bootstrap => bootstrap(root),
        Action::Auth { event } => auth(&event),
        Action::Cleanup => {
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
            std::fs::write(
                &wrapper,
                format!("#!/bin/sh\ntouch '{}'\nexit 91\n", marker.display()),
            )
            .unwrap();
            std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
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
        std::fs::write(cargo.join("bin/rustup"), proxy).unwrap();
        std::fs::set_permissions(
            cargo.join("bin/rustup"),
            std::fs::Permissions::from_mode(0o500),
        )
        .unwrap();
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
            name: "codex".into(),
            url: "https://fixture".into(),
            sha256: Some("bad".into()),
            sha512: None,
            member: "tool".into(),
        };
        assert!(extract(&tool, &archive, temp.path()).is_err());
        assert!(!temp.path().join("codex").exists());
        tool.sha256 = Some(crate::provision::compute_sha256(&archive).unwrap());
        extract(&tool, &archive, temp.path()).unwrap();
        assert_eq!(std::fs::read(temp.path().join("codex")).unwrap(), b"tool");
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
