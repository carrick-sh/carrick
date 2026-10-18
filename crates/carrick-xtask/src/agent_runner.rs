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
    execute(
        std::process::Command::new(program)
            .args(args)
            .current_dir(dir),
        &[],
        std::time::Duration::from_secs(120),
    )?;
    Ok(())
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
    let state = state()?;
    private_dir(&state)?;
    let bin = state.join("bin");
    private_dir(&bin)?;
    private_dir(&state.join("home"))?;
    secret_file(
        &state.join("home/.gitconfig"),
        b"[credential \"https://github.com\"]\n\thelper =\n\thelper = !gh auth git-credential\n",
    )?;
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
    invoke(root, "gh", &["auth", "setup-git"])?;
    let director = state.join("director");
    private_dir(&director)?;
    invoke(&director, "git", &["init"])?;
    invoke(
        &director,
        "git",
        &[
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
        let raw = std::env::var("AGY_AUTH_FILES_JSON")
            .map_err(|_| ScalerError::Guard("missing AGY_AUTH_FILES_JSON"))?;
        // Opaque file contents; parse errors must never include the secret input.
        let files: BTreeMap<String, String> = serde_json::from_str(&raw)
            .map_err(|_| ScalerError::Guard("invalid AGY_AUTH_FILES_JSON"))?;
        if ![
            "antigravity-oauth-token",
            "jetski_state.pbtxt",
            "installation_id",
        ]
        .iter()
        .all(|key| files.get(*key).is_some_and(|v| !v.is_empty()))
            || files.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "antigravity-oauth-token"
                        | "jetski_state.pbtxt"
                        | "installation_id"
                        | "settings.json"
                )
            })
        {
            return Err(ScalerError::Guard("invalid agy auth file set"));
        }
        let gemini = home.join(".gemini");
        private_dir(&gemini)?;
        let agy = gemini.join("antigravity-cli");
        private_dir(&agy)?;
        for (name, data) in files {
            secret_file(&agy.join(name), data.as_bytes())?;
        }
    }
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
