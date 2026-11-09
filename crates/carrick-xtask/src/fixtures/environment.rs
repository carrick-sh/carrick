//! Fixture builds have a declared environment; user Cargo configuration is not input.
use super::{CommitSha, Result, fail, git, safe_path};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Serialized into the bundle and its input digest. Changing the policy requires
/// rebuilding the bundle, just like changing a source input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildPolicy {
    pub version: u32,
    pub inherited_environment: Vec<String>,
    pub fixed_environment: BTreeMap<String, String>,
    pub cargo_configuration: String,
    pub compiler_and_linkers: String,
}

impl Default for BuildPolicy {
    fn default() -> Self {
        Self {
            version: 2,
            inherited_environment: vec!["PATH".into()],
            fixed_environment: BTreeMap::from([
                ("LC_ALL".into(), "C".into()),
                ("TZ".into(), "UTC".into()),
                ("CARGO_NET_OFFLINE".into(), "true".into()),
            ]),
            cargo_configuration: "per-sha-locked-stable-build-dir; isolated-home-cache-and-publisher-remap-path-prefix; metadata-explicit-tracked-checkout-config; snapshot-build-cwd; no-external-ancestor-config; no-embedded-build-dir".into(),
            compiler_and_linkers: "pinned-rustup-toolchain-first; musl=rust-lld; gnu=host-cc-or-aarch64-linux-gnu-gcc".into(),
        }
    }
}

pub(super) fn reject_ambient_overrides() -> Result<()> {
    for (name, _) in std::env::vars_os() {
        let name = name.to_string_lossy();
        if name.starts_with("CARGO_PROFILE_")
            || name.starts_with("CARGO_BUILD_")
            || (name.starts_with("CARGO_TARGET_")
                && (name.ends_with("_RUSTFLAGS") || name.ends_with("_LINKER")))
            || matches!(
                name.as_ref(),
                "RUSTFLAGS"
                    | "CARGO_ENCODED_RUSTFLAGS"
                    | "RUSTC_WRAPPER"
                    | "RUSTC_WORKSPACE_WRAPPER"
            )
        {
            return Err(fail(format!(
                "fixture build policy forbids ambient {name}; use tracked Cargo configuration"
            )));
        }
    }
    Ok(())
}

fn reject_ancestor_config(root: &Path) -> Result<()> {
    for ancestor in root.ancestors().skip(1) {
        for name in [".cargo/config", ".cargo/config.toml"] {
            let path = ancestor.join(name);
            if path.symlink_metadata().is_ok() {
                return Err(fail(format!(
                    "fixture build policy forbids ancestor Cargo configuration: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

/// Validate config before invoking Cargo, including ignored/untracked config.
/// Tracked fixture/package config is already part of the source inventory.
pub(super) fn checkout_configs(root: &Path, directory: &Path) -> Result<Vec<PathBuf>> {
    let mut configs = Vec::new();
    let mut ancestors: Vec<_> = directory
        .ancestors()
        .take_while(|p| p.starts_with(root))
        .collect();
    ancestors.reverse();
    for ancestor in ancestors {
        let mut selected = None;
        for name in [".cargo/config", ".cargo/config.toml"] {
            let path = ancestor.join(name);
            if path.symlink_metadata().is_ok() {
                let relative = path.strip_prefix(root).map_err(|e| fail(e.to_string()))?;
                let relative = relative
                    .to_str()
                    .ok_or_else(|| fail("non-UTF8 Cargo config path"))?;
                safe_path(root, relative)?;
                git(root, &["ls-files", "--error-unmatch", "--", relative]).map_err(|_| {
                    fail(format!(
                        "fixture build policy requires tracked Cargo configuration: {relative}"
                    ))
                })?;
                // Cargo prefers the extensionless file if both spellings exist.
                if selected.is_none() {
                    selected = Some(path);
                }
            }
        }
        if let Some(path) = selected {
            configs.push(path);
        }
    }
    Ok(configs)
}

/// Parent of the per-SHA fixture build directories on this host.
pub(super) fn default_isolation_root() -> PathBuf {
    std::env::temp_dir().join("carrick-fixture-builds")
}

/// One fixture build's private directory, `<isolation root>/<sha>`, held
/// under an exclusive per-SHA `flock` on `<isolation root>/<sha>.lock`.
///
/// The path is derived from the source commit, never randomized: Cargo
/// hashes the absolute location of a path dependency outside the fixture
/// workspace into `-C metadata`, so a random checkout directory changes
/// crate symbols and code (#1891). The lock admits one build per SHA at a
/// time; builds of different SHAs use different locks and directories.
/// A directory left by a crashed build is removed under the lock before
/// reuse, and the directory is removed again before the lock is released.
pub(super) struct IsolatedBuild {
    directory: PathBuf,
    _lock: crate::lock_file::OwnedFileLock,
}

impl IsolatedBuild {
    pub(super) fn acquire(isolation_root: &Path, sha: &CommitSha) -> Result<Self> {
        fs::create_dir_all(isolation_root)?;
        let isolation_root = isolation_root.canonicalize()?;
        // The lock file sits beside the directory, so removing a stale
        // directory never unlinks a live lock.
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(isolation_root.join(format!("{}.lock", sha.0)))?;
        file.lock()?;
        let lock = crate::lock_file::OwnedFileLock::from_locked(file);
        let directory = isolation_root.join(&sha.0);
        remove_stale(&directory)?;
        fs::create_dir(&directory)?;
        Ok(Self {
            directory,
            _lock: lock,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.directory
    }
}

/// `remove_dir_all` removes symlinks without following them, so the shared
/// registry/git caches linked from the isolated Cargo home are untouched.
fn remove_stale(directory: &Path) -> Result<()> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(directory)?,
        Ok(_) => fs::remove_file(directory)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

impl Drop for IsolatedBuild {
    fn drop(&mut self) {
        // Runs before the lock field drops: cleanup happens under the lock.
        let _ = remove_stale(&self.directory);
    }
}

#[derive(Serialize)]
struct RustFlags {
    rustflags: Vec<String>,
}

#[derive(Serialize)]
struct RemapConfig {
    build: RustFlags,
    target: BTreeMap<&'static str, RustFlags>,
}

/// Publisher-owned Cargo-home config mapping the isolated checkout and Cargo
/// home to fixed tokens, so no embedded source path (libc panic locations)
/// depends on the isolation root. Cargo joins equal array keys across config
/// files, and uses `target.<triple>.rustflags` instead of `build.rustflags`
/// whenever any config names the triple. The tracked root config names the
/// musl triple and not the GNU one, so each list here joins the tracked list
/// of the same key. The publisher's embedded-path check fails the build if a
/// remap is ever lost.
pub(super) fn remap_config(checkout: &Path, cargo_home: &Path) -> Result<String> {
    let mut flags = Vec::new();
    for (from, to) in [(checkout, "/src"), (cargo_home, "/cargo")] {
        let from = from
            .to_str()
            .ok_or_else(|| fail("non-UTF8 fixture isolation path"))?;
        flags.push(format!("--remap-path-prefix={from}={to}"));
    }
    toml::to_string(&RemapConfig {
        build: RustFlags {
            rustflags: flags.clone(),
        },
        target: BTreeMap::from([("aarch64-unknown-linux-musl", RustFlags { rustflags: flags })]),
    })
    .map_err(|e| fail(e.to_string()))
}

/// Refuse an executable that names the build's isolation directory: such a
/// path changes with the isolation root, so the bytes would not reproduce.
pub(super) fn reject_embedded_path(name: &str, bytes: &[u8], path: &Path) -> Result<()> {
    let needle = path.as_os_str().as_encoded_bytes();
    if !needle.is_empty() && bytes.windows(needle.len()).any(|window| window == needle) {
        return Err(fail(format!(
            "fixture executable embeds its isolated build path {}: {name}",
            path.display()
        )));
    }
    Ok(())
}

enum Directory {
    /// Metadata resolution: a private scratch directory, nothing embedded.
    Scratch(tempfile::TempDir),
    /// Executable builds: the stable per-SHA directory.
    Isolated(IsolatedBuild),
}

impl Directory {
    fn path(&self) -> &Path {
        match self {
            Self::Scratch(directory) => directory.path(),
            Self::Isolated(build) => build.path(),
        }
    }
}

pub(super) struct BuildEnvironment {
    directory: Directory,
    variables: BTreeMap<OsString, OsString>,
}

impl BuildEnvironment {
    /// Environment for Cargo metadata resolution in a private scratch directory.
    pub(super) fn new(root: &Path) -> Result<Self> {
        Self::with_directory(root, Directory::Scratch(tempfile::tempdir()?))
    }

    /// Environment for executable builds in the stable per-SHA directory
    /// under `isolation_root`, holding its lock for the environment's life.
    /// The source snapshot goes in [`Self::checkout`].
    pub(super) fn isolated(root: &Path, isolation_root: &Path, sha: &CommitSha) -> Result<Self> {
        reject_ambient_overrides()?;
        let build = IsolatedBuild::acquire(isolation_root, sha)?;
        let environment = Self::with_directory(root, Directory::Isolated(build))?;
        let cargo_home = environment.cargo_home()?;
        fs::write(
            cargo_home.join("config.toml"),
            remap_config(&environment.checkout(), &cargo_home)?,
        )?;
        Ok(environment)
    }

    /// Where the source snapshot of an isolated build is extracted.
    pub(super) fn checkout(&self) -> PathBuf {
        self.directory.path().join("checkout")
    }

    fn cargo_home(&self) -> Result<PathBuf> {
        self.variables
            .get(&OsString::from("CARGO_HOME"))
            .map(PathBuf::from)
            .ok_or_else(|| fail("missing isolated CARGO_HOME"))
    }

    fn with_directory(root: &Path, directory: Directory) -> Result<Self> {
        reject_ambient_overrides()?;
        let root = root.canonicalize()?;
        let host_home = PathBuf::from(
            std::env::var_os("HOME")
                .ok_or_else(|| fail("missing HOME for Rust cache discovery"))?,
        );
        let cargo_home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| host_home.join(".cargo"));
        let rustup_home = std::env::var_os("RUSTUP_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| host_home.join(".rustup"))
            .canonicalize()?;
        reject_ancestor_config(directory.path())?;
        let isolated_home = directory.path().join("home");
        let isolated_cargo = directory.path().join("cargo");
        fs::create_dir(&isolated_home)?;
        fs::create_dir(&isolated_cargo)?;
        // Share only downloaded inputs, never the user's config, credentials,
        // compiler wrappers, binaries, or other Cargo-home state.
        let mut shared_cache = false;
        for cache in ["registry", "git"] {
            let source = cargo_home.join(cache);
            if source.exists() {
                shared_cache = true;
                std::os::unix::fs::symlink(source.canonicalize()?, isolated_cargo.join(cache))?;
            }
        }
        if shared_cache {
            // Isolated config must not create a second lock domain for shared
            // registry unpacking/index state. Never replace these live locks.
            for lock in [".package-cache", ".package-cache-mutate"] {
                let path = cargo_home.join(lock);
                fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)?;
                std::os::unix::fs::symlink(path.canonicalize()?, isolated_cargo.join(lock))?;
            }
        }
        let pin = fs::read_to_string(root.join("rust-toolchain.toml"))?;
        let channel = pin
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("channel = \"")
                    .and_then(|s| s.strip_suffix('"'))
            })
            .ok_or_else(|| fail("fixture build policy requires an explicit compiler pin"))?;
        let policy = BuildPolicy::default();
        let mut variables: BTreeMap<OsString, OsString> = policy
            .fixed_environment
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        for name in policy.inherited_environment {
            let value = std::env::var_os(&name)
                .ok_or_else(|| fail(format!("missing {name} for fixture tools")))?;
            variables.insert(name.into(), value);
        }
        variables.insert("HOME".into(), isolated_home.into_os_string());
        variables.insert("CARGO_HOME".into(), isolated_cargo.into_os_string());
        variables.insert("RUSTUP_HOME".into(), rustup_home.into_os_string());
        variables.insert("RUSTUP_TOOLCHAIN".into(), channel.into());
        let mut environment = Self {
            directory,
            variables,
        };
        let mut which = Command::new("rustup");
        environment.configure(&mut which);
        which
            .current_dir(&root)
            .args(["which", "--toolchain", channel, "cargo"]);
        let cargo = PathBuf::from(environment.output(&mut which)?.trim());
        let bin = cargo
            .parent()
            .ok_or_else(|| fail("missing pinned Cargo directory"))?;
        let mut paths = vec![bin.to_path_buf()];
        paths.extend(std::env::split_paths(
            environment
                .variables
                .get(&OsString::from("PATH"))
                .ok_or_else(|| fail("missing controlled PATH"))?,
        ));
        environment.variables.insert(
            "PATH".into(),
            std::env::join_paths(paths).map_err(|e| fail(e.to_string()))?,
        );
        Ok(environment)
    }

    /// Registry/git caches in the isolated Cargo home. Sources under them
    /// are pinned by each fixture's `Cargo.lock` checksums.
    pub(super) fn cargo_cache_roots(&self) -> Vec<PathBuf> {
        let Some(home) = self.variables.get(&OsString::from("CARGO_HOME")) else {
            return Vec::new();
        };
        ["registry", "git"]
            .iter()
            .map(|cache| Path::new(home).join(cache))
            .filter(|path| path.exists())
            .collect()
    }

    pub(super) fn scratch_root(&self) -> &Path {
        self.directory.path()
    }

    pub(super) fn configure<'a>(&self, command: &'a mut Command) -> &'a mut Command {
        command.env_clear().envs(&self.variables)
    }

    pub(super) fn output(&self, command: &mut Command) -> Result<String> {
        let output = command.output()?;
        if !output.status.success() {
            return Err(fail(format!(
                "controlled fixture command failed ({}) : {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        String::from_utf8(output.stdout).map_err(|e| fail(e.to_string()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::test_cargo_env;

    #[test]
    fn build_environment_contains_only_declared_variables() {
        if !test_cargo_env::in_clean_cargo_test() {
            return;
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let environment = BuildEnvironment::new(&root).unwrap();
        let mut command = Command::new("/usr/bin/env");
        environment.configure(&mut command);
        let output = environment.output(&mut command).unwrap();
        let actual: std::collections::BTreeSet<_> = output
            .lines()
            .map(|line| line.split_once('=').unwrap().0)
            .collect();
        assert_eq!(
            actual,
            std::collections::BTreeSet::from([
                "PATH",
                "HOME",
                "CARGO_HOME",
                "RUSTUP_HOME",
                "RUSTUP_TOOLCHAIN",
                "LC_ALL",
                "TZ",
                "CARGO_NET_OFFLINE"
            ])
        );
        let cargo_home = Path::new(
            environment
                .variables
                .get(&OsString::from("CARGO_HOME"))
                .unwrap(),
        );
        assert!(!cargo_home.join("config").exists());
        assert!(!cargo_home.join("config.toml").exists());
    }

    fn sha(digit: char) -> CommitSha {
        CommitSha::try_from(digit.to_string().repeat(40)).unwrap()
    }

    fn checkout_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// Red first on the random-temp publisher (#1891): two consecutive
    /// builds got `.tmpO0UOwQ/cargo` and `.tmpKg3rs5/cargo`.
    #[test]
    fn isolated_build_paths_derive_from_the_sha() {
        let isolation = tempfile::tempdir().unwrap();
        let base = isolation.path().canonicalize().unwrap();
        let first =
            BuildEnvironment::isolated(&checkout_root(), isolation.path(), &sha('a')).unwrap();
        let (first_home, first_checkout) = (first.cargo_home().unwrap(), first.checkout());
        drop(first);
        let second =
            BuildEnvironment::isolated(&checkout_root(), isolation.path(), &sha('a')).unwrap();
        assert_eq!(
            first_home,
            second.cargo_home().unwrap(),
            "isolated Cargo home moved"
        );
        assert_eq!(first_checkout, second.checkout(), "isolated checkout moved");
        let directory = base.join(sha('a').0);
        assert_eq!(first_home, directory.join("cargo"));
        assert_eq!(first_checkout, directory.join("checkout"));
        let config: toml::Value =
            toml::from_str(&fs::read_to_string(first_home.join("config.toml")).unwrap()).unwrap();
        let expected = toml::Value::Array(vec![
            format!("--remap-path-prefix={}=/src", first_checkout.display()).into(),
            format!("--remap-path-prefix={}=/cargo", first_home.display()).into(),
        ]);
        assert_eq!(config["build"]["rustflags"], expected);
        assert_eq!(
            config["target"]["aarch64-unknown-linux-musl"]["rustflags"],
            expected
        );
        let other =
            BuildEnvironment::isolated(&checkout_root(), isolation.path(), &sha('b')).unwrap();
        assert_eq!(
            other.cargo_home().unwrap(),
            base.join(sha('b').0).join("cargo"),
            "a concurrent build of another SHA is independent"
        );
    }

    #[test]
    fn isolated_build_lock_admits_one_build_per_sha() {
        let isolation = tempfile::tempdir().unwrap();
        let base = isolation.path().canonicalize().unwrap();
        let held = IsolatedBuild::acquire(isolation.path(), &sha('c')).unwrap();
        let lock = fs::File::open(base.join(format!("{}.lock", sha('c').0))).unwrap();
        assert!(matches!(
            lock.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        // Another SHA is admitted while this one is held.
        let other = IsolatedBuild::acquire(isolation.path(), &sha('d')).unwrap();
        let (admitted, waiting) = std::sync::mpsc::channel();
        let root = isolation.path().to_path_buf();
        let waiter = std::thread::spawn(move || {
            let build = IsolatedBuild::acquire(&root, &sha('c')).unwrap();
            admitted.send(build.path().to_path_buf()).unwrap();
        });
        assert!(
            waiting
                .recv_timeout(std::time::Duration::from_millis(200))
                .is_err()
        );
        drop(held);
        let path = waiting
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert_eq!(path, base.join(sha('c').0));
        waiter.join().unwrap();
        // Both builds of `c` are over: the lock is free and the directory gone.
        lock.try_lock().unwrap();
        assert!(!base.join(sha('c').0).exists());
        assert!(other.path().is_dir());
    }

    #[test]
    fn stale_isolated_build_is_removed_without_following_links() {
        let isolation = tempfile::tempdir().unwrap();
        let shared = tempfile::tempdir().unwrap();
        fs::write(shared.path().join("crate"), b"shared cache").unwrap();
        let stale = isolation.path().join(sha('e').0);
        fs::create_dir_all(stale.join("checkout")).unwrap();
        fs::create_dir_all(stale.join("cargo")).unwrap();
        fs::write(stale.join("checkout/leftover"), b"crashed build").unwrap();
        std::os::unix::fs::symlink(shared.path(), stale.join("cargo/registry")).unwrap();
        let build = IsolatedBuild::acquire(isolation.path(), &sha('e')).unwrap();
        assert_eq!(fs::read_dir(build.path()).unwrap().count(), 0);
        drop(build);
        assert!(!stale.exists());
        assert_eq!(
            fs::read(shared.path().join("crate")).unwrap(),
            b"shared cache"
        );
    }

    #[test]
    fn executable_naming_its_build_directory_is_refused() {
        let directory = Path::new("/scratch/carrick-fixture-builds/abc");
        let mut bytes = b"\x7fELF...".to_vec();
        reject_embedded_path("probe", &bytes, directory).unwrap();
        bytes.extend_from_slice(b"/scratch/carrick-fixture-builds/abc/cargo/registry/src/libc");
        let error = reject_embedded_path("probe", &bytes, directory).unwrap_err();
        assert!(error.to_string().contains("embeds its isolated build path"));
    }
}
