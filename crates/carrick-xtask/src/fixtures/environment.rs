//! Fixture builds have a declared environment; user Cargo configuration is not input.
use super::{Result, fail, git, safe_path};
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
            version: 1,
            inherited_environment: vec!["PATH".into()],
            fixed_environment: BTreeMap::from([
                ("LC_ALL".into(), "C".into()),
                ("TZ".into(), "UTC".into()),
                ("CARGO_NET_OFFLINE".into(), "true".into()),
            ]),
            cargo_configuration: "isolated-home-cache-only; metadata-explicit-tracked-checkout-config; snapshot-build-cwd; no-external-ancestor-config".into(),
            compiler_and_linkers: "pinned-rustup-toolchain-first; musl=rust-lld; gnu=host-cc-or-aarch64-linux-gnu-gcc".into(),
        }
    }
}

fn reject_ambient_overrides() -> Result<()> {
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

pub(super) struct BuildEnvironment {
    _directory: tempfile::TempDir,
    variables: BTreeMap<OsString, OsString>,
}

impl BuildEnvironment {
    pub(super) fn new(root: &Path) -> Result<Self> {
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
        let directory = tempfile::tempdir()?;
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
            _directory: directory,
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

    pub(super) fn scratch_root(&self) -> &Path {
        self._directory.path()
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

    #[test]
    fn build_environment_contains_only_declared_variables() {
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
}
