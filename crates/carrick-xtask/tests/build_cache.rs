//! Real Cargo recipes with an isolated PATH and no installed compiler cache.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Build {
    root: tempfile::TempDir,
    just: PathBuf,
    path: OsString,
}

fn find(program: &str) -> PathBuf {
    let out = Command::new("sh")
        .args(["-c", "command -v \"$1\"", "test", program])
        .output()
        .unwrap();
    assert!(out.status.success());
    PathBuf::from(String::from_utf8(out.stdout).unwrap().trim())
}

impl Build {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        fs::create_dir_all(root.path().join("scripts/lib")).unwrap();
        fs::create_dir(root.path().join("bin")).unwrap();
        fs::create_dir(root.path().join("src")).unwrap();
        fs::copy(
            repo.join("scripts/lib/build-env.sh"),
            root.path().join("scripts/lib/build-env.sh"),
        )
        .unwrap();
        let mut justfile = fs::read_to_string(repo.join("justfile")).unwrap();
        justfile.push_str("\ncache-recipe-witness:\n    {{_cargo}} check --offline\n    {{_cargo}} check --offline\n");
        fs::write(root.path().join("justfile"), justfile).unwrap();
        fs::write(root.path().join("Cargo.toml"), "[workspace]\n[package]\nname = \"cache-recipe-witness\"\nversion = \"0.0.0\"\nedition = \"2021\"\n").unwrap();
        fs::write(root.path().join("src/lib.rs"), "pub fn witness() {}\n").unwrap();
        symlink(env!("CARGO"), root.path().join("bin/cargo")).unwrap();
        // Link individual utilities instead of admitting their system/cache
        // directories to PATH. Only the exact Rust toolchain bins are shared.
        for name in ["sh", "sed", "rustup"] {
            symlink(find(name), root.path().join("bin").join(name)).unwrap();
        }
        let rustc = Command::new(find("rustup"))
            .args(["which", "rustc"])
            .output()
            .unwrap();
        assert!(rustc.status.success());
        let rustc = PathBuf::from(String::from_utf8(rustc.stdout).unwrap().trim());
        let cargo = fs::canonicalize(env!("CARGO")).unwrap();
        let mut bins = vec![root.path().join("bin"), cargo.parent().unwrap().to_owned()];
        let rustc_bin = fs::canonicalize(rustc)
            .unwrap()
            .parent()
            .unwrap()
            .to_owned();
        if !bins.contains(&rustc_bin) {
            bins.push(rustc_bin);
        }
        let build = Self {
            root,
            just: find("just"),
            path: std::env::join_paths(bins).unwrap(),
        };
        build.assert_no_sccache();
        build
    }

    fn assert_no_sccache(&self) {
        let out = Command::new(self.root.path().join("bin/sh"))
            .args(["-c", "! command -v sccache"])
            .env("PATH", &self.path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "sccache resolved in witness PATH: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    fn command(&self, recipe: &str) -> Command {
        let mut command = Command::new(&self.just);
        command
            .current_dir(self.root.path())
            .arg(recipe)
            .env("PATH", &self.path)
            .env(
                "CARGO_HOME",
                std::env::var_os("CARGO_HOME").unwrap_or_else(|| {
                    PathBuf::from(std::env::var_os("HOME").unwrap())
                        .join(".cargo")
                        .into()
                }),
            )
            .env(
                "RUSTUP_HOME",
                std::env::var_os("RUSTUP_HOME").unwrap_or_else(|| {
                    PathBuf::from(std::env::var_os("HOME").unwrap())
                        .join(".rustup")
                        .into()
                }),
            )
            .env("HOME", self.root.path())
            .env_remove("CARRICK_SCCACHE")
            .env_remove("CARRICK_SCCACHE_BIN")
            .env_remove("CARRICK_SCCACHE_RESOLVED")
            .env_remove("CARRICK_SCCACHE_REQUEST")
            .env_remove("CARRICK_SCCACHE_SEARCH_PATH")
            .env_remove("CARRICK_CARGO_CACHE_CONFIG")
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env_remove("CARGO_BUILD_RUSTC_WRAPPER")
            .env_remove("CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER");
        command
    }
}

fn passed(out: Output) -> String {
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "recipe failed: {stderr}");
    stderr
}

#[test]
fn missing_sccache_runs_real_cargo_recipe_with_one_notice() {
    let build = Build::new();
    let stderr = passed(build.command("cache-recipe-witness").output().unwrap());
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with("build-cache: "))
            .count(),
        1,
        "{stderr}"
    );
    assert!(
        stderr.contains("building without compiler cache"),
        "{stderr}"
    );
}

#[test]
fn unavailable_explicit_sccache_runs_real_cargo_recipe_with_one_notice() {
    let build = Build::new();
    let stderr = passed(
        build
            .command("cache-recipe-witness")
            .env(
                "CARRICK_SCCACHE_BIN",
                build.root.path().join("absent-cache"),
            )
            .output()
            .unwrap(),
    );
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with("build-cache: "))
            .count(),
        1,
        "{stderr}"
    );
    assert!(
        stderr.contains("building without compiler cache"),
        "{stderr}"
    );
}

impl Build {
    fn wrapper(&self, path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "#!/bin/sh\nprintf 'wrapped\\n' >> \"$CACHE_WITNESS_TRACE\"\nif [ \"$1\" = --show-stats ]; then printf 'cache statistics witness\\n'; exit 0; fi\nexec \"$@\"\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn trace(&self) -> PathBuf {
        self.root.path().join("wrapper-trace")
    }
}

#[test]
fn available_path_sccache_wraps_real_cargo_and_reports_stats() {
    let build = Build::new();
    build.wrapper(&build.root.path().join("bin/sccache"));
    let stderr = passed(
        build
            .command("cache-recipe-witness")
            .env("CACHE_WITNESS_TRACE", build.trace())
            .output()
            .unwrap(),
    );
    assert!(!stderr.contains("build-cache: "), "{stderr}");
    assert!(!fs::read_to_string(build.trace()).unwrap().is_empty());
    let out = build
        .command("build-cache")
        .env("CACHE_WITNESS_TRACE", build.trace())
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .contains("cache statistics witness")
    );
}

#[test]
fn explicit_sccache_path_handles_spaces_and_toml_quotes() {
    let build = Build::new();
    let wrapper = build.root.path().join("cache tool/quoted\"wrapper");
    build.wrapper(&wrapper);
    let stderr = passed(
        build
            .command("cache-recipe-witness")
            .env("CARRICK_SCCACHE_BIN", &wrapper)
            .env("CACHE_WITNESS_TRACE", build.trace())
            .output()
            .unwrap(),
    );
    assert!(!stderr.contains("build-cache: "), "{stderr}");
    assert!(!fs::read_to_string(build.trace()).unwrap().is_empty());
}

#[test]
fn cache_opt_out_does_not_invoke_available_sccache() {
    let build = Build::new();
    build.wrapper(&build.root.path().join("bin/sccache"));
    passed(
        build
            .command("cache-recipe-witness")
            .env("CARRICK_SCCACHE", "0")
            .env("CACHE_WITNESS_TRACE", build.trace())
            .output()
            .unwrap(),
    );
    assert!(!build.trace().exists());
}

#[test]
fn hosted_toolchain_setup_works_before_cache_installation() {
    let build = Build::new();
    let stderr = passed(build.command("ci-toolchain").output().unwrap());
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with("build-cache: "))
            .count(),
        1,
        "{stderr}"
    );
}

#[test]
fn nested_recipes_inherit_one_missing_cache_notice() {
    let build = Build::new();
    let mut justfile = fs::read_to_string(build.root.path().join("justfile")).unwrap();
    justfile.push_str("\nnested-cache-witness:\n    \"$CACHE_WITNESS_JUST\" cache-recipe-witness\n    \"$CACHE_WITNESS_JUST\" ci-toolchain\n");
    fs::write(build.root.path().join("justfile"), justfile).unwrap();
    let stderr = passed(
        build
            .command("nested-cache-witness")
            .env("CACHE_WITNESS_JUST", &build.just)
            .output()
            .unwrap(),
    );
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with("build-cache: "))
            .count(),
        1,
        "{stderr}"
    );
}

#[test]
fn cache_opt_out_overrides_inherited_cache_selection() {
    let build = Build::new();
    let wrapper = build.root.path().join("bin/sccache");
    build.wrapper(&wrapper);
    passed(
        build
            .command("cache-recipe-witness")
            .env(
                "CARRICK_CARGO_CACHE_CONFIG",
                format!("build.rustc-wrapper=\"{}\"", wrapper.display()),
            )
            .env("CARRICK_SCCACHE_RESOLVED", &wrapper)
            .env("CARRICK_SCCACHE", "0")
            .env("CACHE_WITNESS_TRACE", build.trace())
            .output()
            .unwrap(),
    );
    assert!(!build.trace().exists());
}

#[test]
fn explicit_binary_change_replaces_inherited_cache_selection() {
    let build = Build::new();
    let wrapper = build.root.path().join("selected-cache");
    build.wrapper(&wrapper);
    let stderr = passed(
        build
            .command("cache-recipe-witness")
            .env(
                "CARRICK_CARGO_CACHE_CONFIG",
                "build.rustc-wrapper=\"/missing/inherited/sccache\"",
            )
            .env("CARRICK_SCCACHE_REQUEST", "sccache")
            .env("CARRICK_SCCACHE_SEARCH_PATH", &build.path)
            .env("CARRICK_SCCACHE_BIN", &wrapper)
            .env("CACHE_WITNESS_TRACE", build.trace())
            .output()
            .unwrap(),
    );
    assert!(!stderr.contains("build-cache: "), "{stderr}");
    assert!(!fs::read_to_string(build.trace()).unwrap().is_empty());
}

#[test]
fn path_change_replaces_inherited_cache_selection() {
    let build = Build::new();
    let stderr = passed(
        build
            .command("cache-recipe-witness")
            .env(
                "CARRICK_CARGO_CACHE_CONFIG",
                "build.rustc-wrapper=\"/missing/inherited/sccache\"",
            )
            .env("CARRICK_SCCACHE_REQUEST", "sccache")
            .env("CARRICK_SCCACHE_SEARCH_PATH", "/previous/path")
            .output()
            .unwrap(),
    );
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with("build-cache: "))
            .count(),
        1,
        "{stderr}"
    );
}
