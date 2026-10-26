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

#[test]
fn lease_and_worktree_children_have_identical_cargo_environments() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = tempfile::tempdir().unwrap();
    let xtask = env!("CARGO_BIN_EXE_carrick-xtask");
    let mut baseline = None;
    // Both top-level supervisor custody and inherited lease children must
    // remove metadata, even when a Cargo-like launcher reinjects it between
    // boundaries. A future CARGO_PKG_* name must follow the same policy.
    for route in [
        vec!["worktree"],
        vec!["lease"],
        vec!["lease", "worktree"],
        vec!["lease", "worktree", "lease"],
    ] {
        let mut args: Vec<OsString> = vec![
            "sh".into(),
            "-c".into(),
            "env | LC_ALL=C sort | grep -E '^(CARGO_|RUSTC_WRAPPER=|CARRICK_CARGO_CACHE_CONFIG=)'"
                .into(),
        ];
        for boundary in route.iter().rev() {
            let mut next: Vec<OsString> = vec![xtask.into()];
            if *boundary == "worktree" {
                next.extend(["worktree-run".into(), "--".into()]);
            } else {
                next.extend([
                    "host-lease".into(),
                    "--mode".into(),
                    "carrick".into(),
                    "--".into(),
                ]);
            }
            next.extend(args);
            args = vec![
                "sh".into(),
                "-c".into(),
                "export CARGO_MANIFEST_DIR=/injected/xtask CARGO_PKG_FUTURE=sentinel; exec \"$@\""
                    .into(),
                "inject-cargo-metadata".into(),
            ];
            args.extend(next);
        }
        let output = Command::new(&args[0])
            .args(&args[1..])
            .current_dir(&repo)
            .env_remove("CARRICK_HOST_LEASE_SOCKET")
            .env("CARRICK_HOST_LEASE_PATH", dir.path().join("host.lock"))
            .env("CARGO_TARGET_DIR", dir.path().join("target"))
            .env("RUSTC_WRAPPER", "/preserved/wrapper")
            .env("CARRICK_CARGO_CACHE_CONFIG", "preserved-cache-config")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{route:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let environment = String::from_utf8(output.stdout).unwrap();
        assert!(
            !environment
                .lines()
                .any(|line| line.starts_with("CARGO_MANIFEST_")),
            "{route:?}: leaked Cargo package metadata"
        );
        assert!(
            !environment
                .lines()
                .any(|line| line.starts_with("CARGO_PKG_")),
            "{route:?}: leaked Cargo package metadata"
        );
        assert!(environment.contains("RUSTC_WRAPPER=/preserved/wrapper"));
        assert!(environment.contains("CARRICK_CARGO_CACHE_CONFIG=preserved-cache-config"));
        assert!(environment.contains(&format!(
            "CARGO_TARGET_DIR={}",
            dir.path().join("target").display()
        )));
        if let Some(expected) = &baseline {
            assert!(
                environment.eq(expected),
                "{route:?}: Cargo environments differ"
            );
        } else {
            baseline = Some(environment);
        }
    }
}

#[test]
fn signed_gate_recipes_remove_ambient_target_and_functional_overrides() {
    let build = Build::new();
    symlink(find("env"), build.root.path().join("bin/env")).unwrap();
    let runner = build.root.path().join("scripts/test-signed.sh");
    fs::write(
        &runner,
        "#!/bin/sh\ntest \"${CARRICK_TEST_TARGET+x}\" != x && test \"${CARRICK_SIGNED_FUNCTIONAL+x}\" != x\n",
    )
    .unwrap();
    fs::set_permissions(&runner, fs::Permissions::from_mode(0o755)).unwrap();
    for recipe in [
        "test-embed",
        "test-hvf",
        "test-hvf-trap-engine",
        "test-conformance-next",
    ] {
        passed(
            build
                .command("--no-deps")
                .arg(recipe)
                .env("CARRICK_TEST_TARGET", "accidentally_exported")
                .env("CARRICK_SIGNED_FUNCTIONAL", "1")
                .output()
                .unwrap(),
        );
    }
}

#[test]
fn artifact_serves_admission_and_direct_xtask_calls_without_cargo_bootstrap() {
    let build = Build::new();
    symlink(find("bash"), build.root.path().join("bin/bash")).unwrap();
    let artifact = build.root.path().join("xtask artifact");
    let log = build.root.path().join("calls");
    fs::write(&artifact, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$XTASK_LOG\"\nif [ \"$1\" = worktree-run ]; then shift 2; exec \"$@\"; fi\n").unwrap();
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o755)).unwrap();
    for (recipe, args) in [
        ("ci-prebuild-xtask", vec![]),
        ("xtask", vec!["authority-debt"]),
        (
            "authority-check-cross",
            vec!["x86_64-unknown-freebsd", "clang", "", "llvm-ar"],
        ),
        ("xtask", vec!["test-batch", "_test-unit-workspace"]),
    ] {
        passed(
            build
                .command(recipe)
                .args(args)
                .env("CARRICK_XTASK_BIN", &artifact)
                .env("XTASK_LOG", &log)
                .output()
                .unwrap(),
        );
    }
    let calls = fs::read_to_string(log).unwrap();
    assert!(calls.contains("authority-debt"));
    assert!(calls.contains("--cross-target x86_64-unknown-freebsd"));
    assert!(calls.contains("test-batch"));
    assert_eq!(
        calls
            .lines()
            .filter(|l| l.starts_with("worktree-run --"))
            .count(),
        3
    );
}

#[test]
fn real_artifact_admission_uses_the_shared_package_environment_scrub() {
    let build = Build::new();
    let git = find("git");
    assert!(
        Command::new(&git)
            .args(["init", "--quiet"])
            .current_dir(build.root.path())
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(&git)
            .args([
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@invalid",
                "commit",
                "--allow-empty",
                "--no-gpg-sign",
                "-qm",
                "fixture root",
            ])
            .current_dir(build.root.path())
            .status()
            .unwrap()
            .success()
    );
    symlink(git, build.root.path().join("bin/git")).unwrap();
    let artifact = build.root.path().join("real xtask artifact");
    fs::copy(env!("CARGO_BIN_EXE_carrick-xtask"), &artifact).unwrap();
    let justfile = build.root.path().join("justfile");
    let mut recipes = fs::read_to_string(&justfile).unwrap();
    recipes.push_str(r#"
artifact-package-env-witness:
    {{_admit}} sh -c 'if [ "${CARGO_MANIFEST_DIR+x}" = x ] || [ "${CARGO_PKG_FUTURE+x}" = x ]; then echo leaked-package-metadata; exit 73; fi; test "$CARGO_TARGET_DIR" = "$EXPECTED_TARGET"'
"#);
    fs::write(justfile, recipes).unwrap();
    let run = |bypass: bool| {
        let mut command = if bypass {
            let mut command = build.command("--set");
            command.args(["_admit", "", "artifact-package-env-witness"]);
            command
        } else {
            build.command("artifact-package-env-witness")
        };
        command
            .env("CARRICK_XTASK_BIN", &artifact)
            .env("CARGO_MANIFEST_DIR", "/injected/xtask")
            .env("CARGO_PKG_FUTURE", "sentinel")
            .env(
                "CARGO_TARGET_DIR",
                build.root.path().join("preserved-target"),
            )
            .env(
                "EXPECTED_TARGET",
                build.root.path().join("preserved-target"),
            )
            .output()
            .unwrap()
    };
    let bypassed = run(true);
    assert!(!bypassed.status.success());
    assert_eq!(
        String::from_utf8(bypassed.stdout).unwrap().trim(),
        "leaked-package-metadata"
    );
    passed(run(false));
}

#[test]
fn timing_recipes_take_checkout_before_gate_and_clear_functional() {
    let build = Build::new();
    symlink(find("env"), build.root.path().join("bin/env")).unwrap();
    let artifact = build.root.path().join("xtask");
    fs::write(
        &artifact,
        r#"#!/bin/sh
case "$1" in
worktree-run)
    test "${LEASE_ORDER:-}" = "" || exit 20
    export LEASE_ORDER=checkout
    shift 2
    exec "$@"
    ;;
host-lease)
    test "${LEASE_ORDER:-}" = checkout || exit 21
    test "$2 $3 $4 $5" = "--mode gate --check-load --" || exit 22
    export LEASE_ORDER=gate
    shift 5
    exec "$@"
    ;;
*) exit 23 ;;
esac
"#,
    )
    .unwrap();
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o755)).unwrap();
    let witness = r#"#!/bin/sh
test "${LEASE_ORDER:-}" = gate || exit 24
test "${CARRICK_SIGNED_FUNCTIONAL+x}" != x || exit 25
"#;
    let cargo = build.root.path().join("bin/cargo");
    fs::remove_file(&cargo).unwrap();
    fs::write(&cargo, witness).unwrap();
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();
    let perf = build.root.path().join("scripts/measure-perf.sh");
    fs::write(&perf, witness).unwrap();
    fs::set_permissions(&perf, fs::Permissions::from_mode(0o755)).unwrap();
    for recipe in [
        "conformance",
        "conformance-quick",
        "bench",
        "bench-hvf-mailbox",
    ] {
        passed(
            build
                .command("--no-deps")
                .arg(recipe)
                .env("CARRICK_XTASK_BIN", &artifact)
                .env("CARRICK_SIGNED_FUNCTIONAL", "1")
                .env_remove("LEASE_ORDER")
                .output()
                .unwrap(),
        );
    }
}
