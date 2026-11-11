//! Verify that `carrick-el1-image/build.rs` watches every workspace crate and
//! build input in the non-dev dependency closure of `carrick-el1-linux`.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "../build.rs"]
#[allow(dead_code)]
mod image_build;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

fn manifest_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .expect("carrick-el1-image manifest dir")
}

fn workspace_root() -> PathBuf {
    manifest_dir()
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

/// Extract `key = { ... path = "..." ... }` or `key.workspace = true` entries
/// from a minimal Cargo.toml parser over normal `[dependencies]` tables that
/// apply to `aarch64-unknown-none-softfloat` (`target_os = "none"`).
fn target_cfg_applies_to_el1(header: &str) -> bool {
    let Some(rest) = header.strip_prefix("target.") else {
        return false;
    };
    let Some(cfg_part) = rest.strip_suffix(".dependencies") else {
        return false;
    };
    let cfg = cfg_part.trim().trim_matches('\'').trim_matches('"');
    // Host-only target tables such as `cfg(not(target_os = "none"))` do not
    // link into `aarch64-unknown-none-softfloat`.
    if cfg.contains("not(target_os = \"none\")")
        || cfg.contains("unix")
        || cfg.contains("windows")
        || cfg.contains("target_os = \"linux\"")
        || cfg.contains("target_os = \"macos\"")
        || cfg.contains("target_os = \"freebsd\"")
        || cfg.contains("target_os = \"netbsd\"")
        || cfg.contains("target_arch = \"x86_64\"")
    {
        return false;
    }
    true
}

fn parse_workspace_paths(root_manifest: &str, workspace: &Path) -> BTreeSet<(String, PathBuf)> {
    let mut result = BTreeSet::new();
    let mut in_workspace_deps = false;
    for raw_line in root_manifest.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_workspace_deps = section.trim() == "workspace.dependencies";
            continue;
        }
        if !in_workspace_deps {
            continue;
        }
        let Some((name, spec)) = line.split_once('=') else {
            continue;
        };
        if let Some(rel) = extract_inline_string(spec, "path") {
            result.insert((name.trim().to_owned(), workspace.join(rel)));
        }
    }
    result
}

fn extract_inline_string<'a>(spec: &'a str, key: &str) -> Option<&'a str> {
    let mut rest = spec;
    while let Some(idx) = rest.find(key) {
        let before_ok = idx == 0 || matches!(rest.as_bytes()[idx - 1], b'{' | b',' | b' ' | b'\t');
        let after = &rest[idx + key.len()..];
        let after_trimmed = after.trim_start();
        if before_ok && let Some(after_eq) = after_trimmed.strip_prefix('=') {
            let quoted = after_eq.trim_start();
            if let Some(inner) = quoted.strip_prefix('"')
                && let Some(end) = inner.find('"')
            {
                return Some(&inner[..end]);
            }
        }
        rest = after;
    }
    None
}

/// Normal (`[dependencies]` and applicable `[target.*.dependencies]`) path
/// dependency closure of `crates/carrick-el1-linux/Cargo.toml`.
fn el1_linux_path_dependency_closure(workspace: &Path) -> BTreeSet<PathBuf> {
    let root_toml =
        std::fs::read_to_string(workspace.join("Cargo.toml")).expect("read root Cargo.toml");
    let ws_paths = parse_workspace_paths(&root_toml, workspace);

    let mut visited = BTreeSet::new();
    let mut stack = vec![workspace.join("crates/carrick-el1-linux")];
    while let Some(dir) = stack.pop() {
        let dir = dir.canonicalize().expect("canonicalize crate dir");
        if !visited.insert(dir.clone()) {
            continue;
        }
        let manifest_path = dir.join("Cargo.toml");
        let manifest = std::fs::read_to_string(&manifest_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", manifest_path.display()));
        let mut active_deps_section = false;
        for raw_line in manifest.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                let section = section.trim();
                active_deps_section =
                    section == "dependencies" || target_cfg_applies_to_el1(section);
                continue;
            }
            if !active_deps_section {
                continue;
            }
            let Some((raw_key, spec)) = line.split_once('=') else {
                continue;
            };
            let key = raw_key.trim();
            let spec = spec.trim();
            if let Some(rel) = extract_inline_string(spec, "path") {
                stack.push(dir.join(rel));
            } else if let Some(dep_name) = key.strip_suffix(".workspace") {
                if spec == "true" {
                    for (ws_name, ws_path) in &ws_paths {
                        if ws_name == dep_name.trim() {
                            stack.push(ws_path.clone());
                        }
                    }
                }
            } else if spec.contains("workspace") && spec.contains("true") {
                for (ws_name, ws_path) in &ws_paths {
                    if ws_name == key {
                        stack.push(ws_path.clone());
                    }
                }
            }
        }
    }
    visited
}

fn resolve_watched_paths(raw_paths: &[PathBuf], manifest_dir: &Path) -> BTreeSet<PathBuf> {
    raw_paths
        .iter()
        .map(|candidate| {
            let resolved = if candidate.is_absolute() {
                candidate.clone()
            } else {
                manifest_dir.join(candidate)
            };
            resolved.canonicalize().unwrap_or(resolved)
        })
        .collect()
}

fn emitted_raw_rerun_paths(build_output: &str) -> Vec<PathBuf> {
    build_output
        .lines()
        .filter_map(|line| {
            line.strip_prefix("cargo:rerun-if-changed=")
                .or_else(|| line.strip_prefix("cargo::rerun-if-changed="))
                .map(PathBuf::from)
        })
        .collect()
}

fn check_watch_list_covers_closure(
    watched: &BTreeSet<PathBuf>,
    workspace: &Path,
    manifest: &Path,
) -> Result<(), String> {
    let closure = el1_linux_path_dependency_closure(workspace);
    assert!(
        !closure.contains(
            &workspace
                .join("crates/carrick-fatal")
                .canonicalize()
                .unwrap()
        ),
        "host-only carrick-fatal must not be in the target_os = \"none\" closure"
    );

    let mut missing_crates = Vec::new();
    let mut missing_files = Vec::new();
    for crate_dir in &closure {
        let crate_name = crate_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unknown>");
        let covers_crate = watched
            .iter()
            .any(|p| p == crate_dir || p.starts_with(crate_dir));
        if !covers_crate {
            missing_crates.push(crate_name.to_owned());
            continue;
        }
        for required in ["Cargo.toml", "src", "build.rs", "link.ld"] {
            let target = crate_dir.join(required);
            if target.exists() {
                let target = target.canonicalize().unwrap();
                let covered = watched
                    .iter()
                    .any(|w| w == &target || target.starts_with(w));
                if !covered {
                    missing_files.push(format!("{crate_name}/{required}"));
                }
            }
        }
    }

    for extra in [
        manifest.join("frame_budget.rs"),
        workspace.join("Cargo.lock"),
    ] {
        let extra = extra.canonicalize().expect("required build input exists");
        if !watched.iter().any(|w| w == &extra || extra.starts_with(w)) {
            missing_files.push(
                extra
                    .strip_prefix(workspace)
                    .unwrap_or(&extra)
                    .display()
                    .to_string(),
            );
        }
    }

    if missing_crates.is_empty() && missing_files.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "EL1 image rerun-if-changed watch list is incomplete:\n  missing crates ({}): {:?}\n  missing inputs ({}): {:?}",
            missing_crates.len(),
            missing_crates,
            missing_files.len(),
            missing_files,
        ))
    }
}

#[test]
fn emitted_watch_list_covers_every_path_dependency_of_el1_image() {
    let manifest = manifest_dir();
    let workspace = workspace_root();
    let out_dir = Path::new(env!("OUT_DIR"));
    let output_path = out_dir
        .parent()
        .expect("Cargo build-script directory")
        .join("output");
    let build_output = std::fs::read_to_string(&output_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", output_path.display()));
    let raw_emitted = emitted_raw_rerun_paths(&build_output);
    let mut sorted_deduped = raw_emitted.clone();
    sorted_deduped.sort();
    sorted_deduped.dedup();
    assert_eq!(
        raw_emitted, sorted_deduped,
        "emitted cargo:rerun-if-changed lines must be deterministic (sorted + deduplicated)"
    );

    let watched = resolve_watched_paths(&raw_emitted, &manifest);
    if let Err(message) = check_watch_list_covers_closure(&watched, &workspace, &manifest) {
        panic!("{message}");
    }
}

#[test]
fn derived_watch_list_matches_real_el1_depfile_and_rejects_omitted_crate() {
    let manifest = manifest_dir();
    let workspace = workspace_root();
    let out_dir = Path::new(env!("OUT_DIR"));
    let depfile_path =
        out_dir.join("el1-target/aarch64-unknown-none-softfloat/release/carrick-el1.d");
    let depfile_text = std::fs::read_to_string(&depfile_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", depfile_path.display()));
    let derived = image_build::derive_watch_list(
        &depfile_text,
        &manifest,
        &workspace,
        out_dir,
        Path::new("/nonexistent-sysroot"),
    )
    .expect("derive watch list from real carrick-el1.d");

    assert!(
        derived.contains(&PathBuf::from("frame_budget.rs")),
        "frame_budget.rs must stay in watch list"
    );
    assert!(
        derived.contains(&PathBuf::from("../carrick-el1-linux/link.ld")),
        "../carrick-el1-linux/link.ld must stay in watch list"
    );
    assert!(
        derived.contains(&PathBuf::from("../../Cargo.lock")),
        "../../Cargo.lock must be in watch list"
    );
    assert!(
        derived.contains(&PathBuf::from("../carrick-fd-core/src/lib.rs")),
        "dep-info source ../carrick-fd-core/src/lib.rs must be watched"
    );

    let watched = resolve_watched_paths(&derived, &manifest);
    check_watch_list_covers_closure(&watched, &workspace, &manifest)
        .expect("derived watch list covers full EL1 closure");

    // Negative control: omitting any crate in the closure (e.g. carrick-fd-core)
    // must fail the coverage check.
    let fd_core_dir = workspace
        .join("crates/carrick-fd-core")
        .canonicalize()
        .unwrap();
    let without_fd_core: BTreeSet<PathBuf> = watched
        .iter()
        .filter(|path| !path.starts_with(&fd_core_dir))
        .cloned()
        .collect();
    let err = check_watch_list_covers_closure(&without_fd_core, &workspace, &manifest)
        .expect_err("omitting carrick-fd-core must fail");
    assert!(err.contains("carrick-fd-core"), "unexpected error: {err}");
}

#[test]
fn parse_depfile_handles_escaped_spaces_continuations_comments_and_phony_rules() {
    let text = "\
# leading comment
/out/dir\\ with\\ space/carrick-el1: /ws/crates/alpha/src/lib.rs \\
  /ws/crates/beta\\ dir/src/main\\ file.rs \\
  /ws/crates/gamma/src/with\\\\backslash.rs /ws/crates/gamma/src/with\\#hash\\:colon.rs

/ws/crates/alpha/src/lib.rs:
/ws/crates/beta\\ dir/src/main\\ file.rs:
";
    let parsed = image_build::parse_depfile(text);
    assert_eq!(
        parsed,
        vec![
            PathBuf::from("/ws/crates/alpha/src/lib.rs"),
            PathBuf::from("/ws/crates/beta dir/src/main file.rs"),
            PathBuf::from("/ws/crates/gamma/src/with\\backslash.rs"),
            PathBuf::from("/ws/crates/gamma/src/with#hash:colon.rs"),
        ]
    );
}

struct TempWorkspace {
    path: PathBuf,
}

impl TempWorkspace {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("carrick-el1-rerun-{label}-{stamp}-{id}"));
        std::fs::create_dir_all(&path).expect("create temp workspace");
        Self { path }
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[test]
fn derive_watch_list_skips_sysroot_registry_and_out_dir_and_stays_sorted() {
    let temp = TempWorkspace::new("filter");
    let ws = temp.path.canonicalize().expect("canonical temp ws");
    let image_crate = ws.join("crates/carrick-el1-image");
    let linux_crate = ws.join("crates/carrick-el1-linux");
    let dep_crate = ws.join("crates/space crate");
    let out_dir = ws.join("target/debug/build/carrick-el1-image-abc/out");
    let sysroot = ws.join("embedded-sysroot");
    let registry = ws.join(".cargo/registry/src/example-1.0");

    for dir in [
        image_crate.join("src"),
        linux_crate.join("src"),
        dep_crate.join("src"),
        out_dir.clone(),
        sysroot.join("lib/rustlib/src/rust/library/core/src"),
        registry.join("src"),
    ] {
        std::fs::create_dir_all(&dir).unwrap();
    }
    std::fs::write(ws.join("Cargo.lock"), "# lock\n").unwrap();
    std::fs::write(
        image_crate.join("Cargo.toml"),
        "[package]\nname = \"carrick-el1-image\"\n",
    )
    .unwrap();
    std::fs::write(image_crate.join("frame_budget.rs"), "// budget\n").unwrap();
    std::fs::write(
        linux_crate.join("Cargo.toml"),
        "[package]\nname = \"carrick-el1-linux\"\n",
    )
    .unwrap();
    std::fs::write(linux_crate.join("build.rs"), "fn main() {}\n").unwrap();
    std::fs::write(linux_crate.join("link.ld"), "SECTIONS {}\n").unwrap();
    std::fs::write(linux_crate.join("src/entry.rs"), "// entry\n").unwrap();
    std::fs::write(
        dep_crate.join("Cargo.toml"),
        "[package]\nname = \"space-crate\"\n",
    )
    .unwrap();
    std::fs::write(dep_crate.join("src/lib.rs"), "// dep\n").unwrap();
    std::fs::write(out_dir.join("generated.rs"), "// generated\n").unwrap();
    std::fs::write(
        sysroot.join("lib/rustlib/src/rust/library/core/src/lib.rs"),
        "// core\n",
    )
    .unwrap();
    std::fs::write(registry.join("src/lib.rs"), "// external\n").unwrap();

    let escape = |p: &Path| p.display().to_string().replace(' ', "\\ ");
    let depfile = format!(
        "{}: {} \\\n  {} \\\n  {} \\\n  {} \\\n  {} \\\n  /external/registry/zerocopy/src/lib.rs\n",
        escape(&out_dir.join("carrick-el1")),
        escape(&linux_crate.join("src/entry.rs")),
        escape(&dep_crate.join("src/lib.rs")),
        escape(&out_dir.join("generated.rs")),
        escape(&sysroot.join("lib/rustlib/src/rust/library/core/src/lib.rs")),
        escape(&registry.join("src/lib.rs")),
    );

    let list = image_build::derive_watch_list(&depfile, &image_crate, &ws, &out_dir, &sysroot)
        .expect("derive watch list");

    assert_eq!(
        list,
        vec![
            PathBuf::from("../../Cargo.lock"),
            PathBuf::from("../carrick-el1-linux/Cargo.toml"),
            PathBuf::from("../carrick-el1-linux/build.rs"),
            PathBuf::from("../carrick-el1-linux/link.ld"),
            PathBuf::from("../carrick-el1-linux/src"),
            PathBuf::from("../carrick-el1-linux/src/entry.rs"),
            PathBuf::from("../space crate/Cargo.toml"),
            PathBuf::from("../space crate/src"),
            PathBuf::from("../space crate/src/lib.rs"),
            PathBuf::from("frame_budget.rs"),
        ]
    );
}
