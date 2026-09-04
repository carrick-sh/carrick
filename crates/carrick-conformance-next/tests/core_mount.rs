//! In-process integration test verifying that core dumps published within a
//! guest mount point are visible as real host files in the mounted host directory.
//!
//! Run signed guest verification via:
//!   ./scripts/test-signed.sh carrick-conformance-next core_publication_visible_on_bind_mount --nocapture
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};

use carrick_conformance_next::{PullPolicy, ResultAssert};

/// Drop carrick's scratch warning so output lines up with Docker's.
fn normalize(s: &str) -> String {
    s.lines()
        .filter(|l| !l.contains("case-insensitive; defaulting") && !l.contains("Pass `--fs host`"))
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_string()
}

/// Stable content fingerprint of a probe's source using DefaultHasher.
fn probe_src_hash(repo_root: &Path, name: &str) -> String {
    use std::hash::{Hash, Hasher};
    match std::fs::read(repo_root.join(format!("conformance-probes/src/bin/{name}.rs"))) {
        Ok(bytes) => {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            bytes.hash(&mut h);
            format!("{:016x}", h.finish())
        }
        Err(_) => "nosrc".to_string(),
    }
}

/// Read and validate a cached Docker oracle output for a probe.
fn cached_probe_oracle(
    repo_root: &Path,
    lane_label: &str,
    libc: &str,
    name: &str,
) -> Result<String, String> {
    let rel_path = format!("crates/carrick-cli/tests/probe-oracle/{lane_label}-{libc}/{name}");
    let path = repo_root.join(&rel_path);
    let raw = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "missing oracle cache for probe {name:?} ({lane_label}-{libc}) at {}: {e}. \
             Bless it on a Docker host.",
            path.display()
        )
    })?;
    let (hash_line, body) = raw.split_once('\n').ok_or_else(|| {
        format!(
            "corrupt oracle cache for probe {name:?} at {}: missing first-line source hash separator",
            path.display()
        )
    })?;
    let expected_hash = probe_src_hash(repo_root, name);
    if hash_line != expected_hash {
        return Err(format!(
            "stale oracle cache for probe {name:?} at {}: \
             source hash mismatch (cache has {hash_line:?}, current source has {expected_hash:?}). \
             Re-bless on a Docker host.",
            path.display()
        ));
    }
    Ok(normalize(body))
}

/// Formats a line-by-line diff between carrick output and oracle output.
fn diff_lines(carrick: &str, oracle: &str) -> Option<String> {
    if carrick == oracle {
        return None;
    }
    let c: Vec<&str> = carrick.lines().collect();
    let o: Vec<&str> = oracle.lines().collect();
    let mut buf = String::new();
    for i in 0..c.len().max(o.len()) {
        let cl = c.get(i).copied();
        let ol = o.get(i).copied();
        if cl == ol {
            continue;
        }
        buf.push_str(&format!("  line {}:\n", i + 1));
        match cl {
            Some(s) => buf.push_str(&format!("    - carrick: {s}\n")),
            None => buf.push_str("    - carrick: <missing>\n"),
        }
        match ol {
            Some(s) => buf.push_str(&format!("    + oracle:  {s}\n")),
            None => buf.push_str("    + oracle:  <missing>\n"),
        }
    }
    Some(buf)
}

/// Locate probe directory for a target triple matching generic shard lookup.
fn find_probe_binary_dir(repo_root: &Path, target: &str) -> Option<PathBuf> {
    let candidate1 = repo_root
        .join("conformance-probes/target")
        .join(target)
        .join("release");
    if candidate1.is_dir() {
        return Some(candidate1);
    }
    let candidate2 = repo_root.join("target").join(target).join("release");
    if candidate2.is_dir() {
        return Some(candidate2);
    }
    None
}

/// Validate that the host core file exists and is a valid 64-bit AArch64 ELF core dump.
fn validate_host_core_file(core_path: &Path) {
    assert!(
        core_path.is_file(),
        "host core file must exist at exact path {}",
        core_path.display()
    );
    let bytes = std::fs::read(core_path).unwrap_or_else(|e| {
        panic!(
            "failed to read host core file at {}: {e}",
            core_path.display()
        )
    });
    assert!(
        bytes.len() >= 64,
        "host core file at {} is too short for ELF header (length: {})",
        core_path.display(),
        bytes.len()
    );
    assert_eq!(
        &bytes[0..4],
        b"\x7fELF",
        "host core at {} lacks ELF magic",
        core_path.display()
    );
    assert_eq!(
        bytes[4],
        2,
        "host core at {} must be ELFCLASS64 (64-bit)",
        core_path.display()
    );
    assert_eq!(
        bytes[5],
        1,
        "host core at {} must be ELFDATA2LSB (little-endian)",
        core_path.display()
    );
    let e_type = u16::from_le_bytes([bytes[16], bytes[17]]);
    assert_eq!(
        e_type,
        4,
        "host core at {} must have e_type = ET_CORE (4), got {e_type}",
        core_path.display()
    );
    let e_machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    assert_eq!(
        e_machine,
        183,
        "host core at {} must have e_machine = EM_AARCH64 (183), got {e_machine}",
        core_path.display()
    );
}

#[test]
fn core_publication_visible_on_bind_mount() {
    let _guard = common::guest_lock();
    let root = common::repo_root();

    let targets = [
        ("aarch64-unknown-linux-musl", "musl"),
        ("aarch64-unknown-linux-gnu", "gnu"),
    ];

    for (target, libc) in targets {
        let probe_dir = find_probe_binary_dir(&root, target).unwrap_or_else(|| {
            panic!(
                "missing probe binaries directory for target {target}; \
                 expected either conformance-probes/target/{target}/release or target/{target}/release — \
                 run scripts/build-probes.sh"
            )
        });

        let init_path = probe_dir.join("probeinit");
        assert!(
            init_path.is_file(),
            "probeinit transport helper missing at {} — run scripts/build-probes.sh",
            init_path.display()
        );

        let probe_name = "coredumpfile";
        let probe_path = probe_dir.join(probe_name);
        assert!(
            probe_path.is_file(),
            "probe binary {probe_name:?} missing for target {target} at {} — \
             run scripts/build-probes.sh",
            probe_path.display()
        );

        let cached_oracle = match cached_probe_oracle(&root, "arm64", libc, probe_name) {
            Ok(out) => out,
            Err(err) => panic!("{err}"),
        };

        let (host_core_dir, _cleanup_guard) = if let Ok(base_dir) =
            std::env::var("CARRICK_REDUCER_ARTIFACT_DIR")
        {
            let base = PathBuf::from(base_dir);
            std::fs::create_dir_all(&base).unwrap_or_else(|e| {
                panic!(
                    "failed to create CARRICK_REDUCER_ARTIFACT_DIR at {}: {e}",
                    base.display()
                )
            });
            let temp = tempfile::Builder::new()
                .prefix(&format!("core_mount_{libc}_"))
                .tempdir_in(&base)
                .unwrap_or_else(|e| panic!("failed to create tempdir in {}: {e}", base.display()));
            let kept_path = temp.keep();
            eprintln!(
                "RETAINED core mount artifact directory for {libc}: {}",
                kept_path.display()
            );
            (kept_path, None)
        } else {
            let temp = tempfile::Builder::new()
                .prefix(&format!("core_mount_{libc}_"))
                .tempdir()
                .expect("create tempdir for core mount");
            let path = temp.path().to_path_buf();
            (path, Some(temp))
        };

        eprintln!(
            "RUN core_mount {target}:{probe_name} with host mount at {}",
            host_core_dir.display()
        );

        let container = common::generic_probe_container(probe_name, &probe_path, &init_path)
            .pull_policy(PullPolicy::Never)
            .mount(host_core_dir.display().to_string(), "/tmp/coredumpfile");

        let outcome = common::with_empty_stdin_pipe(|| container.run(["/tmp/carrick-init"]));
        let result =
            common::run_named_or_fail(&format!("core_mount {target}:{probe_name}"), outcome);

        // Persist stdout and stderr before assertions, failing on write error
        let stdout_path = host_core_dir.join("stdout.log");
        let stderr_path = host_core_dir.join("stderr.log");
        std::fs::write(&stdout_path, &result.stdout).unwrap_or_else(|e| {
            panic!(
                "failed to write stdout artifact to {}: {e}",
                stdout_path.display()
            )
        });
        std::fs::write(&stderr_path, &result.stderr).unwrap_or_else(|e| {
            panic!(
                "failed to write stderr artifact to {}: {e}",
                stderr_path.display()
            )
        });

        // Assert guest exit success
        result.assert_success();

        let mut combined = String::from_utf8_lossy(&result.stdout).into_owned();
        combined.push_str(&String::from_utf8_lossy(&result.stderr));
        let normalized_carrick = normalize(&combined);

        if let Some(diff) = diff_lines(&normalized_carrick, &cached_oracle) {
            eprintln!("DIFF core_mount {target}:{probe_name}");
            eprintln!("--- observed ---\n{normalized_carrick}\n--- oracle ---\n{cached_oracle}");
            panic!("core_mount oracle mismatch for {target}:\n{diff}");
        }

        // Validate exact host core path and ELF headers
        let host_core = host_core_dir.join("core");
        validate_host_core_file(&host_core);

        // Assert no dangling temporary artifacts exist
        let dir_entries = std::fs::read_dir(&host_core_dir).unwrap_or_else(|e| {
            panic!(
                "failed to read host core dir at {}: {e}",
                host_core_dir.display()
            )
        });
        for entry in dir_entries {
            let entry = entry.unwrap_or_else(|e| {
                panic!(
                    "failed to read directory entry in {}: {e}",
                    host_core_dir.display()
                )
            });
            let name = entry.file_name().to_string_lossy().into_owned();
            assert!(
                !name.contains(".carrick-tmp-"),
                "dangling temporary artifact found in host core dir: {name}"
            );
        }
    }
}
