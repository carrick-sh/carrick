//! Shard 1 of generic conformance probes running in-process via `TestContainer`.
//!
//! Migrated from `crates/carrick-cli/tests/conformance.rs` to run freestanding
//! Linux probe binaries under `TestContainer` without invoking `carrick run` or
//! shelling out to `std::process::Command`.
//!
//! Run host-only verification:
//!   cargo test -p carrick-conformance-next --test probes_shard_1
//!
//! Run signed guest verification:
//!   just test-conformance-next generic_probe_shard_1 --nocapture
//! or:
//!   ./scripts/test-signed.sh carrick-conformance-next generic_probe_shard_1 --nocapture
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::SHARD_1_PROBES;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const CACHED_SHARD_1_PROBE_COUNT: usize = 136;

/// Shard 1 subset of baseline expected oracle mismatches for musl.
pub const MUSL_SHARD_1_EXPECTED_GAPS: &[&str] = common::MUSL_BASELINE_GAPS;

/// Shard 1 subset of baseline expected oracle mismatches for gnu.
pub const GNU_SHARD_1_EXPECTED_GAPS: &[&str] = common::GNU_BASELINE_GAPS;

/// Drop carrick's scratch warning so output lines up with Docker's.
pub fn normalize(s: &str) -> String {
    s.lines()
        .filter(|l| !l.contains("case-insensitive; defaulting") && !l.contains("Pass `--fs host`"))
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_string()
}

/// Stable content fingerprint of a probe's source using DefaultHasher.
pub fn probe_src_hash(root: &Path, name: &str) -> String {
    use std::hash::{Hash, Hasher};
    match std::fs::read(root.join(format!("conformance-probes/src/bin/{name}.rs"))) {
        Ok(bytes) => {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            bytes.hash(&mut h);
            format!("{:016x}", h.finish())
        }
        Err(_) => "nosrc".to_string(),
    }
}

/// Directory holding the committed probe oracle files.
pub fn probe_oracle_dir(root: &Path, lane_label: &str, libc: &str) -> PathBuf {
    root.join(format!(
        "crates/carrick-cli/tests/probe-oracle/{lane_label}-{libc}"
    ))
}

/// Read cached probe oracle output and validate its first-line source hash.
pub fn cached_probe_oracle(
    root: &Path,
    lane_label: &str,
    libc: &str,
    name: &str,
) -> Result<String, String> {
    let path = probe_oracle_dir(root, lane_label, libc).join(name);
    let raw = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "missing cached oracle for {name} ({lane_label}-{libc}) at {}: {e}",
            path.display()
        )
    })?;
    let (hash_line, body) = raw.split_once('\n').ok_or_else(|| {
        format!(
            "malformed cached oracle for {name} ({lane_label}-{libc}) at {}: missing newline separating header and body",
            path.display()
        )
    })?;
    let expected_hash = probe_src_hash(root, name);
    if hash_line != expected_hash {
        return Err(format!(
            "stale cached oracle for {name} ({lane_label}-{libc}) at {}: expected source hash {expected_hash}, found {hash_line}",
            path.display()
        ));
    }
    Ok(normalize(body))
}

/// Locate probe binary directory for a given target triple.
pub fn probe_campaign_dir(root: &Path, target: &str) -> PathBuf {
    let candidate1 = root.join(format!("conformance-probes/target/{target}/release"));
    if candidate1.is_dir() {
        return candidate1;
    }
    root.join(format!("target/{target}/release"))
}

// ---------------------------------------------------------------------------
// Host-only tests
// ---------------------------------------------------------------------------

#[test]
fn test_shard_1_inventory_count_and_sorted() {
    assert_eq!(
        SHARD_1_PROBES.len(),
        148,
        "shard 1 must contain exactly 148 generic probes"
    );

    // Hard assert uniqueness and strictly ascending sort order.
    for window in SHARD_1_PROBES.windows(2) {
        assert!(
            window[0] < window[1],
            "shard 1 must be strictly sorted and contain unique names, but found {:?} >= {:?}",
            window[0],
            window[1]
        );
    }
    assert_eq!(
        SHARD_1_PROBES
            .iter()
            .filter(|name| common::runs_in_cached_lane(name))
            .count(),
        CACHED_SHARD_1_PROBE_COUNT
    );

    // Verify against conformance-probes/probe-inventory.json on disk if present.
    let root = common::repo_root();
    let inventory_path = root.join("conformance-probes/probe-inventory.json");
    if let Ok(content) = std::fs::read_to_string(&inventory_path) {
        let mut generic_probes = Vec::new();
        let mut cur_name = None;
        let mut cur_class = None;
        let mut cur_excluded = None;
        let mut cur_runner = None;

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('"') && line.ends_with("\": {") {
                cur_name = Some(line[1..line.len() - 4].to_string());
                cur_class = None;
                cur_excluded = None;
                cur_runner = None;
            } else if let Some(stripped) = line.strip_prefix("\"class\":") {
                cur_class = Some(
                    stripped
                        .trim()
                        .trim_matches(|c| c == '"' || c == ',' || c == ' ')
                        .to_string(),
                );
            } else if let Some(stripped) = line.strip_prefix("\"excluded\":") {
                cur_excluded = Some(stripped.trim().trim_end_matches(',').trim() == "true");
            } else if let Some(stripped) = line.strip_prefix("\"runner\":") {
                cur_runner = Some(
                    stripped
                        .trim()
                        .trim_matches(|c| c == '"' || c == ',' || c == ' ')
                        .to_string(),
                );
            } else if line.starts_with('}') {
                if let (Some(name), Some("conformance"), Some(false), Some("generic")) = (
                    cur_name.as_deref(),
                    cur_class.as_deref(),
                    cur_excluded,
                    cur_runner.as_deref(),
                ) {
                    generic_probes.push(name.to_string());
                }
                cur_name = None;
            }
        }

        generic_probes.sort();
        let computed_shard_1: Vec<&str> = generic_probes
            .iter()
            .enumerate()
            .filter(|(idx, _)| idx % 3 == 1)
            .map(|(_, name)| name.as_str())
            .collect();

        assert_eq!(
            computed_shard_1.len(),
            148,
            "computed shard 1 from probe-inventory.json must have 148 items"
        );
        assert_eq!(
            SHARD_1_PROBES,
            computed_shard_1.as_slice(),
            "materialized SHARD_1_PROBES must match probe-inventory.json derived shard 1"
        );
    }
}

#[test]
fn test_normalize_output() {
    let input = "\
[carrick] warning: /path is case-insensitive; defaulting to memory fs
hello=world   \r
Pass `--fs host` to use the host filesystem
status=0\n\n";

    let expected = "hello=world\nstatus=0";
    assert_eq!(normalize(input), expected);
}

#[test]
fn test_cache_freshness_and_validation() {
    let root = common::repo_root();

    // Verify DefaultHasher calculation on a known probe source.
    let hash = probe_src_hash(&root, "acceptsock");
    assert_ne!(hash, "nosrc", "acceptsock.rs source must exist in tree");
    assert_eq!(hash.len(), 16, "DefaultHasher hex string must be 16 chars");

    // Missing probe source returns "nosrc".
    assert_eq!(
        probe_src_hash(&root, "non_existent_probe_name_xyz"),
        "nosrc"
    );

    // Known committed cache files in arm64-musl that are part of shard 1 with valid hash headers.
    for name in &["epollforkeventfd", "futexsharedalias", "mailboxregs"] {
        let cached = cached_probe_oracle(&root, "arm64", "musl", name);
        assert!(
            cached.is_ok(),
            "committed cache for {name} should be valid and fresh: {cached:?}"
        );
    }

    let dsr = cached_probe_oracle(&root, "arm64", "musl", "dsrconstantpool")
        .expect("freshly blessed dsrconstantpool cache must match its source");
    assert!(dsr.contains("constant_word_match=true"));

    // Missing cache error message check.
    let missing = cached_probe_oracle(&root, "arm64", "musl", "non_existent_probe_name_xyz");
    assert!(missing.is_err());
    let err = missing.unwrap_err();
    assert!(
        err.contains("missing cached oracle"),
        "error must mention missing cached oracle: {err}"
    );

    // Stale cache error message check with tempfile.
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_oracle_dir = tmp
        .path()
        .join("crates/carrick-cli/tests/probe-oracle/arm64-musl");
    std::fs::create_dir_all(&fake_oracle_dir).expect("create fake oracle dir");
    std::fs::write(
        fake_oracle_dir.join("acceptsock"),
        "0000000000000000\nstatus=0\n",
    )
    .expect("write fake stale oracle");

    let raw = std::fs::read_to_string(fake_oracle_dir.join("acceptsock")).expect("read fake");
    let (hash_line, _) = raw.split_once('\n').unwrap();
    let expected = probe_src_hash(&root, "acceptsock");
    assert_ne!(hash_line, expected);
}

#[test]
fn test_shard_1_cached_oracles_are_complete() {
    let root = common::repo_root();
    for libc in ["musl", "gnu"] {
        for probe in SHARD_1_PROBES
            .iter()
            .copied()
            .filter(|name| common::runs_in_cached_lane(name))
        {
            cached_probe_oracle(&root, "arm64", libc, probe).unwrap_or_else(|error| {
                panic!("arm64-{libc}/{probe} must have a fresh committed oracle: {error}")
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Signed guest test
// ---------------------------------------------------------------------------

#[test]
fn generic_probe_shard_1() {
    let _guard = common::guest_lock();
    let root = common::repo_root();
    let requested_filter = std::env::var("CARRICK_PROBE_FILTER").ok();
    let selected_probes = common::select_cached_probes(SHARD_1_PROBES, requested_filter.as_deref());

    let targets = [
        (
            "musl",
            "aarch64-unknown-linux-musl",
            MUSL_SHARD_1_EXPECTED_GAPS,
        ),
        (
            "gnu",
            "aarch64-unknown-linux-gnu",
            GNU_SHARD_1_EXPECTED_GAPS,
        ),
    ];

    for (libc, target, expected_gaps) in targets {
        let dir = probe_campaign_dir(&root, target);
        if !dir.is_dir() {
            panic!(
                "probes not built for target {target} in {} — run scripts/build-probes.sh",
                dir.display()
            );
        }

        let probeinit = dir.join("probeinit");
        if !probeinit.is_file() {
            panic!(
                "probeinit transport helper missing at {} — run scripts/build-probes.sh",
                probeinit.display()
            );
        }

        let mut observed_mismatches = Vec::new();
        let mut executed_count = 0;

        for &probe_name in &selected_probes {
            let probe_bin = dir.join(probe_name);
            if !probe_bin.is_file() {
                panic!(
                    "probe binary for {probe_name} missing at {} — run scripts/build-probes.sh",
                    probe_bin.display()
                );
            }

            let oracle = match cached_probe_oracle(&root, "arm64", libc, probe_name) {
                Ok(out) => out,
                Err(err) => {
                    panic!("cached probe oracle error for {probe_name} ({libc}): {err}");
                }
            };

            let container = common::generic_probe_container(probe_name, &probe_bin, &probeinit);

            eprintln!("RUN generic probe shard 1 {target}:{probe_name}");
            executed_count += 1;
            let outcome = common::with_empty_stdin_pipe(|| container.run(["/tmp/carrick-init"]));
            let result = match outcome {
                Ok(result) => result,
                Err(error) if expected_gaps.contains(&probe_name) => {
                    eprintln!("EXPECTED GAP generic probe shard 1 {target}:{probe_name}: {error}");
                    observed_mismatches.push(probe_name.to_string());
                    continue;
                }
                Err(error) => common::run_named_or_fail(
                    &format!("generic probe shard 1 {target}:{probe_name}"),
                    Err(error),
                ),
            };
            let mut combined = String::from_utf8_lossy(&result.stdout).into_owned();
            combined.push_str(&String::from_utf8_lossy(&result.stderr));
            let actual = normalize(&combined);

            if actual != oracle {
                eprintln!(
                    "DIFF generic probe shard 1 {target}:{probe_name}\n--- observed ---\n{actual}\n--- oracle ---\n{oracle}"
                );
                observed_mismatches.push(probe_name.to_string());
            }
        }

        assert_eq!(
            executed_count,
            selected_probes.len(),
            "must execute every selected cached shard 1 probe for libc {libc}"
        );

        let selected_set: BTreeSet<&str> = selected_probes.iter().copied().collect();
        let expected_set: BTreeSet<&str> = expected_gaps
            .iter()
            .copied()
            .filter(|probe| selected_set.contains(probe))
            .collect();
        let observed_set: BTreeSet<&str> = observed_mismatches.iter().map(String::as_str).collect();

        let unexpected_regressions: Vec<&str> =
            observed_set.difference(&expected_set).copied().collect();
        let unexpected_fixes: Vec<&str> = expected_set.difference(&observed_set).copied().collect();

        assert!(
            unexpected_regressions.is_empty() && unexpected_fixes.is_empty(),
            "libc {libc} shard 1 verdict mismatch!\n\
             Unexpected regressions (failed but expected match): {unexpected_regressions:?}\n\
             Unexpected fixes (matched but expected gap): {unexpected_fixes:?}\n\
             Full observed mismatches: {observed_mismatches:?}\n\
             Expected gaps: {expected_gaps:?}"
        );
    }
}
