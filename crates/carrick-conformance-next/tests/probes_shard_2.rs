//! Conformance probes shard 2 in-process integration test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::SHARD_2_PROBES;
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

const CACHED_SHARD_2_PROBE_COUNT: usize = 138;

/// Derive the shard expected gap subset from the complete baseline gap set.
pub fn expected_gaps_for_shard(baseline: &[&'static str]) -> BTreeSet<&'static str> {
    let shard_set: BTreeSet<&str> = SHARD_2_PROBES.iter().copied().collect();
    baseline
        .iter()
        .copied()
        .filter(|gap| {
            shard_set.contains(gap)
                && common::runs_in_cached_lane(gap)
                && common::probe_filter_allows(gap)
        })
        .collect()
}

/// Drop carrick scratch warnings and trailing whitespace so output matches the oracle.
pub fn normalize(s: &str) -> String {
    s.lines()
        .filter(|l| !l.contains("case-insensitive; defaulting") && !l.contains("Pass `--fs host`"))
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_string()
}

/// Compute the stable DefaultHasher fingerprint of a probe's source file.
pub fn probe_src_hash(repo_root: &Path, name: &str) -> String {
    let src_path = repo_root.join(format!("conformance-probes/src/bin/{name}.rs"));
    match std::fs::read(&src_path) {
        Ok(bytes) => {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            bytes.hash(&mut h);
            format!("{:016x}", h.finish())
        }
        Err(_) => "nosrc".to_string(),
    }
}

/// Load and validate the committed cached oracle output for a probe and libc flavor.
pub fn cached_probe_oracle(repo_root: &Path, libc: &str, name: &str) -> Result<String, String> {
    let cache_path = repo_root.join(format!(
        "crates/carrick-cli/tests/probe-oracle/arm64-{libc}/{name}"
    ));
    let raw = std::fs::read_to_string(&cache_path).map_err(|e| {
        format!(
            "missing cached probe oracle for {name} ({libc}) at {}: {e}",
            cache_path.display()
        )
    })?;
    let (hash_line, body) = raw.split_once('\n').ok_or_else(|| {
        format!(
            "malformed cached probe oracle for {name} ({libc}) at {}: missing newline after hash header",
            cache_path.display()
        )
    })?;
    let expected_hash = probe_src_hash(repo_root, name);
    if hash_line != expected_hash {
        return Err(format!(
            "stale cached probe oracle for {name} ({libc}) at {}: expected hash {expected_hash}, found {hash_line}",
            cache_path.display()
        ));
    }
    Ok(normalize(body))
}

/// Locate probe binaries directory if built.
pub fn probe_campaign_dir(repo_root: &Path, target: &str) -> Option<PathBuf> {
    let p1 = repo_root
        .join("conformance-probes/target")
        .join(target)
        .join("release");
    if p1.exists() {
        return Some(p1);
    }
    let p2 = repo_root.join("target").join(target).join("release");
    if p2.exists() {
        return Some(p2);
    }
    None
}

// ---------------------------------------------------------------------------
// Host-only tests
// ---------------------------------------------------------------------------

#[test]
fn test_shard_2_inventory_definition() {
    // 1. Hard-assert exactly 151 sorted unique names.
    assert_eq!(
        SHARD_2_PROBES.len(),
        151,
        "shard 2 must contain exactly 151 probes"
    );
    let probe_set: BTreeSet<&str> = SHARD_2_PROBES.iter().copied().collect();
    assert_eq!(
        probe_set.len(),
        151,
        "SHARD_2_PROBES must contain 151 unique names"
    );
    for window in SHARD_2_PROBES.windows(2) {
        assert!(
            window[0] < window[1],
            "shard 2 probes list must be strictly sorted: {} >= {}",
            window[0],
            window[1]
        );
    }
    assert_eq!(
        SHARD_2_PROBES
            .iter()
            .filter(|name| common::runs_in_cached_lane(name))
            .count(),
        CACHED_SHARD_2_PROBE_COUNT
    );

    // 2. Validate against probe-inventory.json
    let repo_root = common::repo_root();
    let inventory_path = repo_root.join("conformance-probes/probe-inventory.json");
    let content = std::fs::read_to_string(&inventory_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", inventory_path.display()));

    // Parse probe-inventory.json entries
    let mut generic_conformance_probes = Vec::new();

    for chunk in content.split("\n  \"") {
        let Some((name_part, rest)) = chunk.split_once("\": {") else {
            continue;
        };
        let name = name_part.trim_matches(|c| c == '\"' || c == ' ' || c == '\n' || c == '{');
        if name.is_empty() {
            continue;
        }
        let is_conformance = rest.contains("\"class\": \"conformance\"");
        let is_not_excluded = rest.contains("\"excluded\": false");
        let is_generic_runner = rest.contains("\"runner\": \"generic\"");

        if is_conformance && is_not_excluded && is_generic_runner {
            generic_conformance_probes.push(name.to_string());
        }
    }

    generic_conformance_probes.sort();
    generic_conformance_probes.dedup();
    assert_eq!(
        generic_conformance_probes.len(),
        455,
        "expected exactly 455 generic conformance probes across all shards"
    );

    let derived_shard_2: Vec<&str> = generic_conformance_probes
        .iter()
        .enumerate()
        .filter(|(idx, _)| idx % 3 == 2)
        .map(|(_, name)| name.as_str())
        .collect();

    assert_eq!(
        derived_shard_2.len(),
        151,
        "derived shard 2 must have 151 items"
    );
    assert_eq!(
        derived_shard_2.as_slice(),
        SHARD_2_PROBES,
        "materialized SHARD_2_PROBES must match probe-inventory.json derived shard 2"
    );
}

#[test]
fn test_shard_2_cache_freshness() {
    let repo_root = common::repo_root();

    // Verify all existing committed cache entries in arm64-{musl,gnu} belonging to shard 2
    let mut verified = 0;
    for &libc in &["musl", "gnu"] {
        let dir = repo_root.join(format!(
            "crates/carrick-cli/tests/probe-oracle/arm64-{libc}"
        ));
        if !dir.exists() {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_file() {
                continue;
            }
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if SHARD_2_PROBES.contains(&name_str.as_ref()) {
                let oracle_res = cached_probe_oracle(&repo_root, libc, &name_str);
                assert!(
                    oracle_res.is_ok(),
                    "cache validation failed for probe '{name_str}' ({libc}): {}",
                    oracle_res.err().unwrap()
                );
                verified += 1;
            }
        }
    }

    assert!(
        verified > 0,
        "expected at least one committed shard 2 oracle in arm64-{{musl,gnu}} to verify"
    );

    // Verify specific known committed probe oracle
    let mmap_oracle = cached_probe_oracle(&repo_root, "musl", "mmapfileforkwriteback");
    assert!(
        mmap_oracle.is_ok(),
        "mmapfileforkwriteback oracle should be valid: {:?}",
        mmap_oracle.err()
    );
    assert!(mmap_oracle.unwrap().contains("file_saw_parent_post=true"));

    // Verify missing cache error behavior
    let missing = cached_probe_oracle(&repo_root, "musl", "nonexistent_probe_xyz");
    assert!(missing.is_err());
    assert!(missing.unwrap_err().contains("missing cached probe oracle"));
}

#[test]
fn test_shard_2_cached_oracles_are_complete() {
    let repo_root = common::repo_root();
    for libc in ["musl", "gnu"] {
        for probe in SHARD_2_PROBES
            .iter()
            .copied()
            .filter(|name| common::runs_in_cached_lane(name))
        {
            cached_probe_oracle(&repo_root, libc, probe).unwrap_or_else(|error| {
                panic!("arm64-{libc}/{probe} must have a fresh committed oracle: {error}")
            });
        }
    }
}

#[test]
fn test_normalization_rules() {
    let input = "hello world  \ncase-insensitive; defaulting to something\nPass `--fs host` to avoid\nline 2   \n\n";
    let normalized = normalize(input);
    assert_eq!(normalized, "hello world\nline 2");

    let clean = "clean output\nsecond line";
    assert_eq!(normalize(clean), "clean output\nsecond line");
}

// ---------------------------------------------------------------------------
// Signed guest test
// ---------------------------------------------------------------------------

#[test]
fn generic_probe_shard_2() {
    let _guard = common::guest_lock();
    let repo_root = common::repo_root();
    let requested_filter = std::env::var("CARRICK_PROBE_FILTER").ok();
    let selected_probes = common::select_cached_probes(SHARD_2_PROBES, requested_filter.as_deref());
    let selected_set: BTreeSet<&str> = selected_probes.iter().copied().collect();

    let targets = [
        (
            "aarch64-unknown-linux-musl",
            "musl",
            expected_gaps_for_shard(common::MUSL_BASELINE_GAPS),
        ),
        (
            "aarch64-unknown-linux-gnu",
            "gnu",
            expected_gaps_for_shard(common::GNU_BASELINE_GAPS),
        ),
    ];

    for (target_triple, libc, expected_gaps) in targets {
        let expected_gaps: BTreeSet<&str> =
            expected_gaps.intersection(&selected_set).copied().collect();
        let dir = probe_campaign_dir(&repo_root, target_triple).unwrap_or_else(|| {
            panic!("probes directory not found for {target_triple} — run scripts/build-probes.sh")
        });

        let probeinit_path = dir.join("probeinit");
        assert!(
            probeinit_path.is_file(),
            "probeinit transport helper missing at {} — run scripts/build-probes.sh",
            probeinit_path.display()
        );

        let mut observed_mismatches = BTreeSet::new();
        let mut executed_count = 0;

        for &probe_name in &selected_probes {
            let probe_path = dir.join(probe_name);
            assert!(
                probe_path.is_file(),
                "probe binary missing for {probe_name} at {} — run scripts/build-probes.sh",
                probe_path.display()
            );

            let expected_oracle = cached_probe_oracle(&repo_root, libc, probe_name)
                .unwrap_or_else(|err| panic!("{err}"));

            let container =
                common::generic_probe_container(probe_name, &probe_path, &probeinit_path);

            eprintln!("RUN generic probe shard 2 {target_triple}:{probe_name}");
            let outcome = common::with_empty_stdin_pipe(|| container.run(["/tmp/carrick-init"]));
            let result = common::run_named_or_fail(
                &format!("generic probe shard 2 {target_triple}:{probe_name}"),
                outcome,
            );

            let mut combined = result.stdout_utf8();
            combined.push_str(&result.stderr_utf8());
            let observed = normalize(&combined);

            if observed != expected_oracle {
                eprintln!(
                    "DIFF generic probe shard 2 {target_triple}:{probe_name}\n--- observed ---\n{observed}\n--- oracle ---\n{expected_oracle}"
                );
                observed_mismatches.insert(probe_name);
            }
            executed_count += 1;
        }

        assert_eq!(executed_count, selected_probes.len());

        assert_eq!(
            observed_mismatches,
            expected_gaps,
            "mismatch set divergence for {target_triple} (libc={libc}): \
             unexpected failures: {:?}, unexpected passes (fixed gaps): {:?}",
            observed_mismatches
                .difference(&expected_gaps)
                .collect::<Vec<_>>(),
            expected_gaps
                .difference(&observed_mismatches)
                .collect::<Vec<_>>()
        );
    }
}
