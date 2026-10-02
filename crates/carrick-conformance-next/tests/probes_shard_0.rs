//! In-process conformance probe test suite for generic probe shard 0.
//!
//! Migrates shard 0 of generic conformance probes from
//! `crates/carrick-cli/tests/conformance.rs` into an in-process integration test
//! using `carrick-embed`'s `TestContainer` without invoking `carrick run` or `std::process::Command`.
//!
//! Run host-only verification via:
//!   cargo test -p carrick-conformance-next --test probes_shard_0
//!
//! Run signed guest verification via:
//!   just test-conformance-next generic_probe_shard_0 --nocapture
//! or:
//!   ./scripts/test-signed.sh carrick-conformance-next generic_probe_shard_0 --nocapture
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::SHARD_0_PROBES;
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

fn cached_shard_0_probe_count() -> usize {
    SHARD_0_PROBES
        .iter()
        .filter(|name| common::runs_in_cached_lane(name))
        .count()
}

/// Derive the shard 0 subset from a complete baseline set.
pub fn expected_shard_gaps(baseline: &[&'static str]) -> BTreeSet<&'static str> {
    let shard_set: BTreeSet<&str> = SHARD_0_PROBES.iter().copied().collect();
    baseline
        .iter()
        .copied()
        .filter(|probe| shard_set.contains(probe))
        .collect()
}

/// Drop carrick's scratch warning so output lines up with Docker's.
/// Exact match of the old normalize function in `crates/carrick-cli/tests/conformance.rs`.
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
/// Matches `probe_src_hash` in `crates/carrick-cli/tests/conformance.rs`.
pub fn probe_src_hash(repo_root: &Path, name: &str) -> String {
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
/// Fails with a descriptive error if missing or if the source hash has drifted.
pub fn cached_probe_oracle(
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
pub fn diff_lines(carrick: &str, oracle: &str) -> Option<String> {
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

/// Locate probe directory for a target triple.
pub fn find_probe_binary_dir(repo_root: &Path, target: &str) -> Option<PathBuf> {
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

// ---------------------------------------------------------------------------
// Host-only verification tests
// ---------------------------------------------------------------------------

#[test]
fn test_shard_0_inventory() {
    let mut sorted_probes = SHARD_0_PROBES.to_vec();
    sorted_probes.sort_unstable();
    assert_eq!(
        SHARD_0_PROBES,
        sorted_probes.as_slice(),
        "SHARD_0_PROBES must be strictly sorted"
    );

    let unique_probes: BTreeSet<_> = SHARD_0_PROBES.iter().copied().collect();
    assert_eq!(
        unique_probes.len(),
        SHARD_0_PROBES.len(),
        "SHARD_0_PROBES must contain unique names"
    );
    assert_eq!(
        SHARD_0_PROBES
            .iter()
            .filter(|name| common::runs_in_cached_lane(name))
            .count(),
        cached_shard_0_probe_count(),
        "shard 0 cached probe count must match derived policy"
    );

    // Independently verify against conformance-probes/probe-inventory.json
    let repo_root = common::repo_root();
    let inv_path = repo_root.join("conformance-probes/probe-inventory.json");
    let inventory = carrick_xtask::probe_inventory::load_inventory(&inv_path)
        .expect("read and parse probe inventory");
    let partition = carrick_xtask::probe_inventory::derive_partition(&inventory);
    let derived_shard_0: Vec<&str> = partition.shards[0].iter().map(String::as_str).collect();

    assert_eq!(
        SHARD_0_PROBES.len(),
        derived_shard_0.len(),
        "shard 0 length must match derived shard 0 from probe-inventory.json"
    );
    assert_eq!(
        SHARD_0_PROBES,
        derived_shard_0.as_slice(),
        "SHARD_0_PROBES must match the derived shard 0 from probe-inventory.json"
    );
}

#[test]
fn test_shard_0_generation_responds_to_additions() {
    let repo_root = common::repo_root();
    let inv_path = repo_root.join("conformance-probes/probe-inventory.json");
    let mut inventory =
        carrick_xtask::probe_inventory::load_inventory(&inv_path).expect("read probe inventory");

    let initial_partition = carrick_xtask::probe_inventory::derive_partition(&inventory);
    let initial_shard_0_len = initial_partition.shards[0].len();
    let initial_total = initial_partition.generic_names.len();

    let pad_count = (3 - (initial_total % 3)) % 3;
    for i in 0..pad_count {
        inventory.insert(
            format!("zzz_pad_{i}"),
            carrick_xtask::probe_inventory::ProbeInventoryRow {
                class: "conformance".to_string(),
                runner: "generic".to_string(),
                excluded: false,
                contract_ids: None,
            },
        );
    }
    let target_probe = "zzz_synthetic_probe_for_shard_0".to_string();
    inventory.insert(
        target_probe.clone(),
        carrick_xtask::probe_inventory::ProbeInventoryRow {
            class: "conformance".to_string(),
            runner: "generic".to_string(),
            excluded: false,
            contract_ids: None,
        },
    );

    let updated_partition = carrick_xtask::probe_inventory::derive_partition(&inventory);
    assert_eq!(
        updated_partition.generic_names.len(),
        initial_total + pad_count + 1,
        "total generic probes must increment by added count"
    );
    assert_eq!(
        updated_partition.shards[0].len(),
        initial_shard_0_len + 1,
        "shard 0 must expand by 1"
    );
    assert!(
        updated_partition.shards[0].contains(&target_probe),
        "target probe must be in shard 0"
    );
}

#[test]
fn test_shard_0_expected_gaps_derivation() {
    let musl_shard_gaps = expected_shard_gaps(common::MUSL_BASELINE_GAPS);
    let gnu_shard_gaps = expected_shard_gaps(common::GNU_BASELINE_GAPS);

    let shard_set: BTreeSet<&str> = SHARD_0_PROBES.iter().copied().collect();
    let expected_musl_set: BTreeSet<&str> = common::MUSL_BASELINE_GAPS
        .iter()
        .copied()
        .filter(|p| shard_set.contains(p))
        .collect();
    let expected_gnu_set: BTreeSet<&str> = common::GNU_BASELINE_GAPS
        .iter()
        .copied()
        .filter(|p| shard_set.contains(p))
        .collect();

    assert_eq!(
        musl_shard_gaps, expected_musl_set,
        "musl shard 0 gaps must match derived intersection"
    );
    assert_eq!(
        gnu_shard_gaps, expected_gnu_set,
        "gnu shard 0 gaps must match derived intersection"
    );
}

#[test]
fn test_normalization() {
    let input = "line 1\ncase-insensitive; defaulting to memory fs\nline 2   \nPass `--fs host` to use host fs\nline 3\n\n";
    let normalized = normalize(input);
    assert_eq!(normalized, "line 1\nline 2\nline 3");

    let clean = "clean\noutput\n";
    assert_eq!(normalize(clean), "clean\noutput");

    let empty = "";
    assert_eq!(normalize(empty), "");
}

#[test]
fn test_cache_freshness_and_hashing() {
    let repo_root = common::repo_root();

    // Fingerprint of a non-existent probe source is sentinel "nosrc".
    assert_eq!(
        probe_src_hash(&repo_root, "__definitely_nonexistent_probe__"),
        "nosrc"
    );

    // Any probe source that exists must have a 16-hex-digit fingerprint.
    let abortdeath_hash = probe_src_hash(&repo_root, "abortdeath");
    assert_eq!(abortdeath_hash.len(), 16);
    assert!(abortdeath_hash.chars().all(|c| c.is_ascii_hexdigit()));

    // Verify shard 0 cached entries under arm64-musl match their source hashes.
    for probe_name in [
        "fifoforkeof",
        "futexshare",
        "ptyforkreopen",
        "syscallregpreserve",
    ] {
        let cached = cached_probe_oracle(&repo_root, "arm64", "musl", probe_name);
        assert!(
            cached.is_ok(),
            "cached oracle for arm64-musl/{probe_name} must be fresh: {:?}",
            cached.err()
        );
        let content = cached.unwrap();
        assert_eq!(content, normalize(&content));
    }

    let dsr = cached_probe_oracle(&repo_root, "arm64", "musl", "dsrconstantpool")
        .expect("freshly blessed dsrconstantpool cache must match its source");
    assert!(dsr.contains("constant_word_match=true"));

    // Verify error messages on missing cache queries.
    let missing_err = cached_probe_oracle(&repo_root, "arm64", "musl", "__nonexistent__")
        .expect_err("missing cache entry must return Err");
    assert!(
        missing_err.contains("missing oracle cache for probe \"__nonexistent__\""),
        "error message must clearly state missing oracle cache: {missing_err}"
    );
}

#[test]
fn test_shard_0_cached_oracles_are_complete() {
    let repo_root = common::repo_root();
    for libc in ["musl", "gnu"] {
        for probe in SHARD_0_PROBES
            .iter()
            .copied()
            .filter(|name| common::runs_in_cached_lane(name))
        {
            cached_probe_oracle(&repo_root, "arm64", libc, probe).unwrap_or_else(|error| {
                panic!("arm64-{libc}/{probe} must have a fresh committed oracle: {error}")
            });
        }
    }
}

#[test]
fn test_probe_binary_locator_and_gap_counts() {
    let repo_root = common::repo_root();

    // A non-existent target should return None.
    assert_eq!(
        find_probe_binary_dir(&repo_root, "__nonexistent_target_arch__"),
        None
    );

    // Hard-assert the exact number of derived shard 0 baseline gaps.
    let musl_shard_gaps = expected_shard_gaps(common::MUSL_BASELINE_GAPS);
    let gnu_shard_gaps = expected_shard_gaps(common::GNU_BASELINE_GAPS);
    assert_eq!(
        musl_shard_gaps.len(),
        0,
        "musl shard 0 must contain exactly 0 baseline gap"
    );
    assert_eq!(
        gnu_shard_gaps.len(),
        0,
        "gnu shard 0 must contain exactly 0 baseline gap"
    );
}

// ---------------------------------------------------------------------------
// Signed guest execution test
// ---------------------------------------------------------------------------

#[test]
fn generic_probe_shard_0() {
    let _guard = common::guest_lock();
    let root = common::repo_root();
    let requested_filter = std::env::var("CARRICK_PROBE_FILTER").ok();
    let selected_probes = common::select_cached_probes(SHARD_0_PROBES, requested_filter.as_deref());
    let selected_set: BTreeSet<&str> = selected_probes.iter().copied().collect();

    let targets = [
        ("aarch64-unknown-linux-musl", "musl"),
        ("aarch64-unknown-linux-gnu", "gnu"),
    ];

    for (target, libc) in targets {
        let expected_gaps: BTreeSet<&str> = match libc {
            "musl" => expected_shard_gaps(common::MUSL_BASELINE_GAPS),
            "gnu" => expected_shard_gaps(common::GNU_BASELINE_GAPS),
            _ => unreachable!(),
        }
        .intersection(&selected_set)
        .copied()
        .collect();

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

        let mut observed_mismatches = BTreeSet::new();
        let mut diff_details = Vec::new();
        let mut executed_count = 0usize;

        for probe_name in &selected_probes {
            eprintln!("RUN generic probe shard 0 {target}:{probe_name}");
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

            let container = common::generic_probe_container(probe_name, &probe_path, &init_path);

            let outcome = common::timed_probe_run(
                &format!("generic probe shard 0 {target}:{probe_name}"),
                || common::with_empty_stdin_pipe(|| container.run(["/tmp/carrick-init"])),
            );
            let result = common::run_named_or_fail(
                &format!("generic probe shard 0 {target}:{probe_name}"),
                outcome,
            );
            executed_count += 1;

            let mut combined = String::from_utf8_lossy(&result.stdout).into_owned();
            combined.push_str(&String::from_utf8_lossy(&result.stderr));
            let normalized_carrick = normalize(&combined);

            if let Some(diff) = diff_lines(&normalized_carrick, &cached_oracle) {
                // Announce the mismatch as shards 1 and 2 do. Shard 0 used to
                // surface a diff only inside the assertion message, so an
                // EXPECTED gap left no trace in the log at all and the gate
                // read as if every shard-0 probe matched.
                eprintln!("DIFF generic probe shard 0 {target}:{probe_name}");
                eprintln!(
                    "guest termination: exit_code={} signal={:?} trap_limit_hit={} terminal_reason={:?} traps={}",
                    result.exit_code,
                    result.signal,
                    result.trap_limit_hit,
                    result.terminal_reason,
                    result.traps,
                );
                eprintln!(
                    "--- observed ---\n{normalized_carrick}\n--- oracle ---\n{cached_oracle}"
                );
                observed_mismatches.insert(*probe_name);
                diff_details.push(format!("{probe_name}:\n{diff}"));
            }
        }

        assert_eq!(
            executed_count,
            selected_probes.len(),
            "must execute every selected cached shard 0 probe for target {target}, executed {executed_count}"
        );

        let unexpected_failures: BTreeSet<_> = observed_mismatches
            .difference(&expected_gaps)
            .copied()
            .collect();
        let unexpected_passes: BTreeSet<_> = expected_gaps
            .difference(&observed_mismatches)
            .copied()
            .collect();

        assert!(
            unexpected_failures.is_empty() && unexpected_passes.is_empty(),
            "probe shard 0 verdict mismatch for {target}:\n\
             unexpected failures (new regressions): {unexpected_failures:?}\n\
             unexpected passes (fixed gaps — update baseline): {unexpected_passes:?}\n\
             diffs:\n{}",
            diff_details.join("\n")
        );
    }
}

/// M5 EL0 frame bindings: reuse source-valid cached Linux oracles and the
/// probeinit fork/exec topology. These are semantic witnesses, not proof of
/// EL1 frame ownership. No new subprocess or executable probe is introduced.
#[test]
fn m5_el0_nested_altstack_and_fault_frame_bindings() {
    let _guard = common::guest_lock();
    let root = common::repo_root();
    for (target, libc) in [
        ("aarch64-unknown-linux-musl", "musl"),
        ("aarch64-unknown-linux-gnu", "gnu"),
    ] {
        let dir = find_probe_binary_dir(&root, target).expect("freshly built frame probes");
        let init = dir.join("probeinit");
        assert!(init.is_file());
        for probe in [
            "sigreenter",
            "siglongjmpaltstack",
            "sigbadstack",
            "preemptsigstorm",
        ] {
            let binary = dir.join(probe);
            assert!(binary.is_file(), "missing {target}:{probe}");
            let oracle = cached_probe_oracle(&root, "arm64", libc, probe).unwrap();
            let result = common::run_named_or_fail(
                probe,
                common::with_empty_stdin_pipe(|| {
                    common::generic_probe_container(probe, &binary, &init)
                        .run(["/tmp/carrick-init"])
                }),
            );
            assert!(
                result.success(),
                "{target}:{probe}: exit={} signal={:?}",
                result.exit_code,
                result.signal
            );
            let mut output = result.stdout_utf8();
            output.push_str(&String::from_utf8_lossy(&result.stderr));
            assert_eq!(normalize(&output), oracle, "{target}:{probe}");
        }
    }
}
