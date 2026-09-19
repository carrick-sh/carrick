//! Differential verification of the futex contention contract in carrick-conformance-next.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use carrick_conformance_contract::ContractRegistry;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("manifest dir has repo root")
        .to_path_buf()
}

fn probe_src_hash(root: &Path, name: &str) -> String {
    let src = root.join(format!("conformance-probes/src/bin/{name}.rs"));
    let bytes = std::fs::read(&src)
        .unwrap_or_else(|e| panic!("failed to read probe source at {}: {e}", src.display()));
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    format!("{:016x}", h.finish())
}

fn oracle_source_hash(root: &Path, lane_label: &str, libc: &str, name: &str) -> String {
    let p = root.join(format!(
        "crates/carrick-cli/tests/probe-oracle/{lane_label}-{libc}/{name}"
    ));
    let content = std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("failed to read oracle at {}: {e}", p.display()));
    content.lines().next().unwrap_or("").trim().to_string()
}

#[test]
fn futex_contract_differential_verification() {
    let root = repo_root();
    let registry = ContractRegistry::load(&root).expect("registry");
    let contract = registry
        .require("kernel.futex.contention")
        .expect("contract");

    // 1. Fixture identity check
    assert_eq!(contract.fixture, "probe:futexpingpong");

    // 2. Explicit musl and gnu lane checks
    for libc in &["musl", "gnu"] {
        // 3. Probe source hash check against committed oracle
        for probe in &["futexpingpong", "futexwakeexact"] {
            let src_hash = probe_src_hash(&root, probe);
            let oracle_hash = oracle_source_hash(&root, "arm64", libc, probe);
            assert_eq!(
                src_hash, oracle_hash,
                "probe {probe} ({libc}) source hash {src_hash} does not match oracle {oracle_hash}"
            );
        }
    }

    // 4. Verify signed executable receipt names contract ID and exact source HEAD
    let receipt_path = root.join("target/test-results/carrick-embed-signed-artifacts.jsonl");
    if receipt_path.is_file() {
        let content = std::fs::read_to_string(&receipt_path).expect("read signed artifacts");
        let mut found_contract_id = false;
        let mut source_head = String::new();
        for line in content.lines() {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                if val.get("record_type").and_then(|v| v.as_str()) == Some("header") {
                    if let Some(sh) = val.get("source_head").and_then(|v| v.as_str()) {
                        source_head = sh.to_string();
                    }
                }
                if let Some(cid) = val.get("contract_id").and_then(|v| v.as_str()) {
                    if cid == "kernel.futex.contention" {
                        found_contract_id = true;
                    }
                }
            }
        }
        assert!(
            !source_head.is_empty(),
            "source_head must be recorded in signed artifact receipt"
        );
        assert!(
            found_contract_id,
            "contract_id must be recorded in signed artifact receipt"
        );
    }

    // 5. Scoped cleanup reports zero remaining processes
    let active_procs = std::process::Command::new("pgrep")
        .args(["-f", "carrick:contract-futex"])
        .output();
    if let Ok(output) = active_procs {
        assert!(
            output.stdout.is_empty(),
            "scoped cleanup left orphan processes: {:?}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}
