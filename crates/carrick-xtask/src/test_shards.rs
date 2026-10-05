//! Compare actual recipe selections without building or executing their tests.
//!
//! Equality of the Cargo invocation multiset is deliberately stronger than a
//! list of test names: features, target kinds, filters, serial execution and
//! stack budgets must also match. Whole selections include future tests without
//! maintaining a second test-name inventory. Cargo tree still runs normally so
//! the portable dependency closure remains authoritative.
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use std::os::unix::fs::PermissionsExt;

const CAPTURE: &str = r#"#!/usr/bin/env bash
set -euo pipefail
case "$1" in
    tree) exec "$CARRICK_REAL_CARGO" "$@" ;;
    test)
        { printf '%q ' "RUST_TEST_THREADS=${RUST_TEST_THREADS-}" "RUST_MIN_STACK=${RUST_MIN_STACK-}" "$PWD" "$@"; printf '\n'; } >> "$CARRICK_TEST_CAPTURE"
        ;;
    *) echo "unexpected cargo command during shard capture: $1" >&2; exit 1 ;;
esac
"#;

type Inventory = BTreeMap<String, usize>;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn shard_recipes(root: &Path) -> Result<Vec<String>> {
    let output = Command::new("just")
        .args(["--dump", "--dump-format", "json"])
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "just dump failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let dump: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let recipes = dump["recipes"].as_object().ok_or("missing just recipes")?;
    let shards: Vec<_> = recipes
        .keys()
        .filter(|r| r.starts_with("test-shard-"))
        .cloned()
        .collect();
    if shards.is_empty() {
        return Err("no test-shard-* recipes found".into());
    }
    Ok(shards)
}

pub fn check(root: &Path) -> Result<String> {
    let root = root.canonicalize()?;
    let shards = shard_recipes(&root)?;
    let temp = tempfile::tempdir()?;
    let stub = temp.path().join("cargo");
    std::fs::write(&stub, CAPTURE)?;
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))?;
    let path = std::env::var_os("PATH").ok_or("PATH is unset")?;
    let real_cargo = std::env::split_paths(&path)
        .map(|p| p.join("cargo"))
        .find(|p| p.is_file())
        .ok_or("cargo is unavailable")?;
    let capture_path = std::env::join_paths(
        std::iter::once(temp.path().to_path_buf()).chain(std::env::split_paths(&path)),
    )?;
    let capture = |recipe: &str| -> Result<Inventory> {
        let log = temp.path().join("commands");
        std::fs::write(&log, "")?;
        let output = Command::new("just")
            .arg(recipe)
            .current_dir(&root)
            .env("PATH", &capture_path)
            .env("CARRICK_REAL_CARGO", &real_cargo)
            .env("CARRICK_TEST_CAPTURE", &log)
            .env_remove("RUST_TEST_THREADS")
            .env_remove("RUST_MIN_STACK")
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "recipe {recipe} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        let mut inventory = Inventory::new();
        for line in std::fs::read_to_string(log)?.lines() {
            *inventory.entry(line.to_owned()).or_default() += 1;
        }
        Ok(inventory)
    };
    let expected = capture("test")?;
    if expected.is_empty() {
        return Err("unsharded test recipe selected no Cargo tests".into());
    }
    let mut actual = Inventory::new();
    for shard in &shards {
        for (command, count) in capture(shard)? {
            *actual.entry(command).or_default() += count;
        }
    }
    if expected != actual {
        let mut differences = Vec::new();
        for command in expected
            .keys()
            .chain(actual.keys())
            .collect::<std::collections::BTreeSet<_>>()
        {
            let want = expected.get(command).copied().unwrap_or_default();
            let got = actual.get(command).copied().unwrap_or_default();
            if want != got {
                differences.push(format!("unsharded={want} shards={got}: {command}"));
            }
        }
        return Err(format!("shard coverage differs:\n{}", differences.join("\n")).into());
    }
    Ok(format!(
        "{}: {} Cargo selections match just test exactly on {} (filters, features, serial threads and stack budgets included)",
        shards.join(", "),
        expected.values().sum::<usize>(),
        std::env::consts::OS
    ))
}
