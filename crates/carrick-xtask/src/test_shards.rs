//! Compare actual recipe selections without building or executing their tests.
//!
//! Equality of the Cargo invocation multiset is deliberately stronger than a
//! list of test names: features, target kinds, filters, serial execution and
//! stack budgets must also match. Whole selections include future tests without
//! maintaining a second test-name inventory. Cargo tree still runs normally so
//! the portable dependency closure remains authoritative.
//!
//! In addition to the Cargo invocation multiset, `check-test-shards` resolves
//! per-binary compile-time feature sets across each compilation unit (including
//! `test-batch` unifications and workspace `dev-dependencies`) and verifies that
//! every test binary's feature set in the shards matches `just test`.
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

// Compiler relinks may unlink the pathname of this still-running executable.
// The capture owns a private copy for its entire child-process lifetime.
fn snapshot_xtask(directory: &Path) -> Result<std::path::PathBuf> {
    #[cfg(target_os = "linux")]
    let source = std::path::PathBuf::from("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let source = std::env::current_exe()?;
    let snapshot = directory.join("xtask");
    std::fs::copy(source, &snapshot)?;
    Ok(snapshot)
}

const CAPTURE: &str = r#"#!/usr/bin/env bash
set -euo pipefail

subcmd=""
prev=""
for arg in "$@"; do
    if [ "$prev" = "--config" ] || [ "$prev" = "-Z" ] || [ "$prev" = "--color" ] || [ "$prev" = "--message-format" ] || [ "$prev" = "--manifest-path" ]; then
        prev=""
        continue
    fi
    case "$arg" in
        --config|-Z|--color|--message-format|--manifest-path)
            prev="$arg"
            ;;
        --config=*)
            ;;
        -*)
            ;;
        *)
            subcmd="$arg"
            break
            ;;
    esac
done

case "$subcmd" in
    run)
        if [ -n "${CARRICK_TEST_XTASK-}" ]; then
            while [ "$1" != "--" ]; do shift; done
            shift
            exec "$CARRICK_TEST_XTASK" "$@"
        fi
        exec "$CARRICK_REAL_CARGO" "$@"
        ;;
    tree)
        exec "$CARRICK_REAL_CARGO" "$@"
        ;;
    test)
        { printf '%q ' "RUST_TEST_THREADS=${RUST_TEST_THREADS-}" "RUST_MIN_STACK=${RUST_MIN_STACK-}" "$PWD" "$@"; printf '\n'; } >> "$CARRICK_TEST_CAPTURE"
        if [ -n "${CARRICK_TEST_RECORDS-}" ]; then
            printf '%s\0' "${RUST_TEST_THREADS-}" "${RUST_MIN_STACK-}" "$PWD" "$@" >> "$CARRICK_TEST_RECORDS"
            printf '\0' >> "$CARRICK_TEST_RECORDS"
        fi
        if [ -n "${CARRICK_TEST_BATCH_RECORDS-}" ]; then
            printf '%s\0' "${CARRICK_TEST_BATCH_UNIT-}" "${RUST_TEST_THREADS-}" "${RUST_MIN_STACK-}" "$PWD" "$@" >> "$CARRICK_TEST_BATCH_RECORDS"
            printf '\0' >> "$CARRICK_TEST_BATCH_RECORDS"
        fi
        ;;
    *)
        echo "unexpected cargo command during shard capture: $subcmd (args: $*)" >&2
        exit 1
        ;;
esac
"#;

/// Capture the existing recipe as structured argv, without compiling its tests.
pub fn records(root: &Path, recipe: &str, args: &[String]) -> Result<Vec<Vec<String>>> {
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
    let log = temp.path().join("records");
    let status = Command::new("just")
        .arg(recipe)
        .args(args)
        .current_dir(root)
        .env("PATH", capture_path)
        .env("CARRICK_REAL_CARGO", real_cargo)
        .env("CARRICK_TEST_CAPTURE", temp.path().join("commands"))
        .env("CARRICK_TEST_RECORDS", &log)
        .env("CARRICK_TEST_XTASK", snapshot_xtask(temp.path())?)
        .status()?;
    if !status.success() {
        return Err(format!("capture {recipe} failed").into());
    }
    parse_null_delimited_records(&std::fs::read(log)?, 3)
}

fn parse_null_delimited_records(data: &[u8], min_fields: usize) -> Result<Vec<Vec<String>>> {
    let fields: Vec<_> = data.split(|b| *b == 0).collect();
    let mut records = Vec::new();
    let mut offset = 0;
    while offset + min_fields < fields.len() {
        let end = (offset + min_fields..fields.len())
            .find(|i| fields[*i].is_empty())
            .ok_or("unterminated Cargo record")?;
        records.push(
            fields[offset..end]
                .iter()
                .map(|f| String::from_utf8(f.to_vec()))
                .collect::<std::result::Result<Vec<_>, _>>()?,
        );
        offset = end + 1;
    }
    Ok(records)
}

type Inventory = BTreeMap<String, usize>;
type BinaryFeatureInventory = BTreeMap<String, Vec<BTreeSet<String>>>;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Clone)]
struct ParsedRecord {
    packages: BTreeSet<String>,
    targets: BTreeSet<(String, String, String)>,
    features: BTreeSet<String>,
    no_default: bool,
    doc: bool,
    harness: Vec<String>,
}

fn load_workspace_metadata(root: &Path, real_cargo: &Path) -> Result<Option<Value>> {
    if !root.join("Cargo.toml").is_file() {
        return Ok(None);
    }
    let out = Command::new(real_cargo)
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(root)
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(Some(serde_json::from_slice(&out.stdout)?))
}

fn parse_record_selection(record: &[String], meta: Option<&Value>) -> Result<ParsedRecord> {
    let start = record
        .iter()
        .skip(3)
        .position(|s| s == "test")
        .ok_or("missing cargo test")?
        + 4;
    let mut parsed = ParsedRecord {
        packages: BTreeSet::new(),
        targets: BTreeSet::new(),
        features: BTreeSet::new(),
        no_default: false,
        doc: false,
        harness: Vec::new(),
    };
    let mut excludes = BTreeSet::new();
    let mut kinds = BTreeSet::new();
    let mut explicit_targets = BTreeSet::new();
    let mut workspace = false;
    let mut i = start;
    while i < record.len() {
        let arg = &record[i];
        match arg.as_str() {
            "--" => {
                parsed.harness.extend_from_slice(&record[i + 1..]);
                break;
            }
            "-p" | "--package" | "--exclude" | "--test" | "--bin" | "--features"
            | "--target-dir" => {
                i += 1;
                let value = record.get(i).ok_or("missing option value")?;
                match arg.as_str() {
                    "-p" | "--package" => {
                        parsed.packages.insert(value.clone());
                    }
                    "--exclude" => {
                        excludes.insert(value.clone());
                    }
                    "--test" => {
                        explicit_targets.insert(("test".to_owned(), value.clone()));
                    }
                    "--bin" => {
                        explicit_targets.insert(("bin".to_owned(), value.clone()));
                    }
                    "--target-dir" => {}
                    _ => {
                        parsed.features.extend(
                            value
                                .split([',', ' '])
                                .filter(|s| !s.is_empty())
                                .map(str::to_owned),
                        );
                    }
                }
            }
            "--workspace" => workspace = true,
            "--lib" => {
                kinds.insert("lib".to_owned());
            }
            "--bins" => {
                kinds.insert("bin".to_owned());
            }
            "--tests" => {
                kinds.extend(["lib".to_owned(), "bin".to_owned(), "test".to_owned()]);
            }
            "--doc" => parsed.doc = true,
            "--no-default-features" => parsed.no_default = true,
            "--no-run" | "--locked" | "--no-fail-fast" => {}
            s if !s.starts_with('-') => parsed.harness.push(arg.clone()),
            _ => {}
        }
        i += 1;
    }

    if let Some(meta) = meta {
        let packages = meta["packages"]
            .as_array()
            .ok_or("missing metadata packages")?;
        if workspace || parsed.packages.is_empty() {
            let members = if workspace {
                &meta["workspace_members"]
            } else {
                &meta["workspace_default_members"]
            };
            for pkg in packages {
                if members
                    .as_array()
                    .is_some_and(|ids| ids.contains(&pkg["id"]))
                {
                    parsed
                        .packages
                        .insert(pkg["name"].as_str().ok_or("missing name")?.to_owned());
                }
            }
        }
        parsed.packages.retain(|p| !excludes.contains(p));
        for pkg in packages {
            let pkg_name = pkg["name"].as_str().ok_or("missing name")?;
            if !parsed.packages.contains(pkg_name) {
                continue;
            }
            if parsed.doc {
                parsed
                    .targets
                    .insert((pkg_name.to_owned(), "doc".to_owned(), pkg_name.to_owned()));
                continue;
            }
            for target in pkg["targets"].as_array().ok_or("missing targets")? {
                let kind = target["kind"][0].as_str().ok_or("missing target kind")?;
                let name = target["name"].as_str().ok_or("missing target name")?;
                if target["test"].as_bool() == Some(true)
                    && ((kinds.is_empty()
                        && explicit_targets.is_empty()
                        && matches!(kind, "lib" | "bin" | "test"))
                        || kinds.contains(kind)
                        || explicit_targets.contains(&(kind.to_owned(), name.to_owned())))
                {
                    parsed
                        .targets
                        .insert((pkg_name.to_owned(), kind.to_owned(), name.to_owned()));
                }
            }
        }
    } else {
        if parsed.packages.is_empty() {
            parsed.packages.insert("workspace".to_owned());
        }
        parsed.packages.retain(|p| !excludes.contains(p));
        for pkg_name in &parsed.packages {
            if parsed.doc {
                parsed
                    .targets
                    .insert((pkg_name.clone(), "doc".to_owned(), pkg_name.clone()));
            } else if !explicit_targets.is_empty() {
                for (kind, name) in &explicit_targets {
                    parsed
                        .targets
                        .insert((pkg_name.clone(), kind.clone(), name.clone()));
                }
            } else if !kinds.is_empty() {
                for kind in &kinds {
                    parsed
                        .targets
                        .insert((pkg_name.clone(), kind.clone(), pkg_name.clone()));
                }
            } else {
                parsed
                    .targets
                    .insert((pkg_name.clone(), "all".to_owned(), pkg_name.clone()));
            }
        }
    }
    Ok(parsed)
}

fn target_matches_host(target: Option<&str>, host: &str) -> bool {
    let Some(target) = target else {
        return true;
    };
    if target == "cfg(not(target_os = \"none\"))" {
        return true;
    }
    if target.contains("target_os =") && !target.contains("not(") {
        return target.contains(&format!("target_os = \"{host}\""));
    }
    true
}

fn optional_dep_enabled(pkg: &Value, enabled: &BTreeSet<String>, dep_alias: &str) -> bool {
    if enabled.contains(dep_alias) {
        return true;
    }
    let dep_token = format!("dep:{dep_alias}");
    let dep_prefix = format!("{dep_alias}/");
    for feat in enabled {
        if let Some(items) = pkg["features"][feat].as_array() {
            for item in items {
                if let Some(s) = item.as_str()
                    && (s == dep_token || s.starts_with(&dep_prefix))
                {
                    return true;
                }
            }
        }
    }
    false
}

fn resolve_unit_features(
    unit: &[ParsedRecord],
    meta: Option<&Value>,
    host: &str,
) -> Result<Vec<(String, BTreeSet<String>)>> {
    let Some(meta) = meta else {
        // Synthetic test workspace without Cargo.toml: unify explicit + default features
        // across all records in the compilation unit.
        let mut unit_features = BTreeSet::new();
        for rec in unit {
            for pkg in &rec.packages {
                if !rec.no_default {
                    unit_features.insert(format!("{pkg}/default"));
                }
                for feat in &rec.features {
                    if feat.contains('/') {
                        unit_features.insert(feat.clone());
                    } else {
                        unit_features.insert(format!("{pkg}/{feat}"));
                    }
                }
            }
        }
        let mut out = Vec::new();
        for rec in unit {
            let filter_sig = rec.harness.join(" ");
            for (pkg, kind, name) in &rec.targets {
                let pkg_prefix = format!("{pkg}/");
                let relevant: BTreeSet<String> = unit_features
                    .iter()
                    .filter(|f| f.starts_with(&pkg_prefix))
                    .cloned()
                    .collect();
                out.push((format!("{pkg}::{kind}::{name} [{filter_sig}]"), relevant));
            }
        }
        return Ok(out);
    };

    let packages = meta["packages"]
        .as_array()
        .ok_or("missing metadata packages")?;
    let pkg_map: BTreeMap<&str, &Value> = packages
        .iter()
        .filter_map(|p| Some((p["name"].as_str()?, p)))
        .collect();

    let mut root_pkgs = BTreeSet::new();
    let mut enabled: BTreeMap<String, BTreeSet<String>> = pkg_map
        .keys()
        .map(|k| ((*k).to_owned(), BTreeSet::new()))
        .collect();

    for rec in unit {
        for pkg in &rec.packages {
            root_pkgs.insert(pkg.clone());
            if !rec.no_default
                && pkg_map
                    .get(pkg.as_str())
                    .is_some_and(|p| p["features"].get("default").is_some())
                && let Some(set) = enabled.get_mut(pkg)
            {
                set.insert("default".to_owned());
            }
        }
        for feat in &rec.features {
            if let Some((pkg, f)) = feat.split_once('/') {
                if let Some(set) = enabled.get_mut(pkg) {
                    set.insert(f.to_owned());
                }
            } else {
                for pkg in &rec.packages {
                    if pkg_map.get(pkg.as_str()).is_some_and(|p| {
                        p["features"].get(feat).is_some()
                            || p["dependencies"].as_array().is_some_and(|deps| {
                                deps.iter().any(|d| {
                                    d["optional"].as_bool() == Some(true)
                                        && (d["rename"].as_str().or_else(|| d["name"].as_str())
                                            == Some(feat.as_str()))
                                })
                            })
                    }) && let Some(set) = enabled.get_mut(pkg)
                    {
                        set.insert(feat.clone());
                    }
                }
            }
        }
    }

    let mut active = root_pkgs.clone();
    let mut changed = true;
    while changed {
        changed = false;
        let current_active: Vec<String> = active.iter().cloned().collect();
        for p in current_active {
            let Some(pkg) = pkg_map.get(p.as_str()) else {
                continue;
            };
            let current_feats: Vec<String> = enabled
                .get(&p)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            for f in &current_feats {
                if let Some(items) = pkg["features"][f].as_array() {
                    for item in items {
                        let Some(item_str) = item.as_str() else {
                            continue;
                        };
                        if let Some((dep_part, dep_feat)) = item_str.split_once('/') {
                            let is_weak = dep_part.ends_with('?');
                            let dep_alias = dep_part.trim_end_matches('?');
                            if let Some(deps) = pkg["dependencies"].as_array() {
                                for d in deps {
                                    let Some(dep_name) = d["name"].as_str() else {
                                        continue;
                                    };
                                    if !pkg_map.contains_key(dep_name) {
                                        continue;
                                    }
                                    let alias = d["rename"].as_str().unwrap_or(dep_name);
                                    if alias != dep_alias {
                                        continue;
                                    }
                                    if !target_matches_host(d["target"].as_str(), host) {
                                        continue;
                                    }
                                    let is_opt = d["optional"].as_bool().unwrap_or(false);
                                    let p_enabled = enabled.get(&p).cloned().unwrap_or_default();
                                    if !is_opt
                                        || !is_weak
                                        || optional_dep_enabled(pkg, &p_enabled, dep_alias)
                                    {
                                        if active.insert(dep_name.to_owned()) {
                                            changed = true;
                                        }
                                        if let Some(dep_set) = enabled.get_mut(dep_name) {
                                            if dep_set.insert(dep_feat.to_owned()) {
                                                changed = true;
                                            }
                                            if d["uses_default_features"].as_bool().unwrap_or(true)
                                                && pkg_map.get(dep_name).is_some_and(|dp| {
                                                    dp["features"].get("default").is_some()
                                                })
                                                && dep_set.insert("default".to_owned())
                                            {
                                                changed = true;
                                            }
                                        }
                                    }
                                }
                            }
                        } else if !item_str.starts_with("dep:")
                            && pkg["features"].get(item_str).is_some()
                            && let Some(p_set) = enabled.get_mut(&p)
                            && p_set.insert(item_str.to_owned())
                        {
                            changed = true;
                        }
                    }
                }
            }

            let p_enabled = enabled.get(&p).cloned().unwrap_or_default();
            if let Some(deps) = pkg["dependencies"].as_array() {
                for d in deps {
                    let Some(dep_name) = d["name"].as_str() else {
                        continue;
                    };
                    if !pkg_map.contains_key(dep_name) {
                        continue;
                    }
                    if !target_matches_host(d["target"].as_str(), host) {
                        continue;
                    }
                    if d["kind"].as_str() == Some("dev") && !root_pkgs.contains(&p) {
                        continue;
                    }
                    if d["optional"].as_bool().unwrap_or(false) {
                        let alias = d["rename"].as_str().unwrap_or(dep_name);
                        if !optional_dep_enabled(pkg, &p_enabled, alias) {
                            continue;
                        }
                    }
                    if active.insert(dep_name.to_owned()) {
                        changed = true;
                    }
                    if let Some(dep_set) = enabled.get_mut(dep_name) {
                        if d["uses_default_features"].as_bool().unwrap_or(true)
                            && pkg_map
                                .get(dep_name)
                                .is_some_and(|dp| dp["features"].get("default").is_some())
                            && dep_set.insert("default".to_owned())
                        {
                            changed = true;
                        }
                        if let Some(dfs) = d["features"].as_array() {
                            for df in dfs {
                                if let Some(df_str) = df.as_str()
                                    && dep_set.insert(df_str.to_owned())
                                {
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let reachable_from = |root_pkg: &str| -> BTreeSet<String> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![root_pkg.to_owned()];
        seen.insert(root_pkg.to_owned());
        while let Some(cur) = stack.pop() {
            let Some(pkg) = pkg_map.get(cur.as_str()) else {
                continue;
            };
            let cur_enabled = enabled.get(&cur).cloned().unwrap_or_default();
            if let Some(deps) = pkg["dependencies"].as_array() {
                for d in deps {
                    let Some(dep_name) = d["name"].as_str() else {
                        continue;
                    };
                    if !active.contains(dep_name) {
                        continue;
                    }
                    if !target_matches_host(d["target"].as_str(), host) {
                        continue;
                    }
                    if d["kind"].as_str() == Some("dev") && cur != root_pkg {
                        continue;
                    }
                    if d["optional"].as_bool().unwrap_or(false) {
                        let alias = d["rename"].as_str().unwrap_or(dep_name);
                        if !optional_dep_enabled(pkg, &cur_enabled, alias) {
                            continue;
                        }
                    }
                    if seen.insert(dep_name.to_owned()) {
                        stack.push(dep_name.to_owned());
                    }
                }
            }
        }
        seen
    };

    let mut out = Vec::new();
    for rec in unit {
        let filter_sig = rec.harness.join(" ");
        for (pkg, kind, name) in &rec.targets {
            let mut features_for_binary = BTreeSet::new();
            for dep_pkg in reachable_from(pkg) {
                if let Some(feats) = enabled.get(&dep_pkg) {
                    for f in feats {
                        features_for_binary.insert(format!("{dep_pkg}/{f}"));
                    }
                }
            }
            out.push((
                format!("{pkg}::{kind}::{name} [{filter_sig}]"),
                features_for_binary,
            ));
        }
    }
    Ok(out)
}

fn compute_binary_features(
    batch_records: &[Vec<String>],
    meta: Option<&Value>,
    host: &str,
) -> Result<BinaryFeatureInventory> {
    let mut single_units: Vec<Vec<ParsedRecord>> = Vec::new();
    let mut batched_units: BTreeMap<String, Vec<ParsedRecord>> = BTreeMap::new();

    for raw in batch_records {
        let Some((batch_id, record)) = raw.split_first() else {
            continue;
        };
        let parsed = parse_record_selection(record, meta)?;
        if batch_id.is_empty() || parsed.doc {
            single_units.push(vec![parsed]);
        } else {
            batched_units
                .entry(batch_id.clone())
                .or_default()
                .push(parsed);
        }
    }

    let mut inventory = BinaryFeatureInventory::new();
    for unit in single_units.into_iter().chain(batched_units.into_values()) {
        for (binary_key, feats) in resolve_unit_features(&unit, meta, host)? {
            inventory.entry(binary_key).or_default().push(feats);
        }
    }
    for sets in inventory.values_mut() {
        sets.sort();
    }
    Ok(inventory)
}

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
    let mut shards: Vec<_> = recipes
        .keys()
        .filter(|r| r.starts_with("test-shard-"))
        .cloned()
        .collect();
    if shards.is_empty() {
        return Err("no test-shard-* recipes found".into());
    }
    shards.sort();
    Ok(shards)
}

pub fn check(root: &Path) -> Result<String> {
    let mut hosts = vec![std::env::consts::OS];
    if std::env::consts::OS != "macos" {
        hosts.push("macos");
    }
    hosts
        .into_iter()
        .map(|host| check_host(root, host))
        .collect::<Result<Vec<_>>>()
        .map(|reports| reports.join("\n"))
}

fn check_host(root: &Path, host: &str) -> Result<String> {
    let root = root.canonicalize()?;
    let shards = shard_recipes(&root)?;
    let temp = tempfile::tempdir()?;
    let xtask = snapshot_xtask(temp.path())?;
    let stub = temp.path().join("cargo");
    std::fs::write(&stub, CAPTURE)?;
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))?;
    let path = std::env::var_os("PATH").ok_or("PATH is unset")?;
    let real_cargo = std::env::split_paths(&path)
        .map(|p| p.join("cargo"))
        .find(|p| p.is_file())
        .ok_or("cargo is unavailable")?;
    let meta = load_workspace_metadata(&root, &real_cargo)?;
    let capture_path = std::env::join_paths(
        std::iter::once(temp.path().to_path_buf()).chain(std::env::split_paths(&path)),
    )?;
    let capture = |recipe: &str| -> Result<(Inventory, Vec<Vec<String>>)> {
        let log = temp.path().join("commands");
        let batch_log = temp.path().join("batch_records");
        std::fs::write(&log, "")?;
        std::fs::write(&batch_log, "")?;
        let output = Command::new("just")
            .arg(recipe)
            .current_dir(&root)
            .env("PATH", &capture_path)
            .env("CARRICK_REAL_CARGO", &real_cargo)
            .env("CARRICK_TEST_CAPTURE", &log)
            .env("CARRICK_TEST_BATCH_RECORDS", &batch_log)
            .env("CARRICK_TEST_CAPTURE_HOST", host)
            .env("CARRICK_TEST_XTASK", &xtask)
            .env_remove("CARRICK_TEST_BATCH_UNIT")
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
        let batch_records = parse_null_delimited_records(&std::fs::read(batch_log)?, 4)?;
        Ok((inventory, batch_records))
    };
    let (expected, expected_batch_records) = capture("test")?;
    if expected.is_empty() {
        return Err("unsharded test recipe selected no Cargo tests".into());
    }
    let mut actual = Inventory::new();
    let mut actual_batch_records = Vec::new();
    for shard in &shards {
        let (shard_inv, shard_records) = capture(shard)?;
        for (command, count) in shard_inv {
            *actual.entry(command).or_default() += count;
        }
        actual_batch_records.extend(shard_records);
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

    let expected_features = compute_binary_features(&expected_batch_records, meta.as_ref(), host)?;
    let actual_features = compute_binary_features(&actual_batch_records, meta.as_ref(), host)?;
    if expected_features != actual_features {
        let mut differences = Vec::new();
        for binary in expected_features
            .keys()
            .chain(actual_features.keys())
            .collect::<BTreeSet<_>>()
        {
            let want = expected_features.get(binary);
            let got = actual_features.get(binary);
            if want != got {
                differences.push(format!(
                    "  {binary}:\n    unsharded features: {want:?}\n    shard features:     {got:?}"
                ));
            }
        }
        return Err(format!(
            "shard per-binary feature sets differ on {host}:\n{}",
            differences.join("\n")
        )
        .into());
    }

    Ok(format!(
        "{}: {} Cargo selections and {} per-binary feature sets match just test exactly on {} (filters, features, serial threads and stack budgets included)",
        shards.join(", "),
        expected.values().sum::<usize>(),
        expected_features.values().map(Vec::len).sum::<usize>(),
        host
    ))
}
