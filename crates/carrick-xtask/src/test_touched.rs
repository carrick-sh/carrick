//! Diff selection over the existing just-test command authority.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(clap::Args, Debug)]
pub struct TestTouchedArgs {
    /// Git revision to compare with HEAD (committed changes only).
    pub base: String,
    /// Print the selected crates and source commands without running tests.
    #[arg(long)]
    pub plan: bool,
}

fn selection(root: &Path, meta: &Value, paths: &[PathBuf]) -> Result<BTreeSet<String>> {
    let members = meta["workspace_members"]
        .as_array()
        .ok_or("missing members")?;
    let packages: Vec<_> = meta["packages"]
        .as_array()
        .ok_or("missing packages")?
        .iter()
        .filter(|p| members.contains(&p["id"]))
        .collect();
    let mut selected = BTreeSet::new();
    for path in paths {
        // Longest prefix handles nested workspace packages without selecting parents.
        let owner = packages
            .iter()
            .filter_map(|p| {
                let directory = Path::new(p["manifest_path"].as_str()?).parent()?;
                root.join(path)
                    .starts_with(directory)
                    .then_some((directory, *p))
            })
            .max_by_key(|(dir, _)| dir.components().count());
        if let Some((_, p)) = owner {
            selected.insert(p["name"].as_str().ok_or("missing name")?.to_owned());
        } else if matches!(
            path.to_str(),
            Some("Cargo.toml" | "Cargo.lock" | "justfile" | "rust-toolchain.toml")
        ) || [".cargo", "scripts", "crates", ".github"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
        {
            // Shared build/test inputs have no single owner. Documentation and
            // other non-build files outside packages do not touch a crate.
            selected.extend(
                packages
                    .iter()
                    .filter_map(|p| p["name"].as_str().map(str::to_owned)),
            );
        }
    }
    loop {
        let before = selected.len();
        for p in &packages {
            if p["dependencies"]
                .as_array()
                .ok_or("missing dependencies")?
                .iter()
                .any(|d| {
                    d["path"].is_string()
                        && d["name"].as_str().is_some_and(|n| selected.contains(n))
                })
            {
                selected.insert(p["name"].as_str().ok_or("missing name")?.to_owned());
            }
        }
        if selected.len() == before {
            return Ok(selected);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostLane {
    Runs,
    Unavailable,
    NoTests,
}

fn classify_host_lane(
    by_package_keys: &BTreeSet<String>,
    crate_name: &str,
    has_tests: bool,
) -> HostLane {
    if by_package_keys.contains(crate_name) {
        HostLane::Runs
    } else if has_tests {
        HostLane::Unavailable
    } else {
        HostLane::NoTests
    }
}

pub fn run(root: &Path, args: TestTouchedArgs) -> Result<()> {
    let root = root.canonicalize()?;
    let jobs: usize = std::env::var("JOBS")
        .unwrap_or_else(|_| "3".into())
        .parse()?;
    if jobs == 0 {
        return Err("JOBS must be positive".into());
    }
    let diff = Command::new("git")
        .args([
            "diff",
            "--name-only",
            "-z",
            "--no-renames",
            &format!("{}..HEAD", args.base),
            "--",
        ])
        .current_dir(&root)
        .output()?;
    if !diff.status.success() {
        return Err(String::from_utf8_lossy(&diff.stderr).into_owned().into());
    }
    let paths = diff
        .stdout
        .split(|b| *b == 0)
        .filter(|b| !b.is_empty())
        .map(|b| String::from_utf8(b.to_vec()).map(PathBuf::from))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let meta = crate::test_batch::metadata(&root)?;
    let selected = selection(&root, &meta, &paths)?;
    if selected.is_empty() {
        println!("test-touched: no changed workspace inputs");
        return Ok(());
    }
    if !Command::new("python3")
        .arg("scripts/migrate/check-serial-host-tests.py")
        .current_dir(&root)
        .status()?
        .success()
    {
        return Err("serial_host authority check failed".into());
    }
    // Capture the actual recipe, including its platform closure, host lanes,
    // test-support features and all serial exceptions. No independent table.
    let records = crate::test_shards::records_with_units(&root, "test", &[])?;
    let mut units = BTreeMap::<String, Vec<Vec<String>>>::new();
    for (index, record) in records.into_iter().enumerate() {
        let key = if record[0].is_empty() {
            format!("direct:{index}")
        } else {
            record[0].clone()
        };
        units.entry(key).or_default().push(record[1..].to_vec());
    }
    let mut by_package = BTreeMap::<String, Vec<Vec<Vec<String>>>>::new();
    for records in units.into_values() {
        let mut packages = BTreeSet::new();
        for record in &records {
            let lane = crate::test_batch::parse(record.clone(), &meta)?;
            for package in meta["packages"].as_array().ok_or("missing packages")? {
                if (lane.doc
                    && lane
                        .packages
                        .contains(package["name"].as_str().ok_or("missing name")?))
                    || lane
                        .targets
                        .iter()
                        .any(|(id, _)| Some(id.as_str()) == package["id"].as_str())
                {
                    packages.insert(package["name"].as_str().ok_or("missing name")?.to_owned());
                }
            }
        }
        for name in packages.intersection(&selected) {
            by_package
                .entry(name.clone())
                .or_default()
                .push(records.clone());
        }
    }
    let available_lanes: BTreeSet<String> = by_package.keys().cloned().collect();
    let mut failures = Vec::new();
    let mut unavailable = Vec::new();
    for name in selected {
        println!("test-touched: {name}");
        let has_tests = meta["packages"]
            .as_array()
            .ok_or("missing packages")?
            .iter()
            .find(|p| p["name"].as_str() == Some(&name))
            .and_then(|p| p["targets"].as_array())
            .is_some_and(|targets| targets.iter().any(|t| t["test"] == true));
        match classify_host_lane(&available_lanes, &name, has_tests) {
            HostLane::Unavailable => {
                let reason = format!("{name}: no just test selection on {}", std::env::consts::OS);
                if args.plan {
                    println!("test-touched: {reason}");
                } else {
                    println!("test-touched: UNAVAILABLE: {reason}");
                    unavailable.push(name);
                }
                continue;
            }
            HostLane::NoTests => {
                println!(
                    "test-touched: {name}: no just test selection on {}",
                    std::env::consts::OS
                );
                continue;
            }
            HostLane::Runs => {}
        }
        let Some(records) = by_package.get(&name) else {
            return Err(format!("internal error: missing lane records for {name}").into());
        };
        if args.plan {
            for unit in records {
                println!("  {unit:?}");
            }
            continue;
        }
        let preflight: Result<()> = match name.as_str() {
            "carrick-xtask" => crate::fixtures::reject_ambient_overrides()
                .map_err(|e| format!("host configuration unavailable: {e}").into())
                .and_then(|()| {
                    if crate::target_prune::lsof_binary().is_none() {
                        return Err("host facility unavailable: lsof is required by carrick-xtask target-prune tests".into());
                    }
                    let version = Command::new("rsync").arg("--version").output()
                        .map_err(|e| format!("host facility unavailable: rsync is required by carrick-xtask remote-accept tests: {e}"))?;
                    if !version.status.success() {
                        return Err(format!("host facility unavailable: rsync --version failed: {}", String::from_utf8_lossy(&version.stderr)).into());
                    }
                    Ok(())
                }),
            _ => Ok(()),
        };
        if let Err(e) = preflight {
            eprintln!("test-touched: {name}: {e}");
            failures.push(format!("{name}: {e}"));
            continue;
        }
        let only = BTreeSet::from([name.clone()]);
        let mut red = false;
        // Sequential execution also prevents serial_host processes racing with
        // another crate's tests. JOBS bounds Cargo, not merely the outer runner.
        for record in records {
            if let Err(e) = crate::test_batch::selected_records(&root, record.clone(), &only, jobs)
            {
                eprintln!("test-touched: {name}: {e}");
                red = true;
            }
        }
        if red {
            failures.push(name.clone());
        }
        println!(
            "test-touched: {name}: {}",
            if red { "FAIL" } else { "PASS" }
        );
    }
    if !unavailable.is_empty() {
        println!(
            "test-touched: UNAVAILABLE lanes (not failures): {}",
            unavailable.join(", ")
        );
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("test-touched failures: {}", failures.join(", ")).into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn classify_host_lane_distinguishes_runs_unavailable_and_no_tests() {
        let lanes = BTreeSet::from(["carrick-kernel".to_owned(), "carrick-xtask".to_owned()]);
        assert_eq!(
            classify_host_lane(&lanes, "carrick-vmm-hvf", true),
            HostLane::Unavailable
        );
        assert_eq!(
            classify_host_lane(&lanes, "carrick-kernel", true),
            HostLane::Runs
        );
        assert_eq!(
            classify_host_lane(&lanes, "carrick-kernel", false),
            HostLane::Runs
        );
        assert_eq!(
            classify_host_lane(&lanes, "carrick-x86-cpl0", false),
            HostLane::NoTests
        );
    }
    #[test]
    fn sched_change_selects_transitive_reverse_dependencies() {
        let package = |name: &str, deps: Vec<Value>| {
            serde_json::json!({
                "id": name, "name": name, "manifest_path": format!("/repo/crates/{name}/Cargo.toml"), "dependencies": deps
            })
        };
        let dep = |name| serde_json::json!({"name": name, "path": format!("/repo/crates/{name}")});
        let meta = serde_json::json!({"workspace_members": ["carrick-sched-core", "kernel", "runtime", "unrelated"], "packages": [
            package("carrick-sched-core", vec![]), package("kernel", vec![dep("carrick-sched-core")]),
            package("runtime", vec![dep("kernel")]), package("unrelated", vec![])
        ]});
        assert_eq!(
            selection(
                Path::new("/repo"),
                &meta,
                &[PathBuf::from("crates/carrick-sched-core/src/lib.rs")]
            )
            .unwrap(),
            BTreeSet::from([
                "carrick-sched-core".into(),
                "kernel".into(),
                "runtime".into()
            ])
        );
        assert!(
            selection(Path::new("/repo"), &meta, &[PathBuf::from("AGENTS.md")])
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            selection(Path::new("/repo"), &meta, &[PathBuf::from("Cargo.lock")])
                .unwrap()
                .len(),
            4
        );
    }
}
