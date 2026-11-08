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
        } else {
            // Shared inputs (Cargo.lock, recipes, scripts, etc.) have no single owner.
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

fn kernel_host_facilities() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Probe permission rather than guessing from uid: ping_group_range also
        // admits supplementary groups and capabilities can override that range.
        // SAFETY: socket has no pointer arguments; the fresh fd is closed once.
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                libc::IPPROTO_ICMP,
            )
        };
        if fd < 0 {
            return Err(format!(
                "host facility unavailable: Linux ping socket: {}; net.ipv4.ping_group_range={}",
                std::io::Error::last_os_error(),
                std::fs::read_to_string("/proc/sys/net/ipv4/ping_group_range")
                    .unwrap_or_else(|e| e.to_string())
                    .trim()
            )
            .into());
        }
        // SAFETY: fd is owned by this function.
        unsafe {
            libc::close(fd);
        }
    }
    Ok(())
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
                if lane
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
    let mut failures = Vec::new();
    for name in selected {
        println!("test-touched: {name}");
        let Some(records) = by_package.get(&name) else {
            // Architecture-specific and freestanding crates have no host-test
            // selection in just test. Report that explicitly, never as a pass.
            println!(
                "test-touched: {name}: no just test selection on {}",
                std::env::consts::OS
            );
            continue;
        };
        if args.plan {
            for unit in records {
                println!("  {unit:?}");
            }
            continue;
        }
        if name == "carrick-kernel"
            && let Err(e) = kernel_host_facilities()
        {
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
        assert_eq!(
            selection(Path::new("/repo"), &meta, &[PathBuf::from("Cargo.lock")])
                .unwrap()
                .len(),
            4
        );
    }
}
