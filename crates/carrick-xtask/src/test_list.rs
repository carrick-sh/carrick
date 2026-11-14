//! `test-list`: the tests CI actually compiled, as a per-head manifest (carrick#2328 item 4).
//!
//! A landing check that names an ISA witness (`arm=<file.rs>::<test>`) needs ground truth: the
//! test exists in a binary CI built at that head, not just in the source text. This replays a
//! recipe's exact Cargo test commands (the capture `check-test-shards` uses), compiles each compile
//! unit with `--no-run` as `test-batch` does, and asks every executable for `--list` with the lane's
//! own harness arguments (filters and `--skip`), then again with `--ignored`. Targets of
//! `--lane` lanes (from `[package.metadata.carrick.test-lanes]`, e.g. `signed-hvf`, `kvm`) are
//! compiled and listed too: their VM-booting tests are `#[ignore]`d by rule 0 and run only by
//! their signed or KVM gate, so the manifest records each target's lane and whether a test is
//! ignored, and the consumer decides.
//!
//! The manifest is produced by PR CI from PR code, so it is forgeable by a PR author; under the
//! owner's threat model (only our own agents contribute, 2026-11-05, #231) it guards against
//! mistakes, not adversaries.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use crate::test_batch::{Lane, compile, metadata, parse, selection};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(clap::Args, Debug)]
pub struct TestListArgs {
    /// The PR head (or pushed) commit the manifest describes.
    #[arg(long)]
    pub head: String,
    /// The ISA label of this host's build: `arm` or `x86`.
    #[arg(long)]
    pub isa: String,
    /// Recipes whose Cargo test commands are listed (for example `test-shard-a`).
    #[arg(long)]
    pub recipe: Vec<String>,
    /// Test-lane names whose integration targets are compiled and listed as well.
    #[arg(long)]
    pub lane: Vec<String>,
    /// Maximum Cargo compilation jobs.
    #[arg(long)]
    pub jobs: Option<usize>,
    /// Where the manifest JSON is written.
    #[arg(long)]
    pub out: PathBuf,
}

/// One listed test.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct Listed {
    pub package: String,
    pub target: String,
    pub kind: String,
    pub src_path: String,
    pub lane: String,
    pub test: String,
    pub ignored: bool,
}

/// The `name: test` lines of libtest's `--list --format terse`.
pub fn terse_tests(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| line.strip_suffix(": test"))
        .map(str::to_owned)
        .collect()
}

/// Combine a target's full listing with its `--ignored` listing.
pub fn mark_ignored(all: Vec<String>, ignored: &[String]) -> Vec<(String, bool)> {
    let ignored: BTreeSet<&str> = ignored.iter().map(String::as_str).collect();
    all.into_iter()
        .map(|test| {
            let flag = ignored.contains(test.as_str());
            (test, flag)
        })
        .collect()
}

fn list_exe(exe: &Path, dir: &Path, harness: &[String], ignored: bool) -> Result<Vec<String>> {
    let mut cmd = Command::new(exe);
    cmd.current_dir(dir)
        .args(harness)
        .args(["--list", "--format", "terse"])
        .stdin(Stdio::null());
    if ignored {
        cmd.arg("--ignored");
    }
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(format!(
            "{} --list failed: {}",
            exe.display(),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(terse_tests(&String::from_utf8_lossy(&out.stdout)))
}

struct TargetInfo {
    name: String,
    kind: String,
    src_path: String,
    dir: PathBuf,
}

fn target_info(root: &Path, meta: &Value, id: &str, target: &str) -> Result<TargetInfo> {
    let pkg = meta["packages"]
        .as_array()
        .ok_or("missing packages")?
        .iter()
        .find(|p| p["id"].as_str() == Some(id))
        .ok_or("missing package")?;
    let t = pkg["targets"]
        .as_array()
        .ok_or("missing targets")?
        .iter()
        .find(|t| t["name"].as_str() == Some(target))
        .ok_or("missing target")?;
    let manifest = Path::new(pkg["manifest_path"].as_str().ok_or("missing manifest")?);
    Ok(TargetInfo {
        name: pkg["name"].as_str().ok_or("missing name")?.to_owned(),
        kind: t["kind"][0].as_str().ok_or("missing kind")?.to_owned(),
        // Relative to the checkout, so a consumer matches `crates/<pkg>/src/...` paths directly.
        src_path: Path::new(t["src_path"].as_str().ok_or("missing src_path")?)
            .strip_prefix(root)?
            .to_string_lossy()
            .into_owned(),
        dir: manifest
            .parent()
            .ok_or("missing package dir")?
            .to_path_buf(),
    })
}

/// Compile one unit's lanes and list every target with each lane's harness arguments.
fn list_unit(
    root: &Path,
    meta: &Value,
    lanes: &[Lane],
    lane_of: &BTreeMap<(String, String), String>,
    jobs: Option<usize>,
    out: &mut BTreeSet<Listed>,
) -> Result<()> {
    let lanes: Vec<&Lane> = lanes.iter().filter(|l| !l.doc).collect();
    if lanes.is_empty() {
        return Ok(());
    }
    let owned: Vec<Lane> = lanes
        .iter()
        .map(|l| parse(l.record.clone(), meta))
        .collect::<Result<_>>()?;
    let (packages, features, targets, _) = selection(&owned, meta)?;
    if packages.is_empty() {
        return Ok(());
    }
    let (binaries, _) = compile(root, &owned, meta, &packages, &features, &targets, jobs)?;
    for lane in &owned {
        for target in &lane.targets {
            let exe = binaries
                .get(target)
                .ok_or_else(|| format!("missing test executable: {target:?}"))?;
            let info = target_info(root, meta, &target.0, &target.1)?;
            let all = list_exe(exe, &info.dir, &lane.harness, false)?;
            let ignored = list_exe(exe, &info.dir, &lane.harness, true)?;
            let lane_name = lane_of
                .get(&(info.name.clone(), target.1.clone()))
                .cloned()
                .unwrap_or_else(|| crate::test_lanes::DEFAULT_LANE.to_owned());
            for (test, ignored) in mark_ignored(all, &ignored) {
                out.insert(Listed {
                    package: info.name.clone(),
                    target: target.1.clone(),
                    kind: info.kind.clone(),
                    src_path: info.src_path.clone(),
                    lane: lane_name.clone(),
                    test,
                    ignored,
                });
            }
        }
    }
    Ok(())
}

pub fn run(root: &Path, args: TestListArgs) -> Result<()> {
    let root = root.canonicalize()?;
    if !matches!(args.isa.as_str(), "arm" | "x86") {
        return Err(format!("--isa must be arm or x86, not {}", args.isa).into());
    }
    let meta = metadata(&root)?;
    let (resolved, errors) = crate::test_lanes::resolve(&meta);
    if !errors.is_empty() {
        return Err(format!("test-lanes: {}", errors.join("; ")).into());
    }
    let lane_of: BTreeMap<(String, String), String> = resolved
        .iter()
        .map(|t| ((t.package.clone(), t.target.clone()), t.lane.clone()))
        .collect();
    let mut listed = BTreeSet::new();
    for recipe in &args.recipe {
        // Group the recipe's commands by compile unit, as the real run compiles them: each
        // test-batch unit once, each direct `cargo test` on its own.
        let mut units: BTreeMap<String, Vec<Lane>> = BTreeMap::new();
        for (n, record) in crate::test_shards::records_with_units(&root, recipe, &[])?
            .into_iter()
            .enumerate()
        {
            let unit = if record[0].is_empty() {
                format!("direct:{n}")
            } else {
                record[0].clone()
            };
            units
                .entry(unit)
                .or_default()
                .push(parse(record[1..].to_vec(), &meta)?);
        }
        for lanes in units.values() {
            list_unit(&root, &meta, lanes, &lane_of, args.jobs, &mut listed)?;
        }
    }
    for lane in &args.lane {
        if crate::test_lanes::lane_of(lane).is_none() {
            return Err(format!("unknown test lane {lane}").into());
        }
        let root_str = root.to_string_lossy().into_owned();
        for target in resolved.iter().filter(|t| &t.lane == lane) {
            let record: Vec<String> = [
                "",
                "",
                &root_str,
                "test",
                "-p",
                &target.package,
                "--test",
                &target.target,
            ]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
            let lanes = vec![parse(record, &meta)?];
            list_unit(&root, &meta, &lanes, &lane_of, args.jobs, &mut listed)?;
        }
    }
    let manifest = json!({
        "schema": 1,
        "head": args.head,
        "isa": args.isa,
        "recipes": args.recipe,
        "lanes": args.lane,
        "tests": listed.into_iter().collect::<Vec<_>>(),
    });
    std::fs::write(&args.out, serde_json::to_vec_pretty(&manifest)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terse_listing_keeps_tests_only() {
        let out = "a::b: test\nc::d: benchmark\n\n2 tests, 0 benchmarks\ne: test\n";
        assert_eq!(terse_tests(out), ["a::b", "e"]);
        assert_eq!(
            mark_ignored(vec!["a".into(), "b".into()], &["b".into()]),
            [("a".to_owned(), false), ("b".to_owned(), true)]
        );
    }
}
