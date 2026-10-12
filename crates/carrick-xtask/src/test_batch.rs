//! Compile a recipe's complete selection once, then execute its libtest lanes.
//! Recipes remain the authority for targets, filters and process environments.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(clap::Args, Debug)]
pub struct TestBatchArgs {
    /// Recipe whose Cargo test commands define the lanes.
    pub recipe: String,
    /// Extra arguments passed to the source recipe (for example --no-run).
    #[arg(last = true)]
    pub args: Vec<String>,
}

struct Lane {
    record: Vec<String>,
    packages: BTreeSet<String>,
    targets: BTreeSet<(String, String)>,
    features: BTreeSet<String>,
    harness: Vec<String>,
    doc: bool,
    implicit_doc: bool,
    no_run: bool,
    no_default: bool,
}

fn metadata(root: &Path) -> Result<Value> {
    let out = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(root)
        .output()?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned().into());
    }
    Ok(serde_json::from_slice(&out.stdout)?)
}

fn parse(record: Vec<String>, meta: &Value) -> Result<Lane> {
    let start = record
        .iter()
        .skip(3)
        .position(|s| s == "test")
        .ok_or("missing cargo test")?
        + 4;
    let mut lane = Lane {
        record: record.clone(),
        packages: BTreeSet::new(),
        targets: BTreeSet::new(),
        features: BTreeSet::new(),
        harness: Vec::new(),
        doc: false,
        implicit_doc: false,
        no_run: false,
        no_default: false,
    };
    let mut excludes = BTreeSet::new();
    let mut kinds = BTreeSet::new();
    let mut tests = BTreeSet::new();
    let mut workspace = false;
    let mut i = start;
    while i < record.len() {
        let arg = &record[i];
        match arg.as_str() {
            "--" => {
                lane.harness.extend_from_slice(&record[i + 1..]);
                break;
            }
            "-p" | "--package" | "--exclude" | "--test" | "--bin" | "--features" => {
                i += 1;
                let value = record.get(i).ok_or("missing option value")?;
                match arg.as_str() {
                    "-p" | "--package" => {
                        lane.packages.insert(value.clone());
                    }
                    "--exclude" => {
                        excludes.insert(value.clone());
                    }
                    "--test" => {
                        tests.insert(("test".to_owned(), value.clone()));
                    }
                    "--bin" => {
                        tests.insert(("bin".to_owned(), value.clone()));
                    }
                    _ => {
                        lane.features.extend(
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
                kinds.insert("lib");
            }
            "--bins" => {
                kinds.insert("bin");
            }
            "--tests" => {
                kinds.extend(["lib", "bin", "test"]);
            }
            "--doc" => lane.doc = true,
            "--no-default-features" => lane.no_default = true,
            "--no-run" => lane.no_run = true,
            "--locked" | "--no-fail-fast" => {}
            s if !s.starts_with('-') => lane.harness.push(arg.clone()),
            _ => return Err(format!("unsupported batch option {arg}").into()),
        }
        i += 1;
    }
    lane.implicit_doc = !lane.doc && kinds.is_empty() && tests.is_empty();
    let packages = meta["packages"]
        .as_array()
        .ok_or("missing metadata packages")?;
    if workspace || lane.packages.is_empty() {
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
                lane.packages
                    .insert(pkg["name"].as_str().ok_or("missing name")?.to_owned());
            }
        }
    }
    lane.packages.retain(|p| !excludes.contains(p));
    for pkg in packages {
        if !lane
            .packages
            .contains(pkg["name"].as_str().ok_or("missing name")?)
        {
            continue;
        }
        for target in pkg["targets"].as_array().ok_or("missing targets")? {
            let kind = target["kind"][0].as_str().ok_or("missing target kind")?;
            let name = target["name"].as_str().ok_or("missing target name")?;
            if target["test"].as_bool() == Some(true)
                && ((kinds.is_empty()
                    && tests.is_empty()
                    && matches!(kind, "lib" | "bin" | "test"))
                    || kinds.contains(kind)
                    || tests.contains(&(kind.to_owned(), name.to_owned())))
            {
                lane.targets.insert((
                    pkg["id"].as_str().ok_or("missing package id")?.to_owned(),
                    name.to_owned(),
                ));
            }
        }
    }
    Ok(lane)
}

pub fn run(root: &Path, args: TestBatchArgs) -> Result<()> {
    let root = root.canonicalize()?;
    // The exact-coverage gate captures the source commands, not a new inventory.
    if std::env::var_os("CARRICK_TEST_CAPTURE").is_some() {
        let status = Command::new("just")
            .arg(&args.recipe)
            .args(&args.args)
            .current_dir(&root)
            .status()?;
        return if status.success() {
            Ok(())
        } else {
            Err("source recipe failed".into())
        };
    }
    let meta = metadata(&root)?;
    let lanes = crate::test_shards::records(&root, &args.recipe, &args.args)?
        .into_iter()
        .map(|record| parse(record, &meta))
        .collect::<Result<Vec<_>>>()?;
    if lanes.is_empty() {
        return Err("batch selected no tests".into());
    }
    let mut packages = BTreeSet::new();
    let mut features = BTreeSet::new();
    let mut targets = BTreeSet::new();
    for lane in lanes.iter().filter(|l| !l.doc) {
        packages.extend(lane.packages.iter().cloned());
        targets.extend(lane.targets.iter().cloned());
        if !lane.no_default {
            for pkg in meta["packages"].as_array().ok_or("missing packages")? {
                let name = pkg["name"].as_str().ok_or("missing name")?;
                if lane.packages.contains(name) && pkg["features"].get("default").is_some() {
                    features.insert(format!("{name}/default"));
                }
            }
        }
        // Bare features are package scoped before unifying the package set.
        for feature in &lane.features {
            if feature.contains('/') {
                features.insert(feature.clone());
            } else {
                for pkg in meta["packages"].as_array().ok_or("missing packages")? {
                    let name = pkg["name"].as_str().ok_or("missing name")?;
                    if lane.packages.contains(name) && pkg["features"].get(feature).is_some() {
                        features.insert(format!("{name}/{feature}"));
                    }
                }
            }
        }
    }
    let mut cmd = Command::new("cargo");
    let first = lanes.first().ok_or("missing lanes")?;
    let test_index = first
        .record
        .iter()
        .skip(3)
        .position(|s| s == "test")
        .ok_or("missing cargo test")?
        + 3;
    cmd.args(&first.record[3..test_index]);
    for lane in &lanes {
        let index = lane
            .record
            .iter()
            .skip(3)
            .position(|s| s == "test")
            .ok_or("missing cargo test")?
            + 3;
        if lane.record[3..index] != first.record[3..test_index] {
            return Err("batch lanes must share their Cargo configuration".into());
        }
    }
    cmd.current_dir(&root).args([
        "test",
        "--locked",
        "--no-run",
        "--message-format=json-render-diagnostics",
    ]);
    if lanes.iter().any(|l| l.no_default) {
        cmd.arg("--no-default-features");
    }
    for package in packages {
        cmd.args(["-p", &package]);
    }
    if !features.is_empty() {
        cmd.args([
            "--features",
            &features.into_iter().collect::<Vec<_>>().join(","),
        ]);
    }
    // Select only the union of requested target names, never signed/KVM extras.
    let mut selectors = BTreeSet::new();
    for pkg in meta["packages"].as_array().ok_or("missing packages")? {
        for target in pkg["targets"].as_array().ok_or("missing targets")? {
            let name = target["name"].as_str().ok_or("missing name")?;
            let id = pkg["id"].as_str().ok_or("missing id")?;
            if targets.contains(&(id.to_owned(), name.to_owned())) {
                let kind = target["kind"][0].as_str().ok_or("missing kind")?;
                match kind {
                    "lib" => {
                        selectors.insert(("--lib", String::new()));
                    }
                    "bin" => {
                        selectors.insert(("--bin", name.to_owned()));
                    }
                    "test" => {
                        selectors.insert(("--test", name.to_owned()));
                    }
                    _ => return Err(format!("unsupported target kind {kind}").into()),
                }
            }
        }
    }
    for (flag, name) in selectors {
        cmd.arg(flag);
        if !name.is_empty() {
            cmd.arg(name);
        }
    }
    eprintln!("test-batch: one compile for {} lanes: {cmd:?}", lanes.len());
    let mut child = cmd.stdout(Stdio::piped()).spawn()?;
    let stdout = child.stdout.take().ok_or("missing Cargo stdout")?;
    let mut binaries = BTreeMap::<(String, String), PathBuf>::new();
    for line in BufReader::new(stdout).lines() {
        let msg: Value = serde_json::from_str(&line?)?;
        if msg["reason"] == "compiler-message"
            && let Some(rendered) = msg["message"]["rendered"].as_str()
        {
            eprint!("{rendered}");
        }
        if msg["reason"] == "compiler-artifact"
            && msg["profile"]["test"] == true
            && let Some(exe) = msg["executable"].as_str()
        {
            binaries.insert(
                (
                    msg["package_id"]
                        .as_str()
                        .ok_or("missing artifact package")?
                        .to_owned(),
                    msg["target"]["name"]
                        .as_str()
                        .ok_or("missing artifact name")?
                        .to_owned(),
                ),
                PathBuf::from(exe),
            );
        }
    }
    if !child.wait()?.success() {
        return Err("batch compilation failed".into());
    }
    let mut red = Vec::new();
    for lane in &lanes {
        if lane.no_run {
            continue;
        }
        if lane.doc {
            // rustdoc has no --no-run mode; preserve its separate contract.
            let mut doc = Command::new("cargo");
            doc.current_dir(&lane.record[2]).args(&lane.record[3..]);
            if !doc.status()?.success() {
                red.push("doctest".to_owned());
            }
            continue;
        }
        if lane.targets.is_empty() {
            return Err("lane selected no test targets".into());
        }
        for target in &lane.targets {
            let exe = binaries
                .get(target)
                .ok_or_else(|| format!("missing test executable: {target:?}"))?;
            let mut test = Command::new(exe);
            // Cargo runs each test at the package root, not the workspace root.
            let pkg = meta["packages"]
                .as_array()
                .ok_or("missing packages")?
                .iter()
                .find(|p| p["id"].as_str() == Some(&target.0))
                .ok_or("missing package")?;
            let manifest = Path::new(pkg["manifest_path"].as_str().ok_or("missing manifest")?);
            test.current_dir(manifest.parent().ok_or("missing package directory")?)
                .args(&lane.harness)
                .stdin(Stdio::null());
            for (key, value) in [
                ("RUST_TEST_THREADS", &lane.record[0]),
                ("RUST_MIN_STACK", &lane.record[1]),
            ] {
                if value.is_empty() {
                    test.env_remove(key);
                } else {
                    test.env(key, value);
                }
            }
            eprintln!("test-batch: run {test:?}");
            if !test.status()?.success() {
                red.push(format!("{} {:?}", exe.display(), lane.harness));
            }
        }
        if lane.implicit_doc {
            let mut doc = Command::new("cargo");
            doc.current_dir(&lane.record[2])
                .args(&lane.record[3..])
                .arg("--doc");
            if !doc.status()?.success() {
                red.push("implicit doctest".to_owned());
            }
        }
    }
    if !red.is_empty() {
        return Err(format!("red batch lanes: {}", red.join(", ")).into());
    }
    Ok(())
}
