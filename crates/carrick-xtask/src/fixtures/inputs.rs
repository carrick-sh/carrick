//! Resolve fixture inputs independently of the host workspace's crate population.
use super::{ContentHash, GuestTarget, Result, fail, git, hash_source, safe_path};
use crate::command;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const FIXTURES: &[&str] = &[
    "conformance-probes",
    "fixtures/linux-aarch64-hello",
    "fixtures/embed-interceptor-probe",
    "fixtures/embed-zone-readers",
    "fixtures/embed-icache-reuse",
    "fixtures/embed-el1-sched",
];
const BUILD_INPUTS: &[&str] = &[
    // Path crates inherit workspace package/dependency declarations and lints.
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".cargo",
    "scripts/build-linux-fixtures.sh",
    "scripts/build-embed-interceptor-probe.sh",
    "scripts/build-embed-zone-readers.sh",
    "scripts/build-embed-icache-reuse.sh",
    "scripts/build-embed-el1-sched.sh",
    // The publisher itself constructs the Cargo commands and probe selection.
    "crates/carrick-xtask/src/fixtures.rs",
    "crates/carrick-xtask/src/fixtures/inputs.rs",
    "crates/carrick-xtask/src/probe_inventory.rs",
    "crates/carrick-xtask/src/provision.rs",
];

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<Package>,
    resolve: Option<Resolve>,
    workspace_root: PathBuf,
}
#[derive(Deserialize)]
struct Package {
    id: String,
    source: Option<String>,
    manifest_path: PathBuf,
}
#[derive(Deserialize)]
struct Resolve {
    root: Option<String>,
    nodes: Vec<Node>,
}
#[derive(Deserialize)]
struct Node {
    id: String,
    deps: Vec<Dependency>,
}
#[derive(Deserialize)]
struct Dependency {
    pkg: String,
    dep_kinds: Vec<DependencyKind>,
}
#[derive(Deserialize)]
struct DependencyKind {
    kind: Option<String>,
}

fn relative(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .ok()
        .and_then(Path::to_str)
        .ok_or_else(|| {
            fail(format!(
                "fixture input outside checkout: {}",
                path.display()
            ))
        })?;
    safe_path(root, relative)?;
    Ok(relative.to_owned())
}

fn resolved_inputs(root: &Path) -> Result<BTreeSet<String>> {
    let root = root.canonicalize()?;
    let mut inputs: BTreeSet<_> = BUILD_INPUTS.iter().map(|s| (*s).to_owned()).collect();
    for fixture in FIXTURES {
        let directory = safe_path(&root, fixture)?;
        let manifest = directory.join("Cargo.toml");
        if !manifest.is_file() || !directory.join("Cargo.lock").is_file() {
            return Err(fail(format!(
                "missing fixture manifest or lockfile: {fixture}"
            )));
        }
        let targets: &[GuestTarget] = if *fixture == "conformance-probes" {
            &[GuestTarget::Musl, GuestTarget::Gnu]
        } else {
            &[GuestTarget::Musl]
        };
        for target in targets {
            // Resolve the same default features and target as the locked build.
            // Offline prevents validation from silently relying on registry access;
            // a cold/incomplete Cargo cache is an explicit preparation failure.
            let output = command::run_checked(
                "cargo",
                [
                    "metadata",
                    "--locked",
                    "--offline",
                    "--format-version",
                    "1",
                    "--filter-platform",
                    target.triple(),
                    "--manifest-path",
                    "Cargo.toml",
                ],
                Some(&directory),
            )?;
            let metadata: Metadata = serde_json::from_str(&output.stdout)?;
            inputs.insert(relative(
                &root,
                &metadata.workspace_root.join("Cargo.toml"),
            )?);
            inputs.insert(relative(
                &root,
                &metadata.workspace_root.join("Cargo.lock"),
            )?);
            let resolve = metadata
                .resolve
                .ok_or_else(|| fail("missing fixture Cargo resolve graph"))?;
            let root_id = resolve
                .root
                .ok_or_else(|| fail("missing fixture Cargo resolve root"))?;
            let packages: BTreeMap<_, _> = metadata.packages.iter().map(|p| (&p.id, p)).collect();
            let nodes: BTreeMap<_, _> = resolve.nodes.iter().map(|n| (&n.id, n)).collect();
            let mut pending = vec![root_id];
            let mut seen = BTreeSet::new();
            while let Some(id) = pending.pop() {
                if !seen.insert(id.clone()) {
                    continue;
                }
                let package = packages
                    .get(&id)
                    .ok_or_else(|| fail("missing resolved fixture package"))?;
                let node = nodes
                    .get(&id)
                    .ok_or_else(|| fail("missing resolved fixture dependency node"))?;
                for dependency in &node.deps {
                    let mut built = false;
                    for kind in &dependency.dep_kinds {
                        match kind.kind.as_deref() {
                            None | Some("build") => built = true,
                            Some("dev") => {}
                            Some(other) => {
                                return Err(fail(format!(
                                    "unknown Cargo dependency kind: {other}"
                                )));
                            }
                        }
                    }
                    if dependency.dep_kinds.is_empty() {
                        return Err(fail("missing Cargo dependency kind"));
                    }
                    if built {
                        pending.push(dependency.pkg.clone());
                    }
                }
                if package.source.is_some() {
                    continue;
                }
                let directory = package
                    .manifest_path
                    .parent()
                    .ok_or_else(|| fail("fixture package has no directory"))?;
                // A package at checkout root would reintroduce full-tree hashing.
                inputs.insert(relative(&root, directory)?);
                // Cargo config and inherited workspace declarations can live above
                // a path package, outside its source tree. Include those as well.
                for ancestor in directory.ancestors().take_while(|p| p.starts_with(&root)) {
                    for name in ["Cargo.toml", "Cargo.lock", ".cargo"] {
                        let path = ancestor.join(name);
                        if path.exists() {
                            inputs.insert(relative(&root, &path)?);
                        }
                    }
                }
            }
        }
    }
    Ok(inputs)
}

pub(super) fn source_hashes(root: &Path) -> Result<BTreeMap<String, ContentHash>> {
    let inputs = resolved_inputs(root)?;
    let mut args = vec!["status", "--porcelain", "--untracked-files=all", "--"];
    args.extend(inputs.iter().map(String::as_str));
    if !git(root, &args)?.trim().is_empty() {
        return Err(fail("dirty fixture source inputs"));
    }
    let mut args = vec!["ls-files", "-z", "--"];
    args.extend(inputs.iter().map(String::as_str));
    let paths = git(root, &args)?;
    let mut sources = BTreeMap::new();
    for relative in paths.split('\0').filter(|p| !p.is_empty()) {
        sources.insert(relative.to_owned(), hash_source(root, relative)?);
    }
    if sources.is_empty() {
        return Err(fail("empty fixture source inventory"));
    }
    Ok(sources)
}
