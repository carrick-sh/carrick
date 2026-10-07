//! Resolve fixture inputs independently of the host workspace's crate population.
use super::environment::{BuildEnvironment, checkout_configs};
use super::{BUILD_SCRIPTS, ContentHash, Result, fail, git, hash_source, safe_path};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

const FIXTURES: &[&str] = &[
    "conformance-probes",
    "fixtures/linux-aarch64-hello",
    "fixtures/embed-interceptor-probe",
    "fixtures/embed-zone-readers",
    "fixtures/embed-icache-reuse",
    "fixtures/embed-el1-sched",
];
/// Inputs outside the Cargo graph. Workspace manifests, lockfiles and Cargo
/// configuration are derived from each fixture's resolved graph below.
const BUILD_INPUTS: &[&str] = &[
    // Read by the controlled build environment to select the compiler.
    "rust-toolchain.toml",
    ".cargo",
    // The publisher itself constructs the Cargo commands and probe selection.
    "crates/carrick-xtask/src/fixtures.rs",
    "crates/carrick-xtask/src/fixtures/inputs.rs",
    "crates/carrick-xtask/src/fixtures/environment.rs",
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
    let environment = BuildEnvironment::new(&root)?;
    let mut inputs: BTreeSet<_> = BUILD_INPUTS
        .iter()
        .chain(BUILD_SCRIPTS)
        .map(|s| (*s).to_owned())
        .collect();
    for fixture in FIXTURES {
        let directory = safe_path(&root, fixture)?;
        let manifest = directory.join("Cargo.toml");
        if !manifest.is_file() || !directory.join("Cargo.lock").is_file() {
            return Err(fail(format!(
                "missing fixture manifest or lockfile: {fixture}"
            )));
        }
        // Resolve the unfiltered graph: build-dependencies and proc-macros
        // compile for the publisher's host, which need not be the verifier's,
        // so a target-filtered graph could omit host-only path crates. The
        // union over every platform is a superset of any one build.
        // Offline prevents validation from silently relying on registry access;
        // a cold/incomplete Cargo cache is an explicit preparation failure.
        {
            let configs = checkout_configs(&root, &directory)?;
            let mut command = Command::new("cargo");
            environment
                .configure(&mut command)
                .current_dir(environment.scratch_root());
            for config in configs {
                command.arg("--config").arg(config);
            }
            command
                .args([
                    "metadata",
                    "--locked",
                    "--offline",
                    "--format-version",
                    "1",
                    "--manifest-path",
                ])
                .arg(&manifest);
            let output = environment.output(&mut command)?;
            let metadata: Metadata = serde_json::from_str(&output)?;
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
                // Only the fixture workspace's own lockfile (added above from
                // `workspace_root`) pins its graph: an enclosing host workspace
                // lockfile is never read when building a fixture workspace.
                for ancestor in directory.ancestors().take_while(|p| p.starts_with(&root)) {
                    for name in ["Cargo.toml", ".cargo"] {
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

/// Reject a recorded compiler input that could name anything but a tracked
/// checkout source: escapes, absolute paths and generated `target/` files.
fn validate_compiler_input(root: &Path, relative: &str) -> Result<()> {
    if Path::new(relative)
        .components()
        .any(|c| c == std::path::Component::Normal("target".as_ref()))
    {
        return Err(fail(format!(
            "recorded compiler input under target/: {relative}"
        )));
    }
    safe_path(root, relative)?;
    Ok(())
}

/// Compute the scoped input inventory: the Cargo-graph closure plus the
/// compiler-recorded inputs a bundle names. Every recorded input must be a
/// clean, tracked regular file; a missing one is refused, never skipped.
pub fn source_hashes(
    root: &Path,
    compiler_inputs: &[String],
) -> Result<BTreeMap<String, ContentHash>> {
    let mut inputs = resolved_inputs(root)?;
    for relative in compiler_inputs {
        validate_compiler_input(root, relative)?;
        inputs.insert(relative.clone());
    }
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
    for relative in compiler_inputs {
        if !sources.contains_key(relative) {
            return Err(fail(format!(
                "recorded compiler input is not a tracked file: {relative}"
            )));
        }
    }
    if sources.is_empty() {
        return Err(fail("empty fixture source inventory"));
    }
    Ok(sources)
}
