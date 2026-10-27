//! Resolve fixture inputs independently of the host workspace's crate population.
use super::build_code::{self, REVIEWED_BUILD_CODE, ReviewedEntry};
use super::environment::{BuildEnvironment, checkout_configs};
use super::{BUILD_SCRIPTS, ContentHash, Result, fail, git, hash_source, linker, safe_path};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

pub(super) const FIXTURES: &[&str] = &[
    "conformance-probes",
    "fixtures/linux-aarch64-hello",
    "fixtures/embed-interceptor-probe",
    "fixtures/embed-zone-readers",
    "fixtures/embed-icache-reuse",
    "fixtures/embed-copyout",
    "fixtures/embed-el1-sched",
];
/// Checkout crates a signed fixture may depend on. Every path package in a
/// fixture's closure is a bundle input, so one kernel crate there makes every
/// kernel-only commit invalidate the signed bundle (#891). A leaf here must
/// have no dependencies of its own; growing one is a lint failure, not an
/// allowlist edit.
pub(super) const FIXTURE_LEAF_CRATES: &[&str] = &["carrick-el1-control-abi"];
/// Inputs outside the Cargo graph. Workspace manifests, lockfiles and Cargo
/// configuration are derived from each fixture's resolved graph below.
const BUILD_INPUTS: &[&str] = &[
    // Read by the controlled build environment to select the compiler.
    "rust-toolchain.toml",
    ".cargo",
    // Reviewed build scripts and proc-macros: the review is an input too.
    REVIEWED_BUILD_CODE,
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
    name: String,
    version: String,
    source: Option<String>,
    manifest_path: PathBuf,
    targets: Vec<Target>,
}
#[derive(Deserialize)]
struct Target {
    kind: Vec<String>,
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

/// Every fixture manifest whose lockfile pins dependencies the offline
/// resolution and builds need in the Cargo cache. A missing lockfile is an
/// error: fixtures are always `--locked`.
pub fn fetch_plan(root: &Path) -> Result<Vec<PathBuf>> {
    FIXTURES
        .iter()
        .map(|fixture| {
            let directory = safe_path(root, fixture)?;
            let manifest = directory.join("Cargo.toml");
            if !manifest.is_file() || !directory.join("Cargo.lock").is_file() {
                return Err(fail(format!(
                    "missing fixture manifest or lockfile: {fixture}"
                )));
            }
            Ok(manifest)
        })
        .collect()
}

/// Explicit network preparation, separate from the offline resolution and
/// builds: `cargo fetch --locked` every fixture lockfile into the host Cargo
/// cache, which the controlled build environment then shares read-only by
/// symlink. Contents are pinned by each lockfile's checksums; a warm cache
/// is used offline first and needs no network. Returns the fetch count.
pub fn fetch_dependencies(root: &Path) -> Result<usize> {
    let manifests = fetch_plan(root)?;
    for manifest in &manifests {
        let directory = manifest
            .parent()
            .ok_or_else(|| fail("fixture manifest without directory"))?;
        let fetch = |offline: bool| -> Result<std::process::Output> {
            let mut command = Command::new("cargo");
            command.current_dir(directory).args(["fetch", "--locked"]);
            if offline {
                command.arg("--offline");
            }
            Ok(command.arg("--manifest-path").arg(manifest).output()?)
        };
        if fetch(true)?.status.success() {
            continue;
        }
        let output = fetch(false)?;
        if !output.status.success() {
            return Err(fail(format!(
                "cargo fetch --locked failed for {} ({}): {}",
                manifest.display(),
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
    }
    Ok(manifests.len())
}

fn resolved_inputs(root: &Path) -> Result<BTreeSet<String>> {
    let graph = resolve_graph(root)?;
    build_code::check(root, &graph.build_code)?;
    Ok(graph.inputs)
}

/// Build scripts and proc-macros in the fixture graphs, as reviewed entries.
pub fn current_build_code(root: &Path) -> Result<BTreeSet<ReviewedEntry>> {
    Ok(resolve_graph(root)?.build_code)
}

/// A checkout (path) package other than the fixture itself, reached through
/// built (normal or build) edges of a fixture's resolved graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PathPackage {
    pub name: String,
    /// Built dependencies (registry or path) the package itself declares.
    pub dependencies: Vec<String>,
}

struct Graph {
    inputs: BTreeSet<String>,
    build_code: BTreeSet<ReviewedEntry>,
    /// Fixture directory -> checkout packages in its built closure.
    path_packages: BTreeMap<&'static str, BTreeSet<PathPackage>>,
}

/// Every signed fixture's path-dependency closure may hold only allowlisted,
/// dependency-free leaf crates. Returns the checked closures for reporting.
pub fn check_leaf_closures(root: &Path) -> Result<BTreeMap<&'static str, BTreeSet<PathPackage>>> {
    let graph = resolve_graph(root)?;
    let violations = leaf_violations(&graph.path_packages, FIXTURE_LEAF_CRATES);
    if !violations.is_empty() {
        return Err(fail(format!(
            "signed fixture path-dependency closure holds non-leaf crates; every \
             checkout crate a fixture reaches is a bundle input (docs/signed-fixtures.md, \
             #891). Depend on a dependency-free leaf crate instead:\n  {}",
            violations.join("\n  ")
        )));
    }
    Ok(graph.path_packages)
}

/// Pure leaf rule: each path package is allowlisted and has no built
/// dependencies of its own.
pub(super) fn leaf_violations(
    closures: &BTreeMap<&'static str, BTreeSet<PathPackage>>,
    allowlist: &[&str],
) -> Vec<String> {
    let mut violations = Vec::new();
    for (fixture, packages) in closures {
        for package in packages {
            if !allowlist.contains(&package.name.as_str()) {
                violations.push(format!(
                    "{fixture}: `{}` is not an allowlisted fixture leaf crate",
                    package.name
                ));
            } else if !package.dependencies.is_empty() {
                violations.push(format!(
                    "{fixture}: leaf crate `{}` has dependencies: {}",
                    package.name,
                    package.dependencies.join(", ")
                ));
            }
        }
    }
    violations
}

fn resolve_graph(root: &Path) -> Result<Graph> {
    let root = root.canonicalize()?;
    let mut found = BTreeSet::new();
    let mut path_packages = BTreeMap::new();
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
            let lock = build_code::lock_checksums(&std::fs::read_to_string(
                metadata.workspace_root.join("Cargo.lock"),
            )?);
            let resolve = metadata
                .resolve
                .ok_or_else(|| fail("missing fixture Cargo resolve graph"))?;
            let root_id = resolve
                .root
                .ok_or_else(|| fail("missing fixture Cargo resolve root"))?;
            let packages: BTreeMap<_, _> = metadata.packages.iter().map(|p| (&p.id, p)).collect();
            let nodes: BTreeMap<_, _> = resolve.nodes.iter().map(|n| (&n.id, n)).collect();
            let mut pending = vec![root_id.clone()];
            let mut seen = BTreeSet::new();
            let closure: &mut BTreeSet<PathPackage> = path_packages.entry(*fixture).or_default();
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
                let mut built_dependencies = Vec::new();
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
                        built_dependencies.push(
                            packages
                                .get(&dependency.pkg)
                                .map_or_else(|| dependency.pkg.clone(), |p| p.name.clone()),
                        );
                        pending.push(dependency.pkg.clone());
                    }
                }
                for target in &package.targets {
                    let Some(kind) = target
                        .kind
                        .iter()
                        .find(|k| *k == "custom-build" || *k == "proc-macro")
                    else {
                        continue;
                    };
                    found.insert(build_code::entry(
                        &package.name,
                        &package.version,
                        package.source.as_deref(),
                        kind,
                        &package.manifest_path,
                        &lock,
                    )?);
                }
                if package.source.is_some() {
                    continue;
                }
                if id != root_id {
                    built_dependencies.sort();
                    closure.insert(PathPackage {
                        name: package.name.clone(),
                        dependencies: built_dependencies,
                    });
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
    Ok(Graph {
        inputs,
        build_code: found,
        path_packages,
    })
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
    linker::check_inventory(root, &sources, BUILD_SCRIPTS)?;
    Ok(sources)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn closure(
        fixture: &'static str,
        packages: &[(&str, &[&str])],
    ) -> BTreeMap<&'static str, BTreeSet<PathPackage>> {
        BTreeMap::from([(
            fixture,
            packages
                .iter()
                .map(|(name, deps)| PathPackage {
                    name: (*name).to_owned(),
                    dependencies: deps.iter().map(|d| (*d).to_owned()).collect(),
                })
                .collect(),
        )])
    }

    #[test]
    fn fixture_leaf_closure_admits_dependency_free_allowlisted_leaf() {
        let closures = closure(
            "fixtures/embed-el1-sched",
            &[("carrick-el1-control-abi", &[])],
        );
        assert!(leaf_violations(&closures, FIXTURE_LEAF_CRATES).is_empty());
        let empty = closure("fixtures/embed-copyout", &[]);
        assert!(leaf_violations(&empty, FIXTURE_LEAF_CRATES).is_empty());
    }

    /// Red witness: the pre-#891 `embed-el1-sched` closure reached the kernel
    /// cores through `carrick-el1-abi`.
    #[test]
    fn fixture_leaf_closure_rejects_kernel_crate_closure() {
        let closures = closure(
            "fixtures/embed-el1-sched",
            &[
                (
                    "carrick-el1-abi",
                    &["carrick-sched-core", "carrick-el1-control-abi"],
                ),
                ("carrick-sched-core", &[]),
                ("carrick-el1-control-abi", &[]),
            ],
        );
        let violations = leaf_violations(&closures, FIXTURE_LEAF_CRATES);
        assert_eq!(violations.len(), 2, "{violations:?}");
        assert!(violations[0].contains("`carrick-el1-abi` is not an allowlisted"));
        assert!(violations[1].contains("`carrick-sched-core` is not an allowlisted"));
    }

    #[test]
    fn fixture_leaf_closure_rejects_leaf_that_grew_dependencies() {
        let closures = closure(
            "fixtures/embed-el1-sched",
            &[("carrick-el1-control-abi", &["zerocopy"])],
        );
        let violations = leaf_violations(&closures, FIXTURE_LEAF_CRATES);
        assert_eq!(
            violations,
            [
                "fixtures/embed-el1-sched: leaf crate `carrick-el1-control-abi` has dependencies: zerocopy"
            ]
        );
    }
}
