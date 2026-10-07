//! Test-target lanes: every workspace test target belongs to exactly one gate.
//!
//! A test target that no gate runs is a test that does not exist. Integration
//! targets (`tests/*.rs`) are invisible to `cargo test --lib --bins`, so a test
//! that moves from a crate's `src/` into its `tests/` directory silently leaves
//! every gate. This module makes the lane DERIVED from Cargo metadata instead of
//! hand-listed in recipes:
//!
//! * A target's lane is declared next to the target, in its package manifest:
//!
//!   ```toml
//!   [package.metadata.carrick.test-lanes]
//!   "*" = "signed-hvf"                     # package default
//!   x86_kvm_run = "kvm"                    # one target
//!   live_vcpu = { lane = "manual", reason = "FreeBSD bhyve x86_64 host" }
//!   ```
//!
//!   An undeclared target is in the `host` lane: VM-free, run by `just test`.
//! * `test-lanes args --lane <lane>` prints the `cargo test` selection for a
//!   derived lane, one package per line, so the gate recipe never names targets.
//! * `test-lanes check` fails when a declaration names a missing target or an
//!   unknown lane, when a derived lane's recipe does not consume `test-lanes
//!   args`, or when a named-lane target is absent from its gate recipe.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use thiserror::Error;

/// How a lane reaches a gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// The recipe consumes `test-lanes args --lane <lane>`; it names no target.
    Derived(&'static str),
    /// One of these recipes (or a script it invokes) names `-p <pkg>` and
    /// `--test <target>` on one command line.
    Named(&'static [&'static str]),
    /// Some recipe runs `scripts/test-signed.sh <pkg>` (all of the package's
    /// test executables, signed).
    SignedPackage,
    /// No automated gate can run it (hardware no runner has). Every target here
    /// must carry a `reason`, and `check` prints the whole list.
    Manual,
}

#[derive(Debug, Clone, Copy)]
pub struct Lane {
    pub name: &'static str,
    pub gate: Gate,
}

/// The single source of lane names and the gate each one reaches.
pub const LANES: &[Lane] = &[
    Lane {
        name: "host",
        gate: Gate::Derived("test"),
    },
    Lane {
        name: "kvm",
        gate: Gate::Derived("test-kvm"),
    },
    Lane {
        name: "integration",
        gate: Gate::Named(&["test-integration"]),
    },
    Lane {
        name: "signed-cli",
        gate: Gate::Named(&["conformance-probes", "bench"]),
    },
    Lane {
        name: "signed-hvf",
        gate: Gate::SignedPackage,
    },
    Lane {
        name: "manual",
        gate: Gate::Manual,
    },
];

pub const DEFAULT_LANE: &str = "host";

#[derive(clap::Args, Debug, Clone)]
pub struct TestLanesArgs {
    #[command(subcommand)]
    pub action: TestLanesAction,
    #[arg(
        long,
        global = true,
        help = "Read `cargo metadata --no-deps` JSON from this file instead of running cargo"
    )]
    pub metadata: Option<PathBuf>,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum TestLanesAction {
    #[command(about = "List every test target with its lane")]
    List,
    #[command(about = "Print `cargo test` package selections for a derived lane")]
    Args {
        #[arg(long)]
        lane: String,
        #[arg(
            long,
            default_value = "",
            allow_hyphen_values = true,
            help = "Feature flags appended for packages whose default features select platform-macos"
        )]
        platform_features: String,
    },
    #[command(about = "Fail unless every test target is covered by a gate recipe")]
    Check {
        #[arg(long, default_value = "justfile")]
        justfile: PathBuf,
    },
}

#[derive(Debug, Error)]
pub enum TestLanesError {
    #[error("cargo metadata: {0}")]
    Metadata(String),
    #[error("I/O error at '{}': {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid metadata JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unknown lane `{0}`")]
    UnknownLane(String),
    #[error("lane `{0}` is not derived; its gate recipe names its targets")]
    NotDerived(String),
    #[error("test-lanes check failed:\n{0}")]
    Check(String),
}

/// One `cargo test` target and the lane it resolved to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TestTarget {
    pub package: String,
    pub target: String,
    pub lane: String,
    pub reason: Option<String>,
    pub macos_default: bool,
}

/// Resolve every test target in the workspace and every declaration error.
pub fn resolve(metadata: &Value) -> (Vec<TestTarget>, Vec<String>) {
    let mut targets = Vec::new();
    let mut errors = Vec::new();
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for package in packages {
        let name = package.get("name").and_then(Value::as_str).unwrap_or("");
        let names: BTreeSet<&str> = package
            .get("targets")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter(|target| {
                target
                    .get("kind")
                    .and_then(Value::as_array)
                    .is_some_and(|kinds| kinds.iter().any(|kind| kind == "test"))
            })
            .filter_map(|target| target.get("name").and_then(Value::as_str))
            .collect();
        let declared = package
            .pointer("/metadata/carrick/test-lanes")
            .and_then(Value::as_object);
        let mut declarations: BTreeMap<&str, (String, Option<String>)> = BTreeMap::new();
        if let Some(declared) = declared {
            for (key, value) in declared {
                let parsed = match value {
                    Value::String(lane) => Some((lane.clone(), None)),
                    Value::Object(table) => table.get("lane").and_then(Value::as_str).map(|lane| {
                        (
                            lane.to_owned(),
                            table
                                .get("reason")
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                        )
                    }),
                    _ => None,
                };
                let Some((lane, reason)) = parsed else {
                    errors.push(format!(
                        "{name}: test-lanes.{key} must be a lane string or {{ lane, reason }}"
                    ));
                    continue;
                };
                if key != "*" && !names.contains(key.as_str()) {
                    errors.push(format!(
                        "{name}: test-lanes names `{key}`, which is not a test target of the package"
                    ));
                }
                if lane_of(&lane).is_none() {
                    errors.push(format!(
                        "{name}: test-lanes.{key} uses unknown lane `{lane}`"
                    ));
                }
                declarations.insert(key.as_str(), (lane, reason));
            }
        }
        let macos_default = package
            .pointer("/features/default")
            .and_then(Value::as_array)
            .is_some_and(|features| features.iter().any(|f| f == "platform-macos"));
        for target in names {
            let (lane, reason) = declarations
                .get(target)
                .or_else(|| declarations.get("*"))
                .cloned()
                .unwrap_or_else(|| (DEFAULT_LANE.to_owned(), None));
            targets.push(TestTarget {
                package: name.to_owned(),
                target: target.to_owned(),
                lane,
                reason,
                macos_default,
            });
        }
    }
    targets.sort();
    (targets, errors)
}

pub fn lane_of(name: &str) -> Option<&'static Lane> {
    LANES.iter().find(|lane| lane.name == name)
}

/// `cargo test` selections for a derived lane: one line per package.
pub fn lane_args(
    targets: &[TestTarget],
    lane: &str,
    platform_features: &str,
) -> Result<Vec<String>, TestLanesError> {
    match lane_of(lane) {
        None => return Err(TestLanesError::UnknownLane(lane.to_owned())),
        Some(Lane {
            gate: Gate::Derived(_),
            ..
        }) => {}
        Some(_) => return Err(TestLanesError::NotDerived(lane.to_owned())),
    }
    let mut by_package: BTreeMap<&str, (bool, Vec<&str>)> = BTreeMap::new();
    for target in targets.iter().filter(|target| target.lane == lane) {
        let entry = by_package
            .entry(target.package.as_str())
            .or_insert((target.macos_default, Vec::new()));
        entry.1.push(target.target.as_str());
    }
    Ok(by_package
        .into_iter()
        .map(|(package, (macos_default, names))| {
            let mut line = format!("-p {package}");
            for name in names {
                let _ = write!(line, " --test {name}");
            }
            if macos_default && !platform_features.trim().is_empty() {
                let _ = write!(line, " {}", platform_features.trim());
            }
            line
        })
        .collect())
}

/// Recipe body (backslash continuations joined) of `recipe` in `justfile`, plus
/// the text of every repository script the body invokes.
fn recipe_text(root: &Path, justfile: &str, recipe: &str) -> Option<String> {
    let mut lines = justfile.lines();
    let header = |line: &str| {
        let line = line.strip_prefix('@').unwrap_or(line);
        line.strip_prefix(recipe).is_some_and(|rest| {
            rest.starts_with(':') || rest.starts_with(' ') && rest.contains(':')
        })
    };
    lines.by_ref().find(|line| header(line))?;
    let mut body = String::new();
    for line in lines {
        if !line.is_empty() && !line.starts_with(' ') && !line.starts_with('\t') {
            break;
        }
        body.push_str(line);
        body.push('\n');
    }
    let mut text = body.replace("\\\n", " ");
    let scripts: BTreeSet<String> = text
        .split(|c: char| c.is_whitespace() || c == '"' || c == '\'')
        .map(|token| token.strip_prefix("./").unwrap_or(token))
        .filter(|token| token.starts_with("scripts/") && token.ends_with(".sh"))
        .map(str::to_owned)
        .collect();
    for script in scripts {
        if let Ok(source) = std::fs::read_to_string(root.join(&script)) {
            text.push('\n');
            text.push_str(&source.replace("\\\n", " "));
        }
    }
    Some(text)
}

fn line_selects(line: &str, package: &str, target: &str) -> bool {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let pair = |flag: &str, value: &str| tokens.windows(2).any(|w| w[0] == flag && w[1] == value);
    pair("-p", package) && pair("--test", target)
}

/// Every coverage failure in `targets` against `justfile`.
pub fn coverage_errors(root: &Path, justfile: &str, targets: &[TestTarget]) -> Vec<String> {
    let mut errors = Vec::new();
    for lane in LANES {
        if let Gate::Derived(recipe) = lane.gate {
            let consumer = format!("test-lanes args --lane {}", lane.name);
            match recipe_text(root, justfile, recipe) {
                None => errors.push(format!(
                    "lane `{}`: gate recipe `{recipe}` is missing",
                    lane.name
                )),
                Some(text) if !text.contains(&consumer) => errors.push(format!(
                    "lane `{}`: recipe `{recipe}` does not consume `{consumer}`",
                    lane.name
                )),
                Some(_) => {}
            }
        }
    }
    for target in targets {
        let Some(lane) = lane_of(&target.lane) else {
            continue;
        };
        match lane.gate {
            Gate::Derived(_) => {}
            Gate::Named(recipes) => {
                let covered = recipes.iter().any(|recipe| {
                    recipe_text(root, justfile, recipe).is_some_and(|text| {
                        text.lines()
                            .any(|line| line_selects(line, &target.package, &target.target))
                    })
                });
                if !covered {
                    errors.push(format!(
                        "{}::{} is in lane `{}`, but none of {:?} runs `-p {} --test {}`",
                        target.package,
                        target.target,
                        lane.name,
                        recipes,
                        target.package,
                        target.target
                    ));
                }
            }
            Gate::SignedPackage => {
                let needle = format!("test-signed.sh {}", target.package);
                let covered = justfile.lines().any(|line| {
                    line.contains(&needle)
                        && line[line.find(&needle).unwrap_or(0) + needle.len()..]
                            .chars()
                            .next()
                            .is_none_or(char::is_whitespace)
                });
                if !covered {
                    errors.push(format!(
                        "{}::{} is in lane `signed-hvf`, but no recipe runs `{needle}`",
                        target.package, target.target
                    ));
                }
            }
            Gate::Manual => {
                if target
                    .reason
                    .as_deref()
                    .is_none_or(|reason| reason.trim().is_empty())
                {
                    errors.push(format!(
                        "{}::{} is in lane `manual` without a `reason`",
                        target.package, target.target
                    ));
                }
            }
        }
    }
    errors
}

/// Contract bindings (`[bindings]` in `conformance-contracts/contracts/*.toml`)
/// whose path names an integration test target (`<crate>::<target>::...`).
/// Returns `(contract file, binding, target)` triples and parse errors.
pub fn contract_test_bindings(
    root: &Path,
    targets: &[TestTarget],
) -> (Vec<(String, String, TestTarget)>, Vec<String>) {
    let mut bound = Vec::new();
    let mut errors = Vec::new();
    let dir = root.join("conformance-contracts/contracts");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return (bound, vec![format!("cannot read {}", dir.display())]);
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    files.sort();
    for file in files {
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let parsed: toml::Value = match std::fs::read_to_string(&file)
            .map_err(|e| e.to_string())
            .and_then(|text| text.parse().map_err(|e: toml::de::Error| e.to_string()))
        {
            Ok(value) => value,
            Err(error) => {
                errors.push(format!("{name}: {error}"));
                continue;
            }
        };
        let Some(bindings) = parsed.get("bindings").and_then(toml::Value::as_table) else {
            continue;
        };
        for value in bindings.values().filter_map(toml::Value::as_str) {
            for binding in value.split(';') {
                let path = binding.split_whitespace().next().unwrap_or("");
                let mut segments = path.split("::");
                let (Some(package), Some(target)) = (segments.next(), segments.next()) else {
                    continue;
                };
                let target = target.split('{').next().unwrap_or(target);
                if let Some(found) = targets
                    .iter()
                    .find(|t| t.package == package && t.target == target)
                {
                    bound.push((name.clone(), path.to_owned(), found.clone()));
                }
            }
        }
    }
    (bound, errors)
}

fn load_metadata(root: &Path, file: Option<&Path>) -> Result<Value, TestLanesError> {
    if let Some(file) = file {
        let text = std::fs::read_to_string(file).map_err(|source| TestLanesError::Io {
            path: file.to_path_buf(),
            source,
        })?;
        return Ok(serde_json::from_str(&text)?);
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(root)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--locked",
            "--offline",
        ])
        .output()
        .map_err(|source| TestLanesError::Io {
            path: root.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        return Err(TestLanesError::Metadata(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

pub fn run(
    root: &Path,
    args: TestLanesArgs,
    writer: &mut dyn std::io::Write,
) -> Result<(), TestLanesError> {
    let metadata = load_metadata(root, args.metadata.as_deref())?;
    let (targets, mut errors) = resolve(&metadata);
    let io = |source| TestLanesError::Io {
        path: PathBuf::from("stdout"),
        source,
    };
    match args.action {
        TestLanesAction::List => {
            for target in &targets {
                writeln!(
                    writer,
                    "{:<12} {}::{}",
                    target.lane, target.package, target.target
                )
                .map_err(io)?;
            }
        }
        TestLanesAction::Args {
            lane,
            platform_features,
        } => {
            if !errors.is_empty() {
                return Err(TestLanesError::Check(errors.join("\n")));
            }
            for line in lane_args(&targets, &lane, &platform_features)? {
                writeln!(writer, "{line}").map_err(io)?;
            }
        }
        TestLanesAction::Check { justfile } => {
            let path = root.join(&justfile);
            let text = std::fs::read_to_string(&path)
                .map_err(|source| TestLanesError::Io { path, source })?;
            errors.extend(coverage_errors(root, &text, &targets));
            let (bound, binding_errors) = contract_test_bindings(root, &targets);
            errors.extend(binding_errors);
            for (contract, binding, target) in &bound {
                if lane_of(&target.lane).is_none_or(|lane| lane.gate == Gate::Manual) {
                    errors.push(format!(
                        "{contract}: binding `{binding}` names test target {}::{}, which no gate runs (lane `{}`)",
                        target.package, target.target, target.lane
                    ));
                }
            }
            if !errors.is_empty() {
                return Err(TestLanesError::Check(errors.join("\n")));
            }
            let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
            for target in &targets {
                *counts.entry(target.lane.as_str()).or_default() += 1;
            }
            let summary: Vec<String> = counts
                .iter()
                .map(|(lane, count)| format!("{lane}={count}"))
                .collect();
            writeln!(
                writer,
                "test-lanes: {} test targets, all gated ({}); {} contract bindings name gated test targets",
                targets.len(),
                summary.join(" "),
                bound.len()
            )
            .map_err(io)?;
            for target in targets.iter().filter(|target| target.lane == "manual") {
                writeln!(
                    writer,
                    "test-lanes: manual (no automated gate) {}::{}: {}",
                    target.package,
                    target.target,
                    target.reason.as_deref().unwrap_or("")
                )
                .map_err(io)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn package(name: &str, tests: &[&str], lanes: Value) -> Value {
        json!({
            "name": name,
            "features": {"default": []},
            "targets": tests.iter().map(|t| json!({"name": t, "kind": ["test"]})).collect::<Vec<_>>(),
            "metadata": {"carrick": {"test-lanes": lanes}},
        })
    }

    #[test]
    fn undeclared_targets_default_to_host_and_star_sets_the_package() {
        let metadata = json!({"packages": [
            package("a", &["one", "two"], json!({})),
            package("b", &["three", "four"], json!({"*": "kvm", "four": "host"})),
        ]});
        let (targets, errors) = resolve(&metadata);
        assert!(errors.is_empty(), "{errors:?}");
        let lanes: Vec<(&str, &str)> = targets
            .iter()
            .map(|t| (t.target.as_str(), t.lane.as_str()))
            .collect();
        assert_eq!(
            lanes,
            [
                ("one", "host"),
                ("two", "host"),
                ("four", "host"),
                ("three", "kvm")
            ]
        );
        assert_eq!(
            lane_args(&targets, "host", "").unwrap_or_default(),
            ["-p a --test one --test two", "-p b --test four"]
        );
    }

    #[test]
    fn stale_names_unknown_lanes_and_reasonless_manual_targets_fail() {
        let metadata = json!({"packages": [package(
            "a",
            &["one", "two"],
            json!({"gone": "host", "one": "nowhere", "two": "manual"}),
        )]});
        let (targets, mut errors) = resolve(&metadata);
        errors.extend(coverage_errors(
            Path::new("."),
            "test:\n    x test-lanes args --lane host\ntest-kvm:\n    x test-lanes args --lane kvm\n",
            &targets,
        ));
        let all = errors.join("\n");
        assert!(all.contains("`gone`, which is not a test target"), "{all}");
        assert!(all.contains("unknown lane `nowhere`"), "{all}");
        assert!(
            all.contains("a::two is in lane `manual` without a `reason`"),
            "{all}"
        );
    }

    #[test]
    fn named_lanes_need_the_exact_package_and_target_on_one_command_line() {
        let metadata = json!({"packages": [package(
            "a",
            &["one", "two"],
            json!({"*": "integration"}),
        )]});
        let (targets, _) = resolve(&metadata);
        let justfile = "test:\n    t test-lanes args --lane host\n\
            test-kvm:\n    t test-lanes args --lane kvm\n\
            test-integration:\n    cargo test -p a \\\n        --test one\n    cargo test -p b --test two\n";
        let errors = coverage_errors(Path::new("."), justfile, &targets);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("a::two"), "{errors:?}");
    }

    #[test]
    fn derived_recipes_must_consume_their_lane() {
        let errors = coverage_errors(Path::new("."), "test:\n    cargo test --lib\n", &[]);
        let all = errors.join("\n");
        assert!(all.contains("recipe `test` does not consume"), "{all}");
        assert!(all.contains("gate recipe `test-kvm` is missing"), "{all}");
    }

    #[test]
    fn platform_features_follow_macos_default_packages_only() {
        let mut runtime = package("runtime", &["loop"], json!({}));
        runtime["features"] = json!({"default": ["platform-macos"]});
        let metadata = json!({"packages": [runtime, package("core", &["x"], json!({}))]});
        let (targets, _) = resolve(&metadata);
        assert_eq!(
            lane_args(
                &targets,
                "host",
                "--no-default-features --features platform-linux"
            )
            .unwrap_or_default(),
            [
                "-p core --test x",
                "-p runtime --test loop --no-default-features --features platform-linux"
            ]
        );
        assert!(matches!(
            lane_args(&targets, "integration", ""),
            Err(TestLanesError::NotDerived(_))
        ));
    }
}
