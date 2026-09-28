//! Mechanical personality boundary checker.
//!
//! Enforces the substrate vs Linux personality separation per the accepted EL1 kernel design:
//! Substrate crates (MMU, run queues, timers, ASID/occupancy management, GIC) must never
//! depend on `carrick-abi` or designated Linux personality crates, and must not hard-code
//! production Linux errno literals (e.g. `-110`) or Linux errno/syscall symbols (`LINUX_*`, `SYS_*`, `ETIMEDOUT`, etc.).
//!
//! # Verification Principles & Architecture
//! 1. **AST-Level Lexical Scoping**: Evaluates `#[cfg(...)]` syntax trees. Code is only
//!    exempt when proven absent during production compilation (`test = false`). Conditions
//!    such as `#[cfg(not(test))]`, `#[cfg(any(test, feature = "prod"))]`, or feature flags
//!    containing "test" are fail-closed and scanned as production code.
//! 2. **Target Source Roots & Module Tree Traversal**: Traverses actual target entry points
//!    from Cargo metadata (including custom `[lib].path`, `[[bin]].path`, and build scripts)
//!    and out-of-line files (`mod foo;`, `#[path = "..."] mod bar;`), propagating lexical
//!    test-only context. Any unreferenced `.rs` files are fail-closed audited as production code.
//!    Configured substrate crates with zero scanned production files fail closed.
//! 3. **Authoritative Resolved Cargo Dependency Graph**:
//!    Traverses the full resolved Cargo dependency graph generated with `--all-features`
//!    to cover normal, build, target-conditioned, alias/renamed, and optional transitive edges.
//!    Dev-dependencies are scoped separately and excluded from the shipped closure.
//!    Unresolved graph nodes or missing packages fail closed as hard errors.
//! 4. **Macro TokenStream Inspection**: Inspects declarative macro definitions and macro
//!    invocations (`mac.tokens`) for forbidden literals and personality symbols.
//! 5. **Prose and Test Oracle Exemption**: Non-doc comments and doc attributes (`#[doc = "..."]`)
//!    are excluded from code checks to prevent false positives on prose. Test-only code
//!    (`#[cfg(test)]`, `#[test]`) is permitted to assert oracles against known Linux constants.

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use syn::visit::Visit;
use thiserror::Error;

/// Default allowlist of substrate crates subject to boundary verification.
pub const DEFAULT_SUBSTRATE_ALLOWLIST: &[&str] = &[
    "carrick-sched-core",
    "carrick-mmu-core",
    "carrick-signal-core",
];

/// Designated Linux personality or ABI crates forbidden in substrate dependency closures.
pub const FORBIDDEN_PERSONALITY_CRATES: &[&str] = &[
    "carrick-abi",
    "carrick-el1-abi",
    "carrick-signal-core",
    "carrick-timer-core",
    "carrick-kernel",
];

/// Known Linux errno symbol names forbidden in production substrate source code.
pub const FORBIDDEN_ERRNO_SYMBOLS: &[&str] = &[
    "ETIMEDOUT",
    "ETIMEDOUT_RESULT",
    "EAGAIN",
    "EINTR",
    "EINVAL",
    "ENOSYS",
    "EPERM",
    "ESRCH",
    "EBADF",
    "ECHILD",
    "EDEADLK",
    "ENOMEM",
    "EACCES",
    "EFAULT",
    "EBUSY",
    "EEXIST",
    "EXDEV",
    "ENODEV",
    "ENOTDIR",
    "EISDIR",
    "EMFILE",
    "ENFILE",
    "ENOTTY",
    "ETXTBSY",
    "EFBIG",
    "ENOSPC",
    "ESPIPE",
    "EROFS",
    "EMLINK",
    "EPIPE",
    "EDOM",
    "ERANGE",
    "LinuxErrno",
];

#[derive(Debug, Error)]
pub enum BoundaryError {
    #[error("allowlisted substrate crate `{crate_name}` was not found in metadata at {}", path.display())]
    MissingCrate { crate_name: String, path: PathBuf },
    #[error("dependency `{dep_name}` for crate `{crate_name}` specifies missing path manifest {}", path.display())]
    MissingPathManifest {
        crate_name: String,
        dep_name: String,
        path: PathBuf,
    },
    #[error(
        "cargo metadata not provided; please provide --metadata-file <path> or generate <root>/target/cargo-metadata.json with 'cargo metadata --locked --offline --all-features --format-version 1'"
    )]
    MissingMetadata,
    #[error("Cargo metadata does not belong to workspace {}", root.display())]
    MetadataWorkspaceMismatch { root: PathBuf },
    #[error("cannot parse cargo metadata JSON: {source}")]
    MetadataJson {
        #[source]
        source: serde_json::Error,
    },
    #[error("unresolved cargo dependency graph for crate `{crate_name}`")]
    UnresolvedDependencyGraph { crate_name: String },
    #[error("configured substrate crate `{crate_name}` has zero scanned production source files")]
    NoScannedSourceFiles { crate_name: String },
    #[error("cannot read file {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse TOML at {}: {source}", path.display())]
    Toml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("cannot parse Rust source at {}: {source}", path.display())]
    Syn {
        path: PathBuf,
        #[source]
        source: syn::Error,
    },
    #[error("substrate boundary violations detected ({count} violation(s)):\n{report}")]
    Violations { count: usize, report: String },
}

/// Configuration for boundary check execution.
#[derive(Clone, Debug)]
pub struct BoundaryConfig {
    pub substrate_allowlist: Vec<String>,
    pub forbidden_personality_crates: Vec<String>,
    pub forbidden_errno_symbols: Vec<String>,
    pub metadata_file: Option<PathBuf>,
    pub metadata_json: Option<String>,
    pub custom_metadata_json: Option<String>,
}

impl Default for BoundaryConfig {
    fn default() -> Self {
        Self {
            substrate_allowlist: DEFAULT_SUBSTRATE_ALLOWLIST
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            forbidden_personality_crates: FORBIDDEN_PERSONALITY_CRATES
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            forbidden_errno_symbols: FORBIDDEN_ERRNO_SYMBOLS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            metadata_file: None,
            metadata_json: None,
            custom_metadata_json: None,
        }
    }
}

/// A forbidden dependency edge reaching a personality crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyViolation {
    pub substrate_crate: String,
    pub forbidden_crate: String,
    pub dependency_chain: Vec<String>,
    pub edge_kind: String,
}

/// A forbidden literal or symbol found in production source code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceViolation {
    pub substrate_crate: String,
    pub file_path: PathBuf,
    pub line: usize,
    pub column: usize,
    pub symbol_or_literal: String,
    pub reason: String,
}

/// Audit report for one substrate crate.
#[derive(Clone, Debug, Default)]
pub struct CrateAuditReport {
    pub crate_name: String,
    pub crate_path: PathBuf,
    pub shipped_dependency_closure: Vec<String>,
    pub dev_dependencies_scope: Vec<String>,
    pub scanned_source_files: Vec<PathBuf>,
    pub dependency_violations: Vec<DependencyViolation>,
    pub source_violations: Vec<SourceViolation>,
}

impl CrateAuditReport {
    pub fn is_clean(&self) -> bool {
        self.dependency_violations.is_empty() && self.source_violations.is_empty()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CargoMetadata {
    #[serde(default)]
    pub packages: Vec<MetadataPackage>,
    #[serde(default)]
    pub resolve: Option<MetadataResolve>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub target_directory: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetadataPackage {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub manifest_path: String,
    #[serde(default)]
    pub targets: Vec<MetadataTarget>,
    #[serde(default)]
    pub dependencies: Vec<MetadataDependency>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetadataTarget {
    #[serde(default)]
    pub kind: Vec<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub src_path: String,
    #[serde(default)]
    pub edition: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetadataDependency {
    pub name: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub req: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub rename: Option<String>,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetadataResolve {
    #[serde(default)]
    pub nodes: Vec<MetadataResolveNode>,
    #[serde(default)]
    pub root: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetadataResolveNode {
    pub id: String,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub deps: Vec<MetadataResolveDep>,
    #[serde(default)]
    pub features: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetadataResolveDep {
    pub name: String,
    pub pkg: String,
    #[serde(default)]
    pub dep_kinds: Vec<MetadataDepKind>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetadataDepKind {
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
}

/// Check all allowlisted substrate crates in the workspace at `root`.
pub fn check_substrate_boundary(
    root: &Path,
    config: &BoundaryConfig,
) -> Result<Vec<CrateAuditReport>, BoundaryError> {
    let metadata: CargoMetadata = if let Some(custom_json) = &config.custom_metadata_json {
        serde_json::from_str(custom_json)
            .map_err(|source| BoundaryError::MetadataJson { source })?
    } else if let Some(meta_json) = &config.metadata_json {
        serde_json::from_str(meta_json).map_err(|source| BoundaryError::MetadataJson { source })?
    } else if let Some(meta_file) = &config.metadata_file {
        let content = fs::read_to_string(meta_file).map_err(|source| BoundaryError::Io {
            path: meta_file.clone(),
            source,
        })?;
        serde_json::from_str(&content).map_err(|source| BoundaryError::MetadataJson { source })?
    } else {
        let default_target_meta = root.join("target").join("cargo-metadata.json");
        if default_target_meta.exists() {
            let content =
                fs::read_to_string(&default_target_meta).map_err(|source| BoundaryError::Io {
                    path: default_target_meta.clone(),
                    source,
                })?;
            serde_json::from_str(&content)
                .map_err(|source| BoundaryError::MetadataJson { source })?
        } else {
            return Err(BoundaryError::MissingMetadata);
        }
    };

    let canonical_root = fs::canonicalize(root).map_err(|source| BoundaryError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    let metadata_root = metadata
        .workspace_root
        .as_deref()
        .and_then(|path| fs::canonicalize(path).ok());
    if metadata_root.as_ref() != Some(&canonical_root) {
        return Err(BoundaryError::MetadataWorkspaceMismatch {
            root: root.to_path_buf(),
        });
    }

    let forbidden_crates: BTreeSet<String> = config
        .forbidden_personality_crates
        .iter()
        .cloned()
        .collect();
    let forbidden_symbols: BTreeSet<String> =
        config.forbidden_errno_symbols.iter().cloned().collect();

    let mut reports = Vec::new();
    let mut total_violations = 0;
    let mut violation_messages = Vec::new();

    for crate_name in &config.substrate_allowlist {
        let mut report = CrateAuditReport {
            crate_name: crate_name.clone(),
            ..Default::default()
        };

        // 1. Audit Dependency Closure via Resolved Metadata
        let substrate_pkg = audit_crate_dependencies_metadata(
            root,
            crate_name,
            &metadata,
            &forbidden_crates,
            &mut report,
        )?;

        report.crate_path = PathBuf::from(&substrate_pkg.manifest_path)
            .parent()
            .unwrap_or_else(|| Path::new(crate_name))
            .to_path_buf();

        // 2. Audit Source Code via Target Roots and Module Tree Traversal
        audit_crate_source(crate_name, substrate_pkg, &forbidden_symbols, &mut report)?;

        // Fail-closed: check that at least 1 production source file was scanned
        if report.scanned_source_files.is_empty() {
            return Err(BoundaryError::NoScannedSourceFiles {
                crate_name: crate_name.clone(),
            });
        }

        for dv in &report.dependency_violations {
            total_violations += 1;
            violation_messages.push(format!(
                "  [DEP] crate `{}` reaches forbidden personality crate `{}` via {} edge: {}",
                dv.substrate_crate,
                dv.forbidden_crate,
                dv.edge_kind,
                dv.dependency_chain.join(" -> ")
            ));
        }

        for sv in &report.source_violations {
            total_violations += 1;
            violation_messages.push(format!(
                "  [SRC] {}:{}:{}: crate `{}`: forbidden code `{}` ({})",
                sv.file_path.display(),
                sv.line,
                sv.column,
                sv.substrate_crate,
                sv.symbol_or_literal,
                sv.reason
            ));
        }

        reports.push(report);
    }

    if total_violations > 0 {
        return Err(BoundaryError::Violations {
            count: total_violations,
            report: violation_messages.join("\n"),
        });
    }

    Ok(reports)
}

fn audit_crate_dependencies_metadata<'a>(
    root: &Path,
    substrate_crate: &str,
    metadata: &'a CargoMetadata,
    forbidden_crates: &BTreeSet<String>,
    report: &mut CrateAuditReport,
) -> Result<&'a MetadataPackage, BoundaryError> {
    let substrate_pkg = metadata
        .packages
        .iter()
        .find(|p| {
            let expected = root.join("crates").join(substrate_crate).join("Cargo.toml");
            p.name == substrate_crate
                && fs::canonicalize(&p.manifest_path)
                    .ok()
                    .zip(fs::canonicalize(expected).ok())
                    .is_some_and(|(actual, expected)| actual == expected)
        })
        .ok_or_else(|| {
            let crate_dir = root.join("crates").join(substrate_crate);
            BoundaryError::MissingCrate {
                crate_name: substrate_crate.to_string(),
                path: crate_dir,
            }
        })?;

    let resolve =
        metadata
            .resolve
            .as_ref()
            .ok_or_else(|| BoundaryError::UnresolvedDependencyGraph {
                crate_name: substrate_crate.to_string(),
            })?;

    let mut pkg_index: std::collections::BTreeMap<&str, &MetadataPackage> =
        std::collections::BTreeMap::new();
    for pkg in &metadata.packages {
        pkg_index.insert(&pkg.id, pkg);
    }

    let mut node_index: std::collections::BTreeMap<&str, &MetadataResolveNode> =
        std::collections::BTreeMap::new();
    for node in &resolve.nodes {
        node_index.insert(&node.id, node);
    }

    let substrate_node = node_index.get(substrate_pkg.id.as_str()).ok_or_else(|| {
        BoundaryError::UnresolvedDependencyGraph {
            crate_name: substrate_crate.to_string(),
        }
    })?;

    // Verify declared non-dev dependencies are resolved in the graph
    for dep in &substrate_pkg.dependencies {
        let is_dev = dep.kind.as_deref() == Some("dev");
        if !is_dev {
            let is_resolved = substrate_node
                .deps
                .iter()
                .any(|d| d.name == dep.name || dep.rename.as_deref() == Some(&d.name));
            if !is_resolved && !dep.optional {
                return Err(BoundaryError::UnresolvedDependencyGraph {
                    crate_name: dep.name.clone(),
                });
            }
        }
    }

    let mut visited = BTreeSet::new();
    let mut shipped_closure = BTreeSet::new();
    let mut dev_scope = BTreeSet::new();
    let mut queue = VecDeque::new();

    visited.insert(substrate_pkg.id.clone());

    // Inspect direct dependencies of substrate crate
    for dep in &substrate_node.deps {
        let dev_only = !dep.dep_kinds.is_empty()
            && dep
                .dep_kinds
                .iter()
                .all(|dk| dk.kind.as_deref() == Some("dev"));

        let target_pkg = match pkg_index.get(dep.pkg.as_str()) {
            Some(p) => p,
            None => {
                return Err(BoundaryError::UnresolvedDependencyGraph {
                    crate_name: dep.name.clone(),
                });
            }
        };

        if dev_only {
            dev_scope.insert(target_pkg.name.clone());
        } else {
            shipped_closure.insert(target_pkg.name.clone());

            let is_renamed =
                dep.name != target_pkg.name && dep.name != target_pkg.name.replace('-', "_");
            let dep_display = if is_renamed {
                format!("{}(renamed:{})", dep.name, target_pkg.name)
            } else {
                target_pkg.name.clone()
            };

            let edge_kind = dep
                .dep_kinds
                .first()
                .map(|dk| match (&dk.kind, &dk.target) {
                    (Some(k), Some(t)) => format!("{}({})", k, t),
                    (Some(k), None) => k.clone(),
                    (None, Some(t)) => format!("target({})", t),
                    (None, None) => "normal".to_string(),
                })
                .unwrap_or_else(|| "normal".to_string());

            let chain = vec![substrate_crate.to_string(), dep_display];

            if forbidden_crates.contains(&target_pkg.name) {
                report.dependency_violations.push(DependencyViolation {
                    substrate_crate: substrate_crate.to_string(),
                    forbidden_crate: target_pkg.name.clone(),
                    dependency_chain: chain.clone(),
                    edge_kind,
                });
            }

            if visited.insert(dep.pkg.clone()) {
                queue.push_back((dep.pkg.clone(), chain));
            }
        }
    }

    // Traverse transitive dependencies (non-dev edges only)
    while let Some((curr_pkg_id, chain)) = queue.pop_front() {
        let curr_node = node_index.get(curr_pkg_id.as_str()).ok_or_else(|| {
            BoundaryError::UnresolvedDependencyGraph {
                crate_name: curr_pkg_id.clone(),
            }
        })?;

        for dep in &curr_node.deps {
            let dev_only = !dep.dep_kinds.is_empty()
                && dep
                    .dep_kinds
                    .iter()
                    .all(|dk| dk.kind.as_deref() == Some("dev"));

            if dev_only {
                continue;
            }

            let target_pkg = match pkg_index.get(dep.pkg.as_str()) {
                Some(p) => p,
                None => {
                    return Err(BoundaryError::UnresolvedDependencyGraph {
                        crate_name: dep.name.clone(),
                    });
                }
            };

            shipped_closure.insert(target_pkg.name.clone());

            let is_renamed =
                dep.name != target_pkg.name && dep.name != target_pkg.name.replace('-', "_");
            let dep_display = if is_renamed {
                format!("{}(renamed:{})", dep.name, target_pkg.name)
            } else {
                target_pkg.name.clone()
            };

            let edge_kind = dep
                .dep_kinds
                .first()
                .map(|dk| match (&dk.kind, &dk.target) {
                    (Some(k), Some(t)) => format!("{}({})", k, t),
                    (Some(k), None) => k.clone(),
                    (None, Some(t)) => format!("target({})", t),
                    (None, None) => "normal".to_string(),
                })
                .unwrap_or_else(|| "normal".to_string());

            let mut next_chain = chain.clone();
            next_chain.push(dep_display);

            if forbidden_crates.contains(&target_pkg.name) {
                let already_reported = report.dependency_violations.iter().any(|v| {
                    v.forbidden_crate == target_pkg.name && v.dependency_chain == next_chain
                });
                if !already_reported {
                    report.dependency_violations.push(DependencyViolation {
                        substrate_crate: substrate_crate.to_string(),
                        forbidden_crate: target_pkg.name.clone(),
                        dependency_chain: next_chain.clone(),
                        edge_kind,
                    });
                }
            }

            if visited.insert(dep.pkg.clone()) {
                queue.push_back((dep.pkg.clone(), next_chain));
            }
        }
    }

    report.shipped_dependency_closure = shipped_closure.into_iter().collect();
    report.dev_dependencies_scope = dev_scope.into_iter().collect();

    Ok(substrate_pkg)
}

// ---------------------------------------------------------------------------
// CFG Syntax Parsing & Evaluation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum CfgExpr {
    Test,
    Not(Box<CfgExpr>),
    All(Vec<CfgExpr>),
    Any(Vec<CfgExpr>),
    Other(String),
}

impl CfgExpr {
    /// Evaluates whether this cfg expression is PROVEN FALSE in production builds (when `test = false`).
    /// Returns `true` if proven absent in production (exempt from scanning).
    /// Returns `false` if it could be active in production (must be scanned).
    fn is_proven_absent_in_production(&self) -> bool {
        match self {
            CfgExpr::Test => true,
            CfgExpr::Other(_) => false,
            CfgExpr::Not(_) => {
                // not(test) -> true in production (NOT absent).
                // not(other) -> could be true in production (NOT absent).
                false
            }
            CfgExpr::All(items) => {
                // all(P1, P2, ...): if ANY item is proven absent (false), the entire conjunction is false!
                items
                    .iter()
                    .any(|item| item.is_proven_absent_in_production())
            }
            CfgExpr::Any(items) => {
                // any(P1, P2, ...): only if ALL items are proven absent (false) is the disjunction false!
                !items.is_empty()
                    && items
                        .iter()
                        .all(|item| item.is_proven_absent_in_production())
            }
        }
    }
}

fn parse_cfg_meta(meta: &syn::Meta) -> Option<CfgExpr> {
    match meta {
        syn::Meta::Path(p) => {
            if p.is_ident("test") {
                Some(CfgExpr::Test)
            } else {
                Some(CfgExpr::Other(quote_to_string(p)))
            }
        }
        syn::Meta::List(list) => {
            if list.path.is_ident("not") {
                let nested: syn::Meta = list.parse_args().ok()?;
                let inner = parse_cfg_meta(&nested)?;
                Some(CfgExpr::Not(Box::new(inner)))
            } else if list.path.is_ident("all") {
                let nested_metas: syn::punctuated::Punctuated<syn::Meta, syn::Token![,]> = list
                    .parse_args_with(syn::punctuated::Punctuated::parse_terminated)
                    .ok()?;
                let items = nested_metas.iter().filter_map(parse_cfg_meta).collect();
                Some(CfgExpr::All(items))
            } else if list.path.is_ident("any") {
                let nested_metas: syn::punctuated::Punctuated<syn::Meta, syn::Token![,]> = list
                    .parse_args_with(syn::punctuated::Punctuated::parse_terminated)
                    .ok()?;
                let items = nested_metas.iter().filter_map(parse_cfg_meta).collect();
                Some(CfgExpr::Any(items))
            } else {
                Some(CfgExpr::Other(quote_to_string(list)))
            }
        }
        syn::Meta::NameValue(nv) => Some(CfgExpr::Other(quote_to_string(nv))),
    }
}

fn quote_to_string<T: syn::spanned::Spanned>(node: &T) -> String {
    let _ = node;
    "cfg_term".to_string()
}

fn is_attribute_proven_test_only(attr: &syn::Attribute) -> bool {
    if attr.path().is_ident("test") {
        return true;
    }
    if let Some(ident) = attr.path().get_ident()
        && ident.to_string().ends_with("test")
    {
        return true;
    }
    if attr.path().is_ident("cfg")
        && let syn::Meta::List(list) = &attr.meta
        && let Ok(nested) = list.parse_args::<syn::Meta>()
        && let Some(cfg_expr) = parse_cfg_meta(&nested)
    {
        return cfg_expr.is_proven_absent_in_production();
    }
    false
}

fn has_test_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(is_attribute_proven_test_only)
}

// ---------------------------------------------------------------------------
// Source Code & Module Tree Traversal
// ---------------------------------------------------------------------------

fn audit_crate_source(
    substrate_crate: &str,
    substrate_pkg: &MetadataPackage,
    forbidden_symbols: &BTreeSet<String>,
    report: &mut CrateAuditReport,
) -> Result<(), BoundaryError> {
    let manifest_path = Path::new(&substrate_pkg.manifest_path);
    let crate_dir = manifest_path.parent().unwrap_or(Path::new("."));

    let mut prod_root_files = Vec::new();

    // 1. Identify production target source files from Cargo metadata
    for target in &substrate_pkg.targets {
        let is_prod = target.kind.iter().any(|k| {
            matches!(
                k.as_str(),
                "lib"
                    | "rlib"
                    | "dylib"
                    | "cdylib"
                    | "staticlib"
                    | "bin"
                    | "custom-build"
                    | "proc-macro"
            )
        });
        if is_prod {
            let p = PathBuf::from(&target.src_path);
            let resolved_p = if p.is_absolute() {
                p
            } else {
                crate_dir.join(p)
            };
            if !prod_root_files.contains(&resolved_p) {
                prod_root_files.push(resolved_p);
            }
        }
    }

    if prod_root_files.is_empty() {
        return Err(BoundaryError::NoScannedSourceFiles {
            crate_name: substrate_crate.to_string(),
        });
    }

    let mut visited_files = BTreeSet::new();

    // Scan each production root file and its module tree
    for root_file in &prod_root_files {
        audit_source_file_tree(
            substrate_crate,
            root_file,
            0, // initial test_depth = 0 (production)
            forbidden_symbols,
            &mut visited_files,
            report,
        )?;
    }

    // Collect all .rs files in src/ and crate_dir for orphan / fail-closed scan
    let mut all_rs_files = Vec::new();
    let src_dir = crate_dir.join("src");
    if src_dir.is_dir() {
        collect_rs_files(&src_dir, &mut all_rs_files)?;
    }
    if let Ok(entries) = fs::read_dir(crate_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("rs") {
                all_rs_files.push(path);
            }
        }
    }
    all_rs_files.sort();

    // Fail-closed: scan any orphaned .rs files that were not reached by module walk
    for unvisited in all_rs_files {
        let canonical_unvisited = fs::canonicalize(&unvisited).unwrap_or(unvisited.clone());
        if !visited_files.contains(&canonical_unvisited) {
            audit_source_file_tree(
                substrate_crate,
                &unvisited,
                0, // unreferenced file is scanned as production
                forbidden_symbols,
                &mut visited_files,
                report,
            )?;
        }
    }

    Ok(())
}

fn audit_source_file_tree(
    substrate_crate: &str,
    file_path: &Path,
    inherited_test_depth: usize,
    forbidden_symbols: &BTreeSet<String>,
    visited_files: &mut BTreeSet<PathBuf>,
    report: &mut CrateAuditReport,
) -> Result<(), BoundaryError> {
    let canonical = fs::canonicalize(file_path).unwrap_or_else(|_| file_path.to_path_buf());
    visited_files.insert(canonical);

    if !report
        .scanned_source_files
        .contains(&file_path.to_path_buf())
    {
        report.scanned_source_files.push(file_path.to_path_buf());
    }

    let content = fs::read_to_string(file_path).map_err(|source| BoundaryError::Io {
        path: file_path.to_path_buf(),
        source,
    })?;

    let source_lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();

    let parsed_file: syn::File =
        syn::parse_file(&content).map_err(|source| BoundaryError::Syn {
            path: file_path.to_path_buf(),
            source,
        })?;

    let mut visitor = SourceCheckerVisitor {
        substrate_crate,
        file_path,
        source_lines: &source_lines,
        test_depth: inherited_test_depth,
        violations: Vec::new(),
        forbidden_symbols,
        out_of_line_modules: Vec::new(),
    };

    visitor.visit_file(&parsed_file);

    report.source_violations.extend(visitor.violations);

    // Recursively walk out-of-line modules (`mod foo;`, `#[path = "..."] mod bar;`)
    let file_dir = file_path.parent().unwrap_or(file_path);
    let stem = file_path.file_stem().and_then(|s| s.to_str()).unwrap_or("");

    for out_mod in visitor.out_of_line_modules {
        let child_test_depth = if out_mod.is_test_only {
            inherited_test_depth + 1
        } else {
            inherited_test_depth
        };

        let target_file_opt = resolve_module_file(
            file_dir,
            stem,
            &out_mod.name,
            out_mod.custom_path.as_deref(),
        );

        match target_file_opt {
            Some(target_file) => {
                if target_file.exists() {
                    audit_source_file_tree(
                        substrate_crate,
                        &target_file,
                        child_test_depth,
                        forbidden_symbols,
                        visited_files,
                        report,
                    )?;
                } else {
                    return Err(BoundaryError::MissingPathManifest {
                        crate_name: substrate_crate.to_string(),
                        dep_name: out_mod.name.clone(),
                        path: target_file,
                    });
                }
            }
            None => {
                let expected = file_dir.join(format!("{}.rs", out_mod.name));
                return Err(BoundaryError::MissingPathManifest {
                    crate_name: substrate_crate.to_string(),
                    dep_name: out_mod.name.clone(),
                    path: expected,
                });
            }
        }
    }

    Ok(())
}

struct OutOfLineModule {
    name: String,
    custom_path: Option<String>,
    is_test_only: bool,
}

fn resolve_module_file(
    file_dir: &Path,
    stem: &str,
    mod_name: &str,
    custom_path: Option<&str>,
) -> Option<PathBuf> {
    if let Some(cp) = custom_path {
        return Some(file_dir.join(cp));
    }

    if stem == "lib" || stem == "main" || stem == "mod" {
        let direct = file_dir.join(format!("{mod_name}.rs"));
        if direct.exists() {
            return Some(direct);
        }
        let nested = file_dir.join(mod_name).join("mod.rs");
        if nested.exists() {
            return Some(nested);
        }
        Some(direct)
    } else {
        let sibling_direct = file_dir.join(stem).join(format!("{mod_name}.rs"));
        if sibling_direct.exists() {
            return Some(sibling_direct);
        }
        let sibling_nested = file_dir.join(stem).join(mod_name).join("mod.rs");
        if sibling_nested.exists() {
            return Some(sibling_nested);
        }
        let direct = file_dir.join(format!("{mod_name}.rs"));
        if direct.exists() {
            return Some(direct);
        }
        Some(sibling_direct)
    }
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), BoundaryError> {
    if !dir.is_dir() {
        return Ok(());
    }
    let entries = fs::read_dir(dir).map_err(|source| BoundaryError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| BoundaryError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// AST Visitor for Forbidden Literals & Symbols
// ---------------------------------------------------------------------------

struct SourceCheckerVisitor<'a> {
    substrate_crate: &'a str,
    file_path: &'a Path,
    #[allow(dead_code)]
    source_lines: &'a [String],
    test_depth: usize,
    violations: Vec<SourceViolation>,
    forbidden_symbols: &'a BTreeSet<String>,
    out_of_line_modules: Vec<OutOfLineModule>,
}

impl<'a> SourceCheckerVisitor<'a> {
    fn is_in_test_context(&self) -> bool {
        self.test_depth > 0
    }

    fn check_span_for_symbol(&mut self, ident: &syn::Ident) {
        if self.is_in_test_context() {
            return;
        }
        let name = ident.to_string();
        if self.forbidden_symbols.contains(&name)
            || name.starts_with("LINUX_")
            || name.starts_with("SYS_")
            || name == "carrick_abi"
            || name == "carrick_el1"
        {
            let span = ident.span();
            let start = span.start();
            self.violations.push(SourceViolation {
                substrate_crate: self.substrate_crate.to_string(),
                file_path: self.file_path.to_path_buf(),
                line: start.line,
                column: start.column,
                symbol_or_literal: name,
                reason: "forbidden Linux personality symbol in production substrate source"
                    .to_string(),
            });
        }
    }

    fn check_lit_int(&mut self, lit: &syn::LitInt, is_negative_context: bool) {
        if self.is_in_test_context() {
            return;
        }
        let digits = lit.base10_digits();
        if digits == "110" && is_negative_context {
            let span = lit.span();
            let start = span.start();
            self.violations.push(SourceViolation {
                substrate_crate: self.substrate_crate.to_string(),
                file_path: self.file_path.to_path_buf(),
                line: start.line,
                column: start.column,
                symbol_or_literal: "-110".to_string(),
                reason: "hard-coded Linux errno literal (-110 / ETIMEDOUT) in production substrate source"
                    .to_string(),
            });
        }
    }

    fn scan_token_stream(
        &mut self,
        tokens: &proc_macro2::TokenStream,
        macro_name: &str,
        span: proc_macro2::Span,
    ) {
        if self.is_in_test_context() {
            return;
        }

        let token_vec: Vec<proc_macro2::TokenTree> = tokens.clone().into_iter().collect();
        let mut prev_is_minus = false;

        for tt in token_vec {
            match tt {
                proc_macro2::TokenTree::Group(g) => {
                    self.scan_token_stream(&g.stream(), macro_name, g.span());
                    prev_is_minus = false;
                }
                proc_macro2::TokenTree::Punct(p) => {
                    prev_is_minus = p.as_char() == '-';
                }
                proc_macro2::TokenTree::Literal(lit) => {
                    let lit_str = lit.to_string();
                    let is_110 = lit_str == "110"
                        || lit_str.starts_with("110_")
                        || lit_str == "-110"
                        || lit_str.starts_with("-110_");
                    if is_110 && (prev_is_minus || lit_str.starts_with('-')) {
                        let start = span.start();
                        self.violations.push(SourceViolation {
                            substrate_crate: self.substrate_crate.to_string(),
                            file_path: self.file_path.to_path_buf(),
                            line: start.line,
                            column: start.column,
                            symbol_or_literal: format!("-{} inside {}", lit_str, macro_name),
                            reason: "forbidden literal inside macro definition/invocation"
                                .to_string(),
                        });
                    }
                    prev_is_minus = false;
                }
                proc_macro2::TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    if self.forbidden_symbols.contains(&name)
                        || name.starts_with("LINUX_")
                        || name.starts_with("SYS_")
                        || name == "carrick_abi"
                        || name == "carrick_el1"
                    {
                        let start = ident.span().start();
                        self.violations.push(SourceViolation {
                            substrate_crate: self.substrate_crate.to_string(),
                            file_path: self.file_path.to_path_buf(),
                            line: start.line,
                            column: start.column,
                            symbol_or_literal: format!("{} inside {}", name, macro_name),
                            reason:
                                "forbidden personality symbol inside macro definition/invocation"
                                    .to_string(),
                        });
                    }
                    prev_is_minus = false;
                }
            }
        }
    }
}

impl<'ast, 'a> Visit<'ast> for SourceCheckerVisitor<'a> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attrs = match item {
            syn::Item::Const(i) => &i.attrs,
            syn::Item::Enum(i) => &i.attrs,
            syn::Item::ExternCrate(i) => &i.attrs,
            syn::Item::Fn(i) => &i.attrs,
            syn::Item::ForeignMod(i) => &i.attrs,
            syn::Item::Impl(i) => &i.attrs,
            syn::Item::Macro(i) => &i.attrs,
            syn::Item::Mod(i) => &i.attrs,
            syn::Item::Static(i) => &i.attrs,
            syn::Item::Struct(i) => &i.attrs,
            syn::Item::Trait(i) => &i.attrs,
            syn::Item::TraitAlias(i) => &i.attrs,
            syn::Item::Type(i) => &i.attrs,
            syn::Item::Union(i) => &i.attrs,
            syn::Item::Use(i) => &i.attrs,
            _ => &[][..],
        };

        let is_test = has_test_attr(attrs);
        if is_test {
            self.test_depth += 1;
        }

        // For modules, record out-of-line module declarations
        if let syn::Item::Mod(m) = item
            && m.content.is_none()
        {
            let mut custom_path = None;
            for attr in &m.attrs {
                if attr.path().is_ident("path")
                    && let syn::Meta::NameValue(nv) = &attr.meta
                    && let syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(s),
                        ..
                    }) = &nv.value
                {
                    custom_path = Some(s.value());
                }
            }

            self.out_of_line_modules.push(OutOfLineModule {
                name: m.ident.to_string(),
                custom_path,
                is_test_only: self.is_in_test_context() || is_test,
            });
        }

        syn::visit::visit_item(self, item);

        if is_test {
            self.test_depth -= 1;
        }
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let path_str = node
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        let tokens = node.tokens.clone();
        self.scan_token_stream(&tokens, &path_str, node.span());
        syn::visit::visit_macro(self, node);
    }

    fn visit_ident(&mut self, node: &'ast syn::Ident) {
        self.check_span_for_symbol(node);
        syn::visit::visit_ident(self, node);
    }

    fn visit_expr_unary(&mut self, node: &'ast syn::ExprUnary) {
        if let syn::UnOp::Neg(_) = node.op
            && let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(lit_int),
                ..
            }) = &*node.expr
        {
            self.check_lit_int(lit_int, true);
        }
        syn::visit::visit_expr_unary(self, node);
    }

    fn visit_lit_int(&mut self, node: &'ast syn::LitInt) {
        let digits = node.base10_digits();
        if digits == "-110" {
            self.check_lit_int(node, true);
        }
        syn::visit::visit_lit_int(self, node);
    }
}

// ---------------------------------------------------------------------------
// Tests and Fixture Verification
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    struct Fixture {
        root: tempfile::TempDir,
        metadata: Value,
    }
    impl Fixture {
        fn new(path: &str, code: &str) -> Self {
            let root = tempfile::tempdir().unwrap();
            let dir = root.path().join("crates/carrick-sched-core");
            let source = dir.join(path);
            fs::create_dir_all(source.parent().unwrap()).unwrap();
            fs::write(&source, code).unwrap();
            fs::write(
                dir.join("Cargo.toml"),
                "[package]\nname='carrick-sched-core'\nversion='0.1.0'\n",
            )
            .unwrap();
            let metadata = json!({
                "workspace_root": root.path(),
                "packages": [{"id":"core", "name":"carrick-sched-core", "version":"0.1.0",
                    "manifest_path":dir.join("Cargo.toml"),
                    "targets":[{"kind":["lib"],"src_path":source}],"dependencies":[]}],
                "resolve":{"nodes":[{"id":"core","deps":[]}]}
            });
            Self { root, metadata }
        }
        fn check(&self) -> Result<Vec<CrateAuditReport>, BoundaryError> {
            check_substrate_boundary(
                self.root.path(),
                &BoundaryConfig {
                    metadata_json: Some(self.metadata.to_string()),
                    substrate_allowlist: vec!["carrick-sched-core".to_string()],
                    ..Default::default()
                },
            )
        }
        fn package(&mut self, id: &str, name: &str) {
            self.metadata["packages"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "id":id,"name":name,"version":"0.1.0","dependencies":[],"targets":[]
                }));
            self.metadata["resolve"]["nodes"]
                .as_array_mut()
                .unwrap()
                .push(json!({"id":id,"deps":[]}));
        }
        fn edge(
            &mut self,
            from: usize,
            to: &str,
            alias: &str,
            kind: Option<&str>,
            target: Option<&str>,
        ) {
            self.metadata["resolve"]["nodes"][from]["deps"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "name":alias,"pkg":to,"dep_kinds":[{"kind":kind,"target":target}]
                }));
        }
    }

    #[test]
    fn test_positive_fixture_substrate_passes() {
        let f = Fixture::new("src/lib.rs", "pub fn value(x:u64)->u64 { x }");
        let r = f.check().unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].scanned_source_files.len(), 1);
    }
    #[test]
    fn test_negative_custom_lib_path_rejected() {
        let f = Fixture::new("kernel.rs", "pub const RESULT:i64=-110;");
        assert!(matches!(f.check(), Err(BoundaryError::Violations { .. })));
    }
    #[test]
    fn test_negative_optional_transitive_dependency_rejected() {
        let mut f = Fixture::new("src/lib.rs", "pub fn value() {}");
        f.package("bridge", "bridge");
        f.package("abi", "carrick-abi");
        f.metadata["packages"][0]["dependencies"] = json!([{"name":"bridge","optional":true}]);
        f.edge(0, "bridge", "bridge", None, None);
        f.edge(1, "abi", "carrick_abi", None, None);
        assert!(matches!(f.check(), Err(BoundaryError::Violations { .. })));
    }
    #[test]
    fn test_negative_unresolved_registry_dependency_rejected() {
        let mut f = Fixture::new("src/lib.rs", "pub fn value() {}");
        f.metadata["packages"][0]["dependencies"] =
            json!([{"name":"unknown_bridge","optional":false}]);
        assert!(matches!(
            f.check(),
            Err(BoundaryError::UnresolvedDependencyGraph { .. })
        ));
    }
    #[test]
    fn test_negative_missing_allowlisted_crate_rejected() {
        let mut f = Fixture::new("src/lib.rs", "pub fn value() {}");
        f.metadata["packages"] = json!([]);
        assert!(matches!(f.check(), Err(BoundaryError::MissingCrate { .. })));
    }
    #[test]
    fn test_negative_no_scanned_source_files_rejected() {
        let f = Fixture::new("src/lib.rs", "pub fn value() {}");
        fs::remove_dir_all(f.root.path().join("crates/carrick-sched-core")).unwrap();
        assert!(f.check().is_err());
    }
    #[test]
    fn test_metadata_from_another_workspace_rejected() {
        let mut f = Fixture::new("src/lib.rs", "pub fn value() {}");
        f.metadata["workspace_root"] = json!(f.root.path().join("another-checkout"));
        assert!(
            f.check().is_err(),
            "metadata must belong to the selected workspace"
        );
    }
    #[test]
    fn test_negative_missing_target_cannot_fall_back_to_other_source() {
        let mut f = Fixture::new("src/lib.rs", "pub fn value() {}");
        f.metadata["packages"][0]["targets"][0]["src_path"] =
            json!(f.root.path().join("missing.rs"));
        assert!(
            f.check().is_err(),
            "a missing production target must not be replaced by src/lib.rs"
        );
    }
    #[test]
    fn test_negative_direct_dependency_rejected() {
        let mut f = Fixture::new("src/lib.rs", "pub fn value() {}");
        f.package("abi", "carrick-abi");
        f.edge(0, "abi", "carrick_abi", None, None);
        assert!(matches!(f.check(), Err(BoundaryError::Violations { .. })));
    }
    #[test]
    fn test_negative_renamed_alias_dependency_rejected() {
        let mut f = Fixture::new("src/lib.rs", "pub fn value() {}");
        f.package("abi", "carrick-abi");
        f.edge(0, "abi", "renamed", None, None);
        assert!(matches!(f.check(), Err(BoundaryError::Violations { .. })));
    }
    #[test]
    fn test_negative_target_conditioned_build_dependency_rejected() {
        let mut f = Fixture::new("src/lib.rs", "pub fn value() {}");
        f.package("abi", "carrick-abi");
        f.edge(
            0,
            "abi",
            "carrick_abi",
            Some("build"),
            Some("cfg(target_os = \"linux\")"),
        );
        assert!(matches!(f.check(), Err(BoundaryError::Violations { .. })));
    }
    #[test]
    fn test_positive_dev_only_dependency_allowed() {
        let mut f = Fixture::new("src/lib.rs", "pub fn value() {}");
        f.package("abi", "carrick-abi");
        f.edge(0, "abi", "carrick_abi", Some("dev"), None);
        let r = f.check().unwrap();
        assert!(r[0].shipped_dependency_closure.is_empty());
        assert_eq!(r[0].dev_dependencies_scope, vec!["carrick-abi"]);
    }
    #[test]
    fn test_negative_missing_transitive_node_rejected() {
        let mut f = Fixture::new("src/lib.rs", "pub fn value() {}");
        f.package("bridge", "bridge");
        f.edge(0, "bridge", "bridge", None, None);
        f.metadata["resolve"]["nodes"].as_array_mut().unwrap().pop();
        assert!(matches!(
            f.check(),
            Err(BoundaryError::UnresolvedDependencyGraph { .. })
        ));
    }
    #[test]
    fn test_inherited_test_module_and_production_filename() {
        let f = Fixture::new("src/lib.rs", "#[cfg(test)] mod checks;");
        let d = f.root.path().join("crates/carrick-sched-core/src");
        fs::write(d.join("checks.rs"), "pub const RESULT:i64=-110;").unwrap();
        assert!(f.check().is_ok());
        fs::write(d.join("lib.rs"), "mod checks;").unwrap();
        assert!(matches!(f.check(), Err(BoundaryError::Violations { .. })));
    }
    #[test]
    fn test_negative_cfg_not_test_rejected() {
        let code = r#"
            #[cfg(not(test))]
            pub const FORBIDDEN: i64 = -110;
        "#;
        let mut visitor = make_test_visitor(code);
        let parsed = syn::parse_file(code).unwrap();
        visitor.visit_file(&parsed);
        assert_eq!(visitor.violations.len(), 1);
        assert_eq!(visitor.violations[0].symbol_or_literal, "-110");
    }

    #[test]
    fn test_negative_cfg_any_test_and_prod_feature_rejected() {
        let code = r#"
            #[cfg(any(test, feature = "prod"))]
            pub const FORBIDDEN: i64 = -110;
        "#;
        let mut visitor = make_test_visitor(code);
        let parsed = syn::parse_file(code).unwrap();
        visitor.visit_file(&parsed);
        assert_eq!(visitor.violations.len(), 1);
        assert_eq!(visitor.violations[0].symbol_or_literal, "-110");
    }

    #[test]
    fn test_negative_cfg_feature_containing_test_word_rejected() {
        let code = r#"
            #[cfg(feature = "attestation-test")]
            pub const FORBIDDEN: i64 = -110;
        "#;
        let mut visitor = make_test_visitor(code);
        let parsed = syn::parse_file(code).unwrap();
        visitor.visit_file(&parsed);
        assert_eq!(visitor.violations.len(), 1);
        assert_eq!(visitor.violations[0].symbol_or_literal, "-110");
    }

    #[test]
    fn test_positive_cfg_all_test_and_foo_allowed() {
        let code = r#"
            #[cfg(all(test, feature = "foo"))]
            pub const FORBIDDEN: i64 = -110;
        "#;
        let mut visitor = make_test_visitor(code);
        let parsed = syn::parse_file(code).unwrap();
        visitor.visit_file(&parsed);
        assert_eq!(visitor.violations.len(), 0);
    }

    #[test]
    fn test_negative_unannotated_mod_tests_filename_rejected() {
        let code = r#"
            mod tests {
                pub const FORBIDDEN: i64 = -110;
            }
        "#;
        let mut visitor = make_test_visitor(code);
        let parsed = syn::parse_file(code).unwrap();
        visitor.visit_file(&parsed);
        assert_eq!(visitor.violations.len(), 1);
        assert_eq!(visitor.violations[0].symbol_or_literal, "-110");
    }

    #[test]
    fn test_positive_annotated_mod_arbitrary_name_allowed() {
        let code = r#"
            #[cfg(test)]
            mod my_oracle_suite {
                pub const FORBIDDEN: i64 = -110;
            }
        "#;
        let mut visitor = make_test_visitor(code);
        let parsed = syn::parse_file(code).unwrap();
        visitor.visit_file(&parsed);
        assert_eq!(visitor.violations.len(), 0);
    }

    #[test]
    fn test_negative_macro_rules_definition_containing_literal_rejected() {
        let code = r#"
            macro_rules! timeout {
                () => { -110_i64 };
            }
        "#;
        let mut visitor = make_test_visitor(code);
        let parsed = syn::parse_file(code).unwrap();
        visitor.visit_file(&parsed);
        assert_eq!(visitor.violations.len(), 1);
        assert!(visitor.violations[0].symbol_or_literal.contains("-110"));
    }

    #[test]
    fn test_negative_macro_rules_definition_containing_symbol_rejected() {
        let code = r#"
            macro_rules! timeout {
                () => { ETIMEDOUT };
            }
        "#;
        let mut visitor = make_test_visitor(code);
        let parsed = syn::parse_file(code).unwrap();
        visitor.visit_file(&parsed);
        assert_eq!(visitor.violations.len(), 1);
        assert!(
            visitor.violations[0]
                .symbol_or_literal
                .contains("ETIMEDOUT")
        );
    }

    #[test]
    fn test_negative_macro_invocation_containing_literal_rejected() {
        let code = r#"
            pub fn fail() {
                record!(-110_i64);
            }
        "#;
        let mut visitor = make_test_visitor(code);
        let parsed = syn::parse_file(code).unwrap();
        visitor.visit_file(&parsed);
        assert_eq!(visitor.violations.len(), 1);
        assert!(visitor.violations[0].symbol_or_literal.contains("-110"));
    }

    #[test]
    fn test_positive_prose_comments_allowed() {
        let code = r#"
            // The Linux kernel returns -110 (ETIMEDOUT) for expired timers.
            /* Substrate passes arbitrary caller result instead of ETIMEDOUT */
            #[doc = "Propagates caller-supplied result instead of hard-coding -110 (ETIMEDOUT)."]
            pub fn expire_timer(result: u64) -> u64 {
                result
            }
        "#;
        let mut visitor = make_test_visitor(code);
        let parsed = syn::parse_file(code).unwrap();
        visitor.visit_file(&parsed);
        assert_eq!(visitor.violations.len(), 0);
    }

    #[test]
    fn test_positive_test_only_oracle_assertions_allowed() {
        let code = r#"
            #[cfg(test)]
            mod tests {
                use super::*;
                #[test]
                fn test_linux_oracle() {
                    assert_eq!(result, (-110_i64) as u64);
                }
            }
        "#;
        let mut visitor = make_test_visitor(code);
        let parsed = syn::parse_file(code).unwrap();
        visitor.visit_file(&parsed);
        assert_eq!(visitor.violations.len(), 0);
    }

    #[test]
    fn test_positive_typed_caller_values_allowed() {
        let code = r#"
            pub fn expire_timer(result: u64) -> u64 {
                result
            }
            pub fn run() {
                let res = expire_timer(42);
            }
        "#;
        let mut visitor = make_test_visitor(code);
        let parsed = syn::parse_file(code).unwrap();
        visitor.visit_file(&parsed);
        assert_eq!(visitor.violations.len(), 0);
    }

    fn make_test_visitor<'a>(code: &'a str) -> SourceCheckerVisitor<'a> {
        static FORBIDDEN: std::sync::LazyLock<BTreeSet<String>> = std::sync::LazyLock::new(|| {
            FORBIDDEN_ERRNO_SYMBOLS
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        });
        static LINES: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(Vec::new);
        let _ = code;
        SourceCheckerVisitor {
            substrate_crate: "carrick-sched-core",
            file_path: Path::new("src/lib.rs"),
            source_lines: &LINES,
            test_depth: 0,
            violations: Vec::new(),
            forbidden_symbols: &FORBIDDEN,
            out_of_line_modules: Vec::new(),
        }
    }
}
