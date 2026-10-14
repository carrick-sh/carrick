//! Ratchet for retirement decisions outside the neutral owner.

use quote::ToTokens;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use syn::visit::{self, Visit};

const BASELINE: &str = "scripts/terminal-custody-baseline.txt";

#[derive(Default)]
struct DecisionFinder {
    found: bool,
    group_exit_failure: bool,
}

impl<'ast> Visit<'ast> for DecisionFinder {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if matches!(
            node.method.to_string().as_str(),
            "live" | "claimed_count" | "task_is_live" | "hardware_live_root"
        ) {
            self.found = true;
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        if node.segments.iter().any(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "EntryState" | "TerminalPhase"
            )
        }) {
            self.found = true;
        }
        visit::visit_path(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if node
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "X86GroupExitCustody")
        {
            self.group_exit_failure = true;
        }
        visit::visit_expr_path(self, node);
    }
}

#[derive(Default)]
struct FunctionSites {
    owner: Option<String>,
    names: BTreeSet<String>,
    path: String,
}

#[derive(Default)]
struct DefinitionSites {
    verdicts: usize,
    phase_impls: usize,
}

impl<'ast> Visit<'ast> for DefinitionSites {
    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        if node.ident == "RetirementVerdict" {
            self.verdicts += 1;
        }
        visit::visit_item_enum(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if matches!(&*node.self_ty, syn::Type::Path(path) if path.path.segments.iter().any(|segment| segment.ident == "TerminalCustody"))
        {
            self.phase_impls += 1;
        }
        visit::visit_item_impl(self, node);
    }
}

impl FunctionSites {
    fn record(&mut self, name: &syn::Ident, body: &syn::Block) {
        let name = name.to_string();
        let mut finder = DecisionFinder::default();
        finder.visit_block(body);
        let retirement_decision = finder.found
            && (name.starts_with("retire_")
                || name.starts_with("settle_")
                || name.starts_with("reap"));
        let syscall_exit =
            name == "exit_group" || name == "exit_with_status" || name == "serve_exit";
        let forbidden_failure =
            finder.group_exit_failure && syscall_exit && !self.path.contains("/signal");
        if retirement_decision || forbidden_failure {
            self.names.insert(match &self.owner {
                Some(owner) => format!("{owner}::{name}"),
                None => name,
            });
        }
    }
}

impl<'ast> Visit<'ast> for FunctionSites {
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let previous = self
            .owner
            .replace(node.self_ty.to_token_stream().to_string());
        visit::visit_item_impl(self, node);
        self.owner = previous;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.record(&node.sig.ident, &node.block);
        visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.record(&node.sig.ident, &node.block);
        visit::visit_impl_item_fn(self, node);
    }
}

fn production_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            production_files(root, &path, out)?;
        } else if path.extension().is_some_and(|extension| extension == "rs")
            && path.starts_with(root.join("crates"))
        {
            out.push(path);
        }
    }
    Ok(())
}

fn sites_in_source(path: &str, source: &str) -> Result<BTreeSet<String>, String> {
    let file = syn::parse_file(source).map_err(|error| format!("{path}: {error}"))?;
    let mut visitor = FunctionSites {
        path: path.to_owned(),
        ..FunctionSites::default()
    };
    visitor.visit_file(&file);
    Ok(visitor
        .names
        .into_iter()
        .map(|name| format!("{path}|{name}"))
        .collect())
}

pub fn discover(root: &Path) -> Result<BTreeSet<String>, String> {
    let mut files = Vec::new();
    production_files(root, &root.join("crates"), &mut files)?;
    let mut sites = BTreeSet::new();
    for file in files {
        let path = file
            .strip_prefix(root)
            .map_err(|error| error.to_string())?
            .to_string_lossy();
        // Core and sched-core are the neutral decision owners, not debt.
        if path.starts_with("crates/carrick-core/")
            || path.starts_with("crates/carrick-sched-core/")
        {
            continue;
        }
        let source = fs::read_to_string(&file).map_err(|error| error.to_string())?;
        sites.extend(sites_in_source(&path, &source)?);
    }
    Ok(sites)
}

pub fn check(root: &Path) -> Result<(), String> {
    let baseline = fs::read_to_string(root.join(BASELINE)).map_err(|error| error.to_string())?;
    let allowed: BTreeSet<_> = baseline
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect();
    let sites = discover(root)?;
    validate(&sites, &allowed)?;
    check_definition_ownership(root)?;
    println!(
        "terminal custody: {} current sites, {} baseline sites",
        sites.len(),
        allowed.len()
    );
    Ok(())
}

fn check_definition_ownership(root: &Path) -> Result<(), String> {
    let mut files = Vec::new();
    production_files(root, &root.join("crates"), &mut files)?;
    let mut definitions = Vec::new();
    for file in files {
        let path = file
            .strip_prefix(root)
            .map_err(|error| error.to_string())?
            .to_string_lossy();
        let source = fs::read_to_string(&file).map_err(|error| error.to_string())?;
        let parsed = syn::parse_file(&source).map_err(|error| error.to_string())?;
        let mut visitor = DefinitionSites::default();
        visitor.visit_file(&parsed);
        if visitor.verdicts > 0 {
            definitions.extend(std::iter::repeat_n(path.to_string(), visitor.verdicts));
        }
        if visitor.phase_impls > 0 && !path.starts_with("crates/carrick-core/") {
            return Err(format!("terminal phase impl outside core: {path}"));
        }
    }
    if definitions != ["crates/carrick-core/src/terminal.rs"] {
        return Err(format!(
            "RetirementVerdict must have one core owner: {definitions:?}"
        ));
    }
    Ok(())
}

fn validate(sites: &BTreeSet<String>, allowed: &BTreeSet<String>) -> Result<(), String> {
    if allowed.is_empty() {
        return Err("terminal custody baseline is empty".to_owned());
    }
    let added: Vec<_> = sites.difference(allowed).collect();
    if !added.is_empty() {
        return Err(format!("new retirement decisions outside core: {added:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_fixture_finds_renamed_file_and_deciding_method() {
        let source = include_str!("../tests/fixtures/terminal_custody/negative.rs.txt");
        let sites = sites_in_source("crates/new-lane/src/owner.rs", source).unwrap();
        assert!(sites.contains("crates/new-lane/src/owner.rs|Owner::retire_thread"));
        assert!(validate(&sites, &BTreeSet::from(["other".to_owned()])).is_err());
    }

    #[test]
    fn positive_fixture_keeps_applier_out_of_baseline() {
        let source = include_str!("../tests/fixtures/terminal_custody/positive.rs.txt");
        assert!(
            sites_in_source("crates/new-lane/src/apply.rs", source)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn empty_baseline_is_not_a_green_gate() {
        assert!(validate(&BTreeSet::new(), &BTreeSet::new()).is_err());
    }

    #[test]
    fn definition_fixture_detects_duplicate_verdict_and_external_phase_impl() {
        let parsed = syn::parse_file(
            "enum RetirementVerdict {} impl TerminalCustody<Thread, Live> { fn x(&self) {} }",
        )
        .unwrap();
        let mut visitor = DefinitionSites::default();
        visitor.visit_file(&parsed);
        assert_eq!(visitor.verdicts, 1);
        assert_eq!(visitor.phase_impls, 1);
    }

    #[test]
    fn syscall_group_exit_failure_is_a_retirement_decision() {
        let sites = sites_in_source(
            "crates/new-lane/src/exit.rs",
            "fn exit_group() { NativeRunFailureReason::X86GroupExitCustody; }",
        )
        .unwrap();
        assert!(sites.contains("crates/new-lane/src/exit.rs|exit_group"));
    }
}
