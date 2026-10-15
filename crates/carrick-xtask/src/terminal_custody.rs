//! Ratchet for retirement decisions outside the neutral owner.

use quote::ToTokens;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use syn::visit::{self, Visit};

const BASELINE: &str = "scripts/terminal-custody-baseline.txt";

#[derive(Default)]
struct DecisionFinder {
    rules: BTreeSet<&'static str>,
    group_exit_failure: bool,
}

fn call_rule(name: &syn::Ident) -> Option<&'static str> {
    match name.to_string().as_str() {
        "live" => Some("live"),
        "claimed_count" => Some("claimed_count"),
        "task_is_live" => Some("task_is_live"),
        "hardware_live_root" => Some("hardware_live_root"),
        _ => None,
    }
}

impl<'ast> Visit<'ast> for DecisionFinder {
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        // syn leaves macro arguments opaque. Inspect call-shaped token pairs
        // and recurse into groups so wrapping cannot hide a decision.
        fn identifiers(tokens: proc_macro2::TokenStream, finder: &mut DecisionFinder) {
            let mut tokens = tokens.into_iter().peekable();
            while let Some(token) = tokens.next() {
                match token {
                    proc_macro2::TokenTree::Ident(ident) if ident == "EntryState" => {
                        finder.rules.insert("EntryState");
                    }
                    proc_macro2::TokenTree::Ident(ident) if ident == "TerminalPhase" => {
                        finder.rules.insert("TerminalPhase");
                    }
                    proc_macro2::TokenTree::Ident(ident) if ident == "X86GroupExitCustody" => {
                        finder.group_exit_failure = true;
                    }
                    proc_macro2::TokenTree::Ident(ident)
                        if matches!(tokens.peek(), Some(proc_macro2::TokenTree::Group(group))
                            if group.delimiter() == proc_macro2::Delimiter::Parenthesis) =>
                    {
                        if let Some(rule) = call_rule(&ident) {
                            finder.rules.insert(rule);
                        }
                    }
                    proc_macro2::TokenTree::Group(group) => identifiers(group.stream(), finder),
                    _ => {}
                }
            }
        }
        identifiers(node.tokens.clone(), self);
        visit::visit_macro(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if let Some(rule) = call_rule(&node.method) {
            self.rules.insert(rule);
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*node.func
            && let Some(last) = path.path.segments.last()
            && let Some(rule) = call_rule(&last.ident)
        {
            self.rules.insert(rule);
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        for segment in &node.segments {
            match segment.ident.to_string().as_str() {
                "EntryState" => {
                    self.rules.insert("EntryState");
                }
                "TerminalPhase" => {
                    self.rules.insert("TerminalPhase");
                }
                _ => {}
            }
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
        if finder.group_exit_failure
            && !self.path.contains("/signal")
            && !self.path.ends_with("/native_run_failure.rs")
        {
            finder.rules.insert("X86GroupExitCustody");
        }
        for rule in finder.rules {
            let location = match &self.owner {
                Some(owner) => format!("{owner}::{name}"),
                None => name.clone(),
            };
            self.names.insert(format!("{location}|{rule}"));
        }
    }
}

/// Only a proven false cfg may exempt code. Features and negation can be
/// enabled in production, even when their spelling contains `test`.
fn absent_in_production(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) if list.path.is_ident("all") || list.path.is_ident("any") => {
            let Ok(items) = list.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            ) else {
                return false;
            };
            if list.path.is_ident("all") {
                items.iter().any(absent_in_production)
            } else {
                !items.is_empty() && items.iter().all(absent_in_production)
            }
        }
        _ => false,
    }
}

fn test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr
                    .parse_args::<syn::Meta>()
                    .is_ok_and(|meta| absent_in_production(&meta)))
    })
}

impl<'ast> Visit<'ast> for FunctionSites {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !test_only(&node.attrs) {
            visit::visit_item_mod(self, node);
        }
    }
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if test_only(&node.attrs) {
            return;
        }
        let previous = self
            .owner
            .replace(node.self_ty.to_token_stream().to_string());
        visit::visit_item_impl(self, node);
        self.owner = previous;
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        if test_only(&node.attrs) {
            return;
        }
        let previous = self.owner.replace(node.ident.to_string());
        visit::visit_item_trait(self, node);
        self.owner = previous;
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        if test_only(&node.attrs) {
            return;
        }
        if let Some(body) = &node.default {
            self.record(&node.sig.ident, body);
        }
        visit::visit_trait_item_fn(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if test_only(&node.attrs) {
            return;
        }
        self.record(&node.sig.ident, &node.block);
        visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if test_only(&node.attrs) {
            return;
        }
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
            && !path
                .components()
                .any(|component| component.as_os_str() == "tests")
            && !path
                .components()
                .any(|component| component.as_os_str() == "test_support")
            && !path.file_name().is_some_and(|name| {
                name.to_string_lossy().ends_with("_tests.rs")
                    || name == "tests.rs"
                    || name == "test_support.rs"
            })
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
    // This gate can land before terminal custody itself. Once present, its
    // verdict must have exactly one definition in the neutral owner.
    if !definitions.is_empty() && definitions != ["crates/carrick-core/src/terminal.rs"] {
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
    let stale: Vec<_> = allowed.difference(sites).collect();
    if !stale.is_empty() {
        return Err(format!("stale terminal custody baseline rows: {stale:?}"));
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
        assert!(sites.contains("crates/new-lane/src/owner.rs|Owner::retire_thread|live"));
        assert!(validate(&sites, &BTreeSet::from(["other".to_owned()])).is_err());
    }

    #[test]
    fn trait_default_method_is_scanned_for_retirement_decisions() {
        let sites = sites_in_source(
            "crates/new-lane/src/owner.rs",
            "trait Owner { fn retire(&self) { if self.live() == 0 {} } }",
        )
        .unwrap();
        assert!(sites.contains("crates/new-lane/src/owner.rs|Owner::retire|live"));
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
    fn macro_wrapped_decisions_are_scanned() {
        let source = include_str!("../tests/fixtures/terminal_custody/macro_decisions.rs.txt");
        let sites = sites_in_source("crates/new-lane/src/owner.rs", source).unwrap();
        for rule in [
            "live",
            "claimed_count",
            "task_is_live",
            "hardware_live_root",
            "X86GroupExitCustody",
        ] {
            assert!(
                sites.iter().any(|site| site.ends_with(rule)),
                "macro hid {rule}: {sites:?}"
            );
        }
    }

    #[test]
    fn production_cfg_cannot_hide_retirement_decisions() {
        for source in [
            r#"#[cfg(not(test))] fn stop() { page.live(); }"#,
            r#"#[cfg(any(test, feature = "prod"))] impl Owner { fn stop() { page.live(); } }"#,
            r#"#[cfg(feature = "host-test")] trait Owner { fn stop() { page.live(); } }"#,
        ] {
            assert!(
                !sites_in_source("crates/new-lane/src/owner.rs", source)
                    .unwrap()
                    .is_empty(),
                "production cfg hid a retirement decision: {source}"
            );
        }
    }

    #[test]
    fn proven_test_cfg_is_exempt() {
        for source in [
            "#[cfg(test)] fn stop() { page.live(); }",
            r#"#[cfg(all(test, feature = "prod"))] impl Owner { fn stop() { page.live(); } }"#,
            "#[cfg(any(test, all(test, unix)))] mod nested { fn stop() { page.live(); } }",
        ] {
            assert!(
                sites_in_source("crates/new-lane/src/owner.rs", source)
                    .unwrap()
                    .is_empty()
            );
        }
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
    fn definition_gate_allows_absence_but_rejects_duplicate_or_external_owners() {
        for (path, source, accepted) in [
            ("crates/lane/src/lib.rs", "fn apply() {}", true),
            (
                "crates/carrick-core/src/terminal.rs",
                "enum RetirementVerdict {}",
                true,
            ),
            (
                "crates/carrick-core/src/terminal.rs",
                "enum RetirementVerdict {} mod duplicate { enum RetirementVerdict {} }",
                false,
            ),
            ("crates/lane/src/lib.rs", "enum RetirementVerdict {}", false),
            (
                "crates/lane/src/lib.rs",
                "impl TerminalCustody<Thread, Live> {}",
                false,
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            let file = root.path().join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, source).unwrap();
            assert_eq!(
                check_definition_ownership(root.path()).is_ok(),
                accepted,
                "{source}"
            );
        }
    }

    #[test]
    fn syscall_group_exit_failure_is_a_retirement_decision() {
        let sites = sites_in_source(
            "crates/new-lane/src/exit.rs",
            "fn exit_group() { NativeRunFailureReason::X86GroupExitCustody; }",
        )
        .unwrap();
        assert!(sites.contains("crates/new-lane/src/exit.rs|exit_group|X86GroupExitCustody"));
    }

    #[test]
    fn decision_expressions_are_found_without_retirement_function_names() {
        for (name, source) in [
            (
                "live",
                include_str!("../tests/fixtures/terminal_custody/live.rs.txt"),
            ),
            (
                "claimed_count",
                include_str!("../tests/fixtures/terminal_custody/claimed_count.rs.txt"),
            ),
            (
                "EntryState",
                include_str!("../tests/fixtures/terminal_custody/entry_state.rs.txt"),
            ),
            (
                "TerminalPhase",
                include_str!("../tests/fixtures/terminal_custody/terminal_phase.rs.txt"),
            ),
            (
                "task_is_live",
                include_str!("../tests/fixtures/terminal_custody/task_is_live.rs.txt"),
            ),
            (
                "hardware_live_root",
                include_str!("../tests/fixtures/terminal_custody/hardware_live_root.rs.txt"),
            ),
            (
                "X86GroupExitCustody",
                include_str!("../tests/fixtures/terminal_custody/group_exit.rs.txt"),
            ),
        ] {
            let sites = sites_in_source("crates/new-lane/src/custody.rs", source).unwrap();
            assert!(
                sites.iter().any(|site| site.ends_with(name)),
                "missed {name}: {sites:?}"
            );
            assert!(
                validate(&sites, &BTreeSet::from(["unrelated allowance".to_owned()])).is_err(),
                "planted {name} violation passed the gate"
            );
        }
    }

    #[test]
    fn stale_baseline_row_fails_even_without_new_sites() {
        assert!(
            validate(
                &BTreeSet::from(["live".to_owned()]),
                &BTreeSet::from(["live".to_owned(), "stale".to_owned()])
            )
            .is_err()
        );
    }
}
