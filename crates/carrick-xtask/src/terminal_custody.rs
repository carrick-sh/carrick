//! Ratchet for retirement decisions outside the neutral owner.

use crate::debt_moves::MoveMap;
use quote::ToTokens;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use syn::visit::{self, Visit};

const CEILINGS: &str = "scripts/terminal-custody-ceilings.json";

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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CrateCeiling {
    crate_name: String,
    ceiling: usize,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalCustodyCeilings {
    schema: u32,
    counters: Vec<CrateCeiling>,
}

impl TerminalCustodyCeilings {
    fn counts(&self) -> Result<BTreeMap<String, usize>, String> {
        if self.schema != 1 {
            return Err("unknown terminal custody ceiling schema".to_owned());
        }
        let mut counts = BTreeMap::new();
        for counter in &self.counters {
            if counter.crate_name.is_empty()
                || counter.crate_name.contains(['/', '\\', '|'])
                || counter.ceiling == 0
            {
                return Err(format!(
                    "invalid or zero crate ceiling; delete zero entries: {}",
                    counter.crate_name
                ));
            }
            if counts
                .insert(counter.crate_name.clone(), counter.ceiling)
                .is_some()
            {
                return Err(format!("duplicate crate ceiling: {}", counter.crate_name));
            }
        }
        Ok(counts)
    }
}

fn read_counts(source: &str) -> Result<BTreeMap<String, usize>, String> {
    serde_json::from_str::<TerminalCustodyCeilings>(source)
        .map_err(|error| error.to_string())?
        .counts()
}

fn crate_sites(sites: &BTreeSet<String>) -> BTreeMap<String, Vec<&str>> {
    let mut crates: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for site in sites {
        // Sites are produced from paths under crates/<crate>/ by discover.
        let name = site.split('/').nth(1).unwrap_or(site);
        crates.entry(name.to_owned()).or_default().push(site);
    }
    crates
}

/// Per-crate ceilings may only fall. A reviewed move in `moves` settles its
/// source crate and new destination crate (`debt_moves`); an unmapped new
/// crate is still an increase.
fn ratchet(
    current: &BTreeMap<String, usize>,
    base: &BTreeMap<String, usize>,
    moves: &MoveMap,
) -> Result<(), String> {
    let widen = |counts: &BTreeMap<String, usize>| -> BTreeMap<String, u64> {
        counts
            .iter()
            .map(|(name, count)| (name.clone(), *count as u64))
            .collect()
    };
    let (current, base) = (widen(current), widen(base));
    let settled = moves.settle(
        &base,
        &current,
        |name| name.as_str(),
        |_, name| name.to_owned(),
    )?;
    let current: BTreeMap<_, _> = current
        .into_iter()
        .filter(|(name, _)| !settled.contains(name))
        .collect();
    for (name, count) in &current {
        let previous = base.get(name).copied().unwrap_or(0);
        if *count > previous {
            return Err(format!(
                "terminal custody ceiling increase: {name}: {previous} -> {count}"
            ));
        }
    }
    Ok(())
}

fn base_counts(root: &Path, base: &str) -> Result<BTreeMap<String, usize>, String> {
    let exists = crate::command::run_checked("git", ["ls-tree", base, "--", CEILINGS], Some(root))
        .map_err(|error| error.to_string())?;
    if !exists.stdout.trim().is_empty() {
        let source =
            crate::command::run_checked("git", ["show", &format!("{base}:{CEILINGS}")], Some(root))
                .map_err(|error| error.to_string())?;
        return read_counts(&source.stdout);
    }
    // Bootstrap from the actual base sources, never from the candidate policy
    // or a checked-in site inventory. Corrupt existing policies fail above.
    let archive = std::process::Command::new("git")
        .args(["archive", base])
        .current_dir(root)
        .output()
        .map_err(|error| error.to_string())?;
    if !archive.status.success() {
        return Err("cannot read terminal custody base sources".to_owned());
    }
    let temporary = tempfile::tempdir().map_err(|error| error.to_string())?;
    tar::Archive::new(archive.stdout.as_slice())
        .unpack(temporary.path())
        .map_err(|error| error.to_string())?;
    Ok(crate_sites(&discover(temporary.path())?)
        .into_iter()
        .map(|(name, sites)| (name, sites.len()))
        .collect())
}

pub fn check(root: &Path, base: Option<&str>) -> Result<(), String> {
    let base =
        crate::authority_debt::comparison_base(root, base).map_err(|error| error.to_string())?;
    check_policy(root, base.as_deref())
}

fn check_policy(root: &Path, base: Option<&str>) -> Result<(), String> {
    let allowed =
        read_counts(&fs::read_to_string(root.join(CEILINGS)).map_err(|error| error.to_string())?)?;
    let sites = discover(root)?;
    validate(&sites, &allowed)?;
    if let Some(base) = base {
        let moves = crate::debt_moves::DebtMoves::load(root)?
            .terminal_custody(&crate::debt_moves::DebtMoves::load_at(root, base)?)?;
        ratchet(&allowed, &base_counts(root, base)?, &moves)
            .map_err(|error| format!("{error}; current sites: {sites:?}"))?;
        println!("terminal custody PR-base ratchet passed ({base})");
    } else {
        println!("terminal custody delta: no base provided; delta ratchet not applicable");
    }
    check_definition_ownership(root)?;
    println!(
        "terminal custody: {} current sites across {} nonzero crates",
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

fn validate(sites: &BTreeSet<String>, allowed: &BTreeMap<String, usize>) -> Result<(), String> {
    let actual = crate_sites(sites);
    for name in actual.keys().chain(allowed.keys()).collect::<BTreeSet<_>>() {
        let found = actual.get(name).map_or(0, Vec::len);
        let ceiling = allowed.get(name).copied().unwrap_or(0);
        if found != ceiling {
            return Err(format!(
                "terminal custody crate {name}: {found} sites, ceiling {ceiling}; ratchet decreases and delete zero entries; sites: {:?}",
                actual.get(name).map_or(&[][..], Vec::as_slice)
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_fixture(source: &str, counts: &str) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("crates/lane/src")).unwrap();
        fs::create_dir_all(root.path().join("scripts")).unwrap();
        fs::write(root.path().join("crates/lane/src/lib.rs"), source).unwrap();
        fs::write(root.path().join(CEILINGS), counts).unwrap();
        root
    }

    #[test]
    fn stale_crate_headroom_is_rejected() {
        let root = policy_fixture(
            "fn stop() { page.live(); }",
            r#"{"schema":1,"counters":[{"crate_name":"lane","ceiling":2}]}"#,
        );
        assert!(
            check_policy(root.path(), None).is_err(),
            "unused per-crate headroom must be ratcheted down"
        );
    }

    #[test]
    fn zero_debt_deletes_the_last_crate_entry() {
        let root = policy_fixture("fn apply() {}", r#"{"schema":1,"counters":[]}"#);
        assert!(
            check_policy(root.path(), None).is_ok(),
            "zero debt with no remaining crate entries must pass"
        );
    }

    #[test]
    fn negative_fixture_finds_renamed_file_and_deciding_method() {
        let source = include_str!("../tests/fixtures/terminal_custody/negative.rs.txt");
        let sites = sites_in_source("crates/new-lane/src/owner.rs", source).unwrap();
        assert!(sites.contains("crates/new-lane/src/owner.rs|Owner::retire_thread|live"));
        assert!(validate(&sites, &BTreeMap::new()).is_err());
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
    fn positive_fixture_keeps_applier_out_of_debt() {
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
    fn nonzero_debt_cannot_use_an_empty_policy() {
        let sites = BTreeSet::from(["crates/lane/src/lib.rs|stop|live".to_owned()]);
        assert!(validate(&sites, &BTreeMap::new()).is_err());
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
                validate(&sites, &BTreeMap::new()).is_err(),
                "planted {name} violation passed the gate"
            );
        }
    }

    #[test]
    fn reviewed_crate_moves_transfer_the_cohort_total() {
        use crate::debt_moves::DebtMove;
        let entries = [DebtMove {
            from: "lane".into(),
            to: "lane-linux".into(),
            issue: 673,
        }];
        let moves = MoveMap::new(&entries, &[]).unwrap();
        let inherited = MoveMap::new(&entries, &entries).unwrap();
        let base = BTreeMap::from([("lane".to_owned(), 28)]);
        let split = BTreeMap::from([("lane".to_owned(), 6), ("lane-linux".to_owned(), 22)]);
        assert!(
            ratchet(&split, &base, &moves).is_ok(),
            "a mapped move passes"
        );
        let grown = BTreeMap::from([("lane".to_owned(), 7), ("lane-linux".to_owned(), 22)]);
        assert!(
            ratchet(&grown, &base, &moves).is_err(),
            "a move that increases the total fails"
        );
        assert!(
            ratchet(&split, &base, &MoveMap::default()).is_err(),
            "an unmapped new crate fails"
        );
        let unrelated = BTreeMap::from([("lane".to_owned(), 6), ("other".to_owned(), 22)]);
        assert!(ratchet(&unrelated, &base, &moves).is_err());
        let source_grows = BTreeMap::from([("lane".to_owned(), 29), ("lane-linux".to_owned(), 0)]);
        assert!(
            ratchet(&source_grows, &base, &moves).is_err(),
            "a split whose source grows fails even when the total holds"
        );
        let shifted = BTreeMap::from([("lane".to_owned(), 7), ("lane-linux".to_owned(), 21)]);
        assert!(
            ratchet(
                &shifted,
                &BTreeMap::from([("lane".to_owned(), 6), ("lane-linux".to_owned(), 22)]),
                &moves
            )
            .is_err(),
            "after landing the entry is stale, so halves cannot trade debt"
        );
        let existing = BTreeMap::from([("lane".to_owned(), 28), ("lane-linux".to_owned(), 2)]);
        assert!(
            ratchet(
                &BTreeMap::from([("lane-linux".to_owned(), 30)]),
                &existing,
                &moves
            )
            .is_err(),
            "a move into an existing destination fails"
        );
        let wide = BTreeMap::from([("lane".to_owned(), 28), ("other".to_owned(), 5)]);
        let masked = BTreeMap::from([
            ("lane".to_owned(), 6),
            ("lane-linux".to_owned(), 25),
            ("other".to_owned(), 2),
        ]);
        assert!(
            ratchet(&masked, &wide, &moves).is_err(),
            "growth in the destination is not masked by a shrink elsewhere"
        );
        // (c) After landing, the inherited entry admits nothing: the halves
        // follow the ordinary per-crate rule and cannot trade debt.
        let landed = BTreeMap::from([("lane".to_owned(), 6), ("lane-linux".to_owned(), 22)]);
        assert!(ratchet(&landed, &landed, &inherited).is_ok());
        let traded = BTreeMap::from([("lane".to_owned(), 5), ("lane-linux".to_owned(), 23)]);
        assert!(
            ratchet(&traded, &landed, &inherited).is_err(),
            "an inherited entry cannot launder destination growth"
        );
    }

    #[test]
    fn monotone_counts_allow_relocation_and_deletion_but_not_growth() {
        let base = BTreeMap::from([("lane".to_owned(), 2)]);
        assert!(
            ratchet(
                &BTreeMap::from([("lane".to_owned(), 1)]),
                &base,
                &MoveMap::default()
            )
            .is_ok()
        );
        assert!(ratchet(&BTreeMap::new(), &base, &MoveMap::default()).is_ok());
        assert!(
            ratchet(
                &BTreeMap::from([("lane".to_owned(), 3)]),
                &base,
                &MoveMap::default()
            )
            .is_err()
        );
        assert!(
            ratchet(
                &BTreeMap::from([("new-lane".to_owned(), 1)]),
                &base,
                &MoveMap::default()
            )
            .is_err()
        );
        let relocated = BTreeSet::from(["crates/lane/src/renamed.rs|new_name|live".to_owned()]);
        assert!(validate(&relocated, &BTreeMap::from([("lane".to_owned(), 1)])).is_ok());
    }

    #[test]
    fn base_bootstrap_scans_committed_sources_and_corrupt_policy_fails_closed() {
        let root = policy_fixture(
            "fn stop() { page.live(); }",
            r#"{"schema":1,"counters":[]}"#,
        );
        let git = |args: &[&str]| {
            crate::command::run_checked("git", args, Some(root.path()))
                .unwrap()
                .stdout
        };
        git(&["init", "--quiet"]);
        git(&["config", "commit.gpgsign", "false"]);
        git(&["add", "crates"]);
        git(&[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=noreply@openai.com",
            "commit",
            "--quiet",
            "-m",
            "base sources",
        ]);
        let base = git(&["rev-parse", "HEAD"]);
        assert_eq!(
            base_counts(root.path(), base.trim()).unwrap(),
            BTreeMap::from([("lane".to_owned(), 1)])
        );
        fs::write(root.path().join(CEILINGS), "invalid JSON").unwrap();
        git(&["add", CEILINGS]);
        git(&[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=noreply@openai.com",
            "commit",
            "--quiet",
            "-m",
            "corrupt policy",
        ]);
        let corrupt = git(&["rev-parse", "HEAD"]);
        assert!(base_counts(root.path(), corrupt.trim()).is_err());
    }

    #[test]
    fn policy_rejects_zero_duplicates_unknown_schema_and_fields() {
        for source in [
            r#"{"schema":2,"counters":[]}"#,
            r#"{"schema":1,"counters":[{"crate_name":"lane","ceiling":0}]}"#,
            r#"{"schema":1,"counters":[{"crate_name":"lane","ceiling":1},{"crate_name":"lane","ceiling":1}]}"#,
            r#"{"schema":1,"counters":[],"sites":[]}"#,
        ] {
            assert!(
                read_counts(source).is_err(),
                "invalid policy accepted: {source}"
            );
        }
    }

    #[test]
    fn excess_crate_count_names_the_scanned_sites() {
        let site = "crates/lane/src/lib.rs|stop|live";
        let error = validate(&BTreeSet::from([site.to_owned()]), &BTreeMap::new()).unwrap_err();
        assert!(error.contains(site));
        assert!(error.contains("lane: 1 sites, ceiling 0"));
    }
}
