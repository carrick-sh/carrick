//! Ratchet for unprepared user-memory writes in the syscall dispatcher (#711).
//!
//! An admitted EL1 owner may refuse a host copyout transiently (editor busy,
//! physical supply, retained writer). A handler that writes its result with a
//! direct `write_bytes`/`write_kernel_struct*`/`write_packed`/`write_struct`
//! cannot report that refusal as a retry and lowers it to EFAULT on a valid
//! pointer. `dispatch::copyout` prepares every output before side effects;
//! this counter records the direct writes that remain, per file. Ceilings are
//! exact: a migration must lower its file's entry, a zero entry is deleted, and
//! the total may never rise against the change base. At zero the ratchet
//! itself is deleted.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use syn::visit::{self, Visit};

const CEILINGS: &str = "scripts/copyout-debt-ceilings.json";
const SCOPE: &str = "crates/carrick-kernel/src/dispatch";
/// The typed copyout owns the one sanctioned legacy-venue write.
const OWNER: &str = "crates/carrick-kernel/src/dispatch/copyout.rs";

/// Guest-memory trait methods that write user memory directly. A one-argument
/// `write_bytes` is a pipe or buffer write, not guest memory.
const DIRECT_METHODS: &[(&str, usize)] = &[
    ("write_bytes", 2),
    ("write_struct", 2),
    ("write_struct_va", 2),
    ("write_va", 2),
];

/// Dispatcher helpers that wrap one of the direct methods without preparing.
const DIRECT_HELPERS: &[&str] = &[
    "write_packed",
    "write_kernel_struct",
    "write_kernel_struct_raw",
    "write_termios2",
    "write_statfs",
    "write_u32",
    "write_linux_sockaddr",
];

fn helper(name: &str) -> bool {
    DIRECT_HELPERS.contains(&name)
}

fn method(name: &str, arguments: usize) -> bool {
    DIRECT_METHODS
        .iter()
        .any(|(candidate, arity)| *candidate == name && *arity == arguments)
}

/// Top-level comma-separated arguments in a parenthesized group.
fn arity(stream: proc_macro2::TokenStream) -> usize {
    let mut count = 0;
    let mut pending = false;
    for token in stream {
        match token {
            proc_macro2::TokenTree::Punct(punct) if punct.as_char() == ',' => {
                if pending {
                    count += 1;
                }
                pending = false;
            }
            _ => pending = true,
        }
    }
    count + usize::from(pending)
}

#[derive(Default)]
struct DirectWrites {
    count: usize,
}

impl DirectWrites {
    /// syn leaves macro arguments (every `define_syscall!` handler) opaque.
    /// Scan call-shaped token runs and recurse into groups.
    fn scan_tokens(&mut self, tokens: proc_macro2::TokenStream) {
        let tokens: Vec<_> = tokens.into_iter().collect();
        for (index, token) in tokens.iter().enumerate() {
            match token {
                proc_macro2::TokenTree::Ident(ident) => {
                    let Some(proc_macro2::TokenTree::Group(group)) = tokens.get(index + 1) else {
                        continue;
                    };
                    if group.delimiter() != proc_macro2::Delimiter::Parenthesis {
                        continue;
                    }
                    let previous = index.checked_sub(1).and_then(|before| tokens.get(before));
                    let name = ident.to_string();
                    match previous {
                        Some(proc_macro2::TokenTree::Ident(keyword)) if keyword == "fn" => {}
                        Some(proc_macro2::TokenTree::Punct(punct)) if punct.as_char() == '.' => {
                            if method(&name, arity(group.stream())) {
                                self.count += 1;
                            }
                        }
                        _ => {
                            if helper(&name) {
                                self.count += 1;
                            }
                        }
                    }
                }
                proc_macro2::TokenTree::Group(group) => self.scan_tokens(group.stream()),
                _ => {}
            }
        }
    }
}

/// Only a proven false cfg exempts code; features and negation may be live.
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

impl<'ast> Visit<'ast> for DirectWrites {
    fn visit_item(&mut self, node: &'ast syn::Item) {
        let attrs = match node {
            syn::Item::Fn(item) => &item.attrs,
            syn::Item::Impl(item) => &item.attrs,
            syn::Item::Mod(item) => &item.attrs,
            syn::Item::Trait(item) => &item.attrs,
            syn::Item::Macro(item) => &item.attrs,
            syn::Item::Const(item) => &item.attrs,
            syn::Item::Static(item) => &item.attrs,
            _ => return visit::visit_item(self, node),
        };
        if !test_only(attrs) {
            visit::visit_item(self, node);
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if !test_only(&node.attrs) {
            visit::visit_impl_item_fn(self, node);
        }
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        if !test_only(&node.attrs) {
            visit::visit_trait_item_fn(self, node);
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if method(&node.method.to_string(), node.args.len()) {
            self.count += 1;
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*node.func
            && let Some(last) = path.path.segments.last()
            && helper(&last.ident.to_string())
        {
            self.count += 1;
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        self.scan_tokens(node.tokens.clone());
        visit::visit_macro(self, node);
    }
}

fn production_file(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension == "rs")
        && !path.components().any(|component| {
            matches!(
                component.as_os_str().to_str(),
                Some("tests" | "test_support")
            )
        })
        && !path.file_name().is_some_and(|name| {
            let name = name.to_string_lossy();
            name.ends_with("_tests.rs")
                || name.ends_with("_fixture.rs")
                || name == "tests.rs"
                || name == "test_support.rs"
        })
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))? {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path.is_dir() {
            files(&path, out)?;
        } else if production_file(&path) {
            out.push(path);
        }
    }
    Ok(())
}

pub fn count_source(path: &str, source: &str) -> Result<usize, String> {
    let file = syn::parse_file(source).map_err(|error| format!("{path}: {error}"))?;
    let mut visitor = DirectWrites::default();
    visitor.visit_file(&file);
    Ok(visitor.count)
}

/// Current direct-write counts per production file; zero files are omitted.
pub fn discover(root: &Path) -> Result<BTreeMap<String, usize>, String> {
    let scope = root.join(SCOPE);
    if !scope.is_dir() {
        return Err(format!("copyout debt scope is missing: {SCOPE}"));
    }
    let mut found = Vec::new();
    files(&scope, &mut found)?;
    let mut counts = BTreeMap::new();
    for file in found {
        let path = file
            .strip_prefix(root)
            .map_err(|error| error.to_string())?
            .to_string_lossy()
            .into_owned();
        if path == OWNER {
            continue;
        }
        let source = fs::read_to_string(&file).map_err(|error| error.to_string())?;
        let count = count_source(&path, &source)?;
        if count > 0 {
            counts.insert(path, count);
        }
    }
    Ok(counts)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCeiling {
    path: String,
    ceiling: usize,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CopyoutDebtCeilings {
    schema: u32,
    counters: Vec<FileCeiling>,
}

fn read_counts(source: &str) -> Result<BTreeMap<String, usize>, String> {
    let policy: CopyoutDebtCeilings =
        serde_json::from_str(source).map_err(|error| error.to_string())?;
    if policy.schema != 1 {
        return Err("unknown copyout debt ceiling schema".to_owned());
    }
    let mut counts = BTreeMap::new();
    for counter in policy.counters {
        if !counter.path.starts_with(SCOPE) || counter.ceiling == 0 {
            return Err(format!(
                "invalid or zero copyout debt ceiling; delete zero entries: {}",
                counter.path
            ));
        }
        if counts
            .insert(counter.path.clone(), counter.ceiling)
            .is_some()
        {
            return Err(format!("duplicate copyout debt ceiling: {}", counter.path));
        }
    }
    Ok(counts)
}

fn validate(
    found: &BTreeMap<String, usize>,
    allowed: &BTreeMap<String, usize>,
) -> Result<(), String> {
    for path in found.keys().chain(allowed.keys()) {
        let count = found.get(path).copied().unwrap_or(0);
        let ceiling = allowed.get(path).copied().unwrap_or(0);
        if count != ceiling {
            return Err(format!(
                "copyout debt {path}: {count} direct user-memory writes, ceiling {ceiling}; \
                 prepare outputs through dispatch::copyout, lower the ceiling with each \
                 migration and delete zero entries"
            ));
        }
    }
    Ok(())
}

fn total(counts: &BTreeMap<String, usize>) -> usize {
    counts.values().sum()
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
    // Bootstrap from the base sources themselves, never the candidate policy.
    let archive = std::process::Command::new("git")
        .args(["archive", base, "--", SCOPE])
        .current_dir(root)
        .output()
        .map_err(|error| error.to_string())?;
    if !archive.status.success() {
        return Err("cannot read copyout debt base sources".to_owned());
    }
    let temporary = tempfile::tempdir().map_err(|error| error.to_string())?;
    tar::Archive::new(archive.stdout.as_slice())
        .unpack(temporary.path())
        .map_err(|error| error.to_string())?;
    discover(temporary.path())
}

pub fn check(root: &Path, base: Option<&str>) -> Result<(), String> {
    let base =
        crate::authority_debt::comparison_base(root, base).map_err(|error| error.to_string())?;
    check_policy(root, base.as_deref())
}

fn check_policy(root: &Path, base: Option<&str>) -> Result<(), String> {
    let allowed =
        read_counts(&fs::read_to_string(root.join(CEILINGS)).map_err(|error| error.to_string())?)?;
    let found = discover(root)?;
    validate(&found, &allowed)?;
    if found.is_empty() {
        return Err(
            "copyout debt is zero: delete the copyout-debt ratchet, its ceilings and gate".into(),
        );
    }
    if let Some(base) = base {
        let previous = total(&base_counts(root, base)?);
        if total(&found) > previous {
            return Err(format!(
                "copyout debt increase against {base}: {previous} -> {}",
                total(&found)
            ));
        }
        println!("copyout debt PR-base ratchet passed ({base}: {previous})");
    } else {
        println!("copyout debt delta: no base provided; delta ratchet not applicable");
    }
    println!(
        "copyout debt: {} direct user-memory writes across {} dispatch files",
        total(&found),
        found.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(source: &str) -> usize {
        count_source("fixture.rs", source).unwrap()
    }

    fn fixture(source: &str, ceilings: &str) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join(SCOPE)).unwrap();
        fs::create_dir_all(root.path().join("scripts")).unwrap();
        fs::write(root.path().join(SCOPE).join("fs.rs"), source).unwrap();
        fs::write(root.path().join(CEILINGS), ceilings).unwrap();
        root
    }

    #[test]
    fn direct_guest_writes_are_counted_and_buffer_writes_are_not() {
        assert_eq!(
            count(
                "fn f(m: &mut M) { m.write_bytes(a, b).ok(); pipe.write_bytes(b); \
                 write_kernel_struct(m, a, &v); m.write_struct(a, &v); }"
            ),
            3
        );
        // A definition is not a call site.
        assert_eq!(count("fn write_packed(m: &mut M, a: u64, b: &[u8]) {}"), 0);
    }

    #[test]
    fn handlers_inside_macros_are_scanned() {
        assert_eq!(
            count(
                "define_syscall! { fn pipe2(this, cx, fd: u64) { \
                 (*cx.memory).write_bytes(a, &b)?; write_packed(memory, a, &b); \
                 if x { memory.write_bytes(a, &[0u8; 4]).is_err(); } } }"
            ),
            3
        );
    }

    #[test]
    fn test_only_code_is_exempt_but_live_cfgs_are_not() {
        assert_eq!(
            count("#[cfg(test)] mod t { fn f() { m.write_bytes(a, b); } }"),
            0
        );
        assert_eq!(
            count(r#"#[cfg(feature = "test")] fn f() { m.write_bytes(a, b); }"#),
            1
        );
        assert_eq!(
            count("#[cfg(not(test))] fn f() { m.write_bytes(a, b); }"),
            1
        );
    }

    #[test]
    fn stale_headroom_and_zero_entries_are_rejected() {
        let path = format!("{SCOPE}/fs.rs");
        let root = fixture(
            "fn f() { m.write_bytes(a, b); }",
            &format!(r#"{{"schema":1,"counters":[{{"path":"{path}","ceiling":2}}]}}"#),
        );
        assert!(
            check_policy(root.path(), None)
                .unwrap_err()
                .contains("ceiling 2")
        );
        let root = fixture(
            "fn f() { m.write_bytes(a, b); }",
            &format!(r#"{{"schema":1,"counters":[{{"path":"{path}","ceiling":0}}]}}"#),
        );
        assert!(
            check_policy(root.path(), None)
                .unwrap_err()
                .contains("zero")
        );
        let root = fixture(
            "fn f() { m.write_bytes(a, b); }",
            &format!(r#"{{"schema":1,"counters":[{{"path":"{path}","ceiling":1}}]}}"#),
        );
        check_policy(root.path(), None).unwrap();
    }

    #[test]
    fn zero_debt_deletes_the_ratchet() {
        let root = fixture("fn f() {}", r#"{"schema":1,"counters":[]}"#);
        assert!(
            check_policy(root.path(), None)
                .unwrap_err()
                .contains("delete")
        );
    }
}
