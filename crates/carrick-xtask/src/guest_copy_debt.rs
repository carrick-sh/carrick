//! Syntactic retirement census for #1684. No guest execution or type inference.
//! Inventories named copy calls; ratchets unclassified error consumers and
//! bool copy trait methods separately. Locations are diagnostics only.
use quote::ToTokens;
use std::{collections::BTreeMap, fs, path::Path};
use syn::{
    spanned::Spanned,
    visit::{self, Visit},
};

const POLICY: &str = "scripts/guest-copy-debt-ceilings.json";
const CRATES: &[&str] = &[
    "carrick-core",
    "carrick-el1",
    "carrick-el1-linux",
    "carrick-personality-linux",
    "carrick-kernel",
    "carrick-x86",
];

#[derive(Debug, serde::Serialize)]
pub struct Site {
    pub path: String,
    pub line: usize,
    pub kind: String,
    pub operation: String,
    pub disposition: String,
}

// Keep vocabulary explicit: `copy` and one-argument byte-buffer IO are not
// necessarily guest memory. UFCS includes the receiver as an extra argument.
fn copy_name(name: &str, arity: usize) -> bool {
    match name {
        "copy" | "copy_in" | "copy_out" | "copy_in_bytes" | "copy_out_bytes" | "read_bytes"
        | "read_bytes_raw" | "write_bytes" | "write_bytes_raw" => arity == 2,
        "read_val" | "read_struct" | "read_struct_va" | "read_c_string" => arity >= 1,
        "write_val" | "write_struct" | "write_struct_va" => arity == 2,
        _ => {
            name.starts_with("copyout_")
                || matches!(
                    name,
                    "copy_to_user_guarded"
                        | "copy_from_user_guarded"
                        | "read_user_word"
                        | "copy_user_chunk"
                        | "write_user_bytes"
                        | "read_packed"
                        | "write_packed"
                        | "read_kernel_prefix"
                        | "read_kernel_struct"
                        | "read_guest_c_string"
                        | "read_guest_c_string_bytes"
                        | "read_guest_c_string_bytes_bounded"
                        | "read_guest_c_string_before_effects"
                        | "read_guest_string_array_bytes"
                        | "write_termios2"
                        | "write_statfs"
                        | "write_u32"
                        | "write_linux_sockaddr"
                        | "read_linux_sockaddr"
                        | "write_kernel_struct"
                        | "write_kernel_struct_raw"
                )
        }
    }
}

// Only direct syntactic provenance is claimed; aliases and wrappers need review.
fn contains_copy(expr: &syn::Expr) -> bool {
    #[derive(Default)]
    struct Finder(bool);
    impl<'a> Visit<'a> for Finder {
        fn visit_expr_method_call(&mut self, n: &'a syn::ExprMethodCall) {
            self.0 |= copy_name(&n.method.to_string(), n.args.len());
            visit::visit_expr_method_call(self, n);
        }
        fn visit_expr_call(&mut self, n: &'a syn::ExprCall) {
            if let syn::Expr::Path(p) = &*n.func
                && let Some(last) = p.path.segments.last()
            {
                self.0 |= copy_name(&last.ident.to_string(), n.args.len())
                    || (!n.args.is_empty() && copy_name(&last.ident.to_string(), n.args.len() - 1));
            }
            visit::visit_expr_call(self, n);
        }
    }
    let mut finder = Finder::default();
    finder.visit_expr(expr);
    finder.0
}
fn unclassified_error(pat: &syn::Pat) -> bool {
    match pat {
        syn::Pat::Wild(_) | syn::Pat::Ident(_) => true,
        syn::Pat::TupleStruct(p) if p.path.segments.last().is_some_and(|p| p.ident == "Err") => p
            .elems
            .iter()
            .any(|p| matches!(p, syn::Pat::Wild(_) | syn::Pat::Ident(_))),
        syn::Pat::Or(p) => p.cases.iter().any(unclassified_error),
        _ => false,
    }
}

#[derive(Default)]
struct Census {
    sites: Vec<(usize, &'static str, String, String)>,
    disposition: String,
    trait_name: String,
}
impl Census {
    fn record(&mut self, span: proc_macro2::Span, kind: &'static str, name: String) {
        self.sites
            .push((span.start().line, kind, name, self.disposition.clone()));
    }
    fn macro_groups(&mut self, tokens: proc_macro2::TokenStream) {
        for token in tokens {
            if let proc_macro2::TokenTree::Group(group) = token {
                // define_syscall! has a non-Rust signature, but its handler
                // body is Rust. Parse each largest possible block exactly once.
                if group.delimiter() == proc_macro2::Delimiter::Brace
                    && let Ok(block) = syn::parse2::<syn::Block>(
                        std::iter::once(proc_macro2::TokenTree::Group(group.clone())).collect(),
                    )
                {
                    self.visit_block(&block);
                } else {
                    self.macro_groups(group.stream());
                }
            }
        }
    }
}
impl<'ast> Visit<'ast> for Census {
    fn visit_item(&mut self, node: &'ast syn::Item) {
        let attrs = match node {
            syn::Item::Fn(i) => &i.attrs,
            syn::Item::Impl(i) => &i.attrs,
            syn::Item::Mod(i) => &i.attrs,
            syn::Item::Trait(i) => &i.attrs,
            syn::Item::Macro(i) => &i.attrs,
            syn::Item::Const(i) => &i.attrs,
            syn::Item::Static(i) => &i.attrs,
            _ => return visit::visit_item(self, node),
        };
        if !crate::authority_source::test_only(attrs) {
            visit::visit_item(self, node);
        }
    }
    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        let old = std::mem::replace(&mut self.trait_name, node.ident.to_string());
        visit::visit_item_trait(self, node);
        self.trait_name = old;
    }
    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        if crate::authority_source::test_only(&node.attrs) {
            return;
        }
        let name = node.sig.ident.to_string();
        if (copy_name(&name, node.sig.inputs.len().saturating_sub(1))
            || name.starts_with("copy")
            || name.starts_with("read_user")
            || name.starts_with("write_user"))
            && let syn::ReturnType::Type(_, ty) = &node.sig.output
            && matches!(&**ty, syn::Type::Path(p) if p.path.is_ident("bool"))
        {
            self.record(
                node.sig.ident.span(),
                "bool-trait",
                format!("{}::{name}", self.trait_name),
            );
        }
        visit::visit_trait_item_fn(self, node);
    }
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if !crate::authority_source::test_only(&node.attrs) {
            visit::visit_impl_item_fn(self, node);
        }
    }
    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        if contains_copy(&node.expr) {
            if node.arms.iter().any(|a| unclassified_error(&a.pat)) {
                self.record(node.span(), "error-collapse", "match".into());
            }
            let refusal = node
                .arms
                .iter()
                .filter(|a| !a.pat.to_token_stream().to_string().starts_with("Ok"))
                .map(|a| a.to_token_stream().to_string())
                .collect::<Vec<_>>()
                .join("; ");
            let old = std::mem::replace(&mut self.disposition, refusal);
            self.visit_expr(&node.expr);
            self.disposition = old;
            for arm in &node.arms {
                self.visit_arm(arm);
            }
        } else {
            visit::visit_expr_match(self, node);
        }
    }
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if contains_copy(&node.cond) {
            let refusal = node.then_branch.to_token_stream().to_string();
            let old = std::mem::replace(&mut self.disposition, refusal);
            self.visit_expr(&node.cond);
            self.disposition = old;
            self.visit_block(&node.then_branch);
            if let Some((_, other)) = &node.else_branch {
                self.visit_expr(other);
            }
        } else {
            visit::visit_expr_if(self, node);
        }
    }
    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        let old = std::mem::replace(&mut self.disposition, "? propagates error to caller".into());
        visit::visit_expr_try(self, node);
        self.disposition = old;
    }
    fn visit_local(&mut self, node: &'ast syn::Local) {
        let old = std::mem::take(&mut self.disposition);
        if let Some(init) = &node.init {
            if let Some((_, diverge)) = &init.diverge {
                self.disposition = diverge.to_token_stream().to_string();
            } else if matches!(node.pat, syn::Pat::Wild(_)) {
                self.disposition = "ignored result (let _)".into();
            }
        }
        visit::visit_local(self, node);
        self.disposition = old;
    }
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let name = node.method.to_string();
        if name == "is_done" && contains_copy(&node.receiver) {
            self.record(node.span(), "typed-collapse", name.clone());
        }
        if matches!(
            name.as_str(),
            "map_err"
                | "or_else"
                | "ok"
                | "is_err"
                | "is_ok"
                | "unwrap_or"
                | "unwrap_or_else"
                | "unwrap_or_default"
        ) && contains_copy(&node.receiver)
        {
            self.record(node.span(), "error-collapse", name.clone());
        }
        if copy_name(&name, node.args.len()) {
            self.record(node.span(), "legacy-call", name.clone());
        }
        let old = self.disposition.clone();
        if matches!(
            name.as_str(),
            "map_err"
                | "or_else"
                | "ok"
                | "is_err"
                | "is_ok"
                | "unwrap_or"
                | "unwrap_or_else"
                | "unwrap_or_default"
                | "then_some"
                | "then"
        ) {
            self.disposition = format!("{}({})", name, node.args.to_token_stream());
        }
        visit::visit_expr_method_call(self, node);
        self.disposition = old;
    }
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*node.func
            && let Some(last) = p.path.segments.last()
        {
            let name = last.ident.to_string();
            if copy_name(&name, node.args.len())
                || (!node.args.is_empty() && copy_name(&name, node.args.len() - 1))
            {
                self.record(node.span(), "legacy-call", name.clone());
            }
        }
        visit::visit_expr_call(self, node);
    }
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        self.macro_groups(node.tokens.clone());
    }
}

fn source_sites(path: &str, source: &str) -> Result<Vec<Site>, String> {
    let file = syn::parse_file(source).map_err(|e| format!("{path}: {e}"))?;
    let mut census = Census::default();
    if !crate::authority_source::test_only(&file.attrs) {
        census.visit_file(&file);
    }
    Ok(census
        .sites
        .into_iter()
        .map(|(line, kind, operation, disposition)| Site {
            path: path.into(),
            line,
            kind: kind.into(),
            operation,
            disposition,
        })
        .collect())
}

pub fn discover(root: &Path) -> Result<Vec<Site>, String> {
    let mut sites = Vec::new();
    for name in CRATES {
        let dir = root.join("crates").join(name).join("src");
        let mut files = Vec::new();
        crate::copyout_debt::files(&dir, &mut files)?;
        files.sort();
        for file in files {
            let path = file
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .to_string_lossy();
            sites.extend(source_sites(
                &path,
                &fs::read_to_string(&file).map_err(|e| e.to_string())?,
            )?);
        }
    }
    Ok(sites)
}

type Counts = BTreeMap<String, usize>;
fn counts(sites: &[Site]) -> Counts {
    let mut counts = Counts::new();
    for site in sites.iter().filter(|site| site.kind != "legacy-call") {
        *counts
            .entry(if site.kind == "typed-collapse" {
                // A source-derived monotone total survives neutral code moves
                // while the older per-file categories keep their exact limits.
                "typed-collapse".into()
            } else if site.kind == "bool-trait" {
                format!("{}:{}:{}", site.kind, site.path, site.operation)
            } else {
                format!("{}:{}", site.kind, site.path)
            })
            .or_default() += 1;
    }
    counts
}
fn read_policy(source: &str) -> Result<Counts, String> {
    let counts: Counts = serde_json::from_str(source).map_err(|e| e.to_string())?;
    if counts.values().any(|n| *n == 0) {
        return Err("delete zero guest-copy ceilings".into());
    }
    Ok(counts)
}
fn validate(found: &Counts, allowed: &Counts, previous: &Counts) -> Result<(), String> {
    if found != allowed {
        return Err("guest-copy debt differs from ceilings; retire legacy calls and lower their exact per-file/kind counts".into());
    }
    for (key, count) in found {
        if *count > previous.get(key).copied().unwrap_or(0) {
            return Err(format!("guest-copy debt increased: {key} -> {count}"));
        }
    }
    Ok(())
}

fn source_counts_at(root: &Path, base: &str) -> Result<Counts, String> {
    let output = std::process::Command::new("git")
        .args(["archive", base, "--", "crates"])
        .current_dir(root)
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("cannot archive guest-copy base".into());
    }
    let temp = tempfile::tempdir().map_err(|e| e.to_string())?;
    tar::Archive::new(output.stdout.as_slice())
        .unpack(temp.path())
        .map_err(|e| e.to_string())?;
    Ok(counts(&discover(temp.path())?))
}

pub fn check(root: &Path, base: Option<&str>) -> Result<(), String> {
    let found = counts(&discover(root)?);
    let allowed = read_policy(&fs::read_to_string(root.join(POLICY)).map_err(|e| e.to_string())?)?;
    let base = crate::authority_debt::comparison_base(root, base).map_err(|e| e.to_string())?;
    let previous = if let Some(base) = base {
        let exists =
            crate::command::run_checked("git", ["ls-tree", &base, "--", POLICY], Some(root))
                .map_err(|e| e.to_string())?;
        if exists.stdout.trim().is_empty() {
            // First introduction must compare against base source, not HEAD's
            // newly written ceilings. Never permit bootstrap headroom.
            source_counts_at(root, &base)?
        } else {
            let output = crate::command::run_checked(
                "git",
                ["show", &format!("{base}:{POLICY}")],
                Some(root),
            )
            .map_err(|e| e.to_string())?;
            let mut previous = read_policy(&output.stdout)?;
            if !previous.keys().any(|key| key.as_str() == "typed-collapse") {
                // First census of typed-outcome collapse compares with source,
                // never the newly introduced HEAD ceilings. Once present, the
                // committed category ratchets like every older kind.
                previous.extend(
                    source_counts_at(root, &base)?
                        .into_iter()
                        .filter(|(key, _)| key.as_str() == "typed-collapse"),
                );
            }
            previous
        }
    } else {
        allowed.clone()
    };
    validate(&found, &allowed, &previous)?;
    println!(
        "typed guest-copy collapses: {} -> {}",
        previous.get("typed-collapse").copied().unwrap_or(0),
        found.get("typed-collapse").copied().unwrap_or(0)
    );
    println!(
        "guest-copy debt: {} error collapses/typed collapses/bool trait methods across {} counters",
        found.values().sum::<usize>(),
        found.len()
    );
    Ok(())
}

pub fn list(root: &Path, writer: &mut impl std::io::Write) -> Result<(), String> {
    for site in discover(root)? {
        writeln!(
            writer,
            "{}:{}\t{}\t{}\t{}",
            site.path,
            site.line,
            site.kind,
            site.operation,
            site.disposition.replace('\t', " ")
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn typed_done_test_counts_owner_refusal_collapse() {
        let sites = source_sites("f.rs", "fn f() { if !u.write_val(a, &b).is_done() { fault(); } if !u.copy_out(a, b).is_done() { fault(); } } ").unwrap();
        assert_eq!(
            sites.iter().filter(|s| s.kind == "typed-collapse").count(),
            2
        );
        let handled = source_sites("f.rs", "fn f() { match u.copy_out(a, b) { CopyOutcome::Done => done(), CopyOutcome::Fault => fault(), CopyOutcome::NotYet(request) => park(request) } }").unwrap();
        assert!(counts(&handled).is_empty());
        let baseline = counts(&sites);
        let mut added = baseline.clone();
        *added.get_mut("typed-collapse").unwrap() += 1;
        assert!(validate(&added, &added, &baseline).is_err());
        validate(&counts(&handled), &counts(&handled), &baseline).unwrap();
    }

    #[test]
    fn production_errno_collapse_and_macro_body_are_counted() {
        let source = r#"trait UserCopy { fn copy_in(&mut self, a: &mut [u8], b: u64) -> bool; }
            fn f() { match m.read_bytes(a, n) { Ok(b) => b, Err(_) => return LINUX_EFAULT }; }
            define_syscall! { fn g(this, cx, a: GuestPtr) { m.copyout_bytes(a, b).map_err(|_| LINUX_EFAULT); } }
            #[cfg(test)] mod tests { fn f() { m.read_bytes(a, n); } }"#;
        let sites = source_sites("f.rs", source).unwrap();
        assert_eq!(sites.iter().filter(|s| s.kind != "legacy-call").count(), 3);
        assert_eq!(sites[0].kind, "bool-trait");
    }
    #[test]
    fn ufcs_generics_and_alternative_collapse_spellings_are_counted() {
        let sites = source_sites("f.rs", "fn f() { GuestMemory::read_bytes(m, a, n).ok(); m.read_struct::<T>(a).is_err(); if !u.copy_in(a, b) {} buffer.read_bytes(n); }").unwrap();
        assert_eq!(sites.iter().filter(|s| s.kind == "legacy-call").count(), 3);
    }
    #[test]
    fn wrapping_an_existing_copy_with_errno_collapse_increases_debt() {
        let before = source_sites("f.rs", "fn f() { m.read_bytes(a, n)?; }").unwrap();
        let after = source_sites(
            "f.rs",
            "fn f() { match m.read_bytes(a, n) { Ok(v) => v, Err(_) => return LINUX_EFAULT }; }",
        )
        .unwrap();
        assert_eq!(
            before.iter().filter(|s| s.kind == "legacy-call").count(),
            after.iter().filter(|s| s.kind == "legacy-call").count()
        );
        assert!(validate(&counts(&after), &counts(&after), &counts(&before)).is_err());
        let typed = source_sites("f.rs", "fn f() { match m.read_bytes(a,n) { Ok(v) => v, Err(CopyError::Fault) => fault(), Err(CopyError::Busy) => park() }; }").unwrap();
        assert!(counts(&typed).is_empty());
    }

    #[test]
    fn per_file_and_kind_ratchet_rejects_increases_and_stale_headroom() {
        let base = Counts::from([("bool-trait:a".into(), 1), ("legacy-call:b".into(), 3)]);
        let changed = Counts::from([("bool-trait:a".into(), 2), ("legacy-call:b".into(), 1)]);
        assert!(validate(&changed, &changed, &base).is_err());
        assert!(validate(&base, &changed, &base).is_err());
        assert!(read_policy(r#"{"legacy-call:a":0}"#).is_err());
        validate(&base, &base, &base).unwrap();
    }
}
