//! Syntactic assembly guard: no target compiler or macro expansion required.
//! Literal templates are decoded; operand/specification tokens and effective
//! cfg/cfg_attr attributes are retained. Rust whitespace and comments are ignored.
use crate::command::{CommandError, run_checked};
use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use syn::visit::{self, Visit};
use thiserror::Error;

const CRATES: &[&str] = &[
    "carrick-el1",
    "carrick-el1-abi",
    "carrick-x86-cpl0",
    "carrick-x86",
    "carrick-mmu-core",
];
const SYSREG: &str = "crates/carrick-vmm-hvf/src/trap/sysreg.rs";

#[derive(clap::Args, Debug)]
pub struct AsmDiffArgs {
    #[arg(long)]
    pub base: String,
    #[arg(long)]
    pub head: String,
    #[arg(long, value_enum, default_value = "aarch64")]
    pub arch: Arch,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub enum Arch {
    Aarch64,
    All,
}

#[derive(Debug, Error)]
pub enum AsmDiffError {
    #[error(transparent)]
    Command(#[from] CommandError),
    #[error("{path}: {source}")]
    Parse { path: String, source: syn::Error },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0} assembly block(s) changed, added or removed")]
    Changed(usize),
    #[error("assembly inventory is empty at {0}")]
    Empty(String),
    #[error("cannot inventory {0}")]
    Unsupported(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub krate: String,
    pub module: String,
    pub function: String,
    pub ordinal: usize,
}
impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}::{}::{}#{}",
            self.krate, self.module, self.function, self.ordinal
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assembly {
    pub kind: String,
    pub instructions: Vec<String>,
    /// Includes operands, options, clobber ABI and non-literal templates.
    pub specifications: String,
    pub cfg: Vec<String>,
}
pub type Manifest = BTreeMap<Key, Assembly>;

// Only target_arch is fixed. Features, target_os, test, etc. remain unknown,
// because this guard protects every possible aarch64 build configuration.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Truth {
    Yes,
    No,
    Unknown,
}
impl Truth {
    fn not(self) -> Self {
        match self {
            Self::Yes => Self::No,
            Self::No => Self::Yes,
            Self::Unknown => Self::Unknown,
        }
    }
    fn all(values: impl Iterator<Item = Self>) -> Self {
        values.fold(Self::Yes, |a, b| match (a, b) {
            (Self::No, _) | (_, Self::No) => Self::No,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            _ => Self::Yes,
        })
    }
    fn any(values: impl Iterator<Item = Self>) -> Self {
        Self::all(values.map(Self::not)).not()
    }
}
fn arguments(meta: &syn::MetaList) -> Option<Vec<syn::Meta>> {
    use syn::parse::Parser;
    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
        .parse2(meta.tokens.clone())
        .ok()
        .map(|args| args.into_iter().collect())
}
fn condition(meta: &syn::Meta) -> Truth {
    match meta {
        syn::Meta::NameValue(value) if value.path.is_ident("target_arch") => {
            if let syn::Expr::Lit(literal) = &value.value
                && let syn::Lit::Str(arch) = &literal.lit
            {
                if arch.value() == "aarch64" {
                    Truth::Yes
                } else {
                    Truth::No
                }
            } else {
                Truth::Unknown
            }
        }
        syn::Meta::List(list) => {
            let Some(args) = arguments(list) else {
                return Truth::Unknown;
            };
            if list.path.is_ident("all") {
                Truth::all(args.iter().map(condition))
            } else if list.path.is_ident("any") {
                Truth::any(args.iter().map(condition))
            } else if list.path.is_ident("not") && args.len() == 1 {
                condition(&args[0]).not()
            } else {
                Truth::Unknown
            }
        }
        _ => Truth::Unknown,
    }
}
fn attribute_condition(meta: &syn::Meta) -> Truth {
    let syn::Meta::List(list) = meta else {
        return Truth::Unknown;
    };
    let Some(args) = arguments(list) else {
        return Truth::Unknown;
    };
    if list.path.is_ident("cfg") && args.len() == 1 {
        condition(&args[0])
    } else if list.path.is_ident("cfg_attr") && args.len() >= 2 {
        // cfg_attr(C, cfg(P)) means !C || P. Non-cfg attributes do not
        // constrain reachability; nested cfg_attr is handled recursively.
        let enabled = condition(&args[0]);
        let restrictions = Truth::all(args[1..].iter().map(|attr| {
            if attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr") {
                attribute_condition(attr)
            } else {
                Truth::Yes
            }
        }));
        Truth::any([enabled.not(), restrictions].into_iter())
    } else {
        Truth::Unknown
    }
}
fn guarded(key: &Key, asm: &Assembly, arch: Arch) -> bool {
    if matches!(arch, Arch::All) {
        return true;
    }
    // These ISA crates and explicitly named ISA modules are x86-only even
    // when their crate-level source has no target_arch attribute.
    if matches!(key.krate.as_str(), "carrick-x86" | "carrick-x86-cpl0")
        || key
            .module
            .split("::")
            .any(|part| part == "x86" || part.starts_with("x86_"))
    {
        return false;
    }
    Truth::all(asm.cfg.iter().map(|cfg| {
        syn::parse_str::<syn::Meta>(cfg)
            .map(|meta| attribute_condition(&meta))
            .unwrap_or(Truth::Unknown)
    })) != Truth::No
}

struct ExternalModule {
    module: String,
    candidates: Vec<PathBuf>,
    cfg: Vec<String>,
}
struct Extractor {
    krate: String,
    module: String,
    function: String,
    owner: String,
    module_dir: PathBuf,
    path_attr_dir: PathBuf,
    cfg: Vec<String>,
    blocks: Manifest,
    external: Vec<ExternalModule>,
    unsupported: Option<String>,
}

fn is_cfg(attr: &syn::Attribute) -> bool {
    attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr")
}

// Decode string literals everywhere (also explicit registers/ABI names), so
// raw strings and escaped strings with the same value compare equal.
fn tokens(stream: TokenStream) -> String {
    stream
        .into_iter()
        .map(|token| match token {
            TokenTree::Group(group) => {
                format!("{:?}[{}]", group.delimiter(), tokens(group.stream()))
            }
            TokenTree::Literal(lit) => syn::parse_str::<syn::LitStr>(&lit.to_string())
                .map(|s| format!("{:?}", s.value()))
                .unwrap_or_else(|_| lit.to_string()),
            other => other.to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

impl Extractor {
    fn capture(&mut self, mac: &syn::Macro) {
        let kind = mac
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if kind != "asm" && kind != "global_asm" {
            // syn intentionally treats other macros as opaque. Scan their
            // token trees too, including unexpanded macro_rules bodies.
            self.scan_tokens(mac.tokens.clone());
            return;
        }
        let mut remaining = mac.tokens.clone().into_iter().peekable();
        let mut instructions = Vec::new();
        while let Some(TokenTree::Literal(literal)) = remaining.peek() {
            let Ok(string) = syn::parse_str::<syn::LitStr>(&literal.to_string()) else {
                break;
            };
            instructions.push(string.value());
            remaining.next();
            if matches!(remaining.peek(), Some(TokenTree::Punct(p)) if p.as_char() == ',') {
                remaining.next();
            } else {
                break;
            }
        }
        let specifications: TokenStream = remaining.collect();
        let leading: Vec<_> = specifications.clone().into_iter().take(2).collect();
        let unresolved_template = matches!(&leading[..], [TokenTree::Ident(_), TokenTree::Punct(bang)] if bang.as_char() == '!');
        if instructions.is_empty() || unresolved_template {
            self.unsupported = Some(format!(
                "{}::{}::{}: {kind}! requires literal instruction templates",
                self.krate, self.module, self.function
            ));
            return;
        }
        let ordinal = self
            .blocks
            .keys()
            .filter(|key| key.module == self.module && key.function == self.function)
            .count();
        let mut cfg = self.cfg.clone();
        cfg.sort();
        cfg.dedup();
        self.blocks.insert(
            Key {
                krate: self.krate.clone(),
                module: self.module.clone(),
                function: self.function.clone(),
                ordinal,
            },
            Assembly {
                kind,
                instructions,
                specifications: tokens(specifications)
                    .trim_end_matches(',')
                    .trim_end()
                    .to_owned(),
                cfg,
            },
        );
    }

    fn scan_tokens(&mut self, stream: TokenStream) {
        let trees: Vec<_> = stream.into_iter().collect();
        let mut i = 0;
        while i < trees.len() {
            if let [
                TokenTree::Ident(name),
                TokenTree::Punct(bang),
                TokenTree::Group(group),
                ..,
            ] = &trees[i..]
                && (name == "asm" || name == "global_asm")
                && bang.as_char() == '!'
            {
                // Parse the actual invocation, without an extra delimiter layer.
                let body = group.stream();
                let invocation = quote::quote!(#name!(#body));
                if let Ok(mac) = syn::parse2::<syn::Macro>(invocation) {
                    self.capture(&mac);
                }
                i += 3;
                continue;
            }
            if let TokenTree::Group(group) = &trees[i] {
                self.scan_tokens(group.stream());
            }
            i += 1;
        }
    }
}

impl<'ast> Visit<'ast> for Extractor {
    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        if is_cfg(attr) {
            self.cfg.push(attr.meta.to_token_stream().to_string());
        }
    }
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let n = self.cfg.len();
        visit::visit_item(self, item);
        self.cfg.truncate(n);
    }
    fn visit_expr(&mut self, expr: &'ast syn::Expr) {
        let n = self.cfg.len();
        visit::visit_expr(self, expr);
        self.cfg.truncate(n);
    }
    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        let n = self.cfg.len();
        visit::visit_arm(self, arm);
        self.cfg.truncate(n);
    }
    fn visit_fn_arg(&mut self, arg: &'ast syn::FnArg) {
        let n = self.cfg.len();
        visit::visit_fn_arg(self, arg);
        self.cfg.truncate(n);
    }
    fn visit_local(&mut self, local: &'ast syn::Local) {
        let n = self.cfg.len();
        visit::visit_local(self, local);
        self.cfg.truncate(n);
    }
    fn visit_stmt_macro(&mut self, mac: &'ast syn::StmtMacro) {
        let n = self.cfg.len();
        visit::visit_stmt_macro(self, mac);
        self.cfg.truncate(n);
    }
    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let n = self.cfg.len();
        visit::visit_impl_item(self, item);
        self.cfg.truncate(n);
    }
    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let n = self.cfg.len();
        visit::visit_trait_item(self, item);
        self.cfg.truncate(n);
    }
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let previous = std::mem::replace(&mut self.function, item.sig.ident.to_string());
        visit::visit_item_fn(self, item);
        self.function = previous;
    }
    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        let previous = std::mem::replace(
            &mut self.function,
            format!("{}::{}", self.owner, item.sig.ident),
        );
        visit::visit_impl_item_fn(self, item);
        self.function = previous;
    }
    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        let previous = std::mem::replace(
            &mut self.function,
            format!("{}::{}", self.owner, item.sig.ident),
        );
        visit::visit_trait_item_fn(self, item);
        self.function = previous;
    }
    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let owner = format!(
            "impl {} {}",
            tokens(item.self_ty.to_token_stream()),
            item.trait_
                .as_ref()
                .map(|(_, path, _)| tokens(path.to_token_stream()))
                .unwrap_or_default()
        );
        let previous = std::mem::replace(&mut self.owner, owner);
        visit::visit_item_impl(self, item);
        self.owner = previous;
    }
    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        let previous = std::mem::replace(&mut self.owner, item.ident.to_string());
        visit::visit_item_trait(self, item);
        self.owner = previous;
    }
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        for attr in &item.attrs {
            self.visit_attribute(attr);
        }
        let module = format!("{}::{}", self.module, item.ident);
        if let Some((_, items)) = &item.content {
            let previous = std::mem::replace(&mut self.module, module);
            let dir = self.module_dir.clone();
            let attr_dir = self.path_attr_dir.clone();
            self.module_dir.push(item.ident.to_string());
            self.path_attr_dir.push(item.ident.to_string());
            for child in items {
                self.visit_item(child);
            }
            self.module = previous;
            self.module_dir = dir;
            self.path_attr_dir = attr_dir;
        } else {
            let explicit = item.attrs.iter().find_map(|attr| {
                if attr.path().is_ident("path")
                    && let syn::Meta::NameValue(value) = &attr.meta
                    && let syn::Expr::Lit(literal) = &value.value
                    && let syn::Lit::Str(path) = &literal.lit
                {
                    Some(self.path_attr_dir.join(path.value()))
                } else {
                    None
                }
            });
            let candidates = explicit.map(|path| vec![path]).unwrap_or_else(|| {
                vec![
                    self.module_dir.join(format!("{}.rs", item.ident)),
                    self.module_dir.join(item.ident.to_string()).join("mod.rs"),
                ]
            });
            self.external.push(ExternalModule {
                module,
                candidates,
                cfg: self.cfg.clone(),
            });
        }
    }
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.capture(mac);
    }
}

fn extract(
    krate: &str,
    module: &str,
    path: &Path,
    source: &str,
    cfg: Vec<String>,
) -> Result<Extractor, AsmDiffError> {
    let file = syn::parse_file(source).map_err(|source| AsmDiffError::Parse {
        path: path.display().to_string(),
        source,
    })?;
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let module_dir = if matches!(stem, "lib" | "main" | "mod") {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    };
    let mut visitor = Extractor {
        krate: krate.into(),
        module: module.into(),
        function: "<global>".into(),
        owner: String::new(),
        module_dir,
        path_attr_dir: parent.to_path_buf(),
        cfg,
        blocks: BTreeMap::new(),
        external: Vec::new(),
        unsupported: None,
    };
    visitor.visit_file(&file);
    if let Some(message) = visitor.unsupported.take() {
        return Err(AsmDiffError::Unsupported(message));
    }
    Ok(visitor)
}

struct Walker<'a> {
    sources: &'a BTreeMap<PathBuf, String>,
    seen: BTreeSet<PathBuf>,
    active: BTreeSet<PathBuf>,
    contexts: BTreeSet<(PathBuf, String, Vec<String>)>,
    manifest: Manifest,
}
impl<'a> Walker<'a> {
    fn new(sources: &'a BTreeMap<PathBuf, String>) -> Self {
        Self {
            sources,
            seen: BTreeSet::new(),
            active: BTreeSet::new(),
            contexts: BTreeSet::new(),
            manifest: Manifest::new(),
        }
    }
    fn visit(
        &mut self,
        krate: &str,
        module: &str,
        path: &Path,
        cfg: Vec<String>,
    ) -> Result<(), AsmDiffError> {
        let Some(source) = self.sources.get(path) else {
            return Ok(());
        };
        if self.active.contains(path) {
            return Err(AsmDiffError::Unsupported(format!(
                "recursive module at {}",
                path.display()
            )));
        }
        if !self
            .contexts
            .insert((path.to_path_buf(), module.into(), cfg.clone()))
        {
            return Ok(());
        }
        self.seen.insert(path.to_path_buf());
        self.active.insert(path.to_path_buf());
        let extracted = extract(krate, module, path, source, cfg)?;
        for (mut key, asm) in extracted.blocks {
            // Conditional modules may give distinct invocations the same
            // logical function path. Never overwrite one architecture's asm.
            while self.manifest.contains_key(&key) {
                key.ordinal += 1;
            }
            self.manifest.insert(key, asm);
        }
        for external in extracted.external {
            if let Some(child) = external
                .candidates
                .iter()
                .find(|path| self.sources.contains_key(*path))
            {
                self.visit(krate, &external.module, child, external.cfg)?;
            }
        }
        self.active.remove(path);
        Ok(())
    }
}

fn revision(root: &Path, rev: &str) -> Result<String, AsmDiffError> {
    Ok(run_checked(
        "git",
        [
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{rev}^{{commit}}"),
        ],
        Some(root),
    )?
    .stdout
    .trim()
    .into())
}

fn snapshot(root: &Path, rev: &str) -> Result<Manifest, AsmDiffError> {
    let mut args = vec![
        "ls-tree".to_string(),
        "-rz".into(),
        "--name-only".into(),
        rev.into(),
        "--".into(),
    ];
    args.extend(CRATES.iter().map(|name| format!("crates/{name}")));
    args.push(SYSREG.into());
    let paths = run_checked("git", args, Some(root))?.stdout;
    let mut sources = BTreeMap::new();
    for path in paths.split('\0').filter(|path| path.ends_with(".rs")) {
        let source = run_checked("git", ["show", &format!("{rev}:{path}")], Some(root))?.stdout;
        sources.insert(PathBuf::from(path), source);
    }
    let mut walker = Walker::new(&sources);
    for krate in CRATES {
        for entry in ["lib.rs", "main.rs"] {
            let path = PathBuf::from(format!("crates/{krate}/src/{entry}"));
            let module = if entry == "lib.rs" { "crate" } else { "main" };
            walker.visit(krate, module, &path, Vec::new())?;
        }
    }
    // Include build scripts, tests and source files outside the module tree.
    for path in sources
        .keys()
        .filter(|path| !walker.seen.contains(*path))
        .cloned()
        .collect::<Vec<_>>()
    {
        let components: Vec<_> = path.iter().map(|s| s.to_string_lossy()).collect();
        let krate = components.get(1).map(|s| s.as_ref()).unwrap_or_default();
        let relative = path
            .strip_prefix(format!("crates/{krate}/src/"))
            .unwrap_or(&path);
        let module = format!(
            "crate::{}",
            relative
                .with_extension("")
                .to_string_lossy()
                .replace('/', "::")
        );
        walker.visit(krate, &module, &path, Vec::new())?;
    }
    if walker.manifest.is_empty() {
        return Err(AsmDiffError::Empty(rev.into()));
    }
    Ok(walker.manifest)
}

/// Exact payload matches at different keys are moves. Movement preserves the
/// guard; every instruction, operand, option, cfg, addition or removal fails it.
pub fn compare<W: Write>(
    base: &Manifest,
    head: &Manifest,
    arch: Arch,
    writer: &mut W,
) -> Result<usize, AsmDiffError> {
    let mut old = base.clone();
    let mut new = head.clone();
    for (key, asm) in base {
        if head.get(key) == Some(asm) {
            old.remove(key);
            new.remove(key);
        }
    }
    for (key, asm) in old.clone() {
        if let Some(destination) = new.iter().find_map(|(destination, candidate)| {
            (candidate == &asm
                && guarded(destination, candidate, arch) == guarded(&key, &asm, arch))
            .then(|| destination.clone())
        }) {
            writeln!(writer, "MOVED {key} -> {destination}")?;
            old.remove(&key);
            new.remove(&destination);
        }
    }
    let mut failures = 0;
    for (key, asm) in old {
        if let Some(replacement) = new.remove(&key) {
            let protected = guarded(&key, &asm, arch) || guarded(&key, &replacement, arch);
            failures += usize::from(protected);
            let label = if protected { "CHANGED" } else { "CHANGED-X86" };
            writeln!(
                writer,
                "{label} {key}\n  base: {asm:?}\n  head: {replacement:?}"
            )?;
        } else {
            let protected = guarded(&key, &asm, arch);
            failures += usize::from(protected);
            let label = if protected { "REMOVED" } else { "REMOVED-X86" };
            writeln!(writer, "{label} {key}: {asm:?}")?;
        }
    }
    for (key, asm) in new {
        let protected = guarded(&key, &asm, arch);
        failures += usize::from(protected);
        let label = if protected { "ADDED" } else { "ADDED-X86" };
        writeln!(writer, "{label} {key}: {asm:?}")?;
    }
    writeln!(
        writer,
        "{} base / {} head assembly blocks; {failures} failure(s)",
        base.len(),
        head.len()
    )?;
    Ok(failures)
}

pub fn run<W: Write>(root: &Path, args: AsmDiffArgs, writer: &mut W) -> Result<(), AsmDiffError> {
    let base = snapshot(root, &revision(root, &args.base)?)?;
    let head = snapshot(root, &revision(root, &args.head)?)?;
    let changed = compare(&base, &head, args.arch, writer)?;
    if changed != 0 {
        return Err(AsmDiffError::Changed(changed));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn manifest(source: &str) -> Manifest {
        extract(
            "guest",
            "crate",
            Path::new("src/lib.rs"),
            source,
            Vec::new(),
        )
        .unwrap()
        .blocks
    }

    #[test]
    fn extracts_all_forms_with_effective_cfg_and_method_identity() {
        let source = r##"
#![cfg(target_arch = "aarch64")]
#[cfg(feature = "guest")]
mod nested {
    global_asm!(r#"isb"#);
    impl A {
        #[cfg_attr(test, cfg(feature = "test"))]
        fn same() {
            #[cfg(target_os = "none")]
            unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) value, options(nomem)); }
            asm!("isb");
        }
    }
    impl B { fn same() { asm!("nop"); } }
}
macro_rules! barrier { () => { asm!("dsb sy", options(nostack)); } }
"##;
        let blocks = manifest(source);
        assert_eq!(blocks.len(), 5);
        let register = blocks
            .iter()
            .find(|(_, asm)| asm.instructions == ["mrs {}, cntfrq_el0"])
            .unwrap();
        assert!(register.0.function.contains("impl A"));
        assert_eq!(register.0.module, "crate::nested");
        assert_eq!(register.1.cfg.len(), 4);
        assert!(register.1.specifications.contains("out"));
        let isb = blocks
            .iter()
            .find(|(key, _)| key.function.contains("impl A") && key.ordinal == 1)
            .unwrap();
        assert_eq!(isb.1.cfg.len(), 3); // expression cfg does not leak
        let nop = blocks
            .iter()
            .find(|(_, asm)| asm.instructions == ["nop"])
            .unwrap();
        assert_eq!(nop.1.cfg.len(), 2); // method cfg does not leak
    }

    #[test]
    fn strings_and_rust_whitespace_normalize_but_operands_and_cfg_do_not() {
        let a = manifest(r#"fn f() { asm!("nop", in("x0") value, options(nostack)); }"#);
        let b = manifest(r##"fn f(){asm!(r#"nop"#,in ("x0") value,options( nostack ),);}"##);
        assert_eq!(a, b);
        for source in [
            r#"fn f() { asm!("isb", in("x0") value, options(nostack)); }"#,
            r#"fn f() { asm!("nop", in("x1") value, options(nostack)); }"#,
            r#"fn f() { asm!("nop", in("x0") other, options(nostack)); }"#,
            r#"fn f() { asm!("nop", in("x0") value, options(nomem)); }"#,
            r#"#[cfg(test)] fn f() { asm!("nop", in("x0") value, options(nostack)); }"#,
        ] {
            assert_ne!(
                compare(&a, &manifest(source), Arch::Aarch64, &mut Vec::new()).unwrap(),
                0
            );
        }
    }

    #[test]
    fn reports_moves_reordering_and_duplicate_multiplicity() {
        let a = manifest(r#"fn f() { asm!("isb"); asm!("nop"); asm!("nop"); }"#);
        let b = manifest(r#"mod moved { fn f() { asm!("nop"); asm!("isb"); asm!("nop"); } }"#);
        let mut output = Vec::new();
        assert_eq!(compare(&a, &b, Arch::Aarch64, &mut output).unwrap(), 0);
        assert_eq!(
            String::from_utf8(output).unwrap().matches("MOVED").count(),
            3
        );
        let removed = manifest(r#"fn f() { asm!("isb"); asm!("nop"); }"#);
        assert_eq!(
            compare(&a, &removed, Arch::Aarch64, &mut Vec::new()).unwrap(),
            1
        );
        assert_eq!(
            compare(&removed, &a, Arch::Aarch64, &mut Vec::new()).unwrap(),
            1
        );
    }

    #[test]
    fn follows_external_and_path_modules_with_parent_cfg() {
        let sources = BTreeMap::from([
            (
                PathBuf::from("src/lib.rs"),
                "#[cfg(feature = \"guest\")] mod outer;".into(),
            ),
            (
                PathBuf::from("src/outer.rs"),
                "#[path = \"other.rs\"] mod renamed; mod inner { fn f() { asm!(\"nop\"); } }"
                    .into(),
            ),
            (
                PathBuf::from("src/other.rs"),
                "fn g() { asm!(\"isb\"); }".into(),
            ),
        ]);
        let mut walker = Walker::new(&sources);
        walker
            .visit("guest", "crate", Path::new("src/lib.rs"), Vec::new())
            .unwrap();
        let blocks = walker.manifest;
        assert_eq!(blocks.len(), 2);
        assert!(
            blocks
                .keys()
                .any(|key| key.module == "crate::outer::renamed")
        );
        assert!(blocks.keys().any(|key| key.module == "crate::outer::inner"));
        assert!(blocks.values().all(|asm| asm.cfg.len() == 1));
    }

    #[test]
    fn architecture_filter_evaluates_boolean_cfg_and_cfg_attr_conservatively() {
        let key = Key {
            krate: "guest".into(),
            module: "crate".into(),
            function: "f".into(),
            ordinal: 0,
        };
        for (cfg, expected) in [
            ("cfg(target_arch = \"x86_64\")", false),
            ("cfg(not(target_arch = \"aarch64\"))", false),
            (
                "cfg(all(target_arch = \"x86_64\", feature = \"unknown\"))",
                false,
            ),
            (
                "cfg(any(target_arch = \"x86_64\", feature = \"unknown\"))",
                true,
            ),
            ("cfg(feature = \"unknown\")", true),
            (
                "cfg_attr(target_arch = \"aarch64\", cfg(target_arch = \"x86_64\"))",
                false,
            ),
            ("cfg_attr(test, cfg(target_arch = \"x86_64\"))", true),
            ("cfg_attr(target_arch = \"x86_64\", cfg(any()))", true),
            ("cfg(unsupported(foo))", true),
            ("malformed cfg", true),
        ] {
            let asm = Assembly {
                kind: "asm".into(),
                instructions: vec!["nop".into()],
                specifications: String::new(),
                cfg: vec![cfg.into()],
            };
            assert_eq!(guarded(&key, &asm, Arch::Aarch64), expected, "{cfg}");
            assert!(guarded(&key, &asm, Arch::All));
        }
    }

    #[test]
    fn conditional_modules_never_overwrite_another_architecture() {
        let sources = BTreeMap::from([
            (PathBuf::from("src/lib.rs"), "#[cfg(target_arch = \"x86_64\")] #[path = \"x.rs\"] mod arch; #[cfg(target_arch = \"aarch64\")] #[path = \"a.rs\"] mod arch;".into()),
            (PathBuf::from("src/x.rs"), "fn f() { asm!(\"nop\"); }".into()),
            (PathBuf::from("src/a.rs"), "fn f() { asm!(\"isb\"); }".into()),
        ]);
        let mut walker = Walker::new(&sources);
        walker
            .visit("guest", "crate", Path::new("src/lib.rs"), Vec::new())
            .unwrap();
        assert_eq!(walker.manifest.len(), 2);
        assert_eq!(
            walker
                .manifest
                .iter()
                .filter(|(key, asm)| guarded(key, asm, Arch::Aarch64))
                .count(),
            1
        );
    }
}
