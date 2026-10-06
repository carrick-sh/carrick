//! The census accepts syntax only when its scope and sensitive names are visible.
use crate::authority_debt::DebtError;
use proc_macro2::{Delimiter, Span, TokenStream, TokenTree};
use quote::ToTokens;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::{
    ext::IdentExt,
    parse::Parser,
    spanned::Spanned,
    visit::{self, Visit},
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AttributeAudit {
    name: String,
    reason: String,
    #[serde(default)]
    generated_options: Vec<GeneratedOption>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratedOption {
    option: String,
    operation: GeneratedOperation,
    permitted_owners: BTreeMap<String, BTreeSet<String>>,
}

#[derive(serde::Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum GeneratedOperation {
    EnvironmentRead,
}
impl GeneratedOperation {
    fn description(&self) -> &'static str {
        match self {
            Self::EnvironmentRead => "environment read",
        }
    }
}

fn compiler_derive(name: &str) -> bool {
    matches!(
        name,
        "Clone" | "Copy" | "Debug" | "Default" | "Eq" | "PartialEq" | "Ord" | "PartialOrd" | "Hash"
    )
}

fn compiler_derive_path(path: &syn::Path) -> bool {
    let spelling = name(path).replacen("std::", "core::", 1);
    if compiler_derive(&spelling) {
        return true;
    }
    path.leading_colon.is_some()
        && matches!(
            spelling.as_str(),
            "core::clone::Clone"
                | "core::marker::Copy"
                | "core::fmt::Debug"
                | "core::default::Default"
                | "core::cmp::Eq"
                | "core::cmp::PartialEq"
                | "core::cmp::Ord"
                | "core::cmp::PartialOrd"
                | "core::hash::Hash"
        )
}

pub(super) fn ambient_operation(name: &str) -> bool {
    matches!(
        name,
        "abort"
            | "exit"
            | "var"
            | "var_os"
            | "vars"
            | "vars_os"
            | "set_var"
            | "remove_var"
            | "current_dir"
            | "set_current_dir"
            | "current_exe"
            | "args"
            | "args_os"
            | "home_dir"
            | "temp_dir"
    )
}

fn name(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|s| s.ident.unraw().to_string())
        .collect::<Vec<_>>()
        .join("::")
}

// Literal metadata is not executable Rust. Reject expressions, blocks and
// unrecognized token syntax rather than trying to find calls inside it.
fn metadata(tokens: TokenStream) -> bool {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<()> {
        while !input.is_empty() {
            if input.peek(syn::Lit) {
                let _: syn::Lit = input.parse()?;
            } else {
                let meta: syn::Meta = input.parse()?;
                match meta {
                    syn::Meta::Path(_) => {}
                    syn::Meta::NameValue(value) if matches!(value.value, syn::Expr::Lit(_)) => {}
                    syn::Meta::List(list) if metadata(list.tokens.clone()) => {}
                    _ => return Err(input.error("executable attribute arguments")),
                }
            }
            if !input.is_empty() {
                let _: syn::Token![,] = input.parse()?;
            }
        }
        Ok(())
    }
    parse.parse2(tokens).is_ok()
}

// Macro documentation templates have exactly one built-in attribute name.
// A doc value cannot change cfg scope, a module path, or emit runtime code.
fn doc_template(stream: TokenStream) -> TokenStream {
    stream.into_iter().map(|token| match token {
        TokenTree::Group(group) if group.delimiter() == Delimiter::Bracket => {
            let tokens: Vec<_> = group.stream().into_iter().collect();
            let template = matches!(tokens.first(), Some(TokenTree::Ident(id)) if id.unraw() == "doc")
                && matches!(tokens.get(1), Some(TokenTree::Punct(p)) if p.as_char() == '=')
                && matches!(tokens.get(2), Some(TokenTree::Punct(p)) if p.as_char() == '$')
                && matches!(tokens.get(3), Some(TokenTree::Ident(_)))
                && (tokens.len() == 4 || (tokens.len() == 6
                    && matches!(tokens.get(4), Some(TokenTree::Punct(p)) if p.as_char() == ':')
                    && matches!(tokens.get(5), Some(TokenTree::Ident(id)) if id.unraw() == "expr")));
            if template {
                let mut normalized = proc_macro2::Group::new(Delimiter::Bracket, quote::quote!(doc = ""));
                normalized.set_span(group.span()); TokenTree::Group(normalized)
            } else { TokenTree::Group(group) }
        }
        token => token,
    }).collect()
}

#[derive(Debug, serde::Serialize)]
pub(super) struct CanonicalCall {
    start: usize,
    end: usize,
    path: String,
}
impl CanonicalCall {
    pub(super) fn covers(&self, range: std::ops::Range<usize>) -> bool {
        self.start == range.start && self.end == range.end
    }
}
type Calls = BTreeMap<String, Vec<CanonicalCall>>;

fn item_imports(syntax: &syn::File) -> BTreeMap<String, String> {
    struct Imports(BTreeMap<String, String>);
    impl Imports {
        fn tree(&mut self, tree: &syn::UseTree, prefix: &[String]) {
            match tree {
                syn::UseTree::Path(p) => {
                    let mut prefix = prefix.to_vec();
                    prefix.push(p.ident.unraw().to_string());
                    self.tree(&p.tree, &prefix);
                }
                syn::UseTree::Group(g) => {
                    for tree in &g.items {
                        self.tree(tree, prefix);
                    }
                }
                syn::UseTree::Name(n) if n.ident.unraw() != "self" => {
                    let leaf = n.ident.unraw().to_string();
                    let path = format!("{}::{leaf}", prefix.join("::"));
                    // Conflicting same-named imports are never an authority
                    // binding, even when one occurrence is canonical.
                    self.0
                        .entry(leaf)
                        .and_modify(|old| {
                            if *old != path {
                                old.clear();
                            }
                        })
                        .or_insert(path);
                }
                _ => {}
            }
        }
    }
    impl<'ast> Visit<'ast> for Imports {
        fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
            if !super::authority_source::test_only(&item.attrs)
                && matches!(item.vis, syn::Visibility::Inherited)
            {
                self.tree(
                    &item.tree,
                    &if item.leading_colon.is_some() {
                        vec![String::new()]
                    } else {
                        Vec::new()
                    },
                );
            }
        }
    }
    let mut imports = Imports(BTreeMap::new());
    for item in &syntax.items {
        if let syn::Item::Use(item) = item {
            imports.visit_item_use(item);
        }
    }
    imports.0
}

pub(super) fn validate(
    root: &Path,
    parsed: &BTreeMap<PathBuf, syn::File>,
    operations: &BTreeSet<String>,
    raw_methods: &BTreeSet<String>,
    test_files: &BTreeSet<PathBuf>,
    production: &BTreeSet<PathBuf>,
    module_owners: Option<&BTreeMap<PathBuf, Vec<Vec<String>>>>,
) -> Result<Calls, DebtError> {
    let audits: Vec<AttributeAudit> = serde_json::from_str(include_str!(
        "../../../scripts/migrate/authority-attribute-allowlist.json"
    ))?;
    let mut allowed = BTreeSet::new();
    let mut generated_options = BTreeMap::new();
    for entry in audits {
        if matches!(entry.name.as_str(), "arg" | "clap" | "command")
            && !entry.generated_options.iter().any(|option| {
                option.option == "env" && option.operation == GeneratedOperation::EnvironmentRead
            })
        {
            return Err(DebtError::Policy(format!(
                "missing generated environment read audit: {}",
                entry.name
            )));
        }
        generated_options.insert(entry.name.clone(), entry.generated_options);
        if entry.reason.trim().is_empty() || !allowed.insert(entry.name.clone()) {
            return Err(DebtError::Policy(format!(
                "invalid attribute audit: {}",
                entry.name
            )));
        }
    }
    let macro_audits = super::authority_macro::audits()?;
    if macro_audits
        .iter()
        .any(|a| a.reason.trim().is_empty() || a.names.is_empty())
    {
        return Err(DebtError::Policy("invalid executable macro audit".into()));
    }
    let mut valid_definitions = BTreeMap::new();
    for audit in &macro_audits {
        let valid = match (&audit.definition_file, &audit.definition_sha256) {
            (Some(file), Some(_hash)) => {
                let path = root.join(file);
                parsed
                    .get(&path)
                    .zip(std::fs::read(&path).ok())
                    .is_some_and(|(file, bytes)| {
                        struct Definitions<'a> {
                            audit: &'a super::authority_macro::Audit,
                            bytes: &'a [u8],
                            valid: bool,
                        }
                        impl<'ast> Visit<'ast> for Definitions<'_> {
                            fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
                                if item.ident.as_ref().is_some_and(|id| {
                                    self.audit.names.contains(&id.unraw().to_string())
                                }) && self.bytes.get(item.span().byte_range()).is_some_and(
                                    |body| {
                                        super::authority_source::source_hash(body)
                                            == self.audit.definition_sha256.as_deref().unwrap_or("")
                                    },
                                ) {
                                    self.valid = true;
                                }
                            }
                        }
                        let mut definitions = Definitions {
                            audit,
                            bytes: &bytes,
                            valid: false,
                        };
                        definitions.visit_file(file);
                        definitions.valid
                    })
            }
            (None, None) => true,
            _ => false,
        };
        valid_definitions.insert(audit.names[0].clone(), valid);
    }
    let mut protected: BTreeSet<String> = operations
        .iter()
        .cloned()
        .chain(
            [
                "FileTable",
                "FileDescription",
                "FileSlot",
                "FileTableWriteGuard",
                "FileTableMutexGuard",
                "FileTableRwWriteGuard",
                "FileTableStdioGuard",
                "abort",
                "exit",
                "process",
                "env",
                "std",
                "core",
                "var",
                "var_os",
                "vars",
                "vars_os",
                "set_var",
                "remove_var",
                "current_dir",
                "set_current_dir",
                "current_exe",
                "args",
                "args_os",
                "home_dir",
                "temp_dir",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .collect();
    let original_protected = protected.clone();
    // Name taint is global and monotone: ambiguity only increases rejection.
    // A type alias/re-export cannot turn a protected target into a safe rename.
    loop {
        let mut taint = Taint {
            known: &protected,
            found: BTreeSet::new(),
        };
        for syntax in parsed.values() {
            taint.visit_file(syntax);
        }
        let found = taint.found;
        let previous = protected.len();
        protected.extend(found);
        if previous == protected.len() {
            break;
        }
    }
    let aliases: BTreeSet<_> = protected.difference(&original_protected).cloned().collect();
    let mut errors = Vec::new();
    let mut calls = BTreeMap::new();
    for (path, syntax) in parsed {
        if test_files.contains(path) && !production.contains(path) {
            continue;
        }
        let mut validator = Validator {
            root,
            path,
            allowed: &allowed,
            macro_audits: &macro_audits,
            valid_definitions: &valid_definitions,
            protected: &protected,
            operations,
            aliases: &aliases,
            raw_methods,
            errors: &mut errors,
            proven_test: false,
            opaque: false,
            import_absolute: false,
            glob: None,
            derived_imports: derive_imports(syntax, &allowed),
            helpers: BTreeSet::new(),
            generated_options: &generated_options,
            metadata_owners: Vec::new(),
            local_bindings: BTreeSet::new(),
            item_imports: item_imports(syntax),
            canonical_calls: Vec::new(),
            lexical_owners: Vec::new(),
            module_owners: module_owners
                .and_then(|owners| owners.get(path))
                .cloned()
                .unwrap_or_default(),
            check_metadata_owner: module_owners.is_some(),
        };
        // The source file's outer imports affect all descendant attributes.
        // A glob inside a proven cfg(test) module cannot affect its parent.
        validator.glob = production_glob(syntax);
        validator.visit_file(syntax);
        let relative = path
            .strip_prefix(root)
            .map_err(|e| DebtError::Policy(e.to_string()))?
            .to_string_lossy()
            .into_owned();
        calls.insert(relative, validator.canonical_calls);
    }
    if errors.is_empty() {
        Ok(calls)
    } else {
        Err(DebtError::Policy(errors.join("\n")))
    }
}

struct Taint<'a> {
    known: &'a BTreeSet<String>,
    found: BTreeSet<String>,
}
impl Taint<'_> {
    fn ty(&mut self, ident: &syn::Ident, ty: &syn::Type) {
        struct Names<'a> {
            known: &'a BTreeSet<String>,
            sensitive: bool,
        }
        impl<'ast> Visit<'ast> for Names<'_> {
            fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
                if path
                    .path
                    .segments
                    .last()
                    .is_some_and(|s| self.known.contains(&s.ident.unraw().to_string()))
                {
                    self.sensitive = true;
                }
                visit::visit_type_path(self, path);
            }
        }
        let mut names = Names {
            known: self.known,
            sensitive: false,
        };
        names.visit_type(ty);
        if names.sensitive {
            self.found.insert(ident.unraw().to_string());
        }
    }
}
impl<'ast> Visit<'ast> for Taint<'_> {
    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        self.ty(&item.ident, &item.ty);
    }
    fn visit_impl_item_type(&mut self, item: &'ast syn::ImplItemType) {
        self.ty(&item.ident, &item.ty);
    }
    fn visit_use_rename(&mut self, item: &'ast syn::UseRename) {
        if self.known.contains(&item.ident.unraw().to_string()) {
            self.found.insert(item.rename.unraw().to_string());
        }
    }
}

fn derive_imports(syntax: &syn::File, allowed: &BTreeSet<String>) -> BTreeSet<String> {
    struct Imports<'a> {
        allowed: &'a BTreeSet<String>,
        names: BTreeSet<String>,
    }
    impl Imports<'_> {
        fn tree(&mut self, tree: &syn::UseTree, prefix: &str) {
            match tree {
                syn::UseTree::Path(p) => {
                    self.tree(&p.tree, &format!("{prefix}{}::", p.ident.unraw()))
                }
                syn::UseTree::Group(g) => {
                    for item in &g.items {
                        self.tree(item, prefix);
                    }
                }
                syn::UseTree::Name(n)
                    if self
                        .allowed
                        .contains(&format!("{prefix}{}", n.ident.unraw())) =>
                {
                    self.names.insert(n.ident.unraw().to_string());
                }
                _ => {}
            }
        }
    }
    impl<'ast> Visit<'ast> for Imports<'_> {
        fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
            self.tree(&item.tree, "");
        }
    }
    let mut imports = Imports {
        allowed,
        names: BTreeSet::new(),
    };
    imports.visit_file(syntax);
    imports.names
}

fn production_glob(syntax: &syn::File) -> Option<Span> {
    struct Globs(Option<Span>);
    impl<'ast> Visit<'ast> for Globs {
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            if !super::authority_source::test_only(&item.attrs) {
                visit::visit_item_fn(self, item);
            }
        }
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if !super::authority_source::test_only(&item.attrs) {
                visit::visit_item_mod(self, item);
            }
        }
        fn visit_use_glob(&mut self, glob: &'ast syn::UseGlob) {
            self.0 = Some(glob.span());
        }
    }
    let mut globs = Globs(None);
    globs.visit_file(syntax);
    globs.0
}

struct Validator<'a> {
    root: &'a Path,
    path: &'a Path,
    allowed: &'a BTreeSet<String>,
    macro_audits: &'a [super::authority_macro::Audit],
    valid_definitions: &'a BTreeMap<String, bool>,
    protected: &'a BTreeSet<String>,
    operations: &'a BTreeSet<String>,
    aliases: &'a BTreeSet<String>,
    raw_methods: &'a BTreeSet<String>,
    errors: &'a mut Vec<String>,
    proven_test: bool,
    opaque: bool,
    import_absolute: bool,
    glob: Option<Span>,
    derived_imports: BTreeSet<String>,
    helpers: BTreeSet<String>,
    generated_options: &'a BTreeMap<String, Vec<GeneratedOption>>,
    metadata_owners: Vec<String>,
    local_bindings: BTreeSet<String>,
    item_imports: BTreeMap<String, String>,
    canonical_calls: Vec<CanonicalCall>,
    lexical_owners: Vec<String>,
    module_owners: Vec<Vec<String>>,
    check_metadata_owner: bool,
}
impl Validator<'_> {
    fn reject(&mut self, span: Span, message: impl AsRef<str>) {
        let at = span.start();
        self.errors.push(format!(
            "{}:{}:{}: restricted census dialect: {}",
            self.path.display(),
            at.line,
            at.column + 1,
            message.as_ref()
        ));
    }
    fn has_protected_tokens(&self, stream: TokenStream) -> bool {
        let tokens: Vec<_> = stream.into_iter().collect();
        tokens.iter().enumerate().any(|(index, token)| match token {
            TokenTree::Ident(id) => (self.operation_name(&id.unraw().to_string()) || (id.unraw().to_string().chars().next().is_some_and(char::is_uppercase) && (self.operations.contains(&id.unraw().to_string()) || self.aliases.contains(&id.unraw().to_string()))))
                && (!self.local_bindings.contains(&id.unraw().to_string())
                    || matches!(index.checked_sub(1).and_then(|i| tokens.get(i)), Some(TokenTree::Punct(p)) if matches!(p.as_char(), ':' | '.'))),
            TokenTree::Group(group) => self.has_protected_tokens(group.stream()),
            _ => false,
        })
    }
    fn operation_name(&self, name: &str) -> bool {
        ambient_operation(name)
            || self.operations.contains(name)
                && name.chars().next().is_some_and(char::is_lowercase)
                && !matches!(name, "include" | "include_str")
    }
    fn protected_operation(&self, path: &syn::Path) -> bool {
        path.segments
            .last()
            .is_some_and(|s| self.operation_name(&s.ident.unraw().to_string()))
            || path.segments.iter().any(|s| {
                let name = s.ident.unraw().to_string();
                name.chars().next().is_some_and(char::is_uppercase)
                    && (self.operations.contains(&name) || self.aliases.contains(&name))
            })
    }
    fn canonical_call(&self, path: &syn::ExprPath) -> bool {
        if path.qself.is_some()
            || path
                .path
                .segments
                .iter()
                .any(|s| !matches!(s.arguments, syn::PathArguments::None))
        {
            return false;
        }
        let spelling = name(&path.path);
        if self.glob.is_some()
            && path.path.leading_colon.is_none()
            && path
                .path
                .segments
                .first()
                .is_some_and(|s| s.ident.unraw() != "crate")
            && path.path.segments.len() > 1
        {
            return false;
        }
        if path.path.segments.len() == 1 {
            return self.item_imports.get(&spelling).is_some_and(|target| {
                syn::parse_str::<syn::ExprPath>(target)
                    .is_ok_and(|path| path.path.segments.len() > 1 && self.canonical_call(&path))
            });
        }
        let Some(leaf) = path.path.segments.last() else {
            return false;
        };
        let operation = leaf.ident.unraw().to_string();
        if ambient_operation(&operation)
            && (path.path.segments.len() == 1
                || path
                    .path
                    .segments
                    .iter()
                    .any(|s| matches!(s.ident.unraw().to_string().as_str(), "env" | "process"))
                || spelling.starts_with("libc::"))
        {
            let namespace = if matches!(operation.as_str(), "abort" | "exit") {
                "process"
            } else {
                "env"
            };
            spelling == format!("std::{namespace}::{operation}")
        } else {
            // Receiver calls are visited separately. A free authority call
            // must start at the defining crate, never a type or module alias.
            path.path.segments.len() >= 2
                && path.path.segments.first().is_some_and(|s| {
                    let root = s.ident.unraw().to_string();
                    root == "crate"
                        || root.starts_with("carrick_")
                        || root == "std"
                        || root == "core"
                        || root == "libc"
                        || root == "tokio"
                })
        }
    }
    fn imports(&mut self, tree: &syn::UseTree, prefix: &[String]) {
        // `self` binds the last path component, never the token "self".
        // Check the binding before inspecting the imported item's leaf.
        let bound = match tree {
            syn::UseTree::Name(n) if n.ident.unraw() == "self" => prefix.last().cloned(),
            syn::UseTree::Name(n) => Some(n.ident.unraw().to_string()),
            syn::UseTree::Rename(n) => Some(n.rename.unraw().to_string()),
            _ => None,
        };
        if matches!(tree, syn::UseTree::Name(n) if n.ident.unraw() == "self")
            && bound.as_ref().is_some_and(|bound| compiler_derive(bound))
        {
            self.reject(tree.span(), "self import may rebind a compiler derive");
        }
        if bound.as_ref().is_some_and(|bound| {
            self.allowed.iter().any(|entry| {
                entry.contains("::") && entry.split("::").next() == Some(bound.as_str())
            })
        }) {
            self.reject(
                tree.span(),
                "audited macro binding may rebind a canonical provider",
            );
        }
        if bound.as_ref().is_some_and(|bound| {
            self.macro_audits.iter().any(|a| {
                a.names.iter().any(|name| {
                    name == bound
                        || name.split("::").next() == Some(bound.as_str()) && name.contains("::")
                })
            })
        }) {
            let exact_item = matches!(tree, syn::UseTree::Name(n) if n.ident.unraw() != "self"
                && self.macro_audits.iter().any(|audit| audit.names.contains(&format!("{}::{}", prefix.join("::"), n.ident.unraw()))));
            if !exact_item {
                self.reject(tree.span(), "audited macro binding import is unresolved");
            }
        }
        match tree {
            syn::UseTree::Path(path) => {
                let mut prefix = prefix.to_vec();
                prefix.push(path.ident.unraw().to_string());
                self.imports(&path.tree, &prefix);
            }
            syn::UseTree::Group(group) => {
                for tree in &group.items {
                    self.imports(tree, prefix);
                }
            }
            syn::UseTree::Rename(rename) => {
                let from = rename.ident.unraw().to_string();
                let to = rename.rename.unraw().to_string();
                if self.allowed.iter().any(|entry| {
                    entry.split("::").next() == Some(to.as_str()) && entry.contains("::")
                }) {
                    self.reject(rename.span(), "import may rebind an audited macro provider");
                }
                if self.allowed.contains(&from) || self.allowed.contains(&to) {
                    self.reject(
                        rename.span(),
                        "import may rebind an audited attribute macro",
                    );
                }
                let canonical_anonymous = prefix.len() >= 2
                    && (self.import_absolute || prefix.first().is_some_and(|p| p == "std"))
                    && to == "_"
                    && compiler_derive_path(
                        &syn::parse_str::<syn::Path>(&format!("::{}::{from}", prefix.join("::")))
                            .unwrap_or_else(|_| syn::Path::from(rename.ident.clone())),
                    );
                if (compiler_derive(&from) || compiler_derive(&to)) && !canonical_anonymous {
                    self.reject(rename.span(), "import may rebind a compiler derive");
                }
                if from == "test" || to == "test" {
                    self.reject(rename.span(), "import may rebind built-in test");
                }
                let target = if from == "self" {
                    prefix.last().unwrap_or(&from)
                } else {
                    &from
                };
                if self.protected.contains(target) || self.protected.contains(&to) {
                    self.reject(
                        rename.span(),
                        format!("renamed protected import {target} as {to}"),
                    );
                }
            }
            syn::UseTree::Name(import)
                if compiler_derive(&import.ident.unraw().to_string())
                    && (prefix.len() < 2
                        || !(self.import_absolute
                            || prefix.first().is_some_and(|p| p == "std"))
                        || !compiler_derive_path(
                            &syn::parse_str::<syn::Path>(&format!(
                                "::{}::{}",
                                prefix.join("::"),
                                import.ident.unraw()
                            ))
                            .unwrap_or_else(|_| syn::Path::from(import.ident.clone())),
                        )) =>
            {
                self.reject(import.span(), "import may rebind a compiler derive");
            }
            syn::UseTree::Name(import)
                if import.ident.unraw() == "self"
                    && prefix.last().is_some_and(|p| self.protected.contains(p)) =>
            {
                self.reject(import.span(), "sensitive namespace self import is unsupported; use the explicit canonical path");
            }
            syn::UseTree::Glob(glob)
                if prefix.last().is_some_and(|p| self.protected.contains(p)) =>
            {
                self.reject(glob.span(), "sensitive namespace glob import is unsupported; use the explicit canonical path");
            }
            syn::UseTree::Name(import)
                if self.allowed.iter().any(|entry| {
                    entry.contains("::")
                        && entry.split("::").next()
                            == Some(import.ident.unraw().to_string().as_str())
                }) =>
            {
                self.reject(import.span(), "import may rebind an audited macro provider");
            }
            syn::UseTree::Name(import)
                if self
                    .derived_imports
                    .contains(&import.ident.unraw().to_string())
                    && !self.allowed.contains(&format!(
                        "{}{}",
                        prefix.iter().map(|p| format!("{p}::")).collect::<String>(),
                        import.ident.unraw()
                    )) =>
            {
                self.reject(
                    import.span(),
                    "import may rebind an audited derive macro; use its explicit provider",
                );
            }
            syn::UseTree::Name(import)
                if self.allowed.contains(&import.ident.unraw().to_string()) =>
            {
                self.reject(
                    import.span(),
                    "import may rebind an audited attribute macro",
                );
            }
            syn::UseTree::Name(import)
                if self.operation_name(&import.ident.unraw().to_string())
                    && syn::parse_str::<syn::ExprPath>(&format!(
                        "{}{}::{}",
                        if self.import_absolute { "::" } else { "" },
                        prefix.join("::"),
                        import.ident.unraw()
                    ))
                    .is_ok_and(|path| self.canonical_call(&path)) => {}
            syn::UseTree::Name(import)
                if self.operation_name(&import.ident.unraw().to_string())
                    || matches!(
                        import.ident.unraw().to_string().as_str(),
                        "env" | "process" | "std" | "core"
                    ) =>
            {
                self.reject(import.span(), "unqualified termination or environment import is unsupported; use the explicit canonical path");
            }
            syn::UseTree::Name(import) if import.ident.unraw() == "test" => {
                self.reject(import.span(), "import may rebind built-in test")
            }
            syn::UseTree::Glob(glob) if self.opaque => {
                self.reject(glob.span(), "glob import in macro input is unsupported")
            }
            _ => {}
        }
    }
    fn audited_arguments(&self, attribute: &str, stream: TokenStream) -> bool {
        fn tokens(stream: TokenStream, protected: &BTreeSet<String>, formatting: bool) -> bool {
            let values: Vec<_> = stream.into_iter().collect();
            for (i, token) in values.iter().enumerate() {
                match token {
                    TokenTree::Ident(id)
                        if protected.contains(&id.unraw().to_string())
                            && !(id.unraw() == "env"
                                && matches!(values.get(i+1), Some(TokenTree::Punct(p)) if p.as_char() == '=')) =>
                    {
                        return false;
                    }
                    TokenTree::Group(g) if g.delimiter() == Delimiter::Brace => return false,
                    TokenTree::Group(g) if g.delimiter() == Delimiter::Parenthesis => {
                        if !g.stream().is_empty()
                            || !formatting
                            || !matches!(values.get(i.wrapping_sub(1)), Some(TokenTree::Ident(id)) if matches!(id.unraw().to_string().as_str(), "get" | "as_secs" | "as_millis" | "display"))
                        {
                            return false;
                        }
                    }
                    TokenTree::Group(g) if !tokens(g.stream(), protected, formatting) => {
                        return false;
                    }
                    _ => {}
                }
            }
            true
        }
        tokens(stream, self.protected, attribute == "error")
    }
    fn source_literals(&mut self, stream: TokenStream) {
        for token in stream {
            match token {
                TokenTree::Group(group) => self.source_literals(group.stream()),
                TokenTree::Literal(literal) => {
                    if let Ok(value) = syn::parse2::<syn::LitStr>(literal.to_token_stream()) {
                        let target = super::authority_source::normalized_path(
                            &self.path.parent().unwrap_or(self.root).join(value.value()),
                        );
                        if target.starts_with(self.root.join("crates"))
                            && target.extension().is_some_and(|e| e == "rs")
                            && target.is_file()
                        {
                            self.reject(literal.span(), "unresolved source reference in macro input; use a literal built-in include or parsed mod");
                        }
                    }
                }
                _ => {}
            }
        }
    }
    fn tokens(&mut self, stream: TokenStream, source_literals: bool) {
        let tokens: Vec<_> = stream.into_iter().collect();
        let mut i = 0;
        while i < tokens.len() {
            if matches!(&tokens[i], TokenTree::Punct(p) if p.as_char() == '#') {
                let inner =
                    matches!(tokens.get(i+1), Some(TokenTree::Punct(p)) if p.as_char() == '!');
                let end = i + if inner { 3 } else { 2 };
                if matches!(tokens.get(end-1), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Bracket)
                {
                    if source_literals {
                        self.source_literals(tokens[i..end].iter().cloned().collect());
                    }
                    let stream = tokens[i..end].iter().cloned().collect();
                    let stream = doc_template(stream);
                    let attrs = if inner {
                        syn::Attribute::parse_inner.parse2(stream)
                    } else {
                        syn::Attribute::parse_outer.parse2(stream)
                    };
                    match attrs {
                        Ok(attrs) => {
                            for attr in &attrs {
                                self.visit_attribute(attr);
                            }
                        }
                        Err(_) => {
                            self.reject(tokens[i].span(), "unresolved attribute in macro input")
                        }
                    }
                    i = end;
                    continue;
                }
            }
            // Macro expansion can move a declaration into another module
            // directory, even when the input parses as literal Rust. Only
            // inline literal modules keep their complete body visible here.
            // External modules must be selected by parsed, non-macro Rust.
            if matches!(&tokens[i], TokenTree::Ident(id) if id.unraw() == "mod")
                && !(matches!(tokens.get(i + 1), Some(TokenTree::Ident(_)))
                    && matches!(tokens.get(i + 2), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace))
            {
                self.reject(tokens[i].span(), "module selection in macro input is unsupported; declare external modules in parsed Rust");
            }
            if matches!(&tokens[i], TokenTree::Ident(id) if id.unraw() == "extern")
                && matches!(tokens.get(i + 1), Some(TokenTree::Ident(id)) if id.unraw() == "crate")
            {
                self.reject(
                    tokens[i].span(),
                    "extern crate import in macro input is unresolved",
                );
            }
            if !matches!(i.checked_sub(1).and_then(|p| tokens.get(p)), Some(TokenTree::Ident(id)) if id.unraw() == "fn")
                && matches!(&tokens[i], TokenTree::Ident(id) if ambient_operation(&id.unraw().to_string()))
                && matches!(tokens.get(i + 1), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis)
                && !matches!(i.checked_sub(1).and_then(|p| tokens.get(p)), Some(TokenTree::Punct(p)) if matches!(p.as_char(), '.' | ':'))
            {
                self.reject(tokens[i].span(), "unresolved unqualified termination or environment call in macro input; use the explicit canonical path");
            }
            if matches!(&tokens[i], TokenTree::Ident(id) if id.unraw() == "use")
                && let Some(end) = tokens[i..]
                    .iter()
                    .position(|t| matches!(t, TokenTree::Punct(p) if p.as_char() == ';'))
            {
                let stream = tokens[i..=i + end].iter().cloned().collect();
                match syn::parse2::<syn::ItemUse>(stream) {
                    Ok(item) => self.visit_item_use(&item),
                    Err(_) => self.reject(tokens[i].span(), "unresolved import in macro input"),
                }
                i += end + 1;
                continue;
            }
            match &tokens[i] {
                TokenTree::Group(group) => self.tokens(group.stream(), source_literals),
                TokenTree::Literal(literal) if source_literals => {
                    if let Ok(value) = syn::parse2::<syn::LitStr>(literal.to_token_stream()) {
                        let target = super::authority_source::normalized_path(
                            &self.path.parent().unwrap_or(self.root).join(value.value()),
                        );
                        if target.starts_with(self.root.join("crates"))
                            && target.extension().is_some_and(|e| e == "rs")
                            && target.is_file()
                        {
                            self.reject(literal.span(), "unresolved source reference in macro input; use a literal built-in include or parsed mod");
                        }
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }
}
impl<'ast> Visit<'ast> for Validator<'_> {
    fn visit_file(&mut self, file: &'ast syn::File) {
        if file.attrs.iter().any(|attr| {
            super::authority_source::path_is_ident(attr.path(), "cfg")
                && super::authority_source::cfg_false(&attr.meta)
        }) {
            return;
        }
        let previous_imports = self.item_imports.clone();
        self.item_imports.extend(item_imports(file));
        visit::visit_file(self, file);
        self.item_imports = previous_imports;
    }
    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        let previous_imports = self.item_imports.clone();
        if let Some((_, items)) = &module.content {
            self.item_imports.extend(item_imports(&syn::File {
                shebang: None,
                attrs: Vec::new(),
                items: items.clone(),
            }));
        }

        if module.ident.unraw() == "std" {
            self.reject(
                module.span(),
                "module may rebind a built-in standard namespace",
            );
        }

        if self.allowed.iter().any(|entry| {
            entry.contains("::")
                && entry.split("::").next() == Some(module.ident.unraw().to_string().as_str())
        }) || self.macro_audits.iter().any(|a| {
            a.names.iter().any(|name| {
                name.contains("::")
                    && !matches!(name.split("::").next(), Some("core" | "std" | "alloc"))
                    && name.split("::").next() == Some(module.ident.unraw().to_string().as_str())
            })
        }) {
            self.reject(module.span(), "module may rebind an audited macro provider");
        }

        if module
            .attrs
            .iter()
            .filter(|a| super::authority_source::path_is_ident(a.path(), "path"))
            .count()
            > 1
        {
            self.reject(module.span(), "multiple module paths are unsupported");
        }
        visit::visit_item_mod(self, module);
        self.item_imports = previous_imports;
    }

    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attrs = match item {
            syn::Item::Mod(i) => &i.attrs,
            syn::Item::Fn(i) => &i.attrs,
            syn::Item::Impl(i) => &i.attrs,
            syn::Item::Trait(i) => &i.attrs,
            syn::Item::Macro(i) => &i.attrs,
            syn::Item::Static(i) => &i.attrs,
            syn::Item::Const(i) => &i.attrs,
            syn::Item::Struct(i) => &i.attrs,
            syn::Item::Enum(i) => &i.attrs,
            syn::Item::Union(i) => &i.attrs,
            syn::Item::Type(i) => &i.attrs,
            _ => return visit::visit_item(self, item),
        };
        let previous = self.proven_test;
        let builtin_test = matches!(item, syn::Item::Fn(_))
            && attrs
                .iter()
                .any(|a| super::authority_source::path_is_ident(a.path(), "test"));
        let cfg_excluded = attrs.iter().any(|a| {
            super::authority_source::path_is_ident(a.path(), "cfg")
                && super::authority_source::cfg_false(&a.meta)
        });
        if !self.opaque && !previous && !cfg_excluded && builtin_test && self.glob.is_some() {
            self.reject(item.span(), "glob import makes test exclusion ambiguous");
        }
        self.proven_test |= !self.opaque
            && (builtin_test
                || attrs.iter().any(|a| {
                    super::authority_source::path_is_ident(a.path(), "cfg")
                        && super::authority_source::cfg_false(&a.meta)
                }));
        let previous_owners = self.metadata_owners.clone();
        let ancestor = match item {
            syn::Item::Mod(i) => Some(i.ident.unraw().to_string()),
            syn::Item::Fn(i) => Some(i.sig.ident.unraw().to_string()),
            syn::Item::Impl(i) => Some(super::authority_source::implementation_name(i)),
            syn::Item::Trait(i) => Some(i.ident.unraw().to_string()),
            syn::Item::Const(i) => Some(i.ident.unraw().to_string()),
            syn::Item::Static(i) => Some(i.ident.unraw().to_string()),
            syn::Item::Struct(i) => Some(i.ident.unraw().to_string()),
            syn::Item::Enum(i) => Some(i.ident.unraw().to_string()),
            syn::Item::Union(i) => Some(i.ident.unraw().to_string()),
            syn::Item::Type(i) => Some(i.ident.unraw().to_string()),
            _ => None,
        };
        if let Some(ancestor) = &ancestor {
            self.lexical_owners.push(ancestor.clone());
        }
        if matches!(
            item,
            syn::Item::Struct(_) | syn::Item::Enum(_) | syn::Item::Union(_)
        ) {
            self.metadata_owners = self
                .module_owners
                .iter()
                .map(|module| {
                    let mut full = module.clone();
                    full.extend(self.lexical_owners.clone());
                    full.join("::")
                })
                .collect();
        }
        let previous_helpers = std::mem::take(&mut self.helpers);
        for attr in attrs {
            if name(attr.path()) != "derive" {
                continue;
            }
            let syn::Meta::List(list) = &attr.meta else {
                continue;
            };
            let Ok(paths) =
                syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated
                    .parse2(list.tokens.clone())
            else {
                continue;
            };
            for path in paths {
                let derive = name(&path);
                if self.glob.is_some() && path.leading_colon.is_none() {
                    continue;
                }
                let provider = if self.allowed.contains(&derive) {
                    Some(derive)
                } else {
                    None
                };
                let helpers: &[&str] = match provider.as_deref() {
                    Some("serde::Serialize" | "serde::Deserialize") => &["serde"],
                    Some("thiserror::Error") => &["error", "from", "source"],
                    Some("clap::Args" | "clap::Parser" | "clap::Subcommand") => {
                        &["arg", "command", "clap"]
                    }
                    Some("clap::ValueEnum") => &["value", "clap"],
                    _ => &[],
                };
                self.helpers.extend(helpers.iter().map(|h| (*h).to_owned()));
            }
        }
        if !self.proven_test {
            visit::visit_item(self, item);
        }
        if ancestor.is_some() {
            self.lexical_owners.pop();
        }
        self.metadata_owners = previous_owners;
        self.helpers = previous_helpers;
        self.proven_test = previous;
    }
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let previous = std::mem::take(&mut self.local_bindings);
        visit::visit_item_fn(self, item);
        self.local_bindings = previous;
    }
    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        let previous = std::mem::take(&mut self.local_bindings);
        self.lexical_owners.push(item.sig.ident.unraw().to_string());
        visit::visit_impl_item_fn(self, item);
        self.local_bindings = previous;
        self.lexical_owners.pop();
    }
    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        let previous = std::mem::take(&mut self.local_bindings);
        self.lexical_owners.push(item.sig.ident.unraw().to_string());
        visit::visit_trait_item_fn(self, item);
        self.local_bindings = previous;
        self.lexical_owners.pop();
    }
    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        let attribute = name(attr.path());
        if self.opaque && attribute == "macro_use" {
            self.reject(attr.span(), "macro_use import is unresolved in macro input");
        }
        if self.allowed.contains(&attribute)
            && self.glob.is_some()
            && attr.path().leading_colon.is_none()
            && !self.helpers.contains(&attribute)
        {
            self.reject(
                attr.span(),
                "glob import makes audited macro binding ambiguous",
            );
        }
        if matches!(
            attribute.as_str(),
            "error" | "arg" | "serde" | "from" | "source" | "command" | "value" | "clap"
        ) && (self.opaque || !self.helpers.contains(&attribute))
        {
            self.reject(
                attr.span(),
                "unresolved derive helper; require a matching audited derive on the parsed item",
            );
        }
        let builtin = matches!(
            attribute.as_str(),
            "expect"
                | "no_std"
                | "no_main"
                | "allow"
                | "deny"
                | "warn"
                | "forbid"
                | "cfg"
                | "cfg_attr"
                | "test"
                | "should_panic"
                | "ignore"
                | "path"
                | "doc"
                | "derive"
                | "inline"
                | "cold"
                | "must_use"
                | "non_exhaustive"
                | "repr"
                | "track_caller"
                | "deprecated"
                | "no_mangle"
                | "export_name"
                | "link_section"
                | "link"
                | "link_name"
                | "unsafe"
                | "global_allocator"
                | "panic_handler"
                | "alloc_error_handler"
                | "macro_export"
                | "macro_use"
                | "used"
                | "default"
                | "rustfmt::skip"
        );
        if !builtin && !self.allowed.contains(&attribute) {
            self.reject(
                attr.span(),
                format!("unaudited attribute macro {attribute}"),
            );
        }

        if attr
            .path()
            .segments
            .last()
            .is_some_and(|s| s.ident.unraw() == "test")
        {
            if attribute != "test" {
                self.reject(attr.span(), "qualified test attribute is unsupported");
            } else if !self.proven_test && self.glob.is_some() {
                self.reject(attr.span(), "glob import makes test exclusion ambiguous");
            }
        }
        if self.opaque && super::authority_source::test_only(std::slice::from_ref(attr)) {
            self.reject(attr.span(), "test exclusion in macro input is unsupported");
        }
        if attribute == "path" {
            if self.opaque {
                self.reject(attr.span(), "module path in macro input is unsupported");
            }
            if !matches!(&attr.meta, syn::Meta::NameValue(nv) if matches!(&nv.value, syn::Expr::Lit(lit) if matches!(lit.lit, syn::Lit::Str(_))))
            {
                self.reject(attr.span(), "module path requires a literal string");
            }
        }
        if let syn::Meta::NameValue(nv) = &attr.meta
            && !matches!(nv.value, syn::Expr::Lit(_))
            && attribute != "doc"
        {
            self.reject(
                attr.span(),
                format!("unaudited attribute arguments for {attribute}"),
            );
        }
        if attribute == "doc"
            && let syn::Meta::NameValue(nv) = &attr.meta
            && let syn::Expr::Macro(expr) = &nv.value
        {
            self.visit_macro(&expr.mac);
        }
        if let syn::Meta::List(list) = &attr.meta {
            if attribute == "derive" {
                if let Ok(paths) =
                    syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated
                        .parse2(list.tokens.clone())
                {
                    for path in paths {
                        let derive = name(&path);
                        if self.glob.is_some()
                            && path.leading_colon.is_none()
                            && (self.allowed.contains(&derive)
                                || self.derived_imports.contains(&derive)
                                || compiler_derive(&derive))
                        {
                            self.reject(
                                path.span(),
                                "glob import makes audited macro binding ambiguous",
                            );
                        }
                        if !compiler_derive_path(&path) && !self.allowed.contains(&derive) {
                            self.reject(path.span(), format!("unaudited derive macro {derive}; audited macro binding requires its canonical crate path"));
                        }
                    }
                } else {
                    self.reject(attr.span(), "unresolved derive macro arguments");
                }
            }

            if self.allowed.contains(&attribute)
                && let Ok(children) =
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
                        .parse2(list.tokens.clone())
            {
                for meta in children {
                    if let Some(options) = self.generated_options.get(&attribute) {
                        for option in options {
                            if name(meta.path()) != option.option {
                                continue;
                            }
                            let value = match &meta {
                                syn::Meta::NameValue(nv) => match &nv.value {
                                    syn::Expr::Lit(expr) => match &expr.lit {
                                        syn::Lit::Str(s) => Some(s.value()),
                                        _ => None,
                                    },
                                    _ => None,
                                },
                                _ => None,
                            };
                            let permitted = value.is_some_and(|v| {
                                if self.check_metadata_owner {
                                    !self.metadata_owners.is_empty()
                                        && self.metadata_owners.iter().all(|owner| {
                                            option
                                                .permitted_owners
                                                .get(owner)
                                                .is_some_and(|values| values.contains(&v))
                                        })
                                } else {
                                    option
                                        .permitted_owners
                                        .values()
                                        .any(|values| values.contains(&v))
                                }
                            });
                            if !permitted {
                                self.reject(
                                    meta.span(),
                                    format!(
                                        "generated {} is outside its audited owner/value boundary",
                                        option.operation.description()
                                    ),
                                );
                            }
                        }
                    }
                    if let syn::Meta::NameValue(nv) = meta
                        && matches!(
                            name(&nv.path).as_str(),
                            "default"
                                | "serialize_with"
                                | "deserialize_with"
                                | "with"
                                | "from"
                                | "try_from"
                                | "into"
                        )
                        && let syn::Expr::Lit(expr) = nv.value
                        && let syn::Lit::Str(value) = expr.lit
                        && let Ok(path) = syn::parse_str::<syn::Path>(&value.value())
                        && path
                            .segments
                            .iter()
                            .any(|s| self.protected.contains(&s.ident.unraw().to_string()))
                    {
                        self.reject(
                            value.span(),
                            "protected callback in audited attribute metadata",
                        );
                    }
                }
            }

            if attribute == "cfg_attr" {
                let Ok(children) =
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
                        .parse2(list.tokens.clone())
                else {
                    self.reject(attr.span(), "unresolved conditional attribute");
                    return;
                };
                // The condition itself may mention test; only selected attributes
                // are forbidden from supplying test exclusion or source paths.
                for meta in children.iter().skip(1) {
                    let selected = name(meta.path());
                    if selected == "path" {
                        self.reject(attr.span(), "conditional module path is unsupported");
                    }
                    if selected == "test"
                        || (selected == "cfg" && super::authority_source::cfg_false(meta))
                        || selected.ends_with("::test")
                    {
                        self.reject(attr.span(), "conditional test attribute is unsupported");
                    }
                    let mut selected_attr = attr.clone();
                    selected_attr.meta = meta.clone();
                    self.visit_attribute(&selected_attr);
                }
            } else if !(metadata(list.tokens.clone())
                || self.allowed.contains(&attribute)
                    && self.audited_arguments(&attribute, list.tokens.clone()))
            {
                self.reject(attr.span(), format!("unaudited attribute arguments for {attribute}; rewrite as literal metadata or audit authority-attribute-allowlist.json"));
            }
            let previous = self.opaque;
            self.opaque = true;
            // Detect DSL attribute tokens without trusting a Rust parse.
            self.tokens(list.tokens.clone(), attribute != "cfg_attr");
            self.opaque = previous;
        }
    }
    fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
        self.local_bindings
            .insert(pattern.ident.unraw().to_string());
        visit::visit_pat_ident(self, pattern);
    }
    fn visit_local(&mut self, local: &'ast syn::Local) {
        for attribute in &local.attrs {
            self.visit_attribute(attribute);
        }
        if let Some(initializer) = &local.init {
            self.visit_expr(&initializer.expr);
            if let Some((_, diverge)) = &initializer.diverge {
                self.visit_expr(diverge);
            }
        }
        self.visit_pat(&local.pat);
    }
    fn visit_block(&mut self, block: &'ast syn::Block) {
        let previous = self.local_bindings.clone();
        let previous_imports = self.item_imports.clone();
        let items = block
            .stmts
            .iter()
            .filter_map(|s| match s {
                syn::Stmt::Item(item) => Some(item.clone()),
                _ => None,
            })
            .collect();
        let imports = item_imports(&syn::File {
            shebang: None,
            attrs: Vec::new(),
            items,
        });
        for name in imports.keys() {
            self.local_bindings.remove(name);
        }
        for statement in &block.stmts {
            if let syn::Stmt::Item(syn::Item::Fn(function)) = statement {
                self.local_bindings
                    .remove(&function.sig.ident.unraw().to_string());
            }
        }
        self.item_imports.extend(imports);
        visit::visit_block(self, block);
        self.local_bindings = previous;
        self.item_imports = previous_imports;
    }
    fn visit_expr_let(&mut self, expression: &'ast syn::ExprLet) {
        self.visit_expr(&expression.expr);
        self.visit_pat(&expression.pat);
    }
    fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
        let previous = self.local_bindings.clone();
        self.visit_expr(&expression.expr);
        self.visit_pat(&expression.pat);
        self.visit_block(&expression.body);
        self.local_bindings = previous;
    }
    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        let previous = self.local_bindings.clone();
        self.visit_expr(&expression.cond);
        self.visit_block(&expression.then_branch);
        self.local_bindings = previous;
        if let Some((_, branch)) = &expression.else_branch {
            self.visit_expr(branch);
        }
    }
    fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
        let previous = self.local_bindings.clone();
        self.visit_expr(&expression.cond);
        self.visit_block(&expression.body);
        self.local_bindings = previous;
    }
    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        let previous = self.local_bindings.clone();
        visit::visit_arm(self, arm);
        self.local_bindings = previous;
    }
    fn visit_expr_closure(&mut self, expression: &'ast syn::ExprClosure) {
        let previous = self.local_bindings.clone();
        visit::visit_expr_closure(self, expression);
        self.local_bindings = previous;
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if self.raw_methods.contains(&call.method.unraw().to_string()) && call.turbofish.is_some() {
            self.reject(
                call.span(),
                "protected operation shape: receiver call generic arguments are unsupported",
            );
        }
        visit::visit_expr_method_call(self, call);
    }
    fn visit_expr(&mut self, expr: &'ast syn::Expr) {
        if self.opaque || !super::authority_source::expression_test_only(expr) {
            visit::visit_expr(self, expr);
        }
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref()
            && self.protected_operation(&path.path)
            && !(path.path.segments.len() == 1
                && path
                    .path
                    .segments
                    .first()
                    .is_some_and(|s| self.local_bindings.contains(&s.ident.unraw().to_string())))
        {
            if !self.canonical_call(path) {
                self.reject(call.func.span(), "protected operation shape requires a direct canonical path without generic arguments");
            } else if path.path.segments.len() == 1 {
                let range = path.span().byte_range();
                self.canonical_calls.push(CanonicalCall {
                    start: range.start,
                    end: range.end,
                    path: self.item_imports[&name(&path.path)]
                        .trim_start_matches("::")
                        .to_owned(),
                });
            }
            // The callee is the only position in which a protected path is
            // callable. Arguments and generic expressions are ordinary values.
            for argument in &call.args {
                self.visit_expr(argument);
            }
            return;
        }
        visit::visit_expr_call(self, call);
    }
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if self.protected_operation(&path.path)
            && !(path.path.segments.len() == 1
                && path
                    .path
                    .segments
                    .first()
                    .is_some_and(|s| self.local_bindings.contains(&s.ident.unraw().to_string())))
        {
            self.reject(path.span(), "protected operation shape: function/method values are unsupported; use a direct canonical path call");
        }
        visit::visit_expr_path(self, path);
    }
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let previous = self.import_absolute;
        self.import_absolute = item.leading_colon.is_some();
        self.imports(&item.tree, &[]);
        if !matches!(item.vis, syn::Visibility::Inherited) {
            fn leaves(tree: &syn::UseTree, names: &mut Vec<String>) {
                match tree {
                    syn::UseTree::Name(n) => names.push(n.ident.unraw().to_string()),
                    syn::UseTree::Rename(n) => names.push(n.ident.unraw().to_string()),
                    syn::UseTree::Path(p) => leaves(&p.tree, names),
                    syn::UseTree::Group(g) => {
                        for tree in &g.items {
                            leaves(tree, names);
                        }
                    }
                    _ => {}
                }
            }
            let mut names = Vec::new();
            leaves(&item.tree, &mut names);
            if names.iter().any(|n| self.operation_name(n)) {
                self.reject(
                    item.span(),
                    "protected operation shape: re-export is unsupported",
                );
            }
        }
        self.import_absolute = previous;
    }
    fn visit_item_extern_crate(&mut self, item: &'ast syn::ItemExternCrate) {
        fn macro_use(meta: &syn::Meta) -> bool {
            if name(meta.path()) == "macro_use" {
                return true;
            }
            if name(meta.path()) != "cfg_attr" {
                return false;
            }
            let syn::Meta::List(list) = meta else {
                return false;
            };
            syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
                .parse2(list.tokens.clone())
                .is_ok_and(|children| children.iter().skip(1).any(macro_use))
        }
        if item.attrs.iter().any(|a| macro_use(&a.meta)) {
            self.reject(
                item.span(),
                "macro_use import is unresolved; use explicit audited bindings",
            );
        }
        if item.rename.as_ref().is_some_and(|(_, alias)| {
            compiler_derive(&alias.unraw().to_string()) || alias.unraw() == "test"
        }) {
            self.reject(
                item.span(),
                "extern crate alias may rebind a built-in macro",
            );
        }
        visit::visit_item_extern_crate(self, item);
        if let Some((_, alias)) = &item.rename
            && (self.protected.contains(&alias.unraw().to_string())
                || self.allowed.iter().any(|name| {
                    name.split("::").next() == Some(alias.unraw().to_string().as_str())
                })
                || self.macro_audits.iter().any(|audit| {
                    audit.names.iter().any(|name| {
                        name.contains("::")
                            && name.split("::").next() == Some(alias.unraw().to_string().as_str())
                    })
                }))
        {
            self.reject(
                item.span(),
                "extern crate alias may rebind a protected provider",
            );
        }
    }
    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if let Some(id) = &item.ident
            && let Some(audit) = self
                .macro_audits
                .iter()
                .find(|a| a.names.contains(&id.unraw().to_string()))
            && !(audit
                .definition_file
                .as_ref()
                .is_some_and(|file| self.root.join(file) == self.path)
                && std::fs::read(self.path).is_ok_and(|bytes| {
                    bytes.get(item.span().byte_range()).is_some_and(|body| {
                        audit
                            .definition_sha256
                            .as_ref()
                            .is_some_and(|hash| super::authority_source::source_hash(body) == *hash)
                    })
                }))
        {
            self.reject(
                item.span(),
                "audited macro binding definition is unresolved",
            );
        }

        if item.ident.as_ref().is_some_and(|id| {
            matches!(
                id.unraw().to_string().as_str(),
                "include" | "include_str" | "include_bytes" | "test"
            ) || compiler_derive(&id.unraw().to_string())
                || self.allowed.contains(&id.unraw().to_string())
        }) {
            self.reject(
                item.span(),
                "macro may rebind a built-in or audited attribute name",
            );
        }
        if item.ident.is_none() {
            self.visit_macro(&item.mac);
        } else {
            // Definitions are opaque; the existing census also rejects any
            // operation vocabulary generated without a compiler-resolved owner.
            let previous = self.opaque;
            self.opaque = true;
            self.tokens(item.mac.tokens.clone(), true);
            if self.has_protected_tokens(item.mac.tokens.clone()) {
                self.reject(
                    item.span(),
                    "protected operation shape in an opaque macro definition",
                );
            }
            self.opaque = previous;
        }
    }
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if name(&mac.path).starts_with("core::include") && mac.path.leading_colon.is_none() {
            self.reject(
                mac.span(),
                "unresolved core inclusion namespace; use ::core::include or the built-in spelling",
            );
        }
        let builtin = matches!(
            name(&mac.path).as_str(),
            "include"
                | "std::include"
                | "core::include"
                | "include_str"
                | "std::include_str"
                | "core::include_str"
                | "include_bytes"
                | "std::include_bytes"
                | "core::include_bytes"
        );
        if builtin
            && !name(&mac.path).ends_with("include_bytes")
            && syn::punctuated::Punctuated::<syn::LitStr, syn::Token![,]>::parse_terminated
                .parse2(mac.tokens.clone())
                .is_err()
        {
            self.reject(mac.span(), "nonliteral source inclusion");
        }
        let previous = self.opaque;
        self.opaque = true;
        self.tokens(mac.tokens.clone(), !builtin);
        let spelling = name(&mac.path);
        let audit = self.macro_audits.iter().find(|a| {
            a.names.contains(&spelling)
                && (a.definition_file.is_some()
                    || (mac.path.leading_colon.is_some() && spelling.contains("::")))
        });
        let protected_input = self.has_protected_tokens(mac.tokens.clone());
        if let Some(audit) = audit.filter(|_| protected_input) {
            let definition_valid = self.valid_definitions[&audit.names[0]];
            if !definition_valid {
                self.reject(
                    mac.span(),
                    "audited macro binding has a missing or changed definition",
                );
            } else if self.glob.is_some()
                && mac.path.segments.len() == 1
                && audit.definition_file.is_none()
            {
                self.reject(
                    mac.span(),
                    "audited macro binding is ambiguous under a glob; qualify the provider",
                );
            } else {
                match audit.parse(mac.tokens.clone()) {
                    Ok(input) => input.visit(self),
                    Err(_) if self.has_protected_tokens(mac.tokens.clone()) => self.reject(
                        mac.span(),
                        "protected operation shape in unparsed audited macro input",
                    ),
                    Err(_) => {}
                }
            }
        } else if protected_input {
            self.reject(
                mac.span(),
                "protected operation shape in non-allowlisted or opaque macro input",
            );
        }
        self.opaque = previous;
    }
}
