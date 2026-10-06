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

pub(super) fn validate(
    root: &Path,
    parsed: &BTreeMap<PathBuf, syn::File>,
    operations: &BTreeSet<String>,
    test_files: &BTreeSet<PathBuf>,
    production: &BTreeSet<PathBuf>,
) -> Result<(), DebtError> {
    let audits: Vec<AttributeAudit> = serde_json::from_str(include_str!(
        "../../../scripts/migrate/authority-attribute-allowlist.json"
    ))?;
    let mut allowed = BTreeSet::new();
    for entry in audits {
        if entry.reason.trim().is_empty() || !allowed.insert(entry.name.clone()) {
            return Err(DebtError::Policy(format!(
                "invalid attribute audit: {}",
                entry.name
            )));
        }
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
    let mut errors = Vec::new();
    for (path, syntax) in parsed {
        if test_files.contains(path) && !production.contains(path) {
            continue;
        }
        let mut validator = Validator {
            root,
            path,
            allowed: &allowed,
            protected: &protected,
            errors: &mut errors,
            proven_test: false,
            opaque: false,
            glob: None,
            derived_imports: derive_imports(syntax, &allowed),
            helpers: BTreeSet::new(),
        };
        // The source file's outer imports affect all descendant attributes.
        // A glob inside a proven cfg(test) module cannot affect its parent.
        validator.glob = production_glob(syntax);
        validator.visit_file(syntax);
    }
    if errors.is_empty() {
        Ok(())
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
    protected: &'a BTreeSet<String>,
    errors: &'a mut Vec<String>,
    proven_test: bool,
    opaque: bool,
    glob: Option<Span>,
    derived_imports: BTreeSet<String>,
    helpers: BTreeSet<String>,
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
    fn imports(&mut self, tree: &syn::UseTree, prefix: &[String]) {
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
                if matches!(
                    import.ident.unraw().to_string().as_str(),
                    "abort" | "exit" | "env" | "process" | "std"
                ) || (prefix.iter().any(|p| p == "env")
                    && self.protected.contains(&import.ident.unraw().to_string())) =>
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
            if matches!(&tokens[i], TokenTree::Ident(id) if id.unraw() == "use")
                && let Some(end) = tokens[i..]
                    .iter()
                    .position(|t| matches!(t, TokenTree::Punct(p) if p.as_char() == ';'))
            {
                let stream = tokens[i..=i + end].iter().cloned().collect();
                match syn::parse2::<syn::ItemUse>(stream) {
                    Ok(item) => self.imports(&item.tree, &[]),
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
        visit::visit_file(self, file);
    }
    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        if module.ident.unraw() == "std" {
            self.reject(
                module.span(),
                "module may rebind the built-in std namespace",
            );
        }

        if self.allowed.iter().any(|entry| {
            entry.contains("::")
                && entry.split("::").next() == Some(module.ident.unraw().to_string().as_str())
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
            _ => return visit::visit_item(self, item),
        };
        let previous = self.proven_test;
        self.proven_test |= !self.opaque
            && attrs.iter().any(|a| {
                super::authority_source::path_is_ident(a.path(), "cfg")
                    && super::authority_source::cfg_false(&a.meta)
            });
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
                } else if self.derived_imports.contains(&derive) {
                    self.allowed
                        .iter()
                        .find(|n| n.rsplit("::").next() == Some(derive.as_str()))
                        .cloned()
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
        self.helpers = previous_helpers;
        self.proven_test = previous;
    }
    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        let attribute = name(attr.path());
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
                                || self.derived_imports.contains(&derive))
                        {
                            self.reject(
                                path.span(),
                                "glob import makes audited macro binding ambiguous",
                            );
                        }
                        if !matches!(
                            derive.as_str(),
                            "Clone"
                                | "Copy"
                                | "Debug"
                                | "Default"
                                | "Eq"
                                | "PartialEq"
                                | "Ord"
                                | "PartialOrd"
                                | "Hash"
                        ) && !self.allowed.contains(&derive)
                            && !self.derived_imports.contains(&derive)
                        {
                            self.reject(path.span(), format!("unaudited derive macro {derive}; use an explicitly audited provider"));
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
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.imports(&item.tree, &[]);
    }
    fn visit_item_extern_crate(&mut self, item: &'ast syn::ItemExternCrate) {
        if let Some((_, alias)) = &item.rename
            && (self.protected.contains(&alias.unraw().to_string())
                || self.allowed.iter().any(|name| {
                    name.split("::").next() == Some(alias.unraw().to_string().as_str())
                }))
        {
            self.reject(
                item.span(),
                "extern crate alias may rebind a protected provider",
            );
        }
    }
    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if item.ident.as_ref().is_some_and(|id| {
            matches!(
                id.unraw().to_string().as_str(),
                "include" | "include_str" | "include_bytes" | "test"
            ) || self.allowed.contains(&id.unraw().to_string())
        }) {
            self.reject(
                item.span(),
                "macro may rebind a built-in or audited attribute name",
            );
        }
        visit::visit_item_macro(self, item);
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
        self.opaque = previous;
    }
}
