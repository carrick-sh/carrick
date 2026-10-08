//! Syntax-resolved production owners and legacy authority API calls.
//! Locations only bind ephemeral diagnostics to symbols; they are never saved.
use crate::authority_debt::{DebtError, Lane};
use proc_macro2::{Delimiter, LineColumn, Span, TokenStream, TokenTree};
use quote::ToTokens;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::{
    ext::IdentExt,
    parse::Parser,
    spanned::Spanned,
    visit::{self, Visit},
};

pub(super) fn path_is_ident(path: &syn::Path, expected: &str) -> bool {
    path.get_ident()
        .is_some_and(|ident| ident.unraw() == expected)
}

// Token formatting also participates in type and owner identity. Keep literal
// contents and source spans intact while canonicalizing identifier spellings.
fn semantic_tokens(value: &impl ToTokens) -> String {
    fn normalize(tokens: TokenStream) -> TokenStream {
        tokens
            .into_iter()
            .map(|token| match token {
                TokenTree::Ident(ident) => TokenTree::Ident(ident.unraw()),
                TokenTree::Group(group) => {
                    let mut normalized =
                        proc_macro2::Group::new(group.delimiter(), normalize(group.stream()));
                    normalized.set_span(group.span());
                    TokenTree::Group(normalized)
                }
                token => token,
            })
            .collect()
    }
    normalize(value.to_token_stream()).to_string()
}

// Attributes in macro inputs describe tokens, not compiler-enforced scope:
// a macro may remove or rewrite them. No visitor may derive test exclusion
// from such attributes, even when the rest of the input parses as Rust.
fn macro_input_tokens(tokens: TokenStream) -> TokenStream {
    let tokens: Vec<_> = tokens.into_iter().collect();
    let mut result = TokenStream::new();
    let mut index = 0;
    while index < tokens.len() {
        if matches!(&tokens[index], TokenTree::Punct(p) if p.as_char() == '#') {
            let inner =
                matches!(tokens.get(index + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!');
            let end = index + if inner { 3 } else { 2 };
            if matches!(tokens.get(end - 1), Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Bracket)
            {
                let attribute = tokens[index..end].iter().cloned().collect();
                let parsed = if inner {
                    syn::Attribute::parse_inner.parse2(attribute)
                } else {
                    syn::Attribute::parse_outer.parse2(attribute)
                };
                if parsed.is_ok_and(|attrs| test_only(&attrs)) {
                    index = end;
                    continue;
                }
            }
        }
        result.extend(std::iter::once(match &tokens[index] {
            TokenTree::Group(group) => {
                let mut normalized =
                    proc_macro2::Group::new(group.delimiter(), macro_input_tokens(group.stream()));
                normalized.set_span(group.span());
                TokenTree::Group(normalized)
            }
            token => token.clone(),
        }));
        index += 1;
    }
    result
}

#[derive(Debug)]
pub struct ApiSite {
    pub file: String,
    pub line: usize,
    pub owner: String,
    pub operation: String,
    pub lane: Lane,
}
#[derive(Debug)]
struct Owner {
    name: String,
    lane: Lane,
    start: LineColumn,
    end: LineColumn,
}
#[derive(Debug, Default)]
pub struct SourceCensus {
    build_roots: Vec<super::authority_build::BuildRoot>,
    build_files: BTreeSet<String>,
    source_hashes: BTreeMap<String, String>,
    classifications: BTreeMap<String, Vec<ItemClassification>>,
    canonical_calls: BTreeMap<String, Vec<super::authority_dialect::CanonicalCall>>,
    test_files: std::collections::BTreeSet<String>,
    non_product_files: BTreeSet<String>,
    unbound_files: std::collections::BTreeSet<String>,
    owners: BTreeMap<String, Vec<Owner>>,
    pub k1: Vec<ApiSite>,
    inherent_methods: BTreeMap<String, BTreeSet<String>>,
    unknown_apis: Vec<String>,
    structural_errors: Vec<String>,
    test_ranges: BTreeMap<String, Vec<(LineColumn, LineColumn)>>,
    aliases: BTreeMap<String, Vec<syn::Type>>,
    projections: BTreeMap<String, BTreeSet<String>>,
    vocabulary: BTreeMap<String, AuthorityOperation>,
}
#[derive(Debug, serde::Serialize)]
struct ItemClassification {
    start: usize,
    end: usize,
    production: bool,
}

// A single parsed scope classifier supplies every retained scanner. Opaque
// macro tokens can never establish exclusion (the dialect rejects that syntax).
#[derive(Default)]
struct Classifications(Vec<ItemClassification>);
impl Classifications {
    fn record(&mut self, span: Span, production: bool) {
        let range = span.byte_range();
        self.0.push(ItemClassification {
            start: range.start,
            end: range.end,
            production,
        });
    }
}
impl<'ast> Visit<'ast> for Classifications {
    fn visit_file(&mut self, file: &'ast syn::File) {
        if test_only(&file.attrs) {
            self.record(file.span(), false);
        } else {
            visit::visit_file(self, file);
        }
    }
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attrs: &[syn::Attribute] = match item {
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
            _ => &[],
        };
        let production = !test_only(attrs);
        self.record(item.span(), production);
        if production {
            visit::visit_item(self, item);
        }
    }
    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attrs: &[syn::Attribute] = match item {
            syn::ImplItem::Const(i) => &i.attrs,
            syn::ImplItem::Fn(i) => &i.attrs,
            syn::ImplItem::Type(i) => &i.attrs,
            syn::ImplItem::Macro(i) => &i.attrs,
            _ => &[],
        };
        let production = !test_only(attrs);
        self.record(item.span(), production);
        if production {
            visit::visit_impl_item(self, item);
        }
    }
    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let attrs: &[syn::Attribute] = match item {
            syn::TraitItem::Const(i) => &i.attrs,
            syn::TraitItem::Fn(i) => &i.attrs,
            syn::TraitItem::Type(i) => &i.attrs,
            syn::TraitItem::Macro(i) => &i.attrs,
            _ => &[],
        };
        let production = !test_only(attrs);
        self.record(item.span(), production);
        if production {
            visit::visit_trait_item(self, item);
        }
    }
    fn visit_expr(&mut self, expr: &'ast syn::Expr) {
        if expression_test_only(expr) {
            self.record(expr.span(), false);
        } else {
            visit::visit_expr(self, expr);
        }
    }
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if test_only(&local.attrs) {
            self.record(local.span(), false);
        } else {
            visit::visit_local(self, local);
        }
    }
    fn visit_field_value(&mut self, field: &'ast syn::FieldValue) {
        if test_only(&field.attrs) {
            self.record(field.span(), false);
        } else {
            visit::visit_field_value(self, field);
        }
    }
    fn visit_field(&mut self, field: &'ast syn::Field) {
        if test_only(&field.attrs) {
            self.record(field.span(), false);
        } else {
            visit::visit_field(self, field);
        }
    }
    fn visit_variant(&mut self, variant: &'ast syn::Variant) {
        if test_only(&variant.attrs) {
            self.record(variant.span(), false);
        } else {
            visit::visit_variant(self, variant);
        }
    }
    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        if test_only(&arm.attrs) {
            self.record(arm.span(), false);
        } else {
            visit::visit_arm(self, arm);
        }
    }
}

pub(super) fn source_hash(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuthorityOperation {
    K1,
    DescriptionIo,
    DescriptionGuard,
    FileLifecycle,
    Task,
    RawLock,
    SourceInclude,
    SourceStringInclude,
}
fn authority_vocabulary() -> Result<BTreeMap<String, AuthorityOperation>, DebtError> {
    let groups: BTreeMap<AuthorityOperation, Vec<String>> = serde_json::from_str(include_str!(
        "../../../scripts/migrate/authority-vocabulary.json"
    ))?;
    let mut vocabulary = BTreeMap::new();
    for (kind, operations) in groups {
        for operation in operations {
            if vocabulary.insert(operation.clone(), kind).is_some() {
                return Err(DebtError::Policy(format!(
                    "duplicate authority operation: {operation}"
                )));
            }
        }
    }
    Ok(vocabulary)
}

// These are semantic API boundaries: bodies and source locations are not part
// of the exemption. A trait implementation, another module, wider visibility,
// or a different returned capability must receive its own reviewed boundary.
const TABLE_GUARD_BOUNDARIES: &[(&str, &str)] = &[
    (
        "carrick_kernel::kernel::objects::FileTable::read_open_files",
        "pub(crate) fn read_open_files(&self) -> RwLockReadGuard<'_, FileSlotMap>",
    ),
    (
        "carrick_kernel::kernel::objects::FileTable::write_open_files",
        "pub(crate) fn write_open_files(&self) -> FileTableWriteGuard<'_>",
    ),
    (
        "carrick_kernel::kernel::objects::FileTable::lock_next_fd",
        "pub(crate) fn lock_next_fd(&self) -> FileTableMutexGuard<'_, i32>",
    ),
    (
        "carrick_kernel::kernel::objects::FileTable::lock_stdio_cloexec",
        "pub(crate) fn lock_stdio_cloexec(&self) -> FileTableStdioGuard<'_>",
    ),
    (
        "carrick_kernel::kernel::objects::FileTable::lock_closed_stdio",
        "pub(crate) fn lock_closed_stdio(&self) -> FileTableStdioGuard<'_>",
    ),
    (
        "carrick_kernel::kernel::objects::FileTable::lock_reserved_slots",
        "pub(crate) fn lock_reserved_slots(&self) -> MutexGuard<'_, HashMap<i32, u64>>",
    ),
    (
        "carrick_kernel::kernel::objects::FileTable::read_fd_open_paths",
        "pub(crate) fn read_fd_open_paths(&self) -> RwLockReadGuard<'_, FdOpenPaths>",
    ),
    (
        "carrick_kernel::kernel::objects::FileTable::write_fd_open_paths",
        "pub(crate) fn write_fd_open_paths(&self) -> FileTableRwWriteGuard<'_, FdOpenPaths>",
    ),
    (
        "carrick_kernel::kernel::objects::FileTable::read_epoll_fds",
        "pub(crate) fn read_epoll_fds(&self) -> RwLockReadGuard<'_, BTreeSet<i32>>",
    ),
    (
        "carrick_kernel::kernel::objects::FileTable::write_epoll_fds",
        "pub(crate) fn write_epoll_fds(&self) -> FileTableRwWriteGuard<'_, BTreeSet<i32>>",
    ),
    (
        "carrick_kernel::kernel::objects::FileTable::epoll_wake_registry",
        "pub(crate) fn epoll_wake_registry(&self) -> &crate::dispatch::EpollWakeRegistry",
    ),
    (
        "carrick_kernel::kernel::objects::FileTable::try_lock_next_fd",
        "fn try_lock_next_fd(&self) -> Option<FileTableMutexGuard<'_, i32>>",
    ),
    (
        "carrick_kernel::kernel::objects::FileTable::try_mutex_write",
        "fn try_mutex_write<'a, T>(&'a self, lock: &'a Mutex<T>) -> Option<FileTableMutexGuard<'a, T>>",
    ),
    (
        "carrick_kernel::kernel::objects::FileTable::mutex_write",
        "fn mutex_write<'a, T>(&'a self, lock: &'a Mutex<T>) -> FileTableMutexGuard<'a, T>",
    ),
    (
        "carrick_kernel::kernel::objects::FileTable::rw_write",
        "fn rw_write<'a, T>(&'a self, lock: &'a RwLock<T>) -> FileTableRwWriteGuard<'a, T>",
    ),
    (
        "carrick_kernel::kernel::objects::ipc::FileTable::stdio_guard",
        "pub(super) fn stdio_guard(&self, field: StdioField) -> FileTableStdioGuard<'_>",
    ),
];

fn approved_table_guard(owner: &str, method: &syn::ImplItemFn) -> bool {
    let Some((_, prototype)) = TABLE_GUARD_BOUNDARIES
        .iter()
        .find(|(symbol, _)| *symbol == owner)
    else {
        return false;
    };
    let Ok(expected) = syn::parse_str::<syn::ImplItemFn>(&format!("{prototype} {{}}")) else {
        return false;
    };
    fn signature(method: &syn::ImplItemFn) -> String {
        let mut signature = method.sig.clone();
        // Parameter bindings do not change the capability protocol.
        for input in &mut signature.inputs {
            if let syn::FnArg::Typed(input) = input {
                *input.pat = syn::Pat::Wild(syn::PatWild {
                    attrs: Vec::new(),
                    underscore_token: Default::default(),
                });
            }
        }
        signature.inputs = signature.inputs.into_iter().collect();
        signature.generics.params = signature.generics.params.into_iter().collect();
        if let Some(where_clause) = &mut signature.generics.where_clause {
            where_clause.predicates = where_clause.predicates.iter().cloned().collect();
        }
        let visibility = &method.vis;
        semantic_tokens(&quote::quote!(#visibility #signature))
    }
    signature(method) == signature(&expected)
}

// Closed implementation owners, not source paths. Calls made inside these
// authority primitives are definitions rather than legacy caller debt.
const DEFINITION_OWNERS: &[&str] = &[
    "carrick_kernel::kernel::objects::FileTable::commit_exact_replacement",
    "carrick_kernel::kernel::objects::FileTable::commit_reserved_slot",
    "carrick_kernel::kernel::objects::FileTable::epoll_wake_handle",
    "carrick_kernel::kernel::objects::FileTable::epoll_wake_registry",
    "carrick_kernel::kernel::objects::FileTable::for_exec",
    "carrick_kernel::kernel::objects::FileTable::for_fork_copy",
    "carrick_kernel::kernel::objects::FileTable::install",
    "carrick_kernel::kernel::objects::FileTable::is_bare_stdio_open",
    "carrick_kernel::kernel::objects::FileTable::lock_closed_stdio",
    "carrick_kernel::kernel::objects::FileTable::lock_next_fd",
    "carrick_kernel::kernel::objects::FileTable::lock_stdio_cloexec",
    "carrick_kernel::kernel::objects::FileTable::read_epoll_fds",
    "carrick_kernel::kernel::objects::FileTable::read_fd_open_paths",
    "carrick_kernel::kernel::objects::FileTable::read_open_files",
    "carrick_kernel::kernel::objects::FileTable::record_fd_open_path",
    "carrick_kernel::kernel::objects::FileTable::rename_fd_open_paths",
    "carrick_kernel::kernel::objects::FileTable::reserve_slot_at_or_above",
    "carrick_kernel::kernel::objects::FileTable::with_fd_ceiling",
    "carrick_kernel::kernel::objects::FileTable::write_epoll_fds",
    "carrick_kernel::kernel::objects::FileTable::write_fd_open_paths",
    "carrick_kernel::kernel::objects::FileTable::write_open_files",
    "carrick_kernel::dispatch::fd_table::HostSocketAuthority::set_ipv6_v6only",
    "carrick_kernel::dispatch::fd_table::OpenFile::is_io_uring_backing",
    "carrick_kernel::dispatch::fd_table::OpenFile::record_host_file_absolute_offset",
    "carrick_kernel::dispatch::fd_table::attach_el1_registration",
    "carrick_kernel::dispatch::fd_table::crate::kernel::FileDescription::inspect",
    "carrick_kernel::dispatch::fd_table::crate::kernel::FileDescription::open_description",
    "carrick_kernel::dispatch::fd_table::crate::kernel::FileDescription::read_for_io",
    "carrick_kernel::dispatch::fd_table::crate::kernel::FileDescription::try_inspect",
    "carrick_kernel::dispatch::fd_table::crate::kernel::FileDescription::write_for_io",
    "carrick_kernel::dispatch::fd_table::crate::kernel::FileSlot::from_open_description_with_common",
    "carrick_kernel::dispatch::fd_table::crate::kernel::FileSlot::from_open_description_with_status_flags",
    "carrick_kernel::dispatch::fd_table::kernel_file_description",
    "carrick_kernel::dispatch::fd_table::kernel_file_description_unregistered",
    "carrick_kernel::dispatch::fd_table::super::SyscallDispatcher::rename_open_paths",
];

pub(super) fn test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        path_is_ident(a.path(), "test") || (path_is_ident(a.path(), "cfg") && cfg_false(&a.meta))
    })
}
pub(super) fn cfg_false(meta: &syn::Meta) -> bool {
    use syn::parse::Parser;
    match meta {
        syn::Meta::Path(path) => path_is_ident(path, "test"),
        syn::Meta::NameValue(nv) => {
            path_is_ident(&nv.path, "feature") && semantic_tokens(&nv.value) == "\"test-support\""
        }
        syn::Meta::List(list) => {
            let Ok(children) =
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
                    .parse2(list.tokens.clone())
            else {
                return false;
            };
            if path_is_ident(&list.path, "cfg") || path_is_ident(&list.path, "all") {
                children.iter().any(cfg_false)
            } else if path_is_ident(&list.path, "any") {
                !children.is_empty() && children.iter().all(cfg_false)
            } else {
                false
            }
        }
    }
}
fn files(directory: &Path, result: &mut Vec<std::path::PathBuf>) -> Result<(), DebtError> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            files(&entry.path(), result)?;
        } else if entry.path().extension().is_some_and(|ext| ext == "rs") {
            result.push(entry.path());
        }
    }
    Ok(())
}
fn module_file(
    module: &syn::ItemMod,
    directory: &Path,
    explicit_directory: &Path,
    parsed: &BTreeMap<PathBuf, syn::File>,
) -> (PathBuf, bool) {
    let explicit = module.attrs.iter().find_map(|attr| {
        if !path_is_ident(attr.path(), "path") {
            return None;
        }
        let syn::Meta::NameValue(value) = &attr.meta else {
            return None;
        };
        let syn::Expr::Lit(value) = &value.value else {
            return None;
        };
        let syn::Lit::Str(value) = &value.lit else {
            return None;
        };
        Some(explicit_directory.join(value.value()))
    });
    let explicit_path = explicit.is_some();
    let path = explicit.unwrap_or_else(|| {
        if module.content.is_some() {
            return directory.join(module.ident.unraw().to_string());
        }
        let flat = directory.join(format!("{}.rs", module.ident.unraw()));
        if parsed.contains_key(&flat) {
            flat
        } else {
            directory
                .join(module.ident.unraw().to_string())
                .join("mod.rs")
        }
    });
    (normalized_path(&path), explicit_path)
}
fn test_modules(
    items: &[syn::Item],
    directory: &Path,
    explicit_directory: &Path,
    inherited_test: bool,
    parsed: &BTreeMap<PathBuf, syn::File>,
    result: &mut BTreeSet<PathBuf>,
) {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        let (path, explicit_path) = module_file(module, directory, explicit_directory, parsed);
        let child_directory = if module.content.is_some() {
            path.clone()
        } else {
            directory.join(module.ident.unraw().to_string())
        };
        let is_test = inherited_test || test_only(&module.attrs);
        if let Some((_, items)) = &module.content {
            test_modules(
                items,
                &child_directory,
                &child_directory,
                is_test,
                parsed,
                result,
            );
        } else if is_test
            && result.insert(path.clone())
            && let Some(syntax) = parsed.get(&path)
            && let Some(parent) = path.parent()
        {
            let directory = if explicit_path || path.ends_with("mod.rs") {
                parent.to_path_buf()
            } else {
                path.with_extension("")
            };
            test_modules(&syntax.items, &directory, parent, true, parsed, result);
        }
    }
}

// A parsed test module can include other sources. Close these proven include
// edges before treating otherwise-unbound files as production roots. Opaque
// macro inputs cannot prove a test-only edge; production closure still wins
// whenever a file is also referenced by a production source.
fn test_inclusions(
    parsed: &BTreeMap<PathBuf, syn::File>,
    vocabulary: &BTreeMap<String, AuthorityOperation>,
    test_files: &mut BTreeSet<PathBuf>,
) {
    struct Includes<'a> {
        parent: &'a Path,
        vocabulary: &'a BTreeMap<String, AuthorityOperation>,
        references: BTreeSet<PathBuf>,
    }
    impl<'ast> Visit<'ast> for Includes<'_> {
        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            if mac.path.segments.last().is_some_and(|part| {
                matches!(
                    self.vocabulary.get(&part.ident.unraw().to_string()),
                    Some(
                        AuthorityOperation::SourceInclude | AuthorityOperation::SourceStringInclude
                    )
                )
            }) && let Ok(arguments) =
                syn::punctuated::Punctuated::<syn::LitStr, syn::Token![,]>::parse_terminated
                    .parse2(mac.tokens.clone())
                && arguments.len() == 1
                && let Some(literal) = arguments.first()
            {
                self.references
                    .insert(normalized_path(&self.parent.join(literal.value())));
            }
            // Never infer test reachability from arbitrary macro token streams.
        }
    }
    let mut pending = test_files.clone();
    while let Some(path) = pending.pop_first() {
        let Some(syntax) = parsed.get(&path) else {
            continue;
        };
        let Some(parent) = path.parent() else {
            continue;
        };
        let mut includes = Includes {
            parent,
            vocabulary,
            references: BTreeSet::new(),
        };
        includes.visit_file(syntax);
        for included in includes.references {
            if let Some(syntax) = parsed.get(&included)
                && test_files.insert(included.clone())
            {
                pending.insert(included.clone());
                if let Some(parent) = included.parent() {
                    let before = test_files.clone();
                    test_modules(&syntax.items, parent, parent, true, parsed, test_files);
                    pending.extend(test_files.difference(&before).cloned());
                }
            }
        }
    }
}

// Macro inputs are arbitrary token streams. Parsing them may recover symbolic
// owners, but cannot prove that a referenced source file is test-only. Every
// source literal takes precedence over parsed test module references, even in
// cfg-gated macros, definitions, attributes, or nested DSL groups.
// Strict source edges come only from literal built-in inclusions in parsed
// production syntax. Opaque references are rejected by dialect validation,
// never used to promote a file or to confer test-only scope.
fn resolved_source_references(
    parsed: &BTreeMap<PathBuf, syn::File>,
) -> Result<BTreeMap<PathBuf, BTreeSet<PathBuf>>, DebtError> {
    struct Includes<'a> {
        file: &'a Path,
        references: BTreeSet<PathBuf>,
    }
    impl<'ast> Visit<'ast> for Includes<'_> {
        fn visit_item(&mut self, item: &'ast syn::Item) {
            let attrs = match item {
                syn::Item::Mod(i) => &i.attrs,
                syn::Item::Fn(i) => &i.attrs,
                syn::Item::Impl(i) => &i.attrs,
                syn::Item::Trait(i) => &i.attrs,
                syn::Item::Macro(i) => &i.attrs,
                syn::Item::Static(i) => &i.attrs,
                syn::Item::Const(i) => &i.attrs,
                _ => return visit::visit_item(self, item),
            };
            if !test_only(attrs) {
                visit::visit_item(self, item);
            }
        }
        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            if !test_only(&item.attrs) {
                visit::visit_impl_item_fn(self, item);
            }
        }
        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            let builtin = matches!(
                semantic_tokens(&mac.path)
                    .replace(' ', "")
                    .trim_start_matches("::"),
                "include"
                    | "include_str"
                    | "include_bytes"
                    | "std::include"
                    | "std::include_str"
                    | "std::include_bytes"
                    | "core::include"
                    | "core::include_str"
                    | "core::include_bytes"
            );
            if builtin && let Ok(literal) = syn::parse2::<syn::LitStr>(mac.tokens.clone()) {
                let path = normalized_path(
                    &self
                        .file
                        .parent()
                        .unwrap_or(self.file)
                        .join(literal.value()),
                );
                let code = mac
                    .path
                    .segments
                    .last()
                    .is_some_and(|s| s.ident.unraw() == "include");
                if code || path.extension().is_some_and(|e| e == "rs") {
                    self.references.insert(path);
                }
            }
        }
    }
    let mut references = BTreeMap::new();
    for (path, file) in parsed {
        let mut visitor = Includes {
            file: path,
            references: BTreeSet::new(),
        };
        if !test_only(&file.attrs) {
            visitor.visit_file(file);
        }
        references.insert(path.clone(), visitor.references);
    }
    Ok(references)
}

// Classification is physical reachability, not logical owner resolution. A
// literal-promoted file can have no known owner, but all its production
// descendants must still be counted (and fail closed if their owners are unknown).
fn production_files(
    parsed: &BTreeMap<PathBuf, syn::File>,
    macro_references: &BTreeMap<PathBuf, BTreeSet<PathBuf>>,
    mut production: BTreeSet<PathBuf>,
) -> Result<BTreeSet<PathBuf>, DebtError> {
    struct Modules<'a> {
        directory: PathBuf,
        explicit_directory: PathBuf,
        parsed: &'a BTreeMap<PathBuf, syn::File>,
        references: BTreeSet<PathBuf>,
        opaque: bool,
    }
    impl<'ast> Visit<'ast> for Modules<'_> {
        fn visit_item(&mut self, item: &'ast syn::Item) {
            let attrs = match item {
                syn::Item::Const(item) => &item.attrs,
                syn::Item::Fn(item) => &item.attrs,
                syn::Item::Impl(item) => &item.attrs,
                syn::Item::Macro(item) => &item.attrs,
                syn::Item::Mod(item) => &item.attrs,
                syn::Item::Static(item) => &item.attrs,
                syn::Item::Trait(item) => &item.attrs,
                _ => return visit::visit_item(self, item),
            };
            if self.opaque || !test_only(attrs) {
                visit::visit_item(self, item);
            }
        }
        fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
            if !self.opaque && test_only(&module.attrs) {
                return;
            }
            let (path, explicit_path) = module_file(
                module,
                &self.directory,
                &self.explicit_directory,
                self.parsed,
            );
            let mut candidates = BTreeSet::from([path]);
            if self.opaque && explicit_path {
                // A macro can retain or remove #[path]. Neither candidate is
                // proof that the other physical incarnation is test-only.
                let mut plain = module.clone();
                plain.attrs.clear();
                candidates.insert(
                    module_file(
                        &plain,
                        &self.directory,
                        &self.explicit_directory,
                        self.parsed,
                    )
                    .0,
                );
            }
            for path in candidates {
                if let Some((_, children)) = &module.content {
                    let directory = std::mem::replace(&mut self.directory, path.clone());
                    let explicit = std::mem::replace(&mut self.explicit_directory, path);
                    for item in children {
                        self.visit_item(item);
                    }
                    self.directory = directory;
                    self.explicit_directory = explicit;
                } else if self.parsed.contains_key(&path) || path.is_file() {
                    self.references.insert(path);
                }
            }
        }
        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            if self.opaque || !test_only(&item.attrs) {
                visit::visit_impl_item_fn(self, item);
            }
        }
        fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
            if self.opaque || !test_only(&item.attrs) {
                visit::visit_trait_item_fn(self, item);
            }
        }
        fn visit_expr(&mut self, expression: &'ast syn::Expr) {
            if self.opaque || !expression_test_only(expression) {
                visit::visit_expr(self, expression);
            }
        }
        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            let opaque = std::mem::replace(&mut self.opaque, true);
            visit_macro_inputs(self, mac.tokens.clone());
            self.opaque = opaque;
        }
    }
    let mut pending = production.clone();
    while let Some(path) = pending.pop_first() {
        let syntax = parsed.get(&path).ok_or_else(|| {
            DebtError::Policy(format!(
                "production module reference outside discoverable Rust files: {}",
                path.display()
            ))
        })?;
        let parent = path
            .parent()
            .ok_or_else(|| DebtError::Policy("missing source parent".into()))?;
        let mut references = macro_references.get(&path).cloned().unwrap_or_default();
        // A literal may instantiate this file through include! or #[path],
        // rather than its conventional filename. Follow both lookup contexts
        // conservatively; neither may leave a real descendant test-only.
        let directories = BTreeSet::from([parent.to_path_buf(), path.with_extension("")]);
        for directory in directories {
            let mut visitor = Modules {
                opaque: false,
                directory,
                explicit_directory: parent.to_path_buf(),
                parsed,
                references: BTreeSet::new(),
            };
            visitor.visit_file(syntax);
            references.extend(visitor.references);
        }
        for child in references {
            if production.insert(child.clone()) {
                pending.insert(child);
            }
        }
    }
    Ok(production)
}
fn contains_authority_tokens(
    tokens: TokenStream,
    vocabulary: &BTreeMap<String, AuthorityOperation>,
) -> bool {
    let tokens: Vec<_> = tokens.into_iter().collect();
    // Inline metadata modules do not select physical files. An unexpanded
    // out-of-line declaration could conceal a production incarnation.
    for (index, token) in tokens.iter().enumerate() {
        if matches!(token, TokenTree::Ident(name) if name.unraw() == "mod") {
            for next in &tokens[index + 1..] {
                if matches!(next, TokenTree::Punct(p) if p.as_char() == ';') {
                    return true;
                }
                if matches!(next, TokenTree::Group(group) if group.delimiter() == Delimiter::Brace)
                {
                    break;
                }
            }
        }
    }
    tokens.into_iter().any(|token| match token {
        TokenTree::Group(group) => contains_authority_tokens(group.stream(), vocabulary),
        TokenTree::Ident(name) => vocabulary.contains_key(&name.unraw().to_string()),
        _ => false,
    })
}
// Recover import aliases and logical declarations from literal Rust macro
// inputs with the same parser. File classification uses the independent token
// literal census above, whether or not these inputs parse as Rust syntax.
fn visit_macro_inputs(visitor: &mut impl for<'ast> Visit<'ast>, tokens: TokenStream) {
    let tokens = macro_input_tokens(tokens);
    if let Ok(file) = syn::parse2::<syn::File>(tokens.clone()) {
        visitor.visit_file(&file);
    } else if let Ok(expression) = syn::parse2::<syn::Expr>(tokens.clone()) {
        visitor.visit_expr(&expression);
    } else {
        let tokens: Vec<_> = tokens.into_iter().collect();
        let mut remaining = tokens.as_slice();
        while let Some((token, rest)) = remaining.split_first() {
            if let TokenTree::Ident(name) = token
                && matches!(remaining.get(1), Some(TokenTree::Punct(p)) if p.as_char() == '!')
                && let Some(TokenTree::Group(group)) = remaining.get(2)
            {
                visitor.visit_macro(&syn::Macro {
                    path: syn::Path::from(name.clone()),
                    bang_token: Default::default(),
                    delimiter: syn::MacroDelimiter::Paren(Default::default()),
                    tokens: group.stream(),
                });
                // The invoked visitor already consumes this group. Visiting
                // it again multiplies work through nested macro inputs.
                remaining = &remaining[3..];
            } else {
                if let TokenTree::Group(group) = token {
                    visit_macro_inputs(visitor, group.stream());
                }
                remaining = rest;
            }
        }
    }
}

// Imported builtin macro names can be re-exported and renamed again. Resolve
// all such spellings conservatively; conflicting short names fail closed.
fn collect_source_inclusion_aliases(
    parsed: &BTreeMap<PathBuf, syn::File>,
    vocabulary: &mut BTreeMap<String, AuthorityOperation>,
) -> Result<(), DebtError> {
    struct Imports(Vec<(String, String)>);
    impl<'ast> Visit<'ast> for Imports {
        fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
            if !test_only(&item.attrs) && item.ident.is_none() {
                self.visit_macro(&item.mac);
            }
        }
        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            visit_macro_inputs(self, mac.tokens.clone());
        }
        fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
            if test_only(&item.attrs) {
                return;
            }
            fn collect(tree: &syn::UseTree, imports: &mut Vec<(String, String)>) {
                match tree {
                    syn::UseTree::Path(path) => collect(&path.tree, imports),
                    syn::UseTree::Rename(rename) => imports.push((
                        rename.ident.unraw().to_string(),
                        rename.rename.unraw().to_string(),
                    )),
                    syn::UseTree::Group(group) => {
                        for tree in &group.items {
                            collect(tree, imports);
                        }
                    }
                    _ => {}
                }
            }
            collect(&item.tree, &mut self.0);
        }
    }
    let mut imports = Imports(Vec::new());
    for syntax in parsed.values() {
        imports.visit_file(syntax);
    }
    loop {
        let mut changed = false;
        for (original, alias) in &imports.0 {
            if let Some(
                kind
                @ (AuthorityOperation::SourceInclude | AuthorityOperation::SourceStringInclude),
            ) = vocabulary.get(original).copied()
            {
                match vocabulary.get(alias) {
                    Some(previous) if *previous != kind => {
                        return Err(DebtError::Policy(format!(
                            "ambiguous source inclusion alias: {alias}"
                        )));
                    }
                    Some(_) => {}
                    None => {
                        vocabulary.insert(alias.clone(), kind);
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            return Ok(());
        }
    }
}
pub(super) fn normalized_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::CurDir => {}
            _ => normalized.push(component),
        }
    }
    normalized
}
// Resolve logical module ancestry from declarations, including #[path]. Physical
// files are only inputs to this graph, never authority identities.
fn declared_modules(
    path: &Path,
    modules: &[String],
    explicit_path: bool,
    parsed: &BTreeMap<PathBuf, syn::File>,
    resolved: &mut BTreeMap<PathBuf, Vec<Vec<String>>>,
    vocabulary: &BTreeMap<String, AuthorityOperation>,
) -> Result<(), DebtError> {
    if resolved
        .get(path)
        .is_some_and(|previous| previous.iter().any(|identity| identity == modules))
    {
        return Ok(());
    }
    if modules.len() > 128 {
        return Err(DebtError::Policy("recursive module graph".into()));
    }
    let syntax = parsed.get(path).ok_or_else(|| {
        DebtError::Policy(format!(
            "missing production module owner: {}",
            path.display()
        ))
    })?;
    resolved
        .entry(path.to_path_buf())
        .or_default()
        .push(modules.to_vec());
    let parent = path
        .parent()
        .ok_or_else(|| DebtError::Policy("missing module directory".into()))?;
    let directory = if explicit_path
        || matches!(
            path.file_name().and_then(|s| s.to_str()),
            Some("lib.rs" | "main.rs" | "mod.rs" | "entry.rs")
        ) {
        parent.to_path_buf()
    } else {
        path.with_extension("")
    };
    declared_items(
        &syntax.items,
        path,
        (&directory, parent),
        modules,
        parsed,
        resolved,
        vocabulary,
    )
}
fn declared_items(
    items: &[syn::Item],
    source_file: &Path,
    directories: (&Path, &Path),
    modules: &[String],
    parsed: &BTreeMap<PathBuf, syn::File>,
    resolved: &mut BTreeMap<PathBuf, Vec<Vec<String>>>,
    vocabulary: &BTreeMap<String, AuthorityOperation>,
) -> Result<(), DebtError> {
    let (directory, explicit_directory) = directories;
    for item in items {
        let syn::Item::Mod(module) = item else {
            let mut bodies = DeclarationBodies {
                source_file,
                directory,
                explicit_directory,
                modules: modules.to_vec(),
                parsed,
                resolved,
                vocabulary,
                error: None,
            };
            bodies.visit_item(item);
            if let Some(error) = bodies.error {
                return Err(error);
            }
            continue;
        };
        if test_only(&module.attrs) {
            continue;
        }
        let mut child_modules = modules.to_vec();
        child_modules.push(module.ident.unraw().to_string());
        let (file, explicit_path) = module_file(module, directory, explicit_directory, parsed);
        if let Some((_, children)) = &module.content {
            declared_items(
                children,
                source_file,
                (&file, &file),
                &child_modules,
                parsed,
                resolved,
                vocabulary,
            )?;
        } else {
            declared_modules(
                &file,
                &child_modules,
                explicit_path,
                parsed,
                resolved,
                vocabulary,
            )?;
        }
    }
    Ok(())
}

// Local items retain their enclosing function/impl identity. Their physical
// module lookup directory still belongs to the enclosing module, not the fn.
struct DeclarationBodies<'a> {
    source_file: &'a Path,
    directory: &'a Path,
    explicit_directory: &'a Path,
    modules: Vec<String>,
    parsed: &'a BTreeMap<PathBuf, syn::File>,
    resolved: &'a mut BTreeMap<PathBuf, Vec<Vec<String>>>,
    error: Option<DebtError>,
    vocabulary: &'a BTreeMap<String, AuthorityOperation>,
}
impl DeclarationBodies<'_> {
    fn source_inclusion(&mut self, mac: &syn::Macro, string_data: bool) -> Result<(), DebtError> {
        use syn::parse::Parser;
        let arguments =
            syn::punctuated::Punctuated::<syn::LitStr, syn::Token![,]>::parse_terminated
                .parse2(mac.tokens.clone())
                .map_err(|_| {
                    DebtError::Policy(format!(
                        "nonliteral source inclusion in {}",
                        self.source_file.display()
                    ))
                })?;
        let literal = arguments
            .first()
            .filter(|_| arguments.len() == 1)
            .ok_or_else(|| {
                DebtError::Policy(format!(
                    "source inclusion requires one literal path in {}",
                    self.source_file.display()
                ))
            })?;
        let parent = self
            .source_file
            .parent()
            .ok_or_else(|| DebtError::Policy("missing inclusion parent".into()))?;
        let path = normalized_path(&parent.join(literal.value()));
        if !self.parsed.contains_key(&path) {
            // Non-Rust string data (e.g. bundled DTrace scripts) is not executable
            // source. An executable include outside the discovery domain must
            // be rejected, rather than silently evade the lexical zero rules.
            let source = std::fs::read_to_string(&path).map_err(|error| {
                DebtError::Policy(format!(
                    "cannot read source inclusion {}: {error}",
                    path.display()
                ))
            })?;
            if string_data && syn::parse_file(&source).is_err() {
                return Ok(());
            }
            return Err(DebtError::Policy(format!(
                "source inclusion outside discoverable Rust files: {}",
                path.display()
            )));
        }
        declared_modules(
            &path,
            &self.modules,
            true,
            self.parsed,
            self.resolved,
            self.vocabulary,
        )
    }
}
impl<'ast> Visit<'ast> for DeclarationBodies<'_> {
    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        if self.error.is_none() {
            self.error = declared_items(
                &[syn::Item::Mod(module.clone())],
                self.source_file,
                (self.directory, self.explicit_directory),
                &self.modules,
                self.parsed,
                self.resolved,
                self.vocabulary,
            )
            .err();
        }
    }
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !test_only(&item.attrs) {
            self.modules.push(item.sig.ident.unraw().to_string());
            visit::visit_item_fn(self, item);
            self.modules.pop();
        }
    }
    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !test_only(&item.attrs) {
            self.modules.push(item.sig.ident.unraw().to_string());
            visit::visit_impl_item_fn(self, item);
            self.modules.pop();
        }
    }
    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if !test_only(&item.attrs) {
            self.modules.push(implementation_name(item));
            visit::visit_item_impl(self, item);
            self.modules.pop();
        }
    }
    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        if !test_only(&item.attrs) {
            self.modules.push(item.ident.unraw().to_string());
            visit::visit_item_trait(self, item);
            self.modules.pop();
        }
    }
    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if !test_only(&item.attrs) {
            self.modules.push(item.sig.ident.unraw().to_string());
            visit::visit_trait_item_fn(self, item);
            self.modules.pop();
        }
    }
    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        if !test_only(&item.attrs) {
            self.modules.push(item.ident.unraw().to_string());
            visit::visit_item_static(self, item);
            self.modules.pop();
        }
    }
    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        if !test_only(&item.attrs) {
            self.modules.push(item.ident.unraw().to_string());
            visit::visit_item_const(self, item);
            self.modules.pop();
        }
    }
    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if !test_only(&item.attrs) && item.ident.is_none() {
            self.visit_macro(&item.mac);
        }
    }
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let inclusion = mac
            .path
            .segments
            .last()
            .and_then(|part| self.vocabulary.get(&part.ident.unraw().to_string()));
        if matches!(
            inclusion,
            Some(AuthorityOperation::SourceInclude | AuthorityOperation::SourceStringInclude)
        ) {
            if self.error.is_none() {
                self.error = self
                    .source_inclusion(
                        mac,
                        inclusion == Some(&AuthorityOperation::SourceStringInclude),
                    )
                    .err();
            }
            return;
        }
        visit_macro_inputs(self, mac.tokens.clone());
    }
    fn visit_expr(&mut self, expression: &'ast syn::Expr) {
        if !expression_test_only(expression) {
            visit::visit_expr(self, expression);
        }
    }
}

pub(super) fn expression_test_only(expression: &syn::Expr) -> bool {
    macro_rules! attributes {
        ($($kind:ident),*) => { match expression { $(syn::Expr::$kind(value) => &value.attrs,)* _ => &[] } };
    }
    let attributes: &[syn::Attribute] = attributes!(
        Array, Assign, Async, Await, Binary, Block, Break, Call, Cast, Closure, Const, Continue,
        Field, ForLoop, Group, If, Index, Infer, Let, Lit, Loop, Macro, Match, MethodCall, Paren,
        Path, Range, RawAddr, Reference, Repeat, Return, Struct, Try, TryBlock, Tuple, Unary,
        Unsafe, While, Yield
    );
    test_only(attributes)
}

impl SourceCensus {
    pub fn load(root: &Path) -> Result<Self, DebtError> {
        Self::read(&root.canonicalize()?)
    }

    fn read(root: &Path) -> Result<Self, DebtError> {
        let mut result = Self {
            vocabulary: authority_vocabulary()?,
            ..Self::default()
        };
        let build_roots = super::authority_build::metadata_roots(root)?;
        let build_parsed = super::authority_build::load(root, &build_roots)?;
        let mut leaves: Vec<_> = build_parsed.keys().cloned().collect();
        result.build_roots = build_roots;
        result.build_files = build_parsed
            .keys()
            .map(|path| {
                path.strip_prefix(root)
                    .map(|relative| relative.to_string_lossy().to_string())
                    .map_err(|error| DebtError::Policy(error.to_string()))
            })
            .collect::<Result<_, _>>()?;
        for entry in std::fs::read_dir(root.join("crates"))? {
            let entry = entry?;
            if entry.file_name() == "carrick-xtask" {
                continue;
            }
            let src = entry.path().join("src");
            if src.is_dir() {
                files(&src, &mut leaves)?;
            }
        }
        for path in &leaves {
            let canonical = path.canonicalize()?;
            if path.components().any(|part| part.as_os_str() == "src")
                && build_parsed.contains_key(&canonical)
            {
                return Err(DebtError::Policy(format!(
                    "build-time/production source overlap: {}",
                    path.display()
                )));
            }
        }
        leaves.sort();
        let mut parsed = BTreeMap::new();
        for path in &leaves {
            let source = std::fs::read_to_string(path)?;
            let relative = path
                .strip_prefix(root)
                .map_err(|e| DebtError::Policy(e.to_string()))?
                .to_string_lossy()
                .to_string();
            result
                .source_hashes
                .insert(relative.clone(), source_hash(source.as_bytes()));
            let syntax = syn::parse_file(&source)
                .map_err(|error| DebtError::Policy(format!("{}: {error}", path.display())))?;
            let mut classification = Classifications::default();
            classification.visit_file(&syntax);
            result.classifications.insert(relative, classification.0);
            parsed.insert(path.clone(), syntax);
        }
        let mut test_files = BTreeSet::new();
        for (path, syntax) in &parsed {
            let parent = path
                .parent()
                .ok_or_else(|| DebtError::Policy("missing source parent".into()))?;
            let directory = if matches!(
                path.file_name().and_then(|s| s.to_str()),
                Some("lib.rs" | "mod.rs" | "main.rs")
            ) {
                parent.to_path_buf()
            } else {
                path.with_extension("")
            };
            test_modules(
                &syntax.items,
                &directory,
                parent,
                false,
                &parsed,
                &mut test_files,
            );
        }
        collect_source_inclusion_aliases(&parsed, &mut result.vocabulary)?;
        test_inclusions(&parsed, &result.vocabulary, &mut test_files);
        {
            // Reject invalid selectors before attempting module resolution.
            // A second pass below validates any file also reached in production.
            let provisional = parsed
                .keys()
                .filter(|p| !test_files.contains(*p))
                .cloned()
                .collect();
            crate::authority_dialect::validate(
                root,
                &parsed,
                &result.vocabulary.keys().cloned().collect(),
                &result
                    .vocabulary
                    .iter()
                    .filter(|(_, kind)| **kind == AuthorityOperation::RawLock)
                    .map(|(name, _)| name.clone())
                    .collect(),
                &test_files,
                &provisional,
                None,
            )?;
        }
        let mut resolved = BTreeMap::new();
        for path in &leaves {
            let parent = path
                .parent()
                .ok_or_else(|| DebtError::Policy("missing source parent".into()))?;
            if parent.file_name().is_some_and(|name| name == "src")
                && matches!(
                    path.file_name().and_then(|s| s.to_str()),
                    Some("lib.rs" | "main.rs" | "entry.rs")
                )
            {
                let krate = path
                    .strip_prefix(root)
                    .map_err(|e| DebtError::Policy(e.to_string()))?
                    .components()
                    .nth(1)
                    .ok_or_else(|| DebtError::Policy("missing root crate".into()))?
                    .as_os_str()
                    .to_string_lossy()
                    .replace('-', "_");
                let mut target = vec![krate];
                if path.file_name().is_some_and(|s| s != "lib.rs")
                    && parsed.contains_key(&parent.join("lib.rs"))
                {
                    target.push(format!(
                        "target_{}",
                        path.file_stem().unwrap_or_default().to_string_lossy()
                    ));
                }
                declared_modules(
                    path,
                    &target,
                    false,
                    &parsed,
                    &mut resolved,
                    &result.vocabulary,
                )?;
            }
        }
        if let Some(path) = build_parsed
            .keys()
            .find(|path| resolved.contains_key(*path))
        {
            return Err(DebtError::Policy(format!(
                "build-time/production source overlap: {}",
                path.display()
            )));
        }
        // Macro literals force production scope without inventing a logical
        // owner or extending the retained scanners' source discovery domain.
        let macro_references = resolved_source_references(&parsed)?;
        let mut production = resolved.keys().cloned().collect::<BTreeSet<_>>();
        // Only production files seed reachability. Their macro inputs remain
        // conservative even in cfg-gated syntax, but a test-only literal cycle
        // cannot bootstrap itself into a production incarnation.
        for path in parsed.keys() {
            let relative = path
                .strip_prefix(root)
                .map_err(|e| DebtError::Policy(e.to_string()))?
                .to_string_lossy();
            let probe =
                relative.contains("/src/bin/") && !relative.starts_with("crates/carrick-cli/");
            if !test_files.contains(path) && !probe && !build_parsed.contains_key(path) {
                production.insert(path.clone());
            }
        }
        let production = production_files(&parsed, &macro_references, production)?;
        if let Some(path) = build_parsed.keys().find(|path| production.contains(*path)) {
            return Err(DebtError::Policy(format!(
                "build-time/production source overlap: {}",
                path.display()
            )));
        }
        for build in &result.build_roots {
            declared_modules(
                &root.join(&build.source),
                &[build.package.replace('-', "_"), "build_program".into()],
                true,
                &parsed,
                &mut resolved,
                &result.vocabulary,
            )?;
        }
        {
            result.canonical_calls = crate::authority_dialect::validate(
                root,
                &parsed,
                &result.vocabulary.keys().cloned().collect(),
                &result
                    .vocabulary
                    .iter()
                    .filter(|(_, kind)| **kind == AuthorityOperation::RawLock)
                    .map(|(name, _)| name.clone())
                    .collect(),
                &test_files,
                &production,
                Some(&resolved),
            )?;
        }
        // Parse aliases before any methods: a later type alias or renamed
        // lock import cannot make a raw storage accessor opaque to the census.
        for (path, syntax) in &parsed {
            let relative = path
                .strip_prefix(root)
                .map_err(|e| DebtError::Policy(e.to_string()))?;
            if !production.contains(path) && test_files.contains(path) {
                continue;
            }
            let krate = relative
                .components()
                .nth(1)
                .ok_or_else(|| DebtError::Policy("missing crate".into()))?
                .as_os_str()
                .to_string_lossy()
                .replace('-', "_");
            let incarnations = resolved.get(path).cloned().unwrap_or_else(|| {
                vec![
                    std::iter::once(krate.clone())
                        .chain(
                            relative
                                .components()
                                .skip(3)
                                .map(|part| {
                                    part.as_os_str()
                                        .to_string_lossy()
                                        .trim_end_matches(".rs")
                                        .to_owned()
                                })
                                .filter(|part| part != "mod"),
                        )
                        .collect(),
                ]
            });
            for modules in incarnations {
                let mut collector = AliasCollector {
                    aliases: &mut result.aliases,
                    projections: &mut result.projections,
                    inherent_methods: &mut result.inherent_methods,
                    prefix: modules,
                };
                collector.visit_file(syntax);
            }
        }
        for (path, syntax) in parsed {
            let relative_path = path
                .strip_prefix(root)
                .map_err(|e| DebtError::Policy(e.to_string()))?;
            let relative = relative_path.to_string_lossy().to_string();
            // Standalone probe binaries are outside the reviewed product
            // profiles, not test modules. Preserve that scope only when no
            // production declaration or macro literal references the file.
            if !production.contains(&path)
                && relative.contains("/src/bin/")
                && !relative.starts_with("crates/carrick-cli/")
            {
                result.non_product_files.insert(relative);
                continue;
            }
            // Every production declaration takes precedence over every test
            // declaration, including a #[path] into a test directory or bin.
            if !production.contains(&path) && test_files.contains(&path) {
                result.test_files.insert(relative);
                continue;
            }
            if !resolved.contains_key(&path) {
                result.unbound_files.insert(relative.clone());
            }
            let krate = relative
                .split('/')
                .nth(1)
                .ok_or_else(|| DebtError::Policy("missing source crate".into()))?
                .replace('-', "_");
            let incarnations = resolved.get(&path).cloned().unwrap_or_else(|| {
                vec![
                    std::iter::once(krate.clone())
                        .chain(
                            relative_path
                                .components()
                                .skip(3)
                                .map(|part| {
                                    part.as_os_str()
                                        .to_string_lossy()
                                        .trim_end_matches(".rs")
                                        .to_owned()
                                })
                                .filter(|part| part != "mod"),
                        )
                        .collect(),
                ]
            });
            for modules in incarnations {
                let (krate, modules) = modules
                    .split_first()
                    .ok_or_else(|| DebtError::Policy("missing declared crate owner".into()))?;
                let mut scanner = Scanner {
                    census: &mut result,
                    file: relative.clone(),
                    krate: krate.clone(),
                    modules: modules.to_vec(),
                    implementation: None,
                    implementation_type: None,
                    current_owner: None,
                    bindings: BTreeMap::new(),
                    generic_types: BTreeSet::new(),
                };
                scanner.visit_file(&syntax);
            }
        }
        if !result.unknown_apis.is_empty() {
            return Err(DebtError::Policy(format!(
                "unrecognized authority API definitions: {:?}",
                result.unknown_apis
            )));
        }
        Ok(result)
    }
    pub fn verify_task_rules(&self) -> Result<(), DebtError> {
        for required in [
            "carrick_kernel::kernel::crash_capture::CrashQuorum::poll",
            "carrick_kernel::dispatch::mm_quiesce::drain_exact_mm",
            "carrick_runtime::vcpu_loop::quiesce::try_begin_hvpatch_process_fork_with_admission",
            "carrick_kernel::dispatch::mm_authority::MmExecutorAdmissionRecipe::enter",
            "carrick_kernel::kernel::objects::Thread::enter_crash_safe_point_participation",
        ] {
            if !self
                .owners
                .iter()
                .filter(|(file, _)| !self.unbound_files.contains(*file))
                .flat_map(|(_, owners)| owners)
                .any(|owner| owner.name == required)
            {
                return Err(DebtError::Policy(format!(
                    "missing task structural rule owner: {required}"
                )));
            }
        }
        if !self.structural_errors.is_empty() {
            return Err(DebtError::Policy(format!(
                "task structural rules: {:?}",
                self.structural_errors
            )));
        }
        Ok(())
    }
    pub fn is_test_at(&self, file: &str, line: usize, column: usize) -> bool {
        self.test_files.contains(file)
            || self.test_ranges.get(file).is_some_and(|ranges| {
                ranges.iter().any(|(start, end)| {
                    line >= start.line
                        && line <= end.line
                        && (line > start.line || column >= start.column)
                        && (line < end.line || column <= end.column)
                })
            })
    }
    pub fn is_outside_production_at(&self, file: &str, line: usize, column: usize) -> bool {
        self.non_product_files.contains(file) || self.is_test_at(file, line, column)
    }
    /// Source-bound verdict; consumers must validate both the complete file set
    /// and the hashes before applying any exclusion. Policy identity is built
    /// into the executable so a stale binary cannot bless changed scanner code.
    pub fn verdict(&self, root: &Path) -> Result<serde_json::Value, DebtError> {
        let mut files = BTreeMap::new();
        for (file, hash) in &self.source_hashes {
            if source_hash(&std::fs::read(root.join(file))?) != *hash {
                return Err(DebtError::Policy(format!(
                    "source changed during census: {file}"
                )));
            }
            files.insert(
                file,
                serde_json::json!({
                    "sha256": hash,
                    "production": !self.test_files.contains(file),
                    "product_profile": !self.non_product_files.contains(file) && !self.is_build_file(file),
                    "boundary": if self.is_build_file(file) { "build_time" } else { "production" },
                    "items": self.classifications.get(file),
                    "canonical_calls": self.canonical_calls.get(file).map(Vec::as_slice).unwrap_or_default(),
                }),
            );
        }
        let inputs = census_inputs();
        let tools = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| DebtError::Policy("missing census tool root".into()))?;
        for (file, hash) in &inputs {
            if source_hash(&std::fs::read(tools.join(file))?) != *hash {
                return Err(DebtError::Policy(format!(
                    "stale census executable: {file}"
                )));
            }
        }
        Ok(
            serde_json::json!({"schema": 1, "dialect": "strict", "root": root.canonicalize()?, "tool_root": tools,
            "inputs": inputs, "build_roots": self.build_roots, "rejections": [], "files": files}),
        )
    }
    pub fn is_build_file(&self, file: &str) -> bool {
        self.build_files.contains(file)
    }
    pub fn is_test_file(&self, file: &str) -> bool {
        self.test_files.contains(file)
    }
    pub fn owner_at(&self, file: &str, line: usize, column: usize) -> Result<String, DebtError> {
        self.resolve_owner(file, line, Some(column))
    }
    pub fn lane(&self, owner: &str) -> Result<Lane, DebtError> {
        let nearest = self
            .owners
            .values()
            .flatten()
            .filter(|found| {
                found.name == owner
                    || owner
                        .strip_prefix(&found.name)
                        .is_some_and(|rest| rest.starts_with("::"))
            })
            .max_by_key(|found| found.name.len())
            .ok_or_else(|| DebtError::Policy(format!("missing symbolic owner lane: {owner}")))?;
        if self
            .owners
            .values()
            .flatten()
            .any(|found| found.name == nearest.name && found.lane != nearest.lane)
        {
            return Err(DebtError::Policy(format!(
                "ambiguous symbolic owner lane: {owner}"
            )));
        }
        Ok(nearest.lane)
    }
    pub fn owner_on_line(&self, file: &str, line: usize) -> Result<String, DebtError> {
        self.resolve_owner(file, line, None)
    }
    fn resolve_owner(
        &self,
        file: &str,
        line: usize,
        column: Option<usize>,
    ) -> Result<String, DebtError> {
        if self.unbound_files.contains(file) {
            return Err(DebtError::Policy(format!(
                "undeclared production module owner: {file}"
            )));
        }
        let owners = self.owners.get(file).ok_or_else(|| {
            DebtError::Policy(format!("missing production owner discovery for {file}"))
        })?;
        let matches: Vec<_> = owners
            .iter()
            .filter(|owner| {
                owner.start.line <= line
                    && owner.end.line >= line
                    && column.is_none_or(|column| {
                        (line > owner.start.line || column >= owner.start.column)
                            && (line < owner.end.line || column <= owner.end.column)
                    })
            })
            .collect();
        let nearest = matches
            .iter()
            .min_by_key(|owner| {
                (
                    owner.end.line - owner.start.line,
                    owner.end.column.saturating_sub(owner.start.column),
                )
            })
            .ok_or_else(|| {
                DebtError::Policy(format!("missing rule owner at {file}:{line}:{column:?}"))
            })?;
        if column.is_none()
            && matches.iter().any(|owner| {
                owner.name != nearest.name
                    && (owner.start > nearest.start || owner.end < nearest.end)
            })
        {
            return Err(DebtError::Policy(format!(
                "ambiguous line-only rule owner at {file}:{line}"
            )));
        }
        if matches.iter().any(|owner| {
            owner.start == nearest.start && owner.end == nearest.end && owner.name != nearest.name
        }) {
            return Err(DebtError::Policy(format!(
                "ambiguous compilation-target owner at {file}:{line}:{column:?}"
            )));
        }
        Ok(nearest.name.clone())
    }
}
struct AliasCollector<'a> {
    aliases: &'a mut BTreeMap<String, Vec<syn::Type>>,
    projections: &'a mut BTreeMap<String, BTreeSet<String>>,
    inherent_methods: &'a mut BTreeMap<String, BTreeSet<String>>,
    prefix: Vec<String>,
}
pub(super) fn implementation_name(item: &syn::ItemImpl) -> String {
    let ty = semantic_tokens(&item.self_ty).replace(' ', "");
    if let Some((_, path, _)) = &item.trait_ {
        format!("<{ty} as {}>", semantic_tokens(&path).replace(' ', ""))
    } else {
        ty
    }
}
impl<'ast> Visit<'ast> for AliasCollector<'_> {
    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        if !test_only(&item.attrs) {
            self.inherent_methods
                .entry(format!(
                    "{}::{}",
                    self.prefix.join("::"),
                    item.ident.unraw()
                ))
                .or_default();
            visit::visit_item_struct(self, item);
        }
    }
    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        if !test_only(&item.attrs) {
            self.inherent_methods
                .entry(format!(
                    "{}::{}",
                    self.prefix.join("::"),
                    item.ident.unraw()
                ))
                .or_default();
            visit::visit_item_enum(self, item);
        }
    }
    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if test_only(&item.attrs) {
            return;
        }
        self.prefix.push(implementation_name(item));
        // Unconditional inherent methods stop lookup before Deref/traits.
        let conditional = |attrs: &[syn::Attribute]| {
            attrs.iter().any(|attribute| {
                attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr")
            })
        };
        if item.trait_.is_none()
            && item.generics.type_params().next().is_none()
            && !conditional(&item.attrs)
        {
            for member in &item.items {
                if let syn::ImplItem::Fn(method) = member
                    && !test_only(&method.attrs)
                    && !conditional(&method.attrs)
                {
                    self.inherent_methods
                        .entry(self.prefix.join("::"))
                        .or_default()
                        .insert(method.sig.ident.unraw().to_string());
                }
            }
        }
        if let Some((_, trait_path, _)) = &item.trait_ {
            let trait_name = trait_path
                .segments
                .iter()
                .map(|segment| segment.ident.unraw().to_string())
                .collect::<Vec<_>>()
                .join("::");
            let scope = self.prefix.join("::");
            let inherent_scope = self.prefix[..self.prefix.len() - 1]
                .iter()
                .cloned()
                .chain(std::iter::once(
                    semantic_tokens(&item.self_ty).replace(' ', ""),
                ))
                .collect::<Vec<_>>()
                .join("::");
            for associated in &item.items {
                if let syn::ImplItem::Type(associated) = associated
                    && !test_only(&associated.attrs)
                {
                    let target = format!("{scope}::{}", associated.ident.unraw());
                    for key in [
                        format!(
                            "{scope}::<Self as {trait_name}>::{}",
                            associated.ident.unraw()
                        ),
                        format!("{scope}::{trait_name}::{}", associated.ident.unraw()),
                        format!(
                            "{inherent_scope}::<Self as {trait_name}>::{}",
                            associated.ident.unraw()
                        ),
                        format!(
                            "{inherent_scope}::{trait_name}::{}",
                            associated.ident.unraw()
                        ),
                    ] {
                        self.projections
                            .entry(key)
                            .or_default()
                            .insert(target.clone());
                    }
                }
            }
        }
        visit::visit_item_impl(self, item);
        self.prefix.pop();
    }
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if test_only(&item.attrs) {
            return;
        }
        self.prefix.push(item.sig.ident.unraw().to_string());
        visit::visit_item_fn(self, item);
        self.prefix.pop();
    }
    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if test_only(&item.attrs) {
            return;
        }
        self.prefix.push(item.sig.ident.unraw().to_string());
        visit::visit_impl_item_fn(self, item);
        self.prefix.pop();
    }
    fn visit_impl_item_type(&mut self, item: &'ast syn::ImplItemType) {
        if !test_only(&item.attrs) {
            self.aliases
                .entry(format!(
                    "{}::{}",
                    self.prefix.join("::"),
                    item.ident.unraw()
                ))
                .or_default()
                .push(item.ty.clone());
        }
    }
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if test_only(&item.attrs) {
            return;
        }
        self.prefix.push(item.ident.unraw().to_string());
        visit::visit_item_mod(self, item);
        self.prefix.pop();
    }
    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if !test_only(&item.attrs) {
            self.aliases
                .entry(format!(
                    "{}::{}",
                    self.prefix.join("::"),
                    item.ident.unraw()
                ))
                .or_default()
                .push((*item.ty).clone());
        }
    }
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if test_only(&item.attrs) {
            return;
        }
        fn imports(
            tree: &syn::UseTree,
            prefix: TokenStream,
            aliases: &mut BTreeMap<String, Vec<syn::Type>>,
            scope: &str,
        ) {
            match tree {
                syn::UseTree::Path(path) => {
                    let ident = &path.ident;
                    imports(&path.tree, quote::quote!(#prefix #ident ::), aliases, scope);
                }
                syn::UseTree::Group(group) => {
                    for child in &group.items {
                        imports(child, prefix.clone(), aliases, scope);
                    }
                }
                syn::UseTree::Name(name) => {
                    let ident = &name.ident;
                    if let Ok(ty) = syn::parse2(quote::quote!(#prefix #ident)) {
                        aliases
                            .entry(format!("{scope}::{}", ident.unraw()))
                            .or_default()
                            .push(ty);
                    }
                }
                syn::UseTree::Rename(rename) => {
                    let ident = &rename.ident;
                    if let Ok(ty) = syn::parse2(quote::quote!(#prefix #ident)) {
                        aliases
                            .entry(format!("{scope}::{}", rename.rename.unraw()))
                            .or_default()
                            .push(ty);
                    }
                }
                _ => {}
            }
        }
        imports(
            &item.tree,
            TokenStream::new(),
            self.aliases,
            &self.prefix.join("::"),
        );
    }
}
fn type_alias_keys(path: &syn::TypePath, scope: &str) -> (String, Vec<String>) {
    let mut path_name = path
        .path
        .segments
        .iter()
        .map(|s| s.ident.unraw().to_string())
        .collect::<Vec<_>>()
        .join("::");
    if let Some(qualified) = &path.qself {
        let ty = semantic_tokens(&qualified.ty).replace(' ', "");
        let trait_name = path
            .path
            .segments
            .iter()
            .take(qualified.position)
            .map(|segment| segment.ident.unraw().to_string())
            .collect::<Vec<_>>()
            .join("::");
        let associated = path
            .path
            .segments
            .iter()
            .skip(qualified.position)
            .map(|segment| segment.ident.unraw().to_string())
            .collect::<Vec<_>>()
            .join("::");
        path_name = if qualified.position == 0 {
            format!("<{ty}>::{associated}")
        } else {
            format!("<{ty} as {trait_name}>::{associated}")
        };
    }
    let mut prefix = scope.to_owned();
    let mut keys = Vec::new();
    loop {
        keys.push(format!("{prefix}::{path_name}"));
        let Some((parent, _)) = prefix.rsplit_once("::") else {
            break;
        };
        prefix = parent.to_owned();
    }
    if path_name.starts_with("crate::") {
        keys.push(format!(
            "{}::{}",
            scope.split("::").next().unwrap_or(scope),
            path_name.trim_start_matches("crate::")
        ));
    }
    if path_name.starts_with("self::") {
        keys.push(format!(
            "{}::{}",
            scope,
            path_name.trim_start_matches("self::")
        ));
    }
    if let Some(relative) = path_name.strip_prefix("Self::") {
        keys.push(format!("{}::{relative}", scope));
    }
    let mut relative = path_name.as_str();
    let mut parent = scope;
    while let Some(rest) = relative.strip_prefix("super::") {
        parent = parent.rsplit_once("::").map_or(parent, |(outer, _)| outer);
        relative = rest;
    }
    if relative != path_name {
        keys.push(format!("{parent}::{relative}"));
    }
    keys.push(path_name.clone());
    (path_name, keys)
}

fn authority_type(
    ty: &syn::Type,
    aliases: &BTreeMap<String, Vec<syn::Type>>,
    projections: &BTreeMap<String, BTreeSet<String>>,
    scope: &str,
    seen: &mut Vec<String>,
    names: &[&str],
    deny_unresolved_projection: bool,
) -> bool {
    struct Types<'a> {
        aliases: &'a BTreeMap<String, Vec<syn::Type>>,
        projections: &'a BTreeMap<String, BTreeSet<String>>,
        scope: &'a str,
        seen: &'a mut Vec<String>,
        names: &'a [&'a str],
        protected: bool,
        deny_unresolved_projection: bool,
    }
    impl<'ast> Visit<'ast> for Types<'_> {
        fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
            for segment in &path.path.segments {
                let name = segment.ident.unraw().to_string();
                if self.names.contains(&name.as_str()) {
                    self.protected = true;
                }
            }
            let (path_name, keys) = type_alias_keys(path, self.scope);
            let projection = path.qself.is_some()
                || path_name.starts_with("Self::")
                || self
                    .projections
                    .keys()
                    .any(|key| key.ends_with(&format!("::{path_name}")));
            let mut resolved = false;
            let keys = keys.into_iter().flat_map(|key| {
                self.projections
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| BTreeSet::from([key]))
            });
            for key in keys {
                if let Some(alternatives) = self.aliases.get(&key) {
                    resolved = true;
                    if self.seen.contains(&key) {
                        self.protected = true;
                        break;
                    }
                    self.seen.push(key.clone());
                    for alias in alternatives {
                        self.protected |= authority_type(
                            alias,
                            self.aliases,
                            self.projections,
                            key.rsplit_once("::").map_or(self.scope, |(scope, _)| scope),
                            self.seen,
                            self.names,
                            self.deny_unresolved_projection,
                        );
                    }
                    self.seen.pop();
                }
            }
            if projection && !resolved && self.deny_unresolved_projection {
                // A projection cannot confer authority by being opaque. The
                // FileTable definition must resolve it or name a capability.
                self.protected = true;
            }
            visit::visit_type_path(self, path);
        }
    }
    let mut visitor = Types {
        aliases,
        projections,
        scope,
        seen,
        names,
        protected: false,
        deny_unresolved_projection,
    };
    visitor.visit_type(ty);
    visitor.protected
}
// An unrelated receiver requires an unconditional inherent method proof.
// An opaque binding is unresolved, never silently exempted from the census.
#[derive(Clone, Default)]
struct ReceiverAuthority {
    description: bool,
    file_table: bool,
    kernel: bool,
    inherent_methods: BTreeSet<String>,
}
type ReceiverBindings = BTreeMap<String, Option<ReceiverAuthority>>;

struct Scanner<'a> {
    census: &'a mut SourceCensus,
    file: String,
    krate: String,
    modules: Vec<String>,
    implementation: Option<String>,
    implementation_type: Option<syn::Type>,
    current_owner: Option<String>,
    bindings: ReceiverBindings,
    generic_types: BTreeSet<String>,
}
impl Scanner<'_> {
    fn receiver_authority(&self, ty: &syn::Type) -> ReceiverAuthority {
        let scope = self.scope();
        let protected = |names: &[&str]| {
            authority_type(
                ty,
                &self.census.aliases,
                &self.census.projections,
                &scope,
                &mut Vec::new(),
                names,
                false,
            )
        };
        let mut result = ReceiverAuthority {
            description: protected(&["FileDescription", "OpenDescriptionRef"]),
            file_table: protected(&["FileTable"]),
            kernel: protected(&["Kernel"]),
            ..ReceiverAuthority::default()
        };
        let mut concrete = ty;
        while let syn::Type::Reference(reference) = concrete {
            concrete = &reference.elem;
        }
        if let syn::Type::Path(path) = concrete
            && path.qself.is_none()
            && path
                .path
                .segments
                .iter()
                .all(|segment| matches!(segment.arguments, syn::PathArguments::None))
        {
            let (_, keys) = type_alias_keys(path, &scope);
            for key in keys {
                if let Some(methods) = self.census.inherent_methods.get(&key) {
                    result.inherent_methods = methods.clone();
                    break;
                }
                if self.census.aliases.contains_key(&key) {
                    // Do not inherit an outer type's exemption through a
                    // nearer alias whose concrete receiver is unresolved.
                    break;
                }
            }
        }
        result
    }
    fn parameter_bindings(&mut self, signature: &syn::Signature) -> ReceiverBindings {
        let previous = std::mem::take(&mut self.bindings);
        for input in &signature.inputs {
            if let syn::FnArg::Typed(argument) = input {
                if let syn::Pat::Ident(binding) = argument.pat.as_ref() {
                    let authority = self.receiver_authority(&argument.ty);
                    let mut generics = self.generic_types.clone();
                    generics.extend(
                        signature
                            .generics
                            .type_params()
                            .map(|parameter| parameter.ident.unraw().to_string()),
                    );
                    struct Unresolved<'a> {
                        generics: &'a BTreeSet<String>,
                        aliases: &'a BTreeMap<String, Vec<syn::Type>>,
                        scope: &'a str,
                        seen: BTreeSet<String>,
                        protected: bool,
                        found: bool,
                    }
                    impl<'ast> Visit<'ast> for Unresolved<'_> {
                        fn visit_type_impl_trait(&mut self, _: &'ast syn::TypeImplTrait) {
                            self.found = true;
                        }
                        fn visit_type_trait_object(&mut self, _: &'ast syn::TypeTraitObject) {
                            self.found = true;
                        }
                        fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
                            self.found |= self.protected && path.path.segments.iter().any(|segment| matches!(&segment.arguments, syn::PathArguments::AngleBracketed(arguments) if arguments.args.iter().any(|argument| matches!(argument, syn::GenericArgument::Type(_)))));
                            self.found |= path.qself.is_some()
                                || path.path.segments.first().is_some_and(|segment| {
                                    self.generics.contains(&segment.ident.unraw().to_string())
                                        || (segment.ident.unraw() == "Self"
                                            && path.path.segments.len() > 1)
                                });
                            let (_, keys) = type_alias_keys(path, self.scope);
                            for key in keys {
                                if let Some(types) = self.aliases.get(&key) {
                                    if !self.seen.insert(key.clone()) {
                                        self.found = true;
                                        continue;
                                    }
                                    for ty in types {
                                        self.visit_type(ty);
                                    }
                                    self.seen.remove(&key);
                                }
                            }
                            visit::visit_type_path(self, path);
                        }
                    }
                    let scope = self.scope();
                    let mut unresolved = Unresolved {
                        generics: &generics,
                        aliases: &self.census.aliases,
                        scope: &scope,
                        seen: BTreeSet::new(),
                        protected: authority.description
                            || authority.file_table
                            || authority.kernel,
                        found: false,
                    };
                    unresolved.visit_type(&argument.ty);
                    let generic = unresolved.found;
                    self.bindings.insert(
                        binding.ident.unraw().to_string(),
                        if generic { None } else { Some(authority) },
                    );
                }
            } else if let Some(ty) = &self.implementation_type {
                let authority = self.receiver_authority(ty);
                self.bindings.insert(
                    "self".into(),
                    if self.generic_types.is_empty() {
                        Some(authority)
                    } else {
                        None
                    },
                );
            }
        }
        previous
    }
    fn description_receiver(&self, receiver: &syn::Expr) -> Option<ReceiverAuthority> {
        match receiver {
            syn::Expr::Reference(reference) => self.description_receiver(&reference.expr),
            syn::Expr::Paren(paren) => self.description_receiver(&paren.expr),
            syn::Expr::Group(group) => self.description_receiver(&group.expr),
            syn::Expr::Path(path) if path.path.segments.len() == 1 => self
                .bindings
                .get(&path.path.segments[0].ident.unraw().to_string())
                .cloned()
                .flatten(),
            _ => None,
        }
    }
    fn shadow_pattern(&mut self, pattern: &syn::Pat) {
        struct Bindings<'a>(&'a mut ReceiverBindings);
        impl<'ast> Visit<'ast> for Bindings<'_> {
            fn visit_pat_ident(&mut self, binding: &'ast syn::PatIdent) {
                self.0.insert(binding.ident.unraw().to_string(), None);
                visit::visit_pat_ident(self, binding);
            }
        }
        Bindings(&mut self.bindings).visit_pat(pattern);
    }
    fn owner(&mut self, name: &str, span: Span) -> String {
        let mut parts = vec![self.krate.clone()];
        parts.extend(self.modules.clone());
        if let Some(implementation) = &self.implementation {
            parts.push(implementation.clone());
        }
        parts.push(name.to_owned());
        let name = self
            .current_owner
            .as_ref()
            .map_or_else(|| parts.join("::"), |parent| format!("{parent}::{name}"));
        let lane = self.lane();
        self.census
            .owners
            .entry(self.file.clone())
            .or_default()
            .push(Owner {
                name: name.clone(),
                lane,
                start: span.start(),
                end: span.end(),
            });
        name
    }
    fn macro_tokens(&mut self, tokens: TokenStream) {
        let tokens = macro_input_tokens(tokens);
        // Literal Rust items retain their module, trait and impl boundaries.
        // Expression-style macro inputs fall through to the token-tree walker.
        if let Ok(syntax) = syn::parse2::<syn::File>(tokens.clone()) {
            if test_only(&syntax.attrs) {
                self.test_span(syntax.span());
                return;
            }
            let prefix = self.scope().split("::").map(str::to_owned).collect();
            AliasCollector {
                aliases: &mut self.census.aliases,
                projections: &mut self.census.projections,
                inherent_methods: &mut self.census.inherent_methods,
                prefix,
            }
            .visit_file(&syntax);
            self.visit_file(&syntax);
            return;
        }
        let tokens: Vec<_> = tokens.into_iter().collect();
        let mut index = 0;
        while index < tokens.len() {
            if matches!(&tokens[index], TokenTree::Ident(name) if name.unraw() == "mod" || name.unraw() == "impl" || name.unraw() == "trait")
            {
                self.census
                    .unknown_apis
                    .push(format!("unclassified macro item scope in {}", self.file));
                return;
            }
            if matches!(&tokens[index], TokenTree::Ident(i) if i.unraw() == "fn")
                && let Some(TokenTree::Ident(name)) = tokens.get(index + 1)
                && let Some((offset, TokenTree::Group(body))) = tokens[index + 2..].iter().enumerate().find(|(_, token)| matches!(token, TokenTree::Group(group) if group.delimiter() == Delimiter::Brace))
            {
                let span = tokens[index].span().join(body.span()).unwrap_or(body.span());
                let owner = self.owner(&name.unraw().to_string(), span);
                let previous = self.current_owner.replace(owner);
                self.macro_tokens(body.stream());
                self.current_owner = previous;
                index += offset + 3;
                continue;
            }
            if matches!(&tokens[index], TokenTree::Ident(name) if name.unraw() == "static")
                && let Some(TokenTree::Ident(name)) = tokens.get(index + 1)
                && let Some(end) = tokens[index + 2..]
                    .iter()
                    .position(|token| matches!(token, TokenTree::Punct(p) if p.as_char() == ';'))
            {
                let end = index + 2 + end;
                let span = tokens[index]
                    .span()
                    .join(tokens[end].span())
                    .unwrap_or(name.span());
                let owner = self.owner(&name.unraw().to_string(), span);
                let previous = self.current_owner.replace(owner);
                self.macro_tokens(tokens[index + 2..end].iter().cloned().collect());
                self.current_owner = previous;
                index = end + 1;
                continue;
            }
            if let TokenTree::Group(group) = &tokens[index] {
                self.macro_tokens(group.stream());
            }
            if let TokenTree::Ident(method) = &tokens[index] {
                let method_name = method.unraw().to_string();
                if matches!(tokens.get(index + 1), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis)
                    || matches!(tokens.get(index + 1), Some(TokenTree::Punct(p)) if p.as_char() == ':')
                {
                    self.task_call(&method_name);
                }
                match self.census.vocabulary.get(&method_name) {
                    Some(AuthorityOperation::K1) => self.call(&method_name, method.span()),
                    Some(
                        AuthorityOperation::DescriptionIo
                        | AuthorityOperation::DescriptionGuard
                        | AuthorityOperation::FileLifecycle,
                    ) => {
                        self.census.unknown_apis.push(format!("{}:{}: unresolved authority receiver in opaque macro for {method_name}", self.file, method.span().start().line));
                    }
                    _ => {}
                }
            }
            index += 1;
        }
    }
    fn test_span(&mut self, span: Span) {
        self.census
            .test_ranges
            .entry(self.file.clone())
            .or_default()
            .push((span.start(), span.end()));
    }
    fn lane(&self) -> Lane {
        if self.census.is_build_file(&self.file) {
            Lane::BuildTime
        } else {
            Lane::module(&self.krate, &self.modules)
        }
    }
    fn prefix(&self) -> String {
        std::iter::once(self.krate.as_str())
            .chain(self.modules.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join("::")
    }
    fn scope(&self) -> String {
        self.current_owner.clone().unwrap_or_else(|| {
            let prefix = self.prefix();
            self.implementation.as_ref().map_or_else(
                || prefix.clone(),
                |implementation| format!("{prefix}::{implementation}"),
            )
        })
    }
    fn task_call(&mut self, operation: &str) {
        if self.census.vocabulary.get(operation) != Some(&AuthorityOperation::Task) {
            return;
        }
        let Some(owner) = &self.current_owner else {
            return;
        };
        let forbidden = (operation == "threads"
            && owner.starts_with("carrick_kernel::kernel::crash_capture::"))
            || (operation == "live"
                && [
                    "carrick_kernel::dispatch::mm_quiesce::",
                    "carrick_runtime::vcpu_loop::quiesce::",
                ]
                .iter()
                .any(|prefix| owner.starts_with(prefix)))
            || ([
                "enter_crash_safe_point_participation",
                "leave_crash_safe_point_participation",
            ]
            .contains(&operation)
                && ![
                    "carrick_kernel::dispatch::mm_authority::MmExecutorAdmissionRecipe::enter",
                    "carrick_kernel::kernel::objects::Thread::enter_crash_safe_point_participation",
                ]
                .contains(&owner.as_str()));
        if forbidden {
            self.census
                .structural_errors
                .push(format!("{owner}: forbidden task authority {operation}"));
        }
    }
    fn call(&mut self, operation: &str, span: Span) {
        let Some(owner) = &self.current_owner else {
            self.census
                .unknown_apis
                .push(format!("{operation} has no production owner"));
            return;
        };
        if self.census.unbound_files.contains(&self.file) {
            self.census
                .unknown_apis
                .push(format!("undeclared authority module: {}", self.file));
            return;
        }
        if DEFINITION_OWNERS.contains(&owner.as_str()) {
            return;
        }
        self.census.k1.push(ApiSite {
            file: self.file.clone(),
            line: span.start().line,
            owner: owner.clone(),
            operation: operation.into(),
            lane: self.lane(),
        });
    }
}
impl<'ast> Visit<'ast> for Scanner<'_> {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if test_only(&item.attrs) {
            self.test_span(item.span());
            return;
        }
        let previous = self.current_owner.take();
        self.current_owner = previous
            .as_ref()
            .map(|parent| format!("{parent}::{}", item.ident.unraw()));
        self.modules.push(item.ident.unraw().to_string());
        visit::visit_item_mod(self, item);
        self.modules.pop();
        self.current_owner = previous;
    }
    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if test_only(&item.attrs) {
            self.test_span(item.span());
            return;
        }
        let previous_generics = std::mem::replace(
            &mut self.generic_types,
            item.generics
                .type_params()
                .map(|parameter| parameter.ident.unraw().to_string())
                .collect(),
        );
        let previous_type = self.implementation_type.replace((*item.self_ty).clone());
        let name = implementation_name(item);
        let previous = self.implementation.replace(name.clone());
        let previous_owner = self.current_owner.take();
        self.current_owner = previous_owner
            .as_ref()
            .map(|parent| format!("{parent}::{name}"));
        visit::visit_item_impl(self, item);
        self.implementation = previous;
        self.implementation_type = previous_type;
        self.generic_types = previous_generics;
        self.current_owner = previous_owner;
    }
    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        if test_only(&item.attrs) {
            self.test_span(item.span());
            return;
        }
        let previous = self.implementation.replace(item.ident.unraw().to_string());
        let previous_owner = self.current_owner.take();
        self.current_owner = previous_owner
            .as_ref()
            .map(|parent| format!("{parent}::{}", item.ident.unraw()));
        visit::visit_item_trait(self, item);
        self.implementation = previous;
        self.current_owner = previous_owner;
    }
    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if test_only(&item.attrs) {
            self.test_span(item.span());
            return;
        }
        if item.default.is_none() {
            return;
        }
        let owner = self.owner(&item.sig.ident.unraw().to_string(), item.span());
        let previous = self.current_owner.replace(owner);
        let bindings = self.parameter_bindings(&item.sig);
        visit::visit_trait_item_fn(self, item);
        self.bindings = bindings;
        self.current_owner = previous;
    }
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if self.implementation_type.is_some()
            && let Ok(method) = syn::parse2::<syn::ImplItemFn>(item.to_token_stream())
        {
            self.visit_impl_item_fn(&method);
            return;
        }
        if test_only(&item.attrs) {
            self.test_span(item.span());
            return;
        }
        let owner = self.owner(&item.sig.ident.unraw().to_string(), item.span());
        let previous = self.current_owner.replace(owner);
        let bindings = self.parameter_bindings(&item.sig);
        visit::visit_item_fn(self, item);
        self.bindings = bindings;
        self.current_owner = previous;
    }
    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if test_only(&item.attrs) {
            self.test_span(item.span());
            return;
        }
        let owner = self.owner(&item.sig.ident.unraw().to_string(), item.span());
        // A renamed/new guard accessor must not disappear from the closed call
        // census. Existing private implementation helpers and the reservation
        // guard are explicit boundaries rather than migration API calls.
        if self.implementation_type.as_ref().is_some_and(|ty| {
            authority_type(
                ty,
                &self.census.aliases,
                &self.census.projections,
                &self.scope(),
                &mut Vec::new(),
                &["FileTable"],
                false,
            )
        }) {
            let guard = match &item.sig.output {
                syn::ReturnType::Type(_, ty) => authority_type(
                    ty,
                    &self.census.aliases,
                    &self.census.projections,
                    &self.scope(),
                    &mut Vec::new(),
                    &[
                        "RwLock",
                        "Mutex",
                        "MutexGuard",
                        "RwLockReadGuard",
                        "RwLockWriteGuard",
                        "FileTableWriteGuard",
                        "FileTableMutexGuard",
                        "FileTableRwWriteGuard",
                        "FileTableStdioGuard",
                    ],
                    true,
                ),
                syn::ReturnType::Default => false,
            };
            if guard && !approved_table_guard(&owner, item) {
                self.census.unknown_apis.push(owner.clone());
            }
        }
        let previous = self.current_owner.replace(owner);
        let bindings = self.parameter_bindings(&item.sig);
        visit::visit_impl_item_fn(self, item);
        self.bindings = bindings;
        self.current_owner = previous;
    }
    fn visit_item_foreign_mod(&mut self, item: &'ast syn::ItemForeignMod) {
        if !test_only(&item.attrs) {
            visit::visit_item_foreign_mod(self, item);
        }
    }
    fn visit_foreign_item_static(&mut self, item: &'ast syn::ForeignItemStatic) {
        if !test_only(&item.attrs) {
            self.owner(&item.ident.unraw().to_string(), item.span());
        }
    }
    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        if test_only(&item.attrs) {
            self.test_span(item.span());
            return;
        }
        let owner = self.owner(&item.ident.unraw().to_string(), item.span());
        let previous = self.current_owner.replace(owner);
        visit::visit_item_static(self, item);
        self.current_owner = previous;
    }
    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        if test_only(&item.attrs) {
            self.test_span(item.span());
            return;
        }
        let owner = self.owner(&item.ident.unraw().to_string(), item.span());
        let previous = self.current_owner.replace(owner);
        visit::visit_item_const(self, item);
        self.current_owner = previous;
    }
    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if test_only(&item.attrs) {
            self.test_span(item.span());
            return;
        }
        let name = item
            .ident
            .as_ref()
            .map(|ident| ident.unraw().to_string())
            .unwrap_or_else(|| semantic_tokens(&item.mac.path));
        let owner = if let Some(owner) = &self.current_owner {
            owner.clone()
        } else {
            self.owner(&name, item.span())
        };
        if item.ident.is_some()
            && contains_authority_tokens(item.mac.tokens.clone(), &self.census.vocabulary)
        {
            self.census.unknown_apis.push(format!(
                "authority macro {owner} has no compiler-resolved call owner"
            ));
        } else if item.ident.is_none() {
            self.visit_macro(&item.mac);
        }
    }
    fn visit_impl_item_macro(&mut self, item: &'ast syn::ImplItemMacro) {
        if !test_only(&item.attrs) {
            self.visit_macro(&item.mac);
        }
    }
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if let Some(input) = super::authority_macro::parse(&mac.path, mac.tokens.clone()) {
            input.visit(self);
        } else {
            self.macro_tokens(mac.tokens.clone());
        }
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref()
            && (path.path.segments.len() > 1
                || self
                    .census
                    .canonical_calls
                    .get(&self.file)
                    .is_some_and(|calls| {
                        calls
                            .iter()
                            .any(|call| call.covers(path.span().byte_range()))
                    }))
            && let Some(segment) = path.path.segments.last()
        {
            self.task_call(&segment.ident.unraw().to_string());
        }
        visit::visit_expr_call(self, call);
    }
    fn visit_block(&mut self, block: &'ast syn::Block) {
        let previous = self.bindings.clone();
        visit::visit_block(self, block);
        self.bindings = previous;
    }
    fn visit_local(&mut self, local: &'ast syn::Local) {
        visit::visit_local(self, local);
        if let syn::Pat::Ident(binding) = &local.pat {
            let authority = local
                .init
                .as_ref()
                .and_then(|init| self.description_receiver(&init.expr));
            self.bindings
                .insert(binding.ident.unraw().to_string(), authority);
        } else {
            self.shadow_pattern(&local.pat);
        }
    }
    fn visit_expr_closure(&mut self, expression: &'ast syn::ExprClosure) {
        let previous = self.bindings.clone();
        for input in &expression.inputs {
            self.shadow_pattern(input);
        }
        visit::visit_expr_closure(self, expression);
        self.bindings = previous;
    }
    fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
        let previous = self.bindings.clone();
        self.shadow_pattern(&expression.pat);
        visit::visit_expr_for_loop(self, expression);
        self.bindings = previous;
    }
    fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
        self.visit_expr(&expression.expr);
        for arm in &expression.arms {
            let previous = self.bindings.clone();
            self.shadow_pattern(&arm.pat);
            visit::visit_arm(self, arm);
            self.bindings = previous;
        }
    }
    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        let previous = self.bindings.clone();
        visit::visit_expr_if(self, expression);
        self.bindings = previous;
    }
    fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
        let previous = self.bindings.clone();
        visit::visit_expr_while(self, expression);
        self.bindings = previous;
    }
    fn visit_expr_let(&mut self, expression: &'ast syn::ExprLet) {
        self.visit_expr(&expression.expr);
        self.shadow_pattern(&expression.pat);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.unraw().to_string();
        self.task_call(&method);
        let kind = self.census.vocabulary.get(&method).copied();
        if kind == Some(AuthorityOperation::K1) {
            self.call(&method, call.method.span());
        } else if matches!(
            kind,
            Some(AuthorityOperation::DescriptionIo | AuthorityOperation::DescriptionGuard)
        ) && call.args.is_empty()
        {
            match self.description_receiver(&call.receiver) {
                Some(authority) if authority.description => self.call(&method, call.method.span()),
                Some(authority) if authority.inherent_methods.contains(&method) => {}
                _ => self.census.unknown_apis.push(format!(
                    "{}:{}: unresolved authority receiver for {method}",
                    self.file,
                    call.method.span().start().line
                )),
            }
        } else if kind == Some(AuthorityOperation::FileLifecycle) {
            // Lifecycle receiver calls require an explicit FileTable/Kernel
            // receiver. Other concrete receivers are not this authority.
            match self.description_receiver(&call.receiver) {
                Some(authority)
                    if if method == "copy_file_table_for_host_fork" {
                        authority.kernel
                    } else {
                        authority.file_table
                    } =>
                {
                    self.call(&method, call.method.span())
                }
                Some(authority) if authority.inherent_methods.contains(&method) => {}
                _ => self.census.unknown_apis.push(format!(
                    "{}:{}: unresolved authority receiver for {method}",
                    self.file,
                    call.method.span().start().line
                )),
            }
        }
        visit::visit_expr_method_call(self, call);
    }
    fn visit_expr(&mut self, expression: &'ast syn::Expr) {
        if expression_test_only(expression) {
            self.test_span(expression.span());
        } else {
            visit::visit_expr(self, expression);
        }
    }
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if path
            .path
            .segments
            .iter()
            .any(|segment| segment.ident.unraw() == "OpenDescriptionRef")
        {
            self.call("OpenDescriptionRef", path.span());
        } else if let Some(segment) = path.path.segments.last() {
            let operation = segment.ident.unraw().to_string();
            let kind = self.census.vocabulary.get(&operation).copied();
            let names: &[&str] = match kind {
                Some(AuthorityOperation::FileLifecycle)
                    if operation == "copy_file_table_for_host_fork" =>
                {
                    &["Kernel"]
                }
                Some(AuthorityOperation::FileLifecycle) => &["FileTable"],
                Some(AuthorityOperation::DescriptionIo | AuthorityOperation::DescriptionGuard) => {
                    &["FileDescription", "OpenDescriptionRef"]
                }
                _ => &[],
            };
            let mut receiver_path = path.path.clone();
            receiver_path.segments.pop();
            receiver_path.segments.pop_punct();
            let protected_receiver = !receiver_path.segments.is_empty()
                && authority_type(
                    &syn::Type::Path(syn::TypePath {
                        qself: path.qself.clone(),
                        path: receiver_path,
                    }),
                    &self.census.aliases,
                    &self.census.projections,
                    &self.scope(),
                    &mut Vec::new(),
                    names,
                    false,
                );
            if kind == Some(AuthorityOperation::K1) || (!names.is_empty() && protected_receiver) {
                self.call(&operation, path.span());
            }
        }
        visit::visit_expr_path(self, path);
    }
}

fn census_inputs() -> BTreeMap<&'static str, String> {
    [
        (
            "rust-toolchain.toml",
            include_bytes!("../../../rust-toolchain.toml").as_slice(),
        ),
        (
            "crates/carrick-xtask/src/lib.rs",
            include_bytes!("lib.rs").as_slice(),
        ),
        (
            "Cargo.lock",
            include_bytes!("../../../Cargo.lock").as_slice(),
        ),
        (
            "crates/carrick-xtask/src/authority_debt.rs",
            include_bytes!("authority_debt.rs").as_slice(),
        ),
        (
            "crates/carrick-xtask/src/cli.rs",
            include_bytes!("cli.rs").as_slice(),
        ),
        (
            "crates/carrick-xtask/src/authority_source.rs",
            include_bytes!("authority_source.rs").as_slice(),
        ),
        (
            "crates/carrick-xtask/src/authority_build.rs",
            include_bytes!("authority_build.rs").as_slice(),
        ),
        (
            "crates/carrick-xtask/src/authority_dialect.rs",
            include_bytes!("authority_dialect.rs").as_slice(),
        ),
        (
            "scripts/migrate/authority-vocabulary.json",
            include_bytes!("../../../scripts/migrate/authority-vocabulary.json").as_slice(),
        ),
        (
            "crates/carrick-xtask/src/authority_macro.rs",
            include_bytes!("authority_macro.rs").as_slice(),
        ),
        (
            "scripts/migrate/authority-macro-allowlist.json",
            include_bytes!("../../../scripts/migrate/authority-macro-allowlist.json").as_slice(),
        ),
        (
            "scripts/migrate/authority-attribute-allowlist.json",
            include_bytes!("../../../scripts/migrate/authority-attribute-allowlist.json")
                .as_slice(),
        ),
    ]
    .into_iter()
    .map(|(file, bytes)| (file, source_hash(bytes)))
    .collect()
}
