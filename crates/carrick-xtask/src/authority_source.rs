//! Syntax-resolved production owners and legacy authority API calls.
//! Locations only bind ephemeral diagnostics to symbols; they are never saved.
use crate::authority_debt::{DebtError, Lane};
use proc_macro2::{Delimiter, LineColumn, Span, TokenStream, TokenTree};
use quote::ToTokens;
use std::collections::BTreeMap;
use std::path::Path;
use syn::{
    spanned::Spanned,
    visit::{self, Visit},
};

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
    start: LineColumn,
    end: LineColumn,
}
#[derive(Debug, Default)]
pub struct SourceCensus {
    test_files: std::collections::BTreeSet<String>,
    owners: BTreeMap<String, Vec<Owner>>,
    pub k1: Vec<ApiSite>,
    unknown_apis: Vec<String>,
}
const TABLE_APIS: &[&str] = &[
    "read_open_files",
    "write_open_files",
    "lock_next_fd",
    "lock_stdio_cloexec",
    "lock_closed_stdio",
    "read_fd_open_paths",
    "write_fd_open_paths",
    "lock_splice_pushback",
    "read_epoll_fds",
    "write_epoll_fds",
    "epoll_wake_registry",
    "nofile_soft",
    "set_nofile_soft",
];

// Closed implementation owners, not source paths. Calls made inside these
// authority primitives are definitions rather than legacy caller debt.
const DEFINITION_OWNERS: &[&str] = &[
    "carrick_kernel::FileTable::commit_exact_replacement",
    "carrick_kernel::FileTable::commit_reserved_slot",
    "carrick_kernel::FileTable::epoll_wake_handle",
    "carrick_kernel::FileTable::epoll_wake_registry",
    "carrick_kernel::FileTable::for_exec",
    "carrick_kernel::FileTable::for_fork_copy",
    "carrick_kernel::FileTable::install",
    "carrick_kernel::FileTable::is_bare_stdio_open",
    "carrick_kernel::FileTable::lock_closed_stdio",
    "carrick_kernel::FileTable::lock_next_fd",
    "carrick_kernel::FileTable::lock_stdio_cloexec",
    "carrick_kernel::FileTable::read_epoll_fds",
    "carrick_kernel::FileTable::read_fd_open_paths",
    "carrick_kernel::FileTable::read_open_files",
    "carrick_kernel::FileTable::record_fd_open_path",
    "carrick_kernel::FileTable::rename_fd_open_paths",
    "carrick_kernel::FileTable::reserve_slot_at_or_above",
    "carrick_kernel::FileTable::with_fd_ceiling",
    "carrick_kernel::FileTable::write_epoll_fds",
    "carrick_kernel::FileTable::write_fd_open_paths",
    "carrick_kernel::FileTable::write_open_files",
    "carrick_kernel::HostSocketAuthority::set_ipv6_v6only",
    "carrick_kernel::OpenFile::is_io_uring_backing",
    "carrick_kernel::OpenFile::record_host_file_absolute_offset",
    "carrick_kernel::attach_el1_registration",
    "carrick_kernel::crate::kernel::FileDescription::inspect",
    "carrick_kernel::crate::kernel::FileDescription::open_description",
    "carrick_kernel::crate::kernel::FileDescription::read_for_io",
    "carrick_kernel::crate::kernel::FileDescription::try_inspect",
    "carrick_kernel::crate::kernel::FileDescription::write_for_io",
    "carrick_kernel::crate::kernel::FileSlot::from_open_description_with_common",
    "carrick_kernel::crate::kernel::FileSlot::from_open_description_with_status_flags",
    "carrick_kernel::kernel_file_description",
    "carrick_kernel::kernel_file_description_unregistered",
    "carrick_kernel::super::SyscallDispatcher::rename_open_paths",
];

fn test_only(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|a| a.path().is_ident("test") || (a.path().is_ident("cfg") && cfg_false(&a.meta)))
}
fn cfg_false(meta: &syn::Meta) -> bool {
    use syn::parse::Parser;
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::NameValue(nv) => {
            nv.path.is_ident("feature")
                && nv.value.to_token_stream().to_string() == "\"test-support\""
        }
        syn::Meta::List(list) => {
            let Ok(children) =
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
                    .parse2(list.tokens.clone())
            else {
                return false;
            };
            if list.path.is_ident("cfg") || list.path.is_ident("all") {
                children.iter().any(cfg_false)
            } else if list.path.is_ident("any") {
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
fn test_modules(
    items: &[syn::Item],
    directory: &Path,
    explicit_directory: &Path,
    result: &mut Vec<std::path::PathBuf>,
) {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        let explicit = module.attrs.iter().find_map(|attr| {
            if !attr.path().is_ident("path") {
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
        let path = explicit.unwrap_or_else(|| directory.join(module.ident.to_string()));
        if test_only(&module.attrs) {
            result.push(path);
        } else if let Some((_, items)) = &module.content {
            test_modules(items, &path, &path, result);
        }
    }
}
fn contains_authority_tokens(tokens: TokenStream) -> bool {
    tokens.into_iter().any(|token| match token {
        TokenTree::Group(group) => contains_authority_tokens(group.stream()),
        TokenTree::Ident(name) => {
            TABLE_APIS.contains(&name.to_string().as_str())
                || [
                    "OpenDescriptionRef",
                    "open_description",
                    "concrete_backing",
                    "read_for_io",
                    "write_for_io",
                ]
                .contains(&name.to_string().as_str())
        }
        _ => false,
    })
}
impl SourceCensus {
    pub fn load(root: &Path) -> Result<Self, DebtError> {
        let mut result = Self::default();
        let mut leaves = Vec::new();
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
        leaves.sort();
        // Out-of-line test modules are omitted with their entire subtrees.
        let mut test_roots = Vec::new();
        let mut parsed = Vec::new();
        for path in &leaves {
            let source = std::fs::read_to_string(path)?;
            let syntax = syn::parse_file(&source)
                .map_err(|error| DebtError::Policy(format!("{}: {error}", path.display())))?;
            let parent = if matches!(
                path.file_name().and_then(|s| s.to_str()),
                Some("lib.rs" | "mod.rs" | "main.rs")
            ) {
                path.parent()
                    .ok_or_else(|| DebtError::Policy("missing source parent".into()))?
                    .to_path_buf()
            } else {
                path.with_extension("")
            };
            test_modules(
                &syntax.items,
                &parent,
                path.parent()
                    .ok_or_else(|| DebtError::Policy("missing source parent".into()))?,
                &mut test_roots,
            );
            parsed.push((path.clone(), syntax));
        }
        for (path, syntax) in parsed {
            let relative = path
                .strip_prefix(root)
                .map_err(|e| DebtError::Policy(e.to_string()))?
                .to_string_lossy()
                .to_string();
            if (relative.contains("/src/bin/") && !relative.starts_with("crates/carrick-cli/"))
                || test_only(&syntax.attrs)
                || test_roots
                    .iter()
                    .any(|test| path.starts_with(test) || path == test.with_extension("rs"))
            {
                result.test_files.insert(relative);
                continue;
            }
            let krate = relative
                .split('/')
                .nth(1)
                .ok_or_else(|| DebtError::Policy("missing source crate".into()))?
                .replace('-', "_");
            let mut scanner = Scanner {
                census: &mut result,
                file: relative.clone(),
                krate,
                modules: Vec::new(),
                implementation: None,
                current_owner: None,
            };
            scanner.visit_file(&syntax);
        }
        if !result.unknown_apis.is_empty() {
            return Err(DebtError::Policy(format!(
                "unrecognized authority API definitions: {:?}",
                result.unknown_apis
            )));
        }
        Ok(result)
    }
    pub fn is_test_file(&self, file: &str) -> bool {
        self.test_files.contains(file)
    }
    pub fn owner_at(&self, file: &str, line: usize, column: usize) -> Result<String, DebtError> {
        let owners = self.owners.get(file).ok_or_else(|| {
            DebtError::Policy(format!("missing production owner discovery for {file}"))
        })?;
        owners
            .iter()
            .filter(|owner| {
                owner.start.line <= line
                    && owner.end.line >= line
                    && (column == 0
                        || ((line > owner.start.line || column >= owner.start.column)
                            && (line < owner.end.line || column <= owner.end.column)))
            })
            .min_by_key(|owner| {
                (
                    owner.end.line - owner.start.line,
                    owner.end.column.saturating_sub(owner.start.column),
                )
            })
            .map(|owner| owner.name.clone())
            .ok_or_else(|| {
                DebtError::Policy(format!("missing rule owner at {file}:{line}:{column}"))
            })
    }
}
struct Scanner<'a> {
    census: &'a mut SourceCensus,
    file: String,
    krate: String,
    modules: Vec<String>,
    implementation: Option<String>,
    current_owner: Option<String>,
}
impl Scanner<'_> {
    fn owner(&mut self, name: &str, span: Span) -> String {
        // Impl symbols survive file relocation. Local inline module symbols
        // distinguish free owners without admitting source-path exceptions.
        let name = if let Some(implementation) = &self.implementation {
            format!("{}::{implementation}::{name}", self.krate)
        } else if self.modules.is_empty() {
            format!("{}::{name}", self.krate)
        } else {
            format!("{}::{}::{name}", self.krate, self.modules.join("::"))
        };
        self.census
            .owners
            .entry(self.file.clone())
            .or_default()
            .push(Owner {
                name: name.clone(),
                start: span.start(),
                end: span.end(),
            });
        name
    }
    fn macro_tokens(&mut self, tokens: TokenStream) {
        let tokens: Vec<_> = tokens.into_iter().collect();
        let mut index = 0;
        while index < tokens.len() {
            if matches!(&tokens[index], TokenTree::Ident(i) if i == "fn")
                && let Some(TokenTree::Ident(name)) = tokens.get(index + 1)
                && let Some((offset, TokenTree::Group(body))) = tokens[index + 2..].iter().enumerate().find(|(_, token)| matches!(token, TokenTree::Group(group) if group.delimiter() == Delimiter::Brace))
            {
                let span = name.span().join(body.span()).unwrap_or(body.span());
                let owner = self.owner(&name.to_string(), span);
                let previous = self.current_owner.replace(owner);
                self.macro_tokens(body.stream());
                self.current_owner = previous;
                index += offset + 3;
                continue;
            }
            if let TokenTree::Group(group) = &tokens[index] {
                self.macro_tokens(group.stream());
            }
            if let TokenTree::Ident(method) = &tokens[index] {
                let method_name = method.to_string();
                let called = matches!(tokens.get(index + 1), Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Parenthesis);
                let description = index >= 2
                    && matches!(&tokens[index - 2], TokenTree::Ident(i) if i == "description");
                if called
                    && (TABLE_APIS.contains(&method_name.as_str())
                        || ["open_description", "concrete_backing"].contains(&method_name.as_str())
                        || (description
                            && ["read_for_io", "write_for_io", "inspect", "try_inspect"]
                                .contains(&method_name.as_str())))
                {
                    self.call(&method_name, method.span());
                }
            }
            index += 1;
        }
    }
    fn call(&mut self, operation: &str, span: Span) {
        let Some(owner) = &self.current_owner else {
            self.census
                .unknown_apis
                .push(format!("{operation} has no production owner"));
            return;
        };
        if DEFINITION_OWNERS.contains(&owner.as_str()) {
            return;
        }
        self.census.k1.push(ApiSite {
            file: self.file.clone(),
            line: span.start().line,
            owner: owner.clone(),
            operation: operation.into(),
            lane: Lane::source(&self.file),
        });
    }
}
impl<'ast> Visit<'ast> for Scanner<'_> {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if test_only(&item.attrs) {
            return;
        }
        self.modules.push(item.ident.to_string());
        visit::visit_item_mod(self, item);
        self.modules.pop();
    }
    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if test_only(&item.attrs) {
            return;
        }
        let previous = self
            .implementation
            .replace(item.self_ty.to_token_stream().to_string().replace(' ', ""));
        visit::visit_item_impl(self, item);
        self.implementation = previous;
    }
    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        if test_only(&item.attrs) {
            return;
        }
        let previous = self.implementation.replace(item.ident.to_string());
        visit::visit_item_trait(self, item);
        self.implementation = previous;
    }
    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if test_only(&item.attrs) || item.default.is_none() {
            return;
        }
        let owner = self.owner(&item.sig.ident.to_string(), item.span());
        let previous = self.current_owner.replace(owner);
        visit::visit_trait_item_fn(self, item);
        self.current_owner = previous;
    }
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if test_only(&item.attrs) {
            return;
        }
        let owner = self.owner(&item.sig.ident.to_string(), item.span());
        let previous = self.current_owner.replace(owner);
        visit::visit_item_fn(self, item);
        self.current_owner = previous;
    }
    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if test_only(&item.attrs) {
            return;
        }
        // A renamed/new guard accessor must not disappear from the closed call
        // census. Existing private implementation helpers and the reservation
        // guard are explicit boundaries rather than migration API calls.
        if self.implementation.as_deref() == Some("FileTable") {
            let output = item.sig.output.to_token_stream().to_string();
            let guard = [
                "MutexGuard",
                "RwLockReadGuard",
                "RwLockWriteGuard",
                "FileTableWriteGuard",
                "FileTableMutexGuard",
                "FileTableRwWriteGuard",
                "FileTableStdioGuard",
            ]
            .iter()
            .any(|name| {
                output
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .any(|part| part == *name)
            });
            let name = item.sig.ident.to_string();
            if guard
                && !TABLE_APIS.contains(&name.as_str())
                && ![
                    "try_lock_next_fd",
                    "try_mutex_write",
                    "mutex_write",
                    "rw_write",
                    "lock_reserved_slots",
                    "stdio_guard",
                ]
                .contains(&name.as_str())
            {
                self.census
                    .unknown_apis
                    .push(format!("{}::FileTable::{name}", self.krate));
            }
        }
        let owner = self.owner(&item.sig.ident.to_string(), item.span());
        let previous = self.current_owner.replace(owner);
        visit::visit_impl_item_fn(self, item);
        self.current_owner = previous;
    }
    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        if test_only(&item.attrs) {
            return;
        }
        let owner = self.owner(&item.ident.to_string(), item.span());
        let previous = self.current_owner.replace(owner);
        visit::visit_item_static(self, item);
        self.current_owner = previous;
    }
    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        if test_only(&item.attrs) {
            return;
        }
        let owner = self.owner(&item.ident.to_string(), item.span());
        let previous = self.current_owner.replace(owner);
        visit::visit_item_const(self, item);
        self.current_owner = previous;
    }
    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if test_only(&item.attrs) {
            return;
        }
        let name = item
            .ident
            .as_ref()
            .map(|ident| ident.to_string())
            .unwrap_or_else(|| item.mac.path.to_token_stream().to_string());
        let owner = self.owner(&name, item.span());
        if item.ident.is_some() && contains_authority_tokens(item.mac.tokens.clone()) {
            self.census.unknown_apis.push(format!(
                "authority macro {owner} has no compiler-resolved call owner"
            ));
        } else if item.ident.is_none() {
            let previous = self.current_owner.replace(owner);
            self.macro_tokens(item.mac.tokens.clone());
            self.current_owner = previous;
        }
    }
    fn visit_impl_item_macro(&mut self, item: &'ast syn::ImplItemMacro) {
        if !test_only(&item.attrs) {
            self.macro_tokens(item.mac.tokens.clone());
        }
    }
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.macro_tokens(mac.tokens.clone());
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        let description = if let syn::Expr::Field(field) = call.receiver.as_ref() {
            field.member.to_token_stream().to_string() == "description"
        } else {
            false
        };
        if TABLE_APIS.contains(&method.as_str())
            || ["open_description", "concrete_backing"].contains(&method.as_str())
            || (description
                && ["read_for_io", "write_for_io", "inspect", "try_inspect"]
                    .contains(&method.as_str()))
        {
            self.call(&method, call.method.span());
        }
        visit::visit_expr_method_call(self, call);
    }
    fn visit_expr(&mut self, expression: &'ast syn::Expr) {
        macro_rules! attributes {
            ($($kind:ident),*) => { match expression { $(syn::Expr::$kind(value) => &value.attrs,)* _ => &[] } };
        }
        let attributes: &[syn::Attribute] = attributes!(
            Array, Assign, Async, Await, Binary, Block, Break, Call, Cast, Closure, Const,
            Continue, Field, ForLoop, Group, If, Index, Infer, Let, Lit, Loop, Macro, Match,
            MethodCall, Paren, Path, Range, RawAddr, Reference, Repeat, Return, Struct, Try,
            TryBlock, Tuple, Unary, Unsafe, While, Yield
        );
        if !test_only(attributes) {
            visit::visit_expr(self, expression);
        }
    }
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if path
            .path
            .segments
            .iter()
            .any(|segment| segment.ident == "OpenDescriptionRef")
        {
            self.call("OpenDescriptionRef", path.span());
        } else if let Some(segment) = path.path.segments.last() {
            let operation = segment.ident.to_string();
            if TABLE_APIS.contains(&operation.as_str())
                || [
                    "OpenDescriptionRef",
                    "open_description",
                    "concrete_backing",
                    "read_for_io",
                    "write_for_io",
                ]
                .contains(&operation.as_str())
            {
                self.call(&operation, path.span());
            }
        }
        visit::visit_expr_path(self, path);
    }
}
