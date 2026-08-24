use std::fmt;
use std::str::FromStr;

use proc_macro2::{Delimiter, Group, Span, TokenStream, TokenTree};
use syn::visit::Visit;

const WATCHED_EXTERN: &[&str] = &[
    "waitpid",
    "wait4",
    "waitid",
    "kill",
    "killpg",
    "pthread_kill",
    "fork",
    "vfork",
    "execve",
    "posix_spawn",
    "open",
    "openat",
    "close",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "mkdir",
    "mkdirat",
    "rmdir",
    "chdir",
    "fchdir",
    "chroot",
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FindingKind {
    LibcSyscall,
    LibcDlopen,
    LibcDlsym,
    Assembly,
    Extern,
}

impl FindingKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LibcSyscall => "libc_syscall",
            Self::LibcDlopen => "libc_dlopen",
            Self::LibcDlsym => "libc_dlsym",
            Self::Assembly => "assembly",
            Self::Extern => "extern",
        }
    }

    fn for_libc(operation: &str) -> Option<Self> {
        match operation {
            "syscall" => Some(Self::LibcSyscall),
            "dlopen" => Some(Self::LibcDlopen),
            "dlsym" => Some(Self::LibcDlsym),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Finding {
    pub kind: FindingKind,
    pub line: usize,
    pub column: usize,
    pub detail: String,
}

impl Finding {
    fn new(kind: FindingKind, span: Span, detail: String) -> Self {
        let start = span.start();
        Self {
            kind,
            line: start.line,
            column: start.column + 1,
            detail,
        }
    }

    pub fn render_json(&self, path: &str) -> String {
        format!(
            "{{\"path\":\"{}\",\"line\":{},\"column\":{},\"kind\":\"{}\",\"detail\":\"{}\"}}",
            json_escape(path),
            self.line,
            self.column,
            self.kind.as_str(),
            json_escape(&self.detail),
        )
    }

    pub fn render_text(&self, path: &str) -> String {
        format!(
            "{}:{}:{}: {}: {}",
            path,
            self.line,
            self.column,
            self.kind.as_str(),
            self.detail
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanError(String);

impl fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ScanError {}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CarrierProcessFindingKind {
    Fork,
    Vfork,
    PosixSpawn,
    ProcessCommand,
    Clone,
    Forkpty,
    System,
    Popen,
    Daemon,
    Exec,
    Kill,
    KillProbe,
    Killpg,
    PthreadKill,
    Sigqueue,
    Wait,
    Waitpid,
    Wait4,
    Waitid,
    Ptrace,
    Setpgid,
    Setsid,
}

impl CarrierProcessFindingKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fork => "fork",
            Self::Vfork => "vfork",
            Self::PosixSpawn => "posix_spawn",
            Self::ProcessCommand => "process_command",
            Self::Clone => "clone",
            Self::Forkpty => "forkpty",
            Self::System => "system",
            Self::Popen => "popen",
            Self::Daemon => "daemon",
            Self::Exec => "exec",
            Self::Kill => "kill",
            Self::KillProbe => "kill_probe",
            Self::Killpg => "killpg",
            Self::PthreadKill => "pthread_kill",
            Self::Sigqueue => "sigqueue",
            Self::Wait => "wait",
            Self::Waitpid => "waitpid",
            Self::Wait4 => "wait4",
            Self::Waitid => "waitid",
            Self::Ptrace => "ptrace",
            Self::Setpgid => "setpgid",
            Self::Setsid => "setsid",
        }
    }

    fn from_libc_name(name: &str) -> Option<Self> {
        match name {
            "fork" | "_Fork" | "fork1" | "forkx_np" => Some(Self::Fork),
            "vfork" => Some(Self::Vfork),
            "posix_spawn" | "posix_spawnp" => Some(Self::PosixSpawn),
            "clone" | "clone3" | "rfork" | "pdfork" => Some(Self::Clone),
            "forkpty" => Some(Self::Forkpty),
            "system" => Some(Self::System),
            "popen" => Some(Self::Popen),
            "daemon" => Some(Self::Daemon),
            "execl" | "execle" | "execlp" | "execv" | "execve" | "execvp" | "execvpe"
            | "execveat" | "fexecve" => Some(Self::Exec),
            "kill" => Some(Self::Kill),
            "killpg" => Some(Self::Killpg),
            "pthread_kill" => Some(Self::PthreadKill),
            "sigqueue" | "pthread_sigqueue" | "pidfd_send_signal" => Some(Self::Sigqueue),
            "wait" | "wait3" | "wait6" => Some(Self::Wait),
            "waitpid" => Some(Self::Waitpid),
            "wait4" => Some(Self::Wait4),
            "waitid" => Some(Self::Waitid),
            "ptrace" => Some(Self::Ptrace),
            "setpgid" => Some(Self::Setpgid),
            "setsid" => Some(Self::Setsid),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CarrierProcessFinding {
    pub kind: CarrierProcessFindingKind,
    pub line: usize,
    pub column: usize,
    pub detail: String,
    pub enclosing_item: String,
}

impl CarrierProcessFinding {
    fn new(
        kind: CarrierProcessFindingKind,
        span: Span,
        detail: String,
        enclosing_item: String,
    ) -> Self {
        let start = span.start();
        Self {
            kind,
            line: start.line,
            column: start.column + 1,
            detail,
            enclosing_item,
        }
    }

    pub fn render_json(&self, path: &str) -> String {
        format!(
            "{{\"path\":\"{}\",\"line\":{},\"column\":{},\"kind\":\"{}\",\"detail\":\"{}\",\"enclosing_item\":\"{}\"}}",
            json_escape(path),
            self.line,
            self.column,
            self.kind.as_str(),
            json_escape(&self.detail),
            json_escape(&self.enclosing_item),
        )
    }

    pub fn render_text(&self, path: &str) -> String {
        format!(
            "{}:{}:{}: {} in {}: {}",
            path,
            self.line,
            self.column,
            self.kind.as_str(),
            self.enclosing_item,
            self.detail,
        )
    }
}

/// Find host process creation/control calls in production Rust syntax.
///
/// Items guarded by `cfg(test)` are deliberately omitted. File-level fixtures,
/// integration tests, and explicit probe binaries are classified by the caller,
/// which has the repository path needed to do that without guessing.
pub fn scan_carrier_process_source(source: &str) -> Result<Vec<CarrierProcessFinding>, ScanError> {
    let file = syn::parse_file(source)
        .map_err(|error| ScanError(format!("Rust syntax parse failed: {error}")))?;
    let mut aliases = CarrierAliasCollector::default();
    aliases.visit_file(&file);
    let mut scanner = CarrierProcessScanner {
        command_aliases: aliases.command_aliases,
        libc_aliases: aliases.libc_aliases,
        libc_namespaces: aliases.libc_namespaces,
        process_namespaces: aliases.process_namespaces,
        libc_glob: aliases.libc_glob,
        ..CarrierProcessScanner::default()
    };
    scanner.visit_file(&file);
    scan_impl_macros_in_items(&file.items, &mut scanner);
    scanner.findings.sort();
    scanner.findings.dedup();
    Ok(scanner.findings)
}

fn scan_impl_macros_in_items(items: &[syn::Item], scanner: &mut CarrierProcessScanner) {
    for item in items {
        match item {
            syn::Item::Impl(item) if !cfg_test(&item.attrs) => {
                for child in &item.items {
                    let syn::ImplItem::Macro(item) = child else {
                        continue;
                    };
                    if item.mac.path.is_ident("define_syscall") {
                        scanner.scan_define_syscall_tokens(item.mac.tokens.clone());
                    } else {
                        scanner.scan_macro_tokens(item.mac.tokens.clone());
                    }
                }
            }
            syn::Item::Mod(item) if !cfg_test(&item.attrs) => {
                if let Some((_, nested)) = &item.content {
                    scan_impl_macros_in_items(nested, scanner);
                }
            }
            _ => {}
        }
    }
}

#[derive(Default)]
struct CarrierProcessScanner {
    findings: Vec<CarrierProcessFinding>,
    item_stack: Vec<String>,
    command_aliases: std::collections::BTreeSet<String>,
    libc_aliases: std::collections::BTreeMap<String, CarrierProcessFindingKind>,
    libc_namespaces: std::collections::BTreeSet<String>,
    process_namespaces: std::collections::BTreeSet<String>,
    libc_glob: bool,
}

impl CarrierProcessScanner {
    fn enclosing_item(&self) -> String {
        self.item_stack
            .last()
            .cloned()
            .unwrap_or_else(|| "<module>".to_owned())
    }

    fn record(&mut self, kind: CarrierProcessFindingKind, span: Span, detail: String) {
        self.findings.push(CarrierProcessFinding::new(
            kind,
            span,
            detail,
            self.enclosing_item(),
        ));
    }
}

fn cfg_test(attributes: &[syn::Attribute]) -> bool {
    fn test_only(meta: &syn::Meta) -> bool {
        match meta {
            syn::Meta::Path(path) => path.is_ident("test"),
            syn::Meta::NameValue(_) => false,
            syn::Meta::List(list) if list.path.is_ident("all") => list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .is_ok_and(|items| items.iter().any(test_only)),
            syn::Meta::List(list) if list.path.is_ident("any") => list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .is_ok_and(|items| !items.is_empty() && items.iter().all(test_only)),
            syn::Meta::List(_) => false,
        }
    }

    attributes.iter().any(|attribute| match &attribute.meta {
        syn::Meta::List(list) if list.path.is_ident("cfg") => list
            .parse_args::<syn::Meta>()
            .is_ok_and(|meta| test_only(&meta)),
        _ => false,
    })
}

fn path_segments(path: &syn::Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect()
}

fn path_span(path: &syn::Path) -> Span {
    path.segments
        .first()
        .map_or_else(Span::call_site, |segment| segment.ident.span())
}

fn item_attributes(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::ExternCrate(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::ForeignMod(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::TraitAlias(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Union(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn collect_use_tree(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    libc_aliases: &mut std::collections::BTreeMap<String, CarrierProcessFindingKind>,
    command_aliases: &mut std::collections::BTreeSet<String>,
    libc_namespaces: &mut std::collections::BTreeSet<String>,
    process_namespaces: &mut std::collections::BTreeSet<String>,
    libc_glob: &mut bool,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_tree(
                &path.tree,
                prefix,
                libc_aliases,
                command_aliases,
                libc_namespaces,
                process_namespaces,
                libc_glob,
            );
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let mut full = prefix.clone();
            full.push(name.ident.to_string());
            record_process_import(&full, name.ident.to_string(), libc_aliases, command_aliases);
            record_process_namespace(
                &full,
                name.ident.to_string(),
                libc_namespaces,
                process_namespaces,
            );
        }
        syn::UseTree::Rename(rename) => {
            let mut full = prefix.clone();
            full.push(rename.ident.to_string());
            record_process_import(
                &full,
                rename.rename.to_string(),
                libc_aliases,
                command_aliases,
            );
            record_process_namespace(
                &full,
                rename.rename.to_string(),
                libc_namespaces,
                process_namespaces,
            );
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_use_tree(
                    item,
                    prefix,
                    libc_aliases,
                    command_aliases,
                    libc_namespaces,
                    process_namespaces,
                    libc_glob,
                );
            }
        }
        syn::UseTree::Glob(_) => {
            if prefix.as_slice() == ["libc"] {
                *libc_glob = true;
            }
            if matches!(prefix.as_slice(), [root, process] if matches!(root.as_str(), "std" | "tokio") && process == "process")
            {
                command_aliases.insert("Command".to_owned());
            }
        }
    }
}

fn record_process_namespace(
    full: &[String],
    alias: String,
    libc_namespaces: &mut std::collections::BTreeSet<String>,
    process_namespaces: &mut std::collections::BTreeSet<String>,
) {
    if full == ["libc"] || full == ["libc", "self"] {
        libc_namespaces.insert(alias);
    } else if matches!(full, [root, process] if matches!(root.as_str(), "std" | "tokio") && process == "process")
        || matches!(full, [root, process, this] if matches!(root.as_str(), "std" | "tokio") && process == "process" && this == "self")
    {
        process_namespaces.insert(alias);
    }
}

fn record_process_import(
    full: &[String],
    alias: String,
    libc_aliases: &mut std::collections::BTreeMap<String, CarrierProcessFindingKind>,
    command_aliases: &mut std::collections::BTreeSet<String>,
) {
    if full.len() >= 2
        && full[full.len() - 2] == "libc"
        && let Some(kind) = CarrierProcessFindingKind::from_libc_name(&full[full.len() - 1])
    {
        libc_aliases.insert(alias.clone(), kind);
    }
    if full.len() >= 2 && full[full.len() - 2] == "process" && full[full.len() - 1] == "Command" {
        command_aliases.insert(alias);
    }
}

#[derive(Default)]
struct CarrierAliasCollector {
    command_aliases: std::collections::BTreeSet<String>,
    libc_aliases: std::collections::BTreeMap<String, CarrierProcessFindingKind>,
    libc_namespaces: std::collections::BTreeSet<String>,
    process_namespaces: std::collections::BTreeSet<String>,
    libc_glob: bool,
}

impl<'ast> Visit<'ast> for CarrierAliasCollector {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if cfg_test(item_attributes(item)) {
            return;
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if cfg_test(&item.attrs) {
            return;
        }
        collect_use_tree(
            &item.tree,
            &mut Vec::new(),
            &mut self.libc_aliases,
            &mut self.command_aliases,
            &mut self.libc_namespaces,
            &mut self.process_namespaces,
            &mut self.libc_glob,
        );
    }

    fn visit_item_extern_crate(&mut self, item: &'ast syn::ItemExternCrate) {
        if cfg_test(&item.attrs) || item.ident != "libc" {
            return;
        }
        let alias = item
            .rename
            .as_ref()
            .map_or_else(|| item.ident.to_string(), |(_, alias)| alias.to_string());
        self.libc_namespaces.insert(alias);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if cfg_test(&item.attrs) {
            return;
        }
        if let syn::Type::Path(path) = item.ty.as_ref() {
            let segments = path_segments(&path.path);
            if segments.ends_with(&["process".to_owned(), "Command".to_owned()]) {
                self.command_aliases.insert(item.ident.to_string());
            }
        }
        syn::visit::visit_item_type(self, item);
    }
}

impl<'ast> Visit<'ast> for CarrierProcessScanner {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if cfg_test(item_attributes(item)) {
            return;
        }
        if let syn::Item::Verbatim(tokens) = item {
            self.scan_macro_tokens(tokens.clone());
            return;
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if cfg_test(&item.attrs) {
            return;
        }
        self.item_stack.push(item.sig.ident.to_string());
        syn::visit::visit_item_fn(self, item);
        self.item_stack.pop();
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if cfg_test(&item.attrs) {
            return;
        }
        self.item_stack.push(item.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, item);
        self.item_stack.pop();
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if cfg_test(&item.attrs) {
            return;
        }
        for child in &item.items {
            self.visit_impl_item(child);
        }
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if cfg_test(&item.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if cfg_test(&item.attrs) {
            return;
        }
        collect_use_tree(
            &item.tree,
            &mut Vec::new(),
            &mut self.libc_aliases,
            &mut self.command_aliases,
            &mut self.libc_namespaces,
            &mut self.process_namespaces,
            &mut self.libc_glob,
        );
    }

    fn visit_impl_item_macro(&mut self, item: &'ast syn::ImplItemMacro) {
        if cfg_test(&item.attrs) {
            return;
        }
        if item.mac.path.is_ident("define_syscall") {
            self.scan_define_syscall_tokens(item.mac.tokens.clone());
        } else {
            self.scan_macro_tokens(item.mac.tokens.clone());
        }
    }

    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        if let syn::Expr::Path(callee) = expression.func.as_ref() {
            let segments = path_segments(&callee.path);
            if segments.len() >= 2
                && (segments[segments.len() - 2] == "libc"
                    || self.libc_namespaces.contains(&segments[segments.len() - 2]))
            {
                if let Some(mut kind) =
                    CarrierProcessFindingKind::from_libc_name(&segments[segments.len() - 1])
                {
                    if kind == CarrierProcessFindingKind::Kill
                        && expression.args.len() == 2
                        && expression.args.iter().nth(1).is_some_and(|argument| {
                            matches!(argument, syn::Expr::Lit(literal) if matches!(&literal.lit, syn::Lit::Int(value) if value.base10_digits() == "0"))
                        })
                    {
                        kind = CarrierProcessFindingKind::KillProbe;
                    }
                    self.record(kind, path_span(&callee.path), segments.join("::"));
                }
            } else if segments.len() == 1
                && let Some(kind) = self.libc_aliases.get(&segments[0]).copied()
            {
                self.record(kind, path_span(&callee.path), segments[0].clone());
            } else if segments.len() == 1
                && self.libc_glob
                && let Some(kind) = CarrierProcessFindingKind::from_libc_name(&segments[0])
            {
                self.record(kind, path_span(&callee.path), segments[0].clone());
            } else if segments.ends_with(&["carrick_portable".to_owned(), "ptrace".to_owned()]) {
                self.record(
                    CarrierProcessFindingKind::Ptrace,
                    path_span(&callee.path),
                    segments.join("::"),
                );
            }

            if segments.last().is_some_and(|segment| segment == "new") && segments.len() >= 2 {
                let command = &segments[segments.len() - 2];
                let fully_qualified = segments
                    .windows(2)
                    .any(|window| window[0] == "process" && window[1] == "Command");
                let namespace_alias = segments.len() >= 3
                    && command == "Command"
                    && self
                        .process_namespaces
                        .contains(&segments[segments.len() - 3]);
                if fully_qualified || namespace_alias || self.command_aliases.contains(command) {
                    self.record(
                        CarrierProcessFindingKind::ProcessCommand,
                        path_span(&callee.path),
                        segments.join("::"),
                    );
                }
            }
        }
        syn::visit::visit_expr_call(self, expression);
    }

    fn visit_foreign_item_fn(&mut self, item: &'ast syn::ForeignItemFn) {
        if let Some(kind) = CarrierProcessFindingKind::from_libc_name(&item.sig.ident.to_string()) {
            self.record(
                kind,
                item.sig.ident.span(),
                format!("extern fn {}", item.sig.ident),
            );
        }
        for attribute in &item.attrs {
            if !attribute.path().is_ident("link_name") {
                continue;
            }
            let syn::Meta::NameValue(value) = &attribute.meta else {
                continue;
            };
            let syn::Expr::Lit(literal) = &value.value else {
                continue;
            };
            let syn::Lit::Str(link_name) = &literal.lit else {
                continue;
            };
            if let Some(kind) = CarrierProcessFindingKind::from_libc_name(&link_name.value()) {
                self.record(
                    kind,
                    link_name.span(),
                    format!("extern link_name {}", link_name.value()),
                );
            }
        }
        syn::visit::visit_foreign_item_fn(self, item);
    }

    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        self.scan_macro_tokens(item.tokens.clone());
    }
}

impl CarrierProcessScanner {
    fn scan_define_syscall_tokens(&mut self, stream: TokenStream) {
        let tokens: Vec<TokenTree> = stream.into_iter().collect();
        let mut index = 0;
        while index < tokens.len() {
            if is_ident(&tokens[index], "fn")
                && let Some(TokenTree::Ident(name)) = tokens.get(index + 1)
                && let Some((body_index, TokenTree::Group(body))) = tokens
                    .iter()
                    .enumerate()
                    .skip(index + 2)
                    .find(|(_, token)| matches!(token, TokenTree::Group(group) if group.delimiter() == Delimiter::Brace))
            {
                self.item_stack.push(name.to_string());
                self.scan_macro_tokens(body.stream());
                self.item_stack.pop();
                index = body_index + 1;
                continue;
            }
            index += 1;
        }
    }

    fn scan_macro_tokens(&mut self, stream: TokenStream) {
        let tokens: Vec<TokenTree> = stream.into_iter().collect();
        let mut index = 0;
        while index < tokens.len() {
            // `syscall_table!` bodies contain statement-level cfg(test) fixture
            // blocks. They are macro tokens rather than syn Items, so the
            // ordinary cfg-aware visitor above never sees their attributes.
            // Skip the exact attributed brace group here; this is the token
            // equivalent of `visit_item`'s test-only exclusion, not a product
            // path or operation allowlist.
            if tokens.get(index).is_some_and(|token| is_punct(token, '#'))
                && let Some(TokenTree::Group(attribute)) = tokens.get(index + 1)
                && attribute.delimiter() == proc_macro2::Delimiter::Bracket
                && attribute
                    .stream()
                    .to_string()
                    .chars()
                    .filter(|character| !character.is_whitespace())
                    .eq("cfg(test)".chars())
                && matches!(tokens.get(index + 2), Some(TokenTree::Group(group)) if group.delimiter() == proc_macro2::Delimiter::Brace)
            {
                index += 3;
                continue;
            }
            let direct_libc = match_path_idents(&tokens, index, &["libc"]);
            if let Some((next, _)) = direct_libc
                && let Some(TokenTree::Ident(operation)) = tokens.get(next + 2)
                && tokens.get(next).is_some_and(|token| is_punct(token, ':'))
                && tokens
                    .get(next + 1)
                    .is_some_and(|token| is_punct(token, ':'))
                && let Some(kind) =
                    CarrierProcessFindingKind::from_libc_name(&operation.to_string())
            {
                self.record(
                    kind,
                    operation.span(),
                    format!("libc::{} in macro syntax", operation),
                );
            }
            for namespace in self.libc_namespaces.clone() {
                if let Some((next, _)) = match_path_idents(&tokens, index, &[namespace.as_str()])
                    && let Some(TokenTree::Ident(operation)) = tokens.get(next + 2)
                    && tokens.get(next).is_some_and(|token| is_punct(token, ':'))
                    && tokens
                        .get(next + 1)
                        .is_some_and(|token| is_punct(token, ':'))
                    && matches!(tokens.get(next + 3), Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Parenthesis)
                    && let Some(kind) =
                        CarrierProcessFindingKind::from_libc_name(&operation.to_string())
                {
                    self.record(
                        kind,
                        operation.span(),
                        format!("{namespace}::{} in macro syntax", operation),
                    );
                }
            }
            if let Some((next, _)) = match_path_idents(&tokens, index, &["carrick_portable"])
                && tokens.get(next).is_some_and(|token| is_punct(token, ':'))
                && tokens
                    .get(next + 1)
                    .is_some_and(|token| is_punct(token, ':'))
                && tokens
                    .get(next + 2)
                    .is_some_and(|token| is_ident(token, "ptrace"))
                && let Some(TokenTree::Ident(operation)) = tokens.get(next + 2)
            {
                self.record(
                    CarrierProcessFindingKind::Ptrace,
                    operation.span(),
                    "carrick_portable::ptrace in macro syntax".to_owned(),
                );
            }

            if let TokenTree::Ident(identifier) = &tokens[index] {
                let name = identifier.to_string();
                if let Some(kind) = self.libc_aliases.get(&name).copied()
                    && tokens.get(index + 1).is_some_and(|token| {
                        matches!(token, TokenTree::Group(group) if group.delimiter() == Delimiter::Parenthesis)
                    })
                {
                    self.record(kind, identifier.span(), format!("{name} in macro syntax"));
                } else if self.libc_glob
                    && matches!(tokens.get(index + 1), Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Parenthesis)
                    && let Some(kind) = CarrierProcessFindingKind::from_libc_name(&name)
                {
                    self.record(kind, identifier.span(), format!("{name} in macro syntax"));
                }
            }

            let command_new =
                match_path_idents(&tokens, index, &["std", "process", "Command", "new"])
                    .or_else(|| {
                        match_path_idents(&tokens, index, &["tokio", "process", "Command", "new"])
                    })
                    .or_else(|| match_path_idents(&tokens, index, &["process", "Command", "new"]));
            if let Some((_, span)) = command_new {
                self.record(
                    CarrierProcessFindingKind::ProcessCommand,
                    span,
                    "process::Command::new in macro syntax".to_owned(),
                );
            } else if let TokenTree::Ident(command) = &tokens[index]
                && self.command_aliases.contains(&command.to_string())
                && tokens
                    .get(index + 1)
                    .is_some_and(|token| is_punct(token, ':'))
                && tokens
                    .get(index + 2)
                    .is_some_and(|token| is_punct(token, ':'))
                && tokens
                    .get(index + 3)
                    .is_some_and(|token| is_ident(token, "new"))
            {
                self.record(
                    CarrierProcessFindingKind::ProcessCommand,
                    command.span(),
                    format!("{}::new in macro syntax", command),
                );
            } else {
                for namespace in self.process_namespaces.clone() {
                    if let Some((_, span)) =
                        match_path_idents(&tokens, index, &[namespace.as_str(), "Command", "new"])
                    {
                        self.record(
                            CarrierProcessFindingKind::ProcessCommand,
                            span,
                            format!("{namespace}::Command::new in macro syntax"),
                        );
                    }
                }
            }

            if let TokenTree::Group(group) = &tokens[index] {
                self.scan_macro_tokens(group.stream());
            }
            index += 1;
        }
    }
}

fn match_path_idents(tokens: &[TokenTree], start: usize, names: &[&str]) -> Option<(usize, Span)> {
    let mut index = start;
    if is_double_colon(tokens, index) {
        index += 2;
    }
    let span = match tokens.get(index) {
        Some(TokenTree::Ident(identifier)) if identifier == names[0] => identifier.span(),
        _ => return None,
    };
    index += 1;
    for name in &names[1..] {
        if !is_double_colon(tokens, index) {
            return None;
        }
        index += 2;
        if !tokens.get(index).is_some_and(|token| is_ident(token, name)) {
            return None;
        }
        index += 1;
    }
    Some((index, span))
}

#[derive(Clone, Debug)]
struct UseLeaf {
    absolute: bool,
    segments: Vec<String>,
    span: Span,
}

pub fn scan_source(source: &str) -> Result<Vec<Finding>, ScanError> {
    let stream = TokenStream::from_str(source)
        .map_err(|error| ScanError(format!("Rust tokenization failed: {error}")))?;
    let mut scanner = Scanner::default();
    scanner.scan_stream(stream);
    scanner.findings.sort();
    scanner.findings.dedup();
    Ok(scanner.findings)
}

#[derive(Default)]
struct Scanner {
    findings: Vec<Finding>,
}

impl Scanner {
    fn scan_stream(&mut self, stream: TokenStream) {
        let tokens: Vec<TokenTree> = stream.into_iter().collect();
        let mut index = 0;
        while index < tokens.len() {
            if is_ident(&tokens[index], "use") {
                let semicolon = tokens[index + 1..]
                    .iter()
                    .position(is_semicolon)
                    .map(|offset| index + 1 + offset);
                let end = semicolon.unwrap_or(tokens.len());
                let mut leaves = Vec::new();
                parse_use_tree(&tokens[index + 1..end], &[], false, &mut leaves);
                for leaf in leaves {
                    self.record_use(leaf);
                }
                index = semicolon.map_or(index + 1, |position| position + 1);
                continue;
            }

            if let Some((kind, span, detail)) = match_libc_path(&tokens, index) {
                self.findings.push(Finding::new(kind, span, detail));
            }
            if let Some((span, detail)) = match_assembly_macro(&tokens, index) {
                self.findings
                    .push(Finding::new(FindingKind::Assembly, span, detail));
            }
            if is_ident(&tokens[index], "extern")
                && let Some(group) = extern_group(&tokens, index)
            {
                self.scan_extern_group(group);
            }
            if let TokenTree::Group(group) = &tokens[index] {
                self.scan_stream(group.stream());
            }
            index += 1;
        }
    }

    fn record_use(&mut self, leaf: UseLeaf) {
        if leaf.segments.len() == 2 && leaf.segments[0] == "libc" {
            let operation = &leaf.segments[1];
            if let Some(kind) = FindingKind::for_libc(operation) {
                let prefix = if leaf.absolute { "::" } else { "" };
                self.findings.push(Finding::new(
                    kind,
                    leaf.span,
                    format!("use {prefix}libc::{operation}"),
                ));
            }
        }
        if leaf.segments.len() == 3
            && matches!(leaf.segments[0].as_str(), "core" | "std")
            && leaf.segments[1] == "arch"
            && matches!(leaf.segments[2].as_str(), "asm" | "global_asm")
        {
            let prefix = if leaf.absolute { "::" } else { "" };
            self.findings.push(Finding::new(
                FindingKind::Assembly,
                leaf.span,
                format!("use {prefix}{}", leaf.segments.join("::")),
            ));
        }
    }

    fn scan_extern_group(&mut self, group: &Group) {
        let tokens: Vec<TokenTree> = group.stream().into_iter().collect();
        for index in 0..tokens.len() {
            if is_ident(&tokens[index], "fn")
                && let Some(TokenTree::Ident(name)) = tokens.get(index + 1)
            {
                let name = name.to_string();
                if WATCHED_EXTERN.contains(&name.as_str()) {
                    self.findings.push(Finding::new(
                        FindingKind::Extern,
                        tokens[index].span(),
                        format!("extern fn {name}"),
                    ));
                }
            }
            if is_punct(&tokens[index], '#')
                && let Some(TokenTree::Group(attribute)) = tokens.get(index + 1)
                && attribute.delimiter() == Delimiter::Bracket
            {
                self.scan_link_name_attribute(attribute.stream());
            }
        }
    }

    fn scan_link_name_attribute(&mut self, stream: TokenStream) {
        let tokens: Vec<TokenTree> = stream.into_iter().collect();
        for index in 0..tokens.len() {
            if is_ident(&tokens[index], "link_name")
                && tokens
                    .get(index + 1)
                    .is_some_and(|token| is_punct(token, '='))
                && let Some(TokenTree::Literal(literal)) = tokens.get(index + 2)
                && let Ok(value) = syn::parse_str::<syn::LitStr>(&literal.to_string())
            {
                let value = value.value();
                if WATCHED_EXTERN.contains(&value.as_str()) {
                    self.findings.push(Finding::new(
                        FindingKind::Extern,
                        literal.span(),
                        format!("link_name {value}"),
                    ));
                }
            }
            if let TokenTree::Group(group) = &tokens[index] {
                self.scan_link_name_attribute(group.stream());
            }
        }
    }
}

fn match_libc_path(tokens: &[TokenTree], index: usize) -> Option<(FindingKind, Span, String)> {
    let (libc_index, absolute) = if is_double_colon(tokens, index)
        && tokens
            .get(index + 2)
            .is_some_and(|token| is_ident(token, "libc"))
    {
        (index + 2, true)
    } else if tokens
        .get(index)
        .is_some_and(|token| is_ident(token, "libc"))
    {
        if index >= 2 && is_double_colon(tokens, index - 2) {
            return None;
        }
        (index, false)
    } else {
        return None;
    };
    if !is_double_colon(tokens, libc_index + 1) {
        return None;
    }
    let TokenTree::Ident(operation) = tokens.get(libc_index + 3)? else {
        return None;
    };
    let operation = operation.to_string();
    let kind = FindingKind::for_libc(&operation)?;
    let prefix = if absolute { "::" } else { "" };
    Some((
        kind,
        tokens[libc_index].span(),
        format!("{prefix}libc::{operation}"),
    ))
}

fn match_assembly_macro(tokens: &[TokenTree], index: usize) -> Option<(Span, String)> {
    let TokenTree::Ident(name) = tokens.get(index)? else {
        return None;
    };
    let name = name.to_string();
    if !matches!(name.as_str(), "asm" | "global_asm")
        || !tokens
            .get(index + 1)
            .is_some_and(|token| is_punct(token, '!'))
        || !matches!(tokens.get(index + 2), Some(TokenTree::Group(_)))
    {
        return None;
    }
    let mut segments = vec![name];
    let mut cursor = index;
    while cursor >= 3 && is_double_colon(tokens, cursor - 2) {
        let TokenTree::Ident(segment) = &tokens[cursor - 3] else {
            break;
        };
        segments.push(segment.to_string());
        cursor -= 3;
    }
    segments.reverse();
    Some((tokens[index].span(), format!("{}!", segments.join("::"))))
}

fn extern_group(tokens: &[TokenTree], index: usize) -> Option<&Group> {
    match tokens.get(index + 1)? {
        TokenTree::Group(group) if group.delimiter() == Delimiter::Brace => Some(group),
        TokenTree::Literal(_) => match tokens.get(index + 2)? {
            TokenTree::Group(group) if group.delimiter() == Delimiter::Brace => Some(group),
            _ => None,
        },
        _ => None,
    }
}

fn parse_use_tree(
    tokens: &[TokenTree],
    prefix: &[String],
    inherited_absolute: bool,
    leaves: &mut Vec<UseLeaf>,
) {
    let mut index = 0;
    let absolute = inherited_absolute || is_double_colon(tokens, index);
    if is_double_colon(tokens, index) {
        index += 2;
    }
    let Some(token) = tokens.get(index) else {
        return;
    };
    if let TokenTree::Group(group) = token {
        if group.delimiter() == Delimiter::Brace {
            parse_use_group(group.stream(), prefix, absolute, leaves);
        }
        return;
    }
    let TokenTree::Ident(segment) = token else {
        return;
    };
    let mut next_prefix = prefix.to_vec();
    next_prefix.push(segment.to_string());
    if is_double_colon(tokens, index + 1) {
        parse_use_tree(&tokens[index + 3..], &next_prefix, absolute, leaves);
    } else {
        leaves.push(UseLeaf {
            absolute,
            segments: next_prefix,
            span: segment.span(),
        });
    }
}

fn parse_use_group(
    stream: TokenStream,
    prefix: &[String],
    absolute: bool,
    leaves: &mut Vec<UseLeaf>,
) {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    let mut start = 0;
    for index in 0..=tokens.len() {
        if index == tokens.len() || is_comma(&tokens[index]) {
            parse_use_tree(&tokens[start..index], prefix, absolute, leaves);
            start = index + 1;
        }
    }
}

fn is_ident(token: &TokenTree, expected: &str) -> bool {
    matches!(token, TokenTree::Ident(ident) if ident == expected)
}

fn is_punct(token: &TokenTree, expected: char) -> bool {
    matches!(token, TokenTree::Punct(punct) if punct.as_char() == expected)
}

fn is_double_colon(tokens: &[TokenTree], index: usize) -> bool {
    tokens.get(index).is_some_and(|token| is_punct(token, ':'))
        && tokens
            .get(index + 1)
            .is_some_and(|token| is_punct(token, ':'))
}

fn is_semicolon(token: &TokenTree) -> bool {
    is_punct(token, ';')
}

fn is_comma(token: &TokenTree) -> bool {
    is_punct(token, ',')
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character < ' ' => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }
    }
    escaped
}
