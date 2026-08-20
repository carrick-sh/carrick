use std::fmt;
use std::str::FromStr;

use proc_macro2::{Delimiter, Group, Span, TokenStream, TokenTree};

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
