use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use proc_macro2::{Delimiter, TokenStream, TokenTree};

use crate::{ContractId, ContractRegistry, ExecutionLayer};

/// Resolves concrete `vm_free` and `embed` contract bindings against the
/// workspace source tree so invented crates or module paths fail closed.
pub struct BindingResolver {
    root: PathBuf,
    crates: BTreeMap<String, CrateIndex>,
}

#[derive(Default)]
struct CrateIndex {
    mods: BTreeSet<Vec<String>>,
    bins: BTreeSet<String>,
    idents: BTreeSet<String>,
}

#[derive(Debug, Default, ::serde::Deserialize)]
struct CargoManifestWire {
    #[serde(default)]
    lib: Option<CargoTargetWire>,
    #[serde(default)]
    bin: Vec<CargoTargetWire>,
    #[serde(default)]
    test: Vec<CargoTargetWire>,
}

#[derive(Debug, Default, ::serde::Deserialize)]
struct CargoTargetWire {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    path: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum BindingResolutionError {
    #[error("cannot read crate path {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot tokenize Rust source {path}: {reason}")]
    Lex { path: PathBuf, reason: String },
    #[error("{id}: malformed vm_free binding entry {entry:?} (expected `<crate>::<path>`)")]
    MalformedVmFreeEntry { id: ContractId, entry: String },
    #[error("{id}: malformed embed binding entry {entry:?} (expected `<crate>::<path>` or `probe:<name>`)")]
    MalformedEmbedEntry { id: ContractId, entry: String },
    #[error("{id}: missing {layer} target crate {}", crate_path.display())]
    MissingTargetCrate {
        id: ContractId,
        layer: ExecutionLayer,
        crate_path: PathBuf,
    },
    #[error("{id}: unresolved {layer} binding target {target}")]
    UnresolvedTarget {
        id: ContractId,
        layer: ExecutionLayer,
        target: String,
    },
}

impl BindingResolver {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            crates: BTreeMap::new(),
        }
    }

    pub fn check_registry(
        &mut self,
        registry: &ContractRegistry,
    ) -> Result<(), BindingResolutionError> {
        for contract in registry.contracts() {
            for entry in &contract.bindings.vm_free {
                self.check_vm_free_entry(&contract.id, entry)?;
            }
            for entry in &contract.bindings.embed {
                self.check_embed_entry(&contract.id, entry)?;
            }
        }
        Ok(())
    }

    fn check_vm_free_entry(
        &mut self,
        id: &ContractId,
        entry: &str,
    ) -> Result<(), BindingResolutionError> {
        let trimmed = entry.trim();
        let (is_leading_doctest, after_prefix) = match trimmed.strip_prefix("doctest:") {
            Some(rest) => (true, rest),
            None => (false, trimmed),
        };
        let Some(leading) = parse_target_at_start(after_prefix) else {
            return Err(BindingResolutionError::MalformedVmFreeEntry {
                id: id.clone(),
                entry: entry.to_string(),
            });
        };

        let mut targets = vec![(is_leading_doctest, leading.0, leading.1)];
        for (is_doc, crate_name, raw_path) in extract_embedded_carrick_targets(trimmed) {
            if !targets
                .iter()
                .any(|(_, c, p)| c == &crate_name && p == &raw_path)
            {
                targets.push((is_doc, crate_name, raw_path));
            }
        }

        for (is_doctest, crate_name, raw_path) in targets {
            let crate_dir = self.ensure_crate_exists(id, ExecutionLayer::VmFree, &crate_name)?;
            let Some(expanded_paths) = expand_braces(&raw_path) else {
                return Err(BindingResolutionError::UnresolvedTarget {
                    id: id.clone(),
                    layer: ExecutionLayer::VmFree,
                    target: format!("{crate_name}::{raw_path}"),
                });
            };
            let index = self.crate_index(&crate_name, &crate_dir)?;
            for expanded in expanded_paths {
                let segs = split_segments(&expanded);
                if segs.is_empty() || !index.resolves_vm_free(&segs, is_doctest) {
                    return Err(BindingResolutionError::UnresolvedTarget {
                        id: id.clone(),
                        layer: ExecutionLayer::VmFree,
                        target: format!("{crate_name}::{}", segs.join("::")),
                    });
                }
            }
        }
        Ok(())
    }

    fn check_embed_entry(
        &mut self,
        id: &ContractId,
        entry: &str,
    ) -> Result<(), BindingResolutionError> {
        let trimmed = entry.trim();
        if !trimmed.contains(':') && !trimmed.chars().any(char::is_whitespace) {
            return Err(BindingResolutionError::MalformedEmbedEntry {
                id: id.clone(),
                entry: entry.to_string(),
            });
        }

        let mut targets = Vec::new();
        let after_prefix = trimmed.strip_prefix("doctest:").unwrap_or(trimmed);
        if let Some((crate_name, raw_path)) = parse_target_at_start(after_prefix) {
            targets.push((crate_name, raw_path));
        }
        for (_, crate_name, raw_path) in extract_embedded_carrick_targets(trimmed) {
            if !targets.iter().any(|(c, p)| c == &crate_name && p == &raw_path) {
                targets.push((crate_name, raw_path));
            }
        }

        for (crate_name, raw_path) in targets {
            let crate_dir =
                self.ensure_crate_exists(id, ExecutionLayer::EmbedStructural, &crate_name)?;
            let Some(expanded_paths) = expand_braces(&raw_path) else {
                return Err(BindingResolutionError::UnresolvedTarget {
                    id: id.clone(),
                    layer: ExecutionLayer::EmbedStructural,
                    target: format!("{crate_name}::{raw_path}"),
                });
            };
            for expanded in expanded_paths {
                let segs = split_segments(&expanded);
                if segs.is_empty() {
                    return Err(BindingResolutionError::UnresolvedTarget {
                        id: id.clone(),
                        layer: ExecutionLayer::EmbedStructural,
                        target: format!("{crate_name}::{expanded}"),
                    });
                }
                if segs.len() >= 2 {
                    if crate_name == "carrick-cli"
                        && let [subcmd, profile] = segs.as_slice()
                        && subcmd == "trace"
                    {
                        let dtrace_script = self
                            .root
                            .join("scripts")
                            .join("dtrace")
                            .join(format!("{profile}.d"));
                        if !dtrace_script.is_file() {
                            return Err(BindingResolutionError::UnresolvedTarget {
                                id: id.clone(),
                                layer: ExecutionLayer::EmbedStructural,
                                target: format!("{crate_name}::{}", segs.join("::")),
                            });
                        }
                        continue;
                    }
                    let index = self.crate_index(&crate_name, &crate_dir)?;
                    if !index.resolves_module_or_parent(&segs) {
                        return Err(BindingResolutionError::UnresolvedTarget {
                            id: id.clone(),
                            layer: ExecutionLayer::EmbedStructural,
                            target: format!("{crate_name}::{}", segs.join("::")),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn ensure_crate_exists(
        &self,
        id: &ContractId,
        layer: ExecutionLayer,
        crate_name: &str,
    ) -> Result<PathBuf, BindingResolutionError> {
        let crate_dir = self.root.join("crates").join(crate_name);
        if !crate_dir.is_dir() {
            return Err(BindingResolutionError::MissingTargetCrate {
                id: id.clone(),
                layer,
                crate_path: crate_dir,
            });
        }
        Ok(crate_dir)
    }

    fn crate_index(
        &mut self,
        crate_name: &str,
        crate_dir: &Path,
    ) -> Result<&CrateIndex, BindingResolutionError> {
        if !self.crates.contains_key(crate_name) {
            let built = CrateIndex::build(crate_dir)?;
            self.crates.insert(crate_name.to_string(), built);
        }
        self.crates
            .get(crate_name)
            .ok_or_else(|| BindingResolutionError::Io {
                path: crate_dir.to_path_buf(),
                source: std::io::Error::other("missing cached crate index"),
            })
    }
}

impl CrateIndex {
    fn resolves_vm_free(&self, segs: &[String], is_doctest: bool) -> bool {
        if self.mods.contains(segs) {
            return true;
        }
        if segs.len() == 1 {
            return segs
                .first()
                .is_some_and(|only| self.bins.contains(only) || self.idents.contains(only));
        }
        if self.resolves_module_or_parent(segs) {
            return true;
        }
        if is_doctest && segs.iter().all(|seg| self.idents.contains(seg)) {
            let mod_prefix = segs.get(..segs.len().saturating_sub(2)).unwrap_or(&[]);
            return mod_prefix.is_empty() || self.mods.contains(mod_prefix);
        }
        false
    }

    fn resolves_module_or_parent(&self, segs: &[String]) -> bool {
        if self.mods.contains(segs) {
            return true;
        }
        let parent = segs.get(..segs.len().saturating_sub(1)).unwrap_or(&[]);
        !parent.is_empty() && self.mods.contains(parent)
    }

    fn build(crate_dir: &Path) -> Result<Self, BindingResolutionError> {
        let mut index = Self::default();
        let mut visited: BTreeSet<(PathBuf, Vec<String>)> = BTreeSet::new();

        let manifest_path = crate_dir.join("Cargo.toml");
        let manifest = if manifest_path.is_file() {
            let text = fs::read_to_string(&manifest_path).map_err(|source| {
                BindingResolutionError::Io {
                    path: manifest_path,
                    source,
                }
            })?;
            toml::from_str::<CargoManifestWire>(&text).ok()
        } else {
            None
        };

        let lib_rel = manifest
            .as_ref()
            .and_then(|m| m.lib.as_ref())
            .and_then(|lib| lib.path.as_deref())
            .unwrap_or("src/lib.rs");
        let lib_path = crate_dir.join(lib_rel);
        if lib_path.is_file() {
            index.scan_file(&lib_path, &[], true, &mut visited)?;
        }

        let main_path = crate_dir.join("src/main.rs");
        if main_path.is_file() {
            index.scan_file(&main_path, &[], true, &mut visited)?;
        }

        if let Some(m) = &manifest {
            for bin in &m.bin {
                if let Some(name) = &bin.name {
                    index.bins.insert(name.clone());
                    index.mods.insert(vec![name.clone()]);
                }
                if let Some(rel) = &bin.path {
                    let target = crate_dir.join(rel);
                    if target.is_file() {
                        index.scan_file(&target, &[], true, &mut visited)?;
                        if let Some(name) = &bin.name {
                            index.scan_file(&target, &[name.clone()], true, &mut visited)?;
                        }
                    }
                }
            }
            for test_target in &m.test {
                if let (Some(name), Some(rel)) = (&test_target.name, &test_target.path) {
                    let target = crate_dir.join(rel);
                    if target.is_file() {
                        index.mods.insert(vec![name.clone()]);
                        index.mods.insert(vec!["tests".to_string(), name.clone()]);
                        index.scan_file(&target, &[], true, &mut visited)?;
                        index.scan_file(&target, &[name.clone()], true, &mut visited)?;
                        index.scan_file(
                            &target,
                            &["tests".to_string(), name.clone()],
                            true,
                            &mut visited,
                        )?;
                    }
                }
            }
        }

        let bins_dir = crate_dir.join("src/bin");
        if bins_dir.is_dir() {
            for entry in read_sorted_dir(&bins_dir)? {
                if entry.is_file() && entry.extension().and_then(|e| e.to_str()) == Some("rs") {
                    if let Some(stem) = entry.file_stem().and_then(|s| s.to_str()) {
                        let name = stem.to_string();
                        index.bins.insert(name.clone());
                        index.mods.insert(vec![name.clone()]);
                        index.scan_file(&entry, &[], true, &mut visited)?;
                        index.scan_file(&entry, &[name], true, &mut visited)?;
                    }
                } else if entry.is_dir() {
                    let main_rs = entry.join("main.rs");
                    if main_rs.is_file()
                        && let Some(dir_name) = entry.file_name().and_then(|s| s.to_str())
                    {
                        let name = dir_name.to_string();
                        index.bins.insert(name.clone());
                        index.mods.insert(vec![name.clone()]);
                        index.scan_file(&main_rs, &[], true, &mut visited)?;
                        index.scan_file(&main_rs, &[name], true, &mut visited)?;
                    }
                }
            }
        }

        let tests_dir = crate_dir.join("tests");
        if tests_dir.is_dir() {
            for entry in read_sorted_dir(&tests_dir)? {
                if entry.is_file() && entry.extension().and_then(|e| e.to_str()) == Some("rs") {
                    if let Some(stem) = entry.file_stem().and_then(|s| s.to_str()) {
                        let name = stem.to_string();
                        index.mods.insert(vec![name.clone()]);
                        index.mods.insert(vec!["tests".to_string(), name.clone()]);
                        index.scan_file(&entry, &[], true, &mut visited)?;
                        index.scan_file(&entry, &[name.clone()], true, &mut visited)?;
                        index.scan_file(&entry, &["tests".to_string(), name], true, &mut visited)?;
                    }
                } else if entry.is_dir()
                    && let Some(dir_name) = entry.file_name().and_then(|s| s.to_str())
                {
                    for candidate in ["main.rs", "mod.rs"] {
                        let root_rs = entry.join(candidate);
                        if root_rs.is_file() {
                            let name = dir_name.to_string();
                            index.mods.insert(vec![name.clone()]);
                            index.mods.insert(vec!["tests".to_string(), name.clone()]);
                            index.scan_file(&root_rs, &[], true, &mut visited)?;
                            index.scan_file(&root_rs, &[name.clone()], true, &mut visited)?;
                            index.scan_file(
                                &root_rs,
                                &["tests".to_string(), name],
                                true,
                                &mut visited,
                            )?;
                            break;
                        }
                    }
                }
            }
        }

        Ok(index)
    }

    fn scan_file(
        &mut self,
        file_path: &Path,
        prefix: &[String],
        is_crate_root: bool,
        visited: &mut BTreeSet<(PathBuf, Vec<String>)>,
    ) -> Result<(), BindingResolutionError> {
        let visit_key = (file_path.to_path_buf(), prefix.to_vec());
        if !visited.insert(visit_key) {
            return Ok(());
        }

        let content = fs::read_to_string(file_path).map_err(|source| {
            BindingResolutionError::Io {
                path: file_path.to_path_buf(),
                source,
            }
        })?;
        let stream =
            content
                .parse::<TokenStream>()
                .map_err(|err| BindingResolutionError::Lex {
                    path: file_path.to_path_buf(),
                    reason: err.to_string(),
                })?;

        let file_dir = file_path.parent().unwrap_or(file_path);
        let stem = file_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        let is_root_or_mod = is_crate_root || matches!(stem, "lib" | "main" | "mod");

        self.scan_tokens(stream, file_dir, stem, is_root_or_mod, prefix, visited)
    }

    fn scan_tokens(
        &mut self,
        stream: TokenStream,
        file_dir: &Path,
        stem: &str,
        is_root_or_mod: bool,
        prefix: &[String],
        visited: &mut BTreeSet<(PathBuf, Vec<String>)>,
    ) -> Result<(), BindingResolutionError> {
        let tokens: Vec<TokenTree> = stream.into_iter().collect();
        let mut pending_path: Option<String> = None;
        let mut idx = 0;

        while let Some(tok) = tokens.get(idx) {
            if let TokenTree::Ident(ident) = tok {
                let raw = ident.to_string();
                let clean = raw.strip_prefix("r#").unwrap_or(&raw);
                self.idents.insert(clean.to_string());
            }

            if let TokenTree::Punct(punct) = tok
                && punct.as_char() == '#'
            {
                if let Some(TokenTree::Group(attr_group)) = tokens.get(idx + 1)
                    && attr_group.delimiter() == Delimiter::Bracket
                {
                    if let Some(custom_path) = extract_path_attr(attr_group.stream()) {
                        pending_path = Some(custom_path);
                    }
                    idx += 2;
                    continue;
                }
                if let Some(TokenTree::Punct(bang)) = tokens.get(idx + 1)
                    && bang.as_char() == '!'
                    && let Some(TokenTree::Group(attr_group)) = tokens.get(idx + 2)
                    && attr_group.delimiter() == Delimiter::Bracket
                {
                    idx += 3;
                    continue;
                }
            }

            if let TokenTree::Ident(ident) = tok {
                if ident == "pub" {
                    if let Some(TokenTree::Group(vis_group)) = tokens.get(idx + 1)
                        && vis_group.delimiter() == Delimiter::Parenthesis
                    {
                        idx += 2;
                    } else {
                        idx += 1;
                    }
                    continue;
                }
                if ident == "unsafe" {
                    idx += 1;
                    continue;
                }
                if ident == "include"
                    && let Some(TokenTree::Punct(bang)) = tokens.get(idx + 1)
                    && bang.as_char() == '!'
                    && let Some(TokenTree::Group(group)) = tokens.get(idx + 2)
                {
                    if let Some(rel) = extract_single_string_literal(group.stream()) {
                        let included = file_dir.join(rel);
                        if included.is_file() {
                            self.scan_file(&included, prefix, is_root_or_mod, visited)?;
                        }
                    }
                    pending_path = None;
                    idx += 3;
                    continue;
                }
                if ident == "mod"
                    && let Some(TokenTree::Ident(mod_ident)) = tokens.get(idx + 1)
                {
                    let mod_raw = mod_ident.to_string();
                    let mod_name = mod_raw.strip_prefix("r#").unwrap_or(&mod_raw).to_string();
                    self.idents.insert(mod_name.clone());

                    if let Some(TokenTree::Punct(semi)) = tokens.get(idx + 2)
                        && semi.as_char() == ';'
                    {
                        let custom = pending_path.take();
                        let loaded_via_path_attr = custom.is_some();
                        if let Some(target_file) = resolve_module_file(
                            file_dir,
                            stem,
                            is_root_or_mod,
                            &mod_name,
                            custom.as_deref(),
                        ) {
                            let mut child_prefix = prefix.to_vec();
                            child_prefix.push(mod_name);
                            self.mods.insert(child_prefix.clone());
                            self.scan_file(
                                &target_file,
                                &child_prefix,
                                loaded_via_path_attr,
                                visited,
                            )?;
                        }
                        idx += 3;
                        continue;
                    }

                    if let Some(TokenTree::Group(body)) = tokens.get(idx + 2)
                        && body.delimiter() == Delimiter::Brace
                    {
                        let custom = pending_path.take();
                        let mut child_prefix = prefix.to_vec();
                        child_prefix.push(mod_name.clone());
                        self.mods.insert(child_prefix.clone());
                        let inline_dir = if let Some(cp) = custom {
                            file_dir.join(cp)
                        } else if is_root_or_mod {
                            file_dir.join(&mod_name)
                        } else {
                            file_dir.join(stem).join(&mod_name)
                        };
                        self.scan_tokens(
                            body.stream(),
                            &inline_dir,
                            "mod",
                            true,
                            &child_prefix,
                            visited,
                        )?;
                        idx += 3;
                        continue;
                    }
                }

                pending_path = None;
                idx += 1;
                continue;
            }

            if let TokenTree::Punct(punct) = tok
                && punct.as_char() == ';'
            {
                pending_path = None;
            } else if let TokenTree::Group(group) = tok {
                pending_path = None;
                self.scan_tokens(
                    group.stream(),
                    file_dir,
                    stem,
                    is_root_or_mod,
                    prefix,
                    visited,
                )?;
            }

            idx += 1;
        }

        Ok(())
    }
}

fn read_sorted_dir(dir: &Path) -> Result<Vec<PathBuf>, BindingResolutionError> {
    let entries = fs::read_dir(dir).map_err(|source| BindingResolutionError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| BindingResolutionError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        paths.push(entry.path());
    }
    paths.sort();
    Ok(paths)
}

fn resolve_module_file(
    file_dir: &Path,
    stem: &str,
    is_root_or_mod: bool,
    mod_name: &str,
    custom_path: Option<&str>,
) -> Option<PathBuf> {
    if let Some(cp) = custom_path {
        let custom = file_dir.join(cp);
        return custom.is_file().then_some(custom);
    }

    if is_root_or_mod {
        let candidates = [
            file_dir.join(format!("{mod_name}.rs")),
            file_dir.join(mod_name).join("mod.rs"),
            file_dir.join(stem).join(format!("{mod_name}.rs")),
            file_dir.join(stem).join(mod_name).join("mod.rs"),
        ];
        candidates.into_iter().find(|p| p.is_file())
    } else {
        let candidates = [
            file_dir.join(stem).join(format!("{mod_name}.rs")),
            file_dir.join(stem).join(mod_name).join("mod.rs"),
        ];
        candidates.into_iter().find(|p| p.is_file())
    }
}

fn extract_path_attr(stream: TokenStream) -> Option<String> {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    if let [
        TokenTree::Ident(key),
        TokenTree::Punct(eq),
        TokenTree::Literal(lit),
    ] = tokens.as_slice()
        && key == "path"
        && eq.as_char() == '='
    {
        return syn::parse_str::<syn::LitStr>(&lit.to_string())
            .ok()
            .map(|s| s.value());
    }
    None
}

fn extract_single_string_literal(stream: TokenStream) -> Option<String> {
    let tokens: Vec<TokenTree> = stream.into_iter().collect();
    let lit = match tokens.as_slice() {
        [TokenTree::Literal(lit)] => lit,
        [TokenTree::Literal(lit), TokenTree::Punct(comma)] if comma.as_char() == ',' => lit,
        _ => return None,
    };
    syn::parse_str::<syn::LitStr>(&lit.to_string())
        .ok()
        .map(|s| s.value())
}

fn is_crate_char(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
}

fn parse_target_at_start(text: &str) -> Option<(String, String)> {
    let bytes = text.as_bytes();
    let mut end = 0;
    while let Some(&b) = bytes.get(end) {
        if is_crate_char(b) {
            end += 1;
        } else {
            break;
        }
    }
    if end == 0 {
        return None;
    }
    let crate_name = text.get(..end)?;
    let after_crate = text.get(end..)?.strip_prefix("::")?;
    let raw_path = consume_raw_path(after_crate)?;
    Some((crate_name.to_string(), raw_path.to_string()))
}

fn extract_embedded_carrick_targets(text: &str) -> Vec<(bool, String, String)> {
    let mut results = Vec::new();
    let bytes = text.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        let Some(rel) = text.get(idx..).and_then(|s| s.find("carrick-")) else {
            break;
        };
        let start = idx + rel;
        let prev_ok = start == 0
            || bytes.get(start - 1).is_none_or(|&b| {
                !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            });
        let is_doctest = start >= "doctest:".len()
            && text.get(start - "doctest:".len()..start) == Some("doctest:")
            && (start == "doctest:".len()
                || bytes
                    .get(start - "doctest:".len() - 1)
                    .is_none_or(|&b| !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-')));

        if prev_ok
            && let Some(sub) = text.get(start..)
            && let Some((crate_name, raw_path)) = parse_target_at_start(sub)
        {
            let consumed = crate_name.len() + 2 + raw_path.len();
            results.push((is_doctest, crate_name, raw_path));
            idx = start + consumed;
            continue;
        }
        idx = start + "carrick-".len();
    }
    results
}

fn consume_raw_path(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    let mut idx = 0;
    let mut brace_depth: usize = 0;

    while let Some(&b) = bytes.get(idx) {
        if b == b'{' {
            brace_depth += 1;
            idx += 1;
        } else if b == b'}' {
            if brace_depth == 0 {
                break;
            }
            brace_depth -= 1;
            idx += 1;
        } else if brace_depth > 0 {
            if b.is_ascii_alphanumeric()
                || matches!(b, b'_' | b':' | b',' | b'-' | b'*' | b' ' | b'\t' | b'\n')
            {
                idx += 1;
            } else {
                break;
            }
        } else if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'*') {
            idx += 1;
        } else if b == b':' && bytes.get(idx + 1) == Some(&b':') {
            idx += 2;
        } else {
            break;
        }
    }

    let slice = text.get(..idx)?.trim_end_matches(['-', ':', ',', '.']);
    if slice.is_empty() {
        return None;
    }
    Some(slice)
}

fn expand_braces(input: &str) -> Option<Vec<String>> {
    let mut open_idx = None;
    let mut close_idx = None;
    let mut depth: usize = 0;

    for (idx, ch) in input.char_indices() {
        if ch == '{' {
            if depth == 0 {
                open_idx = Some(idx);
            }
            depth += 1;
        } else if ch == '}' {
            if depth == 0 {
                return None;
            }
            depth -= 1;
            if depth == 0 {
                close_idx = Some(idx);
                break;
            }
        }
    }

    if depth != 0 {
        return None;
    }

    let (Some(open), Some(close)) = (open_idx, close_idx) else {
        return Some(vec![input.trim().to_string()]);
    };

    let prefix = input.get(..open)?;
    let inside = input.get(open + 1..close)?;
    let suffix = input.get(close + 1..)?;

    let mut parts = Vec::new();
    let mut part_start = 0;
    let mut inner_depth: usize = 0;
    for (idx, ch) in inside.char_indices() {
        match ch {
            '{' => inner_depth += 1,
            '}' => inner_depth = inner_depth.saturating_sub(1),
            ',' if inner_depth == 0 => {
                let piece = inside.get(part_start..idx)?.trim();
                if piece.is_empty() {
                    return None;
                }
                parts.push(piece);
                part_start = idx + 1;
            }
            _ => {}
        }
    }
    let tail = inside.get(part_start..)?.trim();
    if tail.is_empty() {
        return None;
    }
    parts.push(tail);

    let mut out = Vec::new();
    for part in parts {
        let combined = format!("{prefix}{part}{suffix}");
        let expanded = expand_braces(&combined)?;
        out.extend(expanded);
    }
    Some(out)
}

fn split_segments(path: &str) -> Vec<String> {
    path.split("::")
        .map(|seg| seg.trim().trim_end_matches([':', ',', '.']))
        .filter(|seg| !seg.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}
