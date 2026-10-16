use clap::Args;
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

#[derive(Args, Debug, Clone)]
pub struct CiChangesArgs {
    #[arg(long, env = "CI_EVENT", default_value = "")]
    pub event: String,

    #[arg(long, env = "CI_DRAFT", default_value = "false")]
    pub draft: String,

    #[arg(long, env = "CI_BASE", default_value = "")]
    pub base: String,

    #[arg(long, env = "CI_BASE_REF", default_value = "")]
    pub base_ref: String,

    #[arg(long, default_value = "HEAD")]
    pub head: String,

    #[arg(long, env = "GITHUB_OUTPUT")]
    pub github_output: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiChangesOutputs {
    pub heavy: bool,
    pub macos: bool,
    pub workflows: bool,
    pub hardware: bool,
}

impl CiChangesOutputs {
    pub fn format_github_output(&self) -> String {
        format!(
            "heavy={}\nmacos={}\nworkflows={}\nhardware={}\n",
            self.heavy, self.macos, self.workflows, self.hardware
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathClass {
    /// True unreferenced prose (`*.md` under `docs/`, `.agents/`, or repo root, plus `LICENSE*`).
    Prose,
    /// `crates/carrick-xtask/**`, `scripts/**`, `justfile`: runs heavy Linux (`lint`, `fmt`,
    /// `clippy`, `check-test-shards`, xtask tests) with `macos=false` and `hardware=false`.
    CiXtask,
    /// `.github/workflows/ci.yml` or non-hardware `.github/*` config (e.g. `.github/actionlint.yaml`):
    /// runs heavy Linux + macOS on `merge_group`, `workflows=true`, `hardware=false`.
    WorkflowCi,
    /// `.github/workflows/kernel-runtime.yml` or other `.github/**`: runs heavy Linux + hardware
    /// lanes, `workflows=true`.
    WorkflowHardware,
    /// Code, Cargo manifests, or any referenced doc/agent file: runs all heavy, macOS (on
    /// `merge_group`), and hardware lanes.
    CodeOrReferencedDoc,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReferencedDocs {
    pub exact_paths: BTreeSet<String>,
    pub dir_prefixes: BTreeSet<String>,
}

#[derive(Debug, Error)]
pub enum CiChangesError {
    #[error("I/O error at '{}': {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Git(String),
}

impl ReferencedDocs {
    /// Scan the repository for references to `docs/`, `.agents/`, or root `*.md` paths in:
    /// - Rust sources (`include_str!`, `include_bytes!`, `fs::read*`, `read_to_string`, path literals)
    /// - `justfile`
    /// - `scripts/**`
    /// - `.github/**`
    pub fn discover(repo_root: &Path) -> Result<Self, CiChangesError> {
        let mut refs = Self::default();
        let mut files = Vec::new();
        let justfile = repo_root.join("justfile");
        if justfile.is_file() {
            files.push(justfile);
        }
        for dir in ["crates", "conformance-probes", "scripts", ".github"] {
            let root = repo_root.join(dir);
            if root.exists() {
                collect_files(&root, &mut files)?;
            }
        }
        let self_src = repo_root.join("crates/carrick-xtask/src/ci_changes.rs");
        let self_test = repo_root.join("crates/carrick-xtask/tests/ci_changes.rs");
        for file in files {
            if file == self_src || file == self_test {
                continue;
            }
            let Ok(bytes) = fs::read(&file) else {
                continue;
            };
            let content = String::from_utf8_lossy(&bytes);
            let is_rust = file.extension().and_then(|e| e.to_str()) == Some("rs");
            if is_rust {
                scan_rust_source(repo_root, &file, &content, &mut refs);
            } else {
                let file_name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let is_synthetic_repo_test = file_name == "test-require-linked-issue.sh"
                    || file_name == "test_check_contract_change.py"
                    || file_name == "test_native_go_build_abba.py";
                scan_script_or_workflow(&content, !is_synthetic_repo_test, &mut refs);
            }
        }
        Ok(refs)
    }

    pub fn is_referenced(&self, repo_rel_path: &str) -> bool {
        let normalized = repo_rel_path.trim_start_matches("./");
        if self.exact_paths.contains(normalized) {
            return true;
        }
        for prefix in &self.dir_prefixes {
            let dir = prefix.trim_end_matches('/');
            if normalized == dir
                || normalized
                    .strip_prefix(dir)
                    .is_some_and(|rest| rest.starts_with('/'))
            {
                return true;
            }
        }
        false
    }
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), CiChangesError> {
    let entries = fs::read_dir(dir).map_err(|source| CiChangesError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| CiChangesError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| CiChangesError::Io {
            path: path.clone(),
            source,
        })?;
        if file_type.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("target") {
                continue;
            }
            collect_files(&path, out)?;
        } else if file_type.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn scan_rust_source(repo_root: &Path, file: &Path, content: &str, refs: &mut ReferencedDocs) {
    let stripped = strip_rust_comments(content);
    let file_dir = file.parent().unwrap_or(repo_root);
    for literal in extract_rust_string_literals(&stripped) {
        record_candidate_token(repo_root, Some(file_dir), &literal, refs);
    }
}

fn scan_script_or_workflow(content: &str, allow_root_md: bool, refs: &mut ReferencedDocs) {
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') && !trimmed.starts_with("#!") {
            continue;
        }
        for token in extract_path_like_tokens(line) {
            record_script_token(token, allow_root_md, refs);
        }
    }
}

fn record_candidate_token(
    repo_root: &Path,
    file_dir: Option<&Path>,
    raw: &str,
    refs: &mut ReferencedDocs,
) {
    let token = raw.trim().trim_matches(|c: char| {
        matches!(
            c,
            '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | ':'
        )
    });
    if token.is_empty() {
        return;
    }

    // Resolve `../../docs/...` or `../../AGENTS.md` relative to the Rust source directory.
    if token.starts_with("../")
        && let Some(dir) = file_dir
        && let Some(resolved) = normalize_relative_join(repo_root, dir, token)
    {
        record_normalized_doc_ref(&resolved, refs);
        return;
    }

    let cleaned = token.trim_start_matches("./");
    if is_doc_or_agent_prefix_candidate(cleaned) {
        record_normalized_doc_ref(cleaned, refs);
    }
}

fn record_script_token(raw: &str, allow_root_md: bool, refs: &mut ReferencedDocs) {
    let token = raw.trim().trim_matches(|c: char| {
        matches!(
            c,
            '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | ':'
        )
    });
    let cleaned = token.trim_start_matches("./");
    if cleaned.contains("{{") || cleaned.contains("${") {
        return;
    }
    if is_doc_or_agent_prefix_candidate(cleaned)
        || (allow_root_md && is_root_markdown_candidate(cleaned))
    {
        record_normalized_doc_ref(cleaned, refs);
    }
}

fn is_doc_or_agent_prefix_candidate(cleaned: &str) -> bool {
    cleaned.starts_with("docs/") || cleaned.starts_with(".agents/")
}

fn is_root_markdown_candidate(cleaned: &str) -> bool {
    !cleaned.contains('/') && cleaned.ends_with(".md") && cleaned != ".md"
}

fn is_doc_or_agent_candidate(cleaned: &str) -> bool {
    is_doc_or_agent_prefix_candidate(cleaned) || is_root_markdown_candidate(cleaned)
}

fn record_normalized_doc_ref(cleaned: &str, refs: &mut ReferencedDocs) {
    let cleaned = cleaned.split('#').next().unwrap_or(cleaned);
    if cleaned.is_empty() || cleaned == "docs" || cleaned == ".agents" {
        return;
    }
    if let Some((prefix, _)) = cleaned.split_once('*') {
        let dir = prefix.trim_end_matches('/');
        if !dir.is_empty() && dir != "docs" && dir != ".agents" {
            refs.dir_prefixes.insert(dir.to_string());
        }
        return;
    }
    if cleaned.ends_with('/') {
        let dir = cleaned.trim_end_matches('/');
        if !dir.is_empty() && dir != "docs" && dir != ".agents" {
            refs.dir_prefixes.insert(dir.to_string());
        }
        return;
    }
    refs.exact_paths.insert(cleaned.to_string());
    let last_segment = cleaned.rsplit('/').next().unwrap_or(cleaned);
    if !last_segment.contains('.')
        && (cleaned.starts_with("docs/") || cleaned.starts_with(".agents/"))
    {
        refs.dir_prefixes.insert(cleaned.to_string());
    }
}

fn normalize_relative_join(repo_root: &Path, base_dir: &Path, rel: &str) -> Option<String> {
    let repo_rel_base = base_dir.strip_prefix(repo_root).ok()?;
    let mut parts: Vec<&str> = repo_rel_base
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect();
    for segment in rel.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    if is_doc_or_agent_candidate(&joined) {
        Some(joined)
    } else {
        None
    }
}

fn strip_rust_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            let mut depth = 1usize;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                    depth += 1;
                    i += 2;
                } else if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                } else {
                    if bytes[i] == b'\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
            }
            continue;
        }
        if bytes[i] == b'"' {
            out.push('"');
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    out.push(bytes[i] as char);
                    out.push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
                let ch = bytes[i] as char;
                out.push(ch);
                i += 1;
                if ch == '"' {
                    break;
                }
            }
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn extract_rust_string_literals(source: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            i += 1;
            let mut lit = String::new();
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    lit.push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
                if bytes[i] == b'"' {
                    i += 1;
                    break;
                }
                lit.push(bytes[i] as char);
                i += 1;
            }
            literals.push(lit);
        } else {
            i += 1;
        }
    }
    literals
}

fn extract_path_like_tokens(line: &str) -> Vec<&str> {
    line.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '=' | '|'
            )
    })
    .filter(|s| !s.is_empty())
    .collect()
}

pub fn classify_path(path: &str, referenced_docs: &ReferencedDocs) -> PathClass {
    let normalized = path.trim().trim_start_matches("./");
    if normalized.is_empty() {
        return PathClass::CodeOrReferencedDoc;
    }

    // 1. Docs / agent instructions / root markdown / LICENSE:
    // Any path referenced by code, tests, scripts, justfile, or workflows is heavy!
    if normalized.starts_with("docs/")
        || normalized.starts_with(".agents/")
        || (!normalized.contains('/') && normalized.ends_with(".md"))
    {
        if referenced_docs.is_referenced(normalized) {
            return PathClass::CodeOrReferencedDoc;
        }
        if normalized.ends_with(".md") {
            return PathClass::Prose;
        }
        // Non-markdown files under `docs/` or `.agents/` (e.g. `.tsv`, `.json`, `.py`, `.sh`)
        // fail safe as heavy even if a new reference pattern wasn't matched.
        return PathClass::CodeOrReferencedDoc;
    }
    if !normalized.contains('/') && normalized.starts_with("LICENSE") {
        return PathClass::Prose;
    }

    // 2. CI xtask & scripts (`crates/carrick-xtask/**`, `scripts/**`, `justfile`):
    // Runs heavy Linux (`lint`, `fmt`, `clippy`, `check-test-shards`, xtask tests) with
    // `macos=false` and `hardware=false`.
    if normalized == "justfile"
        || normalized.starts_with("crates/carrick-xtask/")
        || normalized.starts_with("scripts/")
    {
        return PathClass::CiXtask;
    }

    // 3. Workflows (`.github/workflows/**`, `.github/**`):
    // Runs the lanes the workflow defines.
    if normalized == ".github/workflows/ci.yml" || normalized == ".github/actionlint.yaml" {
        return PathClass::WorkflowCi;
    }
    if normalized.starts_with(".github/") {
        return PathClass::WorkflowHardware;
    }

    // 4. Fail-safe: any unknown or product/test path runs everything.
    PathClass::CodeOrReferencedDoc
}

pub fn evaluate_changes(
    event_name: &str,
    pr_draft: bool,
    changed_paths: Option<&[String]>,
    referenced_docs: &ReferencedDocs,
) -> CiChangesOutputs {
    // Non-PR/non-merge_group events (schedule, workflow_dispatch, push) always run everything.
    if event_name != "pull_request" && event_name != "merge_group" {
        return CiChangesOutputs {
            heavy: true,
            macos: true,
            workflows: true,
            hardware: true,
        };
    }

    let is_merge_group = event_name == "merge_group";
    let Some(paths) = changed_paths else {
        return CiChangesOutputs {
            heavy: true,
            macos: is_merge_group,
            workflows: true,
            hardware: true,
        };
    };

    if paths.is_empty() {
        return CiChangesOutputs {
            heavy: true,
            macos: is_merge_group,
            workflows: true,
            hardware: true,
        };
    }

    let mut heavy = false;
    let mut needs_macos = false;
    let mut workflows = false;
    let mut hardware = false;

    for path in paths {
        match classify_path(path, referenced_docs) {
            PathClass::Prose => {}
            PathClass::CiXtask => {
                heavy = true;
            }
            PathClass::WorkflowCi => {
                heavy = true;
                needs_macos = true;
                workflows = true;
            }
            PathClass::WorkflowHardware => {
                heavy = true;
                workflows = true;
                hardware = true;
            }
            PathClass::CodeOrReferencedDoc => {
                heavy = true;
                needs_macos = true;
                hardware = true;
            }
        }
    }

    let _ = pr_draft;
    CiChangesOutputs {
        heavy,
        macos: is_merge_group && needs_macos,
        workflows,
        hardware,
    }
}

fn git_commit_exists(repo_root: &Path, rev: &str) -> bool {
    Command::new("git")
        .current_dir(repo_root)
        .args(["cat-file", "-e", &format!("{rev}^{{commit}}")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn git_has_origin(repo_root: &Path) -> bool {
    Command::new("git")
        .current_dir(repo_root)
        .args(["remote", "get-url", "origin"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn git_fetch_origin(repo_root: &Path, rev: &str) -> Result<(), CiChangesError> {
    let status = Command::new("git")
        .current_dir(repo_root)
        .args(["fetch", "--no-tags", "origin", rev])
        .status()
        .map_err(|source| CiChangesError::Io {
            path: PathBuf::from("git"),
            source,
        })?;
    if !status.success() {
        return Err(CiChangesError::Git(format!(
            "git fetch --no-tags origin {rev} failed ({status})"
        )));
    }
    Ok(())
}

fn git_diff_null_paths(
    repo_root: &Path,
    base: &str,
    head: &str,
    out: &mut Vec<String>,
) -> Result<(), CiChangesError> {
    let range = format!("{base}...{head}");
    let output = Command::new("git")
        .current_dir(repo_root)
        .args(["diff", "--no-renames", "--name-only", "-z", &range])
        .output()
        .map_err(|source| CiChangesError::Io {
            path: PathBuf::from("git"),
            source,
        })?;
    if !output.status.success() {
        return Err(CiChangesError::Git(format!(
            "git diff --no-renames --name-only -z {range} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    for entry in output.stdout.split(|b| *b == 0) {
        if !entry.is_empty() {
            out.push(String::from_utf8_lossy(entry).into_owned());
        }
    }
    Ok(())
}

pub fn collect_changed_paths(
    repo_root: &Path,
    event: &str,
    base: &str,
    base_ref: &str,
    head: &str,
) -> Result<Option<Vec<String>>, CiChangesError> {
    if event != "pull_request" && event != "merge_group" {
        return Ok(None);
    }
    let base = base.trim();
    if base.is_empty() {
        return Err(CiChangesError::Git(
            "CI_BASE is required for pull_request and merge_group".into(),
        ));
    }
    if !git_commit_exists(repo_root, base) {
        git_fetch_origin(repo_root, base)?;
    }
    let mut paths = Vec::new();
    git_diff_null_paths(repo_root, base, head, &mut paths)?;
    let base_ref = base_ref.trim();
    if event == "merge_group" && !base_ref.is_empty() {
        if git_commit_exists(repo_root, base_ref) {
            git_diff_null_paths(repo_root, base_ref, head, &mut paths)?;
        } else if git_has_origin(repo_root) {
            git_fetch_origin(repo_root, base_ref)?;
            git_diff_null_paths(repo_root, "FETCH_HEAD", head, &mut paths)?;
        } else {
            git_diff_null_paths(repo_root, base_ref, head, &mut paths)?;
        }
    }
    Ok(Some(paths))
}

pub fn run<W: Write>(
    repo_root: &Path,
    args: CiChangesArgs,
    writer: &mut W,
) -> Result<CiChangesOutputs, CiChangesError> {
    let event = args.event.trim();
    if event.is_empty() {
        return Err(CiChangesError::Git("CI_EVENT must be set".into()));
    }
    let referenced_docs = ReferencedDocs::discover(repo_root)?;
    let pr_draft = args.draft.trim() == "true";
    let changed_paths =
        collect_changed_paths(repo_root, event, &args.base, &args.base_ref, &args.head)?;
    let outputs = evaluate_changes(event, pr_draft, changed_paths.as_deref(), &referenced_docs);
    let formatted = outputs.format_github_output();
    if let Some(output_path) = &args.github_output {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(output_path)
            .map_err(|source| CiChangesError::Io {
                path: output_path.clone(),
                source,
            })?;
        file.write_all(formatted.as_bytes())
            .map_err(|source| CiChangesError::Io {
                path: output_path.clone(),
                source,
            })?;
    }
    writeln!(
        writer,
        "Run hosted checks: heavy={} macos={} workflows={} hardware={}",
        outputs.heavy, outputs.macos, outputs.workflows, outputs.hardware
    )
    .map_err(|source| CiChangesError::Io {
        path: PathBuf::from("stdout"),
        source,
    })?;
    Ok(outputs)
}
