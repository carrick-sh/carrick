use clap::Args;
use serde::{Deserialize, Serialize};
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

    #[arg(long, env = "CI_HEAD_REF", default_value = "")]
    pub head_ref: String,

    #[arg(long, env = "CI_REPO", default_value = "carrick-sh/carrick")]
    pub repo: String,

    /// `owner/name` of the PR's head repository. Only a same-repository PR can be a
    /// lower stack layer: a fork's branch name is outsider-chosen and must never
    /// match this repository's base branches.
    #[arg(long, env = "CI_HEAD_REPO", default_value = "")]
    pub head_repo: String,

    #[arg(long, default_value = "HEAD")]
    pub head: String,

    #[arg(long, env = "GITHUB_OUTPUT")]
    pub github_output: Option<PathBuf>,

    #[arg(long, env = "GITHUB_STEP_SUMMARY")]
    pub step_summary: Option<PathBuf>,

    /// Optional JSON file path to write the classification (`{heavy, macos, workflows, hardware}`)
    /// so `kernel-runtime.yml` can upload `ci-class-<sha>.json` as positive fast-path evidence.
    #[arg(long, env = "CI_CLASS_JSON")]
    pub json_out: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiChangesOutputs {
    pub heavy: bool,
    pub macos: bool,
    #[serde(default)]
    pub workflows: bool,
    pub hardware: bool,
    #[serde(default)]
    pub lower_layer: bool,
}

impl CiChangesOutputs {
    pub fn format_github_output(&self) -> String {
        format!(
            "heavy={}\nmacos={}\nworkflows={}\nhardware={}\nlower_layer={}\n",
            self.heavy, self.macos, self.workflows, self.hardware, self.lower_layer
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathClass {
    /// True unreferenced prose (`*.md` under `docs/`, `.agents/`, or repo root, plus `LICENSE*`).
    Prose,
    /// `.github/workflows/**` or `.github/actionlint.yaml`: runs the full heavy, macOS (on
    /// `merge_group`), and hardware suite, plus `actionlint` (`workflows=true`).
    Workflow,
    /// Code, Cargo manifests, `justfile`, `scripts/**`, `crates/carrick-xtask/**`, other
    /// `.github/**`, or any referenced doc/agent file: runs all heavy, macOS (on `merge_group`),
    /// and hardware lanes.
    Full,
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

pub fn scan_rust_source(repo_root: &Path, file: &Path, content: &str, refs: &mut ReferencedDocs) {
    let stripped = strip_rust_comments(content);
    let file_dir = file.parent().unwrap_or(repo_root);
    for line in stripped.lines() {
        let literals = extract_rust_string_literals(line);
        let is_path_join_line = line.contains(".join(")
            || line.contains("Path::new(")
            || line.contains("PathBuf::from(")
            || line.contains("read_to_string(")
            || line.contains("fs::read(");
        for literal in literals {
            record_candidate_token(repo_root, Some(file_dir), &literal, is_path_join_line, refs);
        }
    }
}

pub fn scan_script_or_workflow(content: &str, allow_root_md: bool, refs: &mut ReferencedDocs) {
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') && !trimmed.starts_with("#!") {
            continue;
        }
        // Check for path joins built from pieces in Python/shell scripts, e.g.
        // `root / "docs" / "conformance-exemptions"` or `os.path.join(ROOT, "docs", "conformance-coverage.md")`.
        scan_piecewise_path_joins(line, refs);
        for token in extract_path_like_tokens(line) {
            record_script_token(token, allow_root_md, refs);
        }
    }
}

fn scan_piecewise_path_joins(line: &str, refs: &mut ReferencedDocs) {
    let literals = extract_double_or_single_quoted_literals(line);
    for (idx, seg) in literals.iter().enumerate() {
        if *seg != "docs" && *seg != ".agents" {
            continue;
        }
        let is_join_context = line.contains("os.path.join")
            || line.contains(".join(")
            || line.contains(" / \"docs\"")
            || line.contains(" / 'docs'")
            || line.contains("\"/\"docs\"")
            || line.contains(" / \".agents\"")
            || line.contains(" / '.agents'");
        if !is_join_context {
            continue;
        }
        // Try to resolve literal segments immediately following `"docs"` or `".agents"` in the
        // same join expression; if we cannot resolve a sub-path, mark the entire `docs` or
        // `.agents` tree as referenced (fail-safe).
        let mut parts = vec![seg.as_str()];
        for next in literals.iter().skip(idx + 1) {
            if next.is_empty() || next.contains(' ') || next.starts_with('-') {
                break;
            }
            parts.push(next.as_str());
        }
        let has_dynamic_tail = is_unresolvable_piecewise_join(line, seg, parts.len() > 1);
        if parts.len() > 1 && !has_dynamic_tail {
            let joined = parts.join("/");
            record_normalized_doc_ref(&joined, refs);
        } else {
            // A bare `docs` / `.agents` path segment with no resolved literal subpath, or a path
            // join the classifier cannot statically resolve, counts as heavy for every `docs/**`
            // or `.agents/**` file.
            refs.dir_prefixes.insert((*seg).to_string());
        }
    }
}

fn is_unresolvable_piecewise_join(line: &str, seg: &str, has_following_literal: bool) -> bool {
    if !has_following_literal {
        return true;
    }
    let double_pat = format!("\"{seg}\"");
    let single_pat = format!("'{seg}'");
    let after = line
        .split_once(&double_pat)
        .or_else(|| line.split_once(&single_pat))
        .map(|(_, rest)| rest.trim_start())
        .unwrap_or("");
    // After `"docs"`, if the next operator is `/` or `,`, check whether the operand is a string literal.
    if let Some(rest) = after
        .strip_prefix('/')
        .or_else(|| after.strip_prefix(','))
        .map(str::trim_start)
    {
        return !rest.starts_with('"') && !rest.starts_with('\'');
    }
    false
}

fn extract_double_or_single_quoted_literals(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let quote = bytes[i];
        if quote == b'"' || quote == b'\'' {
            i += 1;
            let mut lit = String::new();
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    lit.push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
                if bytes[i] == quote {
                    i += 1;
                    break;
                }
                lit.push(bytes[i] as char);
                i += 1;
            }
            out.push(lit);
        } else {
            i += 1;
        }
    }
    out
}

fn record_candidate_token(
    repo_root: &Path,
    file_dir: Option<&Path>,
    raw: &str,
    is_path_join_line: bool,
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
    if is_path_join_line && (cleaned == "docs" || cleaned == ".agents") {
        refs.dir_prefixes.insert(cleaned.to_string());
        return;
    }
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
        if let Some((prefix, _)) = cleaned
            .split_once("${")
            .or_else(|| cleaned.split_once("{{"))
        {
            let dir = prefix.trim_end_matches('/');
            if dir == "docs" || dir == ".agents" || is_doc_or_agent_prefix_candidate(dir) {
                refs.dir_prefixes.insert(dir.to_string());
            }
        }
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
    cleaned == "docs"
        || cleaned == ".agents"
        || is_doc_or_agent_prefix_candidate(cleaned)
        || is_root_markdown_candidate(cleaned)
}

fn record_normalized_doc_ref(cleaned: &str, refs: &mut ReferencedDocs) {
    let cleaned = cleaned.split('#').next().unwrap_or(cleaned);
    if cleaned.is_empty() {
        return;
    }
    if cleaned == "docs" || cleaned == ".agents" {
        refs.dir_prefixes.insert(cleaned.to_string());
        return;
    }
    if let Some((prefix, _)) = cleaned.split_once('*') {
        let dir = prefix.trim_end_matches('/');
        if !dir.is_empty() {
            refs.dir_prefixes.insert(dir.to_string());
        }
        return;
    }
    if cleaned.ends_with('/') {
        let dir = cleaned.trim_end_matches('/');
        if !dir.is_empty() {
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
        return PathClass::Full;
    }

    // 1. Docs / agent instructions / root markdown / LICENSE:
    // Any path referenced by code, tests, scripts, justfile, or workflows is heavy!
    if normalized.starts_with("docs/")
        || normalized.starts_with(".agents/")
        || (!normalized.contains('/') && normalized.ends_with(".md"))
    {
        if referenced_docs.is_referenced(normalized) {
            return PathClass::Full;
        }
        if normalized.ends_with(".md") {
            return PathClass::Prose;
        }
        // Non-markdown files under `docs/` or `.agents/` (e.g. `.tsv`, `.json`, `.py`, `.sh`)
        // fail safe as heavy even if a new reference pattern wasn't matched.
        return PathClass::Full;
    }
    if !normalized.contains('/') && normalized.starts_with("LICENSE") {
        return PathClass::Prose;
    }

    // 2. Workflows (`.github/workflows/**`, `.github/actionlint.yaml`):
    // Runs the full set plus `actionlint` (`workflows=true`).
    if normalized.starts_with(".github/workflows/") || normalized == ".github/actionlint.yaml" {
        return PathClass::Workflow;
    }

    // 3. Everything else (`justfile`, `scripts/**`, `crates/**` including `carrick-xtask`,
    // `.github/**`, and any unknown path) runs the full set as main does today.
    PathClass::Full
}

pub fn evaluate_changes(
    event_name: &str,
    pr_draft: bool,
    has_child_layer: bool,
    changed_paths: Option<&[String]>,
    referenced_docs: &ReferencedDocs,
) -> CiChangesOutputs {
    // Only pull_request events may use the docs-only fast path, draft skip, or lower-layer skip.
    // Merge groups, schedule, workflow_dispatch, and push always run everything.
    if event_name != "pull_request" {
        return CiChangesOutputs {
            heavy: true,
            macos: true,
            workflows: true,
            hardware: true,
            lower_layer: false,
        };
    }

    let Some(paths) = changed_paths else {
        return CiChangesOutputs {
            heavy: true,
            macos: true,
            workflows: true,
            hardware: true,
            lower_layer: false,
        };
    };

    if paths.is_empty() {
        return CiChangesOutputs {
            heavy: true,
            macos: true,
            workflows: true,
            hardware: true,
            lower_layer: false,
        };
    }

    let mut heavy = false;
    let mut workflows = false;

    for path in paths {
        match classify_path(path, referenced_docs) {
            PathClass::Prose => {}
            PathClass::Workflow => {
                heavy = true;
                workflows = true;
            }
            PathClass::Full => {
                heavy = true;
            }
        }
    }

    let _ = pr_draft;
    // Pull requests run the full macOS suite whenever they run heavy jobs; the
    // same-repo ones land on the self-hosted carrick-macos-ci runners (#650).
    // Merge groups keep the macOS build, clippy and authority census.
    CiChangesOutputs {
        heavy,
        macos: heavy,
        workflows,
        hardware: heavy,
        lower_layer: has_child_layer,
    }
}

/// Only a same-repository `pull_request` with a head branch may look for child
/// layers. A fork PR (head repo differs, or unknown) always runs the full suite.
pub fn child_lookup_allowed(event: &str, head_ref: &str, head_repo: &str, repo: &str) -> bool {
    event == "pull_request"
        && !head_ref.trim().is_empty()
        && !head_repo.trim().is_empty()
        && head_repo.trim().eq_ignore_ascii_case(repo.trim())
}

pub fn lookup_child_pr(repo: &str, head_ref: &str) -> Result<Option<u64>, CiChangesError> {
    let head_ref = head_ref.trim();
    if head_ref.is_empty() {
        return Ok(None);
    }
    let repo = if repo.trim().is_empty() {
        "carrick-sh/carrick"
    } else {
        repo.trim()
    };
    let mut cmd = Command::new("gh");
    cmd.args([
        "api",
        "--method",
        "GET",
        "-f",
        "state=open",
        "-f",
        &format!("base={head_ref}"),
        "-f",
        "per_page=100",
        &format!("repos/{repo}/pulls"),
    ]);
    if let Ok(token) = std::env::var("GITHUB_TOKEN")
        && !token.is_empty()
        && std::env::var_os("GH_TOKEN").is_none()
    {
        cmd.env("GH_TOKEN", token);
    }
    let output = cmd.output().map_err(|source| CiChangesError::Io {
        path: PathBuf::from("gh"),
        source,
    })?;
    if !output.status.success() {
        return Err(CiChangesError::Git(format!(
            "gh api repos/{repo}/pulls?state=open&base={head_ref} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|source| {
        CiChangesError::Git(format!(
            "parse gh api repos/{repo}/pulls response: {source}"
        ))
    })?;
    let prs = value.as_array().ok_or_else(|| {
        CiChangesError::Git("gh api pulls response is not a JSON array".to_string())
    })?;
    let mut child_numbers = Vec::new();
    for pr in prs {
        if pr["state"].as_str().is_some_and(|s| s != "open") {
            continue;
        }
        if pr["base"]["ref"].as_str().is_some_and(|r| r != head_ref) {
            continue;
        }
        let number = pr["number"].as_u64().ok_or_else(|| {
            CiChangesError::Git("pull request entry missing numeric number".to_string())
        })?;
        child_numbers.push(number);
    }
    Ok(child_numbers.into_iter().min())
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
    if event != "pull_request" {
        return Ok(None);
    }
    let base = base.trim();
    if base.is_empty() {
        return Err(CiChangesError::Git(
            "CI_BASE is required for pull_request".into(),
        ));
    }
    if !git_commit_exists(repo_root, base) {
        git_fetch_origin(repo_root, base)?;
    }
    let mut paths = Vec::new();
    git_diff_null_paths(repo_root, base, head, &mut paths)?;
    let _ = base_ref;
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
    let mut lookup_failed = false;
    let child_pr = if child_lookup_allowed(event, &args.head_ref, &args.head_repo, &args.repo) {
        match lookup_child_pr(&args.repo, &args.head_ref) {
            Ok(pr) => pr,
            Err(err) => {
                lookup_failed = true;
                writeln!(
                    writer,
                    "Child PR lookup failed ({err}); failing closed to full suite"
                )
                .map_err(|source| CiChangesError::Io {
                    path: PathBuf::from("stdout"),
                    source,
                })?;
                None
            }
        }
    } else {
        None
    };
    let has_child_layer = child_pr.is_some();
    let mut outputs = evaluate_changes(
        event,
        pr_draft,
        has_child_layer,
        changed_paths.as_deref(),
        &referenced_docs,
    );
    if lookup_failed {
        // Fail closed: a heavy PR also runs the macOS suite (#650).
        outputs.heavy = true;
        outputs.macos = true;
        outputs.hardware = true;
        outputs.lower_layer = false;
    }
    let mut formatted = outputs.format_github_output();
    if let Some(pr_num) = child_pr {
        formatted.push_str(&format!("child_pr={pr_num}\n"));
    }
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
    if let Some(json_path) = &args.json_out {
        if let Some(parent) = json_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|source| CiChangesError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let json_bytes = serde_json::to_vec(&outputs)
            .map_err(|source| CiChangesError::Git(format!("serialize ci-class.json: {source}")))?;
        fs::write(json_path, json_bytes).map_err(|source| CiChangesError::Io {
            path: json_path.clone(),
            source,
        })?;
    }
    if let Some(pr_num) = child_pr {
        let reason = format!("lower stack layer: child PR #{pr_num}");
        writeln!(writer, "{reason}").map_err(|source| CiChangesError::Io {
            path: PathBuf::from("stdout"),
            source,
        })?;
        if let Some(summary_path) = &args.step_summary {
            let mut summary_file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(summary_path)
                .map_err(|source| CiChangesError::Io {
                    path: summary_path.clone(),
                    source,
                })?;
            writeln!(summary_file, "{reason}").map_err(|source| CiChangesError::Io {
                path: summary_path.clone(),
                source,
            })?;
        }
    }
    writeln!(
        writer,
        "Run hosted checks: heavy={} macos={} workflows={} hardware={} lower_layer={}",
        outputs.heavy, outputs.macos, outputs.workflows, outputs.hardware, outputs.lower_layer
    )
    .map_err(|source| CiChangesError::Io {
        path: PathBuf::from("stdout"),
        source,
    })?;
    Ok(outputs)
}
