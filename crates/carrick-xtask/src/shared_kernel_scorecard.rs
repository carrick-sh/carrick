//! Shared guest-kernel scorecard: measures compiled sharing between the aarch64
//! EL1 guest image and the x86_64 CPL0 guest image.
//!
//! Rebuilds the guest images the same way production build scripts build them,
//! collects the dep-info (`.d`) files rustc emits, identifies repo-local `.rs`
//! sources, and computes line sharing (non-blank, non-comment), per-crate
//! breakdowns, internal `cfg(target_arch ...)` forks in shared files, and defect
//! counts from `docs/shared-kernel-ledger.toml`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(clap::Args, Debug, Clone)]
pub struct ScorecardArgs {
    #[arg(long, help = "Output results in JSON format")]
    pub json: bool,

    #[arg(long, help = "Base git revision to compare against")]
    pub base: Option<String>,
}

#[derive(Debug, Error)]
pub enum ScorecardError {
    #[error("command error: {0}")]
    Command(#[from] crate::command::CommandError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to run cargo build for {image} (exit code: {status})\n{stderr}")]
    BuildFailed {
        image: &'static str,
        status: std::process::ExitStatus,
        stderr: String,
    },
    #[error("failed to parse TOML ledger {path}: {source}")]
    LedgerToml {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("failed to serialize JSON output: {0}")]
    Json(#[from] serde_json::Error),
    #[error("git error: {0}")]
    Git(String),
    #[error("format error: {0}")]
    Fmt(#[from] std::fmt::Error),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DefectCounts {
    pub total: usize,
    pub x86_kvm: usize,
    pub arm_hvf: usize,
    pub other: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedKernelLedger {
    pub schema_version: u32,
    #[serde(default, alias = "defects")]
    pub entries: Vec<DefectEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefectEntry {
    pub date: String,
    pub commit: String,
    pub title: String,
    #[serde(rename = "crate")]
    pub krate: String,
    pub found_on: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrateScorecard {
    pub crate_name: String,
    pub shared_lines: usize,
    pub el1_only_lines: usize,
    pub cpl0_only_lines: usize,
}

impl CrateScorecard {
    pub fn total_lines(&self) -> usize {
        self.shared_lines + self.el1_only_lines + self.cpl0_only_lines
    }

    pub fn shared_percent(&self) -> f64 {
        let total = self.total_lines();
        if total == 0 {
            0.0
        } else {
            (self.shared_lines as f64 / total as f64) * 100.0
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScorecardReport {
    pub revision: String,
    pub shared_lines: usize,
    pub el1_only_lines: usize,
    pub cpl0_only_lines: usize,
    pub total_lines: usize,
    pub shared_percent: f64,
    pub shared_files_count: usize,
    pub el1_only_files_count: usize,
    pub cpl0_only_files_count: usize,
    pub cfg_target_arch_forks: usize,
    pub crates: Vec<CrateScorecard>,
    pub defects: DefectCounts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScorecardOutput {
    pub current: ScorecardReport,
    pub base: Option<ScorecardReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestImage {
    El1,
    Cpl0,
}

impl GuestImage {
    pub fn name(self) -> &'static str {
        match self {
            GuestImage::El1 => "carrick-el1 (aarch64 EL1)",
            GuestImage::Cpl0 => "carrick-x86-cpl0 (x86_64 CPL0)",
        }
    }

    pub fn target(self) -> &'static str {
        match self {
            GuestImage::El1 => "aarch64-unknown-none-softfloat",
            GuestImage::Cpl0 => "x86_64-unknown-none",
        }
    }
}

pub fn read_defects_ledger(repo_root: &Path) -> Result<DefectCounts, ScorecardError> {
    let ledger_path = repo_root.join("docs/shared-kernel-ledger.toml");
    if !ledger_path.exists() {
        return Ok(DefectCounts::default());
    }

    let text = std::fs::read_to_string(&ledger_path)?;
    let ledger: SharedKernelLedger =
        toml::from_str(&text).map_err(|source| ScorecardError::LedgerToml {
            path: ledger_path,
            source,
        })?;

    let mut counts = DefectCounts {
        total: ledger.entries.len(),
        ..DefectCounts::default()
    };

    for entry in &ledger.entries {
        match entry.found_on.as_str() {
            "x86-kvm" => counts.x86_kvm += 1,
            "arm-hvf" => counts.arm_hvf += 1,
            _ => counts.other += 1,
        }
    }

    Ok(counts)
}

/// Parse prerequisites from Makefile-style `.d` dep-info content.
pub fn parse_dep_info(content: &str) -> Vec<PathBuf> {
    let mut prerequisites = Vec::new();
    for rule in content.replace("\\\n", " ").lines() {
        if rule.trim_start().starts_with('#') {
            continue;
        }
        let mut in_prerequisites = false;
        for token in dep_info_tokens(rule) {
            if in_prerequisites {
                prerequisites.push(PathBuf::from(token));
            } else if token.ends_with(':') {
                in_prerequisites = true;
            }
        }
    }
    prerequisites
}

fn dep_info_tokens(rule: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = rule.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&' ') => {
                current.push(' ');
                chars.next();
            }
            '\\' if chars.peek() == Some(&'\\') => {
                current.push('\\');
                chars.next();
            }
            c if c.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Count non-blank, non-comment-only lines in Rust source code.
pub fn count_code_lines(content: &str) -> usize {
    let mut code_lines = 0;
    let mut in_block_comment = 0;
    let mut in_string = false;
    let mut in_raw_string = None;
    let mut escaped = false;

    for line in content.lines() {
        let mut has_code = false;
        let mut chars = line.chars().peekable();

        while let Some(c) = chars.next() {
            if in_block_comment > 0 {
                if c == '/' && chars.peek() == Some(&'*') {
                    chars.next();
                    in_block_comment += 1;
                } else if c == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    in_block_comment -= 1;
                }
                continue;
            }

            if let Some(hashes) = in_raw_string {
                has_code = true;
                if c == '"' {
                    let mut matched_hashes = 0;
                    while matched_hashes < hashes && chars.peek() == Some(&'#') {
                        chars.next();
                        matched_hashes += 1;
                    }
                    if matched_hashes == hashes {
                        in_raw_string = None;
                    }
                }
                continue;
            }

            if in_string {
                has_code = true;
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_string = false;
                }
                continue;
            }

            // Normal state
            if c.is_whitespace() {
                continue;
            }

            if c == '/' {
                if chars.peek() == Some(&'/') {
                    // Line comment ends this line
                    break;
                } else if chars.peek() == Some(&'*') {
                    chars.next();
                    in_block_comment = 1;
                    continue;
                }
            }

            if c == '"' {
                has_code = true;
                in_string = true;
                escaped = false;
                continue;
            }

            if c == 'r' {
                let mut hash_count = 0;
                let mut is_raw = false;
                let mut lookahead = chars.clone();
                while let Some(&peek) = lookahead.peek() {
                    if peek == '#' {
                        lookahead.next();
                        hash_count += 1;
                    } else if peek == '"' {
                        lookahead.next();
                        is_raw = true;
                        break;
                    } else {
                        break;
                    }
                }
                if is_raw {
                    has_code = true;
                    chars = lookahead;
                    in_raw_string = Some(hash_count);
                    continue;
                }
            }

            has_code = true;
        }

        if has_code {
            code_lines += 1;
        }
    }

    code_lines
}

/// Strip comments from Rust source, preserving string contents.
pub fn strip_comments(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut in_block_comment = 0;
    let mut in_string = false;
    let mut in_raw_string = None;
    let mut escaped = false;

    let mut chars = content.chars().peekable();
    while let Some(c) = chars.next() {
        if in_block_comment > 0 {
            if c == '/' && chars.peek() == Some(&'*') {
                chars.next();
                in_block_comment += 1;
            } else if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment -= 1;
            }
            if in_block_comment == 0 {
                out.push(' ');
            }
            continue;
        }

        if let Some(hashes) = in_raw_string {
            out.push(c);
            if c == '"' {
                let mut matched_hashes = 0;
                let mut lookahead = chars.clone();
                while matched_hashes < hashes && lookahead.peek() == Some(&'#') {
                    lookahead.next();
                    matched_hashes += 1;
                }
                if matched_hashes == hashes {
                    for _ in 0..hashes {
                        out.push(chars.next().unwrap_or('#'));
                    }
                    in_raw_string = None;
                }
            }
            continue;
        }

        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }

        if c == '/' {
            if chars.peek() == Some(&'/') {
                // Line comment
                chars.next();
                while let Some(&next) = chars.peek() {
                    if next == '\n' {
                        break;
                    }
                    chars.next();
                }
                out.push('\n');
                continue;
            } else if chars.peek() == Some(&'*') {
                chars.next();
                in_block_comment = 1;
                continue;
            }
        }

        if c == '"' {
            out.push(c);
            in_string = true;
            escaped = false;
            continue;
        }

        if c == 'r' {
            let mut hash_count = 0;
            let mut is_raw = false;
            let mut lookahead = chars.clone();
            while let Some(&peek) = lookahead.peek() {
                if peek == '#' {
                    lookahead.next();
                    hash_count += 1;
                } else if peek == '"' {
                    lookahead.next();
                    is_raw = true;
                    break;
                } else {
                    break;
                }
            }
            if is_raw {
                out.push('r');
                for _ in 0..hash_count {
                    out.push(chars.next().unwrap_or('#'));
                }
                out.push(chars.next().unwrap_or('"'));
                in_raw_string = Some(hash_count);
                continue;
            }
        }

        out.push(c);
    }
    out
}

/// Count `cfg(target_arch ...)` sites in Rust source.
pub fn count_cfg_target_arch_sites(content: &str) -> usize {
    let clean = strip_comments(content);
    let mut count = 0;
    let chars: Vec<char> = clean.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Look for `cfg` keyword
        if i + 3 <= len
            && chars[i] == 'c'
            && chars[i + 1] == 'f'
            && chars[i + 2] == 'g'
            && (i == 0 || !is_ident_char(chars[i - 1]))
        {
            let mut j = i + 3;
            // Handle `cfg!` or `cfg_attr`
            if j < len && chars[j] == '!' {
                j += 1;
            } else if j + 5 <= len
                && chars[j] == '_'
                && chars[j + 1] == 'a'
                && chars[j + 2] == 't'
                && chars[j + 3] == 't'
                && chars[j + 4] == 'r'
            {
                j += 5;
            }

            // Skip whitespace before '('
            while j < len && chars[j].is_whitespace() {
                j += 1;
            }

            if j < len && chars[j] == '(' {
                // Find matching ')'
                let mut depth = 1;
                let start = j + 1;
                j += 1;
                while j < len && depth > 0 {
                    if chars[j] == '(' {
                        depth += 1;
                    } else if chars[j] == ')' {
                        depth -= 1;
                    }
                    j += 1;
                }
                let end = if depth == 0 { j - 1 } else { j };
                let cfg_slice: String = chars[start..end].iter().collect();
                count += count_ident_occurrences(&cfg_slice, "target_arch");
                i = j;
                continue;
            }
        }
        i += 1;
    }

    count
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn count_ident_occurrences(slice: &str, target: &str) -> usize {
    let mut count = 0;
    let chars: Vec<char> = slice.chars().collect();
    let t_chars: Vec<char> = target.chars().collect();
    let t_len = t_chars.len();
    let len = chars.len();

    if len < t_len {
        return 0;
    }

    let mut i = 0;
    while i + t_len <= len {
        let is_match = (0..t_len).all(|k| chars[i + k] == t_chars[k]);
        if is_match {
            let prev_ok = i == 0 || !is_ident_char(chars[i - 1]);
            let next_ok = i + t_len == len || !is_ident_char(chars[i + t_len]);
            if prev_ok && next_ok {
                count += 1;
                i += t_len;
                continue;
            }
        }
        i += 1;
    }

    count
}

pub fn crate_of_path(path: &Path) -> String {
    let mut components = path.components();
    if let Some(Component::Normal(first)) = components.next() {
        if first == "crates" {
            if let Some(Component::Normal(crate_name)) = components.next() {
                return crate_name.to_string_lossy().to_string();
            }
        } else {
            return first.to_string_lossy().to_string();
        }
    }
    "other".to_string()
}

fn run_image_build(
    repo_root: &Path,
    image: GuestImage,
    target_dir: &Path,
) -> Result<(), ScorecardError> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(&cargo);
    cmd.current_dir(repo_root);
    cmd.env_remove("CARGO_MAKEFLAGS");
    cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");

    // Exact invocation matching crates/carrick-el1-image/build.rs and
    // crates/carrick-vmm-kvm/build.rs (same target, features, profile and RUSTFLAGS).
    match image {
        GuestImage::El1 => {
            cmd.args([
                "build",
                "--locked",
                "-p",
                "carrick-el1",
                "--target",
                image.target(),
                "--release",
                "--target-dir",
            ]);
            cmd.arg(target_dir);
            if std::env::var_os("CARGO_FEATURE_ALLOCATOR_TEST_CONTROL").is_some() {
                cmd.arg("--features").arg("allocator-test-control");
            }
        }
        GuestImage::Cpl0 => {
            cmd.args([
                "build",
                "--locked",
                "--release",
                "-p",
                "carrick-x86-cpl0",
                "--bin",
                "carrick-x86-cpl0",
                "--target",
                image.target(),
                "--target-dir",
            ]);
            cmd.arg(target_dir);
        }
    }

    let output = cmd.output()?;
    if !output.status.success() {
        return Err(ScorecardError::BuildFailed {
            image: image.name(),
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }
    Ok(())
}

fn collect_compiled_sources(
    repo_root: &Path,
    target_dir: &Path,
    target: &str,
) -> Result<BTreeSet<PathBuf>, ScorecardError> {
    let canonical_root = repo_root.canonicalize()?;
    let mut sources = BTreeSet::new();

    for search_dir in [
        target_dir.join(target).join("release/deps"),
        target_dir.join(target).join("release"),
    ] {
        if !search_dir.is_dir() {
            continue;
        }

        let entries = std::fs::read_dir(&search_dir)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("d") {
                continue;
            }

            let content = std::fs::read_to_string(&path)?;
            let prereqs = parse_dep_info(&content);
            for prereq in prereqs {
                if prereq.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let resolved = if prereq.is_absolute() {
                    prereq
                } else {
                    canonical_root.join(prereq)
                };
                let Ok(canonical) = resolved.canonicalize() else {
                    continue;
                };
                if let Ok(relative) = canonical.strip_prefix(&canonical_root) {
                    if relative.starts_with("target") || relative.starts_with(".cargo") {
                        continue;
                    }
                    sources.insert(relative.to_path_buf());
                }
            }
        }
    }

    Ok(sources)
}

fn get_git_revision(repo_root: &Path, rev: Option<&str>) -> String {
    let mut cmd = Command::new("git");
    cmd.current_dir(repo_root).arg("rev-parse");
    if let Some(r) = rev {
        cmd.arg(r);
    } else {
        cmd.arg("HEAD");
    }
    match cmd.output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => rev.unwrap_or("HEAD").to_string(),
    }
}

pub fn measure_checkout(repo_root: &Path) -> Result<ScorecardReport, ScorecardError> {
    let scorecard_dir = repo_root.join("target/scorecard");
    let el1_target_dir = scorecard_dir.join("el1");
    let cpl0_target_dir = scorecard_dir.join("cpl0");

    run_image_build(repo_root, GuestImage::El1, &el1_target_dir)?;
    let el1_files = collect_compiled_sources(repo_root, &el1_target_dir, GuestImage::El1.target())?;

    run_image_build(repo_root, GuestImage::Cpl0, &cpl0_target_dir)?;
    let cpl0_files =
        collect_compiled_sources(repo_root, &cpl0_target_dir, GuestImage::Cpl0.target())?;

    let shared_files: BTreeSet<_> = el1_files.intersection(&cpl0_files).cloned().collect();
    let el1_only_files: BTreeSet<_> = el1_files.difference(&cpl0_files).cloned().collect();
    let cpl0_only_files: BTreeSet<_> = cpl0_files.difference(&el1_files).cloned().collect();

    let mut shared_lines = 0;
    let mut el1_only_lines = 0;
    let mut cpl0_only_lines = 0;
    let mut cfg_target_arch_forks = 0;
    let mut crate_map: BTreeMap<String, CrateScorecard> = BTreeMap::new();

    for file in &shared_files {
        let full_path = repo_root.join(file);
        let content = std::fs::read_to_string(&full_path)?;
        let lines = count_code_lines(&content);
        let forks = count_cfg_target_arch_sites(&content);

        shared_lines += lines;
        cfg_target_arch_forks += forks;

        let krate = crate_of_path(file);
        let entry = crate_map
            .entry(krate.clone())
            .or_insert_with(|| CrateScorecard {
                crate_name: krate,
                shared_lines: 0,
                el1_only_lines: 0,
                cpl0_only_lines: 0,
            });
        entry.shared_lines += lines;
    }

    for file in &el1_only_files {
        let full_path = repo_root.join(file);
        let content = std::fs::read_to_string(&full_path)?;
        let lines = count_code_lines(&content);

        el1_only_lines += lines;

        let krate = crate_of_path(file);
        let entry = crate_map
            .entry(krate.clone())
            .or_insert_with(|| CrateScorecard {
                crate_name: krate,
                shared_lines: 0,
                el1_only_lines: 0,
                cpl0_only_lines: 0,
            });
        entry.el1_only_lines += lines;
    }

    for file in &cpl0_only_files {
        let full_path = repo_root.join(file);
        let content = std::fs::read_to_string(&full_path)?;
        let lines = count_code_lines(&content);

        cpl0_only_lines += lines;

        let krate = crate_of_path(file);
        let entry = crate_map
            .entry(krate.clone())
            .or_insert_with(|| CrateScorecard {
                crate_name: krate,
                shared_lines: 0,
                el1_only_lines: 0,
                cpl0_only_lines: 0,
            });
        entry.cpl0_only_lines += lines;
    }

    let total_lines = shared_lines + el1_only_lines + cpl0_only_lines;
    let shared_percent = if total_lines == 0 {
        0.0
    } else {
        (shared_lines as f64 / total_lines as f64) * 100.0
    };

    let defects = read_defects_ledger(repo_root)?;
    let revision = get_git_revision(repo_root, None);

    Ok(ScorecardReport {
        revision,
        shared_lines,
        el1_only_lines,
        cpl0_only_lines,
        total_lines,
        shared_percent,
        shared_files_count: shared_files.len(),
        el1_only_files_count: el1_only_files.len(),
        cpl0_only_files_count: cpl0_only_files.len(),
        cfg_target_arch_forks,
        crates: crate_map.into_values().collect(),
        defects,
    })
}

struct WorktreeGuard {
    repo_root: PathBuf,
    worktree_path: PathBuf,
    #[allow(dead_code)]
    temp_dir: tempfile::TempDir,
}

impl WorktreeGuard {
    fn create(repo_root: &Path, rev: &str) -> Result<Self, ScorecardError> {
        let target_dir = repo_root.join("target");
        let _ = std::fs::create_dir_all(&target_dir);
        let temp_dir = tempfile::Builder::new()
            .prefix("scorecard-base-")
            .tempdir_in(&target_dir)?;
        let worktree_path = temp_dir.path().join("checkout");

        let status = Command::new("git")
            .current_dir(repo_root)
            .args(["worktree", "add", "--detach"])
            .arg(&worktree_path)
            .arg(rev)
            .status()?;

        if !status.success() {
            return Err(ScorecardError::Git(format!(
                "git worktree add failed with exit code {status} for rev {rev}"
            )));
        }

        Ok(Self {
            repo_root: repo_root.to_path_buf(),
            worktree_path,
            temp_dir,
        })
    }

    fn path(&self) -> &Path {
        &self.worktree_path
    }
}

impl Drop for WorktreeGuard {
    fn drop(&mut self) {
        let _ = Command::new("git")
            .current_dir(&self.repo_root)
            .args(["worktree", "remove", "--force"])
            .arg(&self.worktree_path)
            .status();
        let _ = std::fs::remove_dir_all(&self.worktree_path);
    }
}

pub fn run<W: Write>(
    repo_root: &Path,
    args: ScorecardArgs,
    writer: &mut W,
) -> Result<(), ScorecardError> {
    let current_report = measure_checkout(repo_root)?;

    let base_report = if let Some(ref base_rev) = args.base {
        let guard = WorktreeGuard::create(repo_root, base_rev)?;
        let mut report = measure_checkout(guard.path())?;
        report.revision = get_git_revision(repo_root, Some(base_rev));
        Some(report)
    } else {
        None
    };

    let output = ScorecardOutput {
        current: current_report,
        base: base_report,
    };

    if args.json {
        let json_str = serde_json::to_string_pretty(&output)?;
        writeln!(writer, "{json_str}")?;
    } else {
        print_text_report(&output, writer)?;
    }

    Ok(())
}

fn print_text_report<W: Write>(
    output: &ScorecardOutput,
    writer: &mut W,
) -> Result<(), ScorecardError> {
    print_single_report(&output.current, "CURRENT (HEAD)", writer)?;

    if let Some(ref base) = output.base {
        writeln!(writer)?;
        print_single_report(base, &format!("BASE ({})", base.revision), writer)?;
        writeln!(writer)?;
        print_comparison(&output.current, base, writer)?;
    }

    Ok(())
}

fn print_single_report<W: Write>(
    report: &ScorecardReport,
    label: &str,
    writer: &mut W,
) -> Result<(), ScorecardError> {
    writeln!(
        writer,
        "================================================================================"
    )?;
    writeln!(writer, "Shared Guest Kernel Scorecard: {label}")?;
    writeln!(writer, "Revision: {}", report.revision)?;
    writeln!(
        writer,
        "================================================================================"
    )?;
    writeln!(
        writer,
        "{:<38} {:>12} {:>14}",
        "Sharing Metric", "Lines", "Percentage"
    )?;
    writeln!(writer, "{:-<38} {:-<12} {:-<14}", "", "", "")?;
    writeln!(
        writer,
        "{:<38} {:>12} {:>13.1}%",
        "Shared (compiled in both)", report.shared_lines, report.shared_percent
    )?;
    let el1_pct = if report.total_lines == 0 {
        0.0
    } else {
        (report.el1_only_lines as f64 / report.total_lines as f64) * 100.0
    };
    let cpl0_pct = if report.total_lines == 0 {
        0.0
    } else {
        (report.cpl0_only_lines as f64 / report.total_lines as f64) * 100.0
    };
    writeln!(
        writer,
        "{:<38} {:>12} {:>13.1}%",
        "EL1 Only (aarch64 specific)", report.el1_only_lines, el1_pct
    )?;
    writeln!(
        writer,
        "{:<38} {:>12} {:>13.1}%",
        "CPL0 Only (x86_64 specific)", report.cpl0_only_lines, cpl0_pct
    )?;
    writeln!(writer, "{:-<38} {:-<12} {:-<14}", "", "", "")?;
    writeln!(
        writer,
        "{:<38} {:>12} {:>13.1}%",
        "Total Guest Kernel Code", report.total_lines, 100.0
    )?;
    writeln!(writer)?;
    writeln!(
        writer,
        "Compiled Source Files: {} shared, {} EL1-only, {} CPL0-only",
        report.shared_files_count, report.el1_only_files_count, report.cpl0_only_files_count
    )?;
    writeln!(
        writer,
        "Internal Forks:        {} cfg(target_arch ...) sites in shared files",
        report.cfg_target_arch_forks
    )?;
    writeln!(
        writer,
        "x86-found shared defects: {} (x86-kvm: {}, arm-hvf: {})",
        report.defects.x86_kvm, report.defects.x86_kvm, report.defects.arm_hvf
    )?;
    writeln!(writer)?;
    writeln!(writer, "Per-Crate Breakdown:")?;
    writeln!(
        writer,
        "{:<30} {:>10} {:>12} {:>12} {:>10}",
        "Crate", "Shared", "EL1 Only", "CPL0 Only", "Shared %"
    )?;
    writeln!(
        writer,
        "{:-<30} {:-<10} {:-<12} {:-<12} {:-<10}",
        "", "", "", "", ""
    )?;
    for c in &report.crates {
        writeln!(
            writer,
            "{:<30} {:>10} {:>12} {:>12} {:>9.1}%",
            c.crate_name,
            c.shared_lines,
            c.el1_only_lines,
            c.cpl0_only_lines,
            c.shared_percent()
        )?;
    }
    writeln!(
        writer,
        "{:-<30} {:-<10} {:-<12} {:-<12} {:-<10}",
        "", "", "", "", ""
    )?;

    Ok(())
}

fn print_comparison<W: Write>(
    current: &ScorecardReport,
    base: &ScorecardReport,
    writer: &mut W,
) -> Result<(), ScorecardError> {
    writeln!(
        writer,
        "================================================================================"
    )?;
    writeln!(writer, "Comparison vs Base ({})", base.revision)?;
    writeln!(
        writer,
        "================================================================================"
    )?;
    writeln!(
        writer,
        "{:<30} {:>12} {:>12} {:>14}",
        "Metric", "Base", "Current", "Delta"
    )?;
    writeln!(writer, "{:-<30} {:-<12} {:-<12} {:-<14}", "", "", "", "")?;
    let shared_delta = current.shared_lines as i64 - base.shared_lines as i64;
    let shared_pct_delta = current.shared_percent - base.shared_percent;
    let total_delta = current.total_lines as i64 - base.total_lines as i64;
    let forks_delta = current.cfg_target_arch_forks as i64 - base.cfg_target_arch_forks as i64;

    writeln!(
        writer,
        "{:<30} {:>12} {:>12} {:>+14}",
        "Shared Lines", base.shared_lines, current.shared_lines, shared_delta
    )?;
    writeln!(
        writer,
        "{:<30} {:>11.1}% {:>11.1}% {:>+13.1}%",
        "Shared Percentage", base.shared_percent, current.shared_percent, shared_pct_delta
    )?;
    writeln!(
        writer,
        "{:<30} {:>12} {:>12} {:>+14}",
        "EL1 Only Lines",
        base.el1_only_lines,
        current.el1_only_lines,
        current.el1_only_lines as i64 - base.el1_only_lines as i64
    )?;
    writeln!(
        writer,
        "{:<30} {:>12} {:>12} {:>+14}",
        "CPL0 Only Lines",
        base.cpl0_only_lines,
        current.cpl0_only_lines,
        current.cpl0_only_lines as i64 - base.cpl0_only_lines as i64
    )?;
    writeln!(
        writer,
        "{:<30} {:>12} {:>12} {:>+14}",
        "Total Lines", base.total_lines, current.total_lines, total_delta
    )?;
    writeln!(
        writer,
        "{:<30} {:>12} {:>12} {:>+14}",
        "Internal Forks", base.cfg_target_arch_forks, current.cfg_target_arch_forks, forks_delta
    )?;
    writeln!(writer, "{:-<30} {:-<12} {:-<12} {:-<14}", "", "", "", "")?;

    Ok(())
}
