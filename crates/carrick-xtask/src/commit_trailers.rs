use clap::Subcommand;
use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::command;

#[derive(clap::Args, Debug, Clone)]
pub struct CommitTrailersArgs {
    #[command(subcommand)]
    pub action: CommitTrailersAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CommitTrailersAction {
    #[command(
        name = "check-message",
        about = "Validate one commit message file (for the commit-msg hook)"
    )]
    CheckMessage {
        #[arg(help = "Path to commit message file")]
        file: PathBuf,
    },

    #[command(
        name = "check-range",
        about = "Validate every non-merge commit in a git revision range (for CI)"
    )]
    CheckRange {
        #[arg(help = "Git revision range (e.g. base..head)")]
        range: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailerViolation {
    pub commit_id: String,
    pub offending_line: String,
    pub expected: String,
}

impl std::fmt::Display for TrailerViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "commit {}: offending line '{}'\n  expected {}",
            self.commit_id, self.offending_line, self.expected
        )
    }
}

#[derive(Debug, Error)]
pub enum CommitTrailersError {
    #[error("trailer check failed:\n{0}")]
    Violations(String),

    #[error("failed to read commit message file '{path}': {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("git command failed: {0}")]
    Git(#[from] command::CommandError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vendor {
    Anthropic,
    OpenAi,
    Google,
}

impl Vendor {
    pub fn noreply_email(self) -> &'static str {
        match self {
            Self::Anthropic => "noreply@anthropic.com",
            Self::OpenAi => "noreply@openai.com",
            Self::Google => "noreply@google.com",
        }
    }
}

pub fn detect_vendor(name: &str, email: &str) -> Option<Vendor> {
    let name_lower = name.to_ascii_lowercase();
    let email_lower = email.to_ascii_lowercase();

    // Check vendor by name keywords
    if name_lower.contains("claude") || name_lower.contains("anthropic") {
        return Some(Vendor::Anthropic);
    }
    if name_lower.contains("codex")
        || name_lower.contains("openai")
        || contains_gpt_token(&name_lower)
    {
        return Some(Vendor::OpenAi);
    }
    if name_lower.contains("gemini")
        || name_lower.contains("antigravity")
        || name_lower.contains("google")
        || name_lower.split_whitespace().any(|w| w == "agy")
    {
        return Some(Vendor::Google);
    }

    // Check vendor by email domain or keywords
    if email_lower.ends_with("@anthropic.com")
        || email_lower.contains("anthropic")
        || email_lower.contains("claude")
    {
        return Some(Vendor::Anthropic);
    }
    if email_lower.ends_with("@openai.com")
        || email_lower.contains("openai")
        || email_lower.contains("codex")
        || email_lower.contains("gpt")
    {
        return Some(Vendor::OpenAi);
    }
    if email_lower.ends_with("@google.com")
        || email_lower.contains("gemini")
        || email_lower.contains("antigravity")
        || email_lower.contains("google")
        || email_lower
            .split('@')
            .next()
            .is_some_and(|l| l == "agy" || l.starts_with("agy"))
    {
        return Some(Vendor::Google);
    }

    None
}

fn contains_gpt_token(name_lower: &str) -> bool {
    name_lower.contains("gpt")
}

pub fn is_well_formed_email(email: &str) -> bool {
    if email.contains(char::is_whitespace) {
        return false;
    }
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let (local, domain) = (parts[0], parts[1]);
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    if !domain.contains('.') {
        return false;
    }
    for label in domain.split('.') {
        if label.is_empty() {
            return false;
        }
    }
    true
}

pub fn validate_commit_message(commit_id: &str, message: &str) -> Vec<TrailerViolation> {
    let mut violations = Vec::new();

    for line in message.lines() {
        let line = line.trim_end_matches('\r');
        let trimmed = line.trim();

        // Git commit comments (e.g. in COMMIT_EDITMSG) start with '#'
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        let lower = trimmed.to_ascii_lowercase();
        let is_coauthor_candidate = lower.starts_with("co-authored-by")
            || lower.starts_with("coauthored-by")
            || lower.starts_with("co-author-by")
            || lower.starts_with("coauthor-by");

        if !is_coauthor_candidate {
            continue;
        }

        const CANONICAL_PREFIX: &str = "Co-Authored-By: ";
        if !trimmed.starts_with(CANONICAL_PREFIX) {
            let rest = if let Some(idx) = trimmed.find(':') {
                trimmed[idx + 1..].trim()
            } else {
                trimmed
            };

            let expected_line = if let (Some(o), Some(c)) = (rest.rfind('<'), rest.rfind('>')) {
                if o < c && c == rest.len() - 1 {
                    let name = rest[..o].trim();
                    let email = rest[o + 1..c].trim();
                    if !name.is_empty() && !email.is_empty() {
                        let expected_email = match detect_vendor(name, email) {
                            Some(vendor) => vendor.noreply_email(),
                            None => email,
                        };
                        format!("'Co-Authored-By: {name} <{expected_email}>'")
                    } else {
                        "'Co-Authored-By: <Name> <email>'".to_string()
                    }
                } else {
                    "'Co-Authored-By: <Name> <email>'".to_string()
                }
            } else {
                "'Co-Authored-By: <Name> <email>'".to_string()
            };

            violations.push(TrailerViolation {
                commit_id: commit_id.to_string(),
                offending_line: trimmed.to_string(),
                expected: expected_line,
            });
            continue;
        }

        let rest = trimmed[CANONICAL_PREFIX.len()..].trim();
        let (o, c) = match (rest.rfind('<'), rest.rfind('>')) {
            (Some(o), Some(c)) if c == rest.len() - 1 && o < c => (o, c),
            _ => {
                violations.push(TrailerViolation {
                    commit_id: commit_id.to_string(),
                    offending_line: trimmed.to_string(),
                    expected: "'Co-Authored-By: <Name> <email>'".to_string(),
                });
                continue;
            }
        };
        let name = rest[..o].trim();
        let email = rest[o + 1..c].trim();

        if name.is_empty() {
            violations.push(TrailerViolation {
                commit_id: commit_id.to_string(),
                offending_line: trimmed.to_string(),
                expected: "non-empty name in 'Co-Authored-By: <Name> <email>'".to_string(),
            });
            continue;
        }

        if email.is_empty() {
            violations.push(TrailerViolation {
                commit_id: commit_id.to_string(),
                offending_line: trimmed.to_string(),
                expected: format!("'Co-Authored-By: {name} <email>' (email cannot be empty)"),
            });
            continue;
        }

        let vendor = detect_vendor(name, email);

        if let Some(v) = vendor {
            if email != v.noreply_email() {
                violations.push(TrailerViolation {
                    commit_id: commit_id.to_string(),
                    offending_line: trimmed.to_string(),
                    expected: format!("'Co-Authored-By: {name} <{}>'", v.noreply_email()),
                });
                continue;
            }
        } else {
            if !is_well_formed_email(email) {
                violations.push(TrailerViolation {
                    commit_id: commit_id.to_string(),
                    offending_line: trimmed.to_string(),
                    expected: format!("well-formed email in 'Co-Authored-By: {name} <email>'"),
                });
                continue;
            }
            if email.eq_ignore_ascii_case("noreply@example.com") {
                violations.push(TrailerViolation {
                    commit_id: commit_id.to_string(),
                    offending_line: trimmed.to_string(),
                    expected: format!(
                        "personal email in 'Co-Authored-By: {name} <email>' (placeholder address rejected)"
                    ),
                });
                continue;
            }
        }
    }

    violations
}

pub fn run<W: Write>(
    root: &Path,
    args: CommitTrailersArgs,
    writer: &mut W,
) -> Result<(), CommitTrailersError> {
    match args.action {
        CommitTrailersAction::CheckMessage { file } => {
            let path = if file.is_absolute() {
                file
            } else {
                root.join(file)
            };
            let content =
                std::fs::read_to_string(&path).map_err(|source| CommitTrailersError::ReadFile {
                    path: path.clone(),
                    source,
                })?;
            let display_name = path.file_name().map_or_else(
                || path.display().to_string(),
                |n| n.to_string_lossy().to_string(),
            );
            let violations = validate_commit_message(&display_name, &content);
            if violations.is_empty() {
                writeln!(
                    writer,
                    "commit-trailers: message trailers valid ({display_name})."
                )
                .ok();
                Ok(())
            } else {
                let mut report = String::new();
                for v in violations {
                    let _ = writeln!(report, "{v}");
                }
                Err(CommitTrailersError::Violations(
                    report.trim_end().to_string(),
                ))
            }
        }
        CommitTrailersAction::CheckRange { range } => {
            let output = command::run_checked(
                "git",
                ["log", "--no-merges", "--format=format:%H%x00%B%x00", &range],
                Some(root),
            )?;
            let stdout = output.stdout;
            let mut parts = stdout.split('\0');
            let mut count = 0;
            let mut violations = Vec::new();
            while let Some(sha) = parts.next() {
                let sha = sha.trim();
                if sha.is_empty() {
                    break;
                }
                let body = parts.next().unwrap_or("");
                count += 1;
                violations.extend(validate_commit_message(sha, body));
            }
            if violations.is_empty() {
                writeln!(
                    writer,
                    "commit-trailers: checked {count} non-merge commit(s) in range {range}, all trailers valid."
                )
                .ok();
                Ok(())
            } else {
                let mut report = String::new();
                for v in violations {
                    let _ = writeln!(report, "{v}");
                }
                Err(CommitTrailersError::Violations(
                    report.trim_end().to_string(),
                ))
            }
        }
    }
}
