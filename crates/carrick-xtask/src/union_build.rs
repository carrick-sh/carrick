//! `xtask union-build`: a throwaway merge of GitHub main and a list of PR
//! heads, so landing-train interactions and the next blockers show up before
//! anything lands.
//!
//! It fetches the base branch and each PR's head (`refs/pull/<n>/head`, or a
//! pinned `<n>@<sha>`) from the remote, adds a detached worktree at the base,
//! and merges each head in order with `git merge --no-ff`. A head that
//! conflicts is recorded with its conflicting paths and left out (`git merge
//! --abort`), so one conflict never hides the rest of the train. A head
//! already in the base is recorded as such. With `--build` it then runs
//! `just build` in the union worktree.
//!
//! The receipt (`--receipt`, JSON) names the base, every head and its
//! outcome, the union commit and the build's exit status. Nothing is pushed:
//! the worktree's commits exist only locally. Run the rows on its binary with
//! `carrick debug discover --carrick <worktree>/target/release/carrick`.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UnionBuildError {
    #[error("git {args}: {detail}")]
    Git { args: String, detail: String },
    #[error("invalid --pr {0:?}: expected <number> or <number>@<40-hex sha>")]
    BadPin(String),
    #[error("worktree {} already exists", .0.display())]
    WorktreeExists(PathBuf),
    #[error("pinned head {sha} of #{pr} is not reachable from {remote}")]
    PinUnreachable {
        pr: u64,
        sha: String,
        remote: String,
    },
    #[error("I/O error at '{}': {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("receipt: {0}")]
    Json(#[from] serde_json::Error),
}

/// One PR to merge: its number and, when pinned, the exact head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrPin {
    pub number: u64,
    pub sha: Option<String>,
}

impl std::str::FromStr for PrPin {
    type Err = UnionBuildError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bad = || UnionBuildError::BadPin(text.to_owned());
        let (number, sha) = match text.split_once('@') {
            Some((number, sha)) => (number, Some(sha)),
            None => (text, None),
        };
        let number: u64 = number.trim_start_matches('#').parse().map_err(|_| bad())?;
        if let Some(sha) = sha
            && (sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(bad());
        }
        Ok(Self {
            number,
            sha: sha.map(str::to_ascii_lowercase),
        })
    }
}

#[derive(clap::Args, Debug)]
pub struct UnionBuildArgs {
    /// PRs to merge, in order: `<number>` (its current head) or
    /// `<number>@<sha>` (that exact head). Repeat the flag.
    #[arg(long = "pr", required = true)]
    pub prs: Vec<PrPin>,
    /// The base branch on the remote.
    #[arg(long, default_value = "main")]
    pub base: String,
    /// The remote to fetch the base and the PR heads from.
    #[arg(long, default_value = "origin")]
    pub remote: String,
    /// Directory for the detached union worktree; must not exist.
    #[arg(long)]
    pub worktree: PathBuf,
    /// Where to write the JSON receipt (default: `<worktree>.union.json`).
    #[arg(long)]
    pub receipt: Option<PathBuf>,
    /// Run `just build` in the union worktree after merging; its log goes
    /// beside the receipt as `<receipt>.build.log`.
    #[arg(long)]
    pub build: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    Merged,
    AlreadyInBase,
    /// The head conflicts. `with_base` says whether it conflicts with the
    /// base alone (it needs a rebase) or only with heads merged before it
    /// (a landing-train interaction).
    Conflict {
        paths: Vec<String>,
        with_base: bool,
        /// For a train interaction: the earlier merged heads this one
        /// conflicts with on its own conflicting paths, pairwise. Empty when
        /// no single earlier head explains it (a many-way interaction).
        #[serde(default)]
        partners: Vec<u64>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadReceipt {
    pub pr: u64,
    pub head: String,
    #[serde(flatten)]
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnionReceipt {
    pub schema: u32,
    pub remote: String,
    pub base: String,
    pub base_sha: String,
    pub heads: Vec<HeadReceipt>,
    /// The union worktree's HEAD after every merge.
    pub union_sha: String,
    pub worktree: PathBuf,
    /// `just build`'s exit status, when `--build` ran it.
    pub build_status: Option<i32>,
}

impl UnionReceipt {
    pub fn conflicts(&self) -> impl Iterator<Item = &HeadReceipt> {
        self.heads
            .iter()
            .filter(|head| matches!(head.outcome, Outcome::Conflict { .. }))
    }
}

fn git(dir: &Path, args: &[&str]) -> Result<std::process::Output, UnionBuildError> {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .map_err(|source| UnionBuildError::Io {
            path: dir.to_path_buf(),
            source,
        })
}

fn git_ok(dir: &Path, args: &[&str]) -> Result<String, UnionBuildError> {
    let output = git(dir, args)?;
    if !output.status.success() {
        return Err(UnionBuildError::Git {
            args: args.join(" "),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn fetch_sha(root: &Path, remote: &str, refspec: &str) -> Result<String, UnionBuildError> {
    git_ok(root, &["fetch", "--quiet", "--no-tags", remote, refspec])?;
    git_ok(root, &["rev-parse", "--verify", "FETCH_HEAD^{commit}"])
}

/// Merge `ours` and `theirs` in memory (`git merge-tree --write-tree`, no
/// worktree change): `None` when clean, else the conflicting paths.
fn merge_tree_conflicts(
    dir: &Path,
    ours: &str,
    theirs: &str,
) -> Result<Option<Vec<String>>, UnionBuildError> {
    let args = ["merge-tree", "--write-tree", "--name-only", ours, theirs];
    let output = git(dir, &args)?;
    match output.status.code() {
        Some(0) => Ok(None),
        // Exit 1 is a conflicted merge: the tree id, then one path per
        // line, then a blank line before the messages.
        Some(1) => Ok(Some(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .skip(1)
                .take_while(|line| !line.is_empty())
                .map(str::to_owned)
                .collect(),
        )),
        _ => Err(UnionBuildError::Git {
            args: args.join(" "),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        }),
    }
}

/// Resolve every head, merge them onto the base in a new worktree and write
/// the receipt. Returns the receipt; conflicts are outcomes, not errors.
pub fn union(root: &Path, args: &UnionBuildArgs) -> Result<UnionReceipt, UnionBuildError> {
    if args.worktree.exists() {
        return Err(UnionBuildError::WorktreeExists(args.worktree.clone()));
    }
    let base_sha = fetch_sha(root, &args.remote, &format!("refs/heads/{}", args.base))?;
    let mut heads = Vec::new();
    for pin in &args.prs {
        let current = fetch_sha(
            root,
            &args.remote,
            &format!("refs/pull/{}/head", pin.number),
        )?;
        let head = match &pin.sha {
            None => current,
            Some(sha) if *sha == current => current,
            Some(sha) => {
                // An older pinned head: fetch it by id, or refuse.
                if git(root, &["fetch", "--quiet", "--no-tags", &args.remote, sha])?
                    .status
                    .success()
                {
                    git_ok(
                        root,
                        &["rev-parse", "--verify", &format!("{sha}^{{commit}}")],
                    )?
                } else {
                    return Err(UnionBuildError::PinUnreachable {
                        pr: pin.number,
                        sha: sha.clone(),
                        remote: args.remote.clone(),
                    });
                }
            }
        };
        heads.push((pin.number, head));
    }
    let worktree = args.worktree.to_string_lossy().into_owned();
    git_ok(root, &["worktree", "add", "--detach", &worktree, &base_sha])?;
    let mut receipts = Vec::new();
    let mut merged_heads: Vec<(u64, String)> = Vec::new();
    for (pr, head) in heads {
        let in_base = git(
            &args.worktree,
            &["merge-base", "--is-ancestor", &head, "HEAD"],
        )?
        .status
        .success();
        if in_base {
            receipts.push(HeadReceipt {
                pr,
                head,
                outcome: Outcome::AlreadyInBase,
            });
            continue;
        }
        let message = format!("union: merge #{pr} at {head}");
        let merged = git(
            &args.worktree,
            &[
                "-c",
                "user.name=carrick-union",
                "-c",
                "user.email=union@carrick.invalid",
                "merge",
                "--no-ff",
                "--no-edit",
                "-m",
                &message,
                &head,
            ],
        )?;
        if merged.status.success() {
            merged_heads.push((pr, head.clone()));
            receipts.push(HeadReceipt {
                pr,
                head,
                outcome: Outcome::Merged,
            });
            continue;
        }
        let unmerged = git_ok(&args.worktree, &["diff", "--name-only", "--diff-filter=U"])?;
        let mut paths: Vec<String> = unmerged.lines().map(str::to_owned).collect();
        if paths.is_empty() {
            // Not a content conflict (a hook or another refusal): say why.
            paths.push(format!(
                "(merge refused: {})",
                String::from_utf8_lossy(&merged.stderr).trim()
            ));
        }
        git_ok(&args.worktree, &["merge", "--abort"])?;
        // Against the base alone, in memory (no worktree change).
        let with_base = merge_tree_conflicts(&args.worktree, &base_sha, &head)?.is_some();
        // A train interaction names its partners: each earlier merged head
        // that conflicts with this one, pairwise, on a path the union merge
        // itself conflicted on.
        let mut partners = Vec::new();
        if !with_base {
            for (earlier, earlier_head) in &merged_heads {
                if let Some(shared) = merge_tree_conflicts(&args.worktree, earlier_head, &head)?
                    && shared.iter().any(|path| paths.contains(path))
                {
                    partners.push(*earlier);
                }
            }
        }
        receipts.push(HeadReceipt {
            pr,
            head,
            outcome: Outcome::Conflict {
                paths,
                with_base,
                partners,
            },
        });
    }
    let union_sha = git_ok(&args.worktree, &["rev-parse", "HEAD"])?;
    let receipt_path = receipt_path(args);
    let build_status = if args.build {
        let log_path = receipt_path.with_extension("build.log");
        let log = std::fs::File::create(&log_path).map_err(|source| UnionBuildError::Io {
            path: log_path.clone(),
            source,
        })?;
        let err = log.try_clone().map_err(|source| UnionBuildError::Io {
            path: log_path.clone(),
            source,
        })?;
        let status = Command::new("just")
            .arg("build")
            .current_dir(&args.worktree)
            .stdout(log)
            .stderr(err)
            .status()
            .map_err(|source| UnionBuildError::Io {
                path: args.worktree.clone(),
                source,
            })?;
        Some(status.code().unwrap_or(-1))
    } else {
        None
    };
    let receipt = UnionReceipt {
        schema: 1,
        remote: args.remote.clone(),
        base: args.base.clone(),
        base_sha,
        heads: receipts,
        union_sha,
        worktree: args.worktree.clone(),
        build_status,
    };
    let body = serde_json::to_vec_pretty(&receipt)?;
    std::fs::write(&receipt_path, body).map_err(|source| UnionBuildError::Io {
        path: receipt_path.clone(),
        source,
    })?;
    Ok(receipt)
}

fn receipt_path(args: &UnionBuildArgs) -> PathBuf {
    args.receipt.clone().unwrap_or_else(|| {
        let mut name = args.worktree.clone().into_os_string();
        name.push(".union.json");
        PathBuf::from(name)
    })
}

/// A short human summary of a receipt.
pub fn render(receipt: &UnionReceipt) -> String {
    let mut out = format!(
        "union of {}/{} {} and {} heads: {}\n",
        receipt.remote,
        receipt.base,
        &receipt.base_sha[..receipt.base_sha.len().min(12)],
        receipt.heads.len(),
        receipt.union_sha
    );
    for head in &receipt.heads {
        let outcome = match &head.outcome {
            Outcome::Merged => "merged".to_owned(),
            Outcome::AlreadyInBase => "already in base".to_owned(),
            Outcome::Conflict {
                paths,
                with_base,
                partners,
            } => format!(
                "CONFLICT {}: {}",
                if *with_base {
                    "with the base (rebase it)".to_owned()
                } else if partners.is_empty() {
                    "with an earlier head (train interaction, no single partner)".to_owned()
                } else {
                    format!(
                        "with an earlier head (train interaction with {})",
                        partners
                            .iter()
                            .map(|pr| format!("#{pr}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                },
                paths.join(", ")
            ),
        };
        out.push_str(&format!(
            "  #{} {}: {outcome}\n",
            head.pr,
            &head.head[..head.head.len().min(12)]
        ));
    }
    if let Some(status) = receipt.build_status {
        out.push_str(&format!("  just build: exit {status}\n"));
    }
    out.push_str(&format!("  worktree: {}\n", receipt.worktree.display()));
    out
}

pub fn run(
    root: &Path,
    args: UnionBuildArgs,
    writer: &mut dyn std::io::Write,
) -> Result<(), UnionBuildError> {
    let receipt = union(root, &args)?;
    let _ = write!(writer, "{}", render(&receipt));
    let _ = writeln!(writer, "  receipt: {}", receipt_path(&args).display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "init.defaultBranch=main",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    fn commit(dir: &Path, file: &str, body: &str, message: &str) -> String {
        std::fs::write(dir.join(file), body).unwrap();
        sh(dir, &["add", file]);
        sh(dir, &["commit", "-q", "-m", message]);
        sh(dir, &["rev-parse", "HEAD"])
    }

    /// A remote with main, four PR heads (one clean, one conflicting with
    /// the first, one already merged, one conflicting with main) and a
    /// clone of it.
    fn fixture() -> (tempfile::TempDir, PathBuf, [String; 5]) {
        let dir = tempfile::tempdir().unwrap();
        let remote = dir.path().join("remote");
        std::fs::create_dir(&remote).unwrap();
        sh(&remote, &["init", "-q"]);
        let base0 = commit(&remote, "a.txt", "one\n", "base");
        sh(&remote, &["checkout", "-q", "-b", "pr1"]);
        let pr1 = commit(&remote, "a.txt", "one\npr1\n", "pr1");
        sh(&remote, &["checkout", "-q", "main"]);
        sh(&remote, &["checkout", "-q", "-b", "pr2"]);
        let pr2 = commit(&remote, "a.txt", "one\npr2\n", "pr2");
        sh(&remote, &["checkout", "-q", "main"]);
        sh(&remote, &["checkout", "-q", "-b", "pr3"]);
        let pr3 = commit(&remote, "b.txt", "b\n", "pr3");
        sh(&remote, &["checkout", "-q", "main"]);
        sh(&remote, &["checkout", "-q", "-b", "pr4"]);
        let pr4 = commit(&remote, "b.txt", "stale\n", "pr4");
        sh(&remote, &["checkout", "-q", "main"]);
        sh(&remote, &["merge", "-q", "--no-ff", "--no-edit", "pr3"]);
        let main = sh(&remote, &["rev-parse", "HEAD"]);
        assert_ne!(main, base0);
        for (n, sha) in [(1, &pr1), (2, &pr2), (3, &pr3), (4, &pr4)] {
            sh(
                &remote,
                &["update-ref", &format!("refs/pull/{n}/head"), sha],
            );
        }
        let clone = dir.path().join("clone");
        let out = Command::new("git")
            .args(["clone", "-q"])
            .arg(&remote)
            .arg(&clone)
            .output()
            .unwrap();
        assert!(out.status.success());
        (dir, clone, [main, pr1, pr2, pr3, pr4])
    }

    #[test]
    fn pins_parse_numbers_and_exact_heads_only() {
        assert_eq!(
            "2690".parse::<PrPin>().unwrap(),
            PrPin {
                number: 2690,
                sha: None
            }
        );
        let sha = "506907B196e98d03d7002dba61a1a4bf80663252";
        let pin: PrPin = format!("#2690@{sha}").parse().unwrap();
        assert_eq!(pin.sha.as_deref(), Some(&*sha.to_ascii_lowercase()));
        for bad in [
            "",
            "x",
            "12@abc",
            "12@",
            "@506907b196e98d03d7002dba61a1a4bf80663252",
        ] {
            assert!(bad.parse::<PrPin>().is_err(), "{bad}");
        }
    }

    #[test]
    fn a_conflicting_head_is_recorded_and_left_out_and_the_rest_merge() {
        let (dir, clone, [main, pr1, pr2, pr3, pr4]) = fixture();
        let worktree = dir.path().join("union");
        let receipt = union(
            &clone,
            &UnionBuildArgs {
                prs: vec![
                    "1".parse().unwrap(),
                    "2".parse().unwrap(),
                    format!("3@{pr3}").parse().unwrap(),
                    "4".parse().unwrap(),
                ],
                base: "main".to_owned(),
                remote: "origin".to_owned(),
                worktree: worktree.clone(),
                receipt: None,
                build: false,
            },
        )
        .unwrap();
        assert_eq!(receipt.base_sha, main);
        assert_eq!(
            receipt.heads,
            [
                HeadReceipt {
                    pr: 1,
                    head: pr1.clone(),
                    outcome: Outcome::Merged
                },
                HeadReceipt {
                    pr: 2,
                    head: pr2,
                    outcome: Outcome::Conflict {
                        paths: vec!["a.txt".to_owned()],
                        with_base: false,
                        partners: vec![1],
                    }
                },
                HeadReceipt {
                    pr: 3,
                    head: pr3,
                    outcome: Outcome::AlreadyInBase
                },
                HeadReceipt {
                    pr: 4,
                    head: pr4,
                    outcome: Outcome::Conflict {
                        paths: vec!["b.txt".to_owned()],
                        with_base: true,
                        partners: vec![],
                    }
                },
            ]
        );
        assert_eq!(receipt.conflicts().count(), 2);
        // The union holds main and #1, and the aborted merge left it clean.
        assert_eq!(
            std::fs::read_to_string(worktree.join("a.txt")).unwrap(),
            "one\npr1\n"
        );
        assert!(worktree.join("b.txt").exists());
        assert_eq!(sh(&worktree, &["status", "--porcelain"]), "");
        assert_eq!(sh(&worktree, &["rev-parse", "HEAD"]), receipt.union_sha);
        sh(&worktree, &["merge-base", "--is-ancestor", &pr1, "HEAD"]);
        // The receipt on disk is the returned one, and the summary names the conflict.
        let on_disk: UnionReceipt =
            serde_json::from_slice(&std::fs::read(dir.path().join("union.union.json")).unwrap())
                .unwrap();
        assert_eq!(on_disk, receipt);
        assert!(render(&receipt).contains("#2 "), "{}", render(&receipt));
        assert!(
            render(&receipt)
                .contains("CONFLICT with an earlier head (train interaction with #1): a.txt")
        );
        assert!(render(&receipt).contains("CONFLICT with the base (rebase it): b.txt"));
        // An existing worktree path is refused rather than reused.
        let again = union(
            &clone,
            &UnionBuildArgs {
                prs: vec!["1".parse().unwrap()],
                base: "main".to_owned(),
                remote: "origin".to_owned(),
                worktree,
                receipt: None,
                build: false,
            },
        );
        assert!(matches!(again, Err(UnionBuildError::WorktreeExists(_))));
    }

    #[test]
    fn a_train_conflict_names_only_the_head_it_conflicts_with() {
        let (dir, clone, [_, _, pr2, _, _]) = fixture();
        // A fifth head that touches another file merges first and cleanly:
        // it is in the train before #2 but is not #2's partner.
        let remote = dir.path().join("remote");
        sh(&remote, &["checkout", "-q", "-b", "pr5", "main"]);
        let pr5 = commit(&remote, "c.txt", "c\n", "pr5");
        sh(&remote, &["checkout", "-q", "main"]);
        sh(&remote, &["update-ref", "refs/pull/5/head", &pr5]);
        let receipt = union(
            &clone,
            &UnionBuildArgs {
                prs: ["5", "1", "2"].map(|p| p.parse().unwrap()).to_vec(),
                base: "main".to_owned(),
                remote: "origin".to_owned(),
                worktree: dir.path().join("union"),
                receipt: None,
                build: false,
            },
        )
        .unwrap();
        assert_eq!(
            receipt.heads[2],
            HeadReceipt {
                pr: 2,
                head: pr2,
                outcome: Outcome::Conflict {
                    paths: vec!["a.txt".to_owned()],
                    with_base: false,
                    partners: vec![1],
                }
            }
        );
        // A receipt written before partners existed still reads.
        let old =
            r#"{"pr":2,"head":"ab","outcome":"conflict","paths":["a.txt"],"with_base":false}"#;
        let old: HeadReceipt = serde_json::from_str(old).unwrap();
        assert!(matches!(old.outcome, Outcome::Conflict { partners, .. } if partners.is_empty()));
    }

    #[test]
    fn an_unreachable_pinned_head_is_refused() {
        let (dir, clone, _) = fixture();
        let result = union(
            &clone,
            &UnionBuildArgs {
                prs: vec![
                    "1@0000000000000000000000000000000000000001"
                        .parse()
                        .unwrap(),
                ],
                base: "main".to_owned(),
                remote: "origin".to_owned(),
                worktree: dir.path().join("union"),
                receipt: None,
                build: false,
            },
        );
        assert!(
            matches!(result, Err(UnionBuildError::PinUnreachable { pr: 1, .. })),
            "{result:?}"
        );
        assert!(!dir.path().join("union").exists());
    }
}
