//! Conservative, opt-in removal of clean worktrees with proven landed history.
use crate::command::{self, CommandError};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

#[derive(clap::Args, Debug)]
pub struct WorktreeGcArgs {
    /// Remove eligible worktrees; otherwise only print the census.
    #[arg(long)]
    pub apply: bool,
    /// Prune old Cargo intermediates instead of removing worktrees.
    #[arg(long)]
    pub prune_targets: bool,
    /// Minimum artifact age, in days (target pruning only).
    #[arg(long, default_value_t = 2, requires = "prune_targets")]
    pub days: u64,
    /// Prune this target directory instead of registered worktree targets.
    #[arg(long, requires = "prune_targets")]
    pub target_dir: Option<PathBuf>,
}

#[derive(Debug, Error)]
pub enum GcError {
    #[error(transparent)]
    Lease(#[from] crate::host_lease::HostLeaseError),
    #[error(transparent)]
    Command(#[from] CommandError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid worktree census: {0}")]
    Census(String),
}

#[derive(Debug, PartialEq, Eq)]
struct Worktree {
    path: PathBuf,
    head: String,
    branch: String,
    locked: bool,
    primary: bool,
}

fn parse_census(bytes: &[u8]) -> Result<Vec<Worktree>, GcError> {
    let mut trees = Vec::new();
    let mut tree = None;
    let mut bare = false;
    let mut seen_worktree = false;
    for field in bytes.split(|b| *b == 0) {
        let field = std::str::from_utf8(field).map_err(|e| GcError::Census(e.to_string()))?;
        if field.is_empty() {
            if let Some(t) = tree.take()
                && !bare
            {
                trees.push(t);
            }
            bare = false;
        } else if let Some(path) = field.strip_prefix("worktree ") {
            tree = Some(Worktree {
                path: PathBuf::from(path),
                head: String::new(),
                branch: "(detached)".into(),
                locked: false,
                primary: !seen_worktree,
            });
            seen_worktree = true;
        } else if let Some(t) = tree.as_mut() {
            if let Some(head) = field.strip_prefix("HEAD ") {
                t.head = head.into();
            } else if let Some(branch) = field.strip_prefix("branch refs/heads/") {
                t.branch = branch.into();
            } else if field == "bare" {
                bare = true;
            } else if field == "locked" || field.starts_with("locked ") {
                t.locked = true;
            }
        }
    }
    Ok(trees)
}

fn git(root: &Path, args: &[&str]) -> Result<String, GcError> {
    Ok(command::run_checked("git", args, Some(root))?.stdout)
}

// git cherry excludes merges. Unique merge commits can carry conflict-resolution
// changes, so do not let an empty cherry result silently discard those changes.
fn equivalent(root: &Path, upstream: &str, head: &str) -> Result<bool, GcError> {
    let cherry = git(root, &["cherry", upstream, head])?;
    let merges = git(root, &["rev-list", "--merges", head, "--not", upstream])?;
    Ok(patches_landed(&cherry, &merges))
}

fn patches_landed(cherry: &str, unique_merges: &str) -> bool {
    unique_merges.trim().is_empty() && cherry.lines().all(|line| line.starts_with("- "))
}

fn landing(root: &Path, main: &str, head: &str) -> Result<Option<String>, GcError> {
    if equivalent(root, main, head)? {
        return Ok(Some("main (git cherry)".into()));
    }
    let stacks = git(
        root,
        &["for-each-ref", "--format=%(refname)", "refs/heads/land/"],
    )?;
    for stack in stacks.lines() {
        let sha = git(root, &["rev-parse", stack])?;
        let sha = sha.trim();
        // A stack name alone is not evidence. Both legs must be fully landed.
        if equivalent(root, main, sha)? && equivalent(root, sha, head)? {
            return Ok(Some(stack.trim_start_matches("refs/heads/").into()));
        }
    }
    Ok(None)
}

#[derive(Debug, PartialEq, Eq)]
enum UseState {
    Idle,
    Busy,
    Unknown,
}

fn classify_use(code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> UseState {
    if !stdout.is_empty() {
        UseState::Busy
    } else if code == Some(1) && stderr.is_empty() {
        UseState::Idle
    } else {
        UseState::Unknown
    }
}

fn process_use(path: &Path) -> UseState {
    // An unprivileged empty lsof result can hide another user's processes.
    // Resolve the executable before sudo's secure PATH is substituted (lsof
    // may be installed per-user). Only the read-only census is privileged.
    let Some(lsof) = std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join("lsof"))
            .find(|file| {
                std::fs::metadata(file)
                    .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            })
            .and_then(|file| std::fs::canonicalize(file).ok())
    }) else {
        return UseState::Unknown;
    };
    let Ok(uid) = command::run_checked("id", ["-u"], None) else {
        return UseState::Unknown;
    };
    let mut census = if uid.stdout.trim() == "0" {
        Command::new(lsof)
    } else {
        let mut sudo = Command::new("sudo");
        sudo.args(["-n", "-u", "root"]).arg(lsof);
        sudo
    };
    // +D includes cwd, mapped executables and open files anywhere in the tree.
    // Warnings or denied sudo access fail closed; never prompt or retry.
    census.args(["-F", "p"]);
    if path.is_dir() {
        census.arg("+D");
    }
    match census.arg(path).output() {
        Ok(out) => classify_use(out.status.code(), &out.stdout, &out.stderr),
        Err(_) => UseState::Unknown,
    }
}

fn protected(path: &Path, common: &Path, current: &Path, locked: bool, branch: &str) -> bool {
    locked
        || path == current
        || path.join(".git") == common
        || branch == "main"
        || path
            .components()
            .any(|c| c.as_os_str() == "gate-worktree" || c.as_os_str() == "gate-worktrees")
}

fn removable(protected: bool, dirty: bool, landed: bool, usage: &UseState) -> bool {
    !protected && !dirty && landed && *usage == UseState::Idle
}

fn size(path: &Path) -> String {
    command::run_checked("du", [std::ffi::OsStr::new("-sk"), path.as_os_str()], None)
        .ok()
        .and_then(|out| out.stdout.split_whitespace().next()?.parse::<u64>().ok())
        .map(|kib| format!("{:.2} GiB", kib as f64 / 1_048_576.0))
        .unwrap_or_else(|| "unknown".into())
}

fn writable_dirs(path: &Path) -> Result<(), GcError> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Ok(());
    }
    let mut permissions = meta.permissions();
    permissions.set_mode(permissions.mode() | 0o700);
    std::fs::set_permissions(path, permissions)?;
    for entry in std::fs::read_dir(path)? {
        writable_dirs(&entry?.path())?;
    }
    Ok(())
}

pub fn run(root: &Path, args: WorktreeGcArgs, writer: &mut impl Write) -> Result<(), GcError> {
    if args.prune_targets {
        return crate::target_prune::run(root, args, writer);
    }
    let common = PathBuf::from(
        git(
            root,
            &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        )?
        .trim(),
    );
    let common = std::fs::canonicalize(common)?;
    let main = git(root, &["rev-parse", "--verify", "refs/heads/main^{commit}"])?;
    let main = main.trim();
    let census = Command::new("git")
        .current_dir(root)
        .args(["worktree", "list", "--porcelain", "-z"])
        .output()?;
    if !census.status.success() {
        return Err(GcError::Census(
            String::from_utf8_lossy(&census.stderr).into(),
        ));
    }
    writeln!(
        writer,
        "{}: SIZE | BRANCH | DIRTY | LANDED | USE | ACTION | PATH",
        if args.apply { "apply" } else { "dry-run" }
    )?;
    for tree in parse_census(&census.stdout)? {
        let path = match std::fs::canonicalize(&tree.path) {
            Ok(path) => path,
            Err(_) => {
                writeln!(
                    writer,
                    "keep (missing/inaccessible) | {}",
                    tree.path.display()
                )?;
                continue;
            }
        };
        // Git lists the primary checkout first, including when its git-dir is
        // external or reached through a symlink. Preserve the original path's
        // gate classification as well as its canonical identity.
        let protected = tree.primary
            || protected(&path, &common, root, tree.locked, &tree.branch)
            || protected(&tree.path, &common, root, tree.locked, &tree.branch);
        let dirty = !git(&path, &["status", "--porcelain", "--untracked-files=all"])?.is_empty();
        let landed = landing(root, main, &tree.head)?;
        let usage = process_use(&path);
        let eligible = removable(protected, dirty, landed.is_some(), &usage);
        writeln!(
            writer,
            "{} | {} | {} | {} | {:?} | {} | {}",
            size(&path),
            tree.branch,
            dirty,
            landed.as_deref().unwrap_or("unlanded"),
            usage,
            if protected {
                "keep (protected)"
            } else if eligible {
                "eligible"
            } else {
                "keep"
            },
            path.display()
        )?;
        if args.apply && eligible {
            // Recheck mutable evidence immediately before removal. Never force:
            // Git independently refuses tracked/untracked changes and locks.
            let head = git(&path, &["rev-parse", "HEAD"])?;
            let clean = git(&path, &["status", "--porcelain", "--untracked-files=all"])?.is_empty();
            if head.trim() != tree.head || !clean || process_use(&path) != UseState::Idle {
                writeln!(writer, "keep (changed during census) | {}", path.display())?;
                continue;
            }
            writable_dirs(&path)?;
            if process_use(&path) != UseState::Idle {
                writeln!(writer, "keep (in use before removal) | {}", path.display())?;
                continue;
            }
            command::run_checked(
                "git",
                [
                    std::ffi::OsStr::new("worktree"),
                    std::ffi::OsStr::new("remove"),
                    path.as_os_str(),
                ],
                Some(root),
            )?;
            writeln!(writer, "removed | {}", path.display())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_git(root: &Path, args: &[&str]) -> String {
        git(root, args).unwrap()
    }

    #[test]
    fn real_git_requires_the_stack_to_land_and_keeps_new_worker_commits() {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path();
        fixture_git(root, &["init", "-b", "main"]);
        fixture_git(root, &["config", "user.email", "test@example.invalid"]);
        fixture_git(root, &["config", "user.name", "Test"]);
        std::fs::write(root.join("base"), "base\n").unwrap();
        fixture_git(root, &["add", "."]);
        fixture_git(root, &["commit", "-m", "base"]);
        fixture_git(root, &["checkout", "-b", "work/worker"]);
        std::fs::write(root.join("worker"), "change\n").unwrap();
        fixture_git(root, &["add", "."]);
        fixture_git(root, &["commit", "-m", "worker"]);
        let worker = fixture_git(root, &["rev-parse", "HEAD"]);
        fixture_git(root, &["checkout", "-b", "land/stack", "main"]);
        fixture_git(root, &["cherry-pick", "-x", worker.trim()]);
        assert_eq!(landing(root, "main", worker.trim()).unwrap(), None);
        fixture_git(root, &["checkout", "main"]);
        fixture_git(root, &["cherry-pick", "-x", "land/stack"]);
        assert_eq!(
            landing(root, "main", worker.trim()).unwrap(),
            Some("main (git cherry)".into())
        );
        fixture_git(root, &["checkout", "work/worker"]);
        std::fs::write(root.join("worker"), "unlanded\n").unwrap();
        fixture_git(root, &["commit", "-am", "more work"]);
        assert_eq!(landing(root, "main", "HEAD").unwrap(), None);
    }

    #[test]
    fn read_only_census_directories_are_writable_without_following_symlinks() {
        use std::os::unix::fs::symlink;
        let tree = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let census = tree.path().join("census/snapshot");
        std::fs::create_dir_all(&census).unwrap();
        std::fs::set_permissions(&census, std::fs::Permissions::from_mode(0o500)).unwrap();
        std::fs::set_permissions(outside.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        symlink(outside.path(), tree.path().join("outside")).unwrap();
        writable_dirs(tree.path()).unwrap();
        assert_ne!(
            std::fs::metadata(census).unwrap().permissions().mode() & 0o200,
            0
        );
        assert_eq!(
            std::fs::metadata(outside.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o200,
            0
        );
        std::fs::set_permissions(outside.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn patch_classification_requires_all_patches_and_no_unique_merges() {
        assert!(patches_landed("", ""));
        assert!(patches_landed("- abc\n- def\n", ""));
        assert!(!patches_landed("- abc\n+ def\n", ""));
        assert!(!patches_landed("", "merge-sha\n"));
        assert!(!patches_landed("unexpected", ""));
    }

    #[test]
    fn lsof_warnings_and_denied_privilege_never_prove_idle() {
        assert_eq!(classify_use(Some(1), b"", b""), UseState::Idle);
        assert_eq!(classify_use(Some(0), b"p123\n", b""), UseState::Busy);
        assert_eq!(
            classify_use(Some(1), b"", b"incomplete visibility"),
            UseState::Unknown
        );
        assert_eq!(
            classify_use(Some(1), b"", b"sudo: a password is required"),
            UseState::Unknown
        );
        assert_eq!(classify_use(Some(0), b"", b""), UseState::Unknown);
        assert_eq!(classify_use(None, b"", b""), UseState::Unknown);
    }

    #[test]
    fn every_deletion_guard_is_required() {
        assert!(removable(false, false, true, &UseState::Idle));
        assert!(!removable(true, false, true, &UseState::Idle));
        assert!(!removable(false, true, true, &UseState::Idle));
        assert!(!removable(false, false, false, &UseState::Idle));
        assert!(!removable(false, false, true, &UseState::Busy));
        assert!(!removable(false, false, true, &UseState::Unknown));
    }

    #[test]
    fn protects_main_current_gate_and_locked_paths() {
        let common = Path::new("/dev/main/.git");
        let current = Path::new("/dev/current");
        for (path, locked, branch) in [
            ("/dev/main", false, "other"),
            ("/dev/current", false, "other"),
            ("/dev/gate-worktree", false, "other"),
            ("/dev/gate-worktrees/abc", false, "other"),
            ("/dev/other", true, "other"),
            ("/dev/other", false, "main"),
        ] {
            assert!(protected(Path::new(path), common, current, locked, branch));
        }
        assert!(!protected(
            Path::new("/dev/worker"),
            common,
            current,
            false,
            "work/worker"
        ));
    }

    #[test]
    fn bare_repository_does_not_mark_a_linked_worktree_as_primary() {
        let trees = parse_census(
            b"worktree /dev/repo.git\0bare\0\0worktree /dev/linked\0HEAD abc\0detached\0\0",
        )
        .unwrap();
        assert_eq!(trees.len(), 1);
        assert!(!trees[0].primary);
    }

    #[test]
    fn nul_census_preserves_spaces_newlines_and_detached_heads() {
        let trees = parse_census(b"worktree /dev/main\0HEAD abc\0branch refs/heads/main\0\0worktree /dev/a b\nline\0HEAD def\0detached\0locked reason\0\0").unwrap();
        assert_eq!(trees.len(), 2);
        assert!(trees[0].primary);
        assert!(!trees[1].primary);
        assert_eq!(trees[1].path, Path::new("/dev/a b\nline"));
        assert_eq!(trees[1].branch, "(detached)");
        assert!(trees[1].locked);
    }
}
