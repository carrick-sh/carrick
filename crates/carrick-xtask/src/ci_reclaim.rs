//! `ci-reclaim-target`: on a self-hosted CI runner, remove this runner's own
//! Cargo target dir when its volume is below the floor, before a build. The
//! per-runner `target/` on cloudmac's 56 GB volume filled twice on
//! 2026-11-14/15 (ENOSPC in `macos-unit-b`, then in the signed-lane
//! `arm-test-list` build); sccache keeps the rebuild cheap.

use std::ffi::CString;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

#[derive(clap::Args, Debug)]
pub struct ReclaimArgs {
    /// The runner's own Cargo target dir; it must be inside `$GITHUB_WORKSPACE`.
    #[arg(long, default_value = "target")]
    pub target_dir: PathBuf,
    #[arg(long, default_value_t = 15)]
    pub floor_gib: u64,
}

/// GiB available to this user on the volume holding `path` (statvfs).
fn available_gib(path: &Path) -> io::Result<u64> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // SAFETY: an all-zero statvfs is a valid out-buffer.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: c is a valid C string and st a valid out-pointer.
    if unsafe { libc::statvfs(c.as_ptr(), &raw mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((st.f_bavail as u64).saturating_mul(st.f_frsize as u64) >> 30)
}

/// Reclaim only below the floor.
fn reclaim_needed(free_gib: u64, floor_gib: u64) -> bool {
    free_gib < floor_gib
}

/// Why the target dir must not be removed, if it mustn't: it is outside this
/// runner's workspace (never another runner's tree), or a Cargo build in it
/// holds its lock (a build dir's `.cargo-lock`, flock-held by Cargo).
fn reclaim_refusal(target: &Path, workspace: &Path) -> io::Result<Option<String>> {
    let target = match target.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(Some("there is no target dir".into()));
        }
        Err(error) => return Err(error),
    };
    let workspace = workspace.canonicalize()?;
    if target == workspace || !target.starts_with(&workspace) {
        return Ok(Some(format!(
            "{} is not inside this runner's workspace {}",
            target.display(),
            workspace.display()
        )));
    }
    for entry in std::fs::read_dir(&target)? {
        let lock = entry?.path().join(".cargo-lock");
        let Ok(file) = std::fs::File::open(&lock) else {
            continue;
        };
        // SAFETY: file is open; the probe lock is released when it closes.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Ok(Some(format!("a Cargo build holds {}", lock.display())));
        }
    }
    Ok(None)
}

pub fn run(args: &ReclaimArgs) -> io::Result<()> {
    let workspace = std::env::var_os("GITHUB_WORKSPACE")
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::other("ci-reclaim-target runs only on a CI runner ($GITHUB_WORKSPACE unset)")
        })?;
    let target = if args.target_dir.is_absolute() {
        args.target_dir.clone()
    } else {
        workspace.join(&args.target_dir)
    };
    let free = available_gib(&workspace)?;
    if !reclaim_needed(free, args.floor_gib) {
        println!(
            "ci-reclaim-target: {free} GiB free (floor {} GiB); keeping {}",
            args.floor_gib,
            target.display()
        );
        return Ok(());
    }
    if let Some(why) = reclaim_refusal(&target, &workspace)? {
        println!(
            "ci-reclaim-target: {free} GiB free (floor {} GiB), but not removing: {why}",
            args.floor_gib
        );
        return Ok(());
    }
    std::fs::remove_dir_all(&target)?;
    let after = available_gib(&workspace)?;
    println!(
        "ci-reclaim-target: {free} GiB free was below the floor ({} GiB); removed {} ({after} GiB free now)",
        args.floor_gib,
        target.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reclaim_happens_only_below_the_floor() {
        assert!(reclaim_needed(14, 15));
        assert!(reclaim_needed(0, 15));
        assert!(!reclaim_needed(15, 15));
        assert!(!reclaim_needed(56, 15));
    }

    #[test]
    fn free_space_reads_a_real_volume() {
        let dir = tempfile::tempdir().unwrap();
        assert!(available_gib(dir.path()).is_ok());
        assert!(available_gib(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn only_this_runners_own_unlocked_target_is_reclaimable() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("runner-a/_work/carrick/carrick");
        let target = workspace.join("target");
        std::fs::create_dir_all(target.join("debug")).unwrap();
        std::fs::write(target.join("debug/.cargo-lock"), "").unwrap();
        assert_eq!(reclaim_refusal(&target, &workspace).unwrap(), None);
        // Another runner's tree, the workspace itself, and a symlink out of the workspace are refused.
        let other = root.path().join("runner-b/_work/carrick/carrick/target");
        std::fs::create_dir_all(&other).unwrap();
        assert!(
            reclaim_refusal(&other, &workspace)
                .unwrap()
                .unwrap()
                .contains("not inside")
        );
        assert!(
            reclaim_refusal(&workspace, &workspace)
                .unwrap()
                .unwrap()
                .contains("not inside")
        );
        let escape = workspace.join("escape");
        std::os::unix::fs::symlink(&other, &escape).unwrap();
        assert!(
            reclaim_refusal(&escape, &workspace)
                .unwrap()
                .unwrap()
                .contains("not inside")
        );
        // A build holding Cargo's lock in it.
        let held = std::fs::File::open(target.join("debug/.cargo-lock")).unwrap();
        // SAFETY: held is open.
        assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) }, 0);
        assert!(
            reclaim_refusal(&target, &workspace)
                .unwrap()
                .unwrap()
                .contains("holds")
        );
        drop(held);
        assert_eq!(reclaim_refusal(&target, &workspace).unwrap(), None);
        // No target dir at all.
        std::fs::remove_dir_all(&target).unwrap();
        assert!(
            reclaim_refusal(&target, &workspace)
                .unwrap()
                .unwrap()
                .contains("no target dir")
        );
    }
}
