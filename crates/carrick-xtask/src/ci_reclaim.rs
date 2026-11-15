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

/// Remove `<workspace>/target`, the runner's own build output, unless a Cargo build holds any lock in it.
/// The locks (`CargoLocks::claim`: every `.cargo-lock` under target/, cross targets included) are held
/// until the removal finishes, so no build in this tree starts or continues meanwhile; the path must be the
/// canonical, symlink-free one before and immediately at removal (`removal_paths_are_direct`), and that same
/// canonical path is what is removed (#ci-reclaim review). Returns why it was kept, if it was.
fn reclaim(workspace: &Path) -> io::Result<Option<String>> {
    let workspace = workspace.canonicalize()?;
    let target = workspace.join("target");
    if !target.exists() {
        return Ok(Some("there is no target dir".into()));
    }
    let direct = || crate::worktree_gc::removal_paths_are_direct(&target, &target);
    if !direct() {
        return Ok(Some(format!(
            "{} is a symlink or not its canonical path",
            target.display()
        )));
    }
    let locks = crate::worktree_admission::CargoLocks::claim(&workspace)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let Some(locks) = locks else {
        return Ok(Some(format!(
            "a Cargo build holds a lock under {}",
            target.display()
        )));
    };
    if !direct() {
        return Ok(Some(format!("{} changed before removal", target.display())));
    }
    std::fs::remove_dir_all(&target)?;
    drop(locks);
    Ok(None)
}

pub fn run(args: &ReclaimArgs) -> io::Result<()> {
    let workspace = std::env::var_os("GITHUB_WORKSPACE")
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::other("ci-reclaim-target runs only on a CI runner ($GITHUB_WORKSPACE unset)")
        })?;
    let free = available_gib(&workspace)?;
    if !reclaim_needed(free, args.floor_gib) {
        println!(
            "ci-reclaim-target: {free} GiB free (floor {} GiB); keeping target/",
            args.floor_gib
        );
        return Ok(());
    }
    match reclaim(&workspace)? {
        Some(why) => println!(
            "ci-reclaim-target: {free} GiB free is below the floor ({} GiB), but SKIPPED: {why}",
            args.floor_gib
        ),
        None => println!(
            "ci-reclaim-target: {free} GiB free was below the floor ({} GiB); removed target/ ({} GiB free now)",
            args.floor_gib,
            available_gib(&workspace)?
        ),
    }
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
    fn the_runners_own_unlocked_target_is_removed() {
        let ws = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(ws.path().join("target/debug")).unwrap();
        std::fs::write(ws.path().join("target/debug/.cargo-lock"), "").unwrap();
        assert_eq!(reclaim(ws.path()).unwrap(), None);
        assert!(!ws.path().join("target").exists());
        assert!(
            reclaim(ws.path())
                .unwrap()
                .unwrap()
                .contains("no target dir")
        );
    }

    #[test]
    fn a_held_build_lock_anywhere_under_target_keeps_it() {
        // #ci-reclaim review P0: a cross build locks target/<triple>/debug/.cargo-lock, one level deeper.
        for lock in [
            "target/debug/.cargo-lock",
            "target/aarch64-unknown-linux-musl/debug/.cargo-lock",
        ] {
            let ws = tempfile::tempdir().unwrap();
            let path = ws.path().join(lock);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "").unwrap();
            let held = std::fs::File::open(&path).unwrap();
            // SAFETY: held is open.
            assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) }, 0);
            assert!(
                reclaim(ws.path())
                    .unwrap()
                    .unwrap()
                    .contains("holds a lock"),
                "{lock}"
            );
            assert!(path.exists(), "{lock}");
        }
    }

    #[test]
    fn a_symlinked_target_is_never_followed() {
        let ws = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        std::fs::write(other.path().join("keep"), "another runner's file").unwrap();
        std::os::unix::fs::symlink(other.path(), ws.path().join("target")).unwrap();
        assert!(reclaim(ws.path()).unwrap().unwrap().contains("symlink"));
        assert!(other.path().join("keep").exists());
    }
}
