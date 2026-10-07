//! Cleanup restricted to an owned gate checkout, after its host lease ends.
use std::io;
use std::path::Path;

use crate::prune_fs as at;
use std::ffi::OsStr;
use std::fs::File;

#[derive(clap::Args, Debug)]
pub struct CleanupArgs {
    #[arg(long)]
    pub owned_root: std::path::PathBuf,
    #[arg(long)]
    pub run_id: String,
}

/// The remote worker retains the exact sibling checkout lock until cleanup ends.
pub fn cleanup(root: &Path, run_id: &str) -> io::Result<()> {
    if root.file_name() != Some(OsStr::new("gate-worktree")) {
        return Err(io::Error::other("cleanup requires the owned gate-worktree"));
    }
    let lock = root.with_file_name("gate-worktree.lock");
    let lock = at::root(&lock)?;
    use std::io::Read;
    let mut owner = String::new();
    at::open(&lock, OsStr::new("run_id"), false)?.read_to_string(&mut owner)?;
    if run_id.is_empty() || owner.trim() != run_id {
        return Err(io::Error::other("gate checkout belongs to another run"));
    }
    if std::env::var_os("CARRICK_HOST_LEASE_SOCKET").is_some() {
        return Err(io::Error::other("cleanup requires a released host lease"));
    }
    if std::env::var_os("CARRICK_GATE_KEEP_TARGET").as_deref() == Some(OsStr::new("1")) {
        return Ok(());
    }
    prune(root, &root.join("target"))
}

fn remove(parent: &File, name: &OsStr) -> io::Result<()> {
    match at::open(parent, name, true) {
        Ok(directory) => {
            for child in at::entries(&directory)? {
                remove(&directory, &child)?;
            }
            at::unlink(parent, name, true)
        }
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        Err(error) if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) => {
            at::unlink(parent, name, false)
        }
        Err(error) => Err(error),
    }
}

fn profiles(directory: &File, names: &[String]) -> io::Result<()> {
    for name in names {
        remove(directory, OsStr::new(name))?;
    }
    Ok(())
}

pub fn prune(owned_root: &Path, target: &Path) -> io::Result<()> {
    if target != owned_root.join("target") {
        return Err(io::Error::other("target outside owned gate root"));
    }
    let root = at::root(owned_root)?;
    let target = match at::open(&root, OsStr::new("target"), true) {
        Ok(target) => target,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
        Err(error) => return Err(error),
    };
    let mut names = vec!["debug".to_owned(), "release".to_owned()];
    match at::open(&root, OsStr::new("Cargo.toml"), false) {
        Ok(mut manifest) => {
            use std::io::Read;
            let mut text = String::new();
            manifest.read_to_string(&mut text)?;
            let value: toml::Value = toml::from_str(&text).map_err(io::Error::other)?;
            if let Some(profiles) = value.get("profile").and_then(toml::Value::as_table) {
                for name in profiles.keys() {
                    if matches!(name.as_str(), "dev" | "test" | "bench" | "release") {
                        continue;
                    }
                    if name.is_empty()
                        || !name
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                        || matches!(
                            name.as_str(),
                            "fixtures" | "el1-gate" | "remote-gate" | "logs"
                        )
                    {
                        return Err(io::Error::other("unsafe Cargo profile output name"));
                    }
                    names.push(name.clone());
                }
            }
        }
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
        Err(error) => return Err(error),
    }
    profiles(&target, &names)?;
    // Cargo target directories use rustc target triples. Query the local compiler
    // rather than treating arbitrary evidence directories as triples.
    let output = std::process::Command::new("rustc")
        .args(["--print", "target-list"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("rustc target-list failed"));
    }
    let triples = String::from_utf8_lossy(&output.stdout);
    for entry in at::entries(&target)? {
        if !triples.lines().any(|triple| OsStr::new(triple) == entry) {
            continue;
        }
        let directory = at::open(&target, &entry, true)?;
        profiles(&directory, &names)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn removes_profiles_keeps_evidence_and_refuses_outside_root() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("gate-worktree");
        let target = root.join("target");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[profile.dev-fast]\ninherits=\"dev\"\n",
        )
        .unwrap();
        let removed = [
            "debug/deps/a",
            "dev-fast/deps/a",
            "aarch64-apple-darwin/dev-fast/a",
            "release/build/b",
            "aarch64-apple-darwin/release/c",
            "x86_64-unknown-linux-gnu/debug/d",
        ];
        let kept = [
            "el1-gate/receipt.json",
            "remote-gate/log",
            "fixtures/bundle",
            "logs/accept.log",
            "other/data",
            "aarch64-apple-darwin/evidence/log",
        ];
        for path in removed.iter().chain(kept.iter()) {
            let path = target.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "evidence").unwrap();
        }
        let outside = temp.path().join("outside");
        fs::create_dir_all(outside.join("release")).unwrap();
        assert!(prune(&root, &outside).is_err());
        assert!(outside.join("release").exists());
        prune(&root, &target).unwrap();
        for path in removed {
            assert!(!target.join(path).exists(), "{path}");
        }
        for path in kept {
            assert!(target.join(path).exists(), "{path}");
        }
    }
    #[test]
    fn symlinked_target_cannot_escape_owned_root() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("gate-worktree");
        let outside = temp.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir_all(outside.join("release")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("target")).unwrap();
        assert!(prune(&root, &root.join("target")).is_err());
        assert!(outside.join("release").exists());
    }
    #[test]
    fn invalid_profile_name_cannot_remove_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("target/release")).unwrap();
        fs::write(root.join("target/receipt.json"), "evidence").unwrap();
        fs::write(root.join("Cargo.toml"), "[profile.'..']\ninherits='dev'\n").unwrap();
        assert!(prune(root, &root.join("target")).is_err());
        assert!(root.join("target/receipt.json").exists());
        assert!(root.join("target/release").exists());
    }
}
