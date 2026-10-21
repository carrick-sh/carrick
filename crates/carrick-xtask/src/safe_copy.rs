//! Bounded copies of untrusted trees; symlinks are data, never read authority.
//! Callers must keep destination ancestors private. The entry bound is not a byte budget.
use std::fs::File;
use std::io;
use std::path::Path;

#[derive(Clone, Copy)]
pub enum Links {
    Preserve,
    Refuse,
}

pub fn tree(source: &Path, target: &Path, count: &mut usize, links: Links) -> io::Result<()> {
    copy(source, target, count, links, &mut || {})
}
fn copy(
    source: &Path,
    target: &Path,
    count: &mut usize,
    links: Links,
    hook: &mut impl FnMut(),
) -> io::Result<()> {
    directory(&open_root(source)?, target, count, links, hook)
}
fn open_root(source: &Path) -> io::Result<File> {
    use std::path::Component;
    let mut source_fd = crate::prune_fs::root(if source.is_absolute() {
        Path::new("/")
    } else {
        Path::new(".")
    })?;
    for part in source.components() {
        match part {
            Component::Normal(name) => source_fd = crate::prune_fs::open(&source_fd, name, true)?,
            Component::RootDir | Component::CurDir => {}
            _ => return Err(io::Error::other("copy root contains parent traversal")),
        }
    }
    Ok(source_fd)
}
fn directory(
    source: &File,
    target: &Path,
    count: &mut usize,
    links: Links,
    hook: &mut impl FnMut(),
) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir(target)?;
    std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o700))?;
    for name in crate::prune_fs::entries(source)? {
        if name
            .to_str()
            .is_some_and(|name| name == "target" || name.eq_ignore_ascii_case(".git"))
        {
            continue;
        }
        *count += 1;
        if *count > 100_000 {
            return Err(io::Error::other("snapshot file count exceeded"));
        }
        hook();
        let dest = target.join(&name);
        match crate::prune_fs::open(source, &name, false) {
            Ok(mut file) => {
                let metadata = file.metadata()?;
                if metadata.is_dir() {
                    directory(&file, &dest, count, links, hook)?;
                } else if metadata.is_file() {
                    let mut out = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&dest)?;
                    io::copy(&mut file, &mut out)?;
                    out.set_permissions(std::fs::Permissions::from_mode(
                        metadata.permissions().mode() & 0o777,
                    ))?;
                } else {
                    return Err(io::Error::other("snapshot refused nonregular file"));
                }
            }
            Err(error)
                if error.raw_os_error() == Some(libc::ELOOP)
                    && matches!(links, Links::Preserve) =>
            {
                std::os::unix::fs::symlink(read_link(source, &name)?, dest)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn read_link(parent: &File, name: &std::ffi::OsStr) -> io::Result<std::path::PathBuf> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let name = std::ffi::CString::new(name.as_bytes()).map_err(io::Error::other)?;
    let mut bytes = vec![0u8; 65536];
    // SAFETY: retained directory, validated entry name and writable output buffer.
    let size = unsafe {
        libc::readlinkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }
    if size as usize == bytes.len() {
        return Err(io::Error::other("symlink target too long"));
    }
    bytes.truncate(size as usize);
    Ok(std::ffi::OsString::from_vec(bytes).into())
}

pub fn text(path: &Path, limit: u64) -> io::Result<String> {
    read_text(path, limit, || {})
}
fn read_text(path: &Path, limit: u64, hook: impl FnOnce()) -> io::Result<String> {
    use std::io::Read;
    let parent = open_root(
        path.parent()
            .ok_or_else(|| io::Error::other("text parent"))?,
    )?;
    let file = crate::prune_fs::open(
        &parent,
        path.file_name()
            .ok_or_else(|| io::Error::other("text name"))?,
        false,
    )?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > limit {
        return Err(io::Error::other("unsafe or oversized text"));
    }
    hook();
    let mut value = String::new();
    file.take(limit.saturating_add(1))
        .read_to_string(&mut value)?;
    if value.len() as u64 > limit {
        return Err(io::Error::other("text grew beyond limit"));
    }
    Ok(value)
}

pub fn git_command(root: &Path, args: &[&str]) -> std::process::Command {
    let mut cmd = std::process::Command::new("git");
    // Repository-local config still applies; use a fresh repository for untrusted input.
    // Worktree .gitattributes is honored but cannot launch a config-defined driver
    // unless its configuration is admitted. Candidate configuration is never copied.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            cmd.env_remove(key);
        }
    }
    cmd.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_GRAFT_FILE", "/dev/null")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "credential.helper=",
            "-c",
            "filter.lfs.clean=",
            "-c",
            "filter.lfs.smudge=",
            "-c",
            "filter.lfs.process=",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "user.name=github-actions[bot]",
            "-c",
            "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        ])
        .args(args)
        .current_dir(root);
    cmd
}
fn git(root: &Path, args: &[&str]) -> Result<String, crate::ci_scaler::ScalerError> {
    let bytes = crate::ci_scaler::execute(
        &mut git_command(root, args),
        &[],
        std::time::Duration::from_secs(120),
    )?;
    String::from_utf8(bytes)
        .map_err(|_| crate::ci_scaler::ScalerError::Guard("non-UTF8 git output"))
}
/// Snapshot files and Git data without executing candidate configuration.
pub fn repository(
    source: &Path,
    target: &Path,
    branch: &str,
) -> Result<(), crate::ci_scaler::ScalerError> {
    use crate::ci_scaler::ScalerError;
    let source = open_root(source)?;
    let dotgit = crate::prune_fs::open(&source, std::ffi::OsStr::new(".git"), true)?;
    directory(&source, target, &mut 0, Links::Preserve, &mut || {})?;
    git(target, &["init"])?;
    for name in ["HEAD", "packed-refs", "refs", "objects"] {
        let file = match crate::prune_fs::open(&dotgit, std::ffi::OsStr::new(name), false) {
            Ok(file) => file,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && matches!(name, "packed-refs" | "refs") =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let dest = target.join(".git").join(name);
        if file.metadata()?.is_dir() {
            if dest.exists() {
                std::fs::remove_dir_all(&dest)?;
            }
            if name == "objects" {
                std::fs::create_dir(&dest)?;
                for entry in crate::prune_fs::entries(&file)? {
                    if entry == "info" {
                        continue;
                    }
                    let name = entry.to_str().ok_or(ScalerError::Guard("object path"))?;
                    if name != "pack"
                        && !(name.len() == 2 && name.bytes().all(|b| b.is_ascii_hexdigit()))
                    {
                        return Err(ScalerError::Guard("unexpected object directory"));
                    }
                    let child = crate::prune_fs::open(&file, &entry, true)?;
                    directory(&child, &dest.join(entry), &mut 0, Links::Refuse, &mut || {})?;
                }
            } else {
                directory(&file, &dest, &mut 0, Links::Refuse, &mut || {})?;
            }
        } else if file.metadata()?.is_file() && matches!(name, "HEAD" | "packed-refs") {
            io::copy(&mut &file, &mut File::create(dest)?)?;
        } else {
            return Err(ScalerError::Guard("nonregular repository data"));
        }
    }
    if git(target, &["symbolic-ref", "--short", "HEAD"])?.trim() != branch {
        return Err(ScalerError::Guard("candidate changed branch"));
    }
    git(target, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    git(target, &["read-tree", "HEAD"])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn text_swap_does_not_read_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("data");
        let secret = temp.path().join("secret");
        std::fs::write(&path, "ordinary").unwrap();
        std::fs::write(&secret, "SENTINEL-SECRET").unwrap();
        let value = read_text(&path, 100, || {
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(&secret, &path).unwrap();
        })
        .unwrap();
        assert_eq!(value, "ordinary");
    }
    #[test]
    fn packed_refs_are_resolved_without_candidate_configuration() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("copy");
        std::fs::create_dir(&source).unwrap();
        git(&source, &["init"]).unwrap();
        git(&source, &["checkout", "-b", "work/test"]).unwrap();
        std::fs::write(source.join("data"), "ordinary").unwrap();
        git(&source, &["add", "."]).unwrap();
        git(&source, &["commit", "-m", "base"]).unwrap();
        git(&source, &["pack-refs", "--all", "--prune"]).unwrap();
        assert!(!source.join(".git/refs/heads/work/test").exists());
        let marker = tmp.path().join("executed");
        let script = source.join(".git/hooks/post-checkout");
        std::fs::write(
            &script,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(script, std::fs::Permissions::from_mode(0o755)).unwrap();
        repository(&source, &target, "work/test").unwrap();
        assert_eq!(
            git(&source, &["rev-parse", "HEAD"]).unwrap(),
            git(&target, &["rev-parse", "HEAD"]).unwrap()
        );
        assert!(!marker.exists());
    }
    #[test]
    fn swapped_file_never_reads_sentinel() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir(&source).unwrap();
        let entry = source.join("file");
        std::fs::write(&entry, "ordinary").unwrap();
        let sentinel = tmp.path().join("secret");
        std::fs::write(&sentinel, "SENTINEL-SECRET").unwrap();
        let target = tmp.path().join("copy");
        let _ = copy(&source, &target, &mut 0, Links::Refuse, &mut || {
            std::fs::remove_file(&entry).unwrap();
            std::os::unix::fs::symlink(&sentinel, &entry).unwrap();
        });
        assert!(
            !target.join("file").exists()
                || std::fs::read(target.join("file")).unwrap() != b"SENTINEL-SECRET"
        );
    }
}
