//! Bounded copies of untrusted trees; entry symlinks are data, never read authority.
//! Root walks admit only root-owned links protected against untrusted replacement.
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
    directory(&open_root(source)?, target, count, links, hook, None)
}
fn open_root(source: &Path) -> io::Result<File> {
    use std::path::Component;
    let mut source_fd = crate::prune_fs::root(if source.is_absolute() {
        Path::new("/")
    } else {
        Path::new(".")
    })?;
    if source.components().any(|part| part == Component::ParentDir) {
        return Err(io::Error::other("copy root contains parent traversal"));
    }
    // Own the pending components so link targets can be spliced into the walk.
    let mut pending = std::collections::VecDeque::from([source.to_path_buf()]);
    let mut followed = 0;
    while let Some(path) = pending.pop_front() {
        let mut parts = path.components();
        while let Some(part) = parts.next() {
            match part {
                Component::Normal(name) => match crate::prune_fs::open(&source_fd, name, true) {
                    Ok(next) => source_fd = next,
                    Err(error) => {
                        let before = ancestor_link(&source_fd, name)?;
                        if before.st_mode & libc::S_IFMT != libc::S_IFLNK || before.st_uid != 0 {
                            return Err(error);
                        }
                        // Root ownership alone cannot protect the stat/readlink gap
                        // in a directory whose entries an untrusted user can replace.
                        // Sticky root-owned directories protect root-owned entries too.
                        use std::os::unix::fs::MetadataExt;
                        let parent = source_fd.metadata()?;
                        if parent.uid() != 0
                            || (parent.mode() & 0o022 != 0 && parent.mode() & 0o1000 == 0)
                        {
                            return Err(io::Error::other("replaceable copy ancestor symlink"));
                        }
                        followed += 1;
                        if followed > 40 {
                            return Err(io::Error::from_raw_os_error(libc::ELOOP));
                        }
                        let target = read_link(&source_fd, name)?;
                        let after = ancestor_link(&source_fd, name)?;
                        if before.st_dev != after.st_dev
                            || before.st_ino != after.st_ino
                            || after.st_uid != 0
                            || after.st_mode & libc::S_IFMT != libc::S_IFLNK
                        {
                            return Err(io::Error::other("copy ancestor symlink changed"));
                        }
                        pending.push_front(parts.as_path().to_path_buf());
                        pending.push_front(target);
                        break;
                    }
                },
                Component::RootDir => source_fd = crate::prune_fs::root(Path::new("/"))?,
                Component::CurDir => {}
                // Input parent traversal was refused; these come from trusted targets.
                Component::ParentDir => {
                    source_fd =
                        crate::prune_fs::open(&source_fd, std::ffi::OsStr::new(".."), true)?;
                }
                Component::Prefix(_) => return Err(io::Error::other("copy root prefix")),
            }
        }
    }
    Ok(source_fd)
}
// Inspect the link itself, never the object it names.
fn ancestor_link(parent: &File, name: &std::ffi::OsStr) -> io::Result<libc::stat> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(name.as_bytes()).map_err(io::Error::other)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: retained parent, single component C name and writable stat storage.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatat initialized stat.
    Ok(unsafe { stat.assume_init() })
}
fn directory(
    source: &File,
    target: &Path,
    count: &mut usize,
    links: Links,
    hook: &mut impl FnMut(),
    deadline: Option<std::time::Instant>,
) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    check_deadline(deadline)?;
    std::fs::create_dir(target)?;
    std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o700))?;
    for name in crate::prune_fs::entries(source)? {
        check_deadline(deadline)?;
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
                    directory(&file, &dest, count, links, hook, deadline)?;
                } else if metadata.is_file() {
                    let mut out = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&dest)?;
                    copy_file(&mut file, &mut out, deadline)?;
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
fn check_deadline(deadline: Option<std::time::Instant>) -> io::Result<()> {
    if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "snapshot deadline exhausted",
        ));
    }
    Ok(())
}
fn copy_file(
    source: &mut impl io::Read,
    target: &mut impl io::Write,
    deadline: Option<std::time::Instant>,
) -> io::Result<()> {
    let mut buffer = [0; 64 * 1024];
    loop {
        check_deadline(deadline)?;
        let bytes = source.read(&mut buffer)?;
        if bytes == 0 {
            return Ok(());
        }
        target.write_all(&buffer[..bytes])?;
    }
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
pub fn open_text(path: &Path) -> io::Result<File> {
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
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("unsafe text"));
    }
    Ok(file)
}
fn read_text(path: &Path, limit: u64, hook: impl FnOnce()) -> io::Result<String> {
    use std::io::Read;
    let file = open_text(path)?;
    if file.metadata()?.len() > limit {
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
fn git(
    root: &Path,
    args: &[&str],
    deadline: Option<std::time::Instant>,
) -> Result<String, crate::ci_scaler::ScalerError> {
    check_deadline(deadline)?;
    let limit = deadline
        .map(|d| d.saturating_duration_since(std::time::Instant::now()))
        .unwrap_or(std::time::Duration::from_secs(120))
        .min(std::time::Duration::from_secs(120));
    let bytes = crate::ci_scaler::execute(&mut git_command(root, args), &[], limit)?;
    String::from_utf8(bytes)
        .map_err(|_| crate::ci_scaler::ScalerError::Guard("non-UTF8 git output"))
}
/// Snapshot files and Git data without executing candidate configuration.
pub fn repository(
    source: &Path,
    target: &Path,
    branch: &str,
    deadline: Option<std::time::Instant>,
) -> Result<(), crate::ci_scaler::ScalerError> {
    use crate::ci_scaler::ScalerError;
    check_deadline(deadline)?;
    let source = open_root(source)?;
    let dotgit = crate::prune_fs::open(&source, std::ffi::OsStr::new(".git"), true)?;
    directory(
        &source,
        target,
        &mut 0,
        Links::Preserve,
        &mut || {},
        deadline,
    )?;
    git(target, &["init"], deadline)?;
    for name in ["HEAD", "packed-refs", "refs", "objects"] {
        check_deadline(deadline)?;
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
                    directory(
                        &child,
                        &dest.join(entry),
                        &mut 0,
                        Links::Refuse,
                        &mut || {},
                        deadline,
                    )?;
                }
            } else {
                directory(&file, &dest, &mut 0, Links::Refuse, &mut || {}, deadline)?;
            }
        } else if file.metadata()?.is_file() && matches!(name, "HEAD" | "packed-refs") {
            copy_file(&mut &file, &mut File::create(dest)?, deadline)?;
        } else {
            return Err(ScalerError::Guard("nonregular repository data"));
        }
    }
    if git(target, &["symbolic-ref", "--short", "HEAD"], deadline)?.trim() != branch {
        return Err(ScalerError::Guard("candidate changed branch"));
    }
    git(
        target,
        &["rev-parse", "--verify", "HEAD^{commit}"],
        deadline,
    )?;
    git(target, &["read-tree", "HEAD"], deadline)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn git(root: &Path, args: &[&str]) -> Result<String, crate::ci_scaler::ScalerError> {
        super::git(root, args, None)
    }
    #[test]
    fn non_root_symlink_ancestor_is_refused() {
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(real.join("child")).unwrap();
        std::fs::write(real.join("child/data"), "ordinary").unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink("real", &link).unwrap();
        assert_ne!(
            std::fs::symlink_metadata(&link).unwrap().uid(),
            0,
            "this witness requires a non-root test user"
        );
        assert!(open_root(&link.join("child")).is_err());
        assert!(text(&link.join("child/data"), 100).is_err());
        assert!(
            tree(
                &link.join("child"),
                &temp.path().join("copy"),
                &mut 0,
                Links::Refuse
            )
            .is_err()
        );
    }
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
        repository(&source, &target, "work/test", None).unwrap();
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
