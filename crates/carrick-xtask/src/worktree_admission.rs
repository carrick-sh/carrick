//! Cooperative checkout admission. Authorities live outside removable checkouts.
use crate::command;
use crate::worktree_gc::GcError;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(clap::Args, Debug)]
pub struct WorktreeRunArgs {
    /// Foreground command held under the checkout's shared lifetime guard.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<OsString>,
}

#[derive(Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
}

impl Identity {
    fn read(root: &Path) -> std::io::Result<Self> {
        let meta = fs::metadata(root)?;
        Ok(Self {
            device: meta.dev(),
            inode: meta.ino(),
        })
    }

    fn authority(&self, common: &Path) -> PathBuf {
        common
            .join("carrick-worktree-admission")
            .join(format!("{}-{}", self.device, self.inode))
    }
}

fn common(root: &Path) -> Result<PathBuf, GcError> {
    let output = command::run_checked(
        "git",
        ["rev-parse", "--path-format=absolute", "--git-common-dir"],
        Some(root),
    )?;
    Ok(fs::canonicalize(output.stdout.trim())?)
}

fn open(path: &Path, create: bool) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

fn live(mut file: &File) -> std::io::Result<bool> {
    file.seek(SeekFrom::Start(0))?;
    let mut state = String::new();
    file.take(32).read_to_string(&mut state)?;
    Ok(state.is_empty())
}

/// A foreground command retains this shared guard until its child has exited.
pub(crate) struct Admission {
    _file: File,
}

impl Admission {
    pub(crate) fn acquire(root: &Path) -> Result<Self, GcError> {
        let identity = Identity::read(root)?;
        let path = identity.authority(&common(root)?);
        fs::create_dir_all(
            path.parent()
                .ok_or_else(|| GcError::Census("authority has no parent".into()))?,
        )?;
        let file = open(&path, true)?;
        file.lock_shared()?;
        if Identity::read(root)? != identity || !live(&file)? {
            return Err(GcError::Census(
                "checkout has been retired; command refused".into(),
            ));
        }
        Ok(Self { _file: file })
    }
}

/// Only an already managed checkout can acquire exclusive removal authority.
pub(crate) struct Retirement {
    file: File,
}

pub(crate) enum RemovalAuthority {
    Unmanaged,
    Busy,
    Acquired(Retirement),
}

impl Retirement {
    pub(crate) fn claim(root: &Path, common: &Path) -> Result<RemovalAuthority, GcError> {
        let identity = Identity::read(root)?;
        let file = match open(&identity.authority(common), false) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RemovalAuthority::Unmanaged);
            }
            Err(error) => return Err(error.into()),
        };
        match file.try_lock() {
            Ok(()) => (),
            Err(std::fs::TryLockError::WouldBlock) => return Ok(RemovalAuthority::Busy),
            Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
        }
        if Identity::read(root)? != identity || !live(&file)? {
            return Ok(RemovalAuthority::Busy);
        }
        Ok(RemovalAuthority::Acquired(Self { file }))
    }

    pub(crate) fn retire(&mut self) -> std::io::Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(b"retired\n")?;
        self.file.sync_all()
    }

    pub(crate) fn restore(&mut self) -> std::io::Result<()> {
        self.file.set_len(0)?;
        self.file.sync_all()
    }
}

/// Protect existing targets during whole-checkout removal, including cross targets.
pub(crate) struct CargoLocks {
    files: Vec<File>,
}

impl CargoLocks {
    pub(crate) fn owns_descriptor(&self, descriptor: &str) -> bool {
        descriptor
            .parse::<std::os::fd::RawFd>()
            .is_ok_and(|fd| self.files.iter().any(|file| file.as_raw_fd() == fd))
    }

    pub(crate) fn claim(root: &Path) -> Result<Option<Self>, GcError> {
        fn collect(path: &Path, files: &mut Vec<File>) -> std::io::Result<bool> {
            if !path.exists() {
                return Ok(true);
            }
            if fs::symlink_metadata(path)?.file_type().is_symlink() {
                return Ok(false);
            }
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    if !collect(&entry.path(), files)? {
                        return Ok(false);
                    }
                } else if entry.file_name() == ".cargo-lock" {
                    let file = open(&entry.path(), false)?;
                    match file.try_lock() {
                        Ok(()) => files.push(file),
                        Err(std::fs::TryLockError::WouldBlock) => return Ok(false),
                        Err(std::fs::TryLockError::Error(error)) => return Err(error),
                    }
                }
            }
            Ok(true)
        }
        let mut files = Vec::new();
        if collect(&root.join("target"), &mut files)? {
            Ok(Some(Self { files }))
        } else {
            Ok(None)
        }
    }
}

pub fn run(root: &Path, args: WorktreeRunArgs) -> Result<(), GcError> {
    let _admission = Admission::acquire(root)?;
    let (program, argv) = args
        .command
        .split_first()
        .ok_or_else(|| GcError::Census("missing command".into()))?;
    let status = Command::new(program)
        .args(argv)
        .current_dir(root)
        .status()?;
    if !status.success() {
        return Err(GcError::Census(format!(
            "foreground command failed: {status}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository() -> tempfile::TempDir {
        let repo = tempfile::tempdir().unwrap();
        command::run_checked("git", ["init", "-b", "main"], Some(repo.path())).unwrap();
        repo
    }

    #[test]
    fn active_command_excludes_retirement_for_its_entire_lifetime() {
        let repo = repository();
        let root = repo.path();
        let common = common(root).unwrap();
        assert!(matches!(
            Retirement::claim(root, &common).unwrap(),
            RemovalAuthority::Unmanaged
        ));
        let admission = Admission::acquire(root).unwrap();
        assert!(matches!(
            Retirement::claim(root, &common).unwrap(),
            RemovalAuthority::Busy
        ));
        drop(admission);
        assert!(matches!(
            Retirement::claim(root, &common).unwrap(),
            RemovalAuthority::Acquired(_)
        ));
    }

    #[test]
    fn concurrent_command_cannot_enter_during_retirement_or_execute_after_it() {
        let repo = repository();
        let root = repo.path().to_owned();
        drop(Admission::acquire(&root).unwrap());
        let common = common(&root).unwrap();
        let RemovalAuthority::Acquired(mut retirement) = Retirement::claim(&root, &common).unwrap()
        else {
            panic!("idle managed checkout must acquire retirement")
        };
        let file = open(&Identity::read(&root).unwrap().authority(&common), false).unwrap();
        assert!(matches!(
            file.try_lock_shared(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        let marker = root.join("must-not-run");
        let (ready, waiting) = std::sync::mpsc::channel();
        let worker_root = root.clone();
        let worker_marker = marker.clone();
        let worker = std::thread::spawn(move || {
            ready.send(()).unwrap();
            run(
                &worker_root,
                WorktreeRunArgs {
                    command: vec!["touch".into(), worker_marker.into_os_string()],
                },
            )
        });
        waiting.recv().unwrap();
        retirement.retire().unwrap();
        drop(retirement);
        assert!(worker.join().unwrap().is_err());
        assert!(
            !marker.exists(),
            "waiting admission must never execute in a retired checkout"
        );
        assert!(Admission::acquire(&root).is_err());
    }

    #[test]
    fn failed_removal_restores_admission_without_unlinking_the_authority() {
        let repo = repository();
        let root = repo.path();
        drop(Admission::acquire(root).unwrap());
        let common = common(root).unwrap();
        let RemovalAuthority::Acquired(mut retirement) = Retirement::claim(root, &common).unwrap()
        else {
            panic!("managed checkout")
        };
        retirement.retire().unwrap();
        retirement.restore().unwrap();
        drop(retirement);
        assert!(Admission::acquire(root).is_ok());
    }
}
