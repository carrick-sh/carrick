//! Cooperative checkout admission. Authorities live outside removable checkouts.
use crate::command;
use crate::lock_file::OwnedFileLock;
use crate::worktree_gc::GcError;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(clap::Args, Debug)]
pub struct WorktreeRunArgs {
    /// Foreground command held under the checkout's shared lifetime guard.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<OsString>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Generation {
    identity: Identity,
    token: String,
}

impl Generation {
    fn read(root: &Path, create: bool) -> Result<Option<Self>, GcError> {
        let admin = command::run_checked(
            "git",
            ["rev-parse", "--path-format=absolute", "--git-dir"],
            Some(root),
        )?;
        let admin = fs::canonicalize(admin.stdout.trim())?;
        let path = admin.join("carrick-checkout-generation");
        let identity = Identity::read(root)?;
        if create && !path.exists() {
            // Atomic publication lets concurrent first admissions agree. Git
            // removes this metadata on removal; replacement checkouts cannot
            // recover a former authority even when their root inode is reused.
            let mut temporary = tempfile::Builder::new()
                .prefix("generation-")
                .rand_bytes(32)
                .tempfile_in(&admin)?;
            let token = temporary
                .path()
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| GcError::Census("generation filename is not UTF-8".into()))?
                .to_owned();
            serde_json::to_writer(
                &mut temporary,
                &Self {
                    identity: Identity::read(root)?,
                    token,
                },
            )
            .map_err(|error| GcError::Census(error.to_string()))?;
            temporary.as_file().sync_all()?;
            match temporary.persist_noclobber(&path) {
                Ok(_) => (),
                Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(error) => return Err(error.error.into()),
            }
        }
        let file = match open(&path, false) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let generation: Self = serde_json::from_reader(file.take(1024))
            .map_err(|error| GcError::Census(error.to_string()))?;
        if generation.identity != identity
            || Identity::read(root)? != identity
            || !generation.token.starts_with("generation-")
            || !generation
                .token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(GcError::Census(
                "checkout generation identity mismatch".into(),
            ));
        }
        Ok(Some(generation))
    }

    fn authority(&self, common: &Path) -> PathBuf {
        common.join("carrick-worktree-admission").join(&self.token)
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
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn live(mut file: &File) -> std::io::Result<bool> {
    file.seek(SeekFrom::Start(0))?;
    let mut state = String::new();
    file.take(32).read_to_string(&mut state)?;
    Ok(state.is_empty())
}

/// Shared checkout lifetime authority; explicit exec handoff retains it in the
/// command tree, including the lease supervisor through scoped cleanup.
pub(crate) struct Admission {
    _file: OwnedFileLock,
}

impl Admission {
    fn handoff_exec(&self) -> std::io::Result<()> {
        // SAFETY: explicit same-PID exec transfer of this one owned descriptor.
        if unsafe { libc::fcntl(self._file.as_raw_fd(), libc::F_SETFD, 0) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub(crate) fn acquire(root: &Path) -> Result<Self, GcError> {
        let generation = Generation::read(root, true)?
            .ok_or_else(|| GcError::Census("missing checkout generation".into()))?;
        let path = generation.authority(&common(root)?);
        fs::create_dir_all(
            path.parent()
                .ok_or_else(|| GcError::Census("authority has no parent".into()))?,
        )?;
        let file = open(&path, true)?;
        file.lock_shared()?;
        let file = OwnedFileLock::from_locked(file);
        if Generation::read(root, false)?.as_ref() != Some(&generation) || !live(&file)? {
            return Err(GcError::Census(
                "checkout has been retired; command refused".into(),
            ));
        }
        Ok(Self { _file: file })
    }
}

/// Only an already managed checkout can acquire exclusive removal authority.
pub(crate) struct Retirement {
    file: OwnedFileLock,
}

pub(crate) enum RemovalAuthority {
    Unmanaged,
    Busy,
    Acquired(Retirement),
}

impl Retirement {
    pub(crate) fn claim(root: &Path, common: &Path) -> Result<RemovalAuthority, GcError> {
        let Some(generation) = Generation::read(root, false)? else {
            return Ok(RemovalAuthority::Unmanaged);
        };
        let file = match open(&generation.authority(common), false) {
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
        let file = OwnedFileLock::from_locked(file);
        if Generation::read(root, false)?.as_ref() != Some(&generation) || !live(&file)? {
            return Ok(RemovalAuthority::Busy);
        }
        Ok(RemovalAuthority::Acquired(Self { file }))
    }

    pub(crate) fn retire(&mut self) -> std::io::Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(b"retired\n")?;
        self.file.sync_all()
    }
}

/// Protect existing targets during whole-checkout removal, including cross targets.
pub(crate) struct CargoLocks {
    files: Vec<OwnedFileLock>,
}

impl CargoLocks {
    pub(crate) fn owns_descriptor(&self, descriptor: &str) -> bool {
        descriptor
            .parse::<std::os::fd::RawFd>()
            .is_ok_and(|fd| self.files.iter().any(|file| file.as_raw_fd() == fd))
    }

    pub(crate) fn claim(root: &Path) -> Result<Option<Self>, GcError> {
        fn collect(path: &Path, files: &mut Vec<OwnedFileLock>) -> std::io::Result<bool> {
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
                        Ok(()) => files.push(OwnedFileLock::from_locked(file)),
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
    let admission = Admission::acquire(root)?;
    let (program, argv) = args
        .command
        .split_first()
        .ok_or_else(|| GcError::Census("missing command".into()))?;
    let mut command = Command::new(program);
    command.args(argv).current_dir(root);
    // Replace this runner so the lease supervisor watches the public runner's
    // PID, and exit/signal status remains the command's own. Only checkout
    // admission is inherited: the supervisor still exclusively owns host flock.
    // SAFETY: the guard owns this descriptor; fcntl is async-signal-safe. Keep
    // the handoff inside exec so ordinary Admission guards remain CLOEXEC.
    unsafe {
        command.pre_exec(move || admission.handoff_exec());
    }
    Err(command.exec().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository() -> tempfile::TempDir {
        let repo = tempfile::tempdir().unwrap();
        command::run_checked("git", ["init", "-b", "main"], Some(repo.path())).unwrap();
        repo
    }

    fn replacement_checkout_does_not_inherit_authority(retired: bool) {
        let repo = repository();
        let root = repo.path();
        command::run_checked(
            "git",
            [
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "--allow-empty",
                "-m",
                "base",
            ],
            Some(root),
        )
        .unwrap();
        let worker = root.join("worker");
        command::run_checked(
            "git",
            ["worktree", "add", "-b", "worker", worker.to_str().unwrap()],
            Some(root),
        )
        .unwrap();
        drop(Admission::acquire(&worker).unwrap());
        let identity = Identity::read(&worker).unwrap();
        let common = common(&worker).unwrap();
        if retired {
            let RemovalAuthority::Acquired(mut guard) =
                Retirement::claim(&worker, &common).unwrap()
            else {
                panic!("managed old checkout")
            };
            guard.retire().unwrap();
        }
        let admin = command::run_checked(
            "git",
            ["rev-parse", "--path-format=absolute", "--git-dir"],
            Some(&worker),
        )
        .unwrap();
        // Preserve the empty directory to reproduce inode reuse deterministically;
        // replace its Git administrative generation just as remove/add does.
        fs::remove_file(worker.join(".git")).unwrap();
        fs::remove_dir_all(admin.stdout.trim()).unwrap();
        command::run_checked(
            "git",
            [
                "worktree",
                "add",
                "-b",
                "replacement",
                worker.to_str().unwrap(),
            ],
            Some(root),
        )
        .unwrap();
        assert_eq!(Identity::read(&worker).unwrap(), identity);
        let unmanaged = matches!(
            Retirement::claim(&worker, &common).unwrap(),
            RemovalAuthority::Unmanaged
        );
        let admitted = Admission::acquire(&worker).is_ok();
        assert!(
            unmanaged && admitted,
            "replacement inherited stale {} authority: unmanaged={unmanaged}, admitted={admitted}",
            if retired { "tombstone" } else { "live" }
        );
    }

    #[test]
    fn replacement_checkout_cannot_inherit_stale_live_authority() {
        replacement_checkout_does_not_inherit_authority(false);
    }

    #[test]
    fn replacement_checkout_cannot_inherit_stale_tombstone() {
        replacement_checkout_does_not_inherit_authority(true);
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
        let file = open(
            &Generation::read(&root, false)
                .unwrap()
                .unwrap()
                .authority(&common),
            false,
        )
        .unwrap();
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
    fn unrelated_fork_exec_cannot_extend_admission() {
        let repo = repository();
        let root = repo.path();
        let common = common(root).unwrap();
        let admission = Admission::acquire(root).unwrap();
        // CLOEXEC alone cannot prevent a hold between fork and exec.
        assert_ne!(
            unsafe { libc::fcntl(admission._file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        let immediate = crate::lock_file::tests::with_unrelated_fork_exec(
            || {
                drop(admission);
                matches!(
                    Retirement::claim(root, &common).unwrap(),
                    RemovalAuthority::Acquired(_)
                )
            },
            || {
                assert!(matches!(
                    Retirement::claim(root, &common).unwrap(),
                    RemovalAuthority::Acquired(_)
                ))
            },
        );
        assert!(
            immediate,
            "unrelated pre-exec child retained dropped checkout admission despite CLOEXEC"
        );
    }

    #[test]
    fn unrelated_fork_exec_cannot_extend_retirement() {
        let repo = repository();
        let root = repo.path();
        let common = common(root).unwrap();
        drop(Admission::acquire(root).unwrap());
        let RemovalAuthority::Acquired(retirement) = Retirement::claim(root, &common).unwrap()
        else {
            panic!("managed checkout");
        };
        let immediate = crate::lock_file::tests::with_unrelated_fork_exec(
            || {
                drop(retirement);
                matches!(
                    Retirement::claim(root, &common).unwrap(),
                    RemovalAuthority::Acquired(_)
                )
            },
            || {
                assert!(matches!(
                    Retirement::claim(root, &common).unwrap(),
                    RemovalAuthority::Acquired(_)
                ))
            },
        );
        assert!(
            immediate,
            "unrelated pre-exec child retained dropped retirement authority"
        );
    }

    #[test]
    fn unrelated_fork_exec_cannot_extend_cargo_locks() {
        let repo = repository();
        let root = repo.path();
        fs::create_dir_all(root.join("target/debug")).unwrap();
        fs::write(root.join("target/debug/.cargo-lock"), b"").unwrap();
        let locks = CargoLocks::claim(root).unwrap().unwrap();
        let immediate = crate::lock_file::tests::with_unrelated_fork_exec(
            || {
                drop(locks);
                CargoLocks::claim(root).unwrap().is_some()
            },
            || assert!(CargoLocks::claim(root).unwrap().is_some()),
        );
        assert!(
            immediate,
            "unrelated pre-exec child retained dropped native Cargo locks"
        );
    }

    #[test]
    fn failed_removal_keeps_admission_retired() {
        let repo = repository();
        let root = repo.path();
        drop(Admission::acquire(root).unwrap());
        let common = common(root).unwrap();
        let RemovalAuthority::Acquired(mut retirement) = Retirement::claim(root, &common).unwrap()
        else {
            panic!("managed checkout")
        };
        retirement.retire().unwrap();
        drop(retirement);
        assert!(Admission::acquire(root).is_err());
    }
}
