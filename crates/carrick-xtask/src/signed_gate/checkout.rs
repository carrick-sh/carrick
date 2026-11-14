//! Crash-recoverable lifetime of a signed gate's build checkout.
use crate::lock_file::OwnedFileLock;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(super) fn run_name() -> String {
    format!(
        "{}-{}",
        std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| format!("manual-{}", std::process::id())),
        std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "1".into())
    )
}

/// The lock is held before the directory exists and through drop-time removal.
/// A killed owner releases it in the kernel; the next gate can then reap it.
/// Sidecar lock files are permanent, so no contender can lock an unlinked inode.
pub struct GateCheckout {
    directory: PathBuf,
    _lock: OwnedFileLock,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn lock_file(root: &Path, name: &str) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(format!("{name}.lock")))
}

fn remove(directory: &Path) -> io::Result<()> {
    match fs::remove_dir_all(directory) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

impl GateCheckout {
    /// Production allocation entry, also exercised by the killed-child witness.
    pub fn acquire(root: &Path, run: &str) -> io::Result<Self> {
        if !valid_name(run) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid gate run name",
            ));
        }
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)?;
        let metadata = fs::symlink_metadata(root)?;
        // SAFETY: geteuid has no preconditions.
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0
        {
            return Err(io::Error::other(
                "gate root must be an owned directory without group/other write permission",
            ));
        }
        let root = root.canonicalize()?;
        // Claim our name before scanning: concurrent gates may see our directory
        // only once its liveness lock is already held. Duplicate live runs fail.
        let file = lock_file(&root, run)?;
        file.try_lock().map_err(io::Error::from)?;
        let lock = OwnedFileLock::from_locked(file);
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str().filter(|name| valid_name(name)) else {
                continue;
            };
            if name == run || !entry.file_type()?.is_dir() {
                continue;
            }
            let file = lock_file(&root, name)?;
            match file.try_lock() {
                Ok(()) => {
                    let _stale = OwnedFileLock::from_locked(file);
                    remove(&entry.path())?;
                }
                Err(fs::TryLockError::WouldBlock) => (),
                Err(fs::TryLockError::Error(error)) => return Err(error),
            }
        }
        let directory = root.join(run);
        remove(&directory)?;
        fs::create_dir(&directory)?;
        Ok(Self {
            directory,
            _lock: lock,
        })
    }

    pub fn path(&self) -> &Path {
        &self.directory
    }
}

impl Drop for GateCheckout {
    fn drop(&mut self) {
        // Failed removal remains discoverable on the next start, under its lock.
        let _ = remove(&self.directory);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, Write};
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    #[test]
    fn checkout_child() {
        let Some(root) = std::env::var_os("GATE_CHECKOUT_TEST_ROOT") else {
            return;
        };
        let checkout = GateCheckout::acquire(Path::new(&root), "killed-1").unwrap();
        std::fs::create_dir(checkout.path().join("checkout")).unwrap();
        println!("READY:{}", checkout.path().display());
        std::io::stdout().flush().unwrap();
        // Bounded even if the parent test fails before killing us.
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn same_run_cannot_replace_a_live_checkout_or_its_lock() {
        let root = tempfile::tempdir().unwrap();
        let first = GateCheckout::acquire(root.path(), "same-1").unwrap();
        let lock = root.path().join("same-1.lock");
        let inode = fs::metadata(&lock).unwrap().ino();
        fs::write(first.path().join("sentinel"), b"live").unwrap();
        assert!(GateCheckout::acquire(root.path(), "same-1").is_err());
        assert!(first.path().join("sentinel").exists());
        drop(first);
        // A crash during allocation can leave an empty directory too.
        fs::create_dir(root.path().join("same-1")).unwrap();
        let second = GateCheckout::acquire(root.path(), "same-1").unwrap();
        assert!(second.path().exists());
        assert_eq!(fs::metadata(lock).unwrap().ino(), inode);
    }

    #[test]
    fn refuses_path_escape_and_symlink_authority() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        assert!(GateCheckout::acquire(root.path(), "../escape").is_err());
        let outside = tempfile::tempdir().unwrap();
        let alias = root.path().join("alias");
        symlink(outside.path(), &alias).unwrap();
        assert!(GateCheckout::acquire(&alias, "run-1").is_err());
        symlink(
            outside.path().join("must-not-create"),
            root.path().join("run-1.lock"),
        )
        .unwrap();
        assert!(GateCheckout::acquire(root.path(), "run-1").is_err());
        assert!(!outside.path().join("must-not-create").exists());
    }

    #[test]
    fn killed_checkout_is_reaped_but_live_checkout_is_kept() {
        let root = tempfile::tempdir().unwrap();
        let live = GateCheckout::acquire(root.path(), "live-1").unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "signed_gate::checkout::tests::checkout_child",
                "--nocapture",
            ])
            .env("GATE_CHECKOUT_TEST_ROOT", root.path())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let line = line.unwrap();
                if let Some((_, path)) = line.split_once("READY:") {
                    tx.send(PathBuf::from(path)).unwrap();
                    break;
                }
            }
        });
        let ready = rx.recv_timeout(Duration::from_secs(10));
        child.kill().unwrap();
        child.wait().unwrap();
        reader.join().unwrap();
        let stale = ready.unwrap();
        assert!(stale.join("checkout").exists());
        let next = GateCheckout::acquire(root.path(), "next-1").unwrap();
        assert!(
            !stale.exists(),
            "killed gate checkout survived the next gate start"
        );
        assert!(live.path().exists(), "live checkout was reaped");
        let next_path = next.path().to_path_buf();
        drop(next);
        assert!(!next_path.exists(), "normal drop must remove checkout");
    }
}
