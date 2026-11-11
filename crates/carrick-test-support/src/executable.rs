//! Race-free "write an executable, then run it" for tests.
//!
//! On Linux, exec of a file that any process still holds open for writing
//! fails with ETXTBSY. A test that writes a script with `std::fs::write` holds
//! a write descriptor until the call returns, and a sibling test thread that
//! forks in that window hands the descriptor to its child until the child
//! execs. The writer then runs the file and gets "Text file busy".
//!
//! These helpers never open the executable for writing in the test process at
//! all: a short-lived child process creates the file and exits before the
//! caller continues. A fork elsewhere in the test process can only copy
//! descriptors the test process holds, and it holds none for the new inode,
//! so there is no window to retry around. Every test that writes a file it
//! later executes goes through here; `.semgrep/test-executables.yml` refuses a
//! raw write plus `0o7xx` permission change.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

/// Write `contents` to `path` and make it executable (`0o755`).
///
/// An existing file at `path` is replaced by a new inode, so a previous copy
/// that is being executed does not make the write fail.
pub fn write_executable(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) {
    write_executable_mode(path, contents, 0o755);
}

/// [`write_executable`] with an explicit permission mode.
pub fn write_executable_mode(path: impl AsRef<Path>, contents: impl AsRef<[u8]>, mode: u32) {
    let path = path.as_ref();
    replace_target(path);
    let mut child = Command::new("/bin/sh")
        .args(["-c", "exec cat > \"$1\"", "write-executable"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(contents.as_ref())
        .unwrap();
    finish(child, path, mode);
}

/// Copy the file at `from` to `to` and give the copy permission `mode`.
pub fn copy_executable(from: impl AsRef<Path>, to: impl AsRef<Path>, mode: u32) {
    let (from, to) = (from.as_ref(), to.as_ref());
    replace_target(to);
    let child = Command::new("/bin/sh")
        .args(["-c", "exec cat \"$1\" > \"$2\"", "copy-executable"])
        .arg(from)
        .arg(to)
        .spawn()
        .unwrap();
    finish(child, to, mode);
}

fn replace_target(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("replace {}: {e}", path.display()),
    }
}

fn finish(mut child: std::process::Child, path: &Path, mode: u32) {
    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "writing {} failed: {status}",
        path.display()
    );
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}
