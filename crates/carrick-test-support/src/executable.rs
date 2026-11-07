use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

/// Write an executable in an isolated, single-threaded fixture process.
///
/// The test process never opens the published inode for writing. A sibling
/// thread may fork at any point without inheriting a writable descriptor to it.
/// The single-threaded copy process owns the only writer, and exits before
/// publication. No retry or cooperation from other spawns is needed.
/// Replacing an existing path also avoids truncating an executable in use.
pub fn write_executable(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
    mode: u32,
) -> io::Result<()> {
    let path = path.as_ref();
    let staging = tempfile::tempdir_in(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?;
    let staged = staging.path().join("executable");
    let mut child = Command::new("/bin/cp")
        .arg("/dev/stdin")
        .arg(&staged)
        .stdin(Stdio::piped())
        .spawn()?;
    let written = child.stdin.take().unwrap().write_all(contents.as_ref());
    let status = child.wait()?;
    written?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "executable fixture writer: {status}"
        )));
    }
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(staged, path)
}

/// Publish a file assembled by a fixture as an executable on a fresh inode.
///
/// Writable descriptors to the original file, including any inherited by
/// concurrent children, cannot keep the replacement executable text busy.
/// Use `write_executable` directly when the contents are already available.
pub fn publish_executable(path: impl AsRef<Path>, mode: u32) -> io::Result<()> {
    let contents = std::fs::read(path.as_ref())?;
    write_executable(path, contents, mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_host_executable_preserves_bytes_mode_and_replaces_busy_inode() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("fixture with spaces");
        let contents = vec![0xa5; 256 * 1024];
        write_executable(&path, &contents, 0o751).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), contents);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o751
        );
        let old_writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        write_executable(&path, b"#!/bin/sh\nexit 0\n", 0o700).unwrap();
        assert!(Command::new(&path).status().unwrap().success());
        drop(old_writer);
    }
}
