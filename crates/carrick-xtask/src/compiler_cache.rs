//! Job-local sccache lifecycle. The lock inode is retained for the job's lifetime.
use std::fs::OpenOptions;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub(crate) fn start() -> io::Result<()> {
    let socket =
        PathBuf::from(std::env::var_os("SCCACHE_SERVER_UDS").ok_or_else(|| {
            io::Error::other("SCCACHE_SERVER_UDS is required for the local backend")
        })?);
    let mut lock_path = socket.as_os_str().to_owned();
    lock_path.push(".lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)?;
    lock.lock()?;
    let _lock = crate::lock_file::OwnedFileLock::from_locked(lock);
    let bin = std::env::var_os("CARRICK_SCCACHE_BIN").unwrap_or_else(|| "sccache".into());
    // sccache 0.18 returns synthetic statistics when no server answers.
    // A successful stats command alone is therefore not a readiness check.
    match UnixStream::connect(&socket) {
        Ok(connection) => {
            drop(connection);
            if Command::new(&bin)
                .arg("--show-stats")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?
                .success()
            {
                return Ok(());
            }
            return Err(io::Error::other(
                "live sccache server did not return statistics",
            ));
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) => {}
        Err(e) => return Err(e),
    }
    match std::fs::remove_file(&socket) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if !Command::new(bin)
        .env("SCCACHE_IDLE_TIMEOUT", "0")
        .arg("--start-server")
        .status()?
        .success()
    {
        return Err(io::Error::other("sccache server startup failed"));
    }
    Ok(())
}
