//! Per-process credential publication so peer carrick processes can read
//! each other's current effective uid. Used by `bootstrap_signal_send` to
//! enforce Linux's `kill(2)` permission check (LTP `kill05`): a non-root
//! caller cannot signal a process owned by a different uid.
//!
//! Storage: `/tmp/carrick-cred-<host_pid>` — a single u32 little-endian
//! euid value. Each carrick process publishes on `setuid`/`setreuid`/
//! `setresuid`. The file is created at first publish; the process's exit
//! reaps it via the `unpublish` helper. Best-effort throughout — if the
//! file is missing (peer not yet published, peer is a non-carrick process,
//! /tmp not writable), the caller falls back to the conservative ALLOW
//! decision (matching today's pre-fix behaviour).

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

const CRED_DIR: &str = "/tmp";

/// Cached version of the most recently published euid; lets us skip the
/// fs write when nothing has changed. `u32::MAX` is the sentinel for
/// "never published yet".
static LAST_PUBLISHED: AtomicU32 = AtomicU32::new(u32::MAX);

fn cred_path(pid: i32) -> PathBuf {
    PathBuf::from(CRED_DIR).join(format!("carrick-cred-{pid}"))
}

/// Write `euid` to the current process's cred file. Idempotent + cheap on
/// the unchanged path.
pub fn publish_self(euid: u32) {
    if LAST_PUBLISHED.swap(euid, Ordering::Relaxed) == euid {
        return;
    }
    let path = cred_path(std::process::id() as i32);
    // Best-effort atomic-ish write: write to <path>.tmp then rename. A
    // reader catching us mid-write either sees the old contents (rename
    // not yet committed) or the new ones, never a partial.
    let tmp = path.with_extension("tmp");
    let bytes = euid.to_le_bytes();
    // Create the tmp file 0600 (owner-only) with O_NOFOLLOW so a pre-planted
    // symlink at <tmp> makes the open fail (ELOOP) rather than following it.
    // We own the host uid in /tmp and the name is per-pid, so this is
    // best-effort hardening; the value written is our own euid regardless,
    // then atomically renamed into place.
    let open = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp);
    if let Ok(mut f) = open {
        let _ = f.write_all(&bytes);
        let _ = f.sync_all();
        let _ = std::fs::rename(&tmp, &path);
    }
}

/// Read `pid`'s published euid. Returns `None` if the file doesn't exist
/// (peer not running carrick / not yet published), can't be read, or fails
/// the owner / permission / staleness guards below. Falling to `None` is
/// always safe: the kill(2) caller then takes the conservative ALLOW path,
/// so kill conformance is byte-for-byte unchanged.
pub fn read_target(pid: i32) -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;
    let path = cred_path(pid);
    let meta = std::fs::metadata(&path).ok()?;
    // Owner guard: only trust a cred file written by THIS host process's uid.
    // Guest set*id is virtualized, so legit files are always our uid.
    let our_uid = unsafe { libc::getuid() };
    if meta.uid() != our_uid {
        return None;
    }
    // Reject a group/other-writable (tampered/forged) cred file.
    if meta.mode() & 0o022 != 0 {
        return None;
    }
    // Staleness guard: the named host pid must still be alive. kill(pid,0)
    // returns 0 if alive, -1/ESRCH if dead, -1/EPERM if alive-but-foreign.
    // Treat ONLY ESRCH as dead (ignore the file). A positive target pid only
    // reaches here (read_target is called with a positive target).
    if unsafe { libc::kill(pid, 0) } == -1 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if e == libc::ESRCH {
            return None;
        }
    }
    let bytes = std::fs::read(&path).ok()?;
    if bytes.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Remove our cred file on process exit. Best-effort.
pub fn unpublish() {
    let _ = std::fs::remove_file(cred_path(std::process::id() as i32));
}
