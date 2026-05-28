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
    if let Ok(mut f) = std::fs::File::create(&tmp) {
        let _ = f.write_all(&bytes);
        let _ = f.sync_all();
        let _ = std::fs::rename(&tmp, &path);
    }
}

/// Read `pid`'s published euid. Returns `None` if the file doesn't exist
/// (peer not running carrick / not yet published) or can't be read.
pub fn read_target(pid: i32) -> Option<u32> {
    let path = cred_path(pid);
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
