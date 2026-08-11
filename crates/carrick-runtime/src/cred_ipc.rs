//! Durable one-task-adapter credential projection for peer host processes.
//!
//! Kernel `Credentials` remains the sole in-process authority. Only the mature
//! one-Linux-task-per-host-process adapter's task leader publishes here; guest
//! nonleaders and multiplexed HVPatch tasks never overwrite one host-PID slot.
//! Readers use this transport when the target Kernel graph lives in another
//! host process and therefore cannot be joined directly. Used by
//! `bootstrap_signal_send` for the existing cross-process permission model.
//!
//! Storage: `/tmp/carrick-cred-<host_pid>` — a single u32 little-endian
//! leader euid projection. The adapter publishes whenever leader authority is
//! established or its effective uid changes. The file is created at first
//! publish; the process's exit
//! reaps it via the `unpublish` helper. Best-effort throughout — if the
//! file is missing (peer not yet published, peer is a non-carrick process,
//! /tmp not writable), the caller falls back to the conservative ALLOW
//! decision (matching today's pre-fix behaviour).
//!
//! Scope (audit M12): this mechanism publishes the effective **uid** only,
//! because Linux's `kill(2)` permission model is uid-based (a caller may signal
//! a target if its real/effective uid matches the target's real/saved uid).
//! The gid setters (`setgid`/`setregid`/`setresgid`/`setfsgid`) deliberately do
//! NOT publish — no cross-process check consults a peer's gid, so a per-process
//! gid view would be dead state. In-process `getgid`/`getegid`/`getresgid`
//! still round-trip the gid triple faithfully; only the (unused) cross-process
//! gid view is intentionally absent.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const CRED_DIR: &str = "/tmp";

/// Cached `(host_pid, euid)` publication; including the host PID keeps a
/// fork child from inheriting a cache hit for its parent's projection.
/// `u64::MAX` is the sentinel for "never published yet".
static LAST_PUBLISHED: AtomicU64 = AtomicU64::new(u64::MAX);

fn cred_path(pid: i32) -> PathBuf {
    PathBuf::from(CRED_DIR).join(format!("carrick-cred-{pid}"))
}

fn publication_key(host_pid: u32, euid: u32) -> u64 {
    (u64::from(host_pid) << 32) | u64::from(euid)
}

/// Write `euid` to the current process's cred file. Idempotent + cheap on
/// the unchanged path.
pub fn publish_self(euid: u32) {
    let host_pid = std::process::id();
    let publication = publication_key(host_pid, euid);
    if LAST_PUBLISHED.swap(publication, Ordering::Relaxed) == publication {
        return;
    }
    let path = cred_path(host_pid as i32);
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
    LAST_PUBLISHED.store(u64::MAX, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::publication_key;

    #[test]
    fn publication_cache_key_distinguishes_forked_host_processes() {
        assert_ne!(publication_key(41, 1000), publication_key(42, 1000));
        assert_ne!(publication_key(41, 1000), publication_key(41, 1001));
    }
}
