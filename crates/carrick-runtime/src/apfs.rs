//! Carrick's interface to APFS volume management via `diskutil(8)`.
//!
//! Why diskutil and not a Rust crate? `apfs.framework` is a private,
//! undocumented Apple framework — no stable C ABI, no FFI worth
//! depending on, and the published Rust crates (`objc2-disk-arbitration`,
//! `disk-arbitration-sys`) wrap `DiskArbitration`, which handles
//! mount/unmount/notification but NOT volume creation. The supported,
//! upstream-blessed path is `diskutil apfs addVolume`/`deleteVolume`,
//! which every production tool (Lima, Rancher Desktop, Tart, OrbStack)
//! uses. We shell out and parse plist output.
//!
//! What this gives carrick: a one-time `carrick volume create` lays
//! down a case-sensitive APFS volume mounted at `/Volumes/carrick`
//! (or wherever the user prefers). The `HostFsBackend` then defaults
//! its scratch root onto that volume, which means:
//!   - case-sensitive paths (a hard Linux ABI requirement; the user's
//!     usual `/Volumes/Macintosh HD` is case-insensitive and would
//!     silently break paths like `/Foo` vs `/foo`),
//!   - the scratch dir lives on the same APFS volume as the unpacked
//!     rootfs, so a future clonefile(2)-based seed could be O(1) (NOT
//!     yet implemented — current seeding byte-copies via write_all; see
//!     docs/archive/superpowers/plans/2026-05-23-code-quality-darwin-ecosystem.md),
//!   - throw-away on `carrick volume delete` is a single subvolume
//!     destroy instead of an `rm -rf` of millions of inodes.

use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

/// Default name of the carrick-owned APFS subvolume. Visible to the
/// user under `/Volumes/<this>`; chosen to be obvious and unlikely to
/// collide with anything the user might have created themselves.
pub const DEFAULT_VOLUME_NAME: &str = "carrick";

#[derive(Debug, Error)]
pub enum ApfsError {
    #[error(
        "`diskutil` not found on PATH; APFS volume management requires the macOS Disk Utility binary"
    )]
    DiskutilMissing,
    #[error("`diskutil {operation}` failed (exit {code}): {stderr}")]
    DiskutilFailed {
        operation: String,
        code: i32,
        stderr: String,
    },
    #[error("could not locate APFS container for the boot volume: {0}")]
    BootContainerNotFound(String),
    #[error("plist output from diskutil was malformed: {0}")]
    MalformedPlist(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Summary of a carrick-owned APFS subvolume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    /// Disk identifier (e.g. `disk3s7`).
    pub device: String,
    /// Volume name as it appears under `/Volumes/<name>`.
    pub name: String,
    /// Mount point, e.g. `/Volumes/carrick`. `None` if not mounted.
    pub mount_point: Option<PathBuf>,
    /// `true` if the volume was created with the case-sensitive
    /// (`APFSX`) personality — Linux ABI requires this.
    pub case_sensitive: bool,
}

/// Run `diskutil` with the given args; return stdout on success or
/// a structured error on failure.
fn run_diskutil(args: &[&str]) -> Result<String, ApfsError> {
    let out = Command::new("diskutil")
        .args(args)
        .output()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                ApfsError::DiskutilMissing
            } else {
                ApfsError::Io(err)
            }
        })?;
    if !out.status.success() {
        return Err(ApfsError::DiskutilFailed {
            operation: args.join(" "),
            code: out.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Identify the APFS container that hosts the boot volume — that's
/// where we add our subvolume so it shares the boot disk's free space
/// (instead of carving out a new physical store). Parses
/// `diskutil info /` for the "APFS Container" line.
pub fn boot_apfs_container() -> Result<String, ApfsError> {
    let stdout = run_diskutil(&["info", "/"])?;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("APFS Container:") {
            return Ok(value.trim().to_owned());
        }
    }
    Err(ApfsError::BootContainerNotFound(stdout))
}

/// List every APFS volume on the host, returning the subset whose
/// name matches `name`. Used to detect "is the carrick volume already
/// laid down?" without parsing plist (cheap, scrapeable, stable).
pub fn find_volumes_named(name: &str) -> Result<Vec<VolumeInfo>, ApfsError> {
    let stdout = run_diskutil(&["apfs", "list"])?;
    Ok(parse_apfs_list_for(&stdout, name))
}

/// Find the single carrick-owned volume (the one named
/// [`DEFAULT_VOLUME_NAME`]). Returns `None` if it doesn't exist yet,
/// or the multiple-volumes case if the user has more than one — we
/// return `Some(first)` for the multiple case to keep the API simple;
/// callers wanting strictness can use [`find_volumes_named`].
pub fn find_carrick_volume() -> Result<Option<VolumeInfo>, ApfsError> {
    Ok(find_volumes_named(DEFAULT_VOLUME_NAME)?.into_iter().next())
}

/// Create a case-sensitive APFS subvolume in the boot container.
/// Idempotent: if a volume with that name already exists, returns its
/// current `VolumeInfo` without touching anything.
///
/// The subvolume shares the boot container's free space (no fixed
/// quota by default); for a quota-bounded scratch, pass `Some(bytes)`.
pub fn create_carrick_volume(quota_bytes: Option<u64>) -> Result<VolumeInfo, ApfsError> {
    if let Some(existing) = find_carrick_volume()? {
        return Ok(existing);
    }
    let container = boot_apfs_container()?;
    let mut args: Vec<String> = vec![
        "apfs".into(),
        "addVolume".into(),
        container,
        // APFSX is the case-sensitive personality. Linux paths break
        // catastrophically on case-insensitive volumes (e.g. /Foo
        // overlays /foo at the directory level).
        "APFSX".into(),
        DEFAULT_VOLUME_NAME.into(),
    ];
    if let Some(quota) = quota_bytes {
        args.push("-quota".into());
        args.push(quota.to_string());
    }
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let _ = run_diskutil(&arg_refs)?;
    find_carrick_volume()?.ok_or_else(|| {
        ApfsError::BootContainerNotFound(
            "addVolume reported success but the new volume isn't visible to `diskutil apfs list`"
                .to_owned(),
        )
    })
}

/// Tear down the carrick-owned APFS subvolume. Idempotent: returns
/// `Ok(())` if there's nothing to delete.
///
/// This is destructive — anything the user (or a prior carrick run)
/// left on the volume is gone. We require an opt-in argument to
/// reduce footgun blast radius.
pub fn delete_carrick_volume() -> Result<(), ApfsError> {
    let Some(volume) = find_carrick_volume()? else {
        return Ok(());
    };
    let _ = run_diskutil(&["apfs", "deleteVolume", &volume.device])?;
    Ok(())
}

/// Best-effort: ensure the carrick volume is mounted. Newly created
/// volumes are usually auto-mounted, but a reboot leaves them mounted
/// only if launchd is configured for them. Returns the volume's
/// current mount point regardless.
pub fn ensure_mounted(volume: &VolumeInfo) -> Result<PathBuf, ApfsError> {
    if let Some(mp) = &volume.mount_point {
        return Ok(mp.clone());
    }
    let _ = run_diskutil(&["mount", &volume.device])?;
    let refreshed = find_carrick_volume()?.ok_or_else(|| {
        ApfsError::BootContainerNotFound(
            "mount apparently succeeded but the volume disappeared".to_owned(),
        )
    })?;
    refreshed.mount_point.ok_or_else(|| {
        ApfsError::BootContainerNotFound(
            "mount apparently succeeded but no mount point is set".to_owned(),
        )
    })
}

/// Parse `diskutil apfs list`'s text output for entries with the given
/// volume name. The list format is stable in macOS 12+ (sequoia/sonoma),
/// indented with `+-> Volume <disk> <UUID>` headers and `Name: <X> (...)`
/// lines underneath. We anchor on those two patterns.
fn parse_apfs_list_for(stdout: &str, target_name: &str) -> Vec<VolumeInfo> {
    let mut out = Vec::new();
    let mut current_device: Option<String> = None;
    for line in stdout.lines() {
        // diskutil prefixes most lines with `|` tree-drawing chars.
        // Strip both whitespace and pipes so our prefix matches work.
        let trimmed = line
            .trim_start_matches(|c: char| c.is_whitespace() || c == '|')
            .trim_start();
        // "+-> Volume disk3s7 5023506F-9534-4243-..."
        if let Some(rest) = trimmed.strip_prefix("+-> Volume ") {
            current_device = rest.split_whitespace().next().map(|s| s.to_owned());
            continue;
        }
        // "Name: carrick (Case-sensitive)"
        if let Some(rest) = trimmed.strip_prefix("Name:") {
            let rest = rest.trim();
            let (name, suffix) = split_at_last_paren(rest);
            if name == target_name {
                let device = current_device.clone().unwrap_or_default();
                let case_sensitive = suffix.contains("Case-sensitive");
                let mount_point = find_mount_point_for(stdout, &device);
                out.push(VolumeInfo {
                    device,
                    name: name.to_owned(),
                    mount_point,
                    case_sensitive,
                });
            }
        }
    }
    out
}

/// Walk the same stdout looking for the "Mount Point: <path>" or
/// "Mount Point: Not Mounted" line under the given device's section.
fn find_mount_point_for(stdout: &str, device: &str) -> Option<PathBuf> {
    let header_needle = format!("+-> Volume {} ", device);
    let mut in_section = false;
    for line in stdout.lines() {
        let trimmed = line
            .trim_start_matches(|c: char| c.is_whitespace() || c == '|')
            .trim_start();
        if trimmed.starts_with(&header_needle) {
            in_section = true;
            continue;
        }
        if in_section && trimmed.starts_with("+-> Volume ") {
            break;
        }
        if in_section && let Some(rest) = trimmed.strip_prefix("Mount Point:") {
            let rest = rest.trim();
            if rest == "Not Mounted" {
                return None;
            }
            return Some(PathBuf::from(rest));
        }
    }
    None
}

/// "carrick (Case-sensitive)" → ("carrick", "Case-sensitive")
fn split_at_last_paren(s: &str) -> (&str, &str) {
    if let Some(open) = s.rfind('(') {
        let name = s[..open].trim();
        let suffix = s[open + 1..].trim_end_matches(')').trim();
        (name, suffix)
    } else {
        (s.trim(), "")
    }
}

/// Where should `HostFsBackend` place its per-run scratch dir? Prefer
/// the dedicated carrick APFS volume (always case-sensitive, isolated,
/// throw-away-able). Fall back to `~/.carrick/scratch` for hosts where
/// the volume hasn't been laid down yet.
///
/// HOT PATH: this runs at the start of every `carrick` invocation that
/// uses the host FS backend. It must NOT shell out to `diskutil apfs
/// list` — that enumerates every APFS container on the system and costs
/// ~250 ms, which a profile showed dominated trivial-guest startup. A
/// volume named `carrick` is mounted by `diskutil apfs addVolume` at the
/// conventional `/Volumes/carrick`, so a single `stat` of that path is an
/// equivalent (and instant) probe for the common case. The slow
/// `diskutil`-backed `find_carrick_volume` is reserved for the explicit
/// `carrick volume` subcommands, not this per-run path.
pub fn preferred_scratch_root() -> std::io::Result<PathBuf> {
    // Cached once per process; the scratch root cannot change while we run.
    static CACHE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    Ok(CACHE.get_or_init(resolve_scratch_root).clone())
}

fn resolve_scratch_root() -> PathBuf {
    // Fast path: the conventional mount point of the carrick volume. Verify
    // it's actually case-sensitive (a Linux ABI requirement) so a coincidental
    // dir at that path on a case-insensitive boot volume can't be mistaken for
    // our volume.
    let conventional = Path::new("/Volumes").join(DEFAULT_VOLUME_NAME);
    if conventional.is_dir() && probe_case_sensitive(&conventional) {
        return conventional;
    }
    // Fallback: honour the user's $CARRICK_HOME, else $HOME/.carrick. (No
    // diskutil: a host without the conventional mount almost certainly has no
    // carrick volume, and an exotic mount can be pointed at via $CARRICK_HOME.)
    let home = std::env::var_os("CARRICK_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| {
                let mut p = PathBuf::from(h);
                p.push(".carrick");
                p
            })
        })
        .unwrap_or_else(|| PathBuf::from("/tmp/carrick"));
    home.join("scratch")
}

/// Probe whether `path` resides on a case-sensitive filesystem.
/// Tries to round-trip a sentinel file through opposite case spellings;
/// on a case-insensitive volume the two open the same inode. Returns
/// `false` on any error rather than misreporting `true`.
pub fn probe_case_sensitive(path: &Path) -> bool {
    let lower = path.join(".carrick-case-probe");
    let upper = path.join(".CARRICK-case-probe");
    if std::fs::File::create(&lower).is_err() {
        return false;
    }
    let metadata_upper = std::fs::metadata(&upper);
    let _ = std::fs::remove_file(&lower);
    // On case-sensitive: upper doesn't exist → Err.
    // On case-insensitive: upper opens the same inode as lower → Ok.
    metadata_upper.is_err()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_apfs_list_finds_named_case_sensitive_volume() {
        let sample = "\
APFS Containers (1 found)
|
+-- Container disk3 34EBD256-B255-487B-82A0-80EB762E614F
    ====================================================
    |
    +-> Volume disk3s7 11111111-2222-3333-4444-555555555555
    |   ---------------------------------------------------
    |   APFS Volume Disk (Role):   disk3s7 (No specific role)
    |   Name:                      carrick (Case-sensitive)
    |   Mount Point:               /Volumes/carrick
    |   Capacity Consumed:         123456 B
    |
    +-> Volume disk3s8 22222222-3333-4444-5555-666666666666
    |   ---------------------------------------------------
    |   Name:                      ScratchData (Case-insensitive)
    |   Mount Point:               Not Mounted
";
        let found = parse_apfs_list_for(sample, "carrick");
        assert_eq!(found.len(), 1);
        let v = &found[0];
        assert_eq!(v.device, "disk3s7");
        assert_eq!(v.name, "carrick");
        assert_eq!(v.mount_point, Some(PathBuf::from("/Volumes/carrick")));
        assert!(v.case_sensitive);
    }

    #[test]
    fn parse_apfs_list_reports_unmounted_volume() {
        let sample = "\
+-> Volume disk3s9 33333333-4444-5555-6666-777777777777
    Name:        carrick (Case-sensitive)
    Mount Point: Not Mounted
";
        let found = parse_apfs_list_for(sample, "carrick");
        assert_eq!(found.len(), 1);
        assert!(found[0].mount_point.is_none());
    }

    #[test]
    fn parse_apfs_list_returns_empty_when_name_absent() {
        let sample = "\
+-> Volume disk3s1 99999999-...
    Name: Macintosh HD (Case-insensitive)
    Mount Point: /
";
        let found = parse_apfs_list_for(sample, "carrick");
        assert!(found.is_empty());
    }

    #[test]
    fn split_at_last_paren_handles_typical_name() {
        let (n, s) = split_at_last_paren("carrick (Case-sensitive)");
        assert_eq!(n, "carrick");
        assert_eq!(s, "Case-sensitive");
    }

    #[test]
    fn split_at_last_paren_handles_name_without_paren() {
        let (n, s) = split_at_last_paren("just-a-name");
        assert_eq!(n, "just-a-name");
        assert_eq!(s, "");
    }
}
