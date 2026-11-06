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
//!     yet implemented — current seeding byte-copies via write_all),
//!   - throw-away on `carrick volume delete` is a single subvolume
//!     destroy instead of an `rm -rf` of millions of inodes.

use std::path::{Path, PathBuf};

/// Default name of the carrick-owned APFS subvolume. Visible to the
/// user under `/Volumes/<this>`; chosen to be obvious and unlikely to
/// collide with anything the user might have created themselves.
pub const DEFAULT_VOLUME_NAME: &str = "carrick";

#[derive(Debug, ::thiserror::Error)]
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

/// Typed operator capability for the explicit `carrick volume` surface.
///
/// The runtime owns APFS parsing and policy, but never a process launcher. The
/// CLI implements this capability in its operator-only module; carrier launch
/// has no value of this type and therefore cannot invoke `diskutil`.
pub trait ApfsOperator {
    fn run_diskutil(&mut self, args: &[&str]) -> Result<String, ApfsError>;
}

/// Identify the APFS container that hosts the boot volume — that's
/// where we add our subvolume so it shares the boot disk's free space
/// (instead of carving out a new physical store). Parses
/// `diskutil info /` for the "APFS Container" line.
pub fn boot_apfs_container(operator: &mut impl ApfsOperator) -> Result<String, ApfsError> {
    let stdout = operator.run_diskutil(&["info", "/"])?;
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
pub fn find_volumes_named(
    operator: &mut impl ApfsOperator,
    name: &str,
) -> Result<Vec<VolumeInfo>, ApfsError> {
    let stdout = operator.run_diskutil(&["apfs", "list"])?;
    Ok(parse_apfs_list_for(&stdout, name))
}

/// Find the single carrick-owned volume (the one named
/// [`DEFAULT_VOLUME_NAME`]). Returns `None` if it doesn't exist yet,
/// or the multiple-volumes case if the user has more than one — we
/// return `Some(first)` for the multiple case to keep the API simple;
/// callers wanting strictness can use [`find_volumes_named`].
pub fn find_carrick_volume(
    operator: &mut impl ApfsOperator,
) -> Result<Option<VolumeInfo>, ApfsError> {
    Ok(find_volumes_named(operator, DEFAULT_VOLUME_NAME)?
        .into_iter()
        .next())
}

/// Create a case-sensitive APFS subvolume in the boot container.
/// Idempotent: if a volume with that name already exists, returns its
/// current `VolumeInfo` without touching anything.
///
/// The subvolume shares the boot container's free space (no fixed
/// quota by default); for a quota-bounded scratch, pass `Some(bytes)`.
pub fn create_carrick_volume(
    operator: &mut impl ApfsOperator,
    quota_bytes: Option<u64>,
) -> Result<VolumeInfo, ApfsError> {
    if let Some(existing) = find_carrick_volume(operator)? {
        return Ok(existing);
    }
    let container = boot_apfs_container(operator)?;
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
    let _ = operator.run_diskutil(&arg_refs)?;
    find_carrick_volume(operator)?.ok_or_else(|| {
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
pub fn delete_carrick_volume(operator: &mut impl ApfsOperator) -> Result<(), ApfsError> {
    let Some(volume) = find_carrick_volume(operator)? else {
        return Ok(());
    };
    let _ = operator.run_diskutil(&["apfs", "deleteVolume", &volume.device])?;
    Ok(())
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

/// Walk the same stdout looking for the `Mount Point: <path>` or
/// `Mount Point: Not Mounted` line under the given device's section.
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

/// Where should `HostFsBackend` place its per-run scratch dir? An explicit
/// `CARRICK_HOME` places scratch at `$CARRICK_HOME/scratch`, checking it without touching
/// the conventional mount. Prefer
/// the dedicated carrick APFS volume (always case-sensitive, isolated,
/// throw-away-able). Fall back to `~/.carrick/scratch` for hosts where
/// the volume hasn't been laid down yet.
///
/// HOT PATH: this runs at the start of every `carrick` invocation that
/// uses the host FS backend. It must NOT shell out to `diskutil apfs
/// list` — that enumerates every APFS container on the system and costs
/// ~250 ms, which a profile showed dominated trivial-guest startup. A
/// volume named `carrick` is mounted by `diskutil apfs addVolume` at the
/// conventional `/Volumes/carrick`; a nonblocking case-sensitivity probe validates
/// that candidate without enumerating disks. The slow
/// `diskutil`-backed `find_carrick_volume` is reserved for the explicit
/// `carrick volume` subcommands, not this per-run path.
pub fn preferred_scratch_root() -> &'static ScratchRoot {
    // One process configuration authority owns both immutable decisions.
    static CACHE: std::sync::OnceLock<ScratchRoot> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| resolve_scratch_root(&Path::new("/Volumes").join(DEFAULT_VOLUME_NAME)))
}

/// The selected scratch path and its case-sensitivity decision, checked once.
pub struct ScratchRoot {
    path: PathBuf,
    case_sensitive: bool,
}

impl ScratchRoot {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Refuse host-backed Linux paths unless the selected root passed the probe.
    pub fn host_path(&self) -> std::io::Result<&Path> {
        if self.case_sensitive {
            Ok(&self.path)
        } else {
            Err(std::io::Error::other(format!(
                "scratch root {} is not usable as a case-sensitive filesystem",
                self.path.display()
            )))
        }
    }
}

fn checked_scratch_root(path: PathBuf) -> ScratchRoot {
    let case_sensitive = std::fs::create_dir_all(&path).is_ok() && probe_case_sensitive(&path);
    ScratchRoot {
        path,
        case_sensitive,
    }
}

fn resolve_scratch_root(conventional: &Path) -> ScratchRoot {
    if let Some(home) = std::env::var_os("CARRICK_HOME").filter(|s| !s.is_empty()) {
        return checked_scratch_root(PathBuf::from(home).join("scratch"));
    }
    // Fast path: the conventional mount point of the carrick volume. Verify
    // it's actually case-sensitive (a Linux ABI requirement) so a coincidental
    // dir at that path on a case-insensitive boot volume can't be mistaken for
    // our volume.
    if probe_case_sensitive(conventional) {
        return ScratchRoot {
            path: conventional.to_owned(),
            case_sensitive: true,
        };
    }
    // No explicit home and no usable conventional mount: use the user's home.
    let home = std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".carrick"))
        .unwrap_or_else(|| PathBuf::from("/tmp/carrick"));
    checked_scratch_root(home.join("scratch"))
}

/// The default writable-layer backend when the user passes no `--fs`.
///
/// With the `fs-memory` feature enabled, prefer `Host` on case-sensitive
/// volumes (where Linux fs semantics survive) and fall back to the in-memory
/// backend on case-insensitive ones. Without the feature, always `Host` — the
/// in-memory backend is not selectable and is silently incoherent across guest
/// `fork` anyway (see the fs-memory design spec).
pub fn default_writable_backend_kind() -> carrick_spec::FsBackendKind {
    #[cfg(not(feature = "fs-memory"))]
    {
        carrick_spec::FsBackendKind::Host
    }
    #[cfg(feature = "fs-memory")]
    {
        if preferred_scratch_root().case_sensitive {
            carrick_spec::FsBackendKind::Host
        } else {
            carrick_spec::FsBackendKind::Memory
        }
    }
}

/// Probe with exclusive nonblocking creation. Existing files (including FIFOs,
/// devices and symlinks) are unusable and must never be opened or removed.
/// O_NONBLOCK prevents FIFO rendezvous; it does not bound filesystem device I/O.
/// Gate hosts must select an internal root with CARRICK_HOME to avoid USB stalls.
fn probe_case_sensitive(path: &Path) -> bool {
    // A private namespace prevents simultaneous startups from treating each
    // other's live sentinel as an unusable filesystem.
    let Ok(directory) = tempfile::Builder::new()
        .prefix(".carrick-case-")
        .tempdir_in(path)
    else {
        return false;
    };
    probe_case_sensitive_in(directory.path())
}

fn probe_case_sensitive_in(path: &Path) -> bool {
    use std::os::unix::fs::OpenOptionsExt;
    let lower = path.join(".carrick-case-probe");
    let upper = path.join(".CARRICK-case-probe");
    let Ok(file) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_EXCL)
        .open(&lower)
    else {
        return false;
    };
    let regular = file.metadata().is_ok_and(|metadata| metadata.is_file());
    let metadata_upper = std::fs::metadata(&upper);
    let _ = std::fs::remove_file(&lower);
    // On case-sensitive: upper doesn't exist → Err.
    // On case-insensitive: upper opens the same inode as lower → Ok.
    regular && matches!(metadata_upper, Err(error) if error.kind() == std::io::ErrorKind::NotFound)
}

#[cfg(test)]
mod fs_default_tests {
    use super::*;

    #[test]
    fn default_backend_is_host_without_feature() {
        // With the fs-memory feature off (the default build), the default
        // writable backend is always Host regardless of volume case-sensitivity.
        if cfg!(not(feature = "fs-memory")) {
            assert_eq!(
                default_writable_backend_kind(),
                carrick_spec::FsBackendKind::Host
            );
        }
    }
}

#[cfg(test)]
mod serial_host {
    use super::*;

    #[test]
    fn serial_host_scratch_root_override_wins() {
        let root = tempfile::tempdir().unwrap();
        let chosen = root.path().join("internal-scratch");
        let previous = std::env::var_os("CARRICK_HOME");
        // SAFETY: this test runs in the serial_host partition.
        unsafe { std::env::set_var("CARRICK_HOME", &chosen) };
        // The supplied conventional root is available. Even an otherwise
        // usable conventional mount must lose to the explicit override.
        let actual = resolve_scratch_root(root.path());
        unsafe {
            match previous {
                Some(value) => std::env::set_var("CARRICK_HOME", value),
                None => std::env::remove_var("CARRICK_HOME"),
            }
        }
        assert_eq!(actual.path(), chosen.join("scratch"));
        assert!(
            chosen.join("scratch").is_dir(),
            "override must be created and checked for case sensitivity"
        );
    }

    #[test]
    fn serial_host_case_probe_fifo_is_bounded() {
        use std::os::unix::fs::FileTypeExt;
        let root = tempfile::tempdir().unwrap();
        let fifo = root.path().join(".carrick-case-probe");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: name is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(!probe_case_sensitive_in(root.path()));
        assert!(
            std::fs::symlink_metadata(&fifo)
                .unwrap()
                .file_type()
                .is_fifo()
        );
    }

    #[test]
    fn unusable_override_refuses_host_backend() {
        let root = tempfile::tempdir().unwrap();
        let chosen = root.path().join("scratch");
        std::fs::write(&chosen, b"not a directory").unwrap();
        let previous = std::env::var_os("CARRICK_HOME");
        // SAFETY: environment changes run only in the serial_host partition.
        unsafe { std::env::set_var("CARRICK_HOME", root.path()) };
        let actual = resolve_scratch_root(root.path());
        unsafe {
            match previous {
                Some(value) => std::env::set_var("CARRICK_HOME", value),
                None => std::env::remove_var("CARRICK_HOME"),
            }
        }
        assert_eq!(actual.path(), chosen);
        assert!(actual.host_path().is_err());
        assert_eq!(std::fs::read(chosen).unwrap(), b"not a directory");
    }

    #[test]
    fn simultaneous_probes_have_private_namespaces() {
        let root = tempfile::tempdir().unwrap();
        // A sentinel from another run must not make this root unusable.
        std::fs::write(root.path().join(".carrick-case-probe"), b"owned by peer").unwrap();
        let expected = probe_case_sensitive(root.path());
        std::thread::scope(|scope| {
            let tasks: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| probe_case_sensitive(root.path())))
                .collect();
            for task in tasks {
                assert_eq!(task.join().unwrap(), expected);
            }
        });
        assert_eq!(
            std::fs::read(root.path().join(".carrick-case-probe")).unwrap(),
            b"owned by peer"
        );
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn probe_preserves_existing_regular_file() {
        let root = tempfile::tempdir().unwrap();
        let collision = root.path().join(".carrick-case-probe");
        std::fs::write(&collision, b"keep me").unwrap();
        assert!(!probe_case_sensitive_in(root.path()));
        assert_eq!(std::fs::read(collision).unwrap(), b"keep me");
    }

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
