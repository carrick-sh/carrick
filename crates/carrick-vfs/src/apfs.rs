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
/// conventional `/Volumes/carrick`. Classify that mount from cached mount
/// metadata and CoreFoundation's volume properties before touching it:
/// only local, internal, non-removable storage may be case-probed.
/// Device classification has a two-second caller deadline; unknown storage
/// falls through to the existing configured/home scratch root. The slow
/// `diskutil`-backed `find_carrick_volume` is reserved for the explicit
/// `carrick volume` subcommands, not this per-run path.
pub fn preferred_scratch_root() -> std::io::Result<PathBuf> {
    // Cached once per process; the scratch root cannot change while we run.
    static CACHE: ScratchRootCache = ScratchRootCache::new();
    Ok(CACHE.get_or_resolve(resolve_scratch_root))
}

/// The one per-process scratch-root cache. Production owns exactly one
/// (`preferred_scratch_root`'s static); tests construct their own so a
/// resolution, including a cached rejection, is observed in isolation.
struct ScratchRootCache {
    root: std::sync::OnceLock<PathBuf>,
}

impl ScratchRootCache {
    const fn new() -> Self {
        Self {
            root: std::sync::OnceLock::new(),
        }
    }

    /// The cached root, resolving it on first use only. A rejected
    /// conventional mount is cached as its fallback root, so later callers
    /// never classify or probe that candidate again.
    fn get_or_resolve(&self, resolve: impl FnOnce() -> PathBuf) -> PathBuf {
        self.root.get_or_init(resolve).clone()
    }
}

fn resolve_scratch_root() -> PathBuf {
    // Fast path: the conventional mount point of the carrick volume.
    let conventional = Path::new("/Volumes").join(DEFAULT_VOLUME_NAME);
    resolve_scratch_root_at(
        &conventional,
        std::env::var_os("CARRICK_HOME"),
        std::env::var_os("HOME"),
    )
}

/// Resolve the scratch root for one conventional candidate with the real
/// host classifier and case probe. The candidate is case-probed only after
/// the classifier admits it; then verify it's actually case-sensitive (a
/// Linux ABI requirement) so a coincidental dir at that path on a
/// case-insensitive boot volume can't be mistaken for our volume.
fn resolve_scratch_root_at(
    conventional: &Path,
    carrick_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> PathBuf {
    resolve_scratch_root_from(
        conventional,
        conventional_mount_usable(conventional),
        |path| path.is_dir() && probe_case_sensitive(path),
        carrick_home,
        home,
    )
}

fn conventional_volume_usable(local: bool, removable: bool, internal: bool) -> bool {
    local && !removable && internal
}

#[cfg(not(target_os = "macos"))]
fn conventional_mount_usable(_: &Path) -> bool {
    false
}

#[cfg(any(target_os = "macos", test))]
fn bounded_volume_query(
    deadline: std::time::Duration,
    query: impl FnOnce() -> std::io::Result<bool> + Send + 'static,
) -> std::io::Result<bool> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("scratch-volume-classifier".into())
        .spawn(move || {
            let _ = sender.send(query());
        })?;
    receiver.recv_timeout(deadline).map_err(|error| {
        std::io::Error::other(format!(
            "scratch volume classification did not complete: {error}"
        ))
    })?
}

#[cfg(target_os = "macos")]
fn conventional_mount_usable(path: &Path) -> bool {
    let path = path.to_owned();
    match bounded_volume_query(std::time::Duration::from_secs(2), move || {
        classify_conventional_mount(&path)
    }) {
        Ok(usable) => usable,
        Err(error) => {
            tracing::warn!(%error, "skipping conventional scratch volume");
            false
        }
    }
}

#[cfg(target_os = "macos")]
fn classify_conventional_mount(path: &Path) -> std::io::Result<bool> {
    use core_foundation_sys::{
        array::{CFArrayCreate, kCFTypeArrayCallBacks},
        base::{CFIndex, CFRelease},
        dictionary::CFDictionaryGetValue,
        number::{kCFBooleanFalse, kCFBooleanTrue},
        url::{
            CFURLCopyResourcePropertiesForKeys, CFURLCreateFromFileSystemRepresentation,
            kCFURLVolumeIsInternalKey, kCFURLVolumeIsRemovableKey,
        },
    };
    // NOWAIT reads cached mount records without asking any filesystem to
    // refresh its statistics. Do not replace this with statfs(path).
    // SAFETY: a null buffer with zero size requests only the mount count.
    let count = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
    if count < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let count = usize::try_from(count).map_err(std::io::Error::other)?;
    let size = count
        .checked_mul(std::mem::size_of::<libc::statfs>())
        .and_then(|size| libc::c_int::try_from(size).ok())
        .ok_or_else(|| std::io::Error::other("mount table is too large"))?;
    if count == 0 {
        return Ok(false);
    }
    let mut mounts = vec![std::mem::MaybeUninit::<libc::statfs>::uninit(); count];
    // SAFETY: size describes the allocated buffer. Only returned entries are
    // read; a concurrent mount addition can at worst omit our candidate.
    let filled = unsafe { libc::getfsstat(mounts.as_mut_ptr().cast(), size, libc::MNT_NOWAIT) };
    if filled < 0 {
        return Err(std::io::Error::last_os_error());
    }
    for mount in mounts.iter().take((filled as usize).min(count)) {
        // SAFETY: getfsstat initialized each of the returned records.
        let mount = unsafe { mount.assume_init_ref() };
        // SAFETY: the kernel's fixed-size mount names are NUL terminated.
        let mounted_at = unsafe { std::ffi::CStr::from_ptr(mount.f_mntonname.as_ptr()) };
        if mounted_at.to_bytes() != path.as_os_str().as_encoded_bytes() {
            continue;
        }
        if mount.f_flags & libc::MNT_LOCAL as u32 == 0 {
            return Ok(false);
        }
        // Internal excludes external fixed USB disks too, unlike MNT_LOCAL.
        // Query volume metadata only; never create or open a probe file here.
        // SAFETY: Create/Copy objects are checked and released; dictionary
        // values are borrowed only while their dictionary lives.
        return unsafe {
            let bytes = path.as_os_str().as_encoded_bytes();
            let url = CFURLCreateFromFileSystemRepresentation(
                std::ptr::null(),
                bytes.as_ptr(),
                bytes.len() as CFIndex,
                1,
            );
            if url.is_null() {
                return Err(std::io::Error::other("volume URL unavailable"));
            }
            let keys = [
                kCFURLVolumeIsInternalKey.cast(),
                kCFURLVolumeIsRemovableKey.cast(),
            ];
            let array = CFArrayCreate(std::ptr::null(), keys.as_ptr(), 2, &kCFTypeArrayCallBacks);
            if array.is_null() {
                CFRelease(url.cast());
                return Err(std::io::Error::other("volume property keys unavailable"));
            }
            let properties = CFURLCopyResourcePropertiesForKeys(url, array, std::ptr::null_mut());
            let usable = if properties.is_null() {
                Err(std::io::Error::other("volume properties unavailable"))
            } else {
                let internal = CFDictionaryGetValue(properties, kCFURLVolumeIsInternalKey.cast());
                let removable = CFDictionaryGetValue(properties, kCFURLVolumeIsRemovableKey.cast());
                let usable = if internal.is_null() || removable.is_null() {
                    Err(std::io::Error::other(
                        "volume device properties unavailable",
                    ))
                } else {
                    Ok(conventional_volume_usable(
                        true,
                        removable != kCFBooleanFalse.cast(),
                        internal == kCFBooleanTrue.cast(),
                    ))
                };
                CFRelease(properties.cast());
                usable
            };
            CFRelease(array.cast());
            CFRelease(url.cast());
            usable
        };
    }
    Ok(false)
}

fn resolve_scratch_root_from(
    conventional: &Path,
    classified_usable: bool,
    probe: impl FnOnce(&Path) -> bool,
    carrick_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> PathBuf {
    if classified_usable && probe(conventional) {
        return conventional.to_path_buf();
    }
    // Fallback: honour the user's $CARRICK_HOME, else $HOME/.carrick. (No
    // diskutil: a host without the conventional mount almost certainly has no
    // carrick volume, and an exotic mount can be pointed at via $CARRICK_HOME.)
    let home = carrick_home
        .map(PathBuf::from)
        .or_else(|| {
            home.map(|h| {
                let mut p = PathBuf::from(h);
                p.push(".carrick");
                p
            })
        })
        .unwrap_or_else(|| PathBuf::from("/tmp/carrick"));
    home.join("scratch")
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
        let probe = preferred_scratch_root()
            .unwrap_or_else(|_| std::env::temp_dir().join("carrick-scratch"));
        if std::fs::create_dir_all(&probe).is_err() {
            return carrick_spec::FsBackendKind::Memory;
        }
        if probe_case_sensitive(&probe) {
            carrick_spec::FsBackendKind::Host
        } else {
            tracing::warn!(
                "carrick: {} is case-insensitive; defaulting --fs to memory. \
                 Pass `--fs host` to force the cap-std backend (some Linux tools may misbehave).",
                probe.display()
            );
            carrick_spec::FsBackendKind::Memory
        }
    }
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
mod tests {
    use super::*;

    #[test]
    fn conventional_volume_classifier_rejects_unsafe_media() {
        assert!(conventional_volume_usable(true, false, true));
        assert!(!conventional_volume_usable(true, true, true));
        assert!(!conventional_volume_usable(false, false, true));
        assert!(!conventional_volume_usable(true, false, false));
        assert!(!conventional_volume_usable(true, true, false));
    }

    #[test]
    fn conventional_volume_rejected_without_probing() {
        for (local, removable, internal) in [
            (true, true, true),
            (false, false, true),
            (true, false, false),
            (true, true, false),
        ] {
            let usable = conventional_volume_usable(local, removable, internal);
            let root = resolve_scratch_root_from(
                Path::new("/Volumes/carrick"),
                usable,
                |_| panic!("rejected volume must not be probed"),
                Some("/internal/carrick-home".into()),
                Some("/Users/u".into()),
            );
            assert_eq!(root, PathBuf::from("/internal/carrick-home/scratch"));
            let root = resolve_scratch_root_from(
                Path::new("/Volumes/carrick"),
                usable,
                |_| panic!("rejected volume must not be probed"),
                None,
                Some("/Users/u".into()),
            );
            assert_eq!(root, PathBuf::from("/Users/u/.carrick/scratch"));
        }
    }

    #[test]
    fn conventional_volume_internal_keeps_existing_precedence() {
        let conventional = Path::new("/Volumes/carrick");
        let usable = conventional_volume_usable(true, false, true);
        let mut probes = 0;
        let root = resolve_scratch_root_from(
            conventional,
            usable,
            |path| {
                assert_eq!(path, conventional);
                probes += 1;
                true
            },
            Some("/internal/carrick-home".into()),
            None,
        );
        assert_eq!(probes, 1);
        assert_eq!(root, conventional);
        let root = resolve_scratch_root_from(conventional, usable, |_| false, None, None);
        assert_eq!(root, PathBuf::from("/tmp/carrick/scratch"));
    }

    #[test]
    fn conventional_volume_query_known_answer_and_deadline() {
        use std::sync::mpsc::sync_channel;
        use std::time::Duration;

        assert!(bounded_volume_query(Duration::from_secs(5), || Ok(true)).unwrap());
        assert!(
            bounded_volume_query(Duration::from_secs(5), || {
                Err(std::io::Error::other("device query failed"))
            })
            .is_err()
        );
        let (release, blocked) = sync_channel(1);
        let (finished, completion) = sync_channel(1);
        let result = bounded_volume_query(Duration::from_millis(20), move || {
            blocked.recv_timeout(Duration::from_secs(5)).unwrap();
            finished.send(()).unwrap();
            Ok(true)
        });
        assert!(result.is_err());
        let root = resolve_scratch_root_from(
            Path::new("/Volumes/carrick"),
            result.unwrap_or(false),
            |_| panic!("unknown volume must not be probed"),
            Some("/internal/home".into()),
            None,
        );
        assert_eq!(root, PathBuf::from("/internal/home/scratch"));
        release.send(()).unwrap();
        completion.recv_timeout(Duration::from_secs(5)).unwrap();
    }

    /// Plant a file where `probe_case_sensitive` writes its sentinel. The
    /// probe truncates and then unlinks that name, so the planted file
    /// survives exactly when no case probe touched `dir`.
    fn plant_probe_witness(dir: &Path) -> PathBuf {
        let witness = dir.join(".carrick-case-probe");
        std::fs::write(&witness, b"untouched").unwrap();
        witness
    }

    fn assert_never_probed(witness: &Path) {
        assert_eq!(
            std::fs::read(witness).ok().as_deref(),
            Some(&b"untouched"[..]),
            "rejected candidate {} was case-probed",
            witness.display()
        );
    }

    /// Resolve `candidate` through the production cache type twice, the
    /// second time with a different `CARRICK_HOME`: a live cache returns the
    /// first fallback and never runs the second resolution.
    fn assert_cached_rejection(candidate: &Path) {
        let cache = ScratchRootCache::new();
        let resolutions = std::cell::Cell::new(0);
        let resolve = |home: &str| {
            resolutions.set(resolutions.get() + 1);
            resolve_scratch_root_at(candidate, Some(home.into()), None)
        };
        let first = cache.get_or_resolve(|| resolve("/internal/first"));
        let second = cache.get_or_resolve(|| resolve("/internal/second"));
        assert_eq!(first, PathBuf::from("/internal/first/scratch"));
        assert_eq!(second, first);
        assert_eq!(resolutions.get(), 1);
    }

    #[test]
    fn probe_witness_detects_a_case_probe() {
        let dir = tempfile::tempdir().unwrap();
        let witness = plant_probe_witness(dir.path());
        let _ = probe_case_sensitive(dir.path());
        assert!(!witness.exists(), "case probe must consume the witness");
    }

    #[test]
    fn resolution_rejects_unmounted_candidate_without_probing() {
        let dir = tempfile::tempdir().unwrap();
        let candidate = dir.path().canonicalize().unwrap();
        let witness = plant_probe_witness(&candidate);
        let root = resolve_scratch_root_at(
            &candidate,
            Some("/internal/carrick-home".into()),
            Some("/Users/u".into()),
        );
        assert_eq!(root, PathBuf::from("/internal/carrick-home/scratch"));
        let root = resolve_scratch_root_at(&candidate, None, Some("/Users/u".into()));
        assert_eq!(root, PathBuf::from("/Users/u/.carrick/scratch"));
        assert_cached_rejection(&candidate);
        assert_never_probed(&witness);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_classifier_admits_internal_local_volumes() {
        // The boot volume and its data volume are internal, fixed and
        // local on every Mac; both have exact mount records.
        for mount in ["/", "/System/Volumes/Data"] {
            let mount = Path::new(mount);
            assert!(classify_conventional_mount(mount).unwrap(), "{mount:?}");
            assert!(conventional_mount_usable(mount), "{mount:?}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_classifier_rejects_paths_without_exact_mount_record() {
        let dir = tempfile::tempdir().unwrap();
        let unmounted = dir.path().canonicalize().unwrap();
        let checkout = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for path in [
            unmounted.as_path(),
            checkout.as_path(),
            // Prefix, trailing-slash and doubled-slash aliases of real mounts.
            Path::new("/System/Volumes/Dat"),
            Path::new("/System/Volumes/Data/"),
            Path::new("//"),
            // A directory nested inside a mount is not that mount.
            Path::new("/System/Volumes/Data/private"),
            Path::new("/Volumes/definitely-not-mounted-xyz"),
        ] {
            assert!(!classify_conventional_mount(path).unwrap(), "{path:?}");
            assert!(!conventional_mount_usable(path), "{path:?}");
        }
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

    /// Host-mutating witnesses: they spawn `hdiutil` and mount a disk image.
    #[cfg(target_os = "macos")]
    mod serial_host {
        use super::*;
        use std::process::Command;
        use std::time::Duration;

        /// Run a bounded host command; a hang fails the test instead of
        /// wedging the lane.
        fn run(command: &mut Command) {
            let rendered = format!("{command:?}");
            let child = command
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            let pid = child.id();
            std::thread::spawn(move || {
                let _ = sender.send(child.wait_with_output());
            });
            let output = match receiver.recv_timeout(Duration::from_secs(60)) {
                Ok(output) => output.unwrap(),
                Err(error) => {
                    // SAFETY: plain kill(2) of the child this test spawned.
                    unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                    panic!("{rendered} did not finish: {error}");
                }
            };
            assert!(
                output.status.success(),
                "{rendered} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        /// A case-sensitive APFS disk image attached at a private mount
        /// point. `diskutil info` reports attached images as "Device
        /// Location: External", "Removable Media: Removable". It stands in
        /// for non-internal media; it is not the fixed external USB disk
        /// that wedged cloudmac. Detached on drop.
        struct AttachedImage {
            mountpoint: PathBuf,
            _dir: tempfile::TempDir,
        }

        impl AttachedImage {
            fn attach() -> Self {
                let dir = tempfile::tempdir().unwrap();
                let image = dir.path().join("carricktestext.dmg");
                let mountpoint = dir.path().join("mnt");
                std::fs::create_dir(&mountpoint).unwrap();
                run(Command::new("hdiutil")
                    .args(["create", "-quiet", "-size", "20m", "-fs"])
                    .arg("Case-sensitive APFS")
                    .args(["-volname", "carricktestext"])
                    .arg(&image));
                run(Command::new("hdiutil")
                    .args(["attach", "-quiet", "-nobrowse", "-noautoopen"])
                    .arg("-mountpoint")
                    .arg(&mountpoint)
                    .arg(&image));
                // getfsstat records the resolved mount path (/private/var/...).
                let mountpoint = mountpoint.canonicalize().unwrap();
                Self {
                    mountpoint,
                    _dir: dir,
                }
            }
        }

        impl Drop for AttachedImage {
            fn drop(&mut self) {
                let _ = Command::new("hdiutil")
                    .args(["detach", "-quiet", "-force"])
                    .arg(&self.mountpoint)
                    .status();
            }
        }

        #[test]
        fn external_disk_image_is_rejected_without_probing() {
            let image = AttachedImage::attach();
            let mount = image.mountpoint.as_path();
            // Control: the image is a mounted, writable, case-sensitive
            // volume, so the case probe alone would admit it.
            assert!(probe_case_sensitive(mount));
            // CoreFoundation reports an attached image as removable and
            // gives it no internal-bus value at all (`volumeIsInternal` is
            // nil, checked with Foundation on macOS 27); the classifier must
            // refuse it either way, never admit it.
            let verdict = classify_conventional_mount(mount);
            assert!(!matches!(verdict, Ok(true)), "{verdict:?}");
            assert!(!conventional_mount_usable(mount));
            let nested = mount.join("nested");
            std::fs::create_dir(&nested).unwrap();
            assert!(!classify_conventional_mount(&nested).unwrap());

            let witness = plant_probe_witness(mount);
            let root = resolve_scratch_root_at(
                mount,
                Some("/internal/carrick-home".into()),
                Some("/Users/u".into()),
            );
            assert_eq!(root, PathBuf::from("/internal/carrick-home/scratch"));
            let root = resolve_scratch_root_at(mount, None, Some("/Users/u".into()));
            assert_eq!(root, PathBuf::from("/Users/u/.carrick/scratch"));
            assert_cached_rejection(mount);
            assert_never_probed(&witness);
        }
    }
}
