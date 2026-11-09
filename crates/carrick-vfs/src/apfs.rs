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

/// No-progress wedge detector for the scratch worker. Not a load deadline
/// and not a total-time budget: the worker bumps a progress counter each
/// time it starts or finishes an item, and the verdict gives up only when
/// that counter has not moved for this long. The one thing that stops it
/// moving is a single item (in practice a hung volume syscall) that does
/// not return. Trade-off, stated plainly: a long item that is still making
/// no progress for this long IS treated as a wedge, even if it would have
/// finished later; queue delay behind many items that each finish is not.
#[cfg(any(target_os = "macos", test))]
const SCRATCH_WORKER_NO_PROGRESS_BOUND: std::time::Duration = std::time::Duration::from_secs(60);

/// Run one volume query on the scratch-storage worker (`fs_backend::host`,
/// thread `carrick-fs-cleanup`) and return whether the volume is usable.
/// A full queue is "not now" and is re-offered; a slow answer is waited for.
/// `false` because of the worker happens only when it is unavailable, its
/// reply sender is dropped, or its progress counter has not advanced for
/// `no_progress_bound` (each logged as an error). A query that itself
/// reports an error is a genuine "not usable".
#[cfg(any(target_os = "macos", test))]
fn scratch_volume_verdict(
    no_progress_bound: std::time::Duration,
    query: impl FnOnce() -> std::io::Result<bool> + Send + 'static,
) -> bool {
    scratch_volume_verdict_observed(no_progress_bound, query, || {}, &RealVerdictSource::new())
}

/// The two observations the no-progress decision is made from: a monotonic
/// reading and the worker's progress counter. Production reads the real
/// ones; tests inject a clock and counter they advance themselves, so the
/// decision never depends on how fast the host scheduled the test.
#[cfg(any(target_os = "macos", test))]
trait VerdictSource {
    /// Monotonic time since an arbitrary fixed origin.
    fn now(&self) -> std::time::Duration;
    /// Count of items the scratch worker has started or finished.
    fn progress(&self) -> u64;
}

#[cfg(any(target_os = "macos", test))]
struct RealVerdictSource(std::time::Instant);

#[cfg(any(target_os = "macos", test))]
impl RealVerdictSource {
    fn new() -> Self {
        Self(std::time::Instant::now())
    }
}

#[cfg(any(target_os = "macos", test))]
impl VerdictSource for RealVerdictSource {
    fn now(&self) -> std::time::Duration {
        self.0.elapsed()
    }

    fn progress(&self) -> u64 {
        crate::fs_backend::host::scratch_worker_progress()
    }
}

/// `scratch_volume_verdict` with `on_full` invoked each time the worker
/// queue is observed full, so tests can acknowledge the retry branch, and
/// with the elapsed-time and progress observations taken from `source`.
#[cfg(any(target_os = "macos", test))]
fn scratch_volume_verdict_observed(
    no_progress_bound: std::time::Duration,
    query: impl FnOnce() -> std::io::Result<bool> + Send + 'static,
    mut on_full: impl FnMut(),
    source: &impl VerdictSource,
) -> bool {
    use crate::fs_backend::host::{ScratchVolumeEnqueue, enqueue_scratch_volume_query};
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::Duration;
    let poll = (no_progress_bound / 4).clamp(Duration::from_millis(5), Duration::from_millis(250));
    let mut last_progress = source.progress();
    let mut last_change = source.now();
    let mut note_progress = || {
        let progress = source.progress();
        let now = source.now();
        if progress != last_progress {
            last_progress = progress;
            last_change = now;
        }
        now.saturating_sub(last_change) >= no_progress_bound
    };
    let mut query: crate::fs_backend::host::ScratchVolumeQuery = Box::new(query);
    let receiver = loop {
        let observed = crate::fs_backend::host::scratch_worker_progress();
        match enqueue_scratch_volume_query(query) {
            ScratchVolumeEnqueue::Queued(receiver) => break receiver,
            ScratchVolumeEnqueue::Full(returned) => {
                on_full();
                if note_progress() {
                    tracing::error!(
                        ?no_progress_bound,
                        "scratch worker made no progress with a full queue; skipping volume"
                    );
                    return false;
                }
                query = returned;
                // Block until the worker finishes or starts an item (a
                // slot may be free), bounded by `poll` so the injected
                // no-progress decision is re-evaluated.
                crate::fs_backend::host::wait_scratch_worker_progress_after(observed, poll);
            }
            ScratchVolumeEnqueue::Unavailable => {
                tracing::error!("scratch worker unavailable; skipping volume");
                return false;
            }
        }
    };
    loop {
        match receiver.recv_timeout(poll) {
            Ok(Ok(usable)) => return usable,
            Ok(Err(error)) => {
                tracing::warn!(%error, "skipping conventional scratch volume");
                return false;
            }
            Err(RecvTimeoutError::Timeout) => {
                if note_progress() {
                    tracing::error!(
                        ?no_progress_bound,
                        "scratch worker made no progress; skipping volume"
                    );
                    return false;
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                tracing::error!("scratch worker dropped the volume query; skipping volume");
                return false;
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn conventional_mount_usable(path: &Path) -> bool {
    let path = path.to_owned();
    scratch_volume_verdict(SCRATCH_WORKER_NO_PROGRESS_BOUND, move || {
        classify_conventional_mount(&path)
    })
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

    /// The query runs on the process-wide scratch worker, which parallel
    /// cleanup tests also occupy (some park it on barriers), so the exact
    /// deadline answer is witnessed serially.
    mod serial_host_scratch_worker {
        use super::*;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::time::Duration;

        #[test]
        fn volume_verdict_known_answers_and_wedge_is_only_timeout_refusal() {
            use std::sync::mpsc::sync_channel;
            use std::time::Duration;

            let bound = SCRATCH_WORKER_NO_PROGRESS_BOUND;
            assert!(scratch_volume_verdict(bound, || Ok(true)));
            assert!(!scratch_volume_verdict(bound, || Ok(false)));
            assert!(!scratch_volume_verdict(bound, || {
                Err(std::io::Error::other("device query failed"))
            }));
            // A wedged query (blocked past a tiny injected bound) is refused.
            let (release, blocked) = sync_channel::<()>(1);
            let (finished, completion) = sync_channel(1);
            let usable = scratch_volume_verdict(Duration::from_millis(50), move || {
                let _ = blocked.recv_timeout(Duration::from_secs(30));
                finished.send(()).unwrap();
                Ok(true)
            });
            assert!(!usable);
            let root = resolve_scratch_root_from(
                Path::new("/Volumes/carrick"),
                usable,
                |_| panic!("unknown volume must not be probed"),
                Some("/internal/home".into()),
                None,
            );
            assert_eq!(root, PathBuf::from("/internal/home/scratch"));
            release.send(()).unwrap();
            completion.recv_timeout(Duration::from_secs(30)).unwrap();
        }

        /// A slow answer (longer than the old 2 s deadline) is waited for.
        #[test]
        fn slow_volume_query_is_waited_for() {
            assert!(scratch_volume_verdict(
                SCRATCH_WORKER_NO_PROGRESS_BOUND,
                || {
                    std::thread::sleep(std::time::Duration::from_millis(2500));
                    Ok(true)
                }
            ));
        }

        /// A wait armed on an observation the worker has already moved past
        /// returns at once instead of parking. This covers the
        /// observed-before-enqueue ordering only; it does not exercise a
        /// notification (see `full_queue_wait_is_woken_by_worker_progress`).
        #[test]
        fn wait_returns_immediately_when_progress_already_advanced() {
            use crate::fs_backend::host::{
                ScratchVolumeEnqueue, enqueue_scratch_volume_query, scratch_worker_progress,
                wait_scratch_worker_progress_after,
            };
            use std::time::Duration;
            // Generous bound: only a lost wakeup reaches it.
            let bound = Duration::from_secs(60);
            let stale = scratch_worker_progress();
            let ScratchVolumeEnqueue::Queued(receiver) =
                enqueue_scratch_volume_query(Box::new(|| Ok(true)))
            else {
                panic!("idle worker queue must accept an item");
            };
            assert!(receiver.recv_timeout(bound).unwrap().unwrap());
            // The worker bumps progress after replying; the wait observes it.
            wait_scratch_worker_progress_after(stale, bound);
            assert_ne!(scratch_worker_progress(), stale);
        }

        /// Park the scratch worker on blocking items until its bounded
        /// queue is full. Returns one release handle and one reply receiver
        /// per item, in worker order.
        fn fill_worker_queue(
            item_timeout: std::time::Duration,
        ) -> (
            Vec<std::sync::mpsc::SyncSender<()>>,
            Vec<std::sync::mpsc::Receiver<std::io::Result<bool>>>,
        ) {
            use crate::fs_backend::host::{ScratchVolumeEnqueue, enqueue_scratch_volume_query};
            use std::sync::mpsc::sync_channel;
            let mut releases = Vec::new();
            let mut receivers = Vec::new();
            let (started, first_started) = sync_channel::<()>(1);
            loop {
                let (release, blocked) = sync_channel::<()>(1);
                let started = releases.is_empty().then(|| started.clone());
                let query: crate::fs_backend::host::ScratchVolumeQuery = Box::new(move || {
                    if let Some(started) = started {
                        let _ = started.try_send(());
                    }
                    let _ = blocked.recv_timeout(item_timeout);
                    Ok(false)
                });
                match enqueue_scratch_volume_query(query) {
                    ScratchVolumeEnqueue::Queued(receiver) => {
                        releases.push(release);
                        receivers.push(receiver);
                        assert!(releases.len() < 64, "queue never filled");
                        if releases.len() == 1 {
                            // Full only counts once the worker is parked in
                            // the first item; before that a slot frees up
                            // behind our back.
                            first_started
                                .recv_timeout(std::time::Duration::from_secs(60))
                                .expect("worker never started the first item");
                        }
                    }
                    ScratchVolumeEnqueue::Full(_) => return (releases, receivers),
                    ScratchVolumeEnqueue::Unavailable => panic!("worker unavailable"),
                }
            }
        }

        /// Busy once, then success: with the worker queue full the verdict
        /// waits and returns the real answer once the queue drains. The
        /// release happens only after the CALLER observed `Full`, so the
        /// retry branch is what produces the answer.
        #[test]
        fn full_queue_is_not_now() {
            use std::sync::mpsc::sync_channel;
            use std::time::Duration;

            let (releases, receivers) = fill_worker_queue(Duration::from_secs(60));
            let (full_seen, observed) = sync_channel::<()>(1);
            let (done, answer) = sync_channel(1);
            let caller = std::thread::spawn(move || {
                let verdict = scratch_volume_verdict_observed(
                    SCRATCH_WORKER_NO_PROGRESS_BOUND,
                    || Ok(true),
                    move || {
                        let _ = full_seen.try_send(());
                    },
                    &RealVerdictSource::new(),
                );
                done.send(verdict).unwrap();
            });
            observed
                .recv_timeout(Duration::from_secs(60))
                .expect("caller never observed a full queue");
            assert!(
                answer.try_recv().is_err(),
                "verdict before the queue drained"
            );
            drop(releases);
            assert!(answer.recv_timeout(Duration::from_secs(60)).unwrap());
            caller.join().unwrap();
            for receiver in receivers {
                receiver
                    .recv_timeout(Duration::from_secs(60))
                    .unwrap()
                    .unwrap();
            }
        }

        /// The full-queue wait is a notification, not a pacing delay. The
        /// no-progress bound is 60 s, so the retry poll clamps to 250 ms;
        /// with the queue full of gated items the caller parks, and the
        /// worker's progress notification alone must bring it back. The
        /// verdict is then complete well inside one poll period after the
        /// release. A worker that bumped progress without notifying would
        /// only be noticed at the 250 ms poll.
        #[test]
        fn full_queue_wait_is_woken_by_worker_progress() {
            use std::sync::mpsc::{SyncSender, sync_channel};

            /// Signals the first clock reading after the queue was observed
            /// full: the last thing the caller does before it parks.
            struct EnrolSource {
                real: RealVerdictSource,
                full: Arc<AtomicBool>,
                enrolled: SyncSender<()>,
            }
            impl VerdictSource for EnrolSource {
                fn now(&self) -> Duration {
                    if self.full.swap(false, Ordering::SeqCst) {
                        let _ = self.enrolled.try_send(());
                    }
                    self.real.now()
                }
                fn progress(&self) -> u64 {
                    self.real.progress()
                }
            }

            let guard = Duration::from_secs(60);
            let (mut releases, receivers) = fill_worker_queue(guard);
            let full = Arc::new(AtomicBool::new(false));
            let (enrolled, parked) = sync_channel::<()>(1);
            let source = EnrolSource {
                real: RealVerdictSource::new(),
                full: Arc::clone(&full),
                enrolled,
            };
            let (done, answer) = sync_channel(1);
            let caller = std::thread::spawn(move || {
                let verdict = scratch_volume_verdict_observed(
                    Duration::from_secs(60),
                    || Ok(true),
                    move || full.store(true, Ordering::SeqCst),
                    &source,
                );
                done.send(verdict).unwrap();
            });
            parked
                .recv_timeout(guard)
                .expect("caller never observed a full queue");
            let released = std::time::Instant::now();
            for release in releases.drain(..) {
                release.send(()).unwrap();
            }
            // The caller's own item queues behind the drained ones and is
            // answered at once; only a missed wake costs the 250 ms poll.
            let verdict = answer.recv_timeout(guard).expect("verdict never returned");
            let elapsed = released.elapsed();
            caller.join().unwrap();
            assert!(verdict);
            assert!(
                elapsed < Duration::from_millis(100),
                "verdict took {elapsed:?} after release: the parked caller was not woken by \
                 worker progress"
            );
            for receiver in receivers {
                receiver.recv_timeout(guard).unwrap().unwrap();
            }
        }

        /// Test-driven clock and progress counter. `now_calls` counts the
        /// caller's samples so the test can step in lockstep with them.
        #[derive(Clone, Default)]
        struct FakeSource {
            clock_ms: Arc<AtomicU64>,
            progress: Arc<AtomicU64>,
            now_calls: Arc<AtomicU64>,
            /// Virtual milliseconds added on every `now()` reading.
            auto_step_ms: u64,
        }

        impl VerdictSource for FakeSource {
            fn now(&self) -> Duration {
                self.now_calls.fetch_add(1, Ordering::SeqCst);
                let ms = self.clock_ms.fetch_add(self.auto_step_ms, Ordering::SeqCst);
                Duration::from_millis(ms)
            }

            fn progress(&self) -> u64 {
                self.progress.load(Ordering::SeqCst)
            }
        }

        /// Queue delay is not wedge time: the worker is occupied by nine
        /// items released one at a time. Virtual time advances 400 ms per
        /// step (bound 500 ms) and progress advances in every step, so the
        /// total is several bounds while no window is without progress. The
        /// test advances both and waits for two caller samples per step, so
        /// every step is observed; real time never enters the decision.
        #[test]
        fn queue_delay_does_not_consume_the_no_progress_budget() {
            use std::sync::mpsc::sync_channel;

            let bound = Duration::from_millis(500);
            let source = FakeSource::default();
            let (mut releases, receivers) = fill_worker_queue(Duration::from_secs(60));
            let (full_seen, observed) = sync_channel::<()>(1);
            let finished = Arc::new(AtomicBool::new(false));
            let caller_finished = Arc::clone(&finished);
            let caller_source = source.clone();
            let caller = std::thread::spawn(move || {
                let verdict = scratch_volume_verdict_observed(
                    bound,
                    || Ok(true),
                    move || {
                        let _ = full_seen.try_send(());
                    },
                    &caller_source,
                );
                caller_finished.store(true, Ordering::SeqCst);
                verdict
            });
            observed
                .recv_timeout(Duration::from_secs(60))
                .expect("caller never observed a full queue");
            let steps = releases.len();
            for release in releases.drain(..) {
                release.send(()).unwrap();
                source.progress.fetch_add(1, Ordering::SeqCst);
                source.clock_ms.fetch_add(400, Ordering::SeqCst);
                // The first sample after the step may have read the old
                // progress; the second began after it.
                let seen = source.now_calls.load(Ordering::SeqCst);
                let deadline = std::time::Instant::now() + Duration::from_secs(60);
                while source.now_calls.load(Ordering::SeqCst) < seen + 2
                    && !finished.load(Ordering::SeqCst)
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            assert!(
                source.clock_ms.load(Ordering::SeqCst) >= 400 * steps as u64,
                "virtual delay did not exceed the bound"
            );
            assert!(caller.join().unwrap(), "queue delay was read as a wedge");
            for receiver in receivers {
                receiver
                    .recv_timeout(Duration::from_secs(60))
                    .unwrap()
                    .unwrap();
            }
        }

        /// A first item that makes no progress at all is the one refusal.
        /// The virtual clock advances 100 ms per reading with a constant
        /// progress counter; the 300 ms bound is crossed by the clock alone.
        #[test]
        fn stuck_first_item_is_refused_without_progress() {
            use crate::fs_backend::host::{ScratchVolumeEnqueue, enqueue_scratch_volume_query};
            use std::sync::mpsc::sync_channel;

            let (release, blocked) = sync_channel::<()>(1);
            let query: crate::fs_backend::host::ScratchVolumeQuery = Box::new(move || {
                let _ = blocked.recv_timeout(Duration::from_secs(60));
                Ok(false)
            });
            let ScratchVolumeEnqueue::Queued(stuck) = enqueue_scratch_volume_query(query) else {
                panic!("scratch worker did not accept the stuck item");
            };
            let source = FakeSource {
                auto_step_ms: 100,
                ..FakeSource::default()
            };
            assert!(!scratch_volume_verdict_observed(
                Duration::from_millis(300),
                || Ok(true),
                || {},
                &source,
            ));
            release.send(()).unwrap();
            stuck
                .recv_timeout(Duration::from_secs(60))
                .unwrap()
                .unwrap();
            // The worker recovers and answers for real afterwards.
            assert!(scratch_volume_verdict(
                SCRATCH_WORKER_NO_PROGRESS_BOUND,
                || Ok(true)
            ));
        }
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
