//! Per-host persistent store for portable native AArch64 translations.
//!
//! # The store
//!
//! Units live in one translator-ABI-versioned host directory that outlives
//! every container. A valid unit may be sparse: an attached process that
//! reaches an uncovered block can win a nonblocking builder lease and merge
//! its canonical artifact into the existing set. Sequential publishers
//! reload under the per-unit lock, so pathname content grows monotonically
//! unless a byte-level conflict or a capacity/preflight gate preserves the
//! old inode. A size-capped LRU prune runs once per container begin.
//!
//! # The transport
//!
//! A published unit is one `{stem}.unit-v1` inode containing a fixed bundle
//! header, V6 block index/metadata, and digest-bound translated code. Loading
//! opens it with `O_NOFOLLOW`, validates a regular exact extent, and maps the
//! whole inode `MAP_PRIVATE|PROT_READ`. Metadata stays lazy and `source_base`
//! points at the code offset inside that same mapping; the translator replays
//! selected blocks into its existing per-process `MAP_JIT` cache.
//!
//! # Why not a signed dylib (the previous transport)
//!
//! Units used to be emitted as ad-hoc-signed Mach-O dylibs and loaded with
//! `dlopen` — chosen because a file-backed executable mapping is free at
//! `fork(2)` while `MAP_JIT` VA range is not (MEASURED: +567 us fork p50 per
//! 64 MiB of `MAP_JIT`), and AMFI refuses `mmap(PROT_EXEC)` of unsigned
//! files. But the LOAD cost the dylib transport what the fork path saved,
//! many times over: 14.76 ms median per process for a ~6 MiB unit (~400
//! MB/s — page-fault plus code-signature validation, not dyld CPU;
//! `docs/perf-results/2026-08-02-exec-cost-decomposed.jsonl`), paid by
//! every one of a build's ~61 exec'd processes, plus two `/usr/bin/codesign`
//! process spawns per publication. The copy transport adds NO `MAP_JIT`
//! range (the per-process translation cache is already mapped at fixed
//! capacity; copied units consume its cursor exactly like privately
//! translated code), needs no signature (nothing maps the file executable),
//! and loads at memcpy-plus-digest speed.
//!
//! # Crash safety
//!
//! A complete deterministic union is written to a mode-0600 same-directory
//! temporary, fsync'd, deep-preflighted through the production reader, and
//! atomically renamed over the final path before the directory is fsync'd.
//! Old readers pin the old inode; new readers observe either the complete old
//! or complete new union. Directory-sync failure is reported without rolling
//! back already-visible content.

use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use carrick_dsr_aarch64::pending_augmentation::RecordingOwner;
use carrick_dsr_aarch64::shared_cache::{
    ClaimOutcome, DecodedUnitBundle, MergeKind, MergeOutcome, MergeRefusal, PendingTranslationUnit,
    RecordingClaim, SourceFingerprint, TranslationMetadataLoadEvidence, TranslationUnitKey,
    TranslationUnitManifest, UnitMissReason, UnitStoreFailure, UnitStoreFailureClass,
    decode_unit_bundle_v1, encode_unit_bundle_v1, merge_normalized_artifacts,
    shared_source_fingerprint_reuse_enabled,
};

const AUTHORITY_MARKER: &str = ".carrick-authority";

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    Winner,
    Existing,
    Yielded,
}
const AUTHORITY_NONCE_LEN: usize = 16;
const MAX_MAPPED_UNIT_BUNDLE_BYTES: u64 = (104 + 7 + 64 * 1024 * 1024 + 256 * 1024 * 1024) as u64;
const UNIT_V1_SUFFIX: &str = ".unit-v1";
const BUILDER_MAGIC_V1: [u8; 8] = *b"CXBLDR1\0";
const BUILDER_SCHEMA_V1: u32 = 1;
const BUILDER_RECORD_BYTES_V1: usize = 112;
const UNIT_STEM_BYTES: usize = 64;
/// A recording claim older than this is stale even if its pid looks alive:
/// pids recycle across the runs a persistent store outlives, and no
/// legitimate recorder runs this long before publishing at exit or exec.
const BUILDER_CLAIM_TTL: std::time::Duration = std::time::Duration::from_secs(10 * 60);
/// Total current-ABI `.unit-v1` bytes the store may retain; beyond it the
/// oldest inodes (by modification time, refreshed on load) are
/// evicted at container begin. A whole go toolchain's units measure in tens
/// of MiB, so this cap is generous without being unbounded.
const STORE_SIZE_CAP_BYTES: u64 = 1024 * 1024 * 1024;
/// Auxiliary election/lock files (`.builder`, `.lock`, the retired `.seen`)
/// older than this are crash leftovers.
const AUX_FILE_TTL: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 60 * 60);
/// Unrenamed publication temporaries older than this are crash leftovers.
const TEMP_FILE_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// Where the persistent unit store lives: `$CARRICK_DSR_STORE_DIR` when set
/// (tests, bisection), else the carrick home convention shared with the
/// image store (`$CARRICK_HOME`, else `~/.carrick`, else `./.carrick` —
/// `carrick_image::ImageStore::default_for_user`), under a translator-ABI
/// versioned subdirectory so an ABI bump starts a fresh population and the
/// old one ages out by the size cap.
fn persistent_store_root() -> PathBuf {
    if let Some(root) = std::env::var_os("CARRICK_DSR_STORE_DIR") {
        return PathBuf::from(root);
    }
    let home = std::env::var_os("CARRICK_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".carrick")))
        .unwrap_or_else(|| PathBuf::from(".carrick"));
    home.join("native-units").join(format!(
        "abi-{}",
        carrick_dsr_aarch64::shared_cache::TRANSLATOR_ABI_CURRENT
    ))
}

/// Read the store's authority nonce, publishing a fresh one exactly once
/// per store lifetime. Publication uses `link(2)` (never-replace), so two
/// concurrent first runs converge on one winner and the loser reads the
/// winner's nonce — a rename here would silently replace the marker and
/// strand the first creator's descendants on adoption.
fn read_or_publish_marker(
    directory: &File,
    path: &Path,
) -> std::io::Result<[u8; AUTHORITY_NONCE_LEN]> {
    let marker_name = CString::new(AUTHORITY_MARKER)
        .map_err(|_| invalid_data("cache authority marker contains NUL"))?;
    for _ in 0..8 {
        let marker_fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                marker_name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if marker_fd >= 0 {
            let mut marker = unsafe { File::from_raw_fd(marker_fd) };
            let mut authority_nonce = [0_u8; AUTHORITY_NONCE_LEN];
            marker.read_exact(&mut authority_nonce)?;
            let mut trailing = [0_u8; 1];
            if marker.read(&mut trailing)? != 0 {
                return Err(invalid_data("cache authority marker is malformed"));
            }
            return Ok(authority_nonce);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOENT) {
            return Err(error);
        }
        let mut authority_nonce = [0_u8; AUTHORITY_NONCE_LEN];
        getrandom::fill(&mut authority_nonce)
            .map_err(|error| invalid_data(format!("generate cache authority nonce: {error}")))?;
        let mut temporary = tempfile::NamedTempFile::new_in(path)?;
        temporary.write_all(&authority_nonce)?;
        temporary.as_file().sync_all()?;
        let temporary_path = CString::new(temporary.path().as_os_str().as_bytes())
            .map_err(|_| invalid_data("marker temporary path contains NUL"))?;
        let marker_path = CString::new(path.join(AUTHORITY_MARKER).as_os_str().as_bytes())
            .map_err(|_| invalid_data("marker path contains NUL"))?;
        let linked = unsafe { libc::link(temporary_path.as_ptr(), marker_path.as_ptr()) };
        if linked == 0 {
            return Ok(authority_nonce);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(error);
        }
        // Lost the publish race: loop around and read the winner's nonce.
    }
    Err(invalid_data("cache authority marker kept vanishing"))
}

/// One current-ABI atomic unit as the pruner sees it.
struct StoredUnit {
    stem: String,
    bytes: u64,
    modified: std::time::SystemTime,
}

fn current_unit_stem(name: &str) -> Option<&str> {
    let stem = name.strip_suffix(UNIT_V1_SUFFIX)?;
    is_unit_stem(stem).then_some(stem)
}

fn is_unit_stem(stem: &str) -> bool {
    stem.len() == UNIT_STEM_BYTES
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Bound the current ABI store: remove aged temporaries/auxiliary files and
/// evict the oldest complete `.unit-v1` inodes until their total bytes fit.
/// Retired suffixes are outside this ABI directory's accounting and are
/// ignored rather than reinterpreted as current content.
/// Best-effort by design — every removal races benignly with concurrent
/// runs (loads pin inodes; a vanished unit is an ordinary miss), so errors
/// are swallowed rather than failing the container.
fn prune_store(directory: &File, path: &Path, cap_bytes: u64) {
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    let mut units = Vec::new();
    let mut total_bytes = 0_u64;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name == AUTHORITY_MARKER {
            continue;
        }
        let Ok(identity) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        let age = identity
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .unwrap_or_default();
        if let Some(stem) = current_unit_stem(name) {
            if identity.file_type().is_file() {
                total_bytes = total_bytes.saturating_add(identity.len());
                units.push(StoredUnit {
                    stem: stem.to_owned(),
                    bytes: identity.len(),
                    modified: identity.modified().unwrap_or(std::time::UNIX_EPOCH),
                });
            }
        } else if name.ends_with(".code")
            || name.ends_with(".metadata-v5")
            || name.ends_with(".metadata-v3")
            || name.ends_with(".seen")
        {
            // Retired formats are deliberately not current-ABI content.
        } else if name.ends_with(".builder") || name.ends_with(".lock") {
            if age > AUX_FILE_TTL {
                let _ = std::fs::remove_file(entry.path());
            }
        } else if age > TEMP_FILE_TTL {
            // Publication temporaries carry tempfile's random names; anything
            // unrecognized and this old is a crash leftover.
            let _ = std::fs::remove_file(entry.path());
        }
    }
    if total_bytes <= cap_bytes {
        return;
    }
    units.sort_by_key(|unit| unit.modified);
    for unit in units {
        if total_bytes <= cap_bytes {
            break;
        }
        // Evict under the unit lock so a concurrent publisher or claimant of
        // this stem is not raced; busy means in use — skip it this round.
        let Some(lock) = try_lock_stem_for_prune(directory, path, &unit.stem) else {
            continue;
        };
        let _ = std::fs::remove_file(path.join(format!("{}{}", unit.stem, UNIT_V1_SUFFIX)));
        let _ = std::fs::remove_file(path.join(format!("{}.builder", unit.stem)));
        drop(lock);
        let _ = std::fs::remove_file(path.join(format!("{}.lock", unit.stem)));
        total_bytes = total_bytes.saturating_sub(unit.bytes);
    }
}

fn try_lock_stem_for_prune(_directory: &File, path: &Path, stem: &str) -> Option<UnitFileLock> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path.join(format!("{stem}.lock")))
        .ok()?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return None;
    }
    Some(UnitFileLock(lock))
}

static CONTAINER_CACHE: Mutex<Option<ContainerCacheAuthority>> = Mutex::new(None);

#[cfg(test)]
thread_local! {
    static AFTER_BOUNDED_UNIT_OPEN_FOR_TEST: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static PUBLICATION_FAULT_FOR_TEST: std::cell::Cell<Option<PublicationFault>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationFault {
    BeforeTempSync,
    BeforePreflight,
    BeforeRename,
    DirectorySync,
}

#[cfg(test)]
fn arm_publication_fault(fault: PublicationFault) {
    PUBLICATION_FAULT_FOR_TEST.with(|armed| {
        assert!(armed.replace(Some(fault)).is_none(), "fault already armed");
    });
}

#[cfg(test)]
fn take_publication_fault(fault: PublicationFault) -> bool {
    PUBLICATION_FAULT_FOR_TEST.with(|armed| {
        if armed.get() == Some(fault) {
            armed.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
fn arm_after_bounded_unit_open_for_test(hook: impl FnOnce() + 'static) {
    AFTER_BOUNDED_UNIT_OPEN_FOR_TEST.with(|armed| {
        assert!(
            armed.borrow_mut().replace(Box::new(hook)).is_none(),
            "bounded metadata-open hook was already armed"
        );
    });
}

#[cfg(test)]
fn run_after_bounded_unit_open_for_test() {
    AFTER_BOUNDED_UNIT_OPEN_FOR_TEST.with(|armed| {
        if let Some(hook) = armed.borrow_mut().take() {
            hook();
        }
    });
}

#[derive(Debug)]
pub struct UnitStoreError {
    operation: &'static str,
    class: UnitStoreFailureClass,
    reason: UnitMissReason,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl UnitStoreError {
    fn new(operation: &'static str, reason: UnitMissReason) -> Self {
        Self {
            operation,
            class: UnitStoreFailureClass::Validation,
            reason,
            source: None,
        }
    }

    fn with_source(
        operation: &'static str,
        reason: UnitMissReason,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            operation,
            class: UnitStoreFailureClass::Validation,
            reason,
            source: Some(Box::new(source)),
        }
    }

    fn io_with_source(
        operation: &'static str,
        reason: UnitMissReason,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            operation,
            class: UnitStoreFailureClass::Io,
            reason,
            source: Some(Box::new(source)),
        }
    }

    const fn failure(&self) -> UnitStoreFailure {
        UnitStoreFailure {
            class: self.class,
            reason: self.reason,
        }
    }

    pub const fn reason(&self) -> UnitMissReason {
        self.reason
    }
}

impl std::fmt::Display for UnitStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}: translation unit miss ({:?})",
            self.operation, self.reason
        )?;
        if let Some(source) = &self.source {
            write!(formatter, ": {source}")?;
        }
        Ok(())
    }
}

impl std::error::Error for UnitStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

#[derive(Debug)]
pub struct LoadedTranslationUnit {
    // Fields drop in declaration order. Release the whole-bundle mapping
    // last, after neither metadata nor code can reference it.
    lease: Arc<UnitBundleLease>,
    pub manifest: Arc<TranslationUnitManifest>,
    /// Readable source bytes for the translator's per-block replay. Nothing
    /// executes here — see `SharedLoadedTranslationUnit::source_base`.
    pub source_base: std::ptr::NonNull<u8>,
    pub load_evidence: TranslationMetadataLoadEvidence,
}

impl LoadedTranslationUnit {
    fn into_shared(self) -> carrick_dsr_aarch64::shared_cache::SharedLoadedTranslationUnit {
        let source_base = self.source_base.as_ptr() as usize;
        carrick_dsr_aarch64::shared_cache::SharedLoadedTranslationUnit::new_with_evidence(
            self.manifest,
            source_base,
            self.load_evidence,
            self.lease,
        )
    }
}

/// Pins one loaded unit's backing: one read-only private `.unit-v1` mapping
/// and the inode under it. Publication never writes in place; replacement is
/// a whole-inode rename, so an old reader remains valid across augmentation.
#[derive(Debug)]
struct UnitBundleLease {
    _mapping: memmap2::Mmap,
    _file: File,
}

impl AsRef<[u8]> for UnitBundleLease {
    fn as_ref(&self) -> &[u8] {
        &self._mapping
    }
}

// SAFETY: `source_base` addresses the immutable read-only mapping owned by
// `lease`. The manifest is immutable.
unsafe impl Send for LoadedTranslationUnit {}
// SAFETY: see `Send`.
unsafe impl Sync for LoadedTranslationUnit {}

struct UnitFileLock(File);

impl Drop for UnitFileLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BuilderRecord {
    owner: RecordingOwner,
    created_unix_ns: i64,
    stem: String,
}

enum BuilderState {
    Absent,
    Malformed,
    Valid(BuilderRecord),
}

fn encode_builder_record(record: &BuilderRecord) -> Result<[u8; BUILDER_RECORD_BYTES_V1], ()> {
    if !is_unit_stem(&record.stem) {
        return Err(());
    }
    let mut bytes = [0_u8; BUILDER_RECORD_BYTES_V1];
    bytes[0..8].copy_from_slice(&BUILDER_MAGIC_V1);
    bytes[8..12].copy_from_slice(&BUILDER_SCHEMA_V1.to_le_bytes());
    bytes[12..16].copy_from_slice(&(BUILDER_RECORD_BYTES_V1 as u32).to_le_bytes());
    bytes[16..20].copy_from_slice(&record.owner.pid.to_le_bytes());
    bytes[24..40].copy_from_slice(&record.owner.incarnation);
    bytes[40..48].copy_from_slice(&record.created_unix_ns.to_le_bytes());
    bytes[48..].copy_from_slice(record.stem.as_bytes());
    Ok(bytes)
}

fn decode_builder_record(bytes: &[u8], expected_stem: &str) -> Option<BuilderRecord> {
    if bytes.len() != BUILDER_RECORD_BYTES_V1
        || bytes.get(0..8) != Some(&BUILDER_MAGIC_V1)
        || u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?) != BUILDER_SCHEMA_V1
        || u32::from_le_bytes(bytes.get(12..16)?.try_into().ok()?) as usize
            != BUILDER_RECORD_BYTES_V1
        || u32::from_le_bytes(bytes.get(20..24)?.try_into().ok()?) != 0
        || bytes.get(48..)? != expected_stem.as_bytes()
    {
        return None;
    }
    Some(BuilderRecord {
        owner: RecordingOwner {
            pid: i32::from_le_bytes(bytes.get(16..20)?.try_into().ok()?),
            incarnation: bytes.get(24..40)?.try_into().ok()?,
        },
        created_unix_ns: i64::from_le_bytes(bytes.get(40..48)?.try_into().ok()?),
        stem: expected_stem.to_owned(),
    })
}

fn unix_now_ns() -> Result<i64, UnitStoreFailure> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| UnitStoreFailure {
            class: UnitStoreFailureClass::Validation,
            reason: UnitMissReason::Schema,
        })?;
    i64::try_from(elapsed.as_nanos()).map_err(|_| UnitStoreFailure {
        class: UnitStoreFailureClass::Validation,
        reason: UnitMissReason::Schema,
    })
}

fn owner_pid_is_live(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

struct BuilderReleaseGuard<'authority> {
    authority: &'authority ContainerCacheAuthority,
    stem: String,
    owner: RecordingOwner,
}

impl Drop for BuilderReleaseGuard<'_> {
    fn drop(&mut self) {
        self.authority.release_builder(&self.stem, self.owner);
    }
}

/// Open one published bundle by name inside the authority directory:
/// `O_NOFOLLOW`, regular-file-only, with its exact byte length. `ENOENT` is a
/// genuine unit miss; everything else fails closed as schema-shaped.
fn open_unit_regular_file_at(
    directory: &File,
    name: &CStr,
) -> Result<(File, usize), UnitStoreError> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        let reason = if error.raw_os_error() == Some(libc::ENOENT) {
            UnitMissReason::MissingPair
        } else {
            UnitMissReason::Schema
        };
        return Err(if error.raw_os_error() == Some(libc::ELOOP) {
            UnitStoreError::with_source("open translation unit bundle", reason, error)
        } else {
            UnitStoreError::io_with_source("open translation unit bundle", reason, error)
        });
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(UnitStoreError::io_with_source(
            "stat translation unit bundle",
            UnitMissReason::Schema,
            std::io::Error::last_os_error(),
        ));
    }
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(UnitStoreError::new(
            "validate translation unit bundle file type",
            UnitMissReason::Schema,
        ));
    }
    let length = u64::try_from(status.st_size)
        .ok()
        .and_then(|length| usize::try_from(length).ok())
        .ok_or_else(|| {
            UnitStoreError::new(
                "validate translation unit bundle size",
                UnitMissReason::ManifestRange,
            )
        })?;
    Ok((file, length))
}

fn read_and_validate_bundle(
    directory: &File,
    name: &CStr,
    expected_key: &TranslationUnitKey,
) -> Result<
    (
        Arc<UnitBundleLease>,
        DecodedUnitBundle,
        TranslationMetadataLoadEvidence,
    ),
    UnitStoreError,
> {
    let (file, length) = open_unit_regular_file_at(directory, name)?;
    #[cfg(test)]
    run_after_bounded_unit_open_for_test();
    if length == 0 || length as u64 > MAX_MAPPED_UNIT_BUNDLE_BYTES {
        return Err(UnitStoreError::new(
            "validate unit bundle size",
            UnitMissReason::ManifestRange,
        ));
    }
    // SAFETY: the exact fstat-bounded regular inode is mapped
    // MAP_PRIVATE|PROT_READ and retained with its descriptor. Publication
    // replaces the pathname atomically and never mutates this inode.
    let mapping = unsafe {
        memmap2::MmapOptions::new()
            .len(length)
            .map_copy_read_only(&file)
    }
    .map_err(|error| {
        UnitStoreError::io_with_source("map unit bundle", UnitMissReason::CodeMapping, error)
    })?;
    let lease = Arc::new(UnitBundleLease {
        _mapping: mapping,
        _file: file,
    });
    let validation_started = std::time::Instant::now();
    let backing: Arc<dyn AsRef<[u8]> + Send + Sync> = lease.clone();
    let decoded = decode_unit_bundle_v1(backing, expected_key)
        .map_err(|reason| UnitStoreError::new("decode unit bundle", reason))?;
    let validation_ns = u64::try_from(validation_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let evidence = TranslationMetadataLoadEvidence {
        bytes_read: 0,
        bytes_mapped: u64::try_from(length).unwrap_or(u64::MAX),
        validation_ns,
        owned_records: decoded.block_count() as u64,
    };
    Ok((lease, decoded, evidence))
}

/// Identity required to adopt one container's cache directory after host
/// self-reexec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerCacheReexecConfig {
    pub host_fd: i32,
    pub original_host_fd_flags: i32,
    pub host_device: u64,
    pub host_inode: u64,
    pub path: PathBuf,
    pub creator_pid: i32,
    pub authority_nonce: [u8; AUTHORITY_NONCE_LEN],
    pub translator_abi: u32,
}

/// The open-directory capability behind a container-private cache.
#[derive(Debug)]
pub struct ContainerCacheAuthority {
    directory: File,
    path: PathBuf,
    creator_pid: i32,
    authority_nonce: [u8; AUTHORITY_NONCE_LEN],
    cleanup_owner: bool,
}

impl ContainerCacheAuthority {
    /// Open the per-host persistent store, falling back to a per-run
    /// ephemeral directory if the host location cannot be prepared. The
    /// fallback keeps `begin_container_cache` infallible-in-practice: a
    /// broken cache directory costs persistence, never the container.
    ///
    /// The `CARRICK_DSR_PERSISTENT_STORE=0` hatch restores the
    /// pre-persistence lifecycle exactly: a per-run tempdir, removed at
    /// container exit, that the (equally hatched-off) translator lane never
    /// consults.
    fn create() -> std::io::Result<Self> {
        if !carrick_dsr_aarch64::translator::persistent_store_runtime_enabled() {
            return Self::create_ephemeral();
        }
        match Self::open_persistent_at(&persistent_store_root()) {
            Ok(authority) => Ok(authority),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "persistent translation store unavailable; using a per-run directory"
                );
                Self::create_ephemeral()
            }
        }
    }

    /// Open (creating if absent) the persistent unit store rooted at `root`.
    ///
    /// The directory outlives every container: publication atomically grows
    /// each unit's normalized block set, and a second `carrick run` of the
    /// same image replays stored blocks instead of retranslating. The authority nonce lives in the
    /// store's marker file so descendants of any run can validate adoption
    /// against the same identity. Pruning (size cap + stale auxiliary files)
    /// runs here, once per container, in the supervisor.
    fn open_persistent_at(root: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(root)?;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        // Adoption after self-reexec requires an absolute path.
        let path = std::fs::canonicalize(root)?;
        let directory = open_directory(&path)?;
        let identity = directory.metadata()?;
        if !identity.is_dir()
            || identity.uid() != unsafe { libc::geteuid() }
            || identity.mode() & 0o777 != 0o700
        {
            return Err(invalid_data("persistent store root identity mismatch"));
        }
        let authority_nonce = read_or_publish_marker(&directory, &path)?;
        prune_store(&directory, &path, STORE_SIZE_CAP_BYTES);
        Ok(Self {
            directory,
            path,
            creator_pid: unsafe { libc::getpid() },
            authority_nonce,
            cleanup_owner: false,
        })
    }

    /// The pre-persistence per-run store: a private tempdir removed when the
    /// creating supervisor exits. Kept solely as `create`'s fallback for a
    /// host whose cache directory cannot be prepared.
    fn create_ephemeral() -> std::io::Result<Self> {
        let tempdir = tempfile::Builder::new()
            .prefix("carrick-native-aot-")
            .tempdir()?;
        let path = tempdir.path().to_path_buf();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;

        let mut authority_nonce = [0_u8; AUTHORITY_NONCE_LEN];
        getrandom::fill(&mut authority_nonce)
            .map_err(|error| invalid_data(format!("generate cache authority nonce: {error}")))?;
        let marker_path = path.join(AUTHORITY_MARKER);
        let mut marker = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&marker_path)?;
        marker.write_all(&authority_nonce)?;
        marker.sync_all()?;

        let directory = open_directory(&path)?;
        let kept_path = tempdir.keep();
        debug_assert_eq!(kept_path, path);
        Ok(Self {
            directory,
            path,
            creator_pid: unsafe { libc::getpid() },
            authority_nonce,
            cleanup_owner: true,
        })
    }

    fn adopt(config: &ContainerCacheReexecConfig) -> std::io::Result<Self> {
        if config.host_fd < 0
            || !config.path.is_absolute()
            || config.translator_abi != carrick_dsr_aarch64::shared_cache::TRANSLATOR_ABI_CURRENT
        {
            return Err(invalid_data("invalid inherited cache authority"));
        }

        // The reexec transport transfers ownership of this descriptor. Take
        // it before validation so every rejection closes the inherited fd.
        let directory = unsafe { File::from_raw_fd(config.host_fd) };
        let fd_identity = directory.metadata()?;
        let path_identity = std::fs::symlink_metadata(&config.path)?;
        if !path_identity.is_dir()
            || path_identity.file_type().is_symlink()
            || fd_identity.dev() != config.host_device
            || fd_identity.ino() != config.host_inode
            || path_identity.dev() != config.host_device
            || path_identity.ino() != config.host_inode
            || path_identity.uid() != unsafe { libc::geteuid() }
            || path_identity.mode() & 0o777 != 0o700
        {
            return Err(invalid_data("inherited cache authority identity mismatch"));
        }

        let marker_name = CString::new(AUTHORITY_MARKER)
            .map_err(|_| invalid_data("cache authority marker contains NUL"))?;
        let marker_fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                marker_name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if marker_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut marker = unsafe { File::from_raw_fd(marker_fd) };
        let mut authority_nonce = [0_u8; AUTHORITY_NONCE_LEN];
        marker.read_exact(&mut authority_nonce)?;
        let mut trailing = [0_u8; 1];
        if marker.read(&mut trailing)? != 0 || authority_nonce != config.authority_nonce {
            return Err(invalid_data("inherited cache authority nonce mismatch"));
        }

        if unsafe {
            libc::fcntl(
                directory.as_raw_fd(),
                libc::F_SETFD,
                config.original_host_fd_flags,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            directory,
            path: config.path.clone(),
            creator_pid: config.creator_pid,
            authority_nonce,
            // Only the process that created the directory may remove it. An
            // adopted authority is always a descendant's capability.
            cleanup_owner: false,
        })
    }

    pub fn snapshot(&self) -> std::io::Result<ContainerCacheReexecConfig> {
        let host_fd = self.directory.as_raw_fd();
        let original_host_fd_flags = unsafe { libc::fcntl(host_fd, libc::F_GETFD) };
        if original_host_fd_flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let identity = self.directory.metadata()?;
        Ok(ContainerCacheReexecConfig {
            host_fd,
            original_host_fd_flags,
            host_device: identity.dev(),
            host_inode: identity.ino(),
            path: self.path.clone(),
            creator_pid: self.creator_pid,
            authority_nonce: self.authority_nonce,
            translator_abi: carrick_dsr_aarch64::shared_cache::TRANSLATOR_ABI_CURRENT,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(test)]
    #[cfg(test)]
    pub fn publish_unit(
        &self,
        pending: &PendingTranslationUnit,
    ) -> Result<PublishOutcome, UnitStoreError> {
        let claim = RecordingClaim {
            owner: RecordingOwner {
                pid: unsafe { libc::getpid() },
                incarnation: [0x4c; 16],
            },
            stale_takeover: false,
        };
        let outcome = self
            .merge(pending, &claim)
            .map_err(|failure| UnitStoreError::new("merge unit bundle", failure.reason))?;
        match outcome.kind {
            MergeKind::Created | MergeKind::Merged | MergeKind::Repaired => {
                Ok(PublishOutcome::Winner)
            }
            MergeKind::Unchanged => Ok(PublishOutcome::Existing),
            MergeKind::Yielded => Ok(PublishOutcome::Yielded),
            MergeKind::Refused(refusal) => Err(UnitStoreError::new(
                "merge unit bundle refused",
                match refusal {
                    MergeRefusal::Conflict { .. } | MergeRefusal::Capacity => {
                        UnitMissReason::ManifestRange
                    }
                    MergeRefusal::Preflight(reason) => reason,
                },
            )),
        }
    }

    /// Elect one recorder without waiting. Existing units remain claimable:
    /// a process may augment a sparse bundle after an attached-unit gap.
    pub fn claim_recording(
        &self,
        key: &TranslationUnitKey,
        owner: &RecordingOwner,
    ) -> Result<ClaimOutcome, UnitStoreFailure> {
        let stem = key.file_stem().map_err(|error| {
            let _ = error;
            UnitStoreFailure {
                class: UnitStoreFailureClass::Validation,
                reason: UnitMissReason::Schema,
            }
        })?;
        let Some(_lock) = self
            .try_lock_unit(&stem)
            .map_err(|error| UnitStoreFailure {
                class: UnitStoreFailureClass::Io,
                reason: error.reason(),
            })?
        else {
            return Ok(ClaimOutcome::Yielded);
        };
        let now = unix_now_ns()?;
        let state = self.read_builder(&stem)?;
        let stale_takeover = !matches!(state, BuilderState::Absent);
        if let BuilderState::Valid(record) = &state {
            let age = now.checked_sub(record.created_unix_ns);
            let ttl = i64::try_from(BUILDER_CLAIM_TTL.as_nanos()).unwrap_or(i64::MAX);
            if age.is_some_and(|age| age >= 0 && age < ttl) && owner_pid_is_live(record.owner.pid) {
                return Ok(ClaimOutcome::LiveOwner);
            }
        }
        let record = BuilderRecord {
            owner: *owner,
            created_unix_ns: now,
            stem: stem.clone(),
        };
        self.write_builder(&record)?;
        Ok(ClaimOutcome::Won(RecordingClaim {
            owner: *owner,
            stale_takeover,
        }))
    }

    /// Reload the newest pathname under the unit lock, union canonical
    /// artifacts, and publish one fully preflighted inode by atomic rename.
    pub fn merge(
        &self,
        pending: &PendingTranslationUnit,
        claim: &RecordingClaim,
    ) -> Result<MergeOutcome, UnitStoreFailure> {
        let stem = pending.key.file_stem().map_err(|_| UnitStoreFailure {
            class: UnitStoreFailureClass::Validation,
            reason: UnitMissReason::Schema,
        })?;
        let _release = BuilderReleaseGuard {
            authority: self,
            stem: stem.clone(),
            owner: claim.owner,
        };
        if pending.blocks.is_empty() {
            return Ok(MergeOutcome {
                kind: MergeKind::Unchanged,
                blocks_added: 0,
                duplicates: 0,
                post_rename_sync_failed: false,
            });
        }
        let Some(_lock) = self
            .try_lock_unit(&stem)
            .map_err(|error| UnitStoreFailure {
                class: UnitStoreFailureClass::Io,
                reason: error.reason(),
            })?
        else {
            return Ok(MergeOutcome {
                kind: MergeKind::Yielded,
                blocks_added: 0,
                duplicates: 0,
                post_rename_sync_failed: false,
            });
        };

        let name =
            CString::new(format!("{stem}{UNIT_V1_SUFFIX}")).map_err(|_| UnitStoreFailure {
                class: UnitStoreFailureClass::Validation,
                reason: UnitMissReason::Schema,
            })?;
        let current = match read_and_validate_bundle(&self.directory, &name, &pending.key) {
            Ok((_lease, decoded, _evidence)) => match decoded.validate_deep() {
                Ok(()) => Some(decoded.artifacts().map_err(|reason| UnitStoreFailure {
                    class: UnitStoreFailureClass::Validation,
                    reason,
                })?),
                Err(_) => None,
            },
            Err(error) if error.reason() == UnitMissReason::MissingPair => Some(Vec::new()),
            Err(error) if error.class == UnitStoreFailureClass::Validation => None,
            Err(error) => return Err(error.failure()),
        };
        let repairing = current.is_none();
        let existing = current.unwrap_or_default();
        let union = match merge_normalized_artifacts(&existing, &pending.blocks) {
            Ok(union) => union,
            Err(refusal) => {
                return Ok(MergeOutcome {
                    kind: MergeKind::Refused(refusal),
                    blocks_added: 0,
                    duplicates: 0,
                    post_rename_sync_failed: false,
                });
            }
        };
        if !repairing && !existing.is_empty() && union.blocks_added == 0 {
            return Ok(MergeOutcome {
                kind: MergeKind::Unchanged,
                blocks_added: 0,
                duplicates: union.duplicates,
                post_rename_sync_failed: false,
            });
        }
        let bundle = match encode_unit_bundle_v1(&pending.key, &union.blocks) {
            Ok(bundle) => bundle,
            Err(_) => {
                return Ok(MergeOutcome {
                    kind: MergeKind::Refused(MergeRefusal::Preflight(
                        UnitMissReason::ManifestRange,
                    )),
                    blocks_added: 0,
                    duplicates: union.duplicates,
                    post_rename_sync_failed: false,
                });
            }
        };
        let mut temporary =
            tempfile::NamedTempFile::new_in(&self.path).map_err(|_| UnitStoreFailure {
                class: UnitStoreFailureClass::Io,
                reason: UnitMissReason::MissingPair,
            })?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o600))
            .map_err(|_| UnitStoreFailure {
                class: UnitStoreFailureClass::Io,
                reason: UnitMissReason::MissingPair,
            })?;
        temporary.write_all(&bundle).map_err(|_| UnitStoreFailure {
            class: UnitStoreFailureClass::Io,
            reason: UnitMissReason::MissingPair,
        })?;
        temporary.flush().map_err(|_| UnitStoreFailure {
            class: UnitStoreFailureClass::Io,
            reason: UnitMissReason::MissingPair,
        })?;
        #[cfg(test)]
        if take_publication_fault(PublicationFault::BeforeTempSync) {
            return Err(UnitStoreFailure {
                class: UnitStoreFailureClass::Io,
                reason: UnitMissReason::MissingPair,
            });
        }
        temporary
            .as_file()
            .sync_all()
            .map_err(|_| UnitStoreFailure {
                class: UnitStoreFailureClass::Io,
                reason: UnitMissReason::MissingPair,
            })?;
        let temporary_name = temporary
            .path()
            .file_name()
            .and_then(|name| CString::new(name.as_bytes()).ok())
            .ok_or(UnitStoreFailure {
                class: UnitStoreFailureClass::Validation,
                reason: UnitMissReason::Schema,
            })?;
        #[cfg(test)]
        if take_publication_fault(PublicationFault::BeforePreflight) {
            return Ok(MergeOutcome {
                kind: MergeKind::Refused(MergeRefusal::Preflight(UnitMissReason::Schema)),
                blocks_added: 0,
                duplicates: union.duplicates,
                post_rename_sync_failed: false,
            });
        }
        let (_lease, decoded, _evidence) =
            match read_and_validate_bundle(&self.directory, &temporary_name, &pending.key) {
                Ok(decoded) => decoded,
                Err(error) if error.class == UnitStoreFailureClass::Validation => {
                    return Ok(MergeOutcome {
                        kind: MergeKind::Refused(MergeRefusal::Preflight(error.reason())),
                        blocks_added: 0,
                        duplicates: union.duplicates,
                        post_rename_sync_failed: false,
                    });
                }
                Err(error) => return Err(error.failure()),
            };
        if let Err(reason) = decoded.validate_deep() {
            return Ok(MergeOutcome {
                kind: MergeKind::Refused(MergeRefusal::Preflight(reason)),
                blocks_added: 0,
                duplicates: union.duplicates,
                post_rename_sync_failed: false,
            });
        }
        #[cfg(test)]
        if take_publication_fault(PublicationFault::BeforeRename) {
            return Err(UnitStoreFailure {
                class: UnitStoreFailureClass::Io,
                reason: UnitMissReason::MissingPair,
            });
        }
        std::fs::rename(temporary.path(), self.final_path(&stem)).map_err(|_| {
            UnitStoreFailure {
                class: UnitStoreFailureClass::Io,
                reason: UnitMissReason::MissingPair,
            }
        })?;
        #[cfg(test)]
        let injected_directory_sync = take_publication_fault(PublicationFault::DirectorySync);
        #[cfg(not(test))]
        let injected_directory_sync = false;
        let post_rename_sync_failed = injected_directory_sync || self.directory.sync_all().is_err();
        let kind = if repairing {
            MergeKind::Repaired
        } else if existing.is_empty() {
            MergeKind::Created
        } else {
            MergeKind::Merged
        };
        Ok(MergeOutcome {
            kind,
            blocks_added: union.blocks_added,
            duplicates: union.duplicates,
            post_rename_sync_failed,
        })
    }

    pub fn load_unit(
        &self,
        expected_key: &TranslationUnitKey,
        source_words: &[u32],
    ) -> Result<LoadedTranslationUnit, UnitStoreError> {
        self.load_unit_inner(expected_key, source_words)
    }

    fn load_unit_inner(
        &self,
        expected_key: &TranslationUnitKey,
        source_words: &[u32],
    ) -> Result<LoadedTranslationUnit, UnitStoreError> {
        let stem = expected_key.file_stem().map_err(|error| {
            UnitStoreError::with_source("derive unit filename", UnitMissReason::Schema, error)
        })?;
        if !shared_source_fingerprint_reuse_enabled()
            && expected_key.source_fingerprint() != SourceFingerprint::from_words(source_words)
        {
            return Err(UnitStoreError::new(
                "validate unit source",
                UnitMissReason::SourceFingerprint,
            ));
        }
        let name = CString::new(format!("{stem}{UNIT_V1_SUFFIX}")).map_err(|error| {
            UnitStoreError::with_source("encode unit bundle name", UnitMissReason::Schema, error)
        })?;
        let (lease, decoded, load_evidence) =
            read_and_validate_bundle(&self.directory, &name, expected_key)?;
        let source = lease
            .as_ref()
            .as_ref()
            .as_ptr()
            .wrapping_add(decoded.code_offset());
        let source_base = std::ptr::NonNull::new(source.cast_mut()).ok_or_else(|| {
            UnitStoreError::new("map unit bundle code", UnitMissReason::CodeMapping)
        })?;
        let manifest = Arc::new(
            decoded
                .translation_manifest()
                .map_err(|reason| UnitStoreError::new("build unit replay view", reason))?,
        );
        // Refresh only inode timestamps for LRU accounting. Bundle content is
        // immutable and old mappings remain pinned across replacement.
        let _ = unsafe { libc::futimens(lease._file.as_raw_fd(), std::ptr::null()) };
        Ok(LoadedTranslationUnit {
            lease,
            manifest,
            source_base,
            load_evidence,
        })
    }

    /// Acquire one unit's store lock without blocking. `None` means another
    /// process holds it right now — and every caller has a correct
    /// non-waiting answer for that (skip the claim, yield the publication):
    /// no process ever blocks on another's translation.
    fn try_lock_unit(&self, stem: &str) -> Result<Option<UnitFileLock>, UnitStoreError> {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.path.join(format!("{stem}.lock")))
            .map_err(|error| {
                UnitStoreError::io_with_source("open unit lock", UnitMissReason::MissingPair, error)
            })?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Ok(None);
            }
            return Err(UnitStoreError::io_with_source(
                "lock unit",
                UnitMissReason::MissingPair,
                error,
            ));
        }
        Ok(Some(UnitFileLock(lock)))
    }

    fn read_builder(&self, stem: &str) -> Result<BuilderState, UnitStoreFailure> {
        let name = CString::new(format!("{stem}.builder")).map_err(|_| UnitStoreFailure {
            class: UnitStoreFailureClass::Validation,
            reason: UnitMissReason::Schema,
        })?;
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::ENOENT) => Ok(BuilderState::Absent),
                Some(libc::ELOOP) => Ok(BuilderState::Malformed),
                _ => Err(UnitStoreFailure {
                    class: UnitStoreFailureClass::Io,
                    reason: UnitMissReason::MissingPair,
                }),
            };
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let identity = file.metadata().map_err(|_| UnitStoreFailure {
            class: UnitStoreFailureClass::Io,
            reason: UnitMissReason::MissingPair,
        })?;
        if !identity.file_type().is_file() || identity.mode() & 0o777 != 0o600 {
            return Ok(BuilderState::Malformed);
        }
        let mut bytes = Vec::new();
        file.take((BUILDER_RECORD_BYTES_V1 + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| UnitStoreFailure {
                class: UnitStoreFailureClass::Io,
                reason: UnitMissReason::MissingPair,
            })?;
        Ok(match decode_builder_record(&bytes, stem) {
            Some(record) => BuilderState::Valid(record),
            None => BuilderState::Malformed,
        })
    }

    fn write_builder(&self, record: &BuilderRecord) -> Result<(), UnitStoreFailure> {
        let bytes = encode_builder_record(record).map_err(|()| UnitStoreFailure {
            class: UnitStoreFailureClass::Validation,
            reason: UnitMissReason::Schema,
        })?;
        let mut temporary =
            tempfile::NamedTempFile::new_in(&self.path).map_err(|_| UnitStoreFailure {
                class: UnitStoreFailureClass::Io,
                reason: UnitMissReason::MissingPair,
            })?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o600))
            .map_err(|_| UnitStoreFailure {
                class: UnitStoreFailureClass::Io,
                reason: UnitMissReason::MissingPair,
            })?;
        temporary.write_all(&bytes).map_err(|_| UnitStoreFailure {
            class: UnitStoreFailureClass::Io,
            reason: UnitMissReason::MissingPair,
        })?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|_| UnitStoreFailure {
                class: UnitStoreFailureClass::Io,
                reason: UnitMissReason::MissingPair,
            })?;
        std::fs::rename(
            temporary.path(),
            self.path.join(format!("{}.builder", record.stem)),
        )
        .map_err(|_| UnitStoreFailure {
            class: UnitStoreFailureClass::Io,
            reason: UnitMissReason::MissingPair,
        })
    }

    fn release_builder(&self, stem: &str, owner: RecordingOwner) {
        let Ok(Some(_lock)) = self.try_lock_unit(stem) else {
            return;
        };
        let Ok(BuilderState::Valid(record)) = self.read_builder(stem) else {
            return;
        };
        if record.owner == owner {
            let _ = std::fs::remove_file(self.path.join(format!("{stem}.builder")));
        }
    }

    fn final_path(&self, stem: &str) -> PathBuf {
        self.path.join(format!("{stem}{UNIT_V1_SUFFIX}"))
    }

    #[cfg(test)]
    fn directory(&self) -> &File {
        &self.directory
    }
}

impl Drop for ContainerCacheAuthority {
    fn drop(&mut self) {
        // Only the ephemeral fallback is removable: the persistent store is
        // the point of the mechanism, and pruning (not container exit)
        // bounds it.
        if self.cleanup_owner && owns_cleanup(self.creator_pid, unsafe { libc::getpid() }) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Scope guard owned by the parent process that launched one native
/// container. Dropping it after the root guest exits releases this
/// process's authority slot; the persistent store itself outlives it.
#[derive(Debug)]
pub struct ContainerCacheSession {
    creator_pid: i32,
}

impl Drop for ContainerCacheSession {
    fn drop(&mut self) {
        if !owns_cleanup(self.creator_pid, unsafe { libc::getpid() }) {
            return;
        }
        if let Ok(mut authority) = CONTAINER_CACHE.lock()
            && authority
                .as_ref()
                .is_some_and(|cache| cache.creator_pid == self.creator_pid)
        {
            let _ = authority.take();
        }
    }
}

pub fn begin_container_cache() -> std::io::Result<ContainerCacheSession> {
    install_container_cache(ContainerCacheAuthority::create()?)
}

/// Test and bench entry: a persistent store rooted at an explicit directory
/// instead of the host default, so fixtures with deterministic keys never
/// touch (or inherit state from) the user's real store.
pub fn begin_container_cache_at(root: &Path) -> std::io::Result<ContainerCacheSession> {
    install_container_cache(ContainerCacheAuthority::open_persistent_at(root)?)
}

fn install_container_cache(
    authority: ContainerCacheAuthority,
) -> std::io::Result<ContainerCacheSession> {
    let creator_pid = authority.creator_pid;
    let mut active = CONTAINER_CACHE
        .lock()
        .map_err(|_| invalid_data("container cache authority lock poisoned"))?;
    if active.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "a native container cache is already active",
        ));
    }
    *active = Some(authority);
    Ok(ContainerCacheSession { creator_pid })
}

pub fn container_cache_snapshot() -> std::io::Result<Option<ContainerCacheReexecConfig>> {
    CONTAINER_CACHE
        .lock()
        .map_err(|_| invalid_data("container cache authority lock poisoned"))?
        .as_ref()
        .map(ContainerCacheAuthority::snapshot)
        .transpose()
}

pub fn adopt_container_cache(config: &ContainerCacheReexecConfig) -> std::io::Result<()> {
    let authority = ContainerCacheAuthority::adopt(config)?;
    let mut active = CONTAINER_CACHE
        .lock()
        .map_err(|_| invalid_data("container cache authority lock poisoned"))?;
    if active.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "native container cache authority was already initialized",
        ));
    }
    *active = Some(authority);
    Ok(())
}

#[derive(Debug, Default)]
pub struct ActiveContainerUnitStore;

impl carrick_dsr_aarch64::shared_cache::TranslationUnitStore for ActiveContainerUnitStore {
    fn load(
        &self,
        key: &TranslationUnitKey,
        source_words: &[u32],
    ) -> Result<
        Option<carrick_dsr_aarch64::shared_cache::SharedLoadedTranslationUnit>,
        UnitMissReason,
    > {
        // These two used to be `MissingPair`, i.e. indistinguishable from a
        // genuine cache miss. A store-less descendant contributes zero coverage
        // forever, so it has to be countable on its own.
        let active = CONTAINER_CACHE
            .lock()
            .map_err(|_| UnitMissReason::StoreUnavailable)?;
        let authority = active.as_ref().ok_or(UnitMissReason::NoAuthority)?;
        match authority.load_unit(key, source_words) {
            Ok(loaded) => Ok(Some(loaded.into_shared())),
            Err(error) if error.reason() == UnitMissReason::MissingPair => Ok(None),
            Err(error) => {
                // Same reasoning as the publish side: the trait narrows to a
                // bare reason, so the context naming the rejected invariant
                // would be lost exactly where a silent load failure hides.
                tracing::warn!(
                    error = %error,
                    reason = ?error.reason(),
                    "shared translation refused to load a unit it published"
                );
                Err(error.reason())
            }
        }
    }

    fn claim_recording(
        &self,
        key: &TranslationUnitKey,
        owner: &RecordingOwner,
    ) -> Result<ClaimOutcome, UnitStoreFailure> {
        let active = CONTAINER_CACHE.lock().map_err(|_| UnitStoreFailure {
            class: UnitStoreFailureClass::Io,
            reason: UnitMissReason::StoreUnavailable,
        })?;
        let authority = active.as_ref().ok_or(UnitStoreFailure {
            class: UnitStoreFailureClass::Validation,
            reason: UnitMissReason::NoAuthority,
        })?;
        authority.claim_recording(key, owner)
    }

    fn merge(
        &self,
        pending: &PendingTranslationUnit,
        claim: &RecordingClaim,
    ) -> Result<MergeOutcome, UnitStoreFailure> {
        let active = CONTAINER_CACHE.lock().map_err(|_| UnitStoreFailure {
            class: UnitStoreFailureClass::Io,
            reason: UnitMissReason::StoreUnavailable,
        })?;
        let authority = active.as_ref().ok_or(UnitStoreFailure {
            class: UnitStoreFailureClass::Validation,
            reason: UnitMissReason::NoAuthority,
        })?;
        authority.merge(pending, claim)
    }
}

fn open_directory(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
}

fn invalid_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

fn owns_cleanup(creator_pid: i32, current_pid: i32) -> bool {
    creator_pid == current_pid
}

#[cfg(test)]
mod tests {

    use super::*;
    use carrick_dsr::address::NativeHostBias;
    use carrick_dsr_aarch64::artifact_spike::{ArtifactBindings, ArtifactTemplate};
    use carrick_dsr_aarch64::emit::PcMapEntry;
    use carrick_dsr_aarch64::shared_cache::{
        AddressModeIdentity, ExecutableIdentity, GuestCodeLen, ImageFileLen, ImageFileOffset,
        MAX_TRANSLATION_UNIT_CODE_BYTES, NativePageProfileIdentity, PortableBlockCandidate,
        SourceFingerprint,
    };
    use carrick_dsr_aarch64::types::{CacheOffset, CodeGeneration};
    use carrick_guest_mem::GuestVa;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::PermissionsExt;

    const MOV42_RET: [u8; 8] = [0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6];

    /// `CONTAINER_CACHE` is one process-global slot, and `begin_container_cache`
    /// refuses to install a second authority. Any test that asserts on whether
    /// an authority is installed has to hold this.
    static CACHE_SLOT: Mutex<()> = Mutex::new(());

    fn cache_slot() -> std::sync::MutexGuard<'static, ()> {
        CACHE_SLOT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn fixture_pending() -> PendingTranslationUnit {
        let source_words = [u32::from_le_bytes(MOV42_RET[..4].try_into().expect("word"))];
        let words = MOV42_RET
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().expect("word")))
            .collect();
        let template = ArtifactTemplate::normalize(
            words,
            vec![
                PcMapEntry {
                    guest: GuestVa(0x400000),
                    cache: CacheOffset::published(0),
                },
                PcMapEntry {
                    guest: GuestVa(0x400004),
                    cache: CacheOffset::published(4),
                },
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            &ArtifactBindings::from_values([]).expect("empty artifact bindings"),
        )
        .expect("fixture block metadata");
        let key = TranslationUnitKey::for_segment(
            ExecutableIdentity::Digest([0x11; 32]),
            ImageFileOffset::new(0),
            ImageFileLen::new(0x1000).expect("nonzero file length"),
            GuestVa(0x400000),
            GuestCodeLen::new(0x1000).expect("nonzero guest length"),
            SourceFingerprint::from_words(&source_words),
            NativePageProfileIdentity::Native16k,
            AddressModeIdentity::biased(
                NativeHostBias::new(0x8000_0000, 16 * 1024).expect("aligned bias"),
            ),
        );
        PendingTranslationUnit::pack(
            key,
            vec![PortableBlockCandidate {
                guest_start: GuestVa(0x400000),
                source_end: GuestVa(0x400008),
                generation: CodeGeneration::INITIAL,
                requires_sensitive_metadata: false,
                template,
            }],
        )
        .expect("pack fixture pending unit")
    }

    fn fixture_source_words() -> [u32; 1] {
        [u32::from_le_bytes(MOV42_RET[..4].try_into().expect("word"))]
    }

    fn fixture_pending_at(guest_start: u64, first_word: u32) -> PendingTranslationUnit {
        let mut pending = fixture_pending();
        let block = &mut pending.blocks[0];
        block.guest_start = GuestVa(guest_start);
        block.source_end = GuestVa(guest_start + 8);
        block.code[..4].copy_from_slice(&first_word.to_le_bytes());
        pending
    }

    fn fixture_owner(seed: u8) -> carrick_dsr_aarch64::pending_augmentation::RecordingOwner {
        carrick_dsr_aarch64::pending_augmentation::RecordingOwner {
            pid: unsafe { libc::getpid() },
            incarnation: [seed; 16],
        }
    }

    fn claim_fixture(
        authority: &ContainerCacheAuthority,
        pending: &PendingTranslationUnit,
        seed: u8,
    ) -> RecordingClaim {
        match authority
            .claim_recording(&pending.key, &fixture_owner(seed))
            .expect("claim recording")
        {
            ClaimOutcome::Won(claim) => claim,
            outcome => panic!("expected won claim, got {outcome:?}"),
        }
    }

    fn current_region_extended_info(address: usize) -> mach2::vm_region::vm_region_extended_info {
        use mach2::kern_return::KERN_SUCCESS;
        use mach2::mach_port::mach_port_deallocate;
        use mach2::port::MACH_PORT_NULL;
        use mach2::traps::mach_task_self;
        use mach2::vm::mach_vm_region;
        use mach2::vm_region::{VM_REGION_EXTENDED_INFO, VM_REGION_EXTENDED_INFO_COUNT};

        let requested = address as mach2::vm_types::mach_vm_address_t;
        let mut observed = requested;
        let mut size = 0;
        let mut info = mach2::vm_region::vm_region_extended_info::default();
        let mut info_count = VM_REGION_EXTENDED_INFO_COUNT;
        let mut object_name = MACH_PORT_NULL;
        // SAFETY: this queries the current task for a live mapping address and
        // supplies the exact flavor-specific output type and count.
        let task = unsafe { mach_task_self() };
        let result = unsafe {
            mach_vm_region(
                task,
                &mut observed,
                &mut size,
                VM_REGION_EXTENDED_INFO,
                (&raw mut info).cast::<i32>(),
                &mut info_count,
                &mut object_name,
            )
        };
        if object_name != MACH_PORT_NULL {
            // SAFETY: `mach_vm_region` returned this send right for `task`.
            let _ = unsafe { mach_port_deallocate(task, object_name) };
        }
        assert_eq!(result, KERN_SUCCESS, "query mapped metadata VM region");
        assert!(
            observed <= requested && requested < observed.saturating_add(size),
            "requested address must lie inside its VM region"
        );
        assert_ne!(size, 0, "metadata VM region must be nonempty");
        info
    }

    /// A hermetic persistent-store authority rooted in a private tempdir.
    /// Returns the root guard alongside so the store outlives the authority
    /// (persistence is the property under test) and is removed when the test
    /// ends. Fixture keys are deterministic, so tests must never share the
    /// user's real store.
    fn persistent_fixture_authority() -> (tempfile::TempDir, ContainerCacheAuthority) {
        let root = tempfile::Builder::new()
            .prefix("carrick-aot-test-")
            .tempdir()
            .expect("create test store root");
        let authority = ContainerCacheAuthority::open_persistent_at(root.path())
            .expect("open persistent store authority");
        (root, authority)
    }

    fn set_file_age(path: &Path, age: std::time::Duration) {
        let past = std::time::SystemTime::now() - age;
        let seconds = past
            .duration_since(std::time::UNIX_EPOCH)
            .expect("past epoch")
            .as_secs();
        let times = [
            libc::timeval {
                tv_sec: seconds as libc::time_t,
                tv_usec: 0,
            },
            libc::timeval {
                tv_sec: seconds as libc::time_t,
                tv_usec: 0,
            },
        ];
        let c_path = CString::new(path.as_os_str().as_bytes()).expect("path without NUL");
        assert_eq!(
            unsafe { libc::utimes(c_path.as_ptr(), times.as_ptr()) },
            0,
            "age file {}",
            path.display()
        );
    }

    fn duplicated_snapshot(authority: &ContainerCacheAuthority) -> ContainerCacheReexecConfig {
        let mut snapshot = authority.snapshot().expect("snapshot cache authority");
        let duplicate =
            unsafe { libc::fcntl(authority.directory().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        assert!(duplicate >= 0, "duplicate directory fd");
        snapshot.host_fd = duplicate;
        snapshot
    }

    #[test]
    fn authority_is_private_and_survives_validated_reexec_adoption() {
        let (_store, authority) = persistent_fixture_authority();
        let snapshot = duplicated_snapshot(&authority);
        let adopted = ContainerCacheAuthority::adopt(&snapshot).expect("adopt cache authority");

        assert_eq!(adopted.path(), authority.path());
        assert_eq!(
            adopted.snapshot().expect("snapshot adopted authority"),
            snapshot
        );
        assert_eq!(
            std::fs::metadata(authority.path())
                .expect("stat cache directory")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn authority_rejects_substituted_directory_fd() {
        let (_store, authority) = persistent_fixture_authority();
        let (_substitute_store, substitute) = persistent_fixture_authority();
        let mut snapshot = duplicated_snapshot(&substitute);
        let expected = authority.snapshot().expect("snapshot expected authority");
        snapshot.host_device = expected.host_device;
        snapshot.host_inode = expected.host_inode;

        let error = ContainerCacheAuthority::adopt(&snapshot)
            .expect_err("substituted directory must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn authority_rejects_substituted_directory_path() {
        let (_store, authority) = persistent_fixture_authority();
        let (_substitute_store, substitute) = persistent_fixture_authority();
        let mut snapshot = duplicated_snapshot(&authority);
        snapshot.path = substitute.path().to_path_buf();

        let error = ContainerCacheAuthority::adopt(&snapshot)
            .expect_err("substituted path must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn only_the_creator_pid_owns_cleanup() {
        let pid = unsafe { libc::getpid() };
        assert!(owns_cleanup(pid, pid));
        assert!(!owns_cleanup(pid, pid.saturating_add(1)));
    }

    /// The census counts these two outcomes in different buckets, and the
    /// answer to "where did the shared lane's coverage go" depends on which one
    /// a run reports. They used to be the same `UnitMissReason::MissingPair`.
    #[test]
    fn store_load_separates_no_authority_from_a_file_miss() {
        use carrick_dsr_aarch64::shared_cache::TranslationUnitStore as _;

        let _slot = cache_slot();
        let store = ActiveContainerUnitStore;
        let pending = fixture_pending();
        let source_words = [u32::from_le_bytes(MOV42_RET[..4].try_into().expect("word"))];

        // No authority installed: nothing this process does could ever hit.
        assert_eq!(
            store.load(&pending.key, &source_words).err(),
            Some(UnitMissReason::NoAuthority),
        );

        let root = tempfile::Builder::new()
            .prefix("carrick-aot-test-")
            .tempdir()
            .expect("create test store root");
        let session = begin_container_cache_at(root.path()).expect("begin container cache");
        // Authority installed, files absent: a genuine miss, and the only shape
        // that reaches the recorder election.
        assert!(matches!(store.load(&pending.key, &source_words), Ok(None)));
        drop(session);

        assert_eq!(
            store.load(&pending.key, &source_words).err(),
            Some(UnitMissReason::NoAuthority),
        );
    }

    /// The persistent store is the point: a session ending releases this
    /// process's authority slot but leaves the directory — and its published
    /// units — for every future run.
    #[test]
    fn creator_session_keeps_the_persistent_store_after_container_exit() {
        let _slot = cache_slot();
        let root = tempfile::Builder::new()
            .prefix("carrick-aot-test-")
            .tempdir()
            .expect("create test store root");
        let session = begin_container_cache_at(root.path()).expect("begin container cache");
        let path = container_cache_snapshot()
            .expect("snapshot container cache")
            .expect("active container cache")
            .path;
        assert!(path.is_dir());

        drop(session);

        assert!(path.is_dir(), "the store must survive the container");
        assert!(
            path.join(AUTHORITY_MARKER).is_file(),
            "the authority marker must survive for future adoptions"
        );
        assert!(
            container_cache_snapshot()
                .expect("snapshot inactive cache")
                .is_none()
        );
    }

    #[test]
    fn inherited_process_cannot_remove_creator_cache() {
        // Removal-at-drop only exists on the ephemeral fallback; the
        // ownership rule protects a creator's live directory from a
        // descendant's authority drop.
        let mut authority =
            ContainerCacheAuthority::create_ephemeral().expect("create cache authority");
        let path = authority.path().to_path_buf();
        authority.creator_pid = unsafe { libc::getpid() }.saturating_add(1);

        drop(authority);

        assert!(path.is_dir());
        std::fs::remove_dir_all(path).expect("remove test cache");
    }

    #[test]
    fn ephemeral_fallback_is_removed_by_its_creator() {
        let authority =
            ContainerCacheAuthority::create_ephemeral().expect("create cache authority");
        let path = authority.path().to_path_buf();
        assert!(path.is_dir());

        drop(authority);

        assert!(!path.exists());
    }

    #[test]
    fn adoption_takes_ownership_of_the_inherited_fd() {
        let (_store, authority) = persistent_fixture_authority();
        let snapshot = duplicated_snapshot(&authority);
        let inherited_fd = snapshot.host_fd;
        let adopted = ContainerCacheAuthority::adopt(&snapshot).expect("adopt cache authority");
        drop(adopted);

        let borrowed = unsafe { std::fs::File::from_raw_fd(inherited_fd) };
        let result = unsafe { libc::fcntl(borrowed.as_raw_fd(), libc::F_GETFD) };
        std::mem::forget(borrowed);
        assert_eq!(result, -1);
    }

    /// With a persistent store, the accumulated unit amortizes across every future
    /// run and exec, so the first process to MISS a unit must claim its
    /// recording. The retired `.seen` deferral ("prove the unit recurs in
    /// this container first") pushed publication past the SECOND exec's exit
    /// — on the parallel build shape that is "within-build reuse arrives too
    /// late" (2026-08-03 scoreboard correction).
    #[test]
    fn first_file_miss_claims_recording_immediately() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        let owner = fixture_owner(0x51);
        assert!(
            matches!(
                authority
                    .claim_recording(&pending.key, &owner)
                    .expect("first claim"),
                ClaimOutcome::Won(_)
            ),
            "the first process to miss must claim recording"
        );
        // The claim is sticky: the same (still live) claimant blocks rivals.
        assert_eq!(
            authority
                .claim_recording(&pending.key, &owner)
                .expect("second claim"),
            ClaimOutcome::LiveOwner,
            "a live claim must not be handed out twice"
        );
    }

    /// A `.builder` claim from a crashed run must not park a unit forever:
    /// a persistent store outlives pids, and a recycled pid can look alive
    /// indefinitely. Age is the tiebreaker.
    #[test]
    fn stale_builder_claims_are_taken_over_by_age() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        let stem = pending.key.file_stem().expect("unit stem");
        let builder = authority.path().join(format!("{stem}.builder"));
        // Pid 1 (launchd) is always alive and never carrick: exactly the
        // recycled-pid shape.
        std::fs::write(&builder, b"1").expect("write stale builder");
        set_file_age(&builder, std::time::Duration::from_secs(60 * 60));

        assert!(
            matches!(
                authority
                    .claim_recording(&pending.key, &fixture_owner(0x52))
                    .expect("claim over stale builder"),
                ClaimOutcome::Won(RecordingClaim {
                    stale_takeover: true,
                    ..
                })
            ),
            "an hour-old claim is stale regardless of pid liveness"
        );
    }

    /// The core of the lane: a unit published by one authority (one run)
    /// loads from a fresh authority over the same root (the next run), and
    /// the recorder election reports "already published" instead of handing
    /// out a claim.
    #[test]
    fn published_units_survive_into_a_new_authority_over_the_same_root() {
        let (store, first) = persistent_fixture_authority();
        let pending = fixture_pending();
        assert_eq!(
            first.publish_unit(&pending).expect("publish unit"),
            PublishOutcome::Winner
        );
        drop(first);

        let second = ContainerCacheAuthority::open_persistent_at(store.path())
            .expect("reopen persistent store");
        let loaded = second
            .load_unit(&pending.key, &fixture_source_words())
            .expect("load unit published by the previous authority");
        assert_eq!(loaded.manifest.key, pending.key);
        assert!(matches!(
            second
                .claim_recording(&pending.key, &fixture_owner(0x53))
                .expect("claim against a published unit"),
            ClaimOutcome::Won(_)
        ));
        assert_eq!(
            second.publish_unit(&pending).expect("republish unit"),
            PublishOutcome::Existing
        );
    }

    /// Both authorities over one root must agree on the marker nonce, or a
    /// descendant of the second run could not adopt the snapshot.
    #[test]
    fn reopened_store_reads_the_same_authority_nonce() {
        let (store, first) = persistent_fixture_authority();
        let first_nonce = first.authority_nonce;
        drop(first);
        let second = ContainerCacheAuthority::open_persistent_at(store.path())
            .expect("reopen persistent store");
        assert_eq!(second.authority_nonce, first_nonce);
    }

    /// A truncated atomic bundle must fail closed and remain repairable by a
    /// later merge from valid pending data.
    #[test]
    fn truncated_bundle_fails_closed_and_republish_repairs() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        assert_eq!(
            authority.publish_unit(&pending).expect("publish unit"),
            PublishOutcome::Winner
        );
        let stem = pending.key.file_stem().expect("unit stem");
        let unit_path = authority.final_path(&stem);
        let intact = std::fs::read(&unit_path).expect("read bundle");
        std::fs::write(&unit_path, &intact[..intact.len() / 2]).expect("truncate bundle");

        let error = authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect_err("truncated bundle must not load");
        assert_ne!(error.reason(), UnitMissReason::MissingPair);

        let claim = claim_fixture(&authority, &pending, 0x56);
        assert_eq!(
            authority.merge(&pending, &claim).expect("repair").kind,
            MergeKind::Repaired
        );
        authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect("repaired unit loads");
    }

    /// The size cap evicts oldest-used unit inodes first and leaves the store
    /// under the cap; the authority marker survives pruning.
    #[test]
    fn prune_evicts_oldest_units_down_to_the_cap() {
        let (store, authority) = persistent_fixture_authority();
        let old = fixture_pending();
        let mut new = fixture_pending();
        // A distinct key: different guest start yields a different stem.
        new.key = TranslationUnitKey::for_segment(
            ExecutableIdentity::Digest([0x33; 32]),
            ImageFileOffset::new(0),
            ImageFileLen::new(8).expect("nonzero file length"),
            GuestVa(0x400000),
            GuestCodeLen::new(8).expect("nonzero guest length"),
            SourceFingerprint::from_words(&fixture_source_words()),
            NativePageProfileIdentity::Native16k,
            AddressModeIdentity::biased(
                NativeHostBias::new(0x8000_0000, 16 * 1024).expect("aligned bias"),
            ),
        );
        new.blocks[0].guest_start = GuestVa(0x400000);
        assert_eq!(
            authority.publish_unit(&old).expect("publish old"),
            PublishOutcome::Winner
        );
        assert_eq!(
            authority.publish_unit(&new).expect("publish new"),
            PublishOutcome::Winner
        );
        let old_stem = old.key.file_stem().expect("old stem");
        let new_stem = new.key.file_stem().expect("new stem");
        set_file_age(
            &authority.final_path(&old_stem),
            std::time::Duration::from_secs(3 * 60 * 60),
        );

        // A cap of one byte forces eviction of everything not in use; the
        // oldest unit goes first and eviction stops at the cap — here after
        // both, so assert the ORDER by capping between the two unit sizes.
        let keep_bytes = std::fs::metadata(authority.final_path(&new_stem))
            .expect("new unit")
            .len();
        prune_store(authority.directory(), store.path(), keep_bytes);

        assert!(
            !authority.final_path(&old_stem).exists(),
            "the oldest unit must be evicted"
        );
        assert!(
            authority.final_path(&new_stem).is_file(),
            "the newest unit must survive"
        );
        assert!(store.path().join(AUTHORITY_MARKER).is_file());
        authority
            .load_unit(&new.key, &fixture_source_words())
            .expect("survivor still loads");
    }

    /// Aged publication temporaries are crash leftovers; retired suffixes
    /// remain outside current-ABI accounting.
    #[test]
    fn prune_removes_retired_and_aged_auxiliary_files() {
        let (store, authority) = persistent_fixture_authority();
        let seen = store.path().join("deadbeef.seen");
        std::fs::write(&seen, b"").expect("write legacy seen marker");
        let fresh_temp = store.path().join(".tmpfresh1");
        std::fs::write(&fresh_temp, b"half-written").expect("write fresh temporary");
        let stale_temp = store.path().join(".tmpstale1");
        std::fs::write(&stale_temp, b"half-written").expect("write stale temporary");
        set_file_age(
            &stale_temp,
            TEMP_FILE_TTL + std::time::Duration::from_secs(60),
        );

        prune_store(authority.directory(), store.path(), STORE_SIZE_CAP_BYTES);

        assert!(
            seen.exists(),
            "retired suffixes are ignored by ABI-9 pruning"
        );
        assert!(
            fresh_temp.exists(),
            "a young temporary may be a publication in flight"
        );
        assert!(!stale_temp.exists(), "aged temporaries are crash leftovers");
        assert!(store.path().join(AUTHORITY_MARKER).is_file());
    }

    #[test]
    fn concurrent_publishers_converge_on_one_published_unit() {
        let (_store, authority) = persistent_fixture_authority();
        let authority = std::sync::Arc::new(authority);
        let pending = fixture_pending();
        let threads = (0..2)
            .map(|_| {
                let authority = std::sync::Arc::clone(&authority);
                let pending = pending.clone();
                std::thread::spawn(move || authority.publish_unit(&pending))
            })
            .collect::<Vec<_>>();
        let mut outcomes = threads
            .into_iter()
            .map(|thread| {
                thread
                    .join()
                    .expect("publisher thread")
                    .expect("publish unit")
            })
            .collect::<Vec<_>>();
        outcomes.sort_by_key(|outcome| match outcome {
            PublishOutcome::Winner => 0,
            PublishOutcome::Existing | PublishOutcome::Yielded => 1,
        });
        assert_eq!(outcomes[0], PublishOutcome::Winner);
        // The loser either saw the winner's finished unit (Existing) or its
        // held lock (Yielded) — both are non-blocking single-publisher
        // outcomes.
        assert!(
            matches!(
                outcomes[1],
                PublishOutcome::Existing | PublishOutcome::Yielded
            ),
            "loser outcome: {:?}",
            outcomes[1]
        );

        let source_words = [u32::from_le_bytes(MOV42_RET[..4].try_into().expect("word"))];
        let loaded = authority
            .load_unit(&pending.key, &source_words)
            .expect("load published unit");
        assert_eq!(loaded.manifest.key, pending.key);
        let stem = pending.key.file_stem().expect("unit stem");
        assert!(authority.final_path(&stem).is_file());
        // The copy transport hands out READABLE source bytes; nothing at
        // this address is executable. The translator copies them into its
        // own MAP_JIT cache.
        let source = unsafe {
            std::slice::from_raw_parts(loaded.source_base.as_ptr(), pending.blocks[0].code.len())
        };
        assert_eq!(source, pending.blocks[0].code.as_ref());
        assert!(
            std::fs::read_dir(authority.path())
                .expect("read cache directory")
                .filter_map(Result::ok)
                .all(|entry| !entry.file_name().to_string_lossy().starts_with(".tmp")),
            "publisher left a temporary file"
        );
    }

    /// The loaded code source must be a plain read-only private mapping —
    /// never executable. Executability belongs exclusively to the process's
    /// MAP_JIT translation cache the bytes are copied into.
    #[test]
    fn loaded_code_uses_a_private_read_only_vm_region() {
        use mach2::vm_prot::VM_PROT_READ;

        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        authority.publish_unit(&pending).expect("publish unit");
        let loaded = authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect("load unit");

        let region = current_region_extended_info(loaded.source_base.as_ptr() as usize);
        assert_eq!(
            region.protection, VM_PROT_READ,
            "code source must map read-only, never executable"
        );
    }

    /// A complete but foreign unit inode must fail its complete key binding.
    #[test]
    fn bundle_rejects_another_units_substituted_inode() {
        let (_store, authority) = persistent_fixture_authority();
        let first = fixture_pending();
        let mut second = fixture_pending();
        // Same length, different bytes: `mov w0, #43 ; ret`.
        second.blocks[0].code[..4].copy_from_slice(&0x5280_0560_u32.to_le_bytes());
        second.key = TranslationUnitKey::for_segment(
            ExecutableIdentity::Digest([0x33; 32]),
            ImageFileOffset::new(0),
            ImageFileLen::new(8).expect("nonzero file length"),
            GuestVa(0x400000),
            GuestCodeLen::new(8).expect("nonzero guest length"),
            SourceFingerprint::from_words(&fixture_source_words()),
            NativePageProfileIdentity::Native16k,
            AddressModeIdentity::biased(
                NativeHostBias::new(0x8000_0000, 16 * 1024).expect("aligned bias"),
            ),
        );
        authority.publish_unit(&first).expect("publish first unit");
        authority
            .publish_unit(&second)
            .expect("publish second unit");
        let first_path = authority.final_path(&first.key.file_stem().expect("first unit stem"));
        let second_path = authority.final_path(&second.key.file_stem().expect("second unit stem"));
        std::fs::copy(second_path, first_path).expect("substitute valid unit inode");

        assert_eq!(
            authority
                .load_unit(&first.key, &fixture_source_words())
                .expect_err("another unit's inode must not load")
                .reason(),
            UnitMissReason::ImageIdentity
        );
    }

    /// The retired `.seen` deferral made the SECOND observer the recorder;
    /// with a persistent store the FIRST claim wins
    /// (`first_file_miss_claims_recording_immediately`) and this test pins
    /// the remaining property: one live claim excludes the herd, and a
    /// finished unit needs no recorder at all.
    #[test]
    fn one_live_recorder_excludes_the_herd() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        let owner = fixture_owner(0x54);

        let claim = match authority
            .claim_recording(&pending.key, &owner)
            .expect("elect first observer")
        {
            ClaimOutcome::Won(claim) => claim,
            outcome => panic!("unexpected claim outcome: {outcome:?}"),
        };
        assert_eq!(claim.owner, owner);
        assert_eq!(
            authority
                .claim_recording(&pending.key, &owner)
                .expect("observe live recorder"),
            ClaimOutcome::LiveOwner,
            "a live recorder must exclude the thundering herd"
        );
        assert_eq!(
            authority
                .merge(&pending, &claim)
                .expect("publish unit")
                .kind,
            MergeKind::Created
        );
        assert!(matches!(
            authority
                .claim_recording(&pending.key, &fixture_owner(0x55))
                .expect("claim against a published unit"),
            ClaimOutcome::Won(_)
        ));
    }

    /// Publication is exactly one deterministic bundle inode — no pair,
    /// Mach-O, signature, or dylib anywhere in the store.
    #[test]
    fn published_unit_is_one_deterministic_bundle() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        assert_eq!(
            authority.publish_unit(&pending).expect("publish unit"),
            PublishOutcome::Winner
        );
        let stem = pending.key.file_stem().expect("unit stem");
        let unit_path = authority.final_path(&stem);
        let expected =
            encode_unit_bundle_v1(&pending.key, &pending.blocks).expect("encode expected bundle");
        assert_eq!(
            std::fs::read(&unit_path).expect("read published unit"),
            expected,
            "published bytes are the deterministic unit-v1 encoding"
        );
        assert_eq!(
            std::fs::metadata(&unit_path)
                .expect("stat published unit")
                .mode()
                & 0o777,
            0o600,
            "the final inode retains the private temporary's mode"
        );
        assert!(
            std::fs::read_dir(authority.path())
                .expect("read cache directory")
                .filter_map(Result::ok)
                .all(|entry| {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    !name.ends_with(".code")
                        && !name.ends_with(".metadata-v5")
                        && !name.ends_with(".dylib")
                }),
            "the atomic transport publishes no retired half or dylib"
        );
    }

    #[test]
    fn load_rejects_a_flipped_code_byte() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        authority.publish_unit(&pending).expect("publish unit");
        let stem = pending.key.file_stem().expect("unit stem");
        let unit_path = authority.final_path(&stem);
        let mut bytes = std::fs::read(&unit_path).expect("read published unit");
        let code_offset = u64::from_le_bytes(bytes[48..56].try_into().expect("code offset"));
        bytes[code_offset as usize] ^= 0x01;
        std::fs::write(&unit_path, bytes).expect("flip one code byte");

        assert_eq!(
            authority
                .load_unit(&pending.key, &fixture_source_words())
                .expect_err("a flipped byte must fail the digest")
                .reason(),
            UnitMissReason::CodeDigest
        );
    }

    #[test]
    fn load_rejects_a_unit_file_with_the_wrong_extent() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        authority.publish_unit(&pending).expect("publish unit");
        let stem = pending.key.file_stem().expect("unit stem");
        let unit_path = authority.final_path(&stem);
        let mut bytes = std::fs::read(&unit_path).expect("read published unit");
        bytes.extend_from_slice(&[0; 4]);
        std::fs::write(&unit_path, bytes).expect("grow the unit file");

        assert_eq!(
            authority
                .load_unit(&pending.key, &fixture_source_words())
                .expect_err("a grown unit file is not the described extent")
                .reason(),
            UnitMissReason::Schema
        );
    }

    #[test]
    fn abi9_ignores_each_lone_abi8_pair_half() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        let stem = pending.key.file_stem().expect("unit stem");
        let code = authority.path().join(format!("{stem}.code"));
        let manifest = authority.path().join(format!("{stem}.metadata-v5"));
        let source_words = [u32::from_le_bytes(MOV42_RET[..4].try_into().expect("word"))];

        std::fs::write(&manifest, b"{}").expect("write lone manifest");
        assert_eq!(
            authority
                .load_unit(&pending.key, &source_words)
                .expect_err("lone manifest must miss")
                .reason(),
            UnitMissReason::MissingPair
        );
        std::fs::remove_file(&manifest).expect("remove lone manifest");
        std::fs::write(&code, MOV42_RET).expect("write lone code file");
        assert_eq!(
            authority
                .load_unit(&pending.key, &source_words)
                .expect_err("lone code file must miss")
                .reason(),
            UnitMissReason::MissingPair
        );
    }

    #[test]
    fn published_unit_maps_whole_bundle_with_mapped_evidence() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();

        assert_eq!(
            authority.publish_unit(&pending).expect("publish unit"),
            PublishOutcome::Winner
        );
        let stem = pending.key.file_stem().expect("unit stem");
        let unit_path = authority.final_path(&stem);
        assert!(unit_path.is_file());

        let loaded = authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect("load unit");
        assert_eq!(loaded.manifest.blocks().len(), 1);
        assert_eq!(loaded.manifest.blocks()[0].guest_start, GuestVa(0x400000));
        // V6 maps the one bundle instead of reading it: untouched cold blobs
        // stay lazy and the same mapping backs code plus on-demand metadata.
        assert_eq!(loaded.load_evidence.bytes_read, 0);
        assert_eq!(
            loaded.load_evidence.bytes_mapped,
            std::fs::metadata(unit_path)
                .expect("stat unit bundle")
                .len()
        );
        assert!(loaded.load_evidence.owned_records > 0);
    }

    #[test]
    fn unit_bundle_maps_the_bounded_open_extent() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        authority.publish_unit(&pending).expect("publish unit");
        let stem = pending.key.file_stem().expect("unit stem");
        let unit_path = authority.final_path(&stem);
        let bounded_len = std::fs::metadata(&unit_path)
            .expect("stat unit bundle before bounded open")
            .len();
        arm_after_bounded_unit_open_for_test({
            let unit_path = unit_path.clone();
            move || {
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(unit_path)
                    .expect("open unit bundle after bounded open")
                    .write_all(&[0xa5; 16])
                    .expect("grow unit bundle after bounded open");
            }
        });

        let loaded = authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect("map only the extent accepted by bounded open");

        assert_eq!(loaded.load_evidence.bytes_mapped, bounded_len);
    }

    #[test]
    fn abi9_ignores_retired_pair_halves_independently() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        let stem = pending.key.file_stem().expect("unit stem");
        let code = authority.path().join(format!("{stem}.code"));
        let metadata = authority.path().join(format!("{stem}.metadata-v5"));

        std::fs::write(&metadata, b"metadata only").expect("write lone V3 metadata");
        assert_eq!(
            authority
                .load_unit(&pending.key, &fixture_source_words())
                .expect_err("lone V3 metadata must miss")
                .reason(),
            UnitMissReason::MissingPair
        );
        std::fs::remove_file(&metadata).expect("remove lone V3 metadata");
        std::fs::write(&code, MOV42_RET).expect("write lone code file");
        assert_eq!(
            authority
                .load_unit(&pending.key, &fixture_source_words())
                .expect_err("lone code file must miss")
                .reason(),
            UnitMissReason::MissingPair
        );
    }

    #[test]
    fn corrupt_unit_v1_magic_is_typed_before_payload_use() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        authority.publish_unit(&pending).expect("publish unit-v1");
        let stem = pending.key.file_stem().expect("unit stem");
        let unit_path = authority.final_path(&stem);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&unit_path)
            .expect("open unit-v1")
            .write_all(b"BROKEN!!")
            .expect("corrupt unit-v1 magic");

        assert_eq!(
            authority
                .load_unit(&pending.key, &fixture_source_words())
                .expect_err("corrupt unit-v1 must fail before payload use")
                .reason(),
            UnitMissReason::Schema
        );
    }

    #[test]
    fn unit_v1_load_pins_one_read_only_private_inode() {
        use mach2::vm_prot::VM_PROT_READ;

        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        let claim = claim_fixture(&authority, &pending, 0x11);
        assert_eq!(
            authority.merge(&pending, &claim).expect("create unit"),
            MergeOutcome {
                kind: MergeKind::Created,
                blocks_added: 1,
                duplicates: 0,
                post_rename_sync_failed: false,
            }
        );

        let loaded = authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect("load unit-v1");
        let region = current_region_extended_info(loaded.source_base.as_ptr() as usize);
        assert_eq!(region.protection, VM_PROT_READ);
        let source = unsafe {
            std::slice::from_raw_parts(loaded.source_base.as_ptr(), pending.blocks[0].code.len())
        };
        assert_eq!(source, pending.blocks[0].code.as_ref());
        let stem = pending.key.file_stem().expect("unit stem");
        assert!(authority.final_path(&stem).is_file());
        assert_eq!(
            std::fs::read_dir(authority.path())
                .expect("read store")
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".unit-v1"))
                .count(),
            1
        );
    }

    #[test]
    fn unit_v1_load_rejects_symlink_directory_and_nonregular_file() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        let stem = pending.key.file_stem().expect("unit stem");
        let final_path = authority.final_path(&stem);
        let target = authority.path().join("foreign");
        std::fs::write(&target, b"foreign").expect("write symlink target");
        std::os::unix::fs::symlink(&target, &final_path).expect("create unit symlink");
        assert_eq!(
            authority
                .load_unit(&pending.key, &fixture_source_words())
                .expect_err("symlink must fail closed")
                .reason(),
            UnitMissReason::Schema
        );
        std::fs::remove_file(&final_path).expect("remove symlink");

        std::fs::create_dir(&final_path).expect("create unit directory");
        assert_eq!(
            authority
                .load_unit(&pending.key, &fixture_source_words())
                .expect_err("directory must fail closed")
                .reason(),
            UnitMissReason::Schema
        );
        std::fs::remove_dir(&final_path).expect("remove unit directory");

        let fifo_path = CString::new(final_path.as_os_str().as_bytes()).expect("path without NUL");
        assert_eq!(
            unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) },
            0,
            "create nonregular unit fifo"
        );
        assert_eq!(
            authority
                .load_unit(&pending.key, &fixture_source_words())
                .expect_err("nonregular file must fail closed")
                .reason(),
            UnitMissReason::Schema
        );
        std::fs::remove_file(final_path).expect("remove unit fifo");
    }

    #[test]
    fn unit_v1_old_reader_survives_atomic_replacement() {
        let (_store, authority) = persistent_fixture_authority();
        let first = fixture_pending();
        let first_claim = claim_fixture(&authority, &first, 0x21);
        authority.merge(&first, &first_claim).expect("create unit");
        let old = authority
            .load_unit(&first.key, &fixture_source_words())
            .expect("load old inode");
        let old_source = old.source_base;

        let second = fixture_pending_at(0x400100, 0x5280_0560);
        let second_claim = claim_fixture(&authority, &second, 0x22);
        assert_eq!(
            authority
                .merge(&second, &second_claim)
                .expect("augment unit")
                .kind,
            MergeKind::Merged
        );

        assert_eq!(old.manifest.blocks().len(), 1);
        let old_bytes =
            unsafe { std::slice::from_raw_parts(old_source.as_ptr(), first.blocks[0].code.len()) };
        assert_eq!(old_bytes, first.blocks[0].code.as_ref());
    }

    #[test]
    fn unit_v1_new_reader_sees_complete_union_after_replacement() {
        let (_store, authority) = persistent_fixture_authority();
        let first = fixture_pending();
        let first_claim = claim_fixture(&authority, &first, 0x31);
        authority.merge(&first, &first_claim).expect("create unit");
        let second = fixture_pending_at(0x400100, 0x5280_0560);
        let second_claim = claim_fixture(&authority, &second, 0x32);
        authority
            .merge(&second, &second_claim)
            .expect("augment unit");

        let loaded = authority
            .load_unit(&first.key, &fixture_source_words())
            .expect("load replacement inode");
        assert_eq!(
            loaded
                .manifest
                .blocks()
                .iter()
                .map(|block| block.guest_start)
                .collect::<Vec<_>>(),
            vec![GuestVa(0x400000), GuestVa(0x400100)]
        );
    }

    #[test]
    fn pruner_counts_and_removes_only_unit_v1_files_in_current_abi() {
        let (store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        let claim = claim_fixture(&authority, &pending, 0x41);
        authority.merge(&pending, &claim).expect("create unit");
        let stem = pending.key.file_stem().expect("unit stem");
        let old_code = store.path().join(format!("{stem}.code"));
        let old_metadata = store.path().join(format!("{stem}.metadata-v5"));
        let uppercase_unit = store.path().join(format!("{}.unit-v1", "A".repeat(64)));
        std::fs::write(&old_code, b"retired code").expect("write retired code");
        std::fs::write(&old_metadata, b"retired metadata").expect("write retired metadata");
        std::fs::write(&uppercase_unit, b"foreign spelling").expect("write uppercase unit");

        prune_store(authority.directory(), store.path(), 0);

        assert!(!authority.final_path(&stem).exists());
        assert!(
            old_code.is_file(),
            "retired suffix is outside ABI-9 pruning"
        );
        assert!(
            old_metadata.is_file(),
            "retired suffix is outside ABI-9 pruning"
        );
        assert!(
            uppercase_unit.is_file(),
            "only the canonical lowercase stem spelling is current-ABI content"
        );
    }

    #[test]
    fn abi9_ignores_abi8_code_and_metadata_v5_pairs() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        let stem = pending.key.file_stem().expect("unit stem");
        std::fs::write(
            authority.path().join(format!("{stem}.code")),
            b"retired ABI-8 code",
        )
        .expect("write retired code");
        std::fs::write(
            authority.path().join(format!("{stem}.metadata-v5")),
            b"retired ABI-8 metadata",
        )
        .expect("write retired metadata");

        assert_eq!(
            authority
                .load_unit(&pending.key, &fixture_source_words())
                .expect_err("ABI-9 must ignore an ABI-8 pair")
                .reason(),
            UnitMissReason::MissingPair
        );
    }

    #[test]
    fn live_owner_blocks_claim_without_waiting() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        assert!(matches!(
            authority
                .claim_recording(&pending.key, &fixture_owner(0x61))
                .expect("first claim"),
            ClaimOutcome::Won(_)
        ));
        let started = std::time::Instant::now();
        assert_eq!(
            authority
                .claim_recording(&pending.key, &fixture_owner(0x62))
                .expect("contending claim"),
            ClaimOutcome::LiveOwner
        );
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
    }

    #[test]
    fn busy_unit_lock_returns_yielded_without_waiting() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        let stem = pending.key.file_stem().expect("unit stem");
        let _held = authority
            .try_lock_unit(&stem)
            .expect("open unit lock")
            .expect("hold unit lock");
        let started = std::time::Instant::now();
        assert_eq!(
            authority
                .claim_recording(&pending.key, &fixture_owner(0x63))
                .expect("busy claim"),
            ClaimOutcome::Yielded
        );
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
    }

    #[test]
    fn dead_aged_malformed_and_future_builder_records_are_taken_over() {
        enum StaleFixture {
            Dead,
            Aged,
            Malformed,
            Future,
        }
        for (index, fixture) in [
            StaleFixture::Dead,
            StaleFixture::Aged,
            StaleFixture::Malformed,
            StaleFixture::Future,
        ]
        .into_iter()
        .enumerate()
        {
            let (_store, authority) = persistent_fixture_authority();
            let pending = fixture_pending();
            let stem = pending.key.file_stem().expect("unit stem");
            let now = unix_now_ns().expect("current Unix time");
            match fixture {
                StaleFixture::Malformed => {
                    let path = authority.path().join(format!("{stem}.builder"));
                    std::fs::write(&path, b"malformed").expect("write malformed builder");
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .expect("set builder mode");
                }
                StaleFixture::Dead | StaleFixture::Aged | StaleFixture::Future => {
                    let (pid, created_unix_ns) = match fixture {
                        StaleFixture::Dead => (i32::MAX, now),
                        StaleFixture::Aged => (
                            unsafe { libc::getpid() },
                            now - i64::try_from(BUILDER_CLAIM_TTL.as_nanos())
                                .expect("TTL fits i64")
                                - 1,
                        ),
                        StaleFixture::Future => {
                            (unsafe { libc::getpid() }, now + 60 * 60 * 1_000_000_000)
                        }
                        StaleFixture::Malformed => unreachable!(),
                    };
                    authority
                        .write_builder(&BuilderRecord {
                            owner: RecordingOwner {
                                pid,
                                incarnation: [0xa0 + index as u8; 16],
                            },
                            created_unix_ns,
                            stem: stem.clone(),
                        })
                        .expect("write stale builder");
                }
            }
            assert!(matches!(
                authority
                    .claim_recording(&pending.key, &fixture_owner(0x70 + index as u8))
                    .expect("take over stale builder"),
                ClaimOutcome::Won(RecordingClaim {
                    stale_takeover: true,
                    ..
                })
            ));
        }
    }

    #[test]
    fn matching_owner_releases_builder_on_every_clean_merge_return() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        let stem = pending.key.file_stem().expect("unit stem");
        let builder = authority.path().join(format!("{stem}.builder"));

        let mut empty = pending.clone();
        empty.blocks.clear();
        let claim = claim_fixture(&authority, &empty, 0x81);
        assert_eq!(
            authority.merge(&empty, &claim).expect("empty merge").kind,
            MergeKind::Unchanged
        );
        assert!(!builder.exists());

        let claim = claim_fixture(&authority, &pending, 0x82);
        assert_eq!(
            authority
                .merge(&pending, &claim)
                .expect("create merge")
                .kind,
            MergeKind::Created
        );
        assert!(!builder.exists());

        let claim = claim_fixture(&authority, &pending, 0x83);
        assert_eq!(
            authority
                .merge(&pending, &claim)
                .expect("duplicate merge")
                .kind,
            MergeKind::Unchanged
        );
        assert!(!builder.exists());

        let mut conflict = pending.clone();
        conflict.blocks[0].code[0] ^= 1;
        let claim = claim_fixture(&authority, &conflict, 0x84);
        assert!(matches!(
            authority
                .merge(&conflict, &claim)
                .expect("conflict merge")
                .kind,
            MergeKind::Refused(MergeRefusal::Conflict { .. })
        ));
        assert!(!builder.exists());
    }

    #[test]
    fn stale_owner_cannot_unlink_successor_builder() {
        let (_store, authority) = persistent_fixture_authority();
        let mut pending = fixture_pending();
        let stale_claim = claim_fixture(&authority, &pending, 0x91);
        let stem = pending.key.file_stem().expect("unit stem");
        let successor = fixture_owner(0x92);
        authority
            .write_builder(&BuilderRecord {
                owner: successor,
                created_unix_ns: unix_now_ns().expect("current Unix time"),
                stem: stem.clone(),
            })
            .expect("install successor builder");
        pending.blocks.clear();

        authority
            .merge(&pending, &stale_claim)
            .expect("stale owner clean return");

        match authority
            .read_builder(&stem)
            .expect("read successor builder")
        {
            BuilderState::Valid(record) => assert_eq!(record.owner, successor),
            _ => panic!("successor builder was removed"),
        }
    }

    #[test]
    fn existing_unit_does_not_refuse_a_new_recording_claim() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        let first = claim_fixture(&authority, &pending, 0xa1);
        authority.merge(&pending, &first).expect("create unit");
        assert!(matches!(
            authority
                .claim_recording(&pending.key, &fixture_owner(0xa2))
                .expect("claim existing unit"),
            ClaimOutcome::Won(_)
        ));
    }

    #[test]
    fn sequential_publishers_reload_and_preserve_both_unions() {
        let (_store, authority) = persistent_fixture_authority();
        let first = fixture_pending();
        let second = fixture_pending_at(0x400100, 0x5280_0560);
        let first_claim = claim_fixture(&authority, &first, 0xb1);
        let second_claim = RecordingClaim {
            owner: fixture_owner(0xb2),
            stale_takeover: false,
        };
        authority.merge(&first, &first_claim).expect("first merge");
        authority
            .merge(&second, &second_claim)
            .expect("second stale-snapshot merge");
        let loaded = authority
            .load_unit(&first.key, &fixture_source_words())
            .expect("load union");
        assert_eq!(loaded.manifest.blocks().len(), 2);
    }

    #[test]
    fn exact_duplicate_merge_is_unchanged_and_counted() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        let first = claim_fixture(&authority, &pending, 0xc1);
        authority.merge(&pending, &first).expect("create unit");
        let duplicate = claim_fixture(&authority, &pending, 0xc2);
        assert_eq!(
            authority
                .merge(&pending, &duplicate)
                .expect("duplicate merge"),
            MergeOutcome {
                kind: MergeKind::Unchanged,
                blocks_added: 0,
                duplicates: 1,
                post_rename_sync_failed: false,
            }
        );
    }

    #[test]
    fn corrupt_final_is_replaced_only_by_valid_pending_data() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        let first = claim_fixture(&authority, &pending, 0xd1);
        authority.merge(&pending, &first).expect("create unit");
        let stem = pending.key.file_stem().expect("unit stem");
        let path = authority.final_path(&stem);
        let mut corrupt = std::fs::read(&path).expect("read unit");
        corrupt[0] ^= 1;
        std::fs::write(&path, corrupt).expect("corrupt final unit");
        let repair = claim_fixture(&authority, &pending, 0xd2);
        assert_eq!(
            authority
                .merge(&pending, &repair)
                .expect("repair unit")
                .kind,
            MergeKind::Repaired
        );
        authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect("load repaired unit");
    }

    #[test]
    fn conflict_capacity_and_preflight_preserve_old_valid_bundle() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        let first = claim_fixture(&authority, &pending, 0xe1);
        authority.merge(&pending, &first).expect("create unit");
        let stem = pending.key.file_stem().expect("unit stem");
        let path = authority.final_path(&stem);
        let original = std::fs::read(&path).expect("read original unit");

        let mut conflict = pending.clone();
        conflict.blocks[0].code[0] ^= 1;
        let claim = claim_fixture(&authority, &conflict, 0xe2);
        assert!(matches!(
            authority.merge(&conflict, &claim).expect("conflict").kind,
            MergeKind::Refused(MergeRefusal::Conflict { .. })
        ));
        assert_eq!(std::fs::read(&path).expect("read after conflict"), original);

        let mut over_cap = fixture_pending_at(0x400100, 0x5280_0560);
        over_cap.blocks[0].code =
            vec![0_u8; MAX_TRANSLATION_UNIT_CODE_BYTES + 4].into_boxed_slice();
        let claim = claim_fixture(&authority, &over_cap, 0xe3);
        assert_eq!(
            authority.merge(&over_cap, &claim).expect("capacity").kind,
            MergeKind::Refused(MergeRefusal::Capacity)
        );
        assert_eq!(std::fs::read(&path).expect("read after capacity"), original);

        let addition = fixture_pending_at(0x400100, 0x5280_0560);
        let claim = claim_fixture(&authority, &addition, 0xe4);
        arm_publication_fault(PublicationFault::BeforePreflight);
        assert!(matches!(
            authority.merge(&addition, &claim).expect("preflight").kind,
            MergeKind::Refused(MergeRefusal::Preflight(_))
        ));
        assert_eq!(
            std::fs::read(&path).expect("read after preflight"),
            original
        );
    }

    #[test]
    fn post_rename_directory_sync_error_keeps_visible_union_and_reports_it() {
        let (_store, authority) = persistent_fixture_authority();
        let first = fixture_pending();
        let claim = claim_fixture(&authority, &first, 0xf1);
        authority.merge(&first, &claim).expect("create unit");
        let second = fixture_pending_at(0x400100, 0x5280_0560);
        let claim = claim_fixture(&authority, &second, 0xf2);
        arm_publication_fault(PublicationFault::DirectorySync);
        let outcome = authority.merge(&second, &claim).expect("merge unit");
        assert_eq!(outcome.kind, MergeKind::Merged);
        assert!(outcome.post_rename_sync_failed);
        let loaded = authority
            .load_unit(&first.key, &fixture_source_words())
            .expect("load visible post-rename union");
        assert_eq!(loaded.manifest.blocks().len(), 2);
    }

    #[test]
    fn pre_rename_faults_leave_every_new_reader_on_the_complete_old_inode() {
        let (_store, authority) = persistent_fixture_authority();
        let first = fixture_pending();
        let claim = claim_fixture(&authority, &first, 0xf3);
        authority.merge(&first, &claim).expect("create unit");
        let stem = first.key.file_stem().expect("unit stem");
        let path = authority.final_path(&stem);
        let original = std::fs::read(&path).expect("read original inode");
        let addition = fixture_pending_at(0x400100, 0x5280_0560);

        for (seed, fault) in [
            (0xf4, PublicationFault::BeforeTempSync),
            (0xf5, PublicationFault::BeforeRename),
        ] {
            let claim = claim_fixture(&authority, &addition, seed);
            arm_publication_fault(fault);
            assert!(authority.merge(&addition, &claim).is_err());
            assert_eq!(std::fs::read(&path).expect("read retained inode"), original);
            let loaded = authority
                .load_unit(&first.key, &fixture_source_words())
                .expect("load complete old inode");
            assert_eq!(loaded.manifest.blocks().len(), 1);
        }
    }
}
