//! Per-host persistent store for portable native AArch64 translations.
//!
//! # The store
//!
//! Units live in ONE host directory (`persistent_store_root`: the
//! `~/.carrick` convention, translator-ABI versioned) that outlives every
//! container: a unit is published once per key ever, every later exec of
//! the same binary — in this run or any future one — attaches instead of
//! translating, and the unit key's content bindings (`source_fingerprint`
//! over the mapped text, `code_sha256` over the published bytes) keep a
//! stale or colliding unit from ever executing. Recording is elected
//! first-miss-claims per unit (`claim_recording`), publication is
//! winner-takes-all under a non-blocking per-unit `flock`, and a
//! size-capped LRU prune runs once per container begin. A host whose cache
//! directory cannot be prepared falls back to the pre-persistence per-run
//! tempdir.
//!
//! # The transport
//!
//! A published unit is a PAIR of plain files in the store:
//! `{stem}.code` (the concatenated per-block NATIVE-EMISSION template words,
//! relocation immediates zeroed) and `{stem}.metadata-v5` (the serialized
//! manifest: per-block relocations, trusted entries, direct links, PC maps,
//! and recovery, carrying `code_sha256` over the exact code bytes). Loading
//! maps the code read-only, digest-verifies it against the metadata, and
//! hands both to the translator, which REPLAYS each block into its own
//! per-process `MAP_JIT` translation cache through `publish_emitted` — an
//! installed block is indistinguishable from a natively-translated one.
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
//! Both halves are written to `NamedTempFile`s, flushed, fsync'd, preflighted
//! through the READER (metadata), and atomically renamed into place — a
//! half-written unit is never loadable, and the digest binds the code file
//! to the metadata that describes it (a stale orphan from a crashed publish
//! can never pair with fresh metadata).

use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use carrick_dsr_aarch64::shared_cache::ManifestDefect;
pub use carrick_dsr_aarch64::shared_cache::PublishOutcome;
use carrick_dsr_aarch64::shared_cache::{
    MAX_TRANSLATION_UNIT_CODE_BYTES, PendingTranslationUnit, SourceFingerprint,
    TranslationMetadataLoadEvidence, TranslationUnitKey, TranslationUnitManifest, UnitMissReason,
    decode_translation_unit_metadata, encode_translation_unit_metadata,
    shared_source_fingerprint_reuse_enabled,
};
use sha2::{Digest, Sha256};

const AUTHORITY_MARKER: &str = ".carrick-authority";
const AUTHORITY_NONCE_LEN: usize = 16;
const MANIFEST_DECODE_LIMIT: usize = 256 * 1024 * 1024;
const MAX_MAPPED_METADATA_BYTES: u64 = MANIFEST_DECODE_LIMIT as u64;
/// A recording claim older than this is stale even if its pid looks alive:
/// pids recycle across the runs a persistent store outlives, and no
/// legitimate recorder runs this long before publishing at exit or exec.
const BUILDER_CLAIM_TTL: std::time::Duration = std::time::Duration::from_secs(10 * 60);
/// Total `{stem}.code` + `{stem}.metadata-v5` bytes the store may retain;
/// beyond it the oldest pairs (by modification time, refreshed on load) are
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

/// One published unit pair as the pruner sees it.
struct StoredPair {
    stem: String,
    bytes: u64,
    newest_modified: std::time::SystemTime,
}

/// Bound the store: remove crash leftovers (aged temporaries, orphaned
/// election files, half pairs, the retired `.seen` markers) and evict the
/// oldest complete pairs until total pair bytes fit under `cap_bytes`.
/// Best-effort by design — every removal races benignly with concurrent
/// runs (loads pin inodes; a vanished pair is an ordinary miss), so errors
/// are swallowed rather than failing the container.
fn prune_store(directory: &File, path: &Path, cap_bytes: u64) {
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    let mut code_halves = std::collections::BTreeMap::new();
    let mut metadata_halves = std::collections::BTreeMap::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name == AUTHORITY_MARKER {
            continue;
        }
        let Ok(identity) = entry.metadata() else {
            continue;
        };
        let age = identity
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .unwrap_or_default();
        if let Some(stem) = name.strip_suffix(".code") {
            code_halves.insert(stem.to_owned(), identity);
        } else if let Some(stem) = name.strip_suffix(".metadata-v5") {
            metadata_halves.insert(stem.to_owned(), identity);
        } else if name.ends_with(".seen") || name.ends_with(".metadata-v3") {
            // Retired formats: the recurrence-deferral marker and the
            // pre-native-tap mapped metadata. Never produced again.
            let _ = std::fs::remove_file(entry.path());
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
    let mut pairs = Vec::new();
    let mut total_bytes = 0_u64;
    for (stem, code_identity) in &code_halves {
        let Some(metadata_identity) = metadata_halves.get(stem) else {
            // A half pair is either a publication in flight (young) or a
            // crash leftover (old). Only the old ones are removable.
            if code_identity
                .modified()
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age > TEMP_FILE_TTL)
            {
                let _ = std::fs::remove_file(path.join(format!("{stem}.code")));
            }
            continue;
        };
        let bytes = code_identity.len().saturating_add(metadata_identity.len());
        let newest_modified = code_identity
            .modified()
            .ok()
            .into_iter()
            .chain(metadata_identity.modified().ok())
            .max()
            .unwrap_or(std::time::UNIX_EPOCH);
        total_bytes = total_bytes.saturating_add(bytes);
        pairs.push(StoredPair {
            stem: stem.clone(),
            bytes,
            newest_modified,
        });
    }
    for (stem, metadata_identity) in &metadata_halves {
        if !code_halves.contains_key(stem)
            && metadata_identity
                .modified()
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age > TEMP_FILE_TTL)
        {
            let _ = std::fs::remove_file(path.join(format!("{stem}.metadata-v5")));
        }
    }
    if total_bytes <= cap_bytes {
        return;
    }
    pairs.sort_by_key(|pair| pair.newest_modified);
    for pair in pairs {
        if total_bytes <= cap_bytes {
            break;
        }
        // Evict under the unit lock so a concurrent publisher or claimant of
        // this stem is not raced; busy means in use — skip it this round.
        let Some(lock) = try_lock_stem_for_prune(directory, path, &pair.stem) else {
            continue;
        };
        let _ = std::fs::remove_file(path.join(format!("{}.code", pair.stem)));
        let _ = std::fs::remove_file(path.join(format!("{}.metadata-v5", pair.stem)));
        let _ = std::fs::remove_file(path.join(format!("{}.builder", pair.stem)));
        drop(lock);
        let _ = std::fs::remove_file(path.join(format!("{}.lock", pair.stem)));
        total_bytes = total_bytes.saturating_sub(pair.bytes);
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
    static AFTER_BOUNDED_METADATA_OPEN_FOR_TEST: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static LAST_MAPPED_METADATA_ADDRESS_FOR_TEST: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(test)]
fn arm_after_bounded_metadata_open_for_test(hook: impl FnOnce() + 'static) {
    AFTER_BOUNDED_METADATA_OPEN_FOR_TEST.with(|armed| {
        assert!(
            armed.borrow_mut().replace(Box::new(hook)).is_none(),
            "bounded metadata-open hook was already armed"
        );
    });
}

#[cfg(test)]
fn run_after_bounded_metadata_open_for_test() {
    AFTER_BOUNDED_METADATA_OPEN_FOR_TEST.with(|armed| {
        if let Some(hook) = armed.borrow_mut().take() {
            hook();
        }
    });
}

#[derive(Debug)]
pub struct UnitStoreError {
    operation: &'static str,
    reason: UnitMissReason,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl UnitStoreError {
    fn new(operation: &'static str, reason: UnitMissReason) -> Self {
        Self {
            operation,
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
            reason,
            source: Some(Box::new(source)),
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
    // Fields drop in declaration order. Release the source lease (the code
    // file mapping) last, after nothing else can reference it.
    lease: Arc<CodeSourceLease>,
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

/// Pins one loaded unit's backing: the read-only private mapping of
/// `{stem}.code` (and the inode under it, which publication never writes in
/// place — only whole-file renames).
#[derive(Debug)]
struct CodeSourceLease {
    _mapping: memmap2::Mmap,
    _file: File,
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
fn open_metadata_at(directory: &File, name: &CStr) -> Result<(File, usize), UnitStoreError> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        let reason = if error.raw_os_error() == Some(libc::ENOENT) {
            UnitMissReason::MissingPair
        } else {
            UnitMissReason::Schema
        };
        return Err(UnitStoreError::with_source(
            "open mapped metadata",
            reason,
            error,
        ));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(UnitStoreError::with_source(
            "stat mapped metadata",
            UnitMissReason::Schema,
            std::io::Error::last_os_error(),
        ));
    }
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(UnitStoreError::new(
            "validate mapped metadata file type",
            UnitMissReason::Schema,
        ));
    }
    let length = u64::try_from(status.st_size).map_err(|_| {
        UnitStoreError::new(
            "validate mapped metadata size",
            UnitMissReason::ManifestRange,
        )
    })?;
    if length == 0 || length > MAX_MAPPED_METADATA_BYTES {
        return Err(UnitStoreError::new(
            "validate mapped metadata size",
            UnitMissReason::ManifestRange,
        ));
    }
    let length = usize::try_from(length).map_err(|_| {
        UnitStoreError::new(
            "validate mapped metadata size",
            UnitMissReason::ManifestRange,
        )
    })?;
    Ok((file, length))
}

/// Open one published unit half by name inside the authority directory:
/// `O_NOFOLLOW`, regular-file-only, with its exact byte length. `ENOENT` is a
/// `MissingPair` (a genuine cache miss); everything else is schema-shaped.
fn open_unit_regular_file_at(
    directory: &File,
    name: &CStr,
) -> Result<(File, usize), UnitStoreError> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        let reason = if error.raw_os_error() == Some(libc::ENOENT) {
            UnitMissReason::MissingPair
        } else {
            UnitMissReason::Schema
        };
        return Err(UnitStoreError::with_source(
            "open translation code",
            reason,
            error,
        ));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(UnitStoreError::with_source(
            "stat translation code",
            UnitMissReason::Schema,
            std::io::Error::last_os_error(),
        ));
    }
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(UnitStoreError::new(
            "validate translation code file type",
            UnitMissReason::Schema,
        ));
    }
    let length = u64::try_from(status.st_size)
        .ok()
        .and_then(|length| usize::try_from(length).ok())
        .ok_or_else(|| {
            UnitStoreError::new(
                "validate translation code size",
                UnitMissReason::ManifestRange,
            )
        })?;
    Ok((file, length))
}

/// Map and validate one unit's serialized metadata through the READER path
/// (used both at load and as the publish preflight): decode the header and
/// fixed-width index fail-closed, require the exact expected key, and
/// re-run the INDEX invariants. Per-block blobs stay undecoded — this is
/// what makes the per-exec attach proportional to the block count instead
/// of the metadata size. The publish preflight layers `validate_deep` on
/// top (see `publish_unit`); a corrupt blob served to a loader fails
/// closed at that block's replay.
///
/// The mmap (not a read) is load-bearing twice over: the manifest keeps
/// the mapping alive for on-demand blob decode, and untouched cold bytes
/// are never paged in at all.
fn read_and_validate_metadata(
    directory: &File,
    name: &CStr,
    expected_key: &TranslationUnitKey,
) -> Result<
    (
        Arc<TranslationUnitManifest>,
        TranslationMetadataLoadEvidence,
    ),
    UnitStoreError,
> {
    let (file, length) = open_metadata_at(directory, name)?;
    #[cfg(test)]
    run_after_bounded_metadata_open_for_test();
    // SAFETY: `map_copy_read_only` requests `MAP_PRIVATE|PROT_READ`. The
    // private cache authority never writes a published inode in place
    // (publication and repair replace pathnames by whole-file rename), the
    // mmap length is the exact bounded extent accepted by the fstat in
    // `open_metadata_at` (a test-only seam may append past it; the mapping
    // cannot see those bytes), and the mapping is kept alive inside the
    // manifest for the lifetime of every on-demand blob decode.
    let mapping = unsafe {
        memmap2::MmapOptions::new()
            .len(length)
            .map_copy_read_only(&file)
    }
    .map_err(|error| {
        UnitStoreError::with_source("map unit metadata", UnitMissReason::Schema, error)
    })?;
    let validation_started = std::time::Instant::now();
    let manifest = decode_translation_unit_metadata(Arc::new(mapping))
        .map_err(|reason| UnitStoreError::new("decode unit metadata", reason))?;
    if manifest.key != *expected_key {
        return Err(UnitStoreError::new(
            "validate unit metadata key",
            UnitMissReason::ImageIdentity,
        ));
    }
    manifest
        .validate_ranges()
        .map_err(|reason| UnitStoreError::new("validate unit metadata ranges", reason))?;
    let validation_ns = u64::try_from(validation_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let owned_records = manifest.blocks().len() as u64;
    Ok((
        Arc::new(manifest),
        TranslationMetadataLoadEvidence {
            bytes_read: 0,
            bytes_mapped: u64::try_from(length).unwrap_or(u64::MAX),
            validation_ns,
            owned_records,
        },
    ))
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
    /// The directory outlives every container: publication is publish-once
    /// per unit key FOREVER, and a second `carrick run` of the same image
    /// attaches instead of translating. The authority nonce lives in the
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

    pub fn publish_unit(
        &self,
        pending: &PendingTranslationUnit,
    ) -> Result<PublishOutcome, UnitStoreError> {
        let (pending_code, pending_blocks) = pending.pack_legacy_pair().map_err(|error| {
            UnitStoreError::with_source(
                "pack pending legacy pair",
                UnitMissReason::Schema,
                invalid_data(format!("{error:?}")),
            )
        })?;
        if pending_code.is_empty() {
            return Ok(PublishOutcome::Existing);
        }
        if pending_code.len() > MAX_TRANSLATION_UNIT_CODE_BYTES
            || !pending_code.len().is_multiple_of(4)
        {
            return Err(UnitStoreError::new(
                "validate pending unit",
                UnitMissReason::ManifestRange,
            ));
        }
        // Digest the raw code FIRST so the metadata half binds the exact
        // bytes the code half will carry: a loader that ever pairs a stale
        // orphan with fresh metadata fails the digest instead of running
        // code its metadata does not describe.
        let code_sha256: [u8; 32] = Sha256::digest(&pending_code).into();
        let metadata_bytes = Arc::new(
            encode_translation_unit_metadata(
                &pending.key,
                code_sha256,
                pending_code.len() as u64,
                &pending_blocks,
            )
            .map_err(|error| {
                tracing::warn!(
                    blocks = pending.blocks.len(),
                    error = ?error,
                    "unit metadata encode rejected a freshly packed unit"
                );
                UnitStoreError::with_source(
                    "encode unit metadata",
                    UnitMissReason::Schema,
                    invalid_data(format!("{error:?}")),
                )
            })?,
        );
        let manifest = decode_translation_unit_metadata(
            Arc::clone(&metadata_bytes) as Arc<dyn AsRef<[u8]> + Send + Sync>
        )
        .map_err(|reason| UnitStoreError::new("decode freshly encoded unit metadata", reason))?;
        // Name the broken invariant. This preflight rejects a unit CARRICK
        // ITSELF just built, so "ManifestRange" alone says only that the
        // producer and its validator disagree - which is exactly the state a
        // cold go build has been in (33 publication attempts, 0 units, 30 of
        // them ManifestRange with no further detail). `validate_deep`
        // decodes EVERY hot and cold blob: publication is rare and off the
        // hot path, and it is the last moment a producer/reader
        // disagreement can be named rather than read as a store that never
        // loads.
        if let Err(defect) = manifest.validate_deep() {
            return Err(UnitStoreError::new(
                match defect {
                    ManifestDefect::Schema => "validate pending unit: schema",
                    ManifestDefect::TranslatorAbi => "validate pending unit: translator abi",
                    ManifestDefect::BaseExport => "validate pending unit: base export",
                    ManifestDefect::CodeLen => "validate pending unit: code length",
                    ManifestDefect::BlockGeometry => "validate pending unit: block geometry",
                    ManifestDefect::BlockGuestDuplicate => {
                        "validate pending unit: duplicate block guest start"
                    }
                    ManifestDefect::BlockExtentOverlap => {
                        "validate pending unit: overlapping block extents"
                    }
                    ManifestDefect::BlockTemplate => {
                        "validate pending unit: block template metadata"
                    }
                },
                defect.reason(),
            ));
        }
        let stem = pending.key.file_stem().map_err(|error| {
            UnitStoreError::with_source("derive unit filename", UnitMissReason::Schema, error)
        })?;
        // Winner selection precedes all file emission. Toolchain workloads
        // retire many identical siblings at once; every loser should pay one
        // lock round-trip, not a full unit emission — and a HELD lock means a
        // rival is emitting this same unit right now, so yielding (not
        // waiting) is the correct, non-blocking answer.
        let Some(_lock) = self.try_lock_unit(&stem)? else {
            return Ok(PublishOutcome::Yielded);
        };
        let (final_code, final_metadata) = self.final_paths(&stem);
        if final_code.is_file() && final_metadata.is_file() {
            return Ok(PublishOutcome::Existing);
        }
        if final_code.exists() {
            std::fs::remove_file(&final_code).map_err(|error| {
                UnitStoreError::with_source(
                    "remove partial code file",
                    UnitMissReason::MissingPair,
                    error,
                )
            })?;
        }
        if final_metadata.exists() {
            std::fs::remove_file(&final_metadata).map_err(|error| {
                UnitStoreError::with_source(
                    "remove partial metadata",
                    UnitMissReason::MissingPair,
                    error,
                )
            })?;
        }
        let mut code_temp = tempfile::NamedTempFile::new_in(&self.path).map_err(|error| {
            UnitStoreError::with_source("create code temporary", UnitMissReason::MissingPair, error)
        })?;
        code_temp.write_all(&pending_code).map_err(|error| {
            UnitStoreError::with_source("write code temporary", UnitMissReason::MissingPair, error)
        })?;
        code_temp.flush().map_err(|error| {
            UnitStoreError::with_source("flush code temporary", UnitMissReason::MissingPair, error)
        })?;
        code_temp.as_file().sync_all().map_err(|error| {
            UnitStoreError::with_source("sync code temporary", UnitMissReason::MissingPair, error)
        })?;
        let mut metadata_temp = tempfile::NamedTempFile::new_in(&self.path).map_err(|error| {
            UnitStoreError::with_source(
                "create metadata temporary",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        metadata_temp.write_all(&metadata_bytes).map_err(|error| {
            UnitStoreError::with_source(
                "write metadata temporary",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        metadata_temp.flush().map_err(|error| {
            UnitStoreError::with_source(
                "flush metadata temporary",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        metadata_temp.as_file().sync_all().map_err(|error| {
            UnitStoreError::with_source(
                "sync metadata temporary",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        // Preflight the unit through the READER before it is published, so a
        // producer/reader disagreement fails here instead of silently yielding
        // a store that never loads.
        let temporary_name = metadata_temp
            .path()
            .file_name()
            .ok_or_else(|| {
                UnitStoreError::new("derive metadata temporary name", UnitMissReason::Schema)
            })?
            .as_bytes();
        let temporary_name = CString::new(temporary_name).map_err(|error| {
            UnitStoreError::with_source(
                "encode metadata temporary name",
                UnitMissReason::Schema,
                error,
            )
        })?;
        let _validated =
            read_and_validate_metadata(&self.directory, &temporary_name, &pending.key)?;

        std::fs::rename(code_temp.path(), &final_code).map_err(|error| {
            UnitStoreError::with_source("publish code", UnitMissReason::MissingPair, error)
        })?;
        std::fs::rename(metadata_temp.path(), &final_metadata).map_err(|error| {
            UnitStoreError::with_source("publish metadata", UnitMissReason::MissingPair, error)
        })?;
        Ok(PublishOutcome::Winner)
    }

    /// Elect the ONE process that records portable templates for this unit.
    ///
    /// The first process to miss claims immediately: with a persistent store
    /// the publication amortizes across every future exec and run, so the
    /// retired `.seen` deferral ("prove the unit recurs first") only delayed
    /// the unit past the second exec's exit — too late for a parallel
    /// build's serial exec trains. A live claim (its `.builder` pid alive
    /// and the file younger than `BUILDER_CLAIM_TTL`) blocks rivals, so
    /// concurrent processes translate privately WITHOUT recording or
    /// publishing; a dead or aged claim is taken over. Never blocks: a busy
    /// unit lock means another process is deciding right now, and "do not
    /// record" is always a correct answer.
    pub fn claim_recording(&self, key: &TranslationUnitKey) -> Result<bool, UnitStoreError> {
        let stem = key.file_stem().map_err(|error| {
            UnitStoreError::with_source("derive unit filename", UnitMissReason::Schema, error)
        })?;
        let Some(_lock) = self.try_lock_unit(&stem)? else {
            return Ok(false);
        };
        let (code, metadata) = self.final_paths(&stem);
        if code.is_file() && metadata.is_file() {
            return Ok(false);
        }
        let builder = self.path.join(format!("{stem}.builder"));
        let claim_is_live = std::fs::metadata(&builder).is_ok_and(|identity| {
            let fresh = identity
                .modified()
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age < BUILDER_CLAIM_TTL);
            // A pid recycled across runs can stay "alive" forever against a
            // persistent store; age above is the final arbiter.
            fresh
                && std::fs::read_to_string(&builder)
                    .ok()
                    .and_then(|owner| owner.trim().parse::<i32>().ok())
                    .is_some_and(|owner| {
                        let rc = unsafe { libc::kill(owner, 0) };
                        rc == 0
                            || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
                    })
        });
        if claim_is_live {
            return Ok(false);
        }
        let mut builder_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(builder)
            .map_err(|error| {
                UnitStoreError::with_source(
                    "claim unit recording",
                    UnitMissReason::MissingPair,
                    error,
                )
            })?;
        write!(builder_file, "{}", unsafe { libc::getpid() }).map_err(|error| {
            UnitStoreError::with_source(
                "write unit recording owner",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        builder_file.flush().map_err(|error| {
            UnitStoreError::with_source(
                "flush unit recording owner",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        Ok(true)
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
        let (code_path, metadata_path) = self.final_paths(&stem);
        if !code_path.is_file() || !metadata_path.is_file() {
            return Err(UnitStoreError::new(
                "locate translation unit",
                UnitMissReason::MissingPair,
            ));
        }
        let metadata_name = CString::new(format!("{stem}.metadata-v5")).map_err(|error| {
            UnitStoreError::with_source("encode unit metadata name", UnitMissReason::Schema, error)
        })?;
        let (manifest, load_evidence) =
            read_and_validate_metadata(&self.directory, &metadata_name, expected_key)?;
        if !shared_source_fingerprint_reuse_enabled()
            && expected_key.source_fingerprint() != SourceFingerprint::from_words(source_words)
        {
            return Err(UnitStoreError::new(
                "validate unit source",
                UnitMissReason::SourceFingerprint,
            ));
        }
        let code_len = usize::try_from(manifest.code_len).map_err(|_| {
            UnitStoreError::new(
                "validate translation code length",
                UnitMissReason::ManifestRange,
            )
        })?;
        let code_name = CString::new(format!("{stem}.code")).map_err(|error| {
            UnitStoreError::with_source("encode code name", UnitMissReason::Schema, error)
        })?;
        let (code_file, code_file_len) = open_unit_regular_file_at(&self.directory, &code_name)?;
        // The file must be EXACTLY the declared code extent: publication
        // writes nothing else into it, so any difference means it is not the
        // file this metadata describes.
        if code_file_len != code_len || code_len == 0 || code_len > MAX_TRANSLATION_UNIT_CODE_BYTES
        {
            return Err(UnitStoreError::new(
                "validate translation code extent",
                UnitMissReason::ManifestRange,
            ));
        }
        // SAFETY: `map_copy_read_only` requests `MAP_PRIVATE|PROT_READ`. The
        // private cache authority never writes a published inode in place
        // (publication and repair replace pathnames by whole-file rename),
        // the mmap length is the exact bounded extent accepted by the fstat
        // in `open_unit_regular_file_at`, and `_file` pins the inode for the
        // mapping's lifetime.
        let mapping = unsafe {
            memmap2::MmapOptions::new()
                .len(code_len)
                .map_copy_read_only(&code_file)
        }
        .map_err(|error| {
            UnitStoreError::with_source("map translation code", UnitMissReason::CodeMapping, error)
        })?;
        // The digest binds this code file to this metadata: a mismatch means
        // a stale orphan or torn repair race, and running such bytes under
        // this metadata's pc-maps would be memory-unsafe.
        let digest: [u8; 32] = Sha256::digest(&mapping[..]).into();
        if digest != manifest.code_sha256 {
            return Err(UnitStoreError::new(
                "verify translation code digest",
                UnitMissReason::CodeDigest,
            ));
        }
        // Refresh the pair's modification time so the pruner's LRU order
        // reflects USE, not publication age. Timestamps only: the mapped
        // content bytes are still never written in place. Best-effort — a
        // failed touch costs eviction order, never correctness.
        let _ = unsafe { libc::futimens(code_file.as_raw_fd(), std::ptr::null()) };
        let source_base = std::ptr::NonNull::new(mapping.as_ptr().cast_mut()).ok_or_else(|| {
            UnitStoreError::new("map translation code", UnitMissReason::CodeMapping)
        })?;
        Ok(LoadedTranslationUnit {
            lease: Arc::new(CodeSourceLease {
                _mapping: mapping,
                _file: code_file,
            }),
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
                UnitStoreError::with_source("open unit lock", UnitMissReason::MissingPair, error)
            })?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Ok(None);
            }
            return Err(UnitStoreError::with_source(
                "lock unit",
                UnitMissReason::MissingPair,
                error,
            ));
        }
        Ok(Some(UnitFileLock(lock)))
    }

    fn final_paths(&self, stem: &str) -> (PathBuf, PathBuf) {
        (
            self.path.join(format!("{stem}.code")),
            self.path.join(format!("{stem}.metadata-v5")),
        )
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

    fn publish(&self, pending: &PendingTranslationUnit) -> Result<PublishOutcome, UnitMissReason> {
        let active = CONTAINER_CACHE
            .lock()
            .map_err(|_| UnitMissReason::StoreUnavailable)?;
        let authority = active.as_ref().ok_or(UnitMissReason::NoAuthority)?;
        authority.publish_unit(pending).map_err(|error| {
            // The trait returns a bare reason, so the context naming WHICH
            // invariant broke would be lost right here - and publication
            // failing silently is exactly how this lane published zero units
            // across an entire build without anyone noticing. Surface it
            // before narrowing.
            tracing::warn!(
                error = %error,
                reason = ?error.reason(),
                "shared translation rejected a unit carrick itself built"
            );
            error.reason()
        })
    }

    fn claim_recording(&self, key: &TranslationUnitKey) -> bool {
        CONTAINER_CACHE
            .lock()
            .ok()
            .and_then(|active| {
                active
                    .as_ref()
                    .and_then(|authority| authority.claim_recording(key).ok())
            })
            .unwrap_or(false)
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
        NativePageProfileIdentity, PortableBlockCandidate, SourceFingerprint,
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
            ImageFileLen::new(8).expect("nonzero file length"),
            GuestVa(0x400000),
            GuestCodeLen::new(8).expect("nonzero guest length"),
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
        assert_eq!(
            observed, requested,
            "metadata address must begin its region"
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

    /// With a persistent store, publish-once amortizes across every future
    /// run and exec, so the first process to MISS a unit must claim its
    /// recording. The retired `.seen` deferral ("prove the unit recurs in
    /// this container first") pushed publication past the SECOND exec's exit
    /// — on the parallel build shape that is "within-build reuse arrives too
    /// late" (2026-08-03 scoreboard correction).
    #[test]
    fn first_file_miss_claims_recording_immediately() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        assert!(
            authority
                .claim_recording(&pending.key)
                .expect("first claim"),
            "the first process to miss must claim recording"
        );
        // The claim is sticky: the same (still live) claimant blocks rivals.
        assert!(
            !authority
                .claim_recording(&pending.key)
                .expect("second claim"),
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
            authority
                .claim_recording(&pending.key)
                .expect("claim over stale builder"),
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
        assert!(
            !second
                .claim_recording(&pending.key)
                .expect("claim against a published unit"),
            "a published unit needs no recorder"
        );
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

    /// A truncated metadata half — a torn copy, a bad disk — must fail
    /// closed to a load miss reason, never a panic, and the pair must
    /// remain repairable by a later publish.
    #[test]
    fn corrupt_metadata_fails_closed_and_republish_repairs() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        assert_eq!(
            authority.publish_unit(&pending).expect("publish unit"),
            PublishOutcome::Winner
        );
        let stem = pending.key.file_stem().expect("unit stem");
        let metadata_path = authority.path().join(format!("{stem}.metadata-v5"));
        let intact = std::fs::read(&metadata_path).expect("read metadata");
        std::fs::write(&metadata_path, &intact[..intact.len() / 2]).expect("truncate metadata");

        let error = authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect_err("truncated metadata must not load");
        assert_ne!(error.reason(), UnitMissReason::MissingPair);

        // The pair exists (corrupt), so publish takes the repair path:
        // remove-and-replace under the unit lock.
        std::fs::remove_file(authority.path().join(format!("{stem}.code")))
            .expect("break the pair so publish repairs it");
        assert_eq!(
            authority.publish_unit(&pending).expect("republish"),
            PublishOutcome::Winner
        );
        authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect("repaired unit loads");
    }

    /// The size cap evicts oldest-used pairs first and leaves the store
    /// under the cap; the authority marker survives pruning.
    #[test]
    fn prune_evicts_oldest_pairs_down_to_the_cap() {
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
        for suffix in [".code", ".metadata-v5"] {
            set_file_age(
                &store.path().join(format!("{old_stem}{suffix}")),
                std::time::Duration::from_secs(3 * 60 * 60),
            );
        }

        // A cap of one byte forces eviction of everything not in use; the
        // oldest pair goes first and eviction stops at the cap — here after
        // both, so assert the ORDER by capping between the two pair sizes.
        let pair_bytes = |stem: &str| -> u64 {
            [".code", ".metadata-v5"]
                .iter()
                .map(|suffix| {
                    std::fs::metadata(store.path().join(format!("{stem}{suffix}")))
                        .expect("pair half")
                        .len()
                })
                .sum()
        };
        let keep_bytes = pair_bytes(&new_stem);
        prune_store(authority.directory(), store.path(), keep_bytes);

        assert!(
            !store.path().join(format!("{old_stem}.code")).exists(),
            "the oldest pair must be evicted"
        );
        assert!(
            store.path().join(format!("{new_stem}.code")).is_file(),
            "the newest pair must survive"
        );
        assert!(store.path().join(AUTHORITY_MARKER).is_file());
        authority
            .load_unit(&new.key, &fixture_source_words())
            .expect("survivor still loads");
    }

    /// Legacy `.seen` markers (the retired recurrence deferral) and aged
    /// publication temporaries are crash leftovers the pruner removes.
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

        assert!(!seen.exists(), "legacy .seen markers are always removed");
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
        // The loser either saw the winner's finished pair (Existing) or its
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
        assert!(
            authority
                .path()
                .join(format!("{stem}.metadata-v5"))
                .is_file()
        );
        // The copy transport hands out READABLE source bytes; nothing at
        // this address is executable. The translator copies them into its
        // own MAP_JIT cache.
        let (pending_code, _) = pending.pack_legacy_pair().expect("pack fixture code");
        let source =
            unsafe { std::slice::from_raw_parts(loaded.source_base.as_ptr(), pending_code.len()) };
        assert_eq!(source, pending_code.as_slice());
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

    /// The digest in the metadata binds the code file to the metadata that
    /// describes it: swapping in another unit's (equally valid) code file
    /// must fail the digest, not run bytes under the wrong pc-maps.
    #[test]
    fn code_digest_rejects_another_units_substituted_code_file() {
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
        let (first_code, _) =
            authority.final_paths(&first.key.file_stem().expect("first unit stem"));
        let (second_code, _) =
            authority.final_paths(&second.key.file_stem().expect("second unit stem"));
        std::fs::copy(second_code, first_code).expect("substitute valid code file");

        assert_eq!(
            authority
                .load_unit(&first.key, &fixture_source_words())
                .expect_err("another unit's code file must not load")
                .reason(),
            UnitMissReason::CodeDigest
        );
    }

    /// The retired `.seen` deferral made the SECOND observer the recorder;
    /// with a persistent store the FIRST claim wins
    /// (`first_file_miss_claims_recording_immediately`) and this test pins
    /// the remaining property: one live claim excludes the herd, and a
    /// finished pair needs no recorder at all.
    #[test]
    fn one_live_recorder_excludes_the_herd() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();

        assert!(
            authority
                .claim_recording(&pending.key)
                .expect("elect first observer"),
            "the first process to miss owns recording"
        );
        assert!(
            !authority
                .claim_recording(&pending.key)
                .expect("observe live recorder"),
            "a live recorder must exclude the thundering herd"
        );
        assert_eq!(
            authority.publish_unit(&pending).expect("publish unit"),
            PublishOutcome::Winner
        );
        assert!(
            !authority
                .claim_recording(&pending.key)
                .expect("claim against a published unit"),
            "a published unit needs no recorder"
        );
    }

    /// The published pair is raw code beside mapped metadata — no Mach-O, no
    /// signature, no dylib anywhere in the store.
    #[test]
    fn published_pair_is_raw_code_beside_mapped_metadata() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        assert_eq!(
            authority.publish_unit(&pending).expect("publish unit"),
            PublishOutcome::Winner
        );
        let stem = pending.key.file_stem().expect("unit stem");
        let (code_path, metadata_path) = authority.final_paths(&stem);
        let (pending_code, _) = pending.pack_legacy_pair().expect("pack fixture code");
        assert_eq!(
            std::fs::read(&code_path).expect("read published code"),
            pending_code,
            "the code half is the raw translated bytes, verbatim"
        );
        assert!(metadata_path.is_file());
        assert!(
            std::fs::read_dir(authority.path())
                .expect("read cache directory")
                .filter_map(Result::ok)
                .all(|entry| !entry.file_name().to_string_lossy().ends_with(".dylib")),
            "the copy transport publishes no dylib"
        );
    }

    #[test]
    fn load_rejects_a_flipped_code_byte() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        authority.publish_unit(&pending).expect("publish unit");
        let stem = pending.key.file_stem().expect("unit stem");
        let (code_path, _) = authority.final_paths(&stem);
        let mut bytes = std::fs::read(&code_path).expect("read published code");
        bytes[0] ^= 0x01;
        std::fs::write(&code_path, bytes).expect("flip one code byte");

        assert_eq!(
            authority
                .load_unit(&pending.key, &fixture_source_words())
                .expect_err("a flipped byte must fail the digest")
                .reason(),
            UnitMissReason::CodeDigest
        );
    }

    #[test]
    fn load_rejects_a_code_file_with_the_wrong_extent() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        authority.publish_unit(&pending).expect("publish unit");
        let stem = pending.key.file_stem().expect("unit stem");
        let (code_path, _) = authority.final_paths(&stem);
        let mut bytes = std::fs::read(&code_path).expect("read published code");
        bytes.extend_from_slice(&[0; 4]);
        std::fs::write(&code_path, bytes).expect("grow the code file");

        assert_eq!(
            authority
                .load_unit(&pending.key, &fixture_source_words())
                .expect_err("a grown code file is not the described extent")
                .reason(),
            UnitMissReason::ManifestRange
        );
    }

    #[test]
    fn partial_publish_pair_is_never_loadable() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        let stem = pending.key.file_stem().expect("unit stem");
        let (code, manifest) = authority.final_paths(&stem);
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
    fn published_unit_maps_serialized_metadata_with_mapped_evidence() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();

        assert_eq!(
            authority.publish_unit(&pending).expect("publish unit"),
            PublishOutcome::Winner
        );
        let stem = pending.key.file_stem().expect("unit stem");
        let (_, metadata_path) = authority.final_paths(&stem);
        assert_eq!(
            metadata_path.extension().and_then(std::ffi::OsStr::to_str),
            Some("metadata-v5")
        );
        assert!(
            !authority
                .path()
                .join(format!("{stem}.metadata-v3"))
                .exists()
        );

        let loaded = authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect("load unit");
        assert_eq!(loaded.manifest.blocks().len(), 1);
        assert_eq!(loaded.manifest.blocks()[0].guest_start, GuestVa(0x400000));
        // v5 maps the metadata instead of reading it: untouched cold
        // blobs are never paged in, and the mapping backs on-demand
        // per-block decode for the manifest's lifetime.
        assert_eq!(loaded.load_evidence.bytes_read, 0);
        assert_eq!(
            loaded.load_evidence.bytes_mapped,
            std::fs::metadata(metadata_path)
                .expect("stat unit metadata")
                .len()
        );
        assert!(loaded.load_evidence.owned_records > 0);
    }

    #[test]
    fn unit_metadata_maps_the_bounded_open_extent() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        authority.publish_unit(&pending).expect("publish unit");
        let stem = pending.key.file_stem().expect("unit stem");
        let (_, metadata_path) = authority.final_paths(&stem);
        let bounded_len = std::fs::metadata(&metadata_path)
            .expect("stat unit metadata before bounded open")
            .len();
        arm_after_bounded_metadata_open_for_test({
            let metadata_path = metadata_path.clone();
            move || {
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(metadata_path)
                    .expect("open unit metadata after bounded open")
                    .write_all(&[0xa5; 16])
                    .expect("grow unit metadata after bounded open");
            }
        });

        let loaded = authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect("map only the extent accepted by bounded open");

        assert_eq!(loaded.load_evidence.bytes_mapped, bounded_len);
    }

    #[test]
    fn mapped_metadata_and_code_pair_rejects_either_lone_half() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        let stem = pending.key.file_stem().expect("unit stem");
        let (code, metadata) = authority.final_paths(&stem);

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
    fn corrupt_v3_metadata_is_typed_before_the_code_half() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        authority.publish_unit(&pending).expect("publish V3 unit");
        let stem = pending.key.file_stem().expect("unit stem");
        let (code, metadata) = authority.final_paths(&stem);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&metadata)
            .expect("open V3 metadata")
            .write_all(b"BROKEN!!")
            .expect("corrupt V3 magic");
        std::fs::write(code, b"garbage bytes").expect("corrupt code half");

        assert_eq!(
            authority
                .load_unit(&pending.key, &fixture_source_words())
                .expect_err("corrupt V3 metadata must miss before the code half")
                .reason(),
            UnitMissReason::Schema
        );
    }
}
