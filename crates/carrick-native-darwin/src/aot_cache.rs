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
//! `{stem}.code` (the raw translated instruction bytes, with the
//! direct-binding `ADRP`/`ADD` placeholder pairs UNRESOLVED) and
//! `{stem}.metadata-v3` (the mapped metadata, carrying `code_sha256` over
//! those exact bytes). Loading maps both read-only, digest-verifies the code
//! against the metadata, and hands the bytes to the translator, which COPIES
//! them into its own per-process `MAP_JIT` translation cache and re-points
//! the binding placeholders at the zeroed cell block this store allocates
//! per load.
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

use carrick_dsr_aarch64::direct_binding::DirectBindingCellVa;
use carrick_dsr_aarch64::mapped_metadata::{
    MappedMetadataError, MetadataBacking, ValidatedMappedTranslationMetadata,
    encode_translation_metadata_v3,
};
use carrick_dsr_aarch64::shared_cache::ManifestDefect;
pub use carrick_dsr_aarch64::shared_cache::PublishOutcome;
use carrick_dsr_aarch64::shared_cache::{
    LoadedTranslationMetadata, MAX_TRANSLATION_UNIT_CODE_BYTES, PendingTranslationUnit,
    SourceFingerprint, TRANSLATION_UNIT_SCHEMA_V2, TranslationMetadataLoadEvidence,
    TranslationMetadataMode, TranslationUnitKey, TranslationUnitManifest, UnitMissReason,
    shared_source_fingerprint_reuse_enabled, translation_unit_base_export,
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
/// Total `{stem}.code` + `{stem}.metadata-v3` bytes the store may retain;
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
        } else if let Some(stem) = name.strip_suffix(".metadata-v3") {
            metadata_halves.insert(stem.to_owned(), identity);
        } else if name.ends_with(".seen") {
            // The retired recurrence-deferral marker: never produced again.
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
            let _ = std::fs::remove_file(path.join(format!("{stem}.metadata-v3")));
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
        let _ = std::fs::remove_file(path.join(format!("{}.metadata-v3", pair.stem)));
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
    // file mapping plus the unit's cell block) last, after nothing else can
    // reference either.
    lease: Arc<CodeSourceLease>,
    pub metadata: LoadedTranslationMetadata,
    /// Readable source bytes for the translator's install copy. Nothing
    /// executes here — see `SharedLoadedTranslationUnit::source_base`.
    pub source_base: std::ptr::NonNull<u8>,
    pub binding_base: Option<DirectBindingCellVa>,
    pub load_evidence: TranslationMetadataLoadEvidence,
}

impl LoadedTranslationUnit {
    fn into_shared(self) -> carrick_dsr_aarch64::shared_cache::SharedLoadedTranslationUnit {
        let source_base = self.source_base.as_ptr() as usize;
        match self.metadata {
            LoadedTranslationMetadata::V2(manifest) => {
                let mut unit = carrick_dsr_aarch64::shared_cache::SharedLoadedTranslationUnit::new_with_binding_base(
                    manifest,
                    source_base,
                    self.binding_base,
                    self.lease,
                );
                unit.load_evidence = self.load_evidence;
                unit
            }
            LoadedTranslationMetadata::V3(metadata) => {
                carrick_dsr_aarch64::shared_cache::SharedLoadedTranslationUnit::new_mapped_with_binding_base(
                    metadata,
                    source_base,
                    self.binding_base,
                    self.load_evidence,
                    self.lease,
                )
            }
        }
    }
}

#[derive(Debug)]
struct ReadOnlyMetadataMapping {
    mapping: memmap2::Mmap,
    _file: File,
}

impl MetadataBacking for ReadOnlyMetadataMapping {
    fn bytes(&self) -> &[u8] {
        self.mapping.as_ref()
    }
}

/// Pins one loaded unit's backing for the copy transport: the read-only
/// private mapping of `{stem}.code` (and the inode under it, which
/// publication never writes in place — only whole-file renames), plus the
/// unit's zeroed direct-binding cell block when it carries sidecar data.
#[derive(Debug)]
struct CodeSourceLease {
    _mapping: memmap2::Mmap,
    _file: File,
    _cells: Option<BindingCellBlock>,
}

/// Anonymous, zero-initialized, plain-RW cell block — the copy transport's
/// replacement for the dylib `__DATA` segment. Deliberately NOT `MAP_JIT`:
/// cells are written through `DirectBindingCellRef` atomics by threads whose
/// per-thread JIT write window is closed.
#[derive(Debug)]
struct BindingCellBlock {
    base: std::ptr::NonNull<u8>,
    len: usize,
}

impl BindingCellBlock {
    fn new(len: usize) -> std::io::Result<Self> {
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        let base = std::ptr::NonNull::new(mapped.cast::<u8>())
            .ok_or_else(|| std::io::Error::other("cell block mapped at null"))?;
        Ok(Self { base, len })
    }

    fn base_va(&self) -> Option<DirectBindingCellVa> {
        DirectBindingCellVa::mapped(self.base.as_ptr() as usize)
    }
}

impl Drop for BindingCellBlock {
    fn drop(&mut self) {
        // SAFETY: `base`/`len` are exactly the mapping created in `new`.
        let _ = unsafe { libc::munmap(self.base.as_ptr().cast(), self.len) };
    }
}

// SAFETY: the code mapping is immutable (read-only private map of an inode
// that is never written in place) and the cell block is only ever mutated
// through `DirectBindingCellRef` atomics; unmapping happens solely on the
// final lease drop.
unsafe impl Send for BindingCellBlock {}
// SAFETY: see `Send`; shared access to cells is atomic-only.
unsafe impl Sync for BindingCellBlock {}

// SAFETY: `source_base` addresses the immutable read-only mapping owned by
// `lease`; `binding_base` addresses the lease's cell block, mutated only
// through `DirectBindingCellRef` atomics. The metadata is immutable.
unsafe impl Send for LoadedTranslationUnit {}
// SAFETY: see `Send`.
unsafe impl Sync for LoadedTranslationUnit {}

struct UnitFileLock(File);

impl Drop for UnitFileLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}
fn mapped_metadata_miss_reason(error: &MappedMetadataError) -> UnitMissReason {
    match error {
        MappedMetadataError::Key => UnitMissReason::ImageIdentity,
        MappedMetadataError::Magic
        | MappedMetadataError::Schema { .. }
        | MappedMetadataError::EndianMarker { .. }
        | MappedMetadataError::HeaderSize { .. }
        | MappedMetadataError::HeaderReserved
        | MappedMetadataError::ExecutableKind { .. }
        | MappedMetadataError::ExecutableUnusedStorage { .. }
        | MappedMetadataError::HeaderTruncated { .. }
        | MappedMetadataError::TotalLength { .. }
        | MappedMetadataError::SectionKind { .. }
        | MappedMetadataError::SectionReserved { .. }
        | MappedMetadataError::SectionStride { .. }
        | MappedMetadataError::MissingSection { .. } => UnitMissReason::Schema,
        MappedMetadataError::OwnedManifest
        | MappedMetadataError::Arithmetic
        | MappedMetadataError::Block
        | MappedMetadataError::PcMap
        | MappedMetadataError::RecoverySpan
        | MappedMetadataError::RecoveryAction
        | MappedMetadataError::GuestRange
        | MappedMetadataError::Binding
        | MappedMetadataError::BindingRelocation
        | MappedMetadataError::EdgeGroup
        | MappedMetadataError::EdgeBackReference
        | MappedMetadataError::SectionLength { .. }
        | MappedMetadataError::SectionRangeOverflow { .. }
        | MappedMetadataError::SectionBounds { .. }
        | MappedMetadataError::SectionAlignment { .. }
        | MappedMetadataError::DuplicateSection { .. }
        | MappedMetadataError::SectionOverlap { .. } => UnitMissReason::ManifestRange,
    }
}

fn mapped_metadata_error(operation: &'static str, error: MappedMetadataError) -> UnitStoreError {
    UnitStoreError::with_source(
        operation,
        mapped_metadata_miss_reason(&error),
        invalid_data(format!("{error:?}")),
    )
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

fn map_and_validate_metadata(
    directory: &File,
    name: &CStr,
    expected_key: &TranslationUnitKey,
) -> Result<
    (
        Arc<ValidatedMappedTranslationMetadata>,
        TranslationMetadataLoadEvidence,
    ),
    UnitStoreError,
> {
    let (file, length) = open_metadata_at(directory, name)?;
    #[cfg(test)]
    run_after_bounded_metadata_open_for_test();
    // SAFETY: `map_copy_read_only` requests `MAP_PRIVATE|PROT_READ`. The private
    // cache authority makes each backing inode immutable after its temporary
    // is flushed and synced. Publication/replacement may unlink a pathname but
    // never writes or truncates the retained inode. The mmap length is the
    // exact nonzero, bounded extent accepted by the single `fstat` above, and
    // `_file` pins that inode for the mapping's lifetime. The test-only seam
    // may append beyond `length`; it never mutates the extent mapped here.
    let mapping = unsafe {
        memmap2::MmapOptions::new()
            .len(length)
            .map_copy_read_only(&file)
    }
    .map_err(|error| {
        UnitStoreError::with_source("map translation metadata", UnitMissReason::Schema, error)
    })?;
    #[cfg(test)]
    LAST_MAPPED_METADATA_ADDRESS_FOR_TEST.with(|address| address.set(mapping.as_ptr() as usize));
    let backing: Arc<dyn MetadataBacking> = Arc::new(ReadOnlyMetadataMapping {
        mapping,
        _file: file,
    });
    let validation_started = std::time::Instant::now();
    let metadata = ValidatedMappedTranslationMetadata::new(backing, expected_key)
        .map_err(|error| mapped_metadata_error("validate mapped metadata", error))?;
    let validation_ns = u64::try_from(validation_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let mapped_records = metadata.immutable_record_count();
    let bytes_mapped = u64::try_from(length).map_err(|_| {
        UnitStoreError::new("measure mapped metadata", UnitMissReason::ManifestRange)
    })?;
    Ok((
        Arc::new(metadata),
        TranslationMetadataLoadEvidence {
            mode: TranslationMetadataMode::V3,
            bytes_read: 0,
            bytes_mapped,
            validation_ns,
            mapped_records,
            owned_records: 0,
        },
    ))
}

fn code_word(code: &[u8], offset: u32) -> Result<u32, UnitMissReason> {
    let start = usize::try_from(offset).map_err(|_| UnitMissReason::ManifestRange)?;
    let end = start.checked_add(4).ok_or(UnitMissReason::ManifestRange)?;
    let bytes = code.get(start..end).ok_or(UnitMissReason::ManifestRange)?;
    Ok(u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| UnitMissReason::ManifestRange)?,
    ))
}

fn validate_loaded_binding_code(
    metadata: &ValidatedMappedTranslationMetadata,
    code: &[u8],
) -> Result<(), UnitMissReason> {
    // Relocations address a binding's SIDECAR CELL. A unit with no cell
    // machinery (`Disabled` layout, i.e. `binding_data_len == 0`) carries
    // bindings but no relocations, so walking one per binding reads records
    // that do not exist and rejects a unit carrick just published.
    if metadata.binding_data_len() == 0 {
        return Ok(());
    }
    for index in 0..metadata.binding_count() {
        let relocation = metadata
            .binding(index)
            .ok_or(UnitMissReason::ManifestRange)?
            .relocation();
        for (adrp_offset, add_offset) in [
            (relocation.adrp_offset, relocation.add_offset),
            (relocation.miss_adrp_offset, relocation.miss_add_offset),
        ] {
            let adrp = code_word(code, adrp_offset)?;
            let add = code_word(code, add_offset)?;
            if adrp & 0x9f00_001f != 0x9000_000f || add & 0xffc0_03ff != 0x9100_01ef {
                return Err(UnitMissReason::ManifestRange);
            }
        }
    }
    Ok(())
}

fn manifest_for_pending(
    pending: &PendingTranslationUnit,
    code_sha256: [u8; 32],
    base_export: &str,
) -> TranslationUnitManifest {
    TranslationUnitManifest {
        schema: TRANSLATION_UNIT_SCHEMA_V2,
        key: pending.key.clone(),
        code_sha256,
        base_export: base_export.to_owned(),
        code_len: pending.code.len() as u64,
        blocks: pending.blocks.clone(),
        binding_layout: pending.binding_layout,
        binding_export: pending.binding_export.clone(),
        binding_data_len: pending.binding_data_len,
        cell_size: pending.cell_size,
        bindings: pending.bindings.clone(),
        binding_relocations: pending.binding_relocations.clone(),
    }
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
        if pending.code.is_empty()
            || pending.code.len() > MAX_TRANSLATION_UNIT_CODE_BYTES
            || !pending.code.len().is_multiple_of(4)
        {
            return Err(UnitStoreError::new(
                "validate pending unit",
                UnitMissReason::ManifestRange,
            ));
        }
        let base_export = translation_unit_base_export(&pending.key).map_err(|error| {
            UnitStoreError::with_source(
                "derive keyed translation export",
                UnitMissReason::Schema,
                error,
            )
        })?;
        // Digest the raw code FIRST so the metadata half binds the exact
        // bytes the code half will carry: a loader that ever pairs a stale
        // orphan with fresh metadata fails the digest instead of running
        // code its metadata does not describe.
        let manifest =
            manifest_for_pending(pending, Sha256::digest(&pending.code).into(), &base_export);
        // Name the broken invariant. This preflight rejects a unit CARRICK
        // ITSELF just built, so "ManifestRange" alone says only that the
        // producer and its validator disagree - which is exactly the state a
        // cold go build has been in (33 publication attempts, 0 units, 30 of
        // them ManifestRange with no further detail).
        if let Err(defect) = manifest.validate_ranges_detailed() {
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
                    ManifestDefect::BindingOrdinal => "validate pending unit: binding ordinal",
                    ManifestDefect::BindingGeometry => "validate pending unit: binding geometry",
                    ManifestDefect::BindingOwnerDuplicate => {
                        "validate pending unit: duplicate binding stub owner"
                    }
                    ManifestDefect::BindingOrder => "validate pending unit: binding stub order",
                    ManifestDefect::BindingTargetInUnit => {
                        "validate pending unit: binding target is inside this unit"
                    }
                    ManifestDefect::BindingLayoutDisabled => {
                        "validate pending unit: disabled binding layout carries data"
                    }
                    ManifestDefect::BindingLayoutSidecar => {
                        "validate pending unit: sidecar binding layout"
                    }
                    ManifestDefect::BindingRelocation => {
                        "validate pending unit: binding relocation"
                    }
                },
                defect.reason(),
            ));
        }
        manifest
            .validate_binding_data(&pending.binding_data)
            .and_then(|()| manifest.validate_binding_code(&pending.code))
            .map_err(|reason| UnitStoreError::new("validate pending unit payload", reason))?;
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
        let metadata_bytes = encode_translation_metadata_v3(&manifest).map_err(|error| {
            tracing::warn!(
                bindings = manifest.bindings.len(),
                relocations = manifest.binding_relocations.len(),
                binding_ordinals = ?manifest.bindings.iter().map(|b| b.ordinal.get())
                    .take(8).collect::<Vec<_>>(),
                relocation_ordinals = ?manifest.binding_relocations.iter()
                    .map(|r| r.ordinal.get()).take(8).collect::<Vec<_>>(),
                layout = ?manifest.binding_layout,
                error = ?error,
                "mapped metadata encode rejected a freshly packed unit"
            );
            mapped_metadata_error("encode mapped metadata", error)
        })?;
        let mut code_temp = tempfile::NamedTempFile::new_in(&self.path).map_err(|error| {
            UnitStoreError::with_source("create code temporary", UnitMissReason::MissingPair, error)
        })?;
        code_temp.write_all(&pending.code).map_err(|error| {
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
        let _validated = map_and_validate_metadata(&self.directory, &temporary_name, &pending.key)?;

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
        let metadata_name = CString::new(format!("{stem}.metadata-v3")).map_err(|error| {
            UnitStoreError::with_source(
                "encode mapped metadata name",
                UnitMissReason::Schema,
                error,
            )
        })?;
        let (metadata, load_evidence) =
            map_and_validate_metadata(&self.directory, &metadata_name, expected_key)?;
        if !shared_source_fingerprint_reuse_enabled()
            && expected_key.source_fingerprint() != SourceFingerprint::from_words(source_words)
        {
            return Err(UnitStoreError::new(
                "validate unit source",
                UnitMissReason::SourceFingerprint,
            ));
        }
        let code_len = usize::try_from(metadata.code_len()).map_err(|_| {
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
        if digest != metadata.code_sha256() {
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
        if metadata.binding_count() != 0
            && let Err(reason) = validate_loaded_binding_code(&metadata, &mapping)
        {
            return Err(UnitStoreError::new(
                "validate mapped translation code",
                reason,
            ));
        }
        let binding_data_len = usize::try_from(metadata.binding_data_len()).map_err(|_| {
            UnitStoreError::new(
                "validate binding data length",
                UnitMissReason::ManifestRange,
            )
        })?;
        let cells = if binding_data_len == 0 {
            None
        } else {
            Some(BindingCellBlock::new(binding_data_len).map_err(|error| {
                UnitStoreError::with_source(
                    "allocate binding cell block",
                    UnitMissReason::CodeMapping,
                    error,
                )
            })?)
        };
        let binding_base = match &cells {
            Some(cells) => Some(cells.base_va().ok_or_else(|| {
                UnitStoreError::new(
                    "validate binding cell alignment",
                    UnitMissReason::ManifestRange,
                )
            })?),
            None => None,
        };
        let source_base = std::ptr::NonNull::new(mapping.as_ptr().cast_mut()).ok_or_else(|| {
            UnitStoreError::new("map translation code", UnitMissReason::CodeMapping)
        })?;
        Ok(LoadedTranslationUnit {
            lease: Arc::new(CodeSourceLease {
                _mapping: mapping,
                _file: code_file,
                _cells: cells,
            }),
            metadata: LoadedTranslationMetadata::V3(metadata),
            source_base,
            binding_base,
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
            self.path.join(format!("{stem}.metadata-v3")),
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

    /// The load path must accept a unit whose layout has no sidecar cells.
    ///
    /// `PendingTranslationUnit::pack` emits bindings but NO relocations under a
    /// `Disabled` layout, and both the producer's `validate_ranges` and the V2
    /// load arm agree with that. The V3 arm walked one relocation per BINDING
    /// instead, so it read records that do not exist and refused a unit carrick
    /// had just published - the last link in the chain that held the shared
    /// translation lane at zero loaded units. Red against the pre-fix arm with
    /// `UnitMissReason::ManifestRange`.
    #[test]
    fn disabled_layout_units_need_no_binding_code_validation() {
        // Start from the sidecar fixture purely to inherit a NON-EMPTY binding
        // list, then strip the cell machinery: bindings without relocations is
        // exactly the shape a `Disabled` unit publishes.
        let mut pending = fixture_pending_with_binding_sidecar();
        pending.binding_layout = DirectBindingLayout::Disabled;
        pending.binding_export.clear();
        pending.binding_data_len = 0;
        pending.cell_size = 0;
        pending.binding_relocations.clear();
        pending.binding_data.clear();
        assert!(
            !pending.bindings.is_empty(),
            "the shape under test is bindings WITHOUT relocations",
        );

        let base_export =
            translation_unit_base_export(&pending.key).expect("keyed translation export");
        let manifest = TranslationUnitManifest {
            schema: TRANSLATION_UNIT_SCHEMA_V2,
            key: pending.key,
            code_sha256: [0x22; 32],
            base_export,
            code_len: pending.code.len() as u64,
            blocks: pending.blocks,
            binding_layout: pending.binding_layout,
            binding_export: pending.binding_export,
            binding_data_len: pending.binding_data_len,
            cell_size: pending.cell_size,
            bindings: pending.bindings,
            binding_relocations: pending.binding_relocations,
        };
        manifest
            .validate_ranges()
            .expect("a disabled-layout unit is well formed");

        let code = vec![0_u8; manifest.code_len as usize];

        // V3 SPECIFICALLY: the V2 arm iterates the (empty) relocation list and
        // was never wrong. Building V2 here would pass against the pre-fix code
        // and prove nothing.
        let bytes = carrick_dsr_aarch64::mapped_metadata::encode_translation_metadata_v3(&manifest)
            .expect("encode a disabled-layout unit");
        let key = manifest.key;
        let backing: Arc<dyn MetadataBacking> =
            Arc::new(carrick_dsr_aarch64::mapped_metadata::VecMetadataBacking::new(bytes));
        let mapped = ValidatedMappedTranslationMetadata::new(backing, &key)
            .expect("a disabled-layout unit validates as mapped metadata");

        validate_loaded_binding_code(&mapped, &code)
            .expect("a cell-free unit needs no binding-code validation");
    }
    use super::*;
    use carrick_dsr::address::NativeHostBias;
    use carrick_dsr_aarch64::artifact_spike::{ArtifactBindings, ArtifactTemplate};
    use carrick_dsr_aarch64::direct_binding::{
        DirectBindingCellRef, DirectBindingOrdinal, DirectBindingTarget, DirectBindingTargetPrefix,
        PrivateJitEpoch,
    };
    use carrick_dsr_aarch64::emit::{DirectLinkKind, PcMapEntry, RecoveryAction, RecoveryEntry};
    use carrick_dsr_aarch64::shared_cache::{
        AddressModeIdentity, DIRECT_BINDING_CELL_SIZE, DirectBindingLayout,
        DirectBindingRelocation, ExecutableIdentity, GuestCodeLen, ImageFileLen, ImageFileOffset,
        LoadedTranslationMetadata, NativePageProfileIdentity, SharedLoadedTranslationUnit,
        SourceFingerprint, TRANSLATION_UNIT_BINDING_EXPORT, TranslationMetadataMode,
        UnresolvedDirectBindingRecord,
    };
    use carrick_dsr_aarch64::types::{CacheOffset, CodeGeneration};
    use carrick_guest_mem::GuestVa;
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
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
        let template = ArtifactTemplate::normalize(
            Vec::new(),
            vec![PcMapEntry {
                guest: GuestVa(0x400000),
                cache: CacheOffset::published(0),
            }],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            &ArtifactBindings::from_values([]).expect("empty artifact bindings"),
        )
        .expect("fixture block metadata")
        .into_runtime_metadata_only();
        PendingTranslationUnit {
            key: TranslationUnitKey::for_segment(
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
            ),
            code: MOV42_RET.to_vec(),
            blocks: vec![carrick_dsr_aarch64::shared_cache::PortableBlockRecord {
                guest_start: GuestVa(0x400000),
                generation_binding: 0,
                entry_offset: 0,
                code_len: 8,
                requires_sensitive_metadata: false,
                template,
            }],
            binding_layout: DirectBindingLayout::Disabled,
            binding_export: String::new(),
            binding_data_len: 0,
            cell_size: 0,
            bindings: Vec::new(),
            binding_relocations: Vec::new(),
            binding_data: Vec::new(),
        }
    }

    fn fixture_pending_with_binding_sidecar() -> PendingTranslationUnit {
        let mut pending = fixture_pending();
        pending.code.resize(288, 0);
        pending.code[..MOV42_RET.len()].copy_from_slice(&MOV42_RET);
        for offset in [52, 140] {
            pending.code[offset..offset + 4].copy_from_slice(&0x9000_000f_u32.to_le_bytes());
        }
        for offset in [56, 144] {
            pending.code[offset..offset + 4].copy_from_slice(&0x9100_01ef_u32.to_le_bytes());
        }
        pending.binding_layout = DirectBindingLayout::SidecarV1;
        pending.binding_export = TRANSLATION_UNIT_BINDING_EXPORT.to_owned();
        pending.binding_data_len = u64::from(DIRECT_BINDING_CELL_SIZE);
        pending.cell_size = DIRECT_BINDING_CELL_SIZE;
        pending.bindings = vec![UnresolvedDirectBindingRecord {
            source: GuestVa(0x400000),
            target: GuestVa(0x500000),
            kind: DirectLinkKind::Branch,
            ordinal: DirectBindingOrdinal::claimed(0),
            stub_start: 32,
            stub_end: 288,
        }];
        pending.binding_relocations = vec![DirectBindingRelocation {
            ordinal: DirectBindingOrdinal::claimed(0),
            adrp_offset: 52,
            add_offset: 56,
            miss_adrp_offset: 140,
            miss_add_offset: 144,
            data_offset: 0,
        }];
        pending.binding_data = vec![0; DIRECT_BINDING_CELL_SIZE as usize];
        pending
    }

    fn fixture_pending_with_complete_metadata_tables() -> PendingTranslationUnit {
        let mut pending = fixture_pending_with_binding_sidecar();
        pending.blocks[0].template = ArtifactTemplate::normalize(
            Vec::new(),
            vec![
                PcMapEntry {
                    guest: GuestVa(0x400000),
                    cache: CacheOffset::published(0),
                },
                PcMapEntry {
                    guest: GuestVa(0x400008),
                    cache: CacheOffset::published(4),
                },
            ],
            vec![RecoveryEntry {
                cache: CacheOffset::published(0),
                action: RecoveryAction::Noop,
            }],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            &ArtifactBindings::from_values([]).expect("empty artifact bindings"),
        )
        .expect("complete metadata fixture")
        .into_runtime_metadata_only();
        pending
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

    fn pipe_pair() -> [RawFd; 2] {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "create pipe");
        fds
    }

    fn close_fd(fd: RawFd) {
        if fd >= 0 {
            assert_eq!(unsafe { libc::close(fd) }, 0, "close fd {fd}");
        }
    }

    fn write_all_fd(fd: RawFd, mut bytes: &[u8]) -> bool {
        while !bytes.is_empty() {
            let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
            if written > 0 {
                bytes = &bytes[written as usize..];
            } else if written < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
            {
                continue;
            } else {
                return false;
            }
        }
        true
    }

    fn read_exact_fd(fd: RawFd, mut bytes: &mut [u8]) -> bool {
        while !bytes.is_empty() {
            let read = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
            if read > 0 {
                let (_, remaining) = bytes.split_at_mut(read as usize);
                bytes = remaining;
            } else if read < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
            {
                continue;
            } else {
                return false;
            }
        }
        true
    }

    fn wait_for_child(pid: libc::pid_t, label: &str) {
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, 0) },
            pid,
            "wait for {label}"
        );
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "{label} exited with wait status 0x{status:x}"
        );
    }

    fn child_exit(status: i32) -> ! {
        unsafe { libc::_exit(status) }
    }

    fn run_binding_child(
        authority: &ContainerCacheAuthority,
        pending: &PendingTranslationUnit,
        control_read: RawFd,
        report_write: RawFd,
        target_address: usize,
    ) -> ! {
        if !write_all_fd(report_write, b"R") {
            child_exit(10);
        }
        let mut command = [0];
        if !read_exact_fd(control_read, &mut command) || command != *b"L" {
            child_exit(11);
        }
        let loaded = match authority.load_unit(&pending.key, &fixture_source_words()) {
            Ok(loaded) => loaded,
            Err(_) => child_exit(12),
        };
        let Some(binding_base) = loaded.binding_base else {
            child_exit(13);
        };
        let cell = match unsafe { DirectBindingCellRef::from_mapped_address(binding_base) } {
            Ok(cell) => cell,
            Err(_) => child_exit(14),
        };
        let target = std::ptr::without_provenance_mut::<DirectBindingTarget>(target_address);
        if cell.publish_null(target).is_err() {
            child_exit(15);
        }
        if !write_all_fd(report_write, b"P") {
            child_exit(16);
        }
        if !read_exact_fd(control_read, &mut command) || command != *b"R" {
            child_exit(17);
        }
        let observed = cell.load_acquire().addr();
        if !write_all_fd(report_write, &observed.to_ne_bytes()) {
            child_exit(18);
        }
        drop(loaded);
        child_exit(0)
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
        assert!(matches!(&loaded.metadata, LoadedTranslationMetadata::V3(_)));
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
        let metadata_path = authority.path().join(format!("{stem}.metadata-v3"));
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
        for suffix in [".code", ".metadata-v3"] {
            set_file_age(
                &store.path().join(format!("{old_stem}{suffix}")),
                std::time::Duration::from_secs(3 * 60 * 60),
            );
        }

        // A cap of one byte forces eviction of everything not in use; the
        // oldest pair goes first and eviction stops at the cap — here after
        // both, so assert the ORDER by capping between the two pair sizes.
        let pair_bytes = |stem: &str| -> u64 {
            [".code", ".metadata-v3"]
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
        assert!(matches!(&loaded.metadata, LoadedTranslationMetadata::V3(_)));
        let stem = pending.key.file_stem().expect("unit stem");
        assert!(
            authority
                .path()
                .join(format!("{stem}.metadata-v3"))
                .is_file()
        );
        // The copy transport hands out READABLE source bytes; nothing at
        // this address is executable. The translator copies them into its
        // own MAP_JIT cache.
        let source =
            unsafe { std::slice::from_raw_parts(loaded.source_base.as_ptr(), pending.code.len()) };
        assert_eq!(source, pending.code.as_slice());
        assert!(
            std::fs::read_dir(authority.path())
                .expect("read cache directory")
                .filter_map(Result::ok)
                .all(|entry| !entry.file_name().to_string_lossy().starts_with(".tmp")),
            "publisher left a temporary file"
        );
    }

    #[test]
    fn published_unit_loads_zero_aligned_binding_cells() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending_with_binding_sidecar();

        assert_eq!(
            authority
                .publish_unit(&pending)
                .expect("publish complete sidecar"),
            PublishOutcome::Winner
        );
        let loaded = authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect("load complete sidecar");
        let binding_base = loaded.binding_base.expect("typed binding base");
        assert!(
            binding_base
                .get()
                .is_multiple_of(DIRECT_BINDING_CELL_SIZE as usize)
        );
        let cell = unsafe { DirectBindingCellRef::from_mapped_address(binding_base) }
            .expect("mapped atomic binding cell");
        assert!(cell.load_acquire().is_null());
        // The SOURCE keeps its ADRP/ADD placeholder pairs untouched: the
        // translator patches them in ITS COPY at install, against these
        // exact cell addresses. A source that arrived pre-patched would be
        // double-applied.
        // SAFETY: `load_unit` validated the code extent; `loaded` pins it.
        let mapped_code =
            unsafe { std::slice::from_raw_parts(loaded.source_base.as_ptr(), pending.code.len()) };
        for (adrp_offset, add_offset) in [(52, 56), (140, 144)] {
            assert_eq!(
                u32::from_le_bytes(
                    mapped_code[adrp_offset..adrp_offset + 4]
                        .try_into()
                        .expect("placeholder ADRP"),
                ),
                0x9000_000f,
                "hit/miss ADRP placeholder must stay unresolved in the source"
            );
            assert_eq!(
                u32::from_le_bytes(
                    mapped_code[add_offset..add_offset + 4]
                        .try_into()
                        .expect("placeholder ADD"),
                ),
                0x9100_01ef,
                "hit/miss ADD placeholder must stay unresolved in the source"
            );
        }
        assert_eq!(
            authority
                .publish_unit(&pending)
                .expect("republish complete sidecar"),
            PublishOutcome::Existing
        );
    }

    /// Every load gets its OWN zeroed cell block. Under the dylib transport
    /// a second in-process `dlopen` handed back the SAME `__DATA` cells, so
    /// a published descriptor forced the loader to reject the reload; the
    /// copy transport removes that aliasing entirely.
    #[test]
    fn each_load_gets_a_fresh_private_cell_block() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending_with_binding_sidecar();
        authority
            .publish_unit(&pending)
            .expect("publish binding sidecar");
        let first = authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect("first load");
        let binding_base = first.binding_base.expect("typed binding base");
        let cell = unsafe { DirectBindingCellRef::from_mapped_address(binding_base) }
            .expect("mapped atomic binding cell");
        let epoch = PrivateJitEpoch::process_owner();
        let target = Box::into_raw(Box::new(DirectBindingTarget::private(
            DirectBindingTargetPrefix {
                target_cache_pc: 0x1000,
                cache_start: 0x1000,
                cache_end: 0x2000,
                generation_bindings: 0x3000,
            },
            GuestVa(0x500000),
            CodeGeneration::claimed(1),
            &epoch,
        )));
        cell.publish_null(target)
            .expect("atomically publish descriptor");

        let second = authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect("second load must not observe the first load's cells");
        let second_base = second.binding_base.expect("second typed binding base");
        assert_ne!(second_base.get(), binding_base.get());
        let second_cell = unsafe { DirectBindingCellRef::from_mapped_address(second_base) }
            .expect("second mapped atomic binding cell");
        assert!(second_cell.load_acquire().is_null());

        assert!(cell.clear_if(target), "clear published test descriptor");
        // SAFETY: this test allocated `target`, successfully cleared its sole
        // published cell, and retains no other pointer to the allocation.
        unsafe { drop(Box::from_raw(target)) };
    }

    #[test]
    fn two_independent_processes_bind_their_own_cell_blocks_privately() {
        const CHILD_A_TARGET: usize = 0x1111_0000;
        const CHILD_B_TARGET: usize = 0x2222_0000;

        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending_with_binding_sidecar();
        authority
            .publish_unit(&pending)
            .expect("publish binding sidecar before fork");

        let control_a = pipe_pair();
        let report_a = pipe_pair();
        let control_b = pipe_pair();
        let report_b = pipe_pair();

        let child_a = unsafe { libc::fork() };
        assert!(child_a >= 0, "fork child A");
        if child_a == 0 {
            close_fd(control_a[1]);
            close_fd(report_a[0]);
            run_binding_child(
                &authority,
                &pending,
                control_a[0],
                report_a[1],
                CHILD_A_TARGET,
            );
        }

        let child_b = unsafe { libc::fork() };
        assert!(child_b >= 0, "fork child B");
        if child_b == 0 {
            close_fd(control_b[1]);
            close_fd(report_b[0]);
            run_binding_child(
                &authority,
                &pending,
                control_b[0],
                report_b[1],
                CHILD_B_TARGET,
            );
        }

        close_fd(control_a[0]);
        close_fd(report_a[1]);
        close_fd(control_b[0]);
        close_fd(report_b[1]);

        let mut marker = [0];
        assert!(read_exact_fd(report_a[0], &mut marker) && marker == *b"R");
        assert!(read_exact_fd(report_b[0], &mut marker) && marker == *b"R");
        assert!(write_all_fd(control_a[1], b"L"));
        assert!(write_all_fd(control_b[1], b"L"));
        assert!(read_exact_fd(report_a[0], &mut marker) && marker == *b"P");
        assert!(read_exact_fd(report_b[0], &mut marker) && marker == *b"P");
        assert!(write_all_fd(control_a[1], b"R"));
        assert!(write_all_fd(control_b[1], b"R"));

        let mut child_a_observed = [0; std::mem::size_of::<usize>()];
        let mut child_b_observed = [0; std::mem::size_of::<usize>()];
        assert!(read_exact_fd(report_a[0], &mut child_a_observed));
        assert!(read_exact_fd(report_b[0], &mut child_b_observed));
        assert_eq!(usize::from_ne_bytes(child_a_observed), CHILD_A_TARGET);
        assert_eq!(usize::from_ne_bytes(child_b_observed), CHILD_B_TARGET);

        close_fd(control_a[1]);
        close_fd(report_a[0]);
        close_fd(control_b[1]);
        close_fd(report_b[0]);
        wait_for_child(child_a, "binding child A");
        wait_for_child(child_b, "binding child B");
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

    #[test]
    fn loaded_unit_lease_keeps_code_and_cells_alive_after_unlink() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending_with_binding_sidecar();
        authority
            .publish_unit(&pending)
            .expect("publish leased binding sidecar");
        let stem = pending.key.file_stem().expect("unit stem");
        let (code_path, manifest_path) = authority.final_paths(&stem);
        let loaded = std::sync::Arc::new(
            authority
                .load_unit(&pending.key, &fixture_source_words())
                .expect("load leased binding sidecar"),
        );
        let binding_base = loaded.binding_base.expect("typed binding base");
        let lease: std::sync::Arc<dyn Send + Sync> = loaded.clone();
        let shared = match &loaded.metadata {
            LoadedTranslationMetadata::V2(manifest) => {
                SharedLoadedTranslationUnit::new_with_binding_base(
                    std::sync::Arc::clone(manifest),
                    loaded.source_base.as_ptr() as usize,
                    Some(binding_base),
                    lease,
                )
            }
            LoadedTranslationMetadata::V3(metadata) => {
                SharedLoadedTranslationUnit::new_mapped_with_binding_base(
                    std::sync::Arc::clone(metadata),
                    loaded.source_base.as_ptr() as usize,
                    Some(binding_base),
                    loaded.load_evidence,
                    lease,
                )
            }
        };
        drop(loaded);
        std::fs::remove_file(code_path).expect("unlink loaded code");
        std::fs::remove_file(manifest_path).expect("unlink loaded manifest");

        // SAFETY: the shared unit's lease pins the unlinked inode's mapping.
        let source = unsafe {
            std::slice::from_raw_parts(shared.source_base as *const u8, pending.code.len())
        };
        assert_eq!(
            source,
            pending.code.as_slice(),
            "retained lease must keep the source mapped after unlink"
        );
        let cell = unsafe {
            DirectBindingCellRef::from_mapped_address(
                shared.binding_base.expect("shared typed binding base"),
            )
        }
        .expect("retained lease must keep cells mapped");
        assert!(cell.load_acquire().is_null());
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
        second.code[..4].copy_from_slice(&0x5280_0560_u32.to_le_bytes());
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
        assert_eq!(
            std::fs::read(&code_path).expect("read published code"),
            pending.code,
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
    fn published_v3_unit_is_mapped_with_zero_read_evidence() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();

        assert_eq!(
            authority.publish_unit(&pending).expect("publish V3 unit"),
            PublishOutcome::Winner
        );
        let stem = pending.key.file_stem().expect("unit stem");
        let (_, metadata_path) = authority.final_paths(&stem);
        assert_eq!(
            metadata_path.extension().and_then(std::ffi::OsStr::to_str),
            Some("metadata-v3")
        );
        assert!(!authority.path().join(format!("{stem}.manifest")).exists());

        let loaded = authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect("load V3 unit");
        let LoadedTranslationMetadata::V3(metadata) = &loaded.metadata else {
            panic!("default mapped load must retain V3 metadata");
        };
        assert_eq!(metadata.block_count(), 1);
        assert_eq!(
            metadata.block(0).expect("mapped block").guest_start(),
            GuestVa(0x400000)
        );
        assert_eq!(loaded.load_evidence.mode, TranslationMetadataMode::V3);
        assert_eq!(loaded.load_evidence.bytes_read, 0);
        assert_eq!(
            loaded.load_evidence.bytes_mapped,
            std::fs::metadata(metadata_path)
                .expect("stat V3 metadata")
                .len()
        );
        assert_eq!(loaded.load_evidence.mapped_records, 5);
        assert_eq!(loaded.load_evidence.owned_records, 0);
    }

    #[test]
    fn mapped_metadata_uses_the_bounded_open_extent() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        authority.publish_unit(&pending).expect("publish V3 unit");
        let stem = pending.key.file_stem().expect("unit stem");
        let (_, metadata_path) = authority.final_paths(&stem);
        let bounded_len = std::fs::metadata(&metadata_path)
            .expect("stat V3 metadata before bounded open")
            .len();
        arm_after_bounded_metadata_open_for_test({
            let metadata_path = metadata_path.clone();
            move || {
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(metadata_path)
                    .expect("open V3 metadata after bounded open")
                    .write_all(&[0xa5; 16])
                    .expect("grow V3 metadata after bounded open");
            }
        });

        let loaded = authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect("map only the extent accepted by bounded open");

        assert_eq!(loaded.load_evidence.bytes_mapped, bounded_len);
    }

    #[test]
    fn mapped_metadata_evidence_counts_all_twelve_wire_sections() {
        let pending = fixture_pending_with_complete_metadata_tables();
        let (_v3_store, v3_authority) = persistent_fixture_authority();
        v3_authority
            .publish_unit(&pending)
            .expect("publish complete V3 metadata fixture");
        let v3 = v3_authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect("load complete V3 metadata fixture");
        assert_eq!(
            v3.load_evidence.mapped_records, 15,
            "V3 counts every physical record across all twelve wire sections"
        );
        assert_eq!(v3.load_evidence.owned_records, 0);
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

    #[test]
    fn mapped_metadata_survives_unlink_until_the_final_clone_drops() {
        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending_with_binding_sidecar();
        authority
            .publish_unit(&pending)
            .expect("publish V3 sidecar");
        let stem = pending.key.file_stem().expect("unit stem");
        let (code_path, metadata_path) = authority.final_paths(&stem);
        let loaded = authority
            .load_unit(&pending.key, &fixture_source_words())
            .expect("load V3 sidecar");
        let LoadedTranslationMetadata::V3(metadata) = loaded.metadata else {
            panic!("loaded sidecar must retain V3 metadata");
        };
        let metadata_drops = std::sync::Arc::downgrade(&metadata);
        let shared = SharedLoadedTranslationUnit::new_mapped_with_binding_base(
            std::sync::Arc::clone(&metadata),
            loaded.source_base.as_ptr() as usize,
            loaded.binding_base,
            loaded.load_evidence,
            loaded.lease,
        );
        drop(metadata);
        let clone = shared.clone();
        std::fs::remove_file(code_path).expect("unlink loaded code");
        std::fs::remove_file(metadata_path).expect("unlink mapped metadata");

        let mapped = clone.metadata.v3().expect("cloned mapped metadata");
        assert_eq!(mapped.block(0).expect("mapped block").code_len(), 8);
        assert_eq!(
            mapped
                .binding(0)
                .expect("mapped binding")
                .record()
                .ordinal
                .get(),
            0
        );
        // SAFETY: the clone's lease pins the unlinked code mapping.
        let source = unsafe {
            std::slice::from_raw_parts(clone.source_base as *const u8, pending.code.len())
        };
        assert_eq!(source, pending.code.as_slice());
        drop(shared);
        assert!(metadata_drops.upgrade().is_some());
        drop(clone);
        assert!(metadata_drops.upgrade().is_none());
    }

    #[test]
    fn mapped_metadata_uses_a_private_read_only_vm_region() {
        use mach2::vm_prot::VM_PROT_READ;
        use mach2::vm_region::SM_COW;

        let (_store, authority) = persistent_fixture_authority();
        let pending = fixture_pending();
        authority.publish_unit(&pending).expect("publish V3 unit");
        let stem = pending.key.file_stem().expect("unit stem");
        let name = CString::new(format!("{stem}.metadata-v3")).expect("metadata name");
        let (metadata, _) = map_and_validate_metadata(&authority.directory, &name, &pending.key)
            .expect("map V3 metadata through production loader");
        let address = LAST_MAPPED_METADATA_ADDRESS_FOR_TEST.with(std::cell::Cell::get);
        assert_ne!(address, 0, "production mapping address must be observed");

        let region = current_region_extended_info(address);

        assert_eq!(region.protection, VM_PROT_READ);
        assert_eq!(
            region.share_mode, SM_COW,
            "metadata mapping must be kernel-classified as COW"
        );
        drop(metadata);
    }
}
