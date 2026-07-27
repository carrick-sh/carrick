//! Container-lifetime authority for portable native AArch64 translations.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub use carrick_dsr_aarch64::shared_cache::PublishOutcome;
use carrick_dsr_aarch64::shared_cache::{
    DIRECT_BINDING_CELL_SIZE, MAX_TRANSLATION_UNIT_CODE_BYTES, PendingTranslationUnit,
    TRANSLATION_UNIT_BASE_EXPORT, TRANSLATION_UNIT_SCHEMA_V2, TranslationUnitKey,
    TranslationUnitManifest, UnitMissReason,
};
use sha2::{Digest, Sha256};

const AUTHORITY_MARKER: &str = ".carrick-authority";
const AUTHORITY_NONCE_LEN: usize = 16;
const MANIFEST_DECODE_LIMIT: usize = 256 * 1024 * 1024;

static CONTAINER_CACHE: Mutex<Option<ContainerCacheAuthority>> = Mutex::new(None);

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
    pub manifest: TranslationUnitManifest,
    pub base: std::ptr::NonNull<u8>,
    handle: std::ptr::NonNull<libc::c_void>,
}

// SAFETY: dyld owns the immutable executable mapping for `handle`; `base`
// points into that read-only mapping, and the manifest is immutable. Drop is
// the sole `dlclose`, after the last owner releases the loaded unit.
unsafe impl Send for LoadedTranslationUnit {}
// SAFETY: see `Send`; no field permits mutation of the dyld mapping.
unsafe impl Sync for LoadedTranslationUnit {}

impl Drop for LoadedTranslationUnit {
    fn drop(&mut self) {
        let _ = unsafe { libc::dlclose(self.handle.as_ptr()) };
    }
}

struct UnitFileLock(File);

impl Drop for UnitFileLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn encode_manifest(manifest: &TranslationUnitManifest) -> Result<Vec<u8>, std::io::Error> {
    bincode::serde::encode_to_vec(
        manifest,
        bincode::config::standard().with_limit::<MANIFEST_DECODE_LIMIT>(),
    )
    .map_err(|error| invalid_data(format!("encode translation unit manifest: {error}")))
}

fn decode_manifest(bytes: &[u8]) -> Result<TranslationUnitManifest, std::io::Error> {
    let (manifest, consumed) = bincode::serde::decode_from_slice(
        bytes,
        bincode::config::standard().with_limit::<MANIFEST_DECODE_LIMIT>(),
    )
    .map_err(|error| invalid_data(format!("decode translation unit manifest: {error}")))?;
    if consumed != bytes.len() {
        return Err(invalid_data(format!(
            "translation unit manifest has {} trailing bytes",
            bytes.len().saturating_sub(consumed),
        )));
    }
    Ok(manifest)
}

fn manifest_for_pending(
    pending: &PendingTranslationUnit,
    dylib_sha256: [u8; 32],
) -> TranslationUnitManifest {
    TranslationUnitManifest {
        schema: TRANSLATION_UNIT_SCHEMA_V2,
        key: pending.key.clone(),
        dylib_sha256,
        base_export: TRANSLATION_UNIT_BASE_EXPORT.to_owned(),
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
    fn create() -> std::io::Result<Self> {
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
        let preflight_manifest = manifest_for_pending(pending, [0; 32]);
        preflight_manifest
            .validate_ranges()
            .and_then(|()| preflight_manifest.validate_binding_data(&pending.binding_data))
            .and_then(|()| preflight_manifest.validate_binding_code(&pending.code))
            .map_err(|reason| UnitStoreError::new("validate pending unit", reason))?;
        let stem = pending.key.file_stem().map_err(|error| {
            UnitStoreError::with_source("derive unit filename", UnitMissReason::Schema, error)
        })?;
        // Winner selection must precede Mach-O emission and codesigning.
        // Toolchain workloads retire many identical siblings at once; taking
        // the per-key lock only after signing made every loser pay the full
        // signing cost even though exactly one pair could be published.
        let _lock = self.lock_unit(&stem)?;
        let (final_dylib, final_manifest) = self.final_paths(&stem);
        if final_dylib.is_file() && final_manifest.is_file() {
            return Ok(PublishOutcome::Existing);
        }
        if final_dylib.exists() {
            std::fs::remove_file(&final_dylib).map_err(|error| {
                UnitStoreError::with_source(
                    "remove partial dylib",
                    UnitMissReason::MissingPair,
                    error,
                )
            })?;
        }
        if final_manifest.exists() {
            std::fs::remove_file(&final_manifest).map_err(|error| {
                UnitStoreError::with_source(
                    "remove partial manifest",
                    UnitMissReason::MissingPair,
                    error,
                )
            })?;
        }
        let mut exports = vec![crate::aot::AotExport {
            name: TRANSLATION_UNIT_BASE_EXPORT,
            section: crate::aot::AotSection::Text,
            offset: 0,
        }];
        if !pending.binding_data.is_empty() {
            exports.push(crate::aot::AotExport {
                name: &pending.binding_export,
                section: crate::aot::AotSection::Data,
                offset: 0,
            });
        }
        let relocations = pending
            .binding_relocations
            .iter()
            .flat_map(|relocation| {
                [
                    crate::aot::AotCodeToDataRelocation {
                        adrp_offset: relocation.adrp_offset,
                        add_offset: relocation.add_offset,
                        data_offset: relocation.data_offset,
                    },
                    crate::aot::AotCodeToDataRelocation {
                        adrp_offset: relocation.miss_adrp_offset,
                        add_offset: relocation.miss_add_offset,
                        data_offset: relocation.data_offset,
                    },
                ]
            })
            .collect::<Vec<_>>();
        let image = crate::aot::AotImage {
            code: &pending.code,
            data: &pending.binding_data,
            exports: &exports,
            relocations: &relocations,
        };
        let dylib = crate::aot::emit_dylib(&image).map_err(|error| {
            UnitStoreError::with_source(
                "emit translation dylib",
                UnitMissReason::ManifestRange,
                error,
            )
        })?;
        let mut dylib_temp = tempfile::NamedTempFile::new_in(&self.path).map_err(|error| {
            UnitStoreError::with_source(
                "create dylib temporary",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        dylib_temp.write_all(&dylib).map_err(|error| {
            UnitStoreError::with_source("write dylib temporary", UnitMissReason::MissingPair, error)
        })?;
        dylib_temp.flush().map_err(|error| {
            UnitStoreError::with_source("flush dylib temporary", UnitMissReason::MissingPair, error)
        })?;
        dylib_temp.as_file().sync_all().map_err(|error| {
            UnitStoreError::with_source("sync dylib temporary", UnitMissReason::MissingPair, error)
        })?;
        sign_and_verify(dylib_temp.path())?;
        dylib_temp.as_file().sync_all().map_err(|error| {
            UnitStoreError::with_source(
                "sync signed dylib temporary",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        let signed_dylib = std::fs::read(dylib_temp.path()).map_err(|error| {
            UnitStoreError::with_source("read signed dylib", UnitMissReason::DylibDigest, error)
        })?;
        let manifest = manifest_for_pending(pending, Sha256::digest(&signed_dylib).into());
        manifest
            .validate_ranges()
            .map_err(|reason| UnitStoreError::new("validate manifest", reason))?;
        let manifest_bytes = encode_manifest(&manifest).map_err(|error| {
            UnitStoreError::with_source("encode manifest", UnitMissReason::Schema, error)
        })?;
        let mut manifest_temp = tempfile::NamedTempFile::new_in(&self.path).map_err(|error| {
            UnitStoreError::with_source(
                "create manifest temporary",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        manifest_temp.write_all(&manifest_bytes).map_err(|error| {
            UnitStoreError::with_source(
                "write manifest temporary",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        manifest_temp.flush().map_err(|error| {
            UnitStoreError::with_source(
                "flush manifest temporary",
                UnitMissReason::MissingPair,
                error,
            )
        })?;
        manifest_temp.as_file().sync_all().map_err(|error| {
            UnitStoreError::with_source(
                "sync manifest temporary",
                UnitMissReason::MissingPair,
                error,
            )
        })?;

        std::fs::rename(dylib_temp.path(), &final_dylib).map_err(|error| {
            UnitStoreError::with_source("publish dylib", UnitMissReason::MissingPair, error)
        })?;
        std::fs::rename(manifest_temp.path(), &final_manifest).map_err(|error| {
            UnitStoreError::with_source("publish manifest", UnitMissReason::MissingPair, error)
        })?;
        Ok(PublishOutcome::Winner)
    }

    pub fn claim_recording(&self, key: &TranslationUnitKey) -> Result<bool, UnitStoreError> {
        let stem = key.file_stem().map_err(|error| {
            UnitStoreError::with_source("derive unit filename", UnitMissReason::Schema, error)
        })?;
        let _lock = self.lock_unit(&stem)?;
        let (dylib, manifest) = self.final_paths(&stem);
        if dylib.is_file() && manifest.is_file() {
            return Ok(false);
        }
        let seen = self.path.join(format!("{stem}.seen"));
        if !seen.exists() {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(seen)
                .map_err(|error| {
                    UnitStoreError::with_source(
                        "mark first unit observation",
                        UnitMissReason::MissingPair,
                        error,
                    )
                })?;
            return Ok(false);
        }
        let builder = self.path.join(format!("{stem}.builder"));
        if let Ok(owner) = std::fs::read_to_string(&builder)
            && let Ok(owner) = owner.trim().parse::<i32>()
        {
            let rc = unsafe { libc::kill(owner, 0) };
            if rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                return Ok(false);
            }
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
        let stem = expected_key.file_stem().map_err(|error| {
            UnitStoreError::with_source("derive unit filename", UnitMissReason::Schema, error)
        })?;
        let (dylib_path, manifest_path) = self.final_paths(&stem);
        if !dylib_path.is_file() || !manifest_path.is_file() {
            return Err(UnitStoreError::new(
                "locate translation unit",
                UnitMissReason::MissingPair,
            ));
        }
        let manifest_bytes = std::fs::read(&manifest_path).map_err(|error| {
            UnitStoreError::with_source("read manifest", UnitMissReason::Schema, error)
        })?;
        let manifest: TranslationUnitManifest =
            decode_manifest(&manifest_bytes).map_err(|error| {
                UnitStoreError::with_source("decode manifest", UnitMissReason::Schema, error)
            })?;
        manifest
            .validate_ranges()
            .map_err(|reason| UnitStoreError::new("validate manifest", reason))?;
        if &manifest.key != expected_key {
            return Err(UnitStoreError::new(
                "validate unit identity",
                UnitMissReason::ImageIdentity,
            ));
        }
        manifest
            .validate_source(source_words)
            .map_err(|reason| UnitStoreError::new("validate unit source", reason))?;
        let dylib = std::fs::read(&dylib_path).map_err(|error| {
            UnitStoreError::with_source("read dylib", UnitMissReason::DylibDigest, error)
        })?;
        let digest: [u8; 32] = Sha256::digest(&dylib).into();
        if digest != manifest.dylib_sha256 {
            return Err(UnitStoreError::new(
                "validate dylib digest",
                UnitMissReason::DylibDigest,
            ));
        }
        let c_path = CString::new(dylib_path.as_os_str().as_bytes()).map_err(|error| {
            UnitStoreError::with_source("encode dylib path", UnitMissReason::Dlopen, error)
        })?;
        let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        let handle = std::ptr::NonNull::new(handle).ok_or_else(|| {
            UnitStoreError::new("dlopen translation unit", UnitMissReason::Dlopen)
        })?;
        let symbol = CString::new(manifest.base_export.as_bytes()).map_err(|error| {
            UnitStoreError::with_source("encode base export", UnitMissReason::Dlopen, error)
        })?;
        let base = unsafe { libc::dlsym(handle.as_ptr(), symbol.as_ptr()) };
        let Some(base) = std::ptr::NonNull::new(base.cast::<u8>()) else {
            let _ = unsafe { libc::dlclose(handle.as_ptr()) };
            return Err(UnitStoreError::new(
                "resolve translation unit base",
                UnitMissReason::Dlopen,
            ));
        };
        if !manifest.binding_relocations.is_empty() {
            let code_len = usize::try_from(manifest.code_len).map_err(|_| {
                let _ = unsafe { libc::dlclose(handle.as_ptr()) };
                UnitStoreError::new(
                    "validate mapped translation code",
                    UnitMissReason::ManifestRange,
                )
            })?;
            // SAFETY: `base` is the validated translation-unit text export and
            // schema validation bounds the declared code length. The mapping
            // remains live under `handle` for this validation.
            let mapped_code = unsafe { std::slice::from_raw_parts(base.as_ptr(), code_len) };
            if let Err(reason) = manifest.validate_binding_code(mapped_code) {
                let _ = unsafe { libc::dlclose(handle.as_ptr()) };
                return Err(UnitStoreError::new(
                    "validate mapped translation code",
                    reason,
                ));
            }
        }
        if manifest.binding_data_len != 0 {
            let binding_symbol =
                CString::new(manifest.binding_export.as_bytes()).map_err(|error| {
                    let _ = unsafe { libc::dlclose(handle.as_ptr()) };
                    UnitStoreError::with_source(
                        "encode binding export",
                        UnitMissReason::Dlopen,
                        error,
                    )
                })?;
            let binding_base =
                unsafe { libc::dlsym(handle.as_ptr(), binding_symbol.as_ptr()) }.cast::<u8>();
            let Some(binding_base) = std::ptr::NonNull::new(binding_base) else {
                let _ = unsafe { libc::dlclose(handle.as_ptr()) };
                return Err(UnitStoreError::new(
                    "resolve translation unit bindings",
                    UnitMissReason::Dlopen,
                ));
            };
            let binding_len = usize::try_from(manifest.binding_data_len).map_err(|_| {
                let _ = unsafe { libc::dlclose(handle.as_ptr()) };
                UnitStoreError::new(
                    "validate mapped binding cells",
                    UnitMissReason::ManifestRange,
                )
            })?;
            if !(binding_base.as_ptr() as usize).is_multiple_of(DIRECT_BINDING_CELL_SIZE as usize) {
                let _ = unsafe { libc::dlclose(handle.as_ptr()) };
                return Err(UnitStoreError::new(
                    "validate mapped binding alignment",
                    UnitMissReason::ManifestRange,
                ));
            }
            // SAFETY: the resolved binding export names the manifest-declared
            // data region, which stays mapped under `handle` during validation.
            let binding_data =
                unsafe { std::slice::from_raw_parts(binding_base.as_ptr(), binding_len) };
            if let Err(reason) = manifest.validate_binding_data(binding_data) {
                let _ = unsafe { libc::dlclose(handle.as_ptr()) };
                return Err(UnitStoreError::new("validate mapped binding cells", reason));
            }
        }
        Ok(LoadedTranslationUnit {
            manifest,
            base,
            handle,
        })
    }

    fn lock_unit(&self, stem: &str) -> Result<UnitFileLock, UnitStoreError> {
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
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(UnitStoreError::with_source(
                "lock unit",
                UnitMissReason::MissingPair,
                std::io::Error::last_os_error(),
            ));
        }
        Ok(UnitFileLock(lock))
    }

    fn final_paths(&self, stem: &str) -> (PathBuf, PathBuf) {
        (
            self.path.join(format!("{stem}.dylib")),
            self.path.join(format!("{stem}.manifest")),
        )
    }

    #[cfg(test)]
    fn directory(&self) -> &File {
        &self.directory
    }
}

fn sign_and_verify(path: &Path) -> Result<(), UnitStoreError> {
    let signed = std::process::Command::new("/usr/bin/codesign")
        .args(["-s", "-"])
        .arg(path)
        .output()
        .map_err(|error| {
            UnitStoreError::with_source("run codesign", UnitMissReason::Dlopen, error)
        })?;
    if !signed.status.success() {
        return Err(UnitStoreError::new(
            "sign translation unit",
            UnitMissReason::Dlopen,
        ));
    }
    let verified = std::process::Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict"])
        .arg(path)
        .output()
        .map_err(|error| {
            UnitStoreError::with_source("run codesign verification", UnitMissReason::Dlopen, error)
        })?;
    if !verified.status.success() {
        return Err(UnitStoreError::new(
            "verify translation unit signature",
            UnitMissReason::Dlopen,
        ));
    }
    Ok(())
}

impl Drop for ContainerCacheAuthority {
    fn drop(&mut self) {
        if self.cleanup_owner && owns_cleanup(self.creator_pid, unsafe { libc::getpid() }) {
            if std::env::var_os("CARRICK_DSR_KEEP_CONTAINER_CACHE").as_deref()
                == Some(std::ffi::OsStr::new("1"))
            {
                eprintln!("CARRICK_SHARED_CACHE_KEPT path={}", self.path.display());
                return;
            }
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Scope guard owned by the parent process that launched one native
/// container. Dropping it after the root guest exits removes the cache.
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
    let authority = ContainerCacheAuthority::create()?;
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
        let active = CONTAINER_CACHE
            .lock()
            .map_err(|_| UnitMissReason::MissingPair)?;
        let authority = active.as_ref().ok_or(UnitMissReason::MissingPair)?;
        match authority.load_unit(key, source_words) {
            Ok(loaded) => {
                let loaded = std::sync::Arc::new(loaded);
                let base = loaded.base.as_ptr() as usize;
                let manifest = loaded.manifest.clone();
                Ok(Some(
                    carrick_dsr_aarch64::shared_cache::SharedLoadedTranslationUnit::new(
                        manifest, base, loaded,
                    ),
                ))
            }
            Err(error) if error.reason() == UnitMissReason::MissingPair => Ok(None),
            Err(error) => Err(error.reason()),
        }
    }

    fn publish(&self, pending: &PendingTranslationUnit) -> Result<PublishOutcome, UnitMissReason> {
        let active = CONTAINER_CACHE
            .lock()
            .map_err(|_| UnitMissReason::MissingPair)?;
        let authority = active.as_ref().ok_or(UnitMissReason::MissingPair)?;
        authority
            .publish_unit(pending)
            .map_err(|error| error.reason())
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
    use carrick_dsr_aarch64::direct_binding::DirectBindingOrdinal;
    use carrick_dsr_aarch64::emit::DirectLinkKind;
    use carrick_dsr_aarch64::shared_cache::{
        AddressModeIdentity, DirectBindingLayout, DirectBindingRelocation, ExecutableIdentity,
        GuestCodeLen, ImageFileLen, ImageFileOffset, NativePageProfileIdentity, SourceFingerprint,
        TRANSLATION_UNIT_BINDING_EXPORT, UnresolvedDirectBindingRecord,
    };
    use carrick_guest_mem::GuestVa;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::PermissionsExt;

    const MOV42_RET: [u8; 8] = [0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6];

    fn fixture_pending() -> PendingTranslationUnit {
        let source_words = [u32::from_le_bytes(MOV42_RET[..4].try_into().expect("word"))];
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
            blocks: Vec::new(),
            binding_layout: DirectBindingLayout::Disabled,
            binding_export: String::new(),
            binding_data_len: 0,
            cell_size: 0,
            bindings: Vec::new(),
            binding_relocations: Vec::new(),
            binding_data: Vec::new(),
        }
    }

    fn fixture_manifest() -> TranslationUnitManifest {
        let pending = fixture_pending();
        TranslationUnitManifest {
            schema: TRANSLATION_UNIT_SCHEMA_V2,
            key: pending.key,
            dylib_sha256: [0x22; 32],
            base_export: TRANSLATION_UNIT_BASE_EXPORT.to_owned(),
            code_len: pending.code.len() as u64,
            blocks: pending.blocks,
            binding_layout: pending.binding_layout,
            binding_export: pending.binding_export,
            binding_data_len: pending.binding_data_len,
            cell_size: pending.cell_size,
            bindings: pending.bindings,
            binding_relocations: pending.binding_relocations,
        }
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
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
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
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let substitute = ContainerCacheAuthority::create().expect("create substitute authority");
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
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let substitute = ContainerCacheAuthority::create().expect("create substitute authority");
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

    #[test]
    fn creator_session_removes_cache_after_container_exit() {
        let session = begin_container_cache().expect("begin container cache");
        let path = container_cache_snapshot()
            .expect("snapshot container cache")
            .expect("active container cache")
            .path;
        assert!(path.is_dir());

        drop(session);

        assert!(!path.exists());
        assert!(
            container_cache_snapshot()
                .expect("snapshot inactive cache")
                .is_none()
        );
    }

    #[test]
    fn inherited_process_cannot_remove_creator_cache() {
        let mut authority = ContainerCacheAuthority::create().expect("create cache authority");
        let path = authority.path().to_path_buf();
        authority.creator_pid = unsafe { libc::getpid() }.saturating_add(1);

        drop(authority);

        assert!(path.is_dir());
        std::fs::remove_dir_all(path).expect("remove test cache");
    }

    #[test]
    fn adoption_takes_ownership_of_the_inherited_fd() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let snapshot = duplicated_snapshot(&authority);
        let inherited_fd = snapshot.host_fd;
        let adopted = ContainerCacheAuthority::adopt(&snapshot).expect("adopt cache authority");
        drop(adopted);

        let borrowed = unsafe { std::fs::File::from_raw_fd(inherited_fd) };
        let result = unsafe { libc::fcntl(borrowed.as_raw_fd(), libc::F_GETFD) };
        std::mem::forget(borrowed);
        assert_eq!(result, -1);
    }

    #[test]
    fn concurrent_publishers_converge_on_one_signed_unit() {
        let authority =
            std::sync::Arc::new(ContainerCacheAuthority::create().expect("create cache authority"));
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
            PublishOutcome::Existing => 1,
        });
        assert_eq!(
            outcomes,
            vec![PublishOutcome::Winner, PublishOutcome::Existing]
        );

        let source_words = [u32::from_le_bytes(MOV42_RET[..4].try_into().expect("word"))];
        let loaded = authority
            .load_unit(&pending.key, &source_words)
            .expect("load published unit");
        let function: extern "C" fn() -> i32 = unsafe { std::mem::transmute(loaded.base.as_ptr()) };
        assert_eq!(function(), 42);
        assert!(
            std::fs::read_dir(authority.path())
                .expect("read cache directory")
                .filter_map(Result::ok)
                .all(|entry| !entry.file_name().to_string_lossy().starts_with(".tmp")),
            "publisher left a temporary file"
        );
    }

    #[test]
    fn publisher_emits_and_loads_complete_binding_sidecar() {
        fn decoded_cell_address(
            code: &[u8],
            code_addr: usize,
            adrp_offset: usize,
            add_offset: usize,
        ) -> usize {
            let adrp = u32::from_le_bytes(
                code[adrp_offset..adrp_offset + 4]
                    .try_into()
                    .expect("mapped ADRP"),
            );
            let add = u32::from_le_bytes(
                code[add_offset..add_offset + 4]
                    .try_into()
                    .expect("mapped ADD"),
            );
            let immediate = (((adrp >> 5) & 0x7ffff) << 2) | ((adrp >> 29) & 0x3);
            let delta_pages = i128::from(((immediate << 11) as i32) >> 11);
            let pc_page = (code_addr + adrp_offset) & !0xfff;
            (pc_page as i128 + delta_pages * 4096) as usize + ((add >> 10) & 0xfff) as usize
        }

        let authority = ContainerCacheAuthority::create().expect("create cache authority");
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
        pending.binding_data_len = 8;
        pending.cell_size = 8;
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
        pending.binding_data = vec![0; 8];

        assert_eq!(
            authority
                .publish_unit(&pending)
                .expect("publish complete sidecar"),
            PublishOutcome::Winner
        );
        let source_words = [u32::from_le_bytes(MOV42_RET[..4].try_into().expect("word"))];
        let loaded = authority
            .load_unit(&pending.key, &source_words)
            .expect("load complete sidecar");
        let binding_symbol =
            CString::new(TRANSLATION_UNIT_BINDING_EXPORT).expect("binding export CString");
        let binding_base =
            unsafe { libc::dlsym(loaded.handle.as_ptr(), binding_symbol.as_ptr()) }.cast::<u8>();
        let binding_base = std::ptr::NonNull::new(binding_base).expect("resolve binding export");
        assert!((binding_base.as_ptr() as usize).is_multiple_of(DIRECT_BINDING_CELL_SIZE as usize));
        // SAFETY: the base export and manifest code length were validated by
        // `load_unit`; the dlopen handle remains owned by `loaded`.
        let mapped_code =
            unsafe { std::slice::from_raw_parts(loaded.base.as_ptr(), pending.code.len()) };
        for (adrp_offset, add_offset) in [(52, 56), (140, 144)] {
            assert_eq!(
                decoded_cell_address(
                    mapped_code,
                    loaded.base.as_ptr() as usize,
                    adrp_offset,
                    add_offset,
                ),
                binding_base.as_ptr() as usize,
                "hit and miss sites must both address the same binding cell"
            );
        }
        assert_eq!(
            unsafe { std::slice::from_raw_parts(binding_base.as_ptr(), 8) },
            &[0; 8]
        );
        assert_eq!(
            authority
                .publish_unit(&pending)
                .expect("republish complete sidecar"),
            PublishOutcome::Existing
        );
    }

    #[test]
    fn manifest_wire_format_is_materially_smaller_than_json() {
        let manifest = fixture_manifest();
        let json = serde_json::to_vec(&manifest).expect("encode comparison JSON");
        let encoded = encode_manifest(&manifest).expect("encode compact manifest");
        let decoded = decode_manifest(&encoded).expect("decode compact manifest");

        assert_eq!(decoded, manifest);
        assert!(
            encoded.len().saturating_mul(2) < json.len(),
            "compact manifest is {} bytes versus {} bytes of JSON",
            encoded.len(),
            json.len(),
        );
    }

    #[test]
    fn recurring_unit_elects_exactly_one_recorder() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let key = fixture_pending().key;

        assert!(
            !authority
                .claim_recording(&key)
                .expect("record first observation"),
            "a one-off executable must not pay portable recording cost"
        );
        assert!(
            authority
                .claim_recording(&key)
                .expect("elect second observation"),
            "the second process proves recurrence and owns recording"
        );
        assert!(
            !authority
                .claim_recording(&key)
                .expect("observe live recorder"),
            "a live recorder must exclude the thundering herd"
        );
    }

    #[test]
    fn partial_publish_pair_is_never_loadable() {
        let authority = ContainerCacheAuthority::create().expect("create cache authority");
        let pending = fixture_pending();
        let stem = pending.key.file_stem().expect("unit stem");
        let (dylib, manifest) = authority.final_paths(&stem);
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
        std::fs::write(&dylib, MOV42_RET).expect("write lone dylib");
        assert_eq!(
            authority
                .load_unit(&pending.key, &source_words)
                .expect_err("lone dylib must miss")
                .reason(),
            UnitMissReason::MissingPair
        );
    }
}
