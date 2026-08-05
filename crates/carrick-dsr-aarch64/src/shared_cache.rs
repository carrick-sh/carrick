//! Portable identity and wire contracts for immutable AArch64 translation units.

use carrick_dsr::address::NativeHostBias;
use carrick_guest_mem::GuestVa;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

// 4: the reserved-resident virtualization template (new emitted shapes and
// the `CommitReservedResident` recovery action, wire tag 21).
// 5: the lean indirect-branch lookup (flag-free probe, flavor-gated
// trusted-entry hit path, relocated authority switch) and the
// `RestoreIndirectLean`/`RestoreIndirectLeanCall` recovery actions
// (wire tags 22/23).
// 6: the indirect-cache entry's flavor-1 payload packed for paired loads
// (tagged expected at offset 8, code at 24).
// 7: unit payload is the native-emission recording tap — per-block
// `ArtifactTemplate` metadata (relocations + trusted entry + direct links)
// over unbaked `.code` words, installed by per-block replay through
// `publish_emitted`. Replaces the `GenerationGuard::BindingIndex` authority
// emission, edge trampolines, and the direct-binding cell sidecar.
// 8: offset-indexed metadata (`CUNITV5`): a fixed-width per-block index up
// front, then per-block HOT (relocations/trusted entry/links — replay) and
// COLD (pc map/recovery — fault reconstruction) streams, each its own
// bincode blob. Attach parses ONLY the index; a block's hot blob decodes on
// its first lookup and its cold blob only if a fault interrogates it. The
// v4 whole-manifest decode cost more per exec than the retranslation the
// store avoided (~11.6 ms of ~1.79M-record varint decode on the go
// toolchain unit, ~98% of it pc map + recovery).
pub const TRANSLATOR_ABI_CURRENT: u32 = 8;
pub const TRANSLATION_UNIT_SCHEMA_V5: u32 = 5;
pub const MAX_TRANSLATION_UNIT_CODE_BYTES: usize = 64 * 1024 * 1024;
pub const TRANSLATION_UNIT_BASE_EXPORT: &str = "carrick_aot_unit_base";
const DARWIN_HOST_PAGE_SIZE: u64 = 16 * 1024;
static SHARED_MANIFEST_ARC_ENABLED: OnceLock<bool> = OnceLock::new();
static SHARED_SOURCE_FINGERPRINT_REUSE_ENABLED: OnceLock<bool> = OnceLock::new();
static SHARED_RECOVERY_RUNS_ENABLED: OnceLock<bool> = OnceLock::new();

fn shared_manifest_arc_enabled_from(value: Option<&std::ffi::OsStr>) -> bool {
    value != Some(std::ffi::OsStr::new("0"))
}

fn shared_manifest_arc_enabled() -> bool {
    *SHARED_MANIFEST_ARC_ENABLED.get_or_init(|| {
        let value = std::env::var_os("CARRICK_DSR_SHARED_MANIFEST_ARC");
        shared_manifest_arc_enabled_from(value.as_deref())
    })
}

fn retain_loaded_manifest(manifest: Arc<TranslationUnitManifest>) -> Arc<TranslationUnitManifest> {
    if shared_manifest_arc_enabled() {
        manifest
    } else {
        Arc::new((*manifest).clone())
    }
}

fn shared_source_fingerprint_reuse_enabled_from(value: Option<&std::ffi::OsStr>) -> bool {
    value != Some(std::ffi::OsStr::new("0"))
}

pub fn shared_source_fingerprint_reuse_enabled() -> bool {
    *SHARED_SOURCE_FINGERPRINT_REUSE_ENABLED.get_or_init(|| {
        let value = std::env::var_os("CARRICK_DSR_SHARED_SOURCE_FINGERPRINT_REUSE");
        shared_source_fingerprint_reuse_enabled_from(value.as_deref())
    })
}

fn shared_recovery_runs_enabled_from(value: Option<&std::ffi::OsStr>) -> bool {
    value != Some(std::ffi::OsStr::new("0"))
}

fn shared_recovery_runs_enabled() -> bool {
    *SHARED_RECOVERY_RUNS_ENABLED.get_or_init(|| {
        let value = std::env::var_os("CARRICK_DSR_SHARED_RECOVERY_RUNS");
        shared_recovery_runs_enabled_from(value.as_deref())
    })
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct SourceFingerprint(pub [u8; 32]);

impl SourceFingerprint {
    pub fn from_words(words: &[u32]) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"carrick-aarch64-shared-source-v1");
        digest.update((words.len() as u64).to_le_bytes());
        for word in words {
            digest.update(word.to_le_bytes());
        }
        Self(digest.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum NativePageProfileIdentity {
    Native16k,
    Linux4kOn16k,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum ExecutableIdentity {
    HostFile {
        device: u64,
        inode: u64,
        size: u64,
        mtime_seconds: i64,
        mtime_nanoseconds: i64,
    },
    Digest([u8; 32]),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ImageFileOffset(u64);

impl ImageFileOffset {
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ImageFileLen(u64);

impl ImageFileLen {
    pub const fn new(raw: u64) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GuestCodeLen(u64);

impl GuestCodeLen {
    pub const fn new(raw: u64) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HostBiasIdentity(u64);

impl HostBiasIdentity {
    const fn from_validated(bias: NativeHostBias) -> Self {
        Self(bias.get())
    }

    fn from_wire(raw: u64) -> Option<Self> {
        NativeHostBias::new(raw, DARWIN_HOST_PAGE_SIZE)
            .ok()
            .map(Self::from_validated)
    }

    const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AddressModeIdentity {
    Direct,
    Biased { host_bias: HostBiasIdentity },
}

impl AddressModeIdentity {
    pub const fn biased(host_bias: NativeHostBias) -> Self {
        Self::Biased {
            host_bias: HostBiasIdentity::from_validated(host_bias),
        }
    }

    pub const fn host_bias(self) -> Option<u64> {
        match self {
            Self::Direct => None,
            Self::Biased { host_bias } => Some(host_bias.get()),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TranslationUnitKey {
    executable: ExecutableIdentity,
    segment_file_offset: ImageFileOffset,
    segment_file_len: ImageFileLen,
    guest_va_start: GuestVa,
    guest_va_len: GuestCodeLen,
    source_fingerprint: SourceFingerprint,
    page_profile: NativePageProfileIdentity,
    address_mode: AddressModeIdentity,
    translator_abi: u32,
}

impl TranslationUnitKey {
    #[allow(clippy::too_many_arguments)]
    pub fn for_segment(
        executable: ExecutableIdentity,
        segment_file_offset: ImageFileOffset,
        segment_file_len: ImageFileLen,
        guest_va_start: GuestVa,
        guest_va_len: GuestCodeLen,
        source_fingerprint: SourceFingerprint,
        page_profile: NativePageProfileIdentity,
        address_mode: AddressModeIdentity,
    ) -> Self {
        Self {
            executable,
            segment_file_offset,
            segment_file_len,
            guest_va_start,
            guest_va_len,
            source_fingerprint,
            page_profile,
            address_mode,
            translator_abi: TRANSLATOR_ABI_CURRENT,
        }
    }

    pub const fn guest_va_start(&self) -> GuestVa {
        self.guest_va_start
    }

    pub const fn source_fingerprint(&self) -> SourceFingerprint {
        self.source_fingerprint
    }

    pub const fn translator_abi(&self) -> u32 {
        self.translator_abi
    }

    pub const fn host_bias(&self) -> Option<u64> {
        self.address_mode.host_bias()
    }

    /// Domain-separated fixed-width identity for the live translation arena.
    ///
    /// This deliberately hashes the complete exact key encoding rather than
    /// deriving from [`Self::file_stem`]: a live arena record must bind every
    /// existing unit determinant, never a basename or another partial key.
    pub fn live_digest(&self) -> Result<[u8; 32], serde_json::Error> {
        let encoded = serde_json::to_vec(self)?;
        let mut digest = Sha256::new();
        digest.update(b"carrick-live-arena-v1");
        digest.update(crate::live_arena::LIVE_ARENA_SCHEMA_V1.to_le_bytes());
        digest.update(TRANSLATOR_ABI_CURRENT.to_le_bytes());
        digest.update(encoded);
        Ok(digest.finalize().into())
    }

    pub fn file_stem(&self) -> Result<String, serde_json::Error> {
        let encoded = serde_json::to_vec(self)?;
        let digest: [u8; 32] = Sha256::digest(encoded).into();
        let mut stem = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(stem, "{byte:02x}");
        }
        Ok(stem)
    }
}

/// A per-key identity string retained in the manifest (`base_export`) and
/// validated on both sides of the store. Under the retired dylib transport it
/// named the unit's `dlsym` export; the copy transport keeps it purely as a
/// manifest-to-key binding check.
pub fn translation_unit_base_export(key: &TranslationUnitKey) -> Result<String, serde_json::Error> {
    Ok(format!(
        "{TRANSLATION_UNIT_BASE_EXPORT}_{}",
        key.file_stem()?
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableBlockRecord {
    pub guest_start: GuestVa,
    pub entry_offset: u32,
    pub code_len: u32,
    pub requires_sensitive_metadata: bool,
    /// The block's native-emission recording with `words` and `source_words`
    /// cleared: the words live in the unit's digest-bound `.code` image at
    /// `entry_offset`, and the unit key fingerprints the whole segment.
    /// Relocations, the trusted entry, direct links, the PC map, and
    /// recovery are all retained so the install can replay the block into
    /// the private cache exactly like a native emission.
    pub template: crate::artifact_spike::ArtifactTemplate,
}

/// One block of a loaded unit as the fixed-width index describes it. The
/// hot/cold blob extents are parsed alongside but stay private: blob bytes
/// are reached through the manifest's private `block_hot` / `block_cold`
/// accessors, never raw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitBlockIndexEntry {
    pub guest_start: GuestVa,
    pub entry_offset: u32,
    pub code_len: u32,
    pub requires_sensitive_metadata: bool,
    /// Absolute offset of this block's hot blob within the payload region;
    /// the cold blob follows it immediately (tight packing is enforced at
    /// decode).
    payload_offset: usize,
    hot_len: usize,
    cold_len: usize,
}

impl UnitBlockIndexEntry {
    /// Serialized size of the block's HOT (replay) blob — diagnostics only.
    pub fn hot_blob_len(&self) -> usize {
        self.hot_len
    }

    /// Serialized size of the block's COLD (fault) blob — diagnostics only.
    pub fn cold_blob_len(&self) -> usize {
        self.cold_len
    }
}

/// The undecoded per-block blob region, pinned by whatever owns the bytes
/// (the store's metadata mmap, or an in-memory encode for fixtures).
#[derive(Clone)]
struct UnitPayload {
    bytes: Arc<dyn AsRef<[u8]> + Send + Sync>,
    start: usize,
    len: usize,
}

impl UnitPayload {
    fn as_slice(&self) -> &[u8] {
        let all: &[u8] = (*self.bytes).as_ref();
        // The decode that built this payload bounds-checked start/len against
        // the buffer; an sliced-out-of-range here would be a construction bug.
        &all[self.start..self.start + self.len]
    }
}

/// A loaded unit's metadata: the decoded header and fixed-width block
/// index, over the UNDECODED per-block hot/cold blob payload. Per-block
/// templates decode on demand — never as part of loading the unit.
#[derive(Clone)]
pub struct TranslationUnitManifest {
    pub schema: u32,
    pub key: TranslationUnitKey,
    pub code_sha256: [u8; 32],
    pub base_export: String,
    pub code_len: u64,
    index: Vec<UnitBlockIndexEntry>,
    payload: UnitPayload,
}

impl std::fmt::Debug for TranslationUnitManifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TranslationUnitManifest")
            .field("schema", &self.schema)
            .field("key", &self.key)
            .field("code_len", &self.code_len)
            .field("blocks", &self.index.len())
            .field("payload_len", &self.payload.len)
            .finish_non_exhaustive()
    }
}

impl PartialEq for TranslationUnitManifest {
    fn eq(&self, other: &Self) -> bool {
        self.schema == other.schema
            && self.key == other.key
            && self.code_sha256 == other.code_sha256
            && self.base_export == other.base_export
            && self.code_len == other.code_len
            && self.index == other.index
            && self.payload.as_slice() == other.payload.as_slice()
    }
}

impl Eq for TranslationUnitManifest {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingTranslationUnit {
    pub key: TranslationUnitKey,
    /// Concatenated per-block template words, relocation immediates ZEROED
    /// (unbaked). Nothing is patched at pack time: same-unit links, trusted
    /// entries, and process values are all resolved at install by per-block
    /// replay plus `publish_emitted`'s pending-link patching.
    pub code: Vec<u8>,
    pub blocks: Vec<PortableBlockRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableBlockCandidate {
    pub guest_start: GuestVa,
    pub requires_sensitive_metadata: bool,
    /// The FULL native-tap recording (`ArtifactRecord::template` from the
    /// one native emission), words included.
    pub template: crate::artifact_spike::ArtifactTemplate,
}

impl PendingTranslationUnit {
    pub fn pack(
        key: TranslationUnitKey,
        candidates: Vec<PortableBlockCandidate>,
    ) -> Result<Self, crate::types::DsrError> {
        Self::pack_with_recovery_runs(key, candidates, shared_recovery_runs_enabled())
    }

    fn pack_with_recovery_runs(
        key: TranslationUnitKey,
        candidates: Vec<PortableBlockCandidate>,
        recovery_runs: bool,
    ) -> Result<Self, crate::types::DsrError> {
        #[cfg(feature = "alloc-owner-census")]
        let _owner = crate::alloc_owner_census::scope(
            crate::alloc_owner_wire::AllocationOwner::SharedTranslationSupport,
        );
        let mut code = Vec::new();
        let mut blocks = Vec::with_capacity(candidates.len());
        let mut guest_starts = BTreeSet::new();
        for candidate in candidates {
            let words = candidate.template.words();
            if words.is_empty() {
                return Err(crate::types::DsrError::CachePolicy(format!(
                    "translation unit candidate 0x{:x} carries no recorded words",
                    candidate.guest_start.raw()
                )));
            }
            let entry_offset = u32::try_from(code.len()).map_err(|_| {
                crate::types::DsrError::CachePolicy(
                    "translation unit entry offset exceeds u32".to_string(),
                )
            })?;
            let code_len = u32::try_from(words.len().saturating_mul(4)).map_err(|_| {
                crate::types::DsrError::CachePolicy(
                    "translation unit block length exceeds u32".to_string(),
                )
            })?;
            if code.len().saturating_add(code_len as usize) > MAX_TRANSLATION_UNIT_CODE_BYTES {
                return Err(crate::types::DsrError::CachePolicy(
                    "translation unit exceeds the 64 MiB branch-range cap".to_string(),
                ));
            }
            if !guest_starts.insert(candidate.guest_start) {
                return Err(crate::types::DsrError::CachePolicy(format!(
                    "translation unit contains duplicate block 0x{:x}",
                    candidate.guest_start.raw()
                )));
            }
            for word in words {
                code.extend_from_slice(&word.to_le_bytes());
            }
            blocks.push(PortableBlockRecord {
                guest_start: candidate.guest_start,
                entry_offset,
                code_len,
                requires_sensitive_metadata: candidate.requires_sensitive_metadata,
                template: candidate
                    .template
                    .into_unit_record_metadata(recovery_runs)?,
            });
        }
        if code.is_empty() {
            return Err(crate::types::DsrError::CachePolicy(
                "translation unit contains no blocks".to_string(),
            ));
        }
        Ok(Self { key, code, blocks })
    }
}

/// Which manifest invariant a preflight rejected. `UnitMissReason::ManifestRange`
/// collapses eight distinct checks into one value, which is fine for a load-path
/// miss (any of them means "do not use this unit") but useless on the PUBLISH
/// path, where the same value means "carrick built a unit its own validator
/// refuses" and the operator needs to know which rule broke. Measured: a cold
/// go build makes 33 recording claims, attempts 33 publications, and publishes
/// zero units, 30 of them rejected as `ManifestRange` with no further detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestDefect {
    Schema,
    TranslatorAbi,
    BaseExport,
    CodeLen,
    BlockGeometry,
    BlockGuestDuplicate,
    BlockExtentOverlap,
    BlockTemplate,
}

impl ManifestDefect {
    pub const fn reason(self) -> UnitMissReason {
        match self {
            Self::Schema | Self::BaseExport | Self::CodeLen => UnitMissReason::Schema,
            Self::TranslatorAbi => UnitMissReason::TranslatorAbi,
            _ => UnitMissReason::ManifestRange,
        }
    }
}

/// Why a translation-unit lookup did not produce a unit.
///
/// These are counted per process by the translation census
/// (`crate::translator::xlat_census`), so a value here is an ANSWER to "where
/// did the shared lane's coverage go", not just an error tag. That is why
/// [`Self::NoAuthority`] and [`Self::StoreUnavailable`] are separate from
/// [`Self::MissingPair`]: a process that never adopted the container cache and
/// a process whose lookups genuinely missed on disk used to be indistinguishable
/// at every observable point, which is exactly the conflation that made the
/// "one key in the cache directory" result unattributable.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UnitMissReason {
    /// The unit's files are not present in the store. On the load path this is
    /// a genuine cache miss.
    MissingPair,
    /// No container cache authority is installed in THIS process, so no lookup
    /// could have hit whatever the store holds. Distinct from a miss.
    NoAuthority,
    /// The store's own lock is poisoned: a thread panicked holding it. Neither
    /// a miss nor an absent authority — a runtime fault that would otherwise
    /// read as one of them.
    StoreUnavailable,
    Schema,
    TranslatorAbi,
    ImageIdentity,
    SourceFingerprint,
    AddressMode,
    PageProfile,
    CodeDigest,
    ManifestRange,
    CodeMapping,
}

impl UnitMissReason {
    /// Every reason, in wire order. The census indexes its counters by
    /// [`Self::index`], which is a position in this table.
    pub const ALL: [Self; 12] = [
        Self::MissingPair,
        Self::NoAuthority,
        Self::StoreUnavailable,
        Self::Schema,
        Self::TranslatorAbi,
        Self::ImageIdentity,
        Self::SourceFingerprint,
        Self::AddressMode,
        Self::PageProfile,
        Self::CodeDigest,
        Self::ManifestRange,
        Self::CodeMapping,
    ];

    /// Stable wire token used by the census file and by anything that reports
    /// these to a human.
    pub const fn token(self) -> &'static str {
        match self {
            Self::MissingPair => "missing-pair",
            Self::NoAuthority => "no-authority",
            Self::StoreUnavailable => "store-unavailable",
            Self::Schema => "schema",
            Self::TranslatorAbi => "translator-abi",
            Self::ImageIdentity => "image-identity",
            Self::SourceFingerprint => "source-fingerprint",
            Self::AddressMode => "address-mode",
            Self::PageProfile => "page-profile",
            Self::CodeDigest => "code-digest",
            Self::ManifestRange => "manifest-range",
            Self::CodeMapping => "code-mapping",
        }
    }

    /// Inverse of [`Self::token`]. Fails closed on an unknown token so a census
    /// written by a different build is reported rather than silently dropped.
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|reason| reason.token() == token)
    }

    /// Position in [`Self::ALL`]; the census's counter index.
    pub const fn index(self) -> usize {
        match self {
            Self::MissingPair => 0,
            Self::NoAuthority => 1,
            Self::StoreUnavailable => 2,
            Self::Schema => 3,
            Self::TranslatorAbi => 4,
            Self::ImageIdentity => 5,
            Self::SourceFingerprint => 6,
            Self::AddressMode => 7,
            Self::PageProfile => 8,
            Self::CodeDigest => 9,
            Self::ManifestRange => 10,
            Self::CodeMapping => 11,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    Winner,
    Existing,
    /// Another process held the unit's store lock: it is emitting this same
    /// unit right now, so this publisher dropped its copy instead of
    /// blocking on a rival's emission.
    Yielded,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TranslationMetadataLoadEvidence {
    pub bytes_read: u64,
    pub bytes_mapped: u64,
    pub validation_ns: u64,
    /// Physical manifest table entries retained after load (blocks plus
    /// their per-block template records).
    pub owned_records: u64,
}

pub struct SharedLoadedTranslationUnit {
    // Fields drop in declaration order.
    _lease: Arc<dyn Send + Sync>,
    pub manifest: Arc<TranslationUnitManifest>,
    /// Address of the unit's READABLE translated-code bytes
    /// (`manifest.code_len` long), pinned by `_lease`. Nothing executes at
    /// this address: the install replays each block's words into this
    /// process's own `MAP_JIT` translation cache.
    pub source_base: usize,
    pub load_evidence: TranslationMetadataLoadEvidence,
}

impl Clone for SharedLoadedTranslationUnit {
    fn clone(&self) -> Self {
        Self {
            _lease: Arc::clone(&self._lease),
            manifest: if shared_manifest_arc_enabled() {
                Arc::clone(&self.manifest)
            } else {
                Arc::new((*self.manifest).clone())
            },
            source_base: self.source_base,
            load_evidence: self.load_evidence,
        }
    }
}

impl SharedLoadedTranslationUnit {
    pub fn new(
        manifest: impl Into<Arc<TranslationUnitManifest>>,
        source_base: usize,
        lease: Arc<dyn Send + Sync>,
    ) -> Self {
        Self::new_with_evidence(
            manifest,
            source_base,
            TranslationMetadataLoadEvidence::default(),
            lease,
        )
    }

    pub fn new_with_evidence(
        manifest: impl Into<Arc<TranslationUnitManifest>>,
        source_base: usize,
        load_evidence: TranslationMetadataLoadEvidence,
        lease: Arc<dyn Send + Sync>,
    ) -> Self {
        Self {
            _lease: lease,
            manifest: retain_loaded_manifest(manifest.into()),
            source_base,
            load_evidence,
        }
    }

    pub fn key(&self) -> &TranslationUnitKey {
        &self.manifest.key
    }
}

pub trait TranslationUnitStore: Send + Sync {
    fn load(
        &self,
        key: &TranslationUnitKey,
        source_words: &[u32],
    ) -> Result<Option<SharedLoadedTranslationUnit>, UnitMissReason>;

    fn publish(&self, pending: &PendingTranslationUnit) -> Result<PublishOutcome, UnitMissReason>;

    /// Elect at most one portable-template recorder after a unit has proven
    /// that it recurs in this container. The default keeps fixture and
    /// non-Darwin stores simple; Darwin persists the election in the private
    /// container cache directory.
    fn claim_recording(&self, _key: &TranslationUnitKey) -> bool {
        true
    }
}

#[derive(Clone, Debug)]
pub struct SharedImageConfig {
    pub executable: ExecutableIdentity,
    pub page_profile: NativePageProfileIdentity,
    pub address_mode: AddressModeIdentity,
    pub segments: Vec<SharedExecutableSegment>,
}

#[derive(Clone, Debug)]
pub struct SharedExecutableSegment {
    pub file_offset: ImageFileOffset,
    pub file_len: ImageFileLen,
    pub guest_start: GuestVa,
    pub guest_len: GuestCodeLen,
    pub source_words: Arc<[u32]>,
    source_fingerprint: SourceFingerprint,
}

impl SharedExecutableSegment {
    pub fn new(
        file_offset: ImageFileOffset,
        file_len: ImageFileLen,
        guest_start: GuestVa,
        guest_len: GuestCodeLen,
        source_words: Arc<[u32]>,
    ) -> Self {
        let source_fingerprint = SourceFingerprint::from_words(&source_words);
        Self {
            file_offset,
            file_len,
            guest_start,
            guest_len,
            source_words,
            source_fingerprint,
        }
    }

    pub const fn source_fingerprint(&self) -> SourceFingerprint {
        self.source_fingerprint
    }
}

impl SharedImageConfig {
    pub fn executable_digest(&self) -> Option<[u8; 32]> {
        match &self.executable {
            ExecutableIdentity::Digest(digest) => Some(*digest),
            ExecutableIdentity::HostFile { .. } => None,
        }
    }

    pub fn key_for_segment(&self, segment: &SharedExecutableSegment) -> TranslationUnitKey {
        self.key_for_segment_with_fingerprint_reuse(
            segment,
            shared_source_fingerprint_reuse_enabled(),
        )
    }

    fn key_for_segment_with_fingerprint_reuse(
        &self,
        segment: &SharedExecutableSegment,
        reuse: bool,
    ) -> TranslationUnitKey {
        let source_fingerprint = if reuse {
            segment.source_fingerprint()
        } else {
            SourceFingerprint::from_words(&segment.source_words)
        };
        TranslationUnitKey::for_segment(
            self.executable.clone(),
            segment.file_offset,
            segment.file_len,
            segment.guest_start,
            segment.guest_len,
            source_fingerprint,
            self.page_profile,
            self.address_mode,
        )
    }
}

impl TranslationUnitManifest {
    pub fn validate_source(&self, source_words: &[u32]) -> Result<(), UnitMissReason> {
        if self.key.source_fingerprint() != SourceFingerprint::from_words(source_words) {
            return Err(UnitMissReason::SourceFingerprint);
        }
        Ok(())
    }

    /// Load-path form: any defect is one `UnitMissReason` and the unit is not
    /// used. Publication should call [`Self::validate_ranges_detailed`], whose
    /// error names the specific broken invariant.
    pub fn validate_ranges(&self) -> Result<(), UnitMissReason> {
        self.validate_ranges_detailed()
            .map_err(ManifestDefect::reason)
    }

    /// Index-level invariants ONLY — no per-block blob is decoded. This is
    /// the load/attach gate; it must stay proportional to the block COUNT,
    /// never the metadata size, or the attach cost the v5 wire removed
    /// creeps back.
    pub fn validate_ranges_detailed(&self) -> Result<(), ManifestDefect> {
        if self.schema != TRANSLATION_UNIT_SCHEMA_V5 {
            return Err(ManifestDefect::Schema);
        }
        if self.key.translator_abi() != TRANSLATOR_ABI_CURRENT {
            return Err(ManifestDefect::TranslatorAbi);
        }
        let expected_base_export =
            translation_unit_base_export(&self.key).map_err(|_| ManifestDefect::Schema)?;
        if self.base_export != expected_base_export {
            return Err(ManifestDefect::BaseExport);
        }
        if self.code_len == 0 || self.code_len > MAX_TRANSLATION_UNIT_CODE_BYTES as u64 {
            return Err(ManifestDefect::CodeLen);
        }
        let mut guest_starts = BTreeSet::new();
        let mut cache_extents = Vec::with_capacity(self.index.len());
        for block in &self.index {
            let end = u64::from(block.entry_offset)
                .checked_add(u64::from(block.code_len))
                .ok_or(ManifestDefect::BlockGeometry)?;
            if block.code_len == 0
                || !block.entry_offset.is_multiple_of(4)
                || !block.code_len.is_multiple_of(4)
                || end > self.code_len
            {
                return Err(ManifestDefect::BlockGeometry);
            }
            if !guest_starts.insert(block.guest_start) {
                return Err(ManifestDefect::BlockGuestDuplicate);
            }
            cache_extents.push((u64::from(block.entry_offset), end));
        }
        cache_extents.sort_unstable();
        if cache_extents.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(ManifestDefect::BlockExtentOverlap);
        }
        Ok(())
    }

    /// Publication-preflight form: decode EVERY block's hot and cold blobs
    /// and re-check what the index alone cannot see — a stored record must
    /// carry no words of its own (the words live in the digest-bound
    /// `.code` image) and every replay-relevant offset must land inside its
    /// block extent. Load never runs this (a corrupt blob fails closed at
    /// replay, per block); publication does, so a unit carrick built that
    /// its own validators refuse names the defect BEFORE it is renamed
    /// into the store.
    pub fn validate_deep(&self) -> Result<(), ManifestDefect> {
        self.validate_ranges_detailed()?;
        for at in 0..self.index.len() {
            let record = self
                .block_record(at)
                .map_err(|_| ManifestDefect::BlockTemplate)?;
            let counts = record.template.metadata_counts();
            if counts.words != 0 || counts.source_words != 0 {
                return Err(ManifestDefect::BlockTemplate);
            }
            if !record
                .template
                .replay_metadata_fits_code_len(record.code_len)
            {
                return Err(ManifestDefect::BlockTemplate);
            }
        }
        Ok(())
    }

    /// The fixed-width block index, in wire order. Attach iterates this;
    /// nothing here required a blob decode.
    pub fn blocks(&self) -> &[UnitBlockIndexEntry] {
        &self.index
    }

    fn blob(&self, at: usize, cold: bool) -> Result<&[u8], UnitMissReason> {
        let entry = self.index.get(at).ok_or(UnitMissReason::ManifestRange)?;
        let payload = self.payload.as_slice();
        let start = if cold {
            entry
                .payload_offset
                .checked_add(entry.hot_len)
                .ok_or(UnitMissReason::ManifestRange)?
        } else {
            entry.payload_offset
        };
        let len = if cold { entry.cold_len } else { entry.hot_len };
        let end = start
            .checked_add(len)
            .ok_or(UnitMissReason::ManifestRange)?;
        payload.get(start..end).ok_or(UnitMissReason::ManifestRange)
    }

    fn decode_blob<T: serde::de::DeserializeOwned>(blob: &[u8]) -> Result<T, UnitMissReason> {
        let (decoded, consumed): (T, usize) = bincode::serde::decode_from_slice(
            blob,
            bincode::config::standard().with_limit::<TRANSLATION_UNIT_METADATA_DECODE_LIMIT>(),
        )
        .map_err(|_| UnitMissReason::Schema)?;
        if consumed != blob.len() {
            return Err(UnitMissReason::Schema);
        }
        Ok(decoded)
    }

    /// Decode one block's HOT stream (relocations, trusted entry, direct
    /// links) — what replay must have, ~2% of a unit's records.
    pub(crate) fn block_hot(
        &self,
        at: usize,
    ) -> Result<crate::artifact_spike::UnitBlockHotWire, UnitMissReason> {
        Self::decode_blob(self.blob(at, false)?)
    }

    /// Decode one block's COLD stream (pc map, recovery) — fault
    /// reconstruction only; a replayed block never touches this unless a
    /// fault interrogates it.
    pub(crate) fn block_cold(
        &self,
        at: usize,
    ) -> Result<crate::artifact_spike::UnitBlockColdWire, UnitMissReason> {
        Self::decode_blob(self.blob(at, true)?)
    }

    /// Reassemble one block's full logical record (both streams). Publish
    /// preflight and offline diagnostics use this; the runtime replay path
    /// never does.
    pub fn block_record(&self, at: usize) -> Result<PortableBlockRecord, UnitMissReason> {
        let entry = self.index.get(at).ok_or(UnitMissReason::ManifestRange)?;
        let hot = self.block_hot(at)?;
        let cold = self.block_cold(at)?;
        Ok(PortableBlockRecord {
            guest_start: entry.guest_start,
            entry_offset: entry.entry_offset,
            code_len: entry.code_len,
            requires_sensitive_metadata: entry.requires_sensitive_metadata,
            template: crate::artifact_spike::ArtifactTemplate::from_unit_wire_parts(hot, cold),
        })
    }

    /// Build a manifest by round-tripping records through THE wire, so a
    /// fixture or in-memory store is bit-identical to what the persistent
    /// store would serve. There is deliberately no way to hand-assemble the
    /// decoded form.
    pub fn from_blocks(
        key: &TranslationUnitKey,
        code_sha256: [u8; 32],
        code_len: u64,
        blocks: &[PortableBlockRecord],
    ) -> Result<Self, crate::types::DsrError> {
        let bytes = encode_translation_unit_metadata(key, code_sha256, code_len, blocks)?;
        decode_translation_unit_metadata(Arc::new(bytes)).map_err(|reason| {
            crate::types::DsrError::CachePolicy(format!(
                "encoded unit metadata failed to decode: {reason:?}"
            ))
        })
    }
}

/// Magic prefix of the serialized unit metadata (`{stem}.metadata-v5`). A
/// file without it — foreign, truncated, or written by any pre-index
/// binary — refuses to decode and reads as a schema miss, never as a
/// lower-quality unit.
pub const TRANSLATION_UNIT_METADATA_MAGIC: [u8; 8] = *b"CUNITV5\0";
const TRANSLATION_UNIT_METADATA_DECODE_LIMIT: usize = 256 * 1024 * 1024;
/// Fixed wire width of one index row: guest_start u64, entry_offset u32,
/// code_len u32, flags u32, hot_len u32, cold_len u32, all little-endian.
const UNIT_BLOCK_INDEX_ROW_BYTES: usize = 28;
const UNIT_BLOCK_FLAG_SENSITIVE: u32 = 1;

/// The bincode-encoded (varint) leading header of the v5 metadata file; the
/// fixed-width index and the per-block blob payload follow it raw.
#[derive(Serialize, Deserialize)]
struct WireUnitHeader {
    schema: u32,
    key: TranslationUnitKey,
    code_sha256: [u8; 32],
    base_export: String,
    code_len: u64,
    block_count: u64,
    payload_len: u64,
}

/// Serialize unit metadata: magic, a small bincode header, a fixed-width
/// per-block index, then every block's hot blob immediately followed by its
/// cold blob, tightly packed in index order (the decoder recomputes and
/// ENFORCES the packing, so offsets never appear on the wire).
pub fn encode_translation_unit_metadata(
    key: &TranslationUnitKey,
    code_sha256: [u8; 32],
    code_len: u64,
    blocks: &[PortableBlockRecord],
) -> Result<Vec<u8>, crate::types::DsrError> {
    #[cfg(feature = "alloc-owner-census")]
    let _owner = crate::alloc_owner_census::scope(
        crate::alloc_owner_wire::AllocationOwner::SharedTranslationSupport,
    );
    let config = bincode::config::standard().with_limit::<TRANSLATION_UNIT_METADATA_DECODE_LIMIT>();
    let base_export = translation_unit_base_export(key).map_err(|error| {
        crate::types::DsrError::CachePolicy(format!("derive unit base export: {error}"))
    })?;
    let mut index = Vec::with_capacity(blocks.len() * UNIT_BLOCK_INDEX_ROW_BYTES);
    let mut payload = Vec::new();
    for record in blocks {
        let (hot, cold) = record.template.clone().into_unit_wire_parts();
        let hot_blob = bincode::serde::encode_to_vec(&hot, config).map_err(|error| {
            crate::types::DsrError::CachePolicy(format!("encode unit block hot blob: {error}"))
        })?;
        let cold_blob = bincode::serde::encode_to_vec(&cold, config).map_err(|error| {
            crate::types::DsrError::CachePolicy(format!("encode unit block cold blob: {error}"))
        })?;
        let hot_len = u32::try_from(hot_blob.len()).map_err(|_| {
            crate::types::DsrError::CachePolicy("unit block hot blob exceeds u32".to_string())
        })?;
        let cold_len = u32::try_from(cold_blob.len()).map_err(|_| {
            crate::types::DsrError::CachePolicy("unit block cold blob exceeds u32".to_string())
        })?;
        let mut flags = 0_u32;
        if record.requires_sensitive_metadata {
            flags |= UNIT_BLOCK_FLAG_SENSITIVE;
        }
        index.extend_from_slice(&record.guest_start.raw().to_le_bytes());
        index.extend_from_slice(&record.entry_offset.to_le_bytes());
        index.extend_from_slice(&record.code_len.to_le_bytes());
        index.extend_from_slice(&flags.to_le_bytes());
        index.extend_from_slice(&hot_len.to_le_bytes());
        index.extend_from_slice(&cold_len.to_le_bytes());
        payload.extend_from_slice(&hot_blob);
        payload.extend_from_slice(&cold_blob);
    }
    let header = WireUnitHeader {
        schema: TRANSLATION_UNIT_SCHEMA_V5,
        key: key.clone(),
        code_sha256,
        base_export,
        code_len,
        block_count: blocks.len() as u64,
        payload_len: payload.len() as u64,
    };
    let header_bytes = bincode::serde::encode_to_vec(&header, config).map_err(|error| {
        crate::types::DsrError::CachePolicy(format!("encode unit metadata header: {error}"))
    })?;
    let header_len = u32::try_from(header_bytes.len()).map_err(|_| {
        crate::types::DsrError::CachePolicy("unit metadata header exceeds u32".to_string())
    })?;
    let mut bytes = TRANSLATION_UNIT_METADATA_MAGIC.to_vec();
    bytes.extend_from_slice(&header_len.to_le_bytes());
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(&index);
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn read_le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn read_le_u64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

/// Structural decode of the v5 metadata: magic, header, index geometry and
/// EXACT extent accounting (index rows == block count, payload == declared
/// length, file ends where the payload ends). No per-block blob is decoded
/// here — a blob decodes on the block's first lookup (hot) or first fault
/// (cold), fail-closed per block. Semantic invariants (schema/ABI/extents
/// against `code_len`) stay in [`TranslationUnitManifest::validate_ranges`].
///
/// `bytes` is the WHOLE file, kept alive by the returned manifest (the
/// store passes its mmap; fixtures pass the encoded vector) — this is what
/// makes per-block decode possible without copying the payload.
pub fn decode_translation_unit_metadata(
    bytes: Arc<dyn AsRef<[u8]> + Send + Sync>,
) -> Result<TranslationUnitManifest, UnitMissReason> {
    #[cfg(feature = "alloc-owner-census")]
    let _owner = crate::alloc_owner_census::scope(
        crate::alloc_owner_wire::AllocationOwner::SharedTranslationSupport,
    );
    let data: &[u8] = (*bytes).as_ref();
    let body = data
        .strip_prefix(&TRANSLATION_UNIT_METADATA_MAGIC)
        .ok_or(UnitMissReason::Schema)?;
    let header_len =
        usize::try_from(read_le_u32(body, 0).ok_or(UnitMissReason::Schema)?).unwrap_or(usize::MAX);
    let header_bytes = body
        .get(
            4..4_usize
                .checked_add(header_len)
                .ok_or(UnitMissReason::Schema)?,
        )
        .ok_or(UnitMissReason::Schema)?;
    let config = bincode::config::standard().with_limit::<TRANSLATION_UNIT_METADATA_DECODE_LIMIT>();
    let (header, consumed): (WireUnitHeader, usize) =
        bincode::serde::decode_from_slice(header_bytes, config)
            .map_err(|_| UnitMissReason::Schema)?;
    if consumed != header_bytes.len() {
        return Err(UnitMissReason::Schema);
    }
    let block_count =
        usize::try_from(header.block_count).map_err(|_| UnitMissReason::ManifestRange)?;
    let payload_len =
        usize::try_from(header.payload_len).map_err(|_| UnitMissReason::ManifestRange)?;
    let index_start = 4_usize
        .checked_add(header_len)
        .ok_or(UnitMissReason::Schema)?;
    let index_len = block_count
        .checked_mul(UNIT_BLOCK_INDEX_ROW_BYTES)
        .ok_or(UnitMissReason::ManifestRange)?;
    let payload_start = index_start
        .checked_add(index_len)
        .ok_or(UnitMissReason::ManifestRange)?;
    let expected_total = payload_start
        .checked_add(payload_len)
        .ok_or(UnitMissReason::ManifestRange)?;
    if body.len() != expected_total {
        return Err(UnitMissReason::Schema);
    }
    let index_bytes = body
        .get(index_start..payload_start)
        .ok_or(UnitMissReason::Schema)?;
    let mut index = Vec::with_capacity(block_count);
    let mut payload_offset = 0_usize;
    for row in 0..block_count {
        let at = row * UNIT_BLOCK_INDEX_ROW_BYTES;
        let guest_start = read_le_u64(index_bytes, at).ok_or(UnitMissReason::Schema)?;
        let entry_offset = read_le_u32(index_bytes, at + 8).ok_or(UnitMissReason::Schema)?;
        let block_code_len = read_le_u32(index_bytes, at + 12).ok_or(UnitMissReason::Schema)?;
        let flags = read_le_u32(index_bytes, at + 16).ok_or(UnitMissReason::Schema)?;
        let hot_len =
            usize::try_from(read_le_u32(index_bytes, at + 20).ok_or(UnitMissReason::Schema)?)
                .map_err(|_| UnitMissReason::ManifestRange)?;
        let cold_len =
            usize::try_from(read_le_u32(index_bytes, at + 24).ok_or(UnitMissReason::Schema)?)
                .map_err(|_| UnitMissReason::ManifestRange)?;
        if flags & !UNIT_BLOCK_FLAG_SENSITIVE != 0 {
            return Err(UnitMissReason::Schema);
        }
        let blob_len = hot_len
            .checked_add(cold_len)
            .ok_or(UnitMissReason::ManifestRange)?;
        let blob_end = payload_offset
            .checked_add(blob_len)
            .ok_or(UnitMissReason::ManifestRange)?;
        if blob_end > payload_len {
            return Err(UnitMissReason::ManifestRange);
        }
        index.push(UnitBlockIndexEntry {
            guest_start: GuestVa(guest_start),
            entry_offset,
            code_len: block_code_len,
            requires_sensitive_metadata: flags & UNIT_BLOCK_FLAG_SENSITIVE != 0,
            payload_offset,
            hot_len,
            cold_len,
        });
        payload_offset = blob_end;
    }
    // Tight packing: the last blob must end exactly at the payload's end,
    // or the file carries bytes no index row accounts for.
    if payload_offset != payload_len {
        return Err(UnitMissReason::Schema);
    }
    // The payload region is addressed relative to the whole buffer.
    let payload_abs_start = TRANSLATION_UNIT_METADATA_MAGIC
        .len()
        .checked_add(payload_start)
        .ok_or(UnitMissReason::ManifestRange)?;
    Ok(TranslationUnitManifest {
        schema: header.schema,
        key: header.key,
        code_sha256: header.code_sha256,
        base_export: header.base_export,
        code_len: header.code_len,
        index,
        payload: UnitPayload {
            bytes,
            start: payload_abs_start,
            len: payload_len,
        },
    })
}

#[derive(Serialize, Deserialize)]
enum WireAddressModeIdentity {
    Direct,
    Biased { host_bias: u64 },
}

impl From<AddressModeIdentity> for WireAddressModeIdentity {
    fn from(value: AddressModeIdentity) -> Self {
        match value {
            AddressModeIdentity::Direct => Self::Direct,
            AddressModeIdentity::Biased { host_bias } => Self::Biased {
                host_bias: host_bias.get(),
            },
        }
    }
}

#[derive(Serialize, Deserialize)]
struct WireTranslationUnitKey {
    executable: ExecutableIdentity,
    segment_file_offset: u64,
    segment_file_len: u64,
    guest_va_start: u64,
    guest_va_len: u64,
    source_fingerprint: SourceFingerprint,
    page_profile: NativePageProfileIdentity,
    address_mode: WireAddressModeIdentity,
    translator_abi: u32,
}

impl From<&TranslationUnitKey> for WireTranslationUnitKey {
    fn from(value: &TranslationUnitKey) -> Self {
        Self {
            executable: value.executable.clone(),
            segment_file_offset: value.segment_file_offset.get(),
            segment_file_len: value.segment_file_len.get(),
            guest_va_start: value.guest_va_start.raw(),
            guest_va_len: value.guest_va_len.get(),
            source_fingerprint: value.source_fingerprint,
            page_profile: value.page_profile,
            address_mode: value.address_mode.into(),
            translator_abi: value.translator_abi,
        }
    }
}

impl Serialize for TranslationUnitKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        WireTranslationUnitKey::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TranslationUnitKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireTranslationUnitKey::deserialize(deserializer)?;
        let segment_file_len = ImageFileLen::new(wire.segment_file_len)
            .ok_or_else(|| serde::de::Error::custom("segment file length is zero"))?;
        let guest_va_len = GuestCodeLen::new(wire.guest_va_len)
            .ok_or_else(|| serde::de::Error::custom("guest code length is zero"))?;
        let address_mode = match wire.address_mode {
            WireAddressModeIdentity::Direct => AddressModeIdentity::Direct,
            WireAddressModeIdentity::Biased { host_bias } => {
                let host_bias = HostBiasIdentity::from_wire(host_bias)
                    .ok_or_else(|| serde::de::Error::custom("host bias is invalid"))?;
                AddressModeIdentity::Biased { host_bias }
            }
        };
        Ok(Self {
            executable: wire.executable,
            segment_file_offset: ImageFileOffset::new(wire.segment_file_offset),
            segment_file_len,
            guest_va_start: GuestVa(wire.guest_va_start),
            guest_va_len,
            source_fingerprint: wire.source_fingerprint,
            page_profile: wire.page_profile,
            address_mode,
            translator_abi: wire.translator_abi,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_spike::{ArtifactBindings, ArtifactTemplate};
    use crate::block::{BlockPlan, PlannedExit};
    use crate::emit::{
        EmitAddressMode, GenerationGuard, PcMapEntry, RecoveryAction, RecoveryEntry,
    };
    use crate::types::{CacheOffset, CodeGeneration};
    use carrick_dsr::address::NativeHostBias;
    use carrick_guest_mem::GuestVa;
    use std::sync::atomic::AtomicU64;

    /// The census indexes a fixed counter array by [`UnitMissReason::index`],
    /// so a hand-written index that drifts from `ALL` would silently attribute
    /// one reason's misses to another. Pin all three views together.
    #[test]
    fn miss_reason_table_indices_tokens_and_order_agree() {
        for (position, reason) in UnitMissReason::ALL.into_iter().enumerate() {
            assert_eq!(reason.index(), position, "{reason:?} index");
            assert_eq!(
                UnitMissReason::from_token(reason.token()),
                Some(reason),
                "{reason:?} token round trip"
            );
        }
        let tokens: std::collections::BTreeSet<&str> = UnitMissReason::ALL
            .into_iter()
            .map(UnitMissReason::token)
            .collect();
        assert_eq!(tokens.len(), UnitMissReason::ALL.len(), "tokens are unique");
        assert_eq!(UnitMissReason::from_token("not-a-reason"), None);
        // The whole point of the split: these three used to be one value.
        assert_ne!(UnitMissReason::NoAuthority, UnitMissReason::MissingPair);
        assert_ne!(
            UnitMissReason::StoreUnavailable,
            UnitMissReason::MissingPair
        );
    }

    fn key(
        executable: ExecutableIdentity,
        source: SourceFingerprint,
        address_mode: AddressModeIdentity,
    ) -> TranslationUnitKey {
        TranslationUnitKey::for_segment(
            executable,
            ImageFileOffset::new(0x1000),
            ImageFileLen::new(0x4000).expect("nonzero file length"),
            GuestVa(0x400000),
            GuestCodeLen::new(0x4000).expect("nonzero guest length"),
            source,
            NativePageProfileIdentity::Native16k,
            address_mode,
        )
    }

    fn fixture_key() -> TranslationUnitKey {
        key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint([0x22; 32]),
            AddressModeIdentity::Direct,
        )
    }

    /// A candidate recorded through the NATIVE emission tap for a trivial
    /// syscall block starting at `guest_start` — words present, trusted
    /// entry included when the emitter placed one.
    fn native_tap_candidate(guest_start: GuestVa) -> PortableBlockCandidate {
        let generation = AtomicU64::new(CodeGeneration::INITIAL.get());
        let plan = BlockPlan {
            start: guest_start,
            end: GuestVa(guest_start.raw() + 4),
            generation: CodeGeneration::INITIAL,
            instructions: Vec::new(),
            exit: PlannedExit::Syscall {
                guest: guest_start,
                resume: GuestVa(guest_start.raw() + 4),
            },
            extensions: Vec::new(),
        };
        let mut cache = crate::test_jit::test_cache(64 * 1024);
        let (_emitted, artifact) = crate::emit::emit_block_recording_artifact(
            &mut cache,
            &plan,
            GenerationGuard::new(&generation, CodeGeneration::INITIAL),
            EmitAddressMode::Direct,
            vec![0xd400_0001],
        )
        .expect("record native-tap candidate");
        PortableBlockCandidate {
            guest_start,
            requires_sensitive_metadata: false,
            template: artifact.template,
        }
    }

    fn empty_template() -> ArtifactTemplate {
        ArtifactTemplate::normalize(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            &ArtifactBindings::from_values([]).expect("empty bindings"),
        )
        .expect("empty template")
    }

    fn record_template() -> ArtifactTemplate {
        ArtifactTemplate::normalize(
            Vec::new(),
            vec![PcMapEntry {
                guest: GuestVa(0x400000),
                cache: CacheOffset::published(0),
            }],
            vec![RecoveryEntry {
                cache: CacheOffset::published(4),
                action: RecoveryAction::RestoreGuestX17,
            }],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            &ArtifactBindings::from_values([]).expect("empty bindings"),
        )
        .expect("record template")
    }

    fn manifest_block(guest_start: u64, entry_offset: u32, code_len: u32) -> PortableBlockRecord {
        PortableBlockRecord {
            guest_start: GuestVa(guest_start),
            entry_offset,
            code_len,
            requires_sensitive_metadata: false,
            template: record_template(),
        }
    }

    /// Build a manifest through THE wire (encode + decode) from records —
    /// the only construction path the new model offers.
    fn manifest_from(code_len: u64, blocks: &[PortableBlockRecord]) -> TranslationUnitManifest {
        TranslationUnitManifest::from_blocks(&fixture_key(), [0x33; 32], code_len, blocks)
            .expect("round-trip fixture manifest")
    }

    fn manifest_fixture() -> TranslationUnitManifest {
        manifest_from(
            32,
            &[
                manifest_block(0x400000, 0, 16),
                manifest_block(0x400010, 16, 16),
            ],
        )
    }

    #[cfg(feature = "alloc-owner-census")]
    #[test]
    fn allocation_owner_shared_translation_support_owns_pack_and_metadata_wire() {
        use crate::alloc_owner_census::test_support as census;
        use crate::alloc_owner_wire::AllocationOwner;

        let _census = census::lock();
        let candidates = vec![
            native_tap_candidate(GuestVa(0x400000)),
            native_tap_candidate(GuestVa(0x400100)),
        ];
        census::reset_and_arm(0, 0);
        let before_pack = census::snapshot();

        let pending = PendingTranslationUnit::pack(fixture_key(), candidates)
            .expect("pack allocation-owner unit");
        let after_pack = census::snapshot();
        census::assert_only_requested_bytes_increased(
            &before_pack,
            &after_pack,
            &[AllocationOwner::SharedTranslationSupport],
        );
        census::reset_disabled();

        census::reset_and_arm(0, 0);
        let before_encode = census::snapshot();
        let bytes = encode_translation_unit_metadata(
            &pending.key,
            [0x44; 32],
            pending.code.len() as u64,
            &pending.blocks,
        )
        .expect("encode allocation-owner metadata");
        let after_encode = census::snapshot();
        census::assert_only_requested_bytes_increased(
            &before_encode,
            &after_encode,
            &[AllocationOwner::SharedTranslationSupport],
        );
        census::reset_disabled();

        let bytes = Arc::new(bytes);
        census::reset_and_arm(0, 0);
        let before_decode = census::snapshot();
        let manifest = decode_translation_unit_metadata(bytes).expect("decode owner metadata");
        std::hint::black_box(manifest);
        let after_decode = census::snapshot();

        census::assert_only_requested_bytes_increased(
            &before_decode,
            &after_decode,
            &[AllocationOwner::SharedTranslationSupport],
        );
        census::reset_disabled();
    }

    #[test]
    fn pack_concatenates_unbaked_native_tap_words_per_block() {
        let first = native_tap_candidate(GuestVa(0x400000));
        let second = native_tap_candidate(GuestVa(0x400100));
        let first_words = first.template.words().to_vec();
        let second_words = second.template.words().to_vec();
        assert!(!first_words.is_empty());
        assert!(
            first.template.trusted_entry().is_some(),
            "a native-tap candidate carries the trusted entry"
        );
        let pending = PendingTranslationUnit::pack(fixture_key(), vec![first, second])
            .expect("pack native-tap candidates");
        assert_eq!(pending.blocks.len(), 2);
        assert_eq!(pending.blocks[0].entry_offset, 0);
        assert_eq!(
            pending.blocks[0].code_len as usize,
            first_words.len() * 4,
            "first block's extent is its recorded word count"
        );
        assert_eq!(
            pending.blocks[1].entry_offset as usize,
            first_words.len() * 4
        );
        // The code image is EXACTLY the recorded words in order — no
        // same-unit patching, no sidecar rewriting, nothing baked.
        let mut expected = Vec::new();
        for word in first_words.iter().chain(&second_words) {
            expected.extend_from_slice(&word.to_le_bytes());
        }
        assert_eq!(pending.code, expected);
        for block in &pending.blocks {
            let counts = block.template.metadata_counts();
            assert_eq!(counts.words, 0, "stored records carry no words");
            assert_eq!(counts.source_words, 0, "stored records carry no source");
            assert!(
                block.template.trusted_entry().is_some(),
                "the stored record keeps the trusted entry"
            );
        }
    }

    #[test]
    fn pack_rejects_duplicate_blocks_and_empty_candidates() {
        let candidate = native_tap_candidate(GuestVa(0x400000));
        let duplicate = candidate.clone();
        assert!(matches!(
            PendingTranslationUnit::pack(fixture_key(), vec![candidate, duplicate]),
            Err(crate::types::DsrError::CachePolicy(message))
                if message.contains("duplicate block")
        ));
        assert!(matches!(
            PendingTranslationUnit::pack(fixture_key(), Vec::new()),
            Err(crate::types::DsrError::CachePolicy(message))
                if message.contains("no blocks")
        ));
        assert!(matches!(
            PendingTranslationUnit::pack(
                fixture_key(),
                vec![PortableBlockCandidate {
                    guest_start: GuestVa(0x400000),
                    requires_sensitive_metadata: false,
                    template: empty_template(),
                }],
            ),
            Err(crate::types::DsrError::CachePolicy(message))
                if message.contains("no recorded words")
        ));
    }

    #[test]
    fn unit_metadata_encode_decode_round_trips_and_refuses_foreign_payloads() {
        let blocks = vec![
            manifest_block(0x400000, 0, 16),
            manifest_block(0x400010, 16, 16),
        ];
        let bytes = encode_translation_unit_metadata(&fixture_key(), [0x33; 32], 32, &blocks)
            .expect("encode metadata");
        assert!(bytes.starts_with(&TRANSLATION_UNIT_METADATA_MAGIC));
        let decoded =
            decode_translation_unit_metadata(Arc::new(bytes.clone())).expect("decode metadata");
        assert_eq!(decoded, manifest_fixture());
        decoded.validate_ranges().expect("index invariants hold");
        decoded.validate_deep().expect("deep invariants hold");
        // Per-block round trip: the reassembled records equal the inputs
        // (words and source words excepted — the wire cannot carry them).
        for (at, block) in blocks.iter().enumerate() {
            let record = decoded.block_record(at).expect("decode block record");
            assert_eq!(record, *block);
        }
        // No magic: a pre-index or foreign file refuses as Schema.
        assert_eq!(
            decode_translation_unit_metadata(Arc::new(bytes[1..].to_vec())),
            Err(UnitMissReason::Schema)
        );
        // Trailing bytes: a torn or tampered payload refuses as Schema.
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            decode_translation_unit_metadata(Arc::new(trailing)),
            Err(UnitMissReason::Schema)
        );
        // Truncation refuses — at EVERY byte length, not just the last:
        // the header, the index rows, and the payload must all be exactly
        // accounted for.
        for cut in [
            bytes.len() - 1,
            bytes.len() - 17,
            TRANSLATION_UNIT_METADATA_MAGIC.len() + 3,
            TRANSLATION_UNIT_METADATA_MAGIC.len() + 12,
            4,
        ] {
            assert_eq!(
                decode_translation_unit_metadata(Arc::new(bytes[..cut].to_vec())),
                Err(UnitMissReason::Schema),
                "a {cut}-byte prefix must refuse"
            );
        }
    }

    #[test]
    fn manifest_rejects_wrong_schema_and_stale_abi() {
        let mut manifest = manifest_fixture();
        manifest.schema = 2;
        assert_eq!(
            manifest.validate_ranges_detailed(),
            Err(ManifestDefect::Schema)
        );
        let stale = TranslationUnitKey {
            translator_abi: TRANSLATOR_ABI_CURRENT - 1,
            ..fixture_key()
        };
        let manifest = TranslationUnitManifest::from_blocks(
            &stale,
            [0x33; 32],
            16,
            &[manifest_block(0x400000, 0, 16)],
        )
        .expect("round-trip stale-abi manifest");
        assert_eq!(
            manifest.validate_ranges_detailed(),
            Err(ManifestDefect::TranslatorAbi)
        );
    }

    #[test]
    fn manifest_rejects_duplicate_guest_starts() {
        let manifest = manifest_from(
            32,
            &[
                manifest_block(0x400000, 0, 16),
                manifest_block(0x400000, 16, 16),
            ],
        );
        assert_eq!(
            manifest.validate_ranges_detailed(),
            Err(ManifestDefect::BlockGuestDuplicate)
        );
    }

    #[test]
    fn manifest_rejects_overlapping_block_cache_extents() {
        let manifest = manifest_from(
            36,
            &[
                manifest_block(0x400000, 0, 20),
                manifest_block(0x400010, 16, 16),
            ],
        );
        assert_eq!(
            manifest.validate_ranges_detailed(),
            Err(ManifestDefect::BlockExtentOverlap)
        );
    }

    #[test]
    fn manifest_allows_adjacent_and_reverse_disjoint_cache_extents() {
        let manifest = manifest_from(
            32,
            &[
                manifest_block(0x400010, 16, 16),
                manifest_block(0x400000, 0, 16),
            ],
        );
        manifest
            .validate_ranges_detailed()
            .expect("disjoint extents");
    }

    #[test]
    fn the_wire_cannot_carry_block_words() {
        // v4 enforced "stored records carry no words" as a validation rule;
        // the v5 hot/cold streams cannot REPRESENT words at all, so a full
        // template (words still present) round-trips to a wordless record —
        // the words live only in the digest-bound code image.
        let candidate = native_tap_candidate(GuestVa(0x400000));
        let code_len = u32::try_from(candidate.template.words().len() * 4).expect("code length");
        assert!(candidate.template.metadata_counts().words > 0);
        let manifest = manifest_from(
            u64::from(code_len),
            &[PortableBlockRecord {
                guest_start: GuestVa(0x400000),
                entry_offset: 0,
                code_len,
                requires_sensitive_metadata: false,
                template: candidate.template,
            }],
        );
        let record = manifest.block_record(0).expect("decode block record");
        let counts = record.template.metadata_counts();
        assert_eq!(counts.words, 0);
        assert_eq!(counts.source_words, 0);
        manifest.validate_deep().expect("wordless record is valid");
    }

    #[test]
    fn manifest_rejects_replay_metadata_outside_the_block_extent() {
        // A recovery offset at byte 4 needs code_len > 4. The index alone
        // cannot see it — the deep (publication-preflight) pass must.
        let manifest = manifest_from(4, &[manifest_block(0x400000, 0, 4)]);
        manifest
            .validate_ranges_detailed()
            .expect("index invariants alone cannot see template geometry");
        assert_eq!(manifest.validate_deep(), Err(ManifestDefect::BlockTemplate));
    }

    #[test]
    fn source_fingerprint_mismatch_is_a_typed_miss() {
        let manifest = manifest_fixture();
        assert_eq!(
            manifest.validate_source(&[0xd503_201f]),
            Err(UnitMissReason::SourceFingerprint)
        );
    }

    #[test]
    fn same_guest_va_with_different_images_never_aliases() {
        let left = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint([0x22; 32]),
            AddressModeIdentity::Direct,
        );
        let right = key(
            ExecutableIdentity::Digest([0x12; 32]),
            SourceFingerprint([0x22; 32]),
            AddressModeIdentity::Direct,
        );
        assert_ne!(left.file_stem().unwrap(), right.file_stem().unwrap());
        assert_ne!(
            translation_unit_base_export(&left).unwrap(),
            translation_unit_base_export(&right).unwrap()
        );
    }

    #[test]
    fn same_image_with_different_source_fingerprints_never_aliases() {
        let left = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint([0x22; 32]),
            AddressModeIdentity::Direct,
        );
        let right = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint([0x23; 32]),
            AddressModeIdentity::Direct,
        );
        assert_ne!(left.file_stem().unwrap(), right.file_stem().unwrap());
    }

    #[test]
    fn same_image_with_different_host_biases_never_aliases() {
        let bias = |raw| {
            AddressModeIdentity::biased(
                NativeHostBias::new(raw, 16 * 1024).expect("aligned fixture bias"),
            )
        };
        let left = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint([0x22; 32]),
            bias(0x10_0000_0000),
        );
        let right = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint([0x22; 32]),
            bias(0x20_0000_0000),
        );
        assert_ne!(left.file_stem().unwrap(), right.file_stem().unwrap());
    }

    #[test]
    fn source_fingerprint_uses_all_words_in_little_endian_order() {
        assert_ne!(
            SourceFingerprint::from_words(&[1, 2]),
            SourceFingerprint::from_words(&[2, 1])
        );
        assert_ne!(
            SourceFingerprint::from_words(&[1]),
            SourceFingerprint::from_words(&[1, 0])
        );
    }

    #[test]
    fn key_json_round_trips_typed_guest_va() {
        let key = fixture_key();
        let encoded = serde_json::to_vec(&key).expect("encode key");
        let decoded: TranslationUnitKey = serde_json::from_slice(&encoded).expect("decode key");
        assert_eq!(decoded, key);
    }

    #[test]
    fn shared_manifest_arc_is_default_on_with_an_exact_opt_out() {
        assert!(shared_manifest_arc_enabled_from(None));
        assert!(shared_manifest_arc_enabled_from(Some(
            std::ffi::OsStr::new("1")
        )));
        assert!(!shared_manifest_arc_enabled_from(Some(
            std::ffi::OsStr::new("0")
        )));
    }

    #[test]
    fn shared_source_fingerprint_reuse_is_default_on_with_an_exact_opt_out() {
        assert!(shared_source_fingerprint_reuse_enabled_from(None));
        assert!(shared_source_fingerprint_reuse_enabled_from(Some(
            std::ffi::OsStr::new("1")
        )));
        assert!(!shared_source_fingerprint_reuse_enabled_from(Some(
            std::ffi::OsStr::new("0")
        )));
    }

    #[test]
    fn shared_recovery_runs_are_default_on_with_an_exact_opt_out() {
        assert!(shared_recovery_runs_enabled_from(None));
        assert!(shared_recovery_runs_enabled_from(Some(
            std::ffi::OsStr::new("1")
        )));
        assert!(!shared_recovery_runs_enabled_from(Some(
            std::ffi::OsStr::new("0")
        )));
    }

    #[test]
    fn packed_records_run_encode_recovery_when_enabled() {
        let candidate = native_tap_candidate(GuestVa(0x400000));
        let entry_count = candidate.template.metadata_counts().recovery_entries;
        let runs = PendingTranslationUnit::pack_with_recovery_runs(
            fixture_key(),
            vec![candidate.clone()],
            true,
        )
        .expect("pack with runs");
        let entries =
            PendingTranslationUnit::pack_with_recovery_runs(fixture_key(), vec![candidate], false)
                .expect("pack with entries");
        assert!(runs.blocks[0].template.recovery_is_run_encoded());
        assert!(!entries.blocks[0].template.recovery_is_run_encoded());
        assert_eq!(
            runs.blocks[0].template.metadata_counts().recovery_entries,
            entry_count
        );
        assert_eq!(
            entries.blocks[0]
                .template
                .metadata_counts()
                .recovery_entries,
            entry_count
        );
    }

    #[test]
    fn shared_segment_key_reuses_its_construction_time_source_fingerprint() {
        let words: Arc<[u32]> = vec![0xd503_201f; 4].into();
        let segment = SharedExecutableSegment::new(
            ImageFileOffset::new(0),
            ImageFileLen::new(16).expect("nonzero file length"),
            GuestVa(0x400000),
            GuestCodeLen::new(16).expect("nonzero guest length"),
            Arc::clone(&words),
        );
        let image = SharedImageConfig {
            executable: ExecutableIdentity::Digest([0x44; 32]),
            page_profile: NativePageProfileIdentity::Native16k,
            address_mode: AddressModeIdentity::Direct,
            segments: vec![segment],
        };
        let reused = image.key_for_segment_with_fingerprint_reuse(&image.segments[0], true);
        let fresh = image.key_for_segment_with_fingerprint_reuse(&image.segments[0], false);
        assert_eq!(reused, fresh);
        assert_eq!(
            reused.source_fingerprint(),
            SourceFingerprint::from_words(&words)
        );
    }

    #[test]
    fn loaded_unit_clones_share_the_immutable_manifest() {
        let manifest = Arc::new(manifest_fixture());
        let lease: Arc<dyn Send + Sync> = Arc::new(());
        let unit = SharedLoadedTranslationUnit::new(Arc::clone(&manifest), 0x1000, lease);
        let clone = unit.clone();
        assert!(Arc::ptr_eq(&unit.manifest, &clone.manifest));
        assert_eq!(clone.source_base, 0x1000);
        assert_eq!(clone.key(), &manifest.key);
    }
}
