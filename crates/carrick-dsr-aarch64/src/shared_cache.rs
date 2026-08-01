//! Portable identity and wire contracts for immutable AArch64 translation units.

use carrick_dsr::address::NativeHostBias;
use carrick_guest_mem::GuestVa;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use crate::direct_binding::{DirectBindingCellVa, DirectBindingOrdinal};
use crate::emit::{DirectLinkKind, DirectStubEnvelope};

pub const TRANSLATOR_ABI_CURRENT: u32 = 3;
pub const TRANSLATION_UNIT_SCHEMA_V1: u32 = 1;
pub const TRANSLATION_UNIT_SCHEMA_V2: u32 = 2;
pub const DIRECT_BINDING_CELL_SIZE: u32 = 8;
pub const MAX_TRANSLATION_UNIT_CODE_BYTES: usize = 64 * 1024 * 1024;
pub const TRANSLATION_UNIT_BASE_EXPORT: &str = "carrick_aot_unit_base";
pub const TRANSLATION_UNIT_BINDING_EXPORT: &str = "carrick_aot_unit_bindings";
const DARWIN_HOST_PAGE_SIZE: u64 = 16 * 1024;
const DARWIN_HOST_PAGE_SIZE_USIZE: usize = 16 * 1024;
static DIRECT_BINDING_RUNTIME_ENABLED: OnceLock<bool> = OnceLock::new();
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

/// Exact maximum protection assigned to one loaded AOT mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadedTranslationProtection {
    ImmutableCode,
    BindingCells,
}

/// Pins both the current and maximum protection of a loaded AOT mapping.
///
/// # Safety
///
/// `address..address + length` must identify live pages owned exclusively by
/// the loaded translation unit. Pinning maximum protection is irreversible for
/// the lifetime of that mapping.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub unsafe fn pin_loaded_translation_protection(
    address: std::ptr::NonNull<u8>,
    length: usize,
    protection: LoadedTranslationProtection,
) -> Result<(), i32> {
    use mach2::kern_return::KERN_SUCCESS;
    use mach2::vm::mach_vm_protect;

    if length == 0 {
        return Err(libc::KERN_INVALID_ARGUMENT);
    }
    let page_size = DARWIN_HOST_PAGE_SIZE_USIZE;
    let start = address.as_ptr() as usize;
    if !start.is_multiple_of(page_size) || !length.is_multiple_of(page_size) {
        return Err(libc::KERN_INVALID_ARGUMENT);
    }
    start
        .checked_add(length)
        .ok_or(libc::KERN_INVALID_ADDRESS)?;
    let size = u64::try_from(length).map_err(|_| libc::KERN_INVALID_ADDRESS)?;
    let native_protection = match protection {
        LoadedTranslationProtection::ImmutableCode => libc::VM_PROT_READ | libc::VM_PROT_EXECUTE,
        LoadedTranslationProtection::BindingCells => libc::VM_PROT_READ | libc::VM_PROT_WRITE,
    };
    let task = unsafe { mach2::traps::mach_task_self() };
    let set_maximum = unsafe { mach_vm_protect(task, start as u64, size, 1, native_protection) };
    if set_maximum != KERN_SUCCESS {
        return Err(set_maximum);
    }
    let set_current = unsafe { mach_vm_protect(task, start as u64, size, 0, native_protection) };
    if set_current != KERN_SUCCESS {
        return Err(set_current);
    }
    Ok(())
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub unsafe fn pin_loaded_translation_protection(
    _address: std::ptr::NonNull<u8>,
    _length: usize,
    _protection: LoadedTranslationProtection,
) -> Result<(), i32> {
    Err(libc::ENOTSUP)
}

pub fn direct_binding_runtime_enabled() -> bool {
    *DIRECT_BINDING_RUNTIME_ENABLED.get_or_init(|| {
        std::env::var_os("CARRICK_DSR_DIRECT_BINDINGS").as_deref()
            == Some(std::ffi::OsStr::new("1"))
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

    pub(crate) const fn executable(&self) -> &ExecutableIdentity {
        &self.executable
    }

    pub(crate) const fn segment_file_offset(&self) -> ImageFileOffset {
        self.segment_file_offset
    }

    pub(crate) const fn segment_file_len(&self) -> ImageFileLen {
        self.segment_file_len
    }

    pub(crate) const fn guest_va_len(&self) -> GuestCodeLen {
        self.guest_va_len
    }

    pub(crate) const fn page_profile(&self) -> NativePageProfileIdentity {
        self.page_profile
    }

    pub(crate) const fn address_mode(&self) -> AddressModeIdentity {
        self.address_mode
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

/// A dyld export whose signed symbol identity is unique to one translation
/// unit key. Resolving this exact symbol after `dlopen` cheaply binds a loaded
/// image to the manifest without rereading and hashing the entire dylib in
/// every descendant process.
pub fn translation_unit_base_export(key: &TranslationUnitKey) -> Result<String, serde_json::Error> {
    Ok(format!(
        "{TRANSLATION_UNIT_BASE_EXPORT}_{}",
        key.file_stem()?
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableBlockRecord {
    pub guest_start: GuestVa,
    pub generation_binding: u32,
    pub entry_offset: u32,
    pub code_len: u32,
    pub requires_sensitive_metadata: bool,
    pub template: crate::artifact_spike::ArtifactTemplate,
}

#[derive(Serialize, Deserialize)]
struct WirePortableBlockRecord {
    guest_start: u64,
    generation_binding: u32,
    entry_offset: u32,
    code_len: u32,
    requires_sensitive_metadata: bool,
    template: crate::artifact_spike::ArtifactTemplate,
}

impl Serialize for PortableBlockRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        WirePortableBlockRecord {
            guest_start: self.guest_start.raw(),
            generation_binding: self.generation_binding,
            entry_offset: self.entry_offset,
            code_len: self.code_len,
            requires_sensitive_metadata: self.requires_sensitive_metadata,
            template: self.template.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PortableBlockRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WirePortableBlockRecord::deserialize(deserializer)?;
        Ok(Self {
            guest_start: GuestVa(wire.guest_start),
            generation_binding: wire.generation_binding,
            entry_offset: wire.entry_offset,
            code_len: wire.code_len,
            requires_sensitive_metadata: wire.requires_sensitive_metadata,
            template: wire.template,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslationUnitManifest {
    pub schema: u32,
    pub key: TranslationUnitKey,
    pub dylib_sha256: [u8; 32],
    pub base_export: String,
    pub code_len: u64,
    pub blocks: Vec<PortableBlockRecord>,
    pub binding_layout: DirectBindingLayout,
    pub binding_export: String,
    pub binding_data_len: u64,
    pub cell_size: u32,
    pub bindings: Vec<UnresolvedDirectBindingRecord>,
    pub binding_relocations: Vec<DirectBindingRelocation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingTranslationUnit {
    pub key: TranslationUnitKey,
    pub code: Vec<u8>,
    pub blocks: Vec<PortableBlockRecord>,
    pub binding_layout: DirectBindingLayout,
    pub binding_export: String,
    pub binding_data_len: u64,
    pub cell_size: u32,
    pub bindings: Vec<UnresolvedDirectBindingRecord>,
    pub binding_relocations: Vec<DirectBindingRelocation>,
    pub binding_data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectBindingLayout {
    Disabled,
    SidecarV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnresolvedDirectBindingRecord {
    pub source: GuestVa,
    pub target: GuestVa,
    pub kind: DirectLinkKind,
    pub ordinal: DirectBindingOrdinal,
    pub stub_start: u32,
    pub stub_end: u32,
}

#[derive(Serialize, Deserialize)]
struct WireUnresolvedDirectBindingRecord {
    source: u64,
    target: u64,
    kind: DirectLinkKind,
    ordinal: DirectBindingOrdinal,
    stub_start: u32,
    stub_end: u32,
}

impl Serialize for UnresolvedDirectBindingRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        WireUnresolvedDirectBindingRecord {
            source: self.source.raw(),
            target: self.target.raw(),
            kind: self.kind,
            ordinal: self.ordinal,
            stub_start: self.stub_start,
            stub_end: self.stub_end,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UnresolvedDirectBindingRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireUnresolvedDirectBindingRecord::deserialize(deserializer)?;
        Ok(Self {
            source: GuestVa(wire.source),
            target: GuestVa(wire.target),
            kind: wire.kind,
            ordinal: wire.ordinal,
            stub_start: wire.stub_start,
            stub_end: wire.stub_end,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectBindingRelocation {
    pub ordinal: DirectBindingOrdinal,
    pub adrp_offset: u32,
    pub add_offset: u32,
    pub miss_adrp_offset: u32,
    pub miss_add_offset: u32,
    pub data_offset: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableBlockCandidate {
    pub guest_start: GuestVa,
    pub generation_binding: u32,
    pub requires_sensitive_metadata: bool,
    pub template: crate::artifact_spike::ArtifactTemplate,
}

impl PendingTranslationUnit {
    pub fn pack(
        key: TranslationUnitKey,
        candidates: Vec<PortableBlockCandidate>,
        binding_layout: DirectBindingLayout,
    ) -> Result<Self, crate::types::DsrError> {
        Self::pack_with_recovery_runs(
            key,
            candidates,
            binding_layout,
            shared_recovery_runs_enabled(),
        )
    }

    fn pack_with_recovery_runs(
        key: TranslationUnitKey,
        candidates: Vec<PortableBlockCandidate>,
        binding_layout: DirectBindingLayout,
        recovery_runs: bool,
    ) -> Result<Self, crate::types::DsrError> {
        let mut code = Vec::new();
        let mut blocks = Vec::with_capacity(candidates.len());
        let mut entries = BTreeMap::new();
        let mut direct_links = Vec::new();
        for candidate in candidates {
            let words = candidate
                .template
                .materialize_immutable_words(key.host_bias())?;
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
            if entries
                .insert(candidate.guest_start, entry_offset)
                .is_some()
            {
                return Err(crate::types::DsrError::CachePolicy(format!(
                    "translation unit contains duplicate block 0x{:x}",
                    candidate.guest_start.raw()
                )));
            }
            direct_links.push((entry_offset, candidate.template.direct_links().to_vec()));
            for word in words {
                code.extend_from_slice(&word.to_le_bytes());
            }
            blocks.push(PortableBlockRecord {
                guest_start: candidate.guest_start,
                generation_binding: candidate.generation_binding,
                entry_offset,
                code_len,
                requires_sensitive_metadata: candidate.requires_sensitive_metadata,
                template: candidate
                    .template
                    .into_runtime_metadata_only_with_recovery_runs(recovery_runs)?,
            });
        }
        let mut unresolved = Vec::new();
        for (source_entry, links) in direct_links {
            for link in links {
                let slot = source_entry.checked_add(link.slot.get()).ok_or_else(|| {
                    crate::types::DsrError::CachePolicy(
                        "translation unit direct-link source overflow".to_string(),
                    )
                })?;
                let stub_start =
                    source_entry
                        .checked_add(link.stub.start.get())
                        .ok_or_else(|| {
                            crate::types::DsrError::CachePolicy(
                                "translation unit direct-link stub start overflow".to_string(),
                            )
                        })?;
                let stub_end = source_entry
                    .checked_add(link.stub.end.get())
                    .ok_or_else(|| {
                        crate::types::DsrError::CachePolicy(
                            "translation unit direct-link stub end overflow".to_string(),
                        )
                    })?;
                if !slot.is_multiple_of(4)
                    || !stub_start.is_multiple_of(4)
                    || !stub_end.is_multiple_of(4)
                    || stub_start >= stub_end
                    || u64::from(stub_end) > code.len() as u64
                {
                    return Err(crate::types::DsrError::CachePolicy(format!(
                        "translation unit direct-link geometry is invalid: slot={slot} stub={stub_start}..{stub_end}"
                    )));
                }
                let absolute = crate::emit::DirectLink {
                    slot: crate::types::CacheOffset::published(slot),
                    source: link.source,
                    target: link.target,
                    kind: link.kind,
                    stub: DirectStubEnvelope {
                        start: crate::types::CacheOffset::published(stub_start),
                        end: crate::types::CacheOffset::published(stub_end),
                    },
                };
                let Some(target_entry) = entries.get(&link.target).copied() else {
                    unresolved.push(absolute);
                    continue;
                };
                patch_same_unit_direct_link(&mut code, slot, target_entry)?;
            }
        }
        unresolved.sort_by_key(|link| link.stub.start.get());
        if unresolved
            .windows(2)
            .any(|pair| pair[0].stub.end.get() > pair[1].stub.start.get())
        {
            return Err(crate::types::DsrError::CachePolicy(
                "translation unit has conflicting direct-binding stub owners".to_string(),
            ));
        }

        let bindings = unresolved
            .iter()
            .enumerate()
            .map(|(index, link)| {
                let ordinal = u32::try_from(index)
                    .map(DirectBindingOrdinal::claimed)
                    .map_err(|_| {
                        crate::types::DsrError::CachePolicy(
                            "translation unit direct-binding ordinal exceeds u32".to_string(),
                        )
                    })?;
                Ok(UnresolvedDirectBindingRecord {
                    source: link.source,
                    target: link.target,
                    kind: link.kind,
                    ordinal,
                    stub_start: link.stub.start.get(),
                    stub_end: link.stub.end.get(),
                })
            })
            .collect::<Result<Vec<_>, crate::types::DsrError>>()?;

        let (binding_export, cell_size, binding_data, binding_relocations) = match binding_layout {
            DirectBindingLayout::Disabled => (String::new(), 0, Vec::new(), Vec::new()),
            DirectBindingLayout::SidecarV1 => {
                let binding_data_len = bindings
                    .len()
                    .checked_mul(DIRECT_BINDING_CELL_SIZE as usize)
                    .ok_or_else(|| {
                        crate::types::DsrError::CachePolicy(
                            "translation unit binding data length overflow".to_string(),
                        )
                    })?;
                let binding_data = vec![0; binding_data_len];
                let mut relocations = Vec::with_capacity(bindings.len());
                for (link, binding) in unresolved.iter().copied().zip(&bindings) {
                    let data_offset = binding
                        .ordinal
                        .get()
                        .checked_mul(DIRECT_BINDING_CELL_SIZE)
                        .ok_or_else(|| {
                            crate::types::DsrError::CachePolicy(
                                "translation unit binding data offset overflow".to_string(),
                            )
                        })?;
                    relocations.push(crate::emit::rewrite_direct_binding_stub(
                        &mut code,
                        link,
                        binding.ordinal,
                        data_offset,
                    )?);
                }
                (
                    TRANSLATION_UNIT_BINDING_EXPORT.to_owned(),
                    DIRECT_BINDING_CELL_SIZE,
                    binding_data,
                    relocations,
                )
            }
        };
        let binding_data_len = u64::try_from(binding_data.len()).map_err(|_| {
            crate::types::DsrError::CachePolicy(
                "translation unit binding data length exceeds u64".to_string(),
            )
        })?;
        if code.is_empty() {
            return Err(crate::types::DsrError::CachePolicy(
                "translation unit contains no blocks".to_string(),
            ));
        }
        Ok(Self {
            key,
            code,
            blocks,
            binding_layout,
            binding_export,
            binding_data_len,
            cell_size,
            bindings,
            binding_relocations,
            binding_data,
        })
    }
}

fn patch_same_unit_direct_link(
    code: &mut [u8],
    source: u32,
    target_entry: u32,
) -> Result<(), crate::types::DsrError> {
    let displacement = i64::from(target_entry) - i64::from(source);
    if displacement % 4 != 0 {
        return Err(crate::types::DsrError::CachePolicy(format!(
            "translation unit direct-link displacement is unaligned: {displacement}"
        )));
    }
    let words = displacement / 4;
    if !(-(1_i64 << 25)..(1_i64 << 25)).contains(&words) {
        return Err(crate::types::DsrError::CachePolicy(format!(
            "translation unit direct-link target is out of range: {displacement}"
        )));
    }
    let offset = usize::try_from(source).map_err(|_| {
        crate::types::DsrError::CachePolicy(
            "translation unit direct-link offset does not fit usize".to_string(),
        )
    })?;
    let end = offset.checked_add(4).ok_or_else(|| {
        crate::types::DsrError::CachePolicy(
            "translation unit direct-link word overflow".to_string(),
        )
    })?;
    let bytes = code.get_mut(offset..end).ok_or_else(|| {
        crate::types::DsrError::CachePolicy(
            "translation unit direct-link slot is out of bounds".to_string(),
        )
    })?;
    let existing = u32::from_le_bytes(bytes.try_into().map_err(|_| {
        crate::types::DsrError::CachePolicy(
            "translation unit direct-link word is malformed".to_string(),
        )
    })?);
    if existing & 0xfc00_0000 != 0x1400_0000 {
        return Err(crate::types::DsrError::CachePolicy(format!(
            "translation unit direct-link slot is not an AArch64 B: 0x{existing:08x}"
        )));
    }
    let linked = 0x1400_0000 | ((words as i32 as u32) & 0x03ff_ffff);
    bytes.copy_from_slice(&linked.to_le_bytes());
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnitMissReason {
    MissingPair,
    Schema,
    TranslatorAbi,
    ImageIdentity,
    SourceFingerprint,
    AddressMode,
    PageProfile,
    DylibDigest,
    ManifestRange,
    Dlopen,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    Winner,
    Existing,
}

#[derive(Clone, Debug)]
pub enum LoadedTranslationMetadata {
    V2(std::sync::Arc<TranslationUnitManifest>),
    V3(std::sync::Arc<crate::mapped_metadata::ValidatedMappedTranslationMetadata>),
}

impl LoadedTranslationMetadata {
    pub fn key(&self) -> &TranslationUnitKey {
        match self {
            Self::V2(manifest) => &manifest.key,
            Self::V3(metadata) => metadata.key(),
        }
    }

    pub fn code_len(&self) -> u64 {
        match self {
            Self::V2(manifest) => manifest.code_len,
            Self::V3(metadata) => metadata.code_len(),
        }
    }

    pub fn block_count(&self) -> usize {
        match self {
            Self::V2(manifest) => manifest.blocks.len(),
            Self::V3(metadata) => metadata.block_count(),
        }
    }

    pub fn binding_layout(&self) -> DirectBindingLayout {
        match self {
            Self::V2(manifest) => manifest.binding_layout,
            Self::V3(metadata) => metadata.binding_layout(),
        }
    }

    pub fn binding_count(&self) -> usize {
        match self {
            Self::V2(manifest) => manifest.bindings.len(),
            Self::V3(metadata) => metadata.binding_count(),
        }
    }

    pub fn binding_data_len(&self) -> u64 {
        match self {
            Self::V2(manifest) => manifest.binding_data_len,
            Self::V3(metadata) => metadata.binding_data_len(),
        }
    }

    pub fn v2(&self) -> Option<&Arc<TranslationUnitManifest>> {
        match self {
            Self::V2(manifest) => Some(manifest),
            Self::V3(_) => None,
        }
    }

    pub fn v3(&self) -> Option<&Arc<crate::mapped_metadata::ValidatedMappedTranslationMetadata>> {
        match self {
            Self::V2(_) => None,
            Self::V3(metadata) => Some(metadata),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TranslationMetadataMode {
    #[default]
    V2,
    V3,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TranslationMetadataLoadEvidence {
    pub mode: TranslationMetadataMode,
    pub bytes_read: u64,
    pub bytes_mapped: u64,
    pub validation_ns: u64,
    /// Physical V3 wire records across all sections, including its three
    /// retained validation indexes. Zero for V2.
    pub mapped_records: u64,
    /// Physical V2 manifest table entries retained after load. This excludes
    /// guest ranges, edge groups, and validation indexes that only V3 stores.
    pub owned_records: u64,
}

pub struct SharedLoadedTranslationUnit {
    // Fields drop in declaration order. Release the dyld lease first so mapped
    // metadata remains live through handle teardown.
    _lease: Arc<dyn Send + Sync>,
    pub metadata: LoadedTranslationMetadata,
    pub base: usize,
    pub binding_base: Option<DirectBindingCellVa>,
    pub load_evidence: TranslationMetadataLoadEvidence,
}

impl Clone for SharedLoadedTranslationUnit {
    fn clone(&self) -> Self {
        Self {
            _lease: Arc::clone(&self._lease),
            metadata: match &self.metadata {
                LoadedTranslationMetadata::V2(manifest) => {
                    LoadedTranslationMetadata::V2(if shared_manifest_arc_enabled() {
                        Arc::clone(manifest)
                    } else {
                        Arc::new((**manifest).clone())
                    })
                }
                LoadedTranslationMetadata::V3(metadata) => {
                    LoadedTranslationMetadata::V3(Arc::clone(metadata))
                }
            },
            base: self.base,
            binding_base: self.binding_base,
            load_evidence: self.load_evidence,
        }
    }
}

impl SharedLoadedTranslationUnit {
    pub fn new(
        manifest: impl Into<Arc<TranslationUnitManifest>>,
        base: usize,
        lease: Arc<dyn Send + Sync>,
    ) -> Self {
        Self {
            _lease: lease,
            metadata: LoadedTranslationMetadata::V2(retain_loaded_manifest(manifest.into())),
            base,
            binding_base: None,
            load_evidence: TranslationMetadataLoadEvidence::default(),
        }
    }

    pub fn new_with_binding_base(
        manifest: impl Into<Arc<TranslationUnitManifest>>,
        base: usize,
        binding_base: Option<DirectBindingCellVa>,
        lease: Arc<dyn Send + Sync>,
    ) -> Self {
        Self {
            _lease: lease,
            metadata: LoadedTranslationMetadata::V2(retain_loaded_manifest(manifest.into())),
            base,
            binding_base,
            load_evidence: TranslationMetadataLoadEvidence::default(),
        }
    }

    pub fn new_mapped(
        metadata: impl Into<Arc<crate::mapped_metadata::ValidatedMappedTranslationMetadata>>,
        base: usize,
        load_evidence: TranslationMetadataLoadEvidence,
        lease: Arc<dyn Send + Sync>,
    ) -> Self {
        Self::new_mapped_with_binding_base(metadata, base, None, load_evidence, lease)
    }

    pub fn new_mapped_with_binding_base(
        metadata: impl Into<Arc<crate::mapped_metadata::ValidatedMappedTranslationMetadata>>,
        base: usize,
        binding_base: Option<DirectBindingCellVa>,
        mut load_evidence: TranslationMetadataLoadEvidence,
        lease: Arc<dyn Send + Sync>,
    ) -> Self {
        load_evidence.mode = TranslationMetadataMode::V3;
        Self {
            _lease: lease,
            metadata: LoadedTranslationMetadata::V3(metadata.into()),
            base,
            binding_base,
            load_evidence,
        }
    }

    pub fn key(&self) -> &TranslationUnitKey {
        self.metadata.key()
    }

    pub fn binding_layout(&self) -> DirectBindingLayout {
        self.metadata.binding_layout()
    }

    pub fn binding_count(&self) -> usize {
        self.metadata.binding_count()
    }

    pub fn binding_data_len(&self) -> u64 {
        self.metadata.binding_data_len()
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

    pub fn validate_ranges(&self) -> Result<(), UnitMissReason> {
        if self.schema != TRANSLATION_UNIT_SCHEMA_V2 {
            return Err(UnitMissReason::Schema);
        }
        if self.key.translator_abi() != TRANSLATOR_ABI_CURRENT {
            return Err(UnitMissReason::TranslatorAbi);
        }
        let expected_base_export =
            translation_unit_base_export(&self.key).map_err(|_| UnitMissReason::Schema)?;
        if self.base_export != expected_base_export
            || self.code_len == 0
            || self.code_len > MAX_TRANSLATION_UNIT_CODE_BYTES as u64
        {
            return Err(UnitMissReason::Schema);
        }
        let mut guest_starts = BTreeSet::new();
        let mut cache_extents = Vec::with_capacity(self.blocks.len());
        for block in &self.blocks {
            let end = u64::from(block.entry_offset)
                .checked_add(u64::from(block.code_len))
                .ok_or(UnitMissReason::ManifestRange)?;
            if block.code_len == 0
                || !block.entry_offset.is_multiple_of(4)
                || !block.code_len.is_multiple_of(4)
                || end > self.code_len
                || !guest_starts.insert(block.guest_start)
            {
                return Err(UnitMissReason::ManifestRange);
            }
            cache_extents.push((u64::from(block.entry_offset), end));
        }
        cache_extents.sort_unstable();
        if cache_extents.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(UnitMissReason::ManifestRange);
        }
        let same_unit_targets = guest_starts;
        let mut owners = BTreeSet::new();
        let mut previous_stub_end = None;
        for (index, binding) in self.bindings.iter().enumerate() {
            let expected_ordinal =
                u32::try_from(index).map_err(|_| UnitMissReason::ManifestRange)?;
            if binding.ordinal.get() != expected_ordinal
                || !binding.stub_start.is_multiple_of(4)
                || !binding.stub_end.is_multiple_of(4)
                || binding.stub_start >= binding.stub_end
                || u64::from(binding.stub_end) > self.code_len
                || !owners.insert(binding.stub_start)
                || previous_stub_end.is_some_and(|end| end > binding.stub_start)
                || same_unit_targets.contains(&binding.target)
            {
                return Err(UnitMissReason::ManifestRange);
            }
            previous_stub_end = Some(binding.stub_end);
        }
        match self.binding_layout {
            DirectBindingLayout::Disabled => {
                if !self.binding_export.is_empty()
                    || self.binding_data_len != 0
                    || self.cell_size != 0
                    || !self.binding_relocations.is_empty()
                {
                    return Err(UnitMissReason::ManifestRange);
                }
            }
            DirectBindingLayout::SidecarV1 => {
                let expected_len = u64::try_from(self.bindings.len())
                    .ok()
                    .and_then(|count| count.checked_mul(u64::from(DIRECT_BINDING_CELL_SIZE)))
                    .ok_or(UnitMissReason::ManifestRange)?;
                if self.binding_export != TRANSLATION_UNIT_BINDING_EXPORT
                    || self.cell_size != DIRECT_BINDING_CELL_SIZE
                    || !self
                        .binding_data_len
                        .is_multiple_of(u64::from(DIRECT_BINDING_CELL_SIZE))
                    || self.binding_data_len != expected_len
                    || self.binding_relocations.len() != self.bindings.len()
                {
                    return Err(UnitMissReason::ManifestRange);
                }
                let mut relocation_ordinals = BTreeSet::new();
                for relocation in &self.binding_relocations {
                    let ordinal = usize::try_from(relocation.ordinal.get())
                        .map_err(|_| UnitMissReason::ManifestRange)?;
                    let binding = self
                        .bindings
                        .get(ordinal)
                        .ok_or(UnitMissReason::ManifestRange)?;
                    let expected_data_offset = relocation
                        .ordinal
                        .get()
                        .checked_mul(DIRECT_BINDING_CELL_SIZE)
                        .ok_or(UnitMissReason::ManifestRange)?;
                    let offsets = [
                        relocation.adrp_offset,
                        relocation.add_offset,
                        relocation.miss_adrp_offset,
                        relocation.miss_add_offset,
                    ];
                    let expected_offsets =
                        expected_direct_binding_relocation_offsets(binding.stub_start)
                            .ok_or(UnitMissReason::ManifestRange)?;
                    if !relocation_ordinals.insert(relocation.ordinal)
                        || relocation.data_offset != expected_data_offset
                        || offsets != expected_offsets
                        || offsets.iter().any(|offset| {
                            !offset.is_multiple_of(4)
                                || *offset < binding.stub_start
                                || u64::from(*offset) + 4 > u64::from(binding.stub_end)
                                || u64::from(*offset) + 4 > self.code_len
                        })
                    {
                        return Err(UnitMissReason::ManifestRange);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn validate_binding_data(&self, binding_data: &[u8]) -> Result<(), UnitMissReason> {
        if u64::try_from(binding_data.len()).ok() != Some(self.binding_data_len)
            || binding_data.iter().any(|byte| *byte != 0)
        {
            return Err(UnitMissReason::ManifestRange);
        }
        Ok(())
    }

    pub fn validate_binding_code(&self, code: &[u8]) -> Result<(), UnitMissReason> {
        self.validate_ranges()?;
        for relocation in &self.binding_relocations {
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
}

fn expected_direct_binding_relocation_offsets(stub_start: u32) -> Option<[u32; 4]> {
    Some([
        stub_start.checked_add(20)?,
        stub_start.checked_add(24)?,
        stub_start.checked_add(108)?,
        stub_start.checked_add(112)?,
    ])
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
        DirectLink, DirectLinkKind, DirectStubEnvelope, PcMapEntry, RecoveryAction, RecoveryEntry,
    };
    use crate::types::{CacheOffset, CodeGeneration, DirectExit, DirectKind};
    use carrick_dsr::address::NativeHostBias;
    use carrick_guest_mem::GuestVa;

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

    fn unresolved_direct_template(source: GuestVa, target: GuestVa) -> ArtifactTemplate {
        crate::emit::record_portable_block_artifact(
            &BlockPlan {
                start: source,
                end: GuestVa(source.raw() + 4),
                generation: CodeGeneration::INITIAL,
                instructions: Vec::new(),
                exit: PlannedExit::Direct {
                    guest: source,
                    word: 0x1400_0001,
                    exit: DirectExit {
                        kind: DirectKind::Branch,
                        target,
                        resume: GuestVa(source.raw() + 4),
                        condition: None,
                        register: None,
                        bit: None,
                    },
                },
                extensions: Vec::new(),
            },
            0,
            crate::emit::EmitAddressMode::Direct,
            vec![0x1400_0001],
        )
        .expect("record unresolved direct template")
        .template
    }

    fn empty_template() -> ArtifactTemplate {
        ArtifactTemplate::normalize(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            &ArtifactBindings::from_values([]).expect("empty bindings"),
        )
        .expect("empty template")
    }

    fn manifest_v2_fixture() -> TranslationUnitManifest {
        let key = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint([0xaa; 32]),
            AddressModeIdentity::Direct,
        );
        TranslationUnitManifest {
            schema: TRANSLATION_UNIT_SCHEMA_V2,
            base_export: translation_unit_base_export(&key).expect("unit export"),
            key,
            dylib_sha256: [0x22; 32],
            code_len: 512,
            blocks: Vec::new(),
            binding_layout: DirectBindingLayout::SidecarV1,
            binding_export: TRANSLATION_UNIT_BINDING_EXPORT.to_owned(),
            binding_data_len: u64::from(DIRECT_BINDING_CELL_SIZE),
            cell_size: DIRECT_BINDING_CELL_SIZE,
            bindings: vec![UnresolvedDirectBindingRecord {
                source: GuestVa(0x400000),
                target: GuestVa(0x500000),
                kind: DirectLinkKind::Branch,
                ordinal: DirectBindingOrdinal::claimed(0),
                stub_start: 32,
                stub_end: 288,
            }],
            binding_relocations: vec![DirectBindingRelocation {
                ordinal: DirectBindingOrdinal::claimed(0),
                adrp_offset: 52,
                add_offset: 56,
                miss_adrp_offset: 140,
                miss_add_offset: 144,
                data_offset: 0,
            }],
        }
    }

    #[derive(Debug)]
    struct SharedLeaseDropProbe;

    #[derive(Debug)]
    struct SharedLeaseObservedBacking {
        bytes: Vec<u8>,
        lease: std::sync::Weak<SharedLeaseDropProbe>,
        lease_alive_when_dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl crate::mapped_metadata::MetadataBacking for SharedLeaseObservedBacking {
        fn bytes(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Drop for SharedLeaseObservedBacking {
        fn drop(&mut self) {
            self.lease_alive_when_dropped.store(
                self.lease.upgrade().is_some(),
                std::sync::atomic::Ordering::Release,
            );
        }
    }

    #[test]
    fn loaded_unit_clones_share_the_immutable_manifest() {
        let unit = SharedLoadedTranslationUnit::new(manifest_v2_fixture(), 0x1000, Arc::new(()));
        let cloned = unit.clone();
        let manifest = unit.metadata.v2().expect("V2 manifest");
        let cloned_manifest = cloned.metadata.v2().expect("cloned V2 manifest");

        assert!(std::ptr::eq(&manifest.blocks, &cloned_manifest.blocks));
    }

    #[test]
    fn shared_loaded_unit_releases_lease_before_metadata_backing() {
        let mut manifest = manifest_v2_fixture();
        manifest.blocks.push(PortableBlockRecord {
            guest_start: GuestVa(0x400000),
            generation_binding: 0,
            entry_offset: 0,
            code_len: 4,
            requires_sensitive_metadata: false,
            template: ArtifactTemplate::normalize(
                Vec::new(),
                vec![PcMapEntry {
                    guest: GuestVa(0x400000),
                    cache: CacheOffset::published(0),
                }],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                &ArtifactBindings::from_values([]).expect("empty bindings"),
            )
            .expect("drop-order metadata")
            .into_runtime_metadata_only(),
        });
        let bytes = crate::mapped_metadata::encode_translation_metadata_v3(&manifest)
            .expect("encode V3 metadata");
        let lease = Arc::new(SharedLeaseDropProbe);
        let lease_alive_when_dropped = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let backing: Arc<dyn crate::mapped_metadata::MetadataBacking> =
            Arc::new(SharedLeaseObservedBacking {
                bytes,
                lease: Arc::downgrade(&lease),
                lease_alive_when_dropped: Arc::clone(&lease_alive_when_dropped),
            });
        let metadata =
            crate::mapped_metadata::ValidatedMappedTranslationMetadata::new(backing, &manifest.key)
                .expect("validate V3 metadata");
        let unit = SharedLoadedTranslationUnit::new_mapped(
            Arc::new(metadata),
            0x1000,
            TranslationMetadataLoadEvidence::default(),
            lease,
        );

        drop(unit);

        assert!(
            !lease_alive_when_dropped.load(std::sync::atomic::Ordering::Acquire),
            "shared dyld lease must be released before the mapped metadata backing"
        );
    }

    #[test]
    fn shared_manifest_arc_is_default_on_with_an_exact_opt_out() {
        assert!(shared_manifest_arc_enabled_from(None));
        assert!(shared_manifest_arc_enabled_from(Some(
            std::ffi::OsStr::new("1")
        )));
        assert!(shared_manifest_arc_enabled_from(Some(
            std::ffi::OsStr::new("false")
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
        assert!(shared_source_fingerprint_reuse_enabled_from(Some(
            std::ffi::OsStr::new("false")
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
        assert!(shared_recovery_runs_enabled_from(Some(
            std::ffi::OsStr::new("false")
        )));
        assert!(!shared_recovery_runs_enabled_from(Some(
            std::ffi::OsStr::new("0")
        )));
    }

    #[test]
    fn packed_recovery_runs_round_trip_smaller_than_entry_mode() {
        let key = key(
            ExecutableIdentity::Digest([0x51; 32]),
            SourceFingerprint([0x61; 32]),
            AddressModeIdentity::Direct,
        );
        let template = ArtifactTemplate::normalize(
            vec![0xd503_201f; 1024],
            vec![PcMapEntry {
                guest: GuestVa(0x400000),
                cache: CacheOffset::published(0),
            }],
            (0..1024)
                .map(|index| RecoveryEntry {
                    cache: CacheOffset::published(index * 4),
                    action: RecoveryAction::RestoreScratch { register: 16 },
                })
                .collect(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            &ArtifactBindings::from_values([]).expect("empty bindings"),
        )
        .expect("recovery template");
        let candidate = PortableBlockCandidate {
            guest_start: GuestVa(0x400000),
            generation_binding: 0,
            requires_sensitive_metadata: false,
            template,
        };
        let runs = PendingTranslationUnit::pack_with_recovery_runs(
            key.clone(),
            vec![candidate.clone()],
            DirectBindingLayout::Disabled,
            true,
        )
        .expect("pack recovery runs");
        let entries = PendingTranslationUnit::pack_with_recovery_runs(
            key,
            vec![candidate],
            DirectBindingLayout::Disabled,
            false,
        )
        .expect("pack recovery entries");

        assert!(runs.blocks[0].template.recovery_is_run_encoded());
        assert!(!entries.blocks[0].template.recovery_is_run_encoded());
        assert_eq!(
            runs.blocks[0].template.metadata_counts().recovery_entries,
            1024
        );
        assert_eq!(runs.blocks[0].template.metadata_counts().recovery_runs, 1);

        let manifest = |pending: PendingTranslationUnit| TranslationUnitManifest {
            schema: TRANSLATION_UNIT_SCHEMA_V2,
            base_export: translation_unit_base_export(&pending.key).expect("unit export"),
            key: pending.key,
            dylib_sha256: [0x71; 32],
            code_len: pending.code.len() as u64,
            blocks: pending.blocks,
            binding_layout: pending.binding_layout,
            binding_export: pending.binding_export,
            binding_data_len: pending.binding_data_len,
            cell_size: pending.cell_size,
            bindings: pending.bindings,
            binding_relocations: pending.binding_relocations,
        };
        let runs = manifest(runs);
        let entries = manifest(entries);
        let config = bincode::config::standard().with_fixed_int_encoding();
        let run_bytes = bincode::serde::encode_to_vec(&runs, config).expect("encode runs");
        let entry_bytes = bincode::serde::encode_to_vec(&entries, config).expect("encode entries");
        assert!(run_bytes.len() * 4 < entry_bytes.len());
        let (decoded, consumed): (TranslationUnitManifest, usize) =
            bincode::serde::decode_from_slice(&run_bytes, config).expect("decode runs");
        assert_eq!(consumed, run_bytes.len());
        assert_eq!(decoded, runs);
        assert!(decoded.blocks[0].template.recovery_is_run_encoded());
    }

    #[test]
    fn shared_segment_key_reuses_its_construction_time_source_fingerprint() {
        let source_words: Arc<[u32]> = vec![0xd280_0540, 0xd65f_03c0].into();
        let segment = SharedExecutableSegment::new(
            ImageFileOffset::new(0x1000),
            ImageFileLen::new(8).expect("file length"),
            GuestVa(0x400000),
            GuestCodeLen::new(8).expect("guest length"),
            Arc::clone(&source_words),
        );
        let image = SharedImageConfig {
            executable: ExecutableIdentity::Digest([0x11; 32]),
            page_profile: NativePageProfileIdentity::Native16k,
            address_mode: AddressModeIdentity::Direct,
            segments: vec![segment.clone()],
        };

        assert_eq!(
            image.key_for_segment_with_fingerprint_reuse(&segment, true),
            image.key_for_segment_with_fingerprint_reuse(&segment, false),
        );
        assert_eq!(
            image
                .key_for_segment_with_fingerprint_reuse(&segment, true)
                .source_fingerprint(),
            SourceFingerprint::from_words(&source_words),
        );
    }

    fn manifest_block(guest_start: u64, entry_offset: u32, code_len: u32) -> PortableBlockRecord {
        PortableBlockRecord {
            guest_start: GuestVa(guest_start),
            generation_binding: 0,
            entry_offset,
            code_len,
            requires_sensitive_metadata: false,
            template: empty_template(),
        }
    }

    #[test]
    fn shared_cache_manifest_rejects_duplicate_guest_starts() {
        let mut manifest = manifest_v2_fixture();
        manifest.blocks = vec![
            manifest_block(0x410000, 0, 16),
            manifest_block(0x410000, 16, 16),
        ];

        assert_eq!(
            manifest.validate_ranges(),
            Err(UnitMissReason::ManifestRange)
        );
    }

    #[test]
    fn shared_cache_manifest_rejects_overlapping_block_cache_extents() {
        for (case, blocks) in [
            (
                "duplicate",
                vec![
                    manifest_block(0x410000, 0, 16),
                    manifest_block(0x410100, 0, 16),
                ],
            ),
            (
                "partial",
                vec![
                    manifest_block(0x410000, 0, 16),
                    manifest_block(0x410100, 12, 16),
                ],
            ),
            (
                "nested",
                vec![
                    manifest_block(0x410000, 0, 32),
                    manifest_block(0x410100, 8, 8),
                ],
            ),
            (
                "containing in reverse manifest order",
                vec![
                    manifest_block(0x410000, 8, 8),
                    manifest_block(0x410100, 0, 32),
                ],
            ),
        ] {
            let mut manifest = manifest_v2_fixture();
            manifest.blocks = blocks;

            assert_eq!(
                manifest.validate_ranges(),
                Err(UnitMissReason::ManifestRange),
                "{case}"
            );
        }
    }

    #[test]
    fn shared_cache_manifest_allows_adjacent_and_reverse_disjoint_cache_extents() {
        for (case, blocks) in [
            (
                "adjacent",
                vec![
                    manifest_block(0x410000, 0, 16),
                    manifest_block(0x410100, 16, 16),
                ],
            ),
            (
                "reverse disjoint",
                vec![
                    manifest_block(0x410000, 32, 16),
                    manifest_block(0x410100, 0, 16),
                ],
            ),
        ] {
            let mut manifest = manifest_v2_fixture();
            manifest.blocks = blocks;

            assert_eq!(manifest.validate_ranges(), Ok(()), "{case}");
        }
    }

    #[test]
    fn source_fingerprint_mismatch_is_a_typed_miss() {
        let source = [0xd280_0000_u32];
        let key = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint::from_words(&source),
            AddressModeIdentity::Direct,
        );
        let manifest = TranslationUnitManifest {
            schema: TRANSLATION_UNIT_SCHEMA_V2,
            base_export: translation_unit_base_export(&key).expect("unit export"),
            key,
            dylib_sha256: [0x22; 32],
            code_len: 4,
            blocks: Vec::new(),
            binding_layout: DirectBindingLayout::Disabled,
            binding_export: String::new(),
            binding_data_len: 0,
            cell_size: 0,
            bindings: Vec::new(),
            binding_relocations: Vec::new(),
        };

        assert_eq!(
            manifest.validate_source(&[0xd280_0020]),
            Err(UnitMissReason::SourceFingerprint)
        );
    }

    #[test]
    fn previous_target_cache_abi_is_rejected() {
        let source = [0xd280_0000_u32];
        let key = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint::from_words(&source),
            AddressModeIdentity::Direct,
        );
        let mut manifest = TranslationUnitManifest {
            schema: TRANSLATION_UNIT_SCHEMA_V2,
            base_export: translation_unit_base_export(&key).expect("unit export"),
            key,
            dylib_sha256: [0x22; 32],
            code_len: 4,
            blocks: Vec::new(),
            binding_layout: DirectBindingLayout::Disabled,
            binding_export: String::new(),
            binding_data_len: 0,
            cell_size: 0,
            bindings: Vec::new(),
            binding_relocations: Vec::new(),
        };
        manifest.key.translator_abi = 2;

        assert_eq!(
            manifest.validate_ranges(),
            Err(UnitMissReason::TranslatorAbi),
            "ABI-2 authority precursors must not load into the direct-binding sidecar runtime"
        );
    }

    #[test]
    fn same_unit_links_patch_to_b_and_receive_no_cells() {
        let bindings = ArtifactBindings::from_values([]).expect("empty bindings");
        let source = ArtifactTemplate::normalize(
            vec![0x1400_0001, 0xd503_201f, 0xd503_201f],
            vec![PcMapEntry {
                guest: GuestVa(0x400000),
                cache: CacheOffset::published(0),
            }],
            Vec::new(),
            vec![DirectLink {
                slot: CacheOffset::published(0),
                source: GuestVa(0x400000),
                target: GuestVa(0x400100),
                kind: crate::emit::DirectLinkKind::Branch,
                stub: crate::emit::DirectStubEnvelope {
                    start: CacheOffset::published(4),
                    end: CacheOffset::published(12),
                },
            }],
            Vec::new(),
            Vec::new(),
            &bindings,
        )
        .expect("source template");
        let target = ArtifactTemplate::normalize(
            vec![0xd503_201f],
            vec![PcMapEntry {
                guest: GuestVa(0x400100),
                cache: CacheOffset::published(0),
            }],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            &bindings,
        )
        .expect("target template");
        let pending = PendingTranslationUnit::pack(
            key(
                ExecutableIdentity::Digest([0x11; 32]),
                SourceFingerprint([0xaa; 32]),
                AddressModeIdentity::Direct,
            ),
            vec![
                PortableBlockCandidate {
                    guest_start: GuestVa(0x400000),
                    generation_binding: 0,
                    requires_sensitive_metadata: false,
                    template: source,
                },
                PortableBlockCandidate {
                    guest_start: GuestVa(0x400100),
                    generation_binding: 1,
                    requires_sensitive_metadata: false,
                    template: target,
                },
            ],
            DirectBindingLayout::SidecarV1,
        )
        .expect("pack unit");

        assert_eq!(
            u32::from_le_bytes(pending.code[0..4].try_into().expect("branch word")),
            0x1400_0003
        );
        assert!(pending.bindings.is_empty());
        assert!(pending.binding_data.is_empty());
        assert!(pending.binding_relocations.is_empty());
    }

    #[test]
    fn unresolved_stubs_receive_ordinals_in_source_offset_order() {
        let bindings = ArtifactBindings::from_values([]).expect("empty bindings");
        let template = ArtifactTemplate::normalize(
            vec![
                0x1400_0001,
                0x1400_0001,
                0xd503_201f,
                0xd503_201f,
                0xd503_201f,
                0xd503_201f,
            ],
            vec![PcMapEntry {
                guest: GuestVa(0x400000),
                cache: CacheOffset::published(0),
            }],
            Vec::new(),
            vec![
                DirectLink {
                    slot: CacheOffset::published(4),
                    source: GuestVa(0x400004),
                    target: GuestVa(0x600000),
                    kind: DirectLinkKind::Branch,
                    stub: DirectStubEnvelope {
                        start: CacheOffset::published(16),
                        end: CacheOffset::published(24),
                    },
                },
                DirectLink {
                    slot: CacheOffset::published(0),
                    source: GuestVa(0x400000),
                    target: GuestVa(0x500000),
                    kind: DirectLinkKind::Branch,
                    stub: DirectStubEnvelope {
                        start: CacheOffset::published(8),
                        end: CacheOffset::published(16),
                    },
                },
            ],
            Vec::new(),
            Vec::new(),
            &bindings,
        )
        .expect("out-of-order unresolved template");
        let pending = PendingTranslationUnit::pack(
            key(
                ExecutableIdentity::Digest([0x11; 32]),
                SourceFingerprint([0xaa; 32]),
                AddressModeIdentity::Direct,
            ),
            vec![PortableBlockCandidate {
                guest_start: GuestVa(0x400000),
                generation_binding: 0,
                requires_sensitive_metadata: false,
                template,
            }],
            DirectBindingLayout::Disabled,
        )
        .expect("pack disabled unit");

        assert_eq!(
            pending
                .bindings
                .iter()
                .map(|binding| (
                    binding.stub_start,
                    binding.ordinal.get(),
                    binding.source,
                    binding.target,
                ))
                .collect::<Vec<_>>(),
            vec![
                (8, 0, GuestVa(0x400000), GuestVa(0x500000)),
                (16, 1, GuestVa(0x400004), GuestVa(0x600000)),
            ]
        );
        assert!(pending.binding_data.is_empty());
        assert!(pending.binding_relocations.is_empty());
        assert_eq!(
            pending
                .code
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("disabled word")))
                .collect::<Vec<_>>(),
            vec![
                0x1400_0001,
                0x1400_0001,
                0xd503_201f,
                0xd503_201f,
                0xd503_201f,
                0xd503_201f,
            ],
            "Disabled must preserve the authority precursor byte-for-byte"
        );
    }

    #[test]
    fn equal_source_target_pairs_still_own_distinct_cells() {
        let source = GuestVa(0x400000);
        let target = GuestVa(0x500000);
        let template = unresolved_direct_template(source, target);
        let pending = PendingTranslationUnit::pack(
            key(
                ExecutableIdentity::Digest([0x11; 32]),
                SourceFingerprint([0xaa; 32]),
                AddressModeIdentity::Direct,
            ),
            vec![
                PortableBlockCandidate {
                    guest_start: GuestVa(0x400000),
                    generation_binding: 0,
                    requires_sensitive_metadata: false,
                    template: template.clone(),
                },
                PortableBlockCandidate {
                    guest_start: GuestVa(0x400100),
                    generation_binding: 1,
                    requires_sensitive_metadata: false,
                    template,
                },
            ],
            DirectBindingLayout::SidecarV1,
        )
        .expect("pack duplicate-edge unit");

        assert_eq!(pending.bindings.len(), 2);
        assert_eq!(pending.bindings[0].source, source);
        assert_eq!(pending.bindings[1].source, source);
        assert_eq!(pending.bindings[0].target, target);
        assert_eq!(pending.bindings[1].target, target);
        assert_eq!(pending.bindings[0].ordinal.get(), 0);
        assert_eq!(pending.bindings[1].ordinal.get(), 1);
        assert_eq!(pending.binding_data, vec![0; 16]);
        assert_eq!(pending.binding_relocations.len(), 2);
        assert_eq!(pending.binding_relocations[0].data_offset, 0);
        assert_eq!(pending.binding_relocations[1].data_offset, 8);
    }

    #[test]
    fn schema_v2_rejects_old_abi_nonzero_cells_and_out_of_stub_relocations() {
        fn assert_range_miss(case: &str, manifest: TranslationUnitManifest) {
            assert_eq!(
                manifest.validate_ranges(),
                Err(UnitMissReason::ManifestRange),
                "{case}"
            );
        }

        let mut old_schema = manifest_v2_fixture();
        old_schema.schema = 1;
        assert_eq!(
            old_schema.validate_ranges(),
            Err(UnitMissReason::Schema),
            "old schema"
        );

        let mut old_abi = manifest_v2_fixture();
        old_abi.key.translator_abi = 2;
        assert_eq!(
            old_abi.validate_ranges(),
            Err(UnitMissReason::TranslatorAbi),
            "old translator ABI"
        );

        let mut unaligned_data = manifest_v2_fixture();
        unaligned_data.binding_data_len = 9;
        assert_range_miss("unaligned data length", unaligned_data);

        let mut inconsistent_data = manifest_v2_fixture();
        inconsistent_data.binding_data_len = 16;
        assert_range_miss("inconsistent data length", inconsistent_data);

        let mut duplicate_ordinal = manifest_v2_fixture();
        duplicate_ordinal
            .bindings
            .push(UnresolvedDirectBindingRecord {
                source: GuestVa(0x400100),
                target: GuestVa(0x500100),
                kind: DirectLinkKind::Branch,
                ordinal: DirectBindingOrdinal::claimed(0),
                stub_start: 288,
                stub_end: 512,
            });
        duplicate_ordinal
            .binding_relocations
            .push(DirectBindingRelocation {
                ordinal: DirectBindingOrdinal::claimed(0),
                adrp_offset: 308,
                add_offset: 312,
                miss_adrp_offset: 396,
                miss_add_offset: 400,
                data_offset: 8,
            });
        duplicate_ordinal.binding_data_len = 16;
        assert_range_miss("duplicate ordinal", duplicate_ordinal);

        let mut conflicting_owner = manifest_v2_fixture();
        conflicting_owner
            .bindings
            .push(UnresolvedDirectBindingRecord {
                source: GuestVa(0x400100),
                target: GuestVa(0x500100),
                kind: DirectLinkKind::Call,
                ordinal: DirectBindingOrdinal::claimed(1),
                stub_start: 32,
                stub_end: 288,
            });
        conflicting_owner
            .binding_relocations
            .push(DirectBindingRelocation {
                ordinal: DirectBindingOrdinal::claimed(1),
                adrp_offset: 52,
                add_offset: 56,
                miss_adrp_offset: 140,
                miss_add_offset: 144,
                data_offset: 8,
            });
        conflicting_owner.binding_data_len = 16;
        assert_range_miss("conflicting stub owner", conflicting_owner);

        let mut same_unit_binding = manifest_v2_fixture();
        same_unit_binding.blocks.push(PortableBlockRecord {
            guest_start: GuestVa(0x500000),
            generation_binding: 0,
            entry_offset: 0,
            code_len: 4,
            requires_sensitive_metadata: false,
            template: empty_template(),
        });
        assert_range_miss("same-unit binding", same_unit_binding);

        let mut out_of_envelope = manifest_v2_fixture();
        out_of_envelope.binding_relocations[0].adrp_offset = 28;
        assert_range_miss("out-of-envelope relocation", out_of_envelope);

        let mut miss_out_of_envelope = manifest_v2_fixture();
        miss_out_of_envelope.binding_relocations[0].miss_add_offset = 288;
        assert_range_miss("out-of-envelope miss relocation", miss_out_of_envelope);

        let manifest = manifest_v2_fixture();
        assert_eq!(
            manifest.validate_binding_data(&[0; 8]),
            Ok(()),
            "zero cells"
        );
        assert_eq!(
            manifest.validate_binding_data(&[0, 0, 0, 0, 0, 0, 0, 1]),
            Err(UnitMissReason::ManifestRange),
            "nonzero cell bytes"
        );

        let mut code = vec![0; 512];
        for (offset, word) in [
            (52, 0x9000_000f_u32),
            (56, 0x9100_01ef),
            (140, 0x9000_000f),
            (144, 0x9100_01ef),
        ] {
            code[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
        }
        assert_eq!(
            manifest.validate_binding_code(&code),
            Ok(()),
            "both typed relocation pairs"
        );
        code[144..148].copy_from_slice(&0xd503_201f_u32.to_le_bytes());
        assert_eq!(
            manifest.validate_binding_code(&code),
            Err(UnitMissReason::ManifestRange),
            "wrong miss relocation instruction shape"
        );
    }

    #[test]
    fn schema_v2_rejects_aliased_direct_binding_relocations() {
        let mut aliased = manifest_v2_fixture();
        aliased.binding_relocations[0].miss_adrp_offset =
            aliased.binding_relocations[0].adrp_offset;
        aliased.binding_relocations[0].miss_add_offset = aliased.binding_relocations[0].add_offset;
        assert_eq!(
            aliased.validate_ranges(),
            Err(UnitMissReason::ManifestRange),
            "hit and miss relocation pairs must not alias"
        );
    }

    #[test]
    fn schema_v2_rejects_shifted_but_contained_direct_binding_relocations() {
        let mut shifted = manifest_v2_fixture();
        shifted.binding_relocations[0].adrp_offset += 4;
        shifted.binding_relocations[0].add_offset += 4;
        assert_eq!(
            shifted.validate_ranges(),
            Err(UnitMissReason::ManifestRange),
            "contained relocation pairs must still own their fixed stub offsets"
        );
    }

    #[test]
    fn direct_binding_relocation_offsets_reject_stub_start_overflow() {
        assert_eq!(
            expected_direct_binding_relocation_offsets(u32::MAX - 19),
            None,
            "hit ADRP arithmetic must be checked"
        );
        assert_eq!(
            expected_direct_binding_relocation_offsets(u32::MAX - 107),
            None,
            "miss ADRP arithmetic must be checked independently"
        );
    }

    #[test]
    fn same_guest_va_with_different_images_never_aliases() {
        let first = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint([0xaa; 32]),
            AddressModeIdentity::biased(
                NativeHostBias::new(0x8000_0000, 16 * 1024).expect("aligned bias"),
            ),
        );
        let second = key(
            ExecutableIdentity::Digest([0x22; 32]),
            SourceFingerprint([0xaa; 32]),
            AddressModeIdentity::biased(
                NativeHostBias::new(0x8000_0000, 16 * 1024).expect("aligned bias"),
            ),
        );

        assert_ne!(first, second);
        assert_ne!(
            first.file_stem().expect("first stem"),
            second.file_stem().expect("second stem")
        );
    }

    #[test]
    fn translation_unit_base_export_binds_the_full_unit_identity() {
        let first = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint([0xaa; 32]),
            AddressModeIdentity::Direct,
        );
        let second = key(
            ExecutableIdentity::Digest([0x22; 32]),
            SourceFingerprint([0xaa; 32]),
            AddressModeIdentity::Direct,
        );

        let first_export = translation_unit_base_export(&first).expect("first export");
        let second_export = translation_unit_base_export(&second).expect("second export");

        assert!(first_export.starts_with(TRANSLATION_UNIT_BASE_EXPORT));
        assert_ne!(first_export, second_export);
        assert_eq!(
            first_export,
            format!(
                "{TRANSLATION_UNIT_BASE_EXPORT}_{}",
                first.file_stem().expect("first stem")
            )
        );
    }

    #[test]
    fn same_image_with_different_source_fingerprints_never_aliases() {
        let first = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint([0xaa; 32]),
            AddressModeIdentity::Direct,
        );
        let second = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint([0xbb; 32]),
            AddressModeIdentity::Direct,
        );

        assert_ne!(first, second);
        assert_ne!(
            first.file_stem().expect("first stem"),
            second.file_stem().expect("second stem")
        );
    }

    #[test]
    fn same_image_with_different_host_biases_never_aliases() {
        let first = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint([0xaa; 32]),
            AddressModeIdentity::biased(
                NativeHostBias::new(0x8000_0000, 16 * 1024).expect("aligned bias"),
            ),
        );
        let second = key(
            ExecutableIdentity::Digest([0x11; 32]),
            SourceFingerprint([0xaa; 32]),
            AddressModeIdentity::biased(
                NativeHostBias::new(0x9000_0000, 16 * 1024).expect("aligned bias"),
            ),
        );

        assert_ne!(first, second);
        assert_ne!(
            first.file_stem().expect("first stem"),
            second.file_stem().expect("second stem")
        );
    }

    #[test]
    fn source_fingerprint_uses_all_words_in_little_endian_order() {
        let first = SourceFingerprint::from_words(&[0x0102_0304, 0x0506_0708]);
        let second = SourceFingerprint::from_words(&[0x0102_0304, 0x0506_0709]);
        let reordered = SourceFingerprint::from_words(&[0x0506_0708, 0x0102_0304]);

        assert_ne!(first, second);
        assert_ne!(first, reordered);
    }

    #[test]
    fn key_json_round_trips_typed_guest_va() {
        let original = key(
            ExecutableIdentity::Digest([0x44; 32]),
            SourceFingerprint([0x55; 32]),
            AddressModeIdentity::Direct,
        );

        let json = serde_json::to_vec(&original).expect("serialize key");
        let decoded: TranslationUnitKey = serde_json::from_slice(&json).expect("deserialize key");

        assert_eq!(decoded, original);
        assert_eq!(decoded.guest_va_start(), GuestVa(0x400000));
    }
}
