use super::{
    MAX_TRANSLATION_UNIT_CODE_BYTES, PortableBlockCandidate, TranslationUnitKey, UnitMissReason,
};
use crate::artifact_spike::{ArtifactTemplate, UnitBlockColdWire, UnitBlockHotWire};
use crate::types::{CodeGeneration, DsrError};
use carrick_guest_mem::GuestVa;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;

pub const UNIT_BUNDLE_MAGIC_V1: [u8; 8] = *b"CUNITB1\0";
pub const UNIT_BUNDLE_SCHEMA_V1: u32 = 1;
pub const UNIT_BUNDLE_HEADER_BYTES_V1: usize = 104;
const UNIT_METADATA_MAGIC_V6: [u8; 8] = *b"CUNITV6\0";
pub const TRANSLATION_UNIT_SCHEMA_V6: u32 = 6;
const UNIT_METADATA_LIMIT: usize = 256 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredBlockArtifact {
    pub guest_start: GuestVa,
    pub source_end: GuestVa,
    pub generation: CodeGeneration,
    pub requires_sensitive_metadata: bool,
    pub code: Box<[u8]>,
    pub hot: Box<[u8]>,
    pub cold: Box<[u8]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeRefusal {
    Conflict { guest_start: GuestVa },
    Capacity,
    Preflight(UnitMissReason),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeKind {
    Created,
    Merged,
    Unchanged,
    Repaired,
    Yielded,
    Refused(MergeRefusal),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeOutcome {
    pub kind: MergeKind,
    pub blocks_added: u64,
    pub duplicates: u64,
    pub post_rename_sync_failed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnitStoreFailureClass {
    Io,
    Validation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitStoreFailure {
    pub class: UnitStoreFailureClass,
    pub reason: UnitMissReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedUnion {
    pub blocks: Vec<StoredBlockArtifact>,
    pub blocks_added: u64,
    pub duplicates: u64,
}

impl StoredBlockArtifact {
    pub fn from_candidate(
        candidate: PortableBlockCandidate,
        recovery_runs: bool,
    ) -> Result<Self, DsrError> {
        if candidate.generation != CodeGeneration::INITIAL {
            return Err(DsrError::CachePolicy(format!(
                "translation unit candidate 0x{:x} is not INITIAL generation",
                candidate.guest_start.raw()
            )));
        }
        if candidate.source_end.raw() <= candidate.guest_start.raw() {
            return Err(DsrError::CachePolicy(format!(
                "translation unit candidate 0x{:x} has an empty source extent",
                candidate.guest_start.raw()
            )));
        }
        let words = candidate.template.words();
        if words.is_empty() {
            return Err(DsrError::CachePolicy(format!(
                "translation unit candidate 0x{:x} carries no recorded words",
                candidate.guest_start.raw()
            )));
        }
        let mut code = Vec::with_capacity(words.len().saturating_mul(4));
        for word in words {
            code.extend_from_slice(&word.to_le_bytes());
        }
        let metadata = candidate
            .template
            .into_unit_record_metadata(recovery_runs)?;
        let (hot, cold) = metadata.into_unit_wire_parts();
        let config = bincode::config::standard().with_limit::<UNIT_METADATA_LIMIT>();
        let hot = bincode::serde::encode_to_vec(hot, config).map_err(|error| {
            DsrError::CachePolicy(format!("encode unit block hot blob: {error}"))
        })?;
        let cold = bincode::serde::encode_to_vec(cold, config).map_err(|error| {
            DsrError::CachePolicy(format!("encode unit block cold blob: {error}"))
        })?;
        Ok(Self {
            guest_start: candidate.guest_start,
            source_end: candidate.source_end,
            generation: candidate.generation,
            requires_sensitive_metadata: candidate.requires_sensitive_metadata,
            code: code.into_boxed_slice(),
            hot: hot.into_boxed_slice(),
            cold: cold.into_boxed_slice(),
        })
    }

    pub fn decode_template(&self) -> Result<ArtifactTemplate, UnitMissReason> {
        let config = bincode::config::standard().with_limit::<UNIT_METADATA_LIMIT>();
        let (hot, hot_consumed): (UnitBlockHotWire, usize) =
            bincode::serde::decode_from_slice(&self.hot, config)
                .map_err(|_| UnitMissReason::Schema)?;
        if hot_consumed != self.hot.len() {
            return Err(UnitMissReason::Schema);
        }
        let (cold, cold_consumed): (UnitBlockColdWire, usize) =
            bincode::serde::decode_from_slice(&self.cold, config)
                .map_err(|_| UnitMissReason::Schema)?;
        if cold_consumed != self.cold.len() {
            return Err(UnitMissReason::Schema);
        }
        Ok(ArtifactTemplate::from_unit_wire_parts(hot, cold))
    }
}

const UNIT_BLOCK_INDEX_ROW_BYTES_V6: usize = 48;
const UNIT_BLOCK_FLAG_SENSITIVE: u32 = 1;

#[derive(Serialize, Deserialize)]
struct WireMetadataHeaderV6 {
    key: TranslationUnitKey,
    block_count: u64,
    payload_len: u64,
}

#[derive(Clone)]
pub struct DecodedUnitBundle {
    backing: Arc<dyn AsRef<[u8]> + Send + Sync>,
    key: TranslationUnitKey,
    code_offset: usize,
    payload_offset: usize,
    blocks: Vec<DecodedBlockV6>,
}

#[derive(Clone)]
struct DecodedBlockV6 {
    guest_start: GuestVa,
    source_end: GuestVa,
    generation: CodeGeneration,
    requires_sensitive_metadata: bool,
    code_offset: usize,
    code_len: usize,
    hot_offset: usize,
    hot_len: usize,
    cold_len: usize,
}

impl DecodedUnitBundle {
    pub fn key(&self) -> &TranslationUnitKey {
        &self.key
    }

    pub fn code_offset(&self) -> usize {
        self.code_offset
    }

    pub fn artifacts(&self) -> Result<Vec<StoredBlockArtifact>, UnitMissReason> {
        let bytes = self.backing.as_ref().as_ref();
        self.blocks
            .iter()
            .map(|block| {
                let start = self
                    .code_offset
                    .checked_add(block.code_offset)
                    .ok_or(UnitMissReason::ManifestRange)?;
                let end = start
                    .checked_add(block.code_len)
                    .ok_or(UnitMissReason::ManifestRange)?;
                let code = bytes.get(start..end).ok_or(UnitMissReason::ManifestRange)?;
                let hot_start = self
                    .payload_offset
                    .checked_add(block.hot_offset)
                    .ok_or(UnitMissReason::ManifestRange)?;
                let hot_end = hot_start
                    .checked_add(block.hot_len)
                    .ok_or(UnitMissReason::ManifestRange)?;
                let cold_end = hot_end
                    .checked_add(block.cold_len)
                    .ok_or(UnitMissReason::ManifestRange)?;
                let hot = bytes
                    .get(hot_start..hot_end)
                    .ok_or(UnitMissReason::ManifestRange)?;
                let cold = bytes
                    .get(hot_end..cold_end)
                    .ok_or(UnitMissReason::ManifestRange)?;
                Ok(StoredBlockArtifact {
                    guest_start: block.guest_start,
                    source_end: block.source_end,
                    generation: block.generation,
                    requires_sensitive_metadata: block.requires_sensitive_metadata,
                    code: code.into(),
                    hot: hot.into(),
                    cold: cold.into(),
                })
            })
            .collect()
    }
}

pub fn encode_unit_bundle_v1(
    key: &TranslationUnitKey,
    blocks: &[StoredBlockArtifact],
) -> Result<Vec<u8>, DsrError> {
    let mut ordered = blocks.to_vec();
    ordered.sort_by_key(|block| block.guest_start);
    validate_artifacts(key, &ordered)?;

    let mut code = Vec::new();
    let mut index = Vec::with_capacity(ordered.len() * UNIT_BLOCK_INDEX_ROW_BYTES_V6);
    let mut payload = Vec::new();
    for block in ordered {
        let code_offset = u64::try_from(code.len()).map_err(|_| {
            DsrError::CachePolicy("unit bundle code offset exceeds u64".to_string())
        })?;
        let code_len = u32::try_from(block.code.len()).map_err(|_| {
            DsrError::CachePolicy("unit bundle block length exceeds u32".to_string())
        })?;
        let hot_len = u32::try_from(block.hot.len())
            .map_err(|_| DsrError::CachePolicy("unit bundle hot blob exceeds u32".to_string()))?;
        let cold_len = u32::try_from(block.cold.len())
            .map_err(|_| DsrError::CachePolicy("unit bundle cold blob exceeds u32".to_string()))?;
        code.extend_from_slice(&block.code);
        index.extend_from_slice(&block.guest_start.raw().to_le_bytes());
        index.extend_from_slice(&block.source_end.raw().to_le_bytes());
        index.extend_from_slice(&block.generation.get().to_le_bytes());
        index.extend_from_slice(&code_offset.to_le_bytes());
        index.extend_from_slice(&code_len.to_le_bytes());
        index.extend_from_slice(
            &(if block.requires_sensitive_metadata {
                UNIT_BLOCK_FLAG_SENSITIVE
            } else {
                0
            })
            .to_le_bytes(),
        );
        index.extend_from_slice(&hot_len.to_le_bytes());
        index.extend_from_slice(&cold_len.to_le_bytes());
        payload.extend_from_slice(&block.hot);
        payload.extend_from_slice(&block.cold);
    }
    let header = bincode::serde::encode_to_vec(
        WireMetadataHeaderV6 {
            key: key.clone(),
            block_count: blocks.len() as u64,
            payload_len: payload.len() as u64,
        },
        bincode::config::standard().with_limit::<UNIT_METADATA_LIMIT>(),
    )
    .map_err(|error| DsrError::CachePolicy(format!("encode unit metadata v6 header: {error}")))?;
    let header_len = u32::try_from(header.len())
        .map_err(|_| DsrError::CachePolicy("unit metadata v6 header exceeds u32".to_string()))?;
    let metadata_len = 16_usize
        .checked_add(header.len())
        .and_then(|length| length.checked_add(index.len()))
        .and_then(|length| length.checked_add(payload.len()))
        .ok_or_else(|| DsrError::CachePolicy("unit bundle metadata overflow".to_string()))?;
    let mut metadata = Vec::with_capacity(metadata_len);
    metadata.extend_from_slice(&UNIT_METADATA_MAGIC_V6);
    metadata.extend_from_slice(&TRANSLATION_UNIT_SCHEMA_V6.to_le_bytes());
    metadata.extend_from_slice(&header_len.to_le_bytes());
    metadata.extend_from_slice(&header);
    metadata.extend_from_slice(&index);
    metadata.extend_from_slice(&payload);
    validate_bundle_capacity(code.len(), metadata.len()).map_err(|_| {
        DsrError::CachePolicy("unit bundle exceeds a code or metadata cap".to_string())
    })?;
    let metadata_offset = UNIT_BUNDLE_HEADER_BYTES_V1;
    let metadata_end = metadata_offset
        .checked_add(metadata.len())
        .ok_or_else(|| DsrError::CachePolicy("unit bundle metadata overflow".to_string()))?;
    let code_offset = align_up(metadata_end, 8)
        .ok_or_else(|| DsrError::CachePolicy("unit bundle code offset overflow".to_string()))?;
    let file_len = code_offset
        .checked_add(code.len())
        .ok_or_else(|| DsrError::CachePolicy("unit bundle length overflow".to_string()))?;

    let mut bytes = vec![0_u8; file_len];
    bytes[0..8].copy_from_slice(&UNIT_BUNDLE_MAGIC_V1);
    put_u32(&mut bytes, 8, UNIT_BUNDLE_SCHEMA_V1);
    put_u32(&mut bytes, 12, UNIT_BUNDLE_HEADER_BYTES_V1 as u32);
    put_u64(&mut bytes, 16, file_len as u64);
    put_u32(&mut bytes, 24, key.translator_abi());
    put_u32(&mut bytes, 28, 0);
    put_u64(&mut bytes, 32, metadata_offset as u64);
    put_u64(&mut bytes, 40, metadata.len() as u64);
    put_u64(&mut bytes, 48, code_offset as u64);
    put_u64(&mut bytes, 56, code.len() as u64);
    put_u64(&mut bytes, 64, blocks.len() as u64);
    bytes[72..104].copy_from_slice(&Sha256::digest(&code));
    bytes[metadata_offset..metadata_end].copy_from_slice(&metadata);
    bytes[code_offset..].copy_from_slice(&code);
    Ok(bytes)
}

pub fn merge_normalized_artifacts(
    existing: &[StoredBlockArtifact],
    pending: &[StoredBlockArtifact],
) -> Result<NormalizedUnion, MergeRefusal> {
    let mut union = std::collections::BTreeMap::new();
    for block in existing {
        match union.get(&block.guest_start) {
            None => {
                union.insert(block.guest_start, block.clone());
            }
            Some(prior) if prior == block => {}
            Some(_) => {
                return Err(MergeRefusal::Conflict {
                    guest_start: block.guest_start,
                });
            }
        }
    }

    let mut blocks_added = 0_u64;
    let mut duplicates = 0_u64;
    for block in pending {
        match union.get(&block.guest_start) {
            None => {
                union.insert(block.guest_start, block.clone());
                blocks_added = blocks_added.checked_add(1).ok_or(MergeRefusal::Capacity)?;
            }
            Some(prior) if prior == block => {
                duplicates = duplicates.checked_add(1).ok_or(MergeRefusal::Capacity)?;
            }
            Some(_) => {
                return Err(MergeRefusal::Conflict {
                    guest_start: block.guest_start,
                });
            }
        }
    }

    let mut code_len = 0_usize;
    let mut metadata_len = 0_usize;
    for block in union.values() {
        code_len = code_len
            .checked_add(block.code.len())
            .ok_or(MergeRefusal::Capacity)?;
        metadata_len = metadata_len
            .checked_add(block.hot.len())
            .and_then(|total| total.checked_add(block.cold.len()))
            .ok_or(MergeRefusal::Capacity)?;
    }
    validate_bundle_capacity(code_len, metadata_len)?;

    Ok(NormalizedUnion {
        blocks: union.into_values().collect(),
        blocks_added,
        duplicates,
    })
}

pub fn decode_unit_bundle_v1(
    backing: Arc<dyn AsRef<[u8]> + Send + Sync>,
    expected_key: &TranslationUnitKey,
) -> Result<DecodedUnitBundle, UnitMissReason> {
    let bytes = backing.as_ref().as_ref();
    if bytes.get(0..8) != Some(&UNIT_BUNDLE_MAGIC_V1) {
        return Err(UnitMissReason::Schema);
    }
    if read_u32(bytes, 8)? != UNIT_BUNDLE_SCHEMA_V1
        || read_u32(bytes, 12)? as usize != UNIT_BUNDLE_HEADER_BYTES_V1
        || read_u32(bytes, 28)? != 0
    {
        return Err(UnitMissReason::Schema);
    }
    if read_u32(bytes, 24)? != expected_key.translator_abi() {
        return Err(UnitMissReason::TranslatorAbi);
    }
    let file_len = to_usize(read_u64(bytes, 16)?)?;
    if file_len != bytes.len() {
        return Err(UnitMissReason::Schema);
    }
    let metadata_offset = to_usize(read_u64(bytes, 32)?)?;
    let metadata_len = to_usize(read_u64(bytes, 40)?)?;
    let code_offset = to_usize(read_u64(bytes, 48)?)?;
    let code_len = to_usize(read_u64(bytes, 56)?)?;
    let block_count = to_usize(read_u64(bytes, 64)?)?;
    if metadata_offset != UNIT_BUNDLE_HEADER_BYTES_V1
        || !metadata_offset.is_multiple_of(8)
        || !code_offset.is_multiple_of(8)
        || code_len == 0
        || code_len > MAX_TRANSLATION_UNIT_CODE_BYTES
    {
        return Err(UnitMissReason::ManifestRange);
    }
    let metadata_end = metadata_offset
        .checked_add(metadata_len)
        .ok_or(UnitMissReason::ManifestRange)?;
    let code_end = code_offset
        .checked_add(code_len)
        .ok_or(UnitMissReason::ManifestRange)?;
    if metadata_len > UNIT_METADATA_LIMIT
        || metadata_end > code_offset
        || code_end != file_len
        || bytes
            .get(metadata_end..code_offset)
            .ok_or(UnitMissReason::ManifestRange)?
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(UnitMissReason::ManifestRange);
    }
    let code = bytes
        .get(code_offset..code_end)
        .ok_or(UnitMissReason::ManifestRange)?;
    if Sha256::digest(code).as_slice() != bytes.get(72..104).ok_or(UnitMissReason::Schema)? {
        return Err(UnitMissReason::CodeDigest);
    }
    let metadata_bytes = bytes
        .get(metadata_offset..metadata_end)
        .ok_or(UnitMissReason::ManifestRange)?;
    if metadata_bytes.get(0..8) != Some(&UNIT_METADATA_MAGIC_V6)
        || read_u32(metadata_bytes, 8)? != TRANSLATION_UNIT_SCHEMA_V6
    {
        return Err(UnitMissReason::Schema);
    }
    let header_len = read_u32(metadata_bytes, 12)? as usize;
    let header_end = 16_usize
        .checked_add(header_len)
        .ok_or(UnitMissReason::ManifestRange)?;
    let header_bytes = metadata_bytes
        .get(16..header_end)
        .ok_or(UnitMissReason::Schema)?;
    let (header, consumed): (WireMetadataHeaderV6, usize) = bincode::serde::decode_from_slice(
        header_bytes,
        bincode::config::standard().with_limit::<UNIT_METADATA_LIMIT>(),
    )
    .map_err(|_| UnitMissReason::Schema)?;
    if consumed != header_bytes.len() || to_usize(header.block_count)? != block_count {
        return Err(UnitMissReason::Schema);
    }
    validate_key(&header.key, expected_key)?;
    let index_len = block_count
        .checked_mul(UNIT_BLOCK_INDEX_ROW_BYTES_V6)
        .ok_or(UnitMissReason::ManifestRange)?;
    let payload_start = header_end
        .checked_add(index_len)
        .ok_or(UnitMissReason::ManifestRange)?;
    let payload_len = to_usize(header.payload_len)?;
    let expected_metadata_len = payload_start
        .checked_add(payload_len)
        .ok_or(UnitMissReason::ManifestRange)?;
    if expected_metadata_len != metadata_bytes.len() {
        return Err(UnitMissReason::Schema);
    }
    let index = metadata_bytes
        .get(header_end..payload_start)
        .ok_or(UnitMissReason::Schema)?;
    let payload = metadata_bytes
        .get(payload_start..)
        .ok_or(UnitMissReason::Schema)?;
    let mut blocks = Vec::with_capacity(block_count);
    let mut payload_offset = 0_usize;
    let mut expected_code_offset = 0_usize;
    let mut previous_guest_start = None;
    for row in 0..block_count {
        let at = row
            .checked_mul(UNIT_BLOCK_INDEX_ROW_BYTES_V6)
            .ok_or(UnitMissReason::ManifestRange)?;
        let guest_start = GuestVa(read_u64(index, at)?);
        let source_end = GuestVa(read_u64(index, at + 8)?);
        let generation = CodeGeneration::claimed(read_u64(index, at + 16)?);
        let block_code_offset = to_usize(read_u64(index, at + 24)?)?;
        let block_code_len = read_u32(index, at + 32)? as usize;
        let flags = read_u32(index, at + 36)?;
        let hot_len = read_u32(index, at + 40)? as usize;
        let cold_len = read_u32(index, at + 44)? as usize;
        if flags & !UNIT_BLOCK_FLAG_SENSITIVE != 0
            || previous_guest_start.is_some_and(|previous| previous >= guest_start)
            || block_code_offset != expected_code_offset
        {
            return Err(UnitMissReason::ManifestRange);
        }
        let block_code_end = block_code_offset
            .checked_add(block_code_len)
            .ok_or(UnitMissReason::ManifestRange)?;
        if block_code_end > code_len {
            return Err(UnitMissReason::ManifestRange);
        }
        let hot_end = payload_offset
            .checked_add(hot_len)
            .ok_or(UnitMissReason::ManifestRange)?;
        let cold_end = hot_end
            .checked_add(cold_len)
            .ok_or(UnitMissReason::ManifestRange)?;
        let hot = payload
            .get(payload_offset..hot_end)
            .ok_or(UnitMissReason::ManifestRange)?;
        let cold = payload
            .get(hot_end..cold_end)
            .ok_or(UnitMissReason::ManifestRange)?;
        blocks.push(DecodedBlockV6 {
            guest_start,
            source_end,
            generation,
            requires_sensitive_metadata: flags & UNIT_BLOCK_FLAG_SENSITIVE != 0,
            code_offset: block_code_offset,
            code_len: block_code_len,
            hot_offset: payload_offset,
            hot_len: hot.len(),
            cold_len: cold.len(),
        });
        previous_guest_start = Some(guest_start);
        expected_code_offset = block_code_end;
        payload_offset = cold_end;
    }
    if expected_code_offset != code_len || payload_offset != payload_len {
        return Err(UnitMissReason::ManifestRange);
    }
    let decoded = DecodedUnitBundle {
        backing,
        key: header.key,
        code_offset,
        payload_offset: metadata_offset
            .checked_add(payload_start)
            .ok_or(UnitMissReason::ManifestRange)?,
        blocks,
    };
    validate_decoded_artifacts(expected_key, &decoded)?;
    Ok(decoded)
}

fn validate_artifacts(
    key: &TranslationUnitKey,
    blocks: &[StoredBlockArtifact],
) -> Result<(), DsrError> {
    if blocks.is_empty() {
        return Err(DsrError::CachePolicy(
            "translation unit contains no blocks".to_string(),
        ));
    }
    let segment_end = key
        .guest_va_start
        .raw()
        .checked_add(key.guest_va_len.get())
        .ok_or_else(|| DsrError::CachePolicy("unit segment extent overflow".to_string()))?;
    let mut starts = BTreeSet::new();
    let mut total_code = 0_usize;
    let mut total_metadata = 0_usize;
    for block in blocks {
        if block.generation != CodeGeneration::INITIAL
            || block.guest_start.raw() < key.guest_va_start.raw()
            || block.source_end.raw() <= block.guest_start.raw()
            || block.source_end.raw() > segment_end
            || block.code.is_empty()
            || !block.code.len().is_multiple_of(4)
            || !starts.insert(block.guest_start)
        {
            return Err(DsrError::CachePolicy(format!(
                "translation unit block 0x{:x} has invalid geometry",
                block.guest_start.raw()
            )));
        }
        total_code = total_code.checked_add(block.code.len()).ok_or_else(|| {
            DsrError::CachePolicy("translation unit code length overflow".to_string())
        })?;
        total_metadata = total_metadata
            .checked_add(block.hot.len())
            .and_then(|total| total.checked_add(block.cold.len()))
            .ok_or_else(|| {
                DsrError::CachePolicy("translation unit metadata length overflow".to_string())
            })?;
    }
    if validate_bundle_capacity(total_code, total_metadata).is_err() {
        return Err(DsrError::CachePolicy(
            "translation unit exceeds a bundle capacity cap".to_string(),
        ));
    }
    Ok(())
}

fn validate_decoded_artifacts(
    key: &TranslationUnitKey,
    decoded: &DecodedUnitBundle,
) -> Result<(), UnitMissReason> {
    let artifacts = decoded.artifacts()?;
    validate_artifacts(key, &artifacts).map_err(|_| UnitMissReason::ManifestRange)?;
    for artifact in artifacts {
        let template = artifact.decode_template()?;
        let code_len =
            u32::try_from(artifact.code.len()).map_err(|_| UnitMissReason::ManifestRange)?;
        if !template.replay_metadata_fits_code_len(code_len) {
            return Err(UnitMissReason::ManifestRange);
        }
    }
    Ok(())
}

fn validate_key(
    actual: &TranslationUnitKey,
    expected: &TranslationUnitKey,
) -> Result<(), UnitMissReason> {
    if actual.translator_abi != expected.translator_abi {
        return Err(UnitMissReason::TranslatorAbi);
    }
    if actual.executable != expected.executable
        || actual.segment_file_offset != expected.segment_file_offset
        || actual.segment_file_len != expected.segment_file_len
        || actual.guest_va_start != expected.guest_va_start
        || actual.guest_va_len != expected.guest_va_len
    {
        return Err(UnitMissReason::ImageIdentity);
    }
    if actual.source_fingerprint != expected.source_fingerprint {
        return Err(UnitMissReason::SourceFingerprint);
    }
    if actual.address_mode != expected.address_mode {
        return Err(UnitMissReason::AddressMode);
    }
    if actual.page_profile != expected.page_profile {
        return Err(UnitMissReason::PageProfile);
    }
    Ok(())
}

fn validate_bundle_capacity(code_len: usize, metadata_len: usize) -> Result<(), MergeRefusal> {
    if code_len > MAX_TRANSLATION_UNIT_CODE_BYTES || metadata_len > UNIT_METADATA_LIMIT {
        Err(MergeRefusal::Capacity)
    } else {
        Ok(())
    }
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|sum| sum & !(alignment - 1))
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, UnitMissReason> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at.checked_add(4).ok_or(UnitMissReason::Schema)?)
            .ok_or(UnitMissReason::Schema)?
            .try_into()
            .map_err(|_| UnitMissReason::Schema)?,
    ))
}

fn read_u64(bytes: &[u8], at: usize) -> Result<u64, UnitMissReason> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at.checked_add(8).ok_or(UnitMissReason::Schema)?)
            .ok_or(UnitMissReason::Schema)?
            .try_into()
            .map_err(|_| UnitMissReason::Schema)?,
    ))
}

fn to_usize(value: u64) -> Result<usize, UnitMissReason> {
    usize::try_from(value).map_err(|_| UnitMissReason::ManifestRange)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockPlan, PlannedExit};
    use crate::emit::{EmitAddressMode, GenerationGuard};
    use crate::shared_cache::{
        AddressModeIdentity, ExecutableIdentity, GuestCodeLen, ImageFileLen, ImageFileOffset,
        NativePageProfileIdentity, PortableBlockCandidate, SourceFingerprint, TranslationUnitKey,
    };
    use crate::types::CodeGeneration;
    use carrick_guest_mem::GuestVa;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;

    fn fixture_key() -> TranslationUnitKey {
        TranslationUnitKey::for_segment(
            ExecutableIdentity::Digest([0x11; 32]),
            ImageFileOffset::new(0x1000),
            ImageFileLen::new(0x4000).expect("nonzero file length"),
            GuestVa(0x400000),
            GuestCodeLen::new(0x4000).expect("nonzero guest length"),
            SourceFingerprint([0x22; 32]),
            NativePageProfileIdentity::Native16k,
            AddressModeIdentity::Direct,
        )
    }

    fn fixture_key_with_digest(digest: u8) -> TranslationUnitKey {
        TranslationUnitKey::for_segment(
            ExecutableIdentity::Digest([digest; 32]),
            ImageFileOffset::new(0x1000),
            ImageFileLen::new(0x4000).expect("nonzero file length"),
            GuestVa(0x400000),
            GuestCodeLen::new(0x4000).expect("nonzero guest length"),
            SourceFingerprint([0x22; 32]),
            NativePageProfileIdentity::Native16k,
            AddressModeIdentity::Direct,
        )
    }

    fn native_tap_artifact(guest_start: GuestVa, emitted_word: u32) -> StoredBlockArtifact {
        let generation = AtomicU64::new(CodeGeneration::INITIAL.get());
        let source_end = GuestVa(guest_start.raw() + 4);
        let plan = BlockPlan {
            start: guest_start,
            end: source_end,
            generation: CodeGeneration::INITIAL,
            instructions: Vec::new(),
            exit: PlannedExit::Syscall {
                guest: guest_start,
                resume: source_end,
            },
            extensions: Vec::new(),
        };
        let mut cache = crate::test_jit::test_cache(64 * 1024);
        let (_emitted, artifact) = crate::emit::emit_block_recording_artifact(
            &mut cache,
            &plan,
            GenerationGuard::new(&generation, CodeGeneration::INITIAL),
            EmitAddressMode::Direct,
            vec![emitted_word],
        )
        .expect("record native-tap artifact");
        StoredBlockArtifact::from_candidate(
            PortableBlockCandidate {
                guest_start,
                source_end,
                generation: CodeGeneration::INITIAL,
                requires_sensitive_metadata: false,
                template: artifact.template,
            },
            true,
        )
        .expect("normalize native-tap artifact")
    }

    fn decode_error(bytes: Vec<u8>, key: &TranslationUnitKey) -> UnitMissReason {
        match decode_unit_bundle_v1(Arc::new(bytes), key) {
            Ok(_) => panic!("corrupt bundle unexpectedly decoded"),
            Err(reason) => reason,
        }
    }

    #[test]
    fn unit_v1_round_trip_is_byte_deterministic() {
        let key = fixture_key();
        let first = native_tap_artifact(GuestVa(0x400000), 0xd400_0001);
        let second = native_tap_artifact(GuestVa(0x400100), 0xd400_0001);

        let forward = encode_unit_bundle_v1(&key, &[first.clone(), second.clone()])
            .expect("encode forward input");
        let repeated = encode_unit_bundle_v1(&key, &[first.clone(), second.clone()])
            .expect("encode repeated input");
        let reverse = encode_unit_bundle_v1(&key, &[second.clone(), first.clone()])
            .expect("encode reverse input");

        assert_eq!(key.translator_abi(), 9, "unit-v1 lives only under ABI 9");
        assert_eq!(
            u32::from_le_bytes(forward[24..28].try_into().expect("translator ABI")),
            9,
            "the outer header binds the fresh translator ABI"
        );
        assert_eq!(forward, repeated, "the same set has stable bytes");
        assert_eq!(forward, reverse, "input order cannot affect bundle bytes");

        let decoded =
            decode_unit_bundle_v1(Arc::new(forward), &key).expect("decode production bundle");
        assert_eq!(
            decoded.artifacts().expect("decode normalized artifacts"),
            vec![first, second]
        );
    }

    #[test]
    fn artifact_template_round_trips_through_stored_block_artifact() {
        let artifact = native_tap_artifact(GuestVa(0x400000), 0xd400_0001);
        let template = artifact
            .decode_template()
            .expect("decode canonical hot and cold metadata");

        assert!(template.words().is_empty(), "code bytes live in the bundle");
        assert!(
            template.source_words().is_empty(),
            "source identity lives in the key"
        );
        assert!(
            template.trusted_entry().is_some(),
            "replay keeps the native tap's trusted entry"
        );
        assert!(
            template.replay_metadata_fits_code_len(artifact.code.len() as u32),
            "decoded replay metadata remains valid for the exact code extent"
        );
    }

    #[test]
    fn unit_v1_rejects_bad_magic_schema_abi_and_key() {
        let key = fixture_key();
        let artifact = native_tap_artifact(GuestVa(0x400000), 0xd400_0001);
        let valid = encode_unit_bundle_v1(&key, &[artifact]).expect("encode valid bundle");

        let mut bad_magic = valid.clone();
        bad_magic[0] ^= 0xff;
        assert_eq!(decode_error(bad_magic, &key), UnitMissReason::Schema);

        let mut bad_schema = valid.clone();
        bad_schema[8..12].copy_from_slice(&2_u32.to_le_bytes());
        assert_eq!(decode_error(bad_schema, &key), UnitMissReason::Schema);

        let mut bad_abi = valid.clone();
        bad_abi[24..28].copy_from_slice(&(key.translator_abi() + 1).to_le_bytes());
        assert_eq!(decode_error(bad_abi, &key), UnitMissReason::TranslatorAbi);

        assert_eq!(
            decode_error(valid, &fixture_key_with_digest(0x44)),
            UnitMissReason::ImageIdentity
        );
    }

    #[test]
    fn unit_v1_rejects_bad_extent_offset_alignment_overlap_and_trailing_bytes() {
        let key = fixture_key();
        let artifact = native_tap_artifact(GuestVa(0x400000), 0xd400_0001);
        let valid = encode_unit_bundle_v1(&key, &[artifact]).expect("encode valid bundle");

        let mut short_extent = valid.clone();
        short_extent[16..24].copy_from_slice(&((valid.len() - 1) as u64).to_le_bytes());
        assert_eq!(decode_error(short_extent, &key), UnitMissReason::Schema);

        let mut unaligned_code = valid.clone();
        let code_offset = u64::from_le_bytes(valid[48..56].try_into().expect("code offset"));
        unaligned_code[48..56].copy_from_slice(&(code_offset - 1).to_le_bytes());
        assert_eq!(
            decode_error(unaligned_code, &key),
            UnitMissReason::ManifestRange
        );

        let mut overlap = valid.clone();
        overlap[48..56].copy_from_slice(&(UNIT_BUNDLE_HEADER_BYTES_V1 as u64).to_le_bytes());
        assert_eq!(decode_error(overlap, &key), UnitMissReason::ManifestRange);

        let mut trailing = valid;
        trailing.extend_from_slice(&[0]);
        assert_eq!(decode_error(trailing, &key), UnitMissReason::Schema);
    }

    #[test]
    fn unit_v1_rejects_bad_digest_and_truncation() {
        let key = fixture_key();
        let artifact = native_tap_artifact(GuestVa(0x400000), 0xd400_0001);
        let valid = encode_unit_bundle_v1(&key, &[artifact]).expect("encode valid bundle");

        let mut bad_digest = valid.clone();
        let last = bad_digest.len() - 1;
        bad_digest[last] ^= 0xff;
        assert_eq!(decode_error(bad_digest, &key), UnitMissReason::CodeDigest);

        let mut truncated = valid;
        truncated.truncate(UNIT_BUNDLE_HEADER_BYTES_V1 - 1);
        assert_eq!(decode_error(truncated, &key), UnitMissReason::Schema);
    }

    fn metadata_index_start(bytes: &[u8]) -> usize {
        let metadata_offset = usize::try_from(u64::from_le_bytes(
            bytes[32..40].try_into().expect("metadata offset"),
        ))
        .expect("metadata offset fits usize");
        assert_eq!(
            &bytes[metadata_offset..metadata_offset + 8],
            &UNIT_METADATA_MAGIC_V6,
            "metadata starts with its independent V6 magic"
        );
        assert_eq!(
            u32::from_le_bytes(
                bytes[metadata_offset + 8..metadata_offset + 12]
                    .try_into()
                    .expect("metadata schema"),
            ),
            6,
            "the bundle carries only metadata schema V6"
        );
        let header_len = usize::try_from(u32::from_le_bytes(
            bytes[metadata_offset + 12..metadata_offset + 16]
                .try_into()
                .expect("metadata header length"),
        ))
        .expect("header length fits usize");
        metadata_offset + 16 + header_len
    }

    #[test]
    fn unit_v1_rejects_bad_order_duplicate_start_generation_and_source_extent() {
        const ROW_BYTES: usize = 48;
        let key = fixture_key();
        let first = native_tap_artifact(GuestVa(0x400000), 0xd400_0001);
        let second = native_tap_artifact(GuestVa(0x400100), 0xd400_0001);
        let valid = encode_unit_bundle_v1(&key, &[first, second]).expect("encode valid bundle");
        let index = metadata_index_start(&valid);

        let mut duplicate = valid.clone();
        let first_start = duplicate[index..index + 8].to_vec();
        duplicate[index + ROW_BYTES..index + ROW_BYTES + 8].copy_from_slice(&first_start);
        assert_eq!(decode_error(duplicate, &key), UnitMissReason::ManifestRange);

        let mut out_of_order = valid.clone();
        out_of_order[index + ROW_BYTES..index + ROW_BYTES + 8]
            .copy_from_slice(&0x3f_ff00_u64.to_le_bytes());
        assert_eq!(
            decode_error(out_of_order, &key),
            UnitMissReason::ManifestRange
        );

        let mut regenerated = valid.clone();
        regenerated[index + 16..index + 24].copy_from_slice(&1_u64.to_le_bytes());
        assert_eq!(
            decode_error(regenerated, &key),
            UnitMissReason::ManifestRange
        );

        let mut empty_source = valid;
        empty_source[index + 8..index + 16].copy_from_slice(&0x400000_u64.to_le_bytes());
        assert_eq!(
            decode_error(empty_source, &key),
            UnitMissReason::ManifestRange
        );
    }

    #[test]
    fn normalized_union_adds_disjoint_blocks_in_guest_order() {
        let lower = native_tap_artifact(GuestVa(0x400000), 0xd400_0001);
        let upper = native_tap_artifact(GuestVa(0x400100), 0xd400_0001);

        let union =
            merge_normalized_artifacts(std::slice::from_ref(&upper), std::slice::from_ref(&lower))
                .expect("merge disjoint artifacts");

        assert_eq!(union.blocks, vec![lower, upper]);
        assert_eq!(union.blocks_added, 1);
        assert_eq!(union.duplicates, 0);
    }

    #[test]
    fn normalized_union_coalesces_only_byte_exact_duplicates() {
        let artifact = native_tap_artifact(GuestVa(0x400000), 0xd400_0001);

        let union = merge_normalized_artifacts(
            std::slice::from_ref(&artifact),
            std::slice::from_ref(&artifact),
        )
        .expect("coalesce exact duplicate");

        assert_eq!(union.blocks, vec![artifact]);
        assert_eq!(union.blocks_added, 0);
        assert_eq!(union.duplicates, 1);
    }

    #[test]
    fn normalized_union_preserves_old_on_same_start_conflict() {
        let original = native_tap_artifact(GuestVa(0x400000), 0xd400_0001);
        let mut variants = Vec::new();

        let mut source_extent = original.clone();
        source_extent.source_end = GuestVa(source_extent.source_end.raw() + 4);
        variants.push(source_extent);

        let mut code = original.clone();
        code.code[0] ^= 0xff;
        variants.push(code);

        let mut hot = original.clone();
        hot.hot[0] ^= 0xff;
        variants.push(hot);

        let mut cold = original.clone();
        cold.cold[0] ^= 0xff;
        variants.push(cold);

        for conflicting in variants {
            assert_eq!(
                merge_normalized_artifacts(std::slice::from_ref(&original), &[conflicting]),
                Err(MergeRefusal::Conflict {
                    guest_start: original.guest_start,
                })
            );
        }
    }

    #[test]
    fn unit_v1_capacity_boundaries_are_exact() {
        assert_eq!(
            validate_bundle_capacity(MAX_TRANSLATION_UNIT_CODE_BYTES, UNIT_METADATA_LIMIT),
            Ok(())
        );
        assert_eq!(
            validate_bundle_capacity(MAX_TRANSLATION_UNIT_CODE_BYTES + 1, UNIT_METADATA_LIMIT),
            Err(MergeRefusal::Capacity)
        );
        assert_eq!(
            validate_bundle_capacity(MAX_TRANSLATION_UNIT_CODE_BYTES, UNIT_METADATA_LIMIT + 1),
            Err(MergeRefusal::Capacity)
        );
        assert_eq!(
            validate_bundle_capacity(usize::MAX, usize::MAX),
            Err(MergeRefusal::Capacity)
        );
    }
}
