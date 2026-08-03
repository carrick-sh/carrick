//! Append-only pending translation storage and its crash-readable diagnostic ABI.
//!
//! The `#[repr(C)]` objects in this module are evidence surfaces for LLDB and
//! core-file readers. They are not the persistent store format or an import
//! surface. The normal publisher drains the exact `StoredBlockArtifact`
//! allocations referenced by the ABI descriptors, so enabling diagnostics does
//! not create a second pending copy.

use crate::shared_cache::{
    MAX_TRANSLATION_UNIT_CODE_BYTES, PendingTranslationUnit, RecordingClaim, StoredBlockArtifact,
    TranslationUnitKey,
};
use crate::types::CodeGeneration;
use carrick_guest_mem::GuestVa;
use std::collections::HashMap;
use std::fmt;
use std::ptr;
use std::sync::atomic::{AtomicI32, AtomicPtr, AtomicU32, AtomicU64, Ordering};

pub const XLAT_PENDING_CORE_MAGIC_V1: [u8; 8] = *b"CXLATP1\0";
pub const XLAT_PENDING_CORE_SCHEMA_V1: u32 = 1;
pub const XLAT_PENDING_UNIT_MAGIC_V1: [u8; 8] = *b"CXLATU1\0";
pub const XLAT_PENDING_UNIT_SCHEMA_V1: u32 = 1;
pub const XLAT_PENDING_CHUNK_MAGIC_V1: [u8; 8] = *b"CXLATC1\0";
pub const XLAT_PENDING_CHUNK_SCHEMA_V1: u32 = 1;
pub const PENDING_RECORDS_PER_CHUNK: usize = 16;
pub const MAX_PENDING_METADATA_BYTES: usize = 256 * 1024 * 1024;

const PENDING_UNIT_METADATA_BASE_BYTES: usize = 32;
const PENDING_RECORD_METADATA_BYTES: usize = 48;
const PENDING_RECORD_FLAG_SENSITIVE: u32 = 1;
const OWNER_NONCE_ATTEMPTS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordingOwner {
    pub pid: i32,
    pub incarnation: [u8; 16],
}

impl RecordingOwner {
    fn incarnation_hi(self) -> u64 {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&self.incarnation[..8]);
        u64::from_le_bytes(bytes)
    }

    fn incarnation_lo(self) -> u64 {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&self.incarnation[8..]);
        u64::from_le_bytes(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum SegmentClaimState {
    Unseen = 0,
    Attached = 1,
    Uncovered = 2,
    ClaimWon = 3,
    ClaimLost = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingAppendOutcome {
    Appended,
    Capacity,
    Ineligible,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingAugmentationError {
    Entropy(String),
    InvalidSegment,
    OwnerMismatch,
    KeyEncoding(String),
}

impl fmt::Display for PendingAugmentationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entropy(error) => write!(formatter, "generate process incarnation: {error}"),
            Self::InvalidSegment => formatter.write_str("invalid pending translation segment"),
            Self::OwnerMismatch => formatter.write_str("pending translation owner mismatch"),
            Self::KeyEncoding(error) => write!(formatter, "encode translation unit key: {error}"),
        }
    }
}

impl std::error::Error for PendingAugmentationError {}

/// Root of the export-only stopped-live/core ABI.
#[repr(C)]
pub struct XlatPendingCoreRootV1 {
    pub magic: [u8; 8],
    pub schema: u32,
    pub root_len: u32,
    pub pid: AtomicI32,
    pub incarnation_hi: AtomicU64,
    pub incarnation_lo: AtomicU64,
    pub first_unit: AtomicPtr<XlatPendingUnitV1>,
    pub committed_units: AtomicU64,
}

impl XlatPendingCoreRootV1 {
    pub const fn dormant() -> Self {
        Self {
            magic: XLAT_PENDING_CORE_MAGIC_V1,
            schema: XLAT_PENDING_CORE_SCHEMA_V1,
            root_len: std::mem::size_of::<Self>() as u32,
            pid: AtomicI32::new(0),
            incarnation_hi: AtomicU64::new(0),
            incarnation_lo: AtomicU64::new(0),
            first_unit: AtomicPtr::new(ptr::null_mut()),
            committed_units: AtomicU64::new(0),
        }
    }
}

/// One claimed translation unit in the diagnostic ABI.
#[repr(C)]
pub struct XlatPendingUnitV1 {
    pub magic: [u8; 8],
    pub schema: u32,
    pub unit_len: u32,
    pub key_ptr: *const u8,
    pub key_len: u64,
    pub segment_start: u64,
    pub segment_end: u64,
    pub claim_state: AtomicU32,
    pub owner_pid: AtomicI32,
    pub owner_incarnation_hi: AtomicU64,
    pub owner_incarnation_lo: AtomicU64,
    pub first_chunk: AtomicPtr<XlatPendingChunkV1>,
    pub committed_chunks: AtomicU64,
    pub next_unit: AtomicPtr<XlatPendingUnitV1>,
}

/// One immutable artifact descriptor in a committed chunk prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct XlatPendingRecordV1 {
    pub guest_start: u64,
    pub source_end: u64,
    pub generation: u64,
    pub flags: u32,
    pub reserved: u32,
    pub code_ptr: *const u8,
    pub code_len: u64,
    pub hot_ptr: *const u8,
    pub hot_len: u64,
    pub cold_ptr: *const u8,
    pub cold_len: u64,
}

impl XlatPendingRecordV1 {
    const EMPTY: Self = Self {
        guest_start: 0,
        source_end: 0,
        generation: 0,
        flags: 0,
        reserved: 0,
        code_ptr: ptr::null(),
        code_len: 0,
        hot_ptr: ptr::null(),
        hot_len: 0,
        cold_ptr: ptr::null(),
        cold_len: 0,
    };

    fn from_artifact(artifact: &StoredBlockArtifact) -> Self {
        Self {
            guest_start: artifact.guest_start.raw(),
            source_end: artifact.source_end.raw(),
            generation: artifact.generation.get(),
            flags: if artifact.requires_sensitive_metadata {
                PENDING_RECORD_FLAG_SENSITIVE
            } else {
                0
            },
            reserved: 0,
            code_ptr: artifact.code.as_ptr(),
            code_len: artifact.code.len() as u64,
            hot_ptr: artifact.hot.as_ptr(),
            hot_len: artifact.hot.len() as u64,
            cold_ptr: artifact.cold.as_ptr(),
            cold_len: artifact.cold.len() as u64,
        }
    }
}

/// A fixed-capacity append-only chunk. `committed_records` release-publishes
/// the initialized prefix of `records`.
#[repr(C)]
pub struct XlatPendingChunkV1 {
    pub magic: [u8; 8],
    pub schema: u32,
    pub chunk_len: u32,
    pub next_chunk: AtomicPtr<XlatPendingChunkV1>,
    pub committed_records: AtomicU32,
    pub capacity: u32,
    pub records: [XlatPendingRecordV1; PENDING_RECORDS_PER_CHUNK],
}

impl XlatPendingChunkV1 {
    fn empty() -> Self {
        Self {
            magic: XLAT_PENDING_CHUNK_MAGIC_V1,
            schema: XLAT_PENDING_CHUNK_SCHEMA_V1,
            chunk_len: std::mem::size_of::<Self>() as u32,
            next_chunk: AtomicPtr::new(ptr::null_mut()),
            committed_records: AtomicU32::new(0),
            capacity: PENDING_RECORDS_PER_CHUNK as u32,
            records: [XlatPendingRecordV1::EMPTY; PENDING_RECORDS_PER_CHUNK],
        }
    }
}

// The raw pointers above are immutable diagnostic references into allocations
// owned by the same `PendingAugmentation`. Appends are serialized by the
// translator's process-state write lock; only the atomic prefix fields are
// observed concurrently by an external debugger.
unsafe impl Send for XlatPendingUnitV1 {}
unsafe impl Sync for XlatPendingUnitV1 {}
unsafe impl Send for XlatPendingChunkV1 {}
unsafe impl Sync for XlatPendingChunkV1 {}

#[used]
#[unsafe(no_mangle)]
#[allow(non_upper_case_globals)]
pub static carrick_xlat_pending_core_v1: XlatPendingCoreRootV1 = XlatPendingCoreRootV1::dormant();

#[repr(C)]
struct OwnedChunk {
    abi: XlatPendingChunkV1,
    artifacts: Vec<StoredBlockArtifact>,
}

impl OwnedChunk {
    fn empty() -> Box<Self> {
        Box::new(Self {
            abi: XlatPendingChunkV1::empty(),
            artifacts: Vec::with_capacity(PENDING_RECORDS_PER_CHUNK),
        })
    }

    fn committed_len(&self) -> usize {
        self.abi.committed_records.load(Ordering::Acquire) as usize
    }

    fn append(&mut self, artifact: StoredBlockArtifact, commit: bool) {
        let index = self.committed_len();
        debug_assert_eq!(self.artifacts.len(), index);
        debug_assert!(index < PENDING_RECORDS_PER_CHUNK);
        self.artifacts.push(artifact);
        self.abi.records[index] = XlatPendingRecordV1::from_artifact(&self.artifacts[index]);
        if commit {
            self.abi
                .committed_records
                .store((index + 1) as u32, Ordering::Release);
        }
    }
}

#[repr(C)]
// Each box is a deliberate stable-address arena node referenced by the core
// ABI; replacing it with an ordinary Vec element would invalidate pointers on
// growth.
#[allow(clippy::vec_box)]
struct OwnedUnit {
    abi: XlatPendingUnitV1,
    key: TranslationUnitKey,
    claim: RecordingClaim,
    key_bytes: Box<[u8]>,
    chunks: Vec<Box<OwnedChunk>>,
    prepared_chunk: Option<Box<OwnedChunk>>,
    code_bytes: usize,
    metadata_bytes: usize,
    capacity_refused: bool,
}

impl OwnedUnit {
    fn new(
        key: TranslationUnitKey,
        key_bytes: Box<[u8]>,
        segment_end: GuestVa,
        claim: RecordingClaim,
    ) -> Box<Self> {
        let mut first_chunk = OwnedChunk::empty();
        let first_chunk_ptr = &mut first_chunk.abi as *mut XlatPendingChunkV1;
        Box::new(Self {
            abi: XlatPendingUnitV1 {
                magic: XLAT_PENDING_UNIT_MAGIC_V1,
                schema: XLAT_PENDING_UNIT_SCHEMA_V1,
                unit_len: std::mem::size_of::<XlatPendingUnitV1>() as u32,
                key_ptr: key_bytes.as_ptr(),
                key_len: key_bytes.len() as u64,
                segment_start: key.guest_va_start().raw(),
                segment_end: segment_end.raw(),
                claim_state: AtomicU32::new(SegmentClaimState::ClaimWon as u32),
                owner_pid: AtomicI32::new(claim.owner.pid),
                owner_incarnation_hi: AtomicU64::new(claim.owner.incarnation_hi()),
                owner_incarnation_lo: AtomicU64::new(claim.owner.incarnation_lo()),
                first_chunk: AtomicPtr::new(first_chunk_ptr),
                committed_chunks: AtomicU64::new(1),
                next_unit: AtomicPtr::new(ptr::null_mut()),
            },
            key,
            claim,
            metadata_bytes: PENDING_UNIT_METADATA_BASE_BYTES.saturating_add(key_bytes.len()),
            key_bytes,
            chunks: vec![first_chunk],
            prepared_chunk: None,
            code_bytes: 0,
            capacity_refused: false,
        })
    }

    fn accepts(&self, artifact: &StoredBlockArtifact) -> bool {
        artifact.generation == CodeGeneration::INITIAL
            && artifact.guest_start.raw() >= self.abi.segment_start
            && artifact.source_end.raw() > artifact.guest_start.raw()
            && artifact.source_end.raw() <= self.abi.segment_end
            && !artifact.code.is_empty()
            && artifact.code.len().is_multiple_of(4)
            && !self.chunks.iter().any(|chunk| {
                chunk
                    .artifacts
                    .iter()
                    .take(chunk.committed_len())
                    .any(|prior| prior.guest_start == artifact.guest_start)
            })
    }

    fn reserve(&mut self, artifact: &StoredBlockArtifact) -> bool {
        let Some(code_bytes) = self.code_bytes.checked_add(artifact.code.len()) else {
            self.capacity_refused = true;
            return false;
        };
        let Some(record_metadata) = artifact
            .hot
            .len()
            .checked_add(artifact.cold.len())
            .and_then(|bytes| bytes.checked_add(PENDING_RECORD_METADATA_BYTES))
        else {
            self.capacity_refused = true;
            return false;
        };
        let Some(metadata_bytes) = self.metadata_bytes.checked_add(record_metadata) else {
            self.capacity_refused = true;
            return false;
        };
        if code_bytes > MAX_TRANSLATION_UNIT_CODE_BYTES
            || metadata_bytes > MAX_PENDING_METADATA_BYTES
        {
            self.capacity_refused = true;
            return false;
        }
        self.code_bytes = code_bytes;
        self.metadata_bytes = metadata_bytes;
        true
    }

    fn append(&mut self, artifact: StoredBlockArtifact) {
        let Some(tail) = self.chunks.last_mut() else {
            debug_assert!(false, "unit always owns a chunk");
            return;
        };
        if tail.committed_len() < PENDING_RECORDS_PER_CHUNK {
            tail.append(artifact, true);
            return;
        }

        let mut next = OwnedChunk::empty();
        next.append(artifact, true);
        let next_ptr = &mut next.abi as *mut XlatPendingChunkV1;
        tail.abi.next_chunk.store(next_ptr, Ordering::Release);
        self.chunks.push(next);
        self.abi.committed_chunks.fetch_add(1, Ordering::Release);
    }
}

struct SegmentEntry {
    segment_end: GuestVa,
    state: SegmentClaimState,
    claim: Option<RecordingClaim>,
    unit_index: Option<usize>,
}

#[derive(Debug)]
pub struct ClaimedPendingTranslationUnit {
    pub pending: PendingTranslationUnit,
    pub claim: RecordingClaim,
    pub capacity_refused: bool,
}

/// Single-writer owner of the pending translation arena.
// Unit boxes are stable-address arena nodes published through the ABI root.
#[allow(clippy::vec_box)]
pub struct PendingAugmentation {
    owner: Option<RecordingOwner>,
    segments: HashMap<TranslationUnitKey, SegmentEntry>,
    units: Vec<Box<OwnedUnit>>,
    publish_attempted: bool,
}

impl Default for PendingAugmentation {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingAugmentation {
    pub fn new() -> Self {
        Self {
            owner: None,
            segments: HashMap::new(),
            units: Vec::new(),
            publish_attempted: false,
        }
    }

    pub fn recording_owner(&mut self) -> Result<RecordingOwner, PendingAugmentationError> {
        if let Some(owner) = self.owner {
            return Ok(owner);
        }
        for _ in 0..OWNER_NONCE_ATTEMPTS {
            let mut incarnation = [0_u8; 16];
            getrandom::fill(&mut incarnation)
                .map_err(|error| PendingAugmentationError::Entropy(error.to_string()))?;
            if incarnation != [0; 16] {
                let owner = RecordingOwner {
                    pid: unsafe { libc::getpid() },
                    incarnation,
                };
                self.owner = Some(owner);
                Self::publish_owner(owner);
                return Ok(owner);
            }
        }
        Err(PendingAugmentationError::Entropy(
            "random source returned an all-zero nonce repeatedly".to_string(),
        ))
    }

    pub fn current_owner(&self) -> Option<RecordingOwner> {
        self.owner
    }

    pub fn track_segment(
        &mut self,
        key: TranslationUnitKey,
        segment_end: GuestVa,
        state: SegmentClaimState,
        claim: Option<RecordingClaim>,
    ) -> Result<(), PendingAugmentationError> {
        if segment_end.raw() <= key.guest_va_start().raw() {
            return Err(PendingAugmentationError::InvalidSegment);
        }
        if state == SegmentClaimState::ClaimWon && claim.map(|claim| claim.owner) != self.owner {
            return Err(PendingAugmentationError::OwnerMismatch);
        }
        let existing_needs_unit = if let Some(entry) = self.segments.get_mut(&key) {
            if entry.segment_end != segment_end {
                return Err(PendingAugmentationError::InvalidSegment);
            }
            entry.state = state;
            entry.claim = claim;
            if let Some(index) = entry.unit_index {
                self.units[index]
                    .abi
                    .claim_state
                    .store(state as u32, Ordering::Release);
                false
            } else {
                state == SegmentClaimState::ClaimWon
            }
        } else {
            false
        };
        if self.segments.contains_key(&key) {
            let needs_unit = existing_needs_unit;
            if needs_unit {
                let exact_claim = claim.ok_or(PendingAugmentationError::OwnerMismatch)?;
                let index = self.create_unit(key.clone(), segment_end, exact_claim)?;
                if let Some(entry) = self.segments.get_mut(&key) {
                    entry.unit_index = Some(index);
                }
            }
            return Ok(());
        }

        let unit_index = if state == SegmentClaimState::ClaimWon {
            let exact_claim = claim.ok_or(PendingAugmentationError::OwnerMismatch)?;
            Some(self.create_unit(key.clone(), segment_end, exact_claim)?)
        } else {
            None
        };
        self.segments.insert(
            key,
            SegmentEntry {
                segment_end,
                state,
                claim,
                unit_index,
            },
        );
        Ok(())
    }

    pub fn segment_state(&self, key: &TranslationUnitKey) -> Option<SegmentClaimState> {
        self.segments.get(key).map(|entry| entry.state)
    }

    pub fn append(
        &mut self,
        key: &TranslationUnitKey,
        artifact: StoredBlockArtifact,
    ) -> PendingAppendOutcome {
        let Some(entry) = self.segments.get(key) else {
            return PendingAppendOutcome::Ineligible;
        };
        if entry.state != SegmentClaimState::ClaimWon
            || entry.claim.map(|claim| claim.owner) != self.owner
        {
            return PendingAppendOutcome::Ineligible;
        }
        let Some(index) = entry.unit_index else {
            return PendingAppendOutcome::Ineligible;
        };
        let unit = &mut self.units[index];
        if unit.capacity_refused {
            return PendingAppendOutcome::Capacity;
        }
        if !unit.accepts(&artifact) {
            return PendingAppendOutcome::Ineligible;
        }
        if !unit.reserve(&artifact) {
            return PendingAppendOutcome::Capacity;
        }
        unit.append(artifact);
        PendingAppendOutcome::Appended
    }

    /// Detach the ABI root before moving the canonical buffers into batches.
    pub fn drain_committed_units(&mut self) -> Option<Vec<ClaimedPendingTranslationUnit>> {
        if self.publish_attempted {
            return None;
        }
        self.publish_attempted = true;
        self.detach_root_if_owned();
        let mut pending = Vec::with_capacity(self.units.len());
        for unit in std::mem::take(&mut self.units) {
            let OwnedUnit {
                key,
                claim,
                mut chunks,
                capacity_refused,
                ..
            } = *unit;
            let mut blocks = Vec::new();
            for chunk in chunks.drain(..) {
                let committed = chunk.committed_len();
                let OwnedChunk { mut artifacts, .. } = *chunk;
                blocks.extend(artifacts.drain(..committed));
            }
            blocks.sort_by_key(|block| block.guest_start);
            pending.push(ClaimedPendingTranslationUnit {
                pending: PendingTranslationUnit { key, blocks },
                claim,
                capacity_refused,
            });
        }
        self.segments.clear();
        self.owner = None;
        Some(pending)
    }

    pub fn reset_after_fork_child(&mut self) {
        self.detach_root_if_owned();
        self.segments.clear();
        self.units.clear();
        self.owner = None;
        self.publish_attempted = false;
    }

    fn create_unit(
        &mut self,
        key: TranslationUnitKey,
        segment_end: GuestVa,
        claim: RecordingClaim,
    ) -> Result<usize, PendingAugmentationError> {
        let key_bytes = bincode::serde::encode_to_vec(
            &key,
            bincode::config::standard().with_limit::<MAX_PENDING_METADATA_BYTES>(),
        )
        .map_err(|error| PendingAugmentationError::KeyEncoding(error.to_string()))?
        .into_boxed_slice();
        let mut unit = OwnedUnit::new(key, key_bytes, segment_end, claim);
        let unit_ptr = &mut unit.abi as *mut XlatPendingUnitV1;
        if let Some(previous) = self.units.last_mut() {
            previous.abi.next_unit.store(unit_ptr, Ordering::Release);
        } else {
            carrick_xlat_pending_core_v1
                .first_unit
                .store(unit_ptr, Ordering::Release);
        }
        let index = self.units.len();
        self.units.push(unit);
        carrick_xlat_pending_core_v1
            .committed_units
            .fetch_add(1, Ordering::Release);
        Ok(index)
    }

    fn publish_owner(owner: RecordingOwner) {
        carrick_xlat_pending_core_v1
            .incarnation_hi
            .store(owner.incarnation_hi(), Ordering::Relaxed);
        carrick_xlat_pending_core_v1
            .incarnation_lo
            .store(owner.incarnation_lo(), Ordering::Relaxed);
        // PID is the identity commit marker: an acquire reader that observes
        // it also observes both nonce halves.
        carrick_xlat_pending_core_v1
            .pid
            .store(owner.pid, Ordering::Release);
    }

    fn root_matches_owner(&self) -> bool {
        let Some(owner) = self.owner else {
            return false;
        };
        carrick_xlat_pending_core_v1.pid.load(Ordering::Acquire) == owner.pid
            && carrick_xlat_pending_core_v1
                .incarnation_hi
                .load(Ordering::Acquire)
                == owner.incarnation_hi()
            && carrick_xlat_pending_core_v1
                .incarnation_lo
                .load(Ordering::Acquire)
                == owner.incarnation_lo()
    }

    fn detach_root_if_owned(&self) {
        if !self.root_matches_owner() {
            return;
        }
        carrick_xlat_pending_core_v1
            .committed_units
            .store(0, Ordering::Release);
        carrick_xlat_pending_core_v1
            .first_unit
            .store(ptr::null_mut(), Ordering::Release);
        carrick_xlat_pending_core_v1.pid.store(0, Ordering::Release);
        carrick_xlat_pending_core_v1
            .incarnation_hi
            .store(0, Ordering::Release);
        carrick_xlat_pending_core_v1
            .incarnation_lo
            .store(0, Ordering::Release);
    }
}

impl Drop for PendingAugmentation {
    fn drop(&mut self) {
        self.detach_root_if_owned();
    }
}

#[cfg(test)]
impl PendingAugmentation {
    fn append_uncommitted_for_test(
        &mut self,
        key: &TranslationUnitKey,
        artifact: StoredBlockArtifact,
    ) {
        let index = self.segments[key]
            .unit_index
            .expect("test segment owns a unit");
        let tail = self.units[index]
            .chunks
            .last_mut()
            .expect("unit owns a chunk");
        assert!(tail.committed_len() < PENDING_RECORDS_PER_CHUNK);
        tail.append(artifact, false);
    }

    fn prepare_unlinked_chunk_for_test(
        &mut self,
        key: &TranslationUnitKey,
        artifact: StoredBlockArtifact,
    ) {
        let index = self.segments[key]
            .unit_index
            .expect("test segment owns a unit");
        let unit = &mut self.units[index];
        assert_eq!(
            unit.chunks
                .last()
                .expect("unit owns a chunk")
                .committed_len(),
            PENDING_RECORDS_PER_CHUNK
        );
        let mut chunk = OwnedChunk::empty();
        chunk.append(artifact, true);
        unit.prepared_chunk = Some(chunk);
    }

    fn commit_prepared_chunk_for_test(&mut self, key: &TranslationUnitKey) {
        let index = self.segments[key]
            .unit_index
            .expect("test segment owns a unit");
        let unit = &mut self.units[index];
        let mut next = unit.prepared_chunk.take().expect("prepared test chunk");
        let next_ptr = &mut next.abi as *mut XlatPendingChunkV1;
        unit.chunks
            .last()
            .expect("unit owns a chunk")
            .abi
            .next_chunk
            .store(next_ptr, Ordering::Release);
        unit.chunks.push(next);
        unit.abi.committed_chunks.fetch_add(1, Ordering::Release);
    }

    fn set_usage_for_test(&mut self, key: &TranslationUnitKey, code: usize, metadata: usize) {
        let index = self.segments[key]
            .unit_index
            .expect("test segment owns a unit");
        self.units[index].code_bytes = code;
        self.units[index].metadata_bytes = metadata;
    }

    fn committed_guest_starts_for_test(&self) -> Vec<u64> {
        let mut starts = Vec::new();
        let unit_count = carrick_xlat_pending_core_v1
            .committed_units
            .load(Ordering::Acquire);
        let mut unit_ptr = carrick_xlat_pending_core_v1
            .first_unit
            .load(Ordering::Acquire);
        for _ in 0..unit_count {
            assert!(!unit_ptr.is_null());
            // SAFETY: tests hold `core_test_guard`; the owning arena remains
            // alive and committed unit nodes are never moved or freed.
            let unit = unsafe { &*unit_ptr };
            let chunk_count = unit.committed_chunks.load(Ordering::Acquire);
            let mut chunk_ptr = unit.first_chunk.load(Ordering::Acquire);
            for _ in 0..chunk_count {
                assert!(!chunk_ptr.is_null());
                // SAFETY: the chunk is owned by the live arena and the acquire
                // load above limits reads to the release-committed prefix.
                let chunk = unsafe { &*chunk_ptr };
                let committed = chunk.committed_records.load(Ordering::Acquire) as usize;
                starts.extend(
                    chunk.records[..committed]
                        .iter()
                        .map(|record| record.guest_start),
                );
                chunk_ptr = chunk.next_chunk.load(Ordering::Acquire);
            }
            unit_ptr = unit.next_unit.load(Ordering::Acquire);
        }
        starts
    }

    fn first_committed_descriptor_for_test(&self) -> XlatPendingRecordV1 {
        let unit_ptr = carrick_xlat_pending_core_v1
            .first_unit
            .load(Ordering::Acquire);
        assert!(!unit_ptr.is_null());
        // SAFETY: the test guard and live owner pin the unit and chunk.
        let unit = unsafe { &*unit_ptr };
        let chunk_ptr = unit.first_chunk.load(Ordering::Acquire);
        assert!(!chunk_ptr.is_null());
        // SAFETY: the acquire-published first chunk remains owned by `self`.
        let chunk = unsafe { &*chunk_ptr };
        assert!(chunk.committed_records.load(Ordering::Acquire) > 0);
        chunk.records[0]
    }
}

#[cfg(test)]
fn core_test_guard() -> std::sync::MutexGuard<'static, ()> {
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    TEST_LOCK.lock().expect("pending core test lock")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared_cache::{
        AddressModeIdentity, ExecutableIdentity, GuestCodeLen, ImageFileLen, ImageFileOffset,
        MAX_TRANSLATION_UNIT_CODE_BYTES, NativePageProfileIdentity, SourceFingerprint,
        StoredBlockArtifact, TranslationUnitKey,
    };
    use crate::types::CodeGeneration;
    use carrick_dsr::address::NativeHostBias;
    use carrick_guest_mem::GuestVa;
    use std::sync::atomic::Ordering;

    fn fixture_key() -> TranslationUnitKey {
        TranslationUnitKey::for_segment(
            ExecutableIdentity::Digest([0x44; 32]),
            ImageFileOffset::new(0),
            ImageFileLen::new(0x1000).expect("nonzero image extent"),
            GuestVa(0x400000),
            GuestCodeLen::new(0x1000).expect("nonzero guest extent"),
            SourceFingerprint::from_words(&[0xd400_0001]),
            NativePageProfileIdentity::Native16k,
            AddressModeIdentity::biased(
                NativeHostBias::new(0x8000_0000, 16 * 1024).expect("aligned bias"),
            ),
        )
    }

    fn artifact(guest_start: u64, byte: u8) -> StoredBlockArtifact {
        StoredBlockArtifact {
            guest_start: GuestVa(guest_start),
            source_end: GuestVa(guest_start + 4),
            generation: CodeGeneration::INITIAL,
            requires_sensitive_metadata: false,
            code: vec![byte; 4].into_boxed_slice(),
            hot: vec![byte.wrapping_add(1); 3].into_boxed_slice(),
            cold: vec![byte.wrapping_add(2); 2].into_boxed_slice(),
        }
    }

    fn claimed_pending() -> (PendingAugmentation, TranslationUnitKey, RecordingOwner) {
        let mut pending = PendingAugmentation::new();
        let owner = pending
            .recording_owner()
            .expect("generate process incarnation");
        let key = fixture_key();
        pending
            .track_segment(
                key.clone(),
                GuestVa(0x401000),
                SegmentClaimState::ClaimWon,
                Some(RecordingClaim {
                    owner,
                    stale_takeover: false,
                }),
            )
            .expect("track claimed segment");
        (pending, key, owner)
    }

    #[test]
    fn pending_prefix_exposes_only_release_committed_records() {
        let _serial = core_test_guard();
        let (mut pending, key, _) = claimed_pending();
        assert_eq!(
            pending.append(&key, artifact(0x400000, 0x10)),
            PendingAppendOutcome::Appended
        );
        pending.append_uncommitted_for_test(&key, artifact(0x400004, 0x20));

        assert_eq!(pending.committed_guest_starts_for_test(), vec![0x400000]);
    }

    #[test]
    fn pending_chunk_link_is_visible_only_after_initialization() {
        let _serial = core_test_guard();
        let (mut pending, key, _) = claimed_pending();
        for index in 0..PENDING_RECORDS_PER_CHUNK {
            assert_eq!(
                pending.append(&key, artifact(0x400000 + index as u64 * 4, index as u8)),
                PendingAppendOutcome::Appended
            );
        }
        pending.prepare_unlinked_chunk_for_test(
            &key,
            artifact(0x400000 + PENDING_RECORDS_PER_CHUNK as u64 * 4, 0xaa),
        );
        assert_eq!(
            pending.committed_guest_starts_for_test().len(),
            PENDING_RECORDS_PER_CHUNK
        );

        pending.commit_prepared_chunk_for_test(&key);
        assert_eq!(
            pending.committed_guest_starts_for_test().len(),
            PENDING_RECORDS_PER_CHUNK + 1
        );
    }

    #[test]
    fn pending_prefix_reuses_canonical_artifact_bytes() {
        let _serial = core_test_guard();
        let (mut pending, key, _) = claimed_pending();
        let block = artifact(0x400000, 0x33);
        let expected = (block.code.as_ptr(), block.hot.as_ptr(), block.cold.as_ptr());
        assert_eq!(pending.append(&key, block), PendingAppendOutcome::Appended);
        let descriptor = pending.first_committed_descriptor_for_test();
        assert_eq!(descriptor.code_ptr, expected.0);
        assert_eq!(descriptor.hot_ptr, expected.1);
        assert_eq!(descriptor.cold_ptr, expected.2);

        let units = pending
            .drain_committed_units()
            .expect("first drain is authoritative");
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].pending.blocks[0].code.as_ptr(), expected.0);
        assert_eq!(units[0].pending.blocks[0].hot.as_ptr(), expected.1);
        assert_eq!(units[0].pending.blocks[0].cold.as_ptr(), expected.2);
        assert!(pending.drain_committed_units().is_none());
    }

    #[test]
    fn pending_capacity_keeps_the_already_committed_prefix() {
        let _serial = core_test_guard();
        let (mut pending, key, _) = claimed_pending();
        assert_eq!(
            pending.append(&key, artifact(0x400000, 0x10)),
            PendingAppendOutcome::Appended
        );
        pending.set_usage_for_test(
            &key,
            MAX_TRANSLATION_UNIT_CODE_BYTES,
            MAX_PENDING_METADATA_BYTES,
        );
        assert_eq!(
            pending.append(&key, artifact(0x400004, 0x20)),
            PendingAppendOutcome::Capacity
        );
        assert_eq!(pending.committed_guest_starts_for_test(), vec![0x400000]);
    }

    #[test]
    fn fork_child_clears_claim_nonce_pending_prefix_and_publish_guard() {
        let _serial = core_test_guard();
        let (mut pending, key, _) = claimed_pending();
        assert_eq!(
            pending.append(&key, artifact(0x400000, 0x10)),
            PendingAppendOutcome::Appended
        );

        pending.reset_after_fork_child();

        assert_eq!(pending.current_owner(), None);
        assert_eq!(pending.segment_state(&key), None);
        assert_eq!(
            carrick_xlat_pending_core_v1
                .committed_units
                .load(Ordering::Acquire),
            0
        );
        assert!(
            carrick_xlat_pending_core_v1
                .first_unit
                .load(Ordering::Acquire)
                .is_null()
        );
    }

    #[test]
    fn owner_nonce_is_fresh_after_reset_and_never_all_zero() {
        let _serial = core_test_guard();
        let mut pending = PendingAugmentation::new();
        let first = pending.recording_owner().expect("first incarnation");
        assert_ne!(first.incarnation, [0; 16]);

        pending.reset_after_fork_child();
        let second = pending.recording_owner().expect("child incarnation");
        assert_ne!(second.incarnation, [0; 16]);
        assert_ne!(second, first);
    }

    #[test]
    fn core_root_layout_and_symbol_schema_are_pinned() {
        let _serial = core_test_guard();
        assert_eq!(XLAT_PENDING_CORE_MAGIC_V1, *b"CXLATP1\0");
        assert_eq!(XLAT_PENDING_CORE_SCHEMA_V1, 1);
        assert_eq!(std::mem::size_of::<XlatPendingCoreRootV1>(), 56);
        assert_eq!(
            carrick_xlat_pending_core_v1.magic,
            XLAT_PENDING_CORE_MAGIC_V1
        );
        assert_eq!(
            carrick_xlat_pending_core_v1.schema,
            XLAT_PENDING_CORE_SCHEMA_V1
        );
        assert_eq!(
            carrick_xlat_pending_core_v1.root_len as usize,
            std::mem::size_of::<XlatPendingCoreRootV1>()
        );
    }
}
