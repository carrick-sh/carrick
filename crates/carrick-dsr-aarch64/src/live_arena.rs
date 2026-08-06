//! Offset-only, wait-free protocol for a container-lifetime translation arena.
//!
//! This module owns only the portable wire and state-machine contract. Darwin
//! mappings and translator integration deliberately stay outside this layer.

use crate::artifact_spike::validate_shared_initial_metadata;
use crate::emit::{ExpectedLivePublication, PreparedSharedInitial};
use crate::shared_cache::{TRANSLATOR_ABI_CURRENT, TranslationUnitKey};
use carrick_dsr::cache::{PageGenerationDomain, PageGenerationObservation};
use carrick_dsr::ids::CodeGeneration;
use carrick_guest_mem::GuestVa;
use sha2::{Digest, Sha256};
use std::cell::UnsafeCell;
use std::fmt;
use std::ptr::NonNull;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Barrier;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

pub const LIVE_ARENA_SCHEMA_V2: u32 = 2;
pub const LIVE_BLOCK_EMPTY: u32 = 0;
pub const LIVE_BLOCK_BUILDING: u32 = 1;
pub const LIVE_BLOCK_READY: u32 = 2;
pub const LIVE_BLOCK_FAILED: u32 = 3;
pub const LIVE_GROUP_EMPTY: u32 = 0;
pub const LIVE_GROUP_BUILDING: u32 = 1;
pub const LIVE_GROUP_ACTIVE: u32 = 2;
pub const LIVE_GROUP_FAILED: u32 = 3;
pub const LIVE_CHUNK_EMPTY: u32 = 0;
pub const LIVE_CHUNK_ACTIVE: u32 = 1;
pub const LIVE_CHUNK_ABANDONED: u32 = 2;
pub const LIVE_ARENA_BLOCK_RECORDS: usize = 262_144;
pub const LIVE_ARENA_SOURCE_GROUPS: usize = 4_096;
pub const LIVE_ARENA_CHUNKS: usize = 1_024;
pub const LIVE_ARENA_CHUNK_BYTES: u64 = 65_536;
pub const LIVE_ARENA_CODE_CAPACITY: u64 = 67_108_864;
pub const LIVE_ARENA_HOT_CAPACITY: u64 = 1_048_576;
pub const LIVE_ARENA_COLD_CAPACITY: u64 = 33_554_432;
pub const LIVE_SOURCE_PAGE_BYTES: u64 = 16 * 1024;
pub const LIVE_GROUP_NO_CHUNK: u32 = u32::MAX;
pub const LIVE_ARENA_OBJECT_HEADER_BYTES: usize = 64;
pub const LIVE_ARENA_CACHE_LINE_BYTES: usize = 64;
pub const LIVE_ARENA_CONTROL_DIRECTORY_BYTES: usize = 256;
pub const LIVE_ARENA_CONTROL_READY: u32 = 1;
const LIVE_ARENA_PROBES: usize = 16;
const LIVE_BLOCK_MASK: usize = LIVE_ARENA_BLOCK_RECORDS - 1;
const LIVE_GROUP_MASK: usize = LIVE_ARENA_SOURCE_GROUPS - 1;
const LIVE_CURSOR_CAS_ATTEMPTS: usize = 8;
const LIVE_ARENA_INSTRUCTION_BYTES: u64 = 4;
const LIVE_ARENA_METADATA_ALIGN: u64 = 8;
const LIVE_EXPANSION_FREE: u64 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveArenaCapacities {
    pub code: u64,
    pub hot: u64,
    pub cold: u64,
}

impl LiveArenaCapacities {
    pub const fn new(code: u64, hot: u64, cold: u64) -> Self {
        Self { code, hot, cold }
    }

    pub const V2: Self = Self::new(
        LIVE_ARENA_CODE_CAPACITY,
        LIVE_ARENA_HOT_CAPACITY,
        LIVE_ARENA_COLD_CAPACITY,
    );
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveArenaLayoutError(String);

impl LiveArenaLayoutError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for LiveArenaLayoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for LiveArenaLayoutError {}

#[repr(C, align(64))]
pub struct LiveArenaControlDirectoryV2 {
    pub initialization_state: AtomicU32,
    pub schema: u32,
    pub translator_abi: u32,
    pub directory_len: u32,
    pub nonce: [u8; 16],
    pub code_payload_base: u64,
    pub code_capacity: u64,
    pub next_chunk_cursor_offset: u64,
    pub hot_cursor_offset: u64,
    pub cold_cursor_offset: u64,
    pub block_records_offset: u64,
    pub block_records_len: u64,
    pub block_record_count: u32,
    pub block_record_stride: u32,
    pub source_groups_offset: u64,
    pub source_groups_len: u64,
    pub source_group_count: u32,
    pub source_group_stride: u32,
    pub chunk_descriptors_offset: u64,
    pub chunk_descriptors_len: u64,
    pub chunk_count: u32,
    pub chunk_stride: u32,
    pub chunk_size: u64,
    pub hot_base: u64,
    pub hot_capacity: u64,
    pub cold_base: u64,
    pub cold_capacity: u64,
    pub control_len: u64,
    pub leaked_code_extents: AtomicU64,
    pub leaked_hot_extents: AtomicU64,
    pub leaked_cold_extents: AtomicU64,
    pub leaked_chunks: AtomicU64,
    pub private_fallbacks: AtomicU64,
    reserved: [u64; 3],
}

const _: () = assert!(std::mem::align_of::<LiveArenaControlDirectoryV2>() == 64);
const _: () = assert!(
    std::mem::size_of::<LiveArenaControlDirectoryV2>() == LIVE_ARENA_CONTROL_DIRECTORY_BYTES
);
const _: () = assert!(std::mem::offset_of!(LiveArenaControlDirectoryV2, initialization_state) == 0);
const _: () = assert!(std::mem::offset_of!(LiveArenaControlDirectoryV2, nonce) == 16);
const _: () = assert!(std::mem::offset_of!(LiveArenaControlDirectoryV2, code_payload_base) == 32);
const _: () =
    assert!(std::mem::offset_of!(LiveArenaControlDirectoryV2, block_records_offset) == 72);
const _: () =
    assert!(std::mem::offset_of!(LiveArenaControlDirectoryV2, source_groups_offset) == 96);
const _: () =
    assert!(std::mem::offset_of!(LiveArenaControlDirectoryV2, chunk_descriptors_offset) == 120);
const _: () = assert!(std::mem::offset_of!(LiveArenaControlDirectoryV2, chunk_size) == 144);
const _: () = assert!(std::mem::offset_of!(LiveArenaControlDirectoryV2, hot_base) == 152);
const _: () = assert!(std::mem::offset_of!(LiveArenaControlDirectoryV2, control_len) == 184);
const _: () =
    assert!(std::mem::offset_of!(LiveArenaControlDirectoryV2, leaked_code_extents) == 192);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveArenaControlLayout {
    capacities: LiveArenaCapacities,
    host_page: usize,
    code_payload_base: usize,
    code_len: usize,
    directory_offset: usize,
    next_chunk_cursor_offset: usize,
    hot_cursor_offset: usize,
    cold_cursor_offset: usize,
    block_records_offset: usize,
    block_records_len: usize,
    source_groups_offset: usize,
    source_groups_len: usize,
    chunk_descriptors_offset: usize,
    chunk_descriptors_len: usize,
    hot_base: usize,
    cold_base: usize,
    control_payload_end: usize,
    control_len: usize,
}

impl LiveArenaControlLayout {
    pub fn new(
        capacities: LiveArenaCapacities,
        host_page: usize,
    ) -> Result<Self, LiveArenaLayoutError> {
        if capacities != LiveArenaCapacities::V2 {
            return Err(LiveArenaLayoutError::new(
                "live arena capacities are not canonical V2 geometry",
            ));
        }
        if host_page != LIVE_SOURCE_PAGE_BYTES as usize {
            return Err(LiveArenaLayoutError::new(
                "live arena host page is not canonical V2 geometry",
            ));
        }
        Self::new_with_capacities(capacities, host_page)
    }

    #[cfg(test)]
    fn new_for_test(
        capacities: LiveArenaCapacities,
        host_page: usize,
    ) -> Result<Self, LiveArenaLayoutError> {
        Self::new_with_capacities(capacities, host_page)
    }

    fn new_with_capacities(
        capacities: LiveArenaCapacities,
        host_page: usize,
    ) -> Result<Self, LiveArenaLayoutError> {
        if host_page == 0 || !host_page.is_power_of_two() {
            return Err(LiveArenaLayoutError::new(
                "host page must be a nonzero power of two",
            ));
        }
        if capacities.code == 0 {
            return Err(LiveArenaLayoutError::new("code capacity must be nonzero"));
        }
        let code_capacity = usize::try_from(capacities.code)
            .map_err(|_| LiveArenaLayoutError::new("code capacity exceeds usize"))?;
        let hot_capacity = usize::try_from(capacities.hot)
            .map_err(|_| LiveArenaLayoutError::new("HOT capacity exceeds usize"))?;
        let cold_capacity = usize::try_from(capacities.cold)
            .map_err(|_| LiveArenaLayoutError::new("COLD capacity exceeds usize"))?;
        let code_payload_base = checked_align_up(LIVE_ARENA_OBJECT_HEADER_BYTES, host_page)?;
        let code_end = code_payload_base
            .checked_add(code_capacity)
            .ok_or_else(|| LiveArenaLayoutError::new("code object length overflow"))?;
        let code_len = checked_align_up(code_end, host_page)?;
        let directory_offset = LIVE_ARENA_OBJECT_HEADER_BYTES;
        let directory_end = directory_offset
            .checked_add(std::mem::size_of::<LiveArenaControlDirectoryV2>())
            .ok_or_else(|| LiveArenaLayoutError::new("directory end overflow"))?;
        let next_chunk_cursor_offset =
            checked_align_up(directory_end, LIVE_ARENA_CACHE_LINE_BYTES)?;
        let hot_cursor_offset = next_chunk_cursor_offset
            .checked_add(LIVE_ARENA_CACHE_LINE_BYTES)
            .ok_or_else(|| LiveArenaLayoutError::new("HOT cursor offset overflow"))?;
        let cold_cursor_offset = hot_cursor_offset
            .checked_add(LIVE_ARENA_CACHE_LINE_BYTES)
            .ok_or_else(|| LiveArenaLayoutError::new("COLD cursor offset overflow"))?;
        let block_records_offset = cold_cursor_offset
            .checked_add(LIVE_ARENA_CACHE_LINE_BYTES)
            .ok_or_else(|| LiveArenaLayoutError::new("block record offset overflow"))?;
        let block_records_len = LIVE_ARENA_BLOCK_RECORDS
            .checked_mul(std::mem::size_of::<LiveBlockRecordV2>())
            .ok_or_else(|| LiveArenaLayoutError::new("block table length overflow"))?;
        let block_records_end = block_records_offset
            .checked_add(block_records_len)
            .ok_or_else(|| LiveArenaLayoutError::new("block table end overflow"))?;
        let source_groups_offset =
            checked_align_up(block_records_end, LIVE_ARENA_CACHE_LINE_BYTES)?;
        let source_groups_len = LIVE_ARENA_SOURCE_GROUPS
            .checked_mul(std::mem::size_of::<LiveSourceGroupRecordV2>())
            .ok_or_else(|| LiveArenaLayoutError::new("source-group table length overflow"))?;
        let source_groups_end = source_groups_offset
            .checked_add(source_groups_len)
            .ok_or_else(|| LiveArenaLayoutError::new("source-group table end overflow"))?;
        let chunk_descriptors_offset =
            checked_align_up(source_groups_end, LIVE_ARENA_CACHE_LINE_BYTES)?;
        let chunk_descriptors_len = LIVE_ARENA_CHUNKS
            .checked_mul(std::mem::size_of::<LiveChunkDescriptorV2>())
            .ok_or_else(|| LiveArenaLayoutError::new("chunk table length overflow"))?;
        let chunk_descriptors_end = chunk_descriptors_offset
            .checked_add(chunk_descriptors_len)
            .ok_or_else(|| LiveArenaLayoutError::new("chunk table end overflow"))?;
        let hot_base = checked_align_up(chunk_descriptors_end, LIVE_ARENA_METADATA_ALIGN as usize)?;
        let hot_end = hot_base
            .checked_add(hot_capacity)
            .ok_or_else(|| LiveArenaLayoutError::new("HOT pool end overflow"))?;
        let cold_base = checked_align_up(hot_end, LIVE_ARENA_METADATA_ALIGN as usize)?;
        let control_payload_end = cold_base
            .checked_add(cold_capacity)
            .ok_or_else(|| LiveArenaLayoutError::new("COLD pool end overflow"))?;
        let control_len = checked_align_up(control_payload_end, host_page)?;
        Ok(Self {
            capacities,
            host_page,
            code_payload_base,
            code_len,
            directory_offset,
            next_chunk_cursor_offset,
            hot_cursor_offset,
            cold_cursor_offset,
            block_records_offset,
            block_records_len,
            source_groups_offset,
            source_groups_len,
            chunk_descriptors_offset,
            chunk_descriptors_len,
            hot_base,
            cold_base,
            control_payload_end,
            control_len,
        })
    }

    pub const fn capacities(self) -> LiveArenaCapacities {
        self.capacities
    }
    pub const fn host_page(self) -> usize {
        self.host_page
    }
    pub const fn code_payload_base(self) -> usize {
        self.code_payload_base
    }
    pub const fn code_len(self) -> usize {
        self.code_len
    }
    pub const fn directory_offset(self) -> usize {
        self.directory_offset
    }
    pub const fn directory_end(self) -> usize {
        self.directory_offset + LIVE_ARENA_CONTROL_DIRECTORY_BYTES
    }
    pub const fn next_chunk_cursor_offset(self) -> usize {
        self.next_chunk_cursor_offset
    }
    pub const fn hot_cursor_offset(self) -> usize {
        self.hot_cursor_offset
    }
    pub const fn cold_cursor_offset(self) -> usize {
        self.cold_cursor_offset
    }
    pub const fn block_records_offset(self) -> usize {
        self.block_records_offset
    }
    pub const fn block_records_len(self) -> usize {
        self.block_records_len
    }
    pub const fn block_records_end(self) -> usize {
        self.block_records_offset + self.block_records_len
    }
    pub const fn source_groups_offset(self) -> usize {
        self.source_groups_offset
    }
    pub const fn source_groups_len(self) -> usize {
        self.source_groups_len
    }
    pub const fn source_groups_end(self) -> usize {
        self.source_groups_offset + self.source_groups_len
    }
    pub const fn chunk_descriptors_offset(self) -> usize {
        self.chunk_descriptors_offset
    }
    pub const fn chunk_descriptors_len(self) -> usize {
        self.chunk_descriptors_len
    }
    pub const fn chunk_descriptors_end(self) -> usize {
        self.chunk_descriptors_offset + self.chunk_descriptors_len
    }
    pub const fn hot_base(self) -> usize {
        self.hot_base
    }
    pub const fn cold_base(self) -> usize {
        self.cold_base
    }
    pub const fn control_payload_end(self) -> usize {
        self.control_payload_end
    }
    pub const fn control_len(self) -> usize {
        self.control_len
    }
}

fn checked_align_up(value: usize, alignment: usize) -> Result<usize, LiveArenaLayoutError> {
    let remainder = value % alignment;
    value
        .checked_add((alignment - remainder) % alignment)
        .ok_or_else(|| LiveArenaLayoutError::new("layout alignment overflow"))
}

fn pointer_at<T>(base: NonNull<u8>, offset: usize) -> Result<NonNull<T>, LiveArenaLayoutError> {
    let address = (base.as_ptr() as usize)
        .checked_add(offset)
        .ok_or_else(|| LiveArenaLayoutError::new("mapped pointer overflow"))?;
    if !address.is_multiple_of(std::mem::align_of::<T>()) {
        return Err(LiveArenaLayoutError::new("mapped pointer is misaligned"));
    }
    NonNull::new(address as *mut T)
        .ok_or_else(|| LiveArenaLayoutError::new("mapped pointer is null"))
}

fn validate_mapping_geometry(
    base: NonNull<u8>,
    mapped_len: usize,
    layout: LiveArenaControlLayout,
) -> Result<(), LiveArenaLayoutError> {
    if !(base.as_ptr() as usize).is_multiple_of(LIVE_ARENA_CACHE_LINE_BYTES) {
        return Err(LiveArenaLayoutError::new(
            "control mapping base is not cacheline aligned",
        ));
    }
    #[cfg(test)]
    let rebuilt = LiveArenaControlLayout::new_for_test(layout.capacities, layout.host_page)?;
    #[cfg(not(test))]
    let rebuilt = LiveArenaControlLayout::new(layout.capacities, layout.host_page)?;
    if rebuilt != layout {
        return Err(LiveArenaLayoutError::new("control layout is not canonical"));
    }
    if mapped_len != layout.control_len {
        return Err(LiveArenaLayoutError::new(
            "control mapping length differs from layout",
        ));
    }
    Ok(())
}

fn validate_directory(
    directory: &LiveArenaControlDirectoryV2,
    layout: LiveArenaControlLayout,
    nonce: [u8; 16],
) -> Result<(), LiveArenaLayoutError> {
    let matches = directory.schema == LIVE_ARENA_SCHEMA_V2
        && directory.translator_abi == TRANSLATOR_ABI_CURRENT
        && directory.directory_len == LIVE_ARENA_CONTROL_DIRECTORY_BYTES as u32
        && directory.nonce == nonce
        && directory.code_payload_base == layout.code_payload_base as u64
        && directory.code_capacity == layout.capacities.code
        && directory.next_chunk_cursor_offset == layout.next_chunk_cursor_offset as u64
        && directory.hot_cursor_offset == layout.hot_cursor_offset as u64
        && directory.cold_cursor_offset == layout.cold_cursor_offset as u64
        && directory.block_records_offset == layout.block_records_offset as u64
        && directory.block_records_len == layout.block_records_len as u64
        && directory.block_record_count == LIVE_ARENA_BLOCK_RECORDS as u32
        && directory.block_record_stride == std::mem::size_of::<LiveBlockRecordV2>() as u32
        && directory.source_groups_offset == layout.source_groups_offset as u64
        && directory.source_groups_len == layout.source_groups_len as u64
        && directory.source_group_count == LIVE_ARENA_SOURCE_GROUPS as u32
        && directory.source_group_stride == std::mem::size_of::<LiveSourceGroupRecordV2>() as u32
        && directory.chunk_descriptors_offset == layout.chunk_descriptors_offset as u64
        && directory.chunk_descriptors_len == layout.chunk_descriptors_len as u64
        && directory.chunk_count == LIVE_ARENA_CHUNKS as u32
        && directory.chunk_stride == std::mem::size_of::<LiveChunkDescriptorV2>() as u32
        && directory.chunk_size == LIVE_ARENA_CHUNK_BYTES
        && directory.hot_base == layout.hot_base as u64
        && directory.hot_capacity == layout.capacities.hot
        && directory.cold_base == layout.cold_base as u64
        && directory.cold_capacity == layout.capacities.cold
        && directory.control_len == layout.control_len as u64
        && directory.reserved == [0; 3];
    if !matches {
        return Err(LiveArenaLayoutError::new(
            "control directory does not match canonical layout",
        ));
    }
    Ok(())
}

#[repr(C, align(64))]
pub struct LiveBlockRecordV2 {
    state: AtomicU32,
    owner_pid: AtomicI32,
    payload: UnsafeCell<LiveBlockPayloadV2>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
struct LiveBlockPayloadV2 {
    unit_key_digest: [u8; 32],
    code_sha256: [u8; 32],
    guest_start: u64,
    source_page: u64,
    code_offset: u64,
    hot_offset: u64,
    cold_offset: u64,
    code_len: u32,
    entry_offset: u32,
    hot_len: u32,
    cold_len: u32,
}

// SAFETY: `payload` has one writer: the capability returned by the successful
// EMPTY -> BUILDING CAS. No lookup reads it in EMPTY or BUILDING. That writer
// initializes the complete payload before publishing READY or FAILED with a
// Release store; readers access it only after the corresponding Acquire load.
// Terminal records are immutable and never return to BUILDING.
unsafe impl Sync for LiveBlockRecordV2 {}

const _: () = assert!(std::mem::align_of::<LiveBlockRecordV2>() == 64);
const _: () = assert!(std::mem::size_of::<LiveBlockRecordV2>() == 128);
const _: () = assert!(std::mem::size_of::<LiveBlockPayloadV2>() == 120);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV2, state) == 0);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV2, owner_pid) == 4);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV2, payload) == 8);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV2, unit_key_digest) + 8 == 8);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV2, code_sha256) + 8 == 40);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV2, guest_start) + 8 == 72);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV2, source_page) + 8 == 80);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV2, code_offset) + 8 == 88);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV2, hot_offset) + 8 == 96);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV2, cold_offset) + 8 == 104);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV2, code_len) + 8 == 112);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV2, entry_offset) + 8 == 116);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV2, hot_len) + 8 == 120);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV2, cold_len) + 8 == 124);

impl LiveBlockRecordV2 {
    fn empty() -> Self {
        Self {
            state: AtomicU32::new(LIVE_BLOCK_EMPTY),
            owner_pid: AtomicI32::new(0),
            payload: UnsafeCell::new(LiveBlockPayloadV2::empty()),
        }
    }

    /// Returns the immutable terminal payload after the caller has acquired
    /// READY or FAILED from `state`.
    unsafe fn terminal_payload(&self) -> &LiveBlockPayloadV2 {
        // SAFETY: the caller proves terminal-state Acquire ordering. Terminal
        // payloads are never mutated, as documented by the `Sync` contract.
        unsafe { &*self.payload.get() }
    }

    /// Replaces the payload while the caller exclusively owns BUILDING.
    unsafe fn write_building_payload(&self, payload: LiveBlockPayloadV2) {
        // SAFETY: the caller proves it owns the unique BUILDING capability, so
        // no payload reference exists and no other writer can reach this cell.
        unsafe { self.payload.get().write(payload) };
    }
}

impl LiveBlockPayloadV2 {
    const fn empty() -> Self {
        Self {
            unit_key_digest: [0; 32],
            code_sha256: [0; 32],
            guest_start: 0,
            source_page: 0,
            code_offset: 0,
            hot_offset: 0,
            cold_offset: 0,
            code_len: 0,
            entry_offset: 0,
            hot_len: 0,
            cold_len: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
struct LiveSourceGroupIdentityV2 {
    unit_key_digest: [u8; 32],
    source_page: u64,
}

#[repr(C, align(64))]
pub struct LiveSourceGroupRecordV2 {
    state: AtomicU32,
    creator_pid: AtomicI32,
    identity: UnsafeCell<LiveSourceGroupIdentityV2>,
    reserved_identity: [u64; 2],
    current_chunk: AtomicU32,
    reserved_current: u32,
    expansion: AtomicU64,
    reserved_expansion: [u64; 6],
}

unsafe impl Sync for LiveSourceGroupRecordV2 {}

const _: () = assert!(std::mem::size_of::<LiveSourceGroupRecordV2>() == 128);
const _: () = assert!(std::mem::align_of::<LiveSourceGroupRecordV2>() == 64);
const _: () = assert!(std::mem::offset_of!(LiveSourceGroupRecordV2, current_chunk) == 64);
const _: () = assert!(std::mem::offset_of!(LiveSourceGroupRecordV2, expansion) == 72);

impl LiveSourceGroupRecordV2 {
    fn empty() -> Self {
        Self {
            state: AtomicU32::new(LIVE_GROUP_EMPTY),
            creator_pid: AtomicI32::new(0),
            identity: UnsafeCell::new(LiveSourceGroupIdentityV2 {
                unit_key_digest: [0; 32],
                source_page: 0,
            }),
            reserved_identity: [0; 2],
            current_chunk: AtomicU32::new(LIVE_GROUP_NO_CHUNK),
            reserved_current: 0,
            expansion: AtomicU64::new(LIVE_EXPANSION_FREE),
            reserved_expansion: [0; 6],
        }
    }

    unsafe fn active_identity(&self) -> &LiveSourceGroupIdentityV2 {
        unsafe { &*self.identity.get() }
    }

    unsafe fn write_building_identity(&self, identity: LiveSourceGroupIdentityV2) {
        unsafe { self.identity.get().write(identity) };
    }
}

#[repr(C, align(64))]
pub struct LiveChunkDescriptorV2 {
    state: AtomicU32,
    owner_group: AtomicU32,
    cursor: AtomicU64,
    reserved: [u64; 6],
}

const _: () = assert!(std::mem::size_of::<LiveChunkDescriptorV2>() == 64);
const _: () = assert!(std::mem::align_of::<LiveChunkDescriptorV2>() == 64);

impl LiveChunkDescriptorV2 {
    fn empty() -> Self {
        Self {
            state: AtomicU32::new(LIVE_CHUNK_EMPTY),
            owner_group: AtomicU32::new(LIVE_GROUP_NO_CHUNK),
            cursor: AtomicU64::new(0),
            reserved: [0; 6],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LivePrivateReason {
    Building,
    Failed,
    CasLost,
    InvalidRecord,
    Capacity,
    ExhaustedProbes,
    KeyEncoding,
    WriteAttempted,
    UnknownState,
}

pub enum LiveLookup<'a> {
    Ready(ValidatedLiveBlockRecord),
    Publish(LivePublishClaim<'a>),
    Private(LivePrivateReason),
}

// The READY fast path is allocation-free by contract; boxing its offset-only
// capability would add a heap operation to every shared hit.
#[allow(clippy::large_enum_variant)]
pub enum LiveReadyLookup {
    Ready(ValidatedLiveBlockRecord),
    Miss,
    Private(LivePrivateReason),
}

impl LiveLookup<'_> {
    #[cfg(test)]
    fn private_reason(&self) -> Option<LivePrivateReason> {
        match self {
            Self::Private(reason) => Some(*reason),
            Self::Ready(_) | Self::Publish(_) => None,
        }
    }
}

/// An append-only range in one arena object. Offsets are never process-local
/// addresses, and callers cannot turn them into pointers in this layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveReservation {
    pub offset: u64,
    pub len: u64,
}

impl LiveReservation {
    pub fn end(self) -> Option<u64> {
        self.offset.checked_add(self.len)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveBlockExtents {
    pub code: LiveReservation,
    pub hot: LiveReservation,
    pub cold: LiveReservation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LiveArenaViewBrand {
    directory: NonNull<LiveArenaControlDirectoryV2>,
    nonce: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LiveArenaStorageIdentity {
    nonce: [u8; 16],
    schema: u32,
    translator_abi: u32,
    layout: LiveArenaControlLayout,
}

#[derive(Debug)]
struct LiveProcessViewIdentity;

/// Opaque identity for one process-local mapping authority. It is never part
/// of the shared wire and exposes neither addresses nor a serializable value.
pub struct LiveProcessViewBrand {
    identity: Arc<LiveProcessViewIdentity>,
    generation_domain: PageGenerationDomain,
}

impl LiveProcessViewBrand {
    pub fn new(generation_domain: PageGenerationDomain) -> Self {
        Self {
            identity: Arc::new(LiveProcessViewIdentity),
            generation_domain,
        }
    }

    fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveArenaCursorSnapshot {
    pub next_chunk: u64,
    pub hot: u64,
    pub cold: u64,
    /// Nonempty extents stranded when a later cursor reservation fails. The
    /// append-only allocator never reclaims or retries them.
    pub leaked_extents: u64,
    pub leaked_chunks: u64,
    pub private_fallbacks: u64,
}

/// Descriptor-authoritative ownership discovered from one ACTIVE chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveOwnedChunkIdentity {
    pub group_slot: u32,
    pub chunk_index: u32,
    pub unit_key_digest: [u8; 32],
    pub source_page: u64,
}

#[derive(Clone, Copy)]
pub struct LiveTranslationArenaView<'a> {
    directory: &'a LiveArenaControlDirectoryV2,
    block_records: &'a [LiveBlockRecordV2],
    source_groups: &'a [LiveSourceGroupRecordV2],
    chunk_descriptors: &'a [LiveChunkDescriptorV2],
    next_chunk: &'a AtomicU64,
    hot_next: &'a AtomicU64,
    cold_next: &'a AtomicU64,
    layout: LiveArenaControlLayout,
    brand: LiveArenaViewBrand,
    #[cfg(test)]
    cas_barrier: Option<&'a Barrier>,
    #[cfg(test)]
    before_block_cas: Option<&'a dyn Fn()>,
    #[cfg(test)]
    after_group_resolution: Option<&'a dyn Fn()>,
    #[cfg(test)]
    fail_group_creation_after_identity: bool,
    #[cfg(test)]
    after_expansion_claim: Option<&'a dyn Fn()>,
    #[cfg(test)]
    fail_after_chunk_index: bool,
    #[cfg(test)]
    refreshed_chunk_for_test: Option<(u32, u64)>,
    #[cfg(test)]
    forced_chunk_outcome_for_test: Option<(u32, ForcedChunkOutcome)>,
    #[cfg(test)]
    after_payload_write_before_ready: Option<&'a dyn Fn()>,
}

// SAFETY: every pointer exposed through the view addresses atomics or a record
// payload governed by the record's release/acquire state machine. Directory
// fields are immutable after its initialization-state Release publication.
unsafe impl Send for LiveTranslationArenaView<'_> {}
unsafe impl Sync for LiveTranslationArenaView<'_> {}

impl<'a> LiveTranslationArenaView<'a> {
    fn storage_identity(&self) -> LiveArenaStorageIdentity {
        LiveArenaStorageIdentity {
            nonce: self.brand.nonce,
            schema: LIVE_ARENA_SCHEMA_V2,
            translator_abi: TRANSLATOR_ABI_CURRENT,
            layout: self.layout,
        }
    }

    /// Discovers capacities only from the fixed directory location, rebuilds
    /// the canonical layout, then performs full adoption validation.
    ///
    /// # Safety
    ///
    /// The mapping/lifetime contract is identical to `adopt_in_place`.
    pub unsafe fn adopt_discovered_in_place(
        base: NonNull<u8>,
        mapped_len: usize,
        code_len: usize,
        host_page: usize,
        nonce: [u8; 16],
    ) -> Result<Self, LiveArenaLayoutError> {
        if !(base.as_ptr() as usize).is_multiple_of(LIVE_ARENA_CACHE_LINE_BYTES) {
            return Err(LiveArenaLayoutError::new(
                "control mapping base is not cacheline aligned",
            ));
        }
        let fixed_end = LIVE_ARENA_OBJECT_HEADER_BYTES
            .checked_add(std::mem::size_of::<LiveArenaControlDirectoryV2>())
            .ok_or_else(|| LiveArenaLayoutError::new("fixed directory end overflow"))?;
        if mapped_len < fixed_end {
            return Err(LiveArenaLayoutError::new(
                "control mapping is smaller than directory",
            ));
        }
        let directory_ptr =
            pointer_at::<LiveArenaControlDirectoryV2>(base, LIVE_ARENA_OBJECT_HEADER_BYTES)?;
        // SAFETY: only the fixed, alignment-checked directory range is formed;
        // no attacker-controlled offset has been consumed.
        let directory = unsafe { directory_ptr.as_ref() };
        if directory.initialization_state.load(Ordering::Acquire) != LIVE_ARENA_CONTROL_READY {
            return Err(LiveArenaLayoutError::new(
                "control directory is not initialized",
            ));
        }
        let layout = LiveArenaControlLayout::new(
            LiveArenaCapacities::new(
                directory.code_capacity,
                directory.hot_capacity,
                directory.cold_capacity,
            ),
            host_page,
        )?;
        if layout.code_len != code_len {
            return Err(LiveArenaLayoutError::new(
                "code mapping length differs from directory",
            ));
        }
        // SAFETY: the canonical layout derived from fixed fields is validated
        // in full before typed cursor/table references are formed.
        unsafe { Self::adopt_in_place(base, mapped_len, layout, nonce) }
    }

    /// Initializes one exclusively owned control mapping in place.
    ///
    /// # Safety
    ///
    /// `base..base+mapped_len` must be one live, writable allocation aligned to
    /// 64 bytes, exclusively owned for initialization, and remain mapped for
    /// `'a`. No typed reference into it may exist before this call.
    pub unsafe fn initialize_in_place(
        base: NonNull<u8>,
        mapped_len: usize,
        layout: LiveArenaControlLayout,
        nonce: [u8; 16],
    ) -> Result<Self, LiveArenaLayoutError> {
        validate_mapping_geometry(base, mapped_len, layout)?;
        let directory_ptr =
            pointer_at::<LiveArenaControlDirectoryV2>(base, layout.directory_offset)?;
        let directory = LiveArenaControlDirectoryV2 {
            initialization_state: AtomicU32::new(0),
            schema: LIVE_ARENA_SCHEMA_V2,
            translator_abi: TRANSLATOR_ABI_CURRENT,
            directory_len: std::mem::size_of::<LiveArenaControlDirectoryV2>() as u32,
            nonce,
            code_payload_base: layout.code_payload_base as u64,
            code_capacity: layout.capacities.code,
            next_chunk_cursor_offset: layout.next_chunk_cursor_offset as u64,
            hot_cursor_offset: layout.hot_cursor_offset as u64,
            cold_cursor_offset: layout.cold_cursor_offset as u64,
            block_records_offset: layout.block_records_offset as u64,
            block_records_len: layout.block_records_len as u64,
            block_record_count: LIVE_ARENA_BLOCK_RECORDS as u32,
            block_record_stride: std::mem::size_of::<LiveBlockRecordV2>() as u32,
            source_groups_offset: layout.source_groups_offset as u64,
            source_groups_len: layout.source_groups_len as u64,
            source_group_count: LIVE_ARENA_SOURCE_GROUPS as u32,
            source_group_stride: std::mem::size_of::<LiveSourceGroupRecordV2>() as u32,
            chunk_descriptors_offset: layout.chunk_descriptors_offset as u64,
            chunk_descriptors_len: layout.chunk_descriptors_len as u64,
            chunk_count: LIVE_ARENA_CHUNKS as u32,
            chunk_stride: std::mem::size_of::<LiveChunkDescriptorV2>() as u32,
            chunk_size: LIVE_ARENA_CHUNK_BYTES,
            hot_base: layout.hot_base as u64,
            hot_capacity: layout.capacities.hot,
            cold_base: layout.cold_base as u64,
            cold_capacity: layout.capacities.cold,
            control_len: layout.control_len as u64,
            leaked_code_extents: AtomicU64::new(0),
            leaked_hot_extents: AtomicU64::new(0),
            leaked_cold_extents: AtomicU64::new(0),
            leaked_chunks: AtomicU64::new(0),
            private_fallbacks: AtomicU64::new(0),
            reserved: [0; 3],
        };
        // SAFETY: the caller grants exclusive uninitialized storage and the
        // checked pointer is aligned and in bounds for the complete directory.
        unsafe { directory_ptr.as_ptr().write(directory) };
        for offset in [
            layout.next_chunk_cursor_offset,
            layout.hot_cursor_offset,
            layout.cold_cursor_offset,
        ] {
            let cursor = pointer_at::<AtomicU64>(base, offset)?;
            // SAFETY: each separately aligned cursor cell is disjoint and was
            // proved in-bounds by the canonical layout.
            unsafe { cursor.as_ptr().write(AtomicU64::new(0)) };
        }
        let block_records = pointer_at::<LiveBlockRecordV2>(base, layout.block_records_offset)?;
        for index in 0..LIVE_ARENA_BLOCK_RECORDS {
            // SAFETY: the canonical records range contains exactly this many
            // aligned, disjoint records and remains exclusively initialized.
            unsafe {
                block_records
                    .as_ptr()
                    .add(index)
                    .write(LiveBlockRecordV2::empty())
            };
        }
        let source_groups =
            pointer_at::<LiveSourceGroupRecordV2>(base, layout.source_groups_offset)?;
        for index in 0..LIVE_ARENA_SOURCE_GROUPS {
            unsafe {
                source_groups
                    .as_ptr()
                    .add(index)
                    .write(LiveSourceGroupRecordV2::empty())
            };
        }
        let chunk_descriptors =
            pointer_at::<LiveChunkDescriptorV2>(base, layout.chunk_descriptors_offset)?;
        for index in 0..LIVE_ARENA_CHUNKS {
            unsafe {
                chunk_descriptors
                    .as_ptr()
                    .add(index)
                    .write(LiveChunkDescriptorV2::empty())
            };
        }
        // SAFETY: the directory was initialized above and remains mapped.
        let directory = unsafe { directory_ptr.as_ref() };
        directory
            .initialization_state
            .store(LIVE_ARENA_CONTROL_READY, Ordering::Release);
        // SAFETY: initialization is complete and the same checked mapping
        // remains valid for `'a`.
        unsafe { Self::adopt_in_place(base, mapped_len, layout, nonce) }
    }

    /// Adopts one initialized control mapping after validating its complete
    /// canonical geometry before forming record or cursor references.
    ///
    /// # Safety
    ///
    /// The mapping must remain live for `'a`, originate from
    /// `initialize_in_place`, and permit concurrent mutation only through the
    /// protocol atomics and record payload state machine.
    pub unsafe fn adopt_in_place(
        base: NonNull<u8>,
        mapped_len: usize,
        layout: LiveArenaControlLayout,
        nonce: [u8; 16],
    ) -> Result<Self, LiveArenaLayoutError> {
        validate_mapping_geometry(base, mapped_len, layout)?;
        let directory_ptr =
            pointer_at::<LiveArenaControlDirectoryV2>(base, layout.directory_offset)?;
        // SAFETY: fixed directory geometry was checked before this reference.
        let directory = unsafe { directory_ptr.as_ref() };
        if directory.initialization_state.load(Ordering::Acquire) != LIVE_ARENA_CONTROL_READY {
            return Err(LiveArenaLayoutError::new(
                "control directory is not initialized",
            ));
        }
        validate_directory(directory, layout, nonce)?;
        let next_chunk = pointer_at::<AtomicU64>(base, layout.next_chunk_cursor_offset)?;
        let hot_next = pointer_at::<AtomicU64>(base, layout.hot_cursor_offset)?;
        let cold_next = pointer_at::<AtomicU64>(base, layout.cold_cursor_offset)?;
        let block_records = pointer_at::<LiveBlockRecordV2>(base, layout.block_records_offset)?;
        let source_groups =
            pointer_at::<LiveSourceGroupRecordV2>(base, layout.source_groups_offset)?;
        let chunk_descriptors =
            pointer_at::<LiveChunkDescriptorV2>(base, layout.chunk_descriptors_offset)?;
        let block_records =
            unsafe { std::slice::from_raw_parts(block_records.as_ptr(), LIVE_ARENA_BLOCK_RECORDS) };
        let source_groups =
            unsafe { std::slice::from_raw_parts(source_groups.as_ptr(), LIVE_ARENA_SOURCE_GROUPS) };
        let chunk_descriptors =
            unsafe { std::slice::from_raw_parts(chunk_descriptors.as_ptr(), LIVE_ARENA_CHUNKS) };
        Ok(Self {
            directory,
            block_records,
            source_groups,
            chunk_descriptors,
            // SAFETY: each checked cursor pointer is aligned, initialized, and
            // remains mapped for `'a`.
            next_chunk: unsafe { next_chunk.as_ref() },
            hot_next: unsafe { hot_next.as_ref() },
            cold_next: unsafe { cold_next.as_ref() },
            layout,
            brand: LiveArenaViewBrand {
                directory: directory_ptr,
                nonce,
            },
            #[cfg(test)]
            cas_barrier: None,
            #[cfg(test)]
            before_block_cas: None,
            #[cfg(test)]
            after_group_resolution: None,
            #[cfg(test)]
            fail_group_creation_after_identity: false,
            #[cfg(test)]
            after_expansion_claim: None,
            #[cfg(test)]
            fail_after_chunk_index: false,
            #[cfg(test)]
            refreshed_chunk_for_test: None,
            #[cfg(test)]
            forced_chunk_outcome_for_test: None,
            #[cfg(test)]
            after_payload_write_before_ready: None,
        })
    }

    pub fn cursor_snapshot(&self) -> LiveArenaCursorSnapshot {
        LiveArenaCursorSnapshot {
            next_chunk: self.next_chunk.load(Ordering::Acquire),
            hot: self.hot_next.load(Ordering::Acquire),
            cold: self.cold_next.load(Ordering::Acquire),
            leaked_extents: self
                .directory
                .leaked_code_extents
                .load(Ordering::Acquire)
                .saturating_add(self.directory.leaked_hot_extents.load(Ordering::Acquire))
                .saturating_add(self.directory.leaked_cold_extents.load(Ordering::Acquire)),
            leaked_chunks: self.directory.leaked_chunks.load(Ordering::Acquire),
            private_fallbacks: self.directory.private_fallbacks.load(Ordering::Acquire),
        }
    }

    fn private_lookup(&self, reason: LivePrivateReason) -> LiveLookup<'a> {
        increment_saturating(&self.directory.private_fallbacks);
        LiveLookup::Private(reason)
    }

    fn private_ready(&self, reason: LivePrivateReason) -> LiveReadyLookup {
        increment_saturating(&self.directory.private_fallbacks);
        LiveReadyLookup::Private(reason)
    }

    /// Enumerates ownership from ACTIVE descriptors, then validates each
    /// descriptor's owner against an ACTIVE source-group record. Group hash
    /// placement is deliberately not the authority for this reverse lookup.
    pub fn active_chunks_for_source_page(&self, source_page: u64) -> Vec<LiveOwnedChunkIdentity> {
        let mut owned = Vec::new();
        for (chunk_index, descriptor) in self.chunk_descriptors.iter().enumerate() {
            if descriptor.state.load(Ordering::Acquire) != LIVE_CHUNK_ACTIVE {
                continue;
            }
            let group_slot = descriptor.owner_group.load(Ordering::Acquire);
            let Some(group) = self.source_groups.get(group_slot as usize) else {
                continue;
            };
            if group.state.load(Ordering::Acquire) != LIVE_GROUP_ACTIVE {
                continue;
            }
            // SAFETY: ACTIVE was acquired above and group identities are
            // immutable after their ACTIVE Release publication.
            let identity = unsafe { group.active_identity() };
            if identity.source_page != source_page {
                continue;
            }
            let Ok(chunk_index) = u32::try_from(chunk_index) else {
                continue;
            };
            owned.push(LiveOwnedChunkIdentity {
                group_slot,
                chunk_index,
                unit_key_digest: identity.unit_key_digest,
                source_page: identity.source_page,
            });
        }
        owned
    }

    pub const fn layout(&self) -> LiveArenaControlLayout {
        self.layout
    }

    pub fn accepts_claim(&self, claim: &LiveReservedPublishClaim<'_>) -> bool {
        self.brand == claim.claim.arena.brand
    }

    /// Performs the bounded READY read without ever claiming an EMPTY block,
    /// creating a source group, or allocating a chunk.
    pub fn acquire_ready_or_miss(
        &self,
        process_view: &LiveProcessViewBrand,
        key: &TranslationUnitKey,
        guest_start: GuestVa,
    ) -> LiveReadyLookup {
        let Ok(unit_key_digest) = key.live_digest() else {
            return self.private_ready(LivePrivateReason::KeyEncoding);
        };
        let initial = initial_slot(&unit_key_digest, guest_start.raw());
        for probe in 0..LIVE_ARENA_PROBES {
            let record_index = (initial + probe) & LIVE_BLOCK_MASK;
            let record = &self.block_records[record_index];
            match record.state.load(Ordering::Acquire) {
                LIVE_BLOCK_READY => {
                    let payload = unsafe { record.terminal_payload() };
                    if record_matches(payload, &unit_key_digest, guest_start.raw()) {
                        return self
                            .validate_ready(
                                process_view,
                                record_index,
                                payload,
                                &unit_key_digest,
                                guest_start.raw(),
                            )
                            .map(LiveReadyLookup::Ready)
                            .unwrap_or_else(|| {
                                self.private_ready(LivePrivateReason::InvalidRecord)
                            });
                    }
                }
                LIVE_BLOCK_FAILED => {
                    let payload = unsafe { record.terminal_payload() };
                    if record_matches(payload, &unit_key_digest, guest_start.raw()) {
                        return self.private_ready(LivePrivateReason::Failed);
                    }
                }
                LIVE_BLOCK_BUILDING => {
                    return self.private_ready(LivePrivateReason::Building);
                }
                LIVE_BLOCK_EMPTY => return LiveReadyLookup::Miss,
                _ => return self.private_ready(LivePrivateReason::UnknownState),
            }
        }
        self.private_ready(LivePrivateReason::ExhaustedProbes)
    }

    /// Resolves/creates the exact source group before the bounded block CAS.
    /// The group becomes ACTIVE with `NO_CHUNK`; code remains unallocated until
    /// the unique block winner presents its exact prepared length to `reserve`.
    pub fn claim_eligible(
        &self,
        process_view: &'a LiveProcessViewBrand,
        key: &TranslationUnitKey,
        guest_start: GuestVa,
        block_end: GuestVa,
        generation: &PageGenerationObservation,
        owner_pid: i32,
    ) -> LiveLookup<'a> {
        let Ok(unit_key_digest) = key.live_digest() else {
            return self.private_lookup(LivePrivateReason::KeyEncoding);
        };
        if !guest_start
            .raw()
            .is_multiple_of(LIVE_ARENA_INSTRUCTION_BYTES)
        {
            return self.private_lookup(LivePrivateReason::InvalidRecord);
        }
        let source_page = guest_start.raw() / LIVE_SOURCE_PAGE_BYTES * LIVE_SOURCE_PAGE_BYTES;
        let Some(source_page_end) = source_page.checked_add(LIVE_SOURCE_PAGE_BYTES) else {
            return self.private_lookup(LivePrivateReason::InvalidRecord);
        };
        if !key.contains_guest_interval(guest_start, block_end)
            || block_end.raw() <= guest_start.raw()
            || block_end.raw() > source_page_end
            || !generation.belongs_to(&process_view.generation_domain)
            || generation.page().raw() != source_page
            || generation.expected() != CodeGeneration::INITIAL
            || generation.current() != CodeGeneration::INITIAL
        {
            return self.private_lookup(LivePrivateReason::InvalidRecord);
        }
        let group = match self.resolve_or_create_group(&unit_key_digest, source_page, owner_pid) {
            Ok(group) => group,
            Err(reason) => return self.private_lookup(reason),
        };
        #[cfg(test)]
        if let Some(after_group_resolution) = self.after_group_resolution {
            after_group_resolution();
        }
        if generation.current() != CodeGeneration::INITIAL {
            return self.private_lookup(LivePrivateReason::InvalidRecord);
        }
        let initial = initial_slot(&unit_key_digest, guest_start.raw());

        for probe in 0..LIVE_ARENA_PROBES {
            let record_index = (initial + probe) & LIVE_BLOCK_MASK;
            let Ok(record_index_wire) = u32::try_from(record_index) else {
                return self.private_lookup(LivePrivateReason::InvalidRecord);
            };
            let record = &self.block_records[record_index];
            match record.state.load(Ordering::Acquire) {
                LIVE_BLOCK_READY => {
                    // SAFETY: this branch acquired terminal READY above.
                    let payload = unsafe { record.terminal_payload() };
                    if record_matches(payload, &unit_key_digest, guest_start.raw()) {
                        return self
                            .validate_ready(
                                process_view,
                                record_index,
                                payload,
                                &unit_key_digest,
                                guest_start.raw(),
                            )
                            .map(LiveLookup::Ready)
                            .unwrap_or_else(|| {
                                self.private_lookup(LivePrivateReason::InvalidRecord)
                            });
                    }
                }
                LIVE_BLOCK_FAILED => {
                    // SAFETY: this branch acquired terminal FAILED above.
                    let payload = unsafe { record.terminal_payload() };
                    if record_matches(payload, &unit_key_digest, guest_start.raw()) {
                        return self.private_lookup(LivePrivateReason::Failed);
                    }
                }
                LIVE_BLOCK_BUILDING => return self.private_lookup(LivePrivateReason::Building),
                LIVE_BLOCK_EMPTY => {
                    #[cfg(test)]
                    if let Some(barrier) = &self.cas_barrier {
                        barrier.wait();
                    }
                    #[cfg(test)]
                    if let Some(before_block_cas) = self.before_block_cas {
                        before_block_cas();
                    }
                    if generation.current() != CodeGeneration::INITIAL {
                        return self.private_lookup(LivePrivateReason::InvalidRecord);
                    }
                    match record.state.compare_exchange(
                        LIVE_BLOCK_EMPTY,
                        LIVE_BLOCK_BUILDING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            record.owner_pid.store(owner_pid, Ordering::Relaxed);
                            return LiveLookup::Publish(LivePublishClaim {
                                arena: *self,
                                record,
                                record_index: record_index_wire,
                                process_view,
                                unit_key_digest,
                                guest_start: guest_start.raw(),
                                block_end: block_end.raw(),
                                group,
                                generation: generation.clone(),
                                armed: true,
                            });
                        }
                        Err(_) => return self.private_lookup(LivePrivateReason::CasLost),
                    }
                }
                _ => return self.private_lookup(LivePrivateReason::UnknownState),
            }
        }

        self.private_lookup(LivePrivateReason::ExhaustedProbes)
    }

    #[cfg(test)]
    fn claim_eligible_for_test(
        &self,
        process_view: &'a LiveProcessViewBrand,
        key: &TranslationUnitKey,
        guest_start: GuestVa,
        generations: &carrick_dsr::cache::PageGenerationTable,
        owner_pid: i32,
    ) -> LiveLookup<'a> {
        let observation = generations
            .observe(guest_start)
            .expect("test INITIAL observation");
        let block_end = GuestVa(
            guest_start
                .raw()
                .checked_add(LIVE_ARENA_INSTRUCTION_BYTES)
                .expect("test block end"),
        );
        self.claim_eligible(
            process_view,
            key,
            guest_start,
            block_end,
            &observation,
            owner_pid,
        )
    }

    fn validate_ready(
        &self,
        process_view: &LiveProcessViewBrand,
        record_index: usize,
        payload: &LiveBlockPayloadV2,
        expected_key: &[u8; 32],
        expected_guest_start: u64,
    ) -> Option<ValidatedLiveBlockRecord> {
        let extents = LiveBlockExtents {
            code: LiveReservation {
                offset: payload.code_offset,
                len: u64::from(payload.code_len),
            },
            hot: LiveReservation {
                offset: payload.hot_offset,
                len: u64::from(payload.hot_len),
            },
            cold: LiveReservation {
                offset: payload.cold_offset,
                len: u64::from(payload.cold_len),
            },
        };
        let group = self.find_active_group(expected_key, payload.source_page)?;
        let chunk_index = usize::try_from(extents.code.offset / LIVE_ARENA_CHUNK_BYTES).ok()?;
        let descriptor = self.chunk_descriptors.get(chunk_index)?;
        if !record_matches(payload, expected_key, expected_guest_start)
            || !valid_source_page(payload.source_page, expected_guest_start)
            || !self.extents_in_bounds(extents)
            || !valid_code_extent(extents.code)
            || !valid_metadata_extent(extents.hot)
            || !valid_metadata_extent(extents.cold)
            || u64::from(payload.entry_offset) >= extents.code.len
            || !u64::from(payload.entry_offset).is_multiple_of(LIVE_ARENA_INSTRUCTION_BYTES)
            || descriptor.state.load(Ordering::Acquire) != LIVE_CHUNK_ACTIVE
            || descriptor.owner_group.load(Ordering::Acquire) != group.slot
        {
            return None;
        }
        Some(ValidatedLiveBlockRecord {
            record_index: u32::try_from(record_index).ok()?,
            payload: *payload,
            extents,
            group_slot: group.slot,
            chunk_index: u32::try_from(chunk_index).ok()?,
            storage_identity: self.storage_identity(),
            process_view: Arc::clone(&process_view.identity),
        })
    }

    /// Acquire-revalidates an owned READY snapshot against this exact storage
    /// mapping and process-view authority before a native layer resolves its
    /// offsets into local addresses.
    pub fn revalidate_ready(
        &self,
        process_view: &LiveProcessViewBrand,
        ready: &ValidatedLiveBlockRecord,
    ) -> Option<ValidatedLiveBlockRecord> {
        if self.storage_identity() != ready.storage_identity
            || !Arc::ptr_eq(&process_view.identity, &ready.process_view)
        {
            return None;
        }
        let index = usize::try_from(ready.record_index).ok()?;
        let record = self.block_records.get(index)?;
        if record.state.load(Ordering::Acquire) != LIVE_BLOCK_READY {
            return None;
        }
        // SAFETY: this branch acquired terminal READY above.
        let payload = unsafe { record.terminal_payload() };
        if *payload != ready.payload {
            return None;
        }
        let revalidated = self.validate_ready(
            process_view,
            index,
            payload,
            &ready.payload.unit_key_digest,
            ready.payload.guest_start,
        )?;
        (revalidated.group_slot == ready.group_slot && revalidated.chunk_index == ready.chunk_index)
            .then_some(revalidated)
    }

    fn extents_in_bounds(&self, extents: LiveBlockExtents) -> bool {
        extent_in_capacity(extents.code, self.code_capacity())
            && extent_in_capacity(extents.hot, self.hot_capacity())
            && extent_in_capacity(extents.cold, self.cold_capacity())
    }

    fn reserve(
        &self,
        group: LiveSourceGroupAuthority<'a>,
        owner_pid: i32,
        code_len: u64,
        hot_len: u64,
        cold_len: u64,
    ) -> Option<LiveBlockExtents> {
        if code_len == 0
            || !code_len.is_multiple_of(LIVE_ARENA_INSTRUCTION_BYTES)
            || code_len > LIVE_ARENA_CHUNK_BYTES
        {
            return None;
        }
        let code = self.reserve_group_code(group, owner_pid, code_len)?;
        let Some(hot) = reserve_append_bounded(
            self.hot_next,
            self.hot_capacity(),
            hot_len,
            LIVE_ARENA_METADATA_ALIGN,
        ) else {
            increment_saturating(&self.directory.leaked_code_extents);
            return None;
        };
        let Some(cold) = reserve_append_bounded(
            self.cold_next,
            self.cold_capacity(),
            cold_len,
            LIVE_ARENA_METADATA_ALIGN,
        ) else {
            increment_saturating(&self.directory.leaked_code_extents);
            if hot.len != 0 {
                increment_saturating(&self.directory.leaked_hot_extents);
            }
            return None;
        };
        Some(LiveBlockExtents { code, hot, cold })
    }

    fn code_capacity(&self) -> u64 {
        self.layout.capacities.code
    }
    fn hot_capacity(&self) -> u64 {
        self.layout.capacities.hot
    }
    fn cold_capacity(&self) -> u64 {
        self.layout.capacities.cold
    }

    fn resolve_or_create_group(
        &self,
        unit_key_digest: &[u8; 32],
        source_page: u64,
        owner_pid: i32,
    ) -> Result<LiveSourceGroupAuthority<'a>, LivePrivateReason> {
        let initial = initial_group_slot(unit_key_digest, source_page);
        for probe in 0..LIVE_ARENA_PROBES {
            let slot = (initial + probe) & LIVE_GROUP_MASK;
            let slot_wire = u32::try_from(slot).map_err(|_| LivePrivateReason::InvalidRecord)?;
            let record = &self.source_groups[slot];
            match record.state.load(Ordering::Acquire) {
                LIVE_GROUP_ACTIVE => {
                    let identity = unsafe { record.active_identity() };
                    if identity.unit_key_digest == *unit_key_digest
                        && identity.source_page == source_page
                    {
                        return Ok(LiveSourceGroupAuthority {
                            record,
                            slot: slot_wire,
                        });
                    }
                }
                LIVE_GROUP_FAILED => {
                    let identity = unsafe { record.active_identity() };
                    if identity.unit_key_digest == *unit_key_digest
                        && identity.source_page == source_page
                    {
                        return Err(LivePrivateReason::Failed);
                    }
                }
                LIVE_GROUP_BUILDING => return Err(LivePrivateReason::Building),
                LIVE_GROUP_EMPTY => {
                    if record
                        .state
                        .compare_exchange(
                            LIVE_GROUP_EMPTY,
                            LIVE_GROUP_BUILDING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_err()
                    {
                        return Err(LivePrivateReason::CasLost);
                    }
                    record.creator_pid.store(owner_pid, Ordering::Relaxed);
                    unsafe {
                        record.write_building_identity(LiveSourceGroupIdentityV2 {
                            unit_key_digest: *unit_key_digest,
                            source_page,
                        })
                    };
                    record
                        .current_chunk
                        .store(LIVE_GROUP_NO_CHUNK, Ordering::Relaxed);
                    record
                        .expansion
                        .store(LIVE_EXPANSION_FREE, Ordering::Relaxed);
                    let creation = LiveSourceGroupCreationClaim {
                        record,
                        slot: slot_wire,
                        armed: true,
                    };
                    #[cfg(test)]
                    if self.fail_group_creation_after_identity {
                        return Err(LivePrivateReason::InvalidRecord);
                    }
                    return Ok(creation.activate());
                }
                _ => return Err(LivePrivateReason::UnknownState),
            }
        }
        Err(LivePrivateReason::ExhaustedProbes)
    }

    fn find_active_group(
        &self,
        unit_key_digest: &[u8; 32],
        source_page: u64,
    ) -> Option<LiveSourceGroupAuthority<'a>> {
        let initial = initial_group_slot(unit_key_digest, source_page);
        for probe in 0..LIVE_ARENA_PROBES {
            let slot = (initial + probe) & LIVE_GROUP_MASK;
            let record = &self.source_groups[slot];
            match record.state.load(Ordering::Acquire) {
                LIVE_GROUP_ACTIVE => {
                    let identity = unsafe { record.active_identity() };
                    if identity.unit_key_digest == *unit_key_digest
                        && identity.source_page == source_page
                    {
                        return Some(LiveSourceGroupAuthority {
                            record,
                            slot: u32::try_from(slot).ok()?,
                        });
                    }
                }
                LIVE_GROUP_EMPTY | LIVE_GROUP_BUILDING => return None,
                LIVE_GROUP_FAILED => {}
                _ => return None,
            }
        }
        None
    }

    fn reserve_group_code(
        &self,
        group: LiveSourceGroupAuthority<'a>,
        owner_pid: i32,
        code_len: u64,
    ) -> Option<LiveReservation> {
        let current = group.record.current_chunk.load(Ordering::Acquire);
        if current != LIVE_GROUP_NO_CHUNK {
            match self.reserve_existing_chunk(group.slot, current, code_len) {
                ChunkReservation::Reserved(reservation) => return Some(reservation),
                ChunkReservation::Contended | ChunkReservation::Invalid => return None,
                ChunkReservation::Full => {}
            }
        }

        let expansion = expansion_owner(owner_pid);
        group
            .record
            .expansion
            .compare_exchange(
                LIVE_EXPANSION_FREE,
                expansion,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;

        #[cfg(test)]
        if let Some(after_expansion_claim) = self.after_expansion_claim {
            after_expansion_claim();
        }
        #[cfg(test)]
        if let Some((chunk_index, cursor)) = self.refreshed_chunk_for_test {
            let descriptor = &self.chunk_descriptors[chunk_index as usize];
            descriptor.owner_group.store(group.slot, Ordering::Relaxed);
            descriptor.cursor.store(cursor, Ordering::Relaxed);
            descriptor.state.store(LIVE_CHUNK_ACTIVE, Ordering::Release);
            self.next_chunk
                .fetch_max(u64::from(chunk_index) + 1, Ordering::AcqRel);
            group
                .record
                .current_chunk
                .store(chunk_index, Ordering::Release);
        }

        let refreshed = group.record.current_chunk.load(Ordering::Acquire);
        if refreshed != current && refreshed != LIVE_GROUP_NO_CHUNK {
            match self.reserve_existing_chunk(group.slot, refreshed, code_len) {
                ChunkReservation::Reserved(reservation) => {
                    group
                        .record
                        .expansion
                        .store(LIVE_EXPANSION_FREE, Ordering::Release);
                    return Some(reservation);
                }
                ChunkReservation::Full => {}
                ChunkReservation::Contended | ChunkReservation::Invalid => {
                    group
                        .record
                        .expansion
                        .store(LIVE_EXPANSION_FREE, Ordering::Release);
                    return None;
                }
            }
        }

        let available_chunks =
            (self.code_capacity() / LIVE_ARENA_CHUNK_BYTES).min(LIVE_ARENA_CHUNKS as u64);
        let Some(chunk_index) = reserve_append_bounded(self.next_chunk, available_chunks, 1, 1)
            .and_then(|reservation| u32::try_from(reservation.offset).ok())
        else {
            group
                .record
                .expansion
                .store(LIVE_EXPANSION_FREE, Ordering::Release);
            return None;
        };
        let descriptor = &self.chunk_descriptors[chunk_index as usize];
        let Some(offset) = u64::from(chunk_index).checked_mul(LIVE_ARENA_CHUNK_BYTES) else {
            if descriptor.state.load(Ordering::Acquire) == LIVE_CHUNK_EMPTY {
                descriptor
                    .state
                    .store(LIVE_CHUNK_ABANDONED, Ordering::Release);
                increment_saturating(&self.directory.leaked_chunks);
            }
            group
                .record
                .expansion
                .store(LIVE_EXPANSION_FREE, Ordering::Release);
            return None;
        };
        #[cfg(test)]
        if self.fail_after_chunk_index {
            if descriptor.state.load(Ordering::Acquire) == LIVE_CHUNK_EMPTY {
                descriptor
                    .state
                    .store(LIVE_CHUNK_ABANDONED, Ordering::Release);
                increment_saturating(&self.directory.leaked_chunks);
            }
            group
                .record
                .expansion
                .store(LIVE_EXPANSION_FREE, Ordering::Release);
            return None;
        }
        if descriptor.state.load(Ordering::Acquire) != LIVE_CHUNK_EMPTY {
            group
                .record
                .expansion
                .store(LIVE_EXPANSION_FREE, Ordering::Release);
            return None;
        }
        descriptor.owner_group.store(group.slot, Ordering::Relaxed);
        descriptor.cursor.store(code_len, Ordering::Relaxed);
        descriptor.state.store(LIVE_CHUNK_ACTIVE, Ordering::Release);
        group
            .record
            .current_chunk
            .store(chunk_index, Ordering::Release);
        group
            .record
            .expansion
            .store(LIVE_EXPANSION_FREE, Ordering::Release);
        Some(LiveReservation {
            offset,
            len: code_len,
        })
    }

    fn reserve_existing_chunk(
        &self,
        group_slot: u32,
        chunk_index: u32,
        code_len: u64,
    ) -> ChunkReservation {
        let Some(descriptor) = self.chunk_descriptors.get(chunk_index as usize) else {
            return ChunkReservation::Invalid;
        };
        if descriptor.state.load(Ordering::Acquire) != LIVE_CHUNK_ACTIVE
            || descriptor.owner_group.load(Ordering::Acquire) != group_slot
        {
            return ChunkReservation::Invalid;
        }
        #[cfg(test)]
        if let Some((forced_index, outcome)) = self.forced_chunk_outcome_for_test
            && forced_index == chunk_index
        {
            return match outcome {
                ForcedChunkOutcome::Contended => ChunkReservation::Contended,
                ForcedChunkOutcome::Invalid => ChunkReservation::Invalid,
            };
        }
        match reserve_append_bounded_result(
            &descriptor.cursor,
            LIVE_ARENA_CHUNK_BYTES,
            code_len,
            LIVE_ARENA_INSTRUCTION_BYTES,
        ) {
            BoundedReservation::Reserved(local) => {
                let Some(base) = u64::from(chunk_index).checked_mul(LIVE_ARENA_CHUNK_BYTES) else {
                    return ChunkReservation::Invalid;
                };
                let Some(offset) = base.checked_add(local.offset) else {
                    return ChunkReservation::Invalid;
                };
                ChunkReservation::Reserved(LiveReservation {
                    offset,
                    len: code_len,
                })
            }
            BoundedReservation::Full => ChunkReservation::Full,
            BoundedReservation::Contended => ChunkReservation::Contended,
        }
    }
}

#[derive(Clone, Copy)]
struct LiveSourceGroupAuthority<'a> {
    record: &'a LiveSourceGroupRecordV2,
    slot: u32,
}

struct LiveSourceGroupCreationClaim<'a> {
    record: &'a LiveSourceGroupRecordV2,
    slot: u32,
    armed: bool,
}

impl<'a> LiveSourceGroupCreationClaim<'a> {
    fn activate(mut self) -> LiveSourceGroupAuthority<'a> {
        self.record
            .state
            .store(LIVE_GROUP_ACTIVE, Ordering::Release);
        self.armed = false;
        LiveSourceGroupAuthority {
            record: self.record,
            slot: self.slot,
        }
    }
}

impl Drop for LiveSourceGroupCreationClaim<'_> {
    fn drop(&mut self) {
        if self.armed && self.record.state.load(Ordering::Acquire) == LIVE_GROUP_BUILDING {
            self.record
                .state
                .store(LIVE_GROUP_FAILED, Ordering::Release);
            self.armed = false;
        }
    }
}

enum ChunkReservation {
    Reserved(LiveReservation),
    Full,
    Contended,
    Invalid,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum ForcedChunkOutcome {
    Contended,
    Invalid,
}

#[cfg(test)]
pub struct LiveTranslationArena {
    storage: Vec<u8>,
    base: NonNull<u8>,
    layout: LiveArenaControlLayout,
    nonce: [u8; 16],
    generations: Arc<carrick_dsr::cache::PageGenerationTable>,
    process_view: LiveProcessViewBrand,
    cas_barrier: Option<Arc<Barrier>>,
    after_group_resolution: Option<Arc<dyn Fn() + Send + Sync>>,
    fail_group_creation_after_identity: bool,
    after_expansion_claim: Option<Arc<dyn Fn() + Send + Sync>>,
    fail_after_chunk_index: bool,
    refreshed_chunk_for_test: Option<(u32, u64)>,
    forced_chunk_outcome_for_test: Option<(u32, ForcedChunkOutcome)>,
    after_payload_write_before_ready: Option<Arc<dyn Fn() + Send + Sync>>,
}

#[cfg(test)]
// SAFETY: the stable allocation contains only the protocol's atomics and
// state-machine-protected payload cells; all test access routes through a view.
unsafe impl Send for LiveTranslationArena {}
#[cfg(test)]
unsafe impl Sync for LiveTranslationArena {}

#[cfg(test)]
impl LiveTranslationArena {
    pub fn new(code_capacity: u64, hot_capacity: u64, cold_capacity: u64) -> Self {
        let layout = LiveArenaControlLayout::new_for_test(
            LiveArenaCapacities::new(code_capacity, hot_capacity, cold_capacity),
            LIVE_SOURCE_PAGE_BYTES as usize,
        )
        .expect("test arena layout");
        let mut storage = vec![0_u8; layout.control_len + LIVE_ARENA_CACHE_LINE_BYTES - 1];
        let unaligned = storage.as_mut_ptr() as usize;
        let aligned =
            (unaligned + LIVE_ARENA_CACHE_LINE_BYTES - 1) & !(LIVE_ARENA_CACHE_LINE_BYTES - 1);
        let base = NonNull::new(aligned as *mut u8).expect("test arena base");
        let nonce = [0x74; 16];
        // SAFETY: `storage` owns the complete aligned range and remains stable
        // inside the returned owner.
        unsafe {
            LiveTranslationArenaView::initialize_in_place(base, layout.control_len, layout, nonce)
        }
        .expect("initialize test live arena");
        let generations = Arc::new(
            carrick_dsr::cache::PageGenerationTable::new(LIVE_SOURCE_PAGE_BYTES)
                .expect("test generation table"),
        );
        let process_view = LiveProcessViewBrand::new(generations.domain());
        Self {
            storage,
            base,
            layout,
            nonce,
            generations,
            process_view,
            cas_barrier: None,
            after_group_resolution: None,
            fail_group_creation_after_identity: false,
            after_expansion_claim: None,
            fail_after_chunk_index: false,
            refreshed_chunk_for_test: None,
            forced_chunk_outcome_for_test: None,
            after_payload_write_before_ready: None,
        }
    }

    fn view(&self) -> LiveTranslationArenaView<'_> {
        let _keep_storage_alive = &self.storage;
        // SAFETY: this owner initialized and retains the mapping allocation.
        let mut view = unsafe {
            LiveTranslationArenaView::adopt_in_place(
                self.base,
                self.layout.control_len,
                self.layout,
                self.nonce,
            )
        }
        .expect("adopt test live arena");
        view.cas_barrier = self.cas_barrier.as_deref();
        view.after_group_resolution = self
            .after_group_resolution
            .as_deref()
            .map(|hook| hook as &dyn Fn());
        view.fail_group_creation_after_identity = self.fail_group_creation_after_identity;
        view.after_expansion_claim = self
            .after_expansion_claim
            .as_deref()
            .map(|hook| hook as &dyn Fn());
        view.fail_after_chunk_index = self.fail_after_chunk_index;
        view.refreshed_chunk_for_test = self.refreshed_chunk_for_test;
        view.forced_chunk_outcome_for_test = self.forced_chunk_outcome_for_test;
        view.after_payload_write_before_ready = self
            .after_payload_write_before_ready
            .as_deref()
            .map(|hook| hook as &dyn Fn());
        view
    }

    pub fn claim_eligible(
        &self,
        key: &TranslationUnitKey,
        guest_start: GuestVa,
        owner_pid: i32,
    ) -> LiveLookup<'_> {
        self.view().claim_eligible_for_test(
            &self.process_view,
            key,
            guest_start,
            &self.generations,
            owner_pid,
        )
    }

    pub fn acquire_ready_or_miss(
        &self,
        key: &TranslationUnitKey,
        guest_start: GuestVa,
    ) -> LiveReadyLookup {
        self.view()
            .acquire_ready_or_miss(&self.process_view, key, guest_start)
    }
}

pub struct LivePublishClaim<'a> {
    arena: LiveTranslationArenaView<'a>,
    record: &'a LiveBlockRecordV2,
    record_index: u32,
    process_view: &'a LiveProcessViewBrand,
    unit_key_digest: [u8; 32],
    guest_start: u64,
    block_end: u64,
    group: LiveSourceGroupAuthority<'a>,
    generation: PageGenerationObservation,
    armed: bool,
}

impl<'a> LivePublishClaim<'a> {
    pub fn owner_pid(&self) -> i32 {
        self.record.owner_pid.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub const fn unit_key_digest(&self) -> [u8; 32] {
        self.unit_key_digest
    }

    #[doc(hidden)]
    pub const fn guest_start(&self) -> GuestVa {
        GuestVa(self.guest_start)
    }

    /// Seals the decoded eligibility span to the prepared block before any
    /// code/chunk or metadata cursor can advance.
    #[doc(hidden)]
    pub fn bind_prepared_identity(
        mut self,
        prepared: &PreparedSharedInitial,
    ) -> Result<Self, LivePrivateReason> {
        if prepared.matches_live_identity(
            self.unit_key_digest,
            GuestVa(self.guest_start),
            GuestVa(self.block_end),
        ) {
            return Ok(self);
        }
        increment_saturating(&self.arena.directory.private_fallbacks);
        self.publish_failed();
        Err(LivePrivateReason::InvalidRecord)
    }

    /// Reserves disjoint append-only ranges. Failure strands this BUILDING
    /// record as FAILED; it never retries or waits for another publisher.
    pub fn reserve(
        mut self,
        code_len: u64,
        hot_len: u64,
        cold_len: u64,
    ) -> Result<LiveReservedPublishClaim<'a>, LivePrivateReason> {
        if self.record.state.load(Ordering::Acquire) != LIVE_BLOCK_BUILDING {
            increment_saturating(&self.arena.directory.private_fallbacks);
            return Err(LivePrivateReason::Failed);
        }
        if self.generation.current() != CodeGeneration::INITIAL {
            increment_saturating(&self.arena.directory.private_fallbacks);
            self.publish_failed();
            return Err(LivePrivateReason::InvalidRecord);
        }
        let Some(wire_lengths) = LiveWireLengths::new(code_len, hot_len, cold_len) else {
            increment_saturating(&self.arena.directory.private_fallbacks);
            self.publish_failed();
            return Err(LivePrivateReason::InvalidRecord);
        };
        let Some(extents) =
            self.arena
                .reserve(self.group, self.owner_pid(), code_len, hot_len, cold_len)
        else {
            increment_saturating(&self.arena.directory.private_fallbacks);
            self.publish_failed();
            return Err(LivePrivateReason::Capacity);
        };
        Ok(LiveReservedPublishClaim {
            claim: self,
            extents,
            wire_lengths,
            write_attempted: false,
        })
    }

    pub fn fail(mut self) -> LivePrivateReason {
        if self.record.state.load(Ordering::Acquire) != LIVE_BLOCK_BUILDING {
            increment_saturating(&self.arena.directory.private_fallbacks);
            return LivePrivateReason::Failed;
        }
        increment_saturating(&self.arena.directory.private_fallbacks);
        self.publish_failed();
        LivePrivateReason::Failed
    }

    fn publish_failed(&mut self) {
        if !self.armed {
            return;
        }
        let payload = LiveBlockPayloadV2 {
            unit_key_digest: self.unit_key_digest,
            guest_start: self.guest_start,
            ..LiveBlockPayloadV2::empty()
        };
        // SAFETY: this claim is the unique capability created by the successful
        // EMPTY -> BUILDING CAS, and it has not terminally published before.
        unsafe { self.record.write_building_payload(payload) };
        self.record
            .state
            .store(LIVE_BLOCK_FAILED, Ordering::Release);
        self.armed = false;
    }
}

impl Drop for LivePublishClaim<'_> {
    fn drop(&mut self) {
        if self.armed && self.record.state.load(Ordering::Acquire) == LIVE_BLOCK_BUILDING {
            self.publish_failed();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LiveWireLengths {
    code: u32,
    hot: u32,
    cold: u32,
}

impl LiveWireLengths {
    fn new(code_len: u64, hot_len: u64, cold_len: u64) -> Option<Self> {
        if code_len == 0
            || !code_len.is_multiple_of(LIVE_ARENA_INSTRUCTION_BYTES)
            || code_len > LIVE_ARENA_CHUNK_BYTES
        {
            return None;
        }
        Some(Self {
            code: u32::try_from(code_len).ok()?,
            hot: u32::try_from(hot_len).ok()?,
            cold: u32::try_from(cold_len).ok()?,
        })
    }
}

/// A unique BUILDING capability bound to exactly one successful append-only
/// reservation. Publication has no caller-supplied extent field: consuming
/// this value is the only way to publish the reservation it owns.
///
/// Safe caller-owned bytes are not publication authority:
///
/// ```compile_fail
/// use carrick_dsr_aarch64::live_arena::{
///     LiveBlockPublication, LiveReservedPublishClaim,
/// };
///
/// fn safe_caller_bytes_cannot_publish_ready(
///     claim: LiveReservedPublishClaim<'_>,
///     caller_publication: LiveBlockPublication,
/// ) {
///     let _ = claim.publish(caller_publication);
/// }
/// ```
pub struct LiveReservedPublishClaim<'a> {
    claim: LivePublishClaim<'a>,
    extents: LiveBlockExtents,
    wire_lengths: LiveWireLengths,
    write_attempted: bool,
}

impl<'a> LiveReservedPublishClaim<'a> {
    pub fn extents(&self) -> LiveBlockExtents {
        self.extents
    }

    pub fn belongs_to_process_view(&self, process_view: &LiveProcessViewBrand) -> bool {
        self.claim.process_view.same(process_view)
    }

    /// Consumes the exact certification token for this claim and performs the
    /// only production READY Release store.
    pub fn publish(
        mut self,
        written: LiveArenaWrittenBlock<'a>,
    ) -> Result<ValidatedLiveBlockRecord, LivePrivateReason> {
        let record = NonNull::from(self.claim.record);
        let expected_lengths = written.expected.lengths();
        let lengths_match_extents = written.extents.code.len
            == u64::from(written.wire_lengths.code)
            && written.extents.hot.len == u64::from(written.wire_lengths.hot)
            && written.extents.cold.len == u64::from(written.wire_lengths.cold);
        let Ok(chunk_index) = u32::try_from(self.extents.code.offset / LIVE_ARENA_CHUNK_BYTES)
        else {
            increment_saturating(&self.claim.arena.directory.private_fallbacks);
            self.claim.publish_failed();
            return Err(LivePrivateReason::InvalidRecord);
        };
        if self.claim.record.state.load(Ordering::Acquire) != LIVE_BLOCK_BUILDING
            || written.storage_brand != self.claim.arena.brand
            || !written.process_view.same(self.claim.process_view)
            || written.record != record
            || written.record_index != self.claim.record_index
            || written.extents != self.extents
            || written.wire_lengths != self.wire_lengths
            || written.unit_key_digest != self.claim.unit_key_digest
            || written.guest_start != self.claim.guest_start
            || written.translator_abi != TRANSLATOR_ABI_CURRENT
            || written.translator_abi != self.claim.arena.directory.translator_abi
            || expected_lengths.code != u64::from(written.wire_lengths.code)
            || expected_lengths.hot != u64::from(written.wire_lengths.hot)
            || expected_lengths.cold != u64::from(written.wire_lengths.cold)
            || written.code_sha256 != written.expected.code_sha256()
            || !valid_source_page(written.source_page, written.guest_start)
            || written.entry_offset >= written.wire_lengths.code
            || !written
                .entry_offset
                .is_multiple_of(LIVE_ARENA_INSTRUCTION_BYTES as u32)
            || !lengths_match_extents
        {
            increment_saturating(&self.claim.arena.directory.private_fallbacks);
            self.claim.publish_failed();
            return Err(LivePrivateReason::InvalidRecord);
        }
        let payload = LiveBlockPayloadV2 {
            unit_key_digest: written.unit_key_digest,
            code_sha256: written.code_sha256,
            guest_start: written.guest_start,
            source_page: written.source_page,
            code_offset: written.extents.code.offset,
            hot_offset: written.extents.hot.offset,
            cold_offset: written.extents.cold.offset,
            code_len: written.wire_lengths.code,
            entry_offset: written.entry_offset,
            hot_len: written.wire_lengths.hot,
            cold_len: written.wire_lengths.cold,
        };
        // SAFETY: this reserved claim is the unique BUILDING capability, and
        // every field above was rechecked against its private token.
        unsafe { self.claim.record.write_building_payload(payload) };
        #[cfg(test)]
        if let Some(after_payload_write_before_ready) =
            self.claim.arena.after_payload_write_before_ready
        {
            after_payload_write_before_ready();
        }
        if self.claim.generation.current() != CodeGeneration::INITIAL {
            increment_saturating(&self.claim.arena.directory.private_fallbacks);
            self.claim.publish_failed();
            return Err(LivePrivateReason::InvalidRecord);
        }
        self.claim
            .record
            .state
            .store(LIVE_BLOCK_READY, Ordering::Release);
        self.claim.armed = false;
        Ok(ValidatedLiveBlockRecord {
            record_index: self.claim.record_index,
            payload,
            extents: self.extents,
            group_slot: self.claim.group.slot,
            chunk_index,
            storage_identity: self.claim.arena.storage_identity(),
            process_view: Arc::clone(&self.claim.process_view.identity),
        })
    }

    /// Begins the sole mapped-write attempt for this reservation.
    ///
    /// # Safety
    ///
    /// The caller must be the process view that owns `self.claim.process_view`
    /// and must resolve every range exposed by the returned permit from this
    /// claim's exact mapped extents. A caller-owned allocation is not mapped
    /// arena storage and does not satisfy this contract.
    #[doc(hidden)]
    pub unsafe fn begin_mapped_write(
        &mut self,
    ) -> Result<LiveMappedWritePermit<'_, 'a>, LivePrivateReason> {
        if self.write_attempted {
            increment_saturating(&self.claim.arena.directory.private_fallbacks);
            return Err(LivePrivateReason::WriteAttempted);
        }
        self.write_attempted = true;
        if self.claim.generation.current() != CodeGeneration::INITIAL {
            increment_saturating(&self.claim.arena.directory.private_fallbacks);
            self.claim.publish_failed();
            return Err(LivePrivateReason::InvalidRecord);
        }
        Ok(LiveMappedWritePermit { claim: self })
    }

    pub fn fail(mut self) -> LivePrivateReason {
        if self.claim.record.state.load(Ordering::Acquire) != LIVE_BLOCK_BUILDING {
            increment_saturating(&self.claim.arena.directory.private_fallbacks);
            return LivePrivateReason::Failed;
        }
        increment_saturating(&self.claim.arena.directory.private_fallbacks);
        self.claim.publish_failed();
        LivePrivateReason::Failed
    }
}

/// Unique borrowed authority for the one mapped-write attempt owned by a
/// reserved claim. Dropping it never rearms the reservation.
///
/// ```compile_fail
/// use carrick_dsr_aarch64::live_arena::{
///     LiveMappedWritePermit, LiveReservedPublishClaim,
/// };
///
/// fn mapped_write_permit_cannot_escape_claim<'view>(
///     claim: &mut LiveReservedPublishClaim<'view>,
/// ) -> LiveMappedWritePermit<'static, 'view> {
///     // SAFETY: this deliberately tests only the borrow lifetime; no mapped
///     // range is accessed.
///     unsafe { claim.begin_mapped_write() }.unwrap()
/// }
/// ```
pub struct LiveMappedWritePermit<'claim, 'view> {
    claim: &'claim mut LiveReservedPublishClaim<'view>,
}

impl<'claim, 'view> LiveMappedWritePermit<'claim, 'view> {
    pub fn extents(&self) -> LiveBlockExtents {
        self.claim.extents
    }

    /// Certifies the exact mapped ranges written under this one-attempt permit.
    ///
    /// # Safety
    ///
    /// `expected` must come from the same post-prebinding
    /// [`crate::emit::PreparedSharedInitial`] that the caller has consumed
    /// exactly once into the exact claim-bound [`carrick_dsr::cache::TranslationCache`].
    /// That publication must prove the cache-used delta is exactly the claim's
    /// code length, use exactly its code extent, and perform the real host
    /// publisher I-cache flush. The caller must then drop the claim-bound cache
    /// and every emitted address-bearing value before entering certification.
    /// `code`, `hot`, and `cold` must be the complete, disjoint mapped arena
    /// ranges resolved from `self.extents()` by the same process view, with no
    /// mutable alias live.
    /// Caller-owned buffers and a no-op host JIT do not satisfy this production
    /// contract. Under `cfg(test)` only, the module's private fixture uses
    /// stable disjoint live allocations to model already-resolved ranges and
    /// exercise pure portable validation; it is never production mapped
    /// publication authority.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn certify_mapped(
        self,
        code: &[u8],
        hot: &[u8],
        cold: &[u8],
        source_page: GuestVa,
        entry_offset: u32,
        expected: ExpectedLivePublication,
    ) -> Result<LiveArenaWrittenBlock<'view>, LivePrivateReason> {
        // SAFETY: this forwards the caller's complete certification contract;
        // the production path has no test mutation hook.
        unsafe {
            self.certify_mapped_impl(code, hot, cold, source_page, entry_offset, expected, || {})
        }
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    unsafe fn certify_mapped_after_metadata_for_test(
        self,
        code: &[u8],
        hot: &[u8],
        cold: &[u8],
        source_page: GuestVa,
        entry_offset: u32,
        expected: ExpectedLivePublication,
        after_metadata_validation: impl FnOnce(),
    ) -> Result<LiveArenaWrittenBlock<'view>, LivePrivateReason> {
        // SAFETY: this test-only entry preserves the portable range/proof
        // contract and adds only a deterministic event between metadata
        // validation and the final completion phase.
        unsafe {
            self.certify_mapped_impl(
                code,
                hot,
                cold,
                source_page,
                entry_offset,
                expected,
                after_metadata_validation,
            )
        }
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn certify_mapped_impl(
        self,
        code: &[u8],
        hot: &[u8],
        cold: &[u8],
        source_page: GuestVa,
        entry_offset: u32,
        expected: ExpectedLivePublication,
        after_metadata_validation: impl FnOnce(),
    ) -> Result<LiveArenaWrittenBlock<'view>, LivePrivateReason> {
        let generation = &self.claim.claim.generation;
        let expected_lengths = expected.lengths();
        if usize::try_from(expected_lengths.code) != Ok(code.len())
            || usize::try_from(expected_lengths.hot) != Ok(hot.len())
            || usize::try_from(expected_lengths.cold) != Ok(cold.len())
            || expected_lengths.code != u64::from(self.claim.wire_lengths.code)
            || expected_lengths.hot != u64::from(self.claim.wire_lengths.hot)
            || expected_lengths.cold != u64::from(self.claim.wire_lengths.cold)
            || !expected.matches(code, hot, cold)
            || source_page != generation.page()
            || !valid_source_page(source_page.raw(), self.claim.claim.guest_start)
            || generation.expected() != CodeGeneration::INITIAL
            || generation.current() != CodeGeneration::INITIAL
            || !entry_offset.is_multiple_of(LIVE_ARENA_INSTRUCTION_BYTES as u32)
            || entry_offset >= self.claim.wire_lengths.code
        {
            return Err(LivePrivateReason::InvalidRecord);
        }
        validate_shared_initial_metadata(hot, cold, self.claim.wire_lengths.code)
            .map_err(|_| LivePrivateReason::InvalidRecord)?;
        after_metadata_validation();
        if generation.current() != CodeGeneration::INITIAL {
            return Err(LivePrivateReason::InvalidRecord);
        }
        let code_sha256 = expected.code_sha256();
        Ok(LiveArenaWrittenBlock {
            storage_brand: self.claim.claim.arena.brand,
            process_view: self.claim.claim.process_view,
            record: NonNull::from(self.claim.claim.record),
            record_index: self.claim.claim.record_index,
            extents: self.claim.extents,
            wire_lengths: self.claim.wire_lengths,
            unit_key_digest: self.claim.claim.unit_key_digest,
            guest_start: self.claim.claim.guest_start,
            source_page: source_page.raw(),
            entry_offset,
            translator_abi: TRANSLATOR_ABI_CURRENT,
            code_sha256,
            expected,
        })
    }
}

/// Non-cloneable completion authority for one exact mapped write. Only the
/// permit certification seam can construct it.
///
/// ```compile_fail
/// use carrick_dsr_aarch64::live_arena::LiveArenaWrittenBlock;
///
/// fn written_block_cannot_escape_process_view_lifetime<'view>(
///     written: LiveArenaWrittenBlock<'view>,
/// ) -> LiveArenaWrittenBlock<'static> {
///     written
/// }
/// ```
pub struct LiveArenaWrittenBlock<'view> {
    storage_brand: LiveArenaViewBrand,
    process_view: &'view LiveProcessViewBrand,
    record: NonNull<LiveBlockRecordV2>,
    record_index: u32,
    extents: LiveBlockExtents,
    wire_lengths: LiveWireLengths,
    unit_key_digest: [u8; 32],
    guest_start: u64,
    source_page: u64,
    entry_offset: u32,
    translator_abi: u32,
    code_sha256: [u8; 32],
    expected: ExpectedLivePublication,
}

/// Copied READY record containing only shared offsets and opaque identities.
/// It owns no record payload reference and no process-local executable address.
pub struct ValidatedLiveBlockRecord {
    record_index: u32,
    payload: LiveBlockPayloadV2,
    extents: LiveBlockExtents,
    group_slot: u32,
    chunk_index: u32,
    storage_identity: LiveArenaStorageIdentity,
    process_view: Arc<LiveProcessViewIdentity>,
}

impl ValidatedLiveBlockRecord {
    pub fn unit_key_digest(&self) -> [u8; 32] {
        self.payload.unit_key_digest
    }

    pub fn guest_start(&self) -> u64 {
        self.payload.guest_start
    }

    pub fn source_page(&self) -> u64 {
        self.payload.source_page
    }

    pub fn extents(&self) -> LiveBlockExtents {
        self.extents
    }

    pub fn entry_offset(&self) -> u32 {
        self.payload.entry_offset
    }

    pub fn code_sha256(&self) -> [u8; 32] {
        self.payload.code_sha256
    }

    pub const fn record_index(&self) -> u32 {
        self.record_index
    }

    pub const fn group_slot(&self) -> u32 {
        self.group_slot
    }

    pub const fn chunk_index(&self) -> u32 {
        self.chunk_index
    }

    #[cfg(test)]
    fn record_snapshot(&self) -> LiveRecordSnapshot {
        LiveRecordSnapshot {
            state: LIVE_BLOCK_READY,
            unit_key_digest: self.payload.unit_key_digest,
            guest_start: self.payload.guest_start,
            source_page: self.payload.source_page,
            extents: self.extents,
            entry_offset: self.payload.entry_offset,
            code_sha256: self.payload.code_sha256,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LiveRecordSnapshot {
    state: u32,
    unit_key_digest: [u8; 32],
    guest_start: u64,
    source_page: u64,
    extents: LiveBlockExtents,
    entry_offset: u32,
    code_sha256: [u8; 32],
}

fn initial_slot(unit_key_digest: &[u8; 32], guest_start: u64) -> usize {
    let mut digest = Sha256::new();
    digest.update(b"carrick-live-block-v2");
    digest.update(unit_key_digest);
    digest.update(guest_start.to_le_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    let mut low_bytes = [0_u8; 8];
    low_bytes.copy_from_slice(&bytes[..8]);
    let low = u64::from_le_bytes(low_bytes);
    (low as usize) & LIVE_BLOCK_MASK
}

fn initial_group_slot(unit_key_digest: &[u8; 32], source_page: u64) -> usize {
    let mut digest = Sha256::new();
    digest.update(b"carrick-live-group-v2");
    digest.update(unit_key_digest);
    digest.update(source_page.to_le_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    let mut low_bytes = [0_u8; 8];
    low_bytes.copy_from_slice(&bytes[..8]);
    let low = u64::from_le_bytes(low_bytes);
    (low as usize) & LIVE_GROUP_MASK
}

fn record_matches(payload: &LiveBlockPayloadV2, key: &[u8; 32], guest_start: u64) -> bool {
    payload.unit_key_digest == *key && payload.guest_start == guest_start
}

fn valid_source_page(source_page: u64, guest_start: u64) -> bool {
    source_page.is_multiple_of(LIVE_SOURCE_PAGE_BYTES)
        && guest_start.is_multiple_of(LIVE_ARENA_INSTRUCTION_BYTES)
        && source_page == guest_start / LIVE_SOURCE_PAGE_BYTES * LIVE_SOURCE_PAGE_BYTES
}

fn valid_code_extent(extent: LiveReservation) -> bool {
    let Some(end) = extent.end() else {
        return false;
    };
    extent.offset.is_multiple_of(LIVE_ARENA_INSTRUCTION_BYTES)
        && extent.len != 0
        && extent.len.is_multiple_of(LIVE_ARENA_INSTRUCTION_BYTES)
        && extent.len <= LIVE_ARENA_CHUNK_BYTES
        && extent.offset / LIVE_ARENA_CHUNK_BYTES == (end - 1) / LIVE_ARENA_CHUNK_BYTES
}

fn valid_metadata_extent(extent: LiveReservation) -> bool {
    extent.offset.is_multiple_of(LIVE_ARENA_METADATA_ALIGN) && extent.len <= u64::from(u32::MAX)
}

fn extent_in_capacity(extent: LiveReservation, capacity: u64) -> bool {
    extent.end().is_some_and(|end| end <= capacity)
}

enum BoundedReservation {
    Reserved(LiveReservation),
    Full,
    Contended,
}

fn reserve_append_bounded(
    cursor: &AtomicU64,
    capacity: u64,
    len: u64,
    alignment: u64,
) -> Option<LiveReservation> {
    match reserve_append_bounded_result(cursor, capacity, len, alignment) {
        BoundedReservation::Reserved(reservation) => Some(reservation),
        BoundedReservation::Full | BoundedReservation::Contended => None,
    }
}

fn reserve_append_bounded_result(
    cursor: &AtomicU64,
    capacity: u64,
    len: u64,
    alignment: u64,
) -> BoundedReservation {
    reserve_append_bounded_result_impl(cursor, capacity, len, alignment, |_| {})
}

fn reserve_append_bounded_result_impl(
    cursor: &AtomicU64,
    capacity: u64,
    len: u64,
    alignment: u64,
    mut before_compare: impl FnMut(&AtomicU64),
) -> BoundedReservation {
    let mut current = cursor.load(Ordering::Acquire);
    for _ in 0..LIVE_CURSOR_CAS_ATTEMPTS {
        let Some(offset) = align_up(current, alignment) else {
            return BoundedReservation::Full;
        };
        let Some(end) = offset.checked_add(len) else {
            return BoundedReservation::Full;
        };
        if end > capacity {
            return BoundedReservation::Full;
        }
        before_compare(cursor);
        match cursor.compare_exchange_weak(current, end, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return BoundedReservation::Reserved(LiveReservation { offset, len }),
            Err(observed) => current = observed,
        }
    }
    BoundedReservation::Contended
}

fn increment_saturating(counter: &AtomicU64) {
    increment_saturating_impl(counter, || {});
}

fn increment_saturating_impl(counter: &AtomicU64, after_atomic_update: impl FnOnce()) {
    // Diagnostic counters are not cursor/allocation authority: retry inside
    // `fetch_update` is permitted here, while every allocation cursor remains
    // on its literal eight-CAS bounded helper. `checked_add` returns `None` at
    // MAX, so no atomic step can expose a transient wrapped value even if the
    // process dies immediately after this operation.
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        current.checked_add(1)
    });
    after_atomic_update();
}

fn expansion_owner(owner_pid: i32) -> u64 {
    (u64::from(owner_pid as u32) << 32) | 1
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    let remainder = value % alignment;
    value.checked_add((alignment - remainder) % alignment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockPlan, PlannedExit, PlannedInst};
    use crate::emit::{EmitAddressMode, PreparedSharedInitial, prepare_shared_initial};
    use crate::shared_cache::{
        AddressModeIdentity, ExecutableIdentity, GuestCodeLen, ImageFileLen, ImageFileOffset,
        NativePageProfileIdentity, SourceFingerprint, TranslationUnitKey,
    };
    use crate::types::{CodeGeneration, InstAction};
    use carrick_dsr::cache::PageGenerationTable;
    use carrick_guest_mem::GuestVa;
    use std::ptr::NonNull;
    use std::sync::{Arc, Barrier};

    struct RawControlStorage {
        bytes: Vec<u8>,
        base: NonNull<u8>,
        len: usize,
    }

    impl RawControlStorage {
        fn new(len: usize) -> Self {
            let mut bytes = vec![0_u8; len + 63];
            let unaligned = bytes.as_mut_ptr() as usize;
            let aligned = (unaligned + 63) & !63;
            Self {
                bytes,
                base: NonNull::new(aligned as *mut u8).expect("aligned storage base"),
                len,
            }
        }

        fn initialize(
            &self,
            layout: LiveArenaControlLayout,
            nonce: [u8; 16],
        ) -> LiveTranslationArenaView<'_> {
            let _keep_allocation_alive = &self.bytes;
            // SAFETY: this fixture owns `len` writable bytes at a 64-byte-aligned
            // address for the returned view's complete lifetime.
            unsafe {
                LiveTranslationArenaView::initialize_in_place(self.base, self.len, layout, nonce)
            }
            .expect("initialize mapped protocol storage")
        }

        fn adopt(
            &self,
            layout: LiveArenaControlLayout,
            nonce: [u8; 16],
        ) -> LiveTranslationArenaView<'_> {
            let _keep_allocation_alive = &self.bytes;
            // SAFETY: initialization completed through the protocol initializer,
            // and this allocation remains live and shared for the view lifetime.
            unsafe { LiveTranslationArenaView::adopt_in_place(self.base, self.len, layout, nonce) }
                .expect("adopt mapped protocol storage")
        }
    }

    const PAGE: u64 = 16 * 1024;

    #[test]
    fn v2_block_record_is_exactly_128_bytes_with_literal_offsets() {
        // Catches retaining the 192-byte legacy payload wrapper or reordering any
        // immutable V2 wire field. The expected map is hand-checked from the
        // approved protocol; it does not reuse a layout helper under test.
        let payload = std::mem::offset_of!(LiveBlockRecordV2, payload);
        let actual = [
            std::mem::size_of::<LiveBlockRecordV2>(),
            std::mem::align_of::<LiveBlockRecordV2>(),
            std::mem::offset_of!(LiveBlockRecordV2, state),
            std::mem::offset_of!(LiveBlockRecordV2, owner_pid),
            payload + std::mem::offset_of!(LiveBlockPayloadV2, unit_key_digest),
            payload + std::mem::offset_of!(LiveBlockPayloadV2, code_sha256),
            payload + std::mem::offset_of!(LiveBlockPayloadV2, guest_start),
            payload + std::mem::offset_of!(LiveBlockPayloadV2, source_page),
            payload + std::mem::offset_of!(LiveBlockPayloadV2, code_offset),
            payload + std::mem::offset_of!(LiveBlockPayloadV2, hot_offset),
            payload + std::mem::offset_of!(LiveBlockPayloadV2, cold_offset),
            payload + std::mem::offset_of!(LiveBlockPayloadV2, code_len),
            payload + std::mem::offset_of!(LiveBlockPayloadV2, entry_offset),
            payload + std::mem::offset_of!(LiveBlockPayloadV2, hot_len),
            payload + std::mem::offset_of!(LiveBlockPayloadV2, cold_len),
        ];

        assert_eq!(
            actual,
            [
                128, 64, 0, 4, 8, 40, 72, 80, 88, 96, 104, 112, 116, 120, 124
            ]
        );
    }

    #[test]
    fn v2_canonical_geometry_uses_literal_block_group_chunk_capacities() {
        // Catches retaining the legacy 131,072 x 192-byte block table or treating
        // a 16 KiB page as the V2 allocation unit. Every expected value is a
        // literal from the approved V2 geometry, independent of the layout.
        let layout = LiveArenaControlLayout::new(
            LiveArenaCapacities::new(67_108_864, 1_048_576, 33_554_432),
            16_384,
        )
        .expect("V2 literal capacities must form a checked layout");
        let actual = [
            layout.capacities().code,
            layout.capacities().hot,
            layout.capacities().cold,
            LIVE_ARENA_BLOCK_RECORDS as u64,
            std::mem::size_of::<LiveBlockRecordV2>() as u64,
            layout.block_records_len() as u64,
            LIVE_ARENA_CHUNK_BYTES,
            layout.capacities().code / 65_536,
        ];

        assert_eq!(
            actual,
            [
                67_108_864, // 1,024 exclusive 64 KiB chunks
                1_048_576, 33_554_432, 262_144, // block records
                128,     // block stride
                33_554_432, 65_536, // chunk size
                1_024,  // chunk descriptors
            ],
            "the V2 directory must additionally authenticate 4,096 source-group records",
        );
    }

    #[test]
    fn v2_read_only_empty_lookup_never_claims_block_state() {
        // Catches an EMPTY fast-path lookup performing the old
        // EMPTY -> BUILDING CAS before decode/eligibility proof.
        let arena = arena();
        let key = key();
        let digest = key.live_digest().expect("live digest");
        let slot = initial_slot(&digest, key.guest_va_start().raw());
        let view = arena.view();
        let before_state = view.block_records[slot].state.load(Ordering::Acquire);
        let before_cursors = view.cursor_snapshot();

        let lookup = view.acquire_ready_or_miss(&arena.process_view, &key, key.guest_va_start());
        let returned_publish = !matches!(&lookup, LiveReadyLookup::Miss);
        let after_state = view.block_records[slot].state.load(Ordering::Acquire);
        let after_cursors = view.cursor_snapshot();

        assert_eq!(
            (returned_publish, before_state, after_state, after_cursors),
            (false, LIVE_BLOCK_EMPTY, LIVE_BLOCK_EMPTY, before_cursors),
        );
    }

    #[test]
    fn v2_block_hash_uses_domain_separated_low_u64_literal_slot() {
        // Catches omitting the V2 domain or truncating the SHA-256 output to a
        // u32. Independent SHA-256 and OpenSSL calculations give slot 34,187.
        let digest = [0_u8; 32];

        assert_eq!(initial_slot(&digest, 0), 34_187);
    }

    #[test]
    fn v2_source_groups_pack_within_exclusive_64k_chunks() {
        // Catches preserving the per-block 16 KiB allocator, sharing one 64
        // KiB chunk across exact source groups, or overlapping packed blocks.
        let arena = LiveTranslationArena::new(3 * 65_536, 32, 32);
        let make_key = |executable_byte| {
            TranslationUnitKey::for_segment(
                ExecutableIdentity::Digest([executable_byte; 32]),
                ImageFileOffset::new(0),
                ImageFileLen::new(2 * PAGE).expect("two-page file length"),
                GuestVa(0x4000_0000),
                GuestCodeLen::new(2 * PAGE).expect("two-page guest length"),
                SourceFingerprint([0x7a; 32]),
                NativePageProfileIdentity::Native16k,
                AddressModeIdentity::Direct,
            )
        };
        let first_key = make_key(0x42);
        let other_digest_key = make_key(0x43);
        let first_guest = GuestVa(0x4000_0000);
        let same_group_guest = GuestVa(0x4000_0004);
        let other_digest_guest = GuestVa(0x4000_0008);
        let other_page_guest = GuestVa(0x4000_4000);

        let LiveLookup::Publish(claim) = arena.claim_eligible(&first_key, first_guest, 81) else {
            panic!("first exact group must claim an empty block");
        };
        let first = claim.reserve(8, 8, 8).expect("first block fits").extents();
        let LiveLookup::Publish(claim) = arena.claim_eligible(&first_key, same_group_guest, 82)
        else {
            panic!("second block in the same exact group must claim");
        };
        let same_group = claim
            .reserve(8, 8, 8)
            .expect("same-group block fits")
            .extents();
        let LiveLookup::Publish(claim) =
            arena.claim_eligible(&other_digest_key, other_digest_guest, 83)
        else {
            panic!("different-digest group must claim");
        };
        let other_digest = claim
            .reserve(8, 8, 8)
            .expect("different-digest block fits")
            .extents();
        let LiveLookup::Publish(claim) = arena.claim_eligible(&first_key, other_page_guest, 84)
        else {
            panic!("different-source-page group must claim");
        };
        let other_page = claim
            .reserve(8, 8, 8)
            .expect("different-page block fits")
            .extents();

        assert_eq!(
            [
                first.code.offset,
                same_group.code.offset,
                first.code.offset / 65_536,
                same_group.code.offset / 65_536,
                other_digest.code.offset / 65_536,
                other_page.code.offset / 65_536,
            ],
            [0, 8, 0, 0, 1, 2],
        );
    }

    #[test]
    fn v2_generation_drift_before_eligible_claim_mutates_no_shared_protocol_state() {
        // Catches treating a once-INITIAL observation as permanent authority.
        // The mutation happens before claim_eligible, so even group creation is
        // forbidden; the diagnostic fallback counter is the only allowed write.
        let arena = arena();
        let key = key();
        let guest = key.guest_va_start();
        let digest = key.live_digest().expect("live digest");
        let block_slot = initial_slot(&digest, guest.raw());
        let group_slot = initial_group_slot(&digest, guest.raw());
        let observation = arena
            .generations
            .observe(guest)
            .expect("INITIAL observation");
        arena
            .generations
            .note_guest_code_write(guest..GuestVa(guest.raw() + 4))
            .expect("advance authoritative generation");
        let before = arena.view().cursor_snapshot();

        let lookup = arena.view().claim_eligible(
            &arena.process_view,
            &key,
            guest,
            GuestVa(guest.raw() + 4),
            &observation,
            501,
        );
        let view = arena.view();
        let after = view.cursor_snapshot();

        assert_eq!(
            lookup.private_reason(),
            Some(LivePrivateReason::InvalidRecord)
        );
        assert_eq!(
            view.block_records[block_slot].state.load(Ordering::Acquire),
            LIVE_BLOCK_EMPTY
        );
        assert_eq!(
            view.source_groups[group_slot].state.load(Ordering::Acquire),
            LIVE_GROUP_EMPTY
        );
        assert!(
            view.chunk_descriptors
                .iter()
                .all(|descriptor| { descriptor.state.load(Ordering::Acquire) == LIVE_CHUNK_EMPTY })
        );
        assert_eq!((after.next_chunk, after.hot, after.cold), (0, 0, 0));
        assert_eq!(after.private_fallbacks, before.private_fallbacks + 1);
    }

    #[test]
    fn v2_foreign_domain_wrong_page_and_cross_page_claims_mutate_nothing() {
        // Catches accepting a valid INITIAL observation from another domain,
        // from another page in the same domain, or for a decoded interval that
        // crosses the exact 16 KiB source-page boundary.
        let arena = arena();
        let key = key();
        let guest = key.guest_va_start();
        let foreign = PageGenerationTable::new(PAGE).expect("foreign generation table");
        let foreign_observation = foreign.observe(guest).expect("foreign INITIAL observation");
        let wrong_page_observation = arena
            .generations
            .observe(GuestVa(guest.raw() + PAGE))
            .expect("same-domain wrong-page observation");
        let cross_start = GuestVa(guest.raw() + PAGE - 4);
        let cross_observation = arena
            .generations
            .observe(cross_start)
            .expect("cross-page source observation");

        for (start, end, observation) in [
            (guest, GuestVa(guest.raw() + 4), &foreign_observation),
            (guest, GuestVa(guest.raw() + 4), &wrong_page_observation),
            (
                cross_start,
                GuestVa(cross_start.raw() + 8),
                &cross_observation,
            ),
        ] {
            let before = arena.view().cursor_snapshot();
            let lookup = arena.view().claim_eligible(
                &arena.process_view,
                &key,
                start,
                end,
                observation,
                502,
            );
            let after = arena.view().cursor_snapshot();
            assert_eq!(
                lookup.private_reason(),
                Some(LivePrivateReason::InvalidRecord)
            );
            assert_eq!((after.next_chunk, after.hot, after.cold), (0, 0, 0));
            assert_eq!(after.private_fallbacks, before.private_fallbacks + 1);
        }

        let view = arena.view();
        assert!(
            view.block_records
                .iter()
                .all(|record| { record.state.load(Ordering::Acquire) == LIVE_BLOCK_EMPTY })
        );
        assert!(
            view.source_groups
                .iter()
                .all(|group| { group.state.load(Ordering::Acquire) == LIVE_GROUP_EMPTY })
        );
        assert!(
            view.chunk_descriptors
                .iter()
                .all(|descriptor| { descriptor.state.load(Ordering::Acquire) == LIVE_CHUNK_EMPTY })
        );
    }

    #[test]
    fn v2_generation_drift_after_group_resolution_performs_no_block_cas() {
        // Catches moving the second generation recheck after the block CAS.
        // Group ACTIVE/NO_CHUNK is allowed, but the exact block must stay EMPTY
        // and no chunk may be allocated.
        let mut arena = arena();
        let key = key();
        let guest = key.guest_va_start();
        let digest = key.live_digest().expect("live digest");
        let block_slot = initial_slot(&digest, guest.raw());
        let group_slot = initial_group_slot(&digest, guest.raw());
        let generations = Arc::new(PageGenerationTable::new(PAGE).expect("generation table"));
        let process_view = LiveProcessViewBrand::new(generations.domain());
        let observation = generations.observe(guest).expect("INITIAL observation");
        let mutate = Arc::clone(&generations);
        arena.after_group_resolution = Some(Arc::new(move || {
            mutate
                .note_guest_code_write(guest..GuestVa(guest.raw() + 4))
                .expect("advance generation after group resolution");
        }));

        let lookup = arena.view().claim_eligible(
            &process_view,
            &key,
            guest,
            GuestVa(guest.raw() + 4),
            &observation,
            503,
        );
        let view = arena.view();

        assert_eq!(
            lookup.private_reason(),
            Some(LivePrivateReason::InvalidRecord)
        );
        assert_eq!(
            view.block_records[block_slot].state.load(Ordering::Acquire),
            LIVE_BLOCK_EMPTY
        );
        let group = &view.source_groups[group_slot];
        assert_eq!(group.state.load(Ordering::Acquire), LIVE_GROUP_ACTIVE);
        assert_eq!(
            group.current_chunk.load(Ordering::Acquire),
            LIVE_GROUP_NO_CHUNK
        );
        assert_eq!(view.next_chunk.load(Ordering::Acquire), 0);
        assert!(
            view.chunk_descriptors
                .iter()
                .all(|descriptor| { descriptor.state.load(Ordering::Acquire) == LIVE_CHUNK_EMPTY })
        );
    }

    #[test]
    fn v2_generation_drift_inside_empty_branch_performs_no_block_cas() {
        let arena = arena();
        let key = key();
        let guest = key.guest_va_start();
        let digest = key.live_digest().expect("live digest");
        let block_slot = initial_slot(&digest, guest.raw());
        let group_slot = initial_group_slot(&digest, guest.raw());
        let observation = arena
            .generations
            .observe(guest)
            .expect("INITIAL observation");
        let mutate = || {
            arena
                .generations
                .note_guest_code_write(guest..GuestVa(guest.raw() + 4))
                .expect("advance generation immediately before block CAS");
        };
        let mut view = arena.view();
        view.before_block_cas = Some(&mutate);

        let lookup = view.claim_eligible(
            &arena.process_view,
            &key,
            guest,
            GuestVa(guest.raw() + 4),
            &observation,
            504,
        );

        assert_eq!(
            lookup.private_reason(),
            Some(LivePrivateReason::InvalidRecord)
        );
        assert_eq!(
            view.block_records[block_slot].state.load(Ordering::Acquire),
            LIVE_BLOCK_EMPTY
        );
        assert_eq!(
            view.source_groups[group_slot].state.load(Ordering::Acquire),
            LIVE_GROUP_ACTIVE
        );
        assert_eq!(view.next_chunk.load(Ordering::Acquire), 0);
    }

    #[test]
    fn v2_refreshed_full_allocates_but_contended_or_invalid_falls_back() {
        // Catches treating every non-Reserved refreshed-current result as Full.
        // Only Full may allocate a successor; Contended and Invalid must clear
        // expansion and fail the unique block without claiming another chunk.
        for forced in [
            None,
            Some(ForcedChunkOutcome::Contended),
            Some(ForcedChunkOutcome::Invalid),
        ] {
            let mut arena = LiveTranslationArena::new(3 * LIVE_ARENA_CHUNK_BYTES, 64, 64);
            arena.refreshed_chunk_for_test = Some((1, LIVE_ARENA_CHUNK_BYTES));
            arena.forced_chunk_outcome_for_test = forced.map(|outcome| (1, outcome));
            let key = key();
            let guest = key.guest_va_start();
            let digest = key.live_digest().expect("live digest");
            let group_slot = initial_group_slot(&digest, guest.raw());
            let block_slot = initial_slot(&digest, guest.raw());
            let LiveLookup::Publish(claim) = arena.claim_eligible(&key, guest, 601) else {
                panic!("eligible block must win its unique claim");
            };
            {
                let view = arena.view();
                let group = &view.source_groups[group_slot];
                let descriptor = &view.chunk_descriptors[0];
                descriptor
                    .owner_group
                    .store(group_slot as u32, Ordering::Relaxed);
                descriptor
                    .cursor
                    .store(LIVE_ARENA_CHUNK_BYTES, Ordering::Relaxed);
                descriptor.state.store(LIVE_CHUNK_ACTIVE, Ordering::Release);
                group.current_chunk.store(0, Ordering::Release);
                view.next_chunk.store(1, Ordering::Release);
            }

            let result = claim.reserve(8, 8, 8);
            let view = arena.view();
            let group = &view.source_groups[group_slot];
            assert_eq!(group.expansion.load(Ordering::Acquire), LIVE_EXPANSION_FREE);
            match forced {
                None => {
                    let reserved = result.expect("refreshed Full must allocate a successor");
                    assert_eq!(reserved.extents().code.offset, 2 * LIVE_ARENA_CHUNK_BYTES);
                    assert_eq!(group.current_chunk.load(Ordering::Acquire), 2);
                    assert_eq!(view.next_chunk.load(Ordering::Acquire), 3);
                    assert_eq!(
                        view.chunk_descriptors[2].state.load(Ordering::Acquire),
                        LIVE_CHUNK_ACTIVE
                    );
                }
                Some(_) => {
                    assert!(matches!(result, Err(LivePrivateReason::Capacity)));
                    assert_eq!(group.current_chunk.load(Ordering::Acquire), 1);
                    assert_eq!(view.next_chunk.load(Ordering::Acquire), 2);
                    assert_eq!(
                        view.chunk_descriptors[2].state.load(Ordering::Acquire),
                        LIVE_CHUNK_EMPTY
                    );
                    assert_eq!(
                        view.block_records[block_slot].state.load(Ordering::Acquire),
                        LIVE_BLOCK_FAILED
                    );
                }
            }
        }
    }

    #[test]
    fn v2_unexpected_nonempty_descriptor_is_never_overwritten_abandoned() {
        // Catches converting a descriptor owned by another terminal history
        // into ABANDONED merely because next_chunk pointed at it.
        let arena = LiveTranslationArena::new(LIVE_ARENA_CHUNK_BYTES, 64, 64);
        let key = key();
        let guest = key.guest_va_start();
        let digest = key.live_digest().expect("live digest");
        let group_slot = initial_group_slot(&digest, guest.raw());
        let block_slot = initial_slot(&digest, guest.raw());
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, guest, 602) else {
            panic!("eligible block must win its unique claim");
        };
        {
            let view = arena.view();
            let descriptor = &view.chunk_descriptors[0];
            descriptor.owner_group.store(77, Ordering::Relaxed);
            descriptor.cursor.store(123, Ordering::Relaxed);
            descriptor.state.store(LIVE_CHUNK_ACTIVE, Ordering::Release);
        }

        assert!(matches!(
            claim.reserve(8, 8, 8),
            Err(LivePrivateReason::Capacity)
        ));
        let view = arena.view();
        let descriptor = &view.chunk_descriptors[0];
        assert_eq!(descriptor.state.load(Ordering::Acquire), LIVE_CHUNK_ACTIVE);
        assert_eq!(descriptor.owner_group.load(Ordering::Acquire), 77);
        assert_eq!(descriptor.cursor.load(Ordering::Acquire), 123);
        assert_eq!(
            view.source_groups[group_slot]
                .current_chunk
                .load(Ordering::Acquire),
            LIVE_GROUP_NO_CHUNK
        );
        assert_eq!(
            view.source_groups[group_slot]
                .expansion
                .load(Ordering::Acquire),
            LIVE_EXPANSION_FREE
        );
        assert_eq!(
            view.block_records[block_slot].state.load(Ordering::Acquire),
            LIVE_BLOCK_FAILED
        );
        assert_eq!(view.directory.leaked_chunks.load(Ordering::Acquire), 0);
    }

    #[test]
    fn v2_handled_post_index_failure_abandons_only_new_descriptor() {
        // Catches clearing expansion without first making the newly allocated
        // descriptor terminal, or publishing it as current despite failure.
        let mut arena = LiveTranslationArena::new(LIVE_ARENA_CHUNK_BYTES, 64, 64);
        arena.fail_after_chunk_index = true;
        let key = key();
        let guest = key.guest_va_start();
        let digest = key.live_digest().expect("live digest");
        let group_slot = initial_group_slot(&digest, guest.raw());
        let block_slot = initial_slot(&digest, guest.raw());
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, guest, 603) else {
            panic!("eligible block must win its unique claim");
        };

        assert!(matches!(
            claim.reserve(8, 8, 8),
            Err(LivePrivateReason::Capacity)
        ));
        let view = arena.view();
        let group = &view.source_groups[group_slot];
        assert_eq!(view.next_chunk.load(Ordering::Acquire), 1);
        assert_eq!(
            view.chunk_descriptors[0].state.load(Ordering::Acquire),
            LIVE_CHUNK_ABANDONED
        );
        assert_eq!(
            group.current_chunk.load(Ordering::Acquire),
            LIVE_GROUP_NO_CHUNK
        );
        assert_eq!(group.expansion.load(Ordering::Acquire), LIVE_EXPANSION_FREE);
        assert_eq!(
            view.block_records[block_slot].state.load(Ordering::Acquire),
            LIVE_BLOCK_FAILED
        );
        assert_eq!(view.directory.leaked_chunks.load(Ordering::Acquire), 1);
    }

    #[test]
    fn v2_acquired_identity_and_descriptor_scan_cover_later_chunks_and_digests() {
        // Catches deriving revocation authority from a stale process-local hint
        // or only from the acquired block's current group. The descriptor table
        // must reveal a later chunk and another exact digest for the same page.
        let arena = LiveTranslationArena::new(4 * LIVE_ARENA_CHUNK_BYTES, 64, 64);
        let first_key = key();
        let second_key = TranslationUnitKey::for_segment(
            ExecutableIdentity::Digest([0x43; 32]),
            ImageFileOffset::new(0),
            ImageFileLen::new(PAGE * 64).expect("nonzero file length"),
            first_key.guest_va_start(),
            GuestCodeLen::new(PAGE * 64).expect("nonzero guest length"),
            SourceFingerprint([0x7a; 32]),
            NativePageProfileIdentity::Native16k,
            AddressModeIdentity::Direct,
        );
        let page = first_key.guest_va_start().raw();
        let other_page = page + PAGE;
        let first_digest = first_key.live_digest().expect("first digest");
        let second_digest = second_key.live_digest().expect("second digest");
        let first_group = initial_group_slot(&first_digest, page);
        let second_group = initial_group_slot(&second_digest, page);
        let other_page_group = initial_group_slot(&first_digest, other_page);
        assert_ne!(first_group, second_group, "fixture groups must not collide");
        assert_ne!(
            first_group, other_page_group,
            "fixture pages must not collide"
        );
        assert_ne!(
            second_group, other_page_group,
            "fixture groups must not collide"
        );

        let view = arena.view();
        seed_active_group_and_chunk(view, first_digest, page, 0, 8);
        let first_scan = view.active_chunks_for_source_page(page);
        assert_eq!(first_scan.len(), 1);

        // A later cross-process expansion for the same group is authoritative
        // even though an earlier scan could not have cached it.
        seed_active_group_and_chunk(view, first_digest, page, 1, 8);
        seed_active_group_and_chunk(view, second_digest, page, 2, 8);
        seed_active_group_and_chunk(view, first_digest, other_page, 3, 8);

        let guest = first_key.guest_va_start();
        let record_slot = initial_slot(&first_digest, guest.raw());
        let payload = LiveBlockPayloadV2 {
            unit_key_digest: first_digest,
            code_sha256: [0x5a; 32],
            guest_start: guest.raw(),
            source_page: page,
            code_offset: LIVE_ARENA_CHUNK_BYTES,
            hot_offset: 0,
            cold_offset: 0,
            code_len: 8,
            entry_offset: 4,
            hot_len: 8,
            cold_len: 8,
        };
        unsafe { view.block_records[record_slot].write_building_payload(payload) };
        view.block_records[record_slot]
            .state
            .store(LIVE_BLOCK_READY, Ordering::Release);
        let LiveReadyLookup::Ready(ready) =
            view.acquire_ready_or_miss(&arena.process_view, &first_key, guest)
        else {
            panic!("structurally valid packed READY must acquire");
        };

        assert_eq!(ready.group_slot(), first_group as u32);
        assert_eq!(ready.chunk_index(), 1);
        let scan = view.active_chunks_for_source_page(page);
        assert_eq!(
            scan,
            vec![
                LiveOwnedChunkIdentity {
                    group_slot: first_group as u32,
                    chunk_index: 0,
                    unit_key_digest: first_digest,
                    source_page: page,
                },
                LiveOwnedChunkIdentity {
                    group_slot: first_group as u32,
                    chunk_index: 1,
                    unit_key_digest: first_digest,
                    source_page: page,
                },
                LiveOwnedChunkIdentity {
                    group_slot: second_group as u32,
                    chunk_index: 2,
                    unit_key_digest: second_digest,
                    source_page: page,
                },
            ]
        );
        assert!(scan.iter().all(|identity| identity.source_page == page));
    }

    #[test]
    fn v2_adoption_rejects_literal_directory_corruption_classes() {
        // Catches authenticating only capacities while trusting attacker-owned
        // table geometry, cursor positions, strides, schema, or reserved bits.
        fn rejected(mutate: impl FnOnce(&mut LiveArenaControlDirectoryV2)) {
            let layout = LiveArenaControlLayout::new(LiveArenaCapacities::V2, PAGE as usize)
                .expect("canonical V2 layout");
            let nonce = [0x91; 16];
            let storage = RawControlStorage::new(layout.control_len());
            {
                let _initialized = storage.initialize(layout, nonce);
            }
            let directory = unsafe {
                &mut *storage
                    .base
                    .as_ptr()
                    .add(layout.directory_offset())
                    .cast::<LiveArenaControlDirectoryV2>()
            };
            mutate(directory);
            let adopted = unsafe {
                LiveTranslationArenaView::adopt_in_place(storage.base, storage.len, layout, nonce)
            };
            assert!(adopted.is_err(), "corrupt directory must fail closed");
        }

        rejected(|directory| directory.schema = 1);
        rejected(|directory| directory.block_record_count = 262_143);
        rejected(|directory| directory.block_record_stride = 192);
        rejected(|directory| directory.source_group_count = 4_095);
        rejected(|directory| directory.source_group_stride = 64);
        rejected(|directory| directory.chunk_count = 1_023);
        rejected(|directory| directory.chunk_stride = 128);
        rejected(|directory| directory.chunk_size = 16_384);
        rejected(|directory| directory.next_chunk_cursor_offset += 64);
        rejected(|directory| directory.source_groups_offset = directory.block_records_offset);
        rejected(|directory| directory.chunk_descriptors_offset = u64::MAX);
        rejected(|directory| directory.code_capacity = 4);
        rejected(|directory| directory.control_len -= 16_384);
        rejected(|directory| directory.reserved[0] = 1);
    }

    #[test]
    fn v2_production_layout_rejects_noncanonical_capacity_and_checked_overflow() {
        // Catches accepting a directory-sized custom arena in production or
        // wrapping layout arithmetic before adoption validates its ranges.
        for capacities in [
            LiveArenaCapacities::new(4, LIVE_ARENA_HOT_CAPACITY, LIVE_ARENA_COLD_CAPACITY),
            LiveArenaCapacities::new(
                LIVE_ARENA_CODE_CAPACITY,
                LIVE_ARENA_HOT_CAPACITY - 1,
                LIVE_ARENA_COLD_CAPACITY,
            ),
            LiveArenaCapacities::new(
                LIVE_ARENA_CODE_CAPACITY,
                LIVE_ARENA_HOT_CAPACITY,
                LIVE_ARENA_COLD_CAPACITY + 1,
            ),
        ] {
            assert!(LiveArenaControlLayout::new(capacities, PAGE as usize).is_err());
        }
        assert!(
            LiveArenaControlLayout::new_with_capacities(
                LiveArenaCapacities::new(u64::MAX, u64::MAX, u64::MAX),
                PAGE as usize,
            )
            .is_err()
        );
        assert!(LiveArenaControlLayout::new(LiveArenaCapacities::V2, 0).is_err());
        assert!(LiveArenaControlLayout::new(LiveArenaCapacities::V2, 4_096).is_err());
        assert!(LiveArenaControlLayout::new(LiveArenaCapacities::V2, 12_288).is_err());
    }

    #[test]
    fn v2_code_hot_cold_and_next_chunk_cas_budgets_are_exactly_eight() {
        // Catches an unbounded retry or a ninth allocator CAS in any cursor
        // class. All four production call sites share this exact helper.
        for name in ["code", "HOT", "COLD", "next_chunk"] {
            let cursor = AtomicU64::new(0);
            let attempts = AtomicU64::new(0);
            let result = reserve_append_bounded_result_impl(&cursor, 1_024, 4, 4, |cursor| {
                attempts.fetch_add(1, Ordering::Relaxed);
                cursor.fetch_add(4, Ordering::Release);
            });

            assert!(
                matches!(result, BoundedReservation::Contended),
                "{name} cursor"
            );
            assert_eq!(attempts.load(Ordering::Acquire), 8, "{name} cursor");
            assert_eq!(cursor.load(Ordering::Acquire), 32, "{name} cursor");
        }
    }

    #[test]
    fn v2_diagnostic_counters_are_exact_until_bounded_saturation() {
        // Catches either wraparound at MAX or lossy bounded-CAS accounting.
        let counter = Arc::new(AtomicU64::new(0));
        let mut workers = Vec::new();
        for _ in 0..16 {
            let counter = Arc::clone(&counter);
            workers.push(std::thread::spawn(move || {
                for _ in 0..1_000 {
                    increment_saturating(&counter);
                }
            }));
        }
        for worker in workers {
            worker.join().expect("counter worker");
        }
        assert_eq!(counter.load(Ordering::Acquire), 16_000);

        counter.store(u64::MAX - 1, Ordering::Release);
        increment_saturating(&counter);
        assert_eq!(counter.load(Ordering::Acquire), u64::MAX);
        let mut saturated_workers = Vec::new();
        for _ in 0..16 {
            let counter = Arc::clone(&counter);
            saturated_workers.push(std::thread::spawn(move || increment_saturating(&counter)));
        }
        for worker in saturated_workers {
            worker.join().expect("saturation worker");
        }
        assert_eq!(counter.load(Ordering::Acquire), u64::MAX);

        let arena = arena();
        arena
            .view()
            .directory
            .private_fallbacks
            .store(u64::MAX - 1, Ordering::Release);
        let invalid = GuestVa(key().guest_va_start().raw() + 2);
        assert!(matches!(
            arena.claim_eligible(&key(), invalid, 700),
            LiveLookup::Private(LivePrivateReason::InvalidRecord)
        ));
        assert!(matches!(
            arena.claim_eligible(&key(), invalid, 701),
            LiveLookup::Private(LivePrivateReason::InvalidRecord)
        ));
        assert_eq!(arena.view().cursor_snapshot().private_fallbacks, u64::MAX);
    }

    #[test]
    fn v2_diagnostic_saturation_has_no_crash_window_with_wrapped_value() {
        let counter = AtomicU64::new(u64::MAX);
        let observed_after_atomic = AtomicU64::new(0);
        increment_saturating_impl(&counter, || {
            observed_after_atomic.store(counter.load(Ordering::Acquire), Ordering::Release);
        });

        assert_eq!(observed_after_atomic.load(Ordering::Acquire), u64::MAX);
        assert_eq!(counter.load(Ordering::Acquire), u64::MAX);
    }

    #[test]
    fn v2_group_hash_literal_and_collision_probe_are_exact_key_safe() {
        // Independent Ruby/OpenSSL SHA-256 calculation gives slot 1,899 for
        // the zero identity/page and shows [35;32] and [98;32] collide at 942.
        assert_eq!(initial_group_slot(&[0; 32], 0), 1_899);
        assert_eq!(initial_group_slot(&[35; 32], 0), 942);
        assert_eq!(initial_group_slot(&[98; 32], 0), 942);

        let arena = arena();
        let view = arena.view();
        let first = view
            .resolve_or_create_group(&[35; 32], 0, 801)
            .expect("first colliding group");
        let second = view
            .resolve_or_create_group(&[98; 32], 0, 802)
            .expect("second colliding group");
        let same = view
            .resolve_or_create_group(&[35; 32], 0, 803)
            .expect("same exact group");
        assert_eq!((first.slot, second.slot, same.slot), (942, 943, 942));
        assert_eq!(view.next_chunk.load(Ordering::Acquire), 0);
        assert_eq!(
            first.record.current_chunk.load(Ordering::Acquire),
            LIVE_GROUP_NO_CHUNK
        );
        assert_eq!(
            second.record.current_chunk.load(Ordering::Acquire),
            LIVE_GROUP_NO_CHUNK
        );
    }

    #[test]
    fn v2_failed_group_is_exact_key_terminal_but_collision_probe_continues() {
        let arena = arena();
        let view = arena.view();
        let failed_slot = initial_group_slot(&[35; 32], 0);
        let failed = &view.source_groups[failed_slot];
        failed.creator_pid.store(811, Ordering::Relaxed);
        unsafe {
            failed.write_building_identity(LiveSourceGroupIdentityV2 {
                unit_key_digest: [35; 32],
                source_page: 0,
            })
        };
        failed.state.store(LIVE_GROUP_FAILED, Ordering::Release);

        assert!(matches!(
            view.resolve_or_create_group(&[35; 32], 0, 812),
            Err(LivePrivateReason::Failed)
        ));
        let colliding = view
            .resolve_or_create_group(&[98; 32], 0, 813)
            .expect("different-key collision must continue beyond FAILED");
        assert_eq!(colliding.slot, u32::try_from(failed_slot + 1).unwrap());
        assert_eq!(failed.state.load(Ordering::Acquire), LIVE_GROUP_FAILED);
        assert_eq!(failed.creator_pid.load(Ordering::Relaxed), 811);
        assert_eq!(
            unsafe { *failed.active_identity() }.unit_key_digest,
            [35; 32]
        );
    }

    #[test]
    fn v2_handled_group_creation_failure_is_terminal_and_never_reset() {
        let mut arena = arena();
        arena.fail_group_creation_after_identity = true;
        let slot = initial_group_slot(&[35; 32], 0);
        assert!(matches!(
            arena.view().resolve_or_create_group(&[35; 32], 0, 821),
            Err(LivePrivateReason::InvalidRecord)
        ));
        let failed = &arena.view().source_groups[slot];
        assert_eq!(failed.state.load(Ordering::Acquire), LIVE_GROUP_FAILED);
        assert_eq!(failed.creator_pid.load(Ordering::Relaxed), 821);
        assert_eq!(
            unsafe { *failed.active_identity() }.unit_key_digest,
            [35; 32]
        );

        arena.fail_group_creation_after_identity = false;
        assert!(matches!(
            arena.view().resolve_or_create_group(&[35; 32], 0, 822),
            Err(LivePrivateReason::Failed)
        ));
        assert_eq!(
            arena.view().source_groups[slot]
                .state
                .load(Ordering::Acquire),
            LIVE_GROUP_FAILED
        );
        assert_eq!(
            arena.view().source_groups[slot]
                .creator_pid
                .load(Ordering::Relaxed),
            821
        );
    }

    #[test]
    fn v2_group_owner_death_leaves_building_unstealable_and_unread() {
        let arena = arena();
        let view = arena.view();
        let slot = initial_group_slot(&[35; 32], 0);
        let stranded = &view.source_groups[slot];
        stranded.creator_pid.store(831, Ordering::Relaxed);
        stranded.state.store(LIVE_GROUP_BUILDING, Ordering::Release);

        assert!(matches!(
            view.resolve_or_create_group(&[35; 32], 0, 832),
            Err(LivePrivateReason::Building)
        ));
        assert!(matches!(
            view.resolve_or_create_group(&[98; 32], 0, 833),
            Err(LivePrivateReason::Building)
        ));
        assert_eq!(stranded.state.load(Ordering::Acquire), LIVE_GROUP_BUILDING);
        assert_eq!(stranded.creator_pid.load(Ordering::Relaxed), 831);
    }

    #[test]
    fn v2_group_collision_probe_stops_after_literal_sixteen_slots() {
        // Catches an unbounded group-table walk. The target hashes to literal
        // slot 942 and sixteen occupied nonmatching ACTIVE records exhaust it.
        let arena = arena();
        let view = arena.view();
        for probe in 0..16 {
            let slot = 942 + probe;
            let record = &view.source_groups[slot];
            record
                .creator_pid
                .store(900 + probe as i32, Ordering::Relaxed);
            unsafe {
                record.write_building_identity(LiveSourceGroupIdentityV2 {
                    unit_key_digest: [probe as u8; 32],
                    source_page: PAGE,
                })
            };
            record
                .current_chunk
                .store(LIVE_GROUP_NO_CHUNK, Ordering::Relaxed);
            record
                .expansion
                .store(LIVE_EXPANSION_FREE, Ordering::Relaxed);
            record.state.store(LIVE_GROUP_ACTIVE, Ordering::Release);
        }

        assert!(matches!(
            view.resolve_or_create_group(&[35; 32], 0, 999),
            Err(LivePrivateReason::ExhaustedProbes)
        ));
        assert_eq!(view.next_chunk.load(Ordering::Acquire), 0);
    }

    #[test]
    fn v2_active_no_chunk_contention_has_one_winner_and_one_failed_block() {
        // Catches waiting for or stealing first-expansion authority. The winner
        // is paused while holding expansion; the other exact block must fail
        // immediately, allocate nothing, and terminally fail only itself.
        let mut arena = LiveTranslationArena::new(LIVE_ARENA_CHUNK_BYTES, 64, 64);
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let hook_entered = Arc::clone(&entered);
        let hook_release = Arc::clone(&release);
        arena.after_expansion_claim = Some(Arc::new(move || {
            hook_entered.wait();
            hook_release.wait();
        }));
        let key = key();
        let first_guest = key.guest_va_start();
        let second_guest = GuestVa(first_guest.raw() + 4);
        let LiveLookup::Publish(first_claim) = arena.claim_eligible(&key, first_guest, 811) else {
            panic!("first block claim");
        };
        let LiveLookup::Publish(second_claim) = arena.claim_eligible(&key, second_guest, 812)
        else {
            panic!("second block claim in same ACTIVE/NO_CHUNK group");
        };
        let start = Arc::new(Barrier::new(3));
        let (tx, rx) = std::sync::mpsc::channel();
        let (first_result, second_result) = std::thread::scope(|scope| {
            let first_start = Arc::clone(&start);
            let first_tx = tx.clone();
            let first = scope.spawn(move || {
                first_start.wait();
                let result = first_claim.reserve(8, 8, 8);
                first_tx.send(result.is_ok()).expect("first result marker");
                result
            });
            let second_start = Arc::clone(&start);
            let second_tx = tx.clone();
            let second = scope.spawn(move || {
                second_start.wait();
                let result = second_claim.reserve(8, 8, 8);
                second_tx
                    .send(result.is_ok())
                    .expect("second result marker");
                result
            });
            start.wait();
            entered.wait();
            assert!(!rx.recv().expect("expansion loser result"));
            release.wait();
            assert!(rx.recv().expect("expansion winner result"));
            (
                first.join().expect("first publisher thread"),
                second.join().expect("second publisher thread"),
            )
        });
        let winner = match (first_result, second_result) {
            (Ok(winner), Err(LivePrivateReason::Capacity))
            | (Err(LivePrivateReason::Capacity), Ok(winner)) => winner,
            _ => panic!("exactly one first-expansion winner and one capacity loser expected"),
        };

        let digest = key.live_digest().expect("live digest");
        let group_slot = initial_group_slot(&digest, first_guest.raw());
        let first_slot = initial_slot(&digest, first_guest.raw());
        let second_slot = initial_slot(&digest, second_guest.raw());
        let view = arena.view();
        assert_eq!(winner.extents().code.offset, 0);
        assert_eq!(view.next_chunk.load(Ordering::Acquire), 1);
        assert_eq!(
            view.source_groups[group_slot]
                .current_chunk
                .load(Ordering::Acquire),
            0
        );
        assert_eq!(
            view.chunk_descriptors[0].state.load(Ordering::Acquire),
            LIVE_CHUNK_ACTIVE
        );
        assert_eq!(view.chunk_descriptors[0].cursor.load(Ordering::Acquire), 8);
        let states = [
            view.block_records[first_slot].state.load(Ordering::Acquire),
            view.block_records[second_slot]
                .state
                .load(Ordering::Acquire),
        ];
        assert!(states.contains(&LIVE_BLOCK_BUILDING));
        assert!(states.contains(&LIVE_BLOCK_FAILED));
    }

    #[test]
    fn v2_stuck_expansion_preserves_ready_and_never_steals_or_reuses() {
        // Catches clearing a dead owner's expansion or making existing READY
        // dependent on expansion liveness. A full current chunk forces the new
        // block onto the stuck path while the prior READY stays acquirable.
        let arena = LiveTranslationArena::new(2 * LIVE_ARENA_CHUNK_BYTES, 64, 64);
        let key = key();
        let ready = seed_ready(&arena, &key);
        let digest = key.live_digest().expect("live digest");
        let page = key.guest_va_start().raw();
        let group_slot = initial_group_slot(&digest, page);
        let stuck = expansion_owner(8_888);
        {
            let view = arena.view();
            view.chunk_descriptors[0]
                .cursor
                .store(LIVE_ARENA_CHUNK_BYTES, Ordering::Release);
            view.source_groups[group_slot]
                .expansion
                .store(stuck, Ordering::Release);
        }
        let other_guest = GuestVa(page + 4);
        let other_slot = initial_slot(&digest, other_guest.raw());
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, other_guest, 813) else {
            panic!("other block may claim while group is ACTIVE");
        };
        assert!(matches!(
            claim.reserve(8, 8, 8),
            Err(LivePrivateReason::Capacity)
        ));

        let view = arena.view();
        assert_eq!(
            view.source_groups[group_slot]
                .expansion
                .load(Ordering::Acquire),
            stuck
        );
        assert_eq!(
            view.source_groups[group_slot]
                .current_chunk
                .load(Ordering::Acquire),
            0
        );
        assert_eq!(view.next_chunk.load(Ordering::Acquire), 1);
        assert_eq!(
            view.chunk_descriptors[1].state.load(Ordering::Acquire),
            LIVE_CHUNK_EMPTY
        );
        assert_eq!(
            view.block_records[other_slot].state.load(Ordering::Acquire),
            LIVE_BLOCK_FAILED
        );
        let LiveReadyLookup::Ready(acquired) =
            view.acquire_ready_or_miss(&arena.process_view, &key, key.guest_va_start())
        else {
            panic!("READY must remain usable behind a stuck expansion");
        };
        assert_eq!(acquired.record_index(), ready.record_index());
        assert_eq!(acquired.chunk_index(), 0);
    }

    #[test]
    fn v2_code_length_boundaries_mutate_no_chunk_until_valid_65536() {
        // Catches rounding invalid prepared lengths or allocating a first chunk
        // before exact size validation. The ACTIVE group itself remains valid.
        for invalid in [0, 65_535, 65_537] {
            let arena = LiveTranslationArena::new(LIVE_ARENA_CHUNK_BYTES, 0, 0);
            let key = key();
            let guest = key.guest_va_start();
            let digest = key.live_digest().expect("live digest");
            let group_slot = initial_group_slot(&digest, guest.raw());
            let LiveLookup::Publish(claim) = arena.claim_eligible(&key, guest, 821) else {
                panic!("eligible block claim");
            };
            assert!(matches!(
                claim.reserve(invalid, 0, 0),
                Err(LivePrivateReason::InvalidRecord)
            ));
            let view = arena.view();
            assert_eq!(view.next_chunk.load(Ordering::Acquire), 0);
            assert_eq!(
                view.source_groups[group_slot].state.load(Ordering::Acquire),
                LIVE_GROUP_ACTIVE
            );
            assert_eq!(
                view.source_groups[group_slot]
                    .current_chunk
                    .load(Ordering::Acquire),
                LIVE_GROUP_NO_CHUNK
            );
            assert_eq!(
                view.chunk_descriptors[0].state.load(Ordering::Acquire),
                LIVE_CHUNK_EMPTY
            );
        }

        let arena = LiveTranslationArena::new(LIVE_ARENA_CHUNK_BYTES, 0, 0);
        let key = key();
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, key.guest_va_start(), 822)
        else {
            panic!("eligible maximum-size block claim");
        };
        let reserved = claim
            .reserve(65_536, 0, 0)
            .expect("exact 64 KiB block must fit");
        assert_eq!(
            reserved.extents().code,
            LiveReservation {
                offset: 0,
                len: 65_536
            }
        );
        let view = arena.view();
        assert_eq!(view.next_chunk.load(Ordering::Acquire), 1);
        assert_eq!(
            view.chunk_descriptors[0].cursor.load(Ordering::Acquire),
            65_536
        );
    }

    #[test]
    fn v2_last_chunk_checked_arithmetic_fits_exactly_then_exhausts() {
        // Catches wrapping the absolute offset/end at the final descriptor or
        // allowing next_chunk to advance beyond the canonical 1,024 chunks.
        let arena = LiveTranslationArena::new(LIVE_ARENA_CODE_CAPACITY, 0, 0);
        arena
            .view()
            .next_chunk
            .store((LIVE_ARENA_CHUNKS - 1) as u64, Ordering::Release);
        let key = key();
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, key.guest_va_start(), 823)
        else {
            panic!("last-chunk block claim");
        };
        let last = claim
            .reserve(LIVE_ARENA_CHUNK_BYTES, 0, 0)
            .expect("last canonical chunk fits exactly")
            .extents()
            .code;
        assert_eq!(last.offset, 1_023 * 65_536);
        assert_eq!(last.end(), Some(LIVE_ARENA_CODE_CAPACITY));
        assert!(valid_code_extent(last));
        assert!(!valid_code_extent(LiveReservation {
            offset: u64::MAX - 3,
            len: 4,
        }));

        let other_guest = GuestVa(key.guest_va_start().raw() + PAGE);
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, other_guest, 824) else {
            panic!("post-capacity block claim");
        };
        assert!(matches!(
            claim.reserve(4, 0, 0),
            Err(LivePrivateReason::Capacity)
        ));
        assert_eq!(
            arena.view().next_chunk.load(Ordering::Acquire),
            LIVE_ARENA_CHUNKS as u64
        );
    }

    fn key() -> TranslationUnitKey {
        TranslationUnitKey::for_segment(
            ExecutableIdentity::Digest([0x42; 32]),
            ImageFileOffset::new(0),
            ImageFileLen::new(PAGE * 64).expect("nonzero file length"),
            GuestVa(0x4000_0000),
            GuestCodeLen::new(PAGE * 64).expect("nonzero guest length"),
            SourceFingerprint([0x7a; 32]),
            NativePageProfileIdentity::Native16k,
            AddressModeIdentity::Direct,
        )
    }

    fn arena() -> LiveTranslationArena {
        LiveTranslationArena::new(PAGE * 32, PAGE * 2, PAGE * 2)
    }

    fn prepared_publication() -> PreparedSharedInitial {
        prepare_shared_initial(
            &key(),
            &BlockPlan {
                start: GuestVa(0x4000_0000),
                end: GuestVa(0x4000_000c),
                generation: CodeGeneration::INITIAL,
                instructions: vec![
                    PlannedInst {
                        guest: GuestVa(0x4000_0000),
                        action: InstAction::Copy(0xd503_201f),
                    },
                    PlannedInst {
                        guest: GuestVa(0x4000_0004),
                        action: InstAction::Copy(0x9100_0400),
                    },
                ],
                exit: PlannedExit::Syscall {
                    guest: GuestVa(0x4000_0008),
                    resume: GuestVa(0x4000_000c),
                },
                extensions: Vec::new(),
            },
            EmitAddressMode::Direct,
            Vec::new(),
        )
        .expect("prepare real shared INITIAL publication")
    }

    struct MappedPublicationFixture {
        extents: LiveBlockExtents,
        code: Vec<u8>,
        hot: Vec<u8>,
        cold: Vec<u8>,
    }

    impl MappedPublicationFixture {
        fn from_claim(prepared: &PreparedSharedInitial, extents: LiveBlockExtents) -> Self {
            let fixture = Self {
                extents,
                code: prepared.code_bytes().to_vec(),
                hot: prepared.hot_bytes().to_vec(),
                cold: prepared.cold_bytes().to_vec(),
            };
            assert_eq!(fixture.code.len(), extents.code.len as usize);
            assert_eq!(fixture.hot.len(), extents.hot.len as usize);
            assert_eq!(fixture.cold.len(), extents.cold.len as usize);
            fixture
        }

        fn establishes(&self, permit: &LiveMappedWritePermit<'_, '_>) {
            assert_eq!(permit.extents(), self.extents);
        }
    }

    fn certify_prepared<'view>(
        reserved: &mut LiveReservedPublishClaim<'view>,
        prepared: &PreparedSharedInitial,
    ) -> (LiveArenaWrittenBlock<'view>, MappedPublicationFixture) {
        let mapped = MappedPublicationFixture::from_claim(prepared, reserved.extents());
        // SAFETY: this test fixture owns actual disjoint buffers whose lengths
        // resolve the claim's exact extents, and enters the permit once.
        let permit = unsafe { reserved.begin_mapped_write() }.expect("mapped permit");
        mapped.establishes(&permit);
        // SAFETY: the cfg(test) fixture exception establishes exact stable
        // ranges for portable validation only; it is not production completion
        // provenance for a claim-bound cache publication.
        let written = unsafe {
            permit.certify_mapped(
                &mapped.code,
                &mapped.hot,
                &mapped.cold,
                key().guest_va_start(),
                0,
                prepared.expected_publication(),
            )
        }
        .expect("certify prepared mapped publication");
        (written, mapped)
    }

    fn seed_probe_record(
        arena: &mut LiveTranslationArena,
        slot: usize,
        state: u32,
        unit_key_digest: [u8; 32],
        guest_start: u64,
    ) {
        let view = arena.view();
        let record = &view.block_records[slot & LIVE_BLOCK_MASK];
        let payload = LiveBlockPayloadV2 {
            unit_key_digest,
            guest_start,
            source_page: guest_start / PAGE * PAGE,
            code_offset: 0,
            code_len: 8,
            entry_offset: 4,
            hot_offset: 0,
            hot_len: 8,
            cold_offset: 0,
            cold_len: 8,
            code_sha256: [0x5a; 32],
        };
        unsafe { record.write_building_payload(payload) };
        record.state.store(state, Ordering::Release);
    }

    fn seed_active_group_and_chunk(
        view: LiveTranslationArenaView<'_>,
        unit_key_digest: [u8; 32],
        source_page: u64,
        chunk_index: u32,
        used: u64,
    ) {
        let group_slot = initial_group_slot(&unit_key_digest, source_page);
        let group = &view.source_groups[group_slot];
        group.creator_pid.store(1, Ordering::Relaxed);
        unsafe {
            group.write_building_identity(LiveSourceGroupIdentityV2 {
                unit_key_digest,
                source_page,
            })
        };
        group.current_chunk.store(chunk_index, Ordering::Relaxed);
        group
            .expansion
            .store(LIVE_EXPANSION_FREE, Ordering::Relaxed);
        group.state.store(LIVE_GROUP_ACTIVE, Ordering::Release);

        let descriptor = &view.chunk_descriptors[chunk_index as usize];
        descriptor
            .owner_group
            .store(group_slot as u32, Ordering::Relaxed);
        descriptor.cursor.store(used, Ordering::Relaxed);
        descriptor.state.store(LIVE_CHUNK_ACTIVE, Ordering::Release);
        view.next_chunk
            .store(u64::from(chunk_index) + 1, Ordering::Release);
    }

    fn malformed_ready_reason(
        mutate: impl FnOnce(&mut LiveBlockPayloadV2),
    ) -> Option<LivePrivateReason> {
        let arena = arena();
        let key = key();
        let guest_start = key.guest_va_start();
        let digest = key.live_digest().expect("live digest");
        let initial = initial_slot(&digest, guest_start.raw());
        let view = arena.view();
        seed_active_group_and_chunk(view, digest, guest_start.raw(), 0, 8);
        let record = &view.block_records[initial];
        let mut payload = LiveBlockPayloadV2 {
            unit_key_digest: digest,
            guest_start: guest_start.raw(),
            source_page: guest_start.raw(),
            code_offset: 0,
            code_len: 8,
            entry_offset: 4,
            hot_offset: 0,
            hot_len: 8,
            cold_offset: 0,
            cold_len: 8,
            code_sha256: [0x5a; 32],
        };
        mutate(&mut payload);
        unsafe { record.write_building_payload(payload) };
        record.state.store(LIVE_BLOCK_READY, Ordering::Release);

        arena
            .claim_eligible(&key, guest_start, 1234)
            .private_reason()
    }

    fn seed_ready(
        arena: &LiveTranslationArena,
        key: &TranslationUnitKey,
    ) -> ValidatedLiveBlockRecord {
        let guest_start = key.guest_va_start();
        let digest = key.live_digest().expect("live digest");
        let initial = initial_slot(&digest, guest_start.raw());
        let view = arena.view();
        seed_active_group_and_chunk(view, digest, guest_start.raw(), 0, 8);
        let record = &view.block_records[initial];
        let payload = LiveBlockPayloadV2 {
            unit_key_digest: digest,
            guest_start: guest_start.raw(),
            source_page: guest_start.raw(),
            code_offset: 0,
            code_len: 8,
            entry_offset: 4,
            hot_offset: 0,
            hot_len: 8,
            cold_offset: 0,
            cold_len: 8,
            code_sha256: [0x5a; 32],
        };
        // SAFETY: this test utility has exclusive fixture setup authority and
        // publishes the fully initialized payload before the Release store.
        let group = view
            .find_active_group(&digest, guest_start.raw())
            .expect("seeded ACTIVE group");
        assert_eq!(
            view.chunk_descriptors[0]
                .owner_group
                .load(Ordering::Acquire),
            group.slot,
        );
        assert_eq!(
            view.chunk_descriptors[0].state.load(Ordering::Acquire),
            LIVE_CHUNK_ACTIVE,
        );
        assert!(valid_source_page(payload.source_page, payload.guest_start));
        assert!(valid_code_extent(LiveReservation {
            offset: payload.code_offset,
            len: u64::from(payload.code_len),
        }));
        assert!(
            view.validate_ready(
                &arena.process_view,
                initial,
                &payload,
                &digest,
                guest_start.raw(),
            )
            .is_some(),
            "seeded group/descriptor must authorize the READY payload",
        );
        unsafe { record.write_building_payload(payload) };
        record.state.store(LIVE_BLOCK_READY, Ordering::Release);
        let LiveReadyLookup::Ready(ready) = arena.acquire_ready_or_miss(key, guest_start) else {
            panic!("seeded READY record must validate");
        };
        ready
    }

    #[test]
    fn ready_acquire_exposes_complete_record() {
        let arena = arena();
        let key = key();
        let published = seed_ready(&arena, &key);
        let LiveLookup::Ready(ready) = arena.claim_eligible(&key, key.guest_va_start(), 9999)
        else {
            panic!("ready record must be visible to a later acquirer");
        };

        assert_eq!(
            ready.unit_key_digest(),
            key.live_digest().expect("live digest")
        );
        assert_eq!(ready.guest_start(), key.guest_va_start().raw());
        assert_eq!(ready.source_page(), key.guest_va_start().raw());
        assert_eq!(ready.extents(), published.extents());
        assert_eq!(ready.entry_offset(), 4);
        assert_eq!(ready.code_sha256(), [0x5a; 32]);
    }

    #[test]
    fn validated_ready_record_owns_no_payload_reference() {
        fn assert_address_free_and_send<T: Send>() {}
        fn acquire_after_owner_scope() -> ValidatedLiveBlockRecord {
            let arena = arena();
            let key = key();
            seed_ready(&arena, &key)
        }

        assert_address_free_and_send::<ValidatedLiveBlockRecord>();
        let ready = acquire_after_owner_scope();
        assert_eq!(ready.guest_start(), key().guest_va_start().raw());
        assert_eq!(ready.entry_offset(), 4);
    }

    #[test]
    fn ready_record_revalidation_rejects_wrong_storage_brand_or_record() {
        let first = arena();
        let second = arena();
        let key = key();
        let ready = seed_ready(&first, &key);

        assert!(
            first
                .view()
                .revalidate_ready(&first.process_view, &ready)
                .is_some()
        );
        assert!(
            second
                .view()
                .revalidate_ready(&second.process_view, &ready)
                .is_none()
        );

        let mut wrong_record = ready;
        wrong_record.record_index = wrong_record.record_index.wrapping_add(1);
        assert!(
            first
                .view()
                .revalidate_ready(&first.process_view, &wrong_record)
                .is_none()
        );
    }

    #[test]
    fn building_record_falls_back_without_waiting() {
        let arena = arena();
        let key = key();
        let LiveLookup::Publish(_claim) = arena.claim_eligible(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim the empty record");
        };

        assert_eq!(
            arena
                .claim_eligible(&key, key.guest_va_start(), 9999)
                .private_reason(),
            Some(LivePrivateReason::Building)
        );
    }

    #[test]
    fn failed_record_falls_back_without_waiting() {
        let arena = LiveTranslationArena::new(4, PAGE, PAGE);
        let key = key();
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim the empty record");
        };
        assert!(matches!(
            claim.reserve(8, 8, 8),
            Err(LivePrivateReason::Capacity)
        ));

        assert_eq!(
            arena
                .claim_eligible(&key, key.guest_va_start(), 9999)
                .private_reason(),
            Some(LivePrivateReason::Failed)
        );
    }

    #[test]
    fn owner_death_never_steals_building_record() {
        let arena = arena();
        let key = key();
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim the empty record");
        };
        assert_eq!(claim.owner_pid(), 1234);

        assert_eq!(
            arena
                .claim_eligible(&key, key.guest_va_start(), -1)
                .private_reason(),
            Some(LivePrivateReason::Building)
        );
    }

    #[test]
    fn reservation_rejects_misaligned_or_overflowing_lengths() {
        let key = key();
        let invalid_arena = arena();
        let LiveLookup::Publish(claim) =
            invalid_arena.claim_eligible(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim the empty record");
        };
        assert!(matches!(
            claim.reserve(6, 8, 8),
            Err(LivePrivateReason::InvalidRecord)
        ));

        let overflow_arena = arena();
        let LiveLookup::Publish(claim) =
            overflow_arena.claim_eligible(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim the empty record");
        };
        assert!(matches!(
            claim.reserve(u64::MAX - 3, 8, 8),
            Err(LivePrivateReason::InvalidRecord)
        ));
    }

    #[test]
    fn record_rejects_misaligned_or_overflowing_extents() {
        let misaligned = malformed_ready_reason(|payload| payload.code_offset = 1);
        let overflowing = malformed_ready_reason(|payload| {
            payload.code_offset = u64::MAX - (PAGE - 1);
            payload.code_len = 16 * 1024;
        });

        assert_eq!(
            [misaligned, overflowing],
            [
                Some(LivePrivateReason::InvalidRecord),
                Some(LivePrivateReason::InvalidRecord),
            ]
        );
    }

    #[test]
    fn reservation_cursors_never_overlap_under_concurrency() {
        let arena = Arc::new(LiveTranslationArena::new(
            LIVE_ARENA_CHUNK_BYTES * 16,
            PAGE,
            PAGE,
        ));
        let key = key();
        let start = Arc::new(Barrier::new(17));
        let mut workers = Vec::new();
        for index in 0..16 {
            let arena = Arc::clone(&arena);
            let key = key.clone();
            let start = Arc::clone(&start);
            workers.push(std::thread::spawn(move || {
                let guest = GuestVa(key.guest_va_start().raw() + (index + 1) as u64 * PAGE);
                start.wait();
                let LiveLookup::Publish(claim) = arena.claim_eligible(&key, guest, index + 1)
                else {
                    panic!("each distinct record must claim once");
                };
                claim
                    .reserve(8, 8, 8)
                    .expect("reservation must fit")
                    .extents()
            }));
        }
        start.wait();
        let mut reservations: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker must not panic"))
            .collect();
        reservations.sort_by_key(|extents| extents.code.offset);
        let selectors: [fn(&LiveBlockExtents) -> LiveReservation; 3] = [
            |extents: &LiveBlockExtents| extents.code,
            |extents: &LiveBlockExtents| extents.hot,
            |extents: &LiveBlockExtents| extents.cold,
        ];
        for selector in selectors {
            let mut ranges: Vec<_> = reservations.iter().map(selector).collect();
            ranges.sort_by_key(|range| range.offset);
            for pair in ranges.windows(2) {
                assert!(
                    pair[0].end().expect("checked end") <= pair[1].offset,
                    "reservations overlap: {pair:?}"
                );
            }
        }
    }

    #[test]
    fn ready_record_is_immutable() {
        let arena = arena();
        let key = key();
        let published = seed_ready(&arena, &key);
        let first = published.record_snapshot();
        let LiveLookup::Ready(again) = arena.claim_eligible(&key, key.guest_va_start(), 9999)
        else {
            panic!("ready record must stay ready");
        };
        assert_eq!(again.record_snapshot(), first);
    }

    #[test]
    fn publication_consumes_the_claims_exact_reservation() {
        let arena = arena();
        let key = key();
        let prepared = prepared_publication();
        let lengths = prepared.lengths();
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim");
        };
        let mut reserved = claim
            .reserve(lengths.code, lengths.hot, lengths.cold)
            .expect("reserve exact prepared extents");
        let extents = reserved.extents();
        let (written, _mapped_storage) = certify_prepared(&mut reserved, &prepared);

        let ready = reserved
            .publish(written)
            .expect("token must consume its exact reservation");
        assert_eq!(ready.extents(), extents);
        assert!(
            arena
                .view()
                .revalidate_ready(&arena.process_view, &ready)
                .is_some()
        );
    }

    #[test]
    fn record_rejects_wrong_unit_key_or_translator_abi() {
        let prepared = prepared_publication();
        let lengths = prepared.lengths();

        let wrong_key_arena = arena();
        let key = key();
        let LiveLookup::Publish(claim) =
            wrong_key_arena.claim_eligible(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim");
        };
        let mut reserved = claim
            .reserve(lengths.code, lengths.hot, lengths.cold)
            .expect("reserve exact prepared extents");
        let (mut written, _mapped_storage) = certify_prepared(&mut reserved, &prepared);
        written.unit_key_digest = [0xff; 32];
        assert!(matches!(
            reserved.publish(written),
            Err(LivePrivateReason::InvalidRecord)
        ));

        let wrong_abi_arena = arena();
        let LiveLookup::Publish(claim) =
            wrong_abi_arena.claim_eligible(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim");
        };
        let mut reserved = claim
            .reserve(lengths.code, lengths.hot, lengths.cold)
            .expect("reserve exact prepared extents");
        let (mut written, _mapped_storage) = certify_prepared(&mut reserved, &prepared);
        written.translator_abi = TRANSLATOR_ABI_CURRENT + 1;
        assert!(matches!(
            reserved.publish(written),
            Err(LivePrivateReason::InvalidRecord)
        ));
    }

    #[test]
    fn record_rejects_token_digest_mismatch() {
        let arena = arena();
        let key = key();
        let prepared = prepared_publication();
        let lengths = prepared.lengths();
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim");
        };
        let mut reserved = claim
            .reserve(lengths.code, lengths.hot, lengths.cold)
            .expect("reserve exact prepared extents");
        let (mut written, _mapped_storage) = certify_prepared(&mut reserved, &prepared);
        written.code_sha256 = [0xff; 32];

        assert!(matches!(
            reserved.publish(written),
            Err(LivePrivateReason::InvalidRecord)
        ));
    }

    #[test]
    fn ready_release_makes_payload_visible_to_another_thread() {
        let arena = Arc::new(arena());
        let key = key();
        let prepared = prepared_publication();
        let lengths = prepared.lengths();
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim");
        };
        let mut reserved = claim
            .reserve(lengths.code, lengths.hot, lengths.cold)
            .expect("reserve exact prepared extents");
        let extents = reserved.extents();
        let (written, _mapped_storage) = certify_prepared(&mut reserved, &prepared);
        let start = Barrier::new(2);

        std::thread::scope(|scope| {
            scope.spawn(|| {
                start.wait();
                for _ in 0..100_000 {
                    if let LiveLookup::Ready(ready) =
                        arena.claim_eligible(&key, key.guest_va_start(), 9999)
                    {
                        assert_eq!(ready.extents(), extents);
                        assert_eq!(
                            ready.unit_key_digest(),
                            key.live_digest().expect("live digest")
                        );
                        assert_eq!(ready.source_page(), key.guest_va_start().raw());
                        return;
                    }
                    std::thread::yield_now();
                }
                panic!("reader did not Acquire the READY publication");
            });
            start.wait();
            let ready = reserved
                .publish(written)
                .expect("publisher must Release the complete READY payload");
            assert_eq!(ready.extents(), extents);
        });
    }

    #[test]
    fn ready_different_key_continues_to_next_probe() {
        let mut arena = arena();
        let key = key();
        let guest_start = key.guest_va_start();
        let digest = key.live_digest().expect("live digest");
        let initial = initial_slot(&digest, guest_start.raw());
        seed_probe_record(
            &mut arena,
            initial,
            LIVE_BLOCK_READY,
            [0xa5; 32],
            guest_start.raw(),
        );

        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, guest_start, 1234) else {
            panic!("different-key READY must continue to the next empty probe");
        };
        assert!(std::ptr::eq(
            claim.record,
            &arena.view().block_records[(initial + 1) & LIVE_BLOCK_MASK]
        ));
    }

    #[test]
    fn failed_different_key_continues_to_next_probe() {
        let mut arena = arena();
        let key = key();
        let guest_start = key.guest_va_start();
        let digest = key.live_digest().expect("live digest");
        let initial = initial_slot(&digest, guest_start.raw());
        seed_probe_record(
            &mut arena,
            initial,
            LIVE_BLOCK_FAILED,
            [0xa5; 32],
            guest_start.raw(),
        );

        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, guest_start, 1234) else {
            panic!("different-key FAILED must continue to the next empty probe");
        };
        assert!(std::ptr::eq(
            claim.record,
            &arena.view().block_records[(initial + 1) & LIVE_BLOCK_MASK]
        ));
    }

    #[test]
    fn building_different_key_stops_without_probing() {
        let mut arena = arena();
        let key = key();
        let guest_start = key.guest_va_start();
        let digest = key.live_digest().expect("live digest");
        let initial = initial_slot(&digest, guest_start.raw());
        seed_probe_record(
            &mut arena,
            initial,
            LIVE_BLOCK_BUILDING,
            [0xa5; 32],
            guest_start.raw(),
        );

        assert_eq!(
            arena
                .claim_eligible(&key, guest_start, 1234)
                .private_reason(),
            Some(LivePrivateReason::Building)
        );
        assert_eq!(
            arena.view().block_records[(initial + 1) & LIVE_BLOCK_MASK]
                .state
                .load(Ordering::Relaxed),
            LIVE_BLOCK_EMPTY
        );
    }

    #[test]
    fn sixteen_different_terminal_records_exhaust_probe_budget() {
        let mut arena = arena();
        let key = key();
        let guest_start = key.guest_va_start();
        let digest = key.live_digest().expect("live digest");
        let initial = initial_slot(&digest, guest_start.raw());
        for probe in 0..LIVE_ARENA_PROBES {
            let mut different_digest = [0u8; 32];
            different_digest[0..8].copy_from_slice(&(probe as u64 + 1).to_le_bytes());
            seed_probe_record(
                &mut arena,
                initial + probe,
                if probe % 2 == 0 {
                    LIVE_BLOCK_READY
                } else {
                    LIVE_BLOCK_FAILED
                },
                different_digest,
                guest_start.raw(),
            );
        }

        assert_eq!(
            arena
                .claim_eligible(&key, guest_start, 1234)
                .private_reason(),
            Some(LivePrivateReason::ExhaustedProbes)
        );
    }

    #[test]
    fn unrepresentable_lengths_are_rejected_before_any_cursor_advance() {
        let oversized = u64::from(u32::MAX) + 1;
        for lengths in [(oversized, 8, 8), (8, oversized, 8), (8, 8, oversized)] {
            let arena = LiveTranslationArena::new(oversized + PAGE, oversized + 8, oversized + 8);
            let key = key();
            let LiveLookup::Publish(claim) = arena.claim_eligible(&key, key.guest_va_start(), 1234)
            else {
                panic!("first lookup must claim the empty record");
            };

            assert!(matches!(
                claim.reserve(lengths.0, lengths.1, lengths.2),
                Err(LivePrivateReason::InvalidRecord)
            ));
            let cursors = arena.view().cursor_snapshot();
            assert_eq!(cursors.next_chunk, 0);
            assert_eq!(cursors.hot, 0);
            assert_eq!(cursors.cold, 0);
        }
    }

    #[test]
    fn later_cursor_failure_counts_stranded_nonempty_extents() {
        let arena = LiveTranslationArena::new(LIVE_ARENA_CHUNK_BYTES, 8, 0);
        let key = key();
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim the empty record");
        };

        assert!(matches!(
            claim.reserve(8, 8, 8),
            Err(LivePrivateReason::Capacity)
        ));
        let cursors = arena.view().cursor_snapshot();
        assert_eq!(cursors.leaked_extents, 2);
        assert_eq!(cursors.next_chunk, 1);
        assert_eq!(cursors.hot, 8);
        assert_eq!(cursors.cold, 0);
    }

    #[test]
    fn cas_loss_stops_at_the_contended_empty_probe() {
        let mut arena = arena();
        let key = key();
        let gate = Arc::new(Barrier::new(2));
        arena.cas_barrier = Some(Arc::clone(&gate));
        let arena = Arc::new(arena);

        let outcomes: Vec<_> = (0..2)
            .map(|owner_pid| {
                let arena = Arc::clone(&arena);
                let key = key.clone();
                std::thread::spawn(move || {
                    arena
                        .claim_eligible(&key, key.guest_va_start(), owner_pid)
                        .private_reason()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|worker| worker.join().expect("worker must not panic"))
            .collect();

        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == Some(LivePrivateReason::CasLost))
                .count(),
            1
        );
        assert_eq!(
            outcomes.iter().filter(|outcome| outcome.is_none()).count(),
            1
        );
        let digest = key.live_digest().expect("live digest");
        let initial = initial_slot(&digest, key.guest_va_start().raw());
        assert_eq!(
            arena.view().block_records[(initial + 1) & LIVE_BLOCK_MASK]
                .state
                .load(Ordering::Relaxed),
            LIVE_BLOCK_EMPTY
        );
    }

    #[test]
    fn mapped_views_share_claim_state_and_append_cursors() {
        let capacities = LiveArenaCapacities::new(LIVE_ARENA_CHUNK_BYTES * 2, PAGE, PAGE);
        let layout = LiveArenaControlLayout::new_for_test(capacities, PAGE as usize)
            .expect("checked mapped layout");
        let nonce = [0x5a; 16];
        let storage = RawControlStorage::new(layout.control_len());
        let first = storage.initialize(layout, nonce);
        let second = storage.adopt(layout, nonce);
        let generations = PageGenerationTable::new(PAGE).expect("generation table");
        let process_view = LiveProcessViewBrand::new(generations.domain());
        let first_key = key();
        let second_guest = GuestVa(first_key.guest_va_start().raw() + PAGE);

        let LiveLookup::Publish(claim) = first.claim_eligible_for_test(
            &process_view,
            &first_key,
            first_key.guest_va_start(),
            &generations,
            101,
        ) else {
            panic!("first mapped view must win a claim");
        };
        let first_extents = claim.reserve(8, 8, 8).expect("first reservation").extents();
        let LiveLookup::Publish(claim) = second.claim_eligible_for_test(
            &process_view,
            &first_key,
            second_guest,
            &generations,
            202,
        ) else {
            panic!("second mapped view must observe the shared table and next empty slot");
        };
        let second_extents = claim
            .reserve(8, 8, 8)
            .expect("second reservation")
            .extents();

        assert!(first_extents.code.end().expect("code end") <= second_extents.code.offset);
        assert!(first_extents.hot.end().expect("HOT end") <= second_extents.hot.offset);
        assert!(first_extents.cold.end().expect("COLD end") <= second_extents.cold.offset);
        assert_eq!(first.cursor_snapshot(), second.cursor_snapshot());
    }

    #[test]
    fn record_hot_cold_ranges_fit_exactly() {
        let capacities = LiveArenaCapacities::new(PAGE * 7, 24, 40);
        let layout = LiveArenaControlLayout::new_for_test(capacities, PAGE as usize)
            .expect("checked mapped layout");

        assert_eq!(layout.directory_offset(), 64);
        assert_eq!(layout.block_records_len(), 33_554_432);
        assert_eq!(layout.source_groups_len(), 524_288);
        assert_eq!(layout.chunk_descriptors_len(), 65_536);
        assert_eq!(layout.chunk_descriptors_end(), layout.hot_base());
        assert_eq!(layout.hot_base() + 24, layout.cold_base());
        assert_eq!(layout.cold_base() + 40, layout.control_payload_end());
        assert!(layout.control_payload_end() <= layout.control_len());
        assert!(layout.control_len().is_multiple_of(PAGE as usize));
    }

    #[test]
    fn dropped_publish_claim_release_publishes_failed() {
        let arena = arena();
        let key = key();
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim the empty record");
        };
        drop(claim);

        assert_eq!(
            arena
                .claim_eligible(&key, key.guest_va_start(), 9999)
                .private_reason(),
            Some(LivePrivateReason::Failed)
        );
    }

    #[test]
    fn cross_view_claim_authority_is_rejected() {
        let capacities = LiveArenaCapacities::new(PAGE * 4, PAGE, PAGE);
        let layout = LiveArenaControlLayout::new_for_test(capacities, PAGE as usize)
            .expect("checked mapped layout");
        let first_storage = RawControlStorage::new(layout.control_len());
        let second_storage = RawControlStorage::new(layout.control_len());
        let first = first_storage.initialize(layout, [0x11; 16]);
        let second = second_storage.initialize(layout, [0x22; 16]);
        let generations = PageGenerationTable::new(PAGE).expect("generation table");
        let process_view = LiveProcessViewBrand::new(generations.domain());
        let key = key();
        let LiveLookup::Publish(claim) = first.claim_eligible_for_test(
            &process_view,
            &key,
            key.guest_va_start(),
            &generations,
            1234,
        ) else {
            panic!("first view must claim");
        };
        let reserved = claim.reserve(8, 8, 8).expect("reserved claim");

        assert!(first.accepts_claim(&reserved));
        assert!(!second.accepts_claim(&reserved));
    }

    #[test]
    fn reserved_claim_binds_exact_process_view_brand() {
        let capacities = LiveArenaCapacities::new(PAGE * 4, PAGE, PAGE);
        let layout = LiveArenaControlLayout::new_for_test(capacities, PAGE as usize)
            .expect("checked mapped layout");
        let storage = RawControlStorage::new(layout.control_len());
        let view = storage.initialize(layout, [0x33; 16]);
        let generations = PageGenerationTable::new(PAGE).expect("generation table");
        let first_brand = LiveProcessViewBrand::new(generations.domain());
        let second_brand = LiveProcessViewBrand::new(generations.domain());
        let key = key();
        let LiveLookup::Publish(claim) = view.claim_eligible_for_test(
            &first_brand,
            &key,
            key.guest_va_start(),
            &generations,
            1234,
        ) else {
            panic!("first lookup must claim");
        };
        let reserved = claim.reserve(8, 8, 8).expect("reserve exact extents");

        assert!(reserved.belongs_to_process_view(&first_brand));
        assert!(!reserved.belongs_to_process_view(&second_brand));
    }

    #[test]
    fn failed_write_attempt_cannot_retry_and_drop_publishes_failed() {
        let arena = arena();
        let key = key();
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim");
        };
        let mut reserved = claim.reserve(8, 8, 8).expect("reserve exact extents");
        let expected_extents = reserved.extents();
        // SAFETY: this test enters the portable integration seam only to prove
        // its one-attempt state transition; it performs no mapped write.
        {
            let permit = unsafe { reserved.begin_mapped_write() }.expect("first attempt");
            assert_eq!(permit.extents(), expected_extents);
        }

        // SAFETY: the second call intentionally exercises rejection before any
        // range or pointer could be exposed.
        assert!(matches!(
            unsafe { reserved.begin_mapped_write() },
            Err(LivePrivateReason::WriteAttempted)
        ));
        drop(reserved);
        assert_eq!(
            arena
                .claim_eligible(&key, key.guest_va_start(), 9999)
                .private_reason(),
            Some(LivePrivateReason::Failed)
        );
    }

    #[test]
    fn short_code_hot_or_cold_refuses_certification() {
        for short_stream in 0..3 {
            let arena = arena();
            let key = key();
            let prepared = prepared_publication();
            let lengths = prepared.lengths();
            let expected = prepared.expected_publication();
            let LiveLookup::Publish(claim) = arena.claim_eligible(&key, key.guest_va_start(), 1234)
            else {
                panic!("first lookup must claim");
            };
            let mut reserved = claim
                .reserve(lengths.code, lengths.hot, lengths.cold)
                .expect("reserve prepared extents");
            let mapped = MappedPublicationFixture::from_claim(&prepared, reserved.extents());
            // SAFETY: the fixture owns exact disjoint buffers populated from the
            // real prepared publication and uses this permit only once.
            let permit = unsafe { reserved.begin_mapped_write() }.expect("mapped permit");
            mapped.establishes(&permit);
            let code_len = mapped.code.len() - usize::from(short_stream == 0);
            let hot_len = mapped.hot.len() - usize::from(short_stream == 1);
            let cold_len = mapped.cold.len() - usize::from(short_stream == 2);
            // SAFETY: all arguments originate from the fixture's claim-derived
            // buffers; the selected stream is deliberately short, so the seam
            // must reject before treating it as a complete mapped publication.
            let result = unsafe {
                permit.certify_mapped(
                    &mapped.code[..code_len],
                    &mapped.hot[..hot_len],
                    &mapped.cold[..cold_len],
                    key.guest_va_start(),
                    0,
                    expected,
                )
            };
            assert!(matches!(result, Err(LivePrivateReason::InvalidRecord)));
        }
    }

    #[test]
    fn corrupt_code_hot_or_cold_refuses_certification() {
        for corrupt_stream in 0..3 {
            let arena = arena();
            let key = key();
            let prepared = prepared_publication();
            let lengths = prepared.lengths();
            let expected = prepared.expected_publication();
            let LiveLookup::Publish(claim) = arena.claim_eligible(&key, key.guest_va_start(), 1234)
            else {
                panic!("first lookup must claim");
            };
            let mut reserved = claim
                .reserve(lengths.code, lengths.hot, lengths.cold)
                .expect("reserve prepared extents");
            let mut mapped = MappedPublicationFixture::from_claim(&prepared, reserved.extents());
            match corrupt_stream {
                0 => mapped.code[0] ^= 0xff,
                1 => mapped.hot[0] ^= 0xff,
                _ => mapped.cold[0] ^= 0xff,
            }
            // SAFETY: the fixture owns the claim-derived mapped buffers. One
            // stream is deliberately corrupted before certification.
            let permit = unsafe { reserved.begin_mapped_write() }.expect("mapped permit");
            mapped.establishes(&permit);
            // SAFETY: the fixture establishes the mapping/lifetime contract;
            // content authentication is the behavior under test.
            let result = unsafe {
                permit.certify_mapped(
                    &mapped.code,
                    &mapped.hot,
                    &mapped.cold,
                    key.guest_va_start(),
                    0,
                    expected,
                )
            };
            assert!(matches!(result, Err(LivePrivateReason::InvalidRecord)));
        }
    }

    #[test]
    fn generation_change_before_certification_refuses_completion() {
        let arena = arena();
        let key = key();
        let prepared = prepared_publication();
        let lengths = prepared.lengths();
        let expected = prepared.expected_publication();
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim");
        };
        let mut reserved = claim
            .reserve(lengths.code, lengths.hot, lengths.cold)
            .expect("reserve prepared extents");
        let mapped = MappedPublicationFixture::from_claim(&prepared, reserved.extents());
        // SAFETY: the fixture owns the exact disjoint ranges populated from
        // the real prepared publication and enters the permit only once.
        let permit = unsafe { reserved.begin_mapped_write() }.expect("mapped permit");
        mapped.establishes(&permit);
        arena
            .generations
            .note_guest_code_write(key.guest_va_start()..GuestVa(key.guest_va_start().raw() + 4))
            .expect("advance source generation");
        // SAFETY: the fixture establishes the mapping/lifetime contract; the
        // post-observation mutation is the refusal condition under test.
        let result = unsafe {
            permit.certify_mapped(
                &mapped.code,
                &mapped.hot,
                &mapped.cold,
                key.guest_va_start(),
                0,
                expected,
            )
        };

        assert!(matches!(result, Err(LivePrivateReason::InvalidRecord)));
    }

    #[test]
    fn generation_change_after_metadata_validation_refuses_completion() {
        let arena = arena();
        let key = key();
        let prepared = prepared_publication();
        let lengths = prepared.lengths();
        let expected = prepared.expected_publication();
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim");
        };
        let mut reserved = claim
            .reserve(lengths.code, lengths.hot, lengths.cold)
            .expect("reserve prepared extents");
        let mapped = MappedPublicationFixture::from_claim(&prepared, reserved.extents());
        // SAFETY: the fixture owns the exact disjoint ranges populated from
        // the real prepared publication and enters the permit only once.
        let permit = unsafe { reserved.begin_mapped_write() }.expect("mapped permit");
        mapped.establishes(&permit);
        // SAFETY: the fixture establishes the mapping/lifetime contract. The
        // private hook deterministically mutates generation only after exact
        // metadata validation, which is the race under test.
        let result = unsafe {
            permit.certify_mapped_after_metadata_for_test(
                &mapped.code,
                &mapped.hot,
                &mapped.cold,
                key.guest_va_start(),
                0,
                expected,
                || {
                    arena
                        .generations
                        .note_guest_code_write(
                            key.guest_va_start()..GuestVa(key.guest_va_start().raw() + 4),
                        )
                        .expect("advance source generation after metadata validation");
                },
            )
        };

        assert!(matches!(result, Err(LivePrivateReason::InvalidRecord)));
    }

    #[test]
    fn generation_change_before_mapped_write_terminalizes_building_claim() {
        let arena = arena();
        let key = key();
        let prepared = prepared_publication();
        let lengths = prepared.lengths();
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim");
        };
        let record_index = claim.record_index as usize;
        let mut reserved = claim
            .reserve(lengths.code, lengths.hot, lengths.cold)
            .expect("reserve prepared extents");
        arena
            .generations
            .note_guest_code_write(key.guest_va_start()..GuestVa(key.guest_va_start().raw() + 4))
            .expect("advance the claim's authoritative generation");

        // SAFETY: no mapped range is accessed. Generation drift must reject
        // before returning any shared-write authority.
        let result = unsafe { reserved.begin_mapped_write() };

        assert!(matches!(result, Err(LivePrivateReason::InvalidRecord)));
        assert_eq!(
            arena.view().block_records[record_index]
                .state
                .load(Ordering::Acquire),
            LIVE_BLOCK_FAILED
        );
        assert!(matches!(
            unsafe { reserved.begin_mapped_write() },
            Err(LivePrivateReason::WriteAttempted)
        ));
    }

    #[test]
    fn generation_change_after_certification_refuses_ready_publication() {
        let arena = arena();
        let key = key();
        let prepared = prepared_publication();
        let lengths = prepared.lengths();
        let expected = prepared.expected_publication();
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim");
        };
        let record_index = claim.record_index as usize;
        let mut reserved = claim
            .reserve(lengths.code, lengths.hot, lengths.cold)
            .expect("reserve prepared extents");
        let mapped = MappedPublicationFixture::from_claim(&prepared, reserved.extents());
        // SAFETY: the fixture owns the exact disjoint mapped ranges and enters
        // the write permit once.
        let permit = unsafe { reserved.begin_mapped_write() }.expect("mapped permit");
        mapped.establishes(&permit);
        // SAFETY: exact bytes and metadata come from the real prepared value.
        let written = unsafe {
            permit.certify_mapped(
                &mapped.code,
                &mapped.hot,
                &mapped.cold,
                key.guest_va_start(),
                0,
                expected,
            )
        }
        .expect("certify mapped publication before drift");
        arena
            .generations
            .note_guest_code_write(key.guest_va_start()..GuestVa(key.guest_va_start().raw() + 4))
            .expect("advance authoritative generation after certification");

        assert!(matches!(
            reserved.publish(written),
            Err(LivePrivateReason::InvalidRecord)
        ));
        assert_eq!(
            arena.view().block_records[record_index]
                .state
                .load(Ordering::Acquire),
            LIVE_BLOCK_FAILED
        );
    }

    #[test]
    fn generation_change_after_payload_write_refuses_ready_publication() {
        let mut arena = arena();
        let key = key();
        let guest = key.guest_va_start();
        let mutate = Arc::clone(&arena.generations);
        arena.after_payload_write_before_ready = Some(Arc::new(move || {
            mutate
                .note_guest_code_write(guest..GuestVa(guest.raw() + 4))
                .expect("advance generation after BUILDING payload write");
        }));
        let prepared = prepared_publication();
        let lengths = prepared.lengths();
        let LiveLookup::Publish(claim) = arena.claim_eligible(&key, guest, 1234) else {
            panic!("first lookup must claim");
        };
        let record_index = claim.record_index as usize;
        let mut reserved = claim
            .reserve(lengths.code, lengths.hot, lengths.cold)
            .expect("reserve prepared extents");
        let (written, _mapped) = certify_prepared(&mut reserved, &prepared);

        assert!(matches!(
            reserved.publish(written),
            Err(LivePrivateReason::InvalidRecord)
        ));
        assert_eq!(
            arena.view().block_records[record_index]
                .state
                .load(Ordering::Acquire),
            LIVE_BLOCK_FAILED
        );
        assert!(matches!(
            arena.acquire_ready_or_miss(&key, guest),
            LiveReadyLookup::Private(LivePrivateReason::Failed)
        ));
    }

    #[test]
    fn written_block_from_one_claim_cannot_publish_another() {
        let arena = arena();
        let key = key();
        let prepared = prepared_publication();
        let lengths = prepared.lengths();
        let expected = prepared.expected_publication();
        let LiveLookup::Publish(first_claim) =
            arena.claim_eligible(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim");
        };
        let mut first_reserved = first_claim
            .reserve(lengths.code, lengths.hot, lengths.cold)
            .expect("reserve first extents");
        let mapped = MappedPublicationFixture::from_claim(&prepared, first_reserved.extents());
        // SAFETY: the fixture establishes the complete mapped contract for the
        // first claim and enters its permit exactly once.
        let permit = unsafe { first_reserved.begin_mapped_write() }.expect("mapped permit");
        mapped.establishes(&permit);
        // SAFETY: exact bytes and metadata come from the real prepared value.
        let written = unsafe {
            permit.certify_mapped(
                &mapped.code,
                &mapped.hot,
                &mapped.cold,
                key.guest_va_start(),
                0,
                expected,
            )
        }
        .expect("certify first mapped write");

        let other_guest = GuestVa(key.guest_va_start().raw() + PAGE);
        let LiveLookup::Publish(other_claim) = arena.claim_eligible(&key, other_guest, 5678) else {
            panic!("different guest start must claim another record");
        };
        let other_reserved = other_claim
            .reserve(lengths.code, lengths.hot, lengths.cold)
            .expect("reserve other extents");

        assert!(matches!(
            other_reserved.publish(written),
            Err(LivePrivateReason::InvalidRecord)
        ));
        assert_eq!(
            arena
                .claim_eligible(&key, other_guest, 9999)
                .private_reason(),
            Some(LivePrivateReason::Failed)
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct CapacityFixtureHeaderV2 {
        schema: u32,
        header_len: u32,
        record_len: u32,
        record_count: u32,
        capture_source_base_commit: [u8; 20],
        capture_source_snapshot_commit: [u8; 20],
        capture_source_snapshot_tree: [u8; 20],
        capture_source_changed_blob: [u8; 20],
        capture_source_diff_sha256: [u8; 32],
        signed_binary_sha256: [u8; 32],
        image_digest: [u8; 32],
        fresh_capture_content_sha256: [u8; 32],
        path_including_manifest_sha256: [u8; 32],
        path_independent_manifest_sha256: [u8; 32],
        executable_digest: [u8; 32],
        source_fingerprint: [u8; 32],
        segment_file_offset: u64,
        segment_file_len: u64,
        guest_va_start: u64,
        guest_va_len: u64,
        page_profile: u32,
        address_mode: u32,
        host_bias: u64,
        translator_abi: u32,
        compiler_unit_stem: [u8; 32],
        mapped_v2_unit_digest: [u8; 32],
        source_v1_unit_digest: [u8; 32],
        source_group_count: u32,
        max_code_len: u32,
        aligned_code_total: u64,
        aligned_hot_total: u64,
        aligned_cold_total: u64,
        ideal_chunk_count: u32,
        analytical_chunk_bound: u32,
        block_record_capacity: u32,
        source_group_capacity: u32,
        chunk_capacity: u32,
        chunk_bytes: u32,
        hot_capacity: u32,
        cold_capacity: u32,
    }

    fn parse_capacity_fixture_header_v2(fixture: &[u8]) -> CapacityFixtureHeaderV2 {
        fn bytes<const N: usize>(fixture: &[u8], offset: usize) -> [u8; N] {
            fixture[offset..offset + N]
                .try_into()
                .expect("complete fixture header field")
        }
        fn u32_at(fixture: &[u8], offset: usize) -> u32 {
            u32::from_le_bytes(bytes(fixture, offset))
        }
        fn u64_at(fixture: &[u8], offset: usize) -> u64 {
            u64::from_le_bytes(bytes(fixture, offset))
        }

        assert_eq!(&fixture[..16], b"CLVCAPKEYV2\0\0\0\0\0");
        // Authenticated 640-byte little-endian field map. Source/binary/image,
        // raw-receipt manifests, and every exact compiler key determinant are
        // literal fixture fields; measured geometry follows at 496. Records
        // begin at the authenticated header length.
        CapacityFixtureHeaderV2 {
            schema: u32_at(fixture, 16),
            header_len: u32_at(fixture, 20),
            record_len: u32_at(fixture, 24),
            record_count: u32_at(fixture, 28),
            capture_source_base_commit: bytes(fixture, 32),
            capture_source_snapshot_commit: bytes(fixture, 52),
            capture_source_snapshot_tree: bytes(fixture, 72),
            capture_source_changed_blob: bytes(fixture, 92),
            capture_source_diff_sha256: bytes(fixture, 112),
            signed_binary_sha256: bytes(fixture, 144),
            image_digest: bytes(fixture, 176),
            fresh_capture_content_sha256: bytes(fixture, 208),
            path_including_manifest_sha256: bytes(fixture, 240),
            path_independent_manifest_sha256: bytes(fixture, 272),
            executable_digest: bytes(fixture, 304),
            source_fingerprint: bytes(fixture, 336),
            segment_file_offset: u64_at(fixture, 368),
            segment_file_len: u64_at(fixture, 376),
            guest_va_start: u64_at(fixture, 384),
            guest_va_len: u64_at(fixture, 392),
            page_profile: u32_at(fixture, 400),
            address_mode: u32_at(fixture, 404),
            host_bias: u64_at(fixture, 408),
            translator_abi: u32_at(fixture, 416),
            compiler_unit_stem: bytes(fixture, 432),
            mapped_v2_unit_digest: bytes(fixture, 464),
            source_group_count: u32_at(fixture, 496),
            max_code_len: u32_at(fixture, 500),
            aligned_code_total: u64_at(fixture, 504),
            aligned_hot_total: u64_at(fixture, 512),
            aligned_cold_total: u64_at(fixture, 520),
            ideal_chunk_count: u32_at(fixture, 528),
            analytical_chunk_bound: u32_at(fixture, 532),
            block_record_capacity: u32_at(fixture, 536),
            source_group_capacity: u32_at(fixture, 540),
            chunk_capacity: u32_at(fixture, 544),
            chunk_bytes: u32_at(fixture, 548),
            hot_capacity: u32_at(fixture, 552),
            cold_capacity: u32_at(fixture, 556),
            source_v1_unit_digest: bytes(fixture, 560),
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct CapacityFixtureRecord {
        guest: u64,
        code: u16,
        hot: u16,
        cold: u16,
        block_initial: usize,
        group_initial: usize,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct CapacitySimulation {
        block_refusals: usize,
        group_refusals: usize,
        chunks: u64,
    }

    fn simulate_capacity_order(records: &[CapacityFixtureRecord]) -> CapacitySimulation {
        use std::collections::HashMap;

        let mut block_table = vec![None; LIVE_ARENA_BLOCK_RECORDS];
        let mut group_table = vec![None; LIVE_ARENA_SOURCE_GROUPS];
        let mut chunk_fill: HashMap<u64, (u64, u64)> = HashMap::new();
        let mut block_refusals = 0;
        let mut group_refusals = 0;
        for record in records {
            let mut block_inserted = false;
            let initial = record.block_initial;
            for probe in 0..LIVE_ARENA_PROBES {
                let slot = (initial + probe) & LIVE_BLOCK_MASK;
                match block_table[slot] {
                    Some(existing) if existing == record.guest => {
                        block_inserted = true;
                        break;
                    }
                    Some(_) => {}
                    None => {
                        block_table[slot] = Some(record.guest);
                        block_inserted = true;
                        break;
                    }
                }
            }
            block_refusals += usize::from(!block_inserted);

            let source_page = record.guest / LIVE_SOURCE_PAGE_BYTES * LIVE_SOURCE_PAGE_BYTES;
            let mut group_inserted = false;
            let initial = record.group_initial;
            for probe in 0..LIVE_ARENA_PROBES {
                let slot = (initial + probe) & LIVE_GROUP_MASK;
                match group_table[slot] {
                    Some(existing) if existing == source_page => {
                        group_inserted = true;
                        break;
                    }
                    Some(_) => {}
                    None => {
                        group_table[slot] = Some(source_page);
                        group_inserted = true;
                        break;
                    }
                }
            }
            group_refusals += usize::from(!group_inserted);

            let aligned_code = u64::from(record.code).next_multiple_of(4);
            let (used, chunks) = chunk_fill.entry(source_page).or_insert((0, 0));
            if *chunks == 0
                || used
                    .checked_add(aligned_code)
                    .is_none_or(|end| end > 65_536)
            {
                *used = aligned_code;
                *chunks += 1;
            } else {
                *used += aligned_code;
            }
        }
        CapacitySimulation {
            block_refusals,
            group_refusals,
            chunks: chunk_fill.values().map(|(_, chunks)| chunks).sum(),
        }
    }

    fn shuffle_capacity_records(records: &mut [CapacityFixtureRecord], seed: u64) {
        fn splitmix64(state: &mut u64) -> u64 {
            *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut value = *state;
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            value ^ (value >> 31)
        }

        let mut state = seed;
        for index in (1..records.len()).rev() {
            let swap = splitmix64(&mut state) as usize % (index + 1);
            records.swap(index, swap);
        }
    }

    #[test]
    fn v2_capacity_fixture_passes_production_hash_and_chunk_thresholds() {
        use std::collections::{HashMap, HashSet};

        fn bytes<const N: usize>(fixture: &[u8], offset: usize) -> [u8; N] {
            fixture[offset..offset + N]
                .try_into()
                .expect("complete fixture field")
        }
        fn hex<const N: usize>(input: &str) -> [u8; N] {
            assert_eq!(input.len(), N * 2);
            let mut output = [0_u8; N];
            for (index, byte) in output.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16)
                    .expect("literal hex byte");
            }
            output
        }

        let fixture = include_bytes!("../tests/fixtures/live-arena-v2-capacity.bin");
        assert_eq!(fixture.len(), 1_197_990);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(fixture)),
            hex("576ee809efd4091abbd9b85c7aa2a729ad0d81cfc31940abbe3852454cb01368")
        );
        let capture_source_patch =
            include_bytes!("../tests/fixtures/live-arena-v2-capture-source.patch");
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(capture_source_patch)),
            hex("6df147f2a49a2af862e190ff49f5a606f387e94964656918bbd09a0d94587564")
        );
        let header = parse_capacity_fixture_header_v2(fixture);
        assert_eq!(
            header,
            CapacityFixtureHeaderV2 {
                schema: 2,
                header_len: 640,
                record_len: 14,
                record_count: 85_525,
                capture_source_base_commit: hex("776757767cb81e5530a64522f2c51d42703df063",),
                capture_source_snapshot_commit: hex("6e9661a9fd09d2ebceb5e4c877f4b0fa0074278c",),
                capture_source_snapshot_tree: hex("4aff73118b487e794a59b75105dfe9bc07bb22c7",),
                capture_source_changed_blob: hex("cc058f27a56cde9ede1eeb9645fd53178d08d493",),
                capture_source_diff_sha256: hex(
                    "6df147f2a49a2af862e190ff49f5a606f387e94964656918bbd09a0d94587564",
                ),
                signed_binary_sha256: hex(
                    "b93ffe43bef154a3e27ae0e622c76861ea6b46878946e221d546b8174655304f",
                ),
                image_digest: hex(
                    "357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b",
                ),
                fresh_capture_content_sha256: hex(
                    "f1711b8931a04038208376a628f672b594edb100adca97b0f1774b33f85069e4",
                ),
                path_including_manifest_sha256: hex(
                    "770467de78a3bc2a52b047d51f4afd52a3fc297002ef735b4c1e3db2b698d7d7",
                ),
                path_independent_manifest_sha256: hex(
                    "179f9fee387e3d08fb76eab8c4b79ec6f7e3871a55eb5b018b718c3c662798e4",
                ),
                executable_digest: hex(
                    "5d3ce715273cf3bea2215369d94cbf36126aed4727a0b0d193bdb0ea3eb5f1af",
                ),
                source_fingerprint: hex(
                    "daba53756180cae9b69ac6780bd4fc14f47bc6fe9d3a420cb2d72f3bfff97a5d",
                ),
                segment_file_offset: 0x1_0000,
                segment_file_len: 0x8d_5000,
                guest_va_start: 0x1_0000,
                guest_va_len: 0x8d_5000,
                page_profile: 1,
                address_mode: 1,
                host_bias: 0x80_0000_0000,
                translator_abi: 8,
                compiler_unit_stem: hex(
                    "a5948df76537f6a44e99e30b712e46ceae1871f91f3fe11e954b421dab7752b5",
                ),
                mapped_v2_unit_digest: hex(
                    "17aecdd62fbeecd162a9446eee91ae44bea0cd96e190a8cf743402b33f7b456b",
                ),
                source_v1_unit_digest: hex(
                    "5dc3adc12b05baff1a0dbf6d333feb964d7234751a0ce17823e87ceeee1be759",
                ),
                source_group_count: 407,
                max_code_len: 5_536,
                aligned_code_total: 36_341_884,
                aligned_hot_total: 684_200,
                aligned_cold_total: 24_681_640,
                ideal_chunk_count: 781,
                analytical_chunk_bound: 794,
                block_record_capacity: 262_144,
                source_group_capacity: 4_096,
                chunk_capacity: 1_024,
                chunk_bytes: 65_536,
                hot_capacity: 1_048_576,
                cold_capacity: 33_554_432,
            }
        );
        assert_eq!(
            header.translator_abi,
            crate::shared_cache::TRANSLATOR_ABI_CURRENT
        );
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(capture_source_patch)),
            header.capture_source_diff_sha256
        );
        let page_profile = match header.page_profile {
            1 => NativePageProfileIdentity::Native16k,
            value => panic!("unsupported fixture page profile {value}"),
        };
        let address_mode = match header.address_mode {
            0 => AddressModeIdentity::Direct,
            1 => AddressModeIdentity::biased(
                carrick_dsr::address::NativeHostBias::new(header.host_bias, 16 * 1024)
                    .expect("captured aligned host bias"),
            ),
            value => panic!("unsupported fixture address mode {value}"),
        };
        let captured_key = TranslationUnitKey::for_segment(
            ExecutableIdentity::Digest(header.executable_digest),
            ImageFileOffset::new(header.segment_file_offset),
            ImageFileLen::new(header.segment_file_len).expect("captured nonzero file length"),
            GuestVa(header.guest_va_start),
            GuestCodeLen::new(header.guest_va_len).expect("captured nonzero guest length"),
            SourceFingerprint(header.source_fingerprint),
            page_profile,
            address_mode,
        );
        let expected_stem = header
            .compiler_unit_stem
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            captured_key.file_stem().expect("captured key file stem"),
            expected_stem
        );
        let unit_digest = captured_key
            .live_digest()
            .expect("production V2 live digest");
        assert_eq!(unit_digest, header.mapped_v2_unit_digest);

        let mut records = Vec::with_capacity(85_525);
        let header_len = usize::try_from(header.header_len).expect("header length fits usize");
        for record in fixture[header_len..].chunks_exact(14) {
            let guest = u64::from_le_bytes(bytes(record, 0));
            let source_page = guest / LIVE_SOURCE_PAGE_BYTES * LIVE_SOURCE_PAGE_BYTES;
            records.push(CapacityFixtureRecord {
                guest,
                code: u16::from_le_bytes(bytes(record, 8)),
                hot: u16::from_le_bytes(bytes(record, 10)),
                cold: u16::from_le_bytes(bytes(record, 12)),
                block_initial: initial_slot(&unit_digest, guest),
                group_initial: initial_group_slot(&unit_digest, source_page),
            });
        }
        assert_eq!(records.len(), 85_525);
        assert_eq!(
            records
                .iter()
                .map(|record| record.guest)
                .collect::<HashSet<_>>()
                .len(),
            records.len()
        );

        let mut groups: HashMap<u64, (u64, u64)> = HashMap::new();
        let mut code_total = 0_u64;
        let mut hot_total = 0_u64;
        let mut cold_total = 0_u64;
        let mut max_code = 0_u64;
        for record in &records {
            let code = u64::from(record.code).next_multiple_of(4);
            code_total += code;
            hot_total += u64::from(record.hot).next_multiple_of(8);
            cold_total += u64::from(record.cold).next_multiple_of(8);
            max_code = max_code.max(code);
            let source_page = record.guest / LIVE_SOURCE_PAGE_BYTES * LIVE_SOURCE_PAGE_BYTES;
            let group = groups.entry(source_page).or_insert((0, 0));
            group.0 += code;
            group.1 = group.1.max(code);
        }
        let ideal_chunks: u64 = groups
            .values()
            .map(|(total, _)| total.div_ceil(LIVE_ARENA_CHUNK_BYTES))
            .sum();
        let analytical_bound: u64 = groups
            .values()
            .map(|(total, max)| total.div_ceil(LIVE_ARENA_CHUNK_BYTES - max + 1))
            .sum();
        assert_eq!(
            (
                groups.len(),
                code_total,
                hot_total,
                cold_total,
                max_code,
                ideal_chunks,
                analytical_bound,
            ),
            (407, 36_341_884, 684_200, 24_681_640, 5_536, 781, 794)
        );
        assert!(records.len() * 2 <= LIVE_ARENA_BLOCK_RECORDS);
        assert!(groups.len() * 4 <= LIVE_ARENA_SOURCE_GROUPS);
        assert!(hot_total * 100 <= LIVE_ARENA_HOT_CAPACITY * 85);
        assert!(cold_total * 100 <= LIVE_ARENA_COLD_CAPACITY * 85);
        assert!(max_code <= LIVE_ARENA_CHUNK_BYTES);
        assert!(analytical_bound <= LIVE_ARENA_CHUNKS as u64);

        let mut max_block_refusals = 0;
        let mut max_group_refusals = 0;
        let mut min_chunks = u64::MAX;
        let mut max_chunks = 0;
        let mut check_order = |order: &[CapacityFixtureRecord]| {
            let simulation = simulate_capacity_order(order);
            assert!(simulation.block_refusals * 1_000 <= records.len());
            assert_eq!(simulation.group_refusals, 0);
            assert!(simulation.chunks * 10 <= LIVE_ARENA_CHUNKS as u64 * 9);
            max_block_refusals = max_block_refusals.max(simulation.block_refusals);
            max_group_refusals = max_group_refusals.max(simulation.group_refusals);
            min_chunks = min_chunks.min(simulation.chunks);
            max_chunks = max_chunks.max(simulation.chunks);
        };
        check_order(&records);
        let mut sorted = records.clone();
        sorted.sort_unstable_by_key(|record| record.guest);
        check_order(&sorted);
        for seed in 0..100_u64 {
            let mut shuffled = records.clone();
            shuffle_capacity_records(&mut shuffled, 0x6c69_7665_2d76_3200_u64 ^ seed);
            check_order(&shuffled);
        }
        assert_eq!(
            (
                max_block_refusals,
                max_group_refusals,
                min_chunks,
                max_chunks,
            ),
            (0, 0, 781, 784)
        );
    }
}
