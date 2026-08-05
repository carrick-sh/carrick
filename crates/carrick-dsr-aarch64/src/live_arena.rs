//! Offset-only, wait-free protocol for a container-lifetime translation arena.
//!
//! This module owns only the portable wire and state-machine contract. Darwin
//! mappings and translator integration deliberately stay outside this layer.

use crate::artifact_spike::validate_shared_initial_metadata;
use crate::emit::ExpectedLivePublication;
use crate::shared_cache::{TRANSLATOR_ABI_CURRENT, TranslationUnitKey};
use carrick_dsr::cache::PageGenerationObservation;
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

pub const LIVE_ARENA_SCHEMA_V1: u32 = 1;
pub const LIVE_BLOCK_EMPTY: u32 = 0;
pub const LIVE_BLOCK_BUILDING: u32 = 1;
pub const LIVE_BLOCK_READY: u32 = 2;
pub const LIVE_BLOCK_FAILED: u32 = 3;
pub const LIVE_ARENA_RECORDS: usize = 131_072;
pub const LIVE_ARENA_OBJECT_HEADER_BYTES: usize = 64;
pub const LIVE_ARENA_CACHE_LINE_BYTES: usize = 64;
pub const LIVE_ARENA_CONTROL_DIRECTORY_BYTES: usize = 192;
pub const LIVE_ARENA_CONTROL_READY: u32 = 1;
const LIVE_ARENA_PROBES: usize = 16;
const LIVE_ARENA_MASK: usize = LIVE_ARENA_RECORDS - 1;
const LIVE_ARENA_PAGE_BYTES: u64 = 16 * 1024;
const LIVE_ARENA_INSTRUCTION_BYTES: u64 = 4;
const LIVE_ARENA_METADATA_ALIGN: u64 = 8;

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
pub struct LiveArenaControlDirectoryV1 {
    pub initialization_state: AtomicU32,
    pub schema: u32,
    pub translator_abi: u32,
    pub directory_len: u32,
    pub nonce: [u8; 16],
    pub code_payload_base: u64,
    pub code_capacity: u64,
    pub code_cursor_offset: u64,
    pub hot_cursor_offset: u64,
    pub cold_cursor_offset: u64,
    pub records_offset: u64,
    pub records_len: u64,
    pub record_count: u32,
    pub record_stride: u32,
    pub hot_base: u64,
    pub hot_capacity: u64,
    pub cold_base: u64,
    pub cold_capacity: u64,
    pub control_len: u64,
    pub leaked_extents: AtomicU64,
    reserved: [u64; 6],
}

const _: () = assert!(std::mem::align_of::<LiveArenaControlDirectoryV1>() == 64);
const _: () = assert!(
    std::mem::size_of::<LiveArenaControlDirectoryV1>() == LIVE_ARENA_CONTROL_DIRECTORY_BYTES
);
const _: () = assert!(std::mem::offset_of!(LiveArenaControlDirectoryV1, initialization_state) == 0);
const _: () = assert!(std::mem::offset_of!(LiveArenaControlDirectoryV1, nonce) == 16);
const _: () = assert!(std::mem::offset_of!(LiveArenaControlDirectoryV1, code_payload_base) == 32);
const _: () = assert!(std::mem::offset_of!(LiveArenaControlDirectoryV1, records_offset) == 72);
const _: () = assert!(std::mem::offset_of!(LiveArenaControlDirectoryV1, hot_base) == 96);
const _: () = assert!(std::mem::offset_of!(LiveArenaControlDirectoryV1, control_len) == 128);
const _: () = assert!(std::mem::offset_of!(LiveArenaControlDirectoryV1, leaked_extents) == 136);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveArenaControlLayout {
    capacities: LiveArenaCapacities,
    host_page: usize,
    code_payload_base: usize,
    code_len: usize,
    directory_offset: usize,
    code_cursor_offset: usize,
    hot_cursor_offset: usize,
    cold_cursor_offset: usize,
    records_offset: usize,
    records_len: usize,
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
            .checked_add(std::mem::size_of::<LiveArenaControlDirectoryV1>())
            .ok_or_else(|| LiveArenaLayoutError::new("directory end overflow"))?;
        let code_cursor_offset = checked_align_up(directory_end, LIVE_ARENA_CACHE_LINE_BYTES)?;
        let hot_cursor_offset = code_cursor_offset
            .checked_add(LIVE_ARENA_CACHE_LINE_BYTES)
            .ok_or_else(|| LiveArenaLayoutError::new("HOT cursor offset overflow"))?;
        let cold_cursor_offset = hot_cursor_offset
            .checked_add(LIVE_ARENA_CACHE_LINE_BYTES)
            .ok_or_else(|| LiveArenaLayoutError::new("COLD cursor offset overflow"))?;
        let records_offset = cold_cursor_offset
            .checked_add(LIVE_ARENA_CACHE_LINE_BYTES)
            .ok_or_else(|| LiveArenaLayoutError::new("record offset overflow"))?;
        let records_len = LIVE_ARENA_RECORDS
            .checked_mul(std::mem::size_of::<LiveBlockRecordV1>())
            .ok_or_else(|| LiveArenaLayoutError::new("record table length overflow"))?;
        let records_end = records_offset
            .checked_add(records_len)
            .ok_or_else(|| LiveArenaLayoutError::new("record table end overflow"))?;
        let hot_base = checked_align_up(records_end, LIVE_ARENA_METADATA_ALIGN as usize)?;
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
            code_cursor_offset,
            hot_cursor_offset,
            cold_cursor_offset,
            records_offset,
            records_len,
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
    pub const fn code_cursor_offset(self) -> usize {
        self.code_cursor_offset
    }
    pub const fn hot_cursor_offset(self) -> usize {
        self.hot_cursor_offset
    }
    pub const fn cold_cursor_offset(self) -> usize {
        self.cold_cursor_offset
    }
    pub const fn records_offset(self) -> usize {
        self.records_offset
    }
    pub const fn records_len(self) -> usize {
        self.records_len
    }
    pub const fn records_end(self) -> usize {
        self.records_offset + self.records_len
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
    if LiveArenaControlLayout::new(layout.capacities, layout.host_page)? != layout {
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
    directory: &LiveArenaControlDirectoryV1,
    layout: LiveArenaControlLayout,
    nonce: [u8; 16],
) -> Result<(), LiveArenaLayoutError> {
    let matches = directory.schema == LIVE_ARENA_SCHEMA_V1
        && directory.translator_abi == TRANSLATOR_ABI_CURRENT
        && directory.directory_len == LIVE_ARENA_CONTROL_DIRECTORY_BYTES as u32
        && directory.nonce == nonce
        && directory.code_payload_base == layout.code_payload_base as u64
        && directory.code_capacity == layout.capacities.code
        && directory.code_cursor_offset == layout.code_cursor_offset as u64
        && directory.hot_cursor_offset == layout.hot_cursor_offset as u64
        && directory.cold_cursor_offset == layout.cold_cursor_offset as u64
        && directory.records_offset == layout.records_offset as u64
        && directory.records_len == layout.records_len as u64
        && directory.record_count == LIVE_ARENA_RECORDS as u32
        && directory.record_stride == std::mem::size_of::<LiveBlockRecordV1>() as u32
        && directory.hot_base == layout.hot_base as u64
        && directory.hot_capacity == layout.capacities.hot
        && directory.cold_base == layout.cold_base as u64
        && directory.cold_capacity == layout.capacities.cold
        && directory.control_len == layout.control_len as u64
        && directory.reserved == [0; 6];
    if !matches {
        return Err(LiveArenaLayoutError::new(
            "control directory does not match canonical layout",
        ));
    }
    Ok(())
}

#[repr(C, align(64))]
pub struct LiveBlockRecordV1 {
    state: AtomicU32,
    owner_pid: AtomicI32,
    payload: UnsafeCell<LiveBlockPayloadV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
struct LiveBlockPayloadV1 {
    unit_key_digest: [u8; 32],
    guest_start: u64,
    source_page: u64,
    code_offset: u64,
    code_len: u32,
    entry_offset: u32,
    hot_offset: u64,
    hot_len: u32,
    cold_offset: u64,
    cold_len: u32,
    code_sha256: [u8; 32],
}

// SAFETY: `payload` has one writer: the capability returned by the successful
// EMPTY -> BUILDING CAS. No lookup reads it in EMPTY or BUILDING. That writer
// initializes the complete payload before publishing READY or FAILED with a
// Release store; readers access it only after the corresponding Acquire load.
// Terminal records are immutable and never return to BUILDING.
unsafe impl Sync for LiveBlockRecordV1 {}

const _: () = assert!(std::mem::align_of::<LiveBlockRecordV1>() == 64);
const _: () = assert!(std::mem::size_of::<LiveBlockRecordV1>() == 192);
const _: () = assert!(std::mem::align_of::<LiveBlockPayloadV1>() == 8);
const _: () = assert!(std::mem::size_of::<LiveBlockPayloadV1>() == 128);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV1, state) == 0);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV1, owner_pid) == 4);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV1, payload) == 8);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV1, unit_key_digest) == 0);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV1, guest_start) == 32);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV1, source_page) == 40);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV1, code_offset) == 48);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV1, code_len) == 56);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV1, entry_offset) == 60);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV1, hot_offset) == 64);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV1, hot_len) == 72);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV1, cold_offset) == 80);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV1, cold_len) == 88);
const _: () = assert!(std::mem::offset_of!(LiveBlockPayloadV1, code_sha256) == 92);

impl LiveBlockRecordV1 {
    fn empty() -> Self {
        Self {
            state: AtomicU32::new(LIVE_BLOCK_EMPTY),
            owner_pid: AtomicI32::new(0),
            payload: UnsafeCell::new(LiveBlockPayloadV1::empty()),
        }
    }

    /// Returns the immutable terminal payload after the caller has acquired
    /// READY or FAILED from `state`.
    unsafe fn terminal_payload(&self) -> &LiveBlockPayloadV1 {
        // SAFETY: the caller proves terminal-state Acquire ordering. Terminal
        // payloads are never mutated, as documented by the `Sync` contract.
        unsafe { &*self.payload.get() }
    }

    /// Replaces the payload while the caller exclusively owns BUILDING.
    unsafe fn write_building_payload(&self, payload: LiveBlockPayloadV1) {
        // SAFETY: the caller proves it owns the unique BUILDING capability, so
        // no payload reference exists and no other writer can reach this cell.
        unsafe { self.payload.get().write(payload) };
    }
}

impl LiveBlockPayloadV1 {
    const fn empty() -> Self {
        Self {
            unit_key_digest: [0; 32],
            guest_start: 0,
            source_page: 0,
            code_offset: 0,
            code_len: 0,
            entry_offset: 0,
            hot_offset: 0,
            hot_len: 0,
            cold_offset: 0,
            cold_len: 0,
            code_sha256: [0; 32],
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
    directory: NonNull<LiveArenaControlDirectoryV1>,
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
#[derive(Debug)]
pub struct LiveProcessViewBrand {
    identity: Arc<LiveProcessViewIdentity>,
}

impl LiveProcessViewBrand {
    pub fn fresh() -> Self {
        Self {
            identity: Arc::new(LiveProcessViewIdentity),
        }
    }

    fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveArenaCursorSnapshot {
    pub code: u64,
    pub hot: u64,
    pub cold: u64,
    /// Nonempty extents stranded when a later cursor reservation fails. The
    /// append-only allocator never reclaims or retries them.
    pub leaked_extents: u64,
}

#[derive(Clone, Copy)]
pub struct LiveTranslationArenaView<'a> {
    directory: &'a LiveArenaControlDirectoryV1,
    records: &'a [LiveBlockRecordV1],
    code_next: &'a AtomicU64,
    hot_next: &'a AtomicU64,
    cold_next: &'a AtomicU64,
    layout: LiveArenaControlLayout,
    brand: LiveArenaViewBrand,
    #[cfg(test)]
    cas_barrier: Option<&'a Barrier>,
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
            schema: LIVE_ARENA_SCHEMA_V1,
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
            .checked_add(std::mem::size_of::<LiveArenaControlDirectoryV1>())
            .ok_or_else(|| LiveArenaLayoutError::new("fixed directory end overflow"))?;
        if mapped_len < fixed_end {
            return Err(LiveArenaLayoutError::new(
                "control mapping is smaller than directory",
            ));
        }
        let directory_ptr =
            pointer_at::<LiveArenaControlDirectoryV1>(base, LIVE_ARENA_OBJECT_HEADER_BYTES)?;
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
            pointer_at::<LiveArenaControlDirectoryV1>(base, layout.directory_offset)?;
        let directory = LiveArenaControlDirectoryV1 {
            initialization_state: AtomicU32::new(0),
            schema: LIVE_ARENA_SCHEMA_V1,
            translator_abi: TRANSLATOR_ABI_CURRENT,
            directory_len: std::mem::size_of::<LiveArenaControlDirectoryV1>() as u32,
            nonce,
            code_payload_base: layout.code_payload_base as u64,
            code_capacity: layout.capacities.code,
            code_cursor_offset: layout.code_cursor_offset as u64,
            hot_cursor_offset: layout.hot_cursor_offset as u64,
            cold_cursor_offset: layout.cold_cursor_offset as u64,
            records_offset: layout.records_offset as u64,
            records_len: layout.records_len as u64,
            record_count: LIVE_ARENA_RECORDS as u32,
            record_stride: std::mem::size_of::<LiveBlockRecordV1>() as u32,
            hot_base: layout.hot_base as u64,
            hot_capacity: layout.capacities.hot,
            cold_base: layout.cold_base as u64,
            cold_capacity: layout.capacities.cold,
            control_len: layout.control_len as u64,
            leaked_extents: AtomicU64::new(0),
            reserved: [0; 6],
        };
        // SAFETY: the caller grants exclusive uninitialized storage and the
        // checked pointer is aligned and in bounds for the complete directory.
        unsafe { directory_ptr.as_ptr().write(directory) };
        for offset in [
            layout.code_cursor_offset,
            layout.hot_cursor_offset,
            layout.cold_cursor_offset,
        ] {
            let cursor = pointer_at::<AtomicU64>(base, offset)?;
            // SAFETY: each separately aligned cursor cell is disjoint and was
            // proved in-bounds by the canonical layout.
            unsafe { cursor.as_ptr().write(AtomicU64::new(0)) };
        }
        let records = pointer_at::<LiveBlockRecordV1>(base, layout.records_offset)?;
        for index in 0..LIVE_ARENA_RECORDS {
            // SAFETY: the canonical records range contains exactly this many
            // aligned, disjoint records and remains exclusively initialized.
            unsafe {
                records
                    .as_ptr()
                    .add(index)
                    .write(LiveBlockRecordV1::empty())
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
            pointer_at::<LiveArenaControlDirectoryV1>(base, layout.directory_offset)?;
        // SAFETY: fixed directory geometry was checked before this reference.
        let directory = unsafe { directory_ptr.as_ref() };
        if directory.initialization_state.load(Ordering::Acquire) != LIVE_ARENA_CONTROL_READY {
            return Err(LiveArenaLayoutError::new(
                "control directory is not initialized",
            ));
        }
        validate_directory(directory, layout, nonce)?;
        let code_next = pointer_at::<AtomicU64>(base, layout.code_cursor_offset)?;
        let hot_next = pointer_at::<AtomicU64>(base, layout.hot_cursor_offset)?;
        let cold_next = pointer_at::<AtomicU64>(base, layout.cold_cursor_offset)?;
        let records = pointer_at::<LiveBlockRecordV1>(base, layout.records_offset)?;
        // SAFETY: directory validation proved the canonical table range and
        // stride before the slice is formed.
        let records = unsafe { std::slice::from_raw_parts(records.as_ptr(), LIVE_ARENA_RECORDS) };
        Ok(Self {
            directory,
            records,
            // SAFETY: each checked cursor pointer is aligned, initialized, and
            // remains mapped for `'a`.
            code_next: unsafe { code_next.as_ref() },
            hot_next: unsafe { hot_next.as_ref() },
            cold_next: unsafe { cold_next.as_ref() },
            layout,
            brand: LiveArenaViewBrand {
                directory: directory_ptr,
                nonce,
            },
            #[cfg(test)]
            cas_barrier: None,
        })
    }

    pub fn cursor_snapshot(&self) -> LiveArenaCursorSnapshot {
        LiveArenaCursorSnapshot {
            code: self.code_next.load(Ordering::Acquire),
            hot: self.hot_next.load(Ordering::Acquire),
            cold: self.cold_next.load(Ordering::Acquire),
            leaked_extents: self.directory.leaked_extents.load(Ordering::Acquire),
        }
    }

    pub const fn layout(&self) -> LiveArenaControlLayout {
        self.layout
    }

    pub fn accepts_claim(&self, claim: &LiveReservedPublishClaim<'_>) -> bool {
        self.brand == claim.claim.arena.brand
    }

    /// Performs at most one acquire load per probe and one CAS only for an
    /// empty record. A collision probe is bounded lookup work, never waiting.
    pub fn lookup(
        &self,
        process_view: &'a LiveProcessViewBrand,
        key: &TranslationUnitKey,
        guest_start: GuestVa,
        owner_pid: i32,
    ) -> LiveLookup<'a> {
        let Ok(unit_key_digest) = key.live_digest() else {
            return LiveLookup::Private(LivePrivateReason::KeyEncoding);
        };
        let initial = initial_slot(&unit_key_digest, guest_start.raw());

        for probe in 0..LIVE_ARENA_PROBES {
            let record_index = (initial + probe) & LIVE_ARENA_MASK;
            let Ok(record_index_wire) = u32::try_from(record_index) else {
                return LiveLookup::Private(LivePrivateReason::InvalidRecord);
            };
            let record = &self.records[record_index];
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
                            .unwrap_or(LiveLookup::Private(LivePrivateReason::InvalidRecord));
                    }
                }
                LIVE_BLOCK_FAILED => {
                    // SAFETY: this branch acquired terminal FAILED above.
                    let payload = unsafe { record.terminal_payload() };
                    if record_matches(payload, &unit_key_digest, guest_start.raw()) {
                        return LiveLookup::Private(LivePrivateReason::Failed);
                    }
                }
                LIVE_BLOCK_BUILDING => return LiveLookup::Private(LivePrivateReason::Building),
                LIVE_BLOCK_EMPTY => {
                    #[cfg(test)]
                    if let Some(barrier) = &self.cas_barrier {
                        barrier.wait();
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
                                armed: true,
                            });
                        }
                        Err(_) => return LiveLookup::Private(LivePrivateReason::CasLost),
                    }
                }
                _ => return LiveLookup::Private(LivePrivateReason::UnknownState),
            }
        }

        LiveLookup::Private(LivePrivateReason::ExhaustedProbes)
    }

    fn validate_ready(
        &self,
        process_view: &LiveProcessViewBrand,
        record_index: usize,
        payload: &LiveBlockPayloadV1,
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
        if !record_matches(payload, expected_key, expected_guest_start)
            || !valid_source_page(payload.source_page, expected_guest_start)
            || !self.extents_in_bounds(extents)
            || !valid_code_extent(extents.code)
            || !valid_metadata_extent(extents.hot)
            || !valid_metadata_extent(extents.cold)
            || u64::from(payload.entry_offset) >= extents.code.len
            || !u64::from(payload.entry_offset).is_multiple_of(LIVE_ARENA_INSTRUCTION_BYTES)
        {
            return None;
        }
        Some(ValidatedLiveBlockRecord {
            record_index: u32::try_from(record_index).ok()?,
            payload: *payload,
            extents,
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
        let record = self.records.get(index)?;
        if record.state.load(Ordering::Acquire) != LIVE_BLOCK_READY {
            return None;
        }
        // SAFETY: this branch acquired terminal READY above.
        let payload = unsafe { record.terminal_payload() };
        if *payload != ready.payload {
            return None;
        }
        self.validate_ready(
            process_view,
            index,
            payload,
            &ready.payload.unit_key_digest,
            ready.payload.guest_start,
        )
    }

    fn extents_in_bounds(&self, extents: LiveBlockExtents) -> bool {
        extent_in_capacity(extents.code, self.code_capacity())
            && extent_in_capacity(extents.hot, self.hot_capacity())
            && extent_in_capacity(extents.cold, self.cold_capacity())
    }

    fn reserve(&self, code_len: u64, hot_len: u64, cold_len: u64) -> Option<LiveBlockExtents> {
        if code_len == 0 || !code_len.is_multiple_of(LIVE_ARENA_INSTRUCTION_BYTES) {
            return None;
        }
        let code = reserve_append(
            self.code_next,
            self.code_capacity(),
            code_len,
            LIVE_ARENA_PAGE_BYTES,
        )?;
        let Some(hot) = reserve_append(
            self.hot_next,
            self.hot_capacity(),
            hot_len,
            LIVE_ARENA_METADATA_ALIGN,
        ) else {
            self.directory
                .leaked_extents
                .fetch_add(1, Ordering::Relaxed);
            return None;
        };
        let Some(cold) = reserve_append(
            self.cold_next,
            self.cold_capacity(),
            cold_len,
            LIVE_ARENA_METADATA_ALIGN,
        ) else {
            let leaked = 1 + u64::from(hot.len != 0);
            self.directory
                .leaked_extents
                .fetch_add(leaked, Ordering::Relaxed);
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
}

#[cfg(test)]
pub struct LiveTranslationArena {
    storage: Vec<u8>,
    base: NonNull<u8>,
    layout: LiveArenaControlLayout,
    nonce: [u8; 16],
    process_view: LiveProcessViewBrand,
    cas_barrier: Option<Arc<Barrier>>,
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
        let layout = LiveArenaControlLayout::new(
            LiveArenaCapacities::new(code_capacity, hot_capacity, cold_capacity),
            LIVE_ARENA_PAGE_BYTES as usize,
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
        Self {
            storage,
            base,
            layout,
            nonce,
            process_view: LiveProcessViewBrand::fresh(),
            cas_barrier: None,
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
        view
    }

    pub fn lookup(
        &self,
        key: &TranslationUnitKey,
        guest_start: GuestVa,
        owner_pid: i32,
    ) -> LiveLookup<'_> {
        self.view()
            .lookup(&self.process_view, key, guest_start, owner_pid)
    }
}

pub struct LivePublishClaim<'a> {
    arena: LiveTranslationArenaView<'a>,
    record: &'a LiveBlockRecordV1,
    record_index: u32,
    process_view: &'a LiveProcessViewBrand,
    unit_key_digest: [u8; 32],
    guest_start: u64,
    armed: bool,
}

impl<'a> LivePublishClaim<'a> {
    pub fn owner_pid(&self) -> i32 {
        self.record.owner_pid.load(Ordering::Relaxed)
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
            return Err(LivePrivateReason::Failed);
        }
        let Some(wire_lengths) = LiveWireLengths::new(code_len, hot_len, cold_len) else {
            self.publish_failed();
            return Err(LivePrivateReason::InvalidRecord);
        };
        let Some(extents) = self.arena.reserve(code_len, hot_len, cold_len) else {
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
            return LivePrivateReason::Failed;
        }
        self.publish_failed();
        LivePrivateReason::Failed
    }

    fn publish_failed(&mut self) {
        if !self.armed {
            return;
        }
        let payload = LiveBlockPayloadV1 {
            unit_key_digest: self.unit_key_digest,
            guest_start: self.guest_start,
            ..LiveBlockPayloadV1::empty()
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
        if code_len == 0 || !code_len.is_multiple_of(LIVE_ARENA_INSTRUCTION_BYTES) {
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
            self.claim.publish_failed();
            return Err(LivePrivateReason::InvalidRecord);
        }
        let payload = LiveBlockPayloadV1 {
            unit_key_digest: written.unit_key_digest,
            guest_start: written.guest_start,
            source_page: written.source_page,
            code_offset: written.extents.code.offset,
            code_len: written.wire_lengths.code,
            entry_offset: written.entry_offset,
            hot_offset: written.extents.hot.offset,
            hot_len: written.wire_lengths.hot,
            cold_offset: written.extents.cold.offset,
            cold_len: written.wire_lengths.cold,
            code_sha256: written.code_sha256,
        };
        // SAFETY: this reserved claim is the unique BUILDING capability, and
        // every field above was rechecked against its private token.
        unsafe { self.claim.record.write_building_payload(payload) };
        self.claim
            .record
            .state
            .store(LIVE_BLOCK_READY, Ordering::Release);
        self.claim.armed = false;
        Ok(ValidatedLiveBlockRecord {
            record_index: self.claim.record_index,
            payload,
            extents: self.extents,
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
            return Err(LivePrivateReason::WriteAttempted);
        }
        self.write_attempted = true;
        Ok(LiveMappedWritePermit { claim: self })
    }

    pub fn fail(mut self) -> LivePrivateReason {
        if self.claim.record.state.load(Ordering::Acquire) != LIVE_BLOCK_BUILDING {
            return LivePrivateReason::Failed;
        }
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
        generation: &PageGenerationObservation,
        expected: ExpectedLivePublication,
    ) -> Result<LiveArenaWrittenBlock<'view>, LivePrivateReason> {
        // SAFETY: this forwards the caller's complete certification contract;
        // the production path has no test mutation hook.
        unsafe {
            self.certify_mapped_impl(
                code,
                hot,
                cold,
                source_page,
                entry_offset,
                generation,
                expected,
                || {},
            )
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
        generation: &PageGenerationObservation,
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
                generation,
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
        generation: &PageGenerationObservation,
        expected: ExpectedLivePublication,
        after_metadata_validation: impl FnOnce(),
    ) -> Result<LiveArenaWrittenBlock<'view>, LivePrivateReason> {
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
    record: NonNull<LiveBlockRecordV1>,
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
    payload: LiveBlockPayloadV1,
    extents: LiveBlockExtents,
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
    digest.update(unit_key_digest);
    digest.update(guest_start.to_le_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    let low = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    (low as usize) & LIVE_ARENA_MASK
}

fn record_matches(payload: &LiveBlockPayloadV1, key: &[u8; 32], guest_start: u64) -> bool {
    payload.unit_key_digest == *key && payload.guest_start == guest_start
}

fn valid_source_page(source_page: u64, guest_start: u64) -> bool {
    source_page.is_multiple_of(LIVE_ARENA_PAGE_BYTES)
        && guest_start.is_multiple_of(LIVE_ARENA_INSTRUCTION_BYTES)
        && source_page == guest_start / LIVE_ARENA_PAGE_BYTES * LIVE_ARENA_PAGE_BYTES
}

fn valid_code_extent(extent: LiveReservation) -> bool {
    extent.offset.is_multiple_of(LIVE_ARENA_PAGE_BYTES)
        && extent.len != 0
        && extent.len.is_multiple_of(LIVE_ARENA_INSTRUCTION_BYTES)
        && extent.len <= u64::from(u32::MAX)
}

fn valid_metadata_extent(extent: LiveReservation) -> bool {
    extent.offset.is_multiple_of(LIVE_ARENA_METADATA_ALIGN) && extent.len <= u64::from(u32::MAX)
}

fn extent_in_capacity(extent: LiveReservation, capacity: u64) -> bool {
    extent.end().is_some_and(|end| end <= capacity)
}

fn reserve_append(
    cursor: &AtomicU64,
    capacity: u64,
    len: u64,
    alignment: u64,
) -> Option<LiveReservation> {
    let reserved = cursor
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            let offset = align_up(current, alignment)?;
            let end = offset.checked_add(len)?;
            (end <= capacity).then_some(end)
        })
        .ok()?;
    let offset = align_up(reserved, alignment)?;
    Some(LiveReservation { offset, len })
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

    fn key() -> TranslationUnitKey {
        TranslationUnitKey::for_segment(
            ExecutableIdentity::Digest([0x42; 32]),
            ImageFileOffset::new(0),
            ImageFileLen::new(PAGE).expect("nonzero file length"),
            GuestVa(0x4000_0000),
            GuestCodeLen::new(PAGE).expect("nonzero guest length"),
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
        let generations = PageGenerationTable::new(PAGE).expect("generation table");
        let observation = generations
            .observe(key().guest_va_start())
            .expect("INITIAL observation");
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
                &observation,
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
        let record = &view.records[slot & LIVE_ARENA_MASK];
        let payload = LiveBlockPayloadV1 {
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

    fn malformed_ready_reason(
        mutate: impl FnOnce(&mut LiveBlockPayloadV1),
    ) -> Option<LivePrivateReason> {
        let arena = arena();
        let key = key();
        let guest_start = key.guest_va_start();
        let digest = key.live_digest().expect("live digest");
        let initial = initial_slot(&digest, guest_start.raw());
        let view = arena.view();
        let record = &view.records[initial];
        let mut payload = LiveBlockPayloadV1 {
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

        arena.lookup(&key, guest_start, 1234).private_reason()
    }

    fn seed_ready(
        arena: &LiveTranslationArena,
        key: &TranslationUnitKey,
    ) -> ValidatedLiveBlockRecord {
        let guest_start = key.guest_va_start();
        let digest = key.live_digest().expect("live digest");
        let initial = initial_slot(&digest, guest_start.raw());
        let view = arena.view();
        let record = &view.records[initial];
        let payload = LiveBlockPayloadV1 {
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
        unsafe { record.write_building_payload(payload) };
        record.state.store(LIVE_BLOCK_READY, Ordering::Release);
        let LiveLookup::Ready(ready) = arena.lookup(key, guest_start, 1234) else {
            panic!("seeded READY record must validate");
        };
        ready
    }

    #[test]
    fn ready_acquire_exposes_complete_record() {
        let arena = arena();
        let key = key();
        let published = seed_ready(&arena, &key);
        let LiveLookup::Ready(ready) = arena.lookup(&key, key.guest_va_start(), 9999) else {
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
        let LiveLookup::Publish(_claim) = arena.lookup(&key, key.guest_va_start(), 1234) else {
            panic!("first lookup must claim the empty record");
        };

        assert_eq!(
            arena
                .lookup(&key, key.guest_va_start(), 9999)
                .private_reason(),
            Some(LivePrivateReason::Building)
        );
    }

    #[test]
    fn failed_record_falls_back_without_waiting() {
        let arena = LiveTranslationArena::new(4, PAGE, PAGE);
        let key = key();
        let LiveLookup::Publish(claim) = arena.lookup(&key, key.guest_va_start(), 1234) else {
            panic!("first lookup must claim the empty record");
        };
        assert!(matches!(
            claim.reserve(8, 8, 8),
            Err(LivePrivateReason::Capacity)
        ));

        assert_eq!(
            arena
                .lookup(&key, key.guest_va_start(), 9999)
                .private_reason(),
            Some(LivePrivateReason::Failed)
        );
    }

    #[test]
    fn owner_death_never_steals_building_record() {
        let arena = arena();
        let key = key();
        let LiveLookup::Publish(claim) = arena.lookup(&key, key.guest_va_start(), 1234) else {
            panic!("first lookup must claim the empty record");
        };
        assert_eq!(claim.owner_pid(), 1234);

        assert_eq!(
            arena
                .lookup(&key, key.guest_va_start(), -1)
                .private_reason(),
            Some(LivePrivateReason::Building)
        );
    }

    #[test]
    fn reservation_rejects_misaligned_or_overflowing_lengths() {
        let key = key();
        let invalid_arena = arena();
        let LiveLookup::Publish(claim) = invalid_arena.lookup(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim the empty record");
        };
        assert!(matches!(
            claim.reserve(6, 8, 8),
            Err(LivePrivateReason::InvalidRecord)
        ));

        let overflow_arena = arena();
        let LiveLookup::Publish(claim) = overflow_arena.lookup(&key, key.guest_va_start(), 1234)
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
        let arena = Arc::new(LiveTranslationArena::new(PAGE * 32, PAGE, PAGE));
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
                let LiveLookup::Publish(claim) = arena.lookup(&key, guest, index + 1) else {
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
        let LiveLookup::Ready(again) = arena.lookup(&key, key.guest_va_start(), 9999) else {
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
        let LiveLookup::Publish(claim) = arena.lookup(&key, key.guest_va_start(), 1234) else {
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
        let LiveLookup::Publish(claim) = wrong_key_arena.lookup(&key, key.guest_va_start(), 1234)
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
        let LiveLookup::Publish(claim) = wrong_abi_arena.lookup(&key, key.guest_va_start(), 1234)
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
        let LiveLookup::Publish(claim) = arena.lookup(&key, key.guest_va_start(), 1234) else {
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
        let LiveLookup::Publish(claim) = arena.lookup(&key, key.guest_va_start(), 1234) else {
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
                    if let LiveLookup::Ready(ready) = arena.lookup(&key, key.guest_va_start(), 9999)
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

        let LiveLookup::Publish(claim) = arena.lookup(&key, guest_start, 1234) else {
            panic!("different-key READY must continue to the next empty probe");
        };
        assert!(std::ptr::eq(
            claim.record,
            &arena.view().records[(initial + 1) & LIVE_ARENA_MASK]
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

        let LiveLookup::Publish(claim) = arena.lookup(&key, guest_start, 1234) else {
            panic!("different-key FAILED must continue to the next empty probe");
        };
        assert!(std::ptr::eq(
            claim.record,
            &arena.view().records[(initial + 1) & LIVE_ARENA_MASK]
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
            arena.lookup(&key, guest_start, 1234).private_reason(),
            Some(LivePrivateReason::Building)
        );
        assert_eq!(
            arena.view().records[(initial + 1) & LIVE_ARENA_MASK]
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
            arena.lookup(&key, guest_start, 1234).private_reason(),
            Some(LivePrivateReason::ExhaustedProbes)
        );
    }

    #[test]
    fn unrepresentable_lengths_are_rejected_before_any_cursor_advance() {
        let oversized = u64::from(u32::MAX) + 1;
        for lengths in [(oversized, 8, 8), (8, oversized, 8), (8, 8, oversized)] {
            let arena = LiveTranslationArena::new(oversized + PAGE, oversized + 8, oversized + 8);
            let key = key();
            let LiveLookup::Publish(claim) = arena.lookup(&key, key.guest_va_start(), 1234) else {
                panic!("first lookup must claim the empty record");
            };

            assert!(matches!(
                claim.reserve(lengths.0, lengths.1, lengths.2),
                Err(LivePrivateReason::InvalidRecord)
            ));
            let cursors = arena.view().cursor_snapshot();
            assert_eq!(cursors.code, 0);
            assert_eq!(cursors.hot, 0);
            assert_eq!(cursors.cold, 0);
        }
    }

    #[test]
    fn later_cursor_failure_counts_stranded_nonempty_extents() {
        let arena = LiveTranslationArena::new(PAGE * 2, 8, 0);
        let key = key();
        let LiveLookup::Publish(claim) = arena.lookup(&key, key.guest_va_start(), 1234) else {
            panic!("first lookup must claim the empty record");
        };

        assert!(matches!(
            claim.reserve(8, 8, 8),
            Err(LivePrivateReason::Capacity)
        ));
        let cursors = arena.view().cursor_snapshot();
        assert_eq!(cursors.leaked_extents, 2);
        assert_eq!(cursors.code, 8);
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
                        .lookup(&key, key.guest_va_start(), owner_pid)
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
            arena.view().records[(initial + 1) & LIVE_ARENA_MASK]
                .state
                .load(Ordering::Relaxed),
            LIVE_BLOCK_EMPTY
        );
    }

    #[test]
    fn mapped_views_share_claim_state_and_append_cursors() {
        let capacities = LiveArenaCapacities::new(PAGE * 4, PAGE, PAGE);
        let layout =
            LiveArenaControlLayout::new(capacities, PAGE as usize).expect("checked mapped layout");
        let nonce = [0x5a; 16];
        let storage = RawControlStorage::new(layout.control_len());
        let first = storage.initialize(layout, nonce);
        let second = storage.adopt(layout, nonce);
        let process_view = LiveProcessViewBrand::fresh();
        let first_key = key();
        let second_guest = GuestVa(first_key.guest_va_start().raw() + PAGE);

        let LiveLookup::Publish(claim) =
            first.lookup(&process_view, &first_key, first_key.guest_va_start(), 101)
        else {
            panic!("first mapped view must win a claim");
        };
        let first_extents = claim.reserve(8, 8, 8).expect("first reservation").extents();
        let LiveLookup::Publish(claim) =
            second.lookup(&process_view, &first_key, second_guest, 202)
        else {
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
        let layout =
            LiveArenaControlLayout::new(capacities, PAGE as usize).expect("checked mapped layout");

        assert_eq!(layout.directory_offset(), 64);
        assert_eq!(layout.records_len(), LIVE_ARENA_RECORDS * 192);
        assert_eq!(layout.records_end(), layout.hot_base());
        assert_eq!(layout.hot_base() + 24, layout.cold_base());
        assert_eq!(layout.cold_base() + 40, layout.control_payload_end());
        assert!(layout.control_payload_end() <= layout.control_len());
        assert!(layout.control_len().is_multiple_of(PAGE as usize));
    }

    #[test]
    fn dropped_publish_claim_release_publishes_failed() {
        let arena = arena();
        let key = key();
        let LiveLookup::Publish(claim) = arena.lookup(&key, key.guest_va_start(), 1234) else {
            panic!("first lookup must claim the empty record");
        };
        drop(claim);

        assert_eq!(
            arena
                .lookup(&key, key.guest_va_start(), 9999)
                .private_reason(),
            Some(LivePrivateReason::Failed)
        );
    }

    #[test]
    fn cross_view_claim_authority_is_rejected() {
        let capacities = LiveArenaCapacities::new(PAGE * 4, PAGE, PAGE);
        let layout =
            LiveArenaControlLayout::new(capacities, PAGE as usize).expect("checked mapped layout");
        let first_storage = RawControlStorage::new(layout.control_len());
        let second_storage = RawControlStorage::new(layout.control_len());
        let first = first_storage.initialize(layout, [0x11; 16]);
        let second = second_storage.initialize(layout, [0x22; 16]);
        let process_view = LiveProcessViewBrand::fresh();
        let key = key();
        let LiveLookup::Publish(claim) =
            first.lookup(&process_view, &key, key.guest_va_start(), 1234)
        else {
            panic!("first view must claim");
        };
        let reserved = claim.reserve(8, 8, 8).expect("reserved claim");

        assert!(first.accepts_claim(&reserved));
        assert!(!second.accepts_claim(&reserved));
    }

    #[test]
    fn reserved_claim_binds_exact_process_view_brand() {
        let capacities = LiveArenaCapacities::new(PAGE * 4, PAGE, PAGE);
        let layout =
            LiveArenaControlLayout::new(capacities, PAGE as usize).expect("checked mapped layout");
        let storage = RawControlStorage::new(layout.control_len());
        let view = storage.initialize(layout, [0x33; 16]);
        let first_brand = LiveProcessViewBrand::fresh();
        let second_brand = LiveProcessViewBrand::fresh();
        let key = key();
        let LiveLookup::Publish(claim) =
            view.lookup(&first_brand, &key, key.guest_va_start(), 1234)
        else {
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
        let LiveLookup::Publish(claim) = arena.lookup(&key, key.guest_va_start(), 1234) else {
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
                .lookup(&key, key.guest_va_start(), 9999)
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
            let LiveLookup::Publish(claim) = arena.lookup(&key, key.guest_va_start(), 1234) else {
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
            let generations = PageGenerationTable::new(PAGE).expect("generation table");
            let observation = generations
                .observe(key.guest_va_start())
                .expect("INITIAL observation");
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
                    &observation,
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
            let LiveLookup::Publish(claim) = arena.lookup(&key, key.guest_va_start(), 1234) else {
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
            let generations = PageGenerationTable::new(PAGE).expect("generation table");
            let observation = generations
                .observe(key.guest_va_start())
                .expect("INITIAL observation");
            // SAFETY: the fixture establishes the mapping/lifetime contract;
            // content authentication is the behavior under test.
            let result = unsafe {
                permit.certify_mapped(
                    &mapped.code,
                    &mapped.hot,
                    &mapped.cold,
                    key.guest_va_start(),
                    0,
                    &observation,
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
        let LiveLookup::Publish(claim) = arena.lookup(&key, key.guest_va_start(), 1234) else {
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
        let generations = PageGenerationTable::new(PAGE).expect("generation table");
        let observation = generations
            .observe(key.guest_va_start())
            .expect("INITIAL observation");
        generations
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
                &observation,
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
        let LiveLookup::Publish(claim) = arena.lookup(&key, key.guest_va_start(), 1234) else {
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
        let generations = PageGenerationTable::new(PAGE).expect("generation table");
        let observation = generations
            .observe(key.guest_va_start())
            .expect("INITIAL observation");
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
                &observation,
                expected,
                || {
                    generations
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
    fn written_block_from_one_claim_cannot_publish_another() {
        let arena = arena();
        let key = key();
        let prepared = prepared_publication();
        let lengths = prepared.lengths();
        let expected = prepared.expected_publication();
        let LiveLookup::Publish(first_claim) = arena.lookup(&key, key.guest_va_start(), 1234)
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
        let generations = PageGenerationTable::new(PAGE).expect("generation table");
        let observation = generations
            .observe(key.guest_va_start())
            .expect("INITIAL observation");
        // SAFETY: exact bytes and metadata come from the real prepared value.
        let written = unsafe {
            permit.certify_mapped(
                &mapped.code,
                &mapped.hot,
                &mapped.cold,
                key.guest_va_start(),
                0,
                &observation,
                expected,
            )
        }
        .expect("certify first mapped write");

        let other_guest = GuestVa(key.guest_va_start().raw() + PAGE);
        let LiveLookup::Publish(other_claim) = arena.lookup(&key, other_guest, 5678) else {
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
            arena.lookup(&key, other_guest, 9999).private_reason(),
            Some(LivePrivateReason::Failed)
        );
    }
}
