//! Offset-only, wait-free protocol for a container-lifetime translation arena.
//!
//! This module owns only the portable wire and state-machine contract. Darwin
//! mappings and translator integration deliberately stay outside this layer.

use crate::shared_cache::{TRANSLATOR_ABI_CURRENT, TranslationUnitKey};
use carrick_guest_mem::GuestVa;
use sha2::{Digest, Sha256};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
#[cfg(test)]
use std::sync::{Arc, Barrier};

pub const LIVE_ARENA_SCHEMA_V1: u32 = 1;
pub const LIVE_BLOCK_EMPTY: u32 = 0;
pub const LIVE_BLOCK_BUILDING: u32 = 1;
pub const LIVE_BLOCK_READY: u32 = 2;
pub const LIVE_BLOCK_FAILED: u32 = 3;
pub const LIVE_ARENA_RECORDS: usize = 131_072;
const LIVE_ARENA_PROBES: usize = 16;
const LIVE_ARENA_MASK: usize = LIVE_ARENA_RECORDS - 1;
const LIVE_ARENA_PAGE_BYTES: u64 = 16 * 1024;
const LIVE_ARENA_INSTRUCTION_BYTES: u64 = 4;
const LIVE_ARENA_METADATA_ALIGN: u64 = 8;

#[repr(C, align(64))]
pub struct LiveBlockRecordV1 {
    state: AtomicU32,
    owner_pid: AtomicI32,
    payload: UnsafeCell<LiveBlockPayloadV1>,
}

#[derive(Clone, Copy)]
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
    UnknownState,
}

pub enum LiveLookup<'a> {
    Ready(ValidatedLiveBlock<'a>),
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

/// Caller-supplied metadata and bytes for one reserved BUILDING record. The
/// code bytes are authenticated here before the immutable digest reaches the
/// wire record; reservation extents come only from the consuming claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveBlockPublication {
    pub unit_key_digest: [u8; 32],
    pub translator_abi: u32,
    pub source_page: u64,
    pub entry_offset: u32,
    pub code_sha256: [u8; 32],
    pub code: Vec<u8>,
}

pub struct LiveTranslationArena {
    records: Box<[LiveBlockRecordV1]>,
    code_capacity: u64,
    hot_capacity: u64,
    cold_capacity: u64,
    code_next: AtomicU64,
    hot_next: AtomicU64,
    cold_next: AtomicU64,
    #[cfg(test)]
    cas_barrier: Option<Arc<Barrier>>,
}

impl LiveTranslationArena {
    pub fn new(code_capacity: u64, hot_capacity: u64, cold_capacity: u64) -> Self {
        let records = (0..LIVE_ARENA_RECORDS)
            .map(|_| LiveBlockRecordV1::empty())
            .collect();
        Self {
            records,
            code_capacity,
            hot_capacity,
            cold_capacity,
            code_next: AtomicU64::new(0),
            hot_next: AtomicU64::new(0),
            cold_next: AtomicU64::new(0),
            #[cfg(test)]
            cas_barrier: None,
        }
    }

    /// Performs at most one acquire load per probe and one CAS only for an
    /// empty record. A collision probe is bounded lookup work, never waiting.
    pub fn lookup(
        &self,
        key: &TranslationUnitKey,
        guest_start: GuestVa,
        owner_pid: i32,
    ) -> LiveLookup<'_> {
        let Ok(unit_key_digest) = key.live_digest() else {
            return LiveLookup::Private(LivePrivateReason::KeyEncoding);
        };
        let initial = initial_slot(&unit_key_digest, guest_start.raw());

        for probe in 0..LIVE_ARENA_PROBES {
            let record = &self.records[(initial + probe) & LIVE_ARENA_MASK];
            match record.state.load(Ordering::Acquire) {
                LIVE_BLOCK_READY => {
                    // SAFETY: this branch acquired terminal READY above.
                    let payload = unsafe { record.terminal_payload() };
                    if record_matches(payload, &unit_key_digest, guest_start.raw()) {
                        return self
                            .validate_ready(record, payload, &unit_key_digest, guest_start.raw())
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
                                arena: self,
                                record,
                                unit_key_digest,
                                guest_start: guest_start.raw(),
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

    fn validate_ready<'a>(
        &'a self,
        _record: &'a LiveBlockRecordV1,
        payload: &'a LiveBlockPayloadV1,
        expected_key: &[u8; 32],
        expected_guest_start: u64,
    ) -> Option<ValidatedLiveBlock<'a>> {
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
        Some(ValidatedLiveBlock {
            #[cfg(test)]
            record: _record,
            payload,
            extents,
        })
    }

    fn extents_in_bounds(&self, extents: LiveBlockExtents) -> bool {
        extent_in_capacity(extents.code, self.code_capacity)
            && extent_in_capacity(extents.hot, self.hot_capacity)
            && extent_in_capacity(extents.cold, self.cold_capacity)
    }

    fn reserve(&self, code_len: u64, hot_len: u64, cold_len: u64) -> Option<LiveBlockExtents> {
        if code_len == 0 || !code_len.is_multiple_of(LIVE_ARENA_INSTRUCTION_BYTES) {
            return None;
        }
        let code = reserve_append(
            &self.code_next,
            self.code_capacity,
            code_len,
            LIVE_ARENA_PAGE_BYTES,
        )?;
        let hot = reserve_append(
            &self.hot_next,
            self.hot_capacity,
            hot_len,
            LIVE_ARENA_METADATA_ALIGN,
        )?;
        let cold = reserve_append(
            &self.cold_next,
            self.cold_capacity,
            cold_len,
            LIVE_ARENA_METADATA_ALIGN,
        )?;
        Some(LiveBlockExtents { code, hot, cold })
    }
}

pub struct LivePublishClaim<'a> {
    arena: &'a LiveTranslationArena,
    record: &'a LiveBlockRecordV1,
    unit_key_digest: [u8; 32],
    guest_start: u64,
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
    }
}

#[derive(Clone, Copy)]
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
pub struct LiveReservedPublishClaim<'a> {
    claim: LivePublishClaim<'a>,
    extents: LiveBlockExtents,
    wire_lengths: LiveWireLengths,
}

impl<'a> LiveReservedPublishClaim<'a> {
    pub fn extents(&self) -> LiveBlockExtents {
        self.extents
    }

    /// Publishes exactly once. The field writes precede the sole `READY`
    /// release store, so consumers may read them only after acquiring READY.
    pub fn publish(mut self, publication: LiveBlockPublication) -> LiveLookup<'a> {
        if self.claim.record.state.load(Ordering::Acquire) != LIVE_BLOCK_BUILDING {
            return LiveLookup::Private(LivePrivateReason::Failed);
        }
        if !self.valid_publication(&publication) {
            self.claim.publish_failed();
            return LiveLookup::Private(LivePrivateReason::InvalidRecord);
        }

        let payload = LiveBlockPayloadV1 {
            unit_key_digest: publication.unit_key_digest,
            guest_start: self.claim.guest_start,
            source_page: publication.source_page,
            code_offset: self.extents.code.offset,
            code_len: self.wire_lengths.code,
            entry_offset: publication.entry_offset,
            hot_offset: self.extents.hot.offset,
            hot_len: self.wire_lengths.hot,
            cold_offset: self.extents.cold.offset,
            cold_len: self.wire_lengths.cold,
            code_sha256: publication.code_sha256,
        };
        // SAFETY: the inner claim is the unique BUILDING capability. Lookup
        // does not expose payload references until it acquires READY below.
        unsafe { self.claim.record.write_building_payload(payload) };
        self.claim
            .record
            .state
            .store(LIVE_BLOCK_READY, Ordering::Release);
        if self.claim.record.state.load(Ordering::Acquire) != LIVE_BLOCK_READY {
            return LiveLookup::Private(LivePrivateReason::InvalidRecord);
        }
        // SAFETY: this publisher just acquired the terminal READY state.
        let payload = unsafe { self.claim.record.terminal_payload() };
        self.claim
            .arena
            .validate_ready(
                self.claim.record,
                payload,
                &self.claim.unit_key_digest,
                self.claim.guest_start,
            )
            .map(LiveLookup::Ready)
            .unwrap_or(LiveLookup::Private(LivePrivateReason::InvalidRecord))
    }

    pub fn fail(mut self) -> LivePrivateReason {
        if self.claim.record.state.load(Ordering::Acquire) != LIVE_BLOCK_BUILDING {
            return LivePrivateReason::Failed;
        }
        self.claim.publish_failed();
        LivePrivateReason::Failed
    }

    fn valid_publication(&self, publication: &LiveBlockPublication) -> bool {
        publication.unit_key_digest == self.claim.unit_key_digest
            && publication.translator_abi == TRANSLATOR_ABI_CURRENT
            && valid_source_page(publication.source_page, self.claim.guest_start)
            && self.claim.arena.extents_in_bounds(self.extents)
            && valid_code_extent(self.extents.code)
            && valid_metadata_extent(self.extents.hot)
            && valid_metadata_extent(self.extents.cold)
            && u64::from(publication.entry_offset) < self.extents.code.len
            && u64::from(publication.entry_offset).is_multiple_of(LIVE_ARENA_INSTRUCTION_BYTES)
            && publication.code.len() == usize::try_from(self.extents.code.len).unwrap_or(0)
            && <[u8; 32]>::from(Sha256::digest(&publication.code)) == publication.code_sha256
    }
}

pub struct ValidatedLiveBlock<'a> {
    #[cfg(test)]
    record: &'a LiveBlockRecordV1,
    payload: &'a LiveBlockPayloadV1,
    extents: LiveBlockExtents,
}

impl ValidatedLiveBlock<'_> {
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

    #[cfg(test)]
    fn record_snapshot(&self) -> LiveRecordSnapshot {
        LiveRecordSnapshot {
            state: self.record.state.load(Ordering::Acquire),
            owner_pid: self.record.owner_pid.load(Ordering::Relaxed),
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
    owner_pid: i32,
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
    use crate::shared_cache::{
        AddressModeIdentity, ExecutableIdentity, GuestCodeLen, ImageFileLen, ImageFileOffset,
        NativePageProfileIdentity, SourceFingerprint, TranslationUnitKey,
    };
    use carrick_guest_mem::GuestVa;
    use sha2::{Digest, Sha256};
    use std::sync::{Arc, Barrier};

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

    fn publication(key: &TranslationUnitKey) -> LiveBlockPublication {
        let code = vec![0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6];
        LiveBlockPublication {
            unit_key_digest: key.live_digest().expect("live digest"),
            translator_abi: TRANSLATOR_ABI_CURRENT,
            source_page: key.guest_va_start().raw(),
            entry_offset: 4,
            code_sha256: Sha256::digest(&code).into(),
            code,
        }
    }

    fn seed_probe_record(
        arena: &mut LiveTranslationArena,
        slot: usize,
        state: u32,
        unit_key_digest: [u8; 32],
        guest_start: u64,
    ) {
        let record = &mut arena.records[slot & LIVE_ARENA_MASK];
        *record.payload.get_mut() = LiveBlockPayloadV1 {
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
        record.state.store(state, Ordering::Release);
    }

    fn malformed_ready_reason(
        mutate: impl FnOnce(&mut LiveBlockPayloadV1),
    ) -> Option<LivePrivateReason> {
        let mut arena = arena();
        let key = key();
        let guest_start = key.guest_va_start();
        let digest = key.live_digest().expect("live digest");
        let initial = initial_slot(&digest, guest_start.raw());
        let record = &mut arena.records[initial];
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
        *record.payload.get_mut() = payload;
        record.state.store(LIVE_BLOCK_READY, Ordering::Release);

        arena.lookup(&key, guest_start, 1234).private_reason()
    }

    fn publish_ready<'a>(
        arena: &'a LiveTranslationArena,
        key: &TranslationUnitKey,
    ) -> ValidatedLiveBlock<'a> {
        let LiveLookup::Publish(claim) = arena.lookup(key, key.guest_va_start(), 1234) else {
            panic!("first lookup must claim the empty record");
        };
        let reserved = claim.reserve(8, 8, 8).expect("reserve extents");
        let LiveLookup::Ready(ready) = reserved.publish(publication(key)) else {
            panic!("valid publication must become ready");
        };
        ready
    }

    #[test]
    fn ready_acquire_exposes_complete_record() {
        let arena = arena();
        let key = key();
        let published = publish_ready(&arena, &key);
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
    fn record_rejects_wrong_unit_key_or_translator_abi() {
        let key = key();
        let wrong_key_arena = arena();
        let LiveLookup::Publish(claim) = wrong_key_arena.lookup(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim the empty record");
        };
        let reserved = claim.reserve(8, 8, 8).expect("reserve extents");
        let mut wrong_key = publication(&key);
        wrong_key.unit_key_digest = [0xff; 32];
        assert_eq!(
            reserved.publish(wrong_key).private_reason(),
            Some(LivePrivateReason::InvalidRecord)
        );

        let wrong_abi_arena = arena();
        let LiveLookup::Publish(claim) = wrong_abi_arena.lookup(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim the empty record");
        };
        let reserved = claim.reserve(8, 8, 8).expect("reserve extents");
        let mut wrong_abi = publication(&key);
        wrong_abi.translator_abi = TRANSLATOR_ABI_CURRENT + 1;
        assert_eq!(
            reserved.publish(wrong_abi).private_reason(),
            Some(LivePrivateReason::InvalidRecord)
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
        let published = publish_ready(&arena, &key);
        let first = published.record_snapshot();
        let LiveLookup::Ready(again) = arena.lookup(&key, key.guest_va_start(), 9999) else {
            panic!("ready record must stay ready");
        };
        assert_eq!(again.record_snapshot(), first);
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
            &arena.records[(initial + 1) & LIVE_ARENA_MASK]
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
            &arena.records[(initial + 1) & LIVE_ARENA_MASK]
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
            arena.records[(initial + 1) & LIVE_ARENA_MASK]
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
    fn publication_consumes_the_claims_exact_reservation() {
        let arena = arena();
        let key = key();
        let LiveLookup::Publish(claim) = arena.lookup(&key, key.guest_va_start(), 1234) else {
            panic!("first lookup must claim the empty record");
        };
        let reserved = claim.reserve(8, 8, 8).expect("reserve extents");
        let extents = reserved.extents();

        let LiveLookup::Ready(ready) = reserved.publish(publication(&key)) else {
            panic!("publication must consume its bound reservation");
        };
        assert_eq!(ready.extents(), extents);
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
            assert_eq!(arena.code_next.load(Ordering::Relaxed), 0);
            assert_eq!(arena.hot_next.load(Ordering::Relaxed), 0);
            assert_eq!(arena.cold_next.load(Ordering::Relaxed), 0);
        }
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
            arena.records[(initial + 1) & LIVE_ARENA_MASK]
                .state
                .load(Ordering::Relaxed),
            LIVE_BLOCK_EMPTY
        );
    }

    #[test]
    fn ready_release_makes_payload_visible_to_another_thread() {
        let arena = Arc::new(arena());
        let key = key();
        let LiveLookup::Publish(claim) = arena.lookup(&key, key.guest_va_start(), 1234) else {
            panic!("first lookup must claim the empty record");
        };
        let reserved = claim.reserve(8, 8, 8).expect("reserve extents");
        let extents = reserved.extents();
        let publication = publication(&key);
        let gate = Barrier::new(2);

        std::thread::scope(|scope| {
            scope.spawn(|| {
                gate.wait();
                let LiveLookup::Ready(ready) = reserved.publish(publication) else {
                    panic!("publisher must release a complete READY record");
                };
                assert_eq!(ready.extents(), extents);
            });
            gate.wait();
            for _ in 0..100_000 {
                if let LiveLookup::Ready(ready) = arena.lookup(&key, key.guest_va_start(), 9999) {
                    assert_eq!(
                        ready.unit_key_digest(),
                        key.live_digest().expect("live digest")
                    );
                    assert_eq!(ready.guest_start(), key.guest_va_start().raw());
                    assert_eq!(ready.source_page(), key.guest_va_start().raw());
                    assert_eq!(ready.extents(), extents);
                    assert_eq!(ready.entry_offset(), 4);
                    return;
                }
                std::thread::yield_now();
            }
            panic!("reader did not acquire the READY publication");
        });
    }
}
