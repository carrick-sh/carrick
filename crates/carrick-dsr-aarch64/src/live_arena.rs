//! Offset-only, wait-free protocol for a container-lifetime translation arena.
//!
//! This module owns only the portable wire and state-machine contract. Darwin
//! mappings and translator integration deliberately stay outside this layer.

use crate::shared_cache::{TRANSLATOR_ABI_CURRENT, TranslationUnitKey};
use carrick_guest_mem::GuestVa;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

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

const _: () = assert!(std::mem::align_of::<LiveBlockRecordV1>() == 64);
const _: () = assert!(std::mem::size_of::<LiveBlockRecordV1>() == 192);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV1, state) == 0);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV1, owner_pid) == 4);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV1, unit_key_digest) == 8);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV1, guest_start) == 40);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV1, source_page) == 48);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV1, code_offset) == 56);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV1, code_len) == 64);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV1, entry_offset) == 68);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV1, hot_offset) == 72);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV1, hot_len) == 80);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV1, cold_offset) == 88);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV1, cold_len) == 96);
const _: () = assert!(std::mem::offset_of!(LiveBlockRecordV1, code_sha256) == 100);

impl LiveBlockRecordV1 {
    fn empty() -> Self {
        Self {
            state: AtomicU32::new(LIVE_BLOCK_EMPTY),
            owner_pid: AtomicI32::new(0),
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

/// Caller-supplied bytes and offsets for one still-BUILDING record. The code
/// bytes are authenticated here before the immutable digest reaches the wire
/// record; this protocol layer does not own a platform mapping to copy them to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveBlockPublication {
    pub unit_key_digest: [u8; 32],
    pub translator_abi: u32,
    pub source_page: u64,
    pub extents: LiveBlockExtents,
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
                    if record_matches(record, &unit_key_digest, guest_start.raw()) {
                        return self
                            .validate_ready(record, &unit_key_digest, guest_start.raw())
                            .map(LiveLookup::Ready)
                            .unwrap_or(LiveLookup::Private(LivePrivateReason::InvalidRecord));
                    }
                }
                LIVE_BLOCK_FAILED => {
                    if record_matches(record, &unit_key_digest, guest_start.raw()) {
                        return LiveLookup::Private(LivePrivateReason::Failed);
                    }
                }
                LIVE_BLOCK_BUILDING => return LiveLookup::Private(LivePrivateReason::Building),
                LIVE_BLOCK_EMPTY => match record.state.compare_exchange(
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
                },
                _ => return LiveLookup::Private(LivePrivateReason::UnknownState),
            }
        }

        LiveLookup::Private(LivePrivateReason::ExhaustedProbes)
    }

    fn validate_ready<'a>(
        &'a self,
        record: &'a LiveBlockRecordV1,
        expected_key: &[u8; 32],
        expected_guest_start: u64,
    ) -> Option<ValidatedLiveBlock<'a>> {
        let extents = LiveBlockExtents {
            code: LiveReservation {
                offset: record.code_offset,
                len: u64::from(record.code_len),
            },
            hot: LiveReservation {
                offset: record.hot_offset,
                len: u64::from(record.hot_len),
            },
            cold: LiveReservation {
                offset: record.cold_offset,
                len: u64::from(record.cold_len),
            },
        };
        if !record_matches(record, expected_key, expected_guest_start)
            || !valid_source_page(record.source_page, expected_guest_start)
            || !self.extents_in_bounds(extents)
            || !valid_code_extent(extents.code)
            || !valid_metadata_extent(extents.hot)
            || !valid_metadata_extent(extents.cold)
            || u64::from(record.entry_offset) >= extents.code.len
            || !u64::from(record.entry_offset).is_multiple_of(LIVE_ARENA_INSTRUCTION_BYTES)
        {
            return None;
        }
        Some(ValidatedLiveBlock { record, extents })
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
        &mut self,
        code_len: u64,
        hot_len: u64,
        cold_len: u64,
    ) -> Result<LiveBlockExtents, LivePrivateReason> {
        if self.record.state.load(Ordering::Acquire) != LIVE_BLOCK_BUILDING {
            return Err(LivePrivateReason::Failed);
        }
        self.arena
            .reserve(code_len, hot_len, cold_len)
            .ok_or_else(|| {
                self.publish_failed();
                LivePrivateReason::Capacity
            })
    }

    /// Publishes exactly once. The field writes precede the sole `READY`
    /// release store, so consumers may read them only after acquiring READY.
    pub fn publish(mut self, publication: LiveBlockPublication) -> LiveLookup<'a> {
        if self.record.state.load(Ordering::Acquire) != LIVE_BLOCK_BUILDING {
            return LiveLookup::Private(LivePrivateReason::Failed);
        }
        if !self.valid_publication(&publication) {
            self.publish_failed();
            return LiveLookup::Private(LivePrivateReason::InvalidRecord);
        }

        // SAFETY: this claim was created by the only successful EMPTY→BUILDING
        // CAS. Other lookups read no non-atomic fields while BUILDING, and any
        // later reader first acquires the READY release store below.
        unsafe { self.write_publication(&publication) };
        self.record.state.store(LIVE_BLOCK_READY, Ordering::Release);
        if self.record.state.load(Ordering::Acquire) != LIVE_BLOCK_READY {
            return LiveLookup::Private(LivePrivateReason::InvalidRecord);
        }
        self.arena
            .validate_ready(self.record, &self.unit_key_digest, self.guest_start)
            .map(LiveLookup::Ready)
            .unwrap_or(LiveLookup::Private(LivePrivateReason::InvalidRecord))
    }

    pub fn fail(mut self) -> LivePrivateReason {
        if self.record.state.load(Ordering::Acquire) != LIVE_BLOCK_BUILDING {
            return LivePrivateReason::Failed;
        }
        self.publish_failed();
        LivePrivateReason::Failed
    }

    fn valid_publication(&self, publication: &LiveBlockPublication) -> bool {
        publication.unit_key_digest == self.unit_key_digest
            && publication.translator_abi == TRANSLATOR_ABI_CURRENT
            && valid_source_page(publication.source_page, self.guest_start)
            && self.arena.extents_in_bounds(publication.extents)
            && valid_code_extent(publication.extents.code)
            && valid_metadata_extent(publication.extents.hot)
            && valid_metadata_extent(publication.extents.cold)
            && u64::from(publication.entry_offset) < publication.extents.code.len
            && u64::from(publication.entry_offset).is_multiple_of(LIVE_ARENA_INSTRUCTION_BYTES)
            && publication.code.len() == usize::try_from(publication.extents.code.len).unwrap_or(0)
            && <[u8; 32]>::from(Sha256::digest(&publication.code)) == publication.code_sha256
    }

    fn publish_failed(&mut self) {
        // SAFETY: this remains the sole BUILDING owner. FAILED is release-
        // published so a colliding lookup can safely read the key and decide
        // whether it may continue its bounded probe.
        unsafe {
            let record = self.record as *const LiveBlockRecordV1 as *mut LiveBlockRecordV1;
            (*record).unit_key_digest = self.unit_key_digest;
            (*record).guest_start = self.guest_start;
            (*record).source_page = 0;
            (*record).code_offset = 0;
            (*record).code_len = 0;
            (*record).entry_offset = 0;
            (*record).hot_offset = 0;
            (*record).hot_len = 0;
            (*record).cold_offset = 0;
            (*record).cold_len = 0;
            (*record).code_sha256 = [0; 32];
        }
        self.record
            .state
            .store(LIVE_BLOCK_FAILED, Ordering::Release);
    }

    unsafe fn write_publication(&self, publication: &LiveBlockPublication) {
        let record = self.record as *const LiveBlockRecordV1 as *mut LiveBlockRecordV1;
        unsafe {
            (*record).unit_key_digest = publication.unit_key_digest;
            (*record).guest_start = self.guest_start;
            (*record).source_page = publication.source_page;
            (*record).code_offset = publication.extents.code.offset;
            (*record).code_len = publication.extents.code.len as u32;
            (*record).entry_offset = publication.entry_offset;
            (*record).hot_offset = publication.extents.hot.offset;
            (*record).hot_len = publication.extents.hot.len as u32;
            (*record).cold_offset = publication.extents.cold.offset;
            (*record).cold_len = publication.extents.cold.len as u32;
            (*record).code_sha256 = publication.code_sha256;
        }
    }
}

pub struct ValidatedLiveBlock<'a> {
    record: &'a LiveBlockRecordV1,
    extents: LiveBlockExtents,
}

impl ValidatedLiveBlock<'_> {
    pub fn unit_key_digest(&self) -> [u8; 32] {
        self.record.unit_key_digest
    }

    pub fn guest_start(&self) -> u64 {
        self.record.guest_start
    }

    pub fn source_page(&self) -> u64 {
        self.record.source_page
    }

    pub fn extents(&self) -> LiveBlockExtents {
        self.extents
    }

    pub fn entry_offset(&self) -> u32 {
        self.record.entry_offset
    }

    #[cfg(test)]
    fn record_snapshot(&self) -> LiveRecordSnapshot {
        LiveRecordSnapshot {
            state: self.record.state.load(Ordering::Acquire),
            owner_pid: self.record.owner_pid.load(Ordering::Relaxed),
            unit_key_digest: self.record.unit_key_digest,
            guest_start: self.record.guest_start,
            source_page: self.record.source_page,
            extents: self.extents,
            entry_offset: self.record.entry_offset,
            code_sha256: self.record.code_sha256,
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

fn record_matches(record: &LiveBlockRecordV1, key: &[u8; 32], guest_start: u64) -> bool {
    record.unit_key_digest == *key && record.guest_start == guest_start
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

    fn publication(key: &TranslationUnitKey, extents: LiveBlockExtents) -> LiveBlockPublication {
        let code = vec![0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6];
        LiveBlockPublication {
            unit_key_digest: key.live_digest().expect("live digest"),
            translator_abi: TRANSLATOR_ABI_CURRENT,
            source_page: key.guest_va_start().raw(),
            extents,
            entry_offset: 4,
            code_sha256: Sha256::digest(&code).into(),
            code,
        }
    }

    fn publish_ready<'a>(
        arena: &'a LiveTranslationArena,
        key: &TranslationUnitKey,
    ) -> ValidatedLiveBlock<'a> {
        let LiveLookup::Publish(mut claim) = arena.lookup(key, key.guest_va_start(), 1234) else {
            panic!("first lookup must claim the empty record");
        };
        let extents = claim.reserve(8, 8, 8).expect("reserve extents");
        let LiveLookup::Ready(ready) = claim.publish(publication(key, extents)) else {
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
        let LiveLookup::Publish(mut claim) = arena.lookup(&key, key.guest_va_start(), 1234) else {
            panic!("first lookup must claim the empty record");
        };
        assert_eq!(claim.reserve(8, 8, 8), Err(LivePrivateReason::Capacity));
        assert_eq!(
            claim
                .publish(publication(
                    &key,
                    LiveBlockExtents {
                        code: LiveReservation { offset: 0, len: 8 },
                        hot: LiveReservation { offset: 0, len: 8 },
                        cold: LiveReservation { offset: 0, len: 8 },
                    },
                ))
                .private_reason(),
            Some(LivePrivateReason::Failed)
        );

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
    fn record_rejects_misaligned_or_overflowing_extents() {
        let key = key();
        let invalid_arena = arena();
        let LiveLookup::Publish(claim) = invalid_arena.lookup(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim the empty record");
        };
        let mut invalid = publication(
            &key,
            LiveBlockExtents {
                code: LiveReservation { offset: 1, len: 8 },
                hot: LiveReservation { offset: 0, len: 8 },
                cold: LiveReservation { offset: 0, len: 8 },
            },
        );
        invalid.entry_offset = 3;
        assert_eq!(
            claim.publish(invalid).private_reason(),
            Some(LivePrivateReason::InvalidRecord)
        );

        let overflow_arena = arena();
        let LiveLookup::Publish(claim) = overflow_arena.lookup(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim the empty record");
        };
        let overflowing = publication(
            &key,
            LiveBlockExtents {
                code: LiveReservation {
                    offset: u64::MAX - 3,
                    len: 8,
                },
                hot: LiveReservation { offset: 0, len: 8 },
                cold: LiveReservation { offset: 0, len: 8 },
            },
        );
        assert_eq!(
            claim.publish(overflowing).private_reason(),
            Some(LivePrivateReason::InvalidRecord)
        );
    }

    #[test]
    fn record_rejects_wrong_unit_key_or_translator_abi() {
        let key = key();
        let wrong_key_arena = arena();
        let LiveLookup::Publish(mut claim) =
            wrong_key_arena.lookup(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim the empty record");
        };
        let extents = claim.reserve(8, 8, 8).expect("reserve extents");
        let mut wrong_key = publication(&key, extents);
        wrong_key.unit_key_digest = [0xff; 32];
        assert_eq!(
            claim.publish(wrong_key).private_reason(),
            Some(LivePrivateReason::InvalidRecord)
        );

        let wrong_abi_arena = arena();
        let LiveLookup::Publish(mut claim) =
            wrong_abi_arena.lookup(&key, key.guest_va_start(), 1234)
        else {
            panic!("first lookup must claim the empty record");
        };
        let extents = claim.reserve(8, 8, 8).expect("reserve extents");
        let mut wrong_abi = publication(&key, extents);
        wrong_abi.translator_abi = TRANSLATOR_ABI_CURRENT + 1;
        assert_eq!(
            claim.publish(wrong_abi).private_reason(),
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
                let LiveLookup::Publish(mut claim) = arena.lookup(&key, guest, index + 1) else {
                    panic!("each distinct record must claim once");
                };
                claim.reserve(8, 8, 8).expect("reservation must fit")
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
}
