#![allow(dead_code)]

//! Per-block translation-artifact spike store (record + replay of emitted
//! blocks across execve re-exec). Moved verbatim from
//! `carrick-runtime/src/native_darwin/dsr/artifact_spike.rs`; the runtime's
//! re-exec capsule schema (`NativeReexecArtifactSpikeV1`) maps 1:1 onto the
//! plain [`ArtifactSpikeReexecConfig`] carrier defined here.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::FileExt;
use std::ptr::NonNull;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

use super::emit::{
    BiasedBase, BiasedBaseCoordinate, BiasedExclusiveRecovery, DirectBindingCaptureProgress,
    DirectBindingRecoveryPhase, DirectLink, DirectLinkKind, DirectStubEnvelope, EmitAddressMode,
    EmittedBlock, PcMapEntry, RecoveryAction, RecoveryEntry,
};
use super::types::{CacheOffset, DsrError};
use carrick_dsr::cache::TranslationCache;

type RuntimeMetadata = (Vec<PcMapEntry>, Vec<RecoveryEntry>, Vec<DirectLink>);

const MOV_WIDE_IMM16_MASK: u32 = 0x001f_ffe0;
const ARTIFACT_STORE_SIZE: u64 = 256 * 1024 * 1024;
const ARTIFACT_CURSOR_OFFSET: u64 = 16;
const ARTIFACT_GUEST_FILTER_OFFSET: u64 = 4096;
const ARTIFACT_GUEST_FILTER_WORDS: u64 = 16 * 1024;
const ARTIFACT_GUEST_FILTER_BITS: u64 = ARTIFACT_GUEST_FILTER_WORDS * 64;
const ARTIFACT_INDEX_OFFSET: u64 = ARTIFACT_GUEST_FILTER_OFFSET + ARTIFACT_GUEST_FILTER_WORDS * 8;
const ARTIFACT_INDEX_SLOTS: u64 = 128 * 1024;
const ARTIFACT_RECORD_OFFSET: u64 = ARTIFACT_INDEX_OFFSET + ARTIFACT_INDEX_SLOTS * 8;
const ARTIFACT_MAX_PROBES: u64 = 64;
const ARTIFACT_RECORD_MAGIC: [u8; 8] = *b"CARTV4\0\0";
const ARTIFACT_RECORD_DIGEST_OFFSET: usize = 8;
const ARTIFACT_RECORD_GUEST_OFFSET: usize = ARTIFACT_RECORD_DIGEST_OFFSET + 32;
const ARTIFACT_RECORD_MODE_OFFSET: usize = ARTIFACT_RECORD_GUEST_OFFSET + 8;
const ARTIFACT_RECORD_LENGTH_OFFSET: usize = ARTIFACT_RECORD_MODE_OFFSET + 8;
const ARTIFACT_RECORD_HEADER: usize = ARTIFACT_RECORD_LENGTH_OFFSET + 8;
const ARTIFACT_MAX_RECORD: usize = 4 * 1024 * 1024;
const ARTIFACT_DECODE_LIMIT: usize = ARTIFACT_MAX_RECORD;
const ARTIFACT_COUNTER_OFFSET: usize = 64;
static ARTIFACT_AUTHORITY: OnceLock<ArtifactAuthority> = OnceLock::new();

fn encode_artifact_template(template: &ArtifactTemplate) -> Result<Vec<u8>, DsrError> {
    bincode::serde::encode_to_vec(
        WireArtifactTemplate::from(template),
        bincode::config::standard().with_limit::<ARTIFACT_DECODE_LIMIT>(),
    )
    .map_err(|error| DsrError::CachePolicy(format!("encode artifact record: {error}")))
}

fn decode_artifact_template(payload: &[u8]) -> Result<ArtifactTemplate, DsrError> {
    let (wire, consumed): (WireArtifactTemplate, usize) = bincode::serde::decode_from_slice(
        payload,
        bincode::config::standard().with_limit::<ARTIFACT_DECODE_LIMIT>(),
    )
    .map_err(|error| DsrError::CachePolicy(format!("decode artifact record: {error}")))?;
    if consumed != payload.len() {
        return Err(DsrError::CachePolicy(format!(
            "artifact record has {} trailing bytes",
            payload.len().saturating_sub(consumed)
        )));
    }
    Ok(wire.into())
}

pub fn validate_fresh_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var_os("CARRICK_DSR_ARTIFACT_VALIDATE_FRESH").as_deref()
            == Some(std::ffi::OsStr::new("1"))
    })
}

pub fn minimum_source_words() -> usize {
    static MINIMUM: OnceLock<usize> = OnceLock::new();
    *MINIMUM.get_or_init(|| {
        std::env::var("CARRICK_DSR_ARTIFACT_MIN_SOURCE_WORDS")
            .ok()
            .and_then(|raw| raw.parse().ok())
            .unwrap_or(16)
    })
}

pub fn enabled() -> bool {
    std::env::var_os("CARRICK_DSR_ARTIFACT_SPIKE").as_deref() == Some(std::ffi::OsStr::new("1"))
}

/// Plain serializable carrier for handing the artifact-spike authority
/// across an execve re-exec: exactly the fields the runtime's capsule schema
/// (`NativeReexecArtifactSpikeV1`) copies, with the V1 <-> carrier mapping
/// living in the runtime capsule module. `host_fd` is the inherited raw fd;
/// the device/inode/size/nonce quadruple lets `adopt` verify identity before
/// trusting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArtifactSpikeReexecConfig {
    pub host_fd: i32,
    pub original_host_fd_flags: i32,
    pub host_device: u64,
    pub host_inode: u64,
    pub host_size: u64,
    pub authority_nonce: [u8; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactKey {
    digest: [u8; 32],
    guest: carrick_guest_mem::GuestVa,
    address_mode_tag: u8,
}

impl ArtifactKey {
    pub fn from_source(
        start: carrick_guest_mem::GuestVa,
        words: &[u32],
        address_mode: EmitAddressMode,
    ) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"carrick-artifact-spike-v1");
        let address_mode_tag = match address_mode {
            EmitAddressMode::Direct => 0,
            EmitAddressMode::Biased { .. } => 1,
        };
        digest.update([address_mode_tag]);
        digest.update(start.raw().to_le_bytes());
        digest.update((words.len() as u64).to_le_bytes());
        for word in words {
            digest.update(word.to_le_bytes());
        }
        Self {
            digest: digest.finalize().into(),
            guest: start,
            address_mode_tag,
        }
    }

    pub fn from_image_digest(
        start: carrick_guest_mem::GuestVa,
        image_digest: [u8; 32],
        address_mode: EmitAddressMode,
    ) -> Self {
        let address_mode_tag = match address_mode {
            EmitAddressMode::Direct => 0,
            EmitAddressMode::Biased { .. } => 1,
        };
        Self {
            digest: image_digest,
            guest: start,
            address_mode_tag,
        }
    }

    fn first_slot(self) -> u64 {
        let digest = u64::from_le_bytes(self.digest[..8].try_into().unwrap_or([0; 8]));
        let guest = self
            .guest
            .raw()
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .rotate_left(23);
        (digest ^ guest ^ u64::from(self.address_mode_tag).wrapping_mul(0xd6e8_feb8_6659_fd93))
            % ARTIFACT_INDEX_SLOTS
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct WireDirectLink {
    slot: u32,
    source: u64,
    target: u64,
    kind: DirectLinkKind,
    stub_start: u32,
    stub_end: u32,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct WireArtifactTemplate {
    words: Vec<u32>,
    map_deltas: Vec<(i64, u32)>,
    recovery_deltas: Vec<(u32, PortableRecoveryAction)>,
    direct_links: Vec<WireDirectLink>,
    relocations: Vec<ArtifactRelocation>,
    source_words: Vec<u32>,
}

impl serde::Serialize for ArtifactTemplate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        WireArtifactTemplate::from(self).serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for ArtifactTemplate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        WireArtifactTemplate::deserialize(deserializer).map(Into::into)
    }
}

impl From<&ArtifactTemplate> for WireArtifactTemplate {
    fn from(template: &ArtifactTemplate) -> Self {
        let mut previous_guest = 0_i64;
        let mut previous_cache = 0_u32;
        let map_deltas = template
            .map
            .iter()
            .map(|entry| {
                let guest = entry.guest.raw() as i64;
                let cache = entry.cache.get();
                let delta = (
                    guest.wrapping_sub(previous_guest),
                    cache.wrapping_sub(previous_cache),
                );
                previous_guest = guest;
                previous_cache = cache;
                delta
            })
            .collect();
        let mut previous_recovery = 0_u32;
        let recovery_deltas = template
            .recovery
            .iter()
            .map(|entry| {
                let cache = entry.cache.get();
                let delta = cache.wrapping_sub(previous_recovery);
                previous_recovery = cache;
                (delta, entry.action)
            })
            .collect();
        Self {
            words: template.words.clone(),
            map_deltas,
            recovery_deltas,
            direct_links: template
                .direct_links
                .iter()
                .map(|link| WireDirectLink {
                    slot: link.slot.get(),
                    source: link.source.raw(),
                    target: link.target.raw(),
                    kind: link.kind,
                    stub_start: link.stub.start.get(),
                    stub_end: link.stub.end.get(),
                })
                .collect(),
            relocations: template.relocations.clone(),
            source_words: template.source_words.clone(),
        }
    }
}

impl From<WireArtifactTemplate> for ArtifactTemplate {
    fn from(template: WireArtifactTemplate) -> Self {
        let mut guest = 0_i64;
        let mut cache = 0_u32;
        let map = template
            .map_deltas
            .into_iter()
            .map(|(guest_delta, cache_delta)| {
                guest = guest.wrapping_add(guest_delta);
                cache = cache.wrapping_add(cache_delta);
                PcMapEntry {
                    guest: carrick_guest_mem::GuestVa(guest as u64),
                    cache: CacheOffset::published(cache),
                }
            })
            .collect();
        let mut recovery_cache = 0_u32;
        let recovery = template
            .recovery_deltas
            .into_iter()
            .map(|(cache_delta, action)| {
                recovery_cache = recovery_cache.wrapping_add(cache_delta);
                PortableRecoveryEntry {
                    cache: CacheOffset::published(recovery_cache),
                    action,
                }
            })
            .collect();
        Self {
            words: template.words,
            map,
            recovery,
            direct_links: template
                .direct_links
                .into_iter()
                .map(|link| DirectLink {
                    slot: CacheOffset::published(link.slot),
                    source: carrick_guest_mem::GuestVa(link.source),
                    target: carrick_guest_mem::GuestVa(link.target),
                    kind: link.kind,
                    stub: DirectStubEnvelope {
                        start: CacheOffset::published(link.stub_start),
                        end: CacheOffset::published(link.stub_end),
                    },
                })
                .collect(),
            relocations: template.relocations,
            source_words: template.source_words,
        }
    }
}

pub struct ArtifactStore {
    file: File,
    mapping: NonNull<u8>,
    counters: NonNull<SharedArtifactCounters>,
}

#[repr(C)]
struct SharedArtifactCounters {
    lookups: AtomicU64,
    hits: AtomicU64,
    inserts: AtomicU64,
    replay_ns: AtomicU64,
    sealed: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArtifactCounterSnapshot {
    pub lookups: u64,
    pub hits: u64,
    pub inserts: u64,
    pub replay_ns: u64,
    pub sealed: bool,
}

unsafe impl Send for ArtifactStore {}
unsafe impl Sync for ArtifactStore {}

impl Drop for ArtifactStore {
    fn drop(&mut self) {
        let _ = unsafe { libc::munmap(self.mapping.as_ptr().cast(), ARTIFACT_STORE_SIZE as usize) };
    }
}

impl ArtifactStore {
    fn mapped_range(&self, offset: u64, length: usize) -> Result<&[u8], DsrError> {
        let end = offset
            .checked_add(length as u64)
            .ok_or_else(|| DsrError::CachePolicy("artifact mapping range overflow".to_string()))?;
        if end > ARTIFACT_STORE_SIZE {
            return Err(DsrError::CachePolicy(format!(
                "artifact mapping range 0x{offset:x}..0x{end:x} exceeds store"
            )));
        }
        // Records are immutable after their index entry is published. Callers
        // reach this range only after an Acquire load of that entry, so no
        // writer can still be mutating the returned bytes.
        Ok(unsafe {
            std::slice::from_raw_parts(self.mapping.as_ptr().add(offset as usize), length)
        })
    }

    fn write_reserved_record_bytes(&self, offset: u64, bytes: &[u8]) -> Result<(), DsrError> {
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| DsrError::CachePolicy("artifact mapping range overflow".to_string()))?;
        if offset < ARTIFACT_RECORD_OFFSET || end > ARTIFACT_STORE_SIZE {
            return Err(DsrError::CachePolicy(format!(
                "artifact record write 0x{offset:x}..0x{end:x} exceeds record arena"
            )));
        }
        // `reserve_record` assigns each writer a disjoint range. The bytes are
        // copied into that private range before compare_exchange_index_offset
        // publishes its offset with Release ordering, and are never changed
        // after publication.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.mapping.as_ptr().add(offset as usize),
                bytes.len(),
            );
        }
        Ok(())
    }

    fn guest_filter_bits(guest: carrick_guest_mem::GuestVa, address_mode_tag: u8) -> [u64; 2] {
        let tagged = guest.raw() ^ u64::from(address_mode_tag).wrapping_mul(0xd6e8_feb8_6659_fd93);
        let first = tagged.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let second = tagged.rotate_left(29).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        [
            first % ARTIFACT_GUEST_FILTER_BITS,
            second % ARTIFACT_GUEST_FILTER_BITS,
        ]
    }

    fn guest_filter_word(&self, word: u64) -> &AtomicU64 {
        let byte_offset = ARTIFACT_GUEST_FILTER_OFFSET as usize + word as usize * 8;
        unsafe { &*self.mapping.as_ptr().add(byte_offset).cast::<AtomicU64>() }
    }

    pub fn may_contain_guest(
        &self,
        guest: carrick_guest_mem::GuestVa,
        address_mode: EmitAddressMode,
    ) -> bool {
        let address_mode_tag = match address_mode {
            EmitAddressMode::Direct => 0,
            EmitAddressMode::Biased { .. } => 1,
        };
        Self::guest_filter_bits(guest, address_mode_tag)
            .into_iter()
            .all(|bit| {
                self.guest_filter_word(bit / 64).load(Ordering::Acquire) & (1 << (bit % 64)) != 0
            })
    }

    fn publish_guest_filter(&self, key: ArtifactKey) {
        for bit in Self::guest_filter_bits(key.guest, key.address_mode_tag) {
            self.guest_filter_word(bit / 64)
                .fetch_or(1 << (bit % 64), Ordering::Release);
        }
    }

    fn index_offset(&self, slot: u64) -> u64 {
        let byte_offset = ARTIFACT_INDEX_OFFSET as usize + slot as usize * 8;
        let entry = unsafe { &*self.mapping.as_ptr().add(byte_offset).cast::<AtomicU64>() };
        entry.load(Ordering::Acquire)
    }

    fn compare_exchange_index_offset(&self, slot: u64, offset: u64) -> Result<(), u64> {
        let byte_offset = ARTIFACT_INDEX_OFFSET as usize + slot as usize * 8;
        let entry = unsafe { &*self.mapping.as_ptr().add(byte_offset).cast::<AtomicU64>() };
        entry
            .compare_exchange(0, offset, Ordering::Release, Ordering::Acquire)
            .map(|_| ())
    }

    fn cursor(&self) -> &AtomicU64 {
        unsafe {
            &*self
                .mapping
                .as_ptr()
                .add(ARTIFACT_CURSOR_OFFSET as usize)
                .cast::<AtomicU64>()
        }
    }

    fn reserve_record(&self, length: u64) -> Result<Option<u64>, DsrError> {
        let cursor = self.cursor();
        let mut start = cursor.load(Ordering::Acquire);
        loop {
            let end = start.checked_add(length).ok_or_else(|| {
                DsrError::CachePolicy("artifact store cursor overflow".to_string())
            })?;
            if start < ARTIFACT_RECORD_OFFSET || end > ARTIFACT_STORE_SIZE {
                self.seal();
                return Ok(None);
            }
            match cursor.compare_exchange_weak(start, end, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(Some(start)),
                Err(observed) => start = observed,
            }
        }
    }

    fn counters(&self) -> &SharedArtifactCounters {
        unsafe { self.counters.as_ref() }
    }

    pub fn snapshot(&self) -> ArtifactCounterSnapshot {
        let counters = self.counters();
        ArtifactCounterSnapshot {
            lookups: counters.lookups.load(Ordering::Acquire),
            hits: counters.hits.load(Ordering::Acquire),
            inserts: counters.inserts.load(Ordering::Acquire),
            replay_ns: counters.replay_ns.load(Ordering::Acquire),
            sealed: counters.sealed.load(Ordering::Acquire) != 0,
        }
    }

    pub fn accepting_inserts(&self) -> bool {
        self.counters().sealed.load(Ordering::Acquire) == 0
    }

    fn seal(&self) {
        self.counters().sealed.store(1, Ordering::Release);
    }

    pub fn record_replay_ns(&self, elapsed: u64) {
        self.counters()
            .replay_ns
            .fetch_add(elapsed, Ordering::Relaxed);
    }

    pub fn lookup(&self, key: ArtifactKey) -> Result<Option<ArtifactTemplate>, DsrError> {
        self.counters().lookups.fetch_add(1, Ordering::Relaxed);
        let result = self.lookup_index(key)?;
        if result.is_some() {
            self.counters().hits.fetch_add(1, Ordering::Relaxed);
        }
        Ok(result)
    }

    fn lookup_index(&self, key: ArtifactKey) -> Result<Option<ArtifactTemplate>, DsrError> {
        for probe in 0..ARTIFACT_MAX_PROBES {
            let slot = (key.first_slot() + probe) % ARTIFACT_INDEX_SLOTS;
            let offset = self.index_offset(slot);
            if offset == 0 {
                return Ok(None);
            }
            let header = self.mapped_range(offset, ARTIFACT_RECORD_HEADER)?;
            if header[..8] != ARTIFACT_RECORD_MAGIC {
                return Err(DsrError::CachePolicy(format!(
                    "artifact record at 0x{offset:x} has invalid magic"
                )));
            }
            if header[ARTIFACT_RECORD_DIGEST_OFFSET..ARTIFACT_RECORD_GUEST_OFFSET] != key.digest
                || header[ARTIFACT_RECORD_GUEST_OFFSET..ARTIFACT_RECORD_MODE_OFFSET]
                    != key.guest.raw().to_le_bytes()
                || header[ARTIFACT_RECORD_MODE_OFFSET] != key.address_mode_tag
            {
                continue;
            }
            let length = usize::try_from(u64::from_le_bytes(
                header[ARTIFACT_RECORD_LENGTH_OFFSET..ARTIFACT_RECORD_HEADER]
                    .try_into()
                    .unwrap_or([0; 8]),
            ))
            .map_err(|_| DsrError::CachePolicy("artifact record length overflow".to_string()))?;
            if length == 0 || length > ARTIFACT_MAX_RECORD {
                return Err(DsrError::CachePolicy(format!(
                    "artifact record length is invalid: {length}"
                )));
            }
            let payload = self.mapped_range(offset + ARTIFACT_RECORD_HEADER as u64, length)?;
            return decode_artifact_template(payload).map(Some);
        }
        Ok(None)
    }

    pub fn insert(&self, key: ArtifactKey, template: &ArtifactTemplate) -> Result<(), DsrError> {
        if !self.accepting_inserts() {
            return Ok(());
        }
        if self.lookup_index(key)?.is_some() {
            return Ok(());
        }
        let payload = encode_artifact_template(template)?;
        if payload.is_empty() || payload.len() > ARTIFACT_MAX_RECORD {
            return Err(DsrError::CachePolicy(format!(
                "artifact payload length is invalid: {}",
                payload.len()
            )));
        }
        let record_len = (ARTIFACT_RECORD_HEADER as u64)
            .checked_add(payload.len() as u64)
            .ok_or_else(|| DsrError::CachePolicy("artifact record length overflow".to_string()))?;
        let Some(cursor) = self.reserve_record(record_len)? else {
            return Ok(());
        };
        let mut header = [0_u8; ARTIFACT_RECORD_HEADER];
        header[..8].copy_from_slice(&ARTIFACT_RECORD_MAGIC);
        header[ARTIFACT_RECORD_DIGEST_OFFSET..ARTIFACT_RECORD_GUEST_OFFSET]
            .copy_from_slice(&key.digest);
        header[ARTIFACT_RECORD_GUEST_OFFSET..ARTIFACT_RECORD_MODE_OFFSET]
            .copy_from_slice(&key.guest.raw().to_le_bytes());
        header[ARTIFACT_RECORD_MODE_OFFSET] = key.address_mode_tag;
        header[ARTIFACT_RECORD_LENGTH_OFFSET..ARTIFACT_RECORD_HEADER]
            .copy_from_slice(&(payload.len() as u64).to_le_bytes());
        self.write_reserved_record_bytes(cursor + ARTIFACT_RECORD_HEADER as u64, &payload)?;
        self.write_reserved_record_bytes(cursor, &header)?;
        for probe in 0..ARTIFACT_MAX_PROBES {
            let slot = (key.first_slot() + probe) % ARTIFACT_INDEX_SLOTS;
            match self.compare_exchange_index_offset(slot, cursor) {
                Ok(()) => {
                    self.publish_guest_filter(key);
                    self.counters().inserts.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                Err(existing) => {
                    let existing_header = self.mapped_range(existing, ARTIFACT_RECORD_HEADER)?;
                    if existing_header[..8] == ARTIFACT_RECORD_MAGIC
                        && existing_header
                            [ARTIFACT_RECORD_DIGEST_OFFSET..ARTIFACT_RECORD_GUEST_OFFSET]
                            == key.digest
                        && existing_header
                            [ARTIFACT_RECORD_GUEST_OFFSET..ARTIFACT_RECORD_MODE_OFFSET]
                            == key.guest.raw().to_le_bytes()
                        && existing_header[ARTIFACT_RECORD_MODE_OFFSET] == key.address_mode_tag
                    {
                        return Ok(());
                    }
                }
            }
        }
        self.seal();
        Err(DsrError::CachePolicy(
            "artifact index probe budget exhausted".to_string(),
        ))
    }
}

#[derive(Debug)]
pub struct ArtifactAuthority {
    file: File,
    authority_nonce: [u8; 16],
}

impl ArtifactAuthority {
    fn create() -> Result<Self, DsrError> {
        let file = tempfile::tempfile().map_err(|error| DsrError::Host {
            operation: "create translation artifact spike authority",
            error,
        })?;
        file.set_len(ARTIFACT_STORE_SIZE)
            .map_err(|error| DsrError::Host {
                operation: "size translation artifact spike authority",
                error,
            })?;
        let mut authority_nonce = [0_u8; 16];
        getrandom::fill(&mut authority_nonce).map_err(|error| {
            DsrError::CachePolicy(format!("generate artifact authority nonce: {error}"))
        })?;
        file.write_all_at(&authority_nonce, 0)
            .map_err(|error| DsrError::Host {
                operation: "write translation artifact spike nonce",
                error,
            })?;
        file.write_all_at(
            &ARTIFACT_RECORD_OFFSET.to_le_bytes(),
            ARTIFACT_CURSOR_OFFSET,
        )
        .map_err(|error| DsrError::Host {
            operation: "initialize translation artifact spike cursor",
            error,
        })?;
        Ok(Self {
            file,
            authority_nonce,
        })
    }

    #[cfg(test)]
    fn create_for_test() -> Result<Self, DsrError> {
        Self::create()
    }

    pub fn snapshot(&self) -> Result<ArtifactSpikeReexecConfig, DsrError> {
        let fd = self.file.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(DsrError::Host {
                operation: "read artifact authority fd flags",
                error: std::io::Error::last_os_error(),
            });
        }
        let mut identity = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, identity.as_mut_ptr()) } != 0 {
            return Err(DsrError::Host {
                operation: "stat artifact authority",
                error: std::io::Error::last_os_error(),
            });
        }
        let identity = unsafe { identity.assume_init() };
        Ok(ArtifactSpikeReexecConfig {
            host_fd: fd,
            original_host_fd_flags: flags,
            // `st_dev` is i32 on Darwin and u64 on FreeBSD; the widening cast
            // is load-bearing on some targets and an identity on others.
            #[allow(clippy::unnecessary_cast)]
            host_device: identity.st_dev as u64,
            host_inode: identity.st_ino,
            host_size: identity.st_size as u64,
            authority_nonce: self.authority_nonce,
        })
    }

    pub fn map_store(&self) -> Result<ArtifactStore, DsrError> {
        let file = self.file.try_clone().map_err(|error| DsrError::Host {
            operation: "clone translation artifact store authority",
            error,
        })?;
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ARTIFACT_STORE_SIZE as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(DsrError::Host {
                operation: "map translation artifact counters",
                error: std::io::Error::last_os_error(),
            });
        }
        let counters = unsafe {
            NonNull::new_unchecked(
                mapping
                    .cast::<u8>()
                    .add(ARTIFACT_COUNTER_OFFSET)
                    .cast::<SharedArtifactCounters>(),
            )
        };
        let mapping = unsafe { NonNull::new_unchecked(mapping.cast::<u8>()) };
        Ok(ArtifactStore {
            file,
            mapping,
            counters,
        })
    }

    #[cfg(test)]
    fn file(&self) -> &File {
        &self.file
    }
}

fn adopt(snapshot: &ArtifactSpikeReexecConfig) -> Result<ArtifactAuthority, DsrError> {
    let mut identity = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(snapshot.host_fd, identity.as_mut_ptr()) } != 0 {
        return Err(DsrError::Host {
            operation: "stat inherited artifact authority",
            error: std::io::Error::last_os_error(),
        });
    }
    let identity = unsafe { identity.assume_init() };
    // Per-OS `st_dev` width (i32 on Darwin, u64 on FreeBSD) makes the cast
    // conditional — load-bearing there, an identity here.
    #[allow(clippy::unnecessary_cast)]
    if identity.st_dev as u64 != snapshot.host_device
        || identity.st_ino != snapshot.host_inode
        || identity.st_size as u64 != snapshot.host_size
        || snapshot.host_size != ARTIFACT_STORE_SIZE
    {
        return Err(DsrError::CachePolicy(
            "inherited artifact authority identity mismatch".to_string(),
        ));
    }
    let file = unsafe { File::from_raw_fd(snapshot.host_fd) };
    let mut authority_nonce = [0_u8; 16];
    file.read_exact_at(&mut authority_nonce, 0)
        .map_err(|error| DsrError::Host {
            operation: "read inherited artifact authority nonce",
            error,
        })?;
    if authority_nonce != snapshot.authority_nonce {
        return Err(DsrError::CachePolicy(
            "inherited artifact authority nonce mismatch".to_string(),
        ));
    }
    if unsafe {
        libc::fcntl(
            file.as_raw_fd(),
            libc::F_SETFD,
            snapshot.original_host_fd_flags,
        )
    } != 0
    {
        return Err(DsrError::Host {
            operation: "restore inherited artifact authority fd flags",
            error: std::io::Error::last_os_error(),
        });
    }
    Ok(ArtifactAuthority {
        file,
        authority_nonce,
    })
}

pub fn ensure_authority_if_enabled() -> Result<(), DsrError> {
    if !enabled() || ARTIFACT_AUTHORITY.get().is_some() {
        return Ok(());
    }
    let authority = ArtifactAuthority::create()?;
    ARTIFACT_AUTHORITY.set(authority).map_err(|_| {
        DsrError::CachePolicy("artifact authority initialized concurrently".to_string())
    })
}

pub fn authority_snapshot_if_enabled() -> anyhow::Result<Option<ArtifactSpikeReexecConfig>> {
    ensure_authority_if_enabled()
        .map_err(|error| anyhow::anyhow!("create artifact spike authority: {error}"))?;
    ARTIFACT_AUTHORITY
        .get()
        .map(ArtifactAuthority::snapshot)
        .transpose()
        .map_err(|error| anyhow::anyhow!("snapshot artifact spike authority: {error}"))
}

pub fn store_if_enabled() -> Result<Option<ArtifactStore>, DsrError> {
    ensure_authority_if_enabled()?;
    ARTIFACT_AUTHORITY
        .get()
        .map(ArtifactAuthority::map_store)
        .transpose()
}

pub fn adopt_for_resume(snapshot: &ArtifactSpikeReexecConfig) -> anyhow::Result<()> {
    let authority = adopt(snapshot)
        .map_err(|error| anyhow::anyhow!("adopt artifact spike authority: {error}"))?;
    ARTIFACT_AUTHORITY
        .set(authority)
        .map_err(|_| anyhow::anyhow!("artifact spike authority was already initialized"))
}

#[cfg(test)]
fn adopt_for_test(snapshot: &ArtifactSpikeReexecConfig) -> Result<ArtifactAuthority, DsrError> {
    adopt(snapshot)
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum GatewayKind {
    Syscall,
    Direct,
    Indirect,
    Sensitive,
    Unsupported,
    Signal,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum ProcessValue {
    Gateway(GatewayKind),
    GenerationAddress,
    GenerationExpected,
    HostBias,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactBindings {
    values: BTreeMap<ProcessValue, u64>,
}

impl ArtifactBindings {
    pub fn from_values(
        values: impl IntoIterator<Item = (ProcessValue, u64)>,
    ) -> Result<Self, DsrError> {
        let mut result = BTreeMap::new();
        for (kind, value) in values {
            if result.insert(kind, value).is_some() {
                return Err(DsrError::CachePolicy(format!(
                    "duplicate artifact binding for {kind:?}"
                )));
            }
        }
        Ok(Self { values: result })
    }

    fn value(&self, kind: ProcessValue) -> Result<u64, DsrError> {
        self.values
            .get(&kind)
            .copied()
            .ok_or_else(|| DsrError::CachePolicy(format!("missing artifact binding for {kind:?}")))
    }

    fn bind(&mut self, kind: ProcessValue, value: u64) -> Result<(), DsrError> {
        if let Some(existing) = self.values.insert(kind, value)
            && existing != value
        {
            return Err(DsrError::CachePolicy(format!(
                "conflicting artifact binding for {kind:?}: 0x{existing:x} versus 0x{value:x}"
            )));
        }
        Ok(())
    }

    pub fn mismatch_summary(&self, replay: &Self) -> Option<String> {
        self.values.iter().find_map(|(kind, fresh)| {
            let replay = replay.values.get(kind).copied();
            match replay {
                Some(replay) if replay == *fresh => None,
                Some(replay) => Some(format!("{kind:?}: fresh=0x{fresh:x} replay=0x{replay:x}")),
                None => Some(format!("{kind:?}: fresh=0x{fresh:x} replay=<missing>")),
            }
        })
    }

    pub fn for_replay(
        generation_address: u64,
        generation_expected: u64,
        mode: super::emit::EmitAddressMode,
    ) -> Result<Self, DsrError> {
        let mut bindings = Self::from_values([
            (ProcessValue::GenerationAddress, generation_address),
            (ProcessValue::GenerationExpected, generation_expected),
            (
                ProcessValue::Gateway(GatewayKind::Syscall),
                super::gateway::syscall_exit_address(),
            ),
            (
                ProcessValue::Gateway(GatewayKind::Direct),
                super::gateway::direct_exit_address(),
            ),
            (
                ProcessValue::Gateway(GatewayKind::Indirect),
                super::gateway::indirect_exit_address(),
            ),
            (
                ProcessValue::Gateway(GatewayKind::Sensitive),
                super::gateway::sensitive_exit_address(),
            ),
            (
                ProcessValue::Gateway(GatewayKind::Unsupported),
                super::gateway::unsupported_exit_address(),
            ),
            (
                ProcessValue::Gateway(GatewayKind::Signal),
                super::gateway::signal_exit_address(),
            ),
        ])?;
        if let super::emit::EmitAddressMode::Biased { host_bias } = mode {
            bindings.bind(ProcessValue::HostBias, host_bias.get())?;
        }
        Ok(bindings)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaterializedValue {
    Guest(u64),
    Stable(u64),
    Process(ProcessValue, u64),
}

impl MaterializedValue {
    pub const fn raw(self) -> u64 {
        match self {
            Self::Guest(value) | Self::Stable(value) | Self::Process(_, value) => value,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingRelocation {
    first_word: u32,
    register: u8,
    value: ProcessValue,
}

#[derive(Debug, Default)]
pub struct ArtifactRecording {
    bindings: BTreeMap<ProcessValue, u64>,
    relocations: Vec<PendingRelocation>,
}

impl ArtifactRecording {
    pub fn bind(&mut self, kind: ProcessValue, value: u64) -> Result<(), DsrError> {
        let mut bindings = ArtifactBindings {
            values: std::mem::take(&mut self.bindings),
        };
        let result = bindings.bind(kind, value);
        self.bindings = bindings.values;
        result
    }

    pub fn record_mov_wide(
        &mut self,
        first_byte: CacheOffset,
        register: u32,
        value: MaterializedValue,
    ) -> Result<(), DsrError> {
        let MaterializedValue::Process(kind, raw) = value else {
            return Ok(());
        };
        self.bind(kind, raw)?;
        let first_word = first_byte.get().checked_div(4).ok_or_else(|| {
            DsrError::CachePolicy("artifact relocation offset overflow".to_string())
        })?;
        self.relocations.push(PendingRelocation {
            first_word,
            register: u8::try_from(register).map_err(|_| {
                DsrError::CachePolicy(format!(
                    "artifact MOV-wide register does not fit u8: {register}"
                ))
            })?,
            value: kind,
        });
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "finishing a recording captures code and all replay metadata"
    )]
    pub fn finish(
        self,
        words: Vec<u32>,
        map: Vec<PcMapEntry>,
        recovery: Vec<RecoveryEntry>,
        direct_links: Vec<DirectLink>,
        source_words: Vec<u32>,
    ) -> Result<ArtifactRecord, DsrError> {
        let bindings = ArtifactBindings {
            values: self.bindings,
        };
        let recorded_starts = self
            .relocations
            .iter()
            .map(|relocation| relocation.first_word)
            .collect::<BTreeSet<_>>();
        for first in 0..words.len().saturating_sub(3) {
            let sequence = &words[first..first + 4];
            let register = sequence[0] & 0x1f;
            let is_mov_wide = sequence.iter().enumerate().all(|(halfword, word)| {
                let expected = if halfword == 0 {
                    0xd280_0000
                } else {
                    0xf280_0000
                } | ((halfword as u32) << 21)
                    | register;
                (*word & !MOV_WIDE_IMM16_MASK) == expected
            });
            if !is_mov_wide {
                continue;
            }
            let materialized =
                sequence
                    .iter()
                    .enumerate()
                    .fold(0_u64, |value, (halfword, word)| {
                        value | (u64::from((word & MOV_WIDE_IMM16_MASK) >> 5) << (halfword * 16))
                    });
            let exact_process_value = bindings.values.values().any(|value| *value == materialized);
            let biased_literal = bindings
                .values
                .get(&ProcessValue::HostBias)
                .is_some_and(|bias| {
                    materialized >= *bias
                        && materialized.saturating_sub(*bias)
                            < carrick_dsr::address::BIASED_GUEST_LITERAL_TARGET_END
                });
            let first = u32::try_from(first).map_err(|_| {
                DsrError::CachePolicy("artifact MOV-wide index exceeds u32".to_string())
            })?;
            if (exact_process_value || biased_literal) && !recorded_starts.contains(&first) {
                return Err(DsrError::CachePolicy(format!(
                    "unrecorded process-derived MOV-wide value 0x{materialized:x} at word {first}"
                )));
            }
        }
        let relocations = self
            .relocations
            .into_iter()
            .map(|pending| {
                let first = usize::try_from(pending.first_word).map_err(|_| {
                    DsrError::CachePolicy("artifact relocation index overflow".to_string())
                })?;
                let slice = words.get(first..first.saturating_add(4)).ok_or_else(|| {
                    DsrError::CachePolicy(format!(
                        "recorded artifact relocation at word {first} is incomplete"
                    ))
                })?;
                Ok(ArtifactRelocation {
                    first_word: pending.first_word,
                    register: pending.register,
                    value: pending.value,
                    expected_opcode_mask: std::array::from_fn(|index| {
                        slice[index] & !MOV_WIDE_IMM16_MASK
                    }),
                })
            })
            .collect::<Result<Vec<_>, DsrError>>()?;
        let template = ArtifactTemplate::normalize(
            words,
            map,
            recovery,
            direct_links,
            source_words,
            relocations,
            &bindings,
        )?;
        Ok(ArtifactRecord { template, bindings })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactRecord {
    pub template: ArtifactTemplate,
    pub bindings: ArtifactBindings,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArtifactRelocation {
    pub first_word: u32,
    pub register: u8,
    pub value: ProcessValue,
    pub expected_opcode_mask: [u32; 4],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct PortableBiasedMemoryRecovery {
    scratch_registers: [u32; 4],
    scratch_count: u8,
    base_scratch: u32,
    base: BiasedBase,
    base_coordinate: BiasedBaseCoordinate,
    commit_base: bool,
    virtual_x18_scratch: Option<u32>,
    virtual_x28_scratch: Option<u32>,
    virtual_reserved_scratch: Option<u32>,
    instruction_complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum PortableRecoveryAction {
    Noop,
    RestoreGuestX17,
    RestoreGenerationGuardRegisters,
    RestoreGenerationGuard,
    RestoreIndirectRegisters,
    RestoreIndirectResolver,
    RestoreScratch {
        register: u32,
    },
    RestoreScratchInvalidBiasedLiteral {
        register: u32,
    },
    RestoreScratchCompleted {
        register: u32,
    },
    CommitVirtualizedAndRestoreScratch {
        register: u32,
        virtual_register: u32,
    },
    RestoreScratchAndContext {
        register: u32,
        context_register: u32,
    },
    RestoreScratchAndContextCompleted {
        register: u32,
        context_register: u32,
    },
    CommitVirtualizedAndRestoreScratchAndContext {
        register: u32,
        context_register: u32,
        virtual_register: u32,
    },
    RestoreDualVirtualReadOnly {
        x18_scratch: u32,
        x28_scratch: u32,
        context_scratch: u32,
    },
    RestoreDualVirtualReadOnlyCompleted {
        x18_scratch: u32,
        x28_scratch: u32,
        context_scratch: u32,
    },
    CommitDualVirtualAndRestore {
        x18_scratch: u32,
        x28_scratch: u32,
        context_scratch: u32,
        virtual_register: u32,
        virtual_scratch: u32,
    },
    RecoverCounterRead(super::emit::CounterReadRecovery),
    RecoverBiasedMemory(PortableBiasedMemoryRecovery),
    RecoverBiasedExclusive(BiasedExclusiveRecovery),
    RestoreDirectBinding {
        phase: DirectBindingRecoveryPhase,
        capture_progress: DirectBindingCaptureProgress,
        committed_link: Option<u64>,
    },
}

impl PortableRecoveryAction {
    fn normalize(action: RecoveryAction, bindings: &ArtifactBindings) -> Result<Self, DsrError> {
        Ok(match action {
            RecoveryAction::Noop => Self::Noop,
            RecoveryAction::RestoreGuestX17 => Self::RestoreGuestX17,
            RecoveryAction::RestoreGenerationGuardRegisters => {
                Self::RestoreGenerationGuardRegisters
            }
            RecoveryAction::RestoreGenerationGuard => Self::RestoreGenerationGuard,
            RecoveryAction::RestoreIndirectRegisters => Self::RestoreIndirectRegisters,
            RecoveryAction::RestoreIndirectResolver => Self::RestoreIndirectResolver,
            RecoveryAction::RestoreScratch { register } => Self::RestoreScratch { register },
            RecoveryAction::RestoreScratchInvalidBiasedLiteral { register } => {
                Self::RestoreScratchInvalidBiasedLiteral { register }
            }
            RecoveryAction::RestoreScratchCompleted { register } => {
                Self::RestoreScratchCompleted { register }
            }
            RecoveryAction::CommitVirtualizedAndRestoreScratch {
                register,
                virtual_register,
            } => Self::CommitVirtualizedAndRestoreScratch {
                register,
                virtual_register,
            },
            RecoveryAction::RestoreScratchAndContext {
                register,
                context_register,
            } => Self::RestoreScratchAndContext {
                register,
                context_register,
            },
            RecoveryAction::RestoreScratchAndContextCompleted {
                register,
                context_register,
            } => Self::RestoreScratchAndContextCompleted {
                register,
                context_register,
            },
            RecoveryAction::CommitVirtualizedAndRestoreScratchAndContext {
                register,
                context_register,
                virtual_register,
            } => Self::CommitVirtualizedAndRestoreScratchAndContext {
                register,
                context_register,
                virtual_register,
            },
            RecoveryAction::RestoreDualVirtualReadOnly {
                x18_scratch,
                x28_scratch,
                context_scratch,
            } => Self::RestoreDualVirtualReadOnly {
                x18_scratch,
                x28_scratch,
                context_scratch,
            },
            RecoveryAction::RestoreDualVirtualReadOnlyCompleted {
                x18_scratch,
                x28_scratch,
                context_scratch,
            } => Self::RestoreDualVirtualReadOnlyCompleted {
                x18_scratch,
                x28_scratch,
                context_scratch,
            },
            RecoveryAction::CommitDualVirtualAndRestore {
                x18_scratch,
                x28_scratch,
                context_scratch,
                virtual_register,
                virtual_scratch,
            } => Self::CommitDualVirtualAndRestore {
                x18_scratch,
                x28_scratch,
                context_scratch,
                virtual_register,
                virtual_scratch,
            },
            RecoveryAction::RecoverCounterRead(recovery) => Self::RecoverCounterRead(recovery),
            RecoveryAction::RecoverBiasedMemory(recovery) => {
                let bound_bias = bindings.value(ProcessValue::HostBias)?;
                if recovery.host_bias.get() != bound_bias {
                    return Err(DsrError::CachePolicy(format!(
                        "biased recovery binding mismatch: recovery=0x{:x} binding=0x{bound_bias:x}",
                        recovery.host_bias.get()
                    )));
                }
                Self::RecoverBiasedMemory(PortableBiasedMemoryRecovery {
                    scratch_registers: recovery.scratch_registers,
                    scratch_count: recovery.scratch_count,
                    base_scratch: recovery.base_scratch,
                    base: recovery.base,
                    base_coordinate: recovery.base_coordinate,
                    commit_base: recovery.commit_base,
                    virtual_x18_scratch: recovery.virtual_x18_scratch,
                    virtual_x28_scratch: recovery.virtual_x28_scratch,
                    virtual_reserved_scratch: recovery.virtual_reserved_scratch,
                    instruction_complete: recovery.instruction_complete,
                })
            }
            RecoveryAction::RecoverBiasedExclusive(recovery) => {
                Self::RecoverBiasedExclusive(recovery)
            }
            RecoveryAction::RestoreDirectBinding {
                phase,
                capture_progress,
                committed_link,
            } => Self::RestoreDirectBinding {
                phase,
                capture_progress,
                committed_link,
            },
        })
    }

    fn rebind(self, bindings: &ArtifactBindings) -> Result<RecoveryAction, DsrError> {
        Ok(match self {
            Self::Noop => RecoveryAction::Noop,
            Self::RestoreGuestX17 => RecoveryAction::RestoreGuestX17,
            Self::RestoreGenerationGuardRegisters => {
                RecoveryAction::RestoreGenerationGuardRegisters
            }
            Self::RestoreGenerationGuard => RecoveryAction::RestoreGenerationGuard,
            Self::RestoreIndirectRegisters => RecoveryAction::RestoreIndirectRegisters,
            Self::RestoreIndirectResolver => RecoveryAction::RestoreIndirectResolver,
            Self::RestoreScratch { register } => RecoveryAction::RestoreScratch { register },
            Self::RestoreScratchInvalidBiasedLiteral { register } => {
                RecoveryAction::RestoreScratchInvalidBiasedLiteral { register }
            }
            Self::RestoreScratchCompleted { register } => {
                RecoveryAction::RestoreScratchCompleted { register }
            }
            Self::CommitVirtualizedAndRestoreScratch {
                register,
                virtual_register,
            } => RecoveryAction::CommitVirtualizedAndRestoreScratch {
                register,
                virtual_register,
            },
            Self::RestoreScratchAndContext {
                register,
                context_register,
            } => RecoveryAction::RestoreScratchAndContext {
                register,
                context_register,
            },
            Self::RestoreScratchAndContextCompleted {
                register,
                context_register,
            } => RecoveryAction::RestoreScratchAndContextCompleted {
                register,
                context_register,
            },
            Self::CommitVirtualizedAndRestoreScratchAndContext {
                register,
                context_register,
                virtual_register,
            } => RecoveryAction::CommitVirtualizedAndRestoreScratchAndContext {
                register,
                context_register,
                virtual_register,
            },
            Self::RestoreDualVirtualReadOnly {
                x18_scratch,
                x28_scratch,
                context_scratch,
            } => RecoveryAction::RestoreDualVirtualReadOnly {
                x18_scratch,
                x28_scratch,
                context_scratch,
            },
            Self::RestoreDualVirtualReadOnlyCompleted {
                x18_scratch,
                x28_scratch,
                context_scratch,
            } => RecoveryAction::RestoreDualVirtualReadOnlyCompleted {
                x18_scratch,
                x28_scratch,
                context_scratch,
            },
            Self::CommitDualVirtualAndRestore {
                x18_scratch,
                x28_scratch,
                context_scratch,
                virtual_register,
                virtual_scratch,
            } => RecoveryAction::CommitDualVirtualAndRestore {
                x18_scratch,
                x28_scratch,
                context_scratch,
                virtual_register,
                virtual_scratch,
            },
            Self::RecoverCounterRead(recovery) => RecoveryAction::RecoverCounterRead(recovery),
            Self::RecoverBiasedMemory(recovery) => {
                let raw_bias = bindings.value(ProcessValue::HostBias)?;
                let host_bias =
                    carrick_dsr::address::NativeHostBias::new(raw_bias, 1).map_err(|error| {
                        DsrError::CachePolicy(format!(
                            "invalid artifact host-bias binding 0x{raw_bias:x}: {error}"
                        ))
                    })?;
                RecoveryAction::RecoverBiasedMemory(super::emit::BiasedMemoryRecovery {
                    scratch_registers: recovery.scratch_registers,
                    scratch_count: recovery.scratch_count,
                    base_scratch: recovery.base_scratch,
                    base: recovery.base,
                    base_coordinate: recovery.base_coordinate,
                    commit_base: recovery.commit_base,
                    virtual_x18_scratch: recovery.virtual_x18_scratch,
                    virtual_x28_scratch: recovery.virtual_x28_scratch,
                    virtual_reserved_scratch: recovery.virtual_reserved_scratch,
                    host_bias,
                    instruction_complete: recovery.instruction_complete,
                })
            }
            Self::RecoverBiasedExclusive(recovery) => {
                RecoveryAction::RecoverBiasedExclusive(recovery)
            }
            Self::RestoreDirectBinding {
                phase,
                capture_progress,
                committed_link,
            } => RecoveryAction::RestoreDirectBinding {
                phase,
                capture_progress,
                committed_link,
            },
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct PortableRecoveryEntry {
    cache: CacheOffset,
    action: PortableRecoveryAction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactTemplate {
    words: Vec<u32>,
    map: Vec<PcMapEntry>,
    recovery: Vec<PortableRecoveryEntry>,
    direct_links: Vec<DirectLink>,
    relocations: Vec<ArtifactRelocation>,
    source_words: Vec<u32>,
}

impl ArtifactTemplate {
    pub fn source_words(&self) -> &[u32] {
        &self.source_words
    }

    pub fn direct_links(&self) -> &[DirectLink] {
        &self.direct_links
    }

    pub fn matches_source(&self, words: &[u32]) -> bool {
        self.source_words == words
    }

    /// Drop fields consumed while packing immutable code, retaining only the
    /// PC/fault metadata needed after dyld maps the finished unit.
    pub fn into_runtime_metadata_only(mut self) -> Self {
        self.words.clear();
        self.direct_links.clear();
        self.relocations.clear();
        self.source_words.clear();
        self
    }

    pub fn take_runtime_metadata(
        &mut self,
        host_bias: Option<u64>,
    ) -> Result<RuntimeMetadata, DsrError> {
        let bindings = match host_bias {
            Some(host_bias) => {
                ArtifactBindings::from_values([(ProcessValue::HostBias, host_bias)])?
            }
            None => ArtifactBindings::from_values([])?,
        };
        let map = std::mem::take(&mut self.map);
        let recovery = std::mem::take(&mut self.recovery)
            .into_iter()
            .map(|entry| {
                Ok(RecoveryEntry {
                    cache: entry.cache,
                    action: entry.action.rebind(&bindings)?,
                })
            })
            .collect::<Result<Vec<_>, DsrError>>()?;
        Ok((map, recovery, std::mem::take(&mut self.direct_links)))
    }

    /// Materialize only container-stable relocations for an immutable unit.
    ///
    /// Gateway and generation addresses are forbidden: shared blocks reach
    /// gateways through `DsrContext` and generations through a binding index.
    /// A biased host mapping is part of the unit key, so it is the sole value
    /// that may be fixed while packing.
    pub fn materialize_immutable_words(
        &self,
        host_bias: Option<u64>,
    ) -> Result<Vec<u32>, DsrError> {
        let mut words = self.words.clone();
        for relocation in &self.relocations {
            if relocation.value != ProcessValue::HostBias {
                return Err(DsrError::CachePolicy(format!(
                    "immutable unit retains process relocation {:?}",
                    relocation.value
                )));
            }
            let value = host_bias.ok_or_else(|| {
                DsrError::CachePolicy(
                    "immutable unit has a host-bias relocation in direct mode".to_string(),
                )
            })?;
            let first = usize::try_from(relocation.first_word).map_err(|_| {
                DsrError::CachePolicy("immutable relocation index overflow".to_string())
            })?;
            for halfword in 0..4_usize {
                let index = first.checked_add(halfword).ok_or_else(|| {
                    DsrError::CachePolicy("immutable relocation range overflow".to_string())
                })?;
                let word = words.get_mut(index).ok_or_else(|| {
                    DsrError::CachePolicy(format!(
                        "immutable relocation word {index} is out of bounds"
                    ))
                })?;
                if (*word & !MOV_WIDE_IMM16_MASK) != relocation.expected_opcode_mask[halfword]
                    || (*word & MOV_WIDE_IMM16_MASK) != 0
                    || (*word & 0x1f) != u32::from(relocation.register)
                {
                    return Err(DsrError::CachePolicy(format!(
                        "immutable relocation opcode mismatch at word {index}"
                    )));
                }
                let immediate = ((value >> (halfword * 16)) & 0xffff) as u32;
                *word |= immediate << 5;
            }
        }
        Ok(words)
    }

    pub fn runtime_metadata(&self, host_bias: Option<u64>) -> Result<RuntimeMetadata, DsrError> {
        let bindings = match host_bias {
            Some(host_bias) => {
                ArtifactBindings::from_values([(ProcessValue::HostBias, host_bias)])?
            }
            None => ArtifactBindings::from_values([])?,
        };
        let recovery = self
            .recovery
            .iter()
            .map(|entry| {
                Ok(RecoveryEntry {
                    cache: entry.cache,
                    action: entry.action.rebind(&bindings)?,
                })
            })
            .collect::<Result<Vec<_>, DsrError>>()?;
        Ok((self.map.clone(), recovery, self.direct_links.clone()))
    }

    pub fn mismatch_summary(&self, fresh: &Self) -> Option<String> {
        if let Some((index, (stored, fresh))) = self
            .words
            .iter()
            .zip(&fresh.words)
            .enumerate()
            .find(|(_, (stored, fresh))| stored != fresh)
        {
            return Some(format!(
                "words[{index}]: stored=0x{stored:08x} fresh=0x{fresh:08x}"
            ));
        }
        if self.words.len() != fresh.words.len() {
            return Some(format!(
                "words length: stored={} fresh={}",
                self.words.len(),
                fresh.words.len()
            ));
        }
        if self.map != fresh.map {
            return Some(format!("map: stored={:?} fresh={:?}", self.map, fresh.map));
        }
        if self.recovery != fresh.recovery {
            return Some(format!(
                "recovery: stored={:?} fresh={:?}",
                self.recovery, fresh.recovery
            ));
        }
        if self.direct_links != fresh.direct_links {
            return Some(format!(
                "direct_links: stored={:?} fresh={:?}",
                self.direct_links, fresh.direct_links
            ));
        }
        if self.relocations != fresh.relocations {
            return Some(format!(
                "relocations: stored={:?} fresh={:?}",
                self.relocations, fresh.relocations
            ));
        }
        if self.source_words != fresh.source_words {
            return Some(format!(
                "source_words: stored={:?} fresh={:?}",
                self.source_words, fresh.source_words
            ));
        }
        None
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "an artifact template owns code and all replay metadata"
    )]
    pub fn normalize(
        mut words: Vec<u32>,
        map: Vec<PcMapEntry>,
        recovery: Vec<RecoveryEntry>,
        direct_links: Vec<DirectLink>,
        source_words: Vec<u32>,
        mut relocations: Vec<ArtifactRelocation>,
        bindings: &ArtifactBindings,
    ) -> Result<Self, DsrError> {
        relocations.sort_by_key(|relocation| relocation.first_word);
        let mut consumed = BTreeSet::new();
        for relocation in &relocations {
            if relocation.register > 30 {
                return Err(DsrError::CachePolicy(format!(
                    "artifact relocation uses invalid x{}",
                    relocation.register
                )));
            }
            let first = usize::try_from(relocation.first_word).map_err(|_| {
                DsrError::CachePolicy("artifact relocation index overflow".to_string())
            })?;
            let value = bindings.value(relocation.value)?;
            for halfword in 0..4_usize {
                let index = first.checked_add(halfword).ok_or_else(|| {
                    DsrError::CachePolicy("artifact relocation range overflow".to_string())
                })?;
                if !consumed.insert(index) {
                    return Err(DsrError::CachePolicy(format!(
                        "overlapping artifact relocation at word {index}"
                    )));
                }
                let word = words.get_mut(index).ok_or_else(|| {
                    DsrError::CachePolicy(format!(
                        "artifact relocation word {index} is out of bounds"
                    ))
                })?;
                let opcode = *word & !MOV_WIDE_IMM16_MASK;
                if opcode != relocation.expected_opcode_mask[halfword]
                    || (*word & 0x1f) != u32::from(relocation.register)
                {
                    return Err(DsrError::CachePolicy(format!(
                        "artifact relocation opcode mismatch at word {index}"
                    )));
                }
                let encoded = (*word & MOV_WIDE_IMM16_MASK) >> 5;
                let expected = ((value >> (halfword * 16)) & 0xffff) as u32;
                if encoded != expected {
                    return Err(DsrError::CachePolicy(format!(
                        "artifact relocation binding mismatch at word {index}"
                    )));
                }
                *word &= !MOV_WIDE_IMM16_MASK;
            }
        }
        let recovery = recovery
            .into_iter()
            .map(|entry| {
                Ok(PortableRecoveryEntry {
                    cache: entry.cache,
                    action: PortableRecoveryAction::normalize(entry.action, bindings)?,
                })
            })
            .collect::<Result<Vec<_>, DsrError>>()?;
        Ok(Self {
            words,
            map,
            recovery,
            direct_links,
            relocations,
            source_words,
        })
    }
}

pub fn replay_artifact(
    cache: &mut TranslationCache,
    template: &ArtifactTemplate,
    bindings: &ArtifactBindings,
) -> Result<EmittedBlock, DsrError> {
    replay_artifact_parts(
        cache,
        template.words.clone(),
        template.map.clone(),
        template.recovery.clone(),
        template.direct_links.clone(),
        &template.relocations,
        bindings,
    )
}

pub fn replay_artifact_owned(
    cache: &mut TranslationCache,
    template: ArtifactTemplate,
    bindings: &ArtifactBindings,
) -> Result<EmittedBlock, DsrError> {
    replay_artifact_parts(
        cache,
        template.words,
        template.map,
        template.recovery,
        template.direct_links,
        &template.relocations,
        bindings,
    )
}

fn replay_artifact_parts(
    cache: &mut TranslationCache,
    mut words: Vec<u32>,
    map: Vec<PcMapEntry>,
    recovery: Vec<PortableRecoveryEntry>,
    direct_links: Vec<DirectLink>,
    relocations: &[ArtifactRelocation],
    bindings: &ArtifactBindings,
) -> Result<EmittedBlock, DsrError> {
    for relocation in relocations {
        let first = usize::try_from(relocation.first_word).map_err(|_| {
            DsrError::CachePolicy("artifact replay relocation index overflow".to_string())
        })?;
        let value = bindings.value(relocation.value)?;
        for halfword in 0..4_usize {
            let index = first.checked_add(halfword).ok_or_else(|| {
                DsrError::CachePolicy("artifact replay relocation range overflow".to_string())
            })?;
            let word = words.get_mut(index).ok_or_else(|| {
                DsrError::CachePolicy(format!(
                    "artifact replay relocation word {index} is out of bounds"
                ))
            })?;
            if (*word & !MOV_WIDE_IMM16_MASK) != relocation.expected_opcode_mask[halfword]
                || (*word & MOV_WIDE_IMM16_MASK) != 0
                || (*word & 0x1f) != u32::from(relocation.register)
            {
                return Err(DsrError::CachePolicy(format!(
                    "artifact replay opcode mismatch at word {index}"
                )));
            }
            let immediate = ((value >> (halfword * 16)) & 0xffff) as u32;
            *word |= immediate << 5;
        }
    }
    let recovery = recovery
        .into_iter()
        .map(|entry| {
            Ok(RecoveryEntry {
                cache: entry.cache,
                action: entry.action.rebind(bindings)?,
            })
        })
        .collect::<Result<Vec<_>, DsrError>>()?;
    let code = cache.publish_words(&words)?;
    EmittedBlock::from_artifact_parts(code, map, direct_links, recovery)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emit::{
        BiasedBase, BiasedBaseCoordinate, BiasedMemoryRecovery, DirectLink, DirectLinkKind,
        DirectStubEnvelope, PcMapEntry, RecoveryAction, RecoveryEntry,
    };
    use crate::types::CacheOffset;
    use carrick_dsr::address::NativeHostBias;
    use carrick_guest_mem::GuestVa;
    use std::os::fd::AsRawFd;

    const IMM16_MASK: u32 = 0x001f_ffe0;

    fn mov_wide(register: u8, value: u64) -> [u32; 4] {
        std::array::from_fn(|halfword| {
            let base = if halfword == 0 {
                0xd280_0000
            } else {
                0xf280_0000
            };
            let immediate = ((value >> (halfword * 16)) & 0xffff) as u32;
            base | ((halfword as u32) << 21) | (immediate << 5) | u32::from(register)
        })
    }

    fn emit_artifact_fixture(
        generation_address: u64,
        host_bias: u64,
    ) -> (ArtifactTemplate, ArtifactBindings) {
        let mut words = mov_wide(16, generation_address).to_vec();
        words.extend([0xd280_0540, 0xd65f_03c0]); // mov x0, #42; ret
        let relocation = ArtifactRelocation {
            first_word: 0,
            register: 16,
            value: ProcessValue::GenerationAddress,
            expected_opcode_mask: std::array::from_fn(|index| words[index] & !IMM16_MASK),
        };
        let bindings = ArtifactBindings::from_values([
            (ProcessValue::GenerationAddress, generation_address),
            (ProcessValue::HostBias, host_bias),
        ])
        .expect("unique fixture bindings");
        let bias = NativeHostBias::new(host_bias, 16 * 1024).expect("aligned fixture bias");
        let recovery = vec![
            RecoveryEntry {
                cache: CacheOffset::published(0),
                action: RecoveryAction::RecoverBiasedMemory(BiasedMemoryRecovery {
                    scratch_registers: [16, 17, 0, 0],
                    scratch_count: 2,
                    base_scratch: 16,
                    base: BiasedBase::Register(0),
                    base_coordinate: BiasedBaseCoordinate::Guest,
                    commit_base: false,
                    virtual_x18_scratch: None,
                    virtual_x28_scratch: None,
                    virtual_reserved_scratch: None,
                    host_bias: bias,
                    instruction_complete: false,
                }),
            },
            RecoveryEntry {
                cache: CacheOffset::published(4),
                action: RecoveryAction::RestoreDirectBinding {
                    phase: DirectBindingRecoveryPhase::AuthorityInstall,
                    capture_progress: DirectBindingCaptureProgress::Complete,
                    committed_link: Some(0x4004),
                },
            },
        ];
        let template = ArtifactTemplate::normalize(
            words,
            vec![PcMapEntry {
                guest: GuestVa(0x4000),
                cache: CacheOffset::published(0),
            }],
            recovery,
            vec![DirectLink {
                slot: CacheOffset::published(20),
                source: GuestVa(0x4000),
                target: GuestVa(0x5000),
                kind: DirectLinkKind::Branch,
                stub: DirectStubEnvelope {
                    start: CacheOffset::published(24),
                    end: CacheOffset::published(28),
                },
            }],
            vec![0xd280_0540, 0xd65f_03c0],
            vec![relocation],
            &bindings,
        )
        .expect("normalize fixture");
        (template, bindings)
    }

    #[test]
    fn artifact_template_round_trips_through_manifest_serde() {
        let (template, _) = emit_artifact_fixture(0x1234_5678, 0x8000_0000);
        let encoded = serde_json::to_vec(&template).expect("encode artifact template");
        let decoded: ArtifactTemplate =
            serde_json::from_slice(&encoded).expect("decode artifact template");
        assert_eq!(decoded, template);
    }

    #[test]
    fn artifact_store_wire_format_is_compact_and_round_trips() {
        let (template, _) = emit_artifact_fixture(0x1234_5678, 0x8000_0000);
        let json = serde_json::to_vec(&WireArtifactTemplate::from(&template)).expect("encode json");
        let encoded = encode_artifact_template(&template).expect("encode artifact record");
        let decoded = decode_artifact_template(&encoded).expect("decode artifact record");

        assert_eq!(decoded, template);
        assert!(
            encoded.len() * 2 < json.len(),
            "bincode={} json={}",
            encoded.len(),
            json.len()
        );
    }

    #[test]
    fn immutable_materialization_rejects_generation_pointer_relocations() {
        let (template, _) = emit_artifact_fixture(0x1234_5678, 0x8000_0000);
        let error = template
            .materialize_immutable_words(Some(0x8000_0000))
            .expect_err("generation pointer must not enter immutable code");
        assert!(
            error.to_string().contains("GenerationAddress"),
            "unexpected rejection: {error}"
        );
    }

    #[test]
    fn normalization_removes_every_process_value() {
        let (a, a_bindings) = emit_artifact_fixture(0x1000_0000, 0x2000_0000);
        let (b, b_bindings) = emit_artifact_fixture(0x3000_0000, 0x4000_0000);
        assert_eq!(a, b);
        assert_ne!(a_bindings, b_bindings);
    }

    #[test]
    fn artifact_key_separates_address_modes_but_not_process_biases() {
        let guest = GuestVa(0x4000);
        let words = [0xf940_03e0, 0xd65f_03c0];
        let direct = ArtifactKey::from_source(guest, &words, EmitAddressMode::Direct);
        let biased_a = ArtifactKey::from_source(
            guest,
            &words,
            EmitAddressMode::Biased {
                host_bias: NativeHostBias::new(0x1000_0000, 16 * 1024).expect("aligned first bias"),
            },
        );
        let biased_b = ArtifactKey::from_source(
            guest,
            &words,
            EmitAddressMode::Biased {
                host_bias: NativeHostBias::new(0x2000_0000, 16 * 1024)
                    .expect("aligned second bias"),
            },
        );

        assert_ne!(direct, biased_a);
        assert_eq!(biased_a, biased_b);
    }

    #[test]
    fn image_key_separates_executables_guest_addresses_and_address_modes() {
        let guest = GuestVa(0x4000);
        let digest = [0x11; 32];
        let direct = ArtifactKey::from_image_digest(guest, digest, EmitAddressMode::Direct);
        let other_image =
            ArtifactKey::from_image_digest(guest, [0x22; 32], EmitAddressMode::Direct);
        let other_guest =
            ArtifactKey::from_image_digest(GuestVa(0x5000), digest, EmitAddressMode::Direct);
        let biased = ArtifactKey::from_image_digest(
            guest,
            digest,
            EmitAddressMode::Biased {
                host_bias: NativeHostBias::new(0x1000_0000, 16 * 1024).expect("aligned bias"),
            },
        );

        assert_ne!(direct, other_image);
        assert_ne!(direct, other_guest);
        assert_ne!(direct, biased);
    }

    #[test]
    fn template_mismatch_reports_first_differing_word() {
        let (stored, _) = emit_artifact_fixture(0x1000_0000, 0x2000_0000);
        let mut fresh = stored.clone();
        fresh.words[2] ^= 0x20;

        assert_eq!(
            stored.mismatch_summary(&fresh),
            Some("words[2]: stored=0xf2c00010 fresh=0xf2c00030".to_string())
        );
    }

    #[test]
    fn binding_mismatch_reports_process_value() {
        let fresh = ArtifactBindings::from_values([(ProcessValue::GenerationAddress, 0x1000)])
            .expect("fresh bindings");
        let replay = ArtifactBindings::from_values([(ProcessValue::GenerationAddress, 0x3000)])
            .expect("replay bindings");

        assert_eq!(
            fresh.mismatch_summary(&replay),
            Some("GenerationAddress: fresh=0x1000 replay=0x3000".to_string())
        );
    }

    // `replay_matches_fresh_metadata_and_guest_result` and
    // `counter_artifact_replay_matches_fresh_metadata` publish into a live
    // `TranslationCache` through the Darwin host JIT, which still lives in
    // the runtime this slice; they stay in the runtime shim
    // (`native_darwin/dsr/artifact_spike.rs`).

    #[test]
    fn authority_snapshot_preserves_identity_and_nonce() {
        let authority = ArtifactAuthority::create_for_test().expect("authority");
        let snapshot = authority.snapshot().expect("snapshot");
        let adopted_fd = unsafe { libc::fcntl(snapshot.host_fd, libc::F_DUPFD_CLOEXEC, 0) };
        assert!(adopted_fd >= 0);
        let mut inherited = snapshot;
        inherited.host_fd = adopted_fd;
        let adopted = adopt_for_test(&inherited).expect("adopt matching authority");
        assert_eq!(
            adopted
                .snapshot()
                .expect("adopted snapshot")
                .authority_nonce,
            snapshot.authority_nonce
        );
        assert_ne!(adopted.file().as_raw_fd(), authority.file().as_raw_fd());
    }

    #[test]
    fn authority_rejects_substituted_fd() {
        let authority = ArtifactAuthority::create_for_test().expect("authority");
        let mut snapshot = authority.snapshot().expect("snapshot");
        snapshot.host_inode ^= 1;
        assert!(adopt_for_test(&snapshot).is_err());
    }

    #[test]
    fn second_mapping_reads_committed_artifact() {
        let authority = ArtifactAuthority::create_for_test().expect("authority");
        let writer = authority.map_store().expect("writer mapping");
        let reader = authority.map_store().expect("reader mapping");
        let (template, _) = emit_artifact_fixture(0x1000_0000, 0x2000_0000);
        let key = ArtifactKey::from_source(
            GuestVa(0x4000),
            &template.source_words,
            EmitAddressMode::Direct,
        );
        writer.insert(key, &template).expect("insert artifact");
        assert_eq!(reader.lookup(key).expect("lookup artifact"), Some(template));
        let counters = writer.snapshot();
        assert_eq!(counters.lookups, 1);
        assert_eq!(counters.hits, 1);
        assert_eq!(counters.inserts, 1);
    }

    #[test]
    fn concurrent_writers_publish_distinct_artifacts_without_a_global_lock() {
        const WRITERS: u64 = 8;
        const RECORDS_PER_WRITER: u64 = 64;

        let authority = ArtifactAuthority::create_for_test().expect("authority");
        let store = authority.map_store().expect("shared mapping");
        let (template, _) = emit_artifact_fixture(0x1000_0000, 0x2000_0000);
        std::thread::scope(|scope| {
            for writer in 0..WRITERS {
                let store = &store;
                let template = &template;
                scope.spawn(move || {
                    for record in 0..RECORDS_PER_WRITER {
                        let ordinal = writer * RECORDS_PER_WRITER + record;
                        let guest = GuestVa(0x4000 + ordinal * 4);
                        let key = ArtifactKey::from_source(
                            guest,
                            &[ordinal as u32, 0xd65f_03c0],
                            EmitAddressMode::Direct,
                        );
                        store.insert(key, template).expect("insert artifact");
                    }
                });
            }
        });

        for ordinal in 0..WRITERS * RECORDS_PER_WRITER {
            let guest = GuestVa(0x4000 + ordinal * 4);
            let key = ArtifactKey::from_source(
                guest,
                &[ordinal as u32, 0xd65f_03c0],
                EmitAddressMode::Direct,
            );
            assert_eq!(
                store.lookup(key).expect("lookup artifact"),
                Some(template.clone())
            );
        }
        assert_eq!(store.snapshot().inserts, WRITERS * RECORDS_PER_WRITER);
    }

    #[test]
    fn committed_index_offset_is_visible_across_mappings() {
        let authority = ArtifactAuthority::create_for_test().expect("authority");
        let writer = authority.map_store().expect("writer mapping");
        let reader = authority.map_store().expect("reader mapping");
        let (template, _) = emit_artifact_fixture(0x1000_0000, 0x2000_0000);
        let key = ArtifactKey::from_source(
            GuestVa(0x4000),
            &template.source_words,
            EmitAddressMode::Direct,
        );

        assert_eq!(reader.index_offset(key.first_slot()), 0);
        writer.insert(key, &template).expect("insert artifact");
        assert!(reader.index_offset(key.first_slot()) >= ARTIFACT_RECORD_OFFSET);
    }

    #[test]
    fn sealing_store_is_shared_and_disables_recording() {
        let authority = ArtifactAuthority::create_for_test().expect("authority");
        let writer = authority.map_store().expect("writer mapping");
        let reader = authority.map_store().expect("reader mapping");

        assert!(writer.accepting_inserts());
        assert!(reader.accepting_inserts());
        writer.seal();
        assert!(!writer.accepting_inserts());
        assert!(!reader.accepting_inserts());
    }

    #[test]
    fn committed_guest_filter_is_visible_across_mappings() {
        let authority = ArtifactAuthority::create_for_test().expect("authority");
        let writer = authority.map_store().expect("writer mapping");
        let reader = authority.map_store().expect("reader mapping");
        let (template, _) = emit_artifact_fixture(0x1000_0000, 0x2000_0000);
        let guest = GuestVa(0x4000);
        let key = ArtifactKey::from_source(guest, &template.source_words, EmitAddressMode::Direct);

        assert!(!reader.may_contain_guest(guest, EmitAddressMode::Direct));
        writer.insert(key, &template).expect("insert artifact");
        assert!(reader.may_contain_guest(guest, EmitAddressMode::Direct));
        assert!(!reader.may_contain_guest(
            guest,
            EmitAddressMode::Biased {
                host_bias: NativeHostBias::new(0x1000_0000, 16 * 1024).expect("aligned bias"),
            }
        ));
    }

    #[test]
    fn source_mismatched_record_never_replays() {
        let authority = ArtifactAuthority::create_for_test().expect("authority");
        let store = authority.map_store().expect("store mapping");
        let (template, _) = emit_artifact_fixture(0x1000_0000, 0x2000_0000);
        let key = ArtifactKey::from_source(
            GuestVa(0x4000),
            &template.source_words,
            EmitAddressMode::Direct,
        );
        store.insert(key, &template).expect("insert artifact");
        let mismatch =
            ArtifactKey::from_source(GuestVa(0x4000), &[0xd503_201f], EmitAddressMode::Direct);
        assert_eq!(store.lookup(mismatch).expect("mismatched lookup"), None);
    }

    #[test]
    fn prefix_collision_requires_complete_source_match() {
        let (mut stored, _) = emit_artifact_fixture(0x1000_0000, 0x2000_0000);
        stored.source_words = vec![0xa9bf_7bfd, 0x9100_03fd, 0xd65f_03c0];
        let colliding_source = [0xa9bf_7bfd, 0x9100_03fd, 0xd400_0001];

        assert!(stored.matches_source(&stored.source_words));
        assert!(!stored.matches_source(&colliding_source));
    }
}
