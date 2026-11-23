//! Neutral record of shared file windows (#1338 step 2, design v3).
//!
//! A shared file window is a carrier's view of one host file's page cache:
//! every `MAP_SHARED` mapping of the file, in any MM, reaches the same host
//! pages, so there is no second copy and no write-back state. The carrier
//! installs the slot (an x86 CPL0 host-file extent, an HVF or KVM aarch64
//! alias, a soft aarch64 file alias); every decision about who may reach a
//! window and which file offsets may be published lives here, once, for
//! every ISA and carrier.
//!
//! Windows are fixed [`WINDOW_CHUNK_BYTES`] chunks of a file, keyed by
//! `(WindowIdentity, chunk)`, so a window never regrows. Each chunk holds
//! edge-only custody ([`ExtentCustody::edge_only`]): one edge per MM that
//! maps it, kept until that MM's last mapping of the chunk is gone (a chunk
//! mapped twice, or split by a partial `munmap`, keeps its edge until both
//! are unmapped). A chunk drops with its last edge, and a file record drops
//! with its last chunk.
//!
//! A size change that would shrink a mapped file is a state, not a moment:
//! [`WindowRegistry::begin_size_change`] moves the file to
//! [`WindowState::Shrinking`] and returns the edges whose leaves at or past
//! the new size must be revoked first ([`SizeAdmission::NeedsRevoke`]).
//! While it shrinks, a fault at or past the new size parks
//! ([`FaultAdmission::Park`]) and a second size change is
//! [`SizeAdmission::Busy`]; both wait for the file to return to
//! [`WindowState::Live`]. [`WindowRegistry::finish_size_change`] applies the
//! host's result: the new size on success, the old one on failure.
//!
//! The record holds no lease and no MM editor. A caller that gets `Park` or
//! `Busy` releases what it holds, enrols on its carrier's wait for this
//! file, and probes again after the wake that
//! [`WindowRegistry::finish_size_change`] asks for.

use super::publication::{ExtentCustody, ShareEdge};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use carrick_core_abi::{EdgeGeneration, MmIncarnationKey, OwnerGeneration};
use core::num::{NonZeroU32, NonZeroU64};

/// Bytes of a file one window covers.
pub const WINDOW_CHUNK_BYTES: u64 = 2 << 20;

/// One host file as the carrier names it: device and inode, plus the
/// carrier's generation for that inode, so a recycled inode number is a
/// different window.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WindowIdentity {
    pub device: u64,
    pub inode: u64,
    pub generation: NonZeroU64,
}

/// Index of one [`WINDOW_CHUNK_BYTES`] chunk of a file.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WindowChunk(u64);

impl WindowChunk {
    /// The chunk holding file offset `offset`.
    pub const fn of_offset(offset: u64) -> Self {
        Self(offset / WINDOW_CHUNK_BYTES)
    }
    pub const fn index(self) -> u64 {
        self.0
    }
    /// File offset of the chunk's first byte.
    pub const fn start(self) -> u64 {
        self.0.saturating_mul(WINDOW_CHUNK_BYTES)
    }
    /// File offset one past the chunk's last byte.
    pub const fn end(self) -> u64 {
        self.start().saturating_add(WINDOW_CHUNK_BYTES)
    }
}

/// Identity of one shrink, checked when its host result comes back.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ShrinkEpoch(NonZeroU64);

/// A file's size state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowState {
    /// Faults below the believed EOF publish; at or past it they are SIGBUS.
    Live,
    /// A shrink to `new_len` is revoking leaves before the host applies it.
    Shrinking { new_len: u64, epoch: ShrinkEpoch },
}

/// How a mapping may use the window. A writable mapping counts toward
/// [`WindowRegistry::writable_maps`] (memfd `F_SEAL_WRITE` is EBUSY while
/// one is live).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowAccess {
    ReadOnly,
    Writable,
}

/// The answer to a fault at a file offset in a window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultAdmission {
    /// Publish the leaf.
    Publish,
    /// The offset is at or past the file's end: SIGBUS (`BUS_ADRERR`).
    Bus,
    /// A shrink is under way past this offset: not now. Release every lease
    /// and editor, wait for the file, then fault again.
    Park,
}

/// The answer to a host size change of a file before it runs.
#[derive(Debug, Eq, PartialEq)]
pub enum SizeAdmission {
    /// No window is past the new size: run it, then
    /// [`WindowRegistry::observe_eof`] with the result.
    Admit,
    /// Another size change is under way: not now. Wait for the file, then
    /// ask again.
    Busy,
    /// Revoke every listed edge's leaves at or past `from` (the caller rounds
    /// up to its page), shoot down their TLBs, then run the host call and
    /// report it with [`WindowRegistry::finish_size_change`].
    NeedsRevoke(RevokePlan),
}

/// The leaves a shrink must revoke before the host applies it.
#[derive(Debug, Eq, PartialEq)]
pub struct RevokePlan {
    pub epoch: ShrinkEpoch,
    /// The new size: every leaf at or past it goes.
    pub from: u64,
    /// Each chunk that reaches past `from`, with each MM mapping it.
    pub edges: Vec<(WindowChunk, MmIncarnationKey)>,
}

/// What the host size change did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SizeChangeOutcome {
    Applied,
    /// The host refused it: the file keeps its old size.
    Failed,
}

/// What dropping one mapping left.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Detached {
    /// The MM still maps this chunk elsewhere; its edge stays.
    StillMapped,
    /// The MM's last mapping of the chunk is gone and its edge is revoked.
    /// `chunk_dropped`: it was the chunk's last edge, so the carrier may
    /// release (or, where it can't unmap, retire for reuse) the slot.
    EdgeRevoked {
        edge: ShareEdge,
        chunk_dropped: bool,
    },
}

/// A broken invariant: the caller named something the record never gave.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowRefusal {
    /// The MM holds no mapping of this window.
    Foreign,
    /// No record for this file or chunk.
    Unknown,
    /// The size-change result names a shrink that is not the current one.
    StaleEpoch,
    /// A counter would overflow.
    Overflow,
}

struct ChunkRecord {
    custody: ExtentCustody,
    /// Live mappings of this chunk per MM; the MM's edge goes with its last.
    mappings: BTreeMap<MmIncarnationKey, NonZeroU32>,
}

struct FileRecord {
    believed_eof: u64,
    state: WindowState,
    /// The size to return to if a shrink fails.
    eof_before_shrink: u64,
    writable_maps: u64,
    chunks: BTreeMap<WindowChunk, ChunkRecord>,
}

/// Every shared file window of one carrier. The carrier keeps it under the
/// lease that orders its mapping edits; nothing here waits.
#[derive(Default)]
pub struct WindowRegistry {
    files: BTreeMap<WindowIdentity, FileRecord>,
    next_epoch: u64,
}

impl WindowRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one mapping of `chunk` by `mm`. The first mapping of a file
    /// takes `eof` as the believed size; later ones keep the record's own.
    /// The first mapping of a chunk by an MM mints that MM's edge; later
    /// ones count against it. Allowed while the file shrinks: its faults
    /// past the new size park like any other.
    ///
    /// # Safety
    /// Only the carrier's mapping path may call this, after it has itself
    /// admitted `mm`'s mapping of this file ([`ExtentCustody::mint_shared_edge`]).
    pub unsafe fn attach(
        &mut self,
        identity: WindowIdentity,
        chunk: WindowChunk,
        mm: MmIncarnationKey,
        access: WindowAccess,
        eof: u64,
    ) -> Result<EdgeGeneration, WindowRefusal> {
        let file = self.files.entry(identity).or_insert(FileRecord {
            believed_eof: eof,
            state: WindowState::Live,
            eof_before_shrink: eof,
            writable_maps: 0,
            chunks: BTreeMap::new(),
        });
        let writable_maps = match access {
            WindowAccess::Writable => file
                .writable_maps
                .checked_add(1)
                .ok_or(WindowRefusal::Overflow)?,
            WindowAccess::ReadOnly => file.writable_maps,
        };
        let record = file.chunks.entry(chunk).or_insert_with(|| ChunkRecord {
            custody: ExtentCustody::edge_only(OwnerGeneration::new(identity.generation)),
            mappings: BTreeMap::new(),
        });
        let generation = match record.mappings.get(&mm).copied() {
            Some(count) => {
                let count = count.checked_add(1).ok_or(WindowRefusal::Overflow)?;
                let edge = record.custody.edge(mm).ok_or(WindowRefusal::Foreign)?;
                record.mappings.insert(mm, count);
                edge.generation
            }
            None => {
                // SAFETY: the caller admitted this mapping (this fn's contract).
                let Some(generation) = (unsafe { record.custody.mint_shared_edge(mm) }) else {
                    if record.mappings.is_empty() {
                        file.chunks.remove(&chunk);
                    }
                    return Err(WindowRefusal::Overflow);
                };
                record.mappings.insert(mm, NonZeroU32::MIN);
                generation
            }
        };
        file.writable_maps = writable_maps;
        Ok(generation)
    }

    /// Drop one mapping of `chunk` by `mm` (an `munmap`, the unmapped part
    /// of a split, or the MM's teardown, once per mapping).
    pub fn detach(
        &mut self,
        identity: WindowIdentity,
        chunk: WindowChunk,
        mm: MmIncarnationKey,
        access: WindowAccess,
    ) -> Result<Detached, WindowRefusal> {
        let file = self
            .files
            .get_mut(&identity)
            .ok_or(WindowRefusal::Unknown)?;
        let record = file.chunks.get_mut(&chunk).ok_or(WindowRefusal::Unknown)?;
        let count = record
            .mappings
            .get(&mm)
            .copied()
            .ok_or(WindowRefusal::Foreign)?;
        if access == WindowAccess::Writable {
            file.writable_maps = file
                .writable_maps
                .checked_sub(1)
                .ok_or(WindowRefusal::Foreign)?;
        }
        let detached = match NonZeroU32::new(count.get() - 1) {
            Some(rest) => {
                record.mappings.insert(mm, rest);
                Detached::StillMapped
            }
            None => {
                record.mappings.remove(&mm);
                let edge = record
                    .custody
                    .revoke_edge(mm)
                    .ok_or(WindowRefusal::Foreign)?;
                let chunk_dropped = record.custody.edge_count() == 0;
                if chunk_dropped {
                    file.chunks.remove(&chunk);
                }
                Detached::EdgeRevoked {
                    edge,
                    chunk_dropped,
                }
            }
        };
        if file.chunks.is_empty() && file.state == WindowState::Live {
            self.files.remove(&identity);
        }
        Ok(detached)
    }

    /// A fault by `mm` at file offset `offset` of its mapped chunk.
    pub fn fault(
        &self,
        identity: WindowIdentity,
        mm: MmIncarnationKey,
        offset: u64,
    ) -> Result<FaultAdmission, WindowRefusal> {
        let file = self.files.get(&identity).ok_or(WindowRefusal::Unknown)?;
        let record = file
            .chunks
            .get(&WindowChunk::of_offset(offset))
            .ok_or(WindowRefusal::Unknown)?;
        if !record.mappings.contains_key(&mm) {
            return Err(WindowRefusal::Foreign);
        }
        Ok(match file.state {
            WindowState::Live if offset < file.believed_eof => FaultAdmission::Publish,
            WindowState::Live => FaultAdmission::Bus,
            // Below both sizes nothing changes; at or past the new one the
            // leaf may be revoked under it, and a stale size must not
            // republish it.
            WindowState::Shrinking { new_len, .. } if offset < new_len => FaultAdmission::Publish,
            WindowState::Shrinking { .. } => FaultAdmission::Park,
        })
    }

    /// The host size the carrier last observed for a mapped file (after a
    /// write or an admitted size change). Only growth moves the believed
    /// size in `Live`; a shrink runs through [`Self::begin_size_change`].
    pub fn observe_eof(&mut self, identity: WindowIdentity, len: u64) {
        if let Some(file) = self.files.get_mut(&identity)
            && file.state == WindowState::Live
            && len > file.believed_eof
        {
            file.believed_eof = len;
        }
    }

    /// Admit a host size change of `identity` to `new_len` before it runs.
    pub fn begin_size_change(&mut self, identity: WindowIdentity, new_len: u64) -> SizeAdmission {
        let Some(file) = self.files.get_mut(&identity) else {
            return SizeAdmission::Admit;
        };
        if matches!(file.state, WindowState::Shrinking { .. }) {
            return SizeAdmission::Busy;
        }
        if new_len >= file.believed_eof {
            return SizeAdmission::Admit;
        }
        let Some(epoch) = self
            .next_epoch
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .map(ShrinkEpoch)
        else {
            return SizeAdmission::Busy;
        };
        self.next_epoch = epoch.0.get();
        file.eof_before_shrink = file.believed_eof;
        file.state = WindowState::Shrinking { new_len, epoch };
        let edges = file
            .chunks
            .iter()
            .filter(|(chunk, _)| chunk.end() > new_len)
            .flat_map(|(chunk, record)| record.mappings.keys().map(|mm| (*chunk, *mm)))
            .collect();
        SizeAdmission::NeedsRevoke(RevokePlan {
            epoch,
            from: new_len,
            edges,
        })
    }

    /// The host result of the shrink `epoch` admitted. The file returns to
    /// `Live` at the new size, or at its old size if the host refused, and
    /// the caller wakes every fault and size change parked on it.
    pub fn finish_size_change(
        &mut self,
        identity: WindowIdentity,
        epoch: ShrinkEpoch,
        outcome: SizeChangeOutcome,
    ) -> Result<(), WindowRefusal> {
        let file = self
            .files
            .get_mut(&identity)
            .ok_or(WindowRefusal::Unknown)?;
        let WindowState::Shrinking {
            new_len,
            epoch: current,
        } = file.state
        else {
            return Err(WindowRefusal::StaleEpoch);
        };
        if current != epoch {
            return Err(WindowRefusal::StaleEpoch);
        }
        file.believed_eof = match outcome {
            SizeChangeOutcome::Applied => new_len,
            SizeChangeOutcome::Failed => file.eof_before_shrink,
        };
        file.state = WindowState::Live;
        if file.chunks.is_empty() {
            self.files.remove(&identity);
        }
        Ok(())
    }

    /// The file's size state, if any window of it is mapped.
    pub fn state(&self, identity: WindowIdentity) -> Option<WindowState> {
        self.files.get(&identity).map(|file| file.state)
    }

    /// The size faults are checked against in `Live`.
    pub fn believed_eof(&self, identity: WindowIdentity) -> Option<u64> {
        self.files.get(&identity).map(|file| file.believed_eof)
    }

    /// Live writable mappings of the file, in every MM.
    pub fn writable_maps(&self, identity: WindowIdentity) -> u64 {
        self.files
            .get(&identity)
            .map_or(0, |file| file.writable_maps)
    }

    /// The MMs holding an edge on `chunk`.
    pub fn edges(&self, identity: WindowIdentity, chunk: WindowChunk) -> Vec<MmIncarnationKey> {
        self.files
            .get(&identity)
            .and_then(|file| file.chunks.get(&chunk))
            .map(|record| record.mappings.keys().copied().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests;
