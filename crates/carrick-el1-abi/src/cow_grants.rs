//! Host-provisioned replacement frames for guest EL1 fork-COW resolution.
//!
//! A fork arms an MM's private anonymous leaves read-only (`SW_EL1_COW`). On
//! the guest-owned descriptor lane EL1 resolves the first write to such a
//! leaf itself: it takes a *grant* from this pool (a 16 KiB replacement
//! compound whose stage-2 owner and kernel inventory mapping the host already
//! made live for exactly this MM), copies the still-shared bytes into it
//! through the MM's COW copy window, repoints the leaves, and records the
//! completion in the same record. No host exit is taken.
//!
//! The host later *settles* each completion (inventory split, old-frame
//! references, alias publication, disarm) while it excludes the MM's EL1
//! editor, and refills the pool in batches. Every record has exactly one
//! owner at a time, named by its state:
//!
//! ```text
//!   EMPTY --host publish--> WRITING --> READY --EL1 claim--> CLAIMED
//!     ^                                   |                    |  \
//!     |                          host revoke                   |   EL1 abandon
//!     +-----------------------------------+                    |   (back to READY)
//!     +--------------------host settle-------------- USED <----+ EL1 complete
//! ```
//!
//! EL1 claims, completes and abandons only while it holds the MM's exact
//! page-table editor; the host revokes and settles only while it excludes
//! that editor. So a CLAIMED record never exists for an MM the host has
//! excluded, and a USED record is final for EL1: the host is its only
//! reader until it frees the slot. Every (re)publication bumps the record's
//! epoch, so a stale host handle (slot, epoch) can never settle or revoke a
//! successor grant.
//!
//! Lookups are bounded: an MM's records live on a 64-probe chain from a hash
//! of its key. A full chain only declines the guest fast path (the fault is
//! forwarded and the host resolves it as before).

use carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity;
use carrick_sched_core::ExcludedEditor;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

/// Records in the carrier-wide pool.
pub const COW_GRANT_POOL_SLOTS: usize = 1024;
/// Probe chain length for one MM's records.
pub const COW_GRANT_PROBES: usize = 64;
/// Bytes of one grant: the host COW compound.
pub const COW_GRANT_SIZE: u64 = 16 * 1024;
/// Protocol revision, folded into [`crate::EL1_ABI_LAYOUT_HASH`].
pub const COW_GRANT_PROTOCOL_VERSION: u64 = 1;

const EMPTY: u64 = 0;
const WRITING: u64 = 1;
const READY: u64 = 2;
const CLAIMED: u64 = 3;
const USED: u64 = 4;
const STATE_MASK: u64 = 7;
const EPOCH_ONE: u64 = 8;
const PAGE: u64 = 4096;

/// Why EL1 left a COW write fault to the host. Indexes
/// [`CowGrantPool::declined`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum CowDecline {
    /// The leaf is not a valid, EL1-private, COW-armed page EL1 may write
    /// (untagged backend leaf, kernel-only, block, mprotect'd read-only).
    Unclassified = 0,
    /// No grant for this MM was ready.
    PoolEmpty = 1,
    /// Another EL1 editor held the MM, or a host pause closed its gate.
    EditorBusy = 2,
    /// The copy or the repoint refused (stale leaf, window absent, split
    /// needed); the grant went back to the pool untouched semantically.
    Refused = 3,
}

/// Number of [`CowDecline`] reasons.
pub const COW_DECLINE_REASONS: usize = 4;

/// One ready grant as EL1 claimed it, or as the host published it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CowGrant {
    pub slot: usize,
    /// The record's state word at publication, without the state bits.
    pub epoch: u64,
    pub mm_key: u64,
    /// 16 KiB-aligned IPA of the replacement compound.
    pub physical_ipa: u64,
    pub backing: BackingIdentity,
}

/// One guest COW EL1 completed with a grant: `[span_va, span_va + span_len)`
/// moved from `old_ipa` (the span's first page) to `new_ipa`, both inside
/// their 16 KiB compounds at the same offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CowGrantCompletion {
    pub grant: CowGrant,
    pub span_va: u64,
    pub span_len: u64,
    pub old_ipa: u64,
    pub new_ipa: u64,
}

impl CowGrantCompletion {
    /// Whether the completion describes a repoint inside one grant compound
    /// from one old compound at the same offset, page-granular and nonempty.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        let offset = self.new_ipa.wrapping_sub(self.grant.physical_ipa);
        self.span_len != 0
            && self.span_len.is_multiple_of(PAGE)
            && self.span_va.is_multiple_of(PAGE)
            && self.old_ipa.is_multiple_of(PAGE)
            && self.new_ipa >= self.grant.physical_ipa
            && offset + self.span_len <= COW_GRANT_SIZE
            && (self.old_ipa & (COW_GRANT_SIZE - 1)) == offset
            && self.span_va.checked_add(self.span_len).is_some()
    }
}

/// One pool record. The state word is published last (Release) by its
/// owner and read first (Acquire) by the other venue.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct CowGrantRecord {
    state: AtomicU64,
    mm_key: AtomicU64,
    physical_ipa: AtomicU64,
    frame_id: AtomicU64,
    mapping_id: AtomicU64,
    owner_generation: AtomicU64,
    inventory_revision: AtomicU64,
    span_va: AtomicU64,
    span_len: AtomicU64,
    old_ipa: AtomicU64,
    new_ipa: AtomicU64,
}

impl CowGrantRecord {
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(EMPTY),
            mm_key: AtomicU64::new(0),
            physical_ipa: AtomicU64::new(0),
            frame_id: AtomicU64::new(0),
            mapping_id: AtomicU64::new(0),
            owner_generation: AtomicU64::new(0),
            inventory_revision: AtomicU64::new(0),
            span_va: AtomicU64::new(0),
            span_len: AtomicU64::new(0),
            old_ipa: AtomicU64::new(0),
            new_ipa: AtomicU64::new(0),
        }
    }

    fn grant(&self, slot: usize, word: u64) -> Option<CowGrant> {
        let nz = |cell: &AtomicU64| NonZeroU64::new(cell.load(Ordering::Relaxed));
        Some(CowGrant {
            slot,
            epoch: word & !STATE_MASK,
            mm_key: self.mm_key.load(Ordering::Relaxed),
            physical_ipa: self.physical_ipa.load(Ordering::Relaxed),
            backing: BackingIdentity {
                frame_id: nz(&self.frame_id)?,
                mapping_id: nz(&self.mapping_id)?,
                owner_generation: nz(&self.owner_generation)?,
                inventory_revision: nz(&self.inventory_revision)?,
            },
        })
    }
}

impl Default for CowGrantRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// The carrier-wide pool, in the shared EL1 region. All-zero bytes are an
/// empty pool.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct CowGrantPool {
    /// One bit per record in the USED state, so settlement visits only
    /// completions. A set bit is a hint; the record state is the authority.
    used: [AtomicU64; COW_GRANT_POOL_SLOTS / 64],
    /// Guest COW faults EL1 resolved with a grant.
    resolved: AtomicU64,
    /// Guest COW write faults EL1 left to the host, by [`CowDecline`].
    declined: [AtomicU64; COW_DECLINE_REASONS],
    records: [CowGrantRecord; COW_GRANT_POOL_SLOTS],
}

impl CowGrantPool {
    pub const fn new() -> Self {
        Self {
            used: [const { AtomicU64::new(0) }; COW_GRANT_POOL_SLOTS / 64],
            resolved: AtomicU64::new(0),
            declined: [const { AtomicU64::new(0) }; COW_DECLINE_REASONS],
            records: [const { CowGrantRecord::new() }; COW_GRANT_POOL_SLOTS],
        }
    }

    fn probe(mm_key: u64, offset: usize) -> usize {
        let mixed = mm_key.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        ((mixed >> 32) as usize + offset) & (COW_GRANT_POOL_SLOTS - 1)
    }

    /// Host, while it excludes `mm_key`'s EL1 editor: publish one grant whose
    /// replacement compound, stage-2 owner and kernel mapping are live for
    /// exactly this MM. `None`: the MM's probe chain has no free record (the
    /// caller keeps the backing and rolls it back).
    pub fn publish(
        &self,
        mm_key: u64,
        physical_ipa: u64,
        backing: BackingIdentity,
    ) -> Option<CowGrant> {
        if mm_key == 0 || physical_ipa == 0 || !physical_ipa.is_multiple_of(COW_GRANT_SIZE) {
            return None;
        }
        for offset in 0..COW_GRANT_PROBES {
            let slot = Self::probe(mm_key, offset);
            let record = &self.records[slot];
            let word = record.state.load(Ordering::Acquire);
            if word & STATE_MASK != EMPTY {
                continue;
            }
            let writing = (word & !STATE_MASK).wrapping_add(EPOCH_ONE) | WRITING;
            if record
                .state
                .compare_exchange(word, writing, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            record.mm_key.store(mm_key, Ordering::Relaxed);
            record.physical_ipa.store(physical_ipa, Ordering::Relaxed);
            record
                .frame_id
                .store(backing.frame_id.get(), Ordering::Relaxed);
            record
                .mapping_id
                .store(backing.mapping_id.get(), Ordering::Relaxed);
            record
                .owner_generation
                .store(backing.owner_generation.get(), Ordering::Relaxed);
            record
                .inventory_revision
                .store(backing.inventory_revision.get(), Ordering::Relaxed);
            for cell in [
                &record.span_va,
                &record.span_len,
                &record.old_ipa,
                &record.new_ipa,
            ] {
                cell.store(0, Ordering::Relaxed);
            }
            let ready = (writing & !STATE_MASK) | READY;
            record.state.store(ready, Ordering::Release);
            return Some(CowGrant {
                slot,
                epoch: ready & !STATE_MASK,
                mm_key,
                physical_ipa,
                backing,
            });
        }
        None
    }

    /// EL1, holding `mm_key`'s editor: take one ready grant of this MM.
    pub fn claim(&self, mm_key: u64) -> Option<CowGrant> {
        if mm_key == 0 {
            return None;
        }
        for offset in 0..COW_GRANT_PROBES {
            let slot = Self::probe(mm_key, offset);
            let record = &self.records[slot];
            let word = record.state.load(Ordering::Acquire);
            if word & STATE_MASK != READY || record.mm_key.load(Ordering::Relaxed) != mm_key {
                continue;
            }
            let Some(grant) = record.grant(slot, word) else {
                continue;
            };
            if record
                .state
                .compare_exchange(
                    word,
                    (word & !STATE_MASK) | CLAIMED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Some(grant);
            }
        }
        None
    }

    /// EL1, still holding the editor: the claimed grant was not used (the
    /// repoint refused before storing anything); it is ready again.
    pub fn abandon(&self, grant: &CowGrant) -> bool {
        let Some(record) = self.records.get(grant.slot) else {
            return false;
        };
        record
            .state
            .compare_exchange(
                grant.epoch | CLAIMED,
                grant.epoch | READY,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// EL1, still holding the editor, after the repoint was applied and the
    /// MM's stale translations invalidated: record what moved. The record
    /// becomes the host's to settle.
    pub fn complete(&self, completion: &CowGrantCompletion) -> bool {
        let grant = completion.grant;
        let Some(record) = self.records.get(grant.slot) else {
            return false;
        };
        if !completion.is_well_formed()
            || record.state.load(Ordering::Acquire) != grant.epoch | CLAIMED
        {
            return false;
        }
        record.span_va.store(completion.span_va, Ordering::Relaxed);
        record
            .span_len
            .store(completion.span_len, Ordering::Relaxed);
        record.old_ipa.store(completion.old_ipa, Ordering::Relaxed);
        record.new_ipa.store(completion.new_ipa, Ordering::Relaxed);
        if record
            .state
            .compare_exchange(
                grant.epoch | CLAIMED,
                grant.epoch | USED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        self.used[grant.slot / 64].fetch_or(1 << (grant.slot % 64), Ordering::Release);
        self.resolved.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// EL1: a COW write fault was left to the host.
    pub fn note_declined(&self, reason: CowDecline) {
        self.declined[reason as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Guest COW faults EL1 resolved so far.
    #[must_use]
    pub fn resolved(&self) -> u64 {
        self.resolved.load(Ordering::Relaxed)
    }

    /// Guest COW write faults EL1 left to the host, by [`CowDecline`].
    #[must_use]
    pub fn declined(&self) -> [u64; COW_DECLINE_REASONS] {
        core::array::from_fn(|index| self.declined[index].load(Ordering::Relaxed))
    }

    /// Host, while it excludes the MM's EL1 editor: every completion of the
    /// MM, oldest slot first. The host settles each and then frees it with
    /// [`Self::finish`]. The exclusion proof is what makes the records
    /// final: no EL1 editor of the MM can complete or claim meanwhile.
    pub fn completions<'p>(
        &'p self,
        excluded: &ExcludedEditor<'_>,
    ) -> impl Iterator<Item = CowGrantCompletion> + 'p {
        let mm_key = excluded.key();
        self.used
            .iter()
            .enumerate()
            .flat_map(move |(word_index, bits)| {
                let mut bits = bits.load(Ordering::Acquire);
                core::iter::from_fn(move || {
                    while bits != 0 {
                        let bit = bits.trailing_zeros() as usize;
                        bits &= bits - 1;
                        let slot = word_index * 64 + bit;
                        let record = &self.records[slot];
                        let word = record.state.load(Ordering::Acquire);
                        if word & STATE_MASK != USED
                            || record.mm_key.load(Ordering::Relaxed) != mm_key
                        {
                            continue;
                        }
                        let Some(grant) = record.grant(slot, word) else {
                            continue;
                        };
                        return Some(CowGrantCompletion {
                            grant,
                            span_va: record.span_va.load(Ordering::Relaxed),
                            span_len: record.span_len.load(Ordering::Relaxed),
                            old_ipa: record.old_ipa.load(Ordering::Relaxed),
                            new_ipa: record.new_ipa.load(Ordering::Relaxed),
                        });
                    }
                    None
                })
            })
    }

    /// Host (read-only): whether `mm_key` has a completion awaiting
    /// settlement. A host path that builds from the MM's frames asserts this
    /// is false after the exclusion that settles it.
    #[must_use]
    pub fn has_completions_for(&self, mm_key: u64) -> bool {
        self.any_completed()
            && self.used.iter().enumerate().any(|(word_index, bits)| {
                let mut bits = bits.load(Ordering::Acquire);
                while bits != 0 {
                    let slot = word_index * 64 + bits.trailing_zeros() as usize;
                    bits &= bits - 1;
                    let record = &self.records[slot];
                    if record.state.load(Ordering::Acquire) & STATE_MASK == USED
                        && record.mm_key.load(Ordering::Relaxed) == mm_key
                    {
                        return true;
                    }
                }
                false
            })
    }

    /// Host: whether any MM has a completion awaiting settlement.
    #[must_use]
    pub fn any_completed(&self) -> bool {
        self.used
            .iter()
            .any(|bits| bits.load(Ordering::Acquire) != 0)
    }

    /// Host: every ready grant of `mm_key` (the host's own ledger decides
    /// what to revoke; this is its authenticated view of the shared side).
    pub fn ready(&self, mm_key: u64) -> impl Iterator<Item = CowGrant> + '_ {
        (0..COW_GRANT_PROBES).filter_map(move |offset| {
            let slot = Self::probe(mm_key, offset);
            let record = &self.records[slot];
            let word = record.state.load(Ordering::Acquire);
            (word & STATE_MASK == READY && record.mm_key.load(Ordering::Relaxed) == mm_key)
                .then(|| record.grant(slot, word))
                .flatten()
        })
    }

    /// Host, while it excludes the grant MM's EL1 editor: free a settled
    /// completion. Only the exact (slot, epoch) the host settled may free it.
    pub fn finish(&self, excluded: &ExcludedEditor<'_>, grant: &CowGrant) -> bool {
        grant.mm_key == excluded.key() && self.release(grant, USED)
    }

    /// Host, while it excludes the grant MM's EL1 editor: withdraw an unused
    /// grant. `false` if EL1 already used it.
    pub fn revoke(&self, excluded: &ExcludedEditor<'_>, grant: &CowGrant) -> bool {
        grant.mm_key == excluded.key() && self.release(grant, READY)
    }

    /// Host, while it excludes the MM's EL1 editor, as the MM retires: free
    /// every record it holds, ready or used. The MM's backend inventory
    /// retires their frames with the rest of its mappings.
    pub fn release_mm(&self, excluded: &ExcludedEditor<'_>) -> usize {
        let mm_key = excluded.key();
        let mut released = 0;
        for offset in 0..COW_GRANT_PROBES {
            let slot = Self::probe(mm_key, offset);
            let record = &self.records[slot];
            let word = record.state.load(Ordering::Acquire);
            if record.mm_key.load(Ordering::Relaxed) != mm_key {
                continue;
            }
            let Some(grant) = record.grant(slot, word) else {
                continue;
            };
            if matches!(word & STATE_MASK, READY | USED) && self.release(&grant, word & STATE_MASK)
            {
                released += 1;
            }
        }
        released
    }

    fn release(&self, grant: &CowGrant, from: u64) -> bool {
        let Some(record) = self.records.get(grant.slot) else {
            return false;
        };
        if record.mm_key.load(Ordering::Relaxed) != grant.mm_key {
            return false;
        }
        let freed = record
            .state
            .compare_exchange(
                grant.epoch | from,
                grant.epoch | EMPTY,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        if freed && from == USED {
            self.used[grant.slot / 64].fetch_and(!(1 << (grant.slot % 64)), Ordering::AcqRel);
        }
        freed
    }

    /// Host, while it excludes the MM's EL1 editor: whether EL1 still holds
    /// a claimed grant of the MM. Always `false` under a correct exclusion.
    #[must_use]
    pub fn claimed_by(&self, excluded: &ExcludedEditor<'_>) -> bool {
        let mm_key = excluded.key();
        (0..COW_GRANT_PROBES).any(|offset| {
            let record = &self.records[Self::probe(mm_key, offset)];
            record.state.load(Ordering::Acquire) & STATE_MASK == CLAIMED
                && record.mm_key.load(Ordering::Relaxed) == mm_key
        })
    }
}

/// The host's settlement of guest COW completions, installed by the carrier
/// and run by every host exclusion of an MM's EL1 editor before the host
/// touches that MM's translations or frames.
pub trait CowGrantSettlement: Send + Sync {
    /// Settle every completion of the excluded MM.
    fn settle(&self, excluded: &ExcludedEditor<'_>);
    /// The excluded MM is retiring: free its pool records (its inventory
    /// retires their frames).
    fn release(&self, excluded: &ExcludedEditor<'_>);
}

impl Default for CowGrantPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Offset of [`CowGrantPool`] in the EL1 region: the unused heap window
/// between the inotify name cache and the zone tables.
pub const EL1_COW_GRANT_POOL_OFFSET: u64 =
    crate::EL1_NAME_CACHE_OFFSET + crate::EL1_NAME_CACHE_SIZE;
pub const EL1_COW_GRANT_POOL_BASE: u64 = crate::EL1_REGION_BASE + EL1_COW_GRANT_POOL_OFFSET;

const _: () =
    assert!(EL1_COW_GRANT_POOL_OFFSET.is_multiple_of(core::mem::align_of::<CowGrantPool>() as u64));
const _: () = assert!(
    EL1_COW_GRANT_POOL_OFFSET + core::mem::size_of::<CowGrantPool>() as u64
        <= crate::EL1_ZONE_OFFSET
);
const _: () = assert!(COW_GRANT_POOL_SLOTS.is_power_of_two());
const _: () = assert!(COW_GRANT_PROBES <= COW_GRANT_POOL_SLOTS);

/// Layout facts folded into [`crate::EL1_ABI_LAYOUT_HASH`].
pub const COW_GRANT_LAYOUT_FACTS: [u64; 8] = [
    EL1_COW_GRANT_POOL_OFFSET,
    COW_GRANT_PROTOCOL_VERSION,
    COW_GRANT_POOL_SLOTS as u64,
    COW_GRANT_PROBES as u64,
    COW_GRANT_SIZE,
    core::mem::size_of::<CowGrantRecord>() as u64,
    core::mem::size_of::<CowGrantPool>() as u64,
    core::mem::offset_of!(CowGrantPool, records) as u64,
];

/// Host view of the pool, if an EL1 region is installed.
pub fn cow_grant_pool_host() -> Option<&'static CowGrantPool> {
    let ptr = crate::get_el1_region_host_ptr();
    if ptr == 0 {
        return None;
    }
    // SAFETY: the EL1 region owner keeps this mapping alive until it first
    // clears the region pointer; the pool holds only atomics, all-zero is an
    // empty pool, and the offset preserves its alignment.
    Some(unsafe { &*((ptr + EL1_COW_GRANT_POOL_OFFSET as usize) as *const CowGrantPool) })
}

/// Guest view of the pool. Call only while executing in the installed
/// Carrick EL1 image.
#[cfg(target_os = "none")]
pub fn cow_grant_pool_guest() -> &'static CowGrantPool {
    // SAFETY: EL1_COW_GRANT_POOL_BASE is inside the mapped kernel-only EL1
    // region and the layout is included in EL1_ABI_LAYOUT_HASH.
    unsafe { &*(EL1_COW_GRANT_POOL_BASE as *const CowGrantPool) }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn backing(seed: u64) -> BackingIdentity {
        let nz = |v| NonZeroU64::new(v).unwrap();
        BackingIdentity {
            frame_id: nz(seed),
            mapping_id: nz(seed + 1),
            owner_generation: nz(seed + 2),
            inventory_revision: nz(seed + 3),
        }
    }

    /// No published address space names these test MMs: EL1 cannot edit
    /// them, which is the exclusion the host API demands.
    fn excluded(spaces: &carrick_sched_core::AddressSpaces, mm: u64) -> ExcludedEditor<'_> {
        spaces.unpublished(mm).unwrap()
    }

    fn completion(grant: CowGrant) -> CowGrantCompletion {
        CowGrantCompletion {
            grant,
            span_va: 0x4000_1000,
            span_len: 0x3000,
            old_ipa: 0x9_0000_1000,
            new_ipa: grant.physical_ipa + 0x1000,
        }
    }

    #[test]
    fn a_grant_moves_ready_claimed_used_and_back_to_empty() {
        let spaces = carrick_sched_core::AddressSpaces::new();
        let seven = excluded(&spaces, 7);
        let eight = excluded(&spaces, 8);
        let pool = CowGrantPool::new();
        let published = pool.publish(7, 0x8_0000_4000, backing(10)).unwrap();
        assert_eq!(pool.ready(7).collect::<Vec<_>>(), vec![published]);
        assert!(pool.claim(8).is_none(), "another MM never takes this grant");
        let claimed = pool.claim(7).unwrap();
        assert_eq!(claimed, published);
        assert!(
            pool.claim(7).is_none(),
            "one owner: a claimed grant is gone"
        );
        assert!(pool.claimed_by(&seven));
        assert!(
            !pool.revoke(&seven, &published),
            "the host cannot revoke a claimed grant"
        );
        let done = completion(claimed);
        assert!(pool.complete(&done));
        assert!(!pool.claimed_by(&seven));
        assert!(pool.any_completed());
        assert_eq!(pool.completions(&seven).collect::<Vec<_>>(), vec![done]);
        assert_eq!(pool.completions(&eight).count(), 0);
        assert!(
            !pool.revoke(&seven, &published),
            "a used grant is settled, not revoked"
        );
        assert!(
            !pool.finish(&eight, &published),
            "another MM's exclusion settles nothing"
        );
        assert!(pool.finish(&seven, &published));
        assert!(!pool.finish(&seven, &published), "settled exactly once");
        assert!(!pool.any_completed());
        assert_eq!(pool.resolved(), 1);
    }

    #[test]
    fn an_abandoned_claim_is_ready_again_and_revocable() {
        let spaces = carrick_sched_core::AddressSpaces::new();
        let pool = CowGrantPool::new();
        let grant = pool.publish(7, 0x8_0000_4000, backing(10)).unwrap();
        let claimed = pool.claim(7).unwrap();
        assert!(pool.abandon(&claimed));
        assert!(!pool.abandon(&claimed));
        assert!(pool.revoke(&excluded(&spaces, 7), &grant));
        assert!(pool.claim(7).is_none());
        assert_eq!(pool.ready(7).count(), 0);
    }

    #[test]
    fn a_stale_host_handle_never_settles_or_revokes_a_successor() {
        let spaces = carrick_sched_core::AddressSpaces::new();
        let seven = excluded(&spaces, 7);
        let pool = CowGrantPool::new();
        let first = pool.publish(7, 0x8_0000_4000, backing(10)).unwrap();
        assert!(pool.revoke(&seven, &first));
        let second = pool.publish(7, 0x8_0000_8000, backing(20)).unwrap();
        assert_eq!(second.slot, first.slot, "the chain reuses the freed record");
        assert_ne!(second.epoch, first.epoch);
        assert!(
            !pool.revoke(&seven, &first),
            "the old epoch names no live grant"
        );
        let claimed = pool.claim(7).unwrap();
        assert_eq!(claimed.backing, backing(20));
        assert!(pool.complete(&completion(claimed)));
        assert!(!pool.finish(&seven, &first));
        assert!(pool.finish(&seven, &second));
    }

    #[test]
    fn a_completion_must_describe_one_compound_at_the_old_offset() {
        let pool = CowGrantPool::new();
        pool.publish(7, 0x8_0000_4000, backing(10)).unwrap();
        let claimed = pool.claim(7).unwrap();
        let mut bad = completion(claimed);
        bad.new_ipa = claimed.physical_ipa + 0x2000; // offset differs from old
        assert!(!pool.complete(&bad));
        bad = completion(claimed);
        bad.span_len = 0x4000; // runs past the grant compound
        assert!(!pool.complete(&bad));
        bad = completion(claimed);
        bad.span_len = 0;
        assert!(!pool.complete(&bad));
        assert!(pool.complete(&completion(claimed)));
    }

    #[test]
    fn publication_refuses_bad_grants_and_a_full_chain() {
        let pool = CowGrantPool::new();
        assert!(pool.publish(0, 0x8_0000_4000, backing(1)).is_none());
        assert!(pool.publish(7, 0x8_0000_1000, backing(1)).is_none());
        for index in 0..COW_GRANT_PROBES as u64 {
            assert!(
                pool.publish(7, 0x8_0000_0000 + (index + 1) * COW_GRANT_SIZE, backing(1))
                    .is_some()
            );
        }
        assert!(
            pool.publish(7, 0x9_0000_0000, backing(1)).is_none(),
            "an MM's chain is bounded"
        );
        assert_eq!(pool.ready(7).count(), COW_GRANT_PROBES);
    }

    #[test]
    fn a_retiring_mm_releases_exactly_its_own_records() {
        let spaces = carrick_sched_core::AddressSpaces::new();
        let pool = CowGrantPool::new();
        pool.publish(7, 0x8_0000_4000, backing(10)).unwrap();
        pool.publish(7, 0x8_0000_8000, backing(20)).unwrap();
        pool.publish(8, 0x8_0000_c000, backing(30)).unwrap();
        let used = pool.claim(7).unwrap();
        assert!(pool.complete(&completion(used)));
        assert_eq!(pool.release_mm(&excluded(&spaces, 7)), 2);
        assert_eq!(pool.ready(7).count(), 0);
        assert!(!pool.any_completed());
        assert_eq!(pool.ready(8).count(), 1, "another MM keeps its grants");
    }

    #[test]
    fn pending_completions_are_visible_per_mm_until_settled() {
        let spaces = carrick_sched_core::AddressSpaces::new();
        let pool = CowGrantPool::new();
        pool.publish(7, 0x8_0000_4000, backing(10)).unwrap();
        let claimed = pool.claim(7).unwrap();
        assert!(!pool.has_completions_for(7), "a claim is not a completion");
        assert!(pool.complete(&completion(claimed)));
        assert!(pool.has_completions_for(7));
        assert!(!pool.has_completions_for(8));
        assert!(pool.finish(&excluded(&spaces, 7), &claimed));
        assert!(!pool.has_completions_for(7));
    }

    #[test]
    fn declines_are_counted_by_reason() {
        let pool = CowGrantPool::new();
        pool.note_declined(CowDecline::PoolEmpty);
        pool.note_declined(CowDecline::PoolEmpty);
        pool.note_declined(CowDecline::Unclassified);
        assert_eq!(pool.declined(), [1, 2, 0, 0]);
    }
}
