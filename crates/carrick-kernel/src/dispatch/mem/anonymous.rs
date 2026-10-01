//! The single owner of one MM's anonymous-private memory facts.
//!
//! [`AnonymousAuthority::HostSetup`]: the host sets the MM up (exec loader,
//! pre-publication, a fork child). `MemState` owns the program break, the
//! anonymous arena cursor and free list ([`HostArena`]) and every VMA row.
//!
//! [`AnonymousAuthority::Delegated`]: the MM's shared EL1 reservation root is
//! admitted. It owns the break, arena placement and every private anonymous
//! row inside its heap/arena layout, with its fork/dump/lock attributes;
//! there is no cursor or free list
//! left to consult. `MemState` keeps only host-owned rows (file, shared,
//! attributed, out-of-layout), each mirrored in the root as an opaque node, so
//! the root alone answers placement and `RLIMIT_AS`.
//!
//! A host venue of a delegated MM (always under the MM mutation permit, each
//! root step under the per-MM host queue):
//! - an edit the root can express (anonymous private `mmap`, `munmap` and
//!   `mprotect` of root-owned anonymous memory) is ONE root proposal, held
//!   pending across the unchanged backend work and completed or refused with
//!   the syscall's outcome; the host records no row for it;
//! - `mremap` of root-owned anonymous memory is ONE root `mremap` proposal
//!   the same way, its backend work (copy, zero, retire) done by the host;
//! - `madvise` fork/dump attributes and `mlock` state of root-owned memory
//!   are root node attributes (`set_flags`), never host rows: the range
//!   stays EL1-editable, and every lock reader asks [`MemState::locked_view`];
//! - any other edit first demotes the root-owned anonymous nodes it touches
//!   into host-owned rows (which fences the guest venue out of the range),
//!   runs the host path, and mirrors the resulting host rows as opaque nodes.
//!   Host-placed mappings hold an opaque placeholder until that mirror.
//!
//! `/proc/<pid>/maps` of a delegated MM is the root's anonymous projection
//! merged once with the host rows, which never describe root-owned memory.

use super::el1_reservations::{DelegatedRoot, ForkSeed};
use super::*;
use carrick_el1::memory::reservations::{Decision, Mapping, Placement, Refusal, Reservations};
use carrick_el1_abi::{
    ReservationBackingReceipt, ReservationCompletion, ReservationNodeFlags, ReservationOperation,
    ReservationProtection, ReservationRange, ReservationRequest,
};
use carrick_fatal::carrick_fatal;
use carrick_vfs::ProcMapSharing;
use std::borrow::Cow;

/// The one owner of an MM's anonymous-private facts. See the module docs.
#[derive(Clone)]
pub(in crate::dispatch) enum AnonymousAuthority {
    HostSetup(HostArena),
    /// Constructed only by root admission
    /// (`SyscallDispatcher::admit_el1_reservations`).
    Delegated(DelegatedAnonymous),
}

/// Host-setup anonymous facts. Unreachable once the MM is delegated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::dispatch) struct HostArena {
    /// The byte-precise program break.
    pub(in crate::dispatch) brk: u64,
    /// Bump cursor for the anonymous mmap arena.
    pub(in crate::dispatch) mmap_next: u64,
    /// Freed in-arena anonymous/private ranges available for reuse, kept sorted
    /// by start and coalesced. Reclaiming `munmap`'d space so a churning guest
    /// doesn't exhaust the bump arena. NOT used for MAP_FIXED or shared-file
    /// maps (those have their own lifecycles).
    pub(in crate::dispatch) free_regions: Vec<(u64, u64)>,
    /// A fork child's host-setup twin: the parent root generation its rows
    /// were materialized from. Only that fork's commit may admit its root.
    pub(in crate::dispatch) fork_seed: Option<ForkSeed>,
}

impl HostArena {
    pub(in crate::dispatch) fn new(layout: MemoryLayout) -> Self {
        Self {
            brk: layout.heap_base,
            mmap_next: layout.mmap_base,
            free_regions: Vec::new(),
            fork_seed: None,
        }
    }

    /// Return `[address, address + len)` to the arena: lower the cursor when
    /// it is the high-water, otherwise park it on the free list.
    pub(in crate::dispatch) fn release(&mut self, address: u64, len: u64) {
        if address.checked_add(len) == Some(self.mmap_next) {
            lower_mmap_next(&mut self.mmap_next, &mut self.free_regions, address);
        } else {
            free_regions_insert(&mut self.free_regions, address, len);
        }
    }
}

/// A delegated MM: the exact admitted root, plus the one host-venue step this
/// MM's current host syscall holds open on it.
#[derive(Clone)]
pub(in crate::dispatch) struct DelegatedAnonymous {
    root: DelegatedRoot,
    venue: Option<HostVenue>,
}

impl DelegatedAnonymous {
    pub(in crate::dispatch) fn new(root: DelegatedRoot) -> Self {
        Self { root, venue: None }
    }
}

#[derive(Clone, Copy, Debug)]
enum HostVenue {
    /// A pending root proposal: its range is root-owned, so the host path
    /// records no row for it and the outcome completes or refuses it.
    Proposal(ReservationRequest),
    /// A host-placed mapping's opaque placeholder: settled by mirroring the
    /// host rows of the range, whatever the outcome.
    Reserved(ReservationRange),
}

/// A root refusal where the host already committed backend work, or where
/// the MM permit and the host queue exclude every contender: the root is the
/// only owner, so answering from anything else would be a second authority.
pub(super) fn broken_root(context: &str, refusal: Refusal) -> ! {
    carrick_fatal!(
        "dispatch::anonymous",
        "delegated anonymous root refused {context}: {refusal:?}"
    )
}

fn reservation_range(start: u64, end: u64) -> Result<ReservationRange, Refusal> {
    ReservationRange::new(start, end).ok_or(Refusal::Invalid)
}

fn protection(read: bool, write: bool, execute: bool) -> ReservationProtection {
    let bits = u64::from(read) | (u64::from(write) << 1) | (u64::from(execute) << 2);
    ReservationProtection::from_bits(bits).unwrap_or(ReservationProtection::NONE)
}

fn proc_bits(protection: ReservationProtection) -> (bool, bool, bool) {
    let bits = protection.bits();
    (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0)
}

/// The row a root anonymous node describes.
fn anonymous_row(mapping: &Mapping, layout: MemoryLayout) -> SemanticVma {
    let (read, write, execute) = proc_bits(mapping.protection);
    SemanticVma {
        start: mapping.range.start(),
        end: mapping.range.end(),
        read,
        write,
        execute,
        provenance: VmaBackingProvenance::PrivateAnonymous,
        fork_policy: carrick_abi::VmaForkPolicy {
            copy: if mapping.flags.contains(ReservationNodeFlags::DONTFORK) {
                carrick_abi::VmaForkCopyPolicy::Omit
            } else {
                carrick_abi::VmaForkCopyPolicy::Inherit
            },
            child_contents: if mapping.flags.contains(ReservationNodeFlags::WIPEONFORK) {
                carrick_abi::VmaForkChildPolicy::ZeroInChild
            } else {
                carrick_abi::VmaForkChildPolicy::Preserve
            },
        },
        dump_policy: if mapping.flags.contains(ReservationNodeFlags::DONTDUMP) {
            carrick_abi::VmaDumpPolicy::Omit
        } else {
            carrick_abi::VmaDumpPolicy::Include
        },
        droppable: false,
        path: if in_heap(mapping.range.start(), mapping.range.end(), layout) {
            "[heap]".to_owned()
        } else {
            String::new()
        },
        file_page_offset: None,
    }
}

fn proc_row(vma: &SemanticVma) -> ProcMapsEntry {
    ProcMapsEntry {
        start: vma.start,
        end: vma.end,
        read: vma.read,
        write: vma.write,
        execute: vma.execute,
        sharing: ProcMapSharing::Private,
        path: vma.path.clone(),
    }
}

pub(super) fn in_heap(start: u64, end: u64, layout: MemoryLayout) -> bool {
    layout.heap_base <= start
        && layout
            .heap_base
            .checked_add(layout.heap_size)
            .is_some_and(|heap_end| end <= heap_end)
}

fn in_layout(start: u64, end: u64, layout: MemoryLayout) -> bool {
    in_heap(start, end, layout)
        || (layout.mmap_base <= start
            && layout
                .mmap_base
                .checked_add(layout.mmap_size)
                .is_some_and(|arena_end| end <= arena_end))
}

/// Whether the root owns this host row as an EL1-editable anonymous node:
/// private anonymous memory inside the heap/arena layout (its fork/dump
/// attributes ride the node, see [`carried_flags`]).
pub(in crate::dispatch) fn root_owned_row(vma: &SemanticVma, mem: &MemState) -> bool {
    vma.provenance.is_private_anonymous()
        && !vma.droppable
        && !mem
            .growdown_ranges
            .iter()
            .any(|(low, _, end)| vma.start < *end && *low < vma.end)
        && in_layout(vma.start, vma.end, mem.layout)
}

/// The fork/dump attributes a row's policies name, as root node flags.
pub(in crate::dispatch) fn carried_flags(vma: &SemanticVma) -> ReservationNodeFlags {
    let mut flags = ReservationNodeFlags::EMPTY;
    if vma.fork_policy.copy == carrick_abi::VmaForkCopyPolicy::Omit {
        flags = flags.union(ReservationNodeFlags::DONTFORK);
    }
    if vma.fork_policy.child_contents == carrick_abi::VmaForkChildPolicy::ZeroInChild {
        flags = flags.union(ReservationNodeFlags::WIPEONFORK);
    }
    if vma.dump_policy != carrick_abi::VmaDumpPolicy::Include {
        flags = flags.union(ReservationNodeFlags::DONTDUMP);
    }
    flags
}

fn guest_range(start: u64, end: u64) -> Option<carrick_vfs::GuestMemoryRange> {
    carrick_vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(end))
}

/// `[start, end)` minus the sorted, disjoint `covered` pieces.
fn uncovered_segments(start: u64, end: u64, covered: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut segments = Vec::new();
    let mut cursor = start;
    for &(cover_start, cover_end) in covered {
        if cover_start > cursor {
            segments.push((cursor, cover_start.min(end)));
        }
        cursor = cursor.max(cover_end);
    }
    if cursor < end {
        segments.push((cursor, end));
    }
    segments.retain(|(start, end)| start < end);
    segments
}

/// Insertion-time attributes of a host-owned row: `RLIMIT_DATA` and fork read
/// them from the root.
pub(in crate::dispatch) fn opaque_flags(vma: &SemanticVma, mem: &MemState) -> ReservationNodeFlags {
    let mut flags = ReservationNodeFlags::EMPTY;
    if matches!(
        vma.provenance,
        VmaBackingProvenance::PrivateAnonymous
            | VmaBackingProvenance::PrivateFile
            | VmaBackingProvenance::SpecialKernelSynthetic
    ) {
        flags = flags.union(ReservationNodeFlags::PRIVATE);
    }
    if mem
        .growdown_ranges
        .iter()
        .any(|(low, _, end)| vma.start < *end && *low < vma.end)
    {
        flags = flags.union(ReservationNodeFlags::GROWSDOWN);
    }
    if vma.fork_policy.copy == carrick_abi::VmaForkCopyPolicy::Omit {
        flags = flags.union(ReservationNodeFlags::DONTFORK);
    }
    if vma.fork_policy.child_contents == carrick_abi::VmaForkChildPolicy::ZeroInChild {
        flags = flags.union(ReservationNodeFlags::WIPEONFORK);
    }
    if vma.dump_policy != carrick_abi::VmaDumpPolicy::Include {
        flags = flags.union(ReservationNodeFlags::DONTDUMP);
    }
    flags
}

/// Union of `ranges` minus every committed root node, in bytes.
fn uncovered_bytes(ranges: Vec<(u64, u64)>, model: &mut Reservations<'_>) -> Result<u64, Refusal> {
    let mut total = 0u64;
    for (start, end) in union_of(ranges) {
        // Host rows are page-granular Linux VMAs; a sub-page row cannot be
        // a root node's range either.
        let covered = match ReservationRange::new(start, end) {
            Some(range) => model.charges_within(range).bytes,
            None => 0,
        };
        total = total.saturating_add((end - start).saturating_sub(covered));
    }
    Ok(total)
}

/// The sorted, disjoint union of `ranges`.
fn union_of(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.retain(|(start, end)| start < end);
    ranges.sort_unstable();
    let mut union: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match union.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => union.push((start, end)),
        }
    }
    union
}

/// The charges of every Linux-visible mapping the host projects, to be
/// reduced by what the root holds. Computed before the root guard is taken:
/// the projection itself may read the root.
pub(in crate::dispatch) struct HostCharges {
    address: Vec<(u64, u64)>,
    data: Vec<(u64, u64)>,
}

impl HostCharges {
    fn of(mem: &MemState) -> Self {
        Self {
            address: host_vma_ranges(mem),
            data: host_data_ranges(mem),
        }
    }

    /// The charges of a host-setup MM about to be admitted, under the
    /// delegated policy (the heap is root nodes, never a host template).
    /// The rows the root is about to own are still host rows here; every
    /// one becomes a root node, so [`Self::beyond`] never charges it.
    pub(in crate::dispatch) fn at_admission(mem: &MemState) -> Self {
        Self {
            address: host_vma_summaries(mem, false)
                .iter()
                .map(|vma| (vma.start.raw(), vma.end.raw()))
                .collect(),
            data: host_data_ranges(mem),
        }
    }

    /// Charges outside the root's committed nodes: nothing the root holds
    /// (anonymous or opaque) is charged twice. One range-charge descent per
    /// host row: O(host rows x log root nodes), never a walk of the root.
    pub(in crate::dispatch) fn beyond(
        self,
        model: &mut Reservations<'_>,
    ) -> Result<(u64, u64), Refusal> {
        Ok((
            uncovered_bytes(self.address, model)?,
            uncovered_bytes(self.data, model)?,
        ))
    }
}

impl MemState {
    pub(in crate::dispatch) fn anonymous_authority(&self) -> &AnonymousAuthority {
        &self.anonymous
    }

    /// The host-setup arena; `None` once the root owns placement.
    pub(in crate::dispatch) fn host_arena(&self) -> Option<&HostArena> {
        match &self.anonymous {
            AnonymousAuthority::HostSetup(arena) => Some(arena),
            AnonymousAuthority::Delegated(_) => None,
        }
    }

    pub(in crate::dispatch) fn host_arena_mut(&mut self) -> Option<&mut HostArena> {
        match &mut self.anonymous {
            AnonymousAuthority::HostSetup(arena) => Some(arena),
            AnonymousAuthority::Delegated(_) => None,
        }
    }

    pub(in crate::dispatch) fn delegated_root(&self) -> Option<&DelegatedRoot> {
        match &self.anonymous {
            AnonymousAuthority::HostSetup(_) => None,
            AnonymousAuthority::Delegated(delegated) => Some(&delegated.root),
        }
    }

    /// Hand this host-setup MM's anonymous facts to its just-admitted
    /// `root`, which holds every `owned` range as an anonymous node: their
    /// host rows leave, their residency facts name the root incarnations and
    /// their locks become root attributes. The one tail of every admission.
    pub(in crate::dispatch) fn seal_delegated(
        &mut self,
        root: &DelegatedRoot,
        owned: &[(u64, u64)],
    ) {
        // The root now owns these rows; the host keeps no second copy.
        for &(start, end) in owned {
            self.semantic_vmas.remove_range(start, end);
            trim_dynamic_maps_for_range(&mut self.dynamic_maps, start, end - start);
            // A visible boot region is a host row too (hidden backing rows
            // are carrick's own and never trimmed).
            trim_live_boot_regions_for_range(self, start, end - start);
        }
        self.anonymous = AnonymousAuthority::Delegated(DelegatedAnonymous::new(root.clone()));
        // Host residency facts now describe the incarnations just admitted
        // (a fork child's inherited facts already name them).
        for &(start, end) in owned {
            for piece in self.root_first_touch_pieces(start, end) {
                self.resident
                    .hand_over(piece.range, super::ResidencyOwner::Host, piece.owner());
            }
        }
        // Locks become root attributes (`set_locked` routes each piece to
        // its owner; a fork child's root already carries them).
        for &(start, end) in owned {
            let locked: Vec<_> = self
                .locked_ranges
                .iter()
                .filter_map(|range| {
                    guest_range(range.start().raw().max(start), range.end().raw().min(end))
                })
                .collect();
            for range in locked {
                super::locked_ranges_remove(&mut self.locked_ranges, range);
                self.set_locked(range, true);
            }
        }
    }

    /// Whether this MM's current host syscall holds a venue open on its root.
    pub(in crate::dispatch) fn host_venue_open(&self) -> bool {
        matches!(
            &self.anonymous,
            AnonymousAuthority::Delegated(delegated) if delegated.venue.is_some()
        )
    }

    #[cfg(test)]
    pub(in crate::dispatch) fn arena_for_test(&mut self) -> &mut HostArena {
        self.host_arena_mut()
            .expect("test fixture expects a host-setup arena")
    }

    /// The program break as answered by its single owner. A delegated break
    /// is read from the exact admitted root; this state holds no copy.
    pub(in crate::dispatch) fn program_break(&self) -> u64 {
        match &self.anonymous {
            AnonymousAuthority::HostSetup(arena) => arena.brk,
            AnonymousAuthority::Delegated(delegated) => delegated
                .root
                .with_root(|model| Ok(model.brk_current()))
                .unwrap_or_else(|refusal| broken_root("a program break observation", refusal)),
        }
    }

    /// Every committed root mapping overlapping `[start, end)`.
    fn root_mappings(root: &DelegatedRoot, start: u64, end: u64) -> Vec<Mapping> {
        let mut mappings = Vec::new();
        root.with_root(|model| {
            model.observe_range(reservation_range(start, end)?, &mut |mapping| {
                mappings.push(mapping)
            })
        })
        .unwrap_or_else(|refusal| broken_root("a range observation", refusal));
        mappings
    }

    /// Highest arena address any mapping ever reached: the host-setup cursor,
    /// or the end of the root's highest arena node.
    pub(in crate::dispatch) fn arena_high_water(&self) -> u64 {
        match &self.anonymous {
            AnonymousAuthority::HostSetup(arena) => arena.mmap_next,
            AnonymousAuthority::Delegated(delegated) => {
                let base = self.layout.mmap_base;
                let end = base.saturating_add(self.layout.mmap_size);
                // One descent to the highest node, not a walk of the arena.
                delegated
                    .root
                    .with_root(|model| Ok(model.last_mapping_within(reservation_range(base, end)?)))
                    .unwrap_or_else(|refusal| {
                        broken_root("an arena high-water observation", refusal)
                    })
                    .map_or(base, |mapping| mapping.range.end().min(end))
            }
        }
    }

    /// The root's anonymous rows (none in host setup), in address order.
    pub(in crate::dispatch) fn root_anonymous_rows(&self) -> Vec<SemanticVma> {
        let AnonymousAuthority::Delegated(delegated) = &self.anonymous else {
            return Vec::new();
        };
        let layout = self.layout;
        let mut rows = Vec::new();
        delegated
            .root
            .with_root(|model| {
                model.observe_mappings(&mut |mapping| {
                    if mapping.anonymous {
                        rows.push(anonymous_row(&mapping, layout));
                    }
                })
            })
            .unwrap_or_else(|refusal| broken_root("an anonymous observation", refusal));
        rows
    }

    /// The `/proc/<pid>/maps` region list: boot regions and host rows, and
    /// once delegated the root's anonymous rows merged in exactly once. The
    /// root owns the heap and describes it itself, so the hidden heap backing
    /// row is not rendered beside it; the host rows never describe root-owned
    /// memory (only carrick's hidden backing rows may enclose it).
    pub(in crate::dispatch) fn proc_regions(&self) -> Option<Vec<ProcMapsEntry>> {
        let host = || {
            // The hidden mmap arena, shared aperture and private overlay are
            // carrick's backing reservations, not Linux VMAs: they are `rwx`
            // and span the whole window, so rendering them beside the
            // guest's own rows misreports its protections and adds rows.
            // The heap backing row stays: `[heap]` is clamped to `brk`.
            let mut regions = self.address_space_regions.clone().map(|rows| {
                rows.into_iter()
                    .filter(|row| {
                        !super::boot_region_is_hidden_mmap_backing(row, self.layout)
                            && !super::boot_region_is_hidden_shared_aperture(row)
                            && !super::boot_region_is_hidden_private_overlay(row)
                    })
                    .collect::<Vec<_>>()
            });
            if !self.dynamic_maps.is_empty() {
                regions
                    .get_or_insert_with(Vec::new)
                    .extend(self.dynamic_maps.iter().cloned());
            }
            regions
        };
        if self.delegated_root().is_none() {
            return host();
        }
        let layout = self.layout;
        let mut host_rows: Vec<ProcMapsEntry> = self
            .address_space_regions
            .iter()
            .flatten()
            .filter(|map| !super::boot_region_is_hidden_heap_backing(map, layout))
            .chain(self.dynamic_maps.iter())
            .cloned()
            .collect();
        host_rows.sort_by_key(|row| row.start);
        let root_rows: Vec<ProcMapsEntry> =
            self.root_anonymous_rows().iter().map(proc_row).collect();
        if host_rows.is_empty() && root_rows.is_empty() {
            return host();
        }
        Some(merge_root_rows(host_rows, root_rows, |row| {
            super::boot_region_is_hidden_reservation(row, layout)
        }))
    }

    /// Whether a root-owned anonymous row overlaps `[start, start + len)`.
    pub(in crate::dispatch) fn root_anonymous_overlaps(&self, start: u64, len: u64) -> bool {
        let Some(root) = self.delegated_root() else {
            return false;
        };
        let Some(end) = start.checked_add(len).filter(|end| *end > start) else {
            return false;
        };
        Self::root_mappings(root, start, end)
            .iter()
            .any(|mapping| mapping.anonymous)
    }

    /// Every Linux-visible VMA row of this MM: the host rows, plus the root's
    /// anonymous rows once delegated. Readers that need the whole MM use this,
    /// never `semantic_vmas` alone.
    pub(in crate::dispatch) fn observed_vmas(&self) -> Cow<'_, VmaMap> {
        match &self.anonymous {
            AnonymousAuthority::HostSetup(_) => Cow::Borrowed(&self.semantic_vmas),
            AnonymousAuthority::Delegated(_) => {
                let mut rows = self.semantic_vmas.as_slice().to_vec();
                rows.extend(self.root_anonymous_rows());
                rows.sort_by_key(|vma| vma.start);
                Cow::Owned(VmaMap::from_vec(rows))
            }
        }
    }

    /// Every Linux-visible VMA row overlapping `[start, end)`, in address
    /// order: the host rows there and the root's anonymous rows there. The
    /// cost is the range's own rows, never the whole MM.
    pub(in crate::dispatch) fn observed_vmas_within(
        &self,
        start: u64,
        end: u64,
    ) -> Vec<SemanticVma> {
        let mut rows: Vec<SemanticVma> = self
            .semantic_vmas
            .overlapping(start, end)
            .cloned()
            .collect();
        if let Some(root) = self.delegated_root()
            && start < end
        {
            let layout = self.layout;
            let (page_start, page_end) = (
                start & !(LINUX_PAGE_SIZE - 1),
                align_up_u64(end, LINUX_PAGE_SIZE).unwrap_or(!(LINUX_PAGE_SIZE - 1)),
            );
            for mapping in Self::root_mappings(root, page_start, page_end) {
                if mapping.anonymous {
                    rows.push(anonymous_row(&mapping, layout));
                }
            }
            rows.sort_by_key(|vma| vma.start);
        }
        rows
    }

    /// Delegated MM: the bytes charged to `RLIMIT_AS` and `RLIMIT_DATA`, the
    /// root's own aggregates plus the host rows the root does not hold (the
    /// same charges every root proposal is decided against). `None` in host
    /// setup. O(host rows x log root nodes).
    pub(in crate::dispatch) fn delegated_charges(&self) -> Option<(u64, u64)> {
        let root = self.delegated_root()?;
        let host = HostCharges::of(self);
        Some(
            root.with_root(|model| {
                let charges = model.charges();
                let (address, data) = host.beyond(model)?;
                Ok((
                    charges.bytes.saturating_add(address),
                    charges.data.saturating_add(data),
                ))
            })
            .unwrap_or_else(|refusal| broken_root("a charge observation", refusal)),
        )
    }

    /// Delegated MM: the mapped (root or host) bytes of `[start, end)`.
    /// `None` in host setup.
    pub(in crate::dispatch) fn delegated_mapped_within(&self, start: u64, end: u64) -> Option<u64> {
        let root = self.delegated_root()?;
        let host: Vec<(u64, u64)> = host_vma_ranges(self)
            .into_iter()
            .map(|(row_start, row_end)| (row_start.max(start), row_end.min(end)))
            .collect();
        let range = ReservationRange::new(
            start & !(LINUX_PAGE_SIZE - 1),
            align_up_u64(end, LINUX_PAGE_SIZE)?,
        );
        Some(
            root.with_root(|model| {
                let root_bytes = range.map_or(0, |range| model.charges_within(range).bytes);
                Ok(root_bytes.saturating_add(uncovered_bytes(host, model)?))
            })
            .unwrap_or_else(|refusal| broken_root("a mapped-bytes observation", refusal)),
        )
    }

    /// Delegated MM: whether `[start, end)` is fully mapped (root or host
    /// rows). `None` in host setup.
    pub(in crate::dispatch) fn delegated_covers(&self, start: u64, end: u64) -> Option<bool> {
        let root = self.delegated_root()?;
        let mut rows = host_vma_ranges(self);
        if let (Some(page_end), true) = (align_up_u64(end, LINUX_PAGE_SIZE), start < end) {
            for mapping in Self::root_mappings(root, start & !(LINUX_PAGE_SIZE - 1), page_end) {
                rows.push((mapping.range.start(), mapping.range.end()));
            }
        }
        let mut cursor = start;
        for (row_start, row_end) in union_of(rows) {
            if row_end <= cursor {
                continue;
            }
            if row_start > cursor {
                break;
            }
            cursor = row_end;
            if cursor >= end {
                break;
            }
        }
        Some(cursor >= end)
    }

    /// Every committed root anonymous node overlapping `[start, end)`,
    /// clipped to it.
    fn root_anonymous_pieces(root: &DelegatedRoot, start: u64, end: u64) -> Vec<Mapping> {
        let mut pieces = Self::root_mappings(root, start, end);
        pieces.retain(|mapping| mapping.anonymous);
        for mapping in &mut pieces {
            mapping.range = reservation_range(
                mapping.range.start().max(start),
                mapping.range.end().min(end),
            )
            .unwrap_or_else(|refusal| broken_root("a clipped observation", refusal));
        }
        pieces
    }

    /// Every locked range of this MM: the host's lock table (host-owned
    /// rows only) and, once delegated, the root's `LOCKED` anonymous nodes.
    /// Lock readers (`/proc`, `mlock` accounting, `MADV_DONTNEED`,
    /// `MS_INVALIDATE`) use this, never `locked_ranges` alone.
    pub(in crate::dispatch) fn locked_view(&self) -> Cow<'_, [carrick_vfs::GuestMemoryRange]> {
        let Some(root) = self.delegated_root() else {
            return Cow::Borrowed(&self.locked_ranges);
        };
        let mut ranges = self.locked_ranges.clone();
        root.with_root(|model| {
            model.observe_mappings(&mut |mapping| {
                if mapping.anonymous
                    && mapping.flags.contains(ReservationNodeFlags::LOCKED)
                    && let Some(range) = guest_range(mapping.range.start(), mapping.range.end())
                {
                    super::locked_ranges_insert(&mut ranges, range);
                }
            })
        })
        .unwrap_or_else(|refusal| broken_root("a lock observation", refusal));
        Cow::Owned(ranges)
    }

    /// Bytes this MM holds locked: the host lock table plus the root's
    /// `LOCKED` anonymous nodes (disjoint by construction, see
    /// [`Self::set_locked`]), read from the root's aggregate.
    pub(in crate::dispatch) fn locked_bytes(&self) -> u64 {
        let host = super::locked_ranges_total(&self.locked_ranges);
        let Some(root) = self.delegated_root() else {
            return host;
        };
        let root_locked = root
            .with_root(|model| Ok(model.charges().locked))
            .unwrap_or_else(|refusal| broken_root("a lock charge observation", refusal));
        host.saturating_add(root_locked)
    }

    /// Locked bytes inside `[start, end)`: O(log n) in the root.
    pub(in crate::dispatch) fn locked_bytes_within(&self, start: u64, end: u64) -> u64 {
        let host: u64 = self
            .locked_ranges
            .iter()
            .map(|range| {
                range
                    .end()
                    .raw()
                    .min(end)
                    .saturating_sub(range.start().raw().max(start))
            })
            .sum();
        let Some(root) = self.delegated_root() else {
            return host;
        };
        // Lock ranges are page-granular: round out to whole pages.
        let (Some(page_start), Some(page_end)) = (
            Some(start & !(LINUX_PAGE_SIZE - 1)),
            align_up_u64(end, LINUX_PAGE_SIZE),
        ) else {
            return host;
        };
        let Some(range) = ReservationRange::new(page_start, page_end) else {
            return host;
        };
        let root_locked = root
            .with_root(|model| Ok(model.charges_within(range).locked))
            .unwrap_or_else(|refusal| broken_root("a lock charge observation", refusal));
        host.saturating_add(root_locked)
    }

    /// Set (or clear) `set`/`clear` attributes on the root-owned anonymous
    /// part of `[start, end)`; returns the parts the root does not own, in
    /// address order, for the host to apply to its own rows.
    fn edit_root_attributes(
        &mut self,
        start: u64,
        end: u64,
        set: ReservationNodeFlags,
        clear: ReservationNodeFlags,
    ) -> Vec<(u64, u64)> {
        let Some(root) = self.delegated_root().cloned() else {
            return vec![(start, end)];
        };
        if start >= end {
            return Vec::new();
        }
        let pieces = Self::root_anonymous_pieces(&root, start, end);
        if !pieces.is_empty() {
            root.with_root(|model| {
                for piece in &pieces {
                    model.set_flags(piece.range, set, clear)?;
                }
                Ok(())
            })
            .unwrap_or_else(|refusal| broken_root("an attribute edit", refusal));
        }
        let covered: Vec<_> = pieces
            .iter()
            .map(|piece| (piece.range.start(), piece.range.end()))
            .collect();
        uncovered_segments(start, end, &covered)
    }

    /// `mlock`/`munlock` of `range`: the root's anonymous nodes take the
    /// `LOCKED` attribute, host-owned memory the host lock table.
    pub(in crate::dispatch) fn set_locked(
        &mut self,
        range: carrick_vfs::GuestMemoryRange,
        locked: bool,
    ) {
        let (set, clear) = if locked {
            (ReservationNodeFlags::LOCKED, ReservationNodeFlags::EMPTY)
        } else {
            (ReservationNodeFlags::EMPTY, ReservationNodeFlags::LOCKED)
        };
        for (start, end) in
            self.edit_root_attributes(range.start().raw(), range.end().raw(), set, clear)
        {
            let Some(piece) = guest_range(start, end) else {
                continue;
            };
            if locked {
                super::locked_ranges_insert(&mut self.locked_ranges, piece);
            } else {
                super::locked_ranges_remove(&mut self.locked_ranges, piece);
            }
        }
    }

    /// `munlockall`: every lock of the MM, root and host, is dropped.
    pub(in crate::dispatch) fn unlock_all(&mut self) {
        self.locked_ranges.clear();
        let Some(root) = self.delegated_root().cloned() else {
            return;
        };
        let mut locked = Vec::new();
        root.with_root(|model| {
            model.observe_mappings(&mut |mapping| {
                if mapping.anonymous && mapping.flags.contains(ReservationNodeFlags::LOCKED) {
                    locked.push(mapping.range);
                }
            })?;
            for range in &locked {
                model.set_flags(
                    *range,
                    ReservationNodeFlags::EMPTY,
                    ReservationNodeFlags::LOCKED,
                )?;
            }
            Ok(())
        })
        .unwrap_or_else(|refusal| broken_root("munlockall", refusal));
    }

    /// `madvise` fork/dump attributes over `[start, end)`: root-owned
    /// anonymous memory keeps its node and takes the attribute; host rows
    /// take the policy and are mirrored.
    pub(in crate::dispatch) fn update_policy(
        &mut self,
        start: u64,
        end: u64,
        copy_update: Option<carrick_abi::VmaForkCopyPolicy>,
        child_update: Option<carrick_abi::VmaForkChildPolicy>,
        dump_update: Option<carrick_abi::VmaDumpPolicy>,
    ) {
        let mut set = ReservationNodeFlags::EMPTY;
        let mut clear = ReservationNodeFlags::EMPTY;
        let mut edit = |flag, on: bool| {
            if on {
                set = set.union(flag);
            } else {
                clear = clear.union(flag);
            }
        };
        if let Some(copy) = copy_update {
            edit(
                ReservationNodeFlags::DONTFORK,
                copy == carrick_abi::VmaForkCopyPolicy::Omit,
            );
        }
        if let Some(child) = child_update {
            edit(
                ReservationNodeFlags::WIPEONFORK,
                child == carrick_abi::VmaForkChildPolicy::ZeroInChild,
            );
        }
        if let Some(dump) = dump_update {
            edit(
                ReservationNodeFlags::DONTDUMP,
                dump != carrick_abi::VmaDumpPolicy::Include,
            );
        }
        for (piece_start, piece_end) in self.edit_root_attributes(start, end, set, clear) {
            self.semantic_vmas.update_policy(
                piece_start,
                piece_end,
                copy_update,
                child_update,
                dump_update,
            );
            self.mirror_host_rows(piece_start, piece_end);
        }
    }

    /// Whether this MM's host syscall holds a root proposal for `[start, end)`:
    /// those rows are root-owned and the host records none of them.
    pub(in crate::dispatch) fn venue_owns(&self, start: u64, end: u64) -> bool {
        let AnonymousAuthority::Delegated(delegated) = &self.anonymous else {
            return false;
        };
        let within = |range: ReservationRange| range.start() <= start && end <= range.end();
        matches!(
            delegated.venue,
            Some(HostVenue::Proposal(request))
                if within(request.range) || request.source.is_some_and(within)
        )
    }

    /// Mirror the host rows of `[start, end)` into the root as opaque nodes,
    /// replacing whatever the root held there. No-op in host setup and for a
    /// range the pending host proposal owns.
    pub(in crate::dispatch) fn mirror_host_rows(&mut self, start: u64, end: u64) {
        let AnonymousAuthority::Delegated(delegated) = &self.anonymous else {
            return;
        };
        if start >= end {
            return;
        }
        // A host-placed range keeps its placeholder until the syscall
        // settles, which mirrors the whole range once.
        if let Some(HostVenue::Reserved(reserved)) = delegated.venue
            && reserved.start() <= start
            && end <= reserved.end()
        {
            return;
        }
        if let Some(HostVenue::Proposal(request)) = delegated.venue {
            if self.venue_owns(start, end) {
                return;
            }
            // Busy: the root would refuse the opaque edit beside a pending
            // proposal anyway; say which invariant broke.
            broken_root(
                &format!(
                    "a host row edit {start:#x}..{end:#x} beside its own pending proposal {:#x}..{:#x}",
                    request.range.start(),
                    request.range.end()
                ),
                Refusal::Busy,
            );
        }
        // Root-owned anonymous nodes are not host rows: the mirror replaces
        // only the opaque part of the range.
        let covered: Vec<_> = Self::root_anonymous_pieces(&delegated.root, start, end)
            .iter()
            .map(|piece| (piece.range.start(), piece.range.end()))
            .collect();
        let segments = uncovered_segments(start, end, &covered);
        let mut rows = Vec::new();
        for &(segment_start, segment_end) in &segments {
            for vma in self.semantic_vmas.overlapping(segment_start, segment_end) {
                rows.push((
                    vma.start.max(segment_start),
                    vma.end.min(segment_end),
                    protection(vma.read, vma.write, vma.execute),
                    opaque_flags(vma, self),
                ));
            }
        }
        delegated
            .root
            .with_root(|model| {
                for &(segment_start, segment_end) in &segments {
                    model.retire_opaque(reservation_range(segment_start, segment_end)?)?;
                }
                for (row_start, row_end, prot, flags) in rows {
                    model.insert_opaque(reservation_range(row_start, row_end)?, prot, flags)?;
                }
                Ok(())
            })
            .unwrap_or_else(|refusal| broken_root("a host row mirror", refusal));
    }

    /// Demote the root-owned anonymous nodes overlapping `[start, end)` into
    /// host-owned rows before a host-served edit of the range: the root keeps
    /// them as opaque nodes (the guest venue forwards every edit touching
    /// them) and the host gains their rows. Idempotent; no-op in host setup.
    pub(in crate::dispatch) fn demote_root_rows(&mut self, start: u64, end: u64) {
        let AnonymousAuthority::Delegated(delegated) = &self.anonymous else {
            return;
        };
        if start >= end {
            return;
        }
        let layout = self.layout;
        let root = delegated.root.clone();
        // Captured before the demotion retires their incarnations: the
        // residency facts to hand over name them.
        let pieces = self.root_first_touch_pieces(start, end);
        let mut demoted = Vec::new();
        root.with_root(|model| {
            model.observe_range(reservation_range(start, end)?, &mut |mapping| {
                if mapping.anonymous {
                    demoted.push(mapping);
                }
            })?;
            for mapping in &mut demoted {
                let clipped = reservation_range(
                    mapping.range.start().max(start),
                    mapping.range.end().min(end),
                )?;
                mapping.range = clipped;
                model.retire_opaque(clipped)?;
                // The lock moves to the host lock table below.
                model.insert_opaque(
                    clipped,
                    mapping.protection,
                    mapping.flags.difference(ReservationNodeFlags::LOCKED),
                )?;
            }
            Ok(())
        })
        .unwrap_or_else(|refusal| broken_root("a demotion", refusal));
        for mapping in &demoted {
            let row = anonymous_row(mapping, layout);
            let heap = row.path == "[heap]";
            let entry = proc_row(&row);
            self.semantic_vmas.insert_replacing(row);
            if !heap {
                insert_dynamic_map_coalescing(self, entry);
            }
            if mapping.flags.contains(ReservationNodeFlags::LOCKED)
                && let Some(range) = guest_range(mapping.range.start(), mapping.range.end())
            {
                super::locked_ranges_insert(&mut self.locked_ranges, range);
            }
        }
        for piece in &pieces {
            self.adopt_root_first_touch(piece);
        }
    }

    /// The state a fork child starts from, before its own root is published.
    /// A host-setup parent's child is its clone. A delegated parent's child
    /// is its host-setup twin: the parent root's rows, break and arena
    /// occupancy as host facts (the fork projection is derived from them),
    /// stamped with the parent root generation they came from. The fork
    /// commit then seeds the child's root from exactly that generation
    /// (`El1AdmissionOrigin::ForkCommit`), so the child stays delegated; the
    /// child never names the parent's root.
    pub(in crate::dispatch) fn fork_materialized(&self) -> MemState {
        let mut forked = self.clone();
        // The child's own provenance, before any root fact is handed over.
        forked.deferred_anonymous = std::sync::Arc::new(self.deferred_anonymous.fork_private());
        let AnonymousAuthority::Delegated(delegated) = &self.anonymous else {
            // A twin's clone is no fork twin of its own.
            if let Some(arena) = forked.host_arena_mut() {
                arena.fork_seed = None;
            }
            return forked;
        };
        let layout = self.layout;
        let brk = self.program_break();
        let mut mappings = Vec::new();
        let generation = delegated
            .root
            .with_root(|model| {
                model.observe_mappings(&mut |mapping| mappings.push(mapping))?;
                Ok(model.generation())
            })
            .unwrap_or_else(|refusal| broken_root("a fork observation", refusal));
        let arena_start = layout.mmap_base;
        let arena_end = arena_start.saturating_add(layout.mmap_size);
        let mut mmap_next = arena_start;
        let mut free_regions = Vec::new();
        for mapping in &mappings {
            let (start, end) = (mapping.range.start(), mapping.range.end());
            if mapping.anonymous {
                let row = anonymous_row(mapping, layout);
                let entry = proc_row(&row);
                let heap = row.path == "[heap]";
                forked.semantic_vmas.insert_replacing(row);
                if !heap {
                    insert_dynamic_map_coalescing(&mut forked, entry);
                }
                // The host-setup child keeps locks where a host-setup fork
                // does: in its host lock table (cloned with `MemState`).
                if mapping.flags.contains(ReservationNodeFlags::LOCKED)
                    && let Some(range) = guest_range(start, end)
                {
                    super::locked_ranges_insert(&mut forked.locked_ranges, range);
                }
            }
            if start >= arena_start && end <= arena_end {
                if start > mmap_next {
                    free_regions_insert(&mut free_regions, mmap_next, start - mmap_next);
                }
                mmap_next = mmap_next.max(end);
            }
        }
        // Captured before the twin leaves the root: the residency facts the
        // child inherits name the parent's (and the seeded root's)
        // incarnations; in host setup they answer as host facts.
        let pieces = self.root_first_touch_pieces(arena_start, arena_end);
        forked.anonymous = AnonymousAuthority::HostSetup(HostArena {
            brk,
            mmap_next,
            free_regions,
            fork_seed: Some(ForkSeed {
                parent: delegated.root.mm(),
                generation,
            }),
        });
        for piece in &pieces {
            forked.adopt_root_first_touch(piece);
        }
        forked
    }

    fn take_venue(&mut self) -> Option<(DelegatedRoot, HostVenue)> {
        let AnonymousAuthority::Delegated(delegated) = &mut self.anonymous else {
            return None;
        };
        let venue = delegated.venue.take()?;
        Some((delegated.root.clone(), venue))
    }

    fn open_venue(&mut self, venue: HostVenue) {
        let AnonymousAuthority::Delegated(delegated) = &mut self.anonymous else {
            broken_root("a host venue on a host-setup MM", Refusal::Stale);
        };
        if delegated.venue.is_some() {
            broken_root("a second host venue in one syscall", Refusal::Busy);
        }
        delegated.venue = Some(venue);
    }
}

/// Merge the root's sorted anonymous rows into the sorted host rows in one
/// linear pass. A root row may lie only inside a carrick backing row
/// (`encloses`); overlapping any other host row means two owners describe the
/// same memory, which the root admission forbids.
pub(in crate::dispatch) fn merge_root_rows(
    host: Vec<ProcMapsEntry>,
    root: Vec<ProcMapsEntry>,
    encloses: impl Fn(&ProcMapsEntry) -> bool,
) -> Vec<ProcMapsEntry> {
    let mut merged = Vec::with_capacity(host.len() + root.len());
    let mut host = host.into_iter().peekable();
    let mut owners: Vec<ProcMapsEntry> = Vec::new();
    for row in root {
        while let Some(next) = host.next_if(|next| next.start <= row.start) {
            if !encloses(&next) {
                owners.push(next.clone());
            }
            merged.push(next);
        }
        owners.retain(|owner| owner.end > row.start);
        if let Some(conflict) = owners
            .iter()
            .chain(
                host.peek()
                    .filter(|next| !encloses(next) && next.start < row.end),
            )
            .next()
        {
            carrick_fatal!(
                "dispatch::anonymous",
                "host row {:#x}..{:#x} describes root-owned memory {:#x}..{:#x}",
                conflict.start,
                conflict.end,
                row.start,
                row.end
            );
        }
        merged.push(row);
    }
    merged.extend(host);
    merged
}

/// Host projection rows (no root rows) for `RLIMIT_AS`: a delegated root owns
/// the heap, so its template is not a host charge.
fn host_vma_ranges(mem: &MemState) -> Vec<(u64, u64)> {
    let delegated = mem.delegated_root().is_some();
    host_vma_summaries(mem, !delegated)
        .iter()
        .map(|vma| (vma.start.raw(), vma.end.raw()))
        .collect()
}

/// Host rows charged to `RLIMIT_DATA` (the heap is the root's, or counted by
/// the host-setup break separately).
fn host_data_ranges(mem: &MemState) -> Vec<(u64, u64)> {
    mapped_data_rows(mem)
        .map(|map| (map.start, map.end))
        .collect()
}

/// Commit `request` after its backend work.
pub(in crate::dispatch) fn complete_delegated(
    root: &DelegatedRoot,
    request: ReservationRequest,
) -> Result<u64, DispatchError> {
    // SAFETY: the caller holds this exact MM's mutation permit and the root
    // still holds `request` pending (it excludes every other edit). The
    // backend protection, MemoryProtections publication and, for a retire,
    // the scrub or unmap of the released pages completed before this call.
    // Host-venue anonymous backing is identity or deferred memory: no frame
    // was granted to or returned from the inventory. The pending sequence
    // names this substrate transaction.
    let completion = unsafe {
        ReservationCompletion::after_descriptor_and_backing_commit(
            request,
            ReservationBackingReceipt {
                receipt: request.sequence.raw(),
                granted_bytes: 0,
                returned_bytes: 0,
            },
        )
    }
    .ok_or(DispatchError::ReservationAuthority(Refusal::Invalid))?;
    root.with_root(|model| model.complete(completion))
        .map_err(DispatchError::ReservationAuthority)
}

/// A root proposal held open across a runtime host-alias install. Commit
/// replaces its range with the install's host-owned row; dropping it (the
/// install failed or was abandoned) refuses the proposal, which leaves the
/// root exactly as it was before the syscall: a proposal never changes the
/// committed tree.
pub(crate) struct RootAliasProposal {
    root: DelegatedRoot,
    request: ReservationRequest,
    armed: bool,
}

impl RootAliasProposal {
    fn new(root: DelegatedRoot, request: ReservationRequest) -> Self {
        Self {
            root,
            request,
            armed: true,
        }
    }

    /// The install committed: the root replaces the range with one opaque,
    /// host-owned node (the host rows are mirrored over it), from the
    /// proposal's own spare nodes.
    pub(in crate::dispatch) fn commit_host_owned(mut self) {
        self.armed = false;
        let request = self.request;
        // SAFETY: the runtime installed the host alias backing and its
        // protection for exactly this range under the same MM mutation
        // guard that holds the proposal; no inventory frame was granted to
        // or returned from the root's backing.
        let completion = unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                request,
                ReservationBackingReceipt {
                    receipt: request.sequence.raw(),
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
        };
        let Some(completion) = completion else {
            broken_root("a host-alias completion receipt", Refusal::Invalid)
        };
        self.root
            .with_root(|model| model.complete_host_owned(completion))
            .unwrap_or_else(|refusal| broken_root("a host-alias install commit", refusal));
    }
}

impl Drop for RootAliasProposal {
    fn drop(&mut self) {
        if self.armed {
            // Stale only when the MM (and its root) already retired: there
            // is nothing left to restore.
            let _ = self.root.with_root(|model| model.refuse(self.request));
        }
    }
}

/// A page-granular edit range, or `None` when the syscall's own validation
/// will refuse the arguments.
fn edit_range(address: u64, length: u64, page_size: u64) -> Option<ReservationRange> {
    if length == 0 || !address.is_multiple_of(page_size) {
        return None;
    }
    let end = address.checked_add(align_up_u64(length, page_size)?)?;
    ReservationRange::new(address, end)
}

impl MemView<'_> {
    /// One root step with the host's current limits and the charges of
    /// everything the root does not hold pushed first.
    pub(in crate::dispatch) fn with_charged_root<R>(
        &self,
        mem: &MemState,
        root: &DelegatedRoot,
        step: impl FnOnce(&mut Reservations<'_>) -> Result<R, Refusal>,
    ) -> Result<R, Refusal> {
        // Both limits infinite: no proposal can exceed them, so nothing is
        // charged (and the guest venue sees zero external charges until a
        // finite limit is pushed, which charges again).
        let Some((address_limit, data_limit)) = self.address_space_limits_apply(true) else {
            return root.with_root(|model| {
                model.set_limits(LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY);
                model.set_external_charges(0, 0);
                step(model)
            });
        };
        let host = HostCharges::of(mem);
        root.with_root(|model| {
            model.set_limits(address_limit, data_limit);
            let (address, data) = host.beyond(model)?;
            model.set_external_charges(address, data);
            step(model)
        })
    }

    /// Before a host mapping syscall of a delegated MM does any work: secure
    /// the root nodes its host commits (mirrors, demotions, placeholders)
    /// may net consume after the backend work. `munmap` needs only the
    /// splits at its two ends, so a process can always unmap whole mappings
    /// (and so refill the reserve) at exhaustion; every other mapping
    /// syscall needs the full `HOST_RESERVE` bound. `Some(ENOMEM)` is the
    /// syscall's answer when the node pool is exhausted (the map-count
    /// limit), given before anything changed. No-op in host setup.
    pub(in crate::dispatch) fn secure_host_venue_metadata(
        &self,
        munmap: Option<ReservationRange>,
    ) -> Result<Option<LinuxErrno>, DispatchError> {
        let Some(root) = self.mem().lock().delegated_root().cloned() else {
            return Ok(None);
        };
        let secured = root.with_root(|model| {
            let needed = match munmap {
                Some(range) => model.retire_nodes_needed(range),
                None => carrick_el1::memory::reservations::HOST_RESERVE,
            };
            model.secure_host_nodes(needed)
        });
        match secured {
            Ok(()) => Ok(None),
            Err(Refusal::MetadataRequired) => Ok(Some(LINUX_ENOMEM)),
            Err(refusal) => Err(DispatchError::ReservationAuthority(refusal)),
        }
    }

    /// The `munmap` edit range of `[address, address + length)`, for
    /// [`Self::secure_host_venue_metadata`].
    pub(in crate::dispatch) fn munmap_edit_range(
        &self,
        address: u64,
        length: u64,
    ) -> Option<ReservationRange> {
        edit_range(address, length, self.linux_page_size())
    }

    /// Open a root proposal as this syscall's host venue. `Ok(Err)` is the
    /// root's semantic answer (limit, collision, foreign mapping, hole).
    fn propose(
        &self,
        mem: &mut MemState,
        root: &DelegatedRoot,
        step: impl FnOnce(&mut Reservations<'_>) -> Result<Decision, Refusal>,
    ) -> Result<Result<ReservationRequest, Refusal>, DispatchError> {
        match self.with_charged_root(mem, root, step) {
            Ok(Decision::Work(request)) => {
                mem.open_venue(HostVenue::Proposal(request));
                Ok(Ok(request))
            }
            // mmap/munmap/mprotect proposals always carry work.
            Ok(Decision::Complete(_)) => Err(DispatchError::ReservationAuthority(Refusal::Invalid)),
            Err(
                refusal @ (Refusal::Limit
                | Refusal::Collision
                | Refusal::ForeignMapping
                | Refusal::Hole
                | Refusal::MetadataRequired),
            ) => Ok(Err(refusal)),
            Err(refusal) => Err(DispatchError::ReservationAuthority(refusal)),
        }
    }

    /// Place a host-served mapping of `len` bytes on a delegated MM and hold
    /// it with an opaque placeholder. `None` is the root's ENOMEM.
    fn place_host_served(
        &self,
        mem: &mut MemState,
        root: &DelegatedRoot,
        placement: Placement,
        len: u64,
        congruence: MmapGrantCongruence,
    ) -> Result<Result<u64, Refusal>, DispatchError> {
        let slack = match (placement, congruence) {
            (Placement::Anywhere, MmapGrantCongruence::Residue { modulus, .. }) => {
                modulus.saturating_sub(self.linux_page_size())
            }
            _ => 0,
        };
        let placed = root.with_root(|model| {
            let range = model.place(placement, len.checked_add(slack).ok_or(Refusal::Limit)?)?;
            let start = if slack == 0 {
                range.start()
            } else {
                congruence
                    .first_at_or_after(range.start())
                    .ok_or(Refusal::Limit)?
            };
            let placed = reservation_range(start, start.checked_add(len).ok_or(Refusal::Limit)?)?;
            if placed.end() > range.end() {
                return Err(Refusal::Limit);
            }
            // A fixed placement replaces whatever the root held there; the
            // caller demoted the root-owned part first.
            let holes = super::fault::root_holes(model, placed)?;
            model.retire_opaque(placed)?;
            model.insert_opaque(
                placed,
                ReservationProtection::NONE,
                ReservationNodeFlags::EMPTY,
            )?;
            Ok((placed, holes))
        });
        match placed {
            Ok((placed, holes)) => {
                mem.open_venue(HostVenue::Reserved(placed));
                mem.retire_stale_first_touch(&holes);
                Ok(Ok(placed.start()))
            }
            Err(
                refusal @ (Refusal::Limit
                | Refusal::Collision
                | Refusal::ForeignMapping
                | Refusal::MetadataRequired),
            ) => Ok(Err(refusal)),
            Err(refusal) => Err(DispatchError::ReservationAuthority(refusal)),
        }
    }

    /// Delegated placement for `next_mmap_address`. `root_eligible`: a plain
    /// private anonymous mapping the root itself can own.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::dispatch) fn next_delegated_address(
        &self,
        mem: &mut MemState,
        root: DelegatedRoot,
        requested: u64,
        length: u64,
        prot: u64,
        flags: u64,
        congruence: MmapGrantCongruence,
        root_eligible: bool,
    ) -> Result<Option<(u64, bool)>, DispatchError> {
        let page_size = self.linux_page_size();
        let layout = mem.layout;
        let writable = prot & LINUX_PROT_WRITE != 0;
        let fixed = flags & LINUX_MAP_FIXED != 0;
        if fixed && (requested == 0 || !requested.is_multiple_of(page_size)) {
            return Ok(None);
        }
        let placement = if fixed {
            if flags & LINUX_MAP_FIXED_NOREPLACE != 0 {
                Placement::NoReplace(requested)
            } else {
                Placement::Fixed(requested)
            }
        } else if requested != 0 && requested.is_multiple_of(page_size) {
            Placement::Hint(requested)
        } else {
            Placement::Anywhere
        };
        // Only a WRITABLE hand-out can leave a non-zero byte behind; see
        // `mmap_writable_high`. Placement no longer lowers a cursor, so an
        // address below the watermark may hold a prior mapping's bytes.
        let grant = |mem: &mut MemState, address: u64| {
            let end = address.saturating_add(length);
            let stale = !fixed && address < mem.mmap_writable_high;
            if writable && range_within(address, length, layout.mmap_base, layout.mmap_size) {
                mem.mmap_writable_high = mem.mmap_writable_high.max(end);
            }
            Some((address, stale))
        };
        let reservation_prot = ReservationProtection::from_bits(prot & 7);
        if root_eligible
            && congruence == MmapGrantCongruence::Any
            && let Some(reservation_prot) = reservation_prot
        {
            match self.propose(mem, &root, |model| {
                model.mmap(placement, length, reservation_prot)
            })? {
                Ok(request) => {
                    // What the root held no node for is fresh memory, however
                    // the host last saw it.
                    let holes = root
                        .with_root(|model| super::fault::root_holes(model, request.range))
                        .unwrap_or_else(|refusal| broken_root("a placement observation", refusal));
                    mem.retire_stale_first_touch(&holes);
                    return Ok(grant(mem, request.range.start()));
                }
                // ENOMEM: no room, a MAP_FIXED_NOREPLACE collision, or no
                // root node left to record it (a map-count exhaustion).
                Err(Refusal::Limit | Refusal::Collision | Refusal::MetadataRequired) => {
                    return Ok(None);
                }
                // The root cannot own it (outside the layout, or a fixed
                // range over host-owned nodes): the host serves it.
                Err(_) => {}
            }
        }
        if fixed {
            let Some(end) = requested.checked_add(length) else {
                return Ok(None);
            };
            mem.demote_root_rows(requested, end);
            return match self.place_host_served(mem, &root, placement, length, congruence)? {
                Ok(address) => Ok(grant(mem, address)),
                Err(Refusal::MetadataRequired) => Ok(None),
                // Linux honours MAP_FIXED anywhere in the address space; the
                // host maps it outside the root's layout too.
                Err(_) => Ok(Some((requested, false))),
            };
        }
        if let Placement::Hint(hint) = placement {
            match self.place_host_served(mem, &root, placement, length, congruence)? {
                Ok(address) => return Ok(grant(mem, address)),
                Err(Refusal::MetadataRequired) => return Ok(None),
                Err(Refusal::ForeignMapping) => {
                    // An out-of-layout hint: Linux honours a free hint
                    // anywhere, and the host serves it with an alias VA.
                    let rosetta_start = crate::memory::LINUX_ROSETTA_VA_BASE;
                    let rosetta_end =
                        rosetta_start.saturating_add(crate::memory::LINUX_ROSETTA_WINDOW_SIZE);
                    if mmap_address_uses_alias(hint, length, layout)
                        && !guest_vma_overlaps_locked(mem, hint, length)
                        && !ranges_overlap(hint, length, rosetta_start, rosetta_end)
                    {
                        return Ok(Some((hint, false)));
                    }
                }
                Err(_) => {}
            }
        }
        match self.place_host_served(mem, &root, Placement::Anywhere, length, congruence)? {
            Ok(address) => Ok(grant(mem, address)),
            Err(Refusal::MetadataRequired) => Ok(None),
            // The arena is full: the host's high alias window.
            Err(_) => Ok(find_canonical_high_va_gap(mem, length, congruence)),
        }
    }

    /// Whether `mremap` may grow a mapping in place over `[old_end, new_end)`
    /// of the arena: the host-setup cursor sits at `old_end`, or the delegated
    /// root has nothing there (the tail is then held by a placeholder until the
    /// grown rows are mirrored).
    pub(in crate::dispatch) fn claim_arena_tail(
        &self,
        old_end: u64,
        new_end: u64,
    ) -> Result<bool, DispatchError> {
        let authority = self.mem();
        let mut mem = authority.lock();
        let Some(root) = mem.delegated_root().cloned() else {
            return Ok(mem
                .host_arena()
                .is_some_and(|arena| arena.mmap_next == old_end));
        };
        let Some(len) = new_end.checked_sub(old_end).filter(|len| *len > 0) else {
            return Ok(false);
        };
        Ok(self
            .place_host_served(
                &mut mem,
                &root,
                Placement::NoReplace(old_end),
                len,
                MmapGrantCongruence::Any,
            )?
            .is_ok())
    }

    /// Settle this syscall's host venue with its outcome: complete a proposal
    /// the syscall succeeded for, refuse any other, and mirror a host-placed
    /// range's host rows whatever happened.
    fn settle_host_venue(
        &self,
        outcome: &Result<DispatchOutcome, DispatchError>,
        succeeded: impl FnOnce(&DispatchOutcome, &ReservationRequest) -> bool,
    ) -> Result<(), DispatchError> {
        let authority = self.mem();
        let mut mem = authority.lock();
        let Some((root, venue)) = mem.take_venue() else {
            return Ok(());
        };
        match venue {
            HostVenue::Proposal(request) => {
                if matches!(outcome, Ok(outcome) if succeeded(outcome, &request)) {
                    complete_delegated(&root, request)?;
                    if matches!(
                        request.operation,
                        ReservationOperation::Prepare | ReservationOperation::Move
                    ) {
                        // What this syscall made resident belongs to the
                        // incarnations it just created.
                        mem.adopt_completed_residency(request.range.start(), request.range.end());
                    }
                    return Ok(());
                }
                if request.operation == ReservationOperation::Prepare
                    && let Ok(DispatchOutcome::MapHostAlias { transaction, .. }) = outcome
                {
                    // The runtime installs this mapping after the syscall,
                    // under the same MM mutation guard. The proposal stays
                    // pending until then: the install commits it, a failed
                    // install refuses it, and the root never holds anything
                    // the install did not produce.
                    drop(mem);
                    if transaction.attach_root_proposal(RootAliasProposal::new(root, request)) {
                        return Ok(());
                    }
                    return Err(DispatchError::ReservationAuthority(Refusal::Stale));
                }
                root.with_root(|model| model.refuse(request))
                    .map_err(DispatchError::ReservationAuthority)?;
            }
            HostVenue::Reserved(range) => mem.mirror_host_rows(range.start(), range.end()),
        }
        Ok(())
    }

    /// Before a host `munmap`/`mprotect` of a delegated MM: open the root
    /// proposal that owns the edit, or demote the root rows the host path
    /// will edit. `Some(errno)` is the root's final answer.
    fn fence_host_edit(
        &self,
        range: ReservationRange,
        step: impl FnOnce(&mut Reservations<'_>) -> Result<Decision, Refusal>,
    ) -> Result<Option<LinuxErrno>, DispatchError> {
        let authority = self.mem();
        let mut mem = authority.lock();
        let Some(root) = mem.delegated_root().cloned() else {
            return Ok(None);
        };
        match self.propose(&mut mem, &root, step)? {
            Ok(_) => Ok(None),
            // mprotect(2) ENOMEM: a range with unmapped pages, (RLIMIT_DATA)
            // a private mapping made writable past the limit, or a split
            // past the map count (no root node left to record it).
            Err(Refusal::Hole | Refusal::Limit | Refusal::MetadataRequired) => {
                Ok(Some(LINUX_ENOMEM))
            }
            Err(_) => {
                mem.demote_root_rows(range.start(), range.end());
                Ok(None)
            }
        }
    }

    /// Demote the root rows a host-served edit of `[address, address+length)`
    /// touches (no-op in host setup).
    fn demote_for_host_edit(&self, address: u64, length: u64) {
        if let Some(range) = edit_range(address, length, self.linux_page_size()) {
            self.mem()
                .lock()
                .demote_root_rows(range.start(), range.end());
        }
    }

    pub(in crate::dispatch) fn mmap<M: CurrentMmMemory>(
        &self,
        cx: &mut MutationSyscallCtx<'_, '_, '_, M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let outcome = self.mmap_served(cx);
        self.settle_host_venue(&outcome, |outcome, request| {
            matches!(outcome, DispatchOutcome::Returned { value }
                if *value as u64 == request.range.start())
        })?;
        outcome
    }

    pub(in crate::dispatch) fn munmap<M: CurrentMmMemory>(
        &self,
        cx: &mut MutationSyscallCtx<'_, '_, '_, M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address: GuestPtr = cx.typed_arg(0);
        let length: u64 = cx.typed_arg(1);
        if let Some(range) = edit_range(address.0, length, self.linux_page_size())
            && let Some(errno) = self.fence_host_edit(range, |model| model.munmap(range))?
        {
            return Ok(DispatchOutcome::errno(errno));
        }
        let outcome = self.munmap_served(cx);
        self.settle_host_venue(&outcome, |outcome, _| {
            matches!(outcome, DispatchOutcome::Returned { value: 0 })
        })?;
        outcome
    }

    pub(in crate::dispatch) fn mprotect<M: CurrentMmMemory>(
        &self,
        cx: &mut MutationSyscallCtx<'_, '_, '_, M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address: GuestPtr = cx.typed_arg(0);
        let length: u64 = cx.typed_arg(1);
        let prot: u64 = cx.typed_arg(2);
        if prot & !LinuxProtFlags::SUPPORTED_MASK == 0
            && let Some(range) = edit_range(address.0, length, self.linux_page_size())
        {
            let errno = match ReservationProtection::from_bits(prot) {
                Some(prot) => self.fence_host_edit(range, |model| model.mprotect(range, prot))?,
                // PROT_GROWSDOWN/PROT_GROWSUP: a host-served edit.
                None => {
                    self.demote_for_host_edit(address.0, length);
                    None
                }
            };
            if let Some(errno) = errno {
                return Ok(DispatchOutcome::errno(errno));
            }
        }
        let recorded = crate::mprotect_diag::total();
        let outcome = self.mprotect_served(cx);
        if matches!(&outcome, Ok(DispatchOutcome::Errno { errno }) if *errno == LINUX_ENOMEM)
            && crate::mprotect_diag::total() == recorded
        {
            crate::mprotect_diag::record(
                crate::mprotect_diag::MprotectEnomemSite::Unattributed,
                || None,
            );
        }
        self.settle_host_venue(&outcome, |outcome, _| {
            matches!(outcome, DispatchOutcome::Returned { value: 0 })
        })?;
        outcome
    }

    pub(in crate::dispatch) fn mremap<M: CurrentMmMemory>(
        &self,
        cx: &mut MutationSyscallCtx<'_, '_, '_, M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let old_address: GuestPtr = cx.typed_arg(0);
        let old_size: u64 = cx.typed_arg(1);
        let new_size: u64 = cx.typed_arg(2);
        let flags: u64 = cx.typed_arg(3);
        let new_address: GuestPtr = cx.typed_arg(4);
        let root = self.mem().lock().delegated_root().cloned();
        if let Some(root) = root {
            let request = match super::mmap::mremap_request(
                self.linux_page_size(),
                old_address.0,
                old_size,
                new_size,
                flags,
                new_address.0,
            ) {
                Ok(request) => request,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            if let Some(outcome) = self.mremap_root(cx, &root, request)? {
                return Ok(outcome);
            }
        }
        // Any other source is host-served: demote the source and a fixed
        // destination (no-op in host setup).
        self.demote_for_host_edit(old_address.0, old_size);
        if carrick_abi::LinuxMremapFlags::from_bits_retain(flags)
            .contains(carrick_abi::LinuxMremapFlags::FIXED)
        {
            self.demote_for_host_edit(new_address.0, new_size);
        }
        let outcome = self.mremap_served(cx);
        self.settle_host_venue(&outcome, |_, _| false)?;
        outcome
    }

    /// `mremap` of root-owned anonymous memory as ONE root `mremap`
    /// proposal: the root decides the shape (shrink, in-place growth, move,
    /// `MREMAP_DONTUNMAP`) and the placement, the host does the backend
    /// work, and the outcome completes or refuses the proposal. `None`: the
    /// source is not root-owned anonymous arena memory (host-served).
    fn mremap_root<M: CurrentMmMemory>(
        &self,
        cx: &mut MutationSyscallCtx<'_, '_, '_, M>,
        root: &DelegatedRoot,
        request: super::mmap::MremapRequest,
    ) -> Result<Option<DispatchOutcome>, DispatchError> {
        use carrick_el1::memory::reservations::MoveTarget;
        let super::mmap::MremapRequest {
            old_address,
            old_size,
            new_size,
            new_address,
            may_move,
            move_fixed,
            dontunmap,
        } = request;
        let layout = self.mem().lock().layout;
        let Some(old_end) = old_address.checked_add(old_size).filter(|_| old_size != 0) else {
            return Ok(None);
        };
        if !range_within(old_address, old_size, layout.mmap_base, layout.mmap_size) {
            return Ok(None);
        }
        let mappings = MemState::root_mappings(root, old_address, old_end);
        if !mappings.iter().any(|mapping| mapping.anonymous) {
            return Ok(None);
        }
        // mremap(2) EFAULT: the old range must be one mapping; a hole or
        // two mappings (of any owner or attributes) is refused before any
        // other effect.
        let [node] = mappings.as_slice() else {
            return Ok(Some(DispatchOutcome::errno(LINUX_EFAULT)));
        };
        if node.range.start() > old_address
            || node.range.end() < old_end
            || !node.flags.root_editable()
        {
            return Ok(Some(DispatchOutcome::errno(LINUX_EFAULT)));
        }
        let node = *node;
        if move_fixed {
            let in_layout = new_address
                .checked_add(new_size)
                .is_some_and(|end| in_layout(new_address, end, layout));
            if !in_layout {
                // An out-of-layout destination is a host alias placement.
                return Ok(None);
            }
            if super::overlaps_el0_clock_stub(new_address, new_size) {
                return Ok(Some(DispatchOutcome::errno(LINUX_EPERM)));
            }
        }
        // mremap(2) EAGAIN: expanding a locked mapping past RLIMIT_MEMLOCK.
        let locked = node.flags.contains(ReservationNodeFlags::LOCKED);
        if locked && new_size > old_size && !self.cred_snapshot().euid.is_root() {
            let limit = self.effective_resource_limit(LINUX_RLIMIT_MEMLOCK).rlim_cur;
            let held = self.mem().lock().locked_bytes();
            if held
                .checked_add(new_size - old_size)
                .is_none_or(|total| total > limit)
            {
                return Ok(Some(DispatchOutcome::errno(LINUX_EAGAIN)));
            }
        }
        // MREMAP_FIXED discards whatever the destination held first, like
        // mmap(MAP_FIXED): one munmap of the destination through the same
        // authority as the syscall.
        if move_fixed && self.guest_vma_overlaps(new_address, new_size) {
            let unmapped = with_args(cx, [new_address, new_size, 0, 0, 0, 0], |cx| {
                self.munmap(cx)
            })?;
            if unmapped != (DispatchOutcome::Returned { value: 0 }) {
                return Ok(Some(unmapped));
            }
        }
        let target = match (dontunmap, move_fixed, may_move) {
            (true, true, _) => MoveTarget::KeepSource(Some(new_address)),
            (true, false, _) => MoveTarget::KeepSource(None),
            (false, true, _) => MoveTarget::Fixed(new_address),
            (false, false, true) => MoveTarget::MayMove,
            (false, false, false) => MoveTarget::InPlace,
        };
        let source =
            reservation_range(old_address, old_end).map_err(DispatchError::ReservationAuthority)?;
        let proposed = {
            let authority = self.mem();
            let mut mem = authority.lock();
            match self.with_charged_root(&mem, root, |model| model.mremap(source, new_size, target))
            {
                Ok(Decision::Work(request)) => {
                    mem.open_venue(HostVenue::Proposal(request));
                    if request.operation != ReservationOperation::Retire {
                        // What the root held no node for is fresh memory,
                        // however the host last saw it (as for placement).
                        let holes = root
                            .with_root(|model| super::fault::root_holes(model, request.range))
                            .unwrap_or_else(|refusal| {
                                broken_root("an mremap placement observation", refusal)
                            });
                        mem.retire_stale_first_touch(&holes);
                    }
                    request
                }
                Ok(Decision::Complete(value)) => {
                    return Ok(Some(DispatchOutcome::returned_u64_or_errno(value)));
                }
                // Growth over a limit, nothing in place and no room, or no
                // root node left to record it.
                Err(Refusal::Limit | Refusal::MetadataRequired) => {
                    return Ok(Some(DispatchOutcome::errno(LINUX_ENOMEM)));
                }
                Err(Refusal::Hole) => return Ok(Some(DispatchOutcome::errno(LINUX_EFAULT))),
                Err(Refusal::Invalid) => return Ok(Some(DispatchOutcome::errno(LINUX_EINVAL))),
                // A fixed destination the root cannot own.
                Err(Refusal::ForeignMapping | Refusal::Collision) => return Ok(None),
                Err(refusal) => return Err(DispatchError::ReservationAuthority(refusal)),
            }
        };
        let outcome = match proposed.operation {
            ReservationOperation::Retire => {
                // Shrink: the tail is retired exactly as munmap retires it.
                let tail = proposed.range;
                let outcome = with_args(cx, [tail.start(), tail.len(), 0, 0, 0, 0], |cx| {
                    self.munmap_served(cx)
                });
                self.settle_host_venue(&outcome, |outcome, _| {
                    matches!(outcome, DispatchOutcome::Returned { value: 0 })
                })?;
                return Ok(Some(match outcome? {
                    DispatchOutcome::Returned { value: 0 } => {
                        DispatchOutcome::returned_u64_or_errno(old_address)
                    }
                    other => other,
                }));
            }
            ReservationOperation::Prepare if !dontunmap => {
                self.mremap_root_extend(cx, proposed, old_address, locked)
            }
            _ => self.mremap_root_move(cx, proposed, source, dontunmap, locked),
        };
        self.settle_host_venue(&outcome, |outcome, request| {
            matches!(outcome, DispatchOutcome::Returned { value }
                if *value as u64 == request.range.start()
                    || request.operation == ReservationOperation::Prepare && !dontunmap)
        })?;
        outcome.map(Some)
    }

    /// Publish `[start, start+len)` as fresh private anonymous memory with
    /// `prot`: zeroed first when a prior mapping may have dirtied it.
    fn publish_fresh_anonymous<M: CurrentMmMemory>(
        &self,
        memory: &mut M,
        start: u64,
        len: u64,
        prot: LinuxProtFlags,
        stale: bool,
    ) -> Result<(), LinuxErrno> {
        let length = usize::try_from(len).map_err(|_| LINUX_ENOMEM)?;
        if stale && memory.zero_backing(start, length).is_err() {
            return Err(LINUX_ENOMEM);
        }
        let prot_none = prot.is_empty();
        memory.set_mapping_protection_and_sharing(
            start,
            length,
            prot_none,
            !prot_none && !prot.contains(LinuxProtFlags::WRITE),
            carrick_guest_mem::MappingSharing::Private,
        );
        if memory.protect_range(start, length, prot.bits()).is_err() {
            mark_range_unmapped(memory, start, length);
            return Err(LINUX_ENOMEM);
        }
        let mem_authority = self.mem();
        let mut mem = mem_authority.lock();
        // Monotonic: a later reuse of these bytes is zeroed.
        mem.mmap_writable_high = mem.mmap_writable_high.max(start.saturating_add(len));
        Ok(())
    }

    fn writable_high(&self) -> u64 {
        self.mem().lock().mmap_writable_high
    }

    fn populate_locked<M: CurrentMmMemory>(
        &self,
        memory: &mut M,
        start: u64,
        len: u64,
    ) -> Result<(), LinuxErrno> {
        match guest_range(start, start.saturating_add(len)) {
            Some(range) => self.populate_resident_range(memory, range),
            None => Ok(()),
        }
    }

    /// In-place growth: the root's extension becomes part of the mapping.
    fn mremap_root_extend<M: CurrentMmMemory>(
        &self,
        cx: &mut MutationSyscallCtx<'_, '_, '_, M>,
        proposed: ReservationRequest,
        old_address: u64,
        locked: bool,
    ) -> Result<DispatchOutcome, DispatchError> {
        let permit = cx.mm_mutation.host_alias_permit();
        let mut dispatch = self.begin_conditional_vma_dispatch(&permit);
        let memory = &mut *cx.memory;
        let extension = proposed.range;
        let prot = LinuxProtFlags::from_bits_retain(proposed.protection.bits());
        let stale = extension.start() < self.writable_high();
        if let Err(errno) =
            self.publish_fresh_anonymous(memory, extension.start(), extension.len(), prot, stale)
        {
            return Ok(DispatchOutcome::errno(errno));
        }
        if locked
            && let Err(errno) = self.populate_locked(memory, extension.start(), extension.len())
        {
            return Ok(DispatchOutcome::errno(errno));
        }
        self.mark_vma_dispatch(&mut dispatch);
        Ok(DispatchOutcome::returned_u64_or_errno(old_address))
    }

    /// A relocation: the destination receives the contents; the source is
    /// retired (`Move`) or kept as fresh zero pages (`MREMAP_DONTUNMAP`).
    /// The backend work is the one relocation backend host moves use too.
    fn mremap_root_move<M: CurrentMmMemory>(
        &self,
        cx: &mut MutationSyscallCtx<'_, '_, '_, M>,
        proposed: ReservationRequest,
        source: ReservationRange,
        dontunmap: bool,
        locked: bool,
    ) -> Result<DispatchOutcome, DispatchError> {
        let permit = cx.mm_mutation.host_alias_permit();
        let mut dispatch = self.begin_conditional_vma_dispatch(&permit);
        let memory = &mut *cx.memory;
        let destination = proposed.range;
        let relocation = super::Relocation {
            source: source.start(),
            source_len: source.len(),
            destination: destination.start(),
            destination_len: destination.len(),
            copy_len: source.len().min(destination.len()),
            sharing: carrick_guest_mem::MappingSharing::Private,
            prot: LinuxProtFlags::from_bits_retain(proposed.protection.bits()),
            // Only a writable hand-out below the watermark can hold a prior
            // mapping's bytes (see `mmap_writable_high`).
            scrub_destination: destination.start() < self.writable_high(),
            source_after: if dontunmap {
                super::MoveSource::KeepZeroed
            } else {
                super::MoveSource::Reclaim
            },
        };
        if let Err(errno) = self.relocate_contents(memory, relocation) {
            return Ok(DispatchOutcome::errno(errno));
        }
        {
            let mem_authority = self.mem();
            let mut mem = mem_authority.lock();
            // Monotonic: a later reuse of these bytes is zeroed.
            mem.mmap_writable_high = mem.mmap_writable_high.max(destination.end());
        }
        if !dontunmap {
            self.remove_mapping_metadata(source.start(), source.len());
        }
        if locked
            && let Err(errno) = self.populate_locked(memory, destination.start(), destination.len())
        {
            return Ok(DispatchOutcome::errno(errno));
        }
        self.mark_vma_dispatch(&mut dispatch);
        Ok(DispatchOutcome::returned_u64_or_errno(destination.start()))
    }
}

/// Run `f` with `cx` carrying `args` in place of the syscall's own: mremap
/// composes the munmap its Linux semantics name (a shrunk tail, a
/// `MREMAP_FIXED` destination) through the one munmap authority.
fn with_args<'a, 'm, 'x, M: CurrentMmMemory, R>(
    cx: &mut MutationSyscallCtx<'a, 'm, 'x, M>,
    args: [u64; 6],
    f: impl FnOnce(&mut MutationSyscallCtx<'a, 'm, 'x, M>) -> R,
) -> R {
    let saved = cx.request.args;
    cx.request.args = crate::compat::SyscallArgs(args);
    let result = f(cx);
    cx.request.args = saved;
    result
}

#[cfg(test)]
mod tests {
    use super::union_of;

    #[test]
    fn union_of_merges_overlapping_and_abutting_rows() {
        assert_eq!(union_of(vec![(0, 10)]), [(0, 10)]);
        assert_eq!(union_of(vec![(0, 10), (5, 15)]), [(0, 15)]);
        assert_eq!(
            union_of(vec![(20, 30), (0, 10), (10, 12)]),
            [(0, 12), (20, 30)]
        );
        assert_eq!(union_of(vec![(4, 4), (0, 2)]), [(0, 2)]);
    }
}
