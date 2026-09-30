//! The single owner of one MM's anonymous-private memory facts.
//!
//! [`AnonymousAuthority::HostSetup`]: the host sets the MM up (exec loader,
//! pre-publication, a fork child). `MemState` owns the program break, the
//! anonymous arena cursor and free list ([`HostArena`]) and every VMA row.
//!
//! [`AnonymousAuthority::Delegated`]: the MM's shared EL1 reservation root is
//! admitted. It owns the break, arena placement and every plain private
//! anonymous row inside its heap/arena layout; there is no cursor or free list
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
//! - any other edit first demotes the root-owned anonymous nodes it touches
//!   into host-owned rows (which fences the guest venue out of the range),
//!   runs the host path, and mirrors the resulting host rows as opaque nodes.
//!   Host-placed mappings hold an opaque placeholder until that mirror.

use super::el1_reservations::DelegatedRoot;
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
    /// Constructed only by root admission, which production still refuses
    /// (the conformance fixture seals it).
    #[cfg_attr(not(test), allow(dead_code))]
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
}

impl HostArena {
    pub(in crate::dispatch) fn new(layout: MemoryLayout) -> Self {
        Self {
            brk: layout.heap_base,
            mmap_next: layout.mmap_base,
            free_regions: Vec::new(),
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
    #[cfg_attr(not(test), allow(dead_code))]
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
        fork_policy: carrick_abi::VmaForkPolicy::DEFAULT,
        dump_policy: carrick_abi::VmaDumpPolicy::Include,
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

#[cfg_attr(not(test), allow(dead_code))]
fn in_layout(start: u64, end: u64, layout: MemoryLayout) -> bool {
    in_heap(start, end, layout)
        || (layout.mmap_base <= start
            && layout
                .mmap_base
                .checked_add(layout.mmap_size)
                .is_some_and(|arena_end| end <= arena_end))
}

/// Whether the root owns this host row as an EL1-editable anonymous node:
/// plain private anonymous memory inside the heap/arena layout.
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::dispatch) fn root_owned_row(vma: &SemanticVma, mem: &MemState) -> bool {
    vma.provenance.is_private_anonymous()
        && vma.fork_policy == carrick_abi::VmaForkPolicy::DEFAULT
        && vma.dump_policy == carrick_abi::VmaDumpPolicy::Include
        && !vma.droppable
        && !mem
            .growdown_ranges
            .iter()
            .any(|(low, _, end)| vma.start < *end && *low < vma.end)
        && in_layout(vma.start, vma.end, mem.layout)
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

/// Union of `ranges` minus the union of `covered`, in bytes.
fn uncovered_bytes(mut ranges: Vec<(u64, u64)>, covered: &[(u64, u64)]) -> u64 {
    ranges.retain(|(start, end)| start < end);
    ranges.sort_unstable();
    let mut total = 0u64;
    let mut cover = covered.iter().peekable();
    let mut cursor = 0u64;
    for (start, end) in ranges {
        let mut start = start.max(cursor);
        if start >= end {
            continue;
        }
        cursor = end;
        while start < end {
            // `covered` is the root's committed nodes: sorted and disjoint.
            while cover
                .peek()
                .is_some_and(|(_, cover_end)| *cover_end <= start)
            {
                cover.next();
            }
            match cover.peek() {
                Some(&&(cover_start, cover_end)) if cover_start < end => {
                    total = total.saturating_add(cover_start.saturating_sub(start));
                    start = start.max(cover_end);
                }
                _ => {
                    total = total.saturating_add(end - start);
                    start = end;
                }
            }
        }
    }
    total
}

/// The charges of every Linux-visible mapping the host projects, to be
/// reduced by what the root holds. Computed before the root guard is taken:
/// the projection itself may read the root.
struct HostCharges {
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

    /// Charges outside the root's committed nodes: nothing the root holds
    /// (anonymous or opaque) is charged twice.
    fn beyond(self, model: &mut Reservations<'_>) -> Result<(u64, u64), Refusal> {
        let mut nodes = Vec::new();
        model.observe_mappings(&mut |mapping| {
            nodes.push((mapping.range.start(), mapping.range.end()));
        })?;
        Ok((
            uncovered_bytes(self.address, &nodes),
            uncovered_bytes(self.data, &nodes),
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

    /// Seal the admitted root as the owner (conformance fixture only: the
    /// production admission still refuses).
    #[cfg(test)]
    pub(in crate::dispatch) fn delegate_anonymous(&mut self, root: DelegatedRoot) {
        self.anonymous = AnonymousAuthority::Delegated(DelegatedAnonymous::new(root));
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
                Self::root_mappings(&delegated.root, base, end)
                    .last()
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

    /// The `/proc/<pid>/maps` region list: boot regions and host rows, with a
    /// delegated root's anonymous rows merged in from the same observation.
    pub(in crate::dispatch) fn proc_regions(&self) -> Option<Vec<ProcMapsEntry>> {
        let mut regions = self.address_space_regions.clone();
        if !self.dynamic_maps.is_empty() {
            regions
                .get_or_insert_with(Vec::new)
                .extend(self.dynamic_maps.iter().cloned());
        }
        let root_rows = self.root_anonymous_rows();
        if !root_rows.is_empty() {
            let regions = regions.get_or_insert_with(Vec::new);
            for row in &root_rows {
                trim_proc_maps_for_range(regions, row.start, row.end - row.start);
            }
            regions.extend(root_rows.iter().map(proc_row));
            regions.sort_by_key(|region| region.start);
        }
        regions
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

    /// Whether this MM's host syscall holds a root proposal for `[start, end)`:
    /// those rows are root-owned and the host records none of them.
    pub(in crate::dispatch) fn venue_owns(&self, start: u64, end: u64) -> bool {
        let AnonymousAuthority::Delegated(delegated) = &self.anonymous else {
            return false;
        };
        matches!(
            delegated.venue,
            Some(HostVenue::Proposal(request))
                if request.operation != ReservationOperation::Move
                    && request.range.start() <= start
                    && end <= request.range.end()
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
        let rows: Vec<_> = self
            .semantic_vmas
            .overlapping(start, end)
            .map(|vma| {
                (
                    vma.start.max(start),
                    vma.end.min(end),
                    protection(vma.read, vma.write, vma.execute),
                    opaque_flags(vma, self),
                )
            })
            .collect();
        delegated
            .root
            .with_root(|model| {
                model.retire_opaque(reservation_range(start, end)?)?;
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
                model.insert_opaque(clipped, mapping.protection, ReservationNodeFlags::PRIVATE)?;
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
            self.adopt_root_first_touch(mapping);
        }
    }

    /// The state a fork child starts from: its own MM in host setup. A
    /// delegated parent's root rows, break and arena occupancy become the
    /// child's values; the child never names the parent's root.
    pub(in crate::dispatch) fn fork_materialized(&self) -> MemState {
        let mut forked = self.clone();
        let AnonymousAuthority::Delegated(delegated) = &self.anonymous else {
            return forked;
        };
        let layout = self.layout;
        let brk = self.program_break();
        let mut mappings = Vec::new();
        delegated
            .root
            .with_root(|model| model.observe_mappings(&mut |mapping| mappings.push(mapping)))
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
            }
            if start >= arena_start && end <= arena_end {
                if start > mmap_next {
                    free_regions_insert(&mut free_regions, mmap_next, start - mmap_next);
                }
                mmap_next = mmap_next.max(end);
            }
        }
        forked.anonymous = AnonymousAuthority::HostSetup(HostArena {
            brk,
            mmap_next,
            free_regions,
        });
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
        let (address_limit, data_limit) = self
            .address_space_limits_apply(true)
            .unwrap_or((LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY));
        let host = HostCharges::of(mem);
        root.with_root(|model| {
            model.set_limits(address_limit, data_limit);
            let (address, data) = host.beyond(model)?;
            model.set_external_charges(address, data);
            step(model)
        })
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
                | Refusal::Hole),
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
            Err(refusal @ (Refusal::Limit | Refusal::Collision | Refusal::ForeignMapping)) => {
                Ok(Err(refusal))
            }
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
                Err(Refusal::Limit | Refusal::Collision) => return Ok(None),
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
                // Linux honours MAP_FIXED anywhere in the address space; the
                // host maps it outside the root's layout too.
                Err(_) => Ok(Some((requested, false))),
            };
        }
        if let Placement::Hint(hint) = placement {
            match self.place_host_served(mem, &root, placement, length, congruence)? {
                Ok(address) => return Ok(grant(mem, address)),
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
                    return Ok(());
                }
                root.with_root(|model| model.refuse(request))
                    .map_err(DispatchError::ReservationAuthority)?;
                if request.operation == ReservationOperation::Prepare
                    && matches!(outcome, Ok(DispatchOutcome::MapHostAlias { .. }))
                {
                    // The runtime installs this mapping after the syscall;
                    // its commit mirrors the host rows over this placeholder.
                    root.with_root(|model| {
                        model.insert_opaque(
                            request.range,
                            ReservationProtection::NONE,
                            ReservationNodeFlags::EMPTY,
                        )
                    })
                    .map_err(DispatchError::ReservationAuthority)?;
                }
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
            // mprotect(2) ENOMEM: a range with unmapped pages, or (RLIMIT_DATA)
            // a private mapping made writable past the limit.
            Err(Refusal::Hole | Refusal::Limit) => Ok(Some(LINUX_ENOMEM)),
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
        let outcome = self.mprotect_served(cx);
        self.settle_host_venue(&outcome, |outcome, _| {
            matches!(outcome, DispatchOutcome::Returned { value: 0 })
        })?;
        outcome
    }

    pub(in crate::dispatch) fn mremap<M: CurrentMmMemory>(
        &self,
        cx: &mut MutationSyscallCtx<'_, '_, '_, M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // mremap is host-served on a delegated MM (S1c moves it to the
        // root's `mremap`): demote the source and a fixed destination.
        let old_address: GuestPtr = cx.typed_arg(0);
        let old_size: u64 = cx.typed_arg(1);
        let new_size: u64 = cx.typed_arg(2);
        let flags: u64 = cx.typed_arg(3);
        let new_address: GuestPtr = cx.typed_arg(4);
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
}

#[cfg(test)]
mod tests {
    use super::uncovered_bytes;

    #[test]
    fn uncovered_bytes_subtracts_a_sorted_cover_from_a_union() {
        assert_eq!(uncovered_bytes(vec![(0, 10)], &[]), 10);
        assert_eq!(uncovered_bytes(vec![(0, 10), (5, 15)], &[]), 15);
        assert_eq!(uncovered_bytes(vec![(0, 10)], &[(2, 4), (6, 8)]), 6);
        assert_eq!(uncovered_bytes(vec![(0, 10), (20, 30)], &[(5, 25)]), 10);
        assert_eq!(uncovered_bytes(vec![(20, 30), (0, 10)], &[(0, 30)]), 0);
    }
}
