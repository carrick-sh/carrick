//! Owner-selected fork over live descriptors and the production reservation root.
use super::{El1MmHandle, MmError, MmPortal};
use crate::memory::reservations::{Mapping, Reservations};
#[cfg(target_os = "none")]
use crate::rust_alloc::vec::Vec;
use carrick_el1_abi::{
    PinnedMetadataExtent, PortalForkCompletion, PortalForkCustody, PortalForkRequest,
    ReservationNodeFlags,
};
use carrick_mmu_core::aarch64::descriptor_txn::{JournalEntry, LiveDescriptorWords};
use carrick_mmu_core::aarch64::{
    El1PrivateLeafState, TerminalRule, el1_private_leaf_state, split_terminal_descriptor,
    terminal_rule_edit,
};
use core::num::NonZeroU64;
#[cfg(not(target_os = "none"))]
use std::vec::Vec;

const PA: u64 = 0x0000_ffff_ffff_f000;
const SHIFTS: [u32; 4] = [39, 30, 21, 12];

/// All allocation occurs before borrowing either owner. Unlinked table words
/// and parent undo storage stay owned across physical custody suspension.
pub struct ForkScratch {
    child: Vec<u64>,
    parent: Vec<u64>,
    edits: Vec<JournalEntry>,
    reads: Vec<(u64, u64)>,
    custody: Vec<PortalForkCustody>,
    mappings: Vec<Mapping>,
    child_used: usize,
    parent_used: usize,
}
impl ForkScratch {
    pub fn new(request: PortalForkRequest, metadata_capacity: usize) -> Result<Self, MmError> {
        if !request.valid() {
            return Err(MmError::Invalid);
        }
        let child_len =
            usize::try_from(request.child_tables.len / 8).map_err(|_| MmError::Invalid)?;
        let parent_len =
            usize::try_from(request.parent_tables.len / 8).map_err(|_| MmError::Invalid)?;
        Self::bounded(
            request,
            metadata_capacity,
            child_len,
            parent_len,
            child_len,
            child_len
                .checked_add(metadata_capacity)
                .ok_or(MmError::Invalid)?,
        )
    }
    fn bounded(
        request: PortalForkRequest,
        metadata_capacity: usize,
        child_len: usize,
        parent_len: usize,
        live_words: usize,
        custody_len: usize,
    ) -> Result<Self, MmError> {
        if child_len < 512
            || child_len as u64 * 8 > request.child_tables.len
            || parent_len as u64 * 8 > request.parent_tables.len
        {
            return Err(MmError::NoMemory);
        }
        let mut child = Vec::new();
        let mut parent = Vec::new();
        let mut edits = Vec::new();
        let mut reads = Vec::new();
        let mut custody = Vec::new();
        let mut mappings = Vec::new();
        child
            .try_reserve_exact(child_len)
            .map_err(|_| MmError::NoMemory)?;
        parent
            .try_reserve_exact(parent_len)
            .map_err(|_| MmError::NoMemory)?;
        edits
            .try_reserve_exact(live_words)
            .map_err(|_| MmError::NoMemory)?;
        reads
            .try_reserve_exact(live_words)
            .map_err(|_| MmError::NoMemory)?;
        custody
            .try_reserve_exact(custody_len)
            .map_err(|_| MmError::NoMemory)?;
        mappings
            .try_reserve_exact(metadata_capacity)
            .map_err(|_| MmError::NoMemory)?;
        child.resize(512, 0);
        Ok(Self {
            child,
            parent,
            edits,
            reads,
            custody,
            mappings,
            child_used: 512,
            parent_used: 0,
        })
    }
    #[cfg(test)]
    pub(crate) fn allocation_counts(&self) -> (usize, usize, usize, usize) {
        (
            self.child.capacity(),
            self.parent.capacity(),
            self.reads.capacity(),
            self.custody.capacity(),
        )
    }
    fn allocate_child(&mut self) -> Result<usize, MmError> {
        let offset = self.child_used;
        self.child_used = self
            .child_used
            .checked_add(512)
            .filter(|end| *end <= self.child.capacity())
            .ok_or(MmError::NoMemory)?;
        self.child.resize(self.child_used, 0);
        Ok(offset)
    }
    fn allocate_parent(&mut self) -> Result<usize, MmError> {
        let offset = self.parent_used;
        self.parent_used = self
            .parent_used
            .checked_add(512)
            .filter(|end| *end <= self.parent.capacity())
            .ok_or(MmError::NoMemory)?;
        self.parent.resize(self.parent_used, 0);
        Ok(offset)
    }
    fn custody(&mut self, value: PortalForkCustody) -> Result<(), MmError> {
        if self.custody.len() == self.custody.capacity() {
            return Err(MmError::NoMemory);
        }
        self.custody.push(value);
        Ok(())
    }
}

pub struct PreparedOwnerFork {
    request: PortalForkRequest,
    parent_root: u64,
    scratch: ForkScratch,
}
impl PreparedOwnerFork {
    pub fn custody(&self) -> &[PortalForkCustody] {
        &self.scratch.custody
    }
    pub fn request(&self) -> PortalForkRequest {
        self.request
    }
}

/// An unpublished memory result. Task admission chooses commit or rollback;
/// the child gate is closed throughout, and its exact parent undo remains owned.
pub struct UnpublishedEl1Child {
    completion: PortalForkCompletion,
    parent_root: u64,
    scratch: ForkScratch,
}
impl UnpublishedEl1Child {
    pub fn completion(&self) -> PortalForkCompletion {
        self.completion
    }
    /// Reconcile only an owner-completed private COW replacement. Task birth
    /// rollback retains that private parent page; the host restores copyout
    /// bytes separately. No policy or unrelated live-word change is accepted.
    #[cfg(any(test, target_os = "none"))]
    pub(crate) fn reconcile_parent_write<W: LiveDescriptorWords + ?Sized>(
        &mut self,
        words: &W,
        completion: carrick_el1_abi::CowGrantCompletion,
    ) -> Result<(), MmError> {
        if !completion.is_well_formed()
            || completion.grant.mm_key != self.completion.request.operation.mm.raw()
        {
            return Err(MmError::Stale);
        }
        for va in (completion.span_va..completion.span_va + completion.span_len).step_by(4096) {
            self.reconcile_parent_page(
                words,
                va,
                completion.new_ipa + (va - completion.span_va),
                completion.old_ipa + (va - completion.span_va),
            )?;
        }
        Ok(())
    }
    #[cfg(any(test, target_os = "none"))]
    fn reconcile_parent_page<W: LiveDescriptorWords + ?Sized>(
        &mut self,
        words: &W,
        va: u64,
        new_ipa: u64,
        old_ipa: u64,
    ) -> Result<(), MmError> {
        use carrick_mmu_core::aarch64::{
            El1PrivateLeafState, LeafAccess, el1_private_leaf_state,
            terminal_descriptor_permits_el0,
        };
        let mut table = self.parent_root;
        let mut path = [(0u64, 0u64); 4];
        let mut depth = 0;
        for (level, shift) in SHIFTS.into_iter().enumerate() {
            let pa = table + ((va >> shift) & 511) * 8;
            let live = words.load(pa).map_err(|_| MmError::Core)?;
            path[level] = (pa, live);
            depth = level + 1;
            if level == 3 || live & 3 != 3 {
                break;
            }
            table = live & PA;
        }
        let terminal = path[depth - 1].1;
        let owned = terminal & PA == new_ipa
            && depth == 4
            && el1_private_leaf_state(terminal) == El1PrivateLeafState::Resident
            && terminal_descriptor_permits_el0(terminal, LeafAccess::Write);
        for (level, (pa, live)) in path[..depth].iter().copied().enumerate() {
            if let Some(entry) = self.scratch.edits.iter_mut().find(|entry| entry.pa == pa) {
                if live != entry.after {
                    if level != 3 || !owned || entry.after & PA != old_ipa {
                        return Err(MmError::Stale);
                    }
                    entry.after = live;
                    entry.before = live;
                    entry.bbm_len = 0;
                } else if owned && level < 3 && entry.after & 3 == 3 && entry.before & 3 != 3 {
                    entry.before = entry.after;
                    entry.bbm_len = 0;
                }
            }
        }
        Ok(())
    }
    pub fn commit<P: PinnedMetadataExtent>(
        &mut self,
        portal: &MmPortal<'_, P>,
        worker: u32,
    ) -> Result<PortalForkCompletion, MmError> {
        let request = self.completion.request;
        let mut parent = portal.root(request.operation.mm, worker)?;
        let mut child = portal.child_root(request.child_mm, worker)?;
        if parent.incarnation().raw() != request.operation.incarnation.get()
            || parent.generation() != self.completion.parent_generation
            || !child.authenticate_fork_origin(request)
            || !parent.fork_write_authorized(Some(request.operation.sequence))
            || !child.fork_write_authorized(Some(request.operation.sequence))
        {
            return Err(MmError::Stale);
        }
        parent.finish_fork_publication(request.operation)?;
        child.finish_fork_publication(request.operation)?;
        Ok(self.completion)
    }
    pub fn abort<P: PinnedMetadataExtent, W: LiveDescriptorWords + ?Sized>(
        &mut self,
        portal: &MmPortal<'_, P>,
        words: &W,
        worker: u32,
    ) -> Result<(), MmError> {
        let parent = self.completion.request.operation.mm;
        let child = self.completion.child.mm();
        let owner = NonZeroU64::new(u64::from(worker) + 1).ok_or(MmError::Invalid)?;
        let parent_index = portal.spaces.find(parent.raw()).ok_or(MmError::Stale)?;
        let _parent_editor = portal
            .space_access(worker)?
            .try_begin_edit(parent_index, parent.raw(), owner)
            .ok_or(MmError::Busy)?;
        let child_index = portal.spaces.find(child.raw()).ok_or(MmError::Stale)?;
        let _child_editor = portal
            .space_access(worker)?
            .try_begin_closed_child_edit(child_index, child.raw(), owner)
            .ok_or(MmError::Busy)?;
        let mut root = portal.root(parent, worker)?;
        if root.incarnation().raw() != self.completion.request.operation.incarnation.get()
            || root.generation() != self.completion.parent_generation
        {
            return Err(MmError::Stale);
        }
        let mut child_root = portal.child_root(child, worker)?;
        if !root.fork_write_authorized(Some(self.completion.request.operation.sequence))
            || !child_root.fork_write_authorized(Some(self.completion.request.operation.sequence))
            || !child_root.authenticate_fork_origin(self.completion.request)
        {
            return Err(MmError::Stale);
        }
        rollback(words, &self.scratch.edits)?;
        words.publish_barrier();
        words.invalidate_range(0, 1 << 48);
        root.finish_fork_publication(self.completion.request.operation)?;
        self.completion.parent_generation = root.commit_fork_generation()?;
        if !self.scratch.edits.iter().any(|edit| {
            edit.before & 3 == 3
                && self
                    .completion
                    .request
                    .parent_tables
                    .contains(edit.before & PA)
        }) {
            self.completion.parent_tables_used = 0;
        }
        self.completion.child_tables_used = 0;
        drop(root);
        child_root.finish_fork_publication(self.completion.request.operation)?;
        child_root.retire()?;
        // The child's words are unreachable. Physical table/grant custody is
        // returned by the exact operation's host settlement after this receipt.
        let _ = self.parent_root;
        Ok(())
    }
}

impl<P: PinnedMetadataExtent> MmPortal<'_, P> {
    pub fn fork_mapping_count(
        &self,
        mm: carrick_el1_abi::ReservationMm,
        worker: u32,
    ) -> Result<usize, MmError> {
        let mut root = self.root(mm, worker)?;
        let mut count = 0usize;
        root.observe_mappings(&mut |_| count += 1)?;
        Ok(count)
    }
    fn child_root(
        &self,
        mm: carrick_el1_abi::ReservationMm,
        worker: u32,
    ) -> Result<Reservations<'_>, MmError> {
        self.root_any(mm, worker)
    }

    /// First census the reachable graph with fixed recursion and a bounded
    /// temporary owner reservation observation. Allocate undo/table storage
    /// only after releasing editors and metadata, proportional to actual work.
    pub fn census_fork<W: LiveDescriptorWords + ?Sized>(
        &self,
        request: PortalForkRequest,
        words: &W,
        worker: u32,
    ) -> Result<ForkScratch, MmError> {
        let capacity = self.fork_mapping_count(request.operation.mm, worker)?;
        let mut mappings = Vec::new();
        mappings
            .try_reserve_exact(capacity)
            .map_err(|_| MmError::NoMemory)?;
        let owner = NonZeroU64::new(u64::from(worker) + 1).ok_or(MmError::Invalid)?;
        let index = self
            .spaces
            .find(request.operation.mm.raw())
            .ok_or(MmError::Stale)?;
        let editor = self
            .space_access(worker)?
            .try_begin_edit(index, request.operation.mm.raw(), owner)
            .ok_or(MmError::Busy)?;
        let grant = self
            .spaces
            .grant(index, request.operation.mm.raw())
            .ok_or(MmError::Busy)?;
        let mut root = self.root(request.operation.mm, worker)?;
        if root.generation() != request.parent_generation
            || root.incarnation().raw() != request.operation.incarnation.get()
            || root.operation_sequence() != request.operation.sequence.get()
        {
            return Err(MmError::Stale);
        }
        if !root.fork_ready() {
            return Err(MmError::Busy);
        }
        let mut full = false;
        root.observe_mappings(&mut |mapping| {
            if mappings.len() == mappings.capacity() {
                full = true;
            } else {
                mappings.push(mapping);
            }
        })?;
        if full {
            return Err(MmError::NoMemory);
        }
        drop(root);
        let mut count = ForkCensus {
            child: 0,
            parent: 0,
            live: 0,
            custody: mappings
                .iter()
                .filter(|m| {
                    m.host_backing.is_some()
                        && !m.flags.intersects(
                            ReservationNodeFlags::DONTFORK.union(ReservationNodeFlags::WIPEONFORK),
                        )
                })
                .count(),
        };
        census_table(words, &mappings, grant.ttbr0 & PA, 0, 0, &mut count)?;
        drop(editor);
        ForkScratch::bounded(
            request,
            mappings.len(),
            count.child,
            count.parent,
            count.live,
            count.custody,
        )
    }
    pub fn prepare_fork<W: LiveDescriptorWords + ?Sized>(
        &self,
        request: PortalForkRequest,
        mut scratch: ForkScratch,
        words: &W,
        worker: u32,
    ) -> Result<PreparedOwnerFork, MmError> {
        if !request.valid() || request.operation.carrier != self.carrier {
            return Err(MmError::Invalid);
        }
        let owner = NonZeroU64::new(u64::from(worker) + 1).ok_or(MmError::Invalid)?;
        let index = self
            .spaces
            .find(request.operation.mm.raw())
            .ok_or(MmError::Stale)?;
        let editor = self
            .space_access(worker)?
            .try_begin_edit(index, request.operation.mm.raw(), owner)
            .ok_or(MmError::Busy)?;
        let grant = self
            .spaces
            .grant(index, request.operation.mm.raw())
            .ok_or(MmError::Busy)?;
        let child_index = self
            .spaces
            .find(request.child_mm.raw())
            .ok_or(MmError::Stale)?;
        let child_editor = self
            .space_access(worker)?
            .try_begin_closed_child_edit(child_index, request.child_mm.raw(), owner)
            .ok_or(MmError::Busy)?;
        if child_editor.grant().ttbr0 & PA != request.child_tables.base {
            return Err(MmError::Stale);
        }
        let mut root = self.root(request.operation.mm, worker)?;
        if root.incarnation().raw() != request.operation.incarnation.get()
            || root.generation() != request.parent_generation
            || root.operation_sequence() != request.operation.sequence.get()
        {
            return Err(MmError::Stale);
        }
        if !root.fork_ready() {
            return Err(MmError::Busy);
        }
        let child = self.child_root(request.child_mm, worker)?;
        if child.is_admitted() {
            return Err(MmError::Stale);
        }
        drop(child);
        let mut capacity_refused = false;
        root.observe_mappings(&mut |mapping| {
            if scratch.mappings.len() == scratch.mappings.capacity() {
                capacity_refused = true;
                return;
            }
            scratch.mappings.push(mapping);
            if !mapping
                .flags
                .intersects(ReservationNodeFlags::DONTFORK.union(ReservationNodeFlags::WIPEONFORK))
                && let Some(source) = mapping.host_backing
            {
                if scratch.custody.len() == scratch.custody.capacity() {
                    capacity_refused = true;
                    return;
                }
                scratch.custody.push(PortalForkCustody::HostBacking {
                    handle: source.handle(),
                    generation: source.generation(),
                });
            }
        })?;
        if capacity_refused {
            return Err(MmError::NoMemory);
        }
        let parent_root = grant.ttbr0 & PA;
        copy_table(words, request, &mut scratch, parent_root, 0, 0, 0)?;
        if scratch.reads.iter().any(|(pa, _)| {
            request.child_tables.contains(*pa) || request.parent_tables.contains(*pa)
        }) {
            return Err(MmError::Stale);
        }
        drop(root);
        drop(child_editor);
        drop(editor);
        Ok(PreparedOwnerFork {
            request,
            parent_root,
            scratch,
        })
    }
    /// Physical custody is acquired from `plan.custody()` with no owner lock.
    /// After that effect, this phase revalidates every live parent word before
    /// linking any new table, then clones only the owner's reservation tree.
    pub fn publish_fork<W: LiveDescriptorWords + ?Sized>(
        &self,
        plan: PreparedOwnerFork,
        words: &W,
        worker: u32,
    ) -> Result<UnpublishedEl1Child, MmError> {
        let request = plan.request;
        let owner = NonZeroU64::new(u64::from(worker) + 1).ok_or(MmError::Invalid)?;
        let index = self
            .spaces
            .find(request.operation.mm.raw())
            .ok_or(MmError::Stale)?;
        let editor = self
            .space_access(worker)?
            .try_begin_edit(index, request.operation.mm.raw(), owner)
            .ok_or(MmError::Busy)?;
        let child_index = self
            .spaces
            .find(request.child_mm.raw())
            .ok_or(MmError::Stale)?;
        let child_editor = self
            .space_access(worker)?
            .try_begin_closed_child_edit(child_index, request.child_mm.raw(), owner)
            .ok_or(MmError::Busy)?;
        if child_editor.grant().ttbr0 & PA != request.child_tables.base {
            return Err(MmError::Stale);
        }
        let mut root = self.root(request.operation.mm, worker)?;
        if root.incarnation().raw() != request.operation.incarnation.get()
            || root.generation() != request.parent_generation
            || root.operation_sequence() != request.operation.sequence.get()
        {
            return Err(MmError::Stale);
        }
        if !root.fork_ready() {
            return Err(MmError::Busy);
        }
        let mut child = self.child_root(request.child_mm, worker)?;
        if child.is_admitted() {
            return Err(MmError::Stale);
        }
        let child_incarnation = NonZeroU64::new(child.incarnation().raw()).ok_or(MmError::Stale)?;
        for (pa, before) in &plan.scratch.reads {
            if words.load(*pa).map_err(|_| MmError::Core)? != *before {
                return Err(MmError::Stale);
            }
        }
        if request.parent_generation.raw() >= u64::MAX - 1 {
            return Err(MmError::Stale);
        }
        root.reserve_fork_certificate(request)?;
        for (index, word) in plan.scratch.child[..plan.scratch.child_used]
            .iter()
            .enumerate()
        {
            words
                .store_unlinked(request.child_tables.base + index as u64 * 8, *word)
                .map_err(|_| MmError::Core)?;
        }
        for (index, word) in plan.scratch.parent[..plan.scratch.parent_used]
            .iter()
            .enumerate()
        {
            words
                .store_unlinked(request.parent_tables.base + index as u64 * 8, *word)
                .map_err(|_| MmError::Core)?;
        }
        words.publish_barrier();
        for (applied, edit) in plan.scratch.edits.iter().enumerate() {
            let changed = if edit.bbm_len != 0 {
                match words.compare_exchange(edit.pa, edit.before, 0) {
                    Ok(true) => {
                        words.publish_barrier();
                        words.invalidate_range(edit.bbm_va, edit.bbm_len);
                        match words.compare_exchange(edit.pa, 0, edit.after) {
                            Ok(true) => Ok(()),
                            result => {
                                if !words
                                    .compare_exchange(edit.pa, 0, edit.before)
                                    .map_err(|_| MmError::Core)?
                                {
                                    return Err(MmError::Core);
                                }
                                words.publish_barrier();
                                words.invalidate_range(edit.bbm_va, edit.bbm_len);
                                Err(if result.is_err() {
                                    MmError::Core
                                } else {
                                    MmError::Stale
                                })
                            }
                        }
                    }
                    Ok(false) => Err(MmError::Stale),
                    Err(_) => Err(MmError::Core),
                }
            } else {
                match words.compare_exchange(edit.pa, edit.before, edit.after) {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(MmError::Stale),
                    Err(_) => Err(MmError::Core),
                }
            };
            if let Err(error) = changed {
                rollback(words, &plan.scratch.edits[..applied])?;
                return Err(error);
            }
        }
        if let Err(error) = child.set_fork_origin(request) {
            rollback(words, &plan.scratch.edits)?;
            return Err(error.into());
        }
        if let Err(error) = root.clone_into(&mut child) {
            child.clear_fork_origin();
            rollback(words, &plan.scratch.edits)?;
            return Err(error.into());
        }
        // Root/editor exclusion proves these metadata transitions cannot
        // change between preflight and this publication. Advance only once.
        let parent_generation = root.publish_fork_parent(request);
        child.publish_fork_child(request);
        let child_handle = unsafe {
            El1MmHandle::from_admitted_owner(self.carrier, request.child_mm, child_incarnation)
        };
        child_editor.set_mmap_next(editor.mmap_next());
        child_editor.set_brk_current(root.layout().brk);
        words.publish_barrier();
        words.invalidate_range(0, 1 << 48);
        Ok(UnpublishedEl1Child {
            completion: PortalForkCompletion {
                request,
                child: child_handle,
                parent_generation,
                child_tables_used: plan.scratch.child_used as u64 * 8,
                parent_tables_used: plan.scratch.parent_used as u64 * 8,
            },
            parent_root: plan.parent_root,
            scratch: plan.scratch,
        })
    }
}

fn rollback<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    edits: &[JournalEntry],
) -> Result<(), MmError> {
    for edit in edits.iter().rev() {
        if edit.bbm_len != 0 {
            if !words
                .compare_exchange(edit.pa, edit.after, 0)
                .map_err(|_| MmError::Core)?
            {
                return Err(MmError::Core);
            }
            words.publish_barrier();
            words.invalidate_range(edit.bbm_va, edit.bbm_len);
            if !words
                .compare_exchange(edit.pa, 0, edit.before)
                .map_err(|_| MmError::Core)?
            {
                return Err(MmError::Core);
            }
        } else if !words
            .compare_exchange(edit.pa, edit.after, edit.before)
            .map_err(|_| MmError::Core)?
        {
            return Err(MmError::Core);
        }
    }
    words.publish_barrier();
    words.invalidate_range(0, 1 << 48);
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Policy {
    Keep,
    Private,
    Omit,
    Wipe,
    Mixed,
}
fn policy(mappings: &[Mapping], base: u64, span: u64, descriptor: u64) -> Result<Policy, MmError> {
    let end = base.checked_add(span).ok_or(MmError::Invalid)?;
    let start_index = mappings.partition_point(|mapping| mapping.range.end() <= base);
    let mut result = None;
    let mut cursor = base;
    let mut mixed = false;
    for mapping in &mappings[start_index..] {
        if mapping.range.start() >= end {
            break;
        }
        let start = mapping.range.start().max(base);
        let mapping_end = mapping.range.end().min(end);
        if start > cursor {
            mixed = true;
        }
        let value = if mapping.flags.contains(ReservationNodeFlags::DONTFORK) {
            Policy::Omit
        } else if mapping.flags.contains(ReservationNodeFlags::WIPEONFORK) {
            Policy::Wipe
        } else if mapping.flags.contains(ReservationNodeFlags::PRIVATE) {
            Policy::Private
        } else {
            Policy::Keep
        };
        if result.is_some_and(|prior| prior != value) {
            mixed = true;
        }
        result = Some(value);
        cursor = mapping_end;
    }
    if let Some(result) = result {
        Ok(if mixed || cursor < end {
            Policy::Mixed
        } else {
            result
        })
    } else {
        Ok(if descriptor & (1 << 6) == 0 {
            Policy::Keep
        } else {
            Policy::Omit
        })
    }
}

struct ForkCensus {
    child: usize,
    parent: usize,
    live: usize,
    custody: usize,
}
fn census_table<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    mappings: &[Mapping],
    table: u64,
    level: usize,
    base: u64,
    count: &mut ForkCensus,
) -> Result<(), MmError> {
    count.child = count.child.checked_add(512).ok_or(MmError::NoMemory)?;
    count.live = count.live.checked_add(512).ok_or(MmError::NoMemory)?;
    for index in 0..512 {
        census_entry(
            words,
            mappings,
            words.load(table + index * 8).map_err(|_| MmError::Core)?,
            level,
            base + (index << SHIFTS[level]),
            count,
        )?;
    }
    Ok(())
}
fn census_entry<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    mappings: &[Mapping],
    descriptor: u64,
    level: usize,
    va: u64,
    count: &mut ForkCensus,
) -> Result<(), MmError> {
    if descriptor == 0 {
        return Ok(());
    }
    if level < 3 && descriptor & 3 == 3 {
        return census_table(words, mappings, descriptor & PA, level + 1, va, count);
    }
    if level == 0 {
        return Err(MmError::Core);
    }
    if descriptor & 1 == 0 && el1_private_leaf_state(descriptor) == El1PrivateLeafState::Unowned {
        return Ok(());
    }
    let span = 1u64 << SHIFTS[level];
    const CONTROL: u64 = carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE - 0x2_0000;
    let structural = va < CONTROL + 0x20_0000 && va + span > CONTROL;
    let selected = policy(mappings, va, span, descriptor)?;
    if (structural || selected == Policy::Mixed) && level < 3 {
        count.child = count.child.checked_add(512).ok_or(MmError::NoMemory)?;
        if !structural {
            count.parent = count.parent.checked_add(512).ok_or(MmError::NoMemory)?;
        }
        for index in 0..512 {
            census_entry(
                words,
                mappings,
                split_terminal_descriptor(descriptor, level, index)?,
                level + 1,
                va + ((index as u64) << SHIFTS[level + 1]),
                count,
            )?;
        }
    } else if structural {
        let alias = carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE;
        if !(alias..alias + carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE).contains(&va)
            && descriptor & PA != 0
        {
            count.custody = count.custody.checked_add(1).ok_or(MmError::NoMemory)?;
        }
    } else if (selected == Policy::Private
        || (selected == Policy::Keep && descriptor & (1 << 6) != 0))
        && el1_private_leaf_state(descriptor) != El1PrivateLeafState::Retired
        && descriptor & (PA & !(span - 1)) != 0
    {
        count.custody = count.custody.checked_add(1).ok_or(MmError::NoMemory)?;
    }
    Ok(())
}

fn copy_table<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    request: PortalForkRequest,
    scratch: &mut ForkScratch,
    table: u64,
    level: usize,
    base: u64,
    child_offset: usize,
) -> Result<(), MmError> {
    for index in 0..512 {
        let address = table + index as u64 * 8;
        let descriptor = words.load(address).map_err(|_| MmError::Core)?;
        if scratch.reads.len() == scratch.reads.capacity() {
            return Err(MmError::NoMemory);
        }
        scratch.reads.push((address, descriptor));
        let va = base + ((index as u64) << SHIFTS[level]);
        let (parent, child) = copy_entry(words, request, scratch, descriptor, level, va)?;
        scratch.child[child_offset + index] = child;
        if parent != descriptor {
            if scratch.edits.len() == scratch.edits.capacity() {
                return Err(MmError::NoMemory);
            }
            scratch.edits.push(JournalEntry {
                pa: address,
                before: descriptor,
                after: parent,
                bbm_va: va,
                bbm_len: if descriptor & 1 != 0 && parent & 3 == 3 && level < 3 {
                    1 << SHIFTS[level]
                } else {
                    0
                },
            });
        }
    }
    Ok(())
}
fn copy_entry<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    request: PortalForkRequest,
    scratch: &mut ForkScratch,
    descriptor: u64,
    level: usize,
    va: u64,
) -> Result<(u64, u64), MmError> {
    if descriptor == 0 {
        return Ok((0, 0));
    }
    if level < 3 && descriptor & 3 == 3 {
        let child = scratch.allocate_child()?;
        copy_table(
            words,
            request,
            scratch,
            descriptor & PA,
            level + 1,
            va,
            child,
        )?;
        return Ok((
            descriptor,
            (request.child_tables.base + child as u64 * 8) | 3,
        ));
    }
    if level == 0 {
        return Err(MmError::Core);
    }
    if descriptor & 1 == 0 && el1_private_leaf_state(descriptor) == El1PrivateLeafState::Unowned {
        return Ok((descriptor, descriptor));
    }
    if el1_private_leaf_state(descriptor) == El1PrivateLeafState::Retired {
        return Ok((descriptor, 0));
    }
    let span = 1u64 << SHIFTS[level];
    const CONTROL: u64 = carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE - 0x2_0000;
    let structural = va < CONTROL + 0x20_0000 && va + span > CONTROL;
    if structural && level < 3 {
        let child = scratch.allocate_child()?;
        for index in 0..512 {
            let original = split_terminal_descriptor(descriptor, level, index)?;
            let (_, inherited) = copy_entry(
                words,
                request,
                scratch,
                original,
                level + 1,
                va + ((index as u64) << SHIFTS[level + 1]),
            )?;
            scratch.child[child + index] = inherited;
        }
        return Ok((
            descriptor,
            (request.child_tables.base + child as u64 * 8) | 3,
        ));
    }
    if structural {
        let table_start = carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE;
        let table_end = table_start + carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE;
        if (table_start..table_end).contains(&va) {
            let output = request.child_tables.base + (va - table_start);
            if !request.child_tables.contains(output) {
                return Err(MmError::NoMemory);
            }
            return Ok((descriptor, (descriptor & !PA) | output));
        }
        if descriptor & (1 << 7) == 0 {
            let source_ipa = descriptor & PA;
            let destination_ipa = request.kernel_control_ipa + (va - CONTROL);
            scratch.custody(PortalForkCustody::StructuralCopy {
                source_ipa,
                destination_ipa,
                len: span,
                executable: descriptor & (1 << 53) == 0,
            })?;
            return Ok((descriptor, (descriptor & !PA) | destination_ipa));
        }
        let ipa = descriptor & PA;
        if ipa != 0 {
            scratch.custody(PortalForkCustody::Frame {
                va,
                ipa,
                len: span,
                shared: false,
            })?;
        }
        return Ok((descriptor, descriptor));
    }
    let policy = policy(&scratch.mappings, va, span, descriptor)?;
    if policy == Policy::Mixed {
        if level == 3 {
            return Err(MmError::Core);
        }
        let child = scratch.allocate_child()?;
        let parent = scratch.allocate_parent()?;
        let mut parent_changed = false;
        for index in 0..512 {
            let original = split_terminal_descriptor(descriptor, level, index)?;
            let (updated, inherited) = copy_entry(
                words,
                request,
                scratch,
                original,
                level + 1,
                va + ((index as u64) << SHIFTS[level + 1]),
            )?;
            scratch.parent[parent + index] = updated;
            scratch.child[child + index] = inherited;
            parent_changed |= updated != original;
        }
        return Ok((
            if parent_changed {
                (request.parent_tables.base + parent as u64 * 8) | 3
            } else {
                descriptor
            },
            (request.child_tables.base + child as u64 * 8) | 3,
        ));
    }
    match policy {
        Policy::Omit | Policy::Wipe => Ok((descriptor, 0)),
        Policy::Private => {
            if el1_private_leaf_state(descriptor) == El1PrivateLeafState::Retired {
                return Ok((descriptor, 0));
            }
            let armed =
                terminal_rule_edit(true, TerminalRule::fork_arm(true), descriptor, level, va)
                    .map_err(|_| MmError::Core)?
                    .unwrap_or(descriptor);
            let output_mask = PA & !(span - 1);
            let ipa = descriptor & output_mask;
            if ipa != 0 {
                scratch.custody(PortalForkCustody::Frame {
                    va,
                    ipa,
                    len: span,
                    shared: false,
                })?;
            }
            Ok((armed, armed))
        }
        Policy::Keep => {
            let output_mask = PA & !(span - 1);
            let ipa = descriptor & output_mask;
            if ipa != 0 && descriptor & (1 << 6) != 0 {
                scratch.custody(PortalForkCustody::Frame {
                    va,
                    ipa,
                    len: span,
                    shared: {
                        let index = scratch.mappings.partition_point(|m| m.range.end() <= va);
                        scratch.mappings.get(index).is_some_and(|m| {
                            m.range.contains(va) && !m.flags.contains(ReservationNodeFlags::PRIVATE)
                        })
                    },
                })?;
            }
            Ok((descriptor, descriptor))
        }
        Policy::Mixed => Err(MmError::Core),
    }
}

#[cfg(target_os = "none")]
static PENDING_FORKS: [crate::lock::SpinLock<Option<UnpublishedEl1Child>>;
    carrick_el1_abi::EL1_STACK_SLOTS as usize] =
    [const { crate::lock::SpinLock::new(None) }; carrick_el1_abi::EL1_STACK_SLOTS as usize];

/// Production service runs on the carrier maintenance root. The owner drops
/// both root/editor guards before requesting physical custody. Its unpublished
/// child capsule remains owned in EL1 until the separately scheduled FINISH.
#[cfg(target_os = "none")]
pub(super) fn authenticate_pending_parent_write(
    slot: usize,
    handle: El1MmHandle,
    sequence: NonZeroU64,
) -> Result<(), MmError> {
    let pending = PENDING_FORKS.get(slot).ok_or(MmError::Invalid)?.lock();
    let child = pending.as_ref().ok_or(MmError::Stale)?;
    let operation = child.completion.request.operation;
    if operation.carrier != handle.carrier()
        || operation.mm != handle.mm()
        || operation.incarnation != handle.incarnation()
        || operation.sequence != sequence
    {
        return Err(MmError::Stale);
    }
    Ok(())
}
#[cfg(target_os = "none")]
pub(super) fn reconcile_pending_parent_write<W: LiveDescriptorWords + ?Sized>(
    slot: usize,
    handle: El1MmHandle,
    sequence: NonZeroU64,
    completion: carrick_el1_abi::CowGrantCompletion,
    words: &W,
) -> Result<(), MmError> {
    authenticate_pending_parent_write(slot, handle, sequence)?;
    let mut pending = PENDING_FORKS.get(slot).ok_or(MmError::Invalid)?.lock();
    pending
        .as_mut()
        .ok_or(MmError::Stale)?
        .reconcile_parent_write(words, completion)
}

#[cfg(target_os = "none")]
pub fn serve_fork_hw(frame: &mut carrick_el1_abi::TrapFrame) {
    use carrick_mmu_core::aarch64::descriptor_txn::{CallerInvalidatesAsid, PrimaryTableWords};
    let slots =
        unsafe { &*(carrick_el1_abi::EL1_MM_PORTAL_BASE as *const carrick_el1_abi::MmPortalSlots) };
    let Some(slot) = slots.fork(frame.slot as usize) else {
        frame.x[0] = 22;
        return;
    };
    let Some(service) = slot.claim() else {
        frame.x[0] = 16;
        return;
    };
    let request = service.request();
    let run = || -> Result<PortalForkCompletion, MmError> {
        if slots.carrier() != Some(request.operation.carrier) {
            return Err(MmError::Stale);
        }
        if slots.has_outstanding_transfer(request.operation.mm) {
            return Err(MmError::Busy);
        }
        let pending = PENDING_FORKS
            .get(frame.slot as usize)
            .ok_or(MmError::Invalid)?;
        if pending.lock().is_some() {
            return Err(MmError::Busy);
        }
        let zone =
            unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
        let portal = MmPortal::<super::production::GuestMetadataPin> {
            backend: core::marker::PhantomData,
            carrier: request.operation.carrier,
            roots: crate::memory::reservations::shared_guest(),
            spaces: &zone.spaces,
            nodes: None,
            zone: Some(zone),
        };
        let index = zone
            .spaces
            .find(request.operation.mm.raw())
            .ok_or(MmError::Stale)?;
        let grant = zone
            .spaces
            .grant(index, request.operation.mm.raw())
            .ok_or(MmError::Busy)?;
        let base = grant.ttbr0 & PA;
        let pool = carrick_el1_abi::stage1_table_pool_window();
        for arena in [request.child_tables, request.parent_tables] {
            if arena.base < pool.physical_base
                || arena.base + arena.len > pool.physical_base + pool.byte_len as u64
            {
                return Err(MmError::Invalid);
            }
        }
        if base < pool.physical_base || base + 4096 > pool.physical_base + pool.byte_len as u64 {
            return Err(MmError::Invalid);
        }
        let maintenance = CallerInvalidatesAsid;
        let words = unsafe {
            PrimaryTableWords::new(
                base as *mut core::sync::atomic::AtomicU64,
                base,
                4096,
                &maintenance,
            )
            .and_then(|words| words.with_window(pool))
        }
        .map_err(|_| MmError::Core)?;
        let scratch = portal.census_fork(request, &words, frame.slot as u32)?;
        let plan = portal.prepare_fork(request, scratch, &words, frame.slot as u32)?;
        for (index, custody) in plan.custody().iter().copied().enumerate() {
            if !service.retain(index as u64, custody, super::production::yield_host_effect) {
                return Err(MmError::Busy);
            }
        }
        let child = portal.publish_fork(plan, &words, frame.slot as u32)?;
        crate::sched::ThreadCpu::invalidate_asid(&mut crate::sched::HardwareCpu, grant.ttbr0);
        let completion = child.completion();
        *pending.lock() = Some(child);
        service.publish_detached(completion).ok_or(MmError::Stale)?;
        Ok(completion)
    };
    match run() {
        Ok(_) => {
            frame.x[0] = 0;
        }
        Err(error) => {
            let errno = error.errno();
            service.complete(errno);
            frame.x[0] = u64::from(errno);
        }
    }
}

#[cfg(target_os = "none")]
pub fn finish_fork_hw(frame: &mut carrick_el1_abi::TrapFrame) {
    use carrick_mmu_core::aarch64::descriptor_txn::{CallerInvalidatesAsid, PrimaryTableWords};
    let result = (|| -> Result<(), MmError> {
        let slots = unsafe {
            &*(carrick_el1_abi::EL1_MM_PORTAL_BASE as *const carrick_el1_abi::MmPortalSlots)
        };
        let slot = slots.fork(frame.slot as usize).ok_or(MmError::Invalid)?;
        let (request, commit) = slot.finish_request().ok_or(MmError::Stale)?;
        if slots.carrier() != Some(request.operation.carrier) {
            return Err(MmError::Stale);
        }
        let pending = PENDING_FORKS
            .get(frame.slot as usize)
            .ok_or(MmError::Invalid)?;
        let mut child = pending.lock().take().ok_or(MmError::Stale)?;
        if child.completion().request != request {
            *pending.lock() = Some(child);
            return Err(MmError::Stale);
        }
        let zone =
            unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
        let portal = MmPortal::<super::production::GuestMetadataPin> {
            backend: core::marker::PhantomData,
            carrier: request.operation.carrier,
            roots: crate::memory::reservations::shared_guest(),
            spaces: &zone.spaces,
            nodes: None,
            zone: Some(zone),
        };
        let settlement = if commit {
            child.commit(&portal, frame.slot as u32).map(|_| ())
        } else {
            let maintenance = CallerInvalidatesAsid;
            let base = child.parent_root;
            let words = unsafe {
                PrimaryTableWords::new(
                    base as *mut core::sync::atomic::AtomicU64,
                    base,
                    4096,
                    &maintenance,
                )
                .and_then(|words| words.with_window(carrick_el1_abi::stage1_table_pool_window()))
            }
            .map_err(|_| MmError::Core);
            words.and_then(|words| child.abort(&portal, &words, frame.slot as u32))
        };
        if let Err(error) = settlement {
            *pending.lock() = Some(child);
            return Err(error);
        }
        if !commit
            && let Some(index) = zone.spaces.find(request.operation.mm.raw())
            && let Some(grant) = zone.spaces.grant(index, request.operation.mm.raw())
        {
            crate::sched::ThreadCpu::invalidate_asid(&mut crate::sched::HardwareCpu, grant.ttbr0);
        }
        if !slot.complete_finish_receipt(child.completion()) {
            return Err(MmError::Stale);
        }
        Ok(())
    })();
    frame.x[0] = result.err().map_or(0, |error| u64::from(error.errno()));
}
