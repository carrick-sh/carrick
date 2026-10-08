//! Fork census, unpublished child, undo, and receipt validation.

use crate::mm::reservation::{Refusal, ReservationGeometry, ReservationPolicy, Reservations};
use alloc::vec::Vec;
pub use carrick_core_abi::Mapping;
use carrick_core_abi::{
    CowGrantCompletion, El1MmHandle, PortalForkCompletion, PortalForkCustody, PortalForkRequest,
    ReservationGeneration,
};
use carrick_guest_arch::{FrameGpa, UserVa};
use carrick_mmu_core::aarch64::descriptor_txn::{JournalEntry, LiveDescriptorWords};
use carrick_mmu_core::owner_mmu::{Aarch64Mmu, OwnerForkMmu};

const SHIFTS: [u32; 4] = [39, 30, 21, 12];

/// Typed owner refusals preserved across the neutral fork transaction. The
/// personality adapter decides their guest-visible error representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForkOwnerRefusal {
    Invalid,
    Collision,
    Hole,
    ForeignMapping,
    Limit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForkError {
    Invalid,
    NoMemory,
    Busy,
    Stale,
    /// Owner metadata backing must be supplied before publication can finish.
    MetadataRequired,
    OwnerRefusal(ForkOwnerRefusal),
    Core,
}

/// All allocation occurs before borrowing either owner. Unlinked table words
/// and parent undo storage stay owned across physical custody suspension.
#[derive(Clone, Debug)]
pub struct ForkScratch {
    pub child: Vec<u64>,
    pub parent: Vec<u64>,
    pub edits: Vec<JournalEntry>,
    pub reads: Vec<(u64, u64)>,
    pub custody: Vec<PortalForkCustody>,
    pub mappings: Vec<Mapping>,
    pub child_used: usize,
    pub parent_used: usize,
}

impl ForkScratch {
    pub fn new(request: PortalForkRequest, metadata_capacity: usize) -> Result<Self, ForkError> {
        if !request.valid() {
            return Err(ForkError::Invalid);
        }
        let child_len =
            usize::try_from(request.child_tables.len / 8).map_err(|_| ForkError::Invalid)?;
        let parent_len =
            usize::try_from(request.parent_tables.len / 8).map_err(|_| ForkError::Invalid)?;
        Self::bounded(
            request,
            metadata_capacity,
            child_len,
            parent_len,
            child_len,
            child_len
                .checked_add(metadata_capacity)
                .ok_or(ForkError::Invalid)?,
        )
    }

    pub fn bounded(
        request: PortalForkRequest,
        metadata_capacity: usize,
        child_len: usize,
        parent_len: usize,
        live_words: usize,
        custody_len: usize,
    ) -> Result<Self, ForkError> {
        if child_len < 512
            || child_len as u64 * 8 > request.child_tables.len
            || parent_len as u64 * 8 > request.parent_tables.len
        {
            return Err(ForkError::NoMemory);
        }
        let mut child = Vec::new();
        let mut parent = Vec::new();
        let mut edits = Vec::new();
        let mut reads = Vec::new();
        let mut custody = Vec::new();
        let mut mappings = Vec::new();
        child
            .try_reserve_exact(child_len)
            .map_err(|_| ForkError::NoMemory)?;
        parent
            .try_reserve_exact(parent_len)
            .map_err(|_| ForkError::NoMemory)?;
        edits
            .try_reserve_exact(live_words)
            .map_err(|_| ForkError::NoMemory)?;
        reads
            .try_reserve_exact(live_words)
            .map_err(|_| ForkError::NoMemory)?;
        custody
            .try_reserve_exact(custody_len)
            .map_err(|_| ForkError::NoMemory)?;
        mappings
            .try_reserve_exact(metadata_capacity)
            .map_err(|_| ForkError::NoMemory)?;
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

    pub fn allocation_counts(&self) -> (usize, usize, usize, usize) {
        (
            self.child.capacity(),
            self.parent.capacity(),
            self.reads.capacity(),
            self.custody.capacity(),
        )
    }

    pub fn allocate_child(&mut self) -> Result<usize, ForkError> {
        let offset = self.child_used;
        self.child_used = self
            .child_used
            .checked_add(512)
            .filter(|end| *end <= self.child.capacity())
            .ok_or(ForkError::NoMemory)?;
        self.child.resize(self.child_used, 0);
        Ok(offset)
    }

    pub fn allocate_parent(&mut self) -> Result<usize, ForkError> {
        let offset = self.parent_used;
        self.parent_used = self
            .parent_used
            .checked_add(512)
            .filter(|end| *end <= self.parent.capacity())
            .ok_or(ForkError::NoMemory)?;
        self.parent.resize(self.parent_used, 0);
        Ok(offset)
    }

    pub fn custody(&mut self, value: PortalForkCustody) -> Result<(), ForkError> {
        if self.custody.len() == self.custody.capacity() {
            return Err(ForkError::NoMemory);
        }
        self.custody.push(value);
        Ok(())
    }
}

pub trait ForkChildRoot {
    fn incarnation(&self) -> u64;
    fn is_admitted(&self) -> bool;
    fn fork_write_authorized(&mut self, sequence: Option<core::num::NonZeroU64>) -> bool;
    fn authenticate_fork_origin(&mut self, request: PortalForkRequest) -> bool;
    fn set_fork_origin(&mut self, request: PortalForkRequest) -> Result<(), ForkError>;
    fn clear_fork_origin(&mut self);
    fn publish_fork_child(&mut self, request: PortalForkRequest) -> Result<(), ForkError>;
    fn finish_fork_publication(
        &mut self,
        operation: carrick_core_abi::PortalOperation,
    ) -> Result<(), ForkError>;
    fn retire(self) -> Result<(), ForkError>;
}

pub trait ForkParentRoot<C: ForkChildRoot> {
    fn incarnation(&self) -> u64;
    fn generation(&self) -> ReservationGeneration;
    fn operation_sequence(&self) -> u64;
    fn fork_ready(&mut self) -> bool;
    fn fork_write_authorized(&mut self, sequence: Option<core::num::NonZeroU64>) -> bool;
    fn reserve_fork_certificate(&mut self, request: PortalForkRequest) -> Result<(), ForkError>;
    fn clone_into(&mut self, child: &mut C) -> Result<(), ForkError>;
    fn publish_fork_parent(
        &mut self,
        request: PortalForkRequest,
    ) -> Result<ReservationGeneration, ForkError>;
    fn finish_fork_publication(
        &mut self,
        operation: carrick_core_abi::PortalOperation,
    ) -> Result<(), ForkError>;
    fn commit_fork_generation(&mut self) -> Result<ReservationGeneration, ForkError>;
}

fn refusal_to_fork_error(e: Refusal) -> ForkError {
    match e {
        Refusal::Stale => ForkError::Stale,
        Refusal::Busy | Refusal::PreparedConflict => ForkError::Busy,
        Refusal::MetadataRequired => ForkError::MetadataRequired,
        Refusal::Invalid => ForkError::OwnerRefusal(ForkOwnerRefusal::Invalid),
        Refusal::Collision => ForkError::OwnerRefusal(ForkOwnerRefusal::Collision),
        Refusal::Hole => ForkError::OwnerRefusal(ForkOwnerRefusal::Hole),
        Refusal::ForeignMapping => ForkError::OwnerRefusal(ForkOwnerRefusal::ForeignMapping),
        Refusal::Limit => ForkError::OwnerRefusal(ForkOwnerRefusal::Limit),
    }
}

impl<
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    C: Copy + Send + Sync + zerocopy::FromZeros,
> ForkChildRoot for Reservations<'_, Policy, Geometry, C>
{
    fn incarnation(&self) -> u64 {
        self.incarnation().raw()
    }

    fn is_admitted(&self) -> bool {
        self.is_admitted()
    }

    fn fork_write_authorized(&mut self, sequence: Option<core::num::NonZeroU64>) -> bool {
        self.fork_write_authorized(sequence)
    }

    fn authenticate_fork_origin(&mut self, request: PortalForkRequest) -> bool {
        self.authenticate_fork_origin(request)
    }

    fn set_fork_origin(&mut self, request: PortalForkRequest) -> Result<(), ForkError> {
        self.set_fork_origin(request).map_err(refusal_to_fork_error)
    }

    fn clear_fork_origin(&mut self) {
        self.clear_fork_origin();
    }

    fn publish_fork_child(&mut self, request: PortalForkRequest) -> Result<(), ForkError> {
        self.publish_fork_child(request)
            .map_err(refusal_to_fork_error)
    }

    fn finish_fork_publication(
        &mut self,
        operation: carrick_core_abi::PortalOperation,
    ) -> Result<(), ForkError> {
        self.finish_fork_publication(operation)
            .map_err(refusal_to_fork_error)
    }

    fn retire(self) -> Result<(), ForkError> {
        self.retire().map_err(refusal_to_fork_error)
    }
}

impl<
    'b,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    C: Copy + Send + Sync + zerocopy::FromZeros,
> ForkParentRoot<Reservations<'b, Policy, Geometry, C>> for Reservations<'_, Policy, Geometry, C>
{
    fn incarnation(&self) -> u64 {
        self.incarnation().raw()
    }

    fn generation(&self) -> carrick_core_abi::ReservationGeneration {
        self.generation()
    }

    fn operation_sequence(&self) -> u64 {
        self.operation_sequence()
    }

    fn fork_ready(&mut self) -> bool {
        self.fork_ready()
    }

    fn fork_write_authorized(&mut self, sequence: Option<core::num::NonZeroU64>) -> bool {
        self.fork_write_authorized(sequence)
    }

    fn reserve_fork_certificate(&mut self, request: PortalForkRequest) -> Result<(), ForkError> {
        self.reserve_fork_certificate(request)
            .map_err(refusal_to_fork_error)
    }

    fn clone_into(
        &mut self,
        child: &mut Reservations<'b, Policy, Geometry, C>,
    ) -> Result<(), ForkError> {
        self.clone_into(child).map_err(refusal_to_fork_error)
    }

    fn publish_fork_parent(
        &mut self,
        request: PortalForkRequest,
    ) -> Result<carrick_core_abi::ReservationGeneration, ForkError> {
        self.publish_fork_parent(request)
            .map_err(refusal_to_fork_error)
    }

    fn finish_fork_publication(
        &mut self,
        operation: carrick_core_abi::PortalOperation,
    ) -> Result<(), ForkError> {
        self.finish_fork_publication(operation)
            .map_err(refusal_to_fork_error)
    }

    fn commit_fork_generation(
        &mut self,
    ) -> Result<carrick_core_abi::ReservationGeneration, ForkError> {
        self.commit_fork_generation().map_err(refusal_to_fork_error)
    }
}

pub struct PreparedOwnerFork<B: OwnerForkMmu = Aarch64Mmu> {
    pub request: PortalForkRequest,
    pub parent_root: u64,
    pub scratch: ForkScratch,
    pub _marker: core::marker::PhantomData<B>,
}

impl<B: OwnerForkMmu> PreparedOwnerFork<B> {
    pub fn new(request: PortalForkRequest, parent_root: u64, scratch: ForkScratch) -> Self {
        Self {
            request,
            parent_root,
            scratch,
            _marker: core::marker::PhantomData,
        }
    }

    pub fn custody(&self) -> &[PortalForkCustody] {
        &self.scratch.custody
    }

    pub fn request(&self) -> PortalForkRequest {
        self.request
    }

    pub fn publish<W: LiveDescriptorWords + ?Sized, C: ForkChildRoot, P: ForkParentRoot<C>>(
        self,
        words: &W,
        mut parent: P,
        mut child: C,
        child_handle: El1MmHandle,
    ) -> Result<UnpublishedChild<B>, ForkError> {
        for (pa, before) in &self.scratch.reads {
            if words.load(*pa).map_err(|_| ForkError::Core)? != *before {
                return Err(ForkError::Stale);
            }
        }
        if self.request.parent_generation.raw() >= u64::MAX - 1 {
            return Err(ForkError::Stale);
        }
        if parent.incarnation() != self.request.operation.incarnation.get()
            || parent.generation() != self.request.parent_generation
            || parent.operation_sequence() != self.request.operation.sequence.get()
        {
            return Err(ForkError::Stale);
        }
        if !parent.fork_ready() || child.is_admitted() {
            return Err(ForkError::Busy);
        }
        parent.reserve_fork_certificate(self.request)?;
        for (index, word) in self.scratch.child[..self.scratch.child_used]
            .iter()
            .enumerate()
        {
            words
                .store_unlinked(self.request.child_tables.base + index as u64 * 8, *word)
                .map_err(|_| ForkError::Core)?;
        }
        for (index, word) in self.scratch.parent[..self.scratch.parent_used]
            .iter()
            .enumerate()
        {
            words
                .store_unlinked(self.request.parent_tables.base + index as u64 * 8, *word)
                .map_err(|_| ForkError::Core)?;
        }
        words.publish_barrier();
        for (applied, edit) in self.scratch.edits.iter().enumerate() {
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
                                    .map_err(|_| ForkError::Core)?
                                {
                                    return Err(ForkError::Core);
                                }
                                words.publish_barrier();
                                words.invalidate_range(edit.bbm_va, edit.bbm_len);
                                Err(if result.is_err() {
                                    ForkError::Core
                                } else {
                                    ForkError::Stale
                                })
                            }
                        }
                    }
                    Ok(false) => Err(ForkError::Stale),
                    Err(_) => Err(ForkError::Core),
                }
            } else {
                match words.compare_exchange(edit.pa, edit.before, edit.after) {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(ForkError::Stale),
                    Err(_) => Err(ForkError::Core),
                }
            };
            if let Err(error) = changed {
                rollback(words, &self.scratch.edits[..applied])?;
                return Err(error);
            }
        }
        if let Err(error) = child.set_fork_origin(self.request) {
            rollback(words, &self.scratch.edits)?;
            return Err(error);
        }
        if let Err(error) = parent.clone_into(&mut child) {
            child.clear_fork_origin();
            rollback(words, &self.scratch.edits)?;
            return Err(error);
        }
        let parent_generation = match parent.publish_fork_parent(self.request) {
            Ok(generation) => generation,
            Err(error) => {
                child.clear_fork_origin();
                rollback(words, &self.scratch.edits)?;
                return Err(error);
            }
        };
        if let Err(error) = child.publish_fork_child(self.request) {
            child.clear_fork_origin();
            rollback(words, &self.scratch.edits)?;
            return Err(error);
        }
        words.publish_barrier();
        words.invalidate_range(0, 1 << 48);
        Ok(UnpublishedChild::new(
            PortalForkCompletion {
                request: self.request,
                child: child_handle,
                parent_generation,
                child_tables_used: self.scratch.child_used as u64 * 8,
                parent_tables_used: self.scratch.parent_used as u64 * 8,
            },
            self.parent_root,
            self.scratch,
        ))
    }
}

#[derive(Clone, Debug)]
pub struct UnpublishedChild<B: OwnerForkMmu = Aarch64Mmu> {
    pub completion: PortalForkCompletion,
    pub parent_root: u64,
    pub scratch: ForkScratch,
    pub _marker: core::marker::PhantomData<B>,
}

impl<B: OwnerForkMmu> UnpublishedChild<B> {
    pub fn new(completion: PortalForkCompletion, parent_root: u64, scratch: ForkScratch) -> Self {
        Self {
            completion,
            parent_root,
            scratch,
            _marker: core::marker::PhantomData,
        }
    }

    pub fn completion(&self) -> PortalForkCompletion {
        self.completion
    }

    pub fn commit<C: ForkChildRoot, P: ForkParentRoot<C>>(
        &mut self,
        mut parent: P,
        mut child: C,
    ) -> Result<PortalForkCompletion, ForkError> {
        let request = self.completion.request;
        if parent.incarnation() != request.operation.incarnation.get()
            || parent.generation() != self.completion.parent_generation
            || !child.authenticate_fork_origin(request)
            || !parent.fork_write_authorized(Some(request.operation.sequence))
            || !child.fork_write_authorized(Some(request.operation.sequence))
        {
            return Err(ForkError::Stale);
        }
        parent.finish_fork_publication(request.operation)?;
        child.finish_fork_publication(request.operation)?;
        Ok(self.completion)
    }

    pub fn abort<W: LiveDescriptorWords + ?Sized, C: ForkChildRoot, P: ForkParentRoot<C>>(
        &mut self,
        words: &W,
        mut parent: P,
        mut child: C,
    ) -> Result<(), ForkError> {
        let request = self.completion.request;
        if parent.incarnation() != request.operation.incarnation.get()
            || parent.generation() != self.completion.parent_generation
            || !child.authenticate_fork_origin(request)
            || !parent.fork_write_authorized(Some(request.operation.sequence))
            || !child.fork_write_authorized(Some(request.operation.sequence))
        {
            return Err(ForkError::Stale);
        }
        rollback(words, &self.scratch.edits)?;
        words.publish_barrier();
        words.invalidate_range(0, 1 << 48);
        parent.finish_fork_publication(request.operation)?;
        self.completion.parent_generation = parent.commit_fork_generation()?;
        if !self.scratch.edits.iter().any(|edit| {
            B::is_table(edit.before, 0)
                && request
                    .parent_tables
                    .contains(edit.before & B::ADDRESS_MASK)
        }) {
            self.completion.parent_tables_used = 0;
        }
        self.completion.child_tables_used = 0;
        drop(parent);
        child.finish_fork_publication(request.operation)?;
        child.retire()?;
        Ok(())
    }

    pub fn reconcile_parent_write<W: LiveDescriptorWords + ?Sized>(
        &mut self,
        words: &W,
        completion: CowGrantCompletion,
    ) -> Result<(), ForkError> {
        if !completion.is_well_formed()
            || completion.grant.mm_key != self.completion.request.operation.mm.raw()
        {
            return Err(ForkError::Stale);
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

    fn reconcile_parent_page<W: LiveDescriptorWords + ?Sized>(
        &mut self,
        words: &W,
        va: u64,
        new_ipa: u64,
        old_ipa: u64,
    ) -> Result<(), ForkError> {
        let mut table = self.parent_root;
        let mut path = [(0u64, 0u64); 4];
        let mut depth = 0;
        for (level, shift) in SHIFTS.into_iter().enumerate() {
            let pa = table + ((va >> shift) & 511) * 8;
            let live = words.load(pa).map_err(|_| ForkError::Core)?;
            path[level] = (pa, live);
            depth = level + 1;
            if level == 3 || !B::is_table(live, level) {
                break;
            }
            table = live & B::ADDRESS_MASK;
        }
        let terminal = path[depth - 1].1;
        let owned = terminal & B::ADDRESS_MASK == new_ipa
            && depth == 4
            && B::is_owned_resident(terminal)
            && B::is_writable_user(terminal);
        for (level, (pa, live)) in path[..depth].iter().copied().enumerate() {
            if let Some(entry) = self.scratch.edits.iter_mut().find(|entry| entry.pa == pa) {
                if live != entry.after {
                    if level != 3 || !owned || entry.after & B::ADDRESS_MASK != old_ipa {
                        return Err(ForkError::Stale);
                    }
                    entry.after = live;
                    entry.before = live;
                    entry.bbm_len = 0;
                } else if owned
                    && level < 3
                    && B::is_table(entry.after, level)
                    && !B::is_table(entry.before, level)
                {
                    entry.before = entry.after;
                    entry.bbm_len = 0;
                }
            }
        }
        Ok(())
    }
}

pub fn rollback<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    edits: &[JournalEntry],
) -> Result<(), ForkError> {
    for edit in edits.iter().rev() {
        if edit.bbm_len != 0 {
            if !words
                .compare_exchange(edit.pa, edit.after, 0)
                .map_err(|_| ForkError::Core)?
            {
                return Err(ForkError::Core);
            }
            words.publish_barrier();
            words.invalidate_range(edit.bbm_va, edit.bbm_len);
            if !words
                .compare_exchange(edit.pa, 0, edit.before)
                .map_err(|_| ForkError::Core)?
            {
                return Err(ForkError::Core);
            }
        } else if !words
            .compare_exchange(edit.pa, edit.after, edit.before)
            .map_err(|_| ForkError::Core)?
        {
            return Err(ForkError::Core);
        }
    }
    words.publish_barrier();
    words.invalidate_range(0, 1 << 48);
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    Keep,
    Private,
    Omit,
    Wipe,
    Mixed,
}

pub trait MappingInheritancePolicy {
    fn inheritance_policy(&self, mapping: &Mapping) -> Policy;
    fn is_shared(&self, mapping: &Mapping) -> bool;
}

pub fn policy<B: OwnerForkMmu, P: MappingInheritancePolicy>(
    policy_provider: &P,
    mappings: &[Mapping],
    base: u64,
    span: u64,
    descriptor: u64,
) -> Result<Policy, ForkError> {
    let end = base.checked_add(span).ok_or(ForkError::Invalid)?;
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
        let value = policy_provider.inheritance_policy(mapping);
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
        Ok(if B::is_user(descriptor) {
            Policy::Omit
        } else {
            Policy::Keep
        })
    }
}

pub struct ForkCensus {
    pub child: usize,
    pub parent: usize,
    pub live: usize,
    pub custody: usize,
}

pub fn census_table<
    B: OwnerForkMmu,
    P: MappingInheritancePolicy,
    W: LiveDescriptorWords + ?Sized,
>(
    policy_provider: &P,
    words: &W,
    mappings: &[Mapping],
    table: u64,
    level: usize,
    base: u64,
    count: &mut ForkCensus,
) -> Result<(), ForkError> {
    count.child = count.child.checked_add(512).ok_or(ForkError::NoMemory)?;
    count.live = count.live.checked_add(512).ok_or(ForkError::NoMemory)?;
    for index in 0..512 {
        if level == 0 && B::is_shared_root_entry(index as usize) {
            continue;
        }
        census_entry::<B, P, W>(
            policy_provider,
            words,
            mappings,
            words.load(table + index * 8).map_err(|_| ForkError::Core)?,
            level,
            base + (index << SHIFTS[level]),
            count,
        )?;
    }
    Ok(())
}

pub fn census_entry<
    B: OwnerForkMmu,
    P: MappingInheritancePolicy,
    W: LiveDescriptorWords + ?Sized,
>(
    policy_provider: &P,
    words: &W,
    mappings: &[Mapping],
    descriptor: u64,
    level: usize,
    va: u64,
    count: &mut ForkCensus,
) -> Result<(), ForkError> {
    if descriptor == 0 {
        return Ok(());
    }
    if level < 3 && B::is_table(descriptor, level) {
        return census_table::<B, P, W>(
            policy_provider,
            words,
            mappings,
            descriptor & B::ADDRESS_MASK,
            level + 1,
            va,
            count,
        );
    }
    if level == 0 {
        return Err(ForkError::Core);
    }
    if B::is_absent_unowned(descriptor) {
        return Ok(());
    }
    let span = 1u64 << SHIFTS[level];
    let structural = B::control_window()
        .is_some_and(|(start, end)| va < end.raw() && va.saturating_add(span) > start.raw());
    let selected = policy::<B, P>(policy_provider, mappings, va, span, descriptor)?;
    if (structural || selected == Policy::Mixed) && level < 3 {
        count.child = count.child.checked_add(512).ok_or(ForkError::NoMemory)?;
        if !structural {
            count.parent = count.parent.checked_add(512).ok_or(ForkError::NoMemory)?;
        }
        for index in 0..512 {
            census_entry::<B, P, W>(
                policy_provider,
                words,
                mappings,
                B::split(descriptor, level, index).map_err(|_| ForkError::Core)?,
                level + 1,
                va + ((index as u64) << SHIFTS[level + 1]),
                count,
            )?;
        }
    } else if structural {
        if B::control_needs_copy(UserVa::new(va), descriptor) {
            count.custody = count.custody.checked_add(1).ok_or(ForkError::NoMemory)?;
        }
    } else if (selected == Policy::Private || (selected == Policy::Keep && B::is_user(descriptor)))
        && !B::is_retired(descriptor)
        && descriptor & (B::ADDRESS_MASK & !(span - 1)) != 0
    {
        count.custody = count.custody.checked_add(1).ok_or(ForkError::NoMemory)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkTableCursor {
    pub table: u64,
    pub level: usize,
    pub base: u64,
    pub child_offset: usize,
}

pub fn copy_table<B: OwnerForkMmu, P: MappingInheritancePolicy, W: LiveDescriptorWords + ?Sized>(
    policy_provider: &P,
    words: &W,
    request: PortalForkRequest,
    scratch: &mut ForkScratch,
    cursor: ForkTableCursor,
) -> Result<(), ForkError> {
    for index in 0..512 {
        let address = cursor.table + index as u64 * 8;
        let descriptor = words.load(address).map_err(|_| ForkError::Core)?;
        if scratch.reads.len() == scratch.reads.capacity() {
            return Err(ForkError::NoMemory);
        }
        scratch.reads.push((address, descriptor));
        if cursor.level == 0 && B::is_shared_root_entry(index) {
            scratch.child[cursor.child_offset + index] = descriptor;
            continue;
        }
        let va = cursor.base + ((index as u64) << SHIFTS[cursor.level]);
        let (parent, child) = copy_entry::<B, P, W>(
            policy_provider,
            words,
            request,
            scratch,
            descriptor,
            cursor.level,
            va,
        )?;
        scratch.child[cursor.child_offset + index] = child;
        if parent != descriptor {
            if scratch.edits.len() == scratch.edits.capacity() {
                return Err(ForkError::NoMemory);
            }
            scratch.edits.push(JournalEntry {
                pa: address,
                before: descriptor,
                after: parent,
                bbm_va: va,
                bbm_len: if B::needs_break_before_make(descriptor, parent, cursor.level) {
                    1 << SHIFTS[cursor.level]
                } else {
                    0
                },
            });
        }
    }
    Ok(())
}

pub fn copy_entry<B: OwnerForkMmu, P: MappingInheritancePolicy, W: LiveDescriptorWords + ?Sized>(
    policy_provider: &P,
    words: &W,
    request: PortalForkRequest,
    scratch: &mut ForkScratch,
    descriptor: u64,
    level: usize,
    va: u64,
) -> Result<(u64, u64), ForkError> {
    if descriptor == 0 {
        return Ok((0, 0));
    }
    if level < 3 && B::is_table(descriptor, level) {
        let child = scratch.allocate_child()?;
        copy_table::<B, P, W>(
            policy_provider,
            words,
            request,
            scratch,
            ForkTableCursor {
                table: descriptor & B::ADDRESS_MASK,
                level: level + 1,
                base: va,
                child_offset: child,
            },
        )?;
        return Ok((
            descriptor,
            B::table_word(
                FrameGpa::new(request.child_tables.base + child as u64 * 8),
                Some(descriptor),
            ),
        ));
    }
    if level == 0 {
        return Err(ForkError::Core);
    }
    if B::is_absent_unowned(descriptor) {
        return Ok((descriptor, descriptor));
    }
    if B::is_retired(descriptor) {
        return Ok((descriptor, 0));
    }
    let span = 1u64 << SHIFTS[level];
    let structural = B::control_window()
        .is_some_and(|(start, end)| va < end.raw() && va.saturating_add(span) > start.raw());
    if structural && level < 3 {
        let child = scratch.allocate_child()?;
        for index in 0..512 {
            let original = B::split(descriptor, level, index).map_err(|_| ForkError::Core)?;
            let (_, inherited) = copy_entry::<B, P, W>(
                policy_provider,
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
            B::table_word(
                FrameGpa::new(request.child_tables.base + child as u64 * 8),
                Some(descriptor),
            ),
        ));
    }
    if structural {
        if B::is_control_alias(UserVa::new(va)) {
            let output = B::control_alias_destination(
                UserVa::new(va),
                FrameGpa::new(request.child_tables.base),
            )
            .map_err(|_| ForkError::Core)?
            .raw();
            if !request.child_tables.contains(output) {
                return Err(ForkError::NoMemory);
            }
            return Ok((descriptor, (descriptor & !B::ADDRESS_MASK) | output));
        }
        if B::control_needs_copy(UserVa::new(va), descriptor) {
            let source_ipa = descriptor & B::ADDRESS_MASK;
            let destination_ipa = B::control_copy_destination(
                UserVa::new(va),
                FrameGpa::new(request.kernel_control_ipa),
            )
            .map_err(|_| ForkError::Core)?
            .raw();
            scratch.custody(PortalForkCustody::StructuralCopy {
                source_ipa,
                destination_ipa,
                len: span,
                executable: B::is_executable_control(descriptor),
            })?;
            return Ok((
                descriptor,
                (descriptor & !B::ADDRESS_MASK) | destination_ipa,
            ));
        }
        return Ok((descriptor, descriptor));
    }
    let policy = policy::<B, P>(policy_provider, &scratch.mappings, va, span, descriptor)?;
    if policy == Policy::Mixed {
        if level == 3 {
            return Err(ForkError::Core);
        }
        let child = scratch.allocate_child()?;
        let parent = scratch.allocate_parent()?;
        let mut parent_changed = false;
        for index in 0..512 {
            let original = B::split(descriptor, level, index).map_err(|_| ForkError::Core)?;
            let (updated, inherited) = copy_entry::<B, P, W>(
                policy_provider,
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
                B::table_word(
                    FrameGpa::new(request.parent_tables.base + parent as u64 * 8),
                    Some(descriptor),
                )
            } else {
                descriptor
            },
            B::table_word(
                FrameGpa::new(request.child_tables.base + child as u64 * 8),
                Some(descriptor),
            ),
        ));
    }
    match policy {
        Policy::Omit | Policy::Wipe => Ok((descriptor, 0)),
        Policy::Private => {
            if B::is_retired(descriptor) {
                return Ok((descriptor, 0));
            }
            let armed =
                B::arm_private(descriptor, level, UserVa::new(va)).map_err(|_| ForkError::Core)?;
            let output_mask = B::ADDRESS_MASK & !(span - 1);
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
            let output_mask = B::ADDRESS_MASK & !(span - 1);
            let ipa = descriptor & output_mask;
            if ipa != 0 && B::is_user(descriptor) {
                scratch.custody(PortalForkCustody::Frame {
                    va,
                    ipa,
                    len: span,
                    shared: {
                        let index = scratch.mappings.partition_point(|m| m.range.end() <= va);
                        scratch
                            .mappings
                            .get(index)
                            .is_some_and(|m| m.range.contains(va) && policy_provider.is_shared(m))
                    },
                })?;
            }
            Ok((descriptor, descriptor))
        }
        Policy::Mixed => Err(ForkError::Core),
    }
}

/// Exact owner completion and the physical lifetimes it selected.
pub struct OwnerForkReceipt<P> {
    pub completion: PortalForkCompletion,
    pub retained: Vec<P>,
    pub host_backing: Vec<(core::num::NonZeroU64, core::num::NonZeroU64)>,
    pub selected: Vec<PortalForkCustody>,
}

impl<P> OwnerForkReceipt<P> {
    pub fn new(
        completion: PortalForkCompletion,
        retained: Vec<P>,
        host_backing: Vec<(core::num::NonZeroU64, core::num::NonZeroU64)>,
        selected: Vec<PortalForkCustody>,
    ) -> Self {
        Self {
            completion,
            retained,
            host_backing,
            selected,
        }
    }

    pub fn completion(&self) -> PortalForkCompletion {
        self.completion
    }

    pub fn inherited_host_backing(&self) -> &[(core::num::NonZeroU64, core::num::NonZeroU64)] {
        &self.host_backing
    }

    pub fn selected(&self) -> &[PortalForkCustody] {
        &self.selected
    }

    pub fn into_parts(self) -> (PortalForkCompletion, Vec<P>) {
        (self.completion, self.retained)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForkReceiptError {
    StaleChild,
    StaleRequest,
    MismatchedDecision,
    InvalidAbortParentGeneration,
    InvalidAbortChildTables,
    Refused(u32),
}

/// Validate settled completion against expected request, child handle, and initial completion.
pub fn validate_fork_completion(
    expected_request: PortalForkRequest,
    expected_child: El1MmHandle,
    initial_completion: PortalForkCompletion,
    settled_completion: Result<PortalForkCompletion, u32>,
    commit: bool,
) -> Result<PortalForkCompletion, ForkReceiptError> {
    let completion = match settled_completion {
        Ok(c) => c,
        Err(errno) => return Err(ForkReceiptError::Refused(errno)),
    };
    if completion.request != expected_request {
        return Err(ForkReceiptError::StaleRequest);
    }
    if completion.child != expected_child {
        return Err(ForkReceiptError::StaleChild);
    }
    if commit {
        if completion != initial_completion {
            return Err(ForkReceiptError::MismatchedDecision);
        }
    } else {
        let expected_generation = initial_completion
            .parent_generation
            .raw()
            .checked_add(1)
            .unwrap_or(0);
        if completion.parent_generation.raw() != expected_generation {
            return Err(ForkReceiptError::InvalidAbortParentGeneration);
        }
        if completion.child_tables_used != 0 {
            return Err(ForkReceiptError::InvalidAbortChildTables);
        }
        if completion.parent_tables_used != 0
            && completion.parent_tables_used != initial_completion.parent_tables_used
        {
            return Err(ForkReceiptError::MismatchedDecision);
        }
    }
    Ok(completion)
}
