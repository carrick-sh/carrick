//! Fork census, unpublished child, undo, and receipt validation.

use alloc::vec::Vec;
use carrick_el1_abi::{
    CowGrantCompletion, El1MmHandle, HostBackingIdentity, PortalForkCompletion, PortalForkCustody,
    PortalForkRequest, ReservationGeneration, ReservationNodeFlags, ReservationProtection,
    ReservationRange,
};
use carrick_guest_arch::{FrameGpa, UserVa};
use carrick_mmu_core::aarch64::descriptor_txn::{JournalEntry, LiveDescriptorWords};
use carrick_mmu_core::owner_mmu::{Aarch64Mmu, OwnerForkMmu};

const SHIFTS: [u32; 4] = [39, 30, 21, 12];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForkError {
    Invalid,
    NoMemory,
    Busy,
    Stale,
    Core,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub range: ReservationRange,
    pub protection: ReservationProtection,
    pub anonymous: bool,
    pub flags: ReservationNodeFlags,
    pub generation: ReservationGeneration,
    pub host_backing: Option<HostBackingIdentity>,
}

/// All allocation occurs before borrowing either owner. Unlinked table words
/// and parent undo storage stay owned across physical custody suspension.
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
}

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

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Keep,
    Private,
    Omit,
    Wipe,
    Mixed,
}

pub fn policy(
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

pub struct ForkCensus {
    pub child: usize,
    pub parent: usize,
    pub live: usize,
    pub custody: usize,
}

pub fn census_table<B: OwnerForkMmu, W: LiveDescriptorWords + ?Sized>(
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
        census_entry::<B, W>(
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

pub fn census_entry<B: OwnerForkMmu, W: LiveDescriptorWords + ?Sized>(
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
        return census_table::<B, W>(
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
    const CONTROL: u64 = carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE - 0x2_0000;
    let structural = B::PRIVATE_CONTROL_WINDOW && va < CONTROL + 0x20_0000 && va + span > CONTROL;
    let selected = policy(mappings, va, span, descriptor)?;
    if (structural || selected == Policy::Mixed) && level < 3 {
        count.child = count.child.checked_add(512).ok_or(ForkError::NoMemory)?;
        if !structural {
            count.parent = count.parent.checked_add(512).ok_or(ForkError::NoMemory)?;
        }
        for index in 0..512 {
            census_entry::<B, W>(
                words,
                mappings,
                B::split(descriptor, level, index).map_err(|_| ForkError::Core)?,
                level + 1,
                va + ((index as u64) << SHIFTS[level + 1]),
                count,
            )?;
        }
    } else if structural {
        let alias = carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE;
        if !(alias..alias + carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE).contains(&va)
            && descriptor & B::ADDRESS_MASK != 0
        {
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

pub fn copy_table<B: OwnerForkMmu, W: LiveDescriptorWords + ?Sized>(
    words: &W,
    request: PortalForkRequest,
    scratch: &mut ForkScratch,
    table: u64,
    level: usize,
    base: u64,
    child_offset: usize,
) -> Result<(), ForkError> {
    for index in 0..512 {
        let address = table + index as u64 * 8;
        let descriptor = words.load(address).map_err(|_| ForkError::Core)?;
        if scratch.reads.len() == scratch.reads.capacity() {
            return Err(ForkError::NoMemory);
        }
        scratch.reads.push((address, descriptor));
        let va = base + ((index as u64) << SHIFTS[level]);
        let (parent, child) = copy_entry::<B, W>(words, request, scratch, descriptor, level, va)?;
        scratch.child[child_offset + index] = child;
        if parent != descriptor {
            if scratch.edits.len() == scratch.edits.capacity() {
                return Err(ForkError::NoMemory);
            }
            scratch.edits.push(JournalEntry {
                pa: address,
                before: descriptor,
                after: parent,
                bbm_va: va,
                bbm_len: if B::needs_break_before_make(descriptor, parent, level) {
                    1 << SHIFTS[level]
                } else {
                    0
                },
            });
        }
    }
    Ok(())
}

pub fn copy_entry<B: OwnerForkMmu, W: LiveDescriptorWords + ?Sized>(
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
        copy_table::<B, W>(
            words,
            request,
            scratch,
            descriptor & B::ADDRESS_MASK,
            level + 1,
            va,
            child,
        )?;
        return Ok((
            descriptor,
            B::table_word(
                FrameGpa::new(request.child_tables.base + child as u64 * 8),
                None,
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
    const CONTROL: u64 = carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE - 0x2_0000;
    let structural = B::PRIVATE_CONTROL_WINDOW && va < CONTROL + 0x20_0000 && va + span > CONTROL;
    if structural && level < 3 {
        let child = scratch.allocate_child()?;
        for index in 0..512 {
            let original = B::split(descriptor, level, index).map_err(|_| ForkError::Core)?;
            let (_, inherited) = copy_entry::<B, W>(
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
                None,
            ),
        ));
    }
    if structural {
        let table_start = carrick_el1_abi::AARCH64_STAGE1_TABLES_ALIAS_BASE;
        let table_end = table_start + carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE;
        if (table_start..table_end).contains(&va) {
            let output = request.child_tables.base + (va - table_start);
            if !request.child_tables.contains(output) {
                return Err(ForkError::NoMemory);
            }
            return Ok((descriptor, (descriptor & !B::ADDRESS_MASK) | output));
        }
        if B::control_needs_copy(descriptor) {
            let source_ipa = descriptor & B::ADDRESS_MASK;
            let destination_ipa = request.kernel_control_ipa + (va - CONTROL);
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
        let ipa = descriptor & B::ADDRESS_MASK;
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
            return Err(ForkError::Core);
        }
        let child = scratch.allocate_child()?;
        let parent = scratch.allocate_parent()?;
        let mut parent_changed = false;
        for index in 0..512 {
            let original = B::split(descriptor, level, index).map_err(|_| ForkError::Core)?;
            let (updated, inherited) = copy_entry::<B, W>(
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
                    None,
                )
            } else {
                descriptor
            },
            B::table_word(
                FrameGpa::new(request.child_tables.base + child as u64 * 8),
                None,
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
                        scratch.mappings.get(index).is_some_and(|m| {
                            m.range.contains(va) && !m.flags.contains(ReservationNodeFlags::PRIVATE)
                        })
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
