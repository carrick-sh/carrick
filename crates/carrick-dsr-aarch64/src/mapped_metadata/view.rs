use std::fmt;
use std::sync::Arc;

use carrick_guest_mem::GuestVa;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::direct_binding::DirectBindingOrdinal;
use crate::emit::{DirectLinkKind, PcMapEntry, RecoveryAction};
use crate::shared_cache::{
    DIRECT_BINDING_CELL_SIZE, DirectBindingLayout, DirectBindingRelocation,
    MAX_TRANSLATION_UNIT_CODE_BYTES, TranslationUnitKey, UnresolvedDirectBindingRecord,
};
use crate::types::CacheOffset;

use super::builder::wire_key;
use super::wire::{
    HEADER_SIZE_V3, MappedMetadataError, SectionKind, ValidatedLayout, WireBindingRelocationV3,
    WireBindingV3, WireBlockV3, WireEdgeGroupV3, WireEdgeMemberV3, WireGuestRangeV3, WireHeaderV3,
    WirePcMapV3, WireRecoveryActionV3, WireRecoverySpanV3,
};

const BLOCK_FLAG_SENSITIVE: u32 = 1;

pub trait MetadataBacking: Send + Sync + fmt::Debug {
    fn bytes(&self) -> &[u8];
}

#[derive(Debug)]
pub struct VecMetadataBacking(Vec<u8>);

impl VecMetadataBacking {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl MetadataBacking for VecMetadataBacking {
    fn bytes(&self) -> &[u8] {
        &self.0
    }
}

pub struct ValidatedMappedTranslationMetadata {
    backing: Arc<dyn MetadataBacking>,
    layout: ValidatedLayout,
    key: TranslationUnitKey,
    header: WireHeaderV3,
    counts: [usize; 9],
    counts_u64: [u64; 9],
}

impl fmt::Debug for ValidatedMappedTranslationMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedMappedTranslationMetadata")
            .field("layout", &self.layout)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl ValidatedMappedTranslationMetadata {
    pub fn new(
        backing: Arc<dyn MetadataBacking>,
        expected_key: &TranslationUnitKey,
    ) -> Result<Self, MappedMetadataError> {
        let layout = ValidatedLayout::parse(backing.bytes())?;
        let header = *WireHeaderV3::ref_from_bytes(backing.bytes().get(..HEADER_SIZE_V3).ok_or(
            MappedMetadataError::HeaderTruncated {
                actual: backing.bytes().len(),
            },
        )?)
        .map_err(|_| MappedMetadataError::HeaderTruncated {
            actual: backing.bytes().len(),
        })?;
        let mut counts = [0; 9];
        let mut counts_u64 = [0; 9];
        for kind in all_section_kinds() {
            let section = layout
                .section(kind)
                .ok_or(MappedMetadataError::MissingSection { kind })?;
            counts[section_slot(kind)] = usize::try_from(section.count().get())
                .map_err(|_| MappedMetadataError::Arithmetic)?;
            counts_u64[section_slot(kind)] = section.count().get();
        }
        let metadata = Self {
            backing,
            layout,
            key: expected_key.clone(),
            header,
            counts,
            counts_u64,
        };
        metadata.validate(expected_key)?;
        Ok(metadata)
    }

    pub fn key(&self) -> &TranslationUnitKey {
        &self.key
    }
    pub fn dylib_sha256(&self) -> [u8; 32] {
        self.header().dylib_sha256
    }
    pub fn code_len(&self) -> u64 {
        self.header().code_len.get()
    }
    pub fn binding_data_len(&self) -> u64 {
        self.header().binding_data_len.get()
    }
    pub fn cell_size(&self) -> u32 {
        self.header().cell_size.get()
    }
    pub fn binding_layout(&self) -> DirectBindingLayout {
        if self.header().binding_layout.get() == 0 {
            DirectBindingLayout::Disabled
        } else {
            DirectBindingLayout::SidecarV1
        }
    }
    pub fn block_count(&self) -> usize {
        self.count(SectionKind::Block)
    }
    pub fn binding_count(&self) -> usize {
        self.count(SectionKind::Binding)
    }
    pub fn edge_group_count(&self) -> usize {
        self.count(SectionKind::EdgeGroup)
    }
    pub fn block(&self, index: usize) -> Option<MappedBlockView<'_>> {
        if index >= self.block_count() {
            return None;
        }
        let wire = *self
            .record_checked::<WireBlockV3>(SectionKind::Block, index)
            .ok()?;
        Some(MappedBlockView {
            metadata: self,
            generation_binding: u32::try_from(wire.generation_binding.get()).ok()?,
            pc_start: usize::try_from(wire.pc_map_start.get()).ok()?,
            pc_count: usize::try_from(wire.pc_map_count.get()).ok()?,
            recovery_start: usize::try_from(wire.recovery_start.get()).ok()?,
            recovery_count: usize::try_from(wire.recovery_count.get()).ok()?,
            guest_range_start: usize::try_from(wire.guest_range_start.get()).ok()?,
            guest_range_count: usize::try_from(wire.guest_range_count.get()).ok()?,
            wire,
        })
    }
    pub fn binding(&self, index: usize) -> Option<MappedBindingView<'_>> {
        if index >= self.binding_count() {
            return None;
        }
        Some(MappedBindingView {
            _metadata: self,
            kind: binding_kind(
                self.record_checked::<WireBindingV3>(SectionKind::Binding, index)
                    .ok()?
                    .kind
                    .get(),
            )?,
            wire: *self
                .record_checked::<WireBindingV3>(SectionKind::Binding, index)
                .ok()?,
            relocation: *self
                .record_checked::<WireBindingRelocationV3>(SectionKind::BindingRelocation, index)
                .ok()?,
        })
    }
    pub fn edge_group(&self, index: usize) -> Option<MappedEdgeGroupView<'_>> {
        if index >= self.edge_group_count() {
            return None;
        }
        let wire = *self
            .record_checked::<WireEdgeGroupV3>(SectionKind::EdgeGroup, index)
            .ok()?;
        Some(MappedEdgeGroupView {
            metadata: self,
            start: usize::try_from(wire.member_start.get()).ok()?,
            count: usize::try_from(wire.member_count.get()).ok()?,
            wire,
        })
    }

    fn validate(&self, expected_key: &TranslationUnitKey) -> Result<(), MappedMetadataError> {
        for kind in [
            SectionKind::Block,
            SectionKind::PcMap,
            SectionKind::RecoverySpan,
            SectionKind::RecoveryAction,
            SectionKind::GuestRange,
            SectionKind::Binding,
            SectionKind::BindingRelocation,
            SectionKind::EdgeGroup,
            SectionKind::EdgeMember,
        ] {
            if self.layout.section(kind).is_none() {
                return Err(MappedMetadataError::MissingSection { kind });
            }
        }
        let header = self.header();
        let expected_wire = wire_key(expected_key)?;
        if header.key.as_bytes() != expected_wire.as_bytes() {
            return Err(MappedMetadataError::Key);
        }
        let code_len = header.code_len.get();
        let max_code_len = u64::try_from(MAX_TRANSLATION_UNIT_CODE_BYTES)
            .map_err(|_| MappedMetadataError::Block)?;
        if code_len == 0 || code_len > max_code_len {
            return Err(MappedMetadataError::Block);
        }
        if self.block_count() == 0 {
            return Err(MappedMetadataError::Block);
        }
        if !matches!(header.binding_layout.get(), 0 | 1) {
            return Err(MappedMetadataError::Binding);
        }

        for index in 0..self.count(SectionKind::RecoveryAction) {
            self.record_checked::<WireRecoveryActionV3>(SectionKind::RecoveryAction, index)?
                .validate()?;
        }

        let mut expected_entry = 0_u64;
        let mut expected_pc = 0_u64;
        let mut expected_recovery = 0_u64;
        let mut expected_range = 0_u64;
        for block_index in 0..self.block_count() {
            let block = *self.record_checked::<WireBlockV3>(SectionKind::Block, block_index)?;
            for earlier in 0..block_index {
                if self
                    .record_checked::<WireBlockV3>(SectionKind::Block, earlier)?
                    .guest_start
                    .get()
                    == block.guest_start.get()
                {
                    return Err(MappedMetadataError::Block);
                }
            }
            let entry = u64::from(block.entry_offset.get());
            let block_len = u64::from(block.code_len.get());
            let end = entry
                .checked_add(block_len)
                .ok_or(MappedMetadataError::Block)?;
            if block.reserved.get() != 0
                || block.flags.get() & !BLOCK_FLAG_SENSITIVE != 0
                || block.generation_binding.get() > u64::from(u32::MAX)
                || block_len == 0
                || !entry.is_multiple_of(4)
                || !block_len.is_multiple_of(4)
                || entry < expected_entry
                || end > code_len
                || block.pc_map_start.get() != expected_pc
                || block.recovery_start.get() != expected_recovery
                || block.guest_range_start.get() != expected_range
            {
                return Err(MappedMetadataError::Block);
            }
            expected_entry = end;
            let pc_end = checked_slice_end(
                block.pc_map_start.get(),
                block.pc_map_count.get(),
                self.count_u64(SectionKind::PcMap),
                MappedMetadataError::PcMap,
            )?;
            let recovery_end = checked_slice_end(
                block.recovery_start.get(),
                block.recovery_count.get(),
                self.count_u64(SectionKind::RecoverySpan),
                MappedMetadataError::RecoverySpan,
            )?;
            let range_end = checked_slice_end(
                block.guest_range_start.get(),
                block.guest_range_count.get(),
                self.count_u64(SectionKind::GuestRange),
                MappedMetadataError::GuestRange,
            )?;
            if block.pc_map_count.get() == 0 || block.guest_range_count.get() == 0 {
                return Err(MappedMetadataError::PcMap);
            }
            self.validate_pc_map(&block)?;
            self.validate_recovery(&block)?;
            self.validate_guest_ranges(&block)?;
            expected_pc = pc_end;
            expected_recovery = recovery_end;
            expected_range = range_end;
        }
        if expected_pc != self.count_u64(SectionKind::PcMap)
            || expected_recovery != self.count_u64(SectionKind::RecoverySpan)
            || expected_range != self.count_u64(SectionKind::GuestRange)
        {
            return Err(MappedMetadataError::Block);
        }
        self.validate_bindings()
    }

    fn validate_pc_map(&self, block: &WireBlockV3) -> Result<(), MappedMetadataError> {
        let mut previous = None;
        let mut contains_start = false;
        for relative in 0..block.pc_map_count.get() {
            let index = usize_index(
                block
                    .pc_map_start
                    .get()
                    .checked_add(relative)
                    .ok_or(MappedMetadataError::PcMap)?,
                MappedMetadataError::PcMap,
            )?;
            let pc = self.record_checked::<WirePcMapV3>(SectionKind::PcMap, index)?;
            let cache = pc.cache_offset.get();
            if pc.reserved.get() != 0
                || !cache.is_multiple_of(4)
                || cache >= block.code_len.get()
                || previous.is_some_and(|value| value >= cache)
                || !pc.guest.get().is_multiple_of(4)
                || pc.guest.get().checked_add(4).is_none()
            {
                return Err(MappedMetadataError::PcMap);
            }
            contains_start |= pc.guest.get() == block.guest_start.get();
            previous = Some(cache);
        }
        contains_start
            .then_some(())
            .ok_or(MappedMetadataError::PcMap)
    }

    fn validate_recovery(&self, block: &WireBlockV3) -> Result<(), MappedMetadataError> {
        let mut previous_end = None;
        for relative in 0..block.recovery_count.get() {
            let index = usize_index(
                block
                    .recovery_start
                    .get()
                    .checked_add(relative)
                    .ok_or(MappedMetadataError::RecoverySpan)?,
                MappedMetadataError::RecoverySpan,
            )?;
            let span =
                self.record_checked::<WireRecoverySpanV3>(SectionKind::RecoverySpan, index)?;
            let count = span.entry_count.get();
            let last = count
                .checked_sub(1)
                .and_then(|count| count.checked_mul(4))
                .and_then(|delta| span.cache_offset.get().checked_add(delta))
                .ok_or(MappedMetadataError::RecoverySpan)?;
            if !span.cache_offset.get().is_multiple_of(4)
                || last >= block.code_len.get()
                || previous_end.is_some_and(|end| end > span.cache_offset.get())
                || span.action_index.get() >= self.count_u64(SectionKind::RecoveryAction)
            {
                return Err(
                    if span.action_index.get() >= self.count_u64(SectionKind::RecoveryAction) {
                        MappedMetadataError::RecoveryAction
                    } else {
                        MappedMetadataError::RecoverySpan
                    },
                );
            }
            previous_end = last.checked_add(4);
        }
        Ok(())
    }

    fn validate_guest_ranges(&self, block: &WireBlockV3) -> Result<(), MappedMetadataError> {
        let mut previous_end = None;
        for relative in 0..block.guest_range_count.get() {
            let index = usize_index(
                block
                    .guest_range_start
                    .get()
                    .checked_add(relative)
                    .ok_or(MappedMetadataError::GuestRange)?,
                MappedMetadataError::GuestRange,
            )?;
            let range = self.record_checked::<WireGuestRangeV3>(SectionKind::GuestRange, index)?;
            if range.start.get() >= range.end.get()
                || !range.start.get().is_multiple_of(4)
                || !range.end.get().is_multiple_of(4)
                || previous_end.is_some_and(|end| end >= range.start.get())
            {
                return Err(MappedMetadataError::GuestRange);
            }
            let mut guest = range.start.get();
            while guest < range.end.get() {
                let mut found = false;
                for pc_relative in 0..block.pc_map_count.get() {
                    let pc_index = usize_index(
                        block
                            .pc_map_start
                            .get()
                            .checked_add(pc_relative)
                            .ok_or(MappedMetadataError::GuestRange)?,
                        MappedMetadataError::GuestRange,
                    )?;
                    found |= self
                        .record_checked::<WirePcMapV3>(SectionKind::PcMap, pc_index)?
                        .guest
                        .get()
                        == guest;
                }
                if !found {
                    return Err(MappedMetadataError::GuestRange);
                }
                guest = guest
                    .checked_add(4)
                    .ok_or(MappedMetadataError::GuestRange)?;
            }
            previous_end = Some(range.end.get());
        }
        for pc_relative in 0..block.pc_map_count.get() {
            let pc_index = usize_index(
                block
                    .pc_map_start
                    .get()
                    .checked_add(pc_relative)
                    .ok_or(MappedMetadataError::GuestRange)?,
                MappedMetadataError::GuestRange,
            )?;
            let guest = self
                .record_checked::<WirePcMapV3>(SectionKind::PcMap, pc_index)?
                .guest
                .get();
            let mut covered = false;
            for range_relative in 0..block.guest_range_count.get() {
                let range_index = usize_index(
                    block
                        .guest_range_start
                        .get()
                        .checked_add(range_relative)
                        .ok_or(MappedMetadataError::GuestRange)?,
                    MappedMetadataError::GuestRange,
                )?;
                let range =
                    self.record_checked::<WireGuestRangeV3>(SectionKind::GuestRange, range_index)?;
                covered |= range.start.get() <= guest && guest < range.end.get();
            }
            if !covered {
                return Err(MappedMetadataError::GuestRange);
            }
        }
        Ok(())
    }

    fn validate_bindings(&self) -> Result<(), MappedMetadataError> {
        let header = self.header();
        let bindings = self.count_u64(SectionKind::Binding);
        if self.count_u64(SectionKind::BindingRelocation) != bindings
            || self.count_u64(SectionKind::EdgeMember) != bindings
        {
            return Err(MappedMetadataError::BindingRelocation);
        }
        match header.binding_layout.get() {
            0 if bindings == 0
                && header.binding_data_len.get() == 0
                && header.cell_size.get() == 0 => {}
            1 if header.cell_size.get() == DIRECT_BINDING_CELL_SIZE
                && header.binding_data_len.get()
                    == bindings
                        .checked_mul(u64::from(DIRECT_BINDING_CELL_SIZE))
                        .ok_or(MappedMetadataError::Binding)? => {}
            _ => return Err(MappedMetadataError::Binding),
        }
        let mut previous_stub_end = None;
        for index in 0..self.binding_count() {
            let binding = self.record_checked::<WireBindingV3>(SectionKind::Binding, index)?;
            let expected = u32::try_from(index).map_err(|_| MappedMetadataError::Binding)?;
            if binding.ordinal.get() != expected
                || binding_kind(binding.kind.get()).is_none()
                || !binding.stub_start.get().is_multiple_of(4)
                || !binding.stub_end.get().is_multiple_of(4)
                || binding.stub_start.get() >= binding.stub_end.get()
                || u64::from(binding.stub_end.get()) > self.code_len()
                || previous_stub_end.is_some_and(|end| end > binding.stub_start.get())
                || binding.edge_member_index.get() >= bindings
            {
                return Err(MappedMetadataError::Binding);
            }
            for block_index in 0..self.block_count() {
                if self
                    .record_checked::<WireBlockV3>(SectionKind::Block, block_index)?
                    .guest_start
                    .get()
                    == binding.target.get()
                {
                    return Err(MappedMetadataError::Binding);
                }
            }
            previous_stub_end = Some(binding.stub_end.get());
            let relocation = self
                .record_checked::<WireBindingRelocationV3>(SectionKind::BindingRelocation, index)?;
            let expected_offsets = [
                binding.stub_start.get().checked_add(20),
                binding.stub_start.get().checked_add(24),
                binding.stub_start.get().checked_add(108),
                binding.stub_start.get().checked_add(112),
            ];
            if relocation.ordinal.get() != expected
                || [
                    Some(relocation.adrp_offset.get()),
                    Some(relocation.add_offset.get()),
                    Some(relocation.miss_adrp_offset.get()),
                    Some(relocation.miss_add_offset.get()),
                ] != expected_offsets
                || relocation.data_offset.get()
                    != expected
                        .checked_mul(DIRECT_BINDING_CELL_SIZE)
                        .ok_or(MappedMetadataError::BindingRelocation)?
            {
                return Err(MappedMetadataError::BindingRelocation);
            }
        }
        let mut expected_member = 0_u64;
        let mut previous_key = None;
        for group_index in 0..self.edge_group_count() {
            let group =
                self.record_checked::<WireEdgeGroupV3>(SectionKind::EdgeGroup, group_index)?;
            let key = (group.source.get(), group.target.get());
            if previous_key.is_some_and(|previous| previous >= key)
                || group.member_count.get() == 0
                || group.member_start.get() != expected_member
            {
                return Err(MappedMetadataError::EdgeGroup);
            }
            expected_member = checked_slice_end(
                group.member_start.get(),
                group.member_count.get(),
                bindings,
                MappedMetadataError::EdgeGroup,
            )?;
            for member_index in group.member_start.get()..expected_member {
                let member = self.record_checked::<WireEdgeMemberV3>(
                    SectionKind::EdgeMember,
                    usize_index(member_index, MappedMetadataError::EdgeBackReference)?,
                )?;
                let ordinal = usize_index(
                    u64::from(member.binding_ordinal.get()),
                    MappedMetadataError::EdgeBackReference,
                )?;
                let binding =
                    self.record_checked::<WireBindingV3>(SectionKind::Binding, ordinal)?;
                if member.reserved.get() != 0
                    || binding.edge_member_index.get() != member_index
                    || (binding.source.get(), binding.target.get()) != key
                {
                    return Err(MappedMetadataError::EdgeBackReference);
                }
            }
            previous_key = Some(key);
        }
        if expected_member != bindings {
            return Err(MappedMetadataError::EdgeGroup);
        }
        Ok(())
    }

    fn header(&self) -> &WireHeaderV3 {
        &self.header
    }
    fn count(&self, kind: SectionKind) -> usize {
        self.counts[section_slot(kind)]
    }
    fn count_u64(&self, kind: SectionKind) -> u64 {
        self.counts_u64[section_slot(kind)]
    }
    fn record_checked<T: FromBytes + KnownLayout + Immutable>(
        &self,
        kind: SectionKind,
        index: usize,
    ) -> Result<&T, MappedMetadataError> {
        let section = self
            .layout
            .section(kind)
            .ok_or(MappedMetadataError::MissingSection { kind })?;
        let stride = std::mem::size_of::<T>();
        if u32::try_from(stride).ok() != Some(kind.record_stride()) {
            return Err(MappedMetadataError::Arithmetic);
        }
        let relative = index
            .checked_mul(stride)
            .ok_or(MappedMetadataError::Arithmetic)?;
        let start = usize::try_from(section.offset().get())
            .ok()
            .and_then(|offset| offset.checked_add(relative))
            .ok_or(MappedMetadataError::Arithmetic)?;
        let end = start
            .checked_add(stride)
            .ok_or(MappedMetadataError::Arithmetic)?;
        T::ref_from_bytes(
            self.backing
                .bytes()
                .get(start..end)
                .ok_or(MappedMetadataError::Arithmetic)?,
        )
        .map_err(|_| MappedMetadataError::Arithmetic)
    }
}

fn checked_slice_end(
    start: u64,
    count: u64,
    limit: u64,
    error: MappedMetadataError,
) -> Result<u64, MappedMetadataError> {
    let end = start.checked_add(count).ok_or_else(|| error.clone())?;
    (end <= limit).then_some(end).ok_or(error)
}
fn usize_index(index: u64, error: MappedMetadataError) -> Result<usize, MappedMetadataError> {
    usize::try_from(index).map_err(|_| error)
}
fn binding_kind(raw: u32) -> Option<DirectLinkKind> {
    match raw {
        0 => Some(DirectLinkKind::Branch),
        1 => Some(DirectLinkKind::Call),
        2 => Some(DirectLinkKind::ConditionalTaken),
        3 => Some(DirectLinkKind::ConditionalFallthrough),
        4 => Some(DirectLinkKind::Continue),
        _ => None,
    }
}

fn all_section_kinds() -> [SectionKind; 9] {
    [
        SectionKind::Block,
        SectionKind::PcMap,
        SectionKind::RecoverySpan,
        SectionKind::RecoveryAction,
        SectionKind::GuestRange,
        SectionKind::Binding,
        SectionKind::BindingRelocation,
        SectionKind::EdgeGroup,
        SectionKind::EdgeMember,
    ]
}

fn section_slot(kind: SectionKind) -> usize {
    match kind {
        SectionKind::Block => 0,
        SectionKind::PcMap => 1,
        SectionKind::RecoverySpan => 2,
        SectionKind::RecoveryAction => 3,
        SectionKind::GuestRange => 4,
        SectionKind::Binding => 5,
        SectionKind::BindingRelocation => 6,
        SectionKind::EdgeGroup => 7,
        SectionKind::EdgeMember => 8,
    }
}

#[derive(Clone, Copy)]
pub struct MappedBlockView<'a> {
    metadata: &'a ValidatedMappedTranslationMetadata,
    wire: WireBlockV3,
    generation_binding: u32,
    pc_start: usize,
    pc_count: usize,
    recovery_start: usize,
    recovery_count: usize,
    guest_range_start: usize,
    guest_range_count: usize,
}
impl<'a> MappedBlockView<'a> {
    fn wire(&self) -> &WireBlockV3 {
        &self.wire
    }
    pub fn guest_start(self) -> GuestVa {
        GuestVa(self.wire().guest_start.get())
    }
    pub fn generation_binding(self) -> u32 {
        self.generation_binding
    }
    pub fn entry_offset(self) -> u32 {
        self.wire().entry_offset.get()
    }
    pub fn code_len(self) -> u32 {
        self.wire().code_len.get()
    }
    pub fn requires_sensitive_metadata(self) -> bool {
        self.wire().flags.get() & BLOCK_FLAG_SENSITIVE != 0
    }
    pub fn pc_map(self) -> MappedPcMapView<'a> {
        MappedPcMapView {
            metadata: self.metadata,
            start: self.pc_start,
            count: self.pc_count,
        }
    }
    pub fn recovery(self) -> MappedRecoveryView<'a> {
        MappedRecoveryView {
            metadata: self.metadata,
            start: self.recovery_start,
            count: self.recovery_count,
        }
    }
    pub fn guest_ranges(self) -> impl Iterator<Item = std::ops::Range<GuestVa>> + 'a {
        (0..self.guest_range_count).filter_map(move |relative| {
            self.guest_range_start
                .checked_add(relative)
                .and_then(|index| {
                    self.metadata
                        .record_checked::<WireGuestRangeV3>(SectionKind::GuestRange, index)
                        .ok()
                })
                .map(|range| GuestVa(range.start.get())..GuestVa(range.end.get()))
        })
    }
}

#[derive(Clone, Copy)]
pub struct MappedPcMapView<'a> {
    metadata: &'a ValidatedMappedTranslationMetadata,
    start: usize,
    count: usize,
}
impl<'a> MappedPcMapView<'a> {
    pub fn len(self) -> usize {
        self.count
    }
    pub fn is_empty(self) -> bool {
        self.count == 0
    }
    pub fn get(self, index: usize) -> Option<PcMapEntry> {
        if index >= self.count {
            return None;
        }
        let wire = self
            .metadata
            .record_checked::<WirePcMapV3>(SectionKind::PcMap, self.start.checked_add(index)?)
            .ok()?;
        Some(PcMapEntry {
            guest: GuestVa(wire.guest.get()),
            cache: CacheOffset::published(wire.cache_offset.get()),
        })
    }
    pub fn iter(self) -> impl Iterator<Item = PcMapEntry> + 'a {
        (0..self.len()).filter_map(move |index| self.get(index))
    }
    pub fn guest_for_cache(self, cache: CacheOffset) -> Option<GuestVa> {
        let target = cache.get();
        let mut low = 0;
        let mut high = self.len();
        while low < high {
            let mid = low + (high - low) / 2;
            let entry = self.get(mid)?;
            match entry.cache.get().cmp(&target) {
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => high = mid,
                std::cmp::Ordering::Equal => return Some(entry.guest),
            }
        }
        None
    }
}

#[derive(Clone, Copy)]
pub struct MappedRecoveryView<'a> {
    metadata: &'a ValidatedMappedTranslationMetadata,
    start: usize,
    count: usize,
}
impl MappedRecoveryView<'_> {
    pub fn span_count(self) -> usize {
        self.count
    }
    pub fn action_for_cache(
        self,
        cache: CacheOffset,
    ) -> Result<Option<RecoveryAction>, MappedMetadataError> {
        let target = cache.get();
        let mut low = 0_usize;
        let mut high = self.count;
        while low < high {
            let mid = low + (high - low) / 2;
            let span = self.metadata.record_checked::<WireRecoverySpanV3>(
                SectionKind::RecoverySpan,
                self.start
                    .checked_add(mid)
                    .ok_or(MappedMetadataError::RecoverySpan)?,
            )?;
            if span.cache_offset.get() <= target {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        if low == 0 {
            return Ok(None);
        }
        let span = self.metadata.record_checked::<WireRecoverySpanV3>(
            SectionKind::RecoverySpan,
            self.start
                .checked_add(low - 1)
                .ok_or(MappedMetadataError::RecoverySpan)?,
        )?;
        let delta = target
            .checked_sub(span.cache_offset.get())
            .ok_or(MappedMetadataError::RecoverySpan)?;
        if !delta.is_multiple_of(4) || delta / 4 >= span.entry_count.get() {
            return Ok(None);
        }
        let action = *self.metadata.record_checked::<WireRecoveryActionV3>(
            SectionKind::RecoveryAction,
            usize_index(span.action_index.get(), MappedMetadataError::RecoveryAction)?,
        )?;
        crate::artifact_spike::PortableRecoveryAction::decode_v3(
            action,
            self.metadata.key.host_bias(),
        )
        .map(Some)
        .map_err(|_| MappedMetadataError::RecoveryAction)
    }
}

#[derive(Clone, Copy)]
pub struct MappedBindingView<'a> {
    _metadata: &'a ValidatedMappedTranslationMetadata,
    wire: WireBindingV3,
    relocation: WireBindingRelocationV3,
    kind: DirectLinkKind,
}
impl MappedBindingView<'_> {
    fn wire(&self) -> &WireBindingV3 {
        &self.wire
    }
    pub fn record(self) -> UnresolvedDirectBindingRecord {
        let wire = self.wire();
        UnresolvedDirectBindingRecord {
            source: GuestVa(wire.source.get()),
            target: GuestVa(wire.target.get()),
            kind: self.kind,
            ordinal: DirectBindingOrdinal::claimed(wire.ordinal.get()),
            stub_start: wire.stub_start.get(),
            stub_end: wire.stub_end.get(),
        }
    }
    pub fn relocation(self) -> DirectBindingRelocation {
        let wire = &self.relocation;
        DirectBindingRelocation {
            ordinal: DirectBindingOrdinal::claimed(wire.ordinal.get()),
            adrp_offset: wire.adrp_offset.get(),
            add_offset: wire.add_offset.get(),
            miss_adrp_offset: wire.miss_adrp_offset.get(),
            miss_add_offset: wire.miss_add_offset.get(),
            data_offset: wire.data_offset.get(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct MappedEdgeGroupView<'a> {
    metadata: &'a ValidatedMappedTranslationMetadata,
    wire: WireEdgeGroupV3,
    start: usize,
    count: usize,
}
impl<'a> MappedEdgeGroupView<'a> {
    fn wire(&self) -> &WireEdgeGroupV3 {
        &self.wire
    }
    pub fn source(self) -> GuestVa {
        GuestVa(self.wire().source.get())
    }
    pub fn target(self) -> GuestVa {
        GuestVa(self.wire().target.get())
    }
    pub fn members(self) -> impl Iterator<Item = DirectBindingOrdinal> + 'a {
        (0..self.count).filter_map(move |relative| {
            self.start
                .checked_add(relative)
                .and_then(|index| {
                    self.metadata
                        .record_checked::<WireEdgeMemberV3>(SectionKind::EdgeMember, index)
                        .ok()
                })
                .map(|member| DirectBindingOrdinal::claimed(member.binding_ordinal.get()))
        })
    }
}

#[cfg(test)]
type Corruption = (&'static str, fn(&mut Vec<u8>), MappedMetadataError);

#[cfg(test)]
fn test_corruptions() -> [Corruption; 9] {
    [
        (
            "unknown recovery tag",
            |b| {
                let offset = section_offset(b, SectionKind::RecoveryAction);
                put_u32(b, offset, 99);
            },
            MappedMetadataError::RecoveryAction,
        ),
        (
            "nonzero unused recovery payload",
            |b| {
                let offset = section_offset(b, SectionKind::RecoveryAction) + 16;
                put_u64(b, offset, 1);
            },
            MappedMetadataError::RecoveryAction,
        ),
        (
            "PC order reversal",
            |b| {
                let offset = section_offset(b, SectionKind::PcMap) + 16 + 8;
                put_u32(b, offset, 0);
            },
            MappedMetadataError::PcMap,
        ),
        (
            "zero recovery span",
            |b| {
                let offset = section_offset(b, SectionKind::RecoverySpan) + 4;
                put_u32(b, offset, 0);
            },
            MappedMetadataError::RecoverySpan,
        ),
        (
            "bad action index",
            |b| {
                let offset = section_offset(b, SectionKind::RecoverySpan) + 8;
                put_u64(b, offset, u64::MAX);
            },
            MappedMetadataError::RecoveryAction,
        ),
        (
            "guest range mismatch",
            |b| {
                let o = section_offset(b, SectionKind::GuestRange);
                put_u64(b, o, 0x4004);
            },
            MappedMetadataError::GuestRange,
        ),
        (
            "binding ordinal mismatch",
            |b| {
                let offset = section_offset(b, SectionKind::Binding) + 16;
                put_u32(b, offset, 1);
            },
            MappedMetadataError::Binding,
        ),
        (
            "relocation mismatch",
            |b| {
                let offset = section_offset(b, SectionKind::BindingRelocation) + 20;
                put_u32(b, offset, 8);
            },
            MappedMetadataError::BindingRelocation,
        ),
        (
            "binding member back-reference",
            |b| {
                let offset = section_offset(b, SectionKind::Binding) + 32;
                put_u64(b, offset, 1);
            },
            MappedMetadataError::EdgeBackReference,
        ),
    ]
}

#[cfg(test)]
fn section_offset(bytes: &[u8], kind: SectionKind) -> usize {
    usize::try_from(
        ValidatedLayout::parse(bytes)
            .expect("valid fixture layout")
            .section(kind)
            .expect("fixture section")
            .offset()
            .get(),
    )
    .expect("fixture offset")
}
#[cfg(test)]
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
#[cfg(test)]
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
pub(super) mod tests {
    use std::sync::Arc;

    use carrick_guest_mem::GuestVa;

    use super::{ValidatedMappedTranslationMetadata, VecMetadataBacking};
    use crate::artifact_spike::{ArtifactBindings, ArtifactTemplate};
    use crate::direct_binding::DirectBindingOrdinal;
    use crate::emit::{DirectLinkKind, PcMapEntry, RecoveryAction, RecoveryEntry};
    use crate::mapped_metadata::encode_translation_metadata_v3;
    use crate::shared_cache::{
        AddressModeIdentity, DirectBindingLayout, DirectBindingRelocation, ExecutableIdentity,
        GuestCodeLen, ImageFileLen, ImageFileOffset, NativePageProfileIdentity,
        PortableBlockRecord, SourceFingerprint, TRANSLATION_UNIT_BINDING_EXPORT,
        TRANSLATION_UNIT_SCHEMA_V2, TranslationUnitKey, TranslationUnitManifest,
        UnresolvedDirectBindingRecord, translation_unit_base_export,
    };
    use crate::types::CacheOffset;

    pub(crate) fn mapped_manifest_fixture() -> TranslationUnitManifest {
        let key = TranslationUnitKey::for_segment(
            ExecutableIdentity::Digest([0x11; 32]),
            ImageFileOffset::new(0x1000),
            ImageFileLen::new(0x4000).expect("file length"),
            GuestVa(0x4000),
            GuestCodeLen::new(0x4000).expect("guest length"),
            SourceFingerprint([0x22; 32]),
            NativePageProfileIdentity::Native16k,
            AddressModeIdentity::Direct,
        );
        let bindings = ArtifactBindings::from_values([]).expect("empty artifact bindings");
        let first = ArtifactTemplate::normalize(
            vec![0xd503_201f; 32],
            vec![
                PcMapEntry {
                    guest: GuestVa(0x4000),
                    cache: CacheOffset::published(0),
                },
                PcMapEntry {
                    guest: GuestVa(0x4004),
                    cache: CacheOffset::published(8),
                },
            ],
            vec![
                RecoveryEntry {
                    cache: CacheOffset::published(0),
                    action: RecoveryAction::RestoreScratch { register: 16 },
                },
                RecoveryEntry {
                    cache: CacheOffset::published(4),
                    action: RecoveryAction::RestoreScratch { register: 16 },
                },
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            &bindings,
        )
        .expect("first template")
        .into_runtime_metadata_only_with_recovery_runs(true)
        .expect("run recovery");
        let second = ArtifactTemplate::normalize(
            vec![0xd503_201f; 32],
            vec![
                PcMapEntry {
                    guest: GuestVa(0x5000),
                    cache: CacheOffset::published(0),
                },
                PcMapEntry {
                    guest: GuestVa(0x5004),
                    cache: CacheOffset::published(12),
                },
            ],
            vec![RecoveryEntry {
                cache: CacheOffset::published(12),
                action: RecoveryAction::RestoreGuestX17,
            }],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            &bindings,
        )
        .expect("second template")
        .into_runtime_metadata_only_with_recovery_runs(false)
        .expect("entry recovery");
        TranslationUnitManifest {
            schema: TRANSLATION_UNIT_SCHEMA_V2,
            base_export: translation_unit_base_export(&key).expect("base export"),
            key,
            dylib_sha256: [0x33; 32],
            code_len: 512,
            blocks: vec![
                PortableBlockRecord {
                    guest_start: GuestVa(0x4000),
                    generation_binding: 7,
                    entry_offset: 0,
                    code_len: 128,
                    requires_sensitive_metadata: false,
                    template: first,
                },
                PortableBlockRecord {
                    guest_start: GuestVa(0x5000),
                    generation_binding: 9,
                    entry_offset: 128,
                    code_len: 128,
                    requires_sensitive_metadata: true,
                    template: second,
                },
            ],
            binding_layout: DirectBindingLayout::SidecarV1,
            binding_export: TRANSLATION_UNIT_BINDING_EXPORT.to_owned(),
            binding_data_len: 16,
            cell_size: 8,
            bindings: vec![
                UnresolvedDirectBindingRecord {
                    source: GuestVa(0x4000),
                    target: GuestVa(0x9000),
                    kind: DirectLinkKind::Branch,
                    ordinal: DirectBindingOrdinal::claimed(0),
                    stub_start: 256,
                    stub_end: 376,
                },
                UnresolvedDirectBindingRecord {
                    source: GuestVa(0x4000),
                    target: GuestVa(0x9000),
                    kind: DirectLinkKind::Call,
                    ordinal: DirectBindingOrdinal::claimed(1),
                    stub_start: 376,
                    stub_end: 496,
                },
            ],
            binding_relocations: vec![
                DirectBindingRelocation {
                    ordinal: DirectBindingOrdinal::claimed(0),
                    adrp_offset: 276,
                    add_offset: 280,
                    miss_adrp_offset: 364,
                    miss_add_offset: 368,
                    data_offset: 0,
                },
                DirectBindingRelocation {
                    ordinal: DirectBindingOrdinal::claimed(1),
                    adrp_offset: 396,
                    add_offset: 400,
                    miss_adrp_offset: 484,
                    miss_add_offset: 488,
                    data_offset: 8,
                },
            ],
        }
    }

    #[test]
    fn v3_view_is_lossless_against_the_owned_manifest() {
        let manifest = mapped_manifest_fixture();
        let encoded = encode_translation_metadata_v3(&manifest).expect("encode V3 fixture");
        let mapped = ValidatedMappedTranslationMetadata::new(
            Arc::new(VecMetadataBacking::new(encoded)),
            &manifest.key,
        )
        .expect("validate V3 fixture");

        assert_eq!(mapped.key(), &manifest.key);
        assert_eq!(mapped.dylib_sha256(), manifest.dylib_sha256);
        assert_eq!(mapped.code_len(), manifest.code_len);
        assert_eq!(mapped.block_count(), manifest.blocks.len());
        for (index, owned) in manifest.blocks.iter().enumerate() {
            let block = mapped.block(index).expect("mapped block");
            let (pc, recovery, _) = owned
                .template
                .runtime_metadata(manifest.key.host_bias())
                .expect("owned metadata");
            assert_eq!(
                (
                    block.guest_start(),
                    block.generation_binding(),
                    block.entry_offset(),
                    block.code_len(),
                    block.requires_sensitive_metadata()
                ),
                (
                    owned.guest_start,
                    owned.generation_binding,
                    owned.entry_offset,
                    owned.code_len,
                    owned.requires_sensitive_metadata
                )
            );
            assert_eq!(block.pc_map().iter().collect::<Vec<_>>(), pc);
            for entry in &pc {
                assert_eq!(
                    block.pc_map().guest_for_cache(entry.cache),
                    Some(entry.guest)
                );
            }
            for entry in recovery {
                assert_eq!(
                    block
                        .recovery()
                        .action_for_cache(entry.cache)
                        .expect("decode recovery"),
                    Some(entry.action)
                );
            }
        }
        assert_eq!(
            mapped
                .block(0)
                .expect("first block")
                .guest_ranges()
                .collect::<Vec<_>>(),
            vec![GuestVa(0x4000)..GuestVa(0x4008)]
        );
        assert_eq!(
            mapped
                .block(0)
                .expect("first block")
                .recovery()
                .span_count(),
            1
        );
        assert_eq!(
            mapped
                .block(1)
                .expect("second block")
                .recovery()
                .span_count(),
            1
        );
        assert_eq!(mapped.binding_layout(), manifest.binding_layout);
        assert_eq!(mapped.binding_data_len(), manifest.binding_data_len);
        assert_eq!(mapped.cell_size(), manifest.cell_size);
        assert_eq!(mapped.binding_count(), manifest.bindings.len());
        for (index, owned) in manifest.bindings.iter().enumerate() {
            assert_eq!(
                mapped.binding(index).expect("binding").record(),
                owned.clone()
            );
            assert_eq!(
                mapped.binding(index).expect("binding").relocation(),
                manifest.binding_relocations[index]
            );
        }
        let edge = mapped.edge_group(0).expect("shared edge");
        assert_eq!(mapped.edge_group_count(), 1);
        assert_eq!(
            (edge.source(), edge.target()),
            (GuestVa(0x4000), GuestVa(0x9000))
        );
        assert_eq!(
            edge.members().collect::<Vec<_>>(),
            vec![
                DirectBindingOrdinal::claimed(0),
                DirectBindingOrdinal::claimed(1)
            ]
        );
    }

    #[test]
    fn v3_view_rejects_each_semantic_corruption_with_a_typed_error() {
        let manifest = mapped_manifest_fixture();
        let encoded = encode_translation_metadata_v3(&manifest).expect("encode V3 fixture");
        for (name, corrupt, expected) in super::test_corruptions() {
            let mut bytes = encoded.clone();
            corrupt(&mut bytes);
            let error = ValidatedMappedTranslationMetadata::new(
                Arc::new(VecMetadataBacking::new(bytes)),
                &manifest.key,
            )
            .expect_err(name);
            assert_eq!(error, expected, "{name}");
        }
    }
}
