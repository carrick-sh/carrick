use std::collections::{BTreeMap, HashMap};

use zerocopy::byteorder::{U32, U64};
use zerocopy::{Immutable, IntoBytes, KnownLayout};

use crate::artifact_spike::PortableRecoveryMetadata;
use crate::emit::DirectLinkKind;
use crate::shared_cache::{
    AddressModeIdentity, DirectBindingLayout, ExecutableIdentity, NativePageProfileIdentity,
    TranslationUnitManifest,
};

use super::wire::{
    HEADER_SIZE_V3, MAPPED_METADATA_ENDIAN_MARKER_V3, MAPPED_METADATA_MAGIC_V3,
    MAPPED_METADATA_SCHEMA_V3, MappedMetadataError, SectionKind, WIRE_EXECUTABLE_DIGEST_V3,
    WIRE_EXECUTABLE_HOST_FILE_V3, WireBindingRelocationV3, WireBindingV3, WireBlockV3,
    WireDigestExecutableV3, WireEdgeGroupV3, WireEdgeMemberV3, WireGuestRangeV3, WireHeaderV3,
    WireHostFileExecutableV3, WirePcMapV3, WireRecoverySpanV3, WireSectionV3,
    WireTranslationUnitKeyV3,
};

pub fn encode_translation_metadata_v3(
    manifest: &TranslationUnitManifest,
) -> Result<Vec<u8>, MappedMetadataError> {
    manifest
        .validate_ranges()
        .map_err(|_| MappedMetadataError::OwnedManifest)?;
    if manifest.blocks.is_empty()
        || manifest
            .blocks
            .windows(2)
            .any(|pair| pair[0].entry_offset >= pair[1].entry_offset)
    {
        return Err(MappedMetadataError::OwnedManifest);
    }

    let mut block_bytes = Vec::new();
    let mut pc_bytes = Vec::new();
    let mut recovery_span_bytes = Vec::new();
    let mut recovery_action_bytes = Vec::new();
    let mut guest_range_bytes = Vec::new();
    let mut action_indexes = HashMap::<[u8; 48], u64>::new();
    let mut pc_count = 0_u64;
    let mut recovery_span_count = 0_u64;
    let mut recovery_action_count = 0_u64;
    let mut guest_range_count = 0_u64;

    for block in &manifest.blocks {
        let block_pc_start = pc_count;
        let map = block.template.pc_map_entries();
        validate_owned_pc_map(block.guest_start.raw(), block.code_len, map)?;
        for entry in map {
            push_record(
                &mut pc_bytes,
                &WirePcMapV3 {
                    guest: U64::new(entry.guest.raw()),
                    cache_offset: U32::new(entry.cache.get()),
                    reserved: U32::new(0),
                },
            );
            pc_count = pc_count
                .checked_add(1)
                .ok_or(MappedMetadataError::Arithmetic)?;
        }

        let block_recovery_start = recovery_span_count;
        match block.template.portable_recovery() {
            PortableRecoveryMetadata::Entries(entries) => {
                for entry in entries {
                    encode_recovery_span(
                        entry.cache().get(),
                        1,
                        entry.action(),
                        block.code_len,
                        &mut recovery_span_bytes,
                        &mut recovery_action_bytes,
                        &mut action_indexes,
                        &mut recovery_span_count,
                        &mut recovery_action_count,
                    )?;
                }
            }
            PortableRecoveryMetadata::Runs(runs) => {
                for run in runs {
                    encode_recovery_span(
                        run.start.get(),
                        run.entry_count.get(),
                        run.action,
                        block.code_len,
                        &mut recovery_span_bytes,
                        &mut recovery_action_bytes,
                        &mut action_indexes,
                        &mut recovery_span_count,
                        &mut recovery_action_count,
                    )?;
                }
            }
        }
        validate_span_order(
            &recovery_span_bytes,
            block_recovery_start,
            recovery_span_count,
        )?;

        let block_guest_range_start = guest_range_count;
        for (start, end) in exact_guest_ranges(map)? {
            push_record(
                &mut guest_range_bytes,
                &WireGuestRangeV3 {
                    start: U64::new(start),
                    end: U64::new(end),
                },
            );
            guest_range_count = guest_range_count
                .checked_add(1)
                .ok_or(MappedMetadataError::Arithmetic)?;
        }
        push_record(
            &mut block_bytes,
            &WireBlockV3 {
                guest_start: U64::new(block.guest_start.raw()),
                generation_binding: U64::new(u64::from(block.generation_binding)),
                entry_offset: U32::new(block.entry_offset),
                code_len: U32::new(block.code_len),
                flags: U32::new(u32::from(block.requires_sensitive_metadata)),
                reserved: U32::new(0),
                pc_map_start: U64::new(block_pc_start),
                pc_map_count: U64::new(pc_count - block_pc_start),
                recovery_start: U64::new(block_recovery_start),
                recovery_count: U64::new(recovery_span_count - block_recovery_start),
                guest_range_start: U64::new(block_guest_range_start),
                guest_range_count: U64::new(guest_range_count - block_guest_range_start),
            },
        );
    }

    let mut binding_bytes = Vec::new();
    let mut relocation_bytes = Vec::new();
    let mut edge_group_bytes = Vec::new();
    let mut edge_member_bytes = Vec::new();
    let mut groups = BTreeMap::<(u64, u64), Vec<u32>>::new();
    for binding in &manifest.bindings {
        groups
            .entry((binding.source.raw(), binding.target.raw()))
            .or_default()
            .push(binding.ordinal.get());
    }
    let mut binding_member_indexes = vec![None; manifest.bindings.len()];
    let mut member_count = 0_u64;
    for ((source, target), members) in groups {
        let start = member_count;
        for ordinal in members {
            let binding_index =
                usize::try_from(ordinal).map_err(|_| MappedMetadataError::Binding)?;
            let slot = binding_member_indexes
                .get_mut(binding_index)
                .ok_or(MappedMetadataError::Binding)?;
            if slot.replace(member_count).is_some() {
                return Err(MappedMetadataError::EdgeBackReference);
            }
            push_record(
                &mut edge_member_bytes,
                &WireEdgeMemberV3 {
                    binding_ordinal: U32::new(ordinal),
                    reserved: U32::new(0),
                },
            );
            member_count = member_count
                .checked_add(1)
                .ok_or(MappedMetadataError::Arithmetic)?;
        }
        push_record(
            &mut edge_group_bytes,
            &WireEdgeGroupV3 {
                source: U64::new(source),
                target: U64::new(target),
                member_start: U64::new(start),
                member_count: U64::new(member_count - start),
            },
        );
    }
    for (index, binding) in manifest.bindings.iter().enumerate() {
        let edge_member_index =
            binding_member_indexes[index].ok_or(MappedMetadataError::EdgeBackReference)?;
        push_record(
            &mut binding_bytes,
            &WireBindingV3 {
                source: U64::new(binding.source.raw()),
                target: U64::new(binding.target.raw()),
                ordinal: U32::new(binding.ordinal.get()),
                kind: U32::new(binding_kind(binding.kind)),
                stub_start: U32::new(binding.stub_start),
                stub_end: U32::new(binding.stub_end),
                edge_member_index: U64::new(edge_member_index),
            },
        );
    }
    let mut relocations = vec![None; manifest.binding_relocations.len()];
    for relocation in &manifest.binding_relocations {
        let index = usize::try_from(relocation.ordinal.get())
            .map_err(|_| MappedMetadataError::BindingRelocation)?;
        let slot = relocations
            .get_mut(index)
            .ok_or(MappedMetadataError::BindingRelocation)?;
        if slot.replace(*relocation).is_some() {
            return Err(MappedMetadataError::BindingRelocation);
        }
    }
    for relocation in relocations {
        let relocation = relocation.ok_or(MappedMetadataError::BindingRelocation)?;
        push_record(
            &mut relocation_bytes,
            &WireBindingRelocationV3 {
                ordinal: U32::new(relocation.ordinal.get()),
                adrp_offset: U32::new(relocation.adrp_offset),
                add_offset: U32::new(relocation.add_offset),
                miss_adrp_offset: U32::new(relocation.miss_adrp_offset),
                miss_add_offset: U32::new(relocation.miss_add_offset),
                data_offset: U32::new(relocation.data_offset),
            },
        );
    }

    let sections = [
        (SectionKind::Block, block_bytes),
        (SectionKind::PcMap, pc_bytes),
        (SectionKind::RecoverySpan, recovery_span_bytes),
        (SectionKind::RecoveryAction, recovery_action_bytes),
        (SectionKind::GuestRange, guest_range_bytes),
        (SectionKind::Binding, binding_bytes),
        (SectionKind::BindingRelocation, relocation_bytes),
        (SectionKind::EdgeGroup, edge_group_bytes),
        (SectionKind::EdgeMember, edge_member_bytes),
    ];
    serialize_metadata(manifest, sections)
}

#[allow(clippy::too_many_arguments)]
fn encode_recovery_span(
    cache_offset: u32,
    entry_count: u32,
    action: crate::artifact_spike::PortableRecoveryAction,
    block_code_len: u32,
    span_bytes: &mut Vec<u8>,
    action_bytes: &mut Vec<u8>,
    action_indexes: &mut HashMap<[u8; 48], u64>,
    span_count: &mut u64,
    action_count: &mut u64,
) -> Result<(), MappedMetadataError> {
    let last = entry_count
        .checked_sub(1)
        .and_then(|count| count.checked_mul(4))
        .and_then(|delta| cache_offset.checked_add(delta))
        .ok_or(MappedMetadataError::RecoverySpan)?;
    if !cache_offset.is_multiple_of(4) || last >= block_code_len {
        return Err(MappedMetadataError::RecoverySpan);
    }
    let wire = action
        .encode_v3()
        .map_err(|_| MappedMetadataError::RecoveryAction)?;
    let key: [u8; 48] = wire
        .as_bytes()
        .try_into()
        .map_err(|_| MappedMetadataError::RecoveryAction)?;
    let action_index = if let Some(index) = action_indexes.get(&key) {
        *index
    } else {
        let index = *action_count;
        action_indexes.insert(key, index);
        push_record(action_bytes, &wire);
        *action_count = action_count
            .checked_add(1)
            .ok_or(MappedMetadataError::Arithmetic)?;
        index
    };
    push_record(
        span_bytes,
        &WireRecoverySpanV3 {
            cache_offset: U32::new(cache_offset),
            entry_count: U32::new(entry_count),
            action_index: U64::new(action_index),
        },
    );
    *span_count = span_count
        .checked_add(1)
        .ok_or(MappedMetadataError::Arithmetic)?;
    Ok(())
}

fn validate_owned_pc_map(
    guest_start: u64,
    code_len: u32,
    map: &[crate::emit::PcMapEntry],
) -> Result<(), MappedMetadataError> {
    if map.is_empty() {
        return Err(MappedMetadataError::PcMap);
    }
    let mut previous = None;
    let mut contains_start = false;
    for entry in map {
        let cache = entry.cache.get();
        if !cache.is_multiple_of(4)
            || cache >= code_len
            || previous.is_some_and(|previous| previous >= cache)
            || !entry.guest.raw().is_multiple_of(4)
            || entry.guest.raw().checked_add(4).is_none()
        {
            return Err(MappedMetadataError::PcMap);
        }
        contains_start |= entry.guest.raw() == guest_start;
        previous = Some(cache);
    }
    if !contains_start {
        return Err(MappedMetadataError::PcMap);
    }
    Ok(())
}

fn exact_guest_ranges(
    map: &[crate::emit::PcMapEntry],
) -> Result<Vec<(u64, u64)>, MappedMetadataError> {
    let mut guests = map
        .iter()
        .map(|entry| entry.guest.raw())
        .collect::<Vec<_>>();
    guests.sort_unstable();
    guests.dedup();
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for guest in guests {
        let end = guest
            .checked_add(4)
            .ok_or(MappedMetadataError::GuestRange)?;
        if let Some(previous) = ranges.last_mut()
            && previous.1 == guest
        {
            previous.1 = end;
        } else {
            ranges.push((guest, end));
        }
    }
    Ok(ranges)
}

fn validate_span_order(bytes: &[u8], start: u64, end: u64) -> Result<(), MappedMetadataError> {
    let mut previous_end = None;
    for index in start..end {
        let record = record::<WireRecoverySpanV3>(bytes, index, SectionKind::RecoverySpan)?;
        let span_end = record
            .entry_count
            .get()
            .checked_mul(4)
            .and_then(|length| record.cache_offset.get().checked_add(length))
            .ok_or(MappedMetadataError::RecoverySpan)?;
        if previous_end.is_some_and(|previous| previous > record.cache_offset.get()) {
            return Err(MappedMetadataError::RecoverySpan);
        }
        previous_end = Some(span_end);
    }
    Ok(())
}

fn serialize_metadata(
    manifest: &TranslationUnitManifest,
    sections: [(SectionKind, Vec<u8>); 9],
) -> Result<Vec<u8>, MappedMetadataError> {
    let zero = WireSectionV3 {
        kind: U32::new(0),
        stride: U32::new(0),
        offset: U64::new(0),
        byte_len: U64::new(0),
        count: U64::new(0),
        reserved: U64::new(0),
    };
    let mut directory = [zero; 9];
    let mut offset = u64::try_from(HEADER_SIZE_V3).map_err(|_| MappedMetadataError::Arithmetic)?;
    for (slot, (kind, bytes)) in directory.iter_mut().zip(&sections) {
        let byte_len = u64::try_from(bytes.len()).map_err(|_| MappedMetadataError::Arithmetic)?;
        let stride = kind.record_stride();
        let count = byte_len
            .checked_div(u64::from(stride))
            .ok_or(MappedMetadataError::Arithmetic)?;
        *slot = WireSectionV3 {
            kind: U32::new(kind.raw()),
            stride: U32::new(stride),
            offset: U64::new(offset),
            byte_len: U64::new(byte_len),
            count: U64::new(count),
            reserved: U64::new(0),
        };
        offset = offset
            .checked_add(byte_len)
            .ok_or(MappedMetadataError::Arithmetic)?;
    }
    let key = wire_key(&manifest.key)?;
    let header = WireHeaderV3 {
        magic: MAPPED_METADATA_MAGIC_V3,
        schema: U32::new(MAPPED_METADATA_SCHEMA_V3),
        endian_marker: U32::new(MAPPED_METADATA_ENDIAN_MARKER_V3),
        header_size: U32::new(
            u32::try_from(HEADER_SIZE_V3).map_err(|_| MappedMetadataError::Arithmetic)?,
        ),
        reserved: U32::new(0),
        total_len: U64::new(offset),
        key,
        dylib_sha256: manifest.dylib_sha256,
        code_len: U64::new(manifest.code_len),
        binding_data_len: U64::new(manifest.binding_data_len),
        binding_layout: U32::new(binding_layout(manifest.binding_layout)),
        cell_size: U32::new(manifest.cell_size),
        binding_reserved: U64::new(0),
        sections: directory,
    };
    let capacity = usize::try_from(offset).map_err(|_| MappedMetadataError::Arithmetic)?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(header.as_bytes());
    for (_, bytes) in sections {
        output.extend_from_slice(&bytes);
    }
    Ok(output)
}

pub(crate) fn wire_key(
    key: &crate::shared_cache::TranslationUnitKey,
) -> Result<WireTranslationUnitKeyV3, MappedMetadataError> {
    let (executable_kind, host_file, digest) = match key.executable() {
        ExecutableIdentity::HostFile {
            device,
            inode,
            size,
            mtime_seconds,
            mtime_nanoseconds,
        } => (
            WIRE_EXECUTABLE_HOST_FILE_V3,
            WireHostFileExecutableV3 {
                device: U64::new(*device),
                inode: U64::new(*inode),
                size: U64::new(*size),
                mtime_seconds: zerocopy::byteorder::I64::new(*mtime_seconds),
                mtime_nanoseconds: zerocopy::byteorder::I64::new(*mtime_nanoseconds),
            },
            WireDigestExecutableV3 {
                digest: [0; 32],
                reserved: [0; 8],
            },
        ),
        ExecutableIdentity::Digest(value) => (
            WIRE_EXECUTABLE_DIGEST_V3,
            WireHostFileExecutableV3 {
                device: U64::new(0),
                inode: U64::new(0),
                size: U64::new(0),
                mtime_seconds: zerocopy::byteorder::I64::new(0),
                mtime_nanoseconds: zerocopy::byteorder::I64::new(0),
            },
            WireDigestExecutableV3 {
                digest: *value,
                reserved: [0; 8],
            },
        ),
    };
    let (address_mode, host_bias) = match key.address_mode() {
        AddressModeIdentity::Direct => (0, 0),
        AddressModeIdentity::Biased { .. } => (1, key.host_bias().ok_or(MappedMetadataError::Key)?),
    };
    Ok(WireTranslationUnitKeyV3 {
        executable_kind: U32::new(executable_kind),
        page_profile: U32::new(match key.page_profile() {
            NativePageProfileIdentity::Native16k => 0,
            NativePageProfileIdentity::Linux4kOn16k => 1,
        }),
        address_mode: U32::new(address_mode),
        translator_abi: U32::new(key.translator_abi()),
        segment_file_offset: U64::new(key.segment_file_offset().get()),
        segment_file_len: U64::new(key.segment_file_len().get()),
        guest_va_start: U64::new(key.guest_va_start().raw()),
        guest_va_len: U64::new(key.guest_va_len().get()),
        host_bias: U64::new(host_bias),
        host_file,
        digest,
        source_fingerprint: key.source_fingerprint().0,
    })
}

fn binding_layout(layout: DirectBindingLayout) -> u32 {
    match layout {
        DirectBindingLayout::Disabled => 0,
        DirectBindingLayout::SidecarV1 => 1,
    }
}
fn binding_kind(kind: DirectLinkKind) -> u32 {
    match kind {
        DirectLinkKind::Branch => 0,
        DirectLinkKind::Call => 1,
        DirectLinkKind::ConditionalTaken => 2,
        DirectLinkKind::ConditionalFallthrough => 3,
        DirectLinkKind::Continue => 4,
    }
}

fn push_record<T: IntoBytes + Immutable + ?Sized>(bytes: &mut Vec<u8>, record: &T) {
    bytes.extend_from_slice(record.as_bytes());
}

fn record<T: zerocopy::FromBytes + KnownLayout + Immutable>(
    bytes: &[u8],
    index: u64,
    kind: SectionKind,
) -> Result<&T, MappedMetadataError> {
    let stride = std::mem::size_of::<T>();
    let start = usize::try_from(index)
        .ok()
        .and_then(|value| value.checked_mul(stride))
        .ok_or(MappedMetadataError::Arithmetic)?;
    let end = start
        .checked_add(stride)
        .ok_or(MappedMetadataError::Arithmetic)?;
    T::ref_from_bytes(
        bytes
            .get(start..end)
            .ok_or(MappedMetadataError::SectionBounds {
                kind,
                end: u64::try_from(end).map_err(|_| MappedMetadataError::Arithmetic)?,
                total: u64::try_from(bytes.len()).map_err(|_| MappedMetadataError::Arithmetic)?,
            })?,
    )
    .map_err(|_| MappedMetadataError::Arithmetic)
}

#[cfg(test)]
mod tests {
    use super::encode_translation_metadata_v3;

    #[test]
    fn v3_encoder_rejects_an_invalid_owned_manifest() {
        let mut manifest = super::super::view::tests::mapped_manifest_fixture();
        manifest.code_len = 0;

        assert_eq!(
            encode_translation_metadata_v3(&manifest),
            Err(super::super::MappedMetadataError::OwnedManifest)
        );
    }
}
