const SVC_ZERO: u32 = 0xd400_0001;
const B_OPCODE: u32 = 0x1400_0000;
const B_IMMEDIATE_MASK: u32 = 0x03ff_ffff;
const B_MIN_DELTA: i128 = -(128 * 1024 * 1024);
const B_MAX_DELTA: i128 = (128 * 1024 * 1024) - 4;
pub(crate) const ISLAND_STUB_SIZE: u64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PatchSite {
    pub guest_va: u64,
    pub original: u32,
    pub replacement: u32,
    pub island_va: u64,
    pub return_branch: u32,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum PatchError {
    #[error("instruction address 0x{0:x} is not four-byte aligned")]
    UnalignedAddress(u64),
    #[error("island at 0x{target:x} is outside B range of patch site 0x{site:x}")]
    IslandOutOfRange { site: u64, target: u64 },
    #[error("guest virtual address overflow while scanning executable text")]
    AddressOverflow,
}

pub(crate) fn encode_b(site: u64, target: u64) -> Result<u32, PatchError> {
    if !site.is_multiple_of(4) {
        return Err(PatchError::UnalignedAddress(site));
    }
    if !target.is_multiple_of(4) {
        return Err(PatchError::UnalignedAddress(target));
    }

    let delta = i128::from(target) - i128::from(site);
    if !(B_MIN_DELTA..=B_MAX_DELTA).contains(&delta) {
        return Err(PatchError::IslandOutOfRange { site, target });
    }
    let immediate = (delta / 4) as i64 as u64;
    Ok(B_OPCODE | ((immediate as u32) & B_IMMEDIATE_MASK))
}

pub(crate) fn patch_svc_zero(
    text: &mut [u8],
    text_guest_va: u64,
    island_guest_va: u64,
) -> Result<Vec<PatchSite>, PatchError> {
    if !text_guest_va.is_multiple_of(4) {
        return Err(PatchError::UnalignedAddress(text_guest_va));
    }
    let mut manifest = Vec::new();
    let mut skipped_until_word = 0usize;
    for (word_index, bytes) in text.chunks_exact(4).enumerate() {
        let original = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let skipped_by_forward_branch = word_index < skipped_until_word;
        if !skipped_by_forward_branch && original & !B_IMMEDIATE_MASK == B_OPCODE {
            let immediate = original & B_IMMEDIATE_MASK;
            // imm26 is signed. A positive unconditional branch creates a
            // branch-over region which may contain executable-section literal
            // data. Do not interpret words in that region as instructions.
            if immediate != 0 && immediate & (1 << 25) == 0 {
                let branch_target = word_index
                    .checked_add(immediate as usize)
                    .ok_or(PatchError::AddressOverflow)?;
                skipped_until_word = skipped_until_word.max(branch_target);
            }
        }
        if original != SVC_ZERO || skipped_by_forward_branch {
            continue;
        }
        let byte_offset = u64::try_from(word_index)
            .ok()
            .and_then(|index| index.checked_mul(4))
            .ok_or(PatchError::AddressOverflow)?;
        let guest_va = text_guest_va
            .checked_add(byte_offset)
            .ok_or(PatchError::AddressOverflow)?;
        let stub_offset = u64::try_from(manifest.len())
            .ok()
            .and_then(|index| index.checked_mul(ISLAND_STUB_SIZE))
            .ok_or(PatchError::AddressOverflow)?;
        let island_va = island_guest_va
            .checked_add(stub_offset)
            .ok_or(PatchError::AddressOverflow)?;
        let return_site = guest_va.checked_add(4).ok_or(PatchError::AddressOverflow)?;
        let return_branch_pc = island_va
            .checked_add(4)
            .ok_or(PatchError::AddressOverflow)?;
        let replacement = encode_b(guest_va, island_va)?;
        let return_branch = encode_b(return_branch_pc, return_site)?;
        manifest.push(PatchSite {
            guest_va,
            original,
            replacement,
            island_va,
            return_branch,
        });
    }

    for site in &manifest {
        let offset = usize::try_from(site.guest_va - text_guest_va)
            .map_err(|_| PatchError::AddressOverflow)?;
        let destination = text
            .get_mut(offset..offset + 4)
            .ok_or(PatchError::AddressOverflow)?;
        destination.copy_from_slice(&site.replacement.to_le_bytes());
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SVC_ZERO: u32 = 0xd400_0001;

    fn words(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn patches_only_svc_zero_and_records_a_manifest() {
        let mut text = words(&[0xd503_201f, SVC_ZERO, 0xd400_0021, SVC_ZERO]);
        let manifest = patch_svc_zero(&mut text, 0x1000, 0x8000).expect("patch text");

        assert_eq!(manifest.len(), 2);
        assert_eq!(manifest[0].guest_va, 0x1004);
        assert_eq!(manifest[0].original, SVC_ZERO);
        assert_eq!(manifest[0].replacement, 0x1400_1bff);
        assert_eq!(manifest[0].island_va, 0x8000);
        assert_eq!(manifest[0].return_branch, encode_b(0x8004, 0x1008).unwrap());
        assert_eq!(manifest[1].guest_va, 0x100c);
        assert_eq!(manifest[1].island_va, 0x8008);
        assert_eq!(
            u32::from_le_bytes(text[8..12].try_into().unwrap()),
            0xd400_0021
        );
    }

    #[test]
    fn preserves_svc_shaped_data_skipped_by_a_forward_branch() {
        let branch_over_literal = encode_b(0x1000, 0x1008).expect("forward branch");
        let mut text = words(&[branch_over_literal, SVC_ZERO, 0xd65f_03c0]);

        let manifest = patch_svc_zero(&mut text, 0x1000, 0x8000).expect("scan text");

        assert!(manifest.is_empty());
        assert_eq!(u32::from_le_bytes(text[4..8].try_into().unwrap()), SVC_ZERO);
    }

    #[test]
    fn encodes_forward_and_backward_b_at_range_edges() {
        assert_eq!(encode_b(0x1000, 0x1004).unwrap(), 0x1400_0001);
        assert_eq!(encode_b(0x1004, 0x1000).unwrap(), 0x17ff_ffff);
        assert!(encode_b(0, (128 * 1024 * 1024) - 4).is_ok());
        assert!(encode_b(128 * 1024 * 1024, 0).is_ok());
        assert!(encode_b(0, 128 * 1024 * 1024).is_err());
        assert!(encode_b((128 * 1024 * 1024) + 4, 0).is_err());
    }

    #[test]
    fn rejects_unaligned_addresses_but_preserves_trailing_region_bytes() {
        assert!(encode_b(0x1002, 0x2000).is_err());
        assert!(encode_b(0x1000, 0x2002).is_err());
        let mut text = words(&[SVC_ZERO]);
        text.push(0xaa);
        let manifest = patch_svc_zero(&mut text, 0x1000, 0x2000).expect("patch complete words");
        assert_eq!(manifest.len(), 1);
        assert_eq!(text[4], 0xaa);
    }

    #[test]
    fn patched_syscall_branch_does_not_write_the_guest_link_register() {
        let mut text = words(&[SVC_ZERO]);
        let manifest = patch_svc_zero(&mut text, 0x1000, 0x2000).unwrap();
        let opcode = manifest[0].replacement;

        assert_eq!(opcode & 0xfc00_0000, 0x1400_0000, "must encode B");
        assert_ne!(opcode & 0xfc00_0000, 0x9400_0000, "BL clobbers x30");
    }

    #[test]
    fn rejects_an_island_outside_every_patched_sites_branch_range() {
        let mut text = words(&[SVC_ZERO]);
        let error = patch_svc_zero(&mut text, 0x1000, 0x1000 + (128 * 1024 * 1024))
            .expect_err("out-of-range island");
        assert!(error.to_string().contains("outside B range"));
        assert_eq!(u32::from_le_bytes(text.try_into().unwrap()), SVC_ZERO);
    }
}
