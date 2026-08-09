pub(crate) const ISLAND_PAGE_SIZE: usize = 4096;

const SVC_ZERO: u32 = 0xd400_0001;

pub(crate) fn passthrough_island_bytes(
    manifest: &[super::patcher::PatchSite],
) -> Result<Vec<u8>, super::patcher::PatchError> {
    let required = manifest
        .len()
        .saturating_mul(super::patcher::ISLAND_STUB_SIZE as usize);
    let size = required
        .max(ISLAND_PAGE_SIZE)
        .next_multiple_of(ISLAND_PAGE_SIZE);
    let mut bytes = vec![0; size];
    let base = manifest.first().map_or(0, |site| site.island_va);
    for site in manifest {
        let offset = usize::try_from(
            site.island_va
                .checked_sub(base)
                .ok_or(super::patcher::PatchError::AddressOverflow)?,
        )
        .map_err(|_| super::patcher::PatchError::AddressOverflow)?;
        let stub = bytes
            .get_mut(offset..offset + super::patcher::ISLAND_STUB_SIZE as usize)
            .ok_or(super::patcher::PatchError::AddressOverflow)?;
        stub[0..4].copy_from_slice(&SVC_ZERO.to_le_bytes());
        stub[4..8].copy_from_slice(&site.return_branch.to_le_bytes());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_one_island_has_one_svc_and_non_linking_return_per_patch_site() {
        let mut text = 0xd400_0001u32.to_le_bytes();
        let manifest = crate::hvpatch::patcher::patch_svc_zero(&mut text, 0x1000, 0x2000)
            .expect("patch one site");
        let bytes = passthrough_island_bytes(&manifest).expect("build one island");
        assert_eq!(bytes.len(), ISLAND_PAGE_SIZE);
        assert_eq!(
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            0xd400_0001
        );
        assert_eq!(
            u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            crate::hvpatch::patcher::encode_b(0x2004, 0x1004).unwrap()
        );
        assert!(bytes[8..].iter().all(|byte| *byte == 0));
    }
}
