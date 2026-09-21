pub(crate) const ISLAND_PAGE_SIZE: usize = 4096;

const SVC_ZERO: u32 = 0xd400_0001;
const MRS_X0_TPIDRRO_EL0: u32 = 0xd53b_d060;
const MOV_W0_W0: u32 = 0x2a00_03e0;
const LSR_X0_X0_32: u32 = 0xd360_fc00;
const CBZ_X0_PLUS_12: u32 = 0xb400_0060;
const CBZ_X0_PLUS_20: u32 = 0xb400_00a0;
const MOVZ_X0_FFFF_LSL16: u32 = 0xd2bf_ffe0;
const MOVK_X0_002C_LSL32: u32 = 0xf2c0_0580;
const NOP: u32 = 0xd503_201f;

#[inline]
fn enc_ldr_w0_x0(off: u64) -> u32 {
    0xb940_0000 | (((off as u32 / 4) & 0xfff) << 10)
}

fn emit_info_page_stub(
    stub: &mut [u8],
    offset: u64,
    site_island_va: u64,
    return_site: u64,
) -> Result<(), super::patcher::PatchError> {
    let fast_ret = super::patcher::encode_b(site_island_va + 20, return_site)?;
    let fallback_ret = super::patcher::encode_b(site_island_va + 28, return_site)?;
    let ldr_w0 = enc_ldr_w0_x0(offset);
    stub[0..4].copy_from_slice(&MRS_X0_TPIDRRO_EL0.to_le_bytes());
    stub[4..8].copy_from_slice(&CBZ_X0_PLUS_20.to_le_bytes());
    stub[8..12].copy_from_slice(&MOVZ_X0_FFFF_LSL16.to_le_bytes());
    stub[12..16].copy_from_slice(&MOVK_X0_002C_LSL32.to_le_bytes());
    stub[16..20].copy_from_slice(&ldr_w0.to_le_bytes());
    stub[20..24].copy_from_slice(&fast_ret.to_le_bytes());
    stub[24..28].copy_from_slice(&SVC_ZERO.to_le_bytes());
    stub[28..32].copy_from_slice(&fallback_ret.to_le_bytes());
    Ok(())
}

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

        let return_site = site
            .guest_va
            .checked_add(4)
            .ok_or(super::patcher::PatchError::AddressOverflow)?;

        match site.syscall_kind {
            super::patcher::SyscallSiteKind::Direct(178) => {
                // gettid:
                let fast_ret = super::patcher::encode_b(site.island_va + 12, return_site)?;
                let fallback_ret = super::patcher::encode_b(site.island_va + 24, return_site)?;
                stub[0..4].copy_from_slice(&MRS_X0_TPIDRRO_EL0.to_le_bytes());
                stub[4..8].copy_from_slice(&MOV_W0_W0.to_le_bytes());
                stub[8..12].copy_from_slice(&CBZ_X0_PLUS_12.to_le_bytes());
                stub[12..16].copy_from_slice(&fast_ret.to_le_bytes());
                stub[16..20].copy_from_slice(&NOP.to_le_bytes());
                stub[20..24].copy_from_slice(&SVC_ZERO.to_le_bytes());
                stub[24..28].copy_from_slice(&fallback_ret.to_le_bytes());
                stub[28..32].copy_from_slice(&NOP.to_le_bytes());
            }
            super::patcher::SyscallSiteKind::Direct(172) => {
                // getpid:
                let fast_ret = super::patcher::encode_b(site.island_va + 12, return_site)?;
                let fallback_ret = super::patcher::encode_b(site.island_va + 24, return_site)?;
                stub[0..4].copy_from_slice(&MRS_X0_TPIDRRO_EL0.to_le_bytes());
                stub[4..8].copy_from_slice(&LSR_X0_X0_32.to_le_bytes());
                stub[8..12].copy_from_slice(&CBZ_X0_PLUS_12.to_le_bytes());
                stub[12..16].copy_from_slice(&fast_ret.to_le_bytes());
                stub[16..20].copy_from_slice(&NOP.to_le_bytes());
                stub[20..24].copy_from_slice(&SVC_ZERO.to_le_bytes());
                stub[24..28].copy_from_slice(&fallback_ret.to_le_bytes());
                stub[28..32].copy_from_slice(&NOP.to_le_bytes());
            }
            super::patcher::SyscallSiteKind::Direct(173) => {
                // getppid:
                emit_info_page_stub(
                    stub,
                    super::info_page::INFO_PAGE_OFF_PPID,
                    site.island_va,
                    return_site,
                )?;
            }
            super::patcher::SyscallSiteKind::Direct(174) => {
                // getuid:
                emit_info_page_stub(
                    stub,
                    super::info_page::INFO_PAGE_OFF_UID,
                    site.island_va,
                    return_site,
                )?;
            }
            super::patcher::SyscallSiteKind::Direct(175) => {
                // geteuid:
                emit_info_page_stub(
                    stub,
                    super::info_page::INFO_PAGE_OFF_EUID,
                    site.island_va,
                    return_site,
                )?;
            }
            super::patcher::SyscallSiteKind::Direct(176) => {
                // getgid:
                emit_info_page_stub(
                    stub,
                    super::info_page::INFO_PAGE_OFF_GID,
                    site.island_va,
                    return_site,
                )?;
            }
            super::patcher::SyscallSiteKind::Direct(177) => {
                // getegid:
                emit_info_page_stub(
                    stub,
                    super::info_page::INFO_PAGE_OFF_EGID,
                    site.island_va,
                    return_site,
                )?;
            }
            _ => {
                stub[0..4].copy_from_slice(&SVC_ZERO.to_le_bytes());
                stub[4..8].copy_from_slice(&site.return_branch.to_le_bytes());
            }
        }
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

    #[test]
    fn generates_smart_island_for_getpid() {
        let mut text = Vec::new();
        // movz x8, #172 (getpid)
        text.extend_from_slice(&(0xd280_0008u32 | (172 << 5)).to_le_bytes());
        // svc #0
        text.extend_from_slice(&0xd400_0001u32.to_le_bytes());
        let manifest = crate::hvpatch::patcher::patch_svc_zero(&mut text, 0x1000, 0x2000)
            .expect("patch one site");
        assert_eq!(manifest.len(), 1);
        assert_eq!(
            manifest[0].syscall_kind,
            crate::hvpatch::patcher::SyscallSiteKind::Direct(172)
        );

        let bytes = passthrough_island_bytes(&manifest).expect("build one island");
        assert_eq!(bytes.len(), ISLAND_PAGE_SIZE);

        let rd = |start: usize| u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap());
        assert_eq!(rd(0), MRS_X0_TPIDRRO_EL0);
        assert_eq!(rd(4), LSR_X0_X0_32);
        assert_eq!(rd(8), CBZ_X0_PLUS_12);
        assert_eq!(
            rd(12),
            crate::hvpatch::patcher::encode_b(0x200c, 0x1008).unwrap()
        );
        assert_eq!(rd(16), NOP);
        assert_eq!(rd(20), SVC_ZERO);
        assert_eq!(
            rd(24),
            crate::hvpatch::patcher::encode_b(0x2018, 0x1008).unwrap()
        );
        assert_eq!(rd(28), NOP);
        assert!(bytes[32..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn generates_smart_island_for_gettid() {
        let mut text = Vec::new();
        // movz w8, #178 (gettid)
        text.extend_from_slice(&(0x5280_0008u32 | (178 << 5)).to_le_bytes());
        // svc #0
        text.extend_from_slice(&0xd400_0001u32.to_le_bytes());
        let manifest = crate::hvpatch::patcher::patch_svc_zero(&mut text, 0x1000, 0x2000)
            .expect("patch one site");
        assert_eq!(manifest.len(), 1);
        assert_eq!(
            manifest[0].syscall_kind,
            crate::hvpatch::patcher::SyscallSiteKind::Direct(178)
        );

        let bytes = passthrough_island_bytes(&manifest).expect("build one island");
        assert_eq!(bytes.len(), ISLAND_PAGE_SIZE);

        let rd = |start: usize| u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap());
        assert_eq!(rd(0), MRS_X0_TPIDRRO_EL0);
        assert_eq!(rd(4), MOV_W0_W0);
        assert_eq!(rd(8), CBZ_X0_PLUS_12);
        assert_eq!(
            rd(12),
            crate::hvpatch::patcher::encode_b(0x200c, 0x1008).unwrap()
        );
        assert_eq!(rd(16), NOP);
        assert_eq!(rd(20), SVC_ZERO);
        assert_eq!(
            rd(24),
            crate::hvpatch::patcher::encode_b(0x2018, 0x1008).unwrap()
        );
        assert_eq!(rd(28), NOP);
        assert!(bytes[32..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn generates_smart_island_for_info_page_credentials() {
        for (nr, offset) in [
            (173u16, crate::hvpatch::info_page::INFO_PAGE_OFF_PPID),
            (174u16, crate::hvpatch::info_page::INFO_PAGE_OFF_UID),
            (175u16, crate::hvpatch::info_page::INFO_PAGE_OFF_EUID),
            (176u16, crate::hvpatch::info_page::INFO_PAGE_OFF_GID),
            (177u16, crate::hvpatch::info_page::INFO_PAGE_OFF_EGID),
        ] {
            let mut text = Vec::new();
            // movz x8, #nr
            text.extend_from_slice(&(0xd280_0008u32 | (u32::from(nr) << 5)).to_le_bytes());
            // svc #0
            text.extend_from_slice(&0xd400_0001u32.to_le_bytes());
            let manifest = crate::hvpatch::patcher::patch_svc_zero(&mut text, 0x1000, 0x2000)
                .expect("patch one site");
            assert_eq!(manifest.len(), 1);
            assert_eq!(
                manifest[0].syscall_kind,
                crate::hvpatch::patcher::SyscallSiteKind::Direct(nr)
            );

            let bytes = passthrough_island_bytes(&manifest).expect("build one island");
            assert_eq!(bytes.len(), ISLAND_PAGE_SIZE);

            let rd = |start: usize| u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap());
            assert_eq!(rd(0), MRS_X0_TPIDRRO_EL0);
            assert_eq!(rd(4), CBZ_X0_PLUS_20);
            assert_eq!(rd(8), MOVZ_X0_FFFF_LSL16);
            assert_eq!(rd(12), MOVK_X0_002C_LSL32);
            assert_eq!(rd(16), enc_ldr_w0_x0(offset));
            assert_eq!(
                rd(20),
                crate::hvpatch::patcher::encode_b(0x2014, 0x1008).unwrap()
            );
            assert_eq!(rd(24), SVC_ZERO);
            assert_eq!(
                rd(28),
                crate::hvpatch::patcher::encode_b(0x201c, 0x1008).unwrap()
            );
            assert!(bytes[32..].iter().all(|byte| *byte == 0));
        }
    }
}
