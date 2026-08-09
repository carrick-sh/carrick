pub(crate) const INFO_PAGE_BASE: u64 = 0x2c_ffff_0000;
pub(crate) const INFO_PAGE_SIZE: usize = 4096;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InfoPage {
    pub tpidr_el0: u64,
    pub pid: u32,
    pub tid: u32,
    pub ctr_el0: u64,
    pub dczid_el0: u64,
    pub reserved: u64,
}

pub(crate) fn info_page_bytes(page: InfoPage) -> Vec<u8> {
    let mut bytes = vec![0; INFO_PAGE_SIZE];
    bytes[0..8].copy_from_slice(&page.tpidr_el0.to_le_bytes());
    bytes[8..12].copy_from_slice(&page.pid.to_le_bytes());
    bytes[12..16].copy_from_slice(&page.tid.to_le_bytes());
    bytes[16..24].copy_from_slice(&page.ctr_el0.to_le_bytes());
    bytes[24..32].copy_from_slice(&page.dczid_el0.to_le_bytes());
    bytes[32..40].copy_from_slice(&page.reserved.to_le_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_one_layout_is_stable_and_fits_one_linux_page() {
        assert_eq!(std::mem::size_of::<InfoPage>(), 40);
        assert_eq!(std::mem::offset_of!(InfoPage, tpidr_el0), 0);
        assert_eq!(std::mem::offset_of!(InfoPage, pid), 8);
        assert_eq!(std::mem::offset_of!(InfoPage, tid), 12);
        assert_eq!(std::mem::offset_of!(InfoPage, ctr_el0), 16);
        assert_eq!(std::mem::offset_of!(InfoPage, dczid_el0), 24);
        assert_eq!(std::mem::offset_of!(InfoPage, reserved), 32);
        assert_eq!(info_page_bytes(InfoPage::default()).len(), INFO_PAGE_SIZE);
    }

    #[test]
    fn serializes_fields_little_endian_and_zero_fills_the_page() {
        let page = InfoPage {
            tpidr_el0: 0x1122_3344_5566_7788,
            pid: 42,
            tid: 43,
            ctr_el0: 0x99aa_bbcc_ddee_ff00,
            dczid_el0: 0x0102_0304_0506_0708,
            reserved: 0,
        };
        let bytes = info_page_bytes(page);

        assert_eq!(&bytes[0..8], &page.tpidr_el0.to_le_bytes());
        assert_eq!(&bytes[8..12], &page.pid.to_le_bytes());
        assert_eq!(&bytes[12..16], &page.tid.to_le_bytes());
        assert_eq!(&bytes[16..24], &page.ctr_el0.to_le_bytes());
        assert_eq!(&bytes[24..32], &page.dczid_el0.to_le_bytes());
        assert!(bytes[40..].iter().all(|byte| *byte == 0));
    }
}
