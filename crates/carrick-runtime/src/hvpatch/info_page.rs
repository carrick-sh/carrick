pub(crate) const INFO_PAGE_BASE: u64 = carrick_mem::memory::LINUX_INFO_PAGE_BASE;
pub(crate) const INFO_PAGE_SIZE: usize = 4096;

#[allow(dead_code)]
pub(crate) const INFO_PAGE_OFF_PID: u64 = carrick_mem::memory::INFO_PAGE_OFF_PID;
#[allow(dead_code)]
pub(crate) const INFO_PAGE_OFF_TID: u64 = carrick_mem::memory::INFO_PAGE_OFF_TID;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InfoPage {
    pub tpidr_el0: u64,
    pub pid: u32,
    pub tid: u32,
    pub ctr_el0: u64,
    pub dczid_el0: u64,
    pub reserved: u64,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub ppid: u32,
    pub _pad: u32,
}

pub(crate) fn info_page_bytes(page: InfoPage) -> Vec<u8> {
    let mut bytes = vec![0; INFO_PAGE_SIZE];
    bytes[0..8].copy_from_slice(&page.tpidr_el0.to_le_bytes());
    bytes[8..12].copy_from_slice(&page.pid.to_le_bytes());
    bytes[12..16].copy_from_slice(&page.tid.to_le_bytes());
    bytes[16..24].copy_from_slice(&page.ctr_el0.to_le_bytes());
    bytes[24..32].copy_from_slice(&page.dczid_el0.to_le_bytes());
    bytes[32..40].copy_from_slice(&page.reserved.to_le_bytes());
    bytes[40..44].copy_from_slice(&page.uid.to_le_bytes());
    bytes[44..48].copy_from_slice(&page.gid.to_le_bytes());
    bytes[48..52].copy_from_slice(&page.euid.to_le_bytes());
    bytes[52..56].copy_from_slice(&page.egid.to_le_bytes());
    bytes[56..60].copy_from_slice(&page.ppid.to_le_bytes());
    bytes[60..64].copy_from_slice(&page._pad.to_le_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_page_layout_is_stable_and_fits_one_linux_page() {
        assert_eq!(std::mem::size_of::<InfoPage>(), 64);
        assert_eq!(std::mem::offset_of!(InfoPage, tpidr_el0), 0);
        assert_eq!(std::mem::offset_of!(InfoPage, pid), 8);
        assert_eq!(std::mem::offset_of!(InfoPage, tid), 12);
        assert_eq!(std::mem::offset_of!(InfoPage, ctr_el0), 16);
        assert_eq!(std::mem::offset_of!(InfoPage, dczid_el0), 24);
        assert_eq!(std::mem::offset_of!(InfoPage, reserved), 32);
        assert_eq!(std::mem::offset_of!(InfoPage, uid), 40);
        assert_eq!(std::mem::offset_of!(InfoPage, gid), 44);
        assert_eq!(std::mem::offset_of!(InfoPage, euid), 48);
        assert_eq!(std::mem::offset_of!(InfoPage, egid), 52);
        assert_eq!(std::mem::offset_of!(InfoPage, ppid), 56);
        assert_eq!(std::mem::offset_of!(InfoPage, _pad), 60);
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
            uid: 1000,
            gid: 1001,
            euid: 1002,
            egid: 1003,
            ppid: 1,
            _pad: 0,
        };
        let bytes = info_page_bytes(page);

        assert_eq!(&bytes[0..8], &page.tpidr_el0.to_le_bytes());
        assert_eq!(&bytes[8..12], &page.pid.to_le_bytes());
        assert_eq!(&bytes[12..16], &page.tid.to_le_bytes());
        assert_eq!(&bytes[16..24], &page.ctr_el0.to_le_bytes());
        assert_eq!(&bytes[24..32], &page.dczid_el0.to_le_bytes());
        assert_eq!(&bytes[40..44], &page.uid.to_le_bytes());
        assert_eq!(&bytes[44..48], &page.gid.to_le_bytes());
        assert_eq!(&bytes[48..52], &page.euid.to_le_bytes());
        assert_eq!(&bytes[52..56], &page.egid.to_le_bytes());
        assert_eq!(&bytes[56..60], &page.ppid.to_le_bytes());
        assert!(bytes[64..].iter().all(|byte| *byte == 0));
    }
}
