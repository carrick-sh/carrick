//! Host-to-CPL0 initial-image request. All addresses are GPAs in retained
//! carrier memory; the guest validates each span before dereferencing its
//! supervisor direct alias. No host pointer crosses this record.

pub const X86_INITIAL_BOOT_MAGIC: u64 = u64::from_le_bytes(*b"CXRUN001");
pub const X86_INITIAL_BOOT_VERSION: u32 = 1;
pub const X86_INITIAL_BOOT_HEADER_GPA: u64 = 0x1e_0000;
pub const X86_INITIAL_BOOT_PORT: u16 = 0xc6;
pub const X86_INITIAL_MAX_REGIONS: usize = 32;
pub const X86_INITIAL_MAX_STRINGS: usize = 256;

pub const X86_INITIAL_BOOT_PENDING: u32 = 0;
pub const X86_INITIAL_BOOT_LOADED: u32 = 1;
pub const X86_INITIAL_BOOT_REFUSED: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct X86InitialBootHeader {
    pub magic: u64,
    pub version: u32,
    pub reserved: u32,
    pub entry_va: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct X86InitialBootRequest {
    pub magic: u64,
    pub version: u32,
    pub region_count: u32,
    pub entry: u64,
    pub phdr: u64,
    pub phent: u16,
    pub phnum: u16,
    pub argc: u16,
    pub envc: u16,
    pub regions_gpa: u64,
    pub strings_gpa: u64,
    pub grants_gpa: u64,
    pub table_grant_count: u32,
    pub data_grant_count: u32,
    pub publications_gpa: u64,
    pub publication_capacity: u32,
    pub publication_count: u32,
    pub stack_top: u64,
    pub stack_size: u64,
    pub random: [u8; 16],
    pub result_root_gpa: u64,
    pub result_rsp: u64,
    pub result_status: u32,
    pub extent_pages: u32,
    pub mm_key: u64,
    pub generation: u64,
    pub result_table_used: u32,
    pub result_data_used: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct X86InitialBootRegion {
    pub start: u64,
    pub len: u64,
    pub initialized_offset: u64,
    pub source_gpa: u64,
    pub initialized_len: u64,
    /// Bit 0 read, bit 1 write, bit 2 execute. User access is mandatory.
    pub permissions: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct X86InitialBootString {
    pub source_gpa: u64,
    pub len: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct X86InitialBootGrant {
    pub gpa: u64,
    pub frame_id: u64,
    pub mapping_id: u64,
    pub owner_generation: u64,
    pub inventory_revision: u64,
}

const _: () = {
    assert!(core::mem::size_of::<X86InitialBootHeader>() == 24);
    assert!(core::mem::size_of::<X86InitialBootRequest>() == 168);
    assert!(core::mem::align_of::<X86InitialBootRequest>() == 8);
    assert!(core::mem::offset_of!(X86InitialBootRequest, magic) == 0);
    assert!(core::mem::offset_of!(X86InitialBootRequest, region_count) == 12);
    assert!(core::mem::offset_of!(X86InitialBootRequest, regions_gpa) == 40);
    assert!(core::mem::offset_of!(X86InitialBootRequest, grants_gpa) == 56);
    assert!(core::mem::offset_of!(X86InitialBootRequest, publications_gpa) == 72);
    assert!(core::mem::offset_of!(X86InitialBootRequest, random) == 104);
    assert!(core::mem::offset_of!(X86InitialBootRequest, result_status) == 136);
    assert!(core::mem::offset_of!(X86InitialBootRequest, mm_key) == 144);
    assert!(core::mem::offset_of!(X86InitialBootRequest, result_table_used) == 160);
    assert!(core::mem::size_of::<X86InitialBootRegion>() == 48);
    assert!(core::mem::offset_of!(X86InitialBootRegion, source_gpa) == 24);
    assert!(core::mem::size_of::<X86InitialBootString>() == 16);
    assert!(core::mem::size_of::<X86InitialBootGrant>() == 40);
    assert!(core::mem::offset_of!(X86InitialBootGrant, inventory_revision) == 32);
};
