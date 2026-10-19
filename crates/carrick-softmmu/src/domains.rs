//! Typed address, privilege, and fault domains for the software MMU.

pub use carrick_guest_arch::{FrameGpa, GuestVa, RootGpa, UserVa};
pub use carrick_mmu_core::x86::descriptor_txn::{
    ACCESSED, ADDRESS, Access, COW, DEFAULT_MAX_PHY_ADDR, DIRTY, DescriptorRefusal, FaultClass,
    HUGE, HardwareFaultClass, HardwareWalkConfig, LeafSize, LiveDescriptorWords,
    MAX_AD_CAS_RETRIES, MAX_MAX_PHY_ADDR, MAY_EXEC, MAY_WRITE, MIN_MAX_PHY_ADDR, NX, PAGE,
    PAT_LARGE, PREPARED, PRESENT, PRIVATE, RETIRED, TranslatedLeaf, USER, WRITE,
    has_hardware_reserved_bits_when_present, reserved_phyaddr_mask, translate_leaf_hardware,
};

pub const PAGE_SHIFT_4K: u32 = 12;
pub const PAGE_SIZE_4K: u64 = PAGE;
pub const PAGE_OFFSET_MASK_4K: u64 = PAGE_SIZE_4K - 1;
pub const PAGE_BASE_MASK_4K: u64 = !PAGE_OFFSET_MASK_4K;


/// Unauthenticated stage-1 output guest physical address produced by a page-table walk.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Stage1Gpa(u64);

impl Stage1Gpa {
    pub(crate) const fn new(raw: u64) -> Self {
        Self(raw)
    }
    pub(crate) const fn from_leaf_page(leaf: &TranslatedLeaf) -> Self {
        Self(leaf.output.raw() & PAGE_BASE_MASK_4K)
    }
    pub(crate) const fn from_leaf_base(leaf: &TranslatedLeaf) -> Self {
        let sz = if leaf.size >= PAGE_SIZE_4K && leaf.size.is_power_of_two() {
            leaf.size
        } else {
            PAGE_SIZE_4K
        };
        Self(leaf.output.raw() & !(sz - 1))
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Extent-authenticated 4 KiB-aligned guest-physical frame address.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthenticatedGpa(u64);

impl AuthenticatedGpa {
    pub(crate) const fn from_authenticated_raw(raw: u64) -> Self {
        Self(raw & PAGE_BASE_MASK_4K)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Logical owner generation authenticating a physical frame extent against a live stage-1 walk.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OwnerGeneration(u64);

impl OwnerGeneration {
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// x86 current privilege level supported by Carrick's CPL0/CPL3 execution model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cpl {
    Ring0,
    Ring3,
}

impl Cpl {
    pub const fn from_cs_selector(cs: u16) -> Result<Self, u8> {
        Self::from_ring((cs & 0b11) as u8)
    }
    pub const fn from_ring(ring: u8) -> Result<Self, u8> {
        match ring {
            0 => Ok(Self::Ring0),
            3 => Ok(Self::Ring3),
            other => Err(other),
        }
    }
    pub const fn ring(self) -> u8 {
        if matches!(self, Self::Ring0) { 0 } else { 3 }
    }
    pub const fn is_user(self) -> bool {
        matches!(self, Self::Ring3)
    }
}

/// Architectural CPU paging and access context carried into soft-TLB lookups and page-table walks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CpuAccessMode {
    pub cpl: Cpl,
    pub ac: bool,
    pub cr0_wp: bool,
    pub cr4_smep: bool,
    pub cr4_smap: bool,
    pub efer_nxe: bool,
    pub stack_access: bool,
}

impl CpuAccessMode {
    pub const fn ring0(ac: bool) -> Self {
        Self {
            cpl: Cpl::Ring0,
            ac,
            cr0_wp: true,
            cr4_smep: true,
            cr4_smap: true,
            efer_nxe: true,
            stack_access: false,
        }
    }
    pub const fn ring3() -> Self {
        Self::ring3_with_ac(false)
    }
    pub const fn ring3_with_ac(ac: bool) -> Self {
        Self {
            cpl: Cpl::Ring3,
            ..Self::ring0(ac)
        }
    }
    pub const fn with_cr0_wp(mut self, cr0_wp: bool) -> Self {
        self.cr0_wp = cr0_wp;
        self
    }
    pub const fn with_cr4_smep(mut self, cr4_smep: bool) -> Self {
        self.cr4_smep = cr4_smep;
        self
    }
    pub const fn with_cr4_smap(mut self, cr4_smap: bool) -> Self {
        self.cr4_smap = cr4_smap;
        self
    }
    pub const fn with_efer_nxe(mut self, efer_nxe: bool) -> Self {
        self.efer_nxe = efer_nxe;
        self
    }
    pub const fn with_stack_access(mut self, stack_access: bool) -> Self {
        self.stack_access = stack_access;
        self
    }
}

/// Hardware `#PF` error-code bitmask delivered on x86 page faults (Intel SDM Vol. 3A §4.7).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PageFaultErrorCode(u32);

impl PageFaultErrorCode {
    pub const PRESENT: u32 = 1 << 0;
    pub const WRITE: u32 = 1 << 1;
    pub const USER: u32 = 1 << 2;
    pub const RESERVED_WRITE: u32 = 1 << 3;
    pub const INSTRUCTION_FETCH: u32 = 1 << 4;

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
    pub const fn for_page_fault(
        class: PageFaultClass,
        access: Access,
        mode: CpuAccessMode,
    ) -> Self {
        let mut bits = match class {
            PageFaultClass::NotPresent => 0,
            PageFaultClass::ReservedBit => Self::PRESENT | Self::RESERVED_WRITE,
            _ => Self::PRESENT,
        };
        if matches!(access, Access::Write) {
            bits |= Self::WRITE;
        }
        if mode.cpl.is_user() {
            bits |= Self::USER;
        }
        if matches!(access, Access::Execute) && (mode.efer_nxe || mode.cr4_smep) {
            bits |= Self::INSTRUCTION_FETCH;
        }
        Self(bits)
    }
    pub const fn bits(self) -> u32 {
        self.0
    }
    pub const fn bits_u64(self) -> u64 {
        self.0 as u64
    }
    pub const fn present(self) -> bool {
        self.0 & Self::PRESENT != 0
    }
    pub const fn write(self) -> bool {
        self.0 & Self::WRITE != 0
    }
    pub const fn user(self) -> bool {
        self.0 & Self::USER != 0
    }
    pub const fn reserved_bit(self) -> bool {
        self.0 & Self::RESERVED_WRITE != 0
    }
    pub const fn instruction_fetch(self) -> bool {
        self.0 & Self::INSTRUCTION_FETCH != 0
    }
}

/// Architectural `#PF` (IDT vector 14) classification (excludes non-canonical `#GP`/`#SS` and MMIO).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageFaultClass {
    NotPresent,
    Protection,
    NxProtection,
    SmapProtection,
    SmepProtection,
    ReservedBit,
    CowWrite,
}

pub type SoftFaultClass = PageFaultClass;

/// Architectural `#PF` (IDT vector 14) exception record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageFaultInfo {
    pub va: GuestVa,
    pub access: Access,
    pub mode: CpuAccessMode,
    pub class: PageFaultClass,
    pub error_code: PageFaultErrorCode,
    pub leaf: Option<TranslatedLeaf>,
}

impl PageFaultInfo {
    pub(crate) const fn new(
        va: GuestVa,
        access: Access,
        mode: CpuAccessMode,
        class: PageFaultClass,
        leaf: Option<TranslatedLeaf>,
    ) -> Self {
        Self {
            va,
            access,
            mode,
            class,
            error_code: PageFaultErrorCode::for_page_fault(class, access, mode),
            leaf,
        }
    }
}

/// Architectural x86 CPU exception raised by linear memory translation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoftCpuException {
    PageFault(PageFaultInfo),
    GeneralProtection0 { va: GuestVa, access: Access },
    StackSegment0 { va: GuestVa, access: Access },
}

/// Typed slow-path error returned when [`crate::walker::SoftWalker`] stops without resolving RAM or MMIO.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoftTranslationError {
    CpuException(SoftCpuException),
    DescriptorLoad {
        va: GuestVa,
        refusal: DescriptorRefusal,
    },
    AdCasRetryExhausted {
        va: GuestVa,
        retries: usize,
    },
    UnauthenticatedExtent {
        va: GuestVa,
        stage1_gpa: Stage1Gpa,
        expected_generation: Option<OwnerGeneration>,
        leaf: TranslatedLeaf,
    },
    Placement {
        va: GuestVa,
        frame_gpa: AuthenticatedGpa,
        error: crate::placement::PlacementError,
    },
}

impl SoftTranslationError {
    pub const fn as_page_fault(&self) -> Option<&PageFaultInfo> {
        match self {
            Self::CpuException(SoftCpuException::PageFault(pf)) => Some(pf),
            _ => None,
        }
    }
    pub const fn as_cpu_exception(&self) -> Option<&SoftCpuException> {
        match self {
            Self::CpuException(exc) => Some(exc),
            _ => None,
        }
    }
}
