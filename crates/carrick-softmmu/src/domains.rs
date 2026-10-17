//! Typed address, privilege, and fault domains for the software MMU.
//!
//! In accordance with Carrick's typed-domain rules (`AGENTS.md`), guest virtual
//! addresses ([`GuestVa`]), stage-1 output guest physical addresses
//! ([`Stage1Gpa`]), frame inventory guest physical addresses ([`FrameGpa`]),
//! page-table roots ([`RootGpa`]), owner generations ([`OwnerGeneration`]), and
//! host virtual addresses ([`crate::placement::HostVa`]) remain distinct types
//! and are never cross-fed across lookups.

pub use carrick_guest_arch::{FrameGpa, RootGpa, UserVa};
pub use carrick_mmu_core::x86::descriptor_txn::{
    ADDRESS, Access, COW, DescriptorRefusal, FaultClass, HUGE, LeafSize, LiveDescriptorWords,
    MAY_EXEC, MAY_WRITE, NX, PAGE, PREPARED, PRESENT, PRIVATE, RETIRED, TranslatedLeaf, USER,
    WRITE,
};

/// 4 KiB page shift on x86_64.
pub const PAGE_SHIFT_4K: u32 = 12;

/// 4 KiB page size in bytes (`4096`).
pub const PAGE_SIZE_4K: u64 = PAGE;

/// 4 KiB page offset mask (`0xfff`).
pub const PAGE_OFFSET_MASK_4K: u64 = PAGE_SIZE_4K - 1;

/// 4 KiB page base mask (`!0xfff`).
pub const PAGE_BASE_MASK_4K: u64 = !PAGE_OFFSET_MASK_4K;

/// Guest linear virtual address (either lower-half user or upper-half CPL0 supervisor).
///
/// Kept distinct from [`Stage1Gpa`], [`FrameGpa`], [`RootGpa`], and
/// [`crate::placement::HostVa`] so a guest virtual address can never be passed
/// to [`crate::placement::LinearPlacement::host`] or used as a physical frame
/// lookup key.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuestVa(u64);

impl GuestVa {
    /// Wrap a raw 64-bit guest linear address.
    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Convert from a stage-1 [`UserVa`].
    #[inline]
    pub const fn from_user_va(va: UserVa) -> Self {
        Self(va.raw())
    }

    /// Return the raw 64-bit linear address.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Return the 4 KiB-aligned page base of this virtual address (`va & !0xfff`).
    #[inline]
    pub const fn page_base(self) -> u64 {
        self.0 & PAGE_BASE_MASK_4K
    }

    /// Return the byte offset within the 4 KiB page (`(va & 0xfff) as usize`).
    #[inline]
    pub const fn page_offset(self) -> usize {
        (self.0 & PAGE_OFFSET_MASK_4K) as usize
    }

    /// Return `true` when an access of `len` bytes starting at `self` crosses a
    /// 4 KiB page boundary (`len == 0` never crosses; `len > 4096` always crosses).
    #[inline]
    pub const fn crosses_page(self, len: usize) -> bool {
        if len == 0 {
            return false;
        }
        let offset = (self.0 & PAGE_OFFSET_MASK_4K) as usize;
        match offset.checked_add(len) {
            Some(end) => end > (PAGE_SIZE_4K as usize),
            None => true,
        }
    }

    /// Checked byte offset addition in the guest linear address domain.
    #[inline]
    pub const fn checked_add(self, offset: u64) -> Option<Self> {
        match self.0.checked_add(offset) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }

    /// Check whether this address is canonical under 48-bit 4-level IA-32e paging
    /// (bits `48..64` must all equal bit `47`).
    #[inline]
    pub const fn is_canonical_48bit(self) -> bool {
        let sign_extended = ((self.0 as i64) << 16 >> 16) as u64;
        sign_extended == self.0
    }

    /// Convert to the descriptor walker's [`UserVa`] input wrapper.
    #[inline]
    pub const fn to_descriptor_va(self) -> UserVa {
        UserVa::new(self.0)
    }
}

/// Unauthenticated stage-1 output guest physical address produced by a page-table walk.
///
/// Distinct from [`FrameGpa`]: [`crate::placement::LinearPlacement::host`] refuses
/// [`Stage1Gpa`] at compile time until [`crate::walker::ExtentTable::authenticate_leaf`]
/// verifies `(Stage1Gpa, OwnerGeneration)` and yields an authenticated [`FrameGpa`].
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Stage1Gpa(u64);

impl Stage1Gpa {
    /// Wrap a raw stage-1 output GPA.
    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Extract the unauthenticated stage-1 page-base GPA from a [`TranslatedLeaf`].
    #[inline]
    pub const fn from_leaf_page(leaf: &TranslatedLeaf) -> Self {
        Self(leaf.output.raw() & PAGE_BASE_MASK_4K)
    }

    /// Underlying 64-bit guest physical address.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Logical owner generation authenticating a physical frame extent against a live stage-1 walk.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OwnerGeneration(u64);

impl OwnerGeneration {
    /// Construct an [`OwnerGeneration`] token.
    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Underlying generation number.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// x86 current privilege level supported by Carrick's CPL0/CPL3 execution model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cpl {
    /// Supervisor ring (`CPL == 0`, executes the Carrick CPL0 ring image).
    Ring0,
    /// User ring (`CPL == 3`, executes unmodified Linux user binaries).
    Ring3,
}

impl Cpl {
    /// Decode a CPL from the low two RPL bits of `CS`.
    ///
    /// Returns `Err(rpl)` for unused rings 1 and 2 (`rpl == 1` or `rpl == 2`).
    #[inline]
    pub const fn from_cs_selector(cs: u16) -> Result<Self, u8> {
        Self::from_ring((cs & 0b11) as u8)
    }

    /// Decode a CPL from a numeric ring (`0` or `3`).
    #[inline]
    pub const fn from_ring(ring: u8) -> Result<Self, u8> {
        match ring {
            0 => Ok(Self::Ring0),
            3 => Ok(Self::Ring3),
            other => Err(other),
        }
    }

    /// Numeric ring number (`0` or `3`).
    #[inline]
    pub const fn ring(self) -> u8 {
        match self {
            Self::Ring0 => 0,
            Self::Ring3 => 3,
        }
    }

    /// Returns `true` when executing in user mode (`CPL == 3`).
    #[inline]
    pub const fn is_user(self) -> bool {
        matches!(self, Self::Ring3)
    }
}

/// Architectural CPU access context carried into soft-TLB lookups and page-table walks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CpuAccessMode {
    /// Current privilege level (`Ring0` or `Ring3`).
    pub cpl: Cpl,
    /// Architectural `RFLAGS.AC` bit (used by SMAP in `Ring0`).
    pub ac: bool,
}

impl CpuAccessMode {
    /// Construct a supervisor (`CPL0`) access mode with explicit `RFLAGS.AC`.
    #[inline]
    pub const fn ring0(ac: bool) -> Self {
        Self {
            cpl: Cpl::Ring0,
            ac,
        }
    }

    /// Construct a user (`CPL3`) access mode with `RFLAGS.AC == false`.
    #[inline]
    pub const fn ring3() -> Self {
        Self {
            cpl: Cpl::Ring3,
            ac: false,
        }
    }

    /// Construct a user (`CPL3`) access mode preserving the raw `RFLAGS.AC` bit.
    #[inline]
    pub const fn ring3_with_ac(ac: bool) -> Self {
        Self {
            cpl: Cpl::Ring3,
            ac,
        }
    }
}

/// Hardware `#PF` error-code bitmask delivered on x86 page faults (Intel SDM Vol. 3A §4.7).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PageFaultErrorCode(u32);

impl PageFaultErrorCode {
    /// Bit 0 (`P`): `0` = non-present page, `1` = page-level protection violation.
    pub const PRESENT: u32 = 1 << 0;
    /// Bit 1 (`W/R`): `0` = read/fetch access, `1` = write access.
    pub const WRITE: u32 = 1 << 1;
    /// Bit 2 (`U/S`): `0` = supervisor-mode (`CPL0`) access, `1` = user-mode (`CPL3`) access.
    pub const USER: u32 = 1 << 2;
    /// Bit 3 (`RSVD`): `1` = reserved bit set in a present paging-structure entry.
    pub const RESERVED_WRITE: u32 = 1 << 3;
    /// Bit 4 (`I/D`): `1` = instruction fetch caused the fault.
    pub const INSTRUCTION_FETCH: u32 = 1 << 4;

    /// Construct a `#PF` error code from raw architectural bits.
    #[inline]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Construct a hardware `#PF` error code from the fault classification, access kind, and CPU mode.
    #[inline]
    pub const fn for_fault(class: FaultClass, access: Access, mode: CpuAccessMode) -> Self {
        let mut bits = 0u32;
        match class {
            FaultClass::NotPresent => {}
            FaultClass::Protection | FaultClass::CowWrite | FaultClass::Nx => {
                bits |= Self::PRESENT;
            }
            FaultClass::Reserved => {
                bits |= Self::PRESENT | Self::RESERVED_WRITE;
            }
        }
        if matches!(access, Access::Write) {
            bits |= Self::WRITE;
        }
        if mode.cpl.is_user() {
            bits |= Self::USER;
        }
        if matches!(access, Access::Execute) {
            bits |= Self::INSTRUCTION_FETCH;
        }
        Self(bits)
    }

    /// Raw 32-bit error code pushed onto the x86 exception frame.
    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Raw error code zero-extended to 64 bits (as pushed by 64-bit IDT exception delivery).
    #[inline]
    pub const fn bits_u64(self) -> u64 {
        self.0 as u64
    }

    /// Returns `true` if `P` (bit 0) is set.
    #[inline]
    pub const fn present(self) -> bool {
        self.0 & Self::PRESENT != 0
    }

    /// Returns `true` if `W/R` (bit 1) is set.
    #[inline]
    pub const fn write(self) -> bool {
        self.0 & Self::WRITE != 0
    }

    /// Returns `true` if `U/S` (bit 2) is set.
    #[inline]
    pub const fn user(self) -> bool {
        self.0 & Self::USER != 0
    }

    /// Returns `true` if `RSVD` (bit 3) is set.
    #[inline]
    pub const fn reserved_bit(self) -> bool {
        self.0 & Self::RESERVED_WRITE != 0
    }

    /// Returns `true` if `I/D` (bit 4) is set.
    #[inline]
    pub const fn instruction_fetch(self) -> bool {
        self.0 & Self::INSTRUCTION_FETCH != 0
    }
}

/// Detailed classification of a software-MMU slow-path stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoftFaultClass {
    /// Entry at some level had `PRESENT == 0`.
    NotPresent,
    /// Permission check failed (`USER` vs CPL, `WRITE` on read-only ancestor/leaf, `NX` on execute).
    Protection,
    /// Supervisor (`CPL0`) data access to a user page while `RFLAGS.AC == 0` (SMAP violation).
    SmapProtection,
    /// Supervisor (`CPL0`) instruction fetch from a user page (SMEP violation).
    SmepProtection,
    /// A present entry had a reserved bit set (e.g. bit 51 or `PS=1` on PML4/PTE).
    ReservedBit,
    /// Write hit a leaf marked with the software `COW` bit (`1 << 10`) and `WRITE == 0`.
    CowWrite,
    /// Stage-1 leaf GPA lies in a registered MMIO hole (e.g. xAPIC `0xfee0_0000`) and must be
    /// routed to the device model rather than filled into `SoftTlb`.
    MmioHole {
        /// Byte-granular guest physical address of the MMIO access (`leaf.output + page_offset`).
        gpa: u64,
    },
    /// Stage-1 leaf `(Stage1Gpa, OwnerGeneration)` failed extent-table authentication.
    UnauthenticatedExtent {
        /// Stage-1 leaf GPA that failed authentication.
        stage1_gpa: Stage1Gpa,
        /// Software generation expected by the caller/MM.
        expected_generation: OwnerGeneration,
    },
    /// Authenticated frame GPA lies outside the `LinearPlacement` span.
    PlacementOutOfBounds {
        /// Frame GPA that exceeded the placement span.
        frame_gpa: FrameGpa,
    },
}

impl SoftFaultClass {
    /// Map to the architectural [`FaultClass`] used to compute the `#PF` error code.
    #[inline]
    pub const fn to_arch_fault_class(self) -> FaultClass {
        match self {
            Self::NotPresent
            | Self::UnauthenticatedExtent { .. }
            | Self::PlacementOutOfBounds { .. } => FaultClass::NotPresent,
            Self::Protection
            | Self::SmapProtection
            | Self::SmepProtection
            | Self::MmioHole { .. } => FaultClass::Protection,
            Self::ReservedBit => FaultClass::Reserved,
            Self::CowWrite => FaultClass::CowWrite,
        }
    }
}

/// Complete `#PF` / slow-path stop record returned when `SoftWalker` refuses to fill `SoftTlb`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageFaultInfo {
    /// Faulting guest linear address (loaded into `CR2` on `#PF` delivery).
    pub va: GuestVa,
    /// Access kind (`Read`, `Write`, or `Execute`).
    pub access: Access,
    /// CPU privilege level and `RFLAGS.AC` state at the time of the access.
    pub mode: CpuAccessMode,
    /// Specific reason the walk stopped.
    pub class: SoftFaultClass,
    /// Architectural x86 `#PF` error code for IDT vector 14 delivery.
    pub error_code: PageFaultErrorCode,
    /// Live stage-1 leaf descriptor when the walk reached a present leaf (e.g. `CowWrite` or `MmioHole`).
    pub leaf: Option<TranslatedLeaf>,
}

impl PageFaultInfo {
    /// Build a [`PageFaultInfo`] from a fault classification and optional leaf.
    #[inline]
    pub const fn new(
        va: GuestVa,
        access: Access,
        mode: CpuAccessMode,
        class: SoftFaultClass,
        leaf: Option<TranslatedLeaf>,
    ) -> Self {
        let error_code = PageFaultErrorCode::for_fault(class.to_arch_fault_class(), access, mode);
        Self {
            va,
            access,
            mode,
            class,
            error_code,
            leaf,
        }
    }
}
