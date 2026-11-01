//! Pinned `x86-64-v3` guest `CPUID` view shared across the KVM and software x86 lanes (#578).
//!
//! Architectural authorities (clean-room, no kernel or hypervisor implementation source):
//! - Intel 64 and IA-32 Architectures Software Developer's Manual, Vol. 2A, `CPUID`
//! - AMD64 Architecture Programmer's Manual, Vol. 3, Appendix E (`CPUID`)
//! - System V Application Binary Interface, AMD64 Architecture Processor Supplement,
//!   §3.1.2 Table 3.1 ("Micro-Architecture Levels": `x86-64`, `x86-64-v2`, `x86-64-v3`)
//!
//! Both the hardware KVM lane (`carrick-vmm-kvm`) and the software translation lane
//! (`carrick-softcpu-x86` / `carrick-vmm-soft`) must expose the same pinned `x86-64-v3`
//! `CPUID` topology and feature set so guest binaries take identical `glibc` / `musl` /
//! Go / Rust IFUNC and runtime dispatch paths regardless of the host CPU (`x86-64-v4`
//! AVX-512, AMX, SHA, AES, RDRAND, LA57, PKU, CET, and hypervisor leaves stay masked off).

use core::fmt;
use core::num::NonZeroU64;

/// Four 32-bit general-purpose register outputs returned by `CPUID` (`EAX`, `EBX`, `ECX`, `EDX`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuidRegs {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

impl CpuidRegs {
    /// All-zero leaf response for unsupported or unpopulated leaves and subleaves.
    pub const ZERO: Self = Self {
        eax: 0,
        ebx: 0,
        ecx: 0,
        edx: 0,
    };

    /// Construct a `CPUID` register quad `(eax, ebx, ecx, edx)`.
    #[must_use]
    pub const fn new(eax: u32, ebx: u32, ecx: u32, edx: u32) -> Self {
        Self { eax, ebx, ecx, edx }
    }
}

/// Subleaf (`ECX` index) significance flag in [`CpuidLeafEntry::flags`].
///
/// Matches the public Linux KVM userspace ABI constant `KVM_CPUID_FLAG_SIGNIFCANT_INDEX` (`1`).
pub const CPUID_FLAG_SIGNIFICANT_INDEX: u32 = 1;

/// One hypervisor-neutral `CPUID` table entry `(function, index, flags, regs)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuidLeafEntry {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub regs: CpuidRegs,
}

impl CpuidLeafEntry {
    /// Construct an entry whose `ECX` subleaf is ignored (`flags = 0`, `index = 0`).
    #[must_use]
    pub const fn basic(function: u32, regs: CpuidRegs) -> Self {
        Self {
            function,
            index: 0,
            flags: 0,
            regs,
        }
    }

    /// Construct a subleaf-indexed entry (`flags = CPUID_FLAG_SIGNIFICANT_INDEX`).
    #[must_use]
    pub const fn indexed(function: u32, index: u32, regs: CpuidRegs) -> Self {
        Self {
            function,
            index,
            flags: CPUID_FLAG_SIGNIFICANT_INDEX,
            regs,
        }
    }
}

/// Number of entries in [`GuestCpuidView::to_leaf_entries`].
pub const PINNED_CPUID_ENTRY_COUNT: usize = 11;

/// Highest basic `CPUID` function advertised in `CPUID.00H:EAX`.
///
/// Pinned to `0x16` with leaf `0x16` populated as [`CpuidRegs::ZERO`]: per Intel SDM Vol. 2A,
/// out-of-range `CPUID` leaves fall back to the highest basic leaf, so returning zero at `0x16`
/// ensures KVM and software lanes agree (`CpuidRegs::ZERO`) on every out-of-range basic,
/// `0x4000_0000` hypervisor, and `> 0x8000_0008` extended probe.
pub const CPUID_MAX_BASIC_LEAF: u32 = 0x16;

/// Highest extended `CPUID` function advertised in `CPUID.80000000H:EAX`.
pub const CPUID_MAX_EXTENDED_LEAF: u32 = 0x8000_0008;

/// Vendor string `"GenuineIntel"` (`EBX = "Genu"`, `EDX = "ineI"`, `ECX = "ntel"`).
pub const CPUID_VENDOR_EBX: u32 = u32::from_le_bytes(*b"Genu");
pub const CPUID_VENDOR_ECX: u32 = u32::from_le_bytes(*b"ntel");
pub const CPUID_VENDOR_EDX: u32 = u32::from_le_bytes(*b"ineI");

/// Pinned Family 6 Model 61 Stepping 4 (Intel Broadwell, canonical `x86-64-v3` + `SMEP`/`SMAP`).
pub const CPUID_V3_SIGNATURE_EAX: u32 = 0x0003_06d4;

/// `CLFLUSH` line size encoded in 8-byte chunks (`8 * 8 = 64` bytes) in `CPUID.01H:EBX[15:8]`.
pub const CPUID_CLFLUSH_LINE_CHUNKS: u32 = 8;

/// Default nominal guest TSC frequency (`2 GHz`) advertised via `CPUID.15H` when uncalibrated.
pub const DEFAULT_TSC_HZ: u64 = 2_000_000_000;

/// Default guest physical address width (`48` bits) for the pinned `x86-64-v3` view.
pub const DEFAULT_GUEST_MAX_PHY_ADDR: u8 = 48;

/// Minimum host `MAXPHYADDR` admitted by Carrick's x86_64 guest physical layout (`36` bits / 64 GiB).
pub const MIN_GUEST_MAX_PHY_ADDR: u8 = 36;

/// Fixed 4-level paging linear address width (`48` bits; `LA57` is never advertised).
pub const GUEST_LINEAR_ADDR_BITS: u8 = 48;

/// Standard legacy + XSAVE header size in bytes (`512 + 64 = 576`).
pub const XSAVE_LEGACY_BYTES: u32 = 576;

/// AVX `YMM_Hi128` state component size in bytes (`16 * 16 = 256`).
pub const XSAVE_AVX_COMPONENT_BYTES: u32 = 256;

/// Standard `x87 | SSE | AVX` (`XCR0 = 0x7`) XSAVE area size in bytes (`576 + 256 = 832`).
pub const XSAVE_V3_TOTAL_BYTES: u32 = XSAVE_LEGACY_BYTES + XSAVE_AVX_COMPONENT_BYTES;

/// Pinned `XCR0` component mask (`x87(0) | SSE(1) | AVX(2) = 0x7`).
pub const XCR0_X86_64_V3_MASK: u32 = 0x7;

// ─── Leaf 0x0000_0001 ECX (`x86-64-v2` + `x86-64-v3`) ────────────────────────

pub const CPUID_1_ECX_SSE3: u32 = 1 << 0;
pub const CPUID_1_ECX_SSSE3: u32 = 1 << 9;
pub const CPUID_1_ECX_FMA: u32 = 1 << 12;
pub const CPUID_1_ECX_CMPXCHG16B: u32 = 1 << 13;
pub const CPUID_1_ECX_SSE4_1: u32 = 1 << 19;
pub const CPUID_1_ECX_SSE4_2: u32 = 1 << 20;
pub const CPUID_1_ECX_MOVBE: u32 = 1 << 22;
pub const CPUID_1_ECX_POPCNT: u32 = 1 << 23;
pub const CPUID_1_ECX_XSAVE: u32 = 1 << 26;
pub const CPUID_1_ECX_OSXSAVE: u32 = 1 << 27;
pub const CPUID_1_ECX_AVX: u32 = 1 << 28;
pub const CPUID_1_ECX_F16C: u32 = 1 << 29;
pub const CPUID_1_ECX_HYPERVISOR: u32 = 1 << 31;

/// Static hardware `CPUID.01H:ECX` bits required for `x86-64-v3` (excludes dynamic `OSXSAVE`).
pub const CPUID_1_ECX_X86_64_V3_HW: u32 = CPUID_1_ECX_SSE3
    | CPUID_1_ECX_SSSE3
    | CPUID_1_ECX_FMA
    | CPUID_1_ECX_CMPXCHG16B
    | CPUID_1_ECX_SSE4_1
    | CPUID_1_ECX_SSE4_2
    | CPUID_1_ECX_MOVBE
    | CPUID_1_ECX_POPCNT
    | CPUID_1_ECX_XSAVE
    | CPUID_1_ECX_AVX
    | CPUID_1_ECX_F16C;

/// Complete guest-visible `CPUID.01H:ECX` mask when `CR4.OSXSAVE = 1`.
pub const CPUID_1_ECX_X86_64_V3: u32 = CPUID_1_ECX_X86_64_V3_HW | CPUID_1_ECX_OSXSAVE;

// ─── Leaf 0x0000_0001 EDX (`x86-64-v1` + IA-32e / CPL0 baseline) ─────────────

pub const CPUID_1_EDX_FPU: u32 = 1 << 0;
pub const CPUID_1_EDX_DE: u32 = 1 << 2;
pub const CPUID_1_EDX_PSE: u32 = 1 << 3;
pub const CPUID_1_EDX_TSC: u32 = 1 << 4;
pub const CPUID_1_EDX_MSR: u32 = 1 << 5;
pub const CPUID_1_EDX_PAE: u32 = 1 << 6;
pub const CPUID_1_EDX_CX8: u32 = 1 << 8;
pub const CPUID_1_EDX_APIC: u32 = 1 << 9;
pub const CPUID_1_EDX_PGE: u32 = 1 << 13;
pub const CPUID_1_EDX_CMOV: u32 = 1 << 15;
pub const CPUID_1_EDX_PAT: u32 = 1 << 16;
pub const CPUID_1_EDX_CLFSH: u32 = 1 << 19;
pub const CPUID_1_EDX_MMX: u32 = 1 << 23;
pub const CPUID_1_EDX_FXSR: u32 = 1 << 24;
pub const CPUID_1_EDX_SSE: u32 = 1 << 25;
pub const CPUID_1_EDX_SSE2: u32 = 1 << 26;

/// Static hardware `CPUID.01H:EDX` bits required for `x86-64-v3` (excludes dynamic `APIC`).
pub const CPUID_1_EDX_X86_64_V3_HW: u32 = CPUID_1_EDX_FPU
    | CPUID_1_EDX_DE
    | CPUID_1_EDX_PSE
    | CPUID_1_EDX_TSC
    | CPUID_1_EDX_MSR
    | CPUID_1_EDX_PAE
    | CPUID_1_EDX_CX8
    | CPUID_1_EDX_PGE
    | CPUID_1_EDX_CMOV
    | CPUID_1_EDX_PAT
    | CPUID_1_EDX_CLFSH
    | CPUID_1_EDX_MMX
    | CPUID_1_EDX_FXSR
    | CPUID_1_EDX_SSE
    | CPUID_1_EDX_SSE2;

/// Complete guest-visible `CPUID.01H:EDX` mask with `IA32_APIC_BASE.EN = 1`.
pub const CPUID_1_EDX_X86_64_V3: u32 = CPUID_1_EDX_X86_64_V3_HW | CPUID_1_EDX_APIC;

// ─── Leaf 0x0000_0007 Subleaf 0 EBX (`x86-64-v3` + CPL0 SMEP/SMAP) ───────────

pub const CPUID_7_0_EBX_BMI1: u32 = 1 << 3;
pub const CPUID_7_0_EBX_AVX2: u32 = 1 << 5;
pub const CPUID_7_0_EBX_SMEP: u32 = 1 << 7;
pub const CPUID_7_0_EBX_BMI2: u32 = 1 << 8;
pub const CPUID_7_0_EBX_SMAP: u32 = 1 << 20;

/// User-ISA `x86-64-v3` structured extended feature bits in `CPUID.(EAX=07H,ECX=0H):EBX`.
pub const CPUID_7_0_EBX_X86_64_V3_USER: u32 =
    CPUID_7_0_EBX_BMI1 | CPUID_7_0_EBX_AVX2 | CPUID_7_0_EBX_BMI2;

/// Ring-0 CPL0 supervisor page-protection bits in `CPUID.(EAX=07H,ECX=0H):EBX`.
pub const CPUID_7_0_EBX_CPL0_SUPERVISOR: u32 = CPUID_7_0_EBX_SMEP | CPUID_7_0_EBX_SMAP;

/// Complete pinned `CPUID.(EAX=07H,ECX=0H):EBX` mask.
pub const CPUID_7_0_EBX_PINNED: u32 = CPUID_7_0_EBX_X86_64_V3_USER | CPUID_7_0_EBX_CPL0_SUPERVISOR;

// ─── Extended Leaves 0x8000_0001 and 0x8000_0007 ─────────────────────────────

pub const CPUID_8000_0001_ECX_LAHF_LM: u32 = 1 << 0;
pub const CPUID_8000_0001_ECX_LZCNT: u32 = 1 << 5;

/// Complete pinned `CPUID.80000001H:ECX` mask (`LAHF_LM | LZCNT`).
pub const CPUID_8000_0001_ECX_X86_64_V3: u32 =
    CPUID_8000_0001_ECX_LAHF_LM | CPUID_8000_0001_ECX_LZCNT;

pub const CPUID_8000_0001_EDX_SYSCALL: u32 = 1 << 11;
pub const CPUID_8000_0001_EDX_NX: u32 = 1 << 20;
pub const CPUID_8000_0001_EDX_LM: u32 = 1 << 29;

/// Complete pinned `CPUID.80000001H:EDX` mask (`SYSCALL | NX | LM`).
pub const CPUID_8000_0001_EDX_X86_64_V3: u32 =
    CPUID_8000_0001_EDX_SYSCALL | CPUID_8000_0001_EDX_NX | CPUID_8000_0001_EDX_LM;

/// Invariant TSC capability bit in `CPUID.80000007H:EDX[8]`.
pub const CPUID_8000_0007_EDX_INVTSC: u32 = 1 << 8;

/// Architectural `CPUID.15H` TSC/core-crystal ratio (`TSC_Hz = crystal_hz * numer / denom`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TscCrystalRatio {
    denom: u32,
    numer: u32,
    crystal_hz: u32,
}

impl TscCrystalRatio {
    /// Default 2 GHz virtual TSC calibration (`1 * 2_000_000_000 / 1`).
    pub const DEFAULT: Self = Self {
        denom: 1,
        numer: 1,
        crystal_hz: DEFAULT_TSC_HZ as u32,
    };

    /// Construct an exact ratio from `denom` (`EAX`), `numer` (`EBX`), and `crystal_hz` (`ECX`).
    #[must_use]
    pub const fn new(denom: u32, numer: u32, crystal_hz: u32) -> Option<Self> {
        if denom == 0 || numer == 0 || crystal_hz == 0 {
            return None;
        }
        let prod = (crystal_hz as u64).saturating_mul(numer as u64);
        if prod / (denom as u64) == 0 {
            return None;
        }
        Some(Self {
            denom,
            numer,
            crystal_hz,
        })
    }

    /// Encode a host `KVM_GET_TSC_KHZ` value (`khz * 1_000` Hz) without `u32` overflow.
    #[must_use]
    pub const fn from_khz(khz: u32) -> Option<Self> {
        if khz == 0 {
            None
        } else {
            Some(Self {
                denom: 1,
                numer: khz,
                crystal_hz: 1_000,
            })
        }
    }

    /// Encode an exact frequency in Hz when representable in `CPUID.15H`.
    #[must_use]
    pub const fn from_hz(hz: u64) -> Option<Self> {
        if hz == 0 {
            return None;
        }
        if hz <= u32::MAX as u64 {
            return Some(Self {
                denom: 1,
                numer: 1,
                crystal_hz: hz as u32,
            });
        }
        if hz.is_multiple_of(1_000) && (hz / 1_000) <= u32::MAX as u64 {
            return Self::from_khz((hz / 1_000) as u32);
        }
        None
    }

    /// Evaluated TSC frequency in Hz (`ECX * EBX / EAX`).
    #[must_use]
    pub const fn tsc_hz(self) -> NonZeroU64 {
        let hz = ((self.crystal_hz as u128) * (self.numer as u128)) / (self.denom as u128);
        let hz64 = if hz > u64::MAX as u128 {
            u64::MAX
        } else if hz == 0 {
            1
        } else {
            hz as u64
        };
        if let Some(nz) = NonZeroU64::new(hz64) {
            nz
        } else {
            NonZeroU64::MIN
        }
    }

    /// Convert to `CPUID.15H` registers `(denom, numer, crystal_hz, 0)`.
    #[must_use]
    pub const fn to_regs(self) -> CpuidRegs {
        CpuidRegs::new(self.denom, self.numer, self.crystal_hz, 0)
    }
}

/// Which `CPUID` output register lacked a required capability during host qualification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuidRegisterName {
    Eax,
    Ebx,
    Ecx,
    Edx,
}

impl fmt::Display for CpuidRegisterName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eax => f.write_str("EAX"),
            Self::Ebx => f.write_str("EBX"),
            Self::Ecx => f.write_str("ECX"),
            Self::Edx => f.write_str("EDX"),
        }
    }
}

/// Reason why a host's supported `CPUID` table cannot back the pinned `x86-64-v3` guest view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuidQualificationError {
    MissingLeaf {
        leaf: u32,
        subleaf: u32,
    },
    MissingFeature {
        leaf: u32,
        subleaf: u32,
        reg: CpuidRegisterName,
        feature: &'static str,
        bit: u8,
    },
    UnsupportedXsaveGeometry {
        state_mask_eax: u32,
        avx_size_eax: u32,
        avx_offset_ebx: u32,
    },
    InsufficientMaxPhyAddr {
        supported: u8,
        minimum: u8,
    },
    InvalidMaxPhyAddr {
        requested: u8,
    },
    InsufficientLinearAddr {
        supported: u8,
        required: u8,
    },
}

impl fmt::Display for CpuidQualificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingLeaf { leaf, subleaf } => {
                write!(
                    f,
                    "host CPUID lacks required leaf ({leaf:#x}, {subleaf:#x})"
                )
            }
            Self::MissingFeature {
                leaf,
                subleaf,
                reg,
                feature,
                bit,
            } => write!(
                f,
                "host CPUID ({leaf:#x}, {subleaf:#x}).{reg}[bit {bit}] lacks required x86-64-v3/CPL0 feature {feature}"
            ),
            Self::UnsupportedXsaveGeometry {
                state_mask_eax,
                avx_size_eax,
                avx_offset_ebx,
            } => write!(
                f,
                "host XSAVE CPUID (0xd) incompatible with standard 832-byte x87|SSE|AVX layout \
                 (0xd.0.eax={state_mask_eax:#x}, 0xd.2.eax={avx_size_eax}, 0xd.2.ebx={avx_offset_ebx})"
            ),
            Self::InsufficientMaxPhyAddr { supported, minimum } => write!(
                f,
                "host CPUID MAXPHYADDR={supported} is below minimum {minimum} bits"
            ),
            Self::InvalidMaxPhyAddr { requested } => write!(
                f,
                "guest MAXPHYADDR={requested} outside supported pinned range {MIN_GUEST_MAX_PHY_ADDR}..={DEFAULT_GUEST_MAX_PHY_ADDR}"
            ),
            Self::InsufficientLinearAddr {
                supported,
                required,
            } => write!(
                f,
                "host CPUID linear address width {supported} is below required {required} bits"
            ),
        }
    }
}

impl std::error::Error for CpuidQualificationError {}

/// Canonical pinned `x86-64-v3` guest `CPUID` view shared across the KVM and soft lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestCpuidView {
    apic_id: u8,
    max_phy_addr: u8,
    tsc: Option<TscCrystalRatio>,
}

impl Default for GuestCpuidView {
    fn default() -> Self {
        Self::x86_64_v3()
    }
}

impl GuestCpuidView {
    /// Default pinned `x86-64-v3` view (`apic_id = 0`, `MAXPHYADDR = 48`, `TSC = 2 GHz`).
    #[must_use]
    pub const fn x86_64_v3() -> Self {
        Self {
            apic_id: 0,
            max_phy_addr: DEFAULT_GUEST_MAX_PHY_ADDR,
            tsc: Some(TscCrystalRatio::DEFAULT),
        }
    }

    /// Return a copy stamped with per-vCPU initial `APIC ID` (`CPUID.01H:EBX[31:24]`).
    #[must_use]
    pub const fn with_apic_id(mut self, apic_id: u8) -> Self {
        self.apic_id = apic_id;
        self
    }

    /// Return a copy stamped with the `CPUID.15H` TSC/crystal calibration.
    #[must_use]
    pub const fn with_tsc(mut self, tsc: Option<TscCrystalRatio>) -> Self {
        self.tsc = tsc;
        self
    }

    /// Return a copy with `CPUID.80000008H:EAX[7:0]` set to `max_phy_addr` (`36..=48`).
    pub const fn with_max_phy_addr(
        mut self,
        max_phy_addr: u8,
    ) -> Result<Self, CpuidQualificationError> {
        if max_phy_addr < MIN_GUEST_MAX_PHY_ADDR || max_phy_addr > DEFAULT_GUEST_MAX_PHY_ADDR {
            return Err(CpuidQualificationError::InvalidMaxPhyAddr {
                requested: max_phy_addr,
            });
        }
        self.max_phy_addr = max_phy_addr;
        Ok(self)
    }

    /// Per-vCPU initial `APIC ID`.
    #[must_use]
    pub const fn apic_id(&self) -> u8 {
        self.apic_id
    }

    /// Guest physical address width (`36..=48`) advertised in `CPUID.80000008H:EAX[7:0]`.
    #[must_use]
    pub const fn max_phy_addr(&self) -> u8 {
        self.max_phy_addr
    }

    /// Configured `CPUID.15H` crystal/TSC ratio, if any.
    #[must_use]
    pub const fn tsc_ratio(&self) -> Option<TscCrystalRatio> {
        self.tsc
    }

    /// Query `(leaf, subleaf)` for a running 64-bit guest (`CR4.OSXSAVE = 1`, `XCR0 = 0x7`).
    #[must_use]
    pub const fn cpuid(&self, leaf: u32, subleaf: u32) -> CpuidRegs {
        self.cpuid_for_state(leaf, subleaf, true, true)
    }

    /// Query `(leaf, subleaf)` parameterized by live `CR4.OSXSAVE` and `XCR0.AVX` state.
    #[must_use]
    pub const fn cpuid_for_state(
        &self,
        leaf: u32,
        subleaf: u32,
        osxsave_enabled: bool,
        xcr0_avx_enabled: bool,
    ) -> CpuidRegs {
        match (leaf, subleaf) {
            (0, _) => CpuidRegs::new(
                CPUID_MAX_BASIC_LEAF,
                CPUID_VENDOR_EBX,
                CPUID_VENDOR_ECX,
                CPUID_VENDOR_EDX,
            ),
            (1, _) => {
                let ebx = ((self.apic_id as u32) << 24) | (CPUID_CLFLUSH_LINE_CHUNKS << 8);
                let ecx = if osxsave_enabled {
                    CPUID_1_ECX_X86_64_V3
                } else {
                    CPUID_1_ECX_X86_64_V3_HW
                };
                CpuidRegs::new(CPUID_V3_SIGNATURE_EAX, ebx, ecx, CPUID_1_EDX_X86_64_V3)
            }
            (7, 0) => CpuidRegs::new(0, CPUID_7_0_EBX_PINNED, 0, 0),
            (0x0d, 0) => {
                let enabled_bytes = if xcr0_avx_enabled {
                    XSAVE_V3_TOTAL_BYTES
                } else {
                    XSAVE_LEGACY_BYTES
                };
                CpuidRegs::new(XCR0_X86_64_V3_MASK, enabled_bytes, XSAVE_V3_TOTAL_BYTES, 0)
            }
            (0x0d, 2) => CpuidRegs::new(XSAVE_AVX_COMPONENT_BYTES, XSAVE_LEGACY_BYTES, 0, 0),
            (0x15, 0) => match self.tsc {
                Some(ratio) => ratio.to_regs(),
                None => CpuidRegs::ZERO,
            },
            (0x8000_0000, _) => CpuidRegs::new(CPUID_MAX_EXTENDED_LEAF, 0, 0, 0),
            (0x8000_0001, _) => CpuidRegs::new(
                0,
                0,
                CPUID_8000_0001_ECX_X86_64_V3,
                CPUID_8000_0001_EDX_X86_64_V3,
            ),
            (0x8000_0007, _) => CpuidRegs::new(0, 0, 0, CPUID_8000_0007_EDX_INVTSC),
            (0x8000_0008, _) => CpuidRegs::new(
                (self.max_phy_addr as u32) | ((GUEST_LINEAR_ADDR_BITS as u32) << 8),
                0,
                0,
                0,
            ),
            _ => CpuidRegs::ZERO,
        }
    }

    /// Materialize the fixed 11-entry `CPUID` table for hypervisor installation (`KVM_SET_CPUID2`).
    #[must_use]
    pub const fn to_leaf_entries(&self) -> [CpuidLeafEntry; PINNED_CPUID_ENTRY_COUNT] {
        [
            CpuidLeafEntry::basic(0, self.cpuid(0, 0)),
            CpuidLeafEntry::basic(1, self.cpuid(1, 0)),
            CpuidLeafEntry::indexed(7, 0, self.cpuid(7, 0)),
            CpuidLeafEntry::indexed(0x0d, 0, self.cpuid(0x0d, 0)),
            CpuidLeafEntry::indexed(0x0d, 2, self.cpuid(0x0d, 2)),
            CpuidLeafEntry::indexed(0x15, 0, self.cpuid(0x15, 0)),
            CpuidLeafEntry::basic(CPUID_MAX_BASIC_LEAF, CpuidRegs::ZERO),
            CpuidLeafEntry::basic(0x8000_0000, self.cpuid(0x8000_0000, 0)),
            CpuidLeafEntry::basic(0x8000_0001, self.cpuid(0x8000_0001, 0)),
            CpuidLeafEntry::basic(0x8000_0007, self.cpuid(0x8000_0007, 0)),
            CpuidLeafEntry::basic(0x8000_0008, self.cpuid(0x8000_0008, 0)),
        ]
    }

    /// Validate a host's supported `CPUID` leaf table (e.g. `KVM_GET_SUPPORTED_CPUID`)
    /// against `x86-64-v3` and CPL0 requirements, returning the scrubbed [`GuestCpuidView`].
    ///
    /// - Refuses hosts missing any static `x86-64-v3` ISA bit, IA-32e baseline bit,
    ///   or CPL0 supervisor `SMEP`/`SMAP` bit.
    /// - Checks static `XSAVE` (`1.ECX[26]`) rather than dynamic `OSXSAVE` (`1.ECX[27]`),
    ///   and excludes dynamic `APIC` (`1.EDX[9]`), because `/dev/kvm`'s system-wide
    ///   `KVM_GET_SUPPORTED_CPUID` reports pre-`CR4.OSXSAVE` / pre-LAPIC capability masks.
    /// - Verifies standard `x87 | SSE | AVX` XSAVE geometry (`256` bytes at offset `576`).
    /// - Clamps `MAXPHYADDR` to `host_max_phy_addr.min(48)` while refusing `< 36` bits,
    ///   preventing `KVM_SET_CPUID2` `EINVAL` on 46-bit Intel TDP hosts and capping
    ///   52-bit AMD EPYC hosts at 48 bits.
    /// - Leaves `tsc` set only when `(0x15, 0)` in `supported` already carries a valid
    ///   non-zero crystal ratio; otherwise `None` until the caller calibrates per-vCPU TSC.
    pub fn qualify_supported(
        supported: &[CpuidLeafEntry],
    ) -> Result<Self, CpuidQualificationError> {
        const LEAF_1_ECX_REQUIRED: &[(u8, &str)] = &[
            (0, "SSE3"),
            (9, "SSSE3"),
            (12, "FMA"),
            (13, "CMPXCHG16B"),
            (19, "SSE4.1"),
            (20, "SSE4.2"),
            (22, "MOVBE"),
            (23, "POPCNT"),
            (26, "XSAVE"),
            (28, "AVX"),
            (29, "F16C"),
        ];
        const LEAF_1_EDX_REQUIRED: &[(u8, &str)] = &[
            (0, "FPU"),
            (2, "DE"),
            (3, "PSE"),
            (4, "TSC"),
            (5, "MSR"),
            (6, "PAE"),
            (8, "CX8"),
            (13, "PGE"),
            (15, "CMOV"),
            (16, "PAT"),
            (19, "CLFSH"),
            (23, "MMX"),
            (24, "FXSR"),
            (25, "SSE"),
            (26, "SSE2"),
        ];
        const LEAF_7_0_EBX_REQUIRED: &[(u8, &str)] = &[
            (3, "BMI1"),
            (5, "AVX2"),
            (7, "SMEP"),
            (8, "BMI2"),
            (20, "SMAP"),
        ];
        const LEAF_EXT1_ECX_REQUIRED: &[(u8, &str)] = &[(0, "LAHF_LM"), (5, "LZCNT")];
        const LEAF_EXT1_EDX_REQUIRED: &[(u8, &str)] = &[(11, "SYSCALL"), (20, "NX"), (29, "LM")];

        let l1 =
            find_supported_leaf(supported, 1, 0).ok_or(CpuidQualificationError::MissingLeaf {
                leaf: 1,
                subleaf: 0,
            })?;
        require_bits(1, 0, CpuidRegisterName::Ecx, l1.ecx, LEAF_1_ECX_REQUIRED)?;
        require_bits(1, 0, CpuidRegisterName::Edx, l1.edx, LEAF_1_EDX_REQUIRED)?;

        let l7_0 =
            find_supported_leaf(supported, 7, 0).ok_or(CpuidQualificationError::MissingLeaf {
                leaf: 7,
                subleaf: 0,
            })?;
        require_bits(
            7,
            0,
            CpuidRegisterName::Ebx,
            l7_0.ebx,
            LEAF_7_0_EBX_REQUIRED,
        )?;

        let l0d_0 = find_supported_leaf(supported, 0x0d, 0).ok_or(
            CpuidQualificationError::MissingLeaf {
                leaf: 0x0d,
                subleaf: 0,
            },
        )?;
        let l0d_2 = find_supported_leaf(supported, 0x0d, 2).ok_or(
            CpuidQualificationError::MissingLeaf {
                leaf: 0x0d,
                subleaf: 2,
            },
        )?;
        if (l0d_0.eax & XCR0_X86_64_V3_MASK) != XCR0_X86_64_V3_MASK
            || l0d_2.eax != XSAVE_AVX_COMPONENT_BYTES
            || l0d_2.ebx != XSAVE_LEGACY_BYTES
        {
            return Err(CpuidQualificationError::UnsupportedXsaveGeometry {
                state_mask_eax: l0d_0.eax,
                avx_size_eax: l0d_2.eax,
                avx_offset_ebx: l0d_2.ebx,
            });
        }

        let ext1 = find_supported_leaf(supported, 0x8000_0001, 0).ok_or(
            CpuidQualificationError::MissingLeaf {
                leaf: 0x8000_0001,
                subleaf: 0,
            },
        )?;
        require_bits(
            0x8000_0001,
            0,
            CpuidRegisterName::Ecx,
            ext1.ecx,
            LEAF_EXT1_ECX_REQUIRED,
        )?;
        require_bits(
            0x8000_0001,
            0,
            CpuidRegisterName::Edx,
            ext1.edx,
            LEAF_EXT1_EDX_REQUIRED,
        )?;

        let ext8 = find_supported_leaf(supported, 0x8000_0008, 0).ok_or(
            CpuidQualificationError::MissingLeaf {
                leaf: 0x8000_0008,
                subleaf: 0,
            },
        )?;
        let host_phy = (ext8.eax & 0xff) as u8;
        if host_phy < MIN_GUEST_MAX_PHY_ADDR {
            return Err(CpuidQualificationError::InsufficientMaxPhyAddr {
                supported: host_phy,
                minimum: MIN_GUEST_MAX_PHY_ADDR,
            });
        }
        let host_lin = ((ext8.eax >> 8) & 0xff) as u8;
        if host_lin != 0 && host_lin < GUEST_LINEAR_ADDR_BITS {
            return Err(CpuidQualificationError::InsufficientLinearAddr {
                supported: host_lin,
                required: GUEST_LINEAR_ADDR_BITS,
            });
        }

        let supported_tsc = find_supported_leaf(supported, 0x15, 0)
            .and_then(|r| TscCrystalRatio::new(r.eax, r.ebx, r.ecx));
        let clamped_phy = host_phy.min(DEFAULT_GUEST_MAX_PHY_ADDR);
        Self::x86_64_v3()
            .with_tsc(supported_tsc)
            .with_max_phy_addr(clamped_phy)
    }
}

fn find_supported_leaf(supported: &[CpuidLeafEntry], leaf: u32, subleaf: u32) -> Option<CpuidRegs> {
    supported
        .iter()
        .find(|e| {
            e.function == leaf
                && if (e.flags & CPUID_FLAG_SIGNIFICANT_INDEX) != 0 {
                    e.index == subleaf
                } else {
                    subleaf == 0
                }
        })
        .map(|e| e.regs)
}

fn require_bits(
    leaf: u32,
    subleaf: u32,
    reg: CpuidRegisterName,
    actual: u32,
    required: &[(u8, &'static str)],
) -> Result<(), CpuidQualificationError> {
    for &(bit, feature) in required {
        if (actual & (1_u32 << bit)) == 0 {
            return Err(CpuidQualificationError::MissingFeature {
                leaf,
                subleaf,
                reg,
                feature,
                bit,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Lookup helper emulating `KVM_SET_CPUID2` + Intel SDM `check_cpuid_limit` semantics
    /// over an arbitrary `CpuidLeafEntry` slice.
    fn emulate_cpuid_table_query(entries: &[CpuidLeafEntry], leaf: u32, subleaf: u32) -> CpuidRegs {
        if let Some(hit) = entries.iter().find(|e| {
            e.function == leaf
                && ((e.flags & CPUID_FLAG_SIGNIFICANT_INDEX) == 0 || e.index == subleaf)
        }) {
            return hit.regs;
        }
        let range_base = leaf & 0x8000_0000;
        let Some(max_entry) = entries.iter().find(|e| e.function == range_base) else {
            return CpuidRegs::ZERO;
        };
        if leaf <= max_entry.regs.eax {
            return CpuidRegs::ZERO;
        }
        let fallback_leaf = if range_base != 0 {
            let Some(basic0) = entries.iter().find(|e| e.function == 0) else {
                return CpuidRegs::ZERO;
            };
            basic0.regs.eax
        } else {
            max_entry.regs.eax
        };
        entries
            .iter()
            .find(|e| {
                e.function == fallback_leaf
                    && ((e.flags & CPUID_FLAG_SIGNIFICANT_INDEX) == 0 || e.index == subleaf)
            })
            .map_or(CpuidRegs::ZERO, |e| e.regs)
    }

    /// Audit that a CPUID query function exposes every `x86-64-v3` capability and ZERO
    /// features outside the pinned `x86-64-v3` + baseline/CPL0 profile.
    fn audit_strict_x86_64_v3_only(
        query: impl Fn(u32, u32) -> CpuidRegs,
        expected_apic_id: u8,
        expected_max_phy_addr: u8,
    ) -> Result<(), String> {
        let l0 = query(0, 0);
        if l0.eax != CPUID_MAX_BASIC_LEAF
            || l0.ebx != CPUID_VENDOR_EBX
            || l0.ecx != CPUID_VENDOR_ECX
            || l0.edx != CPUID_VENDOR_EDX
        {
            return Err(format!("leaf 0 mismatch: {l0:?}"));
        }

        let l1 = query(1, 0);
        if (l1.ebx >> 24) as u8 != expected_apic_id {
            return Err(format!("leaf 1 APIC ID mismatch: ebx={:#x}", l1.ebx));
        }
        if ((l1.ebx >> 8) & 0xff) != CPUID_CLFLUSH_LINE_CHUNKS || (l1.ebx & 0x00ff_00ff) != 0 {
            return Err(format!(
                "leaf 1 EBX topology/clflush mismatch: ebx={:#x}",
                l1.ebx
            ));
        }
        if l1.ecx != CPUID_1_ECX_X86_64_V3 {
            let missing = CPUID_1_ECX_X86_64_V3 & !l1.ecx;
            let extra = l1.ecx & !CPUID_1_ECX_X86_64_V3;
            return Err(format!(
                "leaf 1 ECX mismatch: got={:#010x} missing={missing:#010x} non_v3_extra={extra:#010x}",
                l1.ecx
            ));
        }
        if (l1.ecx & CPUID_1_ECX_HYPERVISOR) != 0 {
            return Err("hypervisor bit must be clear".into());
        }
        if l1.edx != CPUID_1_EDX_X86_64_V3 {
            let missing = CPUID_1_EDX_X86_64_V3 & !l1.edx;
            let extra = l1.edx & !CPUID_1_EDX_X86_64_V3;
            return Err(format!(
                "leaf 1 EDX mismatch: got={:#010x} missing={missing:#010x} non_v3_extra={extra:#010x}",
                l1.edx
            ));
        }

        let l7_0 = query(7, 0);
        if l7_0 != CpuidRegs::new(0, CPUID_7_0_EBX_PINNED, 0, 0) {
            return Err(format!("leaf (7, 0) mismatch: {l7_0:?}"));
        }
        for subleaf in 1..=4 {
            let r = query(7, subleaf);
            if r != CpuidRegs::ZERO {
                return Err(format!("leaf (7, {subleaf}) leaked non-v3 features: {r:?}"));
            }
        }

        if query(0x0d, 0) != CpuidRegs::new(7, 832, 832, 0) {
            return Err(format!("leaf (0xd, 0) mismatch: {:?}", query(0x0d, 0)));
        }
        if query(0x0d, 1) != CpuidRegs::ZERO {
            return Err(format!(
                "leaf (0xd, 1) leaked XSAVEOPT/XSAVEC/XSAVES: {:?}",
                query(0x0d, 1)
            ));
        }
        if query(0x0d, 2) != CpuidRegs::new(256, 576, 0, 0) {
            return Err(format!("leaf (0xd, 2) mismatch: {:?}", query(0x0d, 2)));
        }
        for subleaf in 3..64 {
            let r = query(0x0d, subleaf);
            if r != CpuidRegs::ZERO {
                return Err(format!(
                    "leaf (0xd, {subleaf}) leaked extended state component: {r:?}"
                ));
            }
        }

        let l15_0 = query(0x15, 0);
        if l15_0.edx != 0
            || (l15_0 != CpuidRegs::ZERO
                && TscCrystalRatio::new(l15_0.eax, l15_0.ebx, l15_0.ecx).is_none())
        {
            return Err(format!("leaf (0x15, 0) invalid TSC ratio: {l15_0:?}"));
        }
        for subleaf in 1..=3 {
            let r = query(0x15, subleaf);
            if r != CpuidRegs::ZERO {
                return Err(format!("leaf (0x15, {subleaf}) leaked {r:?}"));
            }
        }

        for leaf in [
            2, 3, 4, 5, 6, 8, 9, 0x0a, 0x0b, 0x0c, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x16,
            0x17, 0x1f, 0x20,
        ] {
            let r = query(leaf, 0);
            if r != CpuidRegs::ZERO {
                return Err(format!("unpopulated basic leaf {leaf:#x} leaked {r:?}"));
            }
        }
        for hv_leaf in 0x4000_0000..=0x4000_0010 {
            let r = query(hv_leaf, 0);
            if r != CpuidRegs::ZERO {
                return Err(format!("hypervisor leaf {hv_leaf:#x} leaked {r:?}"));
            }
        }

        if query(0x8000_0000, 0) != CpuidRegs::new(0x8000_0008, 0, 0, 0) {
            return Err(format!(
                "leaf 0x8000_0000 mismatch: {:?}",
                query(0x8000_0000, 0)
            ));
        }
        if query(0x8000_0001, 0)
            != CpuidRegs::new(
                0,
                0,
                CPUID_8000_0001_ECX_X86_64_V3,
                CPUID_8000_0001_EDX_X86_64_V3,
            )
        {
            return Err(format!(
                "leaf 0x8000_0001 mismatch: {:?}",
                query(0x8000_0001, 0)
            ));
        }
        if query(0x8000_0007, 0) != CpuidRegs::new(0, 0, 0, CPUID_8000_0007_EDX_INVTSC) {
            return Err(format!(
                "leaf 0x8000_0007 mismatch: {:?}",
                query(0x8000_0007, 0)
            ));
        }
        if query(0x8000_0008, 0)
            != CpuidRegs::new(u32::from(expected_max_phy_addr) | (48 << 8), 0, 0, 0)
        {
            return Err(format!(
                "leaf 0x8000_0008 mismatch: {:?}",
                query(0x8000_0008, 0)
            ));
        }
        for ext_leaf in [
            0x8000_0002,
            0x8000_0003,
            0x8000_0004,
            0x8000_0005,
            0x8000_0006,
            0x8000_0009,
            0x8000_001d,
            0x8000_001f,
            0x8000_0021,
        ] {
            let r = query(ext_leaf, 0);
            if r != CpuidRegs::ZERO {
                return Err(format!("extended leaf {ext_leaf:#x} leaked {r:?}"));
            }
        }
        Ok(())
    }

    fn synthetic_epyc_zen4_v4_supported() -> Vec<CpuidLeafEntry> {
        vec![
            CpuidLeafEntry::basic(
                0,
                CpuidRegs::new(
                    0x10,
                    u32::from_le_bytes(*b"Auth"),
                    u32::from_le_bytes(*b"cAMD"),
                    u32::from_le_bytes(*b"enti"),
                ),
            ),
            // Raw /dev/kvm supported CPUID: OSXSAVE (27) = 0, APIC (9) = 0, plus AES, PCLMULQDQ,
            // RDRAND, PCID, x2APIC, TSC_DEADLINE, HYPERVISOR all set on an x86-64-v4 host.
            CpuidLeafEntry::basic(
                1,
                CpuidRegs::new(
                    0x00a1_0f11,
                    0x0008_0800,
                    CPUID_1_ECX_X86_64_V3_HW
                        | (1 << 1)  // PCLMULQDQ
                        | (1 << 17) // PCID
                        | (1 << 21) // x2APIC
                        | (1 << 24) // TSC_DEADLINE
                        | (1 << 25) // AES
                        | (1 << 30) // RDRAND
                        | CPUID_1_ECX_HYPERVISOR,
                    CPUID_1_EDX_X86_64_V3_HW
                        | (1 << 1)  // VME
                        | (1 << 11) // SEP
                        | (1 << 12) // MTRR
                        | (1 << 28), // HTT
                ),
            ),
            CpuidLeafEntry::indexed(
                7,
                0,
                CpuidRegs::new(
                    1,
                    CPUID_7_0_EBX_PINNED
                        | (1 << 0)  // FSGSBASE
                        | (1 << 16) // AVX512F
                        | (1 << 17) // AVX512DQ
                        | (1 << 18) // RDSEED
                        | (1 << 19) // ADX
                        | (1 << 28) // AVX512CD
                        | (1 << 29) // SHA
                        | (1 << 30) // AVX512BW
                        | (1 << 31), // AVX512VL
                    (1 << 2) | (1 << 3) | (1 << 6) | (1 << 8) | (1 << 9) | (1 << 16), // UMIP, PKU, VBMI2, GFNI, VAES, LA57
                    1 << 24,                                                          // AMX_TILE
                ),
            ),
            CpuidLeafEntry::indexed(7, 1, CpuidRegs::new(1 << 5, 0, 0, 0)), // AVX512_BF16
            CpuidLeafEntry::indexed(0x0d, 0, CpuidRegs::new(0xe7, 2688, 2688, 0)),
            CpuidLeafEntry::indexed(0x0d, 1, CpuidRegs::new(0x0f, 832, 0, 0)),
            CpuidLeafEntry::indexed(0x0d, 2, CpuidRegs::new(256, 576, 0, 0)),
            CpuidLeafEntry::indexed(0x0d, 5, CpuidRegs::new(64, 1088, 0, 0)), // AVX-512 opmask
            CpuidLeafEntry::basic(
                0x4000_0000,
                CpuidRegs::new(
                    0x4000_0001,
                    u32::from_le_bytes(*b"KVMK"),
                    u32::from_le_bytes(*b"KVM\0"),
                    u32::from_le_bytes(*b"VMKV"),
                ),
            ),
            CpuidLeafEntry::basic(0x8000_0000, CpuidRegs::new(0x8000_0022, 0, 0, 0)),
            CpuidLeafEntry::basic(
                0x8000_0001,
                CpuidRegs::new(
                    0,
                    0,
                    CPUID_8000_0001_ECX_X86_64_V3 | (1 << 6) | (1 << 8), // SSE4A | 3DNOWPREFETCH
                    CPUID_8000_0001_EDX_X86_64_V3 | (1 << 26) | (1 << 27), // PDPE1GB | RDTSCP
                ),
            ),
            CpuidLeafEntry::basic(0x8000_0008, CpuidRegs::new(52 | (57 << 8), 1 << 0, 0, 0)),
            CpuidLeafEntry::basic(0x8000_001f, CpuidRegs::new(0xf, 0, 0, 0)), // AMD SEV
        ]
    }

    #[test]
    fn raw_unscrubbed_host_cpuid_fails_v3_isolation_audit() {
        // Negative control reproducing pre-#667 KVM behavior (`KVM_GET_SUPPORTED_CPUID` pass-through).
        let raw = synthetic_epyc_zen4_v4_supported();
        let err = audit_strict_x86_64_v3_only(|l, s| emulate_cpuid_table_query(&raw, l, s), 0, 48)
            .expect_err("raw x86-64-v4 host CPUID table must fail the strict v3 audit");
        assert!(err.contains("mismatch"), "unexpected audit error: {err}");
    }

    #[test]
    fn x86_64_v3_table_advertises_exact_psabi_v3_and_no_feature_outside_v3() {
        let view = GuestCpuidView::x86_64_v3();
        // Keep these architectural bit positions independent of the production
        // masks: adding a feature to a mask must not also update its oracle.
        assert_eq!(view.cpuid(1, 0).ecx, 0x3cd8_3201);
        assert_eq!(view.cpuid(1, 0).edx, 0x0789_a37d);
        assert_eq!(view.cpuid(7, 0), CpuidRegs::new(0, 0x0010_01a8, 0, 0));
        assert_eq!(view.cpuid(0x8000_0001, 0).ecx, 0x21);
        assert_eq!(view.cpuid(0x8000_0001, 0).edx, 0x2010_0800);
        audit_strict_x86_64_v3_only(|leaf, subleaf| view.cpuid(leaf, subleaf), 0, 48)
            .expect("GuestCpuidView::cpuid must satisfy strict x86-64-v3 profile");

        let entries = view.to_leaf_entries();
        assert_eq!(
            entries.len(),
            11,
            "the installed table has a fixed work budget"
        );
        audit_strict_x86_64_v3_only(
            |leaf, subleaf| emulate_cpuid_table_query(&entries, leaf, subleaf),
            0,
            48,
        )
        .expect("installed KVM leaf entries must satisfy strict x86-64-v3 profile");

        for leaf in [
            0,
            1,
            2,
            7,
            0x0b,
            0x0d,
            0x15,
            0x16,
            0x17,
            0x4000_0000,
            0x8000_0000,
            0x8000_0001,
            0x8000_0007,
            0x8000_0008,
            0x8000_001f,
        ] {
            for subleaf in 0..=3 {
                assert_eq!(
                    emulate_cpuid_table_query(&entries, leaf, subleaf),
                    view.cpuid(leaf, subleaf),
                    "KVM leaf table and GuestCpuidView::cpuid diverged at ({leaf:#x}, {subleaf:#x})"
                );
            }
        }
    }

    #[test]
    fn qualify_supported_scrubs_v4_amd_and_intel_hosts_and_clamps_max_phy_addr() {
        // 52-bit AMD EPYC Zen 4 host -> clamped to 48-bit physical, 48-bit linear, zero non-v3 bits.
        let epyc = synthetic_epyc_zen4_v4_supported();
        let view = GuestCpuidView::qualify_supported(&epyc).expect("qualify EPYC Zen 4");
        assert_eq!(view.max_phy_addr(), 48);
        let entries = view.to_leaf_entries();
        audit_strict_x86_64_v3_only(|l, s| emulate_cpuid_table_query(&entries, l, s), 0, 48)
            .expect("scrubbed EPYC table must pass strict v3 audit");

        // 46-bit Intel Xeon Skylake-SP host (lacking UMIP, MAXPHYADDR = 46 < 48) -> clamped to 46.
        let mut skylake = synthetic_epyc_zen4_v4_supported();
        for entry in &mut skylake {
            if entry.function == 7 && entry.index == 0 {
                entry.regs.ecx = 0; // Skylake-SP lacks UMIP
            }
            if entry.function == 0x8000_0008 {
                entry.regs = CpuidRegs::new(46 | (48 << 8), 0, 0, 0);
            }
        }
        let skylake_view = GuestCpuidView::qualify_supported(&skylake).expect("qualify Skylake-SP");
        assert_eq!(skylake_view.max_phy_addr(), 46);
        let skylake_entries = skylake_view.to_leaf_entries();
        audit_strict_x86_64_v3_only(
            |l, s| emulate_cpuid_table_query(&skylake_entries, l, s),
            0,
            46,
        )
        .expect("scrubbed Skylake-SP table must pass strict v3 audit");
    }

    #[test]
    fn qualify_supported_refuses_hosts_missing_any_required_v3_or_cpl0_capability() {
        let base = synthetic_epyc_zen4_v4_supported();

        // Empty table is rejected.
        assert_eq!(
            GuestCpuidView::qualify_supported(&[]),
            Err(CpuidQualificationError::MissingLeaf {
                leaf: 1,
                subleaf: 0
            })
        );

        // Dropping any single required Leaf 1 ECX bit fails closed.
        for bit in [0_u8, 9, 12, 13, 19, 20, 22, 23, 26, 28, 29] {
            let mut broken = base.clone();
            broken
                .iter_mut()
                .find(|e| e.function == 1)
                .unwrap()
                .regs
                .ecx &= !(1 << bit);
            assert!(
                matches!(
                    GuestCpuidView::qualify_supported(&broken),
                    Err(CpuidQualificationError::MissingFeature {
                        leaf: 1,
                        subleaf: 0,
                        reg: CpuidRegisterName::Ecx,
                        bit: b,
                        ..
                    }) if b == bit
                ),
                "missing 1.ECX bit {bit} must be rejected"
            );
        }

        // Dropping any single required Leaf (7, 0) EBX bit (BMI1, AVX2, SMEP, BMI2, SMAP) fails closed.
        for bit in [3_u8, 5, 7, 8, 20] {
            let mut broken = base.clone();
            broken
                .iter_mut()
                .find(|e| e.function == 7 && e.index == 0)
                .unwrap()
                .regs
                .ebx &= !(1 << bit);
            assert!(
                matches!(
                    GuestCpuidView::qualify_supported(&broken),
                    Err(CpuidQualificationError::MissingFeature {
                        leaf: 7,
                        subleaf: 0,
                        reg: CpuidRegisterName::Ebx,
                        bit: b,
                        ..
                    }) if b == bit
                ),
                "missing 7.0.EBX bit {bit} must be rejected"
            );
        }

        // Dropping LAHF_LM (0) or LZCNT (5) in 0x8000_0001.ECX fails closed.
        for bit in [0_u8, 5] {
            let mut broken = base.clone();
            broken
                .iter_mut()
                .find(|e| e.function == 0x8000_0001)
                .unwrap()
                .regs
                .ecx &= !(1 << bit);
            assert!(
                matches!(
                    GuestCpuidView::qualify_supported(&broken),
                    Err(CpuidQualificationError::MissingFeature {
                        leaf: 0x8000_0001,
                        subleaf: 0,
                        reg: CpuidRegisterName::Ecx,
                        bit: b,
                        ..
                    }) if b == bit
                ),
                "missing 0x8000_0001.ECX bit {bit} must be rejected"
            );
        }

        // Dropping SYSCALL (11), NX (20), or LM (29) in 0x8000_0001.EDX fails closed.
        for bit in [11_u8, 20, 29] {
            let mut broken = base.clone();
            broken
                .iter_mut()
                .find(|e| e.function == 0x8000_0001)
                .unwrap()
                .regs
                .edx &= !(1 << bit);
            assert!(
                matches!(
                    GuestCpuidView::qualify_supported(&broken),
                    Err(CpuidQualificationError::MissingFeature {
                        leaf: 0x8000_0001,
                        subleaf: 0,
                        reg: CpuidRegisterName::Edx,
                        bit: b,
                        ..
                    }) if b == bit
                ),
                "missing 0x8000_0001.EDX bit {bit} must be rejected"
            );
        }

        // Broken XSAVE AVX geometry fails closed.
        let mut broken_xsave = base.clone();
        broken_xsave
            .iter_mut()
            .find(|e| e.function == 0x0d && e.index == 2)
            .unwrap()
            .regs
            .ebx = 640;
        assert!(matches!(
            GuestCpuidView::qualify_supported(&broken_xsave),
            Err(CpuidQualificationError::UnsupportedXsaveGeometry { .. })
        ));

        // Insufficient MAXPHYADDR (< 36) fails closed.
        let mut broken_phy = base;
        broken_phy
            .iter_mut()
            .find(|e| e.function == 0x8000_0008)
            .unwrap()
            .regs
            .eax = 32 | (48 << 8);
        assert_eq!(
            GuestCpuidView::qualify_supported(&broken_phy),
            Err(CpuidQualificationError::InsufficientMaxPhyAddr {
                supported: 32,
                minimum: 36,
            })
        );
    }

    #[test]
    fn per_vcpu_apic_id_and_high_frequency_tsc_calibration_round_trip() {
        for apic_id in [0_u8, 1, 7, 255] {
            let ratio = TscCrystalRatio::from_khz(4_500_000).expect("4.5 GHz kHz ratio");
            assert_eq!(ratio.tsc_hz().get(), 4_500_000_000);
            let view = GuestCpuidView::x86_64_v3()
                .with_apic_id(apic_id)
                .with_tsc(Some(ratio));
            assert_eq!((view.cpuid(1, 0).ebx >> 24) as u8, apic_id);
            let l15 = view.cpuid(0x15, 0);
            let computed = u128::from(l15.ecx) * u128::from(l15.ebx) / u128::from(l15.eax);
            assert_eq!(computed, 4_500_000_000);
        }

        // Pre-CR4.OSXSAVE reset state mirrors OSXSAVE=0 while keeping XSAVE=1.
        let reset_l1 = GuestCpuidView::x86_64_v3().cpuid_for_state(1, 0, false, false);
        assert_ne!(reset_l1.ecx & CPUID_1_ECX_XSAVE, 0);
        assert_eq!(reset_l1.ecx & CPUID_1_ECX_OSXSAVE, 0);
        assert_eq!(
            GuestCpuidView::x86_64_v3()
                .cpuid_for_state(0x0d, 0, false, false)
                .ebx,
            576
        );
    }
}
