//! Guest CPUID view trait and architectural profiles for `carrick-softcpu-x86`.
//!
//! Host `CPUID` never leaks into translated blocks: `SoftCpu` routes every `0F A2`
//! (`CPUID`) exit and feature-gated instruction check (`MOV CR4`, `WRMSR`, `XSETBV`,
//! `CLAC`/`STAC`) through [`GuestCpuidView`].

/// Four 32-bit general-purpose register outputs returned by `CPUID` (`EAX`, `EBX`, `ECX`, `EDX`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuidRegs {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

impl CpuidRegs {
    /// All-zero leaf response for unsupported leaves/subleaves.
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

/// Authority supplying the guest-visible `CPUID` topology and feature set for a [`crate::SoftCpu`].
pub trait GuestCpuidView: Send + Sync {
    /// Query `(leaf, subleaf)` (`EAX = leaf`, `ECX = subleaf`).
    fn cpuid(&self, leaf: u32, subleaf: u32) -> CpuidRegs;

    /// Whether `CPUID.01H:ECX.OSXSAVE[bit 27]` should dynamically mirror `CR4.OSXSAVE`
    /// when `CPUID.01H:ECX.XSAVE[bit 26]` is set (Intel SDM Vol. 2A `CPUID`).
    ///
    /// Architectural views enable this; synthetic unit-test stubs default to `false`
    /// so custom register patterns are returned verbatim.
    fn mirrors_osxsave(&self) -> bool {
        false
    }

    /// Guest physical address width (`CPUID.80000008H:EAX[7:0]`), defaulting to 48 bits
    /// when the view leaves `0x8000_0008` unpopulated.
    fn max_phy_addr(&self) -> u8 {
        let raw = (self.cpuid(0x8000_0008, 0).eax & 0xff) as u8;
        if raw == 0 { 48 } else { raw.clamp(32, 52) }
    }

    /// `CPUID.(EAX=07H,ECX=0H):EBX.SMEP[bit 7]`.
    fn supports_smep(&self) -> bool {
        (self.cpuid(7, 0).ebx & (1 << 7)) != 0
    }

    /// `CPUID.(EAX=07H,ECX=0H):EBX.SMAP[bit 20]`.
    fn supports_smap(&self) -> bool {
        (self.cpuid(7, 0).ebx & (1 << 20)) != 0
    }

    /// `CPUID.(EAX=07H,ECX=0H):ECX.UMIP[bit 2]`.
    fn supports_umip(&self) -> bool {
        (self.cpuid(7, 0).ecx & (1 << 2)) != 0
    }

    /// `CPUID.(EAX=07H,ECX=0H):EBX.FSGSBASE[bit 0]`.
    fn supports_fsgsbase(&self) -> bool {
        (self.cpuid(7, 0).ebx & 1) != 0
    }

    /// `CPUID.01H:ECX.PCID[bit 17]`.
    fn supports_pcid(&self) -> bool {
        (self.cpuid(1, 0).ecx & (1 << 17)) != 0
    }

    /// `CPUID.01H:ECX.XSAVE[bit 26]`.
    fn supports_xsave(&self) -> bool {
        (self.cpuid(1, 0).ecx & (1 << 26)) != 0
    }

    /// `CPUID.01H:ECX.TSC_Deadline[bit 24]`.
    fn supports_tsc_deadline(&self) -> bool {
        (self.cpuid(1, 0).ecx & (1 << 24)) != 0
    }

    /// `CPUID.01H:ECX.x2APIC[bit 21]`.
    fn supports_x2apic(&self) -> bool {
        (self.cpuid(1, 0).ecx & (1 << 21)) != 0
    }

    /// `CPUID.80000001H:EDX.NX[bit 20]`.
    fn supports_nxe(&self) -> bool {
        (self.cpuid(0x8000_0001, 0).edx & (1 << 20)) != 0
    }

    /// Supported `XCR0` component bitmap from `CPUID.(EAX=0DH,ECX=0H):EDX:EAX`.
    fn supported_xcr0_mask(&self) -> u64 {
        let leaf = self.cpuid(0x0d, 0);
        (u64::from(leaf.edx) << 32) | u64::from(leaf.eax)
    }
}

/// Default pinned Level 0 `CPUID` view (`SoftCpu::new`), independent of the host CPU.
///
/// Advertises baseline 64-bit integer/SSE2, legacy `XSAVE`/`XSAVEOPT`/`XSAVEC`
/// (`XCR0` mask `0x3`, 576-byte area), `SMEP`, `SMAP`, `UMIP`, `NX`, `SYSCALL`, and
/// 48-bit physical/linear addressing while keeping `FPU=0` and `AVX=0`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Level0CpuidView;

impl GuestCpuidView for Level0CpuidView {
    fn cpuid(&self, leaf: u32, subleaf: u32) -> CpuidRegs {
        match (leaf, subleaf) {
            (0, _) => CpuidRegs::new(
                0x0d,
                u32::from_le_bytes(*b"Genu"),
                u32::from_le_bytes(*b"ntel"),
                u32::from_le_bytes(*b"ineI"),
            ),
            (1, _) => CpuidRegs::new(
                0x0000_0663,
                0,
                (1 << 26) | (1 << 27),
                (1 << 2)
                    | (1 << 4)
                    | (1 << 5)
                    | (1 << 6)
                    | (1 << 7)
                    | (1 << 8)
                    | (1 << 9)
                    | (1 << 11)
                    | (1 << 13)
                    | (1 << 15)
                    | (1 << 16)
                    | (1 << 24)
                    | (1 << 25)
                    | (1 << 26),
            ),
            (7, 0) => CpuidRegs::new(0, (1 << 7) | (1 << 20), 1 << 2, 0),
            (0x0d, 0) => CpuidRegs::new(3, 576, 576, 0),
            (0x0d, 1) => CpuidRegs::new(3, 576, 0, 0),
            (0x8000_0000, _) => CpuidRegs::new(0x8000_0008, 0, 0, 0),
            (0x8000_0001, _) => CpuidRegs::new(0, 0, 1, (1 << 11) | (1 << 20) | (1 << 29)),
            (0x8000_0008, _) => CpuidRegs::new(48 | (48 << 8), 0, 0, 0),
            _ => CpuidRegs::ZERO,
        }
    }

    fn mirrors_osxsave(&self) -> bool {
        true
    }
}

/// Configurable CPL0 supervisor `CPUID` view matching the Carrick x86 CPL0 carrier contract
/// (including `0x15` crystal/TSC frequency, APIC ID, `TSC_Deadline`, `SMEP`, `SMAP`, `PCID`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cpl0CpuidView {
    pub apic_id: u8,
    pub tsc_hz: u32,
    pub max_phy_addr: u8,
    pub smep: bool,
    pub smap: bool,
    pub umip: bool,
    pub pcid: bool,
    pub tsc_deadline: bool,
}

impl Default for Cpl0CpuidView {
    fn default() -> Self {
        Self {
            apic_id: 0,
            tsc_hz: 2_000_000_000,
            max_phy_addr: 48,
            smep: true,
            smap: true,
            umip: true,
            pcid: true,
            tsc_deadline: true,
        }
    }
}

impl Cpl0CpuidView {
    /// Construct a CPL0 `CPUID` view for `apic_id` with deterministic `tsc_hz`.
    #[must_use]
    pub const fn new(apic_id: u8, tsc_hz: u32) -> Self {
        Self {
            apic_id,
            tsc_hz,
            max_phy_addr: 48,
            smep: true,
            smap: true,
            umip: true,
            pcid: true,
            tsc_deadline: true,
        }
    }
}

impl GuestCpuidView for Cpl0CpuidView {
    fn cpuid(&self, leaf: u32, subleaf: u32) -> CpuidRegs {
        let max_basic = if self.tsc_hz != 0 { 0x15 } else { 0x0d };
        match (leaf, subleaf) {
            (0, _) => CpuidRegs::new(
                max_basic,
                u32::from_le_bytes(*b"Genu"),
                u32::from_le_bytes(*b"ntel"),
                u32::from_le_bytes(*b"ineI"),
            ),
            (1, _) => {
                let mut ecx = (1 << 26) | (1 << 27);
                if self.pcid {
                    ecx |= 1 << 17;
                }
                if self.tsc_deadline {
                    ecx |= 1 << 24;
                }
                let ebx = (u32::from(self.apic_id) << 24) | (8 << 8);
                let edx = (1 << 2)
                    | (1 << 4)
                    | (1 << 5)
                    | (1 << 6)
                    | (1 << 7)
                    | (1 << 8)
                    | (1 << 9)
                    | (1 << 11)
                    | (1 << 13)
                    | (1 << 15)
                    | (1 << 16)
                    | (1 << 24)
                    | (1 << 25)
                    | (1 << 26);
                CpuidRegs::new(0x0000_0663, ebx, ecx, edx)
            }
            (7, 0) => {
                let mut ebx = 0u32;
                if self.smep {
                    ebx |= 1 << 7;
                }
                if self.smap {
                    ebx |= 1 << 20;
                }
                let ecx = if self.umip { 1 << 2 } else { 0 };
                CpuidRegs::new(0, ebx, ecx, 0)
            }
            (0x0b, 0) => CpuidRegs::new(0, 1, 0x0100, u32::from(self.apic_id)),
            (0x0b, 1) => CpuidRegs::new(1, 2, 0x0201, u32::from(self.apic_id)),
            (0x0d, 0) => CpuidRegs::new(3, 576, 576, 0),
            (0x0d, 1) => CpuidRegs::new(3, 576, 0, 0),
            (0x15, 0) if self.tsc_hz != 0 => CpuidRegs::new(1, 1, self.tsc_hz, 0),
            (0x8000_0000, _) => CpuidRegs::new(0x8000_0008, 0, 0, 0),
            (0x8000_0001, _) => CpuidRegs::new(0, 0, 1, (1 << 11) | (1 << 20) | (1 << 29)),
            (0x8000_0007, _) => CpuidRegs::new(0, 0, 0, 1 << 8),
            (0x8000_0008, _) => CpuidRegs::new(u32::from(self.max_phy_addr) | (48 << 8), 0, 0, 0),
            _ => CpuidRegs::ZERO,
        }
    }

    fn mirrors_osxsave(&self) -> bool {
        true
    }
}
