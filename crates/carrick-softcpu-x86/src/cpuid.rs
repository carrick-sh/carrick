//! Guest CPUID view trait and architectural profiles for `carrick-softcpu-x86`.
//!
//! Host `CPUID` never leaks into translated blocks: `SoftCpu` routes every `0F A2`
//! (`CPUID`) exit and feature-gated instruction check (`MOV CR4`, `WRMSR`, `XSETBV`,
//! `CLAC`/`STAC`) through [`CpuidAuthority`].

pub use carrick_x86::{CpuidRegs, DEFAULT_TSC_HZ};

/// Authority supplying the guest-visible `CPUID` topology and feature set for a [`crate::SoftCpu`].
pub trait CpuidAuthority: Send + Sync {
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

    /// `CPUID.01H:EDX.VME[bit 1]`.
    fn supports_vme(&self) -> bool {
        (self.cpuid(1, 0).edx & (1 << 1)) != 0
    }

    /// `CPUID.80000001H:EDX.NX[bit 20]`.
    fn supports_nxe(&self) -> bool {
        (self.cpuid(0x8000_0001, 0).edx & (1 << 20)) != 0
    }

    /// Nominal guest TSC frequency in Hz derived from `CPUID.15H` (`ECX * EBX / EAX`),
    /// defaulting to `DEFAULT_TSC_HZ` (2 GHz) when leaf `0x15` is unpopulated.
    fn tsc_hz(&self) -> u64 {
        if self.cpuid(0, 0).eax >= 0x15 {
            let l15 = self.cpuid(0x15, 0);
            if l15.eax != 0 && l15.ebx != 0 && l15.ecx != 0 {
                let hz = (u128::from(l15.ecx) * u128::from(l15.ebx)) / u128::from(l15.eax);
                if let Ok(hz64) = u64::try_from(hz)
                    && hz64 != 0
                {
                    return hz64;
                }
            }
        }
        DEFAULT_TSC_HZ
    }

    /// Supported `XCR0` component bitmap from `CPUID.(EAX=0DH,ECX=0H):EDX:EAX`.
    fn supported_xcr0_mask(&self) -> u64 {
        let leaf = self.cpuid(0x0d, 0);
        (u64::from(leaf.edx) << 32) | u64::from(leaf.eax)
    }

    /// Initial 8-bit xAPIC ID advertised in `CPUID.01H:EBX[31:24]`.
    fn apic_id(&self) -> u8 {
        (self.cpuid(1, 0).ebx >> 24) as u8
    }
}

impl CpuidAuthority for carrick_x86::GuestCpuidView {
    fn cpuid(&self, leaf: u32, subleaf: u32) -> CpuidRegs {
        self.cpuid(leaf, subleaf)
    }
    fn mirrors_osxsave(&self) -> bool {
        true
    }
}
