//! Architectural Model-Specific Register (`MSR`) file for `carrick-softcpu-x86`.
//!
//! `RDMSR` (`0F 32`), `WRMSR` (`0F 30`), `SWAPGS` (`0F 01 F8`), `SYSCALL`, and `SYSRET`
//! operate over [`MsrFile`]. Unimplemented MSR indices, reserved bits, and non-canonical
//! linear-address MSR writes fail closed with [`MsrError::GeneralProtection`] (`#GP(0)`).

use std::mem::offset_of;
use std::sync::OnceLock;
use std::time::Instant;

use crate::cpuid::{DEFAULT_TSC_HZ, GuestCpuidView};
use crate::mmu::is_canonical_va;

/// Typed 32-bit architectural MSR selector (`ECX` operand of `RDMSR`/`WRMSR`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MsrIndex(pub u32);

impl MsrIndex {
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

pub const MSR_IA32_TSC: MsrIndex = MsrIndex(0x0000_0010);
pub const MSR_IA32_APIC_BASE: MsrIndex = MsrIndex(0x0000_001b);
pub const MSR_IA32_MISC_ENABLE: MsrIndex = MsrIndex(0x0000_01a0);
pub const MSR_IA32_PAT: MsrIndex = MsrIndex(0x0000_0277);
pub const MSR_IA32_TSC_DEADLINE: MsrIndex = MsrIndex(0x0000_06e0);
pub const MSR_IA32_EFER: MsrIndex = MsrIndex(0xc000_0080);
pub const MSR_IA32_STAR: MsrIndex = MsrIndex(0xc000_0081);
pub const MSR_IA32_LSTAR: MsrIndex = MsrIndex(0xc000_0082);
pub const MSR_IA32_CSTAR: MsrIndex = MsrIndex(0xc000_0083);
pub const MSR_IA32_FMASK: MsrIndex = MsrIndex(0xc000_0084);
pub const MSR_IA32_SFMASK: MsrIndex = MSR_IA32_FMASK;
pub const MSR_IA32_FS_BASE: MsrIndex = MsrIndex(0xc000_0100);
pub const MSR_IA32_GS_BASE: MsrIndex = MsrIndex(0xc000_0101);
pub const MSR_IA32_KERNEL_GS_BASE: MsrIndex = MsrIndex(0xc000_0102);

/// `IA32_EFER` architectural bits (Intel SDM Vol. 4 / AMD64 APM Vol. 2 §3.1.7).
pub const EFER_SCE: u64 = 1 << 0;
pub const EFER_LME: u64 = 1 << 8;
pub const EFER_LMA: u64 = 1 << 10;
pub const EFER_NXE: u64 = 1 << 11;
pub const EFER_VALID_MASK: u64 = EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE;

/// Reset value of `IA32_PAT` (`WB=6`, `WT=4`, `UC-=7`, `UC=0`).
pub const DEFAULT_IA32_PAT: u64 = 0x0007_0406_0007_0406;
/// Reset value of `IA32_APIC_BASE` (`0xfee0_0000 | BSP(0x100) | EN(0x800)`).
pub const DEFAULT_IA32_APIC_BASE: u64 = 0xfee0_0900;

/// Architectural refusal raised by an illegal `RDMSR`/`WRMSR` access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsrError {
    /// Raises `#GP(0)` without mutating architectural state.
    GeneralProtection,
}

/// CPUID-derived capabilities consulted during `RDMSR`/`WRMSR` validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsrCapabilities {
    pub max_phy_addr: u8,
    pub nxe: bool,
    pub tsc_deadline: bool,
    pub x2apic: bool,
    pub tsc_hz: u64,
}

impl Default for MsrCapabilities {
    fn default() -> Self {
        Self {
            max_phy_addr: 48,
            nxe: true,
            tsc_deadline: false,
            x2apic: false,
            tsc_hz: DEFAULT_TSC_HZ,
        }
    }
}

impl MsrCapabilities {
    /// Derive MSR validation capabilities from a [`GuestCpuidView`].
    #[must_use]
    pub fn from_cpuid(view: &dyn GuestCpuidView) -> Self {
        Self {
            max_phy_addr: view.max_phy_addr(),
            nxe: view.supports_nxe(),
            tsc_deadline: view.supports_tsc_deadline(),
            x2apic: view.supports_x2apic(),
            tsc_hz: view.tsc_hz(),
        }
    }
}

/// Side effects of a committed `WRMSR` on the owning vCPU context.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MsrWriteEffects {
    /// `IA32_EFER.NXE` or `IA32_PAT` changed, requiring a local TLB flush.
    pub flush_tlb: bool,
}

fn default_tsc_epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// Per-vCPU architectural MSR register file (single owner of `EFER`, `FS_BASE`,
/// `GS_BASE`, `KERNEL_GS_BASE`, `SYSCALL` MSRs, and guest `TSC` state).
///
/// Fields are private so no direct field write can bypass [`Self::write`] validation:
///
/// ```compile_fail
/// use carrick_softcpu_x86::MsrFile;
/// fn bypass_msr(msrs: &mut MsrFile) { msrs.efer = 0; }
/// ```
/// ```compile_fail
/// use carrick_softcpu_x86::SoftCpuContext;
/// fn bypass_ctx(ctx: &mut SoftCpuContext) { ctx.fs_base = 0; }
/// ```
#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MsrFile {
    fs_base: u64,
    gs_base: u64,
    kernel_gs_base: u64,
    efer: u64,
    star: u64,
    lstar: u64,
    cstar: u64,
    fmask: u64,
    apic_base: u64,
    misc_enable: u64,
    pat: u64,
    tsc_deadline: u64,
    tsc_base: u64,
    tsc_anchor: Option<Instant>,
}

impl Default for MsrFile {
    fn default() -> Self {
        Self::new()
    }
}

impl MsrFile {
    pub(crate) const FS_BASE_OFFSET: usize = offset_of!(Self, fs_base);
    pub(crate) const GS_BASE_OFFSET: usize = offset_of!(Self, gs_base);

    /// Construct an architectural 64-bit MSR file matching `SoftCpuContext` reset state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            fs_base: 0,
            gs_base: 0,
            kernel_gs_base: 0,
            efer: EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE,
            star: 0,
            lstar: 0,
            cstar: 0,
            fmask: 0,
            apic_base: DEFAULT_IA32_APIC_BASE,
            misc_enable: 1,
            pat: DEFAULT_IA32_PAT,
            tsc_deadline: 0,
            tsc_base: 0,
            tsc_anchor: None,
        }
    }

    pub(crate) fn new_anchored() -> Self {
        let mut msrs = Self::new();
        msrs.tsc_anchor = Some(Instant::now());
        msrs
    }

    #[must_use]
    pub const fn efer(&self) -> u64 {
        self.efer
    }

    #[must_use]
    pub const fn star(&self) -> u64 {
        self.star
    }

    #[must_use]
    pub const fn lstar(&self) -> u64 {
        self.lstar
    }

    #[must_use]
    pub const fn cstar(&self) -> u64 {
        self.cstar
    }

    #[must_use]
    pub const fn fmask(&self) -> u64 {
        self.fmask
    }

    #[must_use]
    pub const fn fs_base(&self) -> u64 {
        self.fs_base
    }

    #[must_use]
    pub const fn gs_base(&self) -> u64 {
        self.gs_base
    }

    #[must_use]
    pub const fn kernel_gs_base(&self) -> u64 {
        self.kernel_gs_base
    }

    #[must_use]
    pub const fn apic_base(&self) -> u64 {
        self.apic_base
    }

    #[must_use]
    pub const fn misc_enable(&self) -> u64 {
        self.misc_enable
    }

    #[must_use]
    pub const fn pat(&self) -> u64 {
        self.pat
    }

    #[must_use]
    pub const fn tsc_deadline(&self) -> u64 {
        self.tsc_deadline
    }

    /// Sample the guest TSC (`RDTSC` and `RDMSR(IA32_TSC)`) scaled by `tsc_hz`.
    #[must_use]
    pub fn read_tsc(&self, tsc_hz: u64) -> u64 {
        let anchor = self.tsc_anchor.unwrap_or_else(default_tsc_epoch);
        let nanos = Instant::now().saturating_duration_since(anchor).as_nanos();
        let delta = (nanos.saturating_mul(u128::from(tsc_hz)) / 1_000_000_000) as u64;
        self.tsc_base.wrapping_add(delta)
    }

    /// Synchronize hardware-owned `IA32_EFER.LMA` (`LME && CR0.PG`) after a `CR0` write.
    pub(crate) fn sync_lma(&mut self, cr0: u64) {
        let lma = if (self.efer & EFER_LME) != 0 && (cr0 & (1 << 31)) != 0 {
            EFER_LMA
        } else {
            0
        };
        self.efer = (self.efer & !EFER_LMA) | lma;
    }

    /// Read an architectural MSR (`RDMSR`), returning `Err(MsrError::GeneralProtection)`
    /// for unknown or feature-disabled MSRs.
    pub fn read(&self, index: MsrIndex, caps: MsrCapabilities) -> Result<u64, MsrError> {
        match index {
            MSR_IA32_TSC => Ok(self.read_tsc(caps.tsc_hz)),
            MSR_IA32_APIC_BASE => Ok(self.apic_base),
            MSR_IA32_MISC_ENABLE => Ok(self.misc_enable),
            MSR_IA32_PAT => Ok(self.pat),
            MSR_IA32_TSC_DEADLINE => {
                if !caps.tsc_deadline {
                    return Err(MsrError::GeneralProtection);
                }
                Ok(self.tsc_deadline)
            }
            MSR_IA32_EFER => Ok(self.efer),
            MSR_IA32_STAR => Ok(self.star),
            MSR_IA32_LSTAR => Ok(self.lstar),
            MSR_IA32_CSTAR => Ok(self.cstar),
            MSR_IA32_FMASK => Ok(self.fmask),
            MSR_IA32_FS_BASE => Ok(self.fs_base),
            MSR_IA32_GS_BASE => Ok(self.gs_base),
            MSR_IA32_KERNEL_GS_BASE => Ok(self.kernel_gs_base),
            _ => Err(MsrError::GeneralProtection),
        }
    }

    /// Write an architectural MSR (`WRMSR`), validating SDM reserved bits, canonical
    /// linear addresses, paging-active `EFER.LME` lock, and CPUID feature gates.
    pub fn write(
        &mut self,
        index: MsrIndex,
        value: u64,
        cr0: u64,
        caps: MsrCapabilities,
    ) -> Result<MsrWriteEffects, MsrError> {
        let mut effects = MsrWriteEffects::default();
        match index {
            MSR_IA32_TSC => {
                self.tsc_base = value;
                self.tsc_anchor = Some(Instant::now());
            }
            MSR_IA32_APIC_BASE => {
                let phy_limit = if caps.max_phy_addr >= 64 {
                    u64::MAX
                } else {
                    (1u64 << caps.max_phy_addr) - 1
                };
                // Bits [7:0], bit 9, and bits >= MAXPHYADDR are reserved.
                if (value & 0x2ff) != 0 || (value & !phy_limit) != 0 {
                    return Err(MsrError::GeneralProtection);
                }
                let extd = (value & (1 << 10)) != 0;
                let en = (value & (1 << 11)) != 0;
                // SDM Vol. 3A §10.12.1: EXTD=1 requires x2APIC support and EN=1.
                if extd && (!caps.x2apic || !en) {
                    return Err(MsrError::GeneralProtection);
                }
                self.apic_base = value;
            }
            MSR_IA32_MISC_ENABLE => {
                if (value >> 39) != 0 {
                    return Err(MsrError::GeneralProtection);
                }
                self.misc_enable = value;
            }
            MSR_IA32_PAT => {
                // SDM Vol. 3A §11.12.2: each of the 8 PAT fields must be 0, 1, 4, 5, 6, or 7.
                for byte in value.to_le_bytes() {
                    if !matches!(byte, 0 | 1 | 4 | 5 | 6 | 7) {
                        return Err(MsrError::GeneralProtection);
                    }
                }
                if self.pat != value {
                    self.pat = value;
                    effects.flush_tlb = true;
                }
            }
            MSR_IA32_TSC_DEADLINE => {
                if !caps.tsc_deadline {
                    return Err(MsrError::GeneralProtection);
                }
                self.tsc_deadline = value;
            }
            MSR_IA32_EFER => {
                if (value & !EFER_VALID_MASK) != 0 {
                    return Err(MsrError::GeneralProtection);
                }
                if !caps.nxe && (value & EFER_NXE) != 0 {
                    return Err(MsrError::GeneralProtection);
                }
                let paging = (cr0 & (1 << 31)) != 0;
                // SDM Vol. 3A §9.8.5: modifying IA32_EFER.LME while CR0.PG=1 raises #GP(0).
                if paging && ((value & EFER_LME) != (self.efer & EFER_LME)) {
                    return Err(MsrError::GeneralProtection);
                }
                // IA32_EFER.LMA is read-only hardware state: LME && CR0.PG.
                let lma = if (value & EFER_LME) != 0 && paging {
                    EFER_LMA
                } else {
                    0
                };
                let next_efer = (value & !EFER_LMA) | lma;
                if (next_efer & EFER_NXE) != (self.efer & EFER_NXE) {
                    effects.flush_tlb = true;
                }
                self.efer = next_efer;
            }
            MSR_IA32_STAR => self.star = value,
            MSR_IA32_FMASK => {
                // SDM Vol. 4 IA32_FMASK: bits [63:32] are reserved and must be zero.
                if (value >> 32) != 0 {
                    return Err(MsrError::GeneralProtection);
                }
                self.fmask = value;
            }
            MSR_IA32_LSTAR
            | MSR_IA32_CSTAR
            | MSR_IA32_FS_BASE
            | MSR_IA32_GS_BASE
            | MSR_IA32_KERNEL_GS_BASE => {
                if !is_canonical_va(value) {
                    return Err(MsrError::GeneralProtection);
                }
                match index {
                    MSR_IA32_LSTAR => self.lstar = value,
                    MSR_IA32_CSTAR => self.cstar = value,
                    MSR_IA32_FS_BASE => self.fs_base = value,
                    MSR_IA32_GS_BASE => self.gs_base = value,
                    _ => self.kernel_gs_base = value,
                }
            }
            _ => return Err(MsrError::GeneralProtection),
        }
        Ok(effects)
    }

    /// Atomically exchange `IA32_GS_BASE` and `IA32_KERNEL_GS_BASE` (`SWAPGS`).
    pub const fn swapgs(&mut self) {
        std::mem::swap(&mut self.gs_base, &mut self.kernel_gs_base);
    }
}
