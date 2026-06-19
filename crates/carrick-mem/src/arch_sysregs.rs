//! aarch64 stage-1 bootstrap system-register VALUES, shared by both hypervisor
//! backends (HVF on macOS, KVM on Linux).
//!
//! The MMU/cache configuration carrick programs into a fresh vCPU before
//! entering the guest is the SAME on both backends — the comments in the KVM
//! path literally read "as HVF" / "identical bootstrap value to the HVF path".
//! These four constants are the neutral, byte-identical core; they were
//! previously hardcoded VERBATIM in two places
//! (`carrick-vmm-kvm::guest_setup::program_sysregs` and
//! `carrick-vmm-hvf::trap`), a boot-critical duplication where a one-sided edit
//! would silently desync the two backends' MMU setup.
//!
//! **What is NOT shared (per-backend glue):** PSTATE/PAN handling. Apple HVF
//! starts vCPUs with PSTATE.PAN=1 (FEAT_PAN3 turns any EL1 fetch from an
//! `AP[1]=1` page into a permission fault), whereas KVM clears PAN so the EL1
//! sentinel store reaches MMIO. SCTLR_EL1.SPAN (bit 23) is the register face of
//! that divergence — see [`SCTLR_EL1_BOOTSTRAP`] — so it stays in each backend.

/// `MAIR_EL1` slot 0 = Normal memory, Inner & Outer Write-Back Cacheable,
/// RW-allocate (`0xFF`). Slots 1..7 stay 0 (Device-nGnRnE), unused for now.
pub const MAIR_EL1_BOOTSTRAP: u64 = 0xFF;

/// `TCR_EL1` bootstrap value — TTBR0 (lower half) and TTBR1 (upper half) BOTH
/// active. Derived once here so the bit-math lives in exactly one place:
///
/// | Field            | Bits    | Value  | Meaning                                  |
/// |------------------|---------|--------|------------------------------------------|
/// | `T0SZ`           | `[5:0]` | 16     | 48-bit VA, lower half                    |
/// | `IRGN0`          | `[9:8]` | `0b11` | Inner Write-Back, RW-allocate (TTBR0)    |
/// | `ORGN0`          | `[11:10]`| `0b11`| Outer Write-Back, RW-allocate (TTBR0)    |
/// | `SH0`            | `[13:12]`| `0b11`| Inner Shareable (TTBR0)                  |
/// | `T1SZ`           | `[21:16]`| 16    | 48-bit VA, upper half                    |
/// | `IRGN1`          | `[25:24]`| `0b11`| Inner Write-Back, RW-allocate (TTBR1)    |
/// | `ORGN1`          | `[27:26]`| `0b11`| Outer Write-Back, RW-allocate (TTBR1)    |
/// | `SH1`            | `[29:28]`| `0b11`| Inner Shareable (TTBR1)                  |
/// | `TG1`            | `[31:30]`| `0b10`| 4 KiB granule (TTBR1 — encoding differs!) |
/// | `IPS`            | `[34:32]`| `0b010`| 40-bit IPA (max for M-series HVF)        |
/// | `TBI0`           | `[37]`   | 1     | Top-byte ignored on translation (lower)  |
/// | `TBI1`           | `[38]`   | 1     | Top-byte ignored on translation (upper)  |
///
/// `EPD1`=0 (TTBR1 walks ENABLED); TG0 is `0b00` (4 KiB, the field's zero
/// default). TBI is required because Rosetta tags pointers in the top byte.
pub const TCR_EL1_BOOTSTRAP: u64 = {
    const T0SZ: u64 = 16;
    const T1SZ: u64 = 16;
    T0SZ
        | (0b11 << 8)   // IRGN0
        | (0b11 << 10)  // ORGN0
        | (0b11 << 12)  // SH0
        | (T1SZ << 16)
        | (0b11 << 24)  // IRGN1
        | (0b11 << 26)  // ORGN1
        | (0b11 << 28)  // SH1
        | (0b10 << 30)  // TG1 = 4 KiB
        | (0b010 << 32) // IPS = 40-bit
        | (1 << 37)     // TBI0
        | (1 << 38) // TBI1
};

/// `SCTLR_EL1` bootstrap value — the bits COMMON to both backends:
/// `M`(0, stage-1 MMU on), `C`(2, data cache), `I`(12, instruction cache),
/// `DZE`(14, EL0 `DC ZVA`), `UCT`(15, EL0 read of `CTR_EL0`),
/// `UCI`(26, EL0 cache-maintenance ops). glibc startup leans on UCT/UCI/DZE.
///
/// NOTE: this is the SHARED base only. KVM additionally ORs in `SPAN`
/// (bit 23) — "PSTATE.PAN left unchanged on EL1 entry" — which is load-bearing
/// for the KVM MMIO sentinel store (it enters EL0 with PAN=0 and needs PAN to
/// stay 0 through the `svc` trap so the EL1 sentinel `str` reaches stage-2 /
/// KVM_EXIT_MMIO). HVF leaves SPAN clear and forces PSTATE.PAN=1 with a
/// FEAT_PAN3 workaround instead. SPAN therefore stays per-backend PAN glue and
/// is NOT part of this shared constant.
pub const SCTLR_EL1_BOOTSTRAP: u64 = (1 << 2) | (1 << 12) | (1 << 14) | (1 << 15) | (1 << 26) | 1;

/// `CPACR_EL1` bootstrap value — `FPEN=0b11` (no FP/SIMD trap at EL0). Without
/// this, the guest libc's first NEON `memset`/`dup` faults on startup.
pub const CPACR_EL1_BOOTSTRAP: u64 = 0x3 << 20;

#[cfg(test)]
mod tests {
    use super::*;

    // Regression lock: these are BOOT-CRITICAL. A future edit that silently
    // changes any of them would wedge every guest on one or both backends. Each
    // assertion repeats the literal independently of the const expression, so a
    // typo in the const cannot be masked by a matching typo in the test.
    #[test]
    fn mair_is_normal_wb_cacheable() {
        assert_eq!(MAIR_EL1_BOOTSTRAP, 0xFF);
    }

    #[test]
    fn tcr_bootstrap_literal() {
        // Exact assembled value (independently computed from the doc table).
        assert_eq!(TCR_EL1_BOOTSTRAP, 0x62_bf10_3f10);
    }

    #[test]
    fn sctlr_shared_base_literal() {
        // M | C | I | DZE | UCT | UCI (NO SPAN — that is per-backend glue).
        assert_eq!(SCTLR_EL1_BOOTSTRAP, 0x0400_d005);
        // SPAN (bit 23) must NOT be set in the shared base.
        assert_eq!(SCTLR_EL1_BOOTSTRAP & (1 << 23), 0);
    }

    #[test]
    fn cpacr_fpen_no_trap_literal() {
        assert_eq!(CPACR_EL1_BOOTSTRAP, 0x0030_0000);
        assert_eq!(CPACR_EL1_BOOTSTRAP, 0x3 << 20);
    }
}
