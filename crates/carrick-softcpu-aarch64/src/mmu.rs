//! Stage-1 translation for the copy-through engine: once SCTLR_EL1.M is set,
//! every handler data access and every block fetch translates through the
//! one AArch64 walker, `carrick_mmu_core::aarch64::stage1_walk::Aarch64Walker`
//! (Arm ARM DDI0487G.a D5), over descriptors read from guest physical memory.
//! A walker fault is an architectural abort taken to EL1 (D1.10, ESR/FAR via
//! `exception::syndrome`); a descriptor read the memory cannot serve, or a
//! TCR_EL1 the walker does not admit, is a provider stop, never a guest fault.
//!
//! With M clear, the address is used untranslated (D5.2.9 flat mapping).
//! There is no translation cache in this slice, so TTBR/TCR/SCTLR writes
//! and TLBI need no invalidation here.
use core::cell::RefCell;

use carrick_guest_arch::GuestVa;
use carrick_mmu_core::aarch64::stage1_walk::{
    Aarch64AccessClass, Aarch64El, Aarch64Fault, Aarch64FaultKind, Aarch64Leaf, Aarch64Level,
    Aarch64Regime, Aarch64WalkContext, Aarch64Walker, UnsupportedRegime,
};
use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
use carrick_mmu_core::live_descriptor_words::LiveDescriptorWords;
use carrick_mmu_core::stage1::{LeafAccess, Stage1Leaf, Stage1Walker, WalkError};

use crate::exception::{Access, Exception, FaultStatus, LeafLevel, TableLevel};
use crate::handler::GuestMemory;
use crate::state::{CpuState, ExceptionLevel, VirtualAddress};

/// The instruction class of a data access (D5.4.3): LDTR*/STTR* are
/// `Unprivileged`; everything else, and every fetch, is `Ordinary`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessClass {
    Ordinary,
    Unprivileged,
}

/// Why an access produced no physical address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage1Error {
    /// The walk faulted: deliver it with [`fault_exception`].
    Abort(Aarch64Fault),
    /// SCTLR_EL1.M is set under a TCR_EL1 this profile does not implement.
    Regime(UnsupportedRegime),
    /// Guest physical memory could not serve a descriptor read.
    Descriptor(DescriptorRefusal),
}

/// Whether stage-1 translation is enabled (SCTLR_EL1.M, D13.2.116).
pub fn enabled(cpu: &CpuState) -> bool {
    cpu.el1.sctlr.0 & 1 != 0
}

/// The admitted regime of `cpu`'s current registers.
pub fn regime(cpu: &CpuState) -> Result<Aarch64Regime, UnsupportedRegime> {
    Aarch64Regime::new(
        cpu.el1.tcr.0,
        cpu.named.ttbr0.0,
        cpu.named.ttbr1.0,
        cpu.el1.sctlr.0,
    )
}

/// Descriptor words read little-endian from guest physical memory.
struct PhysicalWords<'a, M: GuestMemory>(RefCell<&'a mut M>);

impl<M: GuestMemory> LiveDescriptorWords for PhysicalWords<'_, M> {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        let mut bytes = [0; 8];
        self.0
            .borrow_mut()
            .read(VirtualAddress(pa), &mut bytes)
            .map_err(|_| DescriptorRefusal::MissingTable)?;
        Ok(u64::from_le_bytes(bytes))
    }
    // HA=HD=0 in the admitted profile: the walk never updates or publishes.
    fn compare_exchange(&self, _: u64, _: u64, _: u64) -> Result<bool, DescriptorRefusal> {
        Err(DescriptorRefusal::PermissionDenied)
    }
    fn store_unlinked(&self, _: u64, _: u64) -> Result<(), DescriptorRefusal> {
        Err(DescriptorRefusal::PermissionDenied)
    }
    fn publish_barrier(&self) {}
    fn invalidate_range(&self, _: u64, _: u64) {}
}

/// Translate one access at `va` (which must not cross a 4 KiB page) for the
/// current EL, PSTATE.PAN/UAO and `class`. Returns the physical address.
pub fn translate(
    cpu: &CpuState,
    memory: &mut impl GuestMemory,
    va: u64,
    access: LeafAccess,
    class: AccessClass,
) -> Result<u64, Stage1Error> {
    if !enabled(cpu) {
        return Ok(va);
    }
    Ok(walk(cpu, memory, va, access, class)?.output().raw())
}

/// D13.2.103 `PAR_EL1` bit 11 is RES1 in both 64-bit formats (`F=0` and `F=1`).
const PAR_RES1: u64 = 1 << 11;
/// D13.2.103 `PAR_EL1.PA[47:12]` mask when `F=0` (`IPS <= 48` bits).
const PAR_PA_MASK: u64 = 0x0000_ffff_ffff_f000;
/// D13.2.103 `PAR_EL1.SH` shift (`bits [8:7]`); Outer Shareable is `0b10`.
const PAR_SH_SHIFT: u32 = 7;
const PAR_SH_OUTER: u64 = 0b10;

/// Perform an EL1 `AT S1E*` stage-1 translation (Arm ARM DDI0487G.a C6.2.21,
/// C5.3, D5.2.9, D5.4.2, D13.2.103) and return the 64-bit `PAR_EL1` value.
/// Returns `None` for non-EL1 `AT` encodings (`op1 != 0`), which are undefined
/// at EL1. Stage-1 faults never raise exceptions: they return `Ok(par)` with
/// `PAR_EL1.F=1` and `FST=status_code()`.
pub(crate) fn address_translate(
    cpu: &CpuState,
    memory: &mut impl GuestMemory,
    op: crate::Translation,
    va: u64,
) -> Option<Result<u64, Stage1Error>> {
    use crate::Translation;
    let (el, pan, access) = match op {
        Translation::S1E1R => (Aarch64El::El1, false, LeafAccess::Read),
        Translation::S1E1W => (Aarch64El::El1, false, LeafAccess::Write),
        Translation::S1E0R => (Aarch64El::El0, false, LeafAccess::Read),
        Translation::S1E0W => (Aarch64El::El0, false, LeafAccess::Write),
        Translation::S1E1Rp => (Aarch64El::El1, cpu.pstate.pan, LeafAccess::Read),
        Translation::S1E1Wp => (Aarch64El::El1, cpu.pstate.pan, LeafAccess::Write),
        _ => return None,
    };
    if !enabled(cpu) {
        // D5.1.1 / D5.2.9: flat data translation strips an ignored top byte
        // under TBI0/TBI1, faults as L0 address-size above 48 bits, and
        // otherwise yields Device-nGnRnE (ATTR=0x00) and Outer Shareable (0b10).
        let tbi_bit = if (va >> 55) & 1 == 0 { 37 } else { 38 };
        let effective = if (cpu.el1.tcr.0 >> tbi_bit) & 1 != 0 {
            va & 0x00ff_ffff_ffff_ffff
        } else {
            va
        };
        if effective >> 48 != 0 {
            return Some(Ok(PAR_RES1 | 1));
        }
        return Some(Ok((effective & PAR_PA_MASK)
            | PAR_RES1
            | (PAR_SH_OUTER << PAR_SH_SHIFT)));
    }
    let regime = match regime(cpu) {
        Ok(regime) => regime,
        Err(error) => return Some(Err(Stage1Error::Regime(error))),
    };
    let context = Aarch64WalkContext {
        regime,
        el,
        pan,
        uao: false,
        class: Aarch64AccessClass::Ordinary,
    };
    memory.record_stage1_walk();
    let words = PhysicalWords(RefCell::new(memory));
    Some(
        match Aarch64Walker.walk(&words, &context, GuestVa::new(va), access) {
            Ok(leaf) => {
                let attr = (cpu.el1.mair.0 >> (8 * u32::from(leaf.attr_index()))) & 0xff;
                let raw_sh = (leaf.descriptor() >> 8) & 0b11;
                // D5.5 / D13.2.103: Device memory and Normal Inner+Outer
                // Non-cacheable (0x44) are effectively Outer Shareable (0b10);
                // reserved descriptor SH=0b01 behaves as Non-shareable (0b00).
                let sh = if attr & 0xf0 == 0 || attr == 0x44 {
                    PAR_SH_OUTER
                } else if raw_sh == 0b01 {
                    0
                } else {
                    raw_sh
                };
                let pa = leaf.output().raw() & PAR_PA_MASK;
                Ok((attr << 56) | pa | PAR_RES1 | (sh << PAR_SH_SHIFT))
            }
            Err(WalkError::Fault(fault)) => {
                Ok(PAR_RES1 | (u64::from(fault.status_code()) << 1) | 1)
            }
            Err(WalkError::Refusal(refusal)) => Err(Stage1Error::Descriptor(refusal)),
        },
    )
}

/// Walk an enabled stage-1 regime, retaining the selected memory attribute.
pub(crate) fn walk(
    cpu: &CpuState,
    memory: &mut impl GuestMemory,
    va: u64,
    access: LeafAccess,
    class: AccessClass,
) -> Result<Aarch64Leaf, Stage1Error> {
    let context = Aarch64WalkContext {
        regime: regime(cpu).map_err(Stage1Error::Regime)?,
        el: match cpu.pstate.el {
            ExceptionLevel::El0 => Aarch64El::El0,
            ExceptionLevel::El1 => Aarch64El::El1,
        },
        pan: cpu.pstate.pan,
        uao: cpu.pstate.uao,
        class: match class {
            AccessClass::Ordinary => Aarch64AccessClass::Ordinary,
            AccessClass::Unprivileged => Aarch64AccessClass::Unprivileged,
        },
    };
    memory.record_stage1_walk();
    let words = PhysicalWords(RefCell::new(memory));
    match Aarch64Walker.walk(&words, &context, GuestVa::new(va), access) {
        Ok(leaf) => Ok(leaf),
        Err(WalkError::Fault(fault)) => Err(Stage1Error::Abort(fault)),
        Err(WalkError::Refusal(refusal)) => Err(Stage1Error::Descriptor(refusal)),
    }
}

fn table_level(level: Aarch64Level) -> TableLevel {
    match level {
        Aarch64Level::L0 => TableLevel::L0,
        Aarch64Level::L1 => TableLevel::L1,
        Aarch64Level::L2 => TableLevel::L2,
        Aarch64Level::L3 => TableLevel::L3,
    }
}

/// The leaf level of an AF or permission fault; L0 is never a leaf in the
/// admitted 4 KiB profile (no LPA2).
fn leaf_level(level: Aarch64Level) -> Option<LeafLevel> {
    match level {
        Aarch64Level::L0 => None,
        Aarch64Level::L1 => Some(LeafLevel::L1),
        Aarch64Level::L2 => Some(LeafLevel::L2),
        Aarch64Level::L3 => Some(LeafLevel::L3),
    }
}

/// The EL1 abort exception for a walker fault: instruction abort for a
/// fetch, data abort otherwise; FAR is the faulting VA as presented.
pub fn fault_exception(fault: Aarch64Fault) -> Option<Exception> {
    Some(Exception::Abort {
        access: match fault.access {
            LeafAccess::Read => Access::Read,
            LeafAccess::Write => Access::Write,
            LeafAccess::Execute => Access::Fetch,
        },
        status: fault_status(fault)?,
        address: VirtualAddress(fault.va.raw()),
    })
}

pub(crate) fn fault_status(fault: Aarch64Fault) -> Option<FaultStatus> {
    Some(match fault.kind {
        Aarch64FaultKind::AddressSize => FaultStatus::AddressSize(table_level(fault.level)),
        Aarch64FaultKind::Translation => FaultStatus::Translation(table_level(fault.level)),
        Aarch64FaultKind::AccessFlag => FaultStatus::AccessFlag(leaf_level(fault.level)?),
        Aarch64FaultKind::Permission => FaultStatus::Permission(leaf_level(fault.level)?),
    })
}
