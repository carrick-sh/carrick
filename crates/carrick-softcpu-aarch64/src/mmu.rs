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
    Aarch64AccessClass, Aarch64El, Aarch64Fault, Aarch64FaultKind, Aarch64Level, Aarch64Regime,
    Aarch64WalkContext, Aarch64Walker, UnsupportedRegime,
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
    /// The walk faulted: deliver it with [`abort`].
    Abort(Aarch64Fault),
    /// SCTLR_EL1.M is set under a TCR_EL1 this profile does not implement.
    Regime(UnsupportedRegime),
    /// Guest physical memory could not serve a descriptor read.
    Descriptor(DescriptorRefusal),
}

/// Whether stage-1 translation is enabled (SCTLR_EL1.M, D13.2.116).
pub fn enabled(cpu: &CpuState) -> bool {
    // RED WITNESS STUB: translation never engages (the pre-#2480 flat model).
    let _ = cpu;
    false
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
    let words = PhysicalWords(RefCell::new(memory));
    match Aarch64Walker.walk(&words, &context, GuestVa::new(va), access) {
        Ok(leaf) => Ok(leaf.output().raw()),
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
pub fn abort(fault: Aarch64Fault) -> Option<Exception> {
    let status = match fault.kind {
        Aarch64FaultKind::AddressSize => FaultStatus::AddressSize(table_level(fault.level)),
        Aarch64FaultKind::Translation => FaultStatus::Translation(table_level(fault.level)),
        Aarch64FaultKind::AccessFlag => FaultStatus::AccessFlag(leaf_level(fault.level)?),
        Aarch64FaultKind::Permission => FaultStatus::Permission(leaf_level(fault.level)?),
    };
    Some(Exception::Abort {
        access: match fault.access {
            LeafAccess::Read => Access::Read,
            LeafAccess::Write => Access::Write,
            LeafAccess::Execute => Access::Fetch,
        },
        status,
        address: VirtualAddress(fault.va.raw()),
    })
}
