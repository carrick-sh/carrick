//! Arm ARM DDI0487G.a D1.10 exception entry / AArch64.TakeException (J1-7877–7878),
//! D1.11 exception return / AArch64.ExceptionReturn (J1-7951),
//! SetPSTATEFromPSR (J1-8205–8206), and D13.2.37 ESR_EL1.
//! Pure virtual transitions; no host exceptions or provider actions.
//! A3 wiring must enforce restored IL on the next instruction (EC=0x0e)
//! and apply the configured address size to ELR before fetching after ERET.
//! SError ISS=0 is the chosen non-RAS implementation-defined syndrome;
//! HVC at EL1 is a deliberate provider boundary in this EL0/EL1 profile.
use crate::state::{
    CpuState, ExceptionLevel, InterruptMasks, ProgramCounter, Pstate, StackSelect,
    SystemAccessException, VirtualAddress,
};
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Syndrome(pub u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableLevel {
    L0,
    L1,
    L2,
    L3,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafLevel {
    L1,
    L2,
    L3,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Fetch,
    Read,
    Write,
}
/// D13.2.37 ESR_EL1 IFSC/DFSC tables. L0 AF/permission requires LPA2;
/// represented by a separate leaf level type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultStatus {
    AddressSize(TableLevel),
    Translation(TableLevel),
    AccessFlag(LeafLevel),
    Permission(LeafLevel),
    ExternalWalk(TableLevel),
}
impl FaultStatus {
    fn fsc(self) -> u64 {
        match self {
            Self::AddressSize(l) => l as u64,
            Self::Translation(l) => 4 + l as u64,
            Self::AccessFlag(l) => 9 + l as u64,
            Self::Permission(l) => 13 + l as u64,
            Self::ExternalWalk(l) => 20 + l as u64,
        }
    }
}
/// Alignment faults are data-only (D13.2.37 DFSC); there is no Fetch variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataAccess {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Exception immediates use the same typed domain as decoded operands.
/// ```compile_fail
/// use carrick_softcpu_aarch64::exception::Exception;
/// let _ = Exception::Svc(1);
/// ```
pub enum Exception {
    Svc(crate::Immediate16),
    Hvc(crate::Immediate16),
    Brk(u16),
    Unknown,
    SystemAccess(SystemAccessException),
    Irq,
    Fiq,
    SError,
    /// Alignment cannot be combined with instruction fetch.
    /// ```compile_fail
    /// use carrick_softcpu_aarch64::{exception::*, state::VirtualAddress};
    /// let _ = Exception::Alignment { access: Access::Fetch, address: VirtualAddress(0) };
    /// ```
    Alignment {
        access: DataAccess,
        address: VirtualAddress,
    },
    Abort {
        access: Access,
        status: FaultStatus,
        address: VirtualAddress,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderExit {
    pub immediate: crate::Immediate16,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionOutcome {
    Entered,
    ProviderExit(ProviderExit),
}
/// D13.2.37 ESR_EL1 EC and instruction/data abort ISS tables, plus
/// shared pseudocode ExceptionSyndrome. Origin is execution EL, independent
/// of LDTR/STTR permission regime. Scalar EL1-target faults have ISV=0;
/// S1PTW=0 (a stage-1 table read is not a stage-2 table-walk fault).
pub fn syndrome(exception: Exception, origin: ExceptionLevel) -> Syndrome {
    if let Exception::SystemAccess(error) = exception {
        return error.syndrome;
    }
    let current = u64::from(origin == ExceptionLevel::El1);
    let (ec, iss) = match exception {
        Exception::Svc(i) => (0x15, u64::from(i.value())),
        Exception::Hvc(i) => (0x16, u64::from(i.value())),
        Exception::Brk(i) => (0x3c, u64::from(i)),
        Exception::SError => (0x2f, 0),
        Exception::Alignment { access, .. } => (
            0x24 + current,
            0x21 | if access == DataAccess::Write {
                1 << 6
            } else {
                0
            },
        ),
        Exception::Abort { access, status, .. } => (
            if access == Access::Fetch {
                0x20 + current
            } else {
                0x24 + current
            },
            status.fsc() | if access == Access::Write { 1 << 6 } else { 0 },
        ),
        _ => (0, 0),
    };
    Syndrome((ec << 26) | (1 << 25) | iss)
}
/// AArch64.TakeException (D1.10): vector origin is captured before
/// switching to EL1h. SVC saves next PC; abort/BRK/IRQ save restart PC.
/// HVC is Carrick's typed provider boundary, preserving saved EL1 syndrome.
pub fn take_exception(cpu: &mut CpuState, exception: Exception) -> ExceptionOutcome {
    let exception =
        if matches!(exception, Exception::Hvc(_)) && cpu.pstate.el == ExceptionLevel::El0 {
            Exception::Unknown
        } else {
            exception
        };
    if let Exception::Hvc(immediate) = exception {
        return ExceptionOutcome::ProviderExit(ProviderExit { immediate });
    }
    let origin = cpu.pstate;
    let base = if origin.el == ExceptionLevel::El0 {
        0x400
    } else if origin.sp == StackSelect::El0 {
        0
    } else {
        0x200
    };
    let offset = match exception {
        Exception::Irq => 0x80,
        Exception::Fiq => 0x100,
        Exception::SError => 0x180,
        _ => 0,
    };
    cpu.el1.elr = ProgramCounter(cpu.pc.0.wrapping_add(
        if matches!(exception, Exception::Svc(_)) {
            4
        } else {
            0
        },
    ));
    cpu.el1.spsr = origin.save();
    if !matches!(exception, Exception::Irq | Exception::Fiq) {
        cpu.el1.esr = syndrome(exception, origin.el);
    }
    if let Exception::Abort { address, .. } | Exception::Alignment { address, .. } = exception {
        cpu.el1.far = address;
    }
    cpu.pstate.el = ExceptionLevel::El1;
    cpu.pstate.sp = StackSelect::El1;
    cpu.pstate.daif = InterruptMasks::ALL;
    cpu.pstate.pan = !cpu.el1.sctlr.span() || origin.pan;
    cpu.pstate.uao = false;
    cpu.pstate.il = false;
    cpu.pc = ProgramCounter((cpu.el1.vbar.0 & !0x7ff).wrapping_add(base + offset));
    ExceptionOutcome::Entered
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnError {
    UndefinedAtEl0,
}
/// D1.11 Illegal return events from AArch64 state; AArch64.ExceptionReturn.
/// Illegal SPSR.M retains current EL/SP, sets IL, restores NZCV/PAN/DAIF and
/// branches to ELR. ERET at EL0 is undefined and changes no state.
pub fn eret(cpu: &mut CpuState) -> Result<(), ReturnError> {
    if cpu.pstate.el == ExceptionLevel::El0 {
        return Err(ReturnError::UndefinedAtEl0);
    }
    if let Some(pstate) = Pstate::restore(cpu.el1.spsr) {
        cpu.pstate = pstate;
    } else {
        cpu.pstate.il = true;
        cpu.pstate.nzcv = ((cpu.el1.spsr.0 >> 28) & 15) as u8;
        cpu.pstate.pan = cpu.el1.spsr.0 & (1 << 22) != 0;
        cpu.pstate.daif = InterruptMasks(((cpu.el1.spsr.0 >> 6) & 15) as u8);
    }
    cpu.pc = cpu.el1.elr;
    Ok(())
}
