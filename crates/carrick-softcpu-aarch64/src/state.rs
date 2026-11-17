//! Virtual EL0/EL1 state. Arm ARM DDI0487G.a D1.6 (PSTATE), C5.2
//! (special-purpose registers), D13.2 (EL1 registers). No host register access.
use crate::exception::Syndrome;
use crate::{NamedSystemRegister, OperandRegister, SystemRegister};

macro_rules! domain {
    ($name:ident) => {
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
        pub struct $name(pub u64);
    };
}
domain!(RegisterValue);
domain!(ProgramCounter);
domain!(VirtualAddress);
domain!(StackPointer);
domain!(SavedPstate);
domain!(SystemValue);

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionLevel {
    #[default]
    El0,
    El1,
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum StackSelect {
    #[default]
    El0,
    El1,
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct InterruptMasks(pub u8);
impl InterruptMasks {
    pub const ALL: Self = Self(15);
}
/// D1.6 PSTATE; D13.2 SPSR_EL1 bit layout. SS is outside this profile.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Pstate {
    pub el: ExceptionLevel,
    pub sp: StackSelect,
    pub nzcv: u8,
    pub daif: InterruptMasks,
    pub pan: bool,
    pub uao: bool,
    pub il: bool,
}
impl Pstate {
    pub fn save(self) -> SavedPstate {
        SavedPstate(
            (u64::from(self.nzcv & 15) << 28)
                | (u64::from(self.daif.0 & 15) << 6)
                | (u64::from(self.pan) << 22)
                | (u64::from(self.uao) << 23)
                | (u64::from(self.il) << 20)
                | (u64::from(self.el == ExceptionLevel::El1) << 2)
                | u64::from(self.sp == StackSelect::El1),
        )
    }
    pub(crate) fn restore(saved: SavedPstate) -> Option<Self> {
        let v = saved.0;
        let (el, sp) = match v & 31 {
            0 => (ExceptionLevel::El0, StackSelect::El0),
            4 => (ExceptionLevel::El1, StackSelect::El0),
            5 => (ExceptionLevel::El1, StackSelect::El1),
            _ => return None,
        };
        Some(Self {
            el,
            sp,
            nzcv: ((v >> 28) & 15) as u8,
            daif: InterruptMasks(((v >> 6) & 15) as u8),
            pan: v & (1 << 22) != 0,
            uao: v & (1 << 23) != 0,
            il: v & (1 << 20) != 0,
        })
    }
}
/// D13.2 SCTLR_EL1.SPAN (23), EPAN (57), UMA (9).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Sctlr(pub u64);
impl Sctlr {
    pub fn span(self) -> bool {
        self.0 & (1 << 23) != 0
    }
    pub fn epan(self) -> bool {
        self.0 & (1 << 57) != 0
    }
}
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct El1Registers {
    pub elr: ProgramCounter,
    pub spsr: SavedPstate,
    pub esr: Syndrome,
    pub far: VirtualAddress,
    pub vbar: VirtualAddress,
    pub sctlr: Sctlr,
    pub tpidr: SystemValue,
    pub tcr: SystemValue,
    pub mair: SystemValue,
    pub cntkctl: SystemValue,
}
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CpuState {
    x: [RegisterValue; 31],
    pub sp_el0: StackPointer,
    pub sp_el1: StackPointer,
    pub pc: ProgramCounter,
    pub pstate: Pstate,
    pub el1: El1Registers,
    named: [SystemValue; 19],
}
/// Undefined access raises EC=0; denied allocated MRS/MSR raises EC=0x18.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemAccessException {
    pub syndrome: Syndrome,
}
impl CpuState {
    pub fn sp(&self) -> StackPointer {
        if self.pstate.el == ExceptionLevel::El0 || self.pstate.sp == StackSelect::El0 {
            self.sp_el0
        } else {
            self.sp_el1
        }
    }
    pub fn set_sp(&mut self, value: StackPointer) {
        if self.pstate.el == ExceptionLevel::El0 || self.pstate.sp == StackSelect::El0 {
            self.sp_el0 = value;
        } else {
            self.sp_el1 = value;
        }
    }
    pub fn read_operand(&self, r: OperandRegister) -> RegisterValue {
        match r {
            OperandRegister::Zr => RegisterValue(0),
            OperandRegister::Sp => RegisterValue(self.sp().0),
            OperandRegister::Gpr(r) => self
                .x
                .get(usize::from(r.number()))
                .copied()
                .unwrap_or_default(),
        }
    }
    pub fn write_operand(&mut self, r: OperandRegister, value: RegisterValue) {
        match r {
            OperandRegister::Zr => (),
            OperandRegister::Sp => self.set_sp(StackPointer(value.0)),
            OperandRegister::Gpr(r) => {
                if let Some(x) = self.x.get_mut(usize::from(r.number())) {
                    *x = value;
                }
            }
        }
    }
    /// C6.2 MRS/MSR (register), D13 register access pseudocode. Traps carry
    /// D13.2 ESR_EL1 "Trapped MSR, MRS or System instruction" ISS fields.
    /// Rt is required for an exact trapped-instruction syndrome.
    pub fn mrs(
        &self,
        r: SystemRegister,
        rt: OperandRegister,
    ) -> Result<SystemValue, SystemAccessException> {
        let slot = self.access(r, rt, true)?;
        Ok(SystemValue(match slot {
            Slot::Named(i) => self.named[i].0,
            Slot::Elr => self.el1.elr.0,
            Slot::Spsr => self.el1.spsr.0,
            Slot::Esr => self.el1.esr.0,
            Slot::Far => self.el1.far.0,
            Slot::Vbar => self.el1.vbar.0,
            Slot::Sctlr => self.el1.sctlr.0,
            Slot::Tpidr => self.el1.tpidr.0,
            Slot::SpEl0 => self.sp_el0.0,
            Slot::Tcr => self.el1.tcr.0,
            Slot::Mair => self.el1.mair.0,
            Slot::Cntkctl => self.el1.cntkctl.0,
            Slot::Nzcv => u64::from(self.pstate.nzcv & 15) << 28,
            Slot::Daif => u64::from(self.pstate.daif.0 & 15) << 6,
            Slot::Pan => u64::from(self.pstate.pan) << 22,
            Slot::Uao => u64::from(self.pstate.uao) << 23,
            Slot::Spsel => u64::from(self.pstate.sp == StackSelect::El1),
            Slot::CurrentEl => u64::from(self.pstate.el == ExceptionLevel::El1) << 2,
        }))
    }
    pub fn msr(
        &mut self,
        r: SystemRegister,
        rt: OperandRegister,
        value: SystemValue,
    ) -> Result<(), SystemAccessException> {
        let slot = self.access(r, rt, false)?;
        let v = value.0;
        match slot {
            Slot::Named(i) => self.named[i] = value,
            Slot::Elr => self.el1.elr = ProgramCounter(v),
            Slot::Spsr => self.el1.spsr = SavedPstate(v),
            Slot::Esr => self.el1.esr = Syndrome(v & 0xffff_ffff),
            Slot::Far => self.el1.far = VirtualAddress(v),
            Slot::Vbar => self.el1.vbar = VirtualAddress(v & !0x7ff),
            Slot::Sctlr => self.el1.sctlr = Sctlr(v),
            Slot::Tpidr => self.el1.tpidr = value,
            Slot::SpEl0 => self.sp_el0 = StackPointer(v),
            Slot::Tcr => self.el1.tcr = value,
            Slot::Mair => self.el1.mair = value,
            Slot::Cntkctl => self.el1.cntkctl = value,
            Slot::Nzcv => self.pstate.nzcv = ((v >> 28) & 15) as u8,
            Slot::Daif => self.pstate.daif = InterruptMasks(((v >> 6) & 15) as u8),
            Slot::Pan => self.pstate.pan = v & (1 << 22) != 0,
            Slot::Uao => self.pstate.uao = v & (1 << 23) != 0,
            Slot::Spsel => {
                self.pstate.sp = if v & 1 == 0 {
                    StackSelect::El0
                } else {
                    StackSelect::El1
                }
            }
            Slot::CurrentEl => unreachable!("access rejects read-only register"),
        }
        Ok(())
    }
    fn access(
        &self,
        r: SystemRegister,
        rt: OperandRegister,
        read: bool,
    ) -> Result<Slot, SystemAccessException> {
        let undefined = SystemAccessException {
            syndrome: Syndrome(0x0200_0000),
        };
        let slot = Slot::decode(r).ok_or(undefined)?;
        if (read && matches!(slot, Slot::Named(17 | 18)))
            || (!read && matches!(slot, Slot::CurrentEl | Slot::Named(11 | 12 | 15 | 16)))
            || (matches!(slot, Slot::SpEl0) && self.pstate.sp == StackSelect::El0)
        {
            return Err(undefined);
        }
        let allowed = match slot {
            Slot::Named(3 | 6 | 7) | Slot::Nzcv => true,
            Slot::Named(4) => read,
            Slot::Named(11 | 12) => read && self.el1.cntkctl.0 & 2 != 0,
            Slot::Daif => self.el1.sctlr.0 & (1 << 9) != 0,
            _ => false,
        };
        if self.pstate.el == ExceptionLevel::El0 && !allowed {
            let rt = match rt {
                OperandRegister::Gpr(r) => r.number(),
                _ => 31,
            };
            let iss = u64::from(read)
                | (u64::from(r.crm) << 1)
                | (u64::from(rt) << 5)
                | (u64::from(r.crn) << 10)
                | (u64::from(r.op1) << 14)
                | (u64::from(r.op2) << 17)
                | (u64::from(r.op0) << 20);
            return Err(SystemAccessException {
                syndrome: Syndrome(0x6200_0000 | iss),
            });
        }
        Ok(slot)
    }
}
#[derive(Clone, Copy)]
enum Slot {
    Named(usize),
    Elr,
    Spsr,
    Esr,
    Far,
    Vbar,
    Sctlr,
    Tpidr,
    SpEl0,
    Tcr,
    Mair,
    Cntkctl,
    Nzcv,
    Daif,
    Pan,
    Uao,
    Spsel,
    CurrentEl,
}
impl Slot {
    fn decode(r: SystemRegister) -> Option<Self> {
        use NamedSystemRegister as N;
        Some(match N::from_encoding(r) {
            N::Ttbr0El1 => Self::Named(0),
            N::Ttbr1El1 => Self::Named(1),
            N::SpEl0 => Self::SpEl0,
            N::TpidrEl0 => Self::Named(3),
            N::TpidrroEl0 => Self::Named(4),
            N::ContextidrEl1 => Self::Named(5),
            N::Fpcr => Self::Named(6),
            N::Fpsr => Self::Named(7),
            N::Daif => Self::Daif,
            N::Pan => Self::Pan,
            N::ParEl1 => Self::Named(10),
            N::CntfrqEl0 => Self::Named(11),
            N::CntvctEl0 => Self::Named(12),
            N::CntvCtlEl0 => Self::Named(13),
            N::CntvCvalEl0 => Self::Named(14),
            N::MpidrEl1 => Self::Named(15),
            N::IccIar1El1 => Self::Named(16),
            N::IccEoir1El1 => Self::Named(17),
            N::IccSgi1rEl1 => Self::Named(18),
            N::Unnamed(_) => match (r.op0, r.op1, r.crn, r.crm, r.op2) {
                (3, 0, 4, 0, 1) => Self::Elr,
                (3, 0, 4, 0, 0) => Self::Spsr,
                (3, 0, 5, 2, 0) => Self::Esr,
                (3, 0, 6, 0, 0) => Self::Far,
                (3, 0, 12, 0, 0) => Self::Vbar,
                (3, 0, 1, 0, 0) => Self::Sctlr,
                (3, 0, 13, 0, 4) => Self::Tpidr,
                (3, 0, 2, 0, 2) => Self::Tcr,
                (3, 0, 10, 2, 0) => Self::Mair,
                (3, 0, 14, 1, 0) => Self::Cntkctl,
                (3, 3, 4, 2, 0) => Self::Nzcv,
                (3, 0, 4, 2, 4) => Self::Uao,
                (3, 0, 4, 2, 0) => Self::Spsel,
                (3, 0, 4, 2, 2) => Self::CurrentEl,
                _ => return None,
            },
        })
    }
}
