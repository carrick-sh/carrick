//! Virtual EL0/EL1 state. Arm ARM DDI0487G.a D1.6 (PSTATE), C5.2
//! (special-purpose registers), D13.2 (EL1 registers). No host register access.
use crate::exception::Syndrome;
use crate::{NamedSystemRegister, OperandRegister, SystemRegister, VectorRegister};

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

    pub const fn irq_masked(self) -> bool {
        self.0 & 2 != 0
    }
}
/// D1.6 PSTATE; C5.2.17 SPSR_EL1 bit layout. SS is outside this profile.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
/// Public fields are raw provider state. Architectural transitions never create
/// EL0+SP=1; banking and save canonicalize that raw combination to EL0t.
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
                | u64::from(self.el == ExceptionLevel::El1 && self.sp == StackSelect::El1),
        )
    }
    pub fn restore(saved: SavedPstate) -> Option<Self> {
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
/// D13.2.116 SCTLR_EL1.SPAN (23), EPAN (57), UMA (9), A (1).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Sctlr(pub u64);
impl Sctlr {
    pub fn alignment_check(self) -> bool {
        self.0 & (1 << 1) != 0
    }

    pub fn span(self) -> bool {
        self.0 & (1 << 23) != 0
    }
    pub fn epan(self) -> bool {
        self.0 & (1 << 57) != 0
    }

    pub(crate) fn dze(self) -> bool {
        self.0 & (1 << 14) != 0
    }

    pub(crate) fn uct(self) -> bool {
        self.0 & (1 << 15) != 0
    }

    pub(crate) fn uci(self) -> bool {
        self.0 & (1 << 26) != 0
    }

    pub(crate) fn traps_el0_wait(self, wait: crate::exception::WaitInstruction) -> bool {
        use crate::exception::WaitInstruction;
        let bit = match wait {
            WaitInstruction::Wfi => 16, // nTWI
            WaitInstruction::Wfe => 18, // nTWE
        };
        self.0 & (1 << bit) == 0
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
    pub vectors: [u128; 32],
    local_event: bool,
    pub(crate) undefined_el0_deliveries: u64,
    pub sp_el0: StackPointer,
    pub sp_el1: StackPointer,
    pub pc: ProgramCounter,
    pub pstate: Pstate,
    pub el1: El1Registers,
    pub named: NamedRegisters,
}
/// Undefined access raises EC=0; denied allocated MRS/MSR raises EC=0x18.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemAccessException {
    pub syndrome: Syndrome,
}
impl SystemAccessException {
    pub(crate) fn sys64(r: SystemRegister, rt: OperandRegister, read: bool) -> Self {
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
        Self {
            syndrome: Syndrome(0x6200_0000 | iss),
        }
    }
}

/// D13 DCZID_EL0.BS is log2 of the block size in words.
const DC_ZVA_BLOCK_SHIFT: u8 = 4;
pub(crate) const DC_ZVA_BYTES: usize = 4 << DC_ZVA_BLOCK_SHIFT;

/// D13 CTR_EL0: 64-byte I/D lines, PIPT L1 I-cache, baseline RES1 bit 31.
/// Do not claim IDC/DIC or disclose a physical host cache geometry.
const CTR_EL0: u64 = 0x8004_c004;

impl CpuState {
    pub fn read_vector(&self, r: VectorRegister) -> u128 {
        self.vectors[usize::from(r.number())]
    }

    pub fn write_vector(&mut self, r: VectorRegister, value: u128) {
        self.vectors[usize::from(r.number())] = value;
    }

    pub(crate) fn signal_local_event(&mut self) {
        self.local_event = true;
    }

    pub(crate) fn consume_local_event(&mut self) -> bool {
        core::mem::take(&mut self.local_event)
    }

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
            Slot::Named(i) => self.named.read(i).0,
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
            Slot::Ctr => CTR_EL0,
            Slot::Dczid => {
                let prohibited = self.pstate.el == ExceptionLevel::El0 && !self.el1.sctlr.dze();
                (u64::from(prohibited) << 4) | u64::from(DC_ZVA_BLOCK_SHIFT)
            }
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
            Slot::Named(i) => self.named.write(i, value),
            Slot::Elr => self.el1.elr = ProgramCounter(v),
            Slot::Spsr => self.el1.spsr = SavedPstate(v & 0xffff_ffff),
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
            Slot::CurrentEl | Slot::Ctr | Slot::Dczid => {
                return Err(SystemAccessException {
                    syndrome: Syndrome(0x0200_0000),
                });
            }
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
        if (read && matches!(slot, Slot::Named(NamedSlot::IccEoir1 | NamedSlot::IccSgi1r)))
            || (!read
                && matches!(
                    slot,
                    Slot::CurrentEl
                        | Slot::Ctr
                        | Slot::Dczid
                        | Slot::Named(NamedSlot::Cntvct | NamedSlot::Mpidr | NamedSlot::IccIar1)
                ))
            || (matches!(slot, Slot::SpEl0) && self.pstate.sp == StackSelect::El0)
        {
            return Err(undefined);
        }
        if self.pstate.el == ExceptionLevel::El0
            && !read
            && matches!(slot, Slot::Named(NamedSlot::Cntfrq))
        {
            return Err(undefined);
        }
        let allowed = match slot {
            Slot::Named(NamedSlot::TpidrEl0 | NamedSlot::Fpcr | NamedSlot::Fpsr) | Slot::Nzcv => {
                true
            }
            Slot::Named(NamedSlot::TpidrroEl0) => read,
            Slot::Named(NamedSlot::Cntfrq) => read && self.el1.cntkctl.0 & 3 != 0,
            Slot::Named(NamedSlot::Cntvct) => read && self.el1.cntkctl.0 & 2 != 0,
            Slot::Named(NamedSlot::CntvCtl | NamedSlot::CntvCval) => {
                self.el1.cntkctl.0 & (1 << 8) != 0
            }
            Slot::Ctr => self.el1.sctlr.uct(),
            Slot::Dczid => true,
            Slot::Daif => self.el1.sctlr.0 & (1 << 9) != 0,
            _ => false,
        };
        if self.pstate.el == ExceptionLevel::El0 && !allowed {
            if !matches!(
                slot,
                Slot::Daif
                    | Slot::Ctr
                    | Slot::Named(
                        NamedSlot::Cntfrq
                            | NamedSlot::Cntvct
                            | NamedSlot::CntvCtl
                            | NamedSlot::CntvCval
                    )
            ) {
                return Err(undefined);
            }
            return Err(SystemAccessException::sys64(r, rt, read));
        }
        Ok(slot)
    }
}
#[derive(Clone, Copy)]
enum Slot {
    Named(NamedSlot),
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
    Ctr,
    Dczid,
}
impl Slot {
    fn decode(r: SystemRegister) -> Option<Self> {
        use NamedSystemRegister as N;
        Some(match N::from_encoding(r) {
            N::Ttbr0El1 => Self::Named(NamedSlot::Ttbr0),
            N::Ttbr1El1 => Self::Named(NamedSlot::Ttbr1),
            N::SpEl0 => Self::SpEl0,
            N::TpidrEl0 => Self::Named(NamedSlot::TpidrEl0),
            N::TpidrroEl0 => Self::Named(NamedSlot::TpidrroEl0),
            N::ContextidrEl1 => Self::Named(NamedSlot::Contextidr),
            N::CtrEl0 => Self::Ctr,
            N::DczidEl0 => Self::Dczid,
            N::Fpcr => Self::Named(NamedSlot::Fpcr),
            N::Fpsr => Self::Named(NamedSlot::Fpsr),
            N::Daif => Self::Daif,
            N::Pan => Self::Pan,
            N::ParEl1 => Self::Named(NamedSlot::Par),
            N::CntfrqEl0 => Self::Named(NamedSlot::Cntfrq),
            N::CntvctEl0 => Self::Named(NamedSlot::Cntvct),
            N::CntvCtlEl0 => Self::Named(NamedSlot::CntvCtl),
            N::CntvCvalEl0 => Self::Named(NamedSlot::CntvCval),
            N::MpidrEl1 => Self::Named(NamedSlot::Mpidr),
            N::IccIar1El1 => Self::Named(NamedSlot::IccIar1),
            N::IccEoir1El1 => Self::Named(NamedSlot::IccEoir1),
            N::IccSgi1rEl1 => Self::Named(NamedSlot::IccSgi1r),
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

/// D13 named register backing. Timer/GIC values are passive state; A3 owns
/// time advancement and interrupt-controller effects. FP access is enabled
/// in this EL0/EL1 profile (no EL2/EL3 or FP access traps).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NamedRegisters {
    pub ttbr0: SystemValue,
    pub ttbr1: SystemValue,
    pub tpidrel0: SystemValue,
    pub tpidrroel0: SystemValue,
    pub contextidr: SystemValue,
    pub fpcr: SystemValue,
    pub fpsr: SystemValue,
    pub par: SystemValue,
    pub cntfrq: SystemValue,
    pub cntvct: SystemValue,
    pub cntvctl: SystemValue,
    pub cntvcval: SystemValue,
    pub mpidr: SystemValue,
    pub icciar1: SystemValue,
    pub icceoir1: SystemValue,
    pub iccsgi1r: SystemValue,
}
#[derive(Clone, Copy)]
enum NamedSlot {
    Ttbr0,
    Ttbr1,
    TpidrEl0,
    TpidrroEl0,
    Contextidr,
    Fpcr,
    Fpsr,
    Par,
    Cntfrq,
    Cntvct,
    CntvCtl,
    CntvCval,
    Mpidr,
    IccIar1,
    IccEoir1,
    IccSgi1r,
}
// This CPU exposes FPCR exception enables as RAZ/WI. Native blocks
// must not inherit optional host floating-point traps.
pub(crate) const FPCR_MASK: u64 = 0x07c0_0000;
pub(crate) const FPSR_MASK: u64 = 0x0800_009f;

impl NamedRegisters {
    fn read(&self, slot: NamedSlot) -> SystemValue {
        match slot {
            NamedSlot::Ttbr0 => self.ttbr0,
            NamedSlot::Ttbr1 => self.ttbr1,
            NamedSlot::TpidrEl0 => self.tpidrel0,
            NamedSlot::TpidrroEl0 => self.tpidrroel0,
            NamedSlot::Contextidr => self.contextidr,
            NamedSlot::Fpcr => SystemValue(self.fpcr.0 & FPCR_MASK),
            NamedSlot::Fpsr => SystemValue(self.fpsr.0 & FPSR_MASK),
            NamedSlot::Par => self.par,
            NamedSlot::Cntfrq => SystemValue(self.cntfrq.0 & 0xffff_ffff),
            NamedSlot::Cntvct => self.cntvct,
            NamedSlot::CntvCtl => self.cntvctl,
            NamedSlot::CntvCval => self.cntvcval,
            // Aff3, U, MT and Aff2:Aff0 come from the virtual CPU topology.
            // D13.2.99 defines bit 31 as RES1 and other bits as RES0.
            NamedSlot::Mpidr => SystemValue((self.mpidr.0 & 0xff_41ff_ffff) | (1 << 31)),
            NamedSlot::IccIar1 => self.icciar1,
            NamedSlot::IccEoir1 => self.icceoir1,
            NamedSlot::IccSgi1r => self.iccsgi1r,
        }
    }
    fn write(&mut self, slot: NamedSlot, value: SystemValue) {
        match slot {
            NamedSlot::Ttbr0 => self.ttbr0 = value,
            NamedSlot::Ttbr1 => self.ttbr1 = value,
            NamedSlot::TpidrEl0 => self.tpidrel0 = value,
            NamedSlot::TpidrroEl0 => self.tpidrroel0 = value,
            NamedSlot::Contextidr => self.contextidr = SystemValue(value.0 & 0xffff_ffff),
            // C5.2.7/C5.2.8. This AArch64-only profile exposes baseline
            // FP control/status storage, with AArch32, FP16 and AFP fields RAZ.
            NamedSlot::Fpcr => self.fpcr = SystemValue(value.0 & FPCR_MASK),
            NamedSlot::Fpsr => self.fpsr = SystemValue(value.0 & FPSR_MASK),
            NamedSlot::Par => self.par = value,
            NamedSlot::Cntfrq => self.cntfrq = SystemValue(value.0 & 0xffff_ffff),
            NamedSlot::Cntvct => self.cntvct = value,
            // D13.8.25. ISTATUS is supplied by the provider and is read-only.
            NamedSlot::CntvCtl => self.cntvctl = SystemValue((self.cntvctl.0 & 4) | (value.0 & 3)),
            NamedSlot::CntvCval => self.cntvcval = value,
            NamedSlot::Mpidr => self.mpidr = value,
            NamedSlot::IccIar1 => self.icciar1 = value,
            NamedSlot::IccEoir1 => self.icceoir1 = value,
            NamedSlot::IccSgi1r => self.iccsgi1r = value,
        }
    }
}
