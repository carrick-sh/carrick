//! Contract `kernel.vcpu.kick-el0-boundary`, VM-free binding for the EL1
//! syscall hook (Fact 9 of EL1 plan 1a), in both interrupt modes.
//!
//! A host kick that stops the vCPU inside the hook is owed to the EL0
//! boundary: the engine publishes it to the slot's `pending_host_work` flag,
//! clears `I` in the live `SPSR_EL1` when that holds the EL0 return state, and
//! makes the owed-kick interrupt pending (`carrick_aarch64::owed_kick`). The
//! hook saves `SPSR_EL1` into the TrapFrame on entry and reloads it before
//! `eret`, so the served path must leave through the host (the forward path)
//! or `eret` with the owed interrupt still pending and unmasked. Otherwise EL0
//! resumes with the kick masked or consumed, and a thread that makes no
//! further host syscall never stops for the page-table drain that kicked it.
//!
//! With Hypervisor.framework's in-kernel GIC ([`El1IrqMode::GicWindow`]) the
//! owed kick is a redistributor-pending SGI that survives run returns, and the
//! served path opens an EL1 IRQ window that can take it (or the virtual
//! timer) in [`write_el1_irq_hook`]. Taking an IRQ at EL1 overwrites
//! `ELR_EL1`/`SPSR_EL1`, and acknowledging the kick SGI consumes the vehicle,
//! so the model checks both: the EL0 return state is exactly the TrapFrame's,
//! and a consumed kick has been handed back to the host.
//!
//! This interprets the REAL emitted vector bytes, not a model of them, and
//! injects the kick at every instruction boundary of the hook and of the IRQ
//! hook when an interrupt is taken.

use super::*;
use std::collections::BTreeMap;

const PSTATE_I: u64 = 1 << 7;
/// Carrick's EL0 return state: EL0t with DAIF masked.
const EL0_DAIF_MASKED: u64 = 0x3c0;
const GUEST_ELR: u64 = 0x4000_1000;
const SLOT: u64 = 3;
/// The mailbox capture's offset in the test page; reaching it is a host exit.
const CAPTURE: usize = 0x800;
/// `CurrentTask` is 64 bytes (`lsl #6` in the hook); `pending_host_work` at 40.
const PENDING_HOST_WORK: u64 = 40;
const SPURIOUS: u64 = carrick_el1_abi::GIC_SPURIOUS_INTID as u64;
const KICK: u64 = carrick_el1_abi::GIC_KICK_INTID as u64;
const VTIMER: u64 = carrick_el1_abi::GIC_VTIMER_INTID as u64;
/// SPSR_EL1.M for EL1h.
const MODE_EL1H: u64 = 0b0101;

#[derive(Debug, PartialEq, Eq)]
enum Exit {
    /// Reached the mailbox capture: the syscall surfaces to the host.
    Host,
    /// `eret` to EL0 with this `SPSR_EL1` and `ELR_EL1`.
    Eret { spsr: u64, elr: u64 },
    /// `hvc #3`: Carrick's fail-loud trap.
    Fault,
}

/// Where the owed kick stands when the hook leaves.
#[derive(Debug, PartialEq, Eq)]
enum KickFate {
    /// The syscall left through the host, which settles the kick.
    Host,
    /// EL0 resumes with the kick pending and I clear: it is taken at the
    /// first EL0 instruction.
    TakenAtEl0,
    /// EL0 resumes with the kick masked (the pre-fix Fact 9 hole).
    MaskedAtEl0,
    /// The kick SGI was acknowledged at EL1 and nothing handed it back to the
    /// host.
    ConsumedAtEl1,
}

/// Small independent interpreter of the vector page's instruction subset.
/// Unknown instructions fail closed.
struct Machine {
    irq: El1IrqMode,
    regs: [u64; 31],
    sp: u64,
    mem: BTreeMap<u64, u64>,
    elr: u64,
    spsr: u64,
    esr: u64,
    pc: usize,
    /// PSTATE.I at EL1 (exception entry from EL0 masks it).
    irq_masked: bool,
    equal: bool,
    bytes: Vec<u8>,
    /// Instructions retired; the kick lands before instruction `kick_at`.
    retired: usize,
    /// Where the injected kick stopped the vCPU.
    kicked_pc: Option<usize>,
    /// The owed kick is pending (the SGI in GIC mode).
    kick_pending: bool,
    /// The virtual timer's condition holds and it is enabled.
    vtimer_enabled: bool,
    vtimer_pending: bool,
    /// INTIDs acknowledged and not yet completed.
    active: Vec<u64>,
    /// The kick SGI was acknowledged at EL1.
    kick_acknowledged: bool,
}

impl Machine {
    fn new(irq: El1IrqMode) -> Self {
        let mut bytes = vec![0u8; LINUX_EL1_VECTORS_SIZE as usize];
        if let Some(window_isb) =
            write_el1_vector_hook(&mut bytes, EL1_VECTOR_HOOK_OFFSET, CAPTURE, irq)
        {
            write_el1_irq_hook(&mut bytes, EL1_IRQ_HOOK_OFFSET, window_isb);
        }
        Self {
            irq,
            regs: std::array::from_fn(|i| 0xAB00 + i as u64),
            sp: LINUX_SYSCALL_MAILBOX_BASE + SLOT * 256,
            mem: BTreeMap::new(),
            elr: GUEST_ELR,
            spsr: EL0_DAIF_MASKED,
            esr: 0x15 << 26,
            pc: EL1_VECTOR_HOOK_OFFSET,
            irq_masked: true,
            equal: false,
            bytes,
            retired: 0,
            kicked_pc: None,
            kick_pending: false,
            vtimer_enabled: false,
            vtimer_pending: false,
            active: Vec::new(),
            kick_acknowledged: false,
        }
    }

    /// The virtual timer fires before the hook runs.
    fn with_vtimer_pending(mut self) -> Self {
        self.vtimer_enabled = true;
        self.vtimer_pending = true;
        self
    }

    fn pending_host_work_addr() -> u64 {
        carrick_el1_abi::EL1_CURRENT_TASKS_BASE + SLOT * 64 + PENDING_HOST_WORK
    }

    fn irq_taken(&self, intid: u64) -> u64 {
        self.read(
            carrick_el1_abi::EL1_COUNTERS_BASE
                + core::mem::offset_of!(carrick_el1_abi::Counters, irq_taken) as u64
                + intid * 8,
        )
    }

    fn read(&self, addr: u64) -> u64 {
        *self.mem.get(&addr).unwrap_or(&0)
    }

    /// Register `n` as a base/source where 31 is SP.
    fn xn_sp(&self, n: usize) -> u64 {
        if n == 31 { self.sp } else { self.regs[n] }
    }

    fn set_xd_sp(&mut self, d: usize, v: u64) {
        if d == 31 {
            self.sp = v;
        } else {
            self.regs[d] = v;
        }
    }

    /// Register `n` as an operand where 31 is XZR.
    fn xn_zr(&self, n: usize) -> u64 {
        if n == 31 { 0 } else { self.regs[n] }
    }

    fn set_xd_zr(&mut self, d: usize, v: u64) {
        if d != 31 {
            self.regs[d] = v;
        }
    }

    /// The highest-priority pending interrupt (the timer outranks the kick),
    /// if one is pending and not already active.
    fn highest_pending(&self) -> Option<u64> {
        if self.vtimer_pending && !self.active.contains(&VTIMER) {
            Some(VTIMER)
        } else if self.irq == El1IrqMode::GicWindow
            && self.kick_pending
            && !self.active.contains(&KICK)
        {
            Some(KICK)
        } else {
            None
        }
    }

    /// What the engine does when it absorbs a kick inside Carrick's EL1 code
    /// (`OwedKick::absorb`): publish it to the slot, clear `I` in `SPSR_EL1`
    /// when that holds the EL0 return state (not an EL1 IRQ's), and make the
    /// owed interrupt pending.
    fn absorb_kick(&mut self) {
        self.mem.insert(Self::pending_host_work_addr(), 1);
        if self.spsr & 0xF == 0 {
            self.spsr &= !PSTATE_I;
        }
        self.kick_pending = true;
    }

    /// The EL1 image (`carrick_el1_syscall`): forward at entry when host work
    /// is pending, else serve (`Action::Served == 0`) and write the result.
    fn el1_image(&mut self) {
        let frame = self.regs[0];
        let pending = self.read(Self::pending_host_work_addr()) != 0;
        if pending {
            self.regs[0] = 1;
        } else {
            self.mem.insert(frame, 0x5E4E);
            self.regs[0] = 0;
        }
    }

    fn run(&mut self, kick_at: Option<usize>) -> Exit {
        for _ in 0..2000 {
            if Some(self.retired) == kick_at {
                self.kicked_pc = Some(self.pc);
                self.absorb_kick();
            }
            // An unmasked pending interrupt is taken at this boundary.
            if !self.irq_masked && self.highest_pending().is_some() {
                self.elr = self.pc as u64;
                self.spsr = MODE_EL1H | 0x340; // D, A, F masked; I clear
                self.irq_masked = true;
                self.pc = 0x280;
            }
            if self.pc == CAPTURE {
                return Exit::Host;
            }
            let op = u32::from_le_bytes(self.bytes[self.pc..self.pc + 4].try_into().expect("word"));
            let pc = self.pc;
            self.pc += 4;
            self.retired += 1;
            let rd = (op & 31) as usize;
            let rn = ((op >> 5) & 31) as usize;
            let rm = ((op >> 16) & 31) as usize;
            if op == 0xD69F_03E0 {
                if self.spsr & 0xF == MODE_EL1H {
                    // Return from an IRQ taken at EL1.
                    self.pc = self.elr as usize;
                    self.irq_masked = self.spsr & PSTATE_I != 0;
                    continue;
                }
                return Exit::Eret {
                    spsr: self.spsr,
                    elr: self.elr,
                };
            }
            if op == 0xD400_0062 {
                return Exit::Fault;
            }
            if op == 0xD63F_0200 {
                // blr x16: the EL1 image, then return here.
                self.regs[30] = pc as u64 + 4;
                self.el1_image();
                continue;
            }
            match op {
                0xD503_42FF => {
                    self.irq_masked = false; // msr daifclr, #2
                    continue;
                }
                0xD503_42DF => {
                    self.irq_masked = true; // msr daifset, #2
                    continue;
                }
                0xD503_3FDF => continue, // isb
                0xD51B_E33F => {
                    // msr cntv_ctl_el0, xzr: the timer stops asserting.
                    self.vtimer_enabled = false;
                    self.vtimer_pending = false;
                    continue;
                }
                _ => {}
            }
            // mrs/msr of ELR_EL1, SPSR_EL1, ESR_EL1, ISR_EL1, ICC_IAR1_EL1,
            // ICC_EOIR1_EL1 with any Xt.
            match op & !31 {
                0xD538_4020 => self.set_xd_zr(rd, self.elr),
                0xD538_4000 => self.set_xd_zr(rd, self.spsr),
                0xD538_5200 => self.set_xd_zr(rd, self.esr),
                0xD518_4020 => self.elr = self.xn_zr(rd),
                0xD518_4000 => self.spsr = self.xn_zr(rd),
                0xD518_5200 => self.esr = self.xn_zr(rd),
                0xD538_C100 => {
                    let i = if self.highest_pending().is_some() {
                        PSTATE_I
                    } else {
                        0
                    };
                    self.set_xd_zr(rd, i);
                }
                0xD538_CC00 => {
                    let intid = self.highest_pending().unwrap_or(SPURIOUS);
                    if intid != SPURIOUS {
                        self.active.push(intid);
                        match intid {
                            KICK => {
                                self.kick_pending = false;
                                self.kick_acknowledged = true;
                            }
                            _ => self.vtimer_pending = false,
                        }
                    }
                    self.set_xd_zr(rd, intid);
                }
                0xD518_CC20 => {
                    let intid = self.xn_zr(rd);
                    assert!(
                        self.active.contains(&intid),
                        "EOI of INTID {intid} that is not active"
                    );
                    self.active.retain(|active| *active != intid);
                    // A level timer still enabled asserts again.
                    if intid == VTIMER && self.vtimer_enabled {
                        self.vtimer_pending = true;
                    }
                }
                _ => {}
            }
            if matches!(
                op & !31,
                0xD538_4020
                    | 0xD538_4000
                    | 0xD538_5200
                    | 0xD518_4020
                    | 0xD518_4000
                    | 0xD518_5200
                    | 0xD538_C100
                    | 0xD538_CC00
                    | 0xD518_CC20
            ) {
                continue;
            }
            if op & 0xFC00_0000 == 0x1400_0000 {
                let d = ((op << 6) as i32 >> 6) as i64 * 4;
                self.pc = (pc as i64 + d) as usize;
            } else if op & 0xFF00_0010 == 0x5400_0000 {
                // b.eq (cond 0) / b.ne (cond 1)
                assert!(op & 15 <= 1, "unsupported condition in {op:08x}");
                let d = (((op >> 5) & 0x7FFFF) << 13) as i32 >> 13;
                if self.equal == (op & 15 == 0) {
                    self.pc = (pc as i64 + i64::from(d) * 4) as usize;
                }
            } else if op & 0xFF00_0000 == 0x3400_0000 {
                // cbz wN
                let d = (((op >> 5) & 0x7FFFF) << 13) as i32 >> 13;
                if self.xn_zr(rd) & 0xFFFF_FFFF == 0 {
                    self.pc = (pc as i64 + i64::from(d) * 4) as usize;
                }
            } else if op & 0x7F00_0000 == 0x3600_0000 {
                // tbz xN, #bit
                let bit = ((op >> 19) & 31) | ((op >> 26) & 32);
                let d = (((op >> 5) & 0x3FFF) << 18) as i32 >> 18;
                if self.xn_zr(rd) & (1 << bit) == 0 {
                    self.pc = (pc as i64 + i64::from(d) * 4) as usize;
                }
            } else if op & 0x9F00_0000 == 0x1000_0000 {
                // adr xN
                let imm = (((op >> 5) & 0x7FFFF) << 2) | ((op >> 29) & 3);
                let d = ((imm << 11) as i32) >> 11;
                self.set_xd_zr(rd, (pc as i64 + i64::from(d)) as u64);
            } else if op & 0xFFC0_0000 == 0xF900_0000 {
                let addr = self.xn_sp(rn) + u64::from((op >> 10) & 0xFFF) * 8;
                self.mem.insert(addr, self.xn_zr(rd));
            } else if op & 0xFFC0_0000 == 0xF940_0000 {
                let addr = self.xn_sp(rn) + u64::from((op >> 10) & 0xFFF) * 8;
                let v = self.read(addr);
                self.set_xd_zr(rd, v);
            } else if op & 0xFFFF_FC00 == 0x88DF_FC00 {
                let v = self.read(self.xn_sp(rn)) & 0xFFFF_FFFF;
                self.set_xd_zr(rd, v);
            } else if op & 0xFFFF_FC00 == 0x889F_FC00 {
                self.mem
                    .insert(self.xn_sp(rn), self.xn_zr(rd) & 0xFFFF_FFFF);
            } else if op & 0xFFE0_FC1F == 0xF820_001F {
                // stadd xS, [xN]
                let addr = self.xn_sp(rn);
                let v = self.read(addr).wrapping_add(self.xn_zr(rm));
                self.mem.insert(addr, v);
            } else if op & 0xFF80_0000 == 0xD280_0000 {
                let shift = ((op >> 21) & 3) * 16;
                self.set_xd_zr(rd, u64::from((op >> 5) & 0xFFFF) << shift);
            } else if op & 0xFF80_0000 == 0xF280_0000 {
                let shift = ((op >> 21) & 3) * 16;
                let v = (self.xn_zr(rd) & !(0xFFFF << shift))
                    | (u64::from((op >> 5) & 0xFFFF) << shift);
                self.set_xd_zr(rd, v);
            } else if op & 0xFFC0_0000 == 0x9100_0000 {
                let v = self.xn_sp(rn) + u64::from((op >> 10) & 0xFFF);
                self.set_xd_sp(rd, v);
            } else if op & 0xFFC0_0000 == 0xD100_0000 {
                let v = self.xn_sp(rn) - u64::from((op >> 10) & 0xFFF);
                self.set_xd_sp(rd, v);
            } else if op & 0xFFC0_0000 == 0xF100_0000 && rd == 31 {
                self.equal = self.xn_sp(rn) == u64::from((op >> 10) & 0xFFF);
            } else if op & 0xFFE0_FC1F == 0xEB00_001F {
                // cmp xN, xM
                self.equal = self.xn_zr(rn) == self.xn_zr(rm);
            } else if op & 0xFFE0_0000 == 0x8B00_0000 {
                let amount = (op >> 10) & 0x3F;
                self.set_xd_zr(rd, self.xn_zr(rn) + (self.xn_zr(rm) << amount));
            } else if op & 0xFFE0_0000 == 0xCB00_0000 {
                let amount = (op >> 10) & 0x3F;
                self.set_xd_zr(rd, self.xn_zr(rn) - (self.xn_zr(rm) << amount));
            } else if op & 0xFFC0_FC00 == 0xD340_FC00 {
                // lsr xd, xn, #immr
                let amount = (op >> 16) & 0x3F;
                self.set_xd_zr(rd, self.xn_zr(rn) >> amount);
            } else {
                panic!("unsupported vector-page opcode {op:08x} at {pc:#x}");
            }
        }
        panic!("unbounded vector-page control flow");
    }

    /// What became of an owed kick when the hook left through `exit`.
    fn kick_fate(&self, exit: &Exit) -> KickFate {
        match exit {
            Exit::Host => KickFate::Host,
            Exit::Fault => panic!("the hook failed loud (hvc #3)"),
            Exit::Eret { spsr, .. } => {
                if self.kick_pending {
                    if spsr & PSTATE_I == 0 {
                        KickFate::TakenAtEl0
                    } else {
                        KickFate::MaskedAtEl0
                    }
                } else {
                    KickFate::ConsumedAtEl1
                }
            }
        }
    }
}

/// Instructions the vector page retires on the served path with no kick.
fn served_path_len(machine: impl Fn() -> Machine) -> usize {
    let mut m = machine();
    assert!(matches!(m.run(None), Exit::Eret { .. }));
    m.retired
}

/// Inject a kick at every instruction boundary of the served path (and of the
/// IRQ hook, when `machine` takes an interrupt there) and collect the
/// boundaries where the kick did not survive to the host or to EL0.
fn lost_kicks(machine: impl Fn() -> Machine) -> Vec<String> {
    let len = served_path_len(&machine);
    let mut lost = Vec::new();
    for kick_at in 0..len {
        let mut m = machine();
        let exit = m.run(Some(kick_at));
        if let Exit::Eret { spsr, elr } = exit {
            assert_eq!(elr, GUEST_ELR, "EL0 resumed at the wrong PC");
            assert_eq!(
                spsr | PSTATE_I,
                EL0_DAIF_MASKED,
                "EL0 resumed with a return state other than the TrapFrame's"
            );
        }
        let fate = m.kick_fate(&exit);
        if !matches!(fate, KickFate::Host | KickFate::TakenAtEl0) {
            let pc = m.kicked_pc.expect("kick injected");
            lost.push(format!("{pc:#x}: {fate:?}"));
        }
    }
    lost
}

/// No kick: the syscall is served in EL1 and EL0 resumes with its exact
/// PSTATE and return address (the owed-kick machinery is guest-invisible).
#[test]
fn served_path_restores_el0_state_exactly() {
    for irq in [El1IrqMode::Masked, El1IrqMode::GicWindow] {
        let mut m = Machine::new(irq);
        let original = m.regs;
        assert_eq!(
            m.run(None),
            Exit::Eret {
                spsr: EL0_DAIF_MASKED,
                elr: GUEST_ELR,
            },
            "{irq:?}"
        );
        assert_eq!(m.sp, LINUX_SYSCALL_MAILBOX_BASE + SLOT * 256);
        assert_eq!(m.regs[0], 0x5E4E, "x0 is the served result");
        assert_eq!(m.regs[1..], original[1..], "x1..x30 restored ({irq:?})");
    }
}

/// A kick absorbed at ANY instruction boundary of the served hook either
/// leaves through the host or returns to EL0 with IRQs unmasked, so the
/// pending kick IRQ is taken at the first EL0 instruction.
#[test]
fn kick_absorbed_anywhere_in_served_hook_surfaces() {
    let lost = lost_kicks(|| Machine::new(El1IrqMode::Masked));
    assert!(
        lost.is_empty(),
        "an owed kick was lost until the next host exit when absorbed at {lost:?}"
    );
}

/// The same obligation with the in-kernel GIC, where the served path opens
/// an EL1 IRQ window: a kick absorbed at any boundary, before, inside or after
/// the window, leaves through the host or reaches EL0 pending and unmasked,
/// and EL0 resumes with the TrapFrame's exact return state.
#[test]
fn gic_kick_absorbed_anywhere_in_served_hook_surfaces() {
    let lost = lost_kicks(|| Machine::new(El1IrqMode::GicWindow));
    assert!(
        lost.is_empty(),
        "an owed kick was lost when absorbed at {lost:?}"
    );
}

/// With the virtual timer pending, the window takes it at EL1, so the kick is
/// also injected at every boundary of the IRQ hook. The timer is taken exactly
/// once and stopped, and the kick still surfaces.
#[test]
fn gic_kick_absorbed_anywhere_while_el1_takes_the_timer_surfaces() {
    let machine = || Machine::new(El1IrqMode::GicWindow).with_vtimer_pending();
    let mut m = machine();
    assert_eq!(
        m.run(None),
        Exit::Eret {
            spsr: EL0_DAIF_MASKED,
            elr: GUEST_ELR,
        }
    );
    assert_eq!(m.irq_taken(VTIMER), 1, "the timer was taken at EL1 once");
    assert!(!m.vtimer_enabled && !m.vtimer_pending && m.active.is_empty());
    assert!(
        served_path_len(machine) > served_path_len(|| Machine::new(El1IrqMode::GicWindow)),
        "the IRQ hook ran"
    );
    let lost = lost_kicks(machine);
    assert!(
        lost.is_empty(),
        "an owed kick was lost when absorbed at {lost:?}"
    );
}

/// A kick re-armed while the vCPU was inside the EL1 image (`run_to_exit`'s
/// critical-section resume) is pending before the hook's served path with
/// nothing published to the slot. The window takes the SGI and must hand it
/// back to the host through pending host work.
#[test]
fn gic_kick_pending_before_the_window_leaves_through_the_host() {
    let mut m = Machine::new(El1IrqMode::GicWindow);
    m.kick_pending = true;
    let exit = m.run(None);
    assert_eq!(m.kick_fate(&exit), KickFate::Host, "{exit:?}");
    assert!(m.kick_acknowledged);
    assert_eq!(m.irq_taken(KICK), 1);
}

/// The hatch's vector bytes open no window and keep the current-EL IRQ slot a
/// bare `eret`: an IRQ is never unmasked at EL1.
#[test]
fn masked_mode_vector_page_never_unmasks_irqs() {
    let bytes = el1_vectors_bytes_mailbox_irq(true, true, true, El1IrqMode::Masked);
    let words: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().expect("word")))
        .collect();
    assert!(!words.contains(&AARCH64_MSR_DAIFCLR_I_OPCODE));
    assert_eq!(
        words[AARCH64_VECTOR_CUR_EL_SPX_IRQ_OFFSET / 4],
        AARCH64_ERET_OPCODE
    );
    assert_eq!(
        bytes,
        el1_vectors_bytes_mailbox_configured(true, true, true),
        "the hatch's bytes are today's"
    );
}

/// In GIC mode the window and the IRQ hook are installed in otherwise unused
/// vector-page space, and EL1 unmasks IRQs in exactly one place.
#[test]
fn gic_mode_vector_page_has_one_window_and_an_irq_hook() {
    let masked = el1_vectors_bytes_mailbox_irq(true, true, true, El1IrqMode::Masked);
    let gic = el1_vectors_bytes_mailbox_irq(true, true, true, El1IrqMode::GicWindow);
    let words = |bytes: &[u8]| -> Vec<u32> {
        bytes
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().expect("word")))
            .collect()
    };
    let (masked, gic) = (words(&masked), words(&gic));
    assert_eq!(
        gic.iter()
            .filter(|word| **word == AARCH64_MSR_DAIFCLR_I_OPCODE)
            .count(),
        1
    );
    let hook = EL1_IRQ_HOOK_OFFSET / 4;
    let nop = AARCH64_NOP_OPCODE;
    let hook_len = gic[hook..]
        .iter()
        .position(|word| *word == nop)
        .expect("hook end");
    assert!(
        masked[hook..hook + hook_len]
            .iter()
            .all(|word| *word == nop),
        "the IRQ hook overwrote live vector-page code"
    );
    assert_eq!(
        gic[AARCH64_VECTOR_CUR_EL_SPX_IRQ_OFFSET / 4],
        enc_b(
            AARCH64_VECTOR_CUR_EL_SPX_IRQ_OFFSET as u64,
            EL1_IRQ_HOOK_OFFSET as u64
        )
    );
}
