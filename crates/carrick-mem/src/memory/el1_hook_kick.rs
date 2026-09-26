//! Contract `kernel.vcpu.kick-el0-boundary`, VM-free binding for the EL1
//! hooks (Fact 9 of EL1 plan 1a), in both interrupt modes, and the EL0
//! interrupt entry of EL1 plan 1c.
//!
//! A host kick that stops the vCPU inside the syscall hook is owed to the EL0
//! boundary: the engine publishes it to the slot's `pending_host_work` flag,
//! clears `I` in the live `SPSR_EL1` when that holds the EL0 return state, and
//! makes the owed-kick interrupt pending (`carrick_aarch64::owed_kick`). The
//! hook saves `SPSR_EL1` into the TrapFrame on entry and reloads it before
//! `eret`, so the served path must leave through the host (the forward path)
//! or `eret` with the owed interrupt still pending and unmasked. Otherwise EL0
//! resumes with the kick masked or consumed, and a thread that makes no
//! further host syscall never stops for the page-table drain that kicked it.
//!
//! With Hypervisor.framework's in-kernel GIC ([`El1IrqMode::Gic`]) the owed
//! kick is a redistributor-pending SGI that survives run returns, every
//! served return to EL0 unmasks IRQs, and an interrupt taken at EL0 enters
//! the EL1 image through the EL0 IRQ hook, which leaves through `hvc #4` when
//! the image forwards (the kick) and `eret`s otherwise. EL1 never unmasks
//! IRQs itself. The model checks that the EL0 return state is exactly the
//! TrapFrame's (with `I` clear in GIC mode) and that no kick is lost.
//!
//! This interprets the REAL emitted vector bytes, not a model of them, and
//! injects the kick at every instruction boundary of the hooks.

use super::*;
use std::collections::BTreeMap;

const PSTATE_I: u64 = 1 << 7;
/// Carrick's historical EL0 return state: EL0t with DAIF masked.
const EL0_DAIF_MASKED: u64 = 0x3c0;
const GUEST_ELR: u64 = 0x4000_1000;
const SLOT: u64 = 3;
/// The mailbox capture's offset in the test page; reaching it is a host exit.
const CAPTURE: usize = 0x800;
/// `CurrentTask` is 64 bytes (`lsl #6` in the hook); `pending_host_work` at 40.
const PENDING_HOST_WORK: u64 = 40;
const SERVED_WITH_WORK: u64 = 44;
/// A syscall's syndrome (EC 0x15), stale in `ESR_EL1` when an IRQ is taken.
const SVC_ESR: u64 = 0x15 << 26;
/// `Action::Idle`.
const IDLE: u64 = 3;

#[derive(Debug, PartialEq, Eq)]
enum Exit {
    /// Reached the mailbox capture: the syscall surfaces to the host.
    Host,
    /// `eret` to EL0 with this `SPSR_EL1` and `ELR_EL1`.
    Eret { spsr: u64, elr: u64 },
    /// `hvc #4`: the EL0-boundary kick exit, with the EL0 state the host's
    /// decode makes the live PC and PSTATE.
    Kick { spsr: u64, elr: u64 },
    /// `hvc #5`: the idle exit, with SP_EL1 at this value.
    Idle { sp: u64 },
    /// `hvc #3`: Carrick's fail-loud trap.
    Fault,
}

/// Where the owed kick stands when the hook leaves.
#[derive(Debug, PartialEq, Eq)]
enum KickFate {
    /// The vCPU left through the host, which settles the kick.
    Host,
    /// EL0 resumes with the kick pending and I clear: it is taken at the
    /// first EL0 instruction.
    TakenAtEl0,
    /// EL0 resumes with the kick masked (the pre-fix Fact 9 hole).
    MaskedAtEl0,
    /// The kick SGI was acknowledged in EL1 and nothing handed it back to
    /// the host.
    ConsumedAtEl1,
}

/// What the stand-in for the EL1 image (`carrick_el1_syscall`) does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Image {
    /// Serve the syscall (or interrupt) unless host work is pending.
    Serve,
    /// The syscall parks its thread and the idle vCPU leaves for the host.
    Idle,
}

/// Small independent interpreter of the vector page's instruction subset.
/// Unknown instructions fail closed.
struct Machine {
    regs: [u64; 31],
    sp: u64,
    mem: BTreeMap<u64, u64>,
    elr: u64,
    spsr: u64,
    esr: u64,
    pc: usize,
    equal: bool,
    bytes: Vec<u8>,
    image: Image,
    /// Instructions retired; the kick lands before instruction `kick_at`.
    retired: usize,
    /// Where the injected kick stopped the vCPU.
    kicked_pc: Option<usize>,
    /// The owed kick is pending (the SGI in GIC mode).
    kick_pending: bool,
    /// The kick SGI was acknowledged in EL1.
    kick_acknowledged: bool,
    /// The EL1 image ran with an interrupt frame (syndrome 0).
    irq_frames: usize,
}

impl Machine {
    fn bytes(irq: El1IrqMode) -> Vec<u8> {
        let mut bytes = vec![0u8; LINUX_EL1_VECTORS_SIZE as usize];
        write_el1_vector_hook(&mut bytes, EL1_VECTOR_HOOK_OFFSET, CAPTURE, irq);
        if irq == El1IrqMode::Gic {
            write_el0_irq_hook(&mut bytes, EL0_IRQ_HOOK_OFFSET);
        }
        bytes
    }

    /// Entering the syscall hook from the mailbox handler.
    fn syscall(irq: El1IrqMode) -> Self {
        Self {
            regs: std::array::from_fn(|i| 0xAB00 + i as u64),
            sp: LINUX_SYSCALL_MAILBOX_BASE + SLOT * 256,
            mem: BTreeMap::new(),
            elr: GUEST_ELR,
            spsr: EL0_DAIF_MASKED,
            esr: SVC_ESR,
            pc: EL1_VECTOR_HOOK_OFFSET,
            equal: false,
            bytes: Self::bytes(irq),
            image: Image::Serve,
            retired: 0,
            kicked_pc: None,
            kick_pending: false,
            kick_acknowledged: false,
            irq_frames: 0,
        }
    }

    /// An interrupt taken at EL0 (GIC mode): the lower-EL IRQ slot, with
    /// the EL0 return state in ELR/SPSR_EL1 and a stale syscall syndrome.
    fn el0_irq() -> Self {
        Self {
            pc: AARCH64_VECTOR_LOWER_EL_IRQ_OFFSET,
            spsr: EL0_DAIF_MASKED & !PSTATE_I,
            ..Self::syscall(El1IrqMode::Gic)
        }
    }

    fn pending_host_work_addr() -> u64 {
        carrick_el1_abi::EL1_CURRENT_TASKS_BASE + SLOT * 64 + PENDING_HOST_WORK
    }

    fn served_with_work_addr() -> u64 {
        carrick_el1_abi::EL1_CURRENT_TASKS_BASE + SLOT * 64 + SERVED_WITH_WORK
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

    /// What the engine does when it absorbs a kick inside Carrick's EL1 code
    /// (`OwedKick::absorb`): publish it to the slot, clear `I` in `SPSR_EL1`
    /// when that holds the EL0 return state, and make the owed interrupt
    /// pending.
    fn absorb_kick(&mut self) {
        self.mem.insert(Self::pending_host_work_addr(), 1);
        if self.spsr & 0xF == 0 {
            self.spsr &= !PSTATE_I;
        }
        self.kick_pending = true;
    }

    /// The EL1 image (`carrick_el1_syscall`, `x0` = the TrapFrame). For an
    /// interrupt frame (syndrome 0) it acknowledges the kick SGI, which
    /// becomes pending host work, as `Sched::take_irqs` does.
    fn el1_image(&mut self) {
        let frame = self.regs[0];
        let irq = self.read(frame + 264) == 0;
        if irq {
            self.irq_frames += 1;
            if self.kick_pending {
                self.kick_pending = false;
                self.kick_acknowledged = true;
                self.mem.insert(Self::pending_host_work_addr(), 1);
            }
        }
        let pending = self.read(Self::pending_host_work_addr()) != 0;
        self.regs[0] = if pending {
            1
        } else if !irq && self.image == Image::Idle {
            IDLE
        } else {
            if !irq {
                self.mem.insert(frame, 0x5E4E);
            }
            0
        };
    }

    fn run(&mut self, kick_at: Option<usize>) -> Exit {
        for _ in 0..2000 {
            if Some(self.retired) == kick_at {
                self.kicked_pc = Some(self.pc);
                self.absorb_kick();
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
            match op {
                0xD69F_03E0 => {
                    return Exit::Eret {
                        spsr: self.spsr,
                        elr: self.elr,
                    };
                }
                0xD400_0062 => return Exit::Fault,
                0xD400_0082 => {
                    // hvc #4: the host withdraws the kick and resumes at EL0.
                    return Exit::Kick {
                        spsr: self.spsr,
                        elr: self.elr,
                    };
                }
                0xD400_00A2 => return Exit::Idle { sp: self.sp },
                0xD63F_0200 => {
                    // blr x16: the EL1 image, then return here.
                    self.regs[30] = pc as u64 + 4;
                    self.el1_image();
                    continue;
                }
                0xD503_3FDF | 0xD503_201F => continue, // isb, nop
                _ => {}
            }
            // mrs/msr of ELR_EL1, SPSR_EL1, ESR_EL1 with any Xt.
            let handled = match op & !31 {
                0xD538_4020 => {
                    self.set_xd_zr(rd, self.elr);
                    true
                }
                0xD538_4000 => {
                    self.set_xd_zr(rd, self.spsr);
                    true
                }
                0xD538_5200 => {
                    self.set_xd_zr(rd, self.esr);
                    true
                }
                0xD518_4020 => {
                    self.elr = self.xn_zr(rd);
                    true
                }
                0xD518_4000 => {
                    self.spsr = self.xn_zr(rd);
                    true
                }
                0xD518_5200 => {
                    self.esr = self.xn_zr(rd);
                    true
                }
                _ => false,
            };
            if handled {
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
            } else if op & 0xFFE0_FC00 == 0x8A20_0000 {
                // bic xd, xn, xm
                self.set_xd_zr(rd, self.xn_zr(rn) & !self.xn_zr(rm));
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
            Exit::Host | Exit::Kick { .. } | Exit::Idle { .. } => KickFate::Host,
            Exit::Fault => panic!("the hook failed loud (hvc #3)"),
            Exit::Eret { spsr, .. } => {
                if self.kick_pending {
                    if spsr & PSTATE_I == 0 {
                        KickFate::TakenAtEl0
                    } else {
                        KickFate::MaskedAtEl0
                    }
                } else if self.kick_acknowledged {
                    KickFate::ConsumedAtEl1
                } else {
                    // The kick landed after the image looked and was absorbed
                    // without being taken: covered by `kick_pending`.
                    KickFate::TakenAtEl0
                }
            }
        }
    }
}

/// Instructions the vector page retires with no kick.
fn path_len(machine: impl Fn() -> Machine) -> usize {
    let mut m = machine();
    let _ = m.run(None);
    m.retired
}

/// Inject a kick at every instruction boundary and collect the boundaries
/// where the kick did not survive to the host or to EL0, checking at every
/// `eret` and kick exit that EL0 resumes with the TrapFrame's return state.
fn lost_kicks(machine: impl Fn() -> Machine) -> Vec<String> {
    let len = path_len(&machine);
    let mut lost = Vec::new();
    for kick_at in 0..len {
        let mut m = machine();
        let exit = m.run(Some(kick_at));
        if let Exit::Eret { spsr, elr } | Exit::Kick { spsr, elr } = exit {
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
/// PSTATE and return address, except that GIC mode returns with IRQs
/// unmasked (guest-invisible; see `el0_visible_pstate`).
#[test]
fn served_path_restores_el0_state_exactly() {
    for (irq, spsr) in [
        (El1IrqMode::Masked, EL0_DAIF_MASKED),
        (El1IrqMode::Gic, EL0_DAIF_MASKED & !PSTATE_I),
    ] {
        let mut m = Machine::syscall(irq);
        let original = m.regs;
        assert_eq!(
            m.run(None),
            Exit::Eret {
                spsr,
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
    let lost = lost_kicks(|| Machine::syscall(El1IrqMode::Masked));
    assert!(
        lost.is_empty(),
        "an owed kick was lost until the next host exit when absorbed at {lost:?}"
    );
}

/// The same obligation with the in-kernel GIC, where the served path
/// unmasks IRQs for EL0: a kick absorbed at any boundary leaves through the
/// host or reaches EL0 pending and unmasked.
#[test]
fn gic_kick_absorbed_anywhere_in_served_hook_surfaces() {
    let lost = lost_kicks(|| Machine::syscall(El1IrqMode::Gic));
    assert!(
        lost.is_empty(),
        "an owed kick was lost when absorbed at {lost:?}"
    );
}

/// The kick SGI taken at EL0 enters the EL1 image with an interrupt frame,
/// becomes pending host work there, and leaves through `hvc #4` with the
/// interrupted EL0 state and every register as EL0 had it.
#[test]
fn gic_kick_taken_at_el0_leaves_through_the_kick_exit() {
    let mut m = Machine::el0_irq();
    m.kick_pending = true;
    let original = m.regs;
    let exit = m.run(None);
    assert_eq!(
        exit,
        Exit::Kick {
            spsr: EL0_DAIF_MASKED & !PSTATE_I,
            elr: GUEST_ELR,
        }
    );
    assert_eq!(m.irq_frames, 1, "the image saw an interrupt frame");
    assert!(m.kick_acknowledged);
    assert_eq!(m.regs, original, "every EL0 register as it was");
    assert_eq!(m.sp, LINUX_SYSCALL_MAILBOX_BASE + SLOT * 256);
    assert_eq!(
        m.read(Machine::served_with_work_addr()),
        0,
        "an interrupt is not a served syscall"
    );
    assert_eq!(m.esr, SVC_ESR, "ESR_EL1 is left as the last syscall set it");
}

/// An interrupt the image serves (the timer, a reschedule SGI) returns to
/// EL0 exactly; a kick absorbed at any boundary of the EL0 IRQ hook still
/// surfaces.
#[test]
fn gic_el0_irq_hook_returns_exactly_and_loses_no_kick() {
    let mut m = Machine::el0_irq();
    let original = m.regs;
    assert_eq!(
        m.run(None),
        Exit::Eret {
            spsr: EL0_DAIF_MASKED & !PSTATE_I,
            elr: GUEST_ELR,
        }
    );
    assert_eq!(m.regs, original);
    assert_eq!(m.irq_frames, 1);
    let lost = lost_kicks(Machine::el0_irq);
    assert!(
        lost.is_empty(),
        "an owed kick was lost when absorbed at {lost:?}"
    );
}

/// `Action::Idle`: the syscall hook leaves through `hvc #5` with SP_EL1 back
/// on the slot's mailbox, and a resume past it fails loud.
#[test]
fn idle_action_leaves_through_the_idle_exit() {
    let mut m = Machine::syscall(El1IrqMode::Gic);
    m.image = Image::Idle;
    assert_eq!(
        m.run(None),
        Exit::Idle {
            sp: LINUX_SYSCALL_MAILBOX_BASE + SLOT * 256
        }
    );
    assert_eq!(m.run(None), Exit::Fault, "resuming past hvc #5 fails loud");
}

/// The hatch's vector bytes never unmask IRQs, keep the current-EL IRQ slot
/// a bare `eret` and the lower-EL IRQ slot the `hvc #4` kick exit.
#[test]
fn masked_mode_vector_page_never_unmasks_irqs() {
    let bytes = el1_vectors_bytes_mailbox_irq(true, true, true, El1IrqMode::Masked);
    let words: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().expect("word")))
        .collect();
    assert!(!words.contains(&AARCH64_MSR_DAIFCLR_I_OPCODE));
    assert!(!words.contains(&enc_bic_xd_xn_xm(1, 1, 2)));
    assert_eq!(
        words[AARCH64_VECTOR_CUR_EL_SPX_IRQ_OFFSET / 4],
        AARCH64_ERET_OPCODE
    );
    assert_eq!(
        words[AARCH64_VECTOR_LOWER_EL_IRQ_OFFSET / 4],
        AARCH64_HVC_KICK_OPCODE
    );
    assert_eq!(
        bytes,
        el1_vectors_bytes_mailbox_configured(true, true, true),
        "the hatch's bytes are today's"
    );
}

/// In GIC mode the lower-EL IRQ slot enters the EL0 IRQ hook, installed in
/// otherwise unused vector-page space; EL1 never unmasks IRQs (so the
/// current-EL IRQ slot fails loud); and with the EL1 kernel off the page has
/// no hook at all.
#[test]
fn gic_mode_vector_page_routes_el0_interrupts_to_el1() {
    let words = |bytes: &[u8]| -> Vec<u32> {
        bytes
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().expect("word")))
            .collect()
    };
    let masked = words(&el1_vectors_bytes_mailbox_irq(
        true,
        true,
        true,
        El1IrqMode::Masked,
    ));
    let gic = words(&el1_vectors_bytes_mailbox_irq(
        true,
        true,
        true,
        El1IrqMode::Gic,
    ));
    assert!(!gic.contains(&AARCH64_MSR_DAIFCLR_I_OPCODE));
    assert_eq!(
        gic[AARCH64_VECTOR_LOWER_EL_IRQ_OFFSET / 4],
        enc_b(
            AARCH64_VECTOR_LOWER_EL_IRQ_OFFSET as u64,
            EL0_IRQ_HOOK_OFFSET as u64
        )
    );
    assert_eq!(
        gic[AARCH64_VECTOR_CUR_EL_SPX_IRQ_OFFSET / 4],
        AARCH64_HVC_FAULT_OPCODE
    );
    let hook = EL0_IRQ_HOOK_OFFSET / 4;
    let nop = AARCH64_NOP_OPCODE;
    let hook_len = gic[hook..]
        .iter()
        .position(|word| *word == nop)
        .expect("hook end");
    assert!(
        masked[hook..hook + hook_len]
            .iter()
            .all(|word| *word == nop),
        "the EL0 IRQ hook overwrote live vector-page code"
    );
    let off = words(&el1_vectors_bytes_mailbox_irq(
        true,
        true,
        false,
        El1IrqMode::Gic,
    ));
    assert_eq!(
        off[AARCH64_VECTOR_LOWER_EL_IRQ_OFFSET / 4],
        AARCH64_HVC_KICK_OPCODE,
        "no EL1 kernel, no EL1 interrupt entry"
    );
}
