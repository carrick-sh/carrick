//! One PE's GICv3 CPU interface and the private interrupts (SGIs and PPIs)
//! of its redistributor. Arm IHI 0069H: 1.2 (interrupt types), 4.1
//! (interrupt life cycle: inactive, pending, active, active and pending),
//! 4.8 (priority, running priority and the priority mask), 12.2
//! (`ICC_IAR1_EL1`, `ICC_EOIR1_EL1`, `ICC_SGI1R_EL1`). Group 1 only, with
//! `ICC_CTLR_EL1.EOImode` 0 (an EOI drops priority and deactivates) and
//! binary point 0 (preemption compares whole priorities). No EL2 or EL3.
//!
//! The provider programs what a redistributor and CPU-interface bring-up
//! would (enable, priority, priority mask, group enable); the guest owns
//! acknowledge, end of interrupt and SGI generation. A level-sensitive line
//! (the virtual timer's PPI) is pending while its input is asserted and is
//! not latched; an SGI is edge-triggered and latched until acknowledged.

/// What `ICC_IAR1_EL1` returns when no interrupt can be acknowledged.
pub const SPURIOUS_INTID: u32 = 1023;

/// The PPI the EL1 virtual timer drives (Arm BSA/SBSA: INTID 27).
pub const VIRTUAL_TIMER_INTID: u32 = 27;

/// SGIs and PPIs: the interrupts private to one PE.
const PRIVATE_INTIDS: u32 = 32;

/// The idle running priority: no interrupt is active.
const IDLE_PRIORITY: u8 = 0xff;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GicCpuInterface {
    /// `GICR_ISENABLER0`.
    enabled: u32,
    /// The pending latch of edge-triggered interrupts (`GICR_ISPENDR0`).
    pending: u32,
    /// `GICR_ISACTIVER0`.
    active: u32,
    /// `GICR_IPRIORITYR<n>`: lower values are higher priority.
    priority: [u8; PRIVATE_INTIDS as usize],
    /// `ICC_PMR_EL1`: an interrupt is signalled only at a higher priority.
    priority_mask: u8,
    /// `ICC_IGRPEN1_EL1.Enable`.
    group1: bool,
}

impl Default for GicCpuInterface {
    /// The reset state a CPU interface leaves to its bring-up: nothing
    /// enabled, every priority masked, group 1 disabled.
    fn default() -> Self {
        Self {
            enabled: 0,
            pending: 0,
            active: 0,
            priority: [0; PRIVATE_INTIDS as usize],
            priority_mask: 0,
            group1: false,
        }
    }
}

const fn private_bit(intid: u32) -> Option<u32> {
    if intid < PRIVATE_INTIDS {
        Some(1 << intid)
    } else {
        None
    }
}

impl GicCpuInterface {
    /// Redistributor bring-up of one private interrupt: its priority and
    /// enable (`GICR_IPRIORITYR<n>`, `GICR_ISENABLER0`).
    pub fn enable(&mut self, intid: u32, priority: u8) {
        if let Some(bit) = private_bit(intid) {
            self.priority[intid as usize] = priority;
            self.enabled |= bit;
        }
    }

    /// CPU-interface bring-up: `ICC_PMR_EL1` and `ICC_IGRPEN1_EL1`.
    pub fn configure(&mut self, priority_mask: u8, group1: bool) {
        self.priority_mask = priority_mask;
        self.group1 = group1;
    }

    /// `GICR_ISPENDR0` (`true`) or `GICR_ICPENDR0` (`false`) for one
    /// edge-triggered private interrupt.
    pub fn set_pending(&mut self, intid: u32, pending: bool) {
        if let Some(bit) = private_bit(intid) {
            if pending {
                self.pending |= bit;
            } else {
                self.pending &= !bit;
            }
        }
    }

    /// Whether `intid`'s pending latch is set.
    #[must_use]
    pub const fn is_latched(&self, intid: u32) -> bool {
        match private_bit(intid) {
            Some(bit) => self.pending & bit != 0,
            None => false,
        }
    }

    /// Whether `intid` is active (acknowledged and not yet ended).
    #[must_use]
    pub const fn is_active(&self, intid: u32) -> bool {
        match private_bit(intid) {
            Some(bit) => self.active & bit != 0,
            None => false,
        }
    }

    /// 4.8.4: the priority of the highest-priority active interrupt.
    fn running_priority(&self) -> u8 {
        let mut running = IDLE_PRIORITY;
        let mut active = self.active;
        while active != 0 {
            let intid = active.trailing_zeros();
            running = running.min(self.priority[intid as usize]);
            active &= active - 1;
        }
        running
    }

    /// The interrupt the CPU interface signals given the asserted level
    /// inputs `lines`: the highest-priority (then lowest INTID) enabled,
    /// pending and inactive interrupt whose priority passes both the
    /// priority mask and the running priority.
    fn highest_pending(&self, lines: u32) -> Option<u32> {
        if !self.group1 {
            return None;
        }
        let threshold = self.priority_mask.min(self.running_priority());
        let mut candidates = (self.pending | lines) & self.enabled & !self.active;
        let mut best: Option<(u8, u32)> = None;
        while candidates != 0 {
            let intid = candidates.trailing_zeros();
            let priority = self.priority[intid as usize];
            if priority < threshold && best.is_none_or(|(p, _)| priority < p) {
                best = Some((priority, intid));
            }
            candidates &= candidates - 1;
        }
        best.map(|(_, intid)| intid)
    }

    /// Whether the CPU interface asserts the PE's IRQ input. This is the
    /// WFI wake-up condition whatever `PSTATE.I` says (D1.16.2).
    #[must_use]
    pub fn signals_irq(&self, lines: u32) -> bool {
        self.highest_pending(lines).is_some()
    }

    /// 12.2.11 `ICC_IAR1_EL1` read: acknowledge the signalled interrupt
    /// (pending becomes active; a level input stays pending while asserted),
    /// or [`SPURIOUS_INTID`].
    pub fn acknowledge(&mut self, lines: u32) -> u32 {
        let Some(intid) = self.highest_pending(lines) else {
            return SPURIOUS_INTID;
        };
        let bit = 1 << intid;
        self.active |= bit;
        self.pending &= !bit;
        intid
    }

    /// 12.2.9 `ICC_EOIR1_EL1` write with EOImode 0: priority drop and
    /// deactivation of `intid`. A special or unacknowledged INTID is ignored.
    pub fn end_of_interrupt(&mut self, intid: u32) {
        if let Some(bit) = private_bit(intid) {
            self.active &= !bit;
        }
    }

    /// 12.2.21 `ICC_SGI1R_EL1` write by the PE with affinity `mpidr`: the
    /// SGI it makes pending on itself, if the target set includes it.
    /// `IRM` = 1 targets every PE except the writer.
    #[must_use]
    pub const fn sgi_for_self(sgi1r: u64, mpidr: u64) -> Option<u32> {
        let intid = ((sgi1r >> 24) & 0xf) as u32;
        if sgi1r & (1 << 40) != 0 {
            return None;
        }
        let aff0 = mpidr & 0xff;
        let same_cluster = (sgi1r >> 16) & 0xff == (mpidr >> 8) & 0xff
            && (sgi1r >> 32) & 0xff == (mpidr >> 16) & 0xff
            && (sgi1r >> 48) & 0xff == (mpidr >> 32) & 0xff
            && (sgi1r >> 44) & 0xf == aff0 >> 4;
        if same_cluster && sgi1r & (1 << (aff0 & 0xf)) != 0 {
            Some(intid)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KICK: u32 = 15;
    const RESCHED: u32 = 14;

    fn brought_up() -> GicCpuInterface {
        let mut gic = GicCpuInterface::default();
        gic.enable(VIRTUAL_TIMER_INTID, 0x80);
        gic.enable(RESCHED, 0x90);
        gic.enable(KICK, 0xa0);
        gic.configure(0xf0, true);
        gic
    }

    #[test]
    fn reset_interface_signals_nothing() {
        let mut gic = GicCpuInterface::default();
        gic.set_pending(KICK, true);
        assert!(!gic.signals_irq(1 << VIRTUAL_TIMER_INTID));
        assert_eq!(gic.acknowledge(1 << VIRTUAL_TIMER_INTID), SPURIOUS_INTID);
    }

    #[test]
    fn acknowledge_takes_the_highest_priority_then_eoi_reopens() {
        let mut gic = brought_up();
        gic.set_pending(KICK, true);
        gic.set_pending(RESCHED, true);
        let timer = 1 << VIRTUAL_TIMER_INTID;
        assert_eq!(gic.acknowledge(timer), VIRTUAL_TIMER_INTID);
        // Running at the timer's priority, lower-priority SGIs wait.
        assert_eq!(gic.acknowledge(timer), SPURIOUS_INTID);
        // The level input stays asserted: after EOI it is pending again.
        gic.end_of_interrupt(VIRTUAL_TIMER_INTID);
        assert_eq!(gic.acknowledge(timer), VIRTUAL_TIMER_INTID);
        gic.end_of_interrupt(VIRTUAL_TIMER_INTID);
        // The guest drops the line (disables the timer).
        assert_eq!(gic.acknowledge(0), RESCHED);
        gic.end_of_interrupt(RESCHED);
        assert_eq!(gic.acknowledge(0), KICK);
        assert!(!gic.is_latched(KICK) && gic.is_active(KICK));
        gic.end_of_interrupt(KICK);
        assert_eq!(gic.acknowledge(0), SPURIOUS_INTID);
        assert!(!gic.signals_irq(0));
    }

    #[test]
    fn priority_mask_and_disabled_interrupts_are_not_signalled() {
        let mut gic = brought_up();
        gic.configure(0x90, true);
        gic.set_pending(KICK, true);
        gic.set_pending(RESCHED, true);
        assert!(!gic.signals_irq(0), "0x90 and 0xa0 do not pass PMR 0x90");
        assert!(gic.signals_irq(1 << VIRTUAL_TIMER_INTID));
        gic.set_pending(3, true);
        gic.configure(0xf0, true);
        assert_eq!(gic.acknowledge(0), RESCHED, "INTID 3 is not enabled");
    }

    #[test]
    fn sgi1r_targets_follow_affinity_and_irm() {
        let mpidr = 0x8000_0000 | (2 << 8) | 0x13;
        let own = carrick_guest_arch::sgi_target_of(mpidr);
        assert_eq!(
            GicCpuInterface::sgi_for_self(own | (u64::from(RESCHED) << 24), mpidr),
            Some(RESCHED)
        );
        // Same list bit, other range selector or cluster: another PE.
        assert_eq!(
            GicCpuInterface::sgi_for_self(own & !(0xf << 44), mpidr),
            None
        );
        assert_eq!(GicCpuInterface::sgi_for_self(own ^ (1 << 16), mpidr), None);
        // IRM: every PE but the writer.
        assert_eq!(GicCpuInterface::sgi_for_self(own | (1 << 40), mpidr), None);
    }
}
