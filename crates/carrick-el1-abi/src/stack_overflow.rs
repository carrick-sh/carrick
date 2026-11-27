//! Terminal report of an EL1 ring stack overflow (#369).
//!
//! Every EL1 stack sits above an unmapped guard. An overflow takes a stage-1
//! translation fault on the guard; the current-EL synchronous vector reports
//! it through `hvc #3` without storing into the guard, and the host turns
//! that report into this record instead of the generic "guest executed at
//! EL1" corruption verdict. It carries no completion or scheduler authority.
use carrick_guest_arch::{CpuId, KernelVa, SlotId};
use core::fmt;

/// `ESR_EL1.EC` of a data abort taken without a change in exception level.
const EC_DATA_ABORT_SAME_EL: u64 = 0x25;
/// `ESR_EL1.EC` of an instruction abort taken without a change in level.
const EC_INSTRUCTION_ABORT_SAME_EL: u64 = 0x21;

/// How the overflow reached the guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum El1StackOverflowKind {
    /// An access faulted on the guard: `FAR_EL1` names a guard address.
    GuardFault,
    /// Some other synchronous exception was taken with too little stack
    /// left for the vector's scratch: the faulting SP was already within
    /// [`crate::EL1_FAULT_VECTOR_SCRATCH`] bytes of (or inside) a guard.
    ExhaustedStack,
}

/// Most return addresses one overflow report carries.
pub const EL1_OVERFLOW_BACKTRACE_FRAMES: usize = 64;

/// The callers on an overflowed EL1 stack, innermost first (#3093): the
/// faulting frame's link register, then the return address of each AAPCS64
/// frame record reached from its frame pointer. The faulting frame is only
/// where the stack ran out; these name the chain that used it up. Resolve
/// them against the EL1 image, for example
/// `addr2line -fipCe <el1-target>/aarch64-unknown-none-softfloat/el1-image/carrick-el1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El1StackBacktrace {
    returns: [u64; EL1_OVERFLOW_BACKTRACE_FRAMES],
    len: usize,
}

impl El1StackBacktrace {
    pub const EMPTY: Self = Self {
        returns: [0; EL1_OVERFLOW_BACKTRACE_FRAMES],
        len: 0,
    };

    /// Walk `slot`'s frame records from `fp`, after `lr`, reading stack
    /// words with `read`. The walk trusts only records inside `slot`'s
    /// usable stack, 16-byte aligned, each caller strictly above its callee,
    /// with a non-zero return address: it ends on any stack, and an
    /// unreadable word ends it early rather than inventing a caller.
    #[must_use]
    pub fn walk(
        slot: SlotId,
        lr: u64,
        mut fp: u64,
        mut read: impl FnMut(u64) -> Option<u64>,
    ) -> Self {
        let mut trace = Self::EMPTY;
        let usable = crate::stack_slot_usable_base(slot.raw() as usize);
        let top = crate::stack_slot_top(slot.raw() as usize);
        if lr != 0 {
            trace.push(lr);
        }
        while trace.len < EL1_OVERFLOW_BACKTRACE_FRAMES
            && fp >= usable
            && fp.checked_add(16).is_some_and(|end| end <= top)
            && fp.is_multiple_of(16)
        {
            let Some(caller) = read(fp) else { break };
            let Some(return_address) = read(fp + 8).filter(|address| *address != 0) else {
                break;
            };
            trace.push(return_address);
            if caller <= fp {
                break;
            }
            fp = caller;
        }
        trace
    }

    fn push(&mut self, address: u64) {
        if let Some(entry) = self.returns.get_mut(self.len) {
            *entry = address;
            self.len += 1;
        }
    }

    /// The return addresses, innermost first.
    pub fn returns(&self) -> &[u64] {
        &self.returns[..self.len]
    }
}

/// A classified EL1 stack overflow: which CPU took it and whose guard it
/// reached. `executing` is `None` when the VMM could not name the leased
/// CPU, never an invented slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El1StackOverflow {
    pub kind: El1StackOverflowKind,
    /// The CPU whose `hvc #3` reported it.
    pub executing: Option<CpuId>,
    /// The slot whose guard (directly below its usable stack) was reached.
    pub stack: SlotId,
    pub far_el1: KernelVa,
    pub sp_el1: KernelVa,
    pub elr_el1: u64,
    pub esr_el1: u64,
    /// The chain that used the stack up; empty when the VMM could not read it.
    pub backtrace: El1StackBacktrace,
}

impl El1StackOverflow {
    /// Classify the original EL1 exception registers an `hvc #3` report
    /// preserved. `sp_el1` is the faulting SP (the vector restores it before
    /// the `hvc`). Returns `None` for every other current-EL fault.
    #[must_use]
    pub fn classify(
        esr_el1: u64,
        far_el1: u64,
        sp_el1: u64,
        elr_el1: u64,
        executing: Option<CpuId>,
    ) -> Option<Self> {
        let ec = (esr_el1 >> 26) & 0x3f;
        let abort = ec == EC_DATA_ABORT_SAME_EL || ec == EC_INSTRUCTION_ABORT_SAME_EL;
        let (kind, slot) =
            if let Some(slot) = crate::el1_stack_guard_slot(far_el1).filter(|_| abort) {
                (El1StackOverflowKind::GuardFault, slot)
            } else {
                let scratch = sp_el1.checked_sub(crate::EL1_FAULT_VECTOR_SCRATCH)?;
                (
                    El1StackOverflowKind::ExhaustedStack,
                    crate::el1_stack_guard_slot(scratch)?,
                )
            };
        Some(Self {
            kind,
            executing,
            stack: SlotId::from_index(slot)?,
            far_el1: KernelVa::new(far_el1),
            sp_el1: KernelVa::new(sp_el1),
            elr_el1,
            esr_el1,
            backtrace: El1StackBacktrace::EMPTY,
        })
    }

    /// This report with the overflowed stack's callers attached.
    #[must_use]
    pub fn with_backtrace(self, backtrace: El1StackBacktrace) -> Self {
        Self { backtrace, ..self }
    }
}

impl fmt::Display for El1StackOverflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let how = match self.kind {
            El1StackOverflowKind::GuardFault => "faulted on the guard of",
            El1StackOverflowKind::ExhaustedStack => "exhausted",
        };
        match self.executing {
            Some(cpu) => write!(f, "EL1 stack overflow: cpu {}", cpu.raw())?,
            None => write!(f, "EL1 stack overflow: an unnamed cpu")?,
        }
        write!(
            f,
            " {how} EL1 stack slot {} (usable {:#x}..{:#x}): far_el1={:#x} sp_el1={:#x} elr_el1={:#x} esr_el1={:#x}",
            self.stack.raw(),
            crate::stack_slot_usable_base(self.stack.raw() as usize),
            crate::stack_slot_top(self.stack.raw() as usize),
            self.far_el1.raw(),
            self.sp_el1.raw(),
            self.elr_el1,
            self.esr_el1,
        )?;
        if !self.backtrace.returns().is_empty() {
            f.write_str("; ring return addresses:")?;
            for address in self.backtrace.returns() {
                write!(f, " {address:#x}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    const DATA_ABORT_TRANSLATION_L3: u64 = (EC_DATA_ABORT_SAME_EL << 26) | (1 << 25) | 0x07;

    #[test]
    fn a_guard_fault_names_the_slot_whose_guard_was_hit() {
        for slot in [0_usize, 1, 7, crate::EL1_STACK_SLOTS as usize - 1] {
            let usable = crate::stack_slot_usable_base(slot);
            let far = usable - 0x10;
            let report = El1StackOverflow::classify(
                DATA_ABORT_TRANSLATION_L3,
                far,
                usable - 0x10,
                0x2d_0400_1234,
                Some(CpuId::new(slot as u32)),
            )
            .expect("a guard fault is an overflow");
            assert_eq!(report.kind, El1StackOverflowKind::GuardFault);
            assert_eq!(report.stack.raw() as usize, slot);
            let text = std::format!("{report}");
            assert!(text.contains(&std::format!("cpu {slot} ")), "{text}");
            assert!(text.contains(&std::format!("slot {slot} ")), "{text}");
        }
    }

    /// #3093: the report names the chain that used the stack up, from the
    /// faulting LR through every frame record, and stops at the slot's top,
    /// at a record outside the slot, or at a caller below its callee.
    #[test]
    fn backtrace_walks_the_overflowed_slots_frame_records_only() {
        let slot = SlotId::from_index(2).unwrap();
        let usable = crate::stack_slot_usable_base(2);
        let top = crate::stack_slot_top(2);
        let mut words = std::collections::BTreeMap::new();
        let mut record = |frame: u64, caller: u64, ret: u64| {
            words.insert(frame, caller);
            words.insert(frame + 8, ret);
        };
        record(usable + 0x40, usable + 0x400, 0x2d_0400_1000);
        record(usable + 0x400, top - 0x20, 0x2d_0400_2000);
        // The outermost record names a caller outside the slot: kept, then stop.
        record(top - 0x20, top + 0x1000, 0x2d_0400_3000);
        let trace = El1StackBacktrace::walk(slot, 0x2d_0400_0f00, usable + 0x40, |va| {
            words.get(&va).copied()
        });
        assert_eq!(
            trace.returns(),
            [
                0x2d_0400_0f00,
                0x2d_0400_1000,
                0x2d_0400_2000,
                0x2d_0400_3000
            ]
        );
        let report = El1StackOverflow::classify(
            DATA_ABORT_TRANSLATION_L3,
            usable - 0x70,
            usable - 0xd0,
            0x2d_0400_0c70,
            Some(CpuId::new(2)),
        )
        .unwrap()
        .with_backtrace(trace);
        let text = std::format!("{report}");
        assert!(
            text.ends_with(
                "; ring return addresses: 0x2d04000f00 0x2d04001000 0x2d04002000 0x2d04003000"
            ),
            "{text}"
        );
        // A frame pointer outside the slot, unaligned, or a caller below its
        // callee yields only what it could trust.
        assert_eq!(
            El1StackBacktrace::walk(slot, 0, usable - 0x10, |va| words.get(&va).copied()).returns(),
            [] as [u64; 0]
        );
        assert_eq!(
            El1StackBacktrace::walk(slot, 0, usable + 0x48, |va| words.get(&va).copied()).returns(),
            [] as [u64; 0]
        );
        let mut down = std::collections::BTreeMap::new();
        down.insert(usable + 0x400, usable + 0x40);
        down.insert(usable + 0x408, 0x2d_0400_4000);
        assert_eq!(
            El1StackBacktrace::walk(slot, 0, usable + 0x400, |va| down.get(&va).copied()).returns(),
            [0x2d_0400_4000]
        );
        // Unreadable stack keeps the classified record, with no callers.
        let bare = report.with_backtrace(El1StackBacktrace::walk(slot, 0, usable + 0x40, |_| None));
        assert!(!std::format!("{bare}").contains("return addresses"));
    }

    #[test]
    fn only_overflows_are_classified() {
        let usable = crate::stack_slot_usable_base(3);
        let top = crate::stack_slot_top(3);
        // An ordinary EL1 fault on the stack itself or elsewhere is not.
        for far in [usable, top - 8, crate::EL1_STACKS_BASE - 8, 0x1000] {
            assert!(
                El1StackOverflow::classify(DATA_ABORT_TRANSLATION_L3, far, top - 0x200, 0, None)
                    .is_none(),
                "{far:#x}"
            );
        }
        // FAR is UNKNOWN for a non-abort exception: a guard-looking FAR
        // does not make it an overflow while the stack still has room.
        let undefined = 0_u64 << 26;
        assert!(El1StackOverflow::classify(undefined, usable - 8, top - 0x200, 0, None).is_none());
        // ...but no room left for the vector's scratch is one.
        let exhausted = El1StackOverflow::classify(undefined, 0, usable + 16, 0, None)
            .expect("exhausted stack");
        assert_eq!(exhausted.kind, El1StackOverflowKind::ExhaustedStack);
        assert_eq!(exhausted.stack.raw(), 3);
        assert!(El1StackOverflow::classify(undefined, 0, usable + 32, 0, None).is_none());
    }
}
