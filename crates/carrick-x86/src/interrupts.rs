//! Native interrupt constants and gate encoding for the host CPL0 loader.
pub const TIMER_VECTOR: u8 = 0xe0;
pub const KICK_VECTOR: u8 = 0xe1;
pub const RESCHED_VECTOR: u8 = 0xe2;
pub const SHOOTDOWN_VECTOR: u8 = 0xe3;
pub const PAGE_FAULT_VECTOR: u8 = 14;
pub const SPURIOUS_VECTOR: u8 = 0xff;
/// Offset of the CPL0 IRQ header record within the supervisor image.
pub const IRQ_HEADER_OFFSET: u64 = carrick_el1_abi::X86_CPL0_IRQ_HEADER_OFFSET;

/// Guest-physical address of the native IRQ header record, derived from the
/// supervisor image layout (base GPA plus IRQ header section offset).
pub const IRQ_HEADER_GPA: u64 = carrick_el1_abi::X86_CPL0_IRQ_HEADER_GPA;

pub const IRQ_HEADER_MAGIC: u64 = 0x3151_5249_4c50_4358;
pub const LAPIC_BASE: u64 = 0xfee0_0000;
pub const LAPIC_VA: u64 = 0xffff_ffff_d000_0000;

const _: () = {
    assert!(IRQ_HEADER_GPA == carrick_el1_abi::X86_CPL0_SUPERVISOR_IMAGE_GPA + IRQ_HEADER_OFFSET);
};

#[repr(transparent)]
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct TimerTicks(pub u32);

#[repr(transparent)]
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct ApicId(pub u8);

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct IpiBusy;

#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
pub struct InterruptMask {
    enabled: bool,
}
impl InterruptMask {
    pub const fn was_enabled(self) -> bool {
        self.enabled
    }
}

/// Supervisor interrupt gate, no error code, no IST. Existing exception IDT
/// and double-fault IST stay installed.
#[cfg(not(target_os = "none"))]
pub fn interrupt_gate(entry: u64) -> [u8; 16] {
    crate::fault::interrupt_gate_bytes(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn irq_header_gpa_derived_from_supervisor_layout() {
        assert_eq!(
            IRQ_HEADER_GPA,
            carrick_el1_abi::X86_CPL0_SUPERVISOR_IMAGE_GPA
                + carrick_el1_abi::X86_CPL0_IRQ_HEADER_OFFSET
        );
        assert_eq!(
            IRQ_HEADER_OFFSET,
            carrick_el1_abi::X86_CPL0_IRQ_HEADER_OFFSET
        );
    }

    #[test]
    fn guest_interrupts_has_no_stale_irq_header_gpa() {
        const GUEST_INTERRUPTS: &str = include_str!("../../carrick-el1/src/isa/x86/interrupts.rs");
        assert!(
            !GUEST_INTERRUPTS.contains("IRQ_HEADER_GPA"),
            "guest carrick-el1/src/isa/x86/interrupts.rs still contains stale IRQ_HEADER_GPA"
        );
    }
}
