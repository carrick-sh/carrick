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

const LINK_SCRIPT: &str = include_str!("../../carrick-x86-cpl0/link.ld");

/// Compile-time check asserting that `link.ld` maps the `.irq_header` section
/// directly at the supervisor image virtual base (`X86_CPL0_IRQ_HEADER_VA`),
/// so the physical address `IRQ_HEADER_GPA` is exactly `X86_CPL0_SUPERVISOR_IMAGE_GPA + 0`.
const fn verify_link_script_irq_header(script: &str) -> bool {
    let bytes = script.as_bytes();
    let needle = b".irq_header";
    let mut irq_pos = None;
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        let mut matched = true;
        let mut j = 0;
        while j < needle.len() {
            if bytes[i + j] != needle[j] {
                matched = false;
                break;
            }
            j += 1;
        }
        if matched {
            irq_pos = Some(i);
            break;
        }
        i += 1;
    }
    let Some(irq_idx) = irq_pos else {
        return false;
    };

    let dot_needle = b". = 0x";
    let mut dot_pos = None;
    let mut k = irq_idx;
    while k >= dot_needle.len() {
        k -= 1;
        let mut matched = true;
        let mut j = 0;
        while j < dot_needle.len() {
            if bytes[k + j] != dot_needle[j] {
                matched = false;
                break;
            }
            j += 1;
        }
        if matched {
            dot_pos = Some(k + dot_needle.len());
            break;
        }
    }
    let Some(mut hex_idx) = dot_pos else {
        return false;
    };

    let mut base_val = 0_u64;
    while hex_idx < bytes.len() && bytes[hex_idx] != b';' {
        let b = bytes[hex_idx];
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as u64,
            b'a'..=b'f' => (b - b'a' + 10) as u64,
            b'A'..=b'F' => (b - b'A' + 10) as u64,
            _ => return false,
        };
        base_val = (base_val << 4) | digit;
        hex_idx += 1;
    }

    base_val == carrick_el1_abi::X86_CPL0_IRQ_HEADER_VA
}

const _: () = {
    assert!(verify_link_script_irq_header(LINK_SCRIPT));
    assert!(IRQ_HEADER_OFFSET == 0);
    assert!(IRQ_HEADER_GPA == 0x10_0000);
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
        assert_eq!(IRQ_HEADER_GPA, 0x10_0000);
        assert_eq!(IRQ_HEADER_OFFSET, 0);
    }

    #[test]
    fn link_script_places_irq_header_at_supervisor_image_base() {
        assert!(verify_link_script_irq_header(LINK_SCRIPT));
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
