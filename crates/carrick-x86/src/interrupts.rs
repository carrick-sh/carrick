//! Native interrupt constants and gate encoding for the host CPL0 loader.
pub const TIMER_VECTOR: u8 = 0xe0;
pub const KICK_VECTOR: u8 = 0xe1;
pub const SPURIOUS_VECTOR: u8 = 0xff;
pub const LAPIC_BASE: u64 = 0xfee0_0000;
pub const LAPIC_VA: u64 = 0xffff_ffff_d000_0000;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerTicks(pub u32);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApicId(pub u8);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpiBusy;

#[derive(Clone, Copy, Debug)]
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
