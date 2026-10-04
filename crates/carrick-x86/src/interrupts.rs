//! CPL0 interrupt hardware, shared with the thin image. Intel SDM vol. 3:
//! interrupt gates, xAPIC LVT timer/divider/EOI/ICR. One-shot ticks require no
//! TSC-deadline feature on nested AMD KVM. Clock conversion stays with policy.
pub const TIMER_VECTOR: u8 = 0xe0;
pub const KICK_VECTOR: u8 = 0xe1;
pub const SPURIOUS_VECTOR: u8 = 0xff;
pub const LAPIC_BASE: u64 = 0xfee0_0000;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerTicks(pub u32);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApicId(pub u8);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpiBusy;

/// Supervisor interrupt gate, no error code, no IST. Existing exception IDT
/// and double-fault IST stay installed.
pub fn interrupt_gate(entry: u64) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[0..2].copy_from_slice(&(entry as u16).to_le_bytes());
    bytes[2..4].copy_from_slice(&8u16.to_le_bytes());
    bytes[5] = 0x8e;
    bytes[6..8].copy_from_slice(&((entry >> 16) as u16).to_le_bytes());
    bytes[8..12].copy_from_slice(&((entry >> 32) as u32).to_le_bytes());
    bytes
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod hardware {
    use super::*;
    /// # Safety
    /// CPL0, mapped xAPIC page, bootstrap has enabled IA32_APIC_BASE in xAPIC
    /// mode. The caller serializes access with interrupts masked.
    unsafe fn write(offset: u64, value: u32) {
        unsafe { core::ptr::write_volatile((LAPIC_BASE + offset) as *mut u32, value) };
    }
    /// # Safety
    /// Same hardware preconditions as `arm_timer`; vectors must be installed.
    pub unsafe fn enable() {
        unsafe {
            write(0x80, 0);
            write(0xf0, 0x100 | u32::from(SPURIOUS_VECTOR));
        }
    }
    /// # Safety
    /// A live CPL0 xAPIC with TIMER_VECTOR installed. One shot, divide by 16;
    /// None masks/disarms without a host wait, timer thread or semantic exit.
    pub unsafe fn arm_timer(ticks: Option<TimerTicks>) {
        unsafe {
            write(0x3e0, 3);
            write(
                0x320,
                u32::from(TIMER_VECTOR) | if ticks.is_none() { 1 << 16 } else { 0 },
            );
            write(0x380, ticks.map_or(0, |ticks| ticks.0));
        }
    }
    /// # Safety
    /// Complete exactly the interrupt accepted by this CPU's handler.
    pub unsafe fn end_interrupt() {
        unsafe { write(0xb0, 0) };
    }
    /// # Safety
    /// Caller has published wake ownership first. APIC destination names a
    /// retained CPU, never a task/host PID. No interrupt-send busy polling.
    pub unsafe fn send_wake(apic_id: ApicId) -> Result<(), IpiBusy> {
        // A busy command is not a delivered wake. Return owned work to the
        // caller instead of spinning with IF masked or dropping the command.
        if unsafe { core::ptr::read_volatile((LAPIC_BASE + 0x300) as *const u32) } & (1 << 12) != 0
        {
            return Err(IpiBusy);
        }
        unsafe {
            write(0x310, u32::from(apic_id.0) << 24);
            write(0x300, u32::from(KICK_VECTOR));
        }
        Ok(())
    }
}
