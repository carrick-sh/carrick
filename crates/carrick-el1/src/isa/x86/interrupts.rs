//! Native CPL0 interrupt hardware owned by the shared guest kernel.

pub const TIMER_VECTOR: u8 = 0xe0;
pub const KICK_VECTOR: u8 = 0xe1;
pub const RESCHED_VECTOR: u8 = 0xe2;
pub const SPURIOUS_VECTOR: u8 = 0xff;
pub const LAPIC_BASE: u64 = 0xfee0_0000;
pub const LAPIC_VA: u64 = 0xffff_ffff_d000_0000;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerTicks(pub u32);

/// One calibrated APIC segment. A long TSC deadline is split at the hardware
/// counter limit; the scheduler retains the original deadline and re-arms
/// after this segment's interrupt if that deadline is still in the future.
pub fn calibrated_timer_ticks(delta_tsc: u64, apic_hz: u64, tsc_hz: u64) -> Option<TimerTicks> {
    if apic_hz == 0 || tsc_hz == 0 {
        return None;
    }
    let ticks = (u128::from(delta_tsc) * u128::from(apic_hz) / u128::from(tsc_hz))
        .clamp(1, u128::from(u32::MAX));
    u32::try_from(ticks).ok().map(TimerTicks)
}

#[cfg(test)]
mod fallback_tests {
    use super::*;

    #[test]
    fn calibrated_long_deadline_clamps_then_scheduler_can_rearm() {
        let tsc_hz = 1_000_000_000;
        let apic_hz = 1_000_000_000;
        assert_eq!(
            calibrated_timer_ticks(10 * tsc_hz, apic_hz, tsc_hz),
            Some(TimerTicks(u32::MAX))
        );
        assert_eq!(
            calibrated_timer_ticks(tsc_hz / 10, apic_hz, tsc_hz),
            Some(TimerTicks(100_000_000))
        );
        assert_eq!(
            calibrated_timer_ticks(0, apic_hz, tsc_hz),
            Some(TimerTicks(1))
        );
        assert_eq!(calibrated_timer_ticks(1, 0, tsc_hz), None);
    }
}

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

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod hardware {
    use super::*;
    /// # Safety
    /// CPL0, mapped xAPIC page, bootstrap has enabled IA32_APIC_BASE in xAPIC
    /// mode. The caller serializes access with interrupts masked.
    unsafe fn write(offset: u64, value: u32) {
        unsafe { core::ptr::write_volatile((LAPIC_VA + offset) as *mut u32, value) };
    }
    /// # Safety
    /// CPL0 only; the caller restores this mask on the same execution lane.
    pub unsafe fn mask_interrupts() -> InterruptMask {
        let flags: u64;
        unsafe { core::arch::asm!("pushfq", "pop {}", "cli", out(reg) flags) };
        InterruptMask {
            enabled: flags & (1 << 9) != 0,
        }
    }
    /// # Safety
    /// CPL0 only; no scheduler/queue lock may cross re-enabling interrupts.
    pub unsafe fn restore_interrupts(mask: InterruptMask) {
        if mask.enabled {
            unsafe { core::arch::asm!("sti", options(nostack)) };
        } else {
            unsafe { core::arch::asm!("cli", options(nostack)) };
        }
    }
    /// # Safety
    /// CPL0, IF masked, no locks held. STI's interrupt shadow makes HLT
    /// atomic with interrupt admission: an already pending kick cannot be
    /// lost between queue inspection and parking. Returns with IF masked.
    pub unsafe fn park_until_interrupt() {
        unsafe { core::arch::asm!("sti", "hlt", "cli", options(nostack)) };
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
    /// A live CPL0 xAPIC with TIMER_VECTOR installed. One shot, divide by 1;
    /// None masks/disarms without a host wait, timer thread or semantic exit.
    pub unsafe fn arm_timer(ticks: Option<TimerTicks>) {
        unsafe {
            write(0x3e0, 0b1011);
            write(
                0x320,
                u32::from(TIMER_VECTOR) | if ticks.is_none() { 1 << 16 } else { 0 },
            );
            write(0x380, ticks.map_or(0, |ticks| ticks.0));
        }
    }
    /// # Safety
    /// CPL0 with an enabled xAPIC and a qualified TSC-deadline capability.
    /// The deadline is an absolute TSC value; zero disarms the local timer.
    pub unsafe fn arm_tsc_deadline(deadline: Option<u64>) {
        unsafe {
            write(
                0x320,
                u32::from(TIMER_VECTOR) | (1 << 18) | if deadline.is_none() { 1 << 16 } else { 0 },
            );
            let value = deadline.unwrap_or(0);
            core::arch::asm!("wrmsr", in("ecx") 0x6e0_u32,
                in("eax") value as u32, in("edx") (value >> 32) as u32,
                options(nostack, preserves_flags));
        }
    }
    /// # Safety
    /// CPL0 with the mapped local APIC. The caller has a qualified TSC rate;
    /// this bounded sample measures actual countdown ticks against that TSC.
    pub unsafe fn measure_timer_rate(tsc_hz: u64) -> Option<u64> {
        let sample_tsc = (tsc_hz / 1000).max(1);
        unsafe {
            write(0x3e0, 0b1011); // divide by 1
            write(0x320, u32::from(TIMER_VECTOR) | (1 << 16));
            write(0x380, u32::MAX);
        }
        let start = rdtsc();
        while rdtsc().wrapping_sub(start) < sample_tsc {
            core::hint::spin_loop();
        }
        let elapsed = rdtsc().wrapping_sub(start);
        let remaining = unsafe { core::ptr::read_volatile((LAPIC_VA + 0x390) as *const u32) };
        unsafe { write(0x380, 0) };
        let elapsed_apic = u64::from(u32::MAX - remaining);
        if elapsed == 0 || elapsed_apic == 0 {
            return None;
        }
        let hz = u128::from(elapsed_apic) * u128::from(tsc_hz) / u128::from(elapsed);
        u64::try_from(hz).ok().filter(|hz| *hz != 0)
    }
    fn rdtsc() -> u64 {
        let (lo, hi): (u32, u32);
        // SAFETY: RDTSC only reads the current TSC while CPL0 owns this CPU.
        unsafe {
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi,
            options(nomem, nostack, preserves_flags))
        };
        (u64::from(hi) << 32) | u64::from(lo)
    }
    /// # Safety
    /// Complete exactly the interrupt accepted by this CPU's handler.
    pub unsafe fn end_interrupt() {
        unsafe { write(0xb0, 0) };
    }
    /// # Safety
    /// Caller has published wake ownership first. APIC destination names a
    /// retained CPU, never a task/host PID. No interrupt-send busy polling.
    unsafe fn send_ipi(apic_id: ApicId, vector: u8) -> Result<(), IpiBusy> {
        // A busy command is not a delivered wake. Return owned work to the
        // caller instead of spinning with IF masked or dropping the command.
        if unsafe { core::ptr::read_volatile((LAPIC_VA + 0x300) as *const u32) } & (1 << 12) != 0 {
            return Err(IpiBusy);
        }
        unsafe {
            write(0x310, u32::from(apic_id.0) << 24);
            write(0x300, u32::from(vector));
        }
        Ok(())
    }
    /// # Safety
    /// Caller owns a published wake and names a retained APIC destination.
    pub unsafe fn send_wake(apic_id: ApicId) -> Result<(), IpiBusy> {
        unsafe { send_ipi(apic_id, KICK_VECTOR) }
    }
    /// # Safety
    /// Caller owns a published scheduler wake for a retained CPU slot.
    pub unsafe fn send_resched(apic_id: ApicId) -> Result<(), IpiBusy> {
        unsafe { send_ipi(apic_id, RESCHED_VECTOR) }
    }
    /// # Safety
    /// CPL0 reads the mapped local APIC In-Service Register (ISR).
    pub unsafe fn highest_in_service_vector() -> Option<u8> {
        for reg_idx in (0..8).rev() {
            let isr_val = unsafe {
                core::ptr::read_volatile((LAPIC_VA + 0x100 + reg_idx * 0x10) as *const u32)
            };
            if isr_val != 0 {
                let bit = 31 - isr_val.leading_zeros();
                return Some((reg_idx as u8) * 32 + (bit as u8));
            }
        }
        None
    }
}
