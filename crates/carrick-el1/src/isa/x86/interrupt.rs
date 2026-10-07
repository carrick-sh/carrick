//! CPL0 APIC and interrupt-mask projection.

use super::{ArchError, X86Backend, interrupts};
use carrick_guest_arch::{
    CounterFrequency, CounterTick, CpuId, CpuTarget, Deadline, InterruptAck, InterruptBackend,
    InterruptReason, WakeToken,
};
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

fn bound_apic_id(slot: CpuId) -> Result<interrupts::ApicId, ArchError> {
    let binding = super::context::current_cpu_binding().ok_or(ArchError::Unbound)?;
    if binding.wake_routes_address == 0 {
        return Err(ArchError::Unbound);
    }
    // SAFETY: stopped-host bootstrap mapped and initialized this exact table
    // before any vCPU ran; it remains live until every vCPU retires.
    let routes = unsafe {
        &*(binding.wake_routes_address as *const super::context::native::PublishedApicIds)
    };
    routes
        .destination(slot)
        .map(|route| interrupts::ApicId(route.0))
        .ok_or(ArchError::Unbound)
}

/// Send a scheduler reschedule using a slot-indexed published APIC route.
pub fn send_resched(slot: carrick_sched_core::SlotId) -> Result<(), ArchError> {
    let apic = bound_apic_id(CpuId::new(u32::from(slot.raw())))?;
    core::sync::atomic::fence(Ordering::SeqCst);
    // SAFETY: scheduler published the target work before sending this IPI;
    // the stopped bootstrap retains the destination APIC until retirement.
    unsafe { interrupts::hardware::send_resched(apic) }.map_err(|_| ArchError::Busy)
}

/// Query the TSC frequency from architectural CPUID or the exact KVM binding.
pub fn tsc_frequency() -> Option<NonZeroU64> {
    if let Some(hz) = super::context::current_cpu_binding()
        .and_then(|binding| NonZeroU64::new(binding.tsc_hz.load(Ordering::Acquire)))
    {
        return Some(hz);
    }
    let max_leaf: u32;
    // SAFETY: CPUID leaf 0 returns max basic leaf without side effects.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 0u32 => max_leaf,
            out("ecx") _,
            out("edx") _,
            options(nomem, preserves_flags),
        );
    }
    if max_leaf >= 0x15 {
        let eax: u32;
        let ebx: u32;
        let ecx: u32;
        // SAFETY: CPUID leaf 0x15 returns TSC frequency ratio and crystal clock.
        unsafe {
            core::arch::asm!(
                "push rbx",
                "cpuid",
                "mov {0:e}, ebx",
                "pop rbx",
                out(reg) ebx,
                inout("eax") 0x15u32 => eax,
                out("ecx") ecx,
                out("edx") _,
                options(nomem, preserves_flags),
            );
        }
        if eax != 0
            && ebx != 0
            && ecx != 0
            && let Some(prod) = (ecx as u64).checked_mul(ebx as u64)
            && let Some(hz) = NonZeroU64::new(prod / (eax as u64))
        {
            return Some(hz);
        }
    }
    if max_leaf >= 0x16 {
        let eax: u32;
        // SAFETY: CPUID leaf 0x16 returns processor base frequency in MHz.
        unsafe {
            core::arch::asm!(
                "push rbx",
                "cpuid",
                "pop rbx",
                inout("eax") 0x16u32 => eax,
                out("ecx") _,
                out("edx") _,
                options(nomem, preserves_flags),
            );
        }
        if eax != 0
            && let Some(hz) = (eax as u64)
                .checked_mul(1_000_000)
                .and_then(NonZeroU64::new)
        {
            return Some(hz);
        }
    }
    None
}

fn has_tsc_deadline() -> bool {
    let features: u32;
    // SAFETY: CPUID leaf 1 reports this vCPU's TSC-deadline MSR capability.
    unsafe {
        core::arch::asm!(
            "push rbx", "cpuid", "pop rbx",
            inout("eax") 1_u32 => _,
            out("ecx") features,
            out("edx") _,
            options(nomem, preserves_flags),
        );
    }
    features & (1 << 24) != 0
}

impl InterruptBackend for X86Backend {
    fn counter(&mut self) -> Result<CounterTick, Self::Error> {
        let (lo, hi): (u32, u32);
        // SAFETY: RDTSC reads the native monotonic counter without touching
        // guest memory or interrupt state.
        unsafe {
            core::arch::asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
                options(nomem, nostack, preserves_flags)
            );
        }
        Ok(CounterTick::new((u64::from(hi) << 32) | u64::from(lo)))
    }
    fn frequency(&mut self) -> Result<CounterFrequency, Self::Error> {
        tsc_frequency()
            .map(CounterFrequency::new)
            .ok_or(ArchError::Unbound)
    }
    fn arm_timer(&mut self, deadline: Option<Deadline>) -> Result<(), Self::Error> {
        let binding = super::context::current_cpu_binding().ok_or(ArchError::Unbound)?;
        // SAFETY: this exact CPL0 CPU has its xAPIC mapped by bootstrap.
        unsafe { interrupts::hardware::enable() };
        if has_tsc_deadline() {
            // SAFETY: CPUID qualified IA32_TSC_DEADLINE; the argument uses
            // the same absolute TSC domain as `counter()`.
            unsafe { interrupts::hardware::arm_tsc_deadline(deadline.map(|d| d.0.raw())) };
        } else {
            let tsc_hz = self.frequency()?.raw().get();
            let mut apic_hz = binding.apic_timer_hz.load(Ordering::Acquire);
            if deadline.is_some() && apic_hz == 0 {
                // SAFETY: this CPU owns its mapped xAPIC timer while stopped
                // in CPL0. The measured rate is retained for later arms.
                apic_hz = unsafe { interrupts::hardware::measure_timer_rate(tsc_hz) }
                    .ok_or(ArchError::Unbound)?;
                binding.apic_timer_hz.store(apic_hz, Ordering::Release);
            }
            let ticks = deadline
                .map(|d| {
                    let delta = d.0.raw().saturating_sub(self.counter()?.raw()).max(1);
                    interrupts::calibrated_timer_ticks(delta, apic_hz, tsc_hz)
                        .ok_or(ArchError::Unbound)
                })
                .transpose()?;
            // SAFETY: the APIC rate was measured on this CPU; the one-shot
            // count and divider are in the same calibrated tick domain.
            unsafe { interrupts::hardware::arm_timer(ticks) };
        }
        Ok(())
    }
    fn send_wake(&mut self, target: CpuTarget, _token: WakeToken) -> Result<(), Self::Error> {
        let apic_id = bound_apic_id(target.cpu)?;
        core::sync::atomic::fence(Ordering::SeqCst);
        // SAFETY: caller published wake ownership first; target CPU is bound.
        unsafe { interrupts::hardware::send_wake(apic_id) }.map_err(|_| ArchError::Busy)?;
        Ok(())
    }
    fn ack_interrupt(
        &mut self,
    ) -> Result<Option<InterruptAck<Self::HardwareInterrupt>>, Self::Error> {
        // SAFETY: CPL0 reads the local APIC in-service register to determine the active vector.
        let vector = unsafe { interrupts::hardware::highest_in_service_vector() };
        let Some(vector) = vector else {
            return Ok(None);
        };
        if vector == interrupts::SPURIOUS_VECTOR {
            return Ok(None);
        }
        let reason = if vector == interrupts::TIMER_VECTOR {
            InterruptReason::Timer
        } else {
            InterruptReason::External
        };
        Ok(Some(InterruptAck {
            reason,
            hardware: u32::from(vector),
        }))
    }
    fn end_interrupt(
        &mut self,
        _ack: InterruptAck<Self::HardwareInterrupt>,
    ) -> Result<(), Self::Error> {
        // SAFETY: the acknowledged interrupt belongs to this CPL0 CPU.
        unsafe { interrupts::hardware::end_interrupt() };
        Ok(())
    }
    fn mask_interrupts(&mut self) -> Self::InterruptMask {
        // SAFETY: CPL0 owns IF and restores this saved mask on the same lane.
        unsafe { interrupts::hardware::mask_interrupts() }
    }
    fn restore_interrupts(&mut self, mask: Self::InterruptMask) -> Result<(), Self::Error> {
        // SAFETY: the caller has dropped all locks before restoring IF.
        unsafe { interrupts::hardware::restore_interrupts(mask) };
        Ok(())
    }
    fn park_until_interrupt(&mut self) -> Result<(), Self::Error> {
        // SAFETY: the owner has checked its queue with IF masked; STI+HLT
        // closes the lost-wake window and returns with IF masked.
        unsafe { interrupts::hardware::park_until_interrupt() };
        Ok(())
    }
    fn current_cpu(&mut self) -> CpuId {
        let Some(binding) = super::context::current_cpu_binding() else {
            super::transport::fatal_entry_binding();
        };
        CpuId::new(binding.cpu_slot)
    }
}

/// A CPL0-only fixture syscall that exercises this shared kernel interrupt module.
pub const INTERRUPT_WITNESS: u64 = 0xffff_ffff_ffff_ff40;

pub fn witness(op: u64, arg: u64) -> u64 {
    let mut backend = X86Backend;
    match op {
        0 => match backend.frequency() {
            Ok(freq) => freq.raw().get(),
            Err(_) => 0,
        },
        1 => {
            let deadline = if arg != 0 {
                Some(Deadline(CounterTick::new(arg)))
            } else {
                None
            };
            match backend.arm_timer(deadline) {
                Ok(()) => 0,
                Err(_) => u64::MAX,
            }
        }
        2 => {
            let target = CpuTarget {
                cpu: CpuId::new(arg as u32),
                generation: carrick_guest_arch::CpuGeneration::new(core::num::NonZeroU64::MIN),
            };
            let token = WakeToken {
                task: carrick_guest_arch::TaskIdentity {
                    carrier: carrick_guest_arch::CarrierGeneration::new(core::num::NonZeroU64::MIN),
                    task: carrick_guest_arch::TaskSerial::new(core::num::NonZeroU64::MIN),
                    execution: carrick_guest_arch::ExecutionGeneration::new(
                        core::num::NonZeroU64::MIN,
                    ),
                },
                operation: carrick_guest_arch::OperationSequence::new(core::num::NonZeroU64::MIN),
            };
            match backend.send_wake(target, token) {
                Ok(()) => 0,
                Err(_) => u64::MAX,
            }
        }
        3 => match backend.ack_interrupt() {
            Ok(Some(ack)) => u64::from(ack.hardware),
            Ok(None) => 0,
            Err(_) => u64::MAX,
        },
        4 => {
            // Exercise the scheduler's current reschedule path, including
            // its stored route and interrupt identity, on two real vCPUs.
            use crate::substrate::sched::ThreadCpu;
            let Ok(slot) = u8::try_from(arg) else {
                return u64::MAX;
            };
            let route = arg + 1;
            crate::substrate::sched::hw::HardwareCpu
                .send_resched(carrick_sched_core::SlotId::new(slot), route);
            0
        }
        5 => {
            use crate::substrate::sched::ThreadCpu;
            u64::from(crate::substrate::sched::hw::HardwareCpu.ack_irq())
        }
        _ => u64::MAX,
    }
}
