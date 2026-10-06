//! CPL0 APIC and interrupt-mask projection.

use super::{X86Backend, interrupts};
use carrick_guest_arch::{
    CounterFrequency, CounterTick, CpuId, CpuTarget, Deadline, InterruptAck, InterruptBackend,
    WakeToken,
};

#[cold]
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn carrick_x86_unbound_interrupt_entry() -> ! {
    // SAFETY: an IRQ cannot be acknowledged without its native vector owner.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
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
        carrick_x86_unbound_interrupt_entry()
    }
    fn arm_timer(&mut self, _deadline: Option<Deadline>) -> Result<(), Self::Error> {
        carrick_x86_unbound_interrupt_entry()
    }
    fn send_wake(&mut self, _target: CpuTarget, _token: WakeToken) -> Result<(), Self::Error> {
        // CpuId is a scheduler slot, not necessarily an APIC destination.
        carrick_x86_unbound_interrupt_entry()
    }
    fn ack_interrupt(
        &mut self,
    ) -> Result<Option<InterruptAck<Self::HardwareInterrupt>>, Self::Error> {
        carrick_x86_unbound_interrupt_entry()
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
        let binding_address: u64;
        // SAFETY: SWAPGS has installed the retained per-vCPU binding before
        // any shared-kernel entry; GS:[16] is its immutable self pointer.
        unsafe {
            core::arch::asm!(
                "mov {}, gs:[16]",
                out(reg) binding_address,
                options(nostack, preserves_flags)
            );
        }
        // SAFETY: stopped-host bootstrap owns this binding through vCPU
        // retirement. Its slot is immutable after publication.
        let binding = unsafe { &*(binding_address as *const super::context::native::CpuBinding) };
        CpuId::new(binding.cpu_slot)
    }
}
