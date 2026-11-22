//! This CPU's CR4, read from hardware at most once per CPU binding.
//!
//! Under AMD SVM, KVM intercepts every guest `mov reg, cr4`. Without decode
//! assists (the nested CI lanes) each read is also a software-decoded
//! instruction, and a ring syscall that read CR4 around each user access cost
//! about 100 us, ~250x native (#2679). The stopped host programs CR4 (the
//! production SMEP/SMAP, the fixture's `enable_smap`) before the vCPU's first
//! instruction, and the guest kernel never writes CR4, so one read per CPU is
//! exact for the binding's lifetime.

use core::sync::atomic::Ordering;

const CR4_SMAP: u64 = 1 << 21;

/// A CR4 value this CPU had when its kernel first asked.
#[derive(Clone, Copy)]
pub struct Cr4(u64);

impl Cr4 {
    /// This CPU's CR4: the binding's snapshot, or one hardware read that
    /// fills it. A CPU without a published binding reads the hardware.
    pub fn current() -> Self {
        let Some(binding) = super::context::current_cpu_binding() else {
            return Self(super::mmu::read_cr4());
        };
        let cached = binding.cr4_snapshot.load(Ordering::Relaxed);
        if cached != 0 {
            return Self(cached);
        }
        let live = super::mmu::read_cr4();
        // Only this CPU writes its binding's snapshot, and an interrupt that
        // fills it first stores the same hardware value.
        binding.cr4_snapshot.store(live, Ordering::Relaxed);
        Self(live)
    }

    /// The raw register value.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Whether supervisor-mode access prevention is on, so a user access
    /// must bracket itself with STAC/CLAC. As a register word for the asm
    /// operand: nonzero means on.
    pub const fn smap_word(self) -> u64 {
        self.0 & CR4_SMAP
    }
}
