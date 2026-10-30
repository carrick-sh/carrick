//! Explicit post-mortem register sampling on the owning vCPU thread.
//!
//! A cancellation may stop EL0 or EL1. Sample before the trap loop resumes
//! either one. ELR/ESR/FAR/SPSR describe the last EL1 exception and can be
//! stale when PC/CPSR name EL0; x8 is a register value, not a syscall census.
use std::time::Instant;

use carrick_hal::diagnostic_capture::CaptureSlot;
use parking_lot::Mutex;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuestRegisters {
    pub pc: Option<u64>,
    pub cpsr: Option<u64>,
    pub elr: Option<u64>,
    pub esr: Option<u64>,
    pub far: Option<u64>,
    pub spsr: Option<u64>,
    pub x8: Option<u64>,
    pub record: Option<carrick_sched_core::RecordRef>,
}

/// Carrier-owned diagnostic register capture slots for one HVPatch VM.
pub struct GuestCapture {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    slots: [CaptureSlot<GuestRegisters>; carrick_el1_abi::EL1_STACK_SLOTS as usize],
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    capture: Mutex<()>,
}

impl core::fmt::Debug for GuestCapture {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("GuestCapture")
            .finish_non_exhaustive()
    }
}

impl Default for GuestCapture {
    fn default() -> Self {
        Self::new()
    }
}

/// Existing physical-capture sections, with missing observations separated
/// from successfully sampled vCPUs.
#[derive(Default)]
pub struct RunningGuestCapture {
    pub vcpus: Vec<String>,
    pub unavailable: Vec<String>,
}

impl GuestCapture {
    pub const fn new() -> Self {
        Self {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            slots: [const { CaptureSlot::new() }; carrick_el1_abi::EL1_STACK_SLOTS as usize],
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            capture: Mutex::new(()),
        }
    }

    /// No register reads, allocation or logging unless this slot has a request.
    /// Called only by the vCPU owner, immediately after physical run returns.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn observe(&self, slot: usize, read: impl FnOnce() -> GuestRegisters) {
        if let Some(slot) = self.slots.get(slot) {
            slot.observe(read);
        }
    }

    /// Non-coherent diagnostic only: one kick per running slot and one shared
    /// deadline. Sampling forces a physical exit and perturbs execution timing;
    /// it does not mark guest work.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn capture_running(&self) -> RunningGuestCapture {
        use std::time::Duration;
        let mut result = RunningGuestCapture::default();
        let Some(_capture) = self.capture.try_lock() else {
            result
                .unavailable
                .push("guest register capture busy".to_owned());
            return result;
        };
        let Some(zone) = carrick_el1_abi::zone_tables() else {
            result
                .unavailable
                .push("guest register capture unavailable: no zone".to_owned());
            return result;
        };
        let deadline = Instant::now() + Duration::from_millis(250);
        let mut requested = Vec::new();
        for (index, capture) in self.slots.iter().enumerate() {
            let slot = carrick_sched_core::SlotId::new(index as u8);
            if zone.slot(slot).state() != carrick_sched_core::SlotState::Running {
                continue;
            }
            let Some(generation) = capture.request() else {
                result
                    .unavailable
                    .push(format!("slot={index} capture generation exhausted"));
                continue;
            };
            let record = zone
                .slot(slot)
                .current()
                .map(|record| zone.record_ref(record));
            requested.push((index, generation, record));
            crate::vcpu_kick::kick_zone_slot(index);
        }
        for (index, generation, requested_record) in requested {
            match generation.wait(deadline) {
                Some(registers) => {
                    if [
                        registers.pc,
                        registers.cpsr,
                        registers.elr,
                        registers.esr,
                        registers.far,
                        registers.spsr,
                        registers.x8,
                    ]
                    .into_iter()
                    .any(|register| register.is_none())
                    {
                        result.unavailable.push(format!(
                            "slot={index} one or more HVF register reads failed; missing fields are None"
                        ));
                    }
                    result.vcpus.push(format!(
                        "slot={index} request={generation} requested_record={requested_record:?} registers={registers:#x?}; exception registers may be stale at EL0; x8 is not a last-syscall counter"
                    ));
                }
                None => result.unavailable.push(format!(
                    "slot={index} request={generation} requested_record={requested_record:?} registers unavailable: owner did not return before capture deadline"
                )),
            }
        }
        result
    }
}
