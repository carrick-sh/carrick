//! In-guest EL1 fault handling and dispatch.

use carrick_el1_abi::{Action, Counters, TrapFrame};
use core::sync::atomic::Ordering;

/// Dispatch an EL0 data abort at EL1.
///
/// Increments `counters.fault_taken` and returns [`Action::Forward`] to forward
/// the fault to host decoding until in-guest memory service is enabled.
pub fn dispatch_fault(_frame: &mut TrapFrame, counters: &Counters) -> Action {
    counters.fault_taken.fetch_add(1, Ordering::Relaxed);
    Action::Forward
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dispatch_fault_increments_counter_and_forwards() {
        let mut frame = TrapFrame {
            esr: (0xFFFF_0000_u64 << 32) | (0x24 << 26) | (1 << 25) | 0x47,
            far: 0x1000_2000,
            x: {
                let mut x = [42; 31];
                x[8] = 172; // valid syscall nr (SYS_getpid) as canary
                x
            },
            ..TrapFrame::default()
        };
        let counters = Counters::default();
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 0);

        let action = dispatch_fault(&mut frame, &counters);
        assert_eq!(action, Action::Forward);
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
        // Ensure arbitrary x8 was not dispatched as a syscall and syscall counters were not touched
        assert_eq!(counters.forwarded[172].load(Ordering::Relaxed), 0);
        assert_eq!(counters.served[172].load(Ordering::Relaxed), 0);
        assert_eq!(counters.forwarded[42].load(Ordering::Relaxed), 0);
        assert_eq!(counters.served[42].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_ec_classification_bits_31_to_26() {
        // Lower-EL Data Abort EC = 0x24
        let data_abort_clean = 0x24_u64 << 26;
        let data_abort_with_high_bits = (0xDEAD_BEEF_u64 << 32) | (0x24 << 26) | (1 << 25) | 0x3F;
        assert_eq!((data_abort_clean >> 26) & 0x3F, 0x24);
        assert_eq!((data_abort_with_high_bits >> 26) & 0x3F, 0x24);

        // Instruction Abort EC = 0x20
        let inst_abort_with_high_bits = (0xDEAD_BEEF_u64 << 32) | (0x20 << 26) | 0x15;
        assert_ne!((inst_abort_with_high_bits >> 26) & 0x3F, 0x24);
        assert_eq!((inst_abort_with_high_bits >> 26) & 0x3F, 0x20);

        // SVC64 EC = 0x15
        let svc_with_high_bits = (0xCAFE_BABE_u64 << 32) | (0x15 << 26);
        assert_ne!((svc_with_high_bits >> 26) & 0x3F, 0x24);
        assert_eq!((svc_with_high_bits >> 26) & 0x3F, 0x15);
    }
}
