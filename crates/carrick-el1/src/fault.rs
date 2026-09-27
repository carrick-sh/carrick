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
            esr: 0x24 << 26,
            far: 0x1000_2000,
            x: [42; 31],
            ..TrapFrame::default()
        };
        let counters = Counters::default();
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 0);

        let action = dispatch_fault(&mut frame, &counters);
        assert_eq!(action, Action::Forward);
        assert_eq!(counters.fault_taken.load(Ordering::Relaxed), 1);
        // Ensure syscall counters were not touched by the fault
        assert_eq!(counters.forwarded[42].load(Ordering::Relaxed), 0);
        assert_eq!(counters.served[42].load(Ordering::Relaxed), 0);
    }
}
