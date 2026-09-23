//! Carrick in-guest EL1 kernel foundation.
//!
//! Provides the entry point, dispatch logic, and foundations for in-guest
//! execution at EL1.

#![cfg_attr(target_os = "none", no_std)]

pub mod alloc;
pub mod lock;

use carrick_el1_abi::{Action, Counters, TrapFrame};

/// Dispatch an in-guest Linux syscall at EL1.
///
/// For Task 1 (foundation), all syscalls increment the forwarded counter
/// for their syscall number (if < 512) and return [`Action::Forward`].
pub fn dispatch_syscall(frame: &mut TrapFrame, counters: &mut Counters) -> Action {
    let nr = frame.x[8] as usize;
    if nr < 512 {
        counters.forwarded[nr] = counters.forwarded[nr].saturating_add(1);
    }
    Action::Forward
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dispatch_forwards_all_and_counts() {
        let mut frame = TrapFrame::default();
        let mut counters = Counters::default();

        frame.x[8] = 64; // write
        let action = dispatch_syscall(&mut frame, &mut counters);
        assert_eq!(action, Action::Forward);
        assert_eq!(counters.forwarded[64], 1);
        assert_eq!(counters.served[64], 0);

        frame.x[8] = 172; // getpid
        let action = dispatch_syscall(&mut frame, &mut counters);
        assert_eq!(action, Action::Forward);
        assert_eq!(counters.forwarded[172], 1);
        assert_eq!(counters.forwarded[64], 1);

        // Out-of-bounds syscall nr
        frame.x[8] = 999;
        let action = dispatch_syscall(&mut frame, &mut counters);
        assert_eq!(action, Action::Forward);
    }
}
