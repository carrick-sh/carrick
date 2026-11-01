#![cfg_attr(target_os = "none", no_std)]

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
extern crate alloc as rust_alloc;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod anonymous;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod linux_personality;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod native_execution;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod native_process;

use carrick_el1_abi::Action;

/// The production CPL0 transport owed by a completed shared dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionBoundary {
    HostCustody,
    Continue,
    Work,
    Forward,
    Invalid,
}

pub const fn production_boundary(action: Action) -> ProductionBoundary {
    match action {
        Action::Served => ProductionBoundary::Continue,
        Action::ServedWithWork => ProductionBoundary::Work,
        Action::Forward => ProductionBoundary::Forward,
        Action::Idle => ProductionBoundary::Invalid,
        Action::HostCustody => ProductionBoundary::HostCustody,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_work_requires_the_work_exit_before_return() {
        assert_eq!(
            production_boundary(Action::ServedWithWork),
            ProductionBoundary::Work
        );
    }

    #[test]
    fn host_thread_retirement_keeps_distinct_cpl0_transport() {
        assert_eq!(
            production_boundary(Action::HostCustody),
            ProductionBoundary::HostCustody
        );
    }
}

// Non-delegated x86 memory hooks have no host CommitOwed consumer. Refuse
// before acquiring an editor; delegated mappings keep their existing route.
#[unsafe(no_mangle)]
pub static CARRICK_CPL0_ANONYMOUS_HOOK_REFUSALS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

#[cfg(any(target_os = "none", test))]
pub(crate) fn refuse_anonymous_permission(
    counter: &core::sync::atomic::AtomicU64,
) -> carrick_personality_linux::pending_anonymous::PermissionStep {
    counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    carrick_personality_linux::pending_anonymous::PermissionStep::Forward
}

#[cfg(any(target_os = "none", test))]
pub(crate) fn refuse_anonymous_retirement(
    counter: &core::sync::atomic::AtomicU64,
) -> carrick_personality_linux::pending_anonymous::RetirementStep {
    counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    carrick_personality_linux::pending_anonymous::RetirementStep::Forward
}

/// Invalid CPU slots retain the previous forwarding path, never a fatal.
#[cfg(any(target_os = "none", test))]
pub(crate) fn anonymous_call(
    call: carrick_personality_linux::entry::CanonicalCall,
    cpu_slot: u32,
    return_pc: carrick_guest_arch::UserVa,
) -> Option<carrick_el1::memory::AnonymousCall> {
    let slot = usize::try_from(cpu_slot)
        .ok()
        .and_then(carrick_sched_core::SlotId::from_index)?;
    // This venue projects one task, independently of its CPU slot.
    Some(carrick_el1::memory::AnonymousCall::new(
        call, 0, slot, return_pc,
    ))
}

#[cfg(test)]
mod anonymous_refusal_tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};
    #[test]
    fn dead_hooks_count_refusals_without_commit_obligations() {
        let count = AtomicU64::new(0);
        assert!(matches!(
            refuse_anonymous_permission(&count),
            carrick_personality_linux::pending_anonymous::PermissionStep::Forward
        ));
        assert!(matches!(
            refuse_anonymous_retirement(&count),
            carrick_personality_linux::pending_anonymous::RetirementStep::Forward
        ));
        assert_eq!(count.load(Ordering::Relaxed), 2);
    }
    #[test]
    fn invalid_anonymous_slot_declines_without_fatal() {
        let call = carrick_personality_linux::entry::decode_x86_64(10, [0; 6], 0x8000);
        let pc = carrick_guest_arch::UserVa::new(0x40004);
        assert!(anonymous_call(call, u32::MAX, pc).is_none());
        assert_eq!(anonymous_call(call, 7, pc).unwrap().slot().index(), 7);
    }
}
