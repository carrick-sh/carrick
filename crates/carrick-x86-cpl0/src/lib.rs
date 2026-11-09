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
mod native_host_file;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod native_process;

use carrick_el1_abi::Action;

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
mod test_support {
    use core::sync::atomic::Ordering;

    pub const INJECT_ROOT_BUSY_ONCE: u64 = 0xffff_ffff_ffff_fe10;
    pub const INJECT_EDITOR_BUSY_ONCE: u64 = 0xffff_ffff_ffff_fe11;
    pub const INJECT_PREPARED_CONFLICT_ONCE: u64 = 0xffff_ffff_ffff_fe12;
    pub const INJECT_WAIT_PARK_CENSUS: u64 = 0xffff_ffff_ffff_fe13;
    pub const INJECT_METADATA_REQUIRED_ONCE: u64 = 0xffff_ffff_ffff_fe14;
    pub const INJECT_WAIT_HANDBACK_CENSUS: u64 = 0xffff_ffff_ffff_fe15;
    pub const INJECT_METADATA_ON_REPROBE_ONCE: u64 = 0xffff_ffff_ffff_fe16;
    pub const INJECT_CAUGHT_SIGNAL_ON_PARK: u64 = 0xffff_ffff_ffff_fe17;
    /// The second native signal-clock read from now reports tick 0: a sleep
    /// woken at its deadline first sees the clock before it, and every later
    /// read is real again.
    pub const INJECT_SIGNAL_CLOCK_LAG_ON_SECOND_READ: u64 = 0xffff_ffff_ffff_fe19;
    /// Once the calling member next parks, publish a caught SIGUSR1 to it
    /// through the production ingress owner.
    pub const INJECT_CAUGHT_SIGNAL_ON_NEXT_PARK: u64 = 0xffff_ffff_ffff_fe1a;
    /// The next owned (exact-MM, retained-output) user copy is Busy once.
    pub const INJECT_OWNED_COPY_BUSY_ONCE: u64 = 0xffff_ffff_ffff_fe1b;
    pub const INJECT_PEER_IDLE_RELEASE_ONCE: u64 = 0xffff_ffff_ffff_fe18;
    // Test-only actor ordering: armed by CPU0's fixture syscall; CPU0
    // publishes Parked before requesting CPU1's scheduler to release it.
    // The production object-wait queue and notification choose the wake target.
    const RELEASE_ARMED: u64 = 1;
    const RELEASE_ON_PEER: u64 = 2;
    static PEER_IDLE_RELEASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

    pub fn peer_release_pending(slot: carrick_sched_core::SlotId) -> bool {
        slot.raw() == 1 && PEER_IDLE_RELEASE.load(Ordering::Acquire) == RELEASE_ON_PEER
    }

    pub fn defer_release_to_peer(slot: carrick_sched_core::SlotId) -> bool {
        match PEER_IDLE_RELEASE.load(Ordering::Acquire) {
            RELEASE_ARMED if slot.raw() == 0 => {
                PEER_IDLE_RELEASE.store(RELEASE_ON_PEER, Ordering::Release);
                carrick_el1::isa::x86::interrupt::send_resched(carrick_sched_core::SlotId::new(1))
                    .unwrap_or_else(|_| carrick_x86_carrier::entry::fatal_boot());
                true
            }
            RELEASE_ARMED => true,
            RELEASE_ON_PEER if slot.raw() == 0 => true,
            RELEASE_ON_PEER => {
                PEER_IDLE_RELEASE.store(0, Ordering::Release);
                false
            }
            _ => false,
        }
    }

    static EDIT_PARK_PUBLISHED: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);

    pub fn publish_edit_park() {
        EDIT_PARK_PUBLISHED.store(true, Ordering::Release);
    }

    pub fn take_edit_park() -> bool {
        EDIT_PARK_PUBLISHED.swap(false, Ordering::AcqRel)
    }

    static ANONYMOUS_WAIT_HANDBACKS: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    static METADATA_ON_REPROBE: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    static CAUGHT_SIGNAL_ON_PARK: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    static SIGNAL_CLOCK_LAG: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
    static OWNED_COPY_BUSY: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    type ArmedSignal = (
        carrick_sched_core::RecordRef,
        carrick_core_abi::ExecutionBinding,
    );
    static SIGNAL_ON_NEXT_PARK: carrick_el1::lock::SpinLock<Option<ArmedSignal>> =
        carrick_el1::lock::SpinLock::new(None);

    pub fn signal_clock_read_lags() -> bool {
        SIGNAL_CLOCK_LAG
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                left.checked_sub(1)
            })
            .is_ok_and(|left| left == 1)
    }

    /// Called on each scheduler entry: deliver an armed signal once its member
    /// has parked, from the executor that parked it (whose current task is
    /// still that member's), as `INJECT_CAUGHT_SIGNAL_ON_PARK` does.
    pub fn signal_parked_member(
        source: carrick_el1_abi::BornInZoneSource<'static, carrick_sched_core::ParkedContextWords>,
        task: &'static carrick_el1_abi::CurrentTask,
    ) {
        let mut slot = SIGNAL_ON_NEXT_PARK.lock();
        let armed = slot.take_if(|(_, binding)| {
            *binding == carrick_el1_linux::common_entry::execution_binding(task)
        });
        drop(slot);
        if let Some((record, binding)) = armed
            && !crate::native_process::inject_caught_signal_once_parked(
                source, task, record, binding,
            )
        {
            *SIGNAL_ON_NEXT_PARK.lock() = Some((record, binding));
        }
    }

    pub fn take_owned_copy_busy() -> bool {
        OWNED_COPY_BUSY.swap(false, Ordering::AcqRel)
    }

    pub fn take_caught_signal_on_park() -> bool {
        CAUGHT_SIGNAL_ON_PARK.swap(false, Ordering::AcqRel)
    }

    pub fn record_anonymous_wait_handback() {
        ANONYMOUS_WAIT_HANDBACKS.fetch_add(1, Ordering::Relaxed);
    }

    pub fn arm_metadata_for_reprobe() {
        if METADATA_ON_REPROBE.swap(false, Ordering::AcqRel)
            && !carrick_core::mm::reservation::inject_metadata_required_once()
        {
            carrick_x86_carrier::entry::fatal_boot();
        }
    }

    pub fn dispatch(
        native: u64,
        binding: &carrick_el1::isa::x86::context::native::CpuBinding,
    ) -> Option<u64> {
        match native {
            INJECT_PEER_IDLE_RELEASE_ONCE => PEER_IDLE_RELEASE
                .compare_exchange(0, RELEASE_ARMED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                .then_some(0),
            INJECT_ROOT_BUSY_ONCE => {
                carrick_core::mm::reservation::inject_root_busy_once().then_some(0)
            }
            INJECT_EDITOR_BUSY_ONCE => {
                carrick_sched_core::spaces::inject_editor_busy_once().then_some(0)
            }
            INJECT_PREPARED_CONFLICT_ONCE => {
                carrick_core::mm::reservation::inject_prepared_conflict_once().then_some(0)
            }
            INJECT_METADATA_REQUIRED_ONCE => {
                carrick_core::mm::reservation::inject_metadata_required_once().then_some(0)
            }
            INJECT_WAIT_PARK_CENSUS => {
                let slot = carrick_el1::isa::x86::context::native::checked_scheduler_slot(
                    carrick_guest_arch::CpuId::new(binding.cpu_slot),
                )?;
                Some(
                    carrick_x86_carrier::native_execution::source(slot)
                        .zone
                        .counters
                        .el1_parks
                        .load(Ordering::Acquire),
                )
            }
            INJECT_WAIT_HANDBACK_CENSUS => Some(ANONYMOUS_WAIT_HANDBACKS.load(Ordering::Acquire)),
            INJECT_METADATA_ON_REPROBE_ONCE => METADATA_ON_REPROBE
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                .then_some(0),
            INJECT_SIGNAL_CLOCK_LAG_ON_SECOND_READ => SIGNAL_CLOCK_LAG
                .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                .then_some(0),
            INJECT_CAUGHT_SIGNAL_ON_NEXT_PARK => {
                let slot = carrick_el1::isa::x86::context::native::checked_scheduler_slot(
                    carrick_guest_arch::CpuId::new(binding.cpu_slot),
                )?;
                let zone = carrick_x86_carrier::native_execution::source(slot).zone;
                let record = zone.record_ref(zone.slot(slot).current()?);
                let execution = carrick_el1_linux::common_entry::execution_binding(
                    carrick_x86_carrier::native_execution::task(),
                );
                let mut armed = SIGNAL_ON_NEXT_PARK.lock();
                armed.is_none().then(|| {
                    *armed = Some((record, execution));
                    0
                })
            }
            INJECT_OWNED_COPY_BUSY_ONCE => {
                (!OWNED_COPY_BUSY.swap(true, Ordering::AcqRel)).then_some(0)
            }
            INJECT_CAUGHT_SIGNAL_ON_PARK => {
                if !CAUGHT_SIGNAL_ON_PARK.swap(true, Ordering::AcqRel)
                    && carrick_sched_core::spaces::inject_editor_busy_once()
                {
                    Some(0)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

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
        carrick_core::CallOrdinal::from_raw(call.canonical.raw()),
        call.args,
        0,
        slot,
        return_pc,
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
    /// Linux decoding stays at the personality edge, before the neutral view.
    #[test]
    fn both_linux_decoders_project_the_same_anonymous_call() {
        use carrick_el1::memory::AnonymousCallView;
        use carrick_personality_linux::entry::{decode_aarch64, decode_x86_64};
        let args = [0x100000, 0x3000, 1, 0, 0, 0];
        for (arm_nr, x86_nr) in [(222, 9), (226, 10), (215, 11)] {
            let arm = decode_aarch64(arm_nr, args, 0x8000);
            let x86 = decode_x86_64(x86_nr, args, 0x8000);
            let pc = carrick_guest_arch::UserVa::new(0x40004);
            let arm = anonymous_call(arm, 7, pc).unwrap();
            let x86 = anonymous_call(x86, 7, pc).unwrap();
            assert_eq!(arm.canonical(), x86.canonical());
            assert_eq!(x86.canonical().raw(), arm_nr);
            assert_eq!(arm.arguments(), args);
            assert_eq!(x86.arguments(), args);
            assert_eq!(arm.return_address(), pc);
            assert_eq!(x86.return_address(), pc);
            assert_eq!(x86.task_index(), 0);
            assert_eq!(x86.slot().index(), 7);
        }
    }
    #[test]
    fn invalid_anonymous_slot_declines_without_fatal() {
        let call = carrick_personality_linux::entry::decode_x86_64(10, [0; 6], 0x8000);
        let pc = carrick_guest_arch::UserVa::new(0x40004);
        assert!(anonymous_call(call, u32::MAX, pc).is_none());
        assert_eq!(anonymous_call(call, 7, pc).unwrap().slot().index(), 7);
    }
}
