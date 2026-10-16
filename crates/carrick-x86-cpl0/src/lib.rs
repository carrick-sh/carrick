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

/// Migrate queued threads off the completing slot onto idle peers when a
/// syscall continues on the current task rather than suspending into
/// `schedule(slot)`.
///
/// When `route` is `CompletionRoute::Suspended`, the slot is about to call
/// `schedule(slot)` and switch in its own runnable queue head; migrating before
/// `schedule(slot)` drains the slot's own runnable head onto an idle peer and
/// strands the suspending slot in `IdleWfi`.
pub fn migrate_on_completion(
    route: carrick_personality_linux::dispatch::CompletionRoute,
    migrate: impl FnOnce(),
) {
    if !matches!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    ) {
        migrate();
    }
}

/// Forget the retired MM in `retire_context` before publishing slot absence via
/// `leave_space`, so a concurrent fork that reclaims `mm.root` from quarantine
/// as soon as `leave_space` clears the slot's installed space can admit that
/// root for the next child without racing `LiveContexts`.
pub fn retire_context_and_leave_space(
    mm: carrick_guest_arch::AddressContext<carrick_guest_arch::RootGpa>,
    retire_context: impl FnOnce(carrick_guest_arch::AddressContext<carrick_guest_arch::RootGpa>) -> bool,
    leave_space: impl FnOnce() -> bool,
) -> bool {
    retire_context(mm) && leave_space()
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1::isa::x86_live_context::LiveContexts;
    use carrick_guest_arch::{AddressContext, ContextGeneration, FrameGpa, MmGeneration, RootGpa};
    use carrick_personality_linux::dispatch::CompletionRoute;
    use carrick_sched_core::{
        ParkedContextWords, SlotId, ThreadIdentity, WakeEffects, X86_XSAVE_BYTES, ZoneTables,
    };
    use core::num::NonZeroU64;

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

    #[test]
    fn suspended_completion_keeps_queued_peer_for_local_switch_in() {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
        // SAFETY: `ZoneTables` is valid when zero-initialized.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables<ParkedContextWords>>();
            assert!(!ptr.is_null());
            Box::from_raw(ptr)
        };
        let slot_0 = SlotId::new(0);
        let slot_1 = SlotId::new(1);
        let space = zone.spaces.publish_closed(1, 0x1000, 0).unwrap();
        zone.spaces.open(space);
        zone.drive(slot_0, 1);
        zone.publish_slot(slot_0, 1, Some(0), 1);
        zone.enter_guest(slot_0);
        zone.install_space(slot_0, 1).unwrap();
        zone.drive(slot_1, 2);
        zone.publish_slot(slot_1, 1, Some(1), 2);
        zone.enter_guest(slot_1);
        assert!(zone.enter_idle(slot_1, true));

        let address = AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(0x1000)).unwrap(),
            mm: MmGeneration::new(NonZeroU64::MIN),
            generation: ContextGeneration::new(NonZeroU64::MIN),
        };
        let words = ParkedContextWords::from_parts([0; 20], address, 0, 0, [0; X86_XSAVE_BYTES]);

        let _running = zone
            .current_or_new(
                slot_0,
                ThreadIdentity {
                    tid: 41,
                    serial: 101,
                    mm: 1,
                    file_table: 5,
                    generation: 11,
                    affinity: 3,
                    lifecycle_page: 0,
                    control_slot: 0,
                },
            )
            .unwrap();
        let queued = zone
            .alloc_record(ThreadIdentity {
                tid: 42,
                serial: 102,
                mm: 1,
                file_table: 5,
                generation: 12,
                affinity: 3,
                lifecycle_page: 0,
                control_slot: 0,
            })
            .unwrap();
        // SAFETY: `queued` is freshly allocated and not yet published.
        unsafe { *zone.record(queued).ctx_mut() = words };
        zone.requeue_preempted(slot_0, queued);

        // When the running task on `slot_0` suspends (e.g., parks in `wait4` or
        // exits via `exit_group`), `slot_0` clears its current record and
        // enters `schedule(slot_0)`. `migrate_on_completion` must not drain
        // `slot_0`'s runnable head onto idle `slot_1` before `schedule(slot_0)`
        // switches in `queued`.
        zone.clear_current(slot_0);
        let mut effects = WakeEffects::default();
        migrate_on_completion(CompletionRoute::Suspended, || {
            zone.migrate_queued(slot_0, &mut effects);
        });
        assert_eq!(effects.sgi_slots().count(), 0);
        let switched = zone
            .switch_in_full(slot_0)
            .expect("suspending slot must switch in its own queued runnable head");
        assert_eq!(switched.record, queued);

        // By contrast, a non-suspending completion (`CompletionRoute::Served`)
        // while `slot_0` keeps running `switched.record` migrates a newly
        // queued sibling onto idle `slot_1`.
        let sibling = zone
            .alloc_record(ThreadIdentity {
                tid: 43,
                serial: 103,
                mm: 1,
                file_table: 5,
                generation: 13,
                affinity: 3,
                lifecycle_page: 0,
                control_slot: 0,
            })
            .unwrap();
        // SAFETY: `sibling` is freshly allocated and not yet published.
        unsafe { *zone.record(sibling).ctx_mut() = words };
        zone.requeue_preempted(slot_0, sibling);
        migrate_on_completion(CompletionRoute::Served, || {
            zone.migrate_queued(slot_0, &mut effects);
        });
        assert_eq!(effects.sgi_slots().collect::<Vec<_>>(), vec![slot_1]);
        zone.leave_idle(slot_1);
        let peer_switched = zone
            .switch_in_full(slot_1)
            .expect("idle peer must receive migrated runnable sibling");
        assert_eq!(peer_switched.record, sibling);
    }

    #[test]
    fn retire_context_precedes_leave_space_so_reclaimed_root_admits_next_mm() {
        let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
        // SAFETY: `ZoneTables` is valid when zero-initialized.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables<ParkedContextWords>>();
            assert!(!ptr.is_null());
            Box::from_raw(ptr)
        };
        let slot_1 = SlotId::new(1);
        let root = RootGpa::page_aligned(FrameGpa::new(0x2000)).unwrap();
        let mm_1 = MmGeneration::new(NonZeroU64::new(2).unwrap());
        let mm_2 = MmGeneration::new(NonZeroU64::new(3).unwrap());
        let child_1 = AddressContext {
            root,
            mm: mm_1,
            generation: ContextGeneration::new(NonZeroU64::new(1).unwrap()),
        };
        let child_2 = AddressContext {
            root,
            mm: mm_2,
            generation: ContextGeneration::new(NonZeroU64::new(2).unwrap()),
        };

        // Negative control: if `leave_space` publishes `installed_space == 0`
        // before `LiveContexts::retire`, a concurrent fork that reclaims `root`
        // as soon as `installed_space == 0` is visible fails `admit(child_2)`
        // because `root` is still bound to `mm_1`.
        let mut unguarded = LiveContexts::new();
        assert!(unguarded.admit(child_1));
        assert!(!unguarded.admit(child_2));

        // Production ordering (`retire_context_and_leave_space`): `child_1` is
        // retired from `LiveContexts` before `leave_space` clears `slot_1`'s
        // installed space, so a concurrent stock reclaim at the exact moment
        // `installed_space(slot_1)` becomes `0` admits `child_2` on the same
        // physical `root`.
        let space = zone
            .spaces
            .publish_closed(mm_1.raw().get(), root.address().raw(), 0)
            .unwrap();
        zone.spaces.open(space);
        zone.install_space(slot_1, mm_1.raw().get()).unwrap();
        let mut live = core::cell::RefCell::new(LiveContexts::new());
        assert!(live.get_mut().admit(child_1));
        let mut concurrent_reclaim_admitted = false;
        assert!(retire_context_and_leave_space(
            child_1,
            |ctx| live.borrow_mut().retire(ctx.mm, ctx.root),
            || {
                zone.release_space(slot_1);
                assert_eq!(zone.installed_space(slot_1), 0);
                concurrent_reclaim_admitted = live.borrow_mut().admit(child_2);
                true
            },
        ));
        assert!(
            concurrent_reclaim_admitted,
            "reclaimed root must admit the next child MM as soon as leave_space publishes slot absence"
        );
        assert_eq!(live.borrow().authenticate(mm_2, root), Some(child_2));
    }
}
