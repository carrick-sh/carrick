//! #2039: a venue operation whose output copy parks its record behind a
//! fresh `CarrierWork` service notice must leave the slot for the host,
//! vacated, before any other record runs. ARM's doorbell is a no-op: the
//! carrier takes the notice only at this vCPU's next exit, so running a
//! queued record first hands the host the notice on an exit naming that
//! record's address space (the signed `sched_affinity_threads` fatal "EL1
//! zone driver tried to park off-guest: slot still names ring-installed
//! address space").
//!
//! Each witness drives the production dispatcher
//! (`dispatch_syscall_with_native` with a scheduler zone and the native
//! process venue) with two live records on one slot. The operation is
//! `clock_getres`, whose ring-answered resolution goes through the venue's
//! owned copyout (`finish_signal_output`) when the direct copy refuses; the
//! Busy is the test's owner-access seam standing in for an owner-busy page.
use super::native_child_clock_tests::{ChildResumeCpu, fork_child};
use super::*;
use std::sync::Arc;

const CLOCK_GETRES: u64 = 114;
const CLOCK_MONOTONIC: u64 = 1;

/// Clears the owner-access hook on every exit path.
struct ResetAccess;
impl Drop for ResetAccess {
    fn drop(&mut self) {
        crate::aarch64_process::TEST_OWNER_ACCESS.with(|hook| *hook.borrow_mut() = None);
    }
}

/// Refuse the first write to `target` with `Busy`; count every write there.
fn busy_once_at(target: u64) -> (ResetAccess, Arc<AtomicUsize>) {
    let busy = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&busy);
    crate::aarch64_process::TEST_OWNER_ACCESS.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |_, address, _, bytes, _| {
            (address.raw() == target && bytes.is_some() && seen.fetch_add(1, Ordering::AcqRel) == 0)
                .then_some(Err(crate::native_process_runtime::NativeProcessError::Busy))
        }));
    });
    (ResetAccess, busy)
}

/// Run `dispatch` with the direct hardware copyout refused, so the output
/// goes to the venue's owned copyout, where the hook answers.
fn with_direct_copyout_refused<R>(dispatch: impl FnOnce() -> R) -> R {
    crate::file::SIMULATE_COPYOUT_FAULT.with(|fault| fault.store(true, Ordering::Relaxed));
    let result = dispatch();
    crate::file::SIMULATE_COPYOUT_FAULT.with(|fault| fault.store(false, Ordering::Relaxed));
    result
}

/// The state a venue park behind a notice must leave: the entry ends as
/// `Action::Idle` with nothing installed or current on the slot, the other
/// record still queued and the notice pending for the host.
fn assert_left_vacated(
    route: carrick_personality_linux::dispatch::CompletionRoute,
    zone: &ZoneTables<Aarch64ParkedContext>,
    slot: SlotId,
    task: &CurrentTask,
    other: RecordId,
) {
    assert!(
        task.service_notice.is_published(),
        "the Busy copyout parked behind a fresh notice"
    );
    assert_eq!(
        (route, zone.installed_space(slot), zone.slot(slot).current()),
        (
            carrick_personality_linux::dispatch::CompletionRoute::Suspended,
            0,
            None
        ),
        "a published service notice must end the run as Action::Idle: the slot \
         leaves for the host vacated"
    );
    assert!(
        matches!(
            zone.record(other).claim(),
            carrick_sched_core::Claim::Queued { .. }
        ),
        "the other record stays queued for the next entry"
    );
}

/// `clock_getres(CLOCK_MONOTONIC)`: the ring's constant 1 ms resolution.
const RESOLUTION: [u8; 16] = {
    let mut bytes = [0; 16];
    let nanos = 1_000_000_u64.to_le_bytes();
    let mut index = 0;
    while index < 8 {
        bytes[8 + index] = nanos[index];
        index += 1;
    }
    bytes
};

/// The lane A parked on and the queued record B.
struct Lane<'a> {
    zone: &'static ZoneTables<Aarch64ParkedContext>,
    slot: SlotId,
    task: &'static CurrentTask,
    a: RecordId,
    b: RecordId,
    runtime: &'a NativeProcessRuntime<'static, Mm, Aarch64ParkedContext>,
    registry: &'a NativeProcessRegistry<'static, Mm, Aarch64ParkedContext>,
    service: &'a mut Aarch64NativeProcessService<'static, &'static TestStockCrossing>,
}

/// The carrier takes the notice at the exit A left on and acknowledges the
/// owed carrier work. A's next entry finishes the same copyout (Busy once,
/// then success), and B runs after it, in its own space.
fn complete_then_resume(
    lane: Lane<'_>,
    out: &carrick_test_support::GuestUserBuffer,
    busy: &AtomicUsize,
) {
    let Lane {
        zone,
        slot,
        task,
        a,
        b,
        runtime,
        registry,
        service,
    } = lane;
    let notice = task.service_notice.take().unwrap().unwrap();
    let identity = zone.record(a).identity();
    // SAFETY: the live record A retains this control slot in fixture stock.
    let control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
    let queue = zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(zone.record_ref(a))
                .unwrap(),
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
        )
        .unwrap();
    // SAFETY: this fixture owns the parked member and its service queue.
    let ticket = unsafe {
        carrick_core_abi::service::ServiceCell::claim_notice(
            &control.service,
            notice,
            NonZeroU64::MIN,
            identity,
        )
    }
    .unwrap();
    assert!(matches!(
        ticket.request().operation,
        carrick_core_abi::service::ServiceOperation::CarrierWork { .. }
    ));
    assert!(ticket.complete(true).is_ok());
    queue
        .notify_object(slot, &mut carrick_sched_core::WakeEffects::default())
        .unwrap();
    drop(queue);
    // B was queued first; run A ahead of it.
    assert_eq!(zone.switch_in_full(slot).unwrap().record, b);
    assert!(zone.requeue_preempted(slot, b).is_queued());
    let mut cpu = ChildResumeCpu {
        child: a,
        inner: ResumeCpu {
            inner: crate::sched::FakeCpu::default(),
            runtime,
            registry,
            source: BornInZoneSource { zone, slot },
            task,
            service,
        },
    };
    let counters = carrick_el1_abi::Counters::new();
    let run_next = |cpu: &mut ChildResumeCpu<'_, '_>| {
        let mut frame = carrick_el1_abi::TrapFrame::default();
        let served = (crate::sched::Sched {
            handoff: None,
            zone,
            slot,
            task,
            cpu,
            user: &crate::sched::HardwareUserWord,
            counters: &counters,
        })
        .run_next(&mut frame, 0);
        (served, frame)
    };
    let (served, frame) = run_next(&mut cpu);
    assert_eq!(served, crate::sched::Served::Returned { switched: true });
    assert_eq!(zone.slot(slot).current(), Some(a));
    assert_eq!(frame.x[0], 0, "clock_getres returns 0");
    assert_eq!(out.as_bytes(), &RESOLUTION);
    assert_eq!(busy.load(Ordering::Acquire), 2, "Busy once, then success");
    assert!(task.service_notice.take().unwrap().is_none());
    // A's slice ends: B, still queued, runs next in its own space.
    assert!(zone.requeue_preempted(slot, a).is_queued());
    let (served, _) = run_next(&mut cpu);
    assert_eq!(served, crate::sched::Served::Returned { switched: true });
    assert_eq!(zone.slot(slot).current(), Some(b));
    assert_eq!(zone.installed_space(slot), zone.record(b).identity().mm);
}

/// B is the fork parent: a different mm queued on A's slot.
#[test]
fn venue_copyout_repark_leaves_the_slot_before_another_mm_runs() {
    let fork = fork_child();
    let (zone, slot) = (fork.fixture.zone, fork.fixture.slot);
    // A published maintenance root lets EL1 install each process's space.
    zone.spaces.set_idle_ttbr(0x30000);
    assert_eq!(zone.slot(slot).current(), Some(fork.child.record.id));
    assert_ne!(zone.installed_space(slot), 0);
    let out = carrick_test_support::GuestUserBuffer::from_bytes(&[0xcc; 16]);
    let (_reset, busy) = busy_once_at(out.arg());
    let mut service = Aarch64NativeProcessService::with_crossing(
        fork.child_task,
        slot,
        zone,
        fork.fixture.region.table(),
        NonZeroU64::MIN,
        fork.crossing,
    )
    .with_words(fork.words);
    let mut cpu = crate::sched::FakeCpu::default();
    let counters = carrick_el1_abi::Counters::new();
    let names = carrick_el1_abi::InotifyNameCache::new();
    let mut frame = carrick_el1_abi::TrapFrame {
        esr: 0x15 << 26,
        elr: 0x400004,
        slot: u64::from(slot.raw()),
        ..Default::default()
    };
    frame.x[..2].copy_from_slice(&[CLOCK_MONOTONIC, out.arg()]);
    frame.x[8] = CLOCK_GETRES;
    let route = {
        let mut entry = fork
            .runtime
            .enter_registered(
                fork.registry,
                fork.source,
                fork.child_task,
                fork.child.address,
                &fork.child.words,
                &mut service,
            )
            .unwrap();
        with_direct_copyout_refused(|| {
            crate::dispatch::dispatch_syscall_with_native(
                &mut frame,
                &counters,
                core::slice::from_ref(fork.child_task),
                &[],
                &[],
                &[],
                &[],
                &names,
                Some(crate::dispatch::Zone {
                    tables: zone,
                    cpu: &mut cpu,
                    user: &crate::sched::HardwareUserWord,
                }),
                None,
                Some(fork.fixture),
                Some(&mut *entry),
                Some(fork.source),
                None,
                |_| core::ptr::null_mut(),
            )
        })
    };
    assert_eq!(busy.load(Ordering::Acquire), 1, "the copyout was Busy once");
    assert_left_vacated(route, zone, slot, fork.child_task, fork.parent);
    assert_eq!(out.as_bytes(), &[0xcc; 16], "nothing was written yet");
    complete_then_resume(
        Lane {
            zone,
            slot,
            task: fork.child_task,
            a: fork.child.record.id,
            b: fork.parent,
            runtime: &fork.runtime,
            registry: fork.registry,
            service: &mut service,
        },
        &out,
        &busy,
    );
}

/// B is a same-mm sibling: the fork child's ring-born worker, queued behind
/// its leader (`child_thread_admission`'s fixture, which calls this with the
/// leader running right after the clone).
#[cfg(not(target_os = "macos"))]
pub(super) fn same_mm_worker_stays_queued(
    fixture: &'static Fixture,
    frame: &mut carrick_el1_abi::TrapFrame,
    cpu: &mut crate::sched::FakeCpu,
    service: &mut Aarch64NativeProcessService<'static, &'static TestStockCrossing>,
    counters: &carrick_el1_abi::Counters,
) {
    let (zone, slot) = (fixture.zone, fixture.slot);
    let leader = zone.slot(slot).current().unwrap();
    let worker = zone.runnable_head(slot).unwrap();
    assert_ne!(worker, leader);
    assert_eq!(
        zone.record(worker).identity().mm,
        zone.record(leader).identity().mm,
        "the queued record is a same-mm sibling"
    );
    let out = carrick_test_support::GuestUserBuffer::from_bytes(&[0xcc; 16]);
    let (_reset, busy) = busy_once_at(out.arg());
    frame.x[..2].copy_from_slice(&[CLOCK_MONOTONIC, out.arg()]);
    frame.x[8] = CLOCK_GETRES;
    let route = with_direct_copyout_refused(|| {
        super::native_fault_supply_tests::loan_call(fixture, frame, cpu, service, counters)
    });
    assert_eq!(busy.load(Ordering::Acquire), 1, "the copyout was Busy once");
    assert_left_vacated(route, zone, slot, &fixture.task, worker);
    assert_eq!(out.as_bytes(), &[0xcc; 16], "nothing was written yet");
    let runtime = registry()
        .for_record(zone, zone.record_ref(leader))
        .unwrap();
    complete_then_resume(
        Lane {
            zone,
            slot,
            task: &fixture.task,
            a: leader,
            b: worker,
            runtime: &runtime,
            registry: registry(),
            service,
        },
        &out,
        &busy,
    );
}
