//! #2028: a native fork child's `clock_gettime`, `clock_getres` and
//! `gettimeofday` are served in ring. Each witness drives the shipping body
//! end to end with two live processes: dispatch, ARM staging
//! (`native_service_decision`), the begin body (`begin_native_service`), the
//! host `ClockDomain` service, ticket acknowledgment and native resume.
use super::*;
use carrick_kernel::clock_service::ClockResourceService;
use carrick_kernel::kernel::container::ClockDomain;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

const CLOCK_GETTIME: u64 = 113;
const CLOCK_GETRES: u64 = 114;
const GETTIMEOFDAY: u64 = 169;

fn deterministic(secs: u64) -> Arc<ClockDomain> {
    Arc::new(ClockDomain::deterministic(
        UNIX_EPOCH + Duration::from_secs(secs),
    ))
}

fn pair(bytes: &[u8]) -> (i64, i64) {
    (
        i64::from_le_bytes(bytes[..8].try_into().unwrap()),
        i64::from_le_bytes(bytes[8..16].try_into().unwrap()),
    )
}

/// Run one clock call from a production native fork child and return its
/// final result. `x0`/`x1` are the call's first two arguments. The host
/// service answers against `clock`; `served` counts the records it served.
fn child_clock_call(nr: u64, x0: u64, x1: u64, clock: &Arc<ClockDomain>, served: &mut u32) -> i64 {
    use crate::native_process_runtime::{NativeResume, NativeThreadGroupOwner};
    use carrick_personality_linux::dispatch::CompletionRoute;

    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let crossing = Box::leak(Box::new(TestStockCrossing::new(&[
        0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
    ])));
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let child_task: &CurrentTask = Box::leak(Box::new(CurrentTask::new()));
    let registry = Box::leak(Box::new(NativeProcessRegistry::new()));
    let runtime = Arc::new(
        NativeProcessRuntime::admit_fresh_root::<Aarch64Mmu>(
            source,
            &fixture.task,
            fixture.page,
            fixture.control,
            fixture.address,
            fixture.address,
            parked,
        )
        .unwrap(),
    );
    registry
        .register_root(runtime.clone(), source, &fixture.task, fixture.address)
        .unwrap();
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &*crossing,
    )
    .with_words(&*words);
    let LifecycleOutcome::Returned { result, .. } = runtime
        .enter(source, &fixture.task, parked, &mut service)
        .unwrap()
        .fork(ProcessForkChildTid::NONE)
    else {
        panic!("production fork must publish a child");
    };
    assert!(result.raw() > 0);
    let parent = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let child_key = runtime
        .namespace_child_key(parent, result.raw() as u32)
        .unwrap();
    let child = runtime.task_binding(child_key).unwrap();
    let parent_binding = runtime.task_binding(parent).unwrap();
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, parent_binding.record.id)
            .is_queued()
    );
    activate(source, child_task, &child);
    // SAFETY: the live child owner retains this published lifecycle page.
    let page = unsafe {
        &*(child_task.metadata.lifecycle_page.load(Ordering::Acquire) as *const ThreadLifecyclePage)
    };
    assert_eq!(
        registry.thread_group_owner(fixture.zone, page, child_task.visible_pid().unwrap()),
        NativeThreadGroupOwner::ForkChild,
    );
    let counters: &'static carrick_el1_abi::Counters =
        Box::leak(Box::new(carrick_el1_abi::Counters::new()));
    let names = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let mut frame = carrick_el1_abi::TrapFrame {
        esr: 0x15 << 26,
        elr: 0x400004,
        slot: u64::from(fixture.slot.raw()),
        ..Default::default()
    };
    frame.x[8] = nr;
    frame.x[0] = x0;
    frame.x[1] = x1;
    let mut child_service = Aarch64NativeProcessService::with_crossing(
        child_task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &*crossing,
    )
    .with_words(&*words);
    let mut entry = runtime
        .enter_registered(
            registry,
            source,
            child_task,
            child.address,
            &child.words,
            &mut child_service,
        )
        .unwrap();
    let route = crate::dispatch::dispatch_syscall_with_native(
        &mut frame,
        counters,
        core::slice::from_ref(child_task),
        &[],
        &[],
        &[],
        &[],
        &names,
        None::<crate::dispatch::Zone<'_, crate::sched::FakeCpu, crate::sched::HardwareUserWord>>,
        None,
        None,
        Some(&mut *entry),
        Some(source),
        None,
        |_| core::ptr::null_mut(),
    );
    if matches!(route, CompletionRoute::Served | CompletionRoute::WithWork) {
        // Answered in ring without a crossing.
        return frame.x[0] as i64;
    }
    assert_eq!(route, CompletionRoute::NativeService, "clock {nr}");
    let begin = match crate::dispatch::native_service_decision(
        &mut frame,
        child_task,
        carrick_el1_abi::Action::Forward,
        None,
        counters,
        || NativeThreadGroupOwner::ForkChild,
        |_| None,
    ) {
        crate::dispatch::NativeServiceDecision::Begin(begin) => begin,
        crate::dispatch::NativeServiceDecision::Reply(result) => {
            panic!("the ring refused a clock reading with {result}")
        }
        crate::dispatch::NativeServiceDecision::Action(action) => {
            panic!("the ring finished a clock reading with {action:?}")
        }
        crate::dispatch::NativeServiceDecision::Decline => {
            panic!("a child clock reading must publish a clock request")
        }
    };
    let (result, _) = crate::dispatch::begin_native_service(
        &mut *entry,
        nr,
        begin,
        None,
        counters,
        counters,
        || None,
    );
    assert!(matches!(result.unwrap(), NativeResume::Left(None)));
    drop(entry);
    let notice = child_task.service_notice.take().unwrap().unwrap();
    // SAFETY: the live child retains this control slot in fixture-owned stock.
    let child_control = unsafe {
        &*(child_task.metadata.control_slot.load(Ordering::Acquire) as *const ThreadControlSlot)
    };
    let queue = fixture
        .zone
        .object_wait(
            carrick_sched_core::object_wait::ObjectWaitKey::native_service(child.record).unwrap(),
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
        )
        .unwrap();
    // SAFETY: this fixture owns the parked member and its service queue.
    let ticket = unsafe {
        carrick_core_abi::service::ServiceCell::claim_notice(
            &child_control.service,
            notice,
            NonZeroU64::MIN,
            fixture.zone.record(child.record.id).identity(),
        )
    }
    .unwrap();
    let carrick_core_abi::service::ServiceOperation::Clock {
        capability,
        payload,
    } = ticket.request().operation
    else {
        panic!("a child clock reading must stage a typed clock request, not a crossing");
    };
    assert_eq!(
        capability.raw().get(),
        5,
        "the run's capability is inherited by the fork child"
    );
    // SAFETY: the pending ring service retains this exact staging allocation
    // through the ticket's acknowledgment; the member remains parked.
    let record = unsafe {
        &mut *(payload.address().raw() as *mut [u8; carrick_core_abi::clock::CLOCK_RECORD_BYTES])
    };
    ClockResourceService::new(Arc::clone(clock))
        .serve_record(record)
        .unwrap();
    *served += 1;
    assert!(ticket.complete(true).is_ok());
    queue
        .notify_object(
            fixture.slot,
            &mut carrick_sched_core::WakeEffects::default(),
        )
        .unwrap();
    drop(queue);
    let selected = fixture.zone.switch_in_full(fixture.slot).unwrap();
    if selected.record != child.record.id {
        assert_eq!(selected.record, parent_binding.record.id);
        assert!(
            fixture
                .zone
                .requeue_preempted(fixture.slot, selected.record)
                .is_queued()
        );
        assert_eq!(
            fixture.zone.switch_in_full(fixture.slot).unwrap().record,
            child.record.id
        );
    }
    let saved = unsafe { runtime.record_binding(child.record) }
        .unwrap()
        .words;
    let mut entry = runtime
        .enter_registered(
            registry,
            source,
            child_task,
            child.address,
            &saved,
            &mut child_service,
        )
        .unwrap();
    let NativeResume::Returned(result) = entry.resume_checkpoint(|_| Ok(None)).unwrap() else {
        panic!("a completed clock reading resumes with its result");
    };
    assert_eq!(
        counters.refused_child[nr as usize].load(Ordering::Acquire),
        0
    );
    result.raw()
}

#[test]
fn child_clock_gettime_reads_the_container_domain() {
    // Deterministic clocks start at zero monotonic and the configured epoch.
    for (clock_id, expected) in [
        (0_u64, (1_234, 0)),
        (1, (0, 0)),
        (4, (0, 0)),
        (7, (0, 0)),
        (11, (1_234, 0)),
    ] {
        let out = carrick_test_support::GuestUserBuffer::zeroed(16);
        let mut served = 0;
        let value = child_clock_call(
            CLOCK_GETTIME,
            clock_id,
            out.arg(),
            &deterministic(1_234),
            &mut served,
        );
        assert_eq!(value, 0, "clock {clock_id}");
        assert_eq!(served, 1, "clock {clock_id} crosses exactly once");
        assert_eq!(pair(out.as_bytes()), expected, "clock {clock_id}");
    }
}

#[test]
fn child_clock_gettime_honours_a_frozen_domain() {
    let frozen = Arc::new(ClockDomain::frozen(UNIX_EPOCH + Duration::from_secs(777)));
    let out = carrick_test_support::GuestUserBuffer::zeroed(16);
    let mut served = 0;
    assert_eq!(
        child_clock_call(CLOCK_GETTIME, 0, out.arg(), &frozen, &mut served),
        0
    );
    assert_eq!(
        pair(out.as_bytes()),
        (777, 0),
        "the container's virtual realtime, not the host's"
    );
}

#[test]
fn child_gettimeofday_writes_timeval_and_timezone() {
    let tv = carrick_test_support::GuestUserBuffer::from_bytes(&[0xaa; 16]);
    let tz = carrick_test_support::GuestUserBuffer::from_bytes(&[0xbb; 8]);
    let mut served = 0;
    assert_eq!(
        child_gettimeofday(tv.arg(), tz.arg(), &mut served),
        0,
        "both outputs"
    );
    assert_eq!(pair(tv.as_bytes()), (1_234, 0));
    assert_eq!(&tz.as_bytes()[..8], &[0; 8], "UTC timezone");
    let tv = carrick_test_support::GuestUserBuffer::from_bytes(&[0xaa; 16]);
    assert_eq!(child_gettimeofday(tv.arg(), 0, &mut served), 0, "no tz");
    assert_eq!(pair(tv.as_bytes()), (1_234, 0));
    let tz = carrick_test_support::GuestUserBuffer::from_bytes(&[0xbb; 8]);
    assert_eq!(child_gettimeofday(0, tz.arg(), &mut served), 0, "no tv");
    assert_eq!(&tz.as_bytes()[..8], &[0; 8]);
    assert_eq!(served, 3, "one sample per reading");
}

fn child_gettimeofday(tv: u64, tz: u64, served: &mut u32) -> i64 {
    child_clock_call(GETTIMEOFDAY, tv, tz, &deterministic(1_234), served)
}

#[test]
fn child_clock_getres_is_answered_in_ring_without_a_crossing() {
    let out = carrick_test_support::GuestUserBuffer::from_bytes(&[0xcc; 16]);
    let mut served = 0;
    assert_eq!(
        child_clock_call(CLOCK_GETRES, 1, out.arg(), &deterministic(1), &mut served),
        0
    );
    assert_eq!(served, 0, "a resolution is a constant: nothing crosses");
    assert_eq!(pair(out.as_bytes()), (0, 1_000_000));
}

#[test]
fn child_clock_errors_are_linux_errnos() {
    let out = carrick_test_support::GuestUserBuffer::from_bytes(&[0xdd; 16]);
    let mut served = 0;
    let clock = deterministic(1);
    // Bad clock id: EINVAL before the output is touched.
    for nr in [CLOCK_GETTIME, CLOCK_GETRES] {
        assert_eq!(
            child_clock_call(nr, 12, out.arg(), &clock, &mut served),
            -22
        );
    }
    assert_eq!(out.as_bytes(), &[0xdd; 16], "no write on EINVAL");
    // Null output: EFAULT for a read, success for a resolution query.
    assert_eq!(
        child_clock_call(CLOCK_GETTIME, 1, 0, &clock, &mut served),
        -14
    );
    assert_eq!(child_clock_call(CLOCK_GETRES, 1, 0, &clock, &mut served), 0);
    assert_eq!(served, 0, "no refused call reached the service");
}

/// Linux: -1/EFAULT for an unmapped non-null destination. The sample was
/// served, so the failure is the copyout's, and it is the guest's.
#[test]
fn child_clock_gettime_invalid_output_is_efault() {
    let mut served = 0;
    assert_eq!(
        child_clock_call(
            CLOCK_GETTIME,
            0,
            u64::MAX,
            &deterministic(1_234),
            &mut served
        ),
        -14
    );
}

#[test]
fn child_gettimeofday_invalid_timeval_is_efault() {
    assert_eq!(child_gettimeofday(u64::MAX, 0, &mut 0), -14);
}

#[test]
fn child_gettimeofday_faulting_timezone_is_efault_after_timeval() {
    let tv = carrick_test_support::GuestUserBuffer::from_bytes(&[0xaa; 16]);
    assert_eq!(child_gettimeofday(tv.arg(), u64::MAX, &mut 0), -14);
    assert_eq!(
        pair(tv.as_bytes()),
        (1_234, 0),
        "timeval was already written"
    );
}
