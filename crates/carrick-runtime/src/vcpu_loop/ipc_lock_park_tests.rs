//! #1845: a `pipe2` create retained across another party's held IPC
//! readiness-lane lock, driven through the production runtime path:
//! `service_threaded_syscall` (the real threaded dispatcher) returns
//! `IpcLockContended`; `route_outcome` -> `service_outcome` ->
//! `ipc_lock_park` enrolls the zone record and settles into the zone; the
//! real scheduler settles the blocked continuation and owns the wake; the
//! production poll consumes the handback in `ResumeOwnerZone` and runs
//! `resume_ipc_lock_operation`.
//!
//! No refusal is injected: a live holder thread owns the real zone queue
//! lock of a recycled object slot's previous incarnation, as a late waker
//! or unlinker of that incarnation does. Every wait is bounded.
//!
//! Contract `kernel.el1.ipc-two-process`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::binding::*;
use super::executor::TaskBindingResolver;
use super::tests::*;
use super::*;
use carrick_abi::{LinuxCloneFlags, syscall::nr};
use carrick_el1_abi::ipc::pipe::{End, WaitFor};
use carrick_el1_abi::ipc::{IpcBacking, IpcObjectHandle, object_wait_key};
use carrick_el1_abi::{Aarch64ParkedContext, ZoneTables};
use carrick_el1_linux::mm_portal::{
    MmPortal,
    test_support::{ROOT, Region, admit_notified, nodes},
};
use carrick_kernel::el1_zone::HostLockWait;
use carrick_sched_core::object_wait::OwnedObjectWakeEffects;
use std::num::NonZeroU64;
use std::sync::mpsc;
use std::time::Duration;

const OUT: u64 = 0x71_1020;
const PIPE_CAPACITY: usize = 65536;
/// A holder that is never told to release still releases after this bound,
/// so a create that spins on its lock fails the witness instead of hanging.
const HOLDER_BOUND: Duration = Duration::from_secs(10);

fn complete(owned: OwnedObjectWakeEffects<'_, Aarch64ParkedContext>) {
    let zone = owned.zone();
    carrick_sched_core::LockWait::complete_object_wake(&HostLockWait, zone, owned);
}

/// Free a pipe so the next create pops its slot (LIFO free list) as a new
/// incarnation, exactly as a released pipe's slot is recycled.
fn recycled_slot(owner: &carrick_kernel::el1_ipc::HostIpc) -> IpcObjectHandle {
    let object = owner.create_pipe(PIPE_CAPACITY).unwrap();
    for end in [End::Reader, End::Writer] {
        owner
            .release(IpcBacking::Pipe { object, end }.encode())
            .unwrap();
    }
    object
}

/// A live second party holding the real queue lock of `object`'s `lane`
/// (its previous incarnation) until told to release, or until
/// [`HOLDER_BOUND`]. Release is idempotent and waits for the drop.
struct LaneHolder {
    release: Option<mpsc::Sender<()>>,
    released: mpsc::Receiver<()>,
}

impl LaneHolder {
    fn hold<'s>(
        scope: &'s std::thread::Scope<'s, '_>,
        zone: &'static ZoneTables,
        object: IpcObjectHandle,
        lane: WaitFor,
    ) -> Self {
        let (held_tx, held_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel::<()>();
        let (released_tx, released) = mpsc::channel();
        scope.spawn(move || {
            let guard = zone
                .object_wait(
                    object_wait_key(object, lane).unwrap(),
                    &HostLockWait,
                    &complete,
                )
                .unwrap();
            held_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(HOLDER_BOUND);
            drop(guard);
            let _ = released_tx.send(());
        });
        held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        Self {
            release: Some(release),
            released,
        }
    }

    fn release(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
            self.released
                .recv_timeout(HOLDER_BOUND + Duration::from_secs(5))
                .expect("holder released its lane lock");
        }
    }
}

impl Drop for LaneHolder {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

/// A real retained `pipe2` create: the threaded dispatcher meets a live
/// holder of its recycled slot's writable lane. The holder has released by
/// the time this returns; dropping the operation rolls the create back.
pub(super) fn contended_pipe2()
-> Box<carrick_kernel::kernel::continuation::ipc_lock::RetainedIpcLockOperation> {
    let zone = Box::leak(Box::new(Region::new())).zone();
    let dispatcher = SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    carrick_kernel::el1_zone::with_test_zone(zone, || {
        let old = recycled_slot(&context.kernel().ipc().unwrap());
        std::thread::scope(|scope| {
            let mut holder = LaneHolder::hold(scope, zone, old, WaitFor::Writable);
            let tid = ThreadId::synthetic_for_tests(71_605);
            let registry = ThreadRegistry::new(tid);
            let futex = FutexTable::new();
            let mut memory =
                carrick_kernel::dispatch::LinearMemory::new(0x71_0000, vec![0; 0x2000]);
            let outcome = dispatcher
                .dispatch_threaded(
                    &context,
                    SyscallRequest::new(
                        nr::PIPE2.raw(),
                        carrick_kernel::compat::SyscallArgs::from([OUT, 0, 0, 0, 0, 0]),
                    ),
                    &mut memory,
                    &carrick_kernel::compat::CompatReporter::default(),
                    ThreadCtx::new(tid, &registry, &futex),
                )
                .unwrap();
            holder.release();
            let DispatchOutcome::IpcLockContended(op) = outcome else {
                panic!("a held lane lock must retain the create, got {outcome:?}");
            };
            op
        })
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IpcLockCase {
    /// The holder releases after the waiter enrolled and settled.
    ReleaseAfterEnrollment,
    /// The holder releases between the refusal and enrollment: the release
    /// is already complete when `ipc_lock_park` defers, so the handback
    /// arrives before the scheduler settles the continuation.
    ReleaseBeforeEnrollment,
    /// A caught SIGUSR1 arrives while parked: it must not interrupt the
    /// create (`pipe2` has no EINTR); it is delivered after completion.
    CaughtSignal,
    /// SIGKILL arrives while parked: the retained create is dropped and
    /// everything it owned is reclaimed.
    Kill,
    /// The resumed create's `pipefd` output is owner-refused (a sibling
    /// holds the MM editor): the retained create is rolled back on the
    /// resumed dispatcher and `pipe2` reruns from the start after release.
    OutputRefusedOnResume,
}

/// Drive one `pipe2` through the production runtime contention path. See
/// [`IpcLockCase`] for each schedule.
pub(super) fn exercise_ipc_lock_park(case: IpcLockCase) {
    let (process, _) = crate::hvpatch::process_context_for_tests(71_602);
    let dispatcher = SyscallDispatcher::new();
    dispatcher.bind_hvpatch_process(Arc::new(process.clone()));
    let kernel = Arc::new(KernelState::new(
        dispatcher,
        Arc::new(EndpointTestSignalPump),
        Arc::new(EndpointTestSignalArrival),
        Some(process.clone()),
        None,
    ));
    let root = kernel.dispatcher.capture_one_task_context().unwrap();
    root.thread()
        .set_affinity(carrick_hal::CpuAffinity::from_words(&[1]));
    let region = Box::leak(Box::new(Region::new()));
    let zone = region.zone();
    let mm = admit_notified(region, root.shared().mm().id().raw(), ROOT, 1, 0);
    let view = Box::leak(Box::new(nodes(region)));
    let portal = Box::leak(Box::new(
        MmPortal::new(
            NonZeroU64::new(716).unwrap(),
            region.table(),
            &zone.spaces,
            view,
        )
        .with_zone(zone)
        .unwrap(),
    ));
    let handle = portal.admitted_handle(mm, 0).unwrap();
    assert!(
        region
            .portal_slots()
            .bind_carrier(NonZeroU64::new(716).unwrap())
    );
    carrick_el1_abi::record_el1_region_host_ptr(region.ptr.as_ptr() as usize);
    struct ClearRegion;
    impl Drop for ClearRegion {
        fn drop(&mut self) {
            carrick_el1_abi::record_el1_region_host_ptr(0);
        }
    }
    let _clear_region = ClearRegion;
    // A second live thread of the same process: its MM editor refuses the
    // resumed create's output in `OutputRefusedOnResume`.
    let sibling = root
        .kernel()
        .reserve_thread_clone(
            &root,
            carrick_kernel::kernel::ClonePlan::from_flags(
                LinuxCloneFlags::VM | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::THREAD,
            )
            .unwrap(),
            None,
        )
        .unwrap()
        .prepare(ThreadId::synthetic_for_tests(71_603))
        .unwrap()
        .commit()
        .unwrap()
        .into_context()
        .unwrap();
    let root = root
        .kernel()
        .context(root.task().key().id, root.thread().key().tid)
        .unwrap();
    assert!(root.exact_thread_is_live() && sibling.exact_thread_is_live());
    let mut root_state = executor::tests::task_state(&root, 503);
    root_state.asid_generation = process.asid_generation();
    let carrick_hal::threaded::GuestCpuState::Aarch64V1(cpu) = &mut root_state.cpu else {
        unreachable!()
    };
    Arc::make_mut(cpu).asid_generation = process.asid_generation();
    let scheduler = kernel
        .hvpatch_runtime
        .as_ref()
        .unwrap()
        .continuation_services(root.kernel())
        .0;
    let bindings = Arc::new(executor::TaskBindingDirectory::<
        crate::vcpu_loop::continuation::HvpatchTaskBinding,
    >::default());
    bindings.install_scheduler(&scheduler).unwrap();
    let generation = root
        .thread()
        .publish_initial_task_state(root_state.clone())
        .unwrap();
    let binding = executor::tests::hvpatch_test_binding(&root, &root_state, 603);
    let dormant = bindings
        .prepare_submission(
            &scheduler,
            executor::TaskSubmissionShape::Root,
            None,
            Arc::clone(root.thread()),
            generation,
            Arc::clone(&binding),
        )
        .unwrap();
    executor::tests::activate_hvpatch_test_submission(
        dormant,
        &scheduler,
        &root,
        &root_state,
        generation,
        binding.as_ref(),
    );
    // A second runnable thread of the process: while the create is parked,
    // the worker that served it must be free to run this one.
    let root_authority = bindings
        .take_submission_authority(root.thread().key(), generation)
        .unwrap();
    let published = root
        .kernel()
        .reserve_thread_clone(
            &root,
            carrick_kernel::kernel::ClonePlan::from_flags(
                LinuxCloneFlags::VM | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::THREAD,
            )
            .unwrap(),
            None,
        )
        .unwrap()
        .prepare(ThreadId::synthetic_for_tests(71_604))
        .unwrap()
        .reserve_publication_eventually()
        .unwrap()
        .commit()
        .unwrap();
    let other = published.context().unwrap().retain_exact();
    let other_state = executor::tests::task_state(&other, 504);
    let other_generation = other
        .thread()
        .publish_initial_task_state(other_state.clone())
        .unwrap();
    let other_binding = executor::tests::hvpatch_test_binding(&other, &other_state, 604);
    let other_dormant = bindings
        .prepare_submission(
            &scheduler,
            executor::TaskSubmissionShape::SameTaskSibling {
                grant: (root.thread().key(), generation),
            },
            Some(&root_authority),
            Arc::clone(other.thread()),
            other_generation,
            Arc::clone(&other_binding),
        )
        .unwrap();
    let started = published.start_thread().unwrap();
    let gate = started
        .context()
        .thread()
        .take_opened_start_gate(other_generation)
        .unwrap();
    other_dormant
        .activate(
            &scheduler,
            Arc::clone(other.thread()),
            executor::TaskActivationProof::validate(
                &other,
                &other_state,
                other_generation,
                other_binding.identity(),
                gate,
            )
            .unwrap(),
        )
        .unwrap();
    bindings
        .restore_submission_authority(root_authority)
        .unwrap();
    let root = root
        .kernel()
        .context(root.task().key().id, root.thread().key().tid)
        .unwrap();

    let this_tid = ThreadId::synthetic_for_tests(71_602);
    let kicker: Arc<dyn VcpuRegistry> = Arc::new(carrick_hal::GenericVcpuRegistry::new());
    let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
        Arc::new(ThreadRegistry::new(this_tid)),
        Arc::new(FutexTable::new()),
        Arc::new(NoopPlatformFutex),
        Arc::new(|_| Arc::new(NoopPlatformFutex)),
        kernel.process_fork_barrier.clone(),
        kernel.crash_capture.clone(),
        Some(Arc::clone(root.thread())),
        Some(process.pid()),
        root.thread().key().tid,
        kernel.fatal_signal.current_generation(),
        this_tid,
        Arc::new(parking_lot::Mutex::new(Vec::new())),
        Arc::clone(&kicker),
        carrick_hal::InGuestFlag::for_guest_thread(),
        1_000,
    );
    state.guest_execution = Some(
        kernel
            .dispatcher
            .enter_mm_executor_for_thread(
                Some(Arc::clone(root.thread())),
                kicker,
                this_tid,
                test_execution_slot(),
            )
            .expect("root MM executor participation"),
    );
    let frame = carrick_hal::RawSyscall {
        current_guest_sp: None,
        number: nr::PIPE2,
        args: [OUT, 0, 0, 0, 0, 0],
        guest_abi: carrick_abi::LinuxGuestAbi::Aarch64,
        native_number: carrick_abi::NativeNr(nr::PIPE2.raw()),
    };
    // The owner-memory venue, with every output ready: `pipefd` is written
    // through one prepared permit, counted in `prepared_commits`.
    let mut engine = CrashCaptureTestEngine {
        copyout_prepare: Some(Box::new(|| None)),
        ..Default::default()
    };

    let handback_scheduler = Arc::downgrade(&scheduler);
    let handback: carrick_kernel::el1_zone::HandbackPublisher = Arc::new(move |event| {
        if let Some(scheduler) = handback_scheduler.upgrade()
            && let carrick_kernel::el1_zone::HandbackEvent::Ready(record) = event
        {
            scheduler.publish_zone_handback(record);
        }
    });
    carrick_kernel::el1_zone::with_test_handback_publisher(handback, || {
        carrick_kernel::el1_zone::with_test_zone(zone, || {
            let owner = root.kernel().ipc().unwrap();
            let old = recycled_slot(&owner);
            std::thread::scope(|scope| {
                let mut holder = LaneHolder::hold(scope, zone, old, WaitFor::Writable);

                // 1. The real threaded dispatcher meets the held lane lock.
                let started = std::time::Instant::now();
                let first = state
                    .service_threaded_syscall(&kernel, &mut engine, frame, None)
                    .unwrap();
                assert!(
                    started.elapsed() < Duration::from_secs(3),
                    "pipe2 pinned its executor on the held lane lock for {:?}",
                    started.elapsed()
                );
                let DispatchOutcome::IpcLockContended(op) = &first else {
                    panic!("a held lane lock must retain the create, got {first:?}");
                };
                let (object, bound) = op.pipe2_progress().unwrap();
                assert_eq!(object.index(), old.index(), "the recycled slot was popped");
                assert_ne!(object, old, "as a new incarnation");
                assert_eq!(bound, 1, "the readable lane stays bound and owned");
                assert_eq!(engine.prepared_commits, 0, "no output before completion");
                assert!(!engine.guest_memory.contains_key(&OUT));
                assert_eq!(root.resources().files().slot_count(), 0);

                if case == IpcLockCase::ReleaseBeforeEnrollment {
                    holder.release();
                }

                // 2. The production executor routes the outcome: enroll on the
                // lock's release and surrender the executor.
                state.zone_mm = Some(mm.raw());
                let mut snapshot = executor::tests::task_state(&root, 503).cpu;
                let carrick_hal::threaded::GuestCpuState::Aarch64V1(cpu) = &mut snapshot else {
                    unreachable!()
                };
                let cpu = Arc::make_mut(cpu);
                cpu.asid_generation = process.asid_generation();
                cpu.syscall_continuation =
                    Some(carrick_hal::threaded::Aarch64SyscallContinuationV1 {
                        sequence: 1,
                        state: 1,
                        trap_kind: 1,
                        response_action: 0,
                        flags: 0,
                        native_nr: nr::PIPE2.raw(),
                        args: frame.args,
                        x8: nr::PIPE2.raw(),
                        resume_pc: 0x4004,
                        spsr: 0,
                        fp: 0x7000,
                        lr: 0x4100,
                        sp: 0x7100,
                        esr: 0x15 << 26,
                        return_value: 0,
                        resume_x16: 0x1616,
                        resume_x17: 0x1717,
                    });
                engine.exec_support = true;
                engine.snapshot_cpu = Some(snapshot);
                let mut job =
                    suffix_failure_test_job(&kernel, state, HvpatchProductionPhase::Resident, None);
                let registration = scheduler
                    .register_executor(Arc::new(RuntimeTestExecutorKick::default()))
                    .unwrap();
                let mut running = scheduler.take(&registration).unwrap();
                if running.thread_key() != root.thread().key() {
                    scheduler.settle_runnable_successor(running).unwrap();
                    running = scheduler.take(&registration).unwrap();
                }
                assert_eq!(running.thread_key(), root.thread().key());
                let lease = running.take_lease();
                let reject_descendant = |_, _| unreachable!();
                let mut submission = executor::ExecutorSubmissionContext {
                    registration: Some(&registration),
                    scheduler: &scheduler,
                    publish_test_descendant: &reject_descendant,
                    current: None,
                    authority: executor::ExecutionLeaseAuthoritySlot::new(Some(lease)),
                    exec_replacement: None,
                };
                let need_resched = std::sync::atomic::AtomicBool::new(false);
                let mut control = executor::HvpatchQuantumControl {
                    need_resched: &need_resched,
                    submission: &mut submission,
                    binding: Some(&binding),
                    cow_invalidation_observer: None,
                };
                let parked = job
                    .route_outcome(&mut engine, &mut control, frame, first)
                    .unwrap();
                let executor::ExecutorExit::BlockedContinuation {
                    continuation,
                    vfork_activation: None,
                } = parked
                else {
                    panic!("a retained create must surrender its executor, got {parked:?}");
                };
                assert!(matches!(
                    &job.phase,
                    HvpatchProductionPhase::ResumeOwnerZone {
                        resume: OwnedSyscallResume::IpcLock(_),
                        ..
                    }
                ));
                let record = continuation.zone_wait().unwrap().record;
                assert!(
                    zone.live(record).is_some(),
                    "the parked record holds the create's receipt"
                );
                let wait_service = carrick_kernel::kernel::continuation::CarrierWaitService::new(
                    Arc::clone(&scheduler),
                );
                let mut wait_registration = wait_service.prepare_registration(&continuation);
                wait_service.enroll(&mut wait_registration).unwrap();
                running
                    .restore_lease(submission.take_execution_lease().unwrap())
                    .unwrap();
                scheduler
                    .settle_blocked_continuation(running, *continuation, wait_registration)
                    .unwrap();

                // 3. The executor is free while the create waits: its lease is
                // back with the scheduler, the thread is blocked, and the same
                // worker runs the process's other runnable thread.
                carrick_kernel::el1_zone::hand_back_completions();
                let park_other = |other_running: carrick_kernel::kernel::RunnableThread| {
                    assert_eq!(other_running.thread_key(), other.thread().key());
                    scheduler
                        .settle_blocked(
                            other_running,
                            carrick_kernel::kernel::objects::BlockedReason::HostWait,
                        )
                        .unwrap();
                };
                if case == IpcLockCase::ReleaseBeforeEnrollment {
                    assert_eq!(
                        scheduler.queued_len(),
                        2,
                        "a release that won enrollment hands the record back at once"
                    );
                } else {
                    assert!(matches!(
                        root.thread().execution_state(),
                        carrick_kernel::kernel::objects::ThreadExecutionState::Blocked { .. }
                    ));
                    assert_eq!(
                        scheduler.queued_len(),
                        1,
                        "held lock keeps the create parked"
                    );
                    park_other(
                        scheduler.try_take(&registration).unwrap().expect(
                            "the parked create pins no executor: the worker runs another job",
                        ),
                    );
                    assert_eq!(scheduler.queued_len(), 0);
                }

                // 4. Signals while parked.
                let killing = case == IpcLockCase::Kill;
                let post = |signum: i32| {
                    let signal =
                        carrick_kernel::kernel::LinuxSignal::for_signal_number(signum).unwrap();
                    let carrick_kernel::kernel::ExactSignalTargetAuthorization::Allowed(target) =
                        root.kernel().authorize_signal_target_exact(
                            &root,
                            root.task().key(),
                            Some(root.thread().key()),
                            Some(signal),
                        )
                    else {
                        panic!("authorize signal for the exact live waiter")
                    };
                    assert!(matches!(
                        root.kernel()
                            .post_guest_thread_signal_to_authorized_target(&target, signal, None),
                        carrick_kernel::kernel::ExactThreadSignalPost::Posted(Some(_))
                    ));
                    wait_service.publish_signal_for_thread(root.thread().key());
                };
                if case == IpcLockCase::CaughtSignal {
                    let mut action = carrick_abi::LinuxSigaction::empty();
                    action.sa_handler = 0x5000;
                    root.signal_authority().install_action(
                        carrick_kernel::kernel::LinuxSignal::for_signal_number(
                            carrick_abi::LINUX_SIGUSR1,
                        )
                        .unwrap(),
                        action,
                    );
                    post(carrick_abi::LINUX_SIGUSR1);
                    carrick_kernel::el1_zone::hand_back_completions();
                    assert_eq!(
                        scheduler.queued_len(),
                        0,
                        "a caught signal cannot interrupt the retained create"
                    );
                    assert!(
                        root.signal_authority()
                            .thread_pending()
                            .contains(carrick_abi::LINUX_SIGUSR1)
                    );
                    assert!(engine.injected_signals.is_empty());
                }
                if killing {
                    post(carrick_abi::LINUX_SIGKILL);
                    carrick_kernel::el1_zone::hand_back_completions();
                    // The record sits on the lock's admission chain, which
                    // only the holder's release drains (the host claim is
                    // Deferred): SIGKILL takes effect at that release, which a
                    // short-section holder reaches without this executor.
                    assert_eq!(scheduler.queued_len(), 0);
                }

                // 5. An editor held across the resume refuses `pipefd`.
                let (editor_tx, editor_rx) = mpsc::sync_channel::<()>(1);
                let (edit_release_tx, edit_release_rx) = mpsc::sync_channel::<()>(1);
                let editor = (case == IpcLockCase::OutputRefusedOnResume).then(|| {
                    let sibling_mm = sibling.shared().mm().id().raw();
                    scope.spawn(move || {
                        let access = carrick_el1_linux::sched::object_wait::space_access(
                            zone,
                            carrick_sched_core::SlotId::new(1),
                        );
                        let editor = access
                            .try_begin_edit(
                                zone.spaces.find(sibling_mm).unwrap(),
                                mm.raw(),
                                NonZeroU64::new(2).unwrap(),
                            )
                            .unwrap();
                        editor_tx.send(()).unwrap();
                        let _ = edit_release_rx.recv_timeout(HOLDER_BOUND);
                        drop(editor);
                    })
                });
                if editor.is_some() {
                    editor_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    let wait = portal
                        .observe_wait(handle, carrick_el1_abi::PortalWaitCause::Editor)
                        .unwrap()
                        .unwrap();
                    engine.copyout_prepare = None;
                    engine.copyout_owner_probe = Some(CopyoutOwnerProbe::new(wait, zone));
                }

                // 6. The holder's release hands the record back to the scheduler.
                holder.release();
                carrick_kernel::el1_zone::hand_back_completions();
                assert_eq!(
                    scheduler.queued_len(),
                    if case == IpcLockCase::ReleaseBeforeEnrollment {
                        2
                    } else {
                        1
                    },
                    "the lock's release must wake the parked create exactly once"
                );

                // 7. The production poll resumes `ResumeOwnerZone`.
                let mut resumed = scheduler
                    .try_take(&registration)
                    .unwrap()
                    .expect("the handback reaches the registered executor");
                if case == IpcLockCase::ReleaseBeforeEnrollment
                    && resumed.thread_key() != root.thread().key()
                {
                    park_other(resumed);
                    resumed = scheduler.try_take(&registration).unwrap().unwrap();
                }
                assert_eq!(resumed.thread_key(), root.thread().key());
                let continuation::quantum::TaskCpuSave::Zone(saved) =
                    binding.take_cpu_save().expect("the park saves residency")
                else {
                    panic!("the park must retain its guest record");
                };
                let mut residency = executor::residency::TaskCpuResidency::Zone {
                    base: saved.base,
                    record: saved.record,
                    origin: saved.origin,
                };
                engine.snapshot_cpu = Some(
                    residency
                        .materialize_with(|_, _| panic!("zone save owns the CPU state"))
                        .expect("the executor reloads the parked state")
                        .clone(),
                );
                job.state.guest_execution = Some(
                    kernel
                        .dispatcher
                        .enter_mm_executor_for_thread(
                            Some(Arc::clone(root.thread())),
                            Arc::clone(&job.state.kicker),
                            job.state.this_tid,
                            test_execution_slot(),
                        )
                        .expect("resumed MM executor participation"),
                );
                let mut resumed_submission = executor::ExecutorSubmissionContext {
                    registration: Some(&registration),
                    scheduler: &scheduler,
                    publish_test_descendant: &reject_descendant,
                    current: None,
                    authority: executor::ExecutionLeaseAuthoritySlot::new(Some(
                        resumed.take_lease(),
                    )),
                    exec_replacement: None,
                };
                let mut resumed_control = executor::HvpatchQuantumControl::for_test(
                    &need_resched,
                    &mut resumed_submission,
                );
                resumed_control.binding = Some(&binding);
                let HvpatchProductionPhase::ResumeOwnerZone { resume, origin, .. } =
                    std::mem::replace(&mut job.phase, HvpatchProductionPhase::Resident)
                else {
                    panic!("the park lost its retained create");
                };
                let completed = job
                    .resume_owner_zone(&mut engine, &mut resumed_control, frame, resume, origin)
                    .unwrap();
                assert!(
                    zone.live(record).is_none(),
                    "the handed-back record is freed"
                );

                match case {
                    IpcLockCase::Kill => {
                        assert!(
                            matches!(
                                job.phase,
                                HvpatchProductionPhase::TerminalProcessDrain { .. }
                                    | HvpatchProductionPhase::RetainedMemoryRetry { .. }
                            ),
                            "SIGKILL must reach production termination, got {completed:?}"
                        );
                        assert!(kernel.process_exiting());
                        let fatal = kernel
                            .fatal_signal
                            .recorded_for(job.state.fatal_image_generation)
                            .expect("the production signal service records the fatal outcome");
                        assert_eq!(fatal.signo, carrick_abi::LINUX_SIGKILL);
                        assert!(engine.completed_syscalls.is_empty());
                        assert!(engine.injected_signals.is_empty());
                        // Reclaimed: the unpublished object, its bound lane
                        // (the slot binds both lanes again below), the record
                        // (above) and the output and descriptor reservations.
                        assert!(
                            owner.region().observe(object).is_err(),
                            "the retained object is freed"
                        );
                        assert_eq!(engine.prepared_commits, 0);
                        assert!(!engine.guest_memory.contains_key(&OUT));
                        assert_eq!(root.resources().files().slot_count(), 0);
                    }
                    IpcLockCase::OutputRefusedOnResume => {
                        // The refused resume rolled the retained create back on
                        // the resumed dispatcher and parked on the editor.
                        let executor::ExecutorExit::BlockedContinuation {
                            continuation,
                            vfork_activation: None,
                        } = completed
                        else {
                            panic!("a refused output must park on its owner, got {completed:?}");
                        };
                        assert!(matches!(
                            &job.phase,
                            HvpatchProductionPhase::ResumeOwnerZone {
                                resume: OwnedSyscallResume::CopyoutRedispatch,
                                ..
                            }
                        ));
                        assert!(
                            owner.region().observe(object).is_err(),
                            "the rolled-back object is freed, not leaked"
                        );
                        // Nothing the rollback took is still held: both lanes
                        // of the freed incarnation lock at once.
                        for lane in [WaitFor::Readable, WaitFor::Writable] {
                            let lock = zone
                                .object_wait(
                                    object_wait_key(object, lane).unwrap(),
                                    &carrick_kernel::el1_ipc::IpcCreateLockWait,
                                    &complete,
                                )
                                .map(drop);
                            assert_eq!(
                                lock,
                                Err(carrick_sched_core::object_wait::ObjectWaitError::Stale),
                                "{lane:?}: the freed incarnation's lane is unbound, not held"
                            );
                        }
                        assert_eq!(engine.prepared_commits, 0);
                        assert!(engine.completed_syscalls.is_empty());
                        assert_eq!(root.resources().files().slot_count(), 0);
                        let mut wait_registration =
                            wait_service.prepare_registration(&continuation);
                        wait_service.enroll(&mut wait_registration).unwrap();
                        resumed
                            .restore_lease(resumed_submission.take_execution_lease().unwrap())
                            .unwrap();
                        scheduler
                            .settle_blocked_continuation(resumed, *continuation, wait_registration)
                            .unwrap();
                        edit_release_tx.send(()).unwrap();
                        editor.unwrap().join().unwrap();
                        carrick_kernel::el1_zone::hand_back_completions();
                        assert_eq!(scheduler.queued_len(), 1, "editor release wakes pipe2");
                        resumed = scheduler.try_take(&registration).unwrap().unwrap();
                        let continuation::quantum::TaskCpuSave::Zone(saved) =
                            binding.take_cpu_save().unwrap()
                        else {
                            panic!("owner park must retain its guest record");
                        };
                        let mut residency = executor::residency::TaskCpuResidency::Zone {
                            base: saved.base,
                            record: saved.record,
                            origin: saved.origin,
                        };
                        engine.snapshot_cpu = Some(
                            residency
                                .materialize_with(|_, _| panic!("zone save owns the CPU state"))
                                .unwrap()
                                .clone(),
                        );
                        job.state.guest_execution = Some(
                            kernel
                                .dispatcher
                                .enter_mm_executor_for_thread(
                                    Some(Arc::clone(root.thread())),
                                    Arc::clone(&job.state.kicker),
                                    job.state.this_tid,
                                    test_execution_slot(),
                                )
                                .unwrap(),
                        );
                        resumed_submission.authority =
                            executor::ExecutionLeaseAuthoritySlot::new(Some(resumed.take_lease()));
                        let mut control = executor::HvpatchQuantumControl::for_test(
                            &need_resched,
                            &mut resumed_submission,
                        );
                        control.binding = Some(&binding);
                        let HvpatchProductionPhase::ResumeOwnerZone { resume, origin, .. } =
                            std::mem::replace(&mut job.phase, HvpatchProductionPhase::Resident)
                        else {
                            panic!("owner park lost its syscall");
                        };
                        let completed = job
                            .resume_owner_zone(&mut engine, &mut control, frame, resume, origin)
                            .unwrap();
                        assert!(matches!(completed, executor::ExecutorExit::Syscall));
                        assert_eq!(engine.completed_syscalls, [0]);
                        assert_eq!(engine.prepared_commits, 1);
                    }
                    IpcLockCase::ReleaseAfterEnrollment
                    | IpcLockCase::ReleaseBeforeEnrollment
                    | IpcLockCase::CaughtSignal => {
                        assert!(matches!(completed, executor::ExecutorExit::Syscall));
                        assert_eq!(
                            engine.completed_syscalls,
                            [0],
                            "the retained create completes exactly once"
                        );
                        assert_eq!(
                            engine.prepared_commits, 1,
                            "one output permit, committed once"
                        );
                        assert!(
                            owner.region().observe(object).is_ok(),
                            "the resumed create publishes the retained object itself"
                        );
                        if case == IpcLockCase::CaughtSignal {
                            assert_eq!(
                                engine.injected_signals,
                                [(Some(0), Some(0), false)],
                                "the caught signal is delivered after pipe2 completes"
                            );
                            assert!(
                                !root
                                    .signal_authority()
                                    .thread_pending()
                                    .contains(carrick_abi::LINUX_SIGUSR1)
                            );
                        } else {
                            assert!(engine.injected_signals.is_empty());
                        }
                    }
                }
                if !killing {
                    let mut pair = 3i32.to_ne_bytes().to_vec();
                    pair.extend_from_slice(&4i32.to_ne_bytes());
                    assert_eq!(engine.guest_memory[&OUT], pair, "pipefd = [3, 4]");
                    assert_eq!(root.resources().files().slot_count(), 2, "exactly one pair");
                }
                carrick_kernel::el1_zone::hand_back_completions();
                assert_eq!(
                    scheduler.queued_len(),
                    0,
                    "no second wake of the completed create"
                );
                let lease = resumed_submission.take_execution_lease().unwrap();
                resumed.restore_lease(lease).unwrap();
                scheduler.settle_runnable_successor(resumed).unwrap();
            });
            // No binding, object or lock of the contended create survives: the
            // freed slot (or the next free one) binds both lanes uncontended.
            let next = owner.create_pipe(PIPE_CAPACITY).unwrap();
            for end in [End::Reader, End::Writer] {
                owner
                    .release(IpcBacking::Pipe { object: next, end }.encode())
                    .unwrap();
            }
        });
    });
}

#[test]
fn serial_host_pipe2_lane_release_after_enrollment_resumes_through_runtime_once() {
    exercise_ipc_lock_park(IpcLockCase::ReleaseAfterEnrollment);
}

#[test]
fn serial_host_pipe2_lane_release_before_enrollment_hands_back_through_runtime() {
    exercise_ipc_lock_park(IpcLockCase::ReleaseBeforeEnrollment);
}

#[test]
fn serial_host_pipe2_lane_park_keeps_caught_signal_pending_until_completion() {
    exercise_ipc_lock_park(IpcLockCase::CaughtSignal);
}

#[test]
fn serial_host_pipe2_lane_park_sigkill_reclaims_the_retained_create() {
    exercise_ipc_lock_park(IpcLockCase::Kill);
}

#[test]
fn serial_host_pipe2_lane_resume_output_refusal_rolls_back_and_reruns_once() {
    exercise_ipc_lock_park(IpcLockCase::OutputRefusedOnResume);
}
