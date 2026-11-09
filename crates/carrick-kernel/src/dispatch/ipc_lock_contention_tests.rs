//! #1845: `pipe2` through the production dispatcher entry, with another live
//! party holding the IPC readiness-lane lock its create must bind. No
//! refusal is injected: a holder thread owns the real zone queue lock of a
//! recycled object slot's previous incarnation (a late waker or unlinker).
//!
//! Contract `kernel.el1.ipc-two-process`: contention never pins a host
//! executor, never becomes an errno or an invariant failure, and the retained
//! create completes exactly once. Every wait is bounded; a create that spins
//! on the held lock fails the witness instead of hanging it.

use super::*;
use crate::compat::CompatReporter;
use crate::dispatch::fs::DEFAULT_PIPE_CAPACITY;
use crate::kernel::continuation::ipc_lock::RetainedIpcLockOperation;
use carrick_abi::syscall::nr;
use carrick_el1_abi::ipc::pipe::{End, WaitFor};
use carrick_el1_abi::ipc::{IpcBacking, IpcObjectHandle, object_wait_key};
use carrick_el1_abi::{Claim, ZoneTables};
use carrick_guest_mem::GuestMemory;
use carrick_sched_core::object_wait::OperationToken;
use carrick_sched_core::{AffinitySource, RecordId, ThreadIdentity};
use std::sync::mpsc;
use std::time::Duration;

const BASE: u64 = 0x4000_0000;
const OUT: u64 = BASE + 0x100;
/// A create that does not return within this bound is pinned on the lock.
const PINNED: Duration = Duration::from_secs(3);

fn leaked_zone() -> &'static ZoneTables {
    // SAFETY: all-zero is the empty zone state; leaked for `with_test_zone`.
    unsafe {
        let ptr = std::alloc::alloc_zeroed(std::alloc::Layout::new::<ZoneTables>());
        assert!(!ptr.is_null());
        Box::leak(Box::from_raw(ptr.cast::<ZoneTables>()))
    }
}

fn complete(
    owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
        '_,
        carrick_el1_abi::Aarch64ParkedContext,
    >,
) {
    crate::el1_zone::complete_object_wake(owned.zone(), owned);
}

/// Free `count` pipe objects so the next creates pop their slots (LIFO
/// free list) as new incarnations; their lanes stay bound to the old ones.
fn recycled_slots(owner: &crate::el1_ipc::HostIpc, count: usize) -> Vec<IpcObjectHandle> {
    let objects: Vec<_> = (0..count)
        .map(|_| owner.create_pipe(DEFAULT_PIPE_CAPACITY).unwrap())
        .collect();
    for object in &objects {
        for end in [End::Reader, End::Writer] {
            owner
                .release(
                    IpcBacking::Pipe {
                        object: *object,
                        end,
                    }
                    .encode(),
                )
                .unwrap();
        }
    }
    objects
}

fn recycled_slot(owner: &crate::el1_ipc::HostIpc) -> IpcObjectHandle {
    recycled_slots(owner, 1)[0]
}

/// A live second party holding the real queue lock of `objects`' `lane`
/// (their old incarnations) until told to release. Release is idempotent.
struct Holder {
    release: std::sync::Mutex<Option<mpsc::Sender<()>>>,
    released: std::sync::Mutex<mpsc::Receiver<()>>,
}

impl Holder {
    fn hold<'s>(
        scope: &'s std::thread::Scope<'s, '_>,
        zone: &'static ZoneTables,
        objects: Vec<IpcObjectHandle>,
        lane: WaitFor,
    ) -> Self {
        let (held_tx, held_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel::<()>();
        let (released_tx, released) = mpsc::channel();
        scope.spawn(move || {
            let guards: Vec<_> = objects
                .iter()
                .map(|object| {
                    zone.object_wait(
                        object_wait_key(*object, lane).unwrap(),
                        &crate::el1_zone::HostLockWait,
                        &complete,
                    )
                    .unwrap()
                })
                .collect();
            held_tx.send(()).unwrap();
            // Bounded: a wedged witness still releases and finishes.
            let _ = release_rx.recv_timeout(Duration::from_secs(30));
            drop(guards);
            released_tx.send(()).unwrap();
        });
        held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        Self {
            release: std::sync::Mutex::new(Some(release)),
            released: std::sync::Mutex::new(released),
        }
    }

    fn release(&self) {
        let Some(release) = self.release.lock().unwrap().take() else {
            return;
        };
        let _ = release.send(());
        self.released
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(35))
            .expect("holder released its lane locks");
    }
}

fn identity(tid: u64) -> ThreadIdentity {
    ThreadIdentity {
        tid,
        serial: tid,
        mm: 7,
        file_table: 1,
        generation: 1,
        affinity_source: AffinitySource::UNBOUND,
        affinity: 1,
        lifecycle_page: 0,
        control_slot: 0,
    }
}

/// What the runtime does with `IpcLockContended`: one zone record holding
/// the owner-wait receipt, enrolled on the held lock's release.
fn enroll(zone: &ZoneTables, op: &RetainedIpcLockOperation, tid: u64) -> RecordId {
    assert!(std::ptr::eq(op.zone(), zone));
    let record = zone.alloc_record(identity(tid)).unwrap();
    op.defer(record, OperationToken::metadata_request(tid).unwrap())
        .unwrap();
    record
}

fn handed_back(zone: &ZoneTables, record: RecordId) -> bool {
    matches!(zone.record(record).claim(), Claim::Host { .. })
}

/// Consume the handed-back record's receipt exactly once, as
/// `consume_owner_zone` does before resuming the retained syscall.
fn consume(zone: &ZoneTables, record: RecordId, tid: u64) {
    assert!(handed_back(zone, record), "release hands the record back");
    // SAFETY: the host owns this handed-back record; registrations unlinked.
    let token = unsafe { zone.record(record).take_object_operation() };
    assert_eq!(token.and_then(|t| t.metadata_generation()), Some(tid));
    zone.free_record(record);
}

fn pipe2_request(out: u64) -> SyscallRequest {
    SyscallRequest::new(nr::PIPE2.raw(), SyscallArgs::from([out, 0, 0, 0, 0, 0]))
}

fn resume(
    dispatcher: &SyscallDispatcher,
    memory: &mut LinearMemory,
    out: u64,
    op: Box<RetainedIpcLockOperation>,
) -> DispatchOutcome {
    let context = dispatcher.capture_one_task_context().unwrap();
    dispatcher
        .resume_ipc_lock_operation(
            &context,
            pipe2_request(out),
            op,
            memory,
            &CompatReporter::default(),
            None,
            OrdinaryDispatchRoute {
                host_wait: None,
                lease: None,
                mm_executor: None,
            },
        )
        .unwrap()
}

/// The threaded production entry, as an executor reaches it: `&self`, so
/// several pool workers dispatch concurrently.
fn dispatch_pipe2(
    dispatcher: &SyscallDispatcher,
    memory: &mut LinearMemory,
    out: u64,
) -> DispatchOutcome {
    let context = dispatcher.capture_one_task_context().unwrap();
    let tid = crate::thread::ThreadId::from_guest_supplied_tid(1);
    let registry = crate::thread::ThreadRegistry::new(tid);
    let futex = crate::thread::FutexTable::new();
    dispatcher
        .dispatch_threaded(
            &context,
            pipe2_request(out),
            memory,
            &CompatReporter::default(),
            ThreadCtx::new(tid, &registry, &futex),
        )
        .unwrap()
}

fn pair(memory: &LinearMemory, out: u64) -> (i32, i32) {
    let bytes = memory.read_bytes(out, 8).unwrap();
    (
        i32::from_ne_bytes(bytes[..4].try_into().unwrap()),
        i32::from_ne_bytes(bytes[4..].try_into().unwrap()),
    )
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Release {
    /// The holder releases after the waiter enrolled.
    AfterEnrollment,
    /// The holder releases between the refusal and enrollment.
    BeforeEnrollment,
}

/// W1: Busy once, then success. The create binds the readable lane, meets
/// the held writable lane, and returns the retained operation (no errno, no
/// fatal, no spin); the holder's release hands the enrolled record back and
/// the rerun completes the same pipe exactly once.
fn busy_once_then_success(order: Release) {
    let zone = leaked_zone();
    crate::el1_zone::with_test_zone(zone, || {
        let dispatcher = SyscallDispatcher::new();
        let owner = dispatcher
            .capture_one_task_context()
            .unwrap()
            .kernel()
            .ipc()
            .unwrap();
        let old = recycled_slot(&owner);
        let mut memory = LinearMemory::new(BASE, vec![0xa5; 0x1000]);
        std::thread::scope(|scope| {
            let holder = Holder::hold(scope, zone, vec![old], WaitFor::Writable);
            let (done_tx, done_rx) = mpsc::channel();
            let dispatcher = &dispatcher;
            let refused = std::thread::scope(|inner| {
                inner.spawn(move || {
                    crate::el1_zone::with_test_zone(zone, || {
                        let mut memory = LinearMemory::new(BASE, vec![0xa5; 0x1000]);
                        let outcome = dispatch_pipe2(dispatcher, &mut memory, OUT);
                        done_tx.send((outcome, memory)).unwrap();
                    })
                });
                let first = done_rx.recv_timeout(PINNED);
                if first.is_err() {
                    // Red: the create is pinned on the held lock. Release it
                    // so the spinning executor can finish, then fail.
                    holder.release();
                }
                first
            });
            let Ok((refused, refused_memory)) = refused else {
                panic!(
                    "pipe2 did not return within {PINNED:?} while another party held \
                     its readiness lane lock: the create pinned its executor"
                );
            };
            memory = refused_memory;
            let DispatchOutcome::IpcLockContended(op) = refused else {
                panic!("held lane lock must retain the create, got {refused:?}");
            };
            let (object, bound) = op.pipe2_progress().unwrap();
            assert_eq!(object.index(), old.index(), "the recycled slot was popped");
            assert_ne!(object, old, "a new incarnation");
            assert_eq!(bound, 1, "the readable lane is bound and retained");
            assert_eq!(memory.read_bytes(OUT, 8).unwrap(), [0xa5; 8]);
            assert!(dispatcher.open_file(3).is_none() && dispatcher.open_file(4).is_none());
            if order == Release::BeforeEnrollment {
                holder.release();
            }
            let record = enroll(zone, &op, 1845);
            if order == Release::AfterEnrollment {
                assert!(
                    matches!(zone.record(record).claim(), Claim::Transferring { .. }),
                    "a held lock cannot complete the waiter"
                );
                holder.release();
            }
            consume(zone, record, 1845);
            assert_eq!(
                resume(dispatcher, &mut memory, OUT, op),
                DispatchOutcome::Returned { value: 0 }
            );
        });
        assert_eq!(pair(&memory, OUT), (3, 4));
        assert!(dispatcher.open_file(3).is_some() && dispatcher.open_file(4).is_some());
        assert!(dispatcher.open_file(5).is_none(), "exactly one pair");
        // The completed create left no retained binding or object behind:
        // the next create runs uncontended.
        let mut memory2 = LinearMemory::new(BASE, vec![0; 0x1000]);
        assert_eq!(
            dispatch_pipe2(&dispatcher, &mut memory2, OUT),
            DispatchOutcome::Returned { value: 0 }
        );
        assert_eq!(pair(&memory2, OUT), (5, 6));
    });
}

#[test]
fn pipe2_held_lane_lock_retains_create_then_succeeds_once() {
    busy_once_then_success(Release::AfterEnrollment);
}

#[test]
fn pipe2_lane_release_before_enrollment_reruns_now() {
    busy_once_then_success(Release::BeforeEnrollment);
}

/// Cancellation while parked (SIGKILL, exit, exec drop the continuation):
/// the retained object and its bound lane are rolled back; the record the
/// lock's admission chain still holds is retired by the release, never
/// resumed; and the slot is reusable afterwards.
#[test]
fn pipe2_cancel_while_parked_leaks_no_object_or_binding() {
    let zone = leaked_zone();
    crate::el1_zone::with_test_zone(zone, || {
        let dispatcher = SyscallDispatcher::new();
        let owner = dispatcher
            .capture_one_task_context()
            .unwrap()
            .kernel()
            .ipc()
            .unwrap();
        let old = recycled_slot(&owner);
        std::thread::scope(|scope| {
            let holder = Holder::hold(scope, zone, vec![old], WaitFor::Writable);
            let mut memory = LinearMemory::new(BASE, vec![0xa5; 0x1000]);
            let refused = dispatch_pipe2(&dispatcher, &mut memory, OUT);
            let DispatchOutcome::IpcLockContended(op) = refused else {
                holder.release();
                panic!("held lane lock must retain the create, got {refused:?}");
            };
            let (object, _) = op.pipe2_progress().unwrap();
            let record = enroll(zone, &op, 1846);
            // Terminal cancellation: the continuation is dropped, then the
            // parked record is cancelled through its exact claim.
            drop(op);
            assert!(
                owner.region().observe(object).is_err(),
                "the unpublished object is freed"
            );
            assert!(matches!(
                zone.claim_for_host(
                    zone.record_ref(record),
                    None,
                    carrick_el1_abi::Handback::Cancelled,
                    &crate::el1_zone::HostLockWait,
                    &complete,
                ),
                carrick_el1_abi::HostClaim::Deferred
            ));
            holder.release();
            assert!(
                zone.live(zone.record_ref(record)).is_none()
                    || !matches!(zone.record(record).claim(), Claim::Transferring { .. }),
                "the release retires the cancelled record"
            );
            assert_eq!(memory.read_bytes(OUT, 8).unwrap(), [0xa5; 8]);
            assert!(dispatcher.open_file(3).is_none());
        });
        // The slot and both of its lanes bind again for the next incarnation.
        let mut memory = LinearMemory::new(BASE, vec![0; 0x1000]);
        assert_eq!(
            dispatch_pipe2(&dispatcher, &mut memory, OUT),
            DispatchOutcome::Returned { value: 0 }
        );
        assert_eq!(pair(&memory, OUT), (3, 4));
    });
}

/// The runtime's default executor pool for a single-CPU guest: one bound
/// executor plus `2 x nproc` spares (`carrick-runtime`
/// `vcpu_loop::executor::pool`, witnessed by
/// `native_service_waits_do_not_exhaust_the_default_executor_pool`).
const DEFAULT_SINGLE_CPU_POOL: usize = 3;

enum Job {
    Pipe2(usize),
    Resume(usize, Box<RetainedIpcLockOperation>),
    /// The holder's own progress needs an executor too (a guest vCPU that
    /// holds the lane lock runs only when an executor serves it).
    Release,
}

/// W2: more `pipe2` waiters than the default pool has workers, each meeting
/// a held lane lock, and the holder's release queued behind them on the same
/// pool. A create that pins its worker leaves no worker for the release: the
/// pool wedges. A retained create frees its worker at once.
#[test]
fn pipe2_lane_contention_does_not_exhaust_the_default_executor_pool() {
    let workers = DEFAULT_SINGLE_CPU_POOL;
    let waiters = workers + 1;
    let zone = leaked_zone();
    let dispatcher = SyscallDispatcher::new();
    let owner = dispatcher
        .capture_one_task_context()
        .unwrap()
        .kernel()
        .ipc()
        .unwrap();
    let slots: Vec<_> = crate::el1_zone::with_test_zone(zone, || recycled_slots(&owner, waiters));
    let jobs = std::sync::Mutex::new(std::collections::VecDeque::new());
    let ready = std::sync::Condvar::new();
    let push = |job| {
        jobs.lock().unwrap().push_back(Some(job));
        ready.notify_one();
    };
    let (events_tx, events) = mpsc::channel();
    let enrolled = std::sync::atomic::AtomicUsize::new(0);
    let memories: Vec<_> = (0..waiters)
        .map(|_| std::sync::Mutex::new(LinearMemory::new(BASE, vec![0xa5; 0x1000])))
        .collect();
    let result = std::thread::scope(|scope| {
        let holder: &Holder = Box::leak(Box::new(Holder::hold(
            scope,
            zone,
            slots.clone(),
            WaitFor::Writable,
        )));
        for _ in 0..workers {
            let (jobs, ready, events_tx, dispatcher, memories, enrolled) = (
                &jobs,
                &ready,
                events_tx.clone(),
                &dispatcher,
                &memories,
                &enrolled,
            );
            scope.spawn(move || {
                crate::el1_zone::with_test_zone(zone, || {
                    loop {
                        let job = {
                            let mut queue = jobs.lock().unwrap();
                            loop {
                                if let Some(job) = queue.pop_front() {
                                    break job;
                                }
                                queue = ready.wait(queue).unwrap();
                            }
                        };
                        let Some(job) = job else { return };
                        match job {
                            Job::Pipe2(i) => {
                                let outcome = dispatch_pipe2(
                                    dispatcher,
                                    &mut memories[i].lock().unwrap(),
                                    OUT,
                                );
                                match outcome {
                                    DispatchOutcome::IpcLockContended(op) => {
                                        let record = enroll(zone, &op, 2000 + i as u64);
                                        enrolled.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                                        events_tx.send(Ok((i, Some((record, op))))).unwrap();
                                    }
                                    other => events_tx.send(Err((i, other))).unwrap(),
                                }
                            }
                            Job::Resume(i, op) => {
                                let outcome =
                                    resume(dispatcher, &mut memories[i].lock().unwrap(), OUT, op);
                                match outcome {
                                    DispatchOutcome::Returned { value: 0 } => {
                                        events_tx.send(Ok((i, None))).unwrap()
                                    }
                                    other => events_tx.send(Err((i, other))).unwrap(),
                                }
                            }
                            Job::Release => {
                                // Release only once every waiter enrolled, so no
                                // waiter can run uncontended after it.
                                let deadline = std::time::Instant::now() + PINNED;
                                while enrolled.load(std::sync::atomic::Ordering::Acquire) < waiters
                                    && std::time::Instant::now() < deadline
                                {
                                    std::thread::yield_now();
                                }
                                holder.release()
                            }
                        }
                    }
                })
            });
        }
        for i in 0..waiters {
            push(Job::Pipe2(i));
        }
        push(Job::Release);
        // Every waiter must give its worker back while the lock is held.
        let mut parked = Vec::new();
        let mut verdict = Ok(());
        for _ in 0..waiters {
            match events.recv_timeout(PINNED) {
                Ok(Ok((i, Some(parked_op)))) => parked.push((i, parked_op)),
                Ok(other) => {
                    verdict = Err(format!(
                        "a contended pipe2 did not retain its create: {other:?}"
                    ));
                    break;
                }
                Err(_) => {
                    verdict = Err(format!(
                        "pool wedged: {} of {waiters} pipe2 waiters returned their worker \
                         ({workers} workers), so the holder's queued release never ran",
                        parked.len()
                    ));
                    break;
                }
            }
        }
        if verdict.is_ok() {
            for (i, (record, op)) in parked.drain(..) {
                // The queued release ran on a freed worker and handed back.
                let deadline = std::time::Instant::now() + PINNED;
                while !handed_back(zone, record) {
                    assert!(std::time::Instant::now() < deadline, "release never ran");
                    std::thread::yield_now();
                }
                consume(zone, record, 2000 + i as u64);
                push(Job::Resume(i, op));
            }
            for _ in 0..waiters {
                match events.recv_timeout(PINNED) {
                    Ok(Ok((_, None))) => {}
                    other => {
                        verdict = Err(format!("resumed pipe2 did not complete: {other:?}"));
                        break;
                    }
                }
            }
        } else {
            // Unwedge so the scope can join; the verdict is already red.
            holder.release();
        }
        drop(parked);
        for _ in 0..workers {
            jobs.lock().unwrap().push_back(None);
            ready.notify_all();
        }
        verdict
    });
    result.unwrap();
    let mut fds = std::collections::BTreeSet::new();
    for memory in &memories {
        let (read, write) = pair(&memory.lock().unwrap(), OUT);
        assert!(
            fds.insert(read) && fds.insert(write),
            "distinct descriptors"
        );
        assert!(dispatcher.open_file(read).is_some() && dispatcher.open_file(write).is_some());
    }
    assert_eq!(fds.len(), 2 * waiters, "one pipe per waiter");
}
