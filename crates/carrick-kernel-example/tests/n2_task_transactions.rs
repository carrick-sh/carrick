//! D-prep public graph transactions. Linux authority: clone(2), wait4(2),
//! execve(2), vfork(2). These are policy/edge bindings, not syscall routing or
//! signed execution. No private registry access or reference-only MM doubles.
//!
//! Exact rollback means no published task/thread/child edge or retained
//! resource reference, one backend destruction, and a cancelled child-start
//! token. TID user-copy errno/ordering needs an oracle-qualified product hook;
//! dropping a prepared birth models cancellation, not a guessed Linux EFAULT.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::convert::Infallible;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Instant;

use carrick_abi::{LinuxCloneFlags, LinuxResource, LinuxRlimit, NsGid, NsUid};
use carrick_hal::{NullHostSignalBridge, ThreadId};
use carrick_kernel::kernel::{
    ChildStartOutcome, ClonePlan, ExecError, Kernel, KernelContext, KernelFailpoint,
    KernelOperationError, LinuxWaitStatus, MmBackend, MmBackendSnapshot, SnapshotError,
    ThreadPublicationReservationAttempt, VforkReleaseReason, WaitMode, WaitOutcome,
};
use carrick_kernel_example::{AddressSpace, AsidAllocator, ExampleProcess, ScriptCheckpoint};
use carrick_observability::work_meter::{WorkMeter, WorkMetric};

struct Graph {
    asids: AsidAllocator,
    kernel: Arc<Kernel>,
    parents: [KernelContext; 2],
}

fn fork_plan(flags: LinuxCloneFlags) -> ClonePlan {
    ClonePlan::from_flags(flags).unwrap()
}

fn thread_plan() -> ClonePlan {
    fork_plan(
        LinuxCloneFlags::THREAD
            | LinuxCloneFlags::VM
            | LinuxCloneFlags::SIGHAND
            | LinuxCloneFlags::FILES,
    )
}

impl Graph {
    fn new(unprivileged: bool) -> Self {
        let asids = AsidAllocator::new();
        let (_, mut root) = ExampleProcess::boot_root(
            1,
            "D-prep root",
            Arc::new(NullHostSignalBridge::default()),
            AddressSpace::allocate(&asids).unwrap(),
        )
        .unwrap();
        let kernel = Arc::clone(root.kernel());
        if unprivileged {
            root = kernel
                .update_credentials(&root, |c| {
                    c.seed_identity(NsUid::new(1000), NsGid::new(1000))
                })
                .unwrap();
        }
        let peer = kernel
            .reserve_fork(
                &root,
                fork_plan(LinuxCloneFlags::empty()),
                "D-prep peer".into(),
                None,
            )
            .unwrap()
            .prepare_with_mm_backend(
                AddressSpace::allocate(&asids).unwrap().mm_backend(),
                ThreadId::from_guest_supplied_tid(2),
            )
            .unwrap()
            .commit()
            .unwrap()
            .start_child()
            .unwrap()
            .into_parts()
            .0;
        Self {
            asids,
            kernel,
            parents: [root, peer],
        }
    }

    fn current(&self, parent: &KernelContext) -> KernelContext {
        self.kernel
            .context(parent.task().key().id, parent.thread().key().tid)
            .unwrap()
    }

    fn child(
        &self,
        parent: &KernelContext,
        flags: LinuxCloneFlags,
    ) -> (
        KernelContext,
        Option<carrick_kernel::kernel::VforkParentWait>,
    ) {
        let reservation = self
            .kernel
            .reserve_fork(
                &self.current(parent),
                fork_plan(flags),
                "D child".into(),
                None,
            )
            .unwrap();
        let tid = ThreadId::from_guest_supplied_tid(reservation.visible_child_id());
        let prepared = if flags.contains(LinuxCloneFlags::VM) {
            reservation.prepare_shared_mm(tid).unwrap()
        } else {
            reservation
                .prepare_with_mm_backend(
                    AddressSpace::allocate(&self.asids).unwrap().mm_backend(),
                    tid,
                )
                .unwrap()
        };
        prepared
            .commit()
            .unwrap()
            .start_child()
            .unwrap()
            .into_parts()
    }

    fn reap(&self, parent: &KernelContext, child: &KernelContext, code: i32) {
        let WaitOutcome::Exited(zombie) = self
            .kernel
            .wait_child(
                parent.task().key().id,
                Some(child.task().key().id),
                WaitMode::Consume,
            )
            .unwrap()
        else {
            panic!("missing child status")
        };
        assert_eq!(zombie.key, child.task().key());
        assert_eq!(
            zombie.status,
            LinuxWaitStatus::from_wait_encoding(code << 8)
        );
        assert!(matches!(
            self.kernel
                .wait_child(
                    parent.task().key().id,
                    Some(child.task().key().id),
                    WaitMode::Consume
                )
                .unwrap(),
            WaitOutcome::NoChild
        ));
    }
}

struct CountedMm {
    backend: Arc<dyn MmBackend>,
    dropped: Arc<AtomicUsize>,
}

impl MmBackend for CountedMm {
    fn snapshot(&self, deadline: Instant) -> Result<MmBackendSnapshot, SnapshotError> {
        self.backend.snapshot(deadline)
    }
    fn revision(&self) -> u64 {
        self.backend.revision()
    }
}

impl Drop for CountedMm {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn failed_birth_stages_unwind_edges_once_at_1_8_32() {
    for n in [1, 8, 32] {
        let graph = Graph::new(false);
        let meter = WorkMeter::default();
        let work = meter.new_scope();
        graph.kernel.set_work_scope(work.clone());
        for parent in &graph.parents {
            for _ in 0..n {
                for point in [
                    KernelFailpoint::AfterReserve,
                    KernelFailpoint::AfterObjects,
                    KernelFailpoint::AfterBackendPrepare,
                    KernelFailpoint::BeforePublish,
                ] {
                    let current = graph.current(parent);
                    let ids = graph.kernel.ids().counts();
                    let tasks = graph.kernel.registry().task_count();
                    let files = current.resources().files();
                    let credentials = current.resources().credentials();
                    let mm = current.shared().mm();
                    let sighand = current.shared().sighand();
                    let refs = (
                        Arc::strong_count(&files),
                        Arc::strong_count(&credentials),
                        Arc::strong_count(&mm),
                        Arc::strong_count(&sighand),
                    );
                    let dropped = Arc::new(AtomicUsize::new(0));
                    let backend = Arc::new(CountedMm {
                        backend: AddressSpace::allocate(&graph.asids).unwrap().mm_backend(),
                        dropped: dropped.clone(),
                    });
                    let mut refused_child = None;
                    let result = graph
                        .kernel
                        .reserve_fork(
                            &current,
                            fork_plan(LinuxCloneFlags::empty()),
                            "injected birth".into(),
                            Some(point),
                        )
                        .and_then(|r| {
                            refused_child = Some(r.child_id());
                            let tid = ThreadId::from_guest_supplied_tid(r.visible_child_id());
                            r.prepare_with_mm_backend(backend.clone(), tid)
                        })
                        .and_then(|p| p.commit());
                    assert!(matches!(result, Err(KernelOperationError::Injected(p)) if p == point));
                    assert_eq!(Arc::strong_count(&backend), 1, "failed MM edge retained");
                    drop(backend);
                    assert_eq!(dropped.load(Ordering::SeqCst), 1);
                    assert_eq!(graph.kernel.registry().task_count(), tasks);
                    assert_eq!(graph.kernel.ids().counts(), ids);
                    assert_eq!(current.task().threads().len(), 1);
                    if let Some(child) = refused_child {
                        assert!(
                            matches!(
                                graph
                                    .kernel
                                    .wait_child(
                                        current.task().key().id,
                                        Some(child),
                                        WaitMode::Consume
                                    )
                                    .unwrap(),
                                WaitOutcome::NoChild
                            ),
                            "failed birth left a parent-child edge"
                        );
                    }
                    let remaining = graph
                        .kernel
                        .wait_child(current.task().key().id, None, WaitMode::Consume)
                        .unwrap();
                    if current.task().key() == graph.parents[0].task().key() {
                        assert!(matches!(remaining, WaitOutcome::StillRunning(_)));
                    } else {
                        assert!(matches!(remaining, WaitOutcome::NoChild));
                    }
                    assert_eq!(
                        (
                            Arc::strong_count(&files),
                            Arc::strong_count(&credentials),
                            Arc::strong_count(&mm),
                            Arc::strong_count(&sighand)
                        ),
                        refs
                    );
                }
            }
        }
        let snapshot = work.snapshot().unwrap();
        assert_eq!(snapshot.dropped_events(), 0);
        assert!(snapshot.unknown_metrics().is_empty());
        // Three stages reach the actual empty file-table copy; AfterReserve
        // does not. Fixed per-attempt work, including all failed operations.
        assert_eq!(
            snapshot.get(WorkMetric::GuestMemoryCopyBytes),
            Some(2 * n as u64 * 3 * 96)
        );
    }
}

#[test]
fn cancelled_prepublication_birth_cancels_start_and_releases_edges_at_1_8_32() {
    for n in [1, 8, 32] {
        let graph = Graph::new(false);
        for parent in &graph.parents {
            for _ in 0..n {
                let current = graph.current(parent);
                let ids = graph.kernel.ids().counts();
                let files = current.resources().files();
                let refs = Arc::strong_count(&files);
                let reservation = graph
                    .kernel
                    .reserve_fork(
                        &current,
                        fork_plan(LinuxCloneFlags::empty()),
                        "cancelled".into(),
                        None,
                    )
                    .unwrap();
                let tid = ThreadId::from_guest_supplied_tid(reservation.visible_child_id());
                let mut prepared = reservation
                    .prepare_with_mm_backend(
                        AddressSpace::allocate(&graph.asids).unwrap().mm_backend(),
                        tid,
                    )
                    .unwrap();
                let child = prepared.child_key();
                let start = prepared.take_child_start_wait().unwrap();
                assert!(!graph.kernel.task_is_live(child.id));
                // A fallible TID/copy transaction must cancel here, before
                // runnable publication; no errno or copy ordering is inferred.
                drop(prepared);
                let (send, receive) = std::sync::mpsc::channel();
                let waiter = std::thread::spawn(move || send.send(start.wait()).unwrap());
                assert_eq!(
                    receive
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap(),
                    ChildStartOutcome::Cancelled
                );
                waiter.join().unwrap();
                assert!(!graph.kernel.task_is_live(child.id));
                assert_eq!(graph.kernel.ids().counts(), ids);
                assert_eq!(Arc::strong_count(&files), refs);
                assert_eq!(graph.kernel.registry().task_count(), 2);
            }
        }
    }
}

#[test]
fn failed_thread_birth_restores_claim_and_shared_edges_at_1_8_32() {
    for n in [1, 8, 32] {
        let graph = Graph::new(false);
        for parent in &graph.parents {
            for _ in 0..n {
                for point in [
                    KernelFailpoint::AfterReserve,
                    KernelFailpoint::AfterObjects,
                    KernelFailpoint::AfterBackendPrepare,
                    KernelFailpoint::BeforePublish,
                ] {
                    let current = graph.current(parent);
                    let ids = graph.kernel.ids().counts();
                    let files = current.resources().files();
                    let mm = current.shared().mm();
                    let sighand = current.shared().sighand();
                    let refs = (
                        Arc::strong_count(&files),
                        Arc::strong_count(&mm),
                        Arc::strong_count(&sighand),
                    );
                    let result = graph
                        .kernel
                        .reserve_thread_clone(&current, thread_plan(), Some(point))
                        .and_then(|r| {
                            let tid = ThreadId::from_guest_supplied_tid(r.visible_tid());
                            r.prepare(tid)
                        })
                        .and_then(|p| p.commit());
                    assert!(matches!(result, Err(KernelOperationError::Injected(p)) if p == point));
                    assert_eq!(graph.kernel.ids().counts(), ids);
                    assert_eq!(current.task().threads().len(), 1);
                    assert_eq!(
                        (
                            Arc::strong_count(&files),
                            Arc::strong_count(&mm),
                            Arc::strong_count(&sighand)
                        ),
                        refs
                    );
                }
            }
        }
    }
}

#[test]
fn clone_during_exec_close_cannot_publish_and_rollback_reopens_birth_at_1_8_32() {
    for n in [1, 8, 32] {
        let graph = Graph::new(false);
        for parent in &graph.parents {
            for _ in 0..n {
                let current = graph.current(parent);
                let ids = graph.kernel.ids().counts();
                let old_mm = current.shared().mm().id();
                let old_files = current.resources().files();
                let prepared = graph
                    .kernel
                    .prepare_exec_with_mm_backend(
                        &current,
                        AddressSpace::allocate(&graph.asids).unwrap().mm_backend(),
                        None,
                    )
                    .unwrap();
                assert_ne!(prepared.replacement_mm_id(), old_mm);
                // This is an internal admission refusal while exec owns the
                // transaction, not an assertion that Linux clone returns
                // EAGAIN. The adapter must suspend/cancel the exact caller.
                assert!(matches!(
                    graph
                        .kernel
                        .reserve_thread_clone(&current, thread_plan(), None),
                    Err(KernelOperationError::TaskBusy(_))
                ));
                assert_eq!(current.task().threads().len(), 1);
                assert_eq!(graph.kernel.ids().counts(), ids);
                drop(prepared);
                assert_eq!(graph.current(parent).shared().mm().id(), old_mm);
                assert!(Arc::ptr_eq(
                    &graph.current(parent).resources().files(),
                    &old_files
                ));
                let clone = graph
                    .kernel
                    .reserve_thread_clone(&graph.current(parent), thread_plan(), None)
                    .unwrap();
                let tid = ThreadId::from_guest_supplied_tid(clone.visible_tid());
                let sibling = clone
                    .prepare(tid)
                    .unwrap()
                    .commit()
                    .unwrap()
                    .into_context()
                    .unwrap();
                assert!(Arc::ptr_eq(&sibling.resources().files(), &old_files));
                graph.kernel.exit_thread(&sibling, None).unwrap();
                drop(sibling);
                graph.kernel.sweep_retired_threads();
            }
        }
    }
}

#[test]
fn uid_limit_counts_both_live_parents_and_shared_threads_at_1_8_32() {
    // clone(2) EAGAIN + getrlimit(2): RLIMIT_NPROC counts threads for the real
    // uid; root/CAP_SYS_RESOURCE exemption does not apply to this fixture.
    // https://man7.org/linux/man-pages/man2/clone.2.html
    // https://man7.org/linux/man-pages/man2/getrlimit.2.html
    for n in [1, 8, 32] {
        let graph = Graph::new(true);
        for parent in &graph.parents {
            parent
                .task()
                .replace_rlimit(LinuxResource::Nproc, |_| {
                    Ok::<_, Infallible>(LinuxRlimit::new((2 + 2 * n) as u64, 8192))
                })
                .unwrap();
        }
        let mut siblings = Vec::new();
        for parent in &graph.parents {
            for _ in 0..n {
                let reservation = graph
                    .kernel
                    .reserve_thread_clone(&graph.current(parent), thread_plan(), None)
                    .unwrap();
                let tid = ThreadId::from_guest_supplied_tid(reservation.visible_tid());
                siblings.push(
                    reservation
                        .prepare(tid)
                        .unwrap()
                        .commit()
                        .unwrap()
                        .into_context()
                        .unwrap(),
                );
            }
        }
        for parent in &graph.parents {
            assert_eq!(parent.task().threads().len(), n + 1);
            let ids = graph.kernel.ids().counts();
            assert!(
                matches!(graph.kernel.reserve_fork(&graph.current(parent), fork_plan(LinuxCloneFlags::empty()), "over uid budget".into(), None),
                Err(KernelOperationError::ProcessLimitExceeded { count, limit, uid })
                    if count == 2 + 2 * n && limit == count as u64 && uid == NsUid::new(1000))
            );
            assert!(
                matches!(graph.kernel.reserve_thread_clone(&graph.current(parent), thread_plan(), None),
                Err(KernelOperationError::ProcessLimitExceeded { count, limit, .. }) if count as u64 == limit)
            );
            assert_eq!(graph.kernel.ids().counts(), ids);
        }
        let departed = siblings.pop().unwrap();
        graph.kernel.exit_thread(&departed, None).unwrap();
        drop(departed);
        graph.kernel.sweep_retired_threads();
        // Exactly one charge is freed: a reservation consumes it, dropping
        // that reservation releases it once, and either parent can use it.
        for parent in &graph.parents {
            let current = graph.current(parent);
            let reservation = graph
                .kernel
                .reserve_thread_clone(&current, thread_plan(), None)
                .unwrap();
            assert!(matches!(
                graph
                    .kernel
                    .reserve_thread_clone(&current, thread_plan(), None),
                Err(KernelOperationError::ProcessLimitExceeded { .. })
            ));
            drop(reservation);
        }
    }
}

#[test]
fn clone_publication_during_fork_reservation_keeps_exact_shared_edges_at_1_8_32() {
    // clone(2): CLONE_VM/FILES/SIGHAND retain the existing objects; fork
    // receives private MM/files. TaskBusy is internal custody, never evidence
    // for a Linux EAGAIN. No retry, executor or timeout implements this test.
    // https://man7.org/linux/man-pages/man2/clone.2.html
    for n in [1, 8, 32] {
        let graph = Graph::new(false);
        for parent in &graph.parents {
            for _ in 0..n {
                let current = graph.current(parent);
                let clone = graph
                    .kernel
                    .reserve_thread_clone(&current, thread_plan(), None)
                    .unwrap();
                let tid = ThreadId::from_guest_supplied_tid(clone.visible_tid());
                let clone = clone.prepare(tid).unwrap();
                let fork = graph
                    .kernel
                    .reserve_fork(
                        &current,
                        fork_plan(LinuxCloneFlags::empty()),
                        "overlap".into(),
                        None,
                    )
                    .unwrap();
                let ThreadPublicationReservationAttempt::Busy(clone) =
                    clone.try_reserve_publication().unwrap()
                else {
                    panic!("fork must own the publication slot")
                };
                let child_tid = ThreadId::from_guest_supplied_tid(fork.visible_child_id());
                let fork = fork
                    .prepare_with_mm_backend(
                        AddressSpace::allocate(&graph.asids).unwrap().mm_backend(),
                        child_tid,
                    )
                    .unwrap()
                    .commit()
                    .unwrap()
                    .start_child()
                    .unwrap()
                    .into_parts()
                    .0;
                let sibling = clone.commit().unwrap().into_context().unwrap();
                assert!(Arc::ptr_eq(&sibling.shared().mm(), &current.shared().mm()));
                assert!(Arc::ptr_eq(
                    &sibling.resources().files(),
                    &current.resources().files()
                ));
                assert!(Arc::ptr_eq(
                    &sibling.shared().sighand(),
                    &current.shared().sighand()
                ));
                assert!(!Arc::ptr_eq(&fork.shared().mm(), &current.shared().mm()));
                assert!(!Arc::ptr_eq(
                    &fork.resources().files(),
                    &current.resources().files()
                ));
                graph.kernel.exit_thread(&sibling, None).unwrap();
                drop(sibling);
                graph.kernel.sweep_retired_threads();
                graph
                    .kernel
                    .exit_task(
                        fork.task().key().id,
                        LinuxWaitStatus::from_wait_encoding(0),
                        None,
                    )
                    .unwrap();
                graph.reap(parent, &fork, 0);
            }
        }
    }
}

#[test]
fn delayed_parent_notification_preserves_durable_exact_status_at_1_8_32() {
    for n in [1, 8, 32] {
        let graph = Graph::new(false);
        for parent in &graph.parents {
            for _ in 0..n {
                let (child, _) = graph.child(parent, LinuxCloneFlags::empty());
                let committed = ScriptCheckpoint::default();
                let resume = ScriptCheckpoint::default();
                std::thread::scope(|scope| {
                    let exit = scope.spawn(|| {
                        graph
                            .kernel
                            .prepare_task_exit_key(
                                child.task().key(),
                                LinuxWaitStatus::from_wait_encoding(9 << 8),
                                None,
                            )
                            .unwrap()
                            .commit_notifying(|target| {
                                assert_eq!(target, Some(parent.task().key()));
                                committed.signal();
                                assert!(resume.wait());
                            })
                            .unwrap();
                    });
                    assert!(committed.wait());
                    // A delayed signal/wake is not the zombie authority:
                    // scanning already sees the committed exact child status.
                    graph.reap(parent, &child, 9);
                    resume.signal();
                    exit.join().unwrap();
                });
            }
        }
    }
}

#[test]
fn vfork_releases_only_on_exact_child_mm_release_at_1_8_32() {
    // clone(2) CLONE_VFORK / vfork(2): failed exec does not unblock parent;
    // successful exec or child exit does. Independent child exit cannot.
    // https://man7.org/linux/man-pages/man2/clone.2.html
    // https://man7.org/linux/man-pages/man2/vfork.2.html
    for n in [1, 8, 32] {
        let graph = Graph::new(false);
        for (index, parent) in graph.parents.iter().enumerate() {
            let other_parent = &graph.parents[1 - index];
            for release in [VforkReleaseReason::Exec, VforkReleaseReason::Exit] {
                for _ in 0..n {
                    let (child, wait) =
                        graph.child(parent, LinuxCloneFlags::VM | LinuxCloneFlags::VFORK);
                    let wait = wait.unwrap();
                    let old_mm = parent.shared().mm().id();
                    assert_eq!(child.shared().mm().id(), old_mm);
                    assert_eq!(wait.released_reason(), None);
                    let (other, _) = graph.child(other_parent, LinuxCloneFlags::empty());
                    graph
                        .kernel
                        .exit_task(
                            other.task().key().id,
                            LinuxWaitStatus::from_wait_encoding(0),
                            None,
                        )
                        .unwrap();
                    assert_eq!(
                        wait.released_reason(),
                        None,
                        "unrelated child released vfork"
                    );
                    let backend = AddressSpace::allocate(&graph.asids).unwrap().mm_backend();
                    assert!(matches!(
                        graph.kernel.prepare_exec_with_mm_backend(
                            &child,
                            backend.clone(),
                            Some(KernelFailpoint::AfterBackendPrepare)
                        ),
                        Err(ExecError::Injected(KernelFailpoint::AfterBackendPrepare))
                    ));
                    assert_eq!(wait.released_reason(), None);
                    assert_eq!(child.shared().mm().id(), old_mm);
                    let (terminal, reason) = if release == VforkReleaseReason::Exec {
                        let prepared = graph
                            .kernel
                            .prepare_exec_with_mm_backend(&child, backend, None)
                            .unwrap();
                        let successor = graph.kernel.commit_exec(prepared, None).unwrap();
                        assert_ne!(successor.shared().mm().id(), old_mm);
                        assert_eq!(wait.released_reason(), Some(VforkReleaseReason::Exec));
                        (successor, VforkReleaseReason::Exec)
                    } else {
                        (child, VforkReleaseReason::Exit)
                    };
                    graph
                        .kernel
                        .exit_task(
                            terminal.task().key().id,
                            LinuxWaitStatus::from_wait_encoding(7 << 8),
                            None,
                        )
                        .unwrap();
                    assert_eq!(wait.released_reason(), Some(reason));
                    graph.reap(parent, &terminal, 7);
                    assert_eq!(
                        wait.released_reason(),
                        Some(reason),
                        "reap duplicated release"
                    );
                    assert_eq!(parent.shared().mm().id(), old_mm);
                    graph.reap(other_parent, &other, 0);
                }
            }
        }
    }
}
