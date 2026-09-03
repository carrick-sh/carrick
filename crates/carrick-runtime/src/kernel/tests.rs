use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use carrick_abi::LinuxGuestAbi;
use carrick_hal::ThreadId;
use carrick_hal::threaded::{
    Aarch64TaskCpuStateV1, GuestCpuState, X86_TASK_RESUME_MAGIC, X86_TASK_RESUME_PAYLOAD_LEN,
    X86_TASK_XSAVE_LEN, X86TaskCpuStateV1,
};

use super::ids::FileDescriptionId;
use super::objects::{
    AsyncIoOwner, BlockedReason, ExecutionFailure, ExecutorId, FileDescription,
    MigratableTaskState, ThreadExecutionError, ThreadExecutionState,
};
use super::{Kernel, RootBootstrap};

#[derive(Debug, Default)]
struct CountingExitSubscriber(AtomicUsize);

impl super::core::TaskExitSubscriber for CountingExitSubscriber {
    fn publish_exit(&self) {
        self.0.fetch_add(1, Ordering::Release);
    }
}

#[test]
fn two_container_roots_share_one_kernel_graph() {
    use carrick_kernel::arena::KernelArena;

    use super::{
        ClonePlan, Container, KernelFailpoint, LaunchContext, LinuxWaitStatus, RunId, WaitMode,
    };
    use crate::namespace::pid::{NsSharedRegion, host_to_ns_or_self_for};

    let arena = Box::leak(Box::new(KernelArena::create().expect("test kernel arena")));
    let alpha = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "alpha",
    ))));
    alpha
        .install_pid_ns(NsSharedRegion::allocate(arena).expect("alpha pid namespace"))
        .expect("install alpha pid namespace");
    let alpha_bootstrap = RootBootstrap::for_reference_model(
        4_100,
        ThreadId::synthetic_for_tests(4_100),
        "alpha-init".to_owned(),
    )
    .expect("alpha bootstrap")
    .with_container(Arc::clone(&alpha));
    let (kernel, alpha_context) = Kernel::bootstrap_root(alpha_bootstrap).expect("alpha root");

    let beta = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new("beta"))));
    beta.install_pid_ns(NsSharedRegion::allocate(arena).expect("beta pid namespace"))
        .expect("install beta pid namespace");
    let prepared_beta = kernel
        .prepare_container_root(
            ThreadId::synthetic_for_tests(4_200),
            None,
            "beta-init".to_owned(),
            Arc::clone(&beta),
            None,
        )
        .expect("prepare beta root");
    let prepared_beta_context = prepared_beta.context();
    let beta_internal =
        u32::try_from(prepared_beta_context.task().key().id.raw()).expect("beta internal pid");
    assert_ne!(
        beta_internal, 1,
        "later roots retain a private scheduler id"
    );
    assert_eq!(
        crate::namespace::pid::try_ns_self_pid_for(&prepared_beta_context, beta_internal),
        Some(1),
        "a prepared container root must expose namespace PID 1 before identity stamping"
    );
    let beta_context = prepared_beta.commit().expect("commit beta root");
    assert_eq!(beta_context.task().key().id.raw() as u32, beta_internal);

    assert!(Arc::ptr_eq(alpha_context.kernel(), beta_context.kernel()));
    assert_eq!(kernel.container_count(), 2);
    assert_ne!(alpha_context.task().key(), beta_context.task().key());
    assert_ne!(alpha_context.thread().key(), beta_context.thread().key());
    assert_ne!(
        alpha_context.task().process_group(),
        beta_context.task().process_group()
    );
    assert_ne!(
        alpha_context.task().session(),
        beta_context.task().session()
    );
    assert_eq!(
        host_to_ns_or_self_for(
            &alpha_context,
            u32::try_from(alpha_context.task().key().id.raw()).expect("alpha internal pid"),
        ),
        1
    );
    assert_eq!(
        host_to_ns_or_self_for(
            &beta_context,
            u32::try_from(beta_context.task().key().id.raw()).expect("beta internal pid"),
        ),
        1
    );
    assert_eq!(
        alpha
            .pid_region()
            .expect("alpha region")
            .host_to_ns(beta_context.task().key().id.raw() as u32),
        None
    );
    assert_eq!(
        beta.pid_region()
            .expect("beta region")
            .host_to_ns(alpha_context.task().key().id.raw() as u32),
        None
    );

    let gamma = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "gamma",
    ))));
    gamma
        .install_pid_ns(NsSharedRegion::allocate(arena).expect("gamma pid namespace"))
        .expect("install gamma pid namespace");
    let prepared_gamma = kernel
        .prepare_container_root(
            ThreadId::synthetic_for_tests(4_300),
            None,
            "gamma-init".to_owned(),
            gamma,
            None,
        )
        .expect("prepare gamma root");
    let stale_gamma_context = prepared_gamma.context();
    let gamma_internal = stale_gamma_context.task().key().id.raw() as u32;
    assert_eq!(
        crate::namespace::pid::try_ns_self_pid_for(&stale_gamma_context, gamma_internal),
        Some(1)
    );
    drop(prepared_gamma);
    assert_eq!(
        crate::namespace::pid::try_ns_self_pid_for(&stale_gamma_context, gamma_internal),
        None,
        "dropping a prepared root must revoke its context-local PID claim"
    );
    assert_eq!(
        kernel.container_init(alpha.id()),
        Some(alpha_context.task().key())
    );
    assert_eq!(
        kernel.container_init(beta.id()),
        Some(beta_context.task().key())
    );
    assert_eq!(
        kernel
            .registry()
            .live_processes_for_container(alpha.id())
            .into_iter()
            .map(|process| process.key)
            .collect::<Vec<_>>(),
        vec![alpha_context.task().key()]
    );
    assert_eq!(
        kernel
            .registry()
            .live_processes_for_container(beta.id())
            .into_iter()
            .map(|process| process.key)
            .collect::<Vec<_>>(),
        vec![beta_context.task().key()]
    );
    assert!(
        kernel
            .tasks_for_broadcast(alpha_context.task().key().id)
            .is_empty()
    );
    assert!(
        kernel
            .tasks_for_broadcast(beta_context.task().key().id)
            .is_empty()
    );

    let child = kernel
        .reserve_fork(
            &alpha_context,
            ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty()).expect("fork plan"),
            "alpha-retained-child".to_owned(),
            None,
        )
        .expect("reserve alpha child")
        .prepare_reference(ThreadId::synthetic_for_tests(4_101))
        .expect("prepare alpha child")
        .commit()
        .expect("commit alpha child")
        .into_parts()
        .expect("start alpha child")
        .0;
    let retained_child = child;
    kernel
        .exit_task_key_eventually(
            retained_child.task().key(),
            LinuxWaitStatus::from_wait_encoding(0),
        )
        .expect("exit alpha child");
    kernel
        .wait_child(
            alpha_context.task().key().id,
            Some(retained_child.task().key().id),
            WaitMode::Consume,
        )
        .expect("reap alpha child before container retirement");
    assert!(
        kernel
            .observations
            .lock()
            .tasks
            .contains_key(&retained_child.task().key()),
        "the retained child context keeps its weak observation live before container retirement",
    );

    let epoch_before_rejected_retire = kernel.registry().state.read().epoch;
    let alpha_teardown = kernel
        .retire_container_root(alpha.id(), Some(KernelFailpoint::AfterObjects))
        .expect_err("injected retirement failure must preserve alpha");
    assert!(alpha_teardown.to_string().contains("injected"));
    assert_eq!(kernel.container_count(), 2);
    assert_eq!(
        kernel.registry().state.read().epoch,
        epoch_before_rejected_retire,
        "rejected retirement must not publish an epoch"
    );
    assert_eq!(
        kernel.container_init(alpha.id()),
        Some(alpha_context.task().key())
    );

    let alpha_teardown = kernel
        .retire_container_root(alpha.id(), None)
        .expect("retire alpha only");
    assert_eq!(alpha_teardown.tasks_reaped, 1);
    assert!(alpha_teardown.pid_region_released);
    assert_eq!(kernel.container_count(), 1);
    assert_eq!(kernel.container_init(alpha.id()), None);
    let observations = kernel.observations.lock();
    assert!(
        !observations.tasks.contains_key(&alpha_context.task().key()),
        "retirement must revoke the selected container's observation edges even while a stale context is retained",
    );
    assert!(
        !observations
            .tasks
            .contains_key(&retained_child.task().key()),
        "retirement must revoke historical task observations even after the task was reaped",
    );
    drop(observations);
    assert_eq!(
        kernel.container_init(beta.id()),
        Some(beta_context.task().key())
    );
    assert!(
        kernel
            .context(
                beta_context.task().key().id,
                beta_context.thread().key().tid
            )
            .is_ok()
    );
}

#[test]
fn container_root_publication_is_all_or_nothing_for_concurrent_readers() {
    use std::sync::{Barrier, mpsc};
    use std::time::Duration;

    use carrick_kernel::arena::KernelArena;

    use super::{Container, LaunchContext, RunId};
    use crate::namespace::pid::NsSharedRegion;

    let arena = Box::leak(Box::new(KernelArena::create().expect("test kernel arena")));
    let alpha = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "publication-alpha",
    ))));
    alpha
        .install_pid_ns(NsSharedRegion::allocate(arena).expect("alpha pid namespace"))
        .expect("install alpha pid namespace");
    let alpha_bootstrap = RootBootstrap::for_reference_model(
        4_401,
        ThreadId::synthetic_for_tests(4_401),
        "publication-alpha-init".to_owned(),
    )
    .expect("alpha bootstrap")
    .with_container(alpha);
    let (kernel, _alpha_context) = Kernel::bootstrap_root(alpha_bootstrap).expect("alpha root");

    let beta = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "publication-beta",
    ))));
    let beta_region = NsSharedRegion::allocate(arena).expect("beta pid namespace");
    beta.install_pid_ns(Arc::clone(&beta_region))
        .expect("install beta pid namespace");
    let prepared = kernel
        .prepare_container_root(
            ThreadId::synthetic_for_tests(4_402),
            None,
            "publication-beta-init".to_owned(),
            Arc::clone(&beta),
            None,
        )
        .expect("prepare beta root");
    let internal_pid =
        u32::try_from(prepared.context().task().key().id.raw()).expect("internal beta pid");

    // Pause after the complete kernel graph is staged under its write locks,
    // but before namespace membership becomes visible. If membership were
    // published first, the direct namespace read below would expose PID 1
    // without a corresponding kernel root. If graph locks were released
    // first, the concurrent graph reader would complete in this interval.
    let staged = Arc::new(Barrier::new(2));
    let publish = Arc::new(Barrier::new(2));
    kernel.install_container_root_publication_barriers(Arc::clone(&staged), Arc::clone(&publish));

    let commit = std::thread::spawn(move || prepared.commit().expect("commit beta root"));
    staged.wait();

    assert_eq!(
        beta_region.host_to_ns(internal_pid),
        None,
        "namespace PID 1 must remain unpublished while the graph is only staged"
    );
    assert_eq!(
        beta.pid_root(),
        None,
        "the container root edge must remain unpublished with its PID membership"
    );
    assert!(
        kernel
            .registry()
            .state
            .try_read_until(std::time::Instant::now())
            .is_none(),
        "the staged registry graph must remain write-locked until PID membership commits"
    );

    let (observed_tx, observed_rx) = mpsc::channel();
    let reader_kernel = Arc::clone(&kernel);
    let reader_beta = Arc::clone(&beta);
    let reader_region = Arc::clone(&beta_region);
    let reader_ready = Arc::new(Barrier::new(2));
    let reader_start = Arc::clone(&reader_ready);
    let reader = std::thread::spawn(move || {
        reader_start.wait();
        let init = reader_kernel.container_init(reader_beta.id());
        let container = reader_kernel.container(reader_beta.id()).is_some();
        let namespace_pid = reader_region.host_to_ns(internal_pid);
        observed_tx
            .send((init, container, namespace_pid))
            .expect("publish observation");
    });
    reader_ready.wait();
    assert!(
        observed_rx.recv_timeout(Duration::from_millis(25)).is_err(),
        "a graph reader must not pass the publication boundary before PID membership commits"
    );

    publish.wait();
    let beta_context = commit.join().expect("commit thread");
    let (init, container, namespace_pid) = observed_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("reader completes after atomic publication");
    reader.join().expect("reader thread");

    assert_eq!(init, Some(beta_context.task().key()));
    assert!(container);
    assert_eq!(namespace_pid, Some(1));
    assert_eq!(beta.pid_root(), Some(beta_context.task().key()));
}

#[test]
fn failed_pid_membership_commit_rolls_back_every_staged_root_edge() {
    use std::sync::Barrier;

    use carrick_kernel::arena::KernelArena;

    use super::{Container, LaunchContext, RunId};
    use crate::namespace::pid::NsSharedRegion;

    let arena = Box::leak(Box::new(KernelArena::create().expect("test kernel arena")));
    let alpha = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "rollback-alpha",
    ))));
    alpha
        .install_pid_ns(NsSharedRegion::allocate(arena).expect("alpha pid namespace"))
        .expect("install alpha pid namespace");
    let alpha_bootstrap = RootBootstrap::for_reference_model(
        4_411,
        ThreadId::synthetic_for_tests(4_411),
        "rollback-alpha-init".to_owned(),
    )
    .expect("alpha bootstrap")
    .with_container(alpha);
    let (kernel, alpha_context) = Kernel::bootstrap_root(alpha_bootstrap).expect("alpha root");
    let baseline_tasks = kernel.registry().task_count();
    let baseline_groups = kernel.registry().process_group_count();
    let baseline_sessions = kernel.registry().session_count();
    let baseline_epoch = kernel.registry().state.read().epoch;

    let beta = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "rollback-beta",
    ))));
    let beta_region = NsSharedRegion::allocate(arena).expect("beta pid namespace");
    beta.install_pid_ns(Arc::clone(&beta_region))
        .expect("install beta pid namespace");
    let prepared = kernel
        .prepare_container_root(
            ThreadId::synthetic_for_tests(4_412),
            None,
            "rollback-beta-init".to_owned(),
            Arc::clone(&beta),
            None,
        )
        .expect("prepare beta root");
    let internal_task = prepared.context().task().key().id;

    let staged = Arc::new(Barrier::new(2));
    let publish = Arc::new(Barrier::new(2));
    kernel.install_container_root_publication_barriers(Arc::clone(&staged), Arc::clone(&publish));
    let commit = std::thread::spawn(move || prepared.commit());
    staged.wait();
    assert!(
        Arc::clone(&beta_region).retire(),
        "retiring the prepared namespace forces the final membership edge to fail"
    );
    publish.wait();
    let error = commit
        .join()
        .expect("commit thread")
        .expect_err("retired PID namespace must reject root publication");
    assert!(matches!(
        error,
        super::KernelError::PidNamespaceMembership(id) if id == beta.id()
    ));

    assert_eq!(beta.pid_root(), None);
    assert!(kernel.container(beta.id()).is_none());
    assert_eq!(kernel.container_init(beta.id()), None);
    assert_eq!(kernel.registry().task_count(), baseline_tasks);
    assert_eq!(kernel.registry().process_group_count(), baseline_groups);
    assert_eq!(kernel.registry().session_count(), baseline_sessions);
    assert_eq!(kernel.registry().state.read().epoch, baseline_epoch);
    assert!(
        kernel
            .context(
                alpha_context.task().key().id,
                alpha_context.thread().key().tid,
            )
            .is_ok(),
        "the sibling root remains usable after rollback"
    );

    kernel.ids().set_next_for_tests(internal_task.raw());
    let successor = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "rollback-successor",
    ))));
    successor
        .install_pid_ns(NsSharedRegion::allocate(arena).expect("successor pid namespace"))
        .expect("install successor pid namespace");
    let successor = kernel
        .prepare_container_root(
            ThreadId::synthetic_for_tests(4_413),
            None,
            "rollback-successor-init".to_owned(),
            successor,
            None,
        )
        .expect("reclaim rolled-back identities")
        .commit()
        .expect("publish successor root");
    assert_eq!(successor.task().key().id, internal_task);
}

#[test]
fn same_visible_process_group_is_selected_only_inside_its_container() {
    use carrick_abi::LinuxCloneFlags;
    use carrick_kernel::arena::KernelArena;

    use super::{ClonePlan, Container, LaunchContext, LinuxSignal, RunId};
    use crate::kernel::ExactSignalTargetAuthorization;
    use crate::namespace::pid::NsSharedRegion;

    let arena = Box::leak(Box::new(KernelArena::create().expect("test kernel arena")));
    let alpha = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "group-index-alpha",
    ))));
    alpha
        .install_pid_ns(NsSharedRegion::allocate(arena).expect("alpha pid namespace"))
        .expect("install alpha pid namespace");
    let alpha_bootstrap = RootBootstrap::for_reference_model(
        4_600,
        ThreadId::synthetic_for_tests(4_600),
        "group-index-alpha-init".to_owned(),
    )
    .expect("alpha bootstrap")
    .with_container(Arc::clone(&alpha));
    let (kernel, alpha_root) = Kernel::bootstrap_root(alpha_bootstrap).expect("alpha root");

    let beta = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "group-index-beta",
    ))));
    beta.install_pid_ns(NsSharedRegion::allocate(arena).expect("beta pid namespace"))
        .expect("install beta pid namespace");
    let beta_root = kernel
        .prepare_container_root(
            ThreadId::synthetic_for_tests(4_700),
            None,
            "group-index-beta-init".to_owned(),
            Arc::clone(&beta),
            None,
        )
        .expect("prepare beta root")
        .commit()
        .expect("commit beta root");

    let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
    let alpha_child = kernel
        .fork_task(
            &alpha_root,
            plan,
            ThreadId::synthetic_for_tests(4_601),
            "alpha child".to_owned(),
            None,
        )
        .expect("alpha child");
    let beta_child = kernel
        .fork_task(
            &beta_root,
            plan,
            ThreadId::synthetic_for_tests(4_701),
            "beta child".to_owned(),
            None,
        )
        .expect("beta child");
    let alpha_group = kernel
        .create_process_group(alpha_child.task().key().id, None)
        .expect("alpha child group");
    let beta_group = kernel
        .create_process_group(beta_child.task().key().id, None)
        .expect("beta child group");
    assert_ne!(alpha_group, beta_group);

    let sigusr1 = LinuxSignal::for_signal_number(10).expect("SIGUSR1");
    let alpha_targets = kernel
        .authorize_namespace_process_group_signal_targets_exact(&alpha_root, 2, Some(sigusr1))
        .expect("alpha visible group 2");
    let alpha_ticket = alpha_targets
        .into_iter()
        .find_map(|authorization| match authorization {
            ExactSignalTargetAuthorization::Allowed(ticket) => Some(ticket),
            _ => None,
        })
        .expect("alpha child authorization");
    assert!(kernel.post_signal_to_authorized_target(&alpha_ticket, sigusr1, None));
    assert!(
        alpha_child
            .task()
            .shared()
            .pending_signals()
            .present()
            .contains(sigusr1.raw())
    );
    assert!(
        !beta_child
            .task()
            .shared()
            .pending_signals()
            .present()
            .contains(sigusr1.raw()),
        "the same visible pgid in beta must remain invisible to alpha",
    );
    assert_eq!(kernel.validate_invariants(), Ok(()));
}

#[test]
fn fork_and_thread_clone_allocate_namespace_local_identity() {
    use carrick_abi::LinuxCloneFlags;
    use carrick_kernel::arena::KernelArena;

    use super::{
        ClonePlan, Container, LaunchContext, LinuxTid, LinuxWaitStatus, RunId, WaitMode,
        WaitOutcome,
    };
    use crate::namespace::pid::{NsSharedRegion, guest_tid_to_kernel_for};

    let arena = Box::leak(Box::new(KernelArena::create().expect("test kernel arena")));
    let container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "namespace-local-identities",
    ))));
    let region = NsSharedRegion::allocate(arena).expect("pid namespace");
    container
        .install_pid_ns(Arc::clone(&region))
        .expect("install pid namespace");
    let bootstrap = RootBootstrap::for_reference_model(
        4_100,
        ThreadId::synthetic_for_tests(4_100),
        "namespace-local-init".to_owned(),
    )
    .expect("bootstrap")
    .with_container(container);
    let (kernel, root) = Kernel::bootstrap_root(bootstrap).expect("root");

    let fork_plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
    let reservation = kernel
        .reserve_fork(&root, fork_plan, "child".to_owned(), None)
        .expect("fork reservation");
    let child_internal = reservation.child_id();
    assert_eq!(reservation.visible_child_id(), 2);
    let prepared_child = reservation
        .prepare_reference(ThreadId::synthetic_for_tests(4_101))
        .expect("prepare child");
    assert_eq!(prepared_child.visible_child_id(), 2);
    let published_child = prepared_child.commit().expect("commit child");
    assert_eq!(published_child.visible_child_id(), 2);
    let child = published_child.into_parts().expect("start child").0;
    assert_ne!(child_internal.raw(), 2);
    assert_eq!(region.host_to_ns(child_internal.raw() as u32), Some(2));
    assert_eq!(
        crate::namespace::pid::ns_self_pid_for(&child, child_internal.raw() as u32),
        2
    );

    let root = kernel
        .context(root.task().key().id, root.thread().key().tid)
        .expect("refresh root");
    let thread_plan = ClonePlan::from_flags(
        LinuxCloneFlags::THREAD | LinuxCloneFlags::VM | LinuxCloneFlags::SIGHAND,
    )
    .expect("thread plan");
    let thread = kernel
        .reserve_thread_clone(&root, thread_plan, None)
        .expect("thread reservation");
    let internal_tid = thread.tid();
    assert_eq!(thread.visible_tid(), 3);
    let prepared_thread = thread
        .prepare(ThreadId::synthetic_for_tests(4_102))
        .expect("prepare thread");
    assert_eq!(prepared_thread.visible_tid(), 3);
    let published_thread = prepared_thread.commit().expect("commit thread");
    assert_eq!(published_thread.visible_tid(), 3);
    let thread = published_thread.into_context().expect("start thread");
    assert_ne!(internal_tid.raw(), 3);
    assert_eq!(region.host_to_ns(internal_tid.raw() as u32), Some(3));
    assert_eq!(
        guest_tid_to_kernel_for(&thread, 3),
        Some(internal_tid.raw())
    );
    assert_eq!(guest_tid_to_kernel_for(&thread, child_internal.raw()), None);
    assert_eq!(
        LinuxTid::for_task_leader(child.task().key().id).raw(),
        child_internal.raw()
    );

    kernel
        .exit_thread(&thread, None)
        .expect("retire secondary thread");
    assert_eq!(guest_tid_to_kernel_for(&thread, 3), None);

    let child_thread = kernel
        .reserve_thread_clone(&child, thread_plan, None)
        .expect("child thread reservation")
        .prepare(ThreadId::synthetic_for_tests(4_103))
        .expect("prepare child thread")
        .commit()
        .expect("commit child thread")
        .into_context()
        .expect("start child thread");
    let child_thread_internal =
        u32::try_from(child_thread.thread().key().tid.raw()).expect("child thread internal tid");
    assert_eq!(region.host_to_ns(child_thread_internal), Some(4));
    kernel
        .exit_task_key_eventually(child.task().key(), LinuxWaitStatus::from_wait_encoding(0))
        .expect("exit child");
    assert_eq!(
        region.host_to_ns(child_thread_internal),
        None,
        "whole-process exit must release every secondary namespace tid immediately"
    );
    let refreshed_root = kernel
        .context(root.task().key().id, root.thread().key().tid)
        .expect("refresh root for wait");
    let WaitOutcome::Exited(zombie) = kernel
        .wait_child(
            refreshed_root.task().key().id,
            Some(child_internal),
            WaitMode::Consume,
        )
        .expect("consume child zombie")
    else {
        panic!("child exit was not waitable");
    };
    assert_eq!(
        zombie.namespace_pid, 2,
        "the consuming wait receipt must retain the child's visible pid after reaping its mapping"
    );
    assert_eq!(
        crate::namespace::pid::try_ns_self_pid_for(&child, child_internal.raw() as u32),
        None,
        "a missing namespaced self mapping must not leak the internal task id"
    );
}

#[test]
fn failed_container_root_preparation_publishes_no_identity_or_epoch() {
    use carrick_kernel::arena::KernelArena;

    use super::{Container, KernelFailpoint, LaunchContext, RunId};
    use crate::namespace::pid::{NS_INIT_PID, NsSharedRegion};

    let (kernel, root) = bootstrap(4_300);
    let epoch = kernel.registry().state.read().epoch;
    let arena = Box::leak(Box::new(KernelArena::create().expect("test kernel arena")));
    let container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "failed-root",
    ))));
    let region = NsSharedRegion::allocate(arena).expect("pid namespace");
    container
        .install_pid_ns(Arc::clone(&region))
        .expect("install pid namespace");

    let error = kernel
        .prepare_container_root(
            ThreadId::synthetic_for_tests(4_301),
            None,
            "failed-init".to_owned(),
            Arc::clone(&container),
            Some(KernelFailpoint::AfterObjects),
        )
        .expect_err("injected preparation failure");
    assert!(error.to_string().contains("injected"));
    assert_eq!(container.pid_root(), None);
    assert_eq!(region.ns_to_host(NS_INIT_PID), None);
    assert_eq!(kernel.registry().state.read().epoch, epoch);
    assert!(
        kernel
            .context(root.task().key().id, root.thread().key().tid)
            .is_ok(),
        "the existing root context remains valid"
    );
}

#[test]
fn container_retirement_uses_task_exit_settlement_before_reaping() {
    use carrick_abi::LinuxCloneFlags;
    use carrick_kernel::arena::KernelArena;

    use super::{
        ClonePlan, Container, KernelFailpoint, LaunchContext, LinuxWaitStatus, RunId,
        VforkReleaseReason,
    };
    use crate::namespace::pid::NsSharedRegion;

    let arena = Box::leak(Box::new(KernelArena::create().expect("test kernel arena")));
    let container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "retirement-settlement",
    ))));
    container
        .install_pid_ns(NsSharedRegion::allocate(arena).expect("pid namespace"))
        .expect("install pid namespace");
    let bootstrap = RootBootstrap::for_reference_model(
        4_400,
        ThreadId::synthetic_for_tests(4_400),
        "retirement-init".to_owned(),
    )
    .expect("bootstrap")
    .with_container(Arc::clone(&container));
    let (kernel, root) = Kernel::bootstrap_root(bootstrap).expect("root");

    let child = kernel
        .reserve_fork(
            &root,
            ClonePlan::from_flags(LinuxCloneFlags::VFORK | LinuxCloneFlags::VM)
                .expect("vfork plan"),
            "vfork child".to_owned(),
            None,
        )
        .expect("reserve vfork")
        .prepare_reference(ThreadId::synthetic_for_tests(4_401))
        .expect("prepare vfork")
        .commit()
        .expect("publish vfork");
    let (child, wait) = child.into_parts().expect("start vfork child");
    let wait = wait.expect("vfork wait");
    let subscriber = Arc::new(CountingExitSubscriber::default());
    assert_eq!(
        kernel.register_task_exit_subscriber(child.task().key().id, &subscriber),
        Some(child.task().key())
    );

    let refreshed_root = kernel
        .context(root.task().key().id, root.thread().key().tid)
        .expect("refresh root");
    let orphan = kernel
        .reserve_fork(
            &refreshed_root,
            ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
            "orphan zombie".to_owned(),
            None,
        )
        .expect("reserve orphan")
        .prepare_reference(ThreadId::synthetic_for_tests(4_402))
        .expect("prepare orphan")
        .commit()
        .expect("publish orphan")
        .into_parts()
        .expect("start orphan")
        .0;
    kernel
        .exit_task_key_eventually(orphan.task().key(), LinuxWaitStatus::from_wait_encoding(0))
        .expect("exit orphan");
    kernel
        .registry()
        .state
        .write()
        .zombies
        .get_mut(&orphan.task().key().id)
        .expect("orphan zombie")
        .zombie
        .parent = None;

    let epoch = kernel.registry().state.read().epoch;
    assert!(
        kernel
            .retire_container_root(container.id(), Some(KernelFailpoint::AfterObjects))
            .is_err()
    );
    assert_eq!(kernel.registry().state.read().epoch, epoch);
    assert_eq!(subscriber.0.load(Ordering::Acquire), 0);
    assert_eq!(wait.released_reason(), None);
    let refreshed_root = kernel
        .context(root.task().key().id, root.thread().key().tid)
        .expect("root remains live after rejected retirement");
    drop(
        kernel
            .reserve_fork(
                &refreshed_root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                "post-failure reservation".to_owned(),
                None,
            )
            .expect("rejected retirement must not close fork admission"),
    );

    let teardown = kernel
        .retire_container_root(container.id(), None)
        .expect("retire container");

    assert_eq!(teardown.tasks_reaped, 3);
    assert_eq!(subscriber.0.load(Ordering::Acquire), 1);
    assert_eq!(wait.released_reason(), Some(VforkReleaseReason::Exit));
    assert!(
        kernel
            .registry()
            .zombies_for_container(container.id())
            .is_empty()
    );
}

#[test]
fn retirement_reused_tid_cannot_alias_a_surviving_stale_thread_ref() {
    use carrick_abi::LinuxCloneFlags;
    use carrick_kernel::arena::KernelArena;

    use super::{ClonePlan, Container, LaunchContext, RunId};
    use crate::namespace::pid::NsSharedRegion;

    let arena = Box::leak(Box::new(KernelArena::create().expect("test kernel arena")));
    let container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "stale-thread-retirement",
    ))));
    container
        .install_pid_ns(NsSharedRegion::allocate(arena).expect("pid namespace"))
        .expect("install pid namespace");
    let bootstrap = RootBootstrap::for_reference_model(
        4_500,
        ThreadId::synthetic_for_tests(4_500),
        "retirement-init".to_owned(),
    )
    .expect("bootstrap")
    .with_container(Arc::clone(&container));
    let (kernel, root) = Kernel::bootstrap_root(bootstrap).expect("root");
    let child = kernel
        .fork_task(
            &root,
            ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
            ThreadId::synthetic_for_tests(4_501),
            "stale child".to_owned(),
            None,
        )
        .expect("fork child");
    let reused_id = child.task().key().id;
    let old_thread_key = child.thread().key();
    let stale_thread = Arc::clone(child.thread());
    let stale_binding = child.task_binding();

    kernel
        .retire_container_root(container.id(), None)
        .expect("retire container");
    drop(child);
    kernel.ids().set_next_for_tests(reused_id.raw());

    let successor = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "successor",
    ))));
    successor
        .install_pid_ns(NsSharedRegion::allocate(arena).expect("successor pid namespace"))
        .expect("install successor pid namespace");
    let successor_context = kernel
        .prepare_container_root(
            ThreadId::synthetic_for_tests(4_502),
            None,
            "successor-init".to_owned(),
            successor,
            None,
        )
        .expect("prepare successor after stale ref drains")
        .commit()
        .expect("publish successor");
    assert_ne!(
        successor_context.task().key().id,
        reused_id,
        "the shared allocator must skip the tid while a stale thread Arc keeps its claim live"
    );
    assert_eq!(stale_thread.key(), old_thread_key);
    drop(stale_thread);
    kernel.sweep_retired_threads();
    kernel.ids().set_next_for_tests(reused_id.raw());

    let reused = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
        "reused-successor",
    ))));
    reused
        .install_pid_ns(NsSharedRegion::allocate(arena).expect("reused pid namespace"))
        .expect("install reused pid namespace");
    let reused_context = kernel
        .prepare_container_root(
            ThreadId::synthetic_for_tests(4_503),
            None,
            "reused-successor-init".to_owned(),
            reused,
            None,
        )
        .expect("prepare exact numeric reuse after stale ref drains")
        .commit()
        .expect("publish reused successor");
    assert_eq!(reused_context.task().key().id, reused_id);
    assert_ne!(reused_context.thread().key(), old_thread_key);
    assert!(
        stale_binding.capture(old_thread_key.tid).is_err(),
        "an exact old task generation must not capture the reused numeric tid"
    );
}

#[test]
fn retirement_close_rejects_prepared_thread_and_new_fork_admission() {
    use carrick_abi::LinuxCloneFlags;

    use super::{ClonePlan, KernelOperationError};

    let (kernel, root) = bootstrap(4_600);
    let prepared_thread = kernel
        .reserve_thread_clone(
            &root,
            ClonePlan::from_flags(
                LinuxCloneFlags::THREAD | LinuxCloneFlags::VM | LinuxCloneFlags::SIGHAND,
            )
            .expect("thread plan"),
            None,
        )
        .expect("reserve thread before close")
        .prepare(ThreadId::synthetic_for_tests(4_601))
        .expect("prepare thread before close");
    root.container().begin_retirement();

    assert!(matches!(
        prepared_thread.try_reserve_publication(),
        Err(KernelOperationError::ParentExited)
    ));
    assert!(matches!(
        kernel.reserve_fork(
            &root,
            ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
            "rejected child".to_owned(),
            None,
        ),
        Err(KernelOperationError::ParentExited)
    ));
}

fn bootstrap(pid: i32) -> (Arc<Kernel>, super::KernelContext) {
    let input = RootBootstrap::for_reference_model(
        pid,
        ThreadId::synthetic_for_tests(pid),
        "thread execution state test".to_owned(),
    )
    .expect("bootstrap input");
    Kernel::bootstrap_root(input).expect("kernel")
}

fn aarch64_test_task_state() -> Aarch64TaskCpuStateV1 {
    Aarch64TaskCpuStateV1 {
        gprs: std::array::from_fn(|index| index as u64 + 1),
        pc: 0x1000,
        pstate: 0x2000,
        trap_pc: 0x2100,
        trap_pstate: 0x2200,
        sp_el0: 0x3000,
        elr_el1: 0x3100,
        spsr_el1: 0x3200,
        ttbr0: 0x4000,
        ttbr1: 0x5000,
        tcr: 0x6000,
        sctlr_el1: 0x6100,
        mair_el1: 0x6200,
        vbar_el1: 0x6300,
        cpacr_el1: 0x6400,
        cntkctl_el1: 0x6500,
        tpidr_el1: 0x6600,
        actlr_el1: 0x7000,
        tpidr_el0: 0x8000,
        tpidrro_el0: 0x9000,
        contextidr_el1: 0xa000,
        vregs: std::array::from_fn(|index| index as u128 + 0x100),
        fpsr: 0x1100,
        fpcr: 0x1200,
        pending_resume_pc: Some(0x1300),
        last_syscall_nr: Some(221),
        last_syscall_orig_x0: 0x1400,
        last_fault_esr: 0x1500,
        last_exit_class: 0x16,
        is_forked_child: false,
        syscall_continuation: None,
        mm_generation: 17,
        asid_generation: 19,
    }
}

fn x86_test_task_state() -> X86TaskCpuStateV1 {
    let mut resume = vec![0; X86_TASK_RESUME_PAYLOAD_LEN];
    resume[56..64].copy_from_slice(&X86_TASK_RESUME_MAGIC.to_le_bytes());
    X86TaskCpuStateV1::new(
        std::array::from_fn(|index| index as u64 + 0x20),
        0x2000,
        0x202,
        0x3000,
        0x4000,
        0x5000,
        0x6000,
        0x7000,
        0x8000,
        0x9000,
        23,
        29,
        vec![0x5a; X86_TASK_XSAVE_LEN],
        resume,
    )
    .expect("valid x86 task state")
}

fn migratable(context: &super::KernelContext, cpu: GuestCpuState) -> MigratableTaskState {
    let mm = context.shared().mm().id();
    let cpu = match cpu {
        GuestCpuState::Aarch64V1(state) => {
            let mut state = (*state).clone();
            state.mm_generation = mm.raw();
            state.asid_generation = mm.raw();
            GuestCpuState::from_aarch64_v1(state)
        }
        GuestCpuState::X86_64V1(state) => GuestCpuState::from_x86_64_v1(
            X86TaskCpuStateV1::new(
                *state.gprs(),
                state.rip(),
                state.rflags(),
                state.rsp(),
                state.cr0(),
                state.cr3(),
                state.cr4(),
                state.efer(),
                state.fs_base(),
                state.gs_base(),
                mm.raw(),
                mm.raw(),
                state.xsave().to_vec(),
                state.resume_payload().to_vec(),
            )
            .unwrap(),
        )
        .unwrap(),
    };
    MigratableTaskState {
        cpu,
        mm,
        asid_generation: mm.raw(),
    }
}

#[test]
fn thread_execution_claims_exact_generation_and_parks() {
    let (_kernel, context) = bootstrap(9100);
    let thread = context.thread();
    let state = GuestCpuState::from_aarch64_v1(aarch64_test_task_state());
    let generation = thread
        .publish_initial_task_state(migratable(&context, state))
        .unwrap();
    let lease = thread
        .claim_runnable(ExecutorId::synthetic_for_tests(7))
        .unwrap();
    assert_eq!(lease.generation(), generation);
    assert!(
        thread
            .claim_runnable(ExecutorId::synthetic_for_tests(8))
            .is_err()
    );
    thread
        .park_from_executor(lease, BlockedReason::ChildState)
        .unwrap();
    assert!(matches!(
        thread.execution_state(),
        ThreadExecutionState::Blocked { .. }
    ));
}

#[test]
fn thread_execution_rejects_same_key_lease_from_another_kernel() {
    let (_kernel, context) = bootstrap(9108);
    let (_other_kernel, other) = bootstrap(9108);
    let state = GuestCpuState::from_aarch64_v1(aarch64_test_task_state());
    context
        .thread()
        .publish_initial_task_state(migratable(&context, state.clone()))
        .unwrap();
    other
        .thread()
        .publish_initial_task_state(migratable(&other, state))
        .unwrap();
    let executor = ExecutorId::synthetic_for_tests(10);
    let local_lease = context.thread().claim_runnable(executor).unwrap();
    let foreign_lease = other.thread().claim_runnable(executor).unwrap();

    assert_eq!(context.thread().key(), other.thread().key());
    assert_eq!(context.shared().mm().id(), other.shared().mm().id());
    assert_eq!(
        context.thread().execution_state(),
        other.thread().execution_state()
    );
    let (error, foreign_lease) = context
        .thread()
        .park_from_executor(foreign_lease, BlockedReason::ChildState)
        .expect_err("a numerically identical foreign owner must be rejected");
    assert!(matches!(
        error,
        ThreadExecutionError::LeaseOwnerMismatch { .. }
    ));

    context
        .thread()
        .park_from_executor(local_lease, BlockedReason::ChildState)
        .unwrap();
    other
        .thread()
        .park_from_executor(foreign_lease, BlockedReason::ChildState)
        .unwrap();
}

#[test]
fn thread_execution_switching_out_preserves_exact_owner() {
    let (_kernel, context) = bootstrap(9107);
    let thread = context.thread();
    let generation = thread
        .publish_initial_task_state(migratable(
            &context,
            GuestCpuState::from_aarch64_v1(aarch64_test_task_state()),
        ))
        .unwrap();
    let executor = ExecutorId::synthetic_for_tests(9);
    let lease = thread.claim_runnable(executor).unwrap();
    let executor_epoch = lease.executor_epoch();

    thread.begin_switch_out(&lease).unwrap();
    assert_eq!(
        thread.execution_state(),
        ThreadExecutionState::SwitchingOut {
            generation,
            executor,
            executor_epoch,
            wake_pending: false,
        }
    );
    thread.yield_from_executor(lease).unwrap();
}

#[test]
fn exec_invalidation_cannot_revoke_a_switching_out_lease_before_destructive_save() {
    let (_kernel, context) = bootstrap(9112);
    let thread = context.thread();
    thread
        .publish_initial_task_state(migratable(
            &context,
            GuestCpuState::from_aarch64_v1(aarch64_test_task_state()),
        ))
        .unwrap();
    let executor = ExecutorId::synthetic_for_tests(51);
    let mut lease = thread.claim_runnable(executor).unwrap();
    thread.begin_switch_out(&lease).unwrap();

    thread.invalidate_execution_for_exec();
    assert!(matches!(
        thread.execution_state(),
        ThreadExecutionState::SwitchingOut { .. }
    ));

    lease
        .replace_task_state(migratable(
            &context,
            GuestCpuState::from_aarch64_v1(aarch64_test_task_state()),
        ))
        .unwrap();
    thread
        .park_from_executor(lease, BlockedReason::HostWait)
        .unwrap();
    assert!(matches!(
        thread.execution_state(),
        ThreadExecutionState::Exited { .. }
    ));
}

#[test]
fn thread_execution_reclaim_publishes_and_reclaims_exact_typed_state() {
    let (_kernel, context) = bootstrap(9108);
    let thread = context.thread();
    let initial = GuestCpuState::from_aarch64_v1(aarch64_test_task_state());
    thread
        .publish_initial_task_state(migratable(&context, initial))
        .unwrap();
    let executor = ExecutorId::for_transitional_thread(ThreadId::synthetic_for_tests(9108))
        .expect("transitional executor");
    let mut lease = thread.claim_runnable(executor).unwrap();
    let mut replacement = aarch64_test_task_state();
    replacement.gprs[0] = 0xfeed;
    let replacement = GuestCpuState::from_aarch64_v1(replacement);
    let replacement = migratable(&context, replacement);
    lease.replace_task_state(replacement.clone()).unwrap();
    thread.begin_switch_out(&lease).unwrap();
    thread
        .park_from_executor(lease, BlockedReason::HostWait)
        .unwrap();

    let resumed = thread
        .claim_blocked_for_transitional_executor(executor)
        .expect("claim exact blocked generation");
    assert_eq!(
        resumed
            .task_state_for_restore(
                LinuxGuestAbi::Aarch64,
                1,
                context.shared().mm().id(),
                context.shared().mm().id().raw(),
            )
            .unwrap()
            .cpu,
        replacement.cpu
    );
    thread.exit_from_executor(resumed).unwrap();
}

#[test]
fn thread_execution_lease_owns_complete_mm_and_asid_authority() {
    let (_kernel, context) = bootstrap(9109);
    let thread = context.thread();
    let mm = context.shared().mm().id();
    let mut cpu = aarch64_test_task_state();
    cpu.mm_generation = mm.raw();
    cpu.asid_generation = 37;
    let state = MigratableTaskState {
        cpu: GuestCpuState::from_aarch64_v1(cpu),
        mm,
        asid_generation: 37,
    };

    thread
        .publish_initial_task_state(state.clone())
        .expect("publish complete task authority");
    let lease = thread
        .claim_runnable(ExecutorId::synthetic_for_tests(37))
        .expect("claim complete task authority");
    assert_eq!(
        lease
            .task_state_for_restore(LinuxGuestAbi::Aarch64, 1, mm, 37)
            .expect("exact MM/ASID restore"),
        &state
    );
    thread.exit_from_executor(lease).unwrap();
}

#[test]
fn thread_execution_x86_rejects_invalid_xsave_and_resume_payload_sizes() {
    let valid_xsave = vec![0; X86_TASK_XSAVE_LEN];
    let mut valid_resume = vec![0; X86_TASK_RESUME_PAYLOAD_LEN];
    valid_resume[56..64].copy_from_slice(&X86_TASK_RESUME_MAGIC.to_le_bytes());

    assert!(
        X86TaskCpuStateV1::new(
            [0; 16],
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            1,
            valid_xsave[..valid_xsave.len() - 1].to_vec(),
            valid_resume.clone(),
        )
        .is_err()
    );
    assert!(
        X86TaskCpuStateV1::new(
            [0; 16],
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            1,
            valid_xsave,
            valid_resume[..valid_resume.len() - 1].to_vec(),
        )
        .is_err()
    );
}

#[test]
fn thread_execution_restore_rejects_wrong_architecture_and_version() {
    let (_kernel, context) = bootstrap(9101);
    let thread = context.thread();
    thread
        .publish_initial_task_state(migratable(
            &context,
            GuestCpuState::from_aarch64_v1(aarch64_test_task_state()),
        ))
        .unwrap();
    let lease = thread
        .claim_runnable(ExecutorId::synthetic_for_tests(11))
        .unwrap();

    assert!(matches!(
        lease.task_state_for_restore(
            LinuxGuestAbi::X86_64,
            1,
            context.shared().mm().id(),
            context.shared().mm().id().raw(),
        ),
        Err(ThreadExecutionError::SnapshotArchitectureMismatch { .. })
    ));
    assert!(matches!(
        lease.task_state_for_restore(
            LinuxGuestAbi::Aarch64,
            2,
            context.shared().mm().id(),
            context.shared().mm().id().raw(),
        ),
        Err(ThreadExecutionError::SnapshotVersionMismatch { .. })
    ));
    assert!(
        lease
            .task_state_for_restore(
                LinuxGuestAbi::Aarch64,
                1,
                context.shared().mm().id(),
                context.shared().mm().id().raw(),
            )
            .is_ok()
    );
    thread.yield_from_executor(lease).unwrap();
}

#[test]
fn thread_execution_stale_owner_and_generation_cannot_settle() {
    let (_kernel_a, context_a) = bootstrap(9102);
    let (_kernel_b, context_b) = bootstrap(9103);
    let thread_a = context_a.thread();
    let thread_b = context_b.thread();
    thread_a
        .publish_initial_task_state(migratable(
            &context_a,
            GuestCpuState::from_aarch64_v1(aarch64_test_task_state()),
        ))
        .unwrap();
    thread_b
        .publish_initial_task_state(migratable(
            &context_b,
            GuestCpuState::from_x86_64_v1(x86_test_task_state()).unwrap(),
        ))
        .unwrap();

    let wrong_owner_lease = thread_a
        .claim_runnable(ExecutorId::synthetic_for_tests(21))
        .unwrap();
    let (error, wrong_owner_lease) = thread_b
        .yield_from_executor(wrong_owner_lease)
        .expect_err("wrong owner must return the unsettled lease");
    assert!(matches!(
        error,
        ThreadExecutionError::LeaseOwnerMismatch { .. }
    ));
    assert!(matches!(
        thread_a.execution_state(),
        ThreadExecutionState::Running { .. }
    ));
    thread_a
        .yield_from_executor(wrong_owner_lease)
        .expect("true owner settles returned lease");
    assert!(matches!(
        thread_a.execution_state(),
        ThreadExecutionState::Runnable { .. }
    ));
    assert!(matches!(
        thread_b.execution_state(),
        ThreadExecutionState::Runnable { .. }
    ));

    let stale_lease = thread_b
        .claim_runnable(ExecutorId::synthetic_for_tests(22))
        .unwrap();
    thread_b.invalidate_execution_for_exec();
    assert!(matches!(
        thread_b.park_from_executor(stale_lease, BlockedReason::ChildState),
        Err((ThreadExecutionError::StaleLease { .. }, _))
    ));
    assert!(matches!(
        thread_b.execution_state(),
        ThreadExecutionState::Exited { .. }
    ));

    let (_kernel_c, context_c) = bootstrap(9104);
    let thread_c = context_c.thread();
    thread_c
        .publish_initial_task_state(migratable(
            &context_c,
            GuestCpuState::from_aarch64_v1(aarch64_test_task_state()),
        ))
        .unwrap();
    let stale_exit_lease = thread_c
        .claim_runnable(ExecutorId::synthetic_for_tests(23))
        .unwrap();
    thread_c.invalidate_execution_for_exec();
    assert!(matches!(
        thread_c.exit_from_executor(stale_exit_lease),
        Err((ThreadExecutionError::StaleLease { .. }, _))
    ));
    assert!(matches!(
        thread_c.execution_state(),
        ThreadExecutionState::Exited { .. }
    ));
}

#[test]
fn thread_execution_dropped_unsettled_lease_fails_closed() {
    let (_kernel, context) = bootstrap(9105);
    let thread = context.thread();
    let generation = thread
        .publish_initial_task_state(migratable(
            &context,
            GuestCpuState::from_aarch64_v1(aarch64_test_task_state()),
        ))
        .unwrap();
    let lease = thread
        .claim_runnable(ExecutorId::synthetic_for_tests(31))
        .unwrap();
    drop(lease);

    assert!(matches!(
        thread.execution_state(),
        ThreadExecutionState::Failed {
            generation: failed_generation,
            reason: ExecutionFailure::UnsettledLeaseDropped { .. },
        } if failed_generation != generation
    ));
}

#[test]
fn thread_execution_exec_transfers_runner_and_accounting_not_cpu_state() {
    let (kernel, context) = bootstrap(9106);
    let old_thread = Arc::clone(context.thread());
    old_thread
        .publish_initial_task_state(migratable(
            &context,
            GuestCpuState::from_aarch64_v1(aarch64_test_task_state()),
        ))
        .unwrap();
    old_thread.charge_user_ns(17_000);
    old_thread.charge_system_ns(9_000);
    let mut runner = old_thread.bind_runner().expect("old runner");

    let prepared = kernel.prepare_exec(&context, None).expect("prepare exec");
    let committed = kernel.commit_exec(prepared, None).expect("commit exec");
    let replacement = committed.thread();
    runner
        .adopt_thread(replacement)
        .expect("runner ownership transferred");
    // The exec syscall wrapper still holds the captured predecessor context
    // until it charges the complete service interval after publication.
    old_thread.charge_system_ns(2_000);

    assert!(matches!(
        old_thread.execution_state(),
        ThreadExecutionState::Exited { .. }
    ));
    assert_eq!(replacement.system_cpu_us(), 11);
    assert_eq!(replacement.cpu_us(), 17);
    assert_eq!(
        replacement.execution_state(),
        ThreadExecutionState::Uninitialized
    );

    let seeded = GuestCpuState::from_x86_64_v1(x86_test_task_state()).unwrap();
    replacement
        .publish_initial_task_state(migratable(&committed, seeded))
        .unwrap();
    let lease = replacement
        .claim_runnable(ExecutorId::synthetic_for_tests(41))
        .unwrap();
    assert!(
        lease
            .task_state_for_restore(
                LinuxGuestAbi::X86_64,
                1,
                committed.shared().mm().id(),
                committed.shared().mm().id().raw(),
            )
            .is_ok()
    );
    assert!(
        lease
            .task_state_for_restore(
                LinuxGuestAbi::Aarch64,
                1,
                committed.shared().mm().id(),
                committed.shared().mm().id().raw(),
            )
            .is_err()
    );
    replacement.exit_from_executor(lease).unwrap();
}

#[test]
fn thread_execution_cpu_intervals_never_inherit_between_logical_tasks() {
    let (_kernel_a, context_a) = bootstrap(9110);
    let (_kernel_b, context_b) = bootstrap(9111);
    let thread_a = context_a.thread();
    let thread_b = context_b.thread();

    thread_a.charge_user_ns(11_000);
    thread_a.charge_system_ns(13_000);
    thread_b.charge_user_ns(17_000);
    thread_b.charge_system_ns(19_000);

    assert_eq!((thread_a.cpu_us(), thread_a.system_cpu_us()), (11, 13));
    assert_eq!((thread_b.cpu_us(), thread_b.system_cpu_us()), (17, 19));
    assert_eq!(context_a.task().self_cpu_us(), 11);
    assert_eq!(context_a.task().self_system_cpu_us(), 13);
    assert_eq!(context_b.task().self_cpu_us(), 17);
    assert_eq!(context_b.task().self_system_cpu_us(), 19);
}

#[test]
fn description_common_survives_the_closed_transition_and_counts_fd_refs() {
    let description = FileDescription::regular(
        FileDescriptionId::from_raw_u64(1).expect("nonzero file description id"),
    );
    let common = description.common();

    assert_eq!(common.status_flags(), 0);
    assert_eq!(common.fd_refs(), 0);
    assert_eq!(common.owner(), AsyncIoOwner::default());
    assert_eq!(common.async_sig(), 0);
    assert_eq!(common.seals(), None);
    assert!(!common.secretmem());

    common.set_status_flags(carrick_abi::LINUX_O_NONBLOCK);
    common.set_owner(AsyncIoOwner {
        owner_type: 1,
        owner_pid: 42,
    });
    common.set_async_sig(carrick_abi::LINUX_SIGUSR1);
    common.set_seals(Some(0b0001));
    common.set_secretmem(true);

    common.retain_fd_ref();
    common.retain_fd_ref();
    assert_eq!(common.fd_refs(), 2);
    assert_eq!(common.release_fd_ref(), 1);
    assert_eq!(common.fd_refs(), 1);

    // The whole point of hoisting: this state is reachable through the
    // description identity, so it does not vanish when the backing drains to
    // its Closed shell — the case `OpenDescription::base()` aborts on today.
    assert_eq!(common.status_flags(), carrick_abi::LINUX_O_NONBLOCK);
    assert_eq!(
        common.owner(),
        AsyncIoOwner {
            owner_type: 1,
            owner_pid: 42,
        }
    );
    assert_eq!(common.async_sig(), carrick_abi::LINUX_SIGUSR1);
    assert_eq!(common.seals(), Some(0b0001));
    assert!(common.secretmem());
}
